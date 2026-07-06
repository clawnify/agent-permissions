// Rule sources: session (memory), local (CWD .openclaw/), user (~/.openclaw/),
// config (plugin config in openclaw.json).
//
// All four sources contribute rules to the matcher. Session is in-process
// state, the other three read from JSON files (or the plugin config object)
// with the shape:
//
//   { "permissions": { "allow": [...], "deny": [...], "ask": [...] } }
//
// File-source rules are loaded once at register time. v1 has no file
// watchers — restart the gateway to pick up edits to the JSON files. This
// matches how openclaw.json edits are picked up today.

import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import type { PolicyBucket, RuleDestination, RuleSource } from "../api/types.js";
import { parseRuleString, serializeRule, type ParsedRule } from "./rule-parser.js";
import type { RuleSet, SourcedRule } from "./rule-matcher.js";

export interface PermissionsJson {
  permissions?: {
    allow?: string[];
    deny?: string[];
    ask?: string[];
  };
}

export interface ConfigBlock {
  allow?: string[];
  deny?: string[];
  ask?: string[];
}

export interface SourcePaths {
  /** Defaults to .openclaw/permissions.json in CWD. */
  local: string;
  /** Defaults to ~/.openclaw/permissions.json. */
  user: string;
}

export function defaultSourcePaths(overrides?: Partial<SourcePaths>): SourcePaths {
  return {
    local: overrides?.local ?? join(process.cwd(), ".openclaw", "permissions.json"),
    user: overrides?.user ?? join(homedir(), ".openclaw", "permissions.json"),
  };
}

/**
 * A cheap stamp of the rule files' state (mtime + size per file). When this
 * changes, the files were edited — directly, by an operator, or by our own
 * persist — and the cached rule set must be rebuilt. This is what makes edits
 * take effect without a gateway restart (v1 had no reload path, so rules set
 * any way other than via the tool sat unloaded).
 */
export function fileMtimeStamp(paths: SourcePaths): string {
  const stat = (p: string): string => {
    try {
      const s = statSync(p);
      return `${s.mtimeMs}:${s.size}`;
    } catch {
      return "0";
    }
  };
  return `${stat(paths.user)}|${stat(paths.local)}`;
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

export function loadAllRules(args: {
  config: ConfigBlock;
  paths: SourcePaths;
  sessionStore: SessionRuleStore;
  logger: { info: (m: string) => void; warn: (m: string) => void };
}): RuleSet {
  const result: RuleSet = { allow: [], deny: [], ask: [] };

  appendFromFile(result, args.paths.user, "user", args.logger);
  appendFromFile(result, args.paths.local, "local", args.logger);
  appendFromConfig(result, args.config, "config", args.logger);
  appendFromSession(result, args.sessionStore);

  return result;
}

function appendFromFile(
  acc: RuleSet,
  filePath: string,
  source: RuleSource,
  logger: { warn: (m: string) => void },
): void {
  if (!existsSync(filePath)) return;
  let parsed: PermissionsJson;
  try {
    const raw = readFileSync(filePath, "utf8");
    parsed = JSON.parse(raw) as PermissionsJson;
  } catch (err) {
    logger.warn(
      `agent-permissions: could not read ${source} rules at ${filePath} — ${String(err)}`,
    );
    return;
  }
  appendBucket(acc, "allow", parsed.permissions?.allow, source, logger);
  appendBucket(acc, "deny", parsed.permissions?.deny, source, logger);
  appendBucket(acc, "ask", parsed.permissions?.ask, source, logger);
}

function appendFromConfig(
  acc: RuleSet,
  config: ConfigBlock,
  source: RuleSource,
  logger: { warn: (m: string) => void },
): void {
  appendBucket(acc, "allow", config.allow, source, logger);
  appendBucket(acc, "deny", config.deny, source, logger);
  appendBucket(acc, "ask", config.ask, source, logger);
}

function appendFromSession(acc: RuleSet, store: SessionRuleStore): void {
  for (const r of store.allow) acc.allow.push({ rule: r, source: "session" });
  for (const r of store.deny) acc.deny.push({ rule: r, source: "session" });
  for (const r of store.ask) acc.ask.push({ rule: r, source: "session" });
}

function appendBucket(
  acc: RuleSet,
  bucket: PolicyBucket,
  ruleStrings: string[] | undefined,
  source: RuleSource,
  logger: { warn: (m: string) => void },
): void {
  if (!ruleStrings) return;
  for (const s of ruleStrings) {
    const parsed = parseRuleString(s);
    if (!parsed) {
      logger.warn(
        `agent-permissions: ignoring malformed rule '${s}' from ${source} settings`,
      );
      continue;
    }
    const sourced: SourcedRule = { rule: parsed, source };
    if (bucket === "allow") acc.allow.push(sourced);
    else if (bucket === "deny") acc.deny.push(sourced);
    else acc.ask.push(sourced);
  }
}

// ---------------------------------------------------------------------------
// Session rule store (in-memory, no persistence)
// ---------------------------------------------------------------------------

export class SessionRuleStore {
  readonly allow: ParsedRule[] = [];
  readonly deny: ParsedRule[] = [];
  readonly ask: ParsedRule[] = [];

  add(rule: ParsedRule, bucket: PolicyBucket): void {
    const target =
      bucket === "allow" ? this.allow : bucket === "deny" ? this.deny : this.ask;
    if (target.some((existing) => sameRule(existing, rule))) return;
    target.push(rule);
  }

  remove(rule: ParsedRule, bucket: PolicyBucket): boolean {
    const target =
      bucket === "allow" ? this.allow : bucket === "deny" ? this.deny : this.ask;
    const i = target.findIndex((existing) => sameRule(existing, rule));
    if (i < 0) return false;
    target.splice(i, 1);
    return true;
  }
}

function sameRule(a: ParsedRule, b: ParsedRule): boolean {
  return serializeRule(a) === serializeRule(b);
}

// ---------------------------------------------------------------------------
// Persisting an allow-always rule
// ---------------------------------------------------------------------------

/**
 * Append a learned rule to the chosen destination. `session` writes to the
 * in-memory store; `local`/`user` write to the corresponding JSON file
 * (creating directories as needed). Throws if the destination JSON file
 * exists but is unparseable — caller should log + skip rather than crash
 * the hook.
 */
export function persistRule(args: {
  rule: ParsedRule;
  bucket: PolicyBucket;
  destination: RuleDestination;
  paths: SourcePaths;
  sessionStore: SessionRuleStore;
}): void {
  if (args.destination === "session") {
    args.sessionStore.add(args.rule, args.bucket);
    return;
  }

  const filePath = args.destination === "local" ? args.paths.local : args.paths.user;
  const existing = readPermissionsFile(filePath);
  const serialized = serializeRule(args.rule);

  const block = existing.permissions ?? {};
  const bucketKey =
    args.bucket === "allow" ? "allow" : args.bucket === "deny" ? "deny" : "ask";
  const current = block[bucketKey] ?? [];
  if (!current.includes(serialized)) {
    current.push(serialized);
  }
  block[bucketKey] = current;
  existing.permissions = block;

  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(existing, null, 2) + "\n", "utf8");
}

function readPermissionsFile(filePath: string): PermissionsJson {
  if (!existsSync(filePath)) return {};
  const raw = readFileSync(filePath, "utf8");
  if (raw.trim() === "") return {};
  return JSON.parse(raw) as PermissionsJson;
}

/**
 * Remove a rule from the given buckets at the destination. Returns true if
 * anything was actually removed. Used both for explicit removal and to keep a
 * rule in a single bucket (setting it in one bucket removes it from the others,
 * so allow/ask/deny can't silently contradict). Never creates the file.
 */
export function removeRule(args: {
  rule: ParsedRule;
  buckets: PolicyBucket[];
  destination: RuleDestination;
  paths: SourcePaths;
  sessionStore: SessionRuleStore;
}): boolean {
  if (args.destination === "session") {
    let removed = false;
    for (const b of args.buckets) {
      if (args.sessionStore.remove(args.rule, b)) removed = true;
    }
    return removed;
  }

  const filePath = args.destination === "local" ? args.paths.local : args.paths.user;
  if (!existsSync(filePath)) return false;
  const existing = readPermissionsFile(filePath);
  const block = existing.permissions;
  if (!block) return false;
  const serialized = serializeRule(args.rule);

  let changed = false;
  for (const bucket of args.buckets) {
    const arr = block[bucket];
    if (!arr) continue;
    const filtered = arr.filter((r) => r !== serialized);
    if (filtered.length !== arr.length) {
      block[bucket] = filtered;
      changed = true;
    }
  }
  if (changed) {
    existing.permissions = block;
    writeFileSync(filePath, JSON.stringify(existing, null, 2) + "\n", "utf8");
  }
  return changed;
}
