import { z } from "npm:zod@4";
// Type-only imports — erased at compile time, never bundled. They anchor the
// `satisfies ModelDefinition<typeof GlobalArgs>` clause so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";
// Transport uses the Web `fetch`/`AbortController` globals only — NO `node:`
// import, so the extension has zero dependencies and resolves no floating
// `@types/node` at doc-lint time.

/**
 * `@thomas/stalwart` — careful, non-destructive administration of a Stalwart
 * mail server (v0.16+) over its JMAP-over-HTTP management API.
 *
 * SCOPE GUARANTEE (the whole point): this holds a powerful mail-admin credential,
 * so its surface is deliberately narrow and reversible. It NEVER hard-deletes an
 * account, domain, group, or list — the only "off switch" is the reversible
 * set-state (deactivate ⇄ reactivate) pair. The JMAP `destroy` verb is plumbed
 * through the transport for completeness but is reachable from NO method. Every
 * secret it accepts (an account password, a certificate private key) is sent to
 * Stalwart exactly once and is NEVER read back into a resource or logged.
 *
 * Transport: Stalwart 0.16 removed the legacy REST `/api/*` management tree;
 * management is now JMAP (RFC 8620) at `POST {apiUrl}/jmap` — a
 * `{ using, methodCalls }` envelope driving `Foo/get` / `Foo/query` /
 * `Foo/set` {create,update,destroy}. A small `/api/*` set survives for
 * introspection (`/api/account`, `/api/schema`) and metrics
 * (`/metrics/prometheus`); those are reached over the separate REST seam.
 *
 * Auth: a scoped admin API key, sent as `Authorization: Bearer <key>` on every
 * request. No long-lived token is exchanged or stored.
 *
 * Object model (confirmed live against 0.16): individuals use the RFC-standard
 * `Principal/*`; every registry/management object is served under
 * `urn:stalwart:jmap` with an `x:` prefix (`x:Account`, `x:Domain`, `x:Role`,
 * `x:Http`, …); settings singletons are `/get` by the fixed id `singleton`; and
 * server actions (reloads, queue pause/resume) are run by *creating* an
 * `x:Action` with an `@type`. The pinned names live in {@link JMAP_TYPES}.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  apiUrl: z.string().describe(
    "Stalwart base URL, e.g. https://mail.smol.cloud (no trailing /jmap)",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "Scoped admin API key, sent as a Bearer token. Supply via vault: " +
      "${{ vault.get(<vault>, stalwart/api_key) }}",
  ),
  accountId: z.string().optional().describe(
    "JMAP management accountId. Omit to resolve the session's primary account.",
  ),
  httpTimeoutMs: z.coerce.number().int().default(30000).describe(
    "Per-request timeout (ms) for JMAP and REST calls",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type", so
// it must not leak onto the public API (the exported seam types use the loose
// {@link Json} instead — see below).
type GlobalArgsT = z.infer<typeof GlobalArgs>;

/** The set of outcomes a method reports in its `action` field. */
const Action = z.enum([
  "created",
  "unchanged",
  "updated",
  "deactivated",
  "reactivated",
  "installed",
  "reloaded",
  "observed",
]);

// ─────────────────────────── resource schemas ───────────────────────────

const DomainInfo = z.object({
  id: z.string(),
  name: z.string(),
  state: z.string().describe("active | inactive | unknown"),
  dkim: z.boolean().optional().describe(
    "Whether a DKIM signature is configured",
  ),
  action: Action,
  timestamp: z.string(),
});

const AccountInfo = z.object({
  id: z.string(),
  name: z.string().describe("Login name — the local part (e.g. `alice`)"),
  email: z.string().optional().describe("Full primary address (emailAddress)"),
  domainId: z.string().optional().describe("Id of the account's domain"),
  type: z.string().describe("individual | group | unknown (from @type)"),
  aliases: z.array(z.string()).describe(
    "Alias addresses attached to the account",
  ),
  roles: z.string().optional().describe(
    "Role assignment: admin | user | custom | unknown",
  ),
  enabled: z.boolean().optional().describe(
    "False when the account is disabled (permissions replaced with empty)",
  ),
  description: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const RoleInfo = z.object({
  id: z.string(),
  description: z.string().describe("The role's name/description"),
  enabledPermissions: z.array(z.string()).describe(
    "Permissions the role grants",
  ),
  disabledPermissions: z.array(z.string()).optional(),
  nestedRoleIds: z.array(z.string()).optional().describe("Inherited role ids"),
  action: Action,
  timestamp: z.string(),
});

const AliasInfo = z.object({
  id: z.string().describe("The owning principal's id"),
  address: z.string(),
  account: z.string().describe("The owning principal's login name"),
  action: Action,
  timestamp: z.string(),
});

const GroupInfo = z.object({
  id: z.string(),
  name: z.string(),
  members: z.array(z.string()),
  description: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const MailingListInfo = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  recipients: z.array(z.string()).describe("Member recipient addresses"),
  action: Action,
  timestamp: z.string(),
});

const ReportInfo = z.object({
  id: z.string(),
  kind: z.string().describe("dmarc | tls"),
  domain: z.string().optional(),
  rangeStart: z.string().optional(),
  rangeEnd: z.string().optional(),
  summary: z.string().optional().describe(
    "A short human summary of the report",
  ),
  action: Action,
  timestamp: z.string(),
});

const QueueItemInfo = z.object({
  id: z.string(),
  from: z.string().optional(),
  to: z.array(z.string()),
  status: z.string().optional(),
  nextRetry: z.string().optional(),
  size: z.number().optional(),
  action: Action,
  timestamp: z.string(),
});

const HealthInfo = z.object({
  reachable: z.boolean(),
  edition: z.string().optional().describe("oss | community | enterprise"),
  version: z.string().optional(),
  permissions: z.array(z.string()).optional(),
  metrics: z.record(z.string(), z.number()).describe(
    "Curated gauges parsed from /metrics/prometheus (label sets collapsed)",
  ),
  action: Action,
  timestamp: z.string(),
});

const CertificateInfo = z.object({
  id: z.string(),
  subject: z.string().optional(),
  sans: z.array(z.string()).optional(),
  notAfter: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const SpamConfigInfo = z.object({
  id: z.string(),
  kind: z.string().describe("classifier | rule"),
  name: z.string(),
  settings: z.record(z.string(), z.unknown()),
  action: Action,
  timestamp: z.string(),
});

const SettingsInfo = z.object({
  kind: z.string().describe("Which settings singleton (http, system, …)"),
  id: z.string(),
  settings: z.record(z.string(), z.unknown()).describe(
    "The singleton's current fields",
  ),
  action: Action,
  timestamp: z.string(),
});

const StateResult = z.object({
  kind: z.string().describe(
    "account | group | list | domain | server | certificates",
  ),
  id: z.string(),
  state: z.string(),
  action: Action,
  timestamp: z.string(),
});

const SessionInfo = z.object({
  capabilities: z.array(z.string()).describe(
    "Capability URIs advertised by the JMAP session resource",
  ),
  accounts: z.array(z.string()).describe("Account ids in the session"),
  primaryAccounts: z.record(z.string(), z.string()).describe(
    "capability URI → primary accountId",
  ),
  raw: z.string().optional().describe(
    "Full session JSON, for pinning the management method surface",
  ),
  action: Action,
  timestamp: z.string(),
});

const ProbeResult = z.object({
  type: z.string().describe("The JMAP object type that was probed"),
  capability: z.string().describe("The management capability URI used"),
  accountId: z.string().optional(),
  count: z.number().describe("How many ids the query returned"),
  ids: z.array(z.string()).describe("The ids returned (first page)"),
  // A probed object may carry sensitive fields (e.g. a Principal's hashed
  // `secrets`, or key material on an api-key type). Mark sensitive so swamp
  // masks it and never logs it, even though it is stored for shape-pinning.
  sample: z.string().meta({ sensitive: true }).optional().describe(
    "JSON of the first object's fields — for pinning the wire shape",
  ),
  action: Action,
  timestamp: z.string(),
});

// ─────────────────────────── JMAP type constants (PIN IN PHASE 0) ───────────────────────────

/**
 * JMAP capability URIs sent in the `using` array of every envelope. `core` and
 * `principals` are RFC-standard; `mgmt` (`urn:stalwart:jmap`) is the Stalwart
 * capability that serves every registry/management object. Confirmed against the
 * live 0.16 session resource during the Phase 0 discovery spike.
 */
export const USING = {
  core: "urn:ietf:params:jmap:core",
  principals: "urn:ietf:params:jmap:principals",
  mgmt: "urn:stalwart:jmap",
} as const;

/**
 * Wire type names for Stalwart's JMAP objects, confirmed live (Phase 0).
 * The principal family of individuals uses the RFC-standard `Principal` type;
 * every registry/management object is served under `urn:stalwart:jmap` with an
 * `x:` prefix. Singletons (`x:SpamClassifier`, `x:SystemSettings`) are `/get`
 * only. Actions (reloads, queue pause/resume, spam classify) are executed by
 * *creating* an `x:Action` with an `@type` discriminator.
 */
export const JMAP_TYPES = {
  principal: "Principal",
  account: "x:Account",
  domain: "x:Domain",
  mailingList: "x:MailingList",
  role: "x:Role",
  tenant: "x:Tenant",
  dkimSignature: "x:DkimSignature",
  certificate: "x:Certificate",
  acmeProvider: "x:AcmeProvider",
  spamClassifier: "x:SpamClassifier",
  spamRule: "x:SpamRule",
  queuedMessage: "x:QueuedMessage",
  dmarcReport: "x:DmarcInternalReport",
  tlsReport: "x:TlsInternalReport",
  action: "x:Action",
} as const;

// ─────────────────────────── HTTP seams ───────────────────────────

/** A JSON-ish bag — structurally the resolved global args or an API body. */
export type Json = Record<string, unknown>;

/** A JMAP request envelope: the capabilities in use and the method calls to run. */
export interface JmapCall {
  /** Capability URIs (RFC 8620 `using`). */
  using: string[];
  /** Method-call tuples: `[name, arguments, callId]`. */
  methodCalls: unknown[][];
}

/** The parsed result of a {@link JmapCall} — the raw JMAP response body. */
export interface JmapResult {
  /** HTTP status code. */
  status: number;
  /** Parsed response body (`{ methodResponses, sessionState, ... }`). */
  body: Json;
}

/**
 * The JMAP-call seam the methods use — swappable for unit tests. The global args
 * are typed loosely as {@link Json} so this EXPORTED type stays "fast-check"
 * clean (referencing the zod-inferred globals would drag a slow type onto the
 * public API). The real implementation re-narrows.
 */
export type JmapFn = (g: Json, call: JmapCall) => Promise<JmapResult>;

/** One surviving-REST request: a GET/POST against an `/api/*` or `/metrics/*` path. */
export interface RestCall {
  /** HTTP verb. */
  method: "GET" | "POST";
  /** Path relative to `apiUrl`, e.g. `/api/account` or `/metrics/prometheus`. */
  path: string;
  /** Optional `Accept` header (defaults to `application/json`). */
  accept?: string;
  /** Optional JSON request body. */
  body?: unknown;
}

/** The parsed result of a {@link RestCall}. */
export interface RestResult {
  /** HTTP status code. */
  status: number;
  /** Parsed JSON body (`{}` for non-JSON); raw text in `text` for text bodies. */
  body: Json;
  /** Raw response text, for text endpoints like the Prometheus exposition. */
  text?: string;
}

/** The surviving-REST seam — swappable for unit tests. */
export type RestFn = (g: Json, call: RestCall) => Promise<RestResult>;

let _jmapOverride: JmapFn | null = null;
let _restOverride: RestFn | null = null;

/** Test-only seam: substitute the JMAP caller. Pass `null` to restore the real one. */
export function __setJmap(fn: JmapFn | null): void {
  _jmapOverride = fn;
}

/** Test-only seam: substitute the REST caller. Pass `null` to restore the real one. */
export function __setRest(fn: RestFn | null): void {
  _restOverride = fn;
}

function baseUrl(g: GlobalArgsT): string {
  return g.apiUrl.replace(/\/+$/, "");
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

/** The real fetch-backed JMAP implementation behind {@link jmap}. */
async function realJmap(g: GlobalArgsT, c: JmapCall): Promise<JmapResult> {
  const res = await fetchWithTimeout(
    `${baseUrl(g)}/jmap`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${g.apiKey}`,
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ using: c.using, methodCalls: c.methodCalls }),
    },
    g.httpTimeoutMs,
  );
  const text = await res.text();
  let parsed: Json = {};
  if (text) {
    try {
      parsed = JSON.parse(text) as Json;
    } catch {
      parsed = { raw: text };
    }
  }
  if (res.status >= 400) {
    throw new Error(`Stalwart JMAP HTTP ${res.status}: ${text}`);
  }
  return { status: res.status, body: parsed };
}

/** The real fetch-backed REST implementation behind {@link rest}. */
async function realRest(g: GlobalArgsT, c: RestCall): Promise<RestResult> {
  const headers: Record<string, string> = {
    authorization: `Bearer ${g.apiKey}`,
    accept: c.accept ?? "application/json",
  };
  let body: string | undefined;
  if (c.body !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(c.body);
  }
  const res = await fetchWithTimeout(
    `${baseUrl(g)}${c.path}`,
    { method: c.method, headers, body },
    g.httpTimeoutMs,
  );
  const text = await res.text();
  if (res.status >= 400) {
    throw new Error(
      `Stalwart REST ${c.method} ${c.path} -> HTTP ${res.status}: ${text}`,
    );
  }
  let parsed: Json = {};
  const ct = res.headers.get("content-type") ?? "";
  if (text && ct.includes("json")) {
    try {
      parsed = JSON.parse(text) as Json;
    } catch {
      parsed = { raw: text };
    }
  }
  return { status: res.status, body: parsed, text };
}

function jmap(g: GlobalArgsT, c: JmapCall): Promise<JmapResult> {
  return (_jmapOverride ?? realJmap)(g, c);
}

function rest(g: GlobalArgsT, c: RestCall): Promise<RestResult> {
  return (_restOverride ?? realRest)(g, c);
}

// ─────────────────────────── JMAP envelope helpers ───────────────────────────

/**
 * Pull method-call `i` out of a JMAP response and return its arguments object,
 * throwing on a method-level `["error", {...}]` tuple. JMAP reports per-call
 * failures inside an HTTP-200 body, so this is distinct from transport errors.
 */
function methodResponseArgs(body: Json, index = 0): Json {
  const responses = Array.isArray(body.methodResponses)
    ? (body.methodResponses as unknown[][])
    : [];
  const tuple = responses[index];
  if (!Array.isArray(tuple)) {
    throw new Error("Stalwart JMAP: missing methodResponses entry");
  }
  const [name, args] = tuple as [unknown, Json];
  if (name === "error") {
    const type = String((args as Json)?.type ?? "unknown");
    const desc = String((args as Json)?.description ?? "");
    throw new Error(
      `Stalwart JMAP method error: ${type}${desc ? `: ${desc}` : ""}`,
    );
  }
  return (args ?? {}) as Json;
}

function asArray(v: unknown): Json[] {
  return Array.isArray(v) ? (v as Json[]) : [];
}

function nowIso(): string {
  return new Date().toISOString();
}

/** Resolve the management `accountId` (explicit arg, else the session's primary). */
async function resolveAccountId(g: GlobalArgsT): Promise<string | undefined> {
  if (g.accountId) return g.accountId;
  const cached = _accountIdCache.get(g.apiUrl);
  if (cached !== undefined) return cached;
  // The session resource lists accounts under `.accounts` and names the primary
  // under `.primaryAccounts`. Field shapes are confirmed in the Phase 0 spike.
  const r = await rest(g, { method: "GET", path: "/.well-known/jmap" });
  const accounts = (r.body.accounts ?? {}) as Json;
  const primary = (r.body.primaryAccounts ?? {}) as Json;
  const id =
    (typeof primary[USING.mgmt] === "string"
      ? primary[USING.mgmt] as string
      : Object.keys(accounts)[0]) ?? undefined;
  _accountIdCache.set(g.apiUrl, id);
  return id;
}
const _accountIdCache = new Map<string, string | undefined>();

/** Run a `Foo/get` and return its `list[]`. */
async function jmapGet(
  g: GlobalArgsT,
  type: string,
  opts: { accountId?: string; ids?: string[] | null; properties?: string[] },
): Promise<Json[]> {
  const args: Json = {
    accountId: opts.accountId ?? null,
    ids: opts.ids ?? null,
  };
  if (opts.properties) args.properties = opts.properties;
  const r = await jmap(g, {
    using: [USING.core, USING.mgmt],
    methodCalls: [[`${type}/get`, args, "c0"]],
  });
  return asArray(methodResponseArgs(r.body).list);
}

/** Run a `Foo/query` and return matching ids. */
async function jmapQuery(
  g: GlobalArgsT,
  type: string,
  opts: { accountId?: string; filter?: Json; limit?: number },
): Promise<string[]> {
  const args: Json = { accountId: opts.accountId ?? null };
  if (opts.filter) args.filter = opts.filter;
  if (opts.limit !== undefined) args.limit = opts.limit;
  const r = await jmap(g, {
    using: [USING.core, USING.mgmt],
    methodCalls: [[`${type}/query`, args, "c0"]],
  });
  const ids = methodResponseArgs(r.body).ids;
  return Array.isArray(ids) ? ids.map(String) : [];
}

/**
 * Run a `<type>/set` with `create` and/or `update` blocks and return the raw set
 * response. By design it takes NO `destroy` — the no-destroy guarantee is
 * structural: there is no code path that can ask Stalwart to delete an object.
 * Per-item failures land in `notCreated`/`notUpdated`; callers check via
 * {@link setItemError}.
 */
async function jmapSet(
  g: GlobalArgsT,
  type: string,
  opts: { accountId?: string; create?: Json; update?: Json },
): Promise<Json> {
  const args: Json = { accountId: opts.accountId ?? null };
  if (opts.create) args.create = opts.create;
  if (opts.update) args.update = opts.update;
  const r = await jmap(g, {
    using: [USING.core, USING.mgmt],
    methodCalls: [[`${type}/set`, args, "c0"]],
  });
  return methodResponseArgs(r.body);
}

/**
 * Execute a Stalwart server action by *creating* an `x:Action` with the given
 * `@type` (e.g. `ReloadSettings`, `ReloadTlsCertificates`). Actions are
 * create-only and cannot be updated or destroyed. Throws on failure.
 */
async function runAction(
  g: GlobalArgsT,
  accountId: string | undefined,
  atType: string,
): Promise<void> {
  const res = await jmapSet(g, JMAP_TYPES.action, {
    accountId,
    create: { "c0": { "@type": atType } },
  });
  const err = setItemError(res, "c0");
  if (err) throw new Error(`Action ${atType} failed: ${err}`);
}

/**
 * Inspect a set response for a per-item failure under `notCreated`/
 * `notUpdated` for `key`, and return a human message (or null if it succeeded).
 */
function setItemError(setRes: Json, key: string): string | null {
  for (const bucket of ["notCreated", "notUpdated"]) {
    const b = setRes[bucket];
    if (b && typeof b === "object" && key in (b as Json)) {
      const err = (b as Json)[key] as Json;
      const type = String(err?.type ?? "error");
      const desc = err?.description ? `: ${err.description}` : "";
      const props = Array.isArray(err?.properties)
        ? ` (${(err.properties as unknown[]).join(", ")})`
        : "";
      return `${type}${desc}${props}`;
    }
  }
  return null;
}

/**
 * List every object of `type`: page through `<type>/query` (cap 100/page,
 * `position`/`total`) accumulating ids, then one `<type>/get` for the requested
 * `properties`. Returns the full `list[]`. Used by the read/`*_list` methods.
 */
async function listAll(
  g: GlobalArgsT,
  type: string,
  accountId: string | undefined,
  properties?: string[],
): Promise<Json[]> {
  const ids: string[] = [];
  for (let position = 0, guard = 0; guard < 1000; guard++) {
    const r = await jmap(g, {
      using: [USING.core, USING.mgmt],
      methodCalls: [[`${type}/query`, {
        accountId: accountId ?? null,
        limit: 100,
        position,
        calculateTotal: true,
      }, "c0"]],
    });
    const args = methodResponseArgs(r.body);
    const page = Array.isArray(args.ids) ? args.ids.map(String) : [];
    ids.push(...page);
    const total = Number(args.total);
    position += page.length;
    if (page.length === 0) break;
    if (Number.isFinite(total) && ids.length >= total) break;
  }
  if (ids.length === 0) return [];
  return await jmapGet(g, type, { accountId, ids, properties });
}

/** Keys of a Stalwart `Map<T>`/`List<T>` wire object (`{}` → `[]`). */
function mapKeys(v: unknown): string[] {
  return v && typeof v === "object" ? Object.keys(v as Json) : [];
}

/** The `name` addresses out of an `aliases` List<EmailAlias> wire object. */
function aliasAddresses(v: unknown): string[] {
  if (!v || typeof v !== "object") return [];
  return Object.values(v as Record<string, Json>)
    .map((a) => (a && typeof a.name === "string" ? a.name : ""))
    .filter((s) => s.length > 0);
}

/** Friendly role label from a `roles` union (`{@type:"Admin"}` → `admin`). */
function rolesLabel(v: unknown): string {
  const t = v && typeof v === "object" ? (v as Json)["@type"] : undefined;
  return typeof t === "string" ? t.toLowerCase() : "unknown";
}

/** Friendly account type from `@type` (`User` → individual, `Group` → group). */
function accountType(v: unknown): string {
  if (v === "User") return "individual";
  if (v === "Group") return "group";
  return typeof v === "string" ? v.toLowerCase() : "unknown";
}

/** Split an email address into its local part and domain. */
function parseAddress(addr: string): { local: string; domain: string } {
  const at = addr.lastIndexOf("@");
  if (at <= 0 || at === addr.length - 1) {
    throw new Error(`Not a full email address: ${addr}`);
  }
  return { local: addr.slice(0, at), domain: addr.slice(at + 1) };
}

/** Build a `name → id` map of all domains (for resolving account/alias domains). */
async function domainIdMap(
  g: GlobalArgsT,
  accountId: string | undefined,
): Promise<Map<string, string>> {
  const rows = await listAll(g, JMAP_TYPES.domain, accountId, ["id", "name"]);
  return new Map(rows.map((d) => [String(d.name), String(d.id)]));
}

/**
 * Resolve a friendly role name to a JMAP `UserRoles` union: `admin`→`{@type:Admin}`,
 * `user`→`{@type:User}`, anything else → a custom role looked up by description.
 * Returns the union and a friendly label. Throws if a custom role is unknown.
 */
async function buildRolesUnion(
  g: GlobalArgsT,
  accountId: string | undefined,
  roleName: string,
): Promise<{ union: Json; label: string }> {
  const r = roleName.toLowerCase();
  if (r === "admin") return { union: { "@type": "Admin" }, label: "admin" };
  if (r === "user") return { union: { "@type": "User" }, label: "user" };
  const roles = await listAll(g, JMAP_TYPES.role, accountId, [
    "id",
    "description",
  ]);
  const role = roles.find((x) => String(x.description) === roleName);
  if (!role) throw new Error(`Role not found: ${roleName}`);
  return {
    union: { "@type": "Custom", roleIds: { [String(role.id)]: true } },
    label: `custom:${roleName}`,
  };
}

// ─────────────────────────── REST / health helpers ───────────────────────────

/**
 * Parse a Prometheus text-exposition body into a flat `{ metric: value }` map,
 * collapsing label sets (last sample wins) and skipping comments. Pure and
 * exported for tests. Phase 1 curates which gauges `health_status` surfaces.
 */
export function parsePrometheus(text: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const line of text.split("\n")) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    // `name{labels} value` or `name value` — take the metric name before `{`/space.
    const m = s.match(
      /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{[^}]*\})?\s+([-+0-9.eE]+|NaN|[-+]Inf)\s*$/,
    );
    if (!m) continue;
    const value = Number(m[2]);
    if (Number.isFinite(value)) out[m[1]] = value;
  }
  return out;
}

// ─────────────────────────── method argument schemas ───────────────────────────

const Empty = z.object({});

const JmapProbeArgs = z.object({
  type: z.string().describe(
    "JMAP object type to probe, e.g. Principal, Domain, SpamClassifier",
  ),
  limit: z.coerce.number().int().default(5).describe(
    "Max ids to query (kept small — this is a discovery probe)",
  ),
});

const AliasListArgs = z.object({
  account: z.string().optional().describe(
    "Filter to one account's aliases (local part or full address)",
  ),
});

const ReportQueryArgs = z.object({
  kind: z.enum(["dmarc", "tls", "all"]).default("all").describe(
    "Which received aggregate reports to list",
  ),
});

/**
 * A string array that also accepts a JSON-encoded array or a comma-separated
 * string — so list-valued method arguments survive the CLI's `--input k=v`.
 */
const jsonArray = z.preprocess((v) => {
  if (typeof v !== "string") return v;
  const s = v.trim();
  if (s.startsWith("[")) {
    try {
      const p = JSON.parse(s);
      if (Array.isArray(p)) return p;
    } catch { /* fall through to CSV */ }
  }
  return s.split(",").map((x) => x.trim()).filter((x) => x.length > 0);
}, z.array(z.string()));

/**
 * A JSON object argument that also accepts a JSON-encoded string — so an
 * object-valued method argument survives the CLI's `--input k=v`.
 */
const jsonObject = z.preprocess((v) => {
  if (typeof v !== "string") return v;
  try {
    const p = JSON.parse(v);
    if (p && typeof p === "object" && !Array.isArray(p)) return p;
  } catch { /* fall through */ }
  return v;
}, z.record(z.string(), z.unknown()));

/** The fixed object id Stalwart uses for every settings singleton. */
const SINGLETON_ID = "singleton";

/** Friendly settings-singleton name → JMAP type. */
const SETTINGS_TYPES: Record<string, string> = {
  http: "x:Http",
  system: "x:SystemSettings",
  "spam-classifier": "x:SpamClassifier",
  authentication: "x:Authentication",
  imap: "x:Imap",
  jmap: "x:Jmap",
};
const SETTINGS_KINDS = [
  "http",
  "system",
  "spam-classifier",
  "authentication",
  "imap",
  "jmap",
] as const;

const SettingsGetArgs = z.object({
  kind: z.enum(SETTINGS_KINDS).describe("Which settings singleton to read"),
});

const SettingsSetArgs = z.object({
  kind: z.enum(SETTINGS_KINDS).describe("Which settings singleton to update"),
  patch: jsonObject.describe(
    'Fields to set, e.g. {"usePermissiveCors":true}. Merged into the singleton.',
  ),
  reload: z.coerce.boolean().default(true).describe(
    "Run a settings reload after the change so it takes effect",
  ),
});

const MailingListEnsureArgs = z.object({
  address: z.string().describe("Full list address, e.g. team@smol.cloud"),
  recipients: jsonArray.optional().describe(
    "Member recipient addresses (converged to exactly this set when provided)",
  ),
  description: z.string().optional(),
});

const GroupEnsureArgs = z.object({
  address: z.string().describe("Full group address, e.g. staff@smol.cloud"),
  description: z.string().optional(),
});

/**
 * Curated, signed-off role permission sets. `role_ensure --input preset=…`
 * provisions one of these without having to pass a long permission list.
 * `swamp-admin`: non-destructive management (Get/Query/Create/Update, no
 * `*Destroy`). `automated-mailbox`: send-only authenticated SMTP.
 */
const ROLE_PRESETS: Record<string, { description: string; enabled: string[] }> =
  {
    "swamp-admin": {
      description: "Swamp Admin",
      // NB: to ASSIGN a custom role (e.g. `automated-mailbox`), this principal must
      // itself hold every permission that role grants (Stalwart privilege
      // non-escalation). swamp-admin is granted the `User` + `Automated Mailbox`
      // member roles out-of-band via the web-admin (a one-time fallback-admin
      // bootstrap — swamp-admin can't self-escalate) rather than enumerating those
      // perms here, so they are intentionally NOT in this flat list.
      enabled: [
        "authenticate",
        // settings singletons the extension reads/writes (settings_get/_set)
        "sysHttpGet",
        "sysHttpUpdate",
        "sysSystemSettingsGet",
        "sysSystemSettingsUpdate",
        "sysImapGet",
        "sysImapUpdate",
        "sysJmapGet",
        "sysJmapUpdate",
        "sysAuthenticationGet",
        "sysAuthenticationUpdate",
        "sysAccountGet",
        "sysAccountQuery",
        "sysAccountCreate",
        "sysAccountUpdate",
        "sysDomainGet",
        "sysDomainQuery",
        "sysDomainCreate",
        "sysDomainUpdate",
        "sysMailingListGet",
        "sysMailingListQuery",
        "sysMailingListCreate",
        "sysMailingListUpdate",
        "sysRoleGet",
        "sysRoleQuery",
        "sysRoleCreate",
        "sysRoleUpdate",
        "sysDkimSignatureGet",
        "sysDkimSignatureQuery",
        "sysDmarcInternalReportGet",
        "sysDmarcInternalReportQuery",
        "sysTlsInternalReportGet",
        "sysTlsInternalReportQuery",
        "sysArfExternalReportGet",
        "sysArfExternalReportQuery",
        "sysDmarcExternalReportGet",
        "sysDmarcExternalReportQuery",
        "sysTlsExternalReportGet",
        "sysTlsExternalReportQuery",
        "sysQueuedMessageGet",
        "sysQueuedMessageQuery",
        "sysQueuedMessageUpdate",
        "actionPauseMtaQueue",
        "actionResumeMtaQueue",
        "sysSpamRuleGet",
        "sysSpamRuleQuery",
        "sysSpamRuleCreate",
        "sysSpamRuleUpdate",
        "sysSpamClassifierGet",
        "sysSpamClassifierUpdate",
        "sysSpamTrainingSampleGet",
        "sysSpamTrainingSampleQuery",
        "sysSpamTrainingSampleCreate",
        "sysSpamTrainingSampleUpdate",
        "actionClassifySpam",
        "sysCertificateGet",
        "sysCertificateQuery",
        "sysCertificateCreate",
        "sysCertificateUpdate",
        "sysAcmeProviderGet",
        "sysAcmeProviderQuery",
        "actionReloadSettings",
        "actionReloadTlsCertificates",
        "actionReloadLookupStores",
        "actionReloadBlockedIps",
        "actionInvalidateCaches",
        "actionInvalidateNegativeCaches",
        "actionTroubleshootDmarc",
      ],
    },
    "automated-mailbox": {
      description: "Automated Mailbox",
      enabled: ["authenticate", "emailSend", "authenticateWithAlias"],
    },
  };

const RoleEnsureArgs = z.object({
  preset: z.enum(["swamp-admin", "automated-mailbox"]).optional().describe(
    "Use a built-in curated permission set (supplies name + permissions)",
  ),
  name: z.string().optional().describe(
    "Role name/description. Required unless `preset` is given (overrides preset name).",
  ),
  permissions: jsonArray.optional().describe(
    "Explicit enabled-permission names. Required unless `preset` is given.",
  ),
}).describe(
  "Create or converge a role. Supply a preset, or name + permissions.",
);

const RoleAssignArgs = z.object({
  account: z.string().describe("Target account — local part or full address"),
  role: z.string().describe(
    "Role to assign: `admin`, `user`, or a custom role's name/description",
  ),
});

const AccountEnsureArgs = z.object({
  email: z.string().describe("Full primary address, e.g. alice@smol.cloud"),
  aliases: jsonArray.optional().describe(
    "Full alias addresses to attach (converged to exactly this set)",
  ),
  description: z.string().optional().describe("Display name / description"),
  role: z.string().optional().describe(
    "Role: admin | user | a custom role name (default `user` on create)",
  ),
  password: z.string().meta({ sensitive: true }).optional().describe(
    "Initial password, set once on CREATE only (hashed by Stalwart; never read back)",
  ),
});

const CertificateInstallArgs = z.object({
  certificate: z.string().describe("PEM certificate (full chain)"),
  privateKey: z.string().meta({ sensitive: true }).describe(
    "PEM private key — sent once, never read back",
  ),
  certificateId: z.string().optional().describe(
    "Update a specific certificate id; otherwise update the sole existing cert, or create one",
  ),
  reload: z.coerce.boolean().default(true).describe(
    "Run reload-certificates after install so the new cert is served",
  ),
});

const StateArg = z.enum(["active", "inactive"]);
const DomainSetStateArgs = z.object({
  domain: z.string().describe("Domain name, e.g. smol.cloud"),
  state: StateArg.describe("active (enabled) or inactive (disabled)"),
});
const AccountSetStateArgs = z.object({
  account: z.string().describe("Account — local part or full address"),
  state: StateArg.describe(
    "active = permissions Inherit; inactive = permissions Replace-empty (can't authenticate)",
  ),
});

// ─────────────────────────── model ───────────────────────────

type Ctx = MethodContext<GlobalArgsT>;

function logInfo(
  context: Pick<Ctx, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.info?.(message, props ?? {});
}

/**
 * The `@thomas/stalwart` model definition: a `reachable` live check, the mail
 * management resource schemas, and the methods. JMAP-backed methods are added
 * after the Phase 0 discovery spike pins {@link USING} / {@link JMAP_TYPES}; the
 * REST-only `health_status` is available now.
 */
export const model = {
  type: "@thomas/stalwart",
  version: "2026.06.09.1",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify Stalwart is reachable and the API key authenticates (GET /api/account)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        const g = context.globalArgs;
        // `swamp model validate` does not resolve vault expressions, so apiKey is
        // still a literal `${{ … }}` there and can't authenticate. Skip; the real
        // check runs at method-run time when the secret is resolved.
        if (/\$\{\{/.test(String(g.apiKey))) return { pass: true };
        try {
          await rest(g, { method: "GET", path: "/api/account" });
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Cannot reach Stalwart at ${g.apiUrl}: ${(e as Error).message}`,
            ],
          };
        }
      },
    },
  },
  resources: {
    "domain": {
      description: "A mail domain record",
      schema: DomainInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "account": {
      description:
        "An account / individual principal (emails[] = primary + aliases)",
      schema: AccountInfo,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "alias": {
      description: "An alias address — a view over a principal's emails[]",
      schema: AliasInfo,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "group": {
      description: "A group principal and its members",
      schema: GroupInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "mailing-list": {
      description: "A mailing-list principal and its members",
      schema: MailingListInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "report": {
      description: "A DMARC/TLS aggregate report (read-only)",
      schema: ReportInfo,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "queue-item": {
      description: "An outbound mail-queue entry (read-only)",
      schema: QueueItemInfo,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "health": {
      description:
        "Server health: edition/version/permissions + curated metrics",
      schema: HealthInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "certificate": {
      description: "A TLS certificate install result (key never echoed)",
      schema: CertificateInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "spam-config": {
      description: "A spam classifier/rule configuration result",
      schema: SpamConfigInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "role": {
      description: "A role and the permissions it grants",
      schema: RoleInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "settings": {
      description: "A server settings singleton (http, system, …)",
      schema: SettingsInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "state-result": {
      description: "Result of a reversible deactivate/reactivate or a reload",
      schema: StateResult,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "probe": {
      description:
        "Phase 0 discovery probe: the wire shape of one JMAP object type",
      schema: ProbeResult,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "session": {
      description:
        "The JMAP session resource: advertised capabilities + accounts",
      schema: SessionInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    // ───────────── read / health (REST-only; spike-independent) ─────────────
    // ───────────── read / audit (JMAP, factory) ─────────────
    domain_list: {
      description:
        "List mail domains (factory: one `domain` per domain). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing domains");
        const rows = await listAll(g, JMAP_TYPES.domain, accountId, [
          "id",
          "name",
          "isEnabled",
          "description",
        ]);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const d of rows) {
          handles.push(
            await context.writeResource("domain", String(d.name ?? d.id), {
              id: String(d.id ?? ""),
              name: String(d.name ?? ""),
              state: d.isEnabled === false ? "inactive" : "active",
              action: "observed",
              timestamp: ts,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },
    account_list: {
      description:
        "List accounts — individuals and groups (factory: one `account` each). " +
        "`aliases` are the attached addresses. Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing accounts");
        const rows = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "domainId",
          "@type",
          "aliases",
          "roles",
          "permissions",
          "description",
        ]);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const a of rows) {
          const perms = (a.permissions ?? {}) as Json;
          const disabled = perms["@type"] === "Replace" &&
            mapKeys((perms as Json).enabledPermissions).length === 0;
          const acctName = typeof a.emailAddress === "string" && a.emailAddress
            ? a.emailAddress
            : String(a.name ?? a.id);
          handles.push(
            await context.writeResource("account", acctName, {
              id: String(a.id ?? ""),
              name: String(a.name ?? ""),
              email: typeof a.emailAddress === "string"
                ? a.emailAddress
                : undefined,
              domainId: typeof a.domainId === "string" ? a.domainId : undefined,
              type: accountType(a["@type"]),
              aliases: aliasAddresses(a.aliases),
              roles: rolesLabel(a.roles),
              enabled: !disabled,
              description: typeof a.description === "string"
                ? a.description
                : undefined,
              action: "observed",
              timestamp: ts,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },
    alias_list: {
      description:
        "List alias addresses (factory: one `alias` per alias), optionally " +
        "filtered to one account. Derived from accounts' `aliases`. Read-only.",
      arguments: AliasListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AliasListArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing aliases", { account: a.account });
        const rows = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "aliases",
        ]);
        const want = a.account?.toLowerCase();
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const acct of rows) {
          const name = String(acct.name ?? "");
          const email = typeof acct.emailAddress === "string"
            ? acct.emailAddress
            : "";
          if (
            want && want !== name.toLowerCase() && want !== email.toLowerCase()
          ) continue;
          for (const addr of aliasAddresses(acct.aliases)) {
            handles.push(
              await context.writeResource("alias", addr, {
                id: String(acct.id ?? ""),
                address: addr,
                account: name,
                action: "observed",
                timestamp: ts,
              }),
            );
          }
        }
        return { dataHandles: handles };
      },
    },
    role_list: {
      description:
        "List roles and the permissions they grant (factory: one `role` each). " +
        "Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing roles");
        const rows = await listAll(g, JMAP_TYPES.role, accountId, [
          "id",
          "description",
          "enabledPermissions",
          "disabledPermissions",
          "roleIds",
        ]);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const r of rows) {
          handles.push(
            await context.writeResource("role", String(r.description ?? r.id), {
              id: String(r.id ?? ""),
              description: String(r.description ?? ""),
              enabledPermissions: mapKeys(r.enabledPermissions),
              disabledPermissions: mapKeys(r.disabledPermissions),
              nestedRoleIds: mapKeys(r.roleIds),
              action: "observed",
              timestamp: ts,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },
    group_list: {
      description:
        "List group accounts (factory: one `group` each). Read-only. Note: " +
        "membership lives on each member's account, not on the group.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing groups");
        const rows = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "@type",
          "description",
        ]);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const grp of rows.filter((x) => x["@type"] === "Group")) {
          handles.push(
            await context.writeResource(
              "group",
              String(grp.emailAddress ?? grp.name ?? grp.id),
              {
                id: String(grp.id ?? ""),
                name: String(grp.name ?? ""),
                members: [],
                description: typeof grp.description === "string"
                  ? grp.description
                  : undefined,
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    mailing_list_list: {
      description:
        "List mailing lists and their recipients (factory: one `mailing-list` " +
        "each). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing mailing lists");
        const rows = await listAll(g, JMAP_TYPES.mailingList, accountId, [
          "id",
          "name",
          "description",
          "recipients",
        ]);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const ml of rows) {
          handles.push(
            await context.writeResource(
              "mailing-list",
              String(ml.name ?? ml.id),
              {
                id: String(ml.id ?? ""),
                name: String(ml.name ?? ""),
                description: typeof ml.description === "string"
                  ? ml.description
                  : undefined,
                recipients: mapKeys(ml.recipients),
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    queue_list: {
      description:
        "List queued outbound messages (factory: one `queue-item` each). " +
        "Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing mail queue");
        // Field names vary; fetch the default projection and map defensively.
        const rows = await listAll(g, JMAP_TYPES.queuedMessage, accountId);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const q of rows) {
          const to = Array.isArray(q.recipients)
            ? (q.recipients as unknown[]).map(String)
            : Array.isArray(q.to)
            ? (q.to as unknown[]).map(String)
            : [];
          handles.push(
            await context.writeResource("queue-item", String(q.id), {
              id: String(q.id ?? ""),
              from: typeof q.sender === "string"
                ? q.sender
                : typeof q.from === "string"
                ? q.from
                : undefined,
              to,
              status: typeof q.status === "string" ? q.status : undefined,
              action: "observed",
              timestamp: ts,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },
    report_query: {
      description:
        "List received DMARC/TLS aggregate reports (factory: one `report` each). " +
        "Read-only. The raw report fields are captured in `summary`.",
      arguments: ReportQueryArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ReportQueryArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Querying reports", { kind: a.kind });
        const sources: Array<{ kind: string; type: string }> = [];
        if (a.kind === "dmarc" || a.kind === "all") {
          sources.push({ kind: "dmarc", type: JMAP_TYPES.dmarcReport });
        }
        if (a.kind === "tls" || a.kind === "all") {
          sources.push({ kind: "tls", type: JMAP_TYPES.tlsReport });
        }
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const src of sources) {
          const rows = await listAll(g, src.type, accountId);
          for (const r of rows) {
            const summary = { ...r };
            delete summary.id;
            handles.push(
              await context.writeResource("report", `${src.kind}:${r.id}`, {
                id: String(r.id ?? ""),
                kind: src.kind,
                domain: typeof r.domain === "string" ? r.domain : undefined,
                summary: JSON.stringify(summary).slice(0, 2000),
                action: "observed",
                timestamp: ts,
              }),
            );
          }
        }
        return { dataHandles: handles };
      },
    },
    // ───────────── provisioning (idempotent) ─────────────
    role_ensure: {
      description:
        "Create or converge a role (idempotent by name). Pass a `preset` " +
        "(swamp-admin | automated-mailbox) or an explicit name + permissions. " +
        "Never destroys; only adds/updates the enabled-permission set.",
      arguments: RoleEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleEnsureArgs.parse(rawArgs);
        const preset = a.preset ? ROLE_PRESETS[a.preset] : undefined;
        const description = a.name ?? preset?.description;
        const enabled = a.permissions ?? preset?.enabled;
        if (!description || !enabled) {
          throw new Error(
            "role_ensure needs a `preset`, or both `name` and `permissions`",
          );
        }
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Ensuring role", { description });
        // Verify-before-mutate: find an existing role by description.
        const rows = await listAll(g, JMAP_TYPES.role, accountId, [
          "id",
          "description",
          "enabledPermissions",
        ]);
        const existing = rows.find((r) =>
          String(r.description) === description
        );
        const desired = [...new Set(enabled)].sort();
        const permMap: Json = {};
        for (const p of desired) permMap[p] = true;

        let id: string;
        let action: "created" | "updated" | "unchanged";
        if (!existing) {
          const res = await jmapSet(g, JMAP_TYPES.role, {
            accountId,
            create: {
              "new": {
                description,
                enabledPermissions: permMap,
                disabledPermissions: {},
                roleIds: {},
              },
            },
          });
          const err = setItemError(res, "new");
          if (err) {
            throw new Error(`Could not create role ${description}: ${err}`);
          }
          const created = ((res.created ?? {}) as Json)["new"] as Json;
          id = String(created?.id ?? "");
          action = "created";
        } else {
          id = String(existing.id);
          const current = mapKeys(existing.enabledPermissions).sort();
          if (JSON.stringify(current) === JSON.stringify(desired)) {
            action = "unchanged";
          } else {
            const res = await jmapSet(g, JMAP_TYPES.role, {
              accountId,
              update: { [id]: { enabledPermissions: permMap } },
            });
            const err = setItemError(res, id);
            if (err) {
              throw new Error(`Could not update role ${description}: ${err}`);
            }
            action = "updated";
          }
        }
        const handle = await context.writeResource("role", description, {
          id,
          description,
          enabledPermissions: desired,
          disabledPermissions: [],
          nestedRoleIds: [],
          action,
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    role_assign: {
      description:
        "Assign a role to an account (idempotent, reversible). `role` is " +
        "`admin`, `user`, or a custom role name. Re-run with the prior role to " +
        "revert. Verifies the account and role exist first.",
      arguments: RoleAssignArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleAssignArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        const want = a.account.toLowerCase();
        logInfo(context, "Assigning role", {
          account: a.account,
          role: a.role,
        });
        // Verify-before-mutate: resolve the target account.
        const accounts = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "roles",
        ]);
        const acct = accounts.find((x) =>
          String(x.name).toLowerCase() === want ||
          String(x.emailAddress).toLowerCase() === want
        );
        if (!acct) throw new Error(`Account not found: ${a.account}`);

        // Build the desired roles union (verifies a custom role exists).
        const { union: desired, label } = await buildRolesUnion(
          g,
          accountId,
          a.role,
        );

        // Idempotency: compare against the current roles union.
        const current = (acct.roles ?? {}) as Json;
        const same = current["@type"] === desired["@type"] &&
          (desired["@type"] !== "Custom" ||
            JSON.stringify(mapKeys(current.roleIds).sort()) ===
              JSON.stringify(mapKeys(desired.roleIds).sort()));
        let action: "updated" | "unchanged" = "unchanged";
        if (!same) {
          const res = await jmapSet(g, JMAP_TYPES.account, {
            accountId,
            update: { [String(acct.id)]: { roles: desired } },
          });
          const err = setItemError(res, String(acct.id));
          if (err) {
            throw new Error(`Could not assign role to ${a.account}: ${err}`);
          }
          action = "updated";
        }
        const handle = await context.writeResource(
          "state-result",
          `role:${want}`,
          {
            kind: "account-role",
            id: String(acct.emailAddress ?? acct.name ?? acct.id),
            state: label,
            action,
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    account_ensure: {
      description:
        "Create or converge an individual mailbox (idempotent by address). " +
        "Resolves the domain, converges aliases + role + description; an optional " +
        "password is set ONCE on create (hashed by Stalwart, never read back). " +
        "Never deletes; removing an alias = omit it from `aliases`.",
      arguments: AccountEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AccountEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        const { local, domain } = parseAddress(a.email);
        logInfo(context, "Ensuring account", { email: a.email });

        // Resolve every domain referenced (account + each alias) up front.
        const domains = await domainIdMap(g, accountId);
        const domainId = domains.get(domain);
        if (!domainId) throw new Error(`Domain not found: ${domain}`);
        // Aliases are converged ONLY when explicitly provided. Omitting the arg
        // leaves existing aliases untouched (passing [] clears them).
        const desiredAliases: Json = {};
        if (a.aliases) {
          a.aliases.forEach((addr, i) => {
            const p = parseAddress(addr);
            const aDomId = domains.get(p.domain);
            if (!aDomId) throw new Error(`Alias domain not found: ${p.domain}`);
            desiredAliases[String(i)] = {
              name: p.local,
              domainId: aDomId,
              enabled: true,
            };
          });
        }
        const aliasKey = (o: Json) => `${String(o.name)}@${String(o.domainId)}`;
        const desiredAliasKeys = Object.values(desiredAliases)
          .map((o) => aliasKey(o as Json)).sort();

        // Verify-before-mutate: find an existing account by full address.
        const accounts = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "domainId",
          "aliases",
          "roles",
          "description",
        ]);
        const want = a.email.toLowerCase();
        const existing = accounts.find((x) =>
          String(x.emailAddress).toLowerCase() === want ||
          (String(x.name).toLowerCase() === local.toLowerCase() &&
            String(x.domainId) === domainId)
        );

        let id: string;
        let action: "created" | "updated" | "unchanged";
        if (!existing) {
          const create: Json = {
            "@type": "User",
            name: local,
            domainId,
            roles:
              (await buildRolesUnion(g, accountId, a.role ?? "user")).union,
          };
          if (a.aliases) create.aliases = desiredAliases;
          if (a.description) create.description = a.description;
          if (a.password) {
            create.credentials = {
              "0": { "@type": "Password", secret: a.password },
            };
          }
          const res = await jmapSet(g, JMAP_TYPES.account, {
            accountId,
            create: { "new": create },
          });
          const err = setItemError(res, "new");
          if (err) {
            throw new Error(`Could not create account ${a.email}: ${err}`);
          }
          id = String(
            ((res.created ?? {}) as Json)["new"]
              ? (((res.created as Json)["new"]) as Json).id ?? ""
              : "",
          );
          action = "created";
        } else {
          id = String(existing.id);
          // Converge description + aliases (+ role if given).
          const patch: Json = {};
          if (a.aliases) {
            const curAliasKeys = Object.values(
              (existing.aliases ?? {}) as Json,
            ).map((o) => aliasKey(o as Json)).sort();
            if (
              JSON.stringify(curAliasKeys) !== JSON.stringify(desiredAliasKeys)
            ) {
              patch.aliases = desiredAliases;
            }
          }
          if (
            a.description !== undefined &&
            a.description !== existing.description
          ) {
            patch.description = a.description;
          }
          if (a.role) {
            const { union } = await buildRolesUnion(g, accountId, a.role);
            const cur = (existing.roles ?? {}) as Json;
            const same = cur["@type"] === union["@type"] &&
              (union["@type"] !== "Custom" ||
                JSON.stringify(mapKeys(cur.roleIds).sort()) ===
                  JSON.stringify(mapKeys(union.roleIds).sort()));
            if (!same) patch.roles = union;
          }
          if (Object.keys(patch).length === 0) {
            action = "unchanged";
          } else {
            const res = await jmapSet(g, JMAP_TYPES.account, {
              accountId,
              update: { [id]: patch },
            });
            const err = setItemError(res, id);
            if (err) {
              throw new Error(`Could not update account ${a.email}: ${err}`);
            }
            action = "updated";
          }
        }
        const handle = await context.writeResource("account", a.email, {
          id,
          name: local,
          email: a.email,
          domainId,
          type: "individual",
          aliases: a.aliases ?? [],
          roles: a.role ? a.role.toLowerCase() : undefined,
          description: a.description,
          action,
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    mailing_list_ensure: {
      description:
        "Create or converge a mailing list (idempotent by address). Resolves the " +
        "domain; converges recipients (when provided) + description. Never deletes.",
      arguments: MailingListEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MailingListEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        const { local, domain } = parseAddress(a.address);
        const domains = await domainIdMap(g, accountId);
        const domainId = domains.get(domain);
        if (!domainId) throw new Error(`Domain not found: ${domain}`);
        logInfo(context, "Ensuring mailing list", { address: a.address });
        // recipients is a set-semantics Map<String>: {"a@x.test":true, …}.
        const recipientsMap: Json = {};
        for (const r of a.recipients ?? []) recipientsMap[r] = true;

        const rows = await listAll(g, JMAP_TYPES.mailingList, accountId, [
          "id",
          "name",
          "domainId",
          "recipients",
          "description",
        ]);
        const existing = rows.find((x) =>
          String(x.name).toLowerCase() === local.toLowerCase() &&
          String(x.domainId) === domainId
        );
        let id: string;
        let action: "created" | "updated" | "unchanged";
        if (!existing) {
          const create: Json = { name: local, domainId };
          if (a.recipients) create.recipients = recipientsMap;
          if (a.description) create.description = a.description;
          const res = await jmapSet(g, JMAP_TYPES.mailingList, {
            accountId,
            create: { "new": create },
          });
          const err = setItemError(res, "new");
          if (err) {
            throw new Error(`Could not create list ${a.address}: ${err}`);
          }
          id = String((((res.created ?? {}) as Json)["new"] as Json)?.id ?? "");
          action = "created";
        } else {
          id = String(existing.id);
          const patch: Json = {};
          if (
            a.recipients &&
            JSON.stringify(mapKeys(existing.recipients).sort()) !==
              JSON.stringify([...a.recipients].sort())
          ) patch.recipients = recipientsMap;
          if (
            a.description !== undefined &&
            a.description !== existing.description
          ) patch.description = a.description;
          if (Object.keys(patch).length === 0) {
            action = "unchanged";
          } else {
            const res = await jmapSet(g, JMAP_TYPES.mailingList, {
              accountId,
              update: { [id]: patch },
            });
            const err = setItemError(res, id);
            if (err) {
              throw new Error(`Could not update list ${a.address}: ${err}`);
            }
            action = "updated";
          }
        }
        const handle = await context.writeResource("mailing-list", local, {
          id,
          name: local,
          description: a.description,
          recipients: a.recipients ?? [],
          action,
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    group_ensure: {
      description:
        "Create or converge a group account (idempotent by address). Membership " +
        "is set per-user (memberGroupIds), not here. Never deletes.",
      arguments: GroupEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GroupEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        const { local, domain } = parseAddress(a.address);
        const domains = await domainIdMap(g, accountId);
        const domainId = domains.get(domain);
        if (!domainId) throw new Error(`Domain not found: ${domain}`);
        logInfo(context, "Ensuring group", { address: a.address });
        const rows = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "domainId",
          "@type",
          "description",
        ]);
        const existing = rows.find((x) =>
          x["@type"] === "Group" &&
          String(x.name).toLowerCase() === local.toLowerCase() &&
          String(x.domainId) === domainId
        );
        let id: string;
        let action: "created" | "updated" | "unchanged";
        if (!existing) {
          const create: Json = {
            "@type": "Group",
            name: local,
            domainId,
            roles: { "@type": "Default" },
          };
          if (a.description) create.description = a.description;
          const res = await jmapSet(g, JMAP_TYPES.account, {
            accountId,
            create: { "new": create },
          });
          const err = setItemError(res, "new");
          if (err) {
            throw new Error(`Could not create group ${a.address}: ${err}`);
          }
          id = String((((res.created ?? {}) as Json)["new"] as Json)?.id ?? "");
          action = "created";
        } else {
          id = String(existing.id);
          if (
            a.description !== undefined &&
            a.description !== existing.description
          ) {
            const res = await jmapSet(g, JMAP_TYPES.account, {
              accountId,
              update: { [id]: { description: a.description } },
            });
            const err = setItemError(res, id);
            if (err) {
              throw new Error(`Could not update group ${a.address}: ${err}`);
            }
            action = "updated";
          } else {
            action = "unchanged";
          }
        }
        const handle = await context.writeResource("group", local, {
          id,
          name: local,
          members: [],
          description: a.description,
          action,
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    // ───────────── reversible state ─────────────
    domain_set_state: {
      description:
        "Enable or disable a domain (reversible, via `isEnabled`). " +
        "Verify-before-mutate; idempotent.",
      arguments: DomainSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = DomainSetStateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Setting domain state", {
          domain: a.domain,
          state: a.state,
        });
        const rows = await listAll(g, JMAP_TYPES.domain, accountId, [
          "id",
          "name",
          "isEnabled",
        ]);
        const dom = rows.find((d) => String(d.name) === a.domain);
        if (!dom) throw new Error(`Domain not found: ${a.domain}`);
        const want = a.state === "active";
        let action: "reactivated" | "deactivated" | "unchanged";
        if (dom.isEnabled === want) {
          action = "unchanged";
        } else {
          const res = await jmapSet(g, JMAP_TYPES.domain, {
            accountId,
            update: { [String(dom.id)]: { isEnabled: want } },
          });
          const err = setItemError(res, String(dom.id));
          if (err) throw new Error(`Could not set domain state: ${err}`);
          action = want ? "reactivated" : "deactivated";
        }
        const handle = await context.writeResource(
          "state-result",
          `domain:${a.domain}`,
          {
            kind: "domain",
            id: a.domain,
            state: a.state,
            action,
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    account_set_state: {
      description:
        "Disable or re-enable an account WITHOUT deleting it. Disable replaces " +
        "the account's permissions with an empty set (it can no longer " +
        "authenticate); re-enable restores `Inherit` (role-based). Reversible, " +
        "idempotent, verify-before-mutate. Mailbox + aliases are untouched.",
      arguments: AccountSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AccountSetStateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        const want = a.account.toLowerCase();
        logInfo(context, "Setting account state", {
          account: a.account,
          state: a.state,
        });
        const accounts = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "permissions",
        ]);
        const acct = accounts.find((x) =>
          String(x.name).toLowerCase() === want ||
          String(x.emailAddress).toLowerCase() === want
        );
        if (!acct) throw new Error(`Account not found: ${a.account}`);
        const cur = (acct.permissions ?? {}) as Json;
        const isDisabled = cur["@type"] === "Replace" &&
          mapKeys(cur.enabledPermissions).length === 0;
        const wantDisable = a.state === "inactive";
        let action: "deactivated" | "reactivated" | "unchanged";
        if (wantDisable === isDisabled) {
          action = "unchanged";
        } else {
          const desired: Json = wantDisable
            ? {
              "@type": "Replace",
              enabledPermissions: {},
              disabledPermissions: {},
            }
            : { "@type": "Inherit" };
          const res = await jmapSet(g, JMAP_TYPES.account, {
            accountId,
            update: { [String(acct.id)]: { permissions: desired } },
          });
          const err = setItemError(res, String(acct.id));
          if (err) throw new Error(`Could not set account state: ${err}`);
          action = wantDisable ? "deactivated" : "reactivated";
        }
        const handle = await context.writeResource(
          "state-result",
          `account:${want}`,
          {
            kind: "account",
            id: String(acct.emailAddress ?? acct.name ?? acct.id),
            state: a.state,
            action,
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    // ───────────── settings + maintenance actions ─────────────
    settings_get: {
      description:
        "Read a server settings singleton (http, system, spam-classifier, …). " +
        "Read-only.",
      arguments: SettingsGetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = SettingsGetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        const type = SETTINGS_TYPES[a.kind];
        logInfo(context, "Reading settings", { kind: a.kind });
        const list = await jmapGet(g, type, { accountId, ids: [SINGLETON_ID] });
        const obj = (list[0] ?? {}) as Json;
        const settings = { ...obj };
        delete settings.id;
        const handle = await context.writeResource("settings", a.kind, {
          kind: a.kind,
          id: SINGLETON_ID,
          settings,
          action: "observed",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    settings_set: {
      description:
        "Merge `patch` into a settings singleton (idempotent), then reload so it " +
        "takes effect. Verify-before-mutate; only fields you pass are changed.",
      arguments: SettingsSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = SettingsSetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        const type = SETTINGS_TYPES[a.kind];
        logInfo(context, "Updating settings", {
          kind: a.kind,
          fields: Object.keys(a.patch),
        });
        // Verify-before-mutate: read the singleton and diff the patch.
        const list = await jmapGet(g, type, { accountId, ids: [SINGLETON_ID] });
        const obj = list[0] as Json | undefined;
        if (!obj) {
          throw new Error(`Could not read the ${a.kind} settings singleton`);
        }
        const changed = Object.entries(a.patch).some(([k, v]) =>
          JSON.stringify(obj[k]) !== JSON.stringify(v)
        );
        let action: "updated" | "unchanged" = "unchanged";
        if (changed) {
          const res = await jmapSet(g, type, {
            accountId,
            update: { [SINGLETON_ID]: a.patch },
          });
          const err = setItemError(res, SINGLETON_ID);
          if (err) {
            throw new Error(`Could not update ${a.kind} settings: ${err}`);
          }
          action = "updated";
          if (a.reload) await runAction(g, accountId, "ReloadSettings");
        }
        const merged = { ...obj, ...a.patch };
        delete merged.id;
        const handle = await context.writeResource("settings", a.kind, {
          kind: a.kind,
          id: SINGLETON_ID,
          settings: merged,
          action,
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    reload: {
      description:
        "Reload server settings (applies registry changes without a restart).",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Reloading settings");
        await runAction(g, accountId, "ReloadSettings");
        const handle = await context.writeResource("state-result", "reload", {
          kind: "server",
          id: "settings",
          state: "reloaded",
          action: "reloaded",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    certificate_install: {
      description:
        "Install a TLS certificate (PEM cert + key) and reload certificates. " +
        "Updates the sole existing cert in place (or one named by `certificateId`), " +
        "else creates a new one. Issuance stays with your ACME tooling — this is " +
        "the install + reload path. The private key is sent once, never read back.",
      arguments: CertificateInstallArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = CertificateInstallArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Installing certificate");
        // certificate is a PublicText union, privateKey a SecretText union —
        // both inline as `{"@type":"Text", …}` (cert uses `value`, key `secret`).
        const payload: Json = {
          certificate: { "@type": "Text", value: a.certificate },
          privateKey: { "@type": "Text", secret: a.privateKey },
        };
        let id = a.certificateId ?? "";
        let action: "created" | "updated";
        if (!id) {
          const existing = await listAll(g, JMAP_TYPES.certificate, accountId, [
            "id",
          ]);
          if (existing.length > 1) {
            throw new Error(
              `${existing.length} certificates exist — pass certificateId to pick one`,
            );
          }
          id = existing.length === 1 ? String(existing[0].id) : "";
        }
        if (id) {
          const res = await jmapSet(g, JMAP_TYPES.certificate, {
            accountId,
            update: { [id]: payload },
          });
          const err = setItemError(res, id);
          if (err) throw new Error(`Could not update certificate: ${err}`);
          action = "updated";
        } else {
          const res = await jmapSet(g, JMAP_TYPES.certificate, {
            accountId,
            create: { "new": payload },
          });
          const err = setItemError(res, "new");
          if (err) throw new Error(`Could not install certificate: ${err}`);
          id = String((((res.created ?? {}) as Json)["new"] as Json)?.id ?? "");
          action = "created";
        }
        if (a.reload) await runAction(g, accountId, "ReloadTlsCertificates");
        // Best-effort enrichment: read back the parsed SANs / validity.
        let subject: string | undefined;
        let sans: string[] | undefined;
        let notAfter: string | undefined;
        try {
          const got = await jmapGet(g, JMAP_TYPES.certificate, {
            accountId,
            ids: [id],
            properties: [
              "id",
              "issuer",
              "subjectAlternativeNames",
              "notValidAfter",
            ],
          });
          const c = (got[0] ?? {}) as Json;
          subject = typeof c.issuer === "string" ? c.issuer : undefined;
          sans = mapKeys(c.subjectAlternativeNames);
          notAfter = typeof c.notValidAfter === "string"
            ? c.notValidAfter
            : undefined;
        } catch { /* enrichment is optional */ }
        const handle = await context.writeResource("certificate", id, {
          id,
          subject,
          sans,
          notAfter,
          action,
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    reload_certificates: {
      description: "Reload TLS certificates from the store (no restart).",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Reloading TLS certificates");
        await runAction(g, accountId, "ReloadTlsCertificates");
        const handle = await context.writeResource(
          "state-result",
          "reload-certificates",
          {
            kind: "certificates",
            id: "tls",
            state: "reloaded",
            action: "reloaded",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    // ───────────── read / health (REST) ─────────────
    health_status: {
      description:
        "Server health: edition/version/permissions (GET /api/account) plus " +
        "curated gauges (GET /metrics/prometheus). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Reading Stalwart health");
        const acct = await rest(g, { method: "GET", path: "/api/account" });
        let metrics: Record<string, number> = {};
        try {
          const m = await rest(g, {
            method: "GET",
            path: "/metrics/prometheus",
            accept: "text/plain",
          });
          metrics = parsePrometheus(m.text ?? "");
        } catch (e) {
          // Metrics may be gated (edition/permission); health is still useful.
          logInfo(context, "Prometheus metrics unavailable", {
            error: (e as Error).message,
          });
        }
        const edition = typeof acct.body.edition === "string"
          ? acct.body.edition
          : undefined;
        const version = typeof acct.body.version === "string"
          ? acct.body.version
          : undefined;
        const permissions = Array.isArray(acct.body.permissions)
          ? (acct.body.permissions as unknown[]).map(String)
          : undefined;
        const handle = await context.writeResource("health", "current", {
          reachable: true,
          edition,
          version,
          permissions,
          metrics,
          action: "observed",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    // ───────────── Phase 0 discovery (read-only JMAP probe) ─────────────
    session_dump: {
      description:
        "Fetch the JMAP session resource (/.well-known/jmap) and record the " +
        "advertised capabilities + accounts. Read-only; used to pin the " +
        "management capability URI before the Phase 1 methods are built.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Fetching JMAP session");
        const r = await rest(g, { method: "GET", path: "/.well-known/jmap" });
        const caps = (r.body.capabilities ?? {}) as Json;
        const accounts = (r.body.accounts ?? {}) as Json;
        const primary = (r.body.primaryAccounts ?? {}) as Record<
          string,
          string
        >;
        const handle = await context.writeResource("session", "current", {
          capabilities: Object.keys(caps),
          accounts: Object.keys(accounts),
          primaryAccounts: primary,
          raw: r.text ?? JSON.stringify(r.body),
          action: "observed",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    jmap_probe: {
      description:
        "Discovery probe: run `<type>/query` then `<type>/get` for one type and " +
        "capture the wire shape (ids + a sample object). Read-only; used to pin " +
        "the JMAP_TYPES constants before the Phase 1 methods are built.",
      arguments: JmapProbeArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = JmapProbeArgs.parse(rawArgs);
        const g = context.globalArgs;
        const accountId = await resolveAccountId(g);
        logInfo(context, "Probing JMAP type", { type: a.type, accountId });
        const ids = await jmapQuery(g, a.type, { accountId, limit: a.limit });
        let sample: string | undefined;
        if (ids.length) {
          const objs = await jmapGet(g, a.type, {
            accountId,
            ids: ids.slice(0, 1),
          });
          if (objs[0]) sample = JSON.stringify(objs[0]);
        }
        const handle = await context.writeResource("probe", a.type, {
          type: a.type,
          capability: USING.mgmt,
          accountId,
          count: ids.length,
          ids,
          sample,
          action: "observed",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    // ───────────── JMAP-backed methods land here AFTER the Phase 0 spike ─────────────
    // domain_list, account_list, alias_list, group_list, report_query, queue_list,
    // reload, reload_certificates, account_ensure, account_set_state (Phase 1);
    // group_ensure, group_set_state, mailing_list_ensure, role_assign,
    // spam_config_ensure, spam_train (gap-gated), certificate_install (Phase 2).
    // They use jmapGet/jmapQuery/jmapSet + resolveAccountId with the pinned
    // USING/JMAP_TYPES constants. None passes `destroy`.
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
