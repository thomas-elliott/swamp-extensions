import { z } from "npm:zod@4";
// Type-only imports, erased at compile time and never bundled. They type the
// `satisfies ModelDefinition<typeof GlobalArgs>` clause so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";
// The transport uses only the Web `fetch`/`AbortController` globals and no
// `node:` import, so the extension has no dependencies and does not resolve a
// floating `@types/node` at doc-lint time.

/**
 * `@thomas/stalwart`: non-destructive administration of a Stalwart mail server
 * (0.16 and v1) over its JMAP-over-HTTP
 * management API.
 *
 * Scope: this holds a mail-admin credential, so the methods are limited and
 * non-destructive. None deletes an account, domain, group or list, and no
 * method sends the JMAP `destroy` verb. Domains and accounts are disabled with
 * the `*_set_state` methods instead. Some changes cannot be undone from here:
 * `certificate_install` replaces the stored certificate and key, `settings_set`
 * overwrites values, `role_ensure` removes permissions it is not given, and
 * re-enabling an account drops its own permission list. Every secret it
 * accepts (an account password, a certificate private key) is sent to Stalwart
 * once and is never read back into a resource or logged.
 *
 * Transport: Stalwart 0.16 removed the legacy REST `/api/*` management tree;
 * management is now JMAP (RFC 8620) at `POST {apiUrl}/jmap`: a
 * `{ using, methodCalls }` envelope carrying `Foo/get` / `Foo/query` /
 * `Foo/set` {create,update,destroy}. A few `/api/*` endpoints remain for
 * introspection (`/api/account`, `/api/schema`) and metrics
 * (`/metrics/prometheus`); those use the separate REST seam.
 *
 * Auth: a scoped admin API key, sent as `Authorization: Bearer <key>` on every
 * request. No long-lived token is exchanged or stored.
 *
 * Object model (confirmed live against 0.16 and v1): individuals use the RFC-standard
 * `Principal/*`; every registry/management object is served under
 * `urn:stalwart:jmap` with an `x:` prefix (`x:Account`, `x:Domain`, `x:Role`,
 * `x:Http`, …); settings singletons are `/get` by the fixed id `singleton`; and
 * server actions (reloads) are run by *creating* an `x:Action` with an
 * `@type`. The pinned names live in {@link JMAP_TYPES}.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  apiUrl: z.string().describe(
    "Stalwart base URL, e.g. https://mail.example.com (no trailing /jmap). " +
      "A plain http URL works but logs a warning: the API key is sent unencrypted.",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "Scoped admin API key, sent as a Bearer token. Supply via vault: " +
      "${{ vault.get(<vault>, stalwart/api_key) }}",
  ),
  accountId: z.string().optional().describe(
    "JMAP management accountId. Omit to resolve the session's primary account.",
  ),
  httpTimeoutMs: z.coerce.number().int().positive().default(30000).describe(
    "Per-request timeout (ms) for JMAP and REST calls, covering the whole response",
  ),
});

// Resolved global-argument shape. Not exported: `z.infer` is a "slow type", so
// it must not appear on the public API (the exported seam types use the loose
// {@link Json} instead).
type GlobalArgsT = z.infer<typeof GlobalArgs>;

/** The set of outcomes a method reports in its `action` field. */
const Action = z.enum([
  "created",
  "unchanged",
  "updated",
  "deactivated",
  "reactivated",
  "reloaded",
  "observed",
]);

// ─────────────────────────── resource schemas ───────────────────────────

const DomainInfo = z.object({
  id: z.string(),
  name: z.string(),
  state: z.string().describe("active | inactive | unknown"),
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
  memberOf: z.array(z.string()).optional().describe(
    "Group account ids this account is a member of (shared-folder access)",
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

// Membership is tracked on each member's account, not on the group, so there is
// no `members` field here.
const GroupInfo = z.object({
  id: z.string(),
  name: z.string(),
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
  domain: z.string().optional().describe("The policy domain the report covers"),
  rangeStart: z.string().optional().describe("Start of the reported period"),
  rangeEnd: z.string().optional().describe("End of the reported period"),
  summary: z.string().optional().describe(
    "The report's fields as JSON, cut to 2000 characters",
  ),
  summaryTruncated: z.boolean().optional().describe(
    "True when summary was cut short; a cut summary is not valid JSON",
  ),
  action: Action,
  timestamp: z.string(),
});

const QueueItemInfo = z.object({
  id: z.string(),
  from: z.string().optional(),
  to: z.array(z.string()),
  nextRetry: z.string().optional(),
  size: z.number().optional(),
  action: Action,
  timestamp: z.string(),
});

const HealthInfo = z.object({
  reachable: z.boolean(),
  edition: z.string().optional().describe("oss | community | enterprise"),
  permissions: z.array(z.string()).optional(),
  metrics: z.record(z.string(), z.number()).describe(
    "Every metric in /metrics/prometheus, by name (label sets collapsed, " +
      "last sample wins)",
  ),
  action: Action,
  timestamp: z.string(),
});

const CertificateInfo = z.object({
  id: z.string(),
  issuer: z.string().optional(),
  sans: z.array(z.string()).optional(),
  notBefore: z.string().optional(),
  notAfter: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

// Spam classifier/rule configuration is future work (no writer yet), so no
// dedicated resource spec is published for it.

const SettingsInfo = z.object({
  kind: z.string().describe("Which settings singleton (http, system, …)"),
  id: z.string(),
  settings: z.record(z.string(), z.unknown()).describe(
    "The singleton's current fields. A secret's value is replaced by \"<redacted>\".",
  ),
  action: Action,
  timestamp: z.string(),
});

const StateResult = z.object({
  kind: z.string().describe(
    "account | account-role | domain | server | certificates",
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
  // masks it and never logs it, even though it is stored to record the shape.
  sample: z.string().meta({ sensitive: true }).optional().describe(
    "JSON of the first object's fields — for pinning the wire shape",
  ),
  action: Action,
  timestamp: z.string(),
});

// ─────────────────────────── JMAP type constants ───────────────────────────

/**
 * JMAP capability URIs sent in the `using` array of every envelope. `core` and
 * `principals` are RFC-standard; `mgmt` (`urn:stalwart:jmap`) is the Stalwart
 * capability that serves every registry/management object. Confirmed against a
 * live 0.16 and v1 session resource.
 */
export const USING = {
  core: "urn:ietf:params:jmap:core",
  principals: "urn:ietf:params:jmap:principals",
  mgmt: "urn:stalwart:jmap",
} as const;

/**
 * Wire type names for the Stalwart JMAP objects this extension uses, confirmed
 * against live 0.16 and v1 servers. Every registry/management object is served under
 * `urn:stalwart:jmap` with an `x:` prefix. Settings singletons are listed in
 * `SETTINGS_TYPES`. Actions (reloads) are run by *creating* an `x:Action` with
 * an `@type` discriminator.
 */
export const JMAP_TYPES = {
  account: "x:Account",
  domain: "x:Domain",
  mailingList: "x:MailingList",
  role: "x:Role",
  certificate: "x:Certificate",
  queuedMessage: "x:QueuedMessage",
  // The External types are the reports other servers sent us; the Internal
  // ones are the reports Stalwart itself generates and sends out.
  dmarcReport: "x:DmarcExternalReport",
  tlsReport: "x:TlsExternalReport",
  action: "x:Action",
} as const;

// ─────────────────────────── HTTP seams ───────────────────────────

/** A loose JSON object: the resolved global args or an API body. */
export type Json = Record<string, unknown>;

/** A JMAP request envelope: the capabilities in use and the method calls to run. */
export interface JmapCall {
  /** Capability URIs (RFC 8620 `using`). */
  using: string[];
  /** Method-call tuples: `[name, arguments, callId]`. */
  methodCalls: unknown[][];
}

/** The parsed result of a {@link JmapCall}: the raw JMAP response body. */
export interface JmapResult {
  /** HTTP status code. */
  status: number;
  /** Parsed response body (`{ methodResponses, sessionState, ... }`). */
  body: Json;
}

/**
 * The JMAP-call seam the methods use; unit tests can replace it. The global args
 * are typed loosely as {@link Json} so this exported type passes "fast-check"
 * (the zod-inferred globals are a slow type). The real implementation re-narrows.
 */
export type JmapFn = (g: Json, call: JmapCall) => Promise<JmapResult>;

/** A REST request: a GET/POST against an `/api/*` or `/metrics/*` path. */
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

/** The REST seam; unit tests can replace it. */
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
  // The cached accountId came from the previous transport; a different
  // transport (a different fake server) must not reuse it.
  _accountIdCache.clear();
}

function baseUrl(g: GlobalArgsT): string {
  return g.apiUrl.replace(/\/+$/, "");
}

/**
 * Fetch `url` and read the whole body as text, all within `timeoutMs`. The
 * timer runs until the body is read, not just the headers, so a server or proxy
 * that stalls mid-body cannot hang the method.
 */
async function fetchText(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<{ res: Response; text: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    return { res, text: await res.text() };
  } finally {
    clearTimeout(t);
  }
}

/** The real fetch-backed JMAP implementation behind {@link jmap}. */
async function realJmap(g: GlobalArgsT, c: JmapCall): Promise<JmapResult> {
  const { res, text } = await fetchText(
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
  const { res, text } = await fetchText(
    `${baseUrl(g)}${c.path}`,
    { method: c.method, headers, body },
    g.httpTimeoutMs,
  );
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
 * Return the arguments object of method-call `index` in a JMAP response,
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

/**
 * Cache key for the resolved accountId. The session's primary account depends on
 * the credential, so two credentials against one URL must not share an entry.
 * The key carries a digest of the token rather than the token, so the map never
 * holds the secret in clear.
 */
async function accountIdCacheKey(g: GlobalArgsT): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(g.apiKey),
  );
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${g.apiUrl}#${hex}`;
}

/** Resolve the management `accountId` (explicit arg, else the session's primary). */
async function resolveAccountId(g: GlobalArgsT): Promise<string | undefined> {
  if (g.accountId) return g.accountId;
  const cacheKey = await accountIdCacheKey(g);
  const cached = _accountIdCache.get(cacheKey);
  if (cached !== undefined) return cached;
  // The session resource lists accounts under `.accounts` and names the primary
  // under `.primaryAccounts`. Field shapes confirmed against live 0.16 and v1 servers.
  const r = await rest(g, { method: "GET", path: "/.well-known/jmap" });
  const accounts = (r.body.accounts ?? {}) as Json;
  const primary = (r.body.primaryAccounts ?? {}) as Json;
  const id =
    (typeof primary[USING.mgmt] === "string"
      ? primary[USING.mgmt] as string
      : Object.keys(accounts)[0]) ?? undefined;
  _accountIdCache.set(cacheKey, id);
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
 * response. It takes no `destroy` block, so no code path can ask Stalwart to
 * delete an object.
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
 *
 * Returns the warnings the server reported. Stalwart v1 answers
 * `ReloadSettings` with `warnings`, a set of strings sent as a map
 * (`{ "<warning>": true }`); 0.16 sends none.
 */
async function runAction(
  g: GlobalArgsT,
  accountId: string | undefined,
  atType: string,
): Promise<string[]> {
  const res = await jmapSet(g, JMAP_TYPES.action, {
    accountId,
    create: { "c0": { "@type": atType } },
  });
  const err = setItemError(res, "c0");
  if (err) throw new Error(`Action ${atType} failed: ${err}`);
  const created = ((res.created ?? {}) as Json).c0 as Json | undefined;
  return mapKeys(created?.warnings);
}

/**
 * Inspect a set response for a per-item failure under `notCreated`/
 * `notUpdated` for `key`, and return its error message (or null if it succeeded).
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
 * Page size for {@link listAll}. Each page of ids is fetched with its own
 * `<type>/get`, so this must stay within the server's `maxObjectsInGet`;
 * RFC 8620 suggests servers allow at least 500, and Stalwart advertises 500.
 */
const LIST_PAGE_SIZE = 100;

/** The most query pages {@link listAll} reads (100,000 objects at 100 a page). */
const MAX_LIST_PAGES = 1000;

/**
 * List every object of `type`: page through `<type>/query` (`position`/`total`)
 * and run a `<type>/get` for each page's ids and the requested `properties`.
 * Returns the full `list[]`. Used by the read/`*_list` methods. Throws rather
 * than return part of the list if the pages do not run out.
 */
async function listAll(
  g: GlobalArgsT,
  type: string,
  accountId: string | undefined,
  properties?: string[],
): Promise<Json[]> {
  const list: Json[] = [];
  let seen = 0;
  for (let position = 0, page = 0; page < MAX_LIST_PAGES; page++) {
    const r = await jmap(g, {
      using: [USING.core, USING.mgmt],
      methodCalls: [[`${type}/query`, {
        accountId: accountId ?? null,
        limit: LIST_PAGE_SIZE,
        position,
        calculateTotal: true,
      }, "c0"]],
    });
    const args = methodResponseArgs(r.body);
    const ids = Array.isArray(args.ids) ? args.ids.map(String) : [];
    if (ids.length === 0) return list;
    // One /get per page: a single /get of every id fails once a server holds
    // more objects than its maxObjectsInGet.
    list.push(...await jmapGet(g, type, { accountId, ids, properties }));
    seen += ids.length;
    position += ids.length;
    const total = Number(args.total);
    if (Number.isFinite(total) && seen >= total) return list;
  }
  throw new Error(
    `${type}/query returned more than ${MAX_LIST_PAGES} pages; ` +
      "refusing to return a partial list",
  );
}

/** Keys of a Stalwart `Map<T>`/`List<T>` wire object (`{}` → `[]`). */
function mapKeys(v: unknown): string[] {
  return v && typeof v === "object" ? Object.keys(v as Json) : [];
}

/** A string field from a wire object, or undefined when it is not a string. */
function asOptString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/**
 * The name of a domain's on/off flag as this server spells it: `isEnabled` in
 * Stalwart 0.16, `enable` in v1. Read from the domain itself, so callers must
 * fetch domains with every property. Throws when neither is present, rather
 * than guess which name to write.
 */
function domainEnabledKey(d: Json): "enable" | "isEnabled" {
  if (typeof d.enable === "boolean") return "enable";
  if (typeof d.isEnabled === "boolean") return "isEnabled";
  throw new Error(
    `Domain ${d.name ?? d.id} has neither enable (v1) nor isEnabled (0.16)`,
  );
}

/**
 * A domain's state for `domain_list`: `unknown` when it has neither flag, so
 * one odd domain does not stop the listing. `domain_set_state` refuses such a
 * domain instead, through {@link domainEnabledKey}.
 */
function domainState(d: Json): "active" | "inactive" | "unknown" {
  const flag = d.enable ?? d.isEnabled;
  if (typeof flag !== "boolean") return "unknown";
  return flag ? "active" : "inactive";
}

/**
 * Whether an account's `permissions` union is the empty `Replace` that
 * `account_set_state` uses to disable it.
 */
function isDisabled(permissions: unknown): boolean {
  const p = (permissions ?? {}) as Json;
  return p["@type"] === "Replace" && mapKeys(p.enabledPermissions).length === 0;
}

/**
 * The id Stalwart gave the object created under `key` in a set response.
 * Throws when there is none, rather than record the object under an empty name.
 */
function createdId(setRes: Json, key: string, what: string): string {
  const created = ((setRes.created ?? {}) as Json)[key] as Json | undefined;
  const id = created?.id;
  if (id === undefined || id === null || id === "") {
    throw new Error(`Stalwart created ${what} but returned no id for it`);
  }
  return String(id);
}

/** What {@link redactSecrets} puts in place of a secret value. */
const REDACTED = "<redacted>";

/**
 * A copy of `v` with every secret value replaced by {@link REDACTED}. Stalwart
 * returns secrets inline as `{"@type":"Text"|"Value", "secret": …}` (its
 * SecretText and SecretKey types), so any object with a `secret` key is one.
 * Matching on the shape, not on field names, also covers secret fields a later
 * Stalwart adds to a settings singleton.
 */
function redactSecrets(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(redactSecrets);
  if (!v || typeof v !== "object") return v;
  const out: Json = {};
  for (const [k, x] of Object.entries(v as Json)) {
    out[k] = k === "secret" ? REDACTED : redactSecrets(x);
  }
  return out;
}

/** Whether `v` holds a secret: an object with a `secret` key, at any depth. */
function holdsSecret(v: unknown): boolean {
  if (Array.isArray(v)) return v.some(holdsSecret);
  if (!v || typeof v !== "object") return false;
  return Object.entries(v as Json).some(([k, x]) =>
    k === "secret" || holdsSecret(x)
  );
}

/**
 * The data instance name for a record: `<spec>:<key>`, or `<spec>` alone for a
 * one-per-model record. swamp keys stored data by model + name, not by spec, so
 * without the prefix two specs sharing a key would overwrite each other.
 * swamp rejects `/`, `\`, `..` and NUL in a name, so those are percent-encoded,
 * along with `%` itself so that no two keys can end up with the same name.
 */
function dataName(spec: string, key?: string): string {
  if (key === undefined) return spec;
  const safe = key
    .replaceAll("%", "%25")
    .replaceAll("/", "%2F")
    .replaceAll("\\", "%5C")
    .replaceAll("\0", "%00")
    // Encode each dot that is followed by another, so no `..` remains.
    .replace(/\.(?=\.)/g, "%2E");
  return `${spec}:${safe}`;
}

/**
 * The key for an account or group record: its address, lowercased because
 * Stalwart addresses are case-insensitive. Falls back to the server id.
 */
function accountKey(row: Json): string {
  return typeof row.emailAddress === "string" && row.emailAddress
    ? row.emailAddress.toLowerCase()
    : String(row.id);
}

/**
 * Full addresses out of an `aliases` List<EmailAlias> wire object. Stalwart
 * stores an alias as a local part (`name`) plus a `domainId`, so the domain
 * name has to be joined back on; `domainNames` maps domain id to name.
 */
function aliasAddresses(
  v: unknown,
  domainNames: Map<string, string>,
): string[] {
  if (!v || typeof v !== "object") return [];
  return Object.values(v as Record<string, Json>)
    .filter((a) => a && typeof a.name === "string" && a.name.length > 0)
    .map((a) => {
      const domainId = String(a.domainId ?? "");
      return `${a.name}@${domainNames.get(domainId) ?? domainId}`;
    });
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
  // Lowercased because Stalwart stores names lowercased: a name typed in
  // another case would never compare equal, so every run would rewrite it.
  const lower = addr.toLowerCase();
  return { local: lower.slice(0, at), domain: lower.slice(at + 1) };
}

/**
 * Find the one account `wanted` names, by full address or by bare local part.
 * A local part can belong to an account on each domain, so when it matches
 * more than one this throws rather than act on whichever came first.
 */
function findAccount(accounts: Json[], wanted: string): Json {
  const want = wanted.toLowerCase();
  const matches = accounts.filter((x) =>
    String(x.name).toLowerCase() === want ||
    String(x.emailAddress).toLowerCase() === want
  );
  if (matches.length === 0) throw new Error(`Account not found: ${wanted}`);
  if (matches.length > 1) {
    throw new Error(
      `${wanted} matches ${matches.length} accounts (${
        matches.map(accountKey).join(", ")
      }); pass the full address`,
    );
  }
  return matches[0];
}

/** Build a `name → id` map of all domains (for resolving account/alias domains). */
async function domainIdMap(
  g: GlobalArgsT,
  accountId: string | undefined,
): Promise<Map<string, string>> {
  const rows = await listAll(g, JMAP_TYPES.domain, accountId, ["id", "name"]);
  return new Map(
    rows.map((d) => [String(d.name).toLowerCase(), String(d.id)]),
  );
}

/** The inverse of {@link domainIdMap}: `id → name`, for rebuilding alias addresses. */
async function domainNameMap(
  g: GlobalArgsT,
  accountId: string | undefined,
): Promise<Map<string, string>> {
  const byName = await domainIdMap(g, accountId);
  return new Map([...byName].map(([name, id]) => [id, name]));
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
 * exported for tests.
 */
export function parsePrometheus(text: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const line of text.split("\n")) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    // `name{labels} value [timestamp]`: the metric name ends at `{` or a
    // space, and the exposition format allows an optional millisecond
    // timestamp after the value.
    const m = s.match(
      /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{[^}]*\})?\s+([-+0-9.eE]+|NaN|[-+]Inf)(?:\s+-?\d+)?\s*$/,
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
    "JMAP object type to probe, e.g. Principal, x:Domain, x:SpamClassifier",
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

/** The most characters of a report's JSON kept in `ReportInfo.summary`. */
const SUMMARY_MAX = 2000;

const ReportQueryArgs = z.object({
  kind: z.enum(["dmarc", "tls", "all"]).default("all").describe(
    "Which received aggregate reports to list",
  ),
});

/**
 * A string array that also accepts a JSON-encoded array or a comma-separated
 * string, so list-valued method arguments can be passed with the CLI's
 * `--input k=v`.
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
 * A JSON object argument that also accepts a JSON-encoded string, so an
 * object-valued method argument can be passed with the CLI's `--input k=v`.
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
  // Not marked sensitive: swamp would then mask every string, number and
  // field name in it wherever they appear, the settings record included.
  // Secrets come in only through webPushKey.
  patch: jsonObject.describe(
    'Top-level fields to set, e.g. {"usePermissiveCors":true}. Fields not ' +
      "named are kept. Stalwart replaces a list or map value whole. A patch " +
      'holding a secret (any {"secret": …} value) is refused: use webPushKey.',
  ),
  // The one secret field in the six settings singletons (0.16 and v1), so it
  // can be marked sensitive on its own.
  webPushKey: z.string().meta({ sensitive: true }).optional().describe(
    "jmap only: the Web Push key, stored as a Text secret. Pass it as a " +
      "vault reference. It is sent on every run, as the server may not " +
      "return it to compare.",
  ),
  reload: z.boolean().default(true).describe(
    "Run a settings reload afterwards, even when nothing changed, so the " +
      "settings take effect",
  ),
});

const MailingListEnsureArgs = z.object({
  address: z.string().describe("Full list address, e.g. team@example.com"),
  recipients: jsonArray.optional().describe(
    "Member recipient addresses (converged to exactly this set when provided)",
  ),
  description: z.string().optional(),
});

const GroupEnsureArgs = z.object({
  address: z.string().describe("Full group address, e.g. staff@example.com"),
  description: z.string().optional(),
});

/**
 * Built-in role permission sets. `role_ensure --input preset=…`
 * provisions one of these without having to pass a long permission list.
 * `swamp-admin`: non-destructive management (Get/Query/Create/Update, no
 * `*Destroy`). `automated-mailbox`: send-only authenticated SMTP.
 */
const ROLE_PRESETS: Record<string, { description: string; enabled: string[] }> =
  {
    "swamp-admin": {
      description: "Swamp Admin",
      // To assign a custom role (e.g. `automated-mailbox`), the API key's
      // principal must itself hold every permission that role grants: Stalwart
      // does not allow privilege escalation. A principal cannot grant itself
      // permissions, so give it the `User` and `Automated Mailbox` roles from
      // another admin account; they are not in this list.
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
        // No sysSpamTrainingSampleUpdate: Stalwart v1 has no such permission.
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
    "Role name/description. Required unless `preset` is given (overrides " +
      "preset name). `admin` and `user` are refused: they name the built-in roles.",
  ),
  permissions: jsonArray.optional().describe(
    "Explicit enabled-permission names. Required unless `preset` is given.",
  ),
}).describe(
  "Create or converge a role. Supply a preset, or name + permissions.",
);

const RoleAssignArgs = z.object({
  account: z.string().describe(
    "Target account: full address, or a local part that only one account has",
  ),
  role: z.string().describe(
    "The one role to assign: `admin`, `user`, or a custom role's " +
      "name/description. It replaces whatever roles the account held.",
  ),
});

const AccountEnsureArgs = z.object({
  email: z.string().describe("Full primary address, e.g. alice@example.com"),
  aliases: jsonArray.optional().describe(
    "Full alias addresses to attach (converged to exactly this set)",
  ),
  description: z.string().optional().describe("Display name / description"),
  role: z.string().optional().describe(
    "Role: admin | user | a custom role name (default `user` on create)",
  ),
  memberOf: jsonArray.optional().describe(
    "Group addresses this account is a member of (converged to exactly this " +
      "set when provided; each group's inbox then appears as a shared folder " +
      "for this account). Omit to leave membership untouched; pass [] to clear.",
  ),
  password: z.string().meta({ sensitive: true }).optional().describe(
    "Initial password, set only when the account is created (hashed by " +
      "Stalwart; never read back). Ignored, with a warning, for an existing account.",
  ),
});

const CertificateInstallArgs = z.object({
  certificate: z.string().describe("PEM certificate (full chain)"),
  privateKey: z.string().meta({ sensitive: true }).describe(
    "PEM private key — sent once, never read back",
  ),
  certificateId: z.string().optional().describe(
    "Update a specific certificate id; otherwise update the sole existing " +
      "cert, or create one",
  ),
  reload: z.boolean().default(true).describe(
    "Run reload-certificates after install so the new cert is served",
  ),
});

const StateArg = z.enum(["active", "inactive"]);
const DomainSetStateArgs = z.object({
  domain: z.string().describe("Domain name, e.g. example.com"),
  state: StateArg.describe("active (enabled) or inactive (disabled)"),
});
const AccountSetStateArgs = z.object({
  account: z.string().describe(
    "Account: full address, or a local part that only one account has",
  ),
  state: StateArg.describe(
    "active = permissions Inherit (an own Merge/Replace list is lost); " +
      "inactive = permissions Replace-empty (can't authenticate)",
  ),
});

// ─────────────────────────── model ───────────────────────────

type Ctx = MethodContext<GlobalArgsT>;

// swamp's logger renders a prop only where the message names it as
// `{prop}`, so every message below names the props it passes.
function logInfo(
  context: Pick<Ctx, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.info?.(message, props ?? {});
}

function logWarning(
  context: Pick<Ctx, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.warn?.(message, props ?? {});
}

/**
 * The method's global args. Warns when `apiUrl` is plain http, because the
 * admin API key then crosses the network unencrypted. Only a warning: a test
 * server on a private network may run without TLS.
 */
function globalsOf(context: Pick<Ctx, "globalArgs" | "logger">): GlobalArgsT {
  const g = context.globalArgs;
  if (/^http:\/\//i.test(g.apiUrl)) {
    logWarning(
      context,
      "apiUrl {apiUrl} is plain http: the API key is sent unencrypted",
      { apiUrl: g.apiUrl },
    );
  }
  return g;
}

/**
 * The `@thomas/stalwart` model definition: a `reachable` live check, the mail
 * management resource schemas, and the methods. JMAP-backed methods use the
 * {@link USING} / {@link JMAP_TYPES} constants; `health_status` uses REST only.
 */
export const model = {
  type: "@thomas/stalwart",
  version: "2026.10.29.2",
  globalArguments: GlobalArgs,
  upgrades: [
    {
      toVersion: "2026.10.11.1",
      description:
        "httpTimeoutMs must now be positive; a zero or negative value is dropped so the 30000 ms default applies. Stored data is renamed to <spec>:<key> (or <spec>); records under the old names are left as they are and are not migrated. queue-item loses status, health loses version, and certificate's subject is now issuer (with notBefore added). reload arguments accept only a real boolean, and role_ensure refuses the names admin and user.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => {
        // Zero or negative aborted every request at once, so nobody relied on it.
        if (Number(old.httpTimeoutMs) <= 0) {
          const { httpTimeoutMs: _, ...rest } = old;
          return rest;
        }
        return old;
      },
    },
    {
      toVersion: "2026.10.29.1",
      description:
        "Supports Stalwart v1 as well as 0.16. Global arguments are unchanged. The swamp-admin preset no longer grants sysSpamTrainingSampleUpdate, which v1 removed. settings_set's patch is no longer marked sensitive, so the settings record keeps its field names; a patch holding a secret is refused, and jmap's Web Push key is set with the new sensitive webPushKey argument. settings_set refuses system includeSecrets: true.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.10.29.2",
      description:
        "settings_set and reload now log the warnings a Stalwart v1 reload returns; they were dropped before. Global arguments and stored data are unchanged.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
  ],
  checks: {
    "reachable": {
      description:
        "Verify Stalwart is reachable and the API key authenticates (GET /api/account)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        // Checks get globalArgs without the schema's defaults; parse to apply them.
        const parsed = GlobalArgs.safeParse(context.globalArgs);
        if (!parsed.success) {
          return { pass: false, errors: [z.prettifyError(parsed.error)] };
        }
        const g = parsed.data;
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
      description:
        "A group principal (membership is tracked on member accounts)",
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
      description: "Server health: edition, permissions and Prometheus metrics",
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
      description: "Discovery probe: the wire shape of one JMAP object type",
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
    // ───────────── read / audit (JMAP, factory) ─────────────
    domain_list: {
      description:
        "List mail domains (factory: one `domain` per domain). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing domains");
        // Every property, because the on/off flag's name differs between
        // 0.16 and v1 (see domainState).
        const rows = await listAll(g, JMAP_TYPES.domain, accountId);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const d of rows) {
          handles.push(
            await context.writeResource(
              "domain",
              dataName("domain", String(d.name ?? d.id).toLowerCase()),
              {
                id: String(d.id ?? ""),
                name: String(d.name ?? ""),
                state: domainState(d),
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Domains recorded: {count}", {
          count: handles.length,
        });
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
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing accounts");
        const domainNames = await domainNameMap(g, accountId);
        const rows = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "domainId",
          "@type",
          "aliases",
          "roles",
          "memberGroupIds",
          "permissions",
          "description",
        ]);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const a of rows) {
          handles.push(
            await context.writeResource(
              "account",
              dataName("account", accountKey(a)),
              {
                id: String(a.id ?? ""),
                name: String(a.name ?? ""),
                email: typeof a.emailAddress === "string"
                  ? a.emailAddress
                  : undefined,
                domainId: typeof a.domainId === "string"
                  ? a.domainId
                  : undefined,
                type: accountType(a["@type"]),
                aliases: aliasAddresses(a.aliases, domainNames),
                roles: rolesLabel(a.roles),
                memberOf: mapKeys(a.memberGroupIds),
                enabled: !isDisabled(a.permissions),
                description: typeof a.description === "string"
                  ? a.description
                  : undefined,
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Accounts recorded: {count}", {
          count: handles.length,
        });
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
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing aliases of {account}", {
          account: a.account ?? "every account",
        });
        const domainNames = await domainNameMap(g, accountId);
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
          for (const addr of aliasAddresses(acct.aliases, domainNames)) {
            handles.push(
              await context.writeResource(
                "alias",
                dataName("alias", addr.toLowerCase()),
                {
                  id: String(acct.id ?? ""),
                  address: addr,
                  account: name,
                  action: "observed",
                  timestamp: ts,
                },
              ),
            );
          }
        }
        logInfo(context, "Aliases recorded: {count}", {
          count: handles.length,
        });
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
        const g = globalsOf(context);
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
            await context.writeResource(
              "role",
              dataName("role", String(r.description ?? r.id)),
              {
                id: String(r.id ?? ""),
                description: String(r.description ?? ""),
                enabledPermissions: mapKeys(r.enabledPermissions),
                disabledPermissions: mapKeys(r.disabledPermissions),
                nestedRoleIds: mapKeys(r.roleIds),
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Roles recorded: {count}", { count: handles.length });
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
        const g = globalsOf(context);
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
              dataName("group", accountKey(grp)),
              {
                id: String(grp.id ?? ""),
                name: String(grp.name ?? ""),
                description: typeof grp.description === "string"
                  ? grp.description
                  : undefined,
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Groups recorded: {count}", { count: handles.length });
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
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing mailing lists");
        const domainNames = await domainNameMap(g, accountId);
        const rows = await listAll(g, JMAP_TYPES.mailingList, accountId, [
          "id",
          "name",
          "domainId",
          "emailAddress",
          "description",
          "recipients",
        ]);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const ml of rows) {
          // Named by full address, as mailing_list_ensure does: team@a.com and
          // team@b.com are different lists. Stalwart derives emailAddress;
          // rebuild it from name + domain if a server leaves it out.
          const domainName = domainNames.get(String(ml.domainId));
          const key = typeof ml.emailAddress === "string" && ml.emailAddress
            ? ml.emailAddress.toLowerCase()
            : typeof ml.name === "string" && domainName
            ? `${ml.name}@${domainName}`.toLowerCase()
            : String(ml.id);
          handles.push(
            await context.writeResource(
              "mailing-list",
              dataName("mailing-list", key),
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
        logInfo(context, "Mailing lists recorded: {count}", {
          count: handles.length,
        });
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
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Listing mail queue");
        const rows = await listAll(g, JMAP_TYPES.queuedMessage, accountId, [
          "id",
          "returnPath",
          "recipients",
          "nextRetry",
          "size",
        ]);
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const q of rows) {
          handles.push(
            await context.writeResource(
              "queue-item",
              dataName("queue-item", String(q.id)),
              {
                id: String(q.id ?? ""),
                // The envelope sender is `returnPath`; `recipients` is keyed
                // by address, each value holding that recipient's own status.
                from: asOptString(q.returnPath),
                to: mapKeys(q.recipients),
                nextRetry: asOptString(q.nextRetry),
                size: typeof q.size === "number" ? q.size : undefined,
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Queued messages recorded: {count}", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },
    report_query: {
      description:
        "List received DMARC/TLS aggregate reports (factory: one `report` each). " +
        "Read-only. The report's fields are kept in `summary` as JSON, cut to " +
        "2000 characters; `summaryTruncated` is true when it was cut.",
      arguments: ReportQueryArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ReportQueryArgs.parse(rawArgs);
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Querying {kind} reports", { kind: a.kind });
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
            const fields = { ...r };
            delete fields.id;
            const summary = JSON.stringify(fields);
            // The report body sits under `report`. DMARC names the policy
            // domain and range once; TLS-RPT names the domain per policy. The
            // range start is `dateRangeStart`, except in 0.16 DMARC reports,
            // which call it `dateRangeBegin`.
            const body = (r.report ?? {}) as Json;
            // A Stalwart List is sent as an index-keyed object, not an array.
            const policy =
              (Object.values(body.policies ?? {})[0] ?? {}) as Json;
            handles.push(
              await context.writeResource(
                "report",
                dataName("report", `${src.kind}:${r.id}`),
                {
                  id: String(r.id ?? ""),
                  kind: src.kind,
                  domain: asOptString(body.policyDomain) ??
                    asOptString(policy.policyDomain),
                  rangeStart: asOptString(body.dateRangeBegin) ??
                    asOptString(body.dateRangeStart),
                  rangeEnd: asOptString(body.dateRangeEnd),
                  summary: summary.slice(0, SUMMARY_MAX),
                  summaryTruncated: summary.length > SUMMARY_MAX,
                  action: "observed",
                  timestamp: ts,
                },
              ),
            );
          }
        }
        logInfo(context, "Reports recorded: {count}", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },
    // ───────────── provisioning (idempotent) ─────────────
    role_ensure: {
      description:
        "Create or converge a role (idempotent by name). Pass a `preset` " +
        "(swamp-admin | automated-mailbox) or an explicit name + permissions. " +
        "Never destroys the role. Sets its enabled permissions to exactly the given " +
        "list, so a permission not listed is removed; other role settings are kept. " +
        "Refuses the names `admin` and `user`, which mean the built-in roles.",
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
        // role_assign and account_ensure read `admin` and `user` as the
        // built-in roles, so a custom role with either name could never be
        // assigned by name.
        if (["admin", "user"].includes(description.toLowerCase())) {
          throw new Error(
            `${description} is the name of a built-in role; choose another name`,
          );
        }
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Ensuring role {description}", { description });
        const rows = await listAll(g, JMAP_TYPES.role, accountId, [
          "id",
          "description",
          "enabledPermissions",
          "disabledPermissions",
          "roleIds",
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
          id = createdId(res, "new", `role ${description}`);
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
        const handle = await context.writeResource(
          "role",
          dataName("role", description),
          {
            id,
            description,
            enabledPermissions: desired,
            // Only enabledPermissions is written; the other sets are as they were.
            disabledPermissions: mapKeys(existing?.disabledPermissions),
            nestedRoleIds: mapKeys(existing?.roleIds),
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Role {description}: {action}", {
          description,
          action,
        });
        return { dataHandles: [handle] };
      },
    },
    role_assign: {
      description:
        "Assign one role to an account (idempotent). `role` is `admin`, " +
        "`user`, or a custom role name. The account ends up holding only this " +
        "role. To revert, re-run with the prior role; an account that held " +
        "several custom roles cannot be restored this way, because only one " +
        "role can be passed. Checks the account and role exist first.",
      arguments: RoleAssignArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleAssignArgs.parse(rawArgs);
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Assigning role {role} to {account}", {
          account: a.account,
          role: a.role,
        });
        const accounts = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "roles",
        ]);
        const acct = findAccount(accounts, a.account);

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
          dataName("state-result", `role:${accountKey(acct)}`),
          {
            kind: "account-role",
            id: String(acct.emailAddress ?? acct.name ?? acct.id),
            state: label,
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Role of {account}: {action}", {
          account: accountKey(acct),
          action,
        });
        return { dataHandles: [handle] };
      },
    },
    account_ensure: {
      description:
        "Create or converge an individual mailbox (idempotent by address). " +
        "Resolves the domain, converges aliases + role + group membership " +
        "(`memberOf`) + description; an optional password is set once, on " +
        "create (hashed by Stalwart, never read back); for an existing account " +
        "it is ignored with a warning. Never deletes; to remove an alias or " +
        "membership, omit it from `aliases`/`memberOf`.",
      arguments: AccountEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AccountEnsureArgs.parse(rawArgs);
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        const { local, domain } = parseAddress(a.email);
        const email = a.email.toLowerCase();
        logInfo(context, "Ensuring account {email}", { email });

        // Resolve every domain referenced (account + each alias) up front.
        const domains = await domainIdMap(g, accountId);
        const domainId = domains.get(domain);
        if (!domainId) throw new Error(`Domain not found: ${domain}`);
        // Aliases are converged only when passed. Omitting the argument leaves
        // existing aliases untouched (passing [] clears them).
        const aliasKey = (o: Json) => `${String(o.name)}@${String(o.domainId)}`;
        const desiredAliases = new Map<string, Json>();
        for (const addr of a.aliases ?? []) {
          const p = parseAddress(addr);
          const aDomId = domains.get(p.domain);
          if (!aDomId) throw new Error(`Alias domain not found: ${p.domain}`);
          const alias = { name: p.local, domainId: aDomId };
          // Keyed so a repeated address is sent once; a list with a repeat
          // would never match the server's and so would never be unchanged.
          if (!desiredAliases.has(aliasKey(alias))) {
            desiredAliases.set(aliasKey(alias), alias);
          }
        }
        const desiredAliasKeys = [...desiredAliases.keys()].sort();

        const accounts = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "@type",
          "name",
          "emailAddress",
          "domainId",
          "aliases",
          "roles",
          "memberGroupIds",
          "permissions",
          "description",
        ]);
        const existing = accounts.find((x) =>
          String(x.emailAddress).toLowerCase() === email ||
          (String(x.name).toLowerCase() === local.toLowerCase() &&
            String(x.domainId) === domainId)
        );
        // Groups share the x:Account collection, so an address match alone is
        // not enough: patching a Group with individual fields would either be
        // rejected by the server or quietly change the group. Refuse instead.
        if (existing && existing["@type"] !== "User") {
          throw new Error(
            `${a.email} is a ${
              accountType(existing["@type"])
            } account, not an individual; account_ensure only manages ` +
              "individuals (use group_ensure for groups)",
          );
        }

        // The alias list to send, when aliases were passed. Stalwart replaces
        // the whole list on update, so an alias the account already has keeps
        // its description and its enabled flag (one disabled in the UI stays
        // disabled). The flag is copied under the name the server sent:
        // `enabled` in Stalwart 0.16, `enable` in v1. A new alias carries no
        // flag, and both versions default it to enabled.
        let aliasList: Json | undefined;
        if (a.aliases) {
          const current = Object.values(
            (existing?.aliases ?? {}) as Record<string, Json>,
          );
          aliasList = {};
          let i = 0;
          for (const alias of desiredAliases.values()) {
            const kept = current.find((c) => aliasKey(c) === aliasKey(alias));
            const entry: Json = { ...alias };
            for (const flag of ["enable", "enabled"]) {
              if (typeof kept?.[flag] === "boolean") entry[flag] = kept[flag];
            }
            if (typeof kept?.description === "string") {
              entry.description = kept.description;
            }
            aliasList[String(i++)] = entry;
          }
        }

        // Resolve group memberships only when passed. Each entry must be an
        // existing group account; membership lives here on the
        // member (`memberGroupIds`), not on the group. Set-semantics Map, like
        // `roleIds`: { "<groupId>": true }.
        let desiredMembers: Json | undefined;
        let desiredMemberKeys: string[] | undefined;
        if (a.memberOf) {
          desiredMembers = {};
          for (const addr of a.memberOf) {
            const wantGrp = addr.toLowerCase();
            const grp = accounts.find((x) =>
              String(x.emailAddress).toLowerCase() === wantGrp
            );
            if (!grp) throw new Error(`Group not found: ${addr}`);
            if (grp["@type"] !== "Group") {
              throw new Error(`Not a group account: ${addr}`);
            }
            (desiredMembers as Json)[String(grp.id)] = true;
          }
          desiredMemberKeys = Object.keys(desiredMembers).sort();
        }

        let id: string;
        let action: "created" | "updated" | "unchanged";
        // The role union the account holds afterwards, for the resource.
        let roles: unknown = existing?.roles;
        if (!existing) {
          roles = (await buildRolesUnion(g, accountId, a.role ?? "user")).union;
          const create: Json = {
            "@type": "User",
            name: local,
            domainId,
            roles,
          };
          if (aliasList) create.aliases = aliasList;
          if (desiredMembers) create.memberGroupIds = desiredMembers;
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
          id = createdId(res, "new", `account ${email}`);
          action = "created";
        } else {
          id = String(existing.id);
          if (a.password) {
            logWarning(
              context,
              "Account {email} already exists, so the password was not " +
                "changed; it is only set on create",
              { email },
            );
          }
          // Converge description + aliases (+ role if given).
          const patch: Json = {};
          if (aliasList) {
            const curAliasKeys = Object.values(
              (existing.aliases ?? {}) as Json,
            ).map((o) => aliasKey(o as Json)).sort();
            if (
              JSON.stringify(curAliasKeys) !== JSON.stringify(desiredAliasKeys)
            ) {
              patch.aliases = aliasList;
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
            roles = union;
            const cur = (existing.roles ?? {}) as Json;
            const same = cur["@type"] === union["@type"] &&
              (union["@type"] !== "Custom" ||
                JSON.stringify(mapKeys(cur.roleIds).sort()) ===
                  JSON.stringify(mapKeys(union.roleIds).sort()));
            if (!same) patch.roles = union;
          }
          if (desiredMembers && desiredMemberKeys) {
            const curMemberKeys = mapKeys(existing.memberGroupIds).sort();
            if (
              JSON.stringify(curMemberKeys) !==
                JSON.stringify(desiredMemberKeys)
            ) {
              patch.memberGroupIds = desiredMembers;
            }
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
        // Record the account as it is now, shaped like account_list: what was
        // not passed is what the server kept.
        const domainNames = new Map([...domains].map(([n, i]) => [i, n]));
        const handle = await context.writeResource(
          "account",
          dataName("account", email),
          {
            id,
            name: local,
            email,
            domainId,
            type: "individual",
            aliases: aliasAddresses(
              aliasList ?? existing?.aliases,
              domainNames,
            ),
            roles: rolesLabel(roles),
            memberOf: desiredMemberKeys ?? mapKeys(existing?.memberGroupIds),
            // account_ensure never changes permissions, so a new account is
            // enabled and an existing one is as it was.
            enabled: !isDisabled(existing?.permissions),
            description: a.description ?? asOptString(existing?.description),
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Account {email}: {action}", { email, action });
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
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        const { local, domain } = parseAddress(a.address);
        const domains = await domainIdMap(g, accountId);
        const domainId = domains.get(domain);
        if (!domainId) throw new Error(`Domain not found: ${domain}`);
        const address = a.address.toLowerCase();
        logInfo(context, "Ensuring mailing list {address}", { address });
        // recipients is a set-semantics Map<String>: {"a@x.test":true, …}, so
        // a repeated address collapses to one entry.
        const recipientsMap: Json = {};
        for (const r of a.recipients ?? []) recipientsMap[r] = true;
        const desiredRecipients = Object.keys(recipientsMap);

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
          id = createdId(res, "new", `list ${address}`);
          action = "created";
        } else {
          id = String(existing.id);
          const patch: Json = {};
          if (
            a.recipients &&
            JSON.stringify(mapKeys(existing.recipients).sort()) !==
              JSON.stringify([...desiredRecipients].sort())
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
        // Named by full address: team@a.com and team@b.com are different lists.
        const handle = await context.writeResource(
          "mailing-list",
          dataName("mailing-list", address),
          {
            id,
            name: local,
            description: a.description ?? asOptString(existing?.description),
            recipients: a.recipients
              ? desiredRecipients
              : mapKeys(existing?.recipients),
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Mailing list {address}: {action}", {
          address,
          action,
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
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        const { local, domain } = parseAddress(a.address);
        const domains = await domainIdMap(g, accountId);
        const domainId = domains.get(domain);
        if (!domainId) throw new Error(`Domain not found: ${domain}`);
        const address = a.address.toLowerCase();
        logInfo(context, "Ensuring group {address}", { address });
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
          id = createdId(res, "new", `group ${address}`);
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
        // Named by full address: team@a.com and team@b.com are different groups.
        const handle = await context.writeResource(
          "group",
          dataName("group", address),
          {
            id,
            name: local,
            description: a.description ?? asOptString(existing?.description),
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Group {address}: {action}", { address, action });
        return { dataHandles: [handle] };
      },
    },
    // ───────────── reversible state ─────────────
    domain_set_state: {
      description:
        "Enable or disable a domain (reversible, via `enable`, or `isEnabled` " +
        "on Stalwart 0.16). Checks the domain exists first; idempotent.",
      arguments: DomainSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = DomainSetStateArgs.parse(rawArgs);
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Setting domain {domain} to {state}", {
          domain: a.domain,
          state: a.state,
        });
        // Every property, so domainEnabledKey can tell 0.16 from v1.
        const rows = await listAll(g, JMAP_TYPES.domain, accountId);
        const dom = rows.find((d) =>
          String(d.name).toLowerCase() === a.domain.toLowerCase()
        );
        if (!dom) throw new Error(`Domain not found: ${a.domain}`);
        const key = domainEnabledKey(dom);
        const want = a.state === "active";
        let action: "reactivated" | "deactivated" | "unchanged";
        if (dom[key] === want) {
          action = "unchanged";
        } else {
          const res = await jmapSet(g, JMAP_TYPES.domain, {
            accountId,
            update: { [String(dom.id)]: { [key]: want } },
          });
          const err = setItemError(res, String(dom.id));
          if (err) throw new Error(`Could not set domain state: ${err}`);
          action = want ? "reactivated" : "deactivated";
        }
        const handle = await context.writeResource(
          "state-result",
          dataName("state-result", `domain:${a.domain.toLowerCase()}`),
          {
            kind: "domain",
            id: a.domain,
            state: a.state,
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Domain {domain}: {action}", {
          domain: a.domain,
          action,
        });
        return { dataHandles: [handle] };
      },
    },
    account_set_state: {
      description:
        "Disable or re-enable an account without deleting it. Disable replaces " +
        "the account's permissions with an empty set (it can no longer " +
        "authenticate); re-enable sets them to `Inherit` (role-based). An account " +
        "that had its own Merge or Replace permission list loses it on re-enable, " +
        "so for such an account this cannot be undone. Idempotent. Mailbox and " +
        "aliases are untouched.",
      arguments: AccountSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AccountSetStateArgs.parse(rawArgs);
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Setting account {account} to {state}", {
          account: a.account,
          state: a.state,
        });
        const accounts = await listAll(g, JMAP_TYPES.account, accountId, [
          "id",
          "name",
          "emailAddress",
          "permissions",
        ]);
        const acct = findAccount(accounts, a.account);
        const wantDisable = a.state === "inactive";
        let action: "deactivated" | "reactivated" | "unchanged";
        if (wantDisable === isDisabled(acct.permissions)) {
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
          dataName("state-result", `account:${accountKey(acct)}`),
          {
            kind: "account",
            id: String(acct.emailAddress ?? acct.name ?? acct.id),
            state: a.state,
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Account {account}: {action}", {
          account: accountKey(acct),
          action,
        });
        return { dataHandles: [handle] };
      },
    },
    // ───────────── settings + maintenance actions ─────────────
    settings_get: {
      description:
        "Read a server settings singleton (http, system, spam-classifier, …). " +
        "Read-only. Secret values (e.g. jmap `webPushKey`) are recorded as " +
        '"<redacted>".',
      arguments: SettingsGetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = SettingsGetArgs.parse(rawArgs);
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        const type = SETTINGS_TYPES[a.kind];
        logInfo(context, "Reading {kind} settings", { kind: a.kind });
        const list = await jmapGet(g, type, { accountId, ids: [SINGLETON_ID] });
        const obj = (list[0] ?? {}) as Json;
        const settings = redactSecrets(obj) as Json;
        delete settings.id;
        const handle = await context.writeResource(
          "settings",
          dataName("settings", a.kind),
          {
            kind: a.kind,
            id: SINGLETON_ID,
            settings,
            action: "observed",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    settings_set: {
      description:
        "Set the top-level fields in `patch` on a settings singleton " +
        "(idempotent), then reload so they take effect; with `reload` true it " +
        "reloads even when nothing changed. Fields not in `patch` " +
        "are kept; a list or map value is replaced whole. Records the " +
        'singleton as the server holds it afterwards; secret values are "<redacted>".',
      arguments: SettingsSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = SettingsSetArgs.parse(rawArgs);
        if (a.webPushKey !== undefined && a.kind !== "jmap") {
          throw new Error("webPushKey is a jmap setting; use kind jmap");
        }
        // patch is not sensitive, so swamp would store a secret in it in clear.
        if (holdsSecret(a.patch)) {
          throw new Error(
            'patch holds a secret value (a {"secret": …} object), which swamp ' +
              "would store in clear. Set the jmap Web Push key with the " +
              "webPushKey argument, from a vault reference.",
          );
        }
        // Stalwart v1's system includeSecrets makes every management API reply
        // carry passwords and keys in clear, which this credential must not
        // switch on.
        if (a.kind === "system" && a.patch.includeSecrets === true) {
          throw new Error(
            "Refusing includeSecrets: true, which makes Stalwart return " +
              "secrets in every management API reply",
          );
        }
        const update: Json = { ...a.patch };
        if (a.webPushKey !== undefined) {
          update.webPushKey = { "@type": "Text", secret: a.webPushKey };
        }
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        const type = SETTINGS_TYPES[a.kind];
        logInfo(context, "Updating {kind} settings: {fields}", {
          kind: a.kind,
          fields: Object.keys(update),
        });
        const readSingleton = async (): Promise<Json> => {
          const list = await jmapGet(g, type, {
            accountId,
            ids: [SINGLETON_ID],
          });
          if (!list[0]) {
            throw new Error(`Could not read the ${a.kind} settings singleton`);
          }
          return list[0];
        };
        let current = await readSingleton();
        const changed = Object.entries(update).some(([k, v]) =>
          JSON.stringify(current[k]) !== JSON.stringify(v)
        );
        let action: "updated" | "unchanged" = "unchanged";
        if (changed) {
          const res = await jmapSet(g, type, {
            accountId,
            update: { [SINGLETON_ID]: update },
          });
          const err = setItemError(res, SINGLETON_ID);
          if (err) {
            throw new Error(`Could not update ${a.kind} settings: ${err}`);
          }
          action = "updated";
          // Re-read rather than merge locally: Stalwart merges nested objects
          // but replaces lists and maps, so only the server knows the result.
          current = await readSingleton();
        }
        // Reload even when nothing changed: an earlier run may have saved the
        // change and then failed to reload, and a retry finds nothing to change.
        if (a.reload) {
          try {
            for (
              const warning of await runAction(g, accountId, "ReloadSettings")
            ) {
              logWarning(context, "Reload warning: {warning}", { warning });
            }
          } catch (e) {
            throw new Error(
              `The ${a.kind} settings are saved but the reload failed, so ` +
                `they may not be live yet; run the \`reload\` method. ` +
                (e as Error).message,
            );
          }
        }
        const settings = redactSecrets(current) as Json;
        delete settings.id;
        const handle = await context.writeResource(
          "settings",
          dataName("settings", a.kind),
          {
            kind: a.kind,
            id: SINGLETON_ID,
            settings,
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Settings {kind}: {action}", { kind: a.kind, action });
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
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Reloading settings");
        for (const warning of await runAction(g, accountId, "ReloadSettings")) {
          logWarning(context, "Reload warning: {warning}", { warning });
        }
        const handle = await context.writeResource(
          "state-result",
          dataName("state-result", "reload"),
          {
            kind: "server",
            id: "settings",
            state: "reloaded",
            action: "reloaded",
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Settings reloaded");
        return { dataHandles: [handle] };
      },
    },
    certificate_install: {
      description:
        "Install a TLS certificate (PEM cert + key) and reload certificates. " +
        "Updates the sole existing cert in place (or one named by `certificateId`), " +
        "else creates a new one. Issuance stays with your ACME tooling — this is " +
        "the install + reload path. The private key is sent once, never read back. " +
        "Records the certificate's issuer, SANs and validity period.",
      arguments: CertificateInstallArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = CertificateInstallArgs.parse(rawArgs);
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Installing certificate");
        // certificate is a PublicText union, privateKey a SecretText union;
        // both are sent inline as `{"@type":"Text", …}` (cert uses `value`, key `secret`).
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
          id = createdId(res, "new", "a certificate");
          action = "created";
        }
        if (a.reload) {
          try {
            await runAction(g, accountId, "ReloadTlsCertificates");
          } catch (e) {
            throw new Error(
              `Certificate ${id} is saved but the reload failed, so it may ` +
                "not be served yet; run `reload_certificates`. " +
                (e as Error).message,
            );
          }
        }
        // Best effort: read back the parsed SANs / validity.
        let issuer: string | undefined;
        let sans: string[] | undefined;
        let notBefore: string | undefined;
        let notAfter: string | undefined;
        try {
          const got = await jmapGet(g, JMAP_TYPES.certificate, {
            accountId,
            ids: [id],
            properties: [
              "id",
              "issuer",
              "subjectAlternativeNames",
              "notValidBefore",
              "notValidAfter",
            ],
          });
          const c = (got[0] ?? {}) as Json;
          issuer = asOptString(c.issuer);
          notBefore = asOptString(c.notValidBefore);
          sans = mapKeys(c.subjectAlternativeNames);
          notAfter = typeof c.notValidAfter === "string"
            ? c.notValidAfter
            : undefined;
        } catch (e) {
          // The install worked; only the read-back for the record failed.
          logWarning(
            context,
            "Certificate {id} installed, but reading back its details " +
              "failed: {error}",
            { id, error: (e as Error).message },
          );
        }
        const handle = await context.writeResource(
          "certificate",
          dataName("certificate", id),
          {
            id,
            issuer,
            sans,
            notBefore,
            notAfter,
            action,
            timestamp: nowIso(),
          },
        );
        logInfo(context, "Certificate {id}: {action}", { id, action });
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
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Reloading TLS certificates");
        await runAction(g, accountId, "ReloadTlsCertificates");
        const handle = await context.writeResource(
          "state-result",
          dataName("state-result", "reload-certificates"),
          {
            kind: "certificates",
            id: "tls",
            state: "reloaded",
            action: "reloaded",
            timestamp: nowIso(),
          },
        );
        logInfo(context, "TLS certificates reloaded");
        return { dataHandles: [handle] };
      },
    },
    // ───────────── read / health (REST) ─────────────
    health_status: {
      description:
        "Server health: edition and permissions (GET /api/account) plus every " +
        "metric in GET /metrics/prometheus. Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = globalsOf(context);
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
          logWarning(context, "Prometheus metrics unavailable: {error}", {
            error: (e as Error).message,
          });
        }
        const edition = typeof acct.body.edition === "string"
          ? acct.body.edition
          : undefined;
        const permissions = Array.isArray(acct.body.permissions)
          ? (acct.body.permissions as unknown[]).map(String)
          : undefined;
        const handle = await context.writeResource(
          "health",
          dataName("health"),
          {
            reachable: true,
            edition,
            permissions,
            metrics,
            action: "observed",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    // ───────────── discovery (read-only JMAP probe) ─────────────
    session_dump: {
      description:
        "Fetch the JMAP session resource (/.well-known/jmap) and record the " +
        "advertised capabilities + accounts. Read-only; used to check the " +
        "management capability URI against a Stalwart version.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = globalsOf(context);
        logInfo(context, "Fetching JMAP session");
        const r = await rest(g, { method: "GET", path: "/.well-known/jmap" });
        const caps = (r.body.capabilities ?? {}) as Json;
        const accounts = (r.body.accounts ?? {}) as Json;
        const primary = (r.body.primaryAccounts ?? {}) as Record<
          string,
          string
        >;
        const handle = await context.writeResource(
          "session",
          dataName("session"),
          {
            capabilities: Object.keys(caps),
            accounts: Object.keys(accounts),
            primaryAccounts: primary,
            raw: r.text ?? JSON.stringify(r.body),
            action: "observed",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    jmap_probe: {
      description:
        "Discovery probe: run `<type>/query` then `<type>/get` for one type and " +
        "capture the wire shape (ids + a sample object). Read-only; used to check " +
        "the JMAP_TYPES constants against a Stalwart version.",
      arguments: JmapProbeArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = JmapProbeArgs.parse(rawArgs);
        const g = globalsOf(context);
        const accountId = await resolveAccountId(g);
        logInfo(context, "Probing JMAP type {type}", { type: a.type });
        const ids = await jmapQuery(g, a.type, { accountId, limit: a.limit });
        let sample: string | undefined;
        if (ids.length) {
          const objs = await jmapGet(g, a.type, {
            accountId,
            ids: ids.slice(0, 1),
          });
          if (objs[0]) sample = JSON.stringify(objs[0]);
        }
        const handle = await context.writeResource(
          "probe",
          dataName("probe", a.type),
          {
            type: a.type,
            capability: USING.mgmt,
            accountId,
            count: ids.length,
            ids,
            sample,
            action: "observed",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
