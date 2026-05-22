import { z } from "npm:zod@4";
// Type-only imports — erased at compile time, never bundled. They anchor the
// `satisfies ModelDefinition<typeof GlobalArgs>` clause on `model` so every
// method's `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";
import https from "node:https";
import http from "node:http";
import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";

/**
 * `@thomas/technitium` — management of a Technitium DNS Server, fronted entirely
 * by its HTTP API. A permanent API token (sent both as `Authorization: Bearer`
 * and as the legacy `?token=` query param) is the only credential; the extension
 * never touches the server host directly. Every mutation goes through the API.
 *
 * Method sections (by prefix):
 *   - `blocking_*` — built-in ad-blocking: enable/disable, temporary disable,
 *     allow/block list URLs, force list update. (NOT the Advanced Blocking app.)
 *   - `zone_*` / `record_*` — authoritative zone + record lifecycle.
 *   - `allowed_*` / `blocked_*` — the built-in Allowed/Blocked custom-domain zones.
 *   - `client_*` — the DNS client resolver, for debugging queries (ephemeral output).
 *   - `logs_*` — structured query-log retrieval (requires the Query Logs (Sqlite) app).
 *   - `cache_*` — DNS cache flush / list / delete.
 *   - `dashboard_*` — query statistics.
 *   - `settings_*` — full settings backup (zip) and restore (multipart upload).
 *
 * Only blocking-relevant fields of the server settings are surfaced as data —
 * the full settings blob is intentionally NOT passed through, to avoid leaking
 * secrets (e.g. TLS certificate passwords) into the data model.
 */

const GlobalArgs = z.object({
  baseUrl: z.string().describe(
    "Technitium base URL including port, e.g. https://dns.example:5380",
  ),
  apiToken: z.string().meta({ sensitive: true }).describe(
    "Permanent Technitium API token. Supply via vault: ${{ vault.get(technitium, api_token) }}",
  ),
  skipTlsVerify: z.boolean().default(false).describe(
    "Accept self-signed certs (default false — a valid cert is expected)",
  ),
});

const Action = z.enum([
  "created",
  "updated",
  "unchanged",
  "deleted",
  "observed",
]);

// ---------------------------------------------------------------------------
// Resource schemas. Spec keys (the `resources` keys below) are camelCase with
// no hyphens, per the swamp model API rule.
// ---------------------------------------------------------------------------

const ZoneResource = z.object({
  name: z.string(),
  type: z.string().optional().describe(
    "Primary | Secondary | Stub | Forwarder | SecondaryForwarder | Catalog | SecondaryCatalog | (internal types)",
  ),
  disabled: z.boolean().optional(),
  internal: z.boolean().optional(),
  dnssecStatus: z.string().optional(),
  action: Action,
  observedAt: z.string(),
});

const ZoneRecordResource = z.object({
  zone: z.string(),
  name: z.string().describe("Record owner name (FQDN)"),
  type: z.string(),
  ttl: z.number().optional(),
  disabled: z.boolean().optional(),
  rData: z.record(z.string(), z.unknown()).optional().describe(
    "Type-specific record data (e.g. { ipAddress } for A, { cname } for CNAME)",
  ),
  action: Action,
  observedAt: z.string(),
});

const SettingsResource = z.object({
  enableBlocking: z.boolean().optional(),
  temporaryDisableBlockingTill: z.string().optional().describe(
    "ISO timestamp until which blocking is temporarily disabled (absent when not)",
  ),
  blockListUrls: z.array(z.string()).optional(),
  allowListUrls: z.array(z.string()).optional(),
  blockListUrlUpdateIntervalHours: z.number().optional(),
  observedAt: z.string(),
});

const StatsResource = z.object({
  range: z.string().describe("LastHour | LastDay | LastWeek | ... | Custom"),
  totalQueries: z.number().optional(),
  totalNoError: z.number().optional(),
  totalServerFailure: z.number().optional(),
  totalNxDomain: z.number().optional(),
  totalRefused: z.number().optional(),
  totalBlocked: z.number().optional(),
  totalCached: z.number().optional(),
  totalClients: z.number().optional(),
  topDomains: z.array(z.unknown()).optional(),
  topBlockedDomains: z.array(z.unknown()).optional(),
  topClients: z.array(z.unknown()).optional(),
  observedAt: z.string(),
}).passthrough();

const ListEntryResource = z.object({
  list: z.enum(["allowed", "blocked"]),
  domain: z.string(),
  action: Action,
  observedAt: z.string(),
});

const DnsResponseResource = z.object({
  server: z.string(),
  domain: z.string(),
  type: z.string(),
  protocol: z.string(),
  rcode: z.string().optional(),
  answer: z.array(z.unknown()).optional(),
  observedAt: z.string(),
}).passthrough();

const QueryLogResource = z.object({
  rowNumber: z.number().optional(),
  timestamp: z.string().optional(),
  clientIpAddress: z.string().optional(),
  protocol: z.string().optional(),
  responseType: z.string().optional(),
  rcode: z.string().optional(),
  qname: z.string().optional(),
  qtype: z.string().optional(),
  qclass: z.string().optional(),
  answer: z.string().optional(),
  observedAt: z.string(),
}).passthrough();

const CacheEntryResource = z.object({
  name: z.string(),
  kind: z.string().optional().describe("zone | record"),
  action: Action,
  observedAt: z.string(),
});

const OperationResultResource = z.object({
  operation: z.string(),
  target: z.string().optional(),
  success: z.boolean(),
  detail: z.string().optional(),
  observedAt: z.string(),
});

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

const API = "/api";
const REQUEST_TIMEOUT_MS = 30_000;

type GlobalArgsT = z.infer<typeof GlobalArgs>;
type Json = Record<string, unknown>;
type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";
type Params = Record<string, string | number | boolean | undefined>;
type HttpResult = { status: number; body: Buffer };

/** Low-level HTTPS/HTTP request returning the raw status and body bytes. */
function httpRequest(
  opts: https.RequestOptions,
  secure: boolean,
  body?: string | Uint8Array,
): Promise<HttpResult> {
  const transport = secure ? https : http;
  return new Promise((resolve, reject) => {
    const req = transport.request(opts, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks),
        }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(
      REQUEST_TIMEOUT_MS,
      () => req.destroy(new Error("request timed out")),
    );
    if (body) req.write(body);
    req.end();
  });
}

/** Parse a JSON body, returning null for an empty body and the raw string if it isn't JSON. */
function safeJson(body: string): unknown {
  if (!body) return null;
  try {
    return JSON.parse(body);
  } catch {
    return body;
  }
}

/**
 * Unwrap Technitium's `{ status, response, errorMessage }` envelope. Throws on
 * any status other than `"ok"` (e.g. `"error"`, `"invalid-token"`), surfacing
 * the server's `errorMessage`. Returns the inner `response` object.
 */
export function unwrapEnvelope(parsed: unknown, context: string): Json {
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const o = parsed as Json;
    const status = o.status;
    if (status !== undefined && status !== "ok") {
      const msg = typeof o.errorMessage === "string" && o.errorMessage
        ? o.errorMessage
        : String(status);
      throw new Error(`Technitium ${context}: ${msg}`);
    }
    const resp = o.response;
    if (resp && typeof resp === "object" && !Array.isArray(resp)) {
      return resp as Json;
    }
    return {};
  }
  return {};
}

type TechFn = (
  g: GlobalArgsT,
  method: HttpMethod,
  path: string,
  params?: Params,
) => Promise<Json>;

let _techOverride: TechFn | null = null;

/** Test-only seam: substitute the Technitium HTTP transport. Pass `null` to restore the real one. */
export function __setTechnitiumTransport(fn: TechFn | null): void {
  _techOverride = fn;
}

/**
 * Build the request URL (always carrying the `token` query param) and the
 * `Authorization: Bearer` header for a Technitium API call.
 */
function buildRequest(
  g: GlobalArgsT,
  path: string,
  query: Params,
): { url: URL; headers: Record<string, string>; secure: boolean } {
  const u = new URL(g.baseUrl.replace(/\/+$/, "") + API + path);
  u.searchParams.set("token", g.apiToken);
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) u.searchParams.set(k, String(v));
  }
  return {
    url: u,
    secure: u.protocol === "https:",
    headers: {
      "Authorization": `Bearer ${g.apiToken}`,
      "Accept": "application/json",
    },
  };
}

/**
 * Call a Technitium API path (relative to `/api`) that returns the JSON
 * envelope. GET params go in the query string; POST params go in an
 * `application/x-www-form-urlencoded` body (so long block-list URLs don't blow
 * the URL length limit). Routes through the test seam when one is installed.
 */
function apiCall(
  g: GlobalArgsT,
  method: HttpMethod,
  path: string,
  params?: Params,
): Promise<Json> {
  return (_techOverride ?? apiCallReal)(g, method, path, params ?? {});
}

/** The real HTTP implementation behind `apiCall`. */
async function apiCallReal(
  g: GlobalArgsT,
  method: HttpMethod,
  path: string,
  params: Params,
): Promise<Json> {
  const isPost = method === "POST";
  const query: Params = {};
  const form = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null) continue;
    if (isPost) form.set(k, String(v));
    else query[k] = v;
  }
  const { url, headers, secure } = buildRequest(g, path, query);
  const payload = isPost ? form.toString() : undefined;
  if (payload !== undefined) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    headers["Content-Length"] = String(Buffer.byteLength(payload));
  }
  const res = await httpRequest(
    {
      hostname: url.hostname,
      port: url.port ? parseInt(url.port, 10) : (secure ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers,
      rejectUnauthorized: !g.skipTlsVerify,
    },
    secure,
    payload,
  );
  const text = res.body.toString("utf8");
  if (res.status >= 400) {
    throw new Error(
      `Technitium ${method} ${path} -> HTTP ${res.status}: ${text}`,
    );
  }
  return unwrapEnvelope(safeJson(text), `${method} ${path}`);
}

/**
 * Download a binary response (e.g. the settings backup zip). The backup endpoint
 * returns raw `application/zip`, NOT the JSON envelope, so this bypasses
 * `unwrapEnvelope`. Not routed through the test seam (exercised live).
 */
async function apiDownload(
  g: GlobalArgsT,
  path: string,
  params: Params,
): Promise<Uint8Array> {
  const { url, headers, secure } = buildRequest(g, path, params);
  const res = await httpRequest(
    {
      hostname: url.hostname,
      port: url.port ? parseInt(url.port, 10) : (secure ? 443 : 80),
      path: url.pathname + url.search,
      method: "GET",
      headers,
      rejectUnauthorized: !g.skipTlsVerify,
    },
    secure,
  );
  if (res.status >= 400) {
    throw new Error(
      `Technitium GET ${path} -> HTTP ${res.status}: ${
        res.body.toString("utf8")
      }`,
    );
  }
  return new Uint8Array(res.body);
}

/**
 * Upload a file via multipart/form-data (the settings restore endpoint). Parses
 * the JSON envelope from the response. Not routed through the test seam.
 */
async function apiUpload(
  g: GlobalArgsT,
  path: string,
  params: Params,
  fileBytes: Uint8Array,
  fileName: string,
): Promise<Json> {
  const { body, contentType } = buildMultipart(
    "fileToUpload",
    fileName,
    fileBytes,
  );
  const { url, headers, secure } = buildRequest(g, path, params);
  headers["Content-Type"] = contentType;
  headers["Content-Length"] = String(body.length);
  const res = await httpRequest(
    {
      hostname: url.hostname,
      port: url.port ? parseInt(url.port, 10) : (secure ? 443 : 80),
      path: url.pathname + url.search,
      method: "POST",
      headers,
      rejectUnauthorized: !g.skipTlsVerify,
    },
    secure,
    body,
  );
  const text = res.body.toString("utf8");
  if (res.status >= 400) {
    throw new Error(`Technitium POST ${path} -> HTTP ${res.status}: ${text}`);
  }
  return unwrapEnvelope(safeJson(text), `POST ${path}`);
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit tests)
// ---------------------------------------------------------------------------

/** First defined value among the given keys (tolerates camel/snake/Pascal drift). */
function pick(o: Json, ...keys: string[]): unknown {
  for (const k of keys) {
    if (o[k] !== undefined && o[k] !== null) return o[k];
  }
  return undefined;
}

function asString(v: unknown): string | undefined {
  return v === undefined || v === null ? undefined : String(v);
}

function asNumber(v: unknown): number | undefined {
  if (typeof v === "number") return v;
  if (typeof v === "string" && v.trim() !== "" && !Number.isNaN(Number(v))) {
    return Number(v);
  }
  return undefined;
}

function toStringArray(v: unknown): string[] | undefined {
  if (Array.isArray(v)) return v.map((x) => String(x));
  return undefined;
}

/**
 * Slugify an arbitrary label into a safe swamp data instance name. swamp rejects
 * instance names containing `/`, `..`, `\`, or null bytes, so dotted domains and
 * record names are flattened.
 */
export function slug(s: string): string {
  const out = s.replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  return out.length > 0 ? out : "root";
}

/** Pull an array out of a Technitium response under any of the given keys. */
export function coerceArray(resp: Json, ...keys: string[]): Json[] {
  for (const k of keys) {
    if (Array.isArray(resp[k])) return resp[k] as Json[];
  }
  return [];
}

/**
 * Collect distinct domain names from a Technitium list response — entries may be
 * bare strings (subdomain names) or objects with a `name`/`domain` field, under
 * `zones` and/or `records` arrays. Deduplicated, since a domain can appear in
 * both arrays and the names are used as unique data instance keys.
 */
export function namesFrom(resp: Json, ...keys: string[]): string[] {
  const seen = new Set<string>();
  for (const k of keys) {
    const arr = resp[k];
    if (!Array.isArray(arr)) continue;
    for (const e of arr) {
      if (typeof e === "string") seen.add(e);
      else if (e && typeof e === "object") {
        const n = asString(pick(e as Json, "name", "domain"));
        if (n) seen.add(n);
      }
    }
  }
  return [...seen];
}

/**
 * Join block/allow list URLs into Technitium's comma-separated form, returning
 * the joined string plus any URLs exceeding Technitium's 255-char-per-entry
 * limit (so the caller can warn).
 */
export function joinListUrls(
  urls: string[],
): { joined: string; tooLong: string[] } {
  return {
    joined: urls.join(","),
    tooLong: urls.filter((u) => u.length > 255),
  };
}

/**
 * Prefix record-data keys with `new` (PascalCased) for Technitium's
 * `/zones/records/update` endpoint, e.g. `{ ipAddress }` → `{ newIpAddress }`.
 */
export function prefixNew(rData: Record<string, unknown>): Params {
  const out: Params = {};
  for (const [k, v] of Object.entries(rData)) {
    if (v === undefined || v === null) continue;
    const key = "new" + k.charAt(0).toUpperCase() + k.slice(1);
    out[key] = v as string | number | boolean;
  }
  return out;
}

/** Flatten a record's rData object into flat query params (Technitium uses flat names). */
function spreadRData(into: Params, rData?: Record<string, unknown>): Params {
  if (rData) {
    for (const [k, v] of Object.entries(rData)) {
      if (v !== undefined && v !== null) {
        into[k] = v as string | number | boolean;
      }
    }
  }
  return into;
}

/** Build a multipart/form-data body for a single file part. */
export function buildMultipart(
  fieldName: string,
  fileName: string,
  bytes: Uint8Array,
): { body: Uint8Array; contentType: string; boundary: string } {
  const boundary = "----swampTechnitium" +
    crypto.randomUUID().replace(/-/g, "");
  const enc = new TextEncoder();
  const head = enc.encode(
    `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${fieldName}"; filename="${fileName}"\r\n` +
      `Content-Type: application/zip\r\n\r\n`,
  );
  const tail = enc.encode(`\r\n--${boundary}--\r\n`);
  const body = new Uint8Array(head.length + bytes.length + tail.length);
  body.set(head, 0);
  body.set(bytes, head.length);
  body.set(tail, head.length + bytes.length);
  return {
    body,
    contentType: `multipart/form-data; boundary=${boundary}`,
    boundary,
  };
}

/** Extract the blocking-relevant subset of a Technitium settings response. */
function extractSettings(
  r: Json,
  observedAt: string,
): z.infer<typeof SettingsResource> {
  return {
    enableBlocking: pick(r, "enableBlocking") as boolean | undefined,
    temporaryDisableBlockingTill: asString(
      pick(r, "temporaryDisableBlockingTill"),
    ),
    blockListUrls: toStringArray(pick(r, "blockListUrls")),
    allowListUrls: toStringArray(pick(r, "allowListUrls")),
    blockListUrlUpdateIntervalHours: asNumber(
      pick(r, "blockListUrlUpdateIntervalHours"),
    ),
    observedAt,
  };
}

/** Build an operation-result record. */
function opResult(
  operation: string,
  success: boolean,
  target?: string,
  detail?: string,
): z.infer<typeof OperationResultResource> {
  return {
    operation,
    target,
    success,
    detail,
    observedAt: new Date().toISOString(),
  };
}

/** Structured info log when a logger is present (no-op otherwise). Never pass secrets. */
function logInfo(
  context: Pick<MethodContext<GlobalArgsT>, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.info?.(message, props ?? {});
}

const ZoneType = z.enum([
  "Primary",
  "Secondary",
  "Stub",
  "Forwarder",
  "SecondaryForwarder",
  "Catalog",
  "SecondaryCatalog",
]);

const StatsRange = z.enum([
  "LastHour",
  "LastDay",
  "LastWeek",
  "LastMonth",
  "LastYear",
  "Custom",
]);

const RData = z.record(
  z.string(),
  z.union([z.string(), z.number(), z.boolean()]),
);

// ---------------------------------------------------------------------------
// Method argument schemas (named so `execute` can annotate `args`)
// ---------------------------------------------------------------------------

const NoArgs = z.object({});
const ZoneRefArgs = z.object({ zone: z.string() });
const DomainArgs = z.object({ domain: z.string() });
const DomainOptArgs = z.object({
  domain: z.string().optional().describe("Sub-tree to list; root if omitted"),
});

const BlockingSetStateArgs = z.object({ enable: z.boolean() });

const BlockingTempDisableArgs = z.object({
  minutes: z.number().int().positive().describe(
    "Minutes to disable blocking (e.g. 5, 15, 30, 60, 1440)",
  ),
});

const BlockingSetListsArgs = z.object({
  blockListUrls: z.array(z.string()).optional(),
  allowListUrls: z.array(z.string()).optional(),
});

const ZoneCreateArgs = z.object({
  zone: z.string().describe("Zone name, e.g. lab.example.com"),
  type: ZoneType.default("Primary"),
});

const RecordAddArgs = z.object({
  zone: z.string().optional().describe(
    "Zone name; inferred from domain if omitted",
  ),
  domain: z.string().describe("Record owner FQDN"),
  type: z.string().describe(
    "A | AAAA | CNAME | TXT | MX | SRV | NS | PTR | ...",
  ),
  ttl: z.number().int().optional(),
  rData: RData.optional(),
});

const RecordUpdateArgs = z.object({
  zone: z.string().optional(),
  domain: z.string(),
  type: z.string(),
  ttl: z.number().int().optional(),
  rData: RData.optional().describe(
    "Existing record data, to identify the record",
  ),
  newRData: RData.optional().describe("New record data (e.g. { ipAddress })"),
  newDomain: z.string().optional().describe("Rename the record owner, if set"),
});

const RecordDeleteArgs = z.object({
  zone: z.string().optional(),
  domain: z.string(),
  type: z.string(),
  rData: RData.optional(),
});

const ClientResolveArgs = z.object({
  domain: z.string(),
  type: z.string().default("A"),
  server: z.string().default("this-server").describe(
    "this-server | recursive-resolver | system-dns | <ip/hostname>",
  ),
  protocol: z.enum(["Udp", "Tcp", "Tls", "Https", "Quic"]).default("Udp"),
  dnssecValidation: z.boolean().optional(),
});

const LogsQueryArgs = z.object({
  appName: z.string().default("Query Logs (Sqlite)").describe(
    "DNS app providing query logs (override if your install differs)",
  ),
  classPath: z.string().default("QueryLogsSqlite.App").describe(
    "App class path (override if your install differs)",
  ),
  pageNumber: z.number().int().optional(),
  entriesPerPage: z.number().int().optional(),
  descendingOrder: z.boolean().optional(),
  start: z.string().optional().describe("ISO 8601 start time"),
  end: z.string().optional().describe("ISO 8601 end time"),
  clientIpAddress: z.string().optional(),
  protocol: z.string().optional(),
  responseType: z.string().optional(),
  qname: z.string().optional(),
  qtype: z.string().optional(),
  qclass: z.string().optional(),
});

const DashboardStatsArgs = z.object({
  type: StatsRange.default("LastHour"),
  start: z.string().optional().describe("ISO 8601 start (when type=Custom)"),
  end: z.string().optional().describe("ISO 8601 end (when type=Custom)"),
});

const SettingsBackupArgs = z.object({
  options: z.record(z.string(), z.boolean()).optional().describe(
    "Section flags (blockLists, zones, allowedZones, blockedZones, scopes, apps, dnsApps, authConfig, logs, stats). Defaults to a config-only backup.",
  ),
});

const SettingsRestoreArgs = z.object({
  filePath: z.string().describe(
    "Absolute path to the backup zip on the swamp host",
  ),
  options: z.record(z.string(), z.boolean()).optional().describe(
    "Section flags controlling what to restore (mirrors settings_backup).",
  ),
  deleteExistingFiles: z.boolean().optional().describe(
    "Delete existing config files not present in the backup",
  ),
});

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

export const model = {
  type: "@thomas/technitium",
  version: "2026.05.23.1",
  globalArguments: GlobalArgs,
  resources: {
    "zone": {
      description: "An authoritative DNS zone",
      schema: ZoneResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "zoneRecord": {
      description: "A resource record within a zone",
      schema: ZoneRecordResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "settings": {
      description:
        "Blocking-relevant server settings (enable state, temp-disable, list URLs)",
      schema: SettingsResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "stats": {
      description: "Dashboard query statistics for a time range",
      schema: StatsResource,
      lifetime: "1d",
      garbageCollection: 5,
    },
    "listEntry": {
      description: "A domain in the built-in Allowed or Blocked zone",
      schema: ListEntryResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "dnsResponse": {
      description: "Result of a DNS client resolve (debugging — ephemeral)",
      schema: DnsResponseResource,
      lifetime: "ephemeral",
      garbageCollection: 5,
    },
    "queryLog": {
      description: "A query-log entry (requires the Query Logs (Sqlite) app)",
      schema: QueryLogResource,
      lifetime: "7d",
      garbageCollection: 5,
    },
    "cacheEntry": {
      description: "A cached zone or record name",
      schema: CacheEntryResource,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "operationResult": {
      description:
        "Result of a one-shot operation (flush, temp-disable, restore, ...)",
      schema: OperationResultResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  files: {
    "backup": {
      description:
        "A full Technitium settings backup (zip). May contain secrets — short-lived.",
      contentType: "application/zip",
      lifetime: "7d",
      garbageCollection: 5,
    },
  },
  methods: {
    // ----- blocking_ (built-in) ------------------------------------------
    blocking_get_settings: {
      description:
        "Get the blocking-relevant server settings (enable state, temp-disable expiry, list URLs).",
      arguments: NoArgs,
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/settings/get");
        const handle = await context.writeResource(
          "settings",
          "current",
          extractSettings(r, new Date().toISOString()),
        );
        return { dataHandles: [handle] };
      },
    },

    blocking_set_state: {
      description:
        "Enable or disable DNS blocking permanently (writes only `enableBlocking`).",
      arguments: BlockingSetStateArgs,
      execute: async (
        args: z.infer<typeof BlockingSetStateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Setting blocking state", { enable: args.enable });
        const r = await apiCall(g, "POST", "/settings/set", {
          enableBlocking: args.enable,
        });
        const handle = await context.writeResource(
          "settings",
          "current",
          extractSettings(r, new Date().toISOString()),
        );
        return { dataHandles: [handle] };
      },
    },

    blocking_temporary_disable: {
      description:
        "Temporarily disable blocking for N minutes; it re-enables automatically afterwards.",
      arguments: BlockingTempDisableArgs,
      execute: async (
        args: z.infer<typeof BlockingTempDisableArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Temporarily disabling blocking", {
          minutes: args.minutes,
        });
        const r = await apiCall(
          g,
          "GET",
          "/settings/temporaryDisableBlocking",
          {
            minutes: args.minutes,
          },
        );
        const till = asString(pick(r, "temporaryDisableBlockingTill"));
        const handle = await context.writeResource(
          "operationResult",
          "blocking-temporary-disable",
          opResult(
            "blocking_temporary_disable",
            true,
            `${args.minutes}m`,
            till ? `disabled until ${till}` : undefined,
          ),
        );
        return { dataHandles: [handle] };
      },
    },

    blocking_set_lists: {
      description:
        "Set the block-list and/or allow-list URLs (comma-joined; only the lists you provide are changed).",
      arguments: BlockingSetListsArgs,
      execute: async (
        args: z.infer<typeof BlockingSetListsArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        if (!args.blockListUrls && !args.allowListUrls) {
          throw new Error(
            "Provide at least one of blockListUrls / allowListUrls",
          );
        }
        const params: Params = {};
        if (args.blockListUrls) {
          const { joined, tooLong } = joinListUrls(args.blockListUrls);
          if (tooLong.length) {
            logInfo(
              context,
              "Block-list URL(s) exceed Technitium's 255-char limit",
              {
                count: tooLong.length,
              },
            );
          }
          params.blockListUrls = joined;
        }
        if (args.allowListUrls) {
          const { joined, tooLong } = joinListUrls(args.allowListUrls);
          if (tooLong.length) {
            logInfo(
              context,
              "Allow-list URL(s) exceed Technitium's 255-char limit",
              {
                count: tooLong.length,
              },
            );
          }
          params.allowListUrls = joined;
        }
        const r = await apiCall(g, "POST", "/settings/set", params);
        const handle = await context.writeResource(
          "settings",
          "current",
          extractSettings(r, new Date().toISOString()),
        );
        return { dataHandles: [handle] };
      },
    },

    blocking_force_update_lists: {
      description:
        "Force an immediate refresh of all configured block-list URLs.",
      arguments: NoArgs,
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Forcing block-list update");
        await apiCall(g, "POST", "/settings/forceUpdateBlockLists");
        const handle = await context.writeResource(
          "operationResult",
          "blocking-force-update-lists",
          opResult("blocking_force_update_lists", true),
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- zone_ ----------------------------------------------------------
    zone_list: {
      description:
        "List all zones (factory: one `zone` per entry, keyed by zone name).",
      arguments: NoArgs,
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/zones/list");
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const z of coerceArray(r, "zones")) {
          const name = asString(pick(z, "name")) ?? "unnamed";
          handles.push(
            await context.writeResource("zone", `zone-${slug(name)}`, {
              name,
              type: asString(pick(z, "type")),
              disabled: pick(z, "disabled") as boolean | undefined,
              internal: pick(z, "internal") as boolean | undefined,
              dnssecStatus: asString(pick(z, "dnssecStatus")),
              action: "observed",
              observedAt,
            }),
          );
        }
        logInfo(context, "Listed zones", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    zone_create: {
      description: "Create an authoritative zone.",
      arguments: ZoneCreateArgs,
      execute: async (
        args: z.infer<typeof ZoneCreateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Creating zone", { zone: args.zone, type: args.type });
        await apiCall(g, "POST", "/zones/create", {
          zone: args.zone,
          type: args.type,
        });
        const handle = await context.writeResource(
          "zone",
          `zone-${slug(args.zone)}`,
          {
            name: args.zone,
            type: args.type,
            disabled: false,
            action: "created",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    zone_delete: {
      description: "Delete a zone.",
      arguments: ZoneRefArgs,
      execute: async (
        args: z.infer<typeof ZoneRefArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Deleting zone", { zone: args.zone });
        await apiCall(g, "POST", "/zones/delete", { zone: args.zone });
        const handle = await context.writeResource(
          "zone",
          `zone-${slug(args.zone)}`,
          {
            name: args.zone,
            action: "deleted",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    zone_enable: {
      description: "Enable a previously disabled zone.",
      arguments: ZoneRefArgs,
      execute: async (
        args: z.infer<typeof ZoneRefArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/zones/enable", { zone: args.zone });
        const handle = await context.writeResource(
          "zone",
          `zone-${slug(args.zone)}`,
          {
            name: args.zone,
            disabled: false,
            action: "updated",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    zone_disable: {
      description: "Disable a zone without deleting it.",
      arguments: ZoneRefArgs,
      execute: async (
        args: z.infer<typeof ZoneRefArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/zones/disable", { zone: args.zone });
        const handle = await context.writeResource(
          "zone",
          `zone-${slug(args.zone)}`,
          {
            name: args.zone,
            disabled: true,
            action: "updated",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- record_ --------------------------------------------------------
    record_list: {
      description:
        "List all records in a zone (factory: one `zoneRecord` per record).",
      arguments: ZoneRefArgs,
      execute: async (
        args: z.infer<typeof ZoneRefArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/zones/records/get", {
          domain: args.zone,
          zone: args.zone,
          listZone: true,
        });
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        let i = 0;
        for (const rec of coerceArray(r, "records")) {
          const name = asString(pick(rec, "name")) ?? args.zone;
          const type = asString(pick(rec, "type")) ?? "UNKNOWN";
          handles.push(
            await context.writeResource(
              "zoneRecord",
              `rec-${slug(args.zone)}-${slug(name)}-${type}-${i++}`,
              {
                zone: args.zone,
                name,
                type,
                ttl: asNumber(pick(rec, "ttl")),
                disabled: pick(rec, "disabled") as boolean | undefined,
                rData:
                  (pick(rec, "rData") as Record<string, unknown> | undefined) ??
                    undefined,
                action: "observed",
                observedAt,
              },
            ),
          );
        }
        logInfo(context, "Listed zone records", {
          zone: args.zone,
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    record_add: {
      description:
        "Add a record. `rData` carries the type-specific fields (e.g. { ipAddress } for A, { cname } for CNAME, { exchange, preference } for MX).",
      arguments: RecordAddArgs,
      execute: async (
        args: z.infer<typeof RecordAddArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const params: Params = { domain: args.domain, type: args.type };
        if (args.zone) params.zone = args.zone;
        if (args.ttl !== undefined) params.ttl = args.ttl;
        spreadRData(params, args.rData);
        logInfo(context, "Adding record", {
          domain: args.domain,
          type: args.type,
        });
        await apiCall(g, "POST", "/zones/records/add", params);
        const zone = args.zone ?? args.domain;
        const handle = await context.writeResource(
          "zoneRecord",
          `rec-${slug(zone)}-${slug(args.domain)}-${args.type}`,
          {
            zone,
            name: args.domain,
            type: args.type,
            ttl: args.ttl,
            rData: args.rData,
            action: "created",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    record_update: {
      description:
        "Update a record. `rData` identifies the existing record; `newRData` carries the new values (mapped to Technitium's new* params).",
      arguments: RecordUpdateArgs,
      execute: async (
        args: z.infer<typeof RecordUpdateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const params: Params = { domain: args.domain, type: args.type };
        if (args.zone) params.zone = args.zone;
        if (args.ttl !== undefined) params.ttl = args.ttl;
        if (args.newDomain) params.newDomain = args.newDomain;
        spreadRData(params, args.rData);
        if (args.newRData) Object.assign(params, prefixNew(args.newRData));
        logInfo(context, "Updating record", {
          domain: args.domain,
          type: args.type,
        });
        await apiCall(g, "POST", "/zones/records/update", params);
        const zone = args.zone ?? args.domain;
        const handle = await context.writeResource(
          "zoneRecord",
          `rec-${slug(zone)}-${
            slug(args.newDomain ?? args.domain)
          }-${args.type}`,
          {
            zone,
            name: args.newDomain ?? args.domain,
            type: args.type,
            ttl: args.ttl,
            rData: args.newRData ?? args.rData,
            action: "updated",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    record_delete: {
      description:
        "Delete a record. `rData` identifies which record (e.g. { ipAddress }).",
      arguments: RecordDeleteArgs,
      execute: async (
        args: z.infer<typeof RecordDeleteArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const params: Params = { domain: args.domain, type: args.type };
        if (args.zone) params.zone = args.zone;
        spreadRData(params, args.rData);
        logInfo(context, "Deleting record", {
          domain: args.domain,
          type: args.type,
        });
        await apiCall(g, "POST", "/zones/records/delete", params);
        const zone = args.zone ?? args.domain;
        const handle = await context.writeResource(
          "zoneRecord",
          `rec-${slug(zone)}-${slug(args.domain)}-${args.type}`,
          {
            zone,
            name: args.domain,
            type: args.type,
            rData: args.rData,
            action: "deleted",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- allowed_ / blocked_ -------------------------------------------
    allowed_add: {
      description: "Add a domain to the built-in Allowed zone.",
      arguments: DomainArgs,
      execute: async (
        args: z.infer<typeof DomainArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/allowed/add", { domain: args.domain });
        const handle = await context.writeResource(
          "listEntry",
          `allowed-${slug(args.domain)}`,
          {
            list: "allowed",
            domain: args.domain,
            action: "created",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    allowed_delete: {
      description: "Remove a domain from the built-in Allowed zone.",
      arguments: DomainArgs,
      execute: async (
        args: z.infer<typeof DomainArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/allowed/delete", { domain: args.domain });
        const handle = await context.writeResource(
          "listEntry",
          `allowed-${slug(args.domain)}`,
          {
            list: "allowed",
            domain: args.domain,
            action: "deleted",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    allowed_list: {
      description:
        "List domains in the built-in Allowed zone (factory: one `listEntry` per domain).",
      arguments: DomainOptArgs,
      execute: async (
        args: z.infer<typeof DomainOptArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/allowed/list", {
          domain: args.domain,
        });
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const d of namesFrom(r, "zones", "records")) {
          handles.push(
            await context.writeResource("listEntry", `allowed-${slug(d)}`, {
              list: "allowed",
              domain: d,
              action: "observed",
              observedAt,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },

    allowed_flush: {
      description: "Remove all domains from the built-in Allowed zone.",
      arguments: NoArgs,
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/allowed/flush");
        const handle = await context.writeResource(
          "operationResult",
          "allowed-flush",
          opResult("allowed_flush", true),
        );
        return { dataHandles: [handle] };
      },
    },

    blocked_add: {
      description: "Add a domain to the built-in Blocked zone.",
      arguments: DomainArgs,
      execute: async (
        args: z.infer<typeof DomainArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/blocked/add", { domain: args.domain });
        const handle = await context.writeResource(
          "listEntry",
          `blocked-${slug(args.domain)}`,
          {
            list: "blocked",
            domain: args.domain,
            action: "created",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    blocked_delete: {
      description: "Remove a domain from the built-in Blocked zone.",
      arguments: DomainArgs,
      execute: async (
        args: z.infer<typeof DomainArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/blocked/delete", { domain: args.domain });
        const handle = await context.writeResource(
          "listEntry",
          `blocked-${slug(args.domain)}`,
          {
            list: "blocked",
            domain: args.domain,
            action: "deleted",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    blocked_list: {
      description:
        "List domains in the built-in Blocked zone (factory: one `listEntry` per domain).",
      arguments: DomainOptArgs,
      execute: async (
        args: z.infer<typeof DomainOptArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/blocked/list", {
          domain: args.domain,
        });
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const d of namesFrom(r, "zones", "records")) {
          handles.push(
            await context.writeResource("listEntry", `blocked-${slug(d)}`, {
              list: "blocked",
              domain: d,
              action: "observed",
              observedAt,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },

    blocked_flush: {
      description: "Remove all domains from the built-in Blocked zone.",
      arguments: NoArgs,
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/blocked/flush");
        const handle = await context.writeResource(
          "operationResult",
          "blocked-flush",
          opResult("blocked_flush", true),
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- client_ (debugging, ephemeral) --------------------------------
    client_resolve: {
      description:
        "Resolve a domain via the server's DNS client, for debugging. Output is ephemeral.",
      arguments: ClientResolveArgs,
      execute: async (
        args: z.infer<typeof ClientResolveArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/dnsClient/resolve", {
          server: args.server,
          domain: args.domain,
          type: args.type,
          protocol: args.protocol,
          dnssecValidation: args.dnssecValidation,
        });
        // The parsed DNS datagram (RCODE, Answer, ...) is nested under `result`.
        const result = (pick(r, "result") as Json | undefined) ?? r;
        const handle = await context.writeResource(
          "dnsResponse",
          `resolve-${slug(args.domain)}-${args.type}`,
          {
            ...r,
            server: args.server,
            domain: args.domain,
            type: args.type,
            protocol: args.protocol,
            rcode: asString(pick(result, "RCODE", "rcode")),
            answer:
              (pick(result, "Answer", "answer") as unknown[] | undefined) ??
                undefined,
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- logs_ ----------------------------------------------------------
    logs_query: {
      description:
        "Query recent DNS query logs (factory: one `queryLog` per entry). Requires the Query Logs (Sqlite) DNS app to be installed.",
      arguments: LogsQueryArgs,
      execute: async (
        args: z.infer<typeof LogsQueryArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/logs/query", {
          name: args.appName,
          classPath: args.classPath,
          pageNumber: args.pageNumber,
          entriesPerPage: args.entriesPerPage,
          descendingOrder: args.descendingOrder,
          start: args.start,
          end: args.end,
          clientIpAddress: args.clientIpAddress,
          protocol: args.protocol,
          responseType: args.responseType,
          qname: args.qname,
          qtype: args.qtype,
          qclass: args.qclass,
        });
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        let i = 0;
        for (const e of coerceArray(r, "entries")) {
          handles.push(
            await context.writeResource("queryLog", `log-${i++}`, {
              rowNumber: asNumber(pick(e, "rowNumber")),
              timestamp: asString(pick(e, "timestamp")),
              clientIpAddress: asString(pick(e, "clientIpAddress")),
              protocol: asString(pick(e, "protocol")),
              responseType: asString(pick(e, "responseType")),
              rcode: asString(pick(e, "rcode")),
              qname: asString(pick(e, "qname")),
              qtype: asString(pick(e, "qtype")),
              qclass: asString(pick(e, "qclass")),
              answer: asString(pick(e, "answer")),
              observedAt,
            }),
          );
        }
        logInfo(context, "Queried DNS logs", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    // ----- cache_ ---------------------------------------------------------
    cache_flush: {
      description: "Flush the entire DNS cache.",
      arguments: NoArgs,
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Flushing DNS cache");
        await apiCall(g, "POST", "/cache/flush");
        const handle = await context.writeResource(
          "operationResult",
          "cache-flush",
          opResult("cache_flush", true),
        );
        return { dataHandles: [handle] };
      },
    },

    cache_list: {
      description:
        "List cached zones/records under a domain (factory: one `cacheEntry` per name).",
      arguments: DomainOptArgs,
      execute: async (
        args: z.infer<typeof DomainOptArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/cache/list", {
          domain: args.domain,
        });
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const n of namesFrom(r, "zones")) {
          handles.push(
            await context.writeResource("cacheEntry", `cache-zone-${slug(n)}`, {
              name: n,
              kind: "zone",
              action: "observed",
              observedAt,
            }),
          );
        }
        for (const n of namesFrom(r, "records")) {
          handles.push(
            await context.writeResource("cacheEntry", `cache-rec-${slug(n)}`, {
              name: n,
              kind: "record",
              action: "observed",
              observedAt,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },

    cache_delete: {
      description: "Delete a cached domain entry.",
      arguments: DomainArgs,
      execute: async (
        args: z.infer<typeof DomainArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await apiCall(g, "POST", "/cache/delete", { domain: args.domain });
        const handle = await context.writeResource(
          "operationResult",
          `cache-delete-${slug(args.domain)}`,
          opResult("cache_delete", true, args.domain),
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- dashboard_ -----------------------------------------------------
    dashboard_stats: {
      description: "Get dashboard query statistics for a time range.",
      arguments: DashboardStatsArgs,
      execute: async (
        args: z.infer<typeof DashboardStatsArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/dashboard/stats/get", {
          type: args.type,
          start: args.start,
          end: args.end,
          utc: true,
        });
        const s = (pick(r, "stats") as Json | undefined) ?? {};
        const handle = await context.writeResource(
          "stats",
          `stats-${args.type}`,
          {
            range: args.type,
            totalQueries: asNumber(pick(s, "totalQueries")),
            totalNoError: asNumber(pick(s, "totalNoError")),
            totalServerFailure: asNumber(pick(s, "totalServerFailure")),
            totalNxDomain: asNumber(pick(s, "totalNxDomain")),
            totalRefused: asNumber(pick(s, "totalRefused")),
            totalBlocked: asNumber(pick(s, "totalBlocked")),
            totalCached: asNumber(pick(s, "totalCached")),
            totalClients: asNumber(pick(s, "totalClients")),
            topDomains: pick(r, "topDomains") as unknown[] | undefined,
            topBlockedDomains: pick(r, "topBlockedDomains") as
              | unknown[]
              | undefined,
            topClients: pick(r, "topClients") as unknown[] | undefined,
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- settings_ ------------------------------------------------------
    settings_backup: {
      description:
        "Download a full settings backup (zip) and store it as a `backup` file. May contain secrets.",
      arguments: SettingsBackupArgs,
      execute: async (
        args: z.infer<typeof SettingsBackupArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const flags: Params = {
          blockLists: true,
          zones: true,
          allowedZones: true,
          blockedZones: true,
          scopes: true,
          apps: true,
          dnsApps: true,
          authConfig: true,
          logs: false,
          stats: false,
          ...(args.options ?? {}),
        };
        logInfo(context, "Downloading settings backup");
        const bytes = await apiDownload(g, "/settings/backup", flags);
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");
        const writer = context.createFileWriter("backup", `backup-${stamp}`);
        const handle = await writer.writeAll(bytes);
        return { dataHandles: [handle] };
      },
    },

    settings_restore: {
      description:
        "Restore settings from a local backup zip (multipart upload). Verify the file before running this.",
      arguments: SettingsRestoreArgs,
      execute: async (
        args: z.infer<typeof SettingsRestoreArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const flags: Params = {
          blockLists: true,
          zones: true,
          allowedZones: true,
          blockedZones: true,
          scopes: true,
          apps: true,
          dnsApps: true,
          authConfig: true,
          logs: false,
          stats: false,
          deleteExistingFiles: args.deleteExistingFiles ?? false,
          ...(args.options ?? {}),
        };
        const bytes = new Uint8Array(await readFile(args.filePath));
        logInfo(context, "Restoring settings from backup", {
          bytes: bytes.length,
        });
        await apiUpload(g, "/settings/restore", flags, bytes, "backup.zip");
        const handle = await context.writeResource(
          "operationResult",
          "settings-restore",
          opResult("settings_restore", true, args.filePath),
        );
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
