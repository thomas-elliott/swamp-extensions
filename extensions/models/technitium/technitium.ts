import { z } from "npm:zod@4";
// Type-only imports, erased at compile time and never bundled. They type the
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
 * `@thomas/technitium` manages a Technitium DNS Server entirely through its
 * HTTP API. A permanent API token, sent only as an `Authorization: Bearer`
 * header (Technitium 15 and later), is the only credential; the extension
 * never touches the server host directly. Every mutation goes through the API.
 *
 * Only a named subset of the server settings is stored as data: blocking,
 * web-service TLS, DNSSEC validation and DNS-over-TLS. The full settings object
 * is NOT passed through, so it cannot leak secrets (e.g. TLS certificate
 * passwords) into the data model.
 */

const GlobalArgs = z.object({
  baseUrl: z.string().describe(
    "Technitium base URL including port, e.g. https://dns.example:5380",
  ),
  apiToken: z.string().meta({ sensitive: true }).describe(
    "Permanent Technitium API token. Supply via vault: ${{ vault.get(technitium, api_token) }}",
  ),
  skipTlsVerify: z.boolean().default(false).describe(
    "Turn off TLS certificate verification entirely (default false). This " +
      "accepts a self-signed cert, but also any cert for any hostname.",
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
  catalog: z.string().optional().describe(
    "Name of the catalog zone this zone is a member of, if any",
  ),
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
  blockListUrlUpdateIntervalHours: z.number().optional().describe(
    "Hours between automatic block-list downloads (Technitium's `blockListUpdateIntervalHours`)",
  ),
  // Web-service TLS and resolver security settings (read-only copy; the
  // cert password is never included).
  webServiceEnableTls: z.boolean().optional().describe(
    "Whether the admin web service serves HTTPS (on webServiceTlsPort)",
  ),
  webServiceTlsPort: z.number().optional(),
  webServiceUseSelfSignedTlsCertificate: z.boolean().optional().describe(
    "true = self-signed cert (browsers reject); false = uses webServiceTlsCertificatePath",
  ),
  webServiceTlsCertificatePath: z.string().optional().describe(
    "PKCS#12 cert path on the server (relative paths resolve against the config dir)",
  ),
  webServiceHttpToTlsRedirect: z.boolean().optional().describe(
    "Whether plaintext HTTP requests are redirected to HTTPS",
  ),
  dnssecValidation: z.boolean().optional().describe(
    "Whether the resolver validates DNSSEC signatures on upstream answers",
  ),
  enableDnsOverTls: z.boolean().optional().describe(
    "Whether DNS-over-TLS is enabled (dnsOverTlsPort, default 853)",
  ),
  observedAt: z.string(),
});

const StatsResource = z.object({
  range: z.string().describe("LastHour | LastDay | LastWeek | ... | Custom"),
  start: z.string().optional().describe("Start of a Custom range, as given"),
  end: z.string().optional().describe("End of a Custom range, as given"),
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
});

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
  result: z.unknown().optional().describe(
    "The parsed DNS response as Technitium returns it",
  ),
  rawResponses: z.array(z.unknown()).optional(),
  observedAt: z.string(),
});

const QueryLogResource = z.object({
  rowNumber: z.number().optional().describe(
    "Position in the query's results when last read; not an id",
  ),
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
});

const QueryLogPageResource = z.object({
  pageNumber: z.number().optional(),
  totalPages: z.number().optional(),
  totalEntries: z.number().optional().describe(
    "Entries the query matched across all pages",
  ),
  entriesOnPage: z.number(),
  observedAt: z.string(),
});

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
/** A parsed JSON object. */
export type Json = Record<string, unknown>;
/** An HTTP verb used by the Technitium transport. */
export type HttpMethod = "GET" | "POST";
/** Query/form parameters for a Technitium API call. */
export type Params = Record<string, string | number | boolean | undefined>;
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
  const o = parsed && typeof parsed === "object" && !Array.isArray(parsed)
    ? parsed as Json
    : undefined;
  // Every Technitium API reply carries `status`. A 200 without one is
  // something else answering, such as a proxy's login page, and must not
  // count as success.
  if (o?.status === undefined) {
    throw new Error(
      `Technitium ${context}: the reply is not a Technitium API response ` +
        "(no status field); check baseUrl and anything proxying it",
    );
  }
  if (o.status !== "ok") {
    const msg = typeof o.errorMessage === "string" && o.errorMessage
      ? o.errorMessage
      : String(o.status);
    throw new Error(`Technitium ${context}: ${msg}`);
  }
  const resp = o.response;
  if (resp && typeof resp === "object" && !Array.isArray(resp)) {
    return resp as Json;
  }
  return {};
}

/** Signature of the Technitium HTTP transport, swappable via {@link __setTechnitiumTransport}. */
export type TechFn = (
  g: Json,
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
 * Build the request URL and headers for a Technitium API call. The token goes
 * only in the `Authorization: Bearer` header, never the URL, so it stays out
 * of proxy and access logs. Technitium before 15 needs it in the URL and is
 * not supported.
 */
export function buildRequest(
  g: { baseUrl: string; apiToken: string },
  path: string,
  query: Params,
): { url: URL; headers: Record<string, string>; secure: boolean } {
  const u = new URL(g.baseUrl.replace(/\/+$/, "") + API + path);
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
 * Where `http.request` should connect for `url`. `URL.hostname` keeps the
 * brackets around an IPv6 literal (`[::1]`), which `http.request` would try to
 * resolve as a hostname and fail, so they are removed.
 */
export function requestTarget(
  url: URL,
): { hostname: string; port: number; path: string } {
  const secure = url.protocol === "https:";
  return {
    hostname: url.hostname.replace(/^\[(.*)\]$/, "$1"),
    port: url.port ? parseInt(url.port, 10) : (secure ? 443 : 80),
    path: url.pathname + url.search,
  };
}

/**
 * Call a Technitium API path (relative to `/api`) that returns the JSON
 * envelope. GET params go in the query string; POST params go in an
 * `application/x-www-form-urlencoded` body (so long block-list URLs don't exceed
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
      ...requestTarget(url),
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
      ...requestTarget(url),
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
  // Anything that is not a zip (a JSON error, a proxy's login page) is not a
  // backup, however it was served.
  if (!isZip(res.body)) {
    throw new Error(
      `Technitium GET ${path}: the reply is not a zip file: ${
        res.body.subarray(0, 200).toString("utf8")
      }`,
    );
  }
  return new Uint8Array(res.body);
}

/** Does `bytes` start with "PK", the signature every zip file starts with? */
function isZip(bytes: Uint8Array): boolean {
  return bytes[0] === 0x50 && bytes[1] === 0x4b;
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
      ...requestTarget(url),
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
 * The data instance name for a record of `spec`: `<spec>:<key>`, or `<spec>`
 * alone for a one-per-model record. swamp keys stored data by model + instance
 * name, not by spec, so the spec prefix stops two specs overwriting each other.
 */
export function dataName(spec: string, key?: string): string {
  return key === undefined ? spec : `${spec}:${key}`;
}

/**
 * A DNS name as a data-name key. DNS names are case-insensitive and Technitium
 * ignores a trailing dot, so both are normalised. Dots stay as they are. `%`,
 * `:`, `/` and `\` are percent-escaped: swamp rejects `/` and `\` (which a
 * classless reverse name such as `0/26.2.0.192.in-addr.arpa` can contain), and
 * escaping `:` keeps the `:`-separated parts of a record key unambiguous.
 */
export function dnsKey(name: string): string {
  return name.toLowerCase().replace(/\.$/, "").replace(
    /[%:/\\]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase(),
  );
}

/**
 * Deterministic short hash (FNV-1a → base36) of a record's rData. Values are
 * hashed as the server returns them, case and all (TXT data is case-sensitive),
 * and nested values (SVCB params, APL lists) as JSON.
 */
function rDataHash(rData?: Record<string, unknown>): string {
  return shortHash(canonicalRData(rData));
}

/** Deterministic short hash (FNV-1a → base36) of a string. */
function shortHash(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(36).padStart(7, "0");
}

/** rData as a key-order-independent string, so two copies of one record compare equal. */
function canonicalRData(rData?: Record<string, unknown>): string {
  return rData
    ? JSON.stringify(Object.keys(rData).sort().map((k) => [k, rData[k]]))
    : "";
}

/**
 * The data name for a zone record, shared by every record method:
 * `zoneRecord:<zone>:<name>:<TYPE>:<rData hash>`. DNS records have no id, so
 * the key is the record itself. Every writer passes the record as Technitium
 * returns it (not the caller's rData), so one record has one name whichever
 * method wrote it, and two records at one name (e.g. two A records) differ.
 */
export function recordInstanceName(
  zone: string,
  name: string,
  type: string,
  rData?: Record<string, unknown>,
): string {
  return dataName(
    "zoneRecord",
    `${dnsKey(zone)}:${dnsKey(name)}:${type.toUpperCase()}:${rDataHash(rData)}`,
  );
}

/** Pull an array out of a Technitium response under any of the given keys. */
export function coerceArray(resp: Json, ...keys: string[]): Json[] {
  for (const k of keys) {
    if (Array.isArray(resp[k])) return resp[k] as Json[];
  }
  return [];
}

/**
 * Collect distinct domain names from a Technitium list response. Entries may be
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
    // settings/set removes every URL when sent `false`; an empty value is
    // not how the API clears a list.
    joined: urls.length === 0 ? "false" : urls.join(","),
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

/**
 * CNAME and DNAME records have no `new*` update params. A name holds at most
 * one of each, and `records/update` replaces it with the target sent as
 * `cname`/`dname`.
 */
function hasNoNewParams(type: string): boolean {
  return ["CNAME", "DNAME"].includes(type.toUpperCase());
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

/**
 * Map an APP record's rData to Technitium's APP write params for add/update.
 * APP content is carried under the `data` key (that's how `record_list` returns
 * it), but Technitium's write endpoints read it from `recordData`, and the app
 * is identified by `appName` + `classPath`. APP records use NO `new*` scheme:
 * the new content goes in `recordData` and the record is matched by domain+type.
 * Spreading the keys verbatim (as `spreadRData` does) sends an unrecognized
 * `data` param, so Technitium writes the record with empty data → SERVFAIL.
 */
function spreadAppRData(into: Params, rData?: Record<string, unknown>): Params {
  if (!rData) return into;
  // `data` is the key record_list reads APP content back under; accept the
  // Technitium-native `recordData` too for callers working straight from its docs.
  const recordData = rData.recordData ?? rData.data;
  if (rData.appName !== undefined && rData.appName !== null) {
    into.appName = rData.appName as string;
  }
  if (rData.classPath !== undefined && rData.classPath !== null) {
    into.classPath = rData.classPath as string;
  }
  if (recordData !== undefined && recordData !== null) {
    into.recordData = recordData as string;
  }
  return into;
}

type LiveRecord = {
  name: string;
  type: string;
  ttl?: number;
  disabled?: boolean;
  comments?: string;
  expiryTtl?: number;
  rData?: Record<string, unknown>;
};

/**
 * A record as Technitium writes it in JSON (`records/get`, `addedRecord`,
 * `updatedRecord`). A FWD record's `proxyPassword` is dropped: Technitium
 * returns it in clear, and this record is what gets stored as data.
 */
function toLiveRecord(rec: Json, fallbackName: string): LiveRecord {
  const rData = pick(rec, "rData") as Record<string, unknown> | undefined;
  let stored = rData;
  if (rData && "proxyPassword" in rData) {
    const { proxyPassword: _secret, ...rest } = rData;
    stored = rest;
  }
  return {
    name: asString(pick(rec, "name")) ?? fallbackName,
    type: asString(pick(rec, "type")) ?? "UNKNOWN",
    ttl: asNumber(pick(rec, "ttl")),
    disabled: pick(rec, "disabled") as boolean | undefined,
    comments: asString(pick(rec, "comments")),
    expiryTtl: asNumber(pick(rec, "expiryTtl")),
    rData: stored,
  };
}

/**
 * The record a write response says the server stored: `addedRecord` from
 * `records/add`, `updatedRecord` from `records/update`. Undefined when the
 * response does not carry one.
 */
function writtenRecord(
  resp: Json,
  key: "addedRecord" | "updatedRecord",
  fallbackName: string,
): LiveRecord | undefined {
  const rec = resp[key];
  return rec && typeof rec === "object"
    ? toLiveRecord(rec as Json, fallbackName)
    : undefined;
}

/**
 * The live records at one domain, and the zone that holds them as Technitium
 * reports it. Without an explicit `zone` that is the only way to know it: the
 * domain `www.example.com` lives in zone `example.com`.
 */
async function getDomainRecords(
  g: GlobalArgsT,
  domain: string,
  zone?: string,
): Promise<{ zone: string; records: LiveRecord[] }> {
  const params: Params = { domain, listZone: false };
  if (zone) params.zone = zone;
  const r = await apiCall(g, "GET", "/zones/records/get", params);
  const zoneInfo = (r.zone ?? {}) as Json;
  return {
    zone: asString(pick(zoneInfo, "name")) ?? zone ?? domain,
    records: coerceArray(r, "records").map((rec) => toLiveRecord(rec, domain)),
  };
}

/**
 * Write parameters that Technitium reads back under another name. The add,
 * update and delete endpoints take a type prefix that the record's JSON drops
 * (`WriteRecordAsJson` in Technitium's `WebServiceZonesApi.cs`).
 */
const READ_KEY: Record<string, string> = {
  naptrOrder: "order",
  naptrPreference: "preference",
  naptrFlags: "flags",
  naptrServices: "services",
  naptrRegexp: "regexp",
  naptrReplacement: "replacement",
  sshfpAlgorithm: "algorithm",
  sshfpFingerprintType: "fingerprintType",
  sshfpFingerprint: "fingerprint",
  tlsaCertificateUsage: "certificateUsage",
  tlsaSelector: "selector",
  tlsaMatchingType: "matchingType",
  tlsaCertificateAssociationData: "certificateAssociationData",
  uriPriority: "priority",
  uriWeight: "weight",
  forwarderPriority: "priority",
};

/**
 * DS, SSHFP and TLSA fields that Technitium accepts as a number or a name but
 * always reads back as the name, keyed by record type and read-shape field.
 * The names are the enum names in TechnitiumLibrary (`DnssecAlgorithm`,
 * `DnssecDigestType`, `DnsSSHFPAlgorithm`, `DnsSSHFPFingerprintType`,
 * `DnsTLSACertificateUsage`, `DnsTLSASelector`, `DnsTLSAMatchingType`). A
 * number missing here is read back as the number, so it still compares equal.
 */
const ENUM_NAMES: Record<string, Record<string, Record<number, string>>> = {
  DS: {
    algorithm: {
      0: "Unknown",
      1: "RSAMD5",
      3: "DSA",
      5: "RSASHA1",
      6: "DSA_NSEC3_SHA1",
      7: "RSASHA1_NSEC3_SHA1",
      8: "RSASHA256",
      10: "RSASHA512",
      12: "ECC_GOST",
      13: "ECDSAP256SHA256",
      14: "ECDSAP384SHA384",
      15: "ED25519",
      16: "ED448",
      253: "PRIVATEDNS",
      254: "PRIVATEOID",
    },
    digestType: {
      0: "Unknown",
      1: "SHA1",
      2: "SHA256",
      3: "GOST_R_34_11_94",
      4: "SHA384",
    },
  },
  SSHFP: {
    algorithm: {
      0: "Reserved",
      1: "RSA",
      2: "DSA",
      3: "ECDSA",
      4: "Ed25519",
      6: "Ed448",
    },
    fingerprintType: { 0: "Reserved", 1: "SHA1", 2: "SHA256" },
  },
  TLSA: {
    certificateUsage: {
      0: "PKIX_TA",
      1: "PKIX_EE",
      2: "DANE_TA",
      3: "DANE_EE",
      255: "PrivCert",
    },
    selector: { 0: "Cert", 1: "SPKI", 255: "PrivSel" },
    matchingType: {
      0: "Full",
      1: "SHA2_256",
      2: "SHA2_512",
      255: "PrivMatch",
    },
  },
};

/**
 * A caller's enum value in the form Technitium reads it back: a number becomes
 * its name. Technitium prints some names with `-` for `_` (TLSA `PKIX-TA`) and
 * accepts either on write, so both sides compare with `_`.
 */
function enumComparable(
  type: string,
  key: string,
  v: unknown,
): string | undefined {
  const names = ENUM_NAMES[type.toUpperCase()]?.[key];
  if (!names) return undefined;
  const s = String(v ?? "").trim();
  const name = /^\d+$/.test(s) ? names[Number(s)] ?? s : s;
  return name.toLowerCase().replace(/-/g, "_");
}

/** Write options that change how a record is added but are not part of it. */
const WRITE_ONLY_PARAMS = new Set([
  "ptr",
  "createPtrZone",
  "glue",
  "updateSvcbHints",
  "overwrite",
]);

/**
 * One rData value in a form the caller's and the server's copies agree on.
 * Technitium trims a trailing dot from names, prints hex in capitals and
 * prints IPv6 addresses compressed. TXT text is case-sensitive, so it is
 * compared as it is.
 */
function comparableValue(key: string, v: unknown): string {
  const s = String(v ?? "");
  if (key === "text") return s;
  if (key === "ipAddress" && s.includes(":")) {
    // The URL parser prints an IPv6 address in the same compressed form.
    try {
      return new URL(`http://[${s}]`).hostname;
    } catch {
      return s;
    }
  }
  return s.toLowerCase().replace(/\.$/, "");
}

/**
 * Does a live `type` record's rData satisfy every field in `want`? `want` is
 * the caller's rData, in the write endpoints' parameter names and as typed, so
 * each field is renamed and normalised to the read shape first, and a DS,
 * SSHFP or TLSA enum given as a number is compared by its name. Write-only
 * options are skipped, and so are structured live values (SVCB `svcParams`,
 * APL lists): the caller sends those as a string the server parses. APP
 * content is reported under `data` but written via `recordData`, so the two
 * compare equal.
 */
function rDataMatches(
  want: Record<string, unknown> | undefined,
  live: Record<string, unknown> | undefined,
  type: string,
): boolean {
  if (!want) return true;
  const got = live ?? {};
  const eq = (a: unknown, b: unknown) => String(a ?? "") === String(b ?? "");
  if (type.toUpperCase() === "APP") {
    const wantData = want.recordData ?? want.data;
    return (want.appName == null || eq(got.appName, want.appName)) &&
      (want.classPath == null || eq(got.classPath, want.classPath)) &&
      (wantData == null || eq(got.recordData ?? got.data, wantData));
  }
  for (const [k, v] of Object.entries(want)) {
    if (v === undefined || v === null || WRITE_ONLY_PARAMS.has(k)) continue;
    const key = READ_KEY[k] ?? k;
    const liveValue = got[key];
    if (typeof liveValue === "object" && liveValue !== null) continue;
    const wantEnum = enumComparable(type, key, v);
    if (wantEnum !== undefined) {
      if (enumComparable(type, key, liveValue) !== wantEnum) return false;
    } else if (comparableValue(key, liveValue) !== comparableValue(key, v)) {
      return false;
    }
  }
  return true;
}

/**
 * Read the record back after a mutation and assert it reflects the intended
 * state. Technitium can return `ok` while writing empty data, and an APP record
 * with empty data makes the whole zone answer SERVFAIL: for add/update assert a `type` record
 * matching the write now exists at `domain`; for delete assert none remains. Throws
 * on mismatch so the method reports an error instead of success. Returns the
 * zone Technitium reports and, for add/update, the matching live record, so the
 * caller names its data from the server's record as `record_list` does.
 *
 * `known` is the server's own copy of the record when the caller has one: the
 * record a write response returned, or the record read before a delete. It is
 * compared exactly, since both copies come from the same server code. Without
 * it the caller's `want` is compared field by field. APP records always
 * compare `want`, since that is what catches the empty-data write.
 */
async function verifyRecordWrite(
  g: GlobalArgsT,
  op: "added" | "updated" | "deleted",
  domain: string,
  type: string,
  want: Record<string, unknown> | undefined,
  zone?: string,
  known?: LiveRecord,
): Promise<{ zone: string; record?: LiveRecord }> {
  const live = await getDomainRecords(g, domain, zone);
  const matched = known && type.toUpperCase() !== "APP"
    ? live.records.find((r) =>
      r.type.toUpperCase() === type.toUpperCase() &&
      canonicalRData(r.rData) === canonicalRData(known.rData)
    )
    : findRecord(live.records, type, want);
  if (op === "deleted") {
    if (matched) {
      throw new Error(
        `Post-delete read-back failed: a ${type} record at ${domain} still ` +
          `matches the deleted data — Technitium reported success but the record persists.`,
      );
    }
    return { zone: live.zone };
  }
  if (!matched) {
    throw new Error(
      `Post-${op} read-back failed: no ${type} record at ${domain} matches the ` +
        `intended data — Technitium reported success but the live record is missing ` +
        `or has different/empty data (e.g. an APP record written with empty recordData).`,
    );
  }
  return { zone: live.zone, record: matched };
}

/** The first live `type` record whose rData satisfies `want`. */
function findRecord(
  records: LiveRecord[],
  type: string,
  want: Record<string, unknown> | undefined,
): LiveRecord | undefined {
  return records
    .filter((r) => r.type.toUpperCase() === type.toUpperCase())
    .find((r) => rDataMatches(want, r.rData, type));
}

/** A record after a write, as the server stored it, ready to name and store. */
type WrittenRecord = {
  zone: string;
  name: string;
  ttl?: number;
  disabled?: boolean;
  rData?: Record<string, unknown>;
};

/**
 * Add a record and read it back. With `overwrite`, Technitium replaces every
 * record of the type at the name with this one.
 */
async function addRecord(
  g: GlobalArgsT,
  args: z.infer<typeof RecordAddArgs>,
  overwrite = false,
): Promise<WrittenRecord> {
  const params: Params = { domain: args.domain, type: args.type };
  if (args.zone) params.zone = args.zone;
  if (args.ttl !== undefined) params.ttl = args.ttl;
  if (overwrite) params.overwrite = true;
  if (args.type.toUpperCase() === "APP") {
    spreadAppRData(params, args.rData);
  } else {
    spreadRData(params, args.rData);
  }
  const resp = await apiCall(g, "POST", "/zones/records/add", params);
  // Name and store the record as Technitium reports it, so the name
  // matches the one record_list and record_get write.
  const { zone, record } = await verifyRecordWrite(
    g,
    "added",
    args.domain,
    args.type,
    args.rData,
    args.zone,
    writtenRecord(resp, "addedRecord", args.domain),
  );
  return {
    zone,
    name: record?.name ?? args.domain,
    // The server's TTL, which is its default when none was passed.
    ttl: record?.ttl ?? args.ttl,
    disabled: record?.disabled,
    rData: record?.rData ?? args.rData,
  };
}

/** Update a record, keeping the fields not passed, and read it back. */
async function updateRecord(
  g: GlobalArgsT,
  args: z.infer<typeof RecordUpdateArgs>,
): Promise<WrittenRecord> {
  const isApp = args.type.toUpperCase() === "APP";
  // `records/update` resets every field it is not sent: ttl to the server
  // default, disable to false, comments and expiryTtl to empty. Read the
  // record first so changing one field leaves the others as they were.
  // APP records are matched by domain+type alone (only one exists per name).
  const existing = (await getDomainRecords(g, args.domain, args.zone))
    .records.filter((r) => r.type.toUpperCase() === args.type.toUpperCase())
    .find((r) => isApp || rDataMatches(args.rData, r.rData, args.type));
  if (!existing) {
    throw new Error(
      `record_update: no ${args.type} record at ${args.domain} matches the given rData`,
    );
  }
  const ttl = args.ttl ?? existing.ttl;
  const disable = args.disable ?? existing.disabled;
  const comments = args.comments ?? existing.comments;
  const expiryTtl = args.expiryTtl ?? existing.expiryTtl;
  const params: Params = { domain: args.domain, type: args.type };
  if (args.zone) params.zone = args.zone;
  if (ttl !== undefined) params.ttl = ttl;
  if (disable !== undefined) params.disable = disable;
  if (comments !== undefined) params.comments = comments;
  if (expiryTtl !== undefined) params.expiryTtl = expiryTtl;
  if (args.newDomain) params.newDomain = args.newDomain;
  // An APP update rewrites the whole record from the params, and a
  // missing `recordData` becomes empty data. Start from the record as it
  // is, so a `newRData` without `data` (or none at all) keeps the content.
  const appRData = isApp
    ? { ...existing.rData, ...(args.newRData ?? args.rData) }
    : undefined;
  if (isApp) {
    // APP records have no `new*` params: write the desired final state directly.
    spreadAppRData(params, appRData);
  } else if (hasNoNewParams(args.type)) {
    // Technitium has no newCname/newDname: it reads the new target from
    // `cname`/`dname` and replaces the name's only record with it.
    spreadRData(params, args.newRData ?? args.rData);
  } else {
    spreadRData(params, args.rData);
    if (args.newRData) Object.assign(params, prefixNew(args.newRData));
  }
  const resp = await apiCall(g, "POST", "/zones/records/update", params);
  // Name and store the record as Technitium reports it (see addRecord).
  const { zone, record } = await verifyRecordWrite(
    g,
    "updated",
    args.newDomain ?? args.domain,
    args.type,
    appRData ?? args.newRData ?? args.rData,
    args.zone,
    writtenRecord(resp, "updatedRecord", args.newDomain ?? args.domain),
  );
  return {
    zone,
    name: record?.name ?? args.newDomain ?? args.domain,
    ttl,
    disabled: disable,
    rData: record?.rData ?? args.newRData ?? args.rData,
  };
}

/** Store a record as `zoneRecord` under the name every record method uses. */
function writeZoneRecord(
  context: Pick<MethodContext<GlobalArgsT>, "writeResource">,
  rec: WrittenRecord,
  type: string,
  action: z.infer<typeof Action>,
): Promise<DataHandle> {
  return context.writeResource(
    "zoneRecord",
    recordInstanceName(rec.zone, rec.name, type, rec.rData),
    {
      zone: rec.zone,
      name: rec.name,
      type,
      ttl: rec.ttl,
      disabled: rec.disabled,
      rData: rec.rData,
      action,
      observedAt: new Date().toISOString(),
    },
  );
}

/**
 * Every domain in the built-in Allowed or Blocked zone at or under `root`.
 * `/allowed/list` and `/blocked/list` browse a label tree one node at a time:
 * `zones` holds the node's children as full names, and `records` is non-empty
 * when the node is itself an entry. The server skips nodes with one child and
 * no entry, and reports the node it stopped at as `domain`.
 */
async function listZoneEntries(
  g: GlobalArgsT,
  list: "allowed" | "blocked",
  root?: string,
): Promise<string[]> {
  const entries: string[] = [];
  const visited = new Set<string>();
  const pending: (string | undefined)[] = [root];
  while (pending.length > 0) {
    const r = await apiCall(g, "GET", `/${list}/list`, {
      domain: pending.pop(),
    });
    const node = asString(pick(r, "domain")) ?? "";
    // A tree has no cycles, but a server that repeated a node would loop forever.
    if (visited.has(node)) continue;
    visited.add(node);
    if (node !== "" && coerceArray(r, "records").length > 0) entries.push(node);
    pending.push(...(toStringArray(r.zones) ?? []));
  }
  return entries.sort();
}

type ZoneFields = Omit<z.infer<typeof ZoneResource>, "action" | "observedAt">;

/** The stored fields of a zone as Technitium describes it (`zones/list`, `records/get`). */
function zoneFields(z: Json): ZoneFields {
  return {
    name: asString(pick(z, "name")) ?? "unnamed",
    type: asString(pick(z, "type")),
    disabled: pick(z, "disabled") as boolean | undefined,
    internal: pick(z, "internal") as boolean | undefined,
    dnssecStatus: asString(pick(z, "dnssecStatus")),
    catalog: asString(pick(z, "catalog")),
  };
}

/**
 * Read one zone's description from the server, so zone methods can store the
 * whole zone rather than only the field they changed. `records/get` at the
 * zone apex returns it. That endpoint falls back to the closest enclosing zone
 * when the named one does not exist, so a different name means "not found",
 * as does its "No such zone" error. Undefined when the zone does not exist.
 */
async function readZone(
  g: GlobalArgsT,
  zone: string,
): Promise<ZoneFields | undefined> {
  let r: Json;
  try {
    r = await apiCall(g, "GET", "/zones/records/get", {
      domain: zone,
      zone,
      listZone: false,
    });
  } catch (e) {
    // With no enclosing zone either, the server answers with this error.
    if ((e as Error).message.includes("No such zone was found")) {
      return undefined;
    }
    throw e;
  }
  const fields = zoneFields((r.zone ?? {}) as Json);
  return dnsKey(fields.name) === dnsKey(zone) ? fields : undefined;
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

/**
 * Reject list URLs that `blockListUrls` cannot hold as given. The setting is
 * one comma-separated string in which a leading `!` marks an allow list, so a
 * URL with a comma would be split in two, a block URL starting with `!` would
 * become an allow list, and an allow URL passed with its `!` would get a second.
 */
export function checkListUrls(block?: string[], allow?: string[]): void {
  const problems: string[] = [];
  for (const u of [...(block ?? []), ...(allow ?? [])]) {
    if (u.includes(",")) problems.push(`${u} contains a comma`);
  }
  for (const u of block ?? []) {
    if (u.startsWith("!")) {
      problems.push(
        `${u} starts with "!"; pass it in allowListUrls without it`,
      );
    }
  }
  for (const u of allow ?? []) {
    if (u.startsWith("!")) {
      problems.push(`${u} starts with "!"; pass allow-list URLs without it`);
    }
  }
  if (problems.length > 0) {
    throw new Error(`Invalid list URL(s): ${problems.join("; ")}`);
  }
}

/**
 * Split Technitium's single `blockListUrls` setting into block and allow lists.
 * Technitium has no separate allow-list setting: an allow list is an entry in
 * `blockListUrls` with a `!` in front.
 */
function splitListUrls(r: Json): { block: string[]; allow: string[] } {
  const all = toStringArray(pick(r, "blockListUrls")) ?? [];
  return {
    block: all.filter((u) => !u.startsWith("!")),
    allow: all.filter((u) => u.startsWith("!")).map((u) => u.slice(1)),
  };
}

/**
 * Extract the stored subset of a Technitium settings response: blocking,
 * web-service TLS, DNSSEC validation and DNS-over-TLS.
 */
function extractSettings(
  r: Json,
  observedAt: string,
): z.infer<typeof SettingsResource> {
  const lists = splitListUrls(r);
  return {
    enableBlocking: pick(r, "enableBlocking") as boolean | undefined,
    temporaryDisableBlockingTill: asString(
      pick(r, "temporaryDisableBlockingTill"),
    ),
    blockListUrls: lists.block,
    allowListUrls: lists.allow,
    blockListUrlUpdateIntervalHours: asNumber(
      pick(r, "blockListUpdateIntervalHours"),
    ),
    webServiceEnableTls: pick(r, "webServiceEnableTls") as boolean | undefined,
    webServiceTlsPort: asNumber(pick(r, "webServiceTlsPort")),
    webServiceUseSelfSignedTlsCertificate: pick(
      r,
      "webServiceUseSelfSignedTlsCertificate",
    ) as boolean | undefined,
    webServiceTlsCertificatePath: asString(
      pick(r, "webServiceTlsCertificatePath"),
    ),
    webServiceHttpToTlsRedirect: pick(
      r,
      "webServiceHttpToTlsRedirect",
    ) as boolean | undefined,
    dnssecValidation: pick(r, "dnssecValidation") as boolean | undefined,
    enableDnsOverTls: pick(r, "enableDnsOverTls") as boolean | undefined,
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

/**
 * Structured info log when a logger is present (no-op otherwise). swamp's
 * logger prints only the props named as `{placeholders}` in the message, so
 * every prop worth reading belongs in the message. Never pass secrets.
 */
function logInfo(
  context: Pick<MethodContext<GlobalArgsT>, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.info?.(message, props ?? {});
}

/** As {@link logInfo}, at warning level. */
function logWarning(
  context: Pick<MethodContext<GlobalArgsT>, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.warn?.(message, props ?? {});
}

// Only the types zone_create can make with the arguments it takes. Secondary,
// Stub and the forwarder and secondary catalog types need a primary server or
// a forwarder address.
const ZoneType = z.enum(["Primary", "Catalog"]);

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
const ListEntriesArgs = z.object({
  domain: z.string().optional().describe(
    "List only this domain and the domains under it; the whole zone if omitted",
  ),
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

const WebServiceSetTlsArgs = z.object({
  certificatePath: z.string().optional().describe(
    "PKCS#12 (.pfx/.p12) cert path on the server. Relative paths resolve " +
      "against Technitium's config dir (e.g. `wildcard.example.com.pfx` → /etc/dns).",
  ),
  certificatePassword: z.string().meta({ sensitive: true }).optional().describe(
    "Export password for the PKCS#12 file. Supply via vault expression. " +
      "Without certificatePath it applies to the certificate already configured.",
  ),
  useSelfSignedCertificate: z.boolean().optional().describe(
    "Set false when installing a real cert via certificatePath.",
  ),
  enableTls: z.boolean().optional().describe(
    "Enable/disable the HTTPS listener (webServiceTlsPort).",
  ),
  tlsPort: z.number().int().positive().optional().describe(
    "HTTPS listener port (Technitium default 53443).",
  ),
  httpToTlsRedirect: z.boolean().optional().describe(
    "Redirect plaintext HTTP to HTTPS. Enable only AFTER verifying the cert.",
  ),
});

const DnssecValidationSetArgs = z.object({
  enable: z.boolean().describe(
    "Whether the resolver validates DNSSEC on upstream answers.",
  ),
});

const ZoneCreateArgs = z.object({
  zone: z.string().describe("Zone name, e.g. lab.example.com"),
  type: ZoneType.default("Primary"),
  catalog: z.string().optional().describe(
    "Name of an existing catalog zone to join as a member zone, so secondaries " +
      "provision it automatically. Valid only for a Primary zone.",
  ),
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
  ttl: z.number().int().optional().describe(
    "New TTL; the record's current TTL is kept when omitted",
  ),
  disable: z.boolean().optional().describe(
    "Disable or enable the record; its current state is kept when omitted",
  ),
  comments: z.string().optional().describe(
    "New comment; the current comment is kept when omitted",
  ),
  expiryTtl: z.number().int().optional().describe(
    "Seconds after last modification to auto-delete (0 = never); kept when omitted",
  ),
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

const RecordEnsureArgs = z.object({
  records: z.array(
    RecordAddArgs.extend({
      rData: RData,
      ttl: z.number().int().optional().describe(
        "TTL to ensure; the current TTL is kept when omitted",
      ),
      // No default: replace removes round-robin siblings, so the caller says
      // which they mean.
      mode: z.enum(["replace", "add"]).describe(
        "replace: this becomes the only record of its type at the name. " +
          "add: other records of the type at the name are left alone.",
      ),
    }),
  ).min(1),
});

const RecordGetArgs = z.object({
  zone: z.string().optional().describe(
    "Zone name; inferred by Technitium if omitted",
  ),
  domain: z.string().describe("Record owner FQDN to read live"),
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
  rcode: z.string().optional().describe("DNS response code, e.g. NxDomain"),
  qname: z.string().optional(),
  qtype: z.string().optional(),
  qclass: z.string().optional(),
});

const DashboardStatsArgs = z.object({
  type: StatsRange.default("LastHour"),
  start: z.string().optional().describe("ISO 8601 start (when type=Custom)"),
  end: z.string().optional().describe("ISO 8601 end (when type=Custom)"),
});

/**
 * Every section flag `/settings/backup` and `/settings/restore` accept. The
 * server defaults each one to `false`, so a flag left out is a section left out.
 */
export const SETTINGS_SECTIONS = [
  "authConfig",
  "clusterConfig",
  "webServiceSettings",
  "dnsSettings",
  "logSettings",
  "zones",
  "allowedZones",
  "blockedZones",
  "blockLists",
  "apps",
  "scopes",
  "stats",
  "logs",
] as const;

/** One of the section names in {@link SETTINGS_SECTIONS}. */
export type SettingsSection = typeof SETTINGS_SECTIONS[number];

/**
 * Build the section flags for a backup or restore call: every section is sent
 * explicitly, as `defaults` overridden by the caller's `options`. An unknown
 * option name throws rather than being forwarded, because the server ignores
 * names it does not know and the caller would never learn the section was skipped.
 */
export function settingsSectionFlags(
  defaults: Record<SettingsSection, boolean>,
  options: Record<string, boolean> | undefined,
): Params {
  const known = new Set<string>(SETTINGS_SECTIONS);
  const unknown = Object.keys(options ?? {}).filter((k) => !known.has(k));
  if (unknown.length > 0) {
    throw new Error(
      `Unknown settings section(s): ${unknown.join(", ")}. ` +
        `Valid sections: ${SETTINGS_SECTIONS.join(", ")}`,
    );
  }
  return { ...defaults, ...(options ?? {}) };
}

/** Backup default: every configuration section. Logs and stats are runtime data, not settings. */
const BACKUP_DEFAULTS: Record<SettingsSection, boolean> = {
  authConfig: true,
  clusterConfig: true,
  webServiceSettings: true,
  dnsSettings: true,
  logSettings: true,
  zones: true,
  allowedZones: true,
  blockedZones: true,
  blockLists: true,
  apps: true,
  scopes: true,
  stats: false,
  logs: false,
};

/**
 * Restore default: the DNS data and settings, but not the three sections that
 * change how the operator reaches the server. `authConfig` replaces every user
 * and token, including the one making this call; `webServiceSettings` can move
 * the port or TLS the call arrived on; `clusterConfig` rebinds cluster membership.
 * Each has to be asked for by name.
 */
const RESTORE_DEFAULTS: Record<SettingsSection, boolean> = {
  authConfig: false,
  clusterConfig: false,
  webServiceSettings: false,
  dnsSettings: true,
  logSettings: true,
  zones: true,
  allowedZones: true,
  blockedZones: true,
  blockLists: true,
  apps: true,
  scopes: true,
  stats: false,
  logs: false,
};

const SettingsBackupArgs = z.object({
  options: z.record(z.string(), z.boolean()).optional().describe(
    `Section flags (${
      SETTINGS_SECTIONS.join(", ")
    }). Defaults to every configuration section; logs and stats are off.`,
  ),
});

const SettingsRestoreArgs = z.object({
  filePath: z.string().describe(
    "Absolute path to the backup zip on the swamp host",
  ),
  options: z.record(z.string(), z.boolean()).optional().describe(
    `Section flags (${
      SETTINGS_SECTIONS.join(", ")
    }). Defaults to DNS data and settings; authConfig, clusterConfig and webServiceSettings must be asked for explicitly.`,
  ),
  deleteExistingFiles: z.boolean().optional().describe(
    "Delete the server's existing files for each section being restored",
  ),
});

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/** The `@thomas/technitium` swamp model: schema, methods, and lifecycle for managing a Technitium DNS server. */
export const model = {
  type: "@thomas/technitium",
  version: "2026.10.25.1",
  globalArguments: GlobalArgs,
  upgrades: [
    {
      toVersion: "2026.10.11.1",
      description:
        "Global arguments are unchanged. Stored data is renamed to <spec>:<key> (or <spec>), with DNS names keeping their dots; records under the old names are left as they are and are not migrated. The API token goes only in the Authorization header, so Technitium before 15 is not supported. Several methods change behaviour; see the README's Breaking changes.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.10.25.1",
      description: "No change to global arguments or stored data.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
  ],
  checks: {
    "reachable": {
      // `user/session/get` needs no permission beyond a valid token, so a
      // token scoped to zones alone still passes.
      description:
        "Verify the Technitium API authenticates (GET /api/user/session/get)",
      labels: ["live"],
      execute: async (
        context: Pick<MethodContext<GlobalArgsT>, "globalArgs">,
      ) => {
        // Checks get globalArgs without the schema's defaults; parse to apply them.
        const parsed = GlobalArgs.safeParse(context.globalArgs);
        if (!parsed.success) {
          return { pass: false, errors: [z.prettifyError(parsed.error)] };
        }
        const g = parsed.data;
        try {
          await apiCall(g, "GET", "/user/session/get");
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Cannot reach Technitium at ${g.baseUrl}: ${
                (e as Error).message
              }`,
            ],
          };
        }
      },
    },
  },
  resources: {
    "zone": {
      description: "An authoritative DNS zone",
      schema: ZoneResource,
      // As for zoneRecord: zone_list refreshes the zones that still exist, and
      // one removed outside swamp expires instead of reading as current.
      lifetime: "30d",
      garbageCollection: 10,
    },
    "zoneRecord": {
      description: "A resource record within a zone",
      schema: ZoneRecordResource,
      // A copy of live server state that expires. Re-listing a record resets its
      // timer; records that are deleted or change value stop being refreshed and
      // expire (swamp does not auto-prune orphaned instances, so a finite lifetime
      // is what removes stale entries).
      lifetime: "30d",
      garbageCollection: 10,
    },
    "settings": {
      description:
        "Selected server settings: blocking, web-service TLS, DNSSEC validation and DNS-over-TLS",
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
      // As for zoneRecord: _list refreshes entries that still exist.
      lifetime: "30d",
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
    "queryLogPage": {
      description:
        "Which page the last logs_query read, and how many entries and pages its query matched",
      schema: QueryLogPageResource,
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
        "Get the stored subset of the server settings (blocking, web-service TLS, DNSSEC validation, DNS-over-TLS).",
      arguments: NoArgs,
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const r = await apiCall(g, "GET", "/settings/get");
        const settings = extractSettings(r, new Date().toISOString());
        const handle = await context.writeResource(
          "settings",
          dataName("settings"),
          settings,
        );
        logInfo(context, "Read settings: blocking enabled {enableBlocking}", {
          enableBlocking: settings.enableBlocking,
        });
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
        logInfo(context, "Setting blocking enabled to {enable}", {
          enable: args.enable,
        });
        const r = await apiCall(g, "POST", "/settings/set", {
          enableBlocking: args.enable,
        });
        logInfo(context, "Set blocking enabled to {enable}", {
          enable: args.enable,
        });
        const handle = await context.writeResource(
          "settings",
          dataName("settings"),
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
        logInfo(context, "Disabling blocking for {minutes} minutes", {
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
        logInfo(context, "Blocking disabled until {till}", { till });
        const handle = await context.writeResource(
          "operationResult",
          dataName("operationResult", "blocking_temporary_disable"),
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
        "Set the block-list and/or allow-list URLs; only the lists you provide are changed, and an " +
        "empty list clears it. Technitium keeps both in one setting, allow entries prefixed with `!`.",
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
        checkListUrls(args.blockListUrls, args.allowListUrls);
        // Both lists live in the one blockListUrls setting, so keep the side
        // that was not passed as it is now.
        const current = splitListUrls(
          await apiCall(g, "GET", "/settings/get"),
        );
        const block = args.blockListUrls ?? current.block;
        const allow = args.allowListUrls ?? current.allow;
        const { joined, tooLong } = joinListUrls([
          ...block,
          ...allow.map((u) => `!${u}`),
        ]);
        if (tooLong.length) {
          logWarning(
            context,
            "{count} list URL(s) exceed Technitium's 255-character limit",
            { count: tooLong.length },
          );
        }
        logInfo(
          context,
          "Setting {blockCount} block-list and {allowCount} allow-list URLs",
          { blockCount: block.length, allowCount: allow.length },
        );
        const params: Params = { blockListUrls: joined };
        const r = await apiCall(g, "POST", "/settings/set", params);
        logInfo(context, "Set the block-list and allow-list URLs");
        const handle = await context.writeResource(
          "settings",
          dataName("settings"),
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
        logInfo(context, "Forcing a block-list update");
        await apiCall(g, "POST", "/settings/forceUpdateBlockLists");
        logInfo(context, "Block-list update started");
        const handle = await context.writeResource(
          "operationResult",
          dataName("operationResult", "blocking_force_update_lists"),
          opResult("blocking_force_update_lists", true),
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- security settings ---------------------------------------------
    web_service_set_tls: {
      description:
        "Configure the admin web service TLS (HTTPS) listener: install a " +
        "PKCS#12 certificate, toggle the self-signed fallback, the HTTPS " +
        "listener, its port, and HTTP→HTTPS redirect. Only the fields you " +
        "provide are changed. Enable httpToTlsRedirect ONLY after verifying " +
        "the cert serves correctly, or you can lock yourself out of the UI.",
      arguments: WebServiceSetTlsArgs,
      execute: async (
        args: z.infer<typeof WebServiceSetTlsArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const params: Params = {};
        if (args.certificatePath !== undefined) {
          params.webServiceTlsCertificatePath = args.certificatePath;
        }
        if (args.certificatePassword !== undefined) {
          params.webServiceTlsCertificatePassword = args.certificatePassword;
        }
        if (args.useSelfSignedCertificate !== undefined) {
          params.webServiceUseSelfSignedTlsCertificate =
            args.useSelfSignedCertificate;
        }
        if (args.enableTls !== undefined) {
          params.webServiceEnableTls = args.enableTls;
        }
        if (args.tlsPort !== undefined) {
          params.webServiceTlsPort = args.tlsPort;
        }
        if (args.httpToTlsRedirect !== undefined) {
          params.webServiceHttpToTlsRedirect = args.httpToTlsRedirect;
        }
        if (Object.keys(params).length === 0) {
          throw new Error(
            "Provide at least one web-service TLS field to change",
          );
        }
        // Technitium reads the password only alongside a path, and ignores it
        // otherwise. A password on its own means "the current certificate's
        // new password", so send the current path with it.
        if (
          args.certificatePassword !== undefined &&
          args.certificatePath === undefined
        ) {
          const current = asString(
            pick(
              await apiCall(g, "GET", "/settings/get"),
              "webServiceTlsCertificatePath",
            ),
          );
          if (!current) {
            throw new Error(
              "certificatePassword was given without certificatePath, and no " +
                "certificate is configured to apply it to",
            );
          }
          params.webServiceTlsCertificatePath = current;
        }
        // Log which fields change, never the password itself.
        logInfo(context, "Setting web-service TLS fields: {fields}", {
          fields: Object.keys(params).join(", "),
        });
        const r = await apiCall(g, "POST", "/settings/set", params);
        logInfo(context, "Set web-service TLS");
        const handle = await context.writeResource(
          "settings",
          dataName("settings"),
          extractSettings(r, new Date().toISOString()),
        );
        return { dataHandles: [handle] };
      },
    },

    dnssec_validation_set: {
      description: "Enable or disable DNSSEC validation of upstream answers " +
        "(writes only `dnssecValidation`).",
      arguments: DnssecValidationSetArgs,
      execute: async (
        args: z.infer<typeof DnssecValidationSetArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Setting DNSSEC validation to {enable}", {
          enable: args.enable,
        });
        const r = await apiCall(g, "POST", "/settings/set", {
          dnssecValidation: args.enable,
        });
        logInfo(context, "Set DNSSEC validation to {enable}", {
          enable: args.enable,
        });
        const handle = await context.writeResource(
          "settings",
          dataName("settings"),
          extractSettings(r, new Date().toISOString()),
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
          const fields = zoneFields(z);
          handles.push(
            await context.writeResource(
              "zone",
              dataName("zone", dnsKey(fields.name)),
              { ...fields, action: "observed", observedAt },
            ),
          );
        }
        logInfo(context, "Listed {count} zones", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    zone_create: {
      description:
        "Create an authoritative zone. If a zone of the same type, in the `catalog` given if any, already exists it is left as it is (`unchanged`); any other existing zone is an error.",
      arguments: ZoneCreateArgs,
      execute: async (
        args: z.infer<typeof ZoneCreateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Creating {type} zone {zone}", {
          zone: args.zone,
          type: args.type,
        });
        let r: Json;
        try {
          r = await apiCall(g, "POST", "/zones/create", {
            zone: args.zone,
            type: args.type,
            ...(args.catalog ? { catalog: args.catalog } : {}),
          });
        } catch (e) {
          // A rerun finds the zone it made last time. A zone of the same type
          // (in the catalog asked for, if any) is the outcome asked for;
          // anything else is a real conflict.
          if (!(e as Error).message.includes("Zone already exists")) throw e;
          const existing = await readZone(g, args.zone);
          if (existing?.type !== args.type) throw e;
          if (
            args.catalog &&
            dnsKey(existing.catalog ?? "") !== dnsKey(args.catalog)
          ) {
            throw new Error(
              `${(e as Error).message}, and it is ${
                existing.catalog
                  ? `in catalog ${existing.catalog}`
                  : "in no catalog"
              }, not ${args.catalog}`,
            );
          }
          logInfo(context, "Zone {zone} already exists as {type}", {
            zone: existing.name,
            type: existing.type,
          });
          const handle = await context.writeResource(
            "zone",
            dataName("zone", dnsKey(existing.name)),
            {
              ...existing,
              action: "unchanged",
              observedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        }
        // The server names the zone it made: an IP address or a CIDR range
        // (`192.0.2.0/24`) becomes its reverse zone (`2.0.192.in-addr.arpa`).
        const name = asString(pick(r, "domain")) ?? args.zone;
        logInfo(context, "Created zone {name}", { name });
        const handle = await context.writeResource(
          "zone",
          dataName("zone", dnsKey(name)),
          {
            name,
            type: args.type,
            catalog: args.catalog,
            disabled: false,
            action: "created",
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    zone_delete: {
      description:
        "Delete a zone. A zone that does not exist is reported as deleted.",
      arguments: ZoneRefArgs,
      execute: async (
        args: z.infer<typeof ZoneRefArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Deleting zone {zone}", { zone: args.zone });
        // Read the zone first: once deleted, the server can no longer
        // describe it, and the deleted record should still say what it was.
        const before = await readZone(g, args.zone);
        if (before) {
          await apiCall(g, "POST", "/zones/delete", { zone: args.zone });
          logInfo(context, "Deleted zone {zone}", { zone: args.zone });
        } else {
          // Already gone, which is the outcome asked for.
          logInfo(context, "Zone {zone} does not exist; nothing to delete", {
            zone: args.zone,
          });
        }
        const handle = await context.writeResource(
          "zone",
          dataName("zone", dnsKey(args.zone)),
          {
            ...(before ?? { name: args.zone }),
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
        logInfo(context, "Enabling zone {zone}", { zone: args.zone });
        await apiCall(g, "POST", "/zones/enable", { zone: args.zone });
        logInfo(context, "Enabled zone {zone}", { zone: args.zone });
        // Store the whole zone, not only `disabled`, so its type and catalog
        // stay readable from the latest version.
        const after = await readZone(g, args.zone);
        const handle = await context.writeResource(
          "zone",
          dataName("zone", dnsKey(args.zone)),
          {
            ...(after ?? { name: args.zone }),
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
        logInfo(context, "Disabling zone {zone}", { zone: args.zone });
        await apiCall(g, "POST", "/zones/disable", { zone: args.zone });
        logInfo(context, "Disabled zone {zone}", { zone: args.zone });
        // Store the whole zone, not only `disabled`, so its type and catalog
        // stay readable from the latest version.
        const after = await readZone(g, args.zone);
        const handle = await context.writeResource(
          "zone",
          dataName("zone", dnsKey(args.zone)),
          {
            ...(after ?? { name: args.zone }),
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
        // Store the zone's name as the server spells it, as the other record
        // methods do, not as the caller typed it.
        const zone = asString(pick((r.zone ?? {}) as Json, "name")) ??
          args.zone;
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const raw of coerceArray(r, "records")) {
          const rec = toLiveRecord(raw, zone);
          handles.push(
            await context.writeResource(
              "zoneRecord",
              recordInstanceName(zone, rec.name, rec.type, rec.rData),
              {
                zone,
                name: rec.name,
                type: rec.type,
                ttl: rec.ttl,
                disabled: rec.disabled,
                rData: rec.rData,
                action: "observed",
                observedAt,
              },
            ),
          );
        }
        logInfo(context, "Listed {count} records in zone {zone}", {
          zone,
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    record_get: {
      description:
        "Read the live records at a single domain straight from Technitium (factory: one `zoneRecord` each). Ground-truth read-back for one name — unlike `record_list` it queries a single domain rather than the whole zone.",
      arguments: RecordGetArgs,
      execute: async (
        args: z.infer<typeof RecordGetArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const { zone, records } = await getDomainRecords(
          g,
          args.domain,
          args.zone,
        );
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const rec of records) {
          handles.push(
            await context.writeResource(
              "zoneRecord",
              recordInstanceName(
                zone,
                rec.name,
                rec.type,
                rec.rData,
              ),
              {
                zone,
                name: rec.name,
                type: rec.type,
                ttl: rec.ttl,
                disabled: rec.disabled,
                rData: rec.rData,
                action: "observed",
                observedAt,
              },
            ),
          );
        }
        logInfo(context, "Read {count} records at {domain}", {
          domain: args.domain,
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
        logInfo(context, "Adding {type} record at {domain}", {
          domain: args.domain,
          type: args.type,
        });
        const rec = await addRecord(g, args);
        logInfo(context, "Added {type} record at {name}", {
          name: rec.name,
          type: args.type,
        });
        return {
          dataHandles: [
            await writeZoneRecord(context, rec, args.type, "created"),
          ],
        };
      },
    },

    record_update: {
      description:
        "Update a record. `rData` identifies the existing record; `newRData` carries the new values (mapped to Technitium's new* params, except for APP, CNAME and DNAME, which take the new values as they are).",
      arguments: RecordUpdateArgs,
      execute: async (
        args: z.infer<typeof RecordUpdateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Updating {type} record at {domain}", {
          domain: args.domain,
          type: args.type,
        });
        const rec = await updateRecord(g, args);
        logInfo(context, "Updated {type} record at {name}", {
          name: rec.name,
          type: args.type,
        });
        return {
          dataHandles: [
            await writeZoneRecord(context, rec, args.type, "updated"),
          ],
        };
      },
    },

    record_ensure: {
      description:
        "Make records match the given data and TTL, safe to rerun: adds a record that is missing, updates one whose TTL differs, and leaves one that already matches (action `unchanged`). Each entry's `mode` decides what happens to other records of its type at its name: `replace` makes it the only one (the others are removed and stored as `deleted`); `add` leaves them as they are. Fans out over `records` in one run.",
      arguments: RecordEnsureArgs,
      execute: async (
        args: z.infer<typeof RecordEnsureArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        // A replace makes its record the only one of its type at the name, so
        // any other entry for that name and type contradicts it. Refuse before
        // writing anything rather than let the later entry undo the earlier.
        const byName = new Map<string, string[]>();
        for (const spec of args.records) {
          const key = `${dnsKey(spec.domain)} ${spec.type.toUpperCase()}`;
          byName.set(key, [...(byName.get(key) ?? []), spec.mode]);
        }
        for (const [key, modes] of byName) {
          if (modes.length > 1 && modes.includes("replace")) {
            throw new Error(
              `record_ensure: ${key} appears ${modes.length} times and at least once with mode replace; a replace must be the only entry for its name and type`,
            );
          }
        }
        const handles: DataHandle[] = [];
        for (const spec of args.records) {
          const type = spec.type.toUpperCase();
          const live = await getDomainRecords(g, spec.domain, spec.zone);
          const sameType = live.records.filter((r) =>
            r.type.toUpperCase() === type
          );
          const match = findRecord(sameType, type, spec.rData);
          const ttlMatches = spec.ttl === undefined || match?.ttl === spec.ttl;
          // In replace mode any other record of the type is a difference too.
          const othersAllowed = spec.mode === "add" || sameType.length === 1;
          if (match && ttlMatches && othersAllowed) {
            handles.push(
              await writeZoneRecord(
                context,
                { ...match, zone: live.zone },
                type,
                "unchanged",
              ),
            );
            continue;
          }
          // Technitium gives every record of a type at a name one TTL, and an
          // add without a TTL resets it to the server default for all of
          // them. Keep the current TTL unless the caller set one.
          const ttl = spec.ttl ?? match?.ttl ?? sameType[0]?.ttl;
          let rec: WrittenRecord;
          let action: "created" | "updated";
          if (spec.mode === "replace") {
            logInfo(context, "Replacing {type} records at {domain}", {
              domain: spec.domain,
              type,
            });
            rec = await addRecord(g, { ...spec, type, ttl }, true);
            action = sameType.length > 0 ? "updated" : "created";
            // The overwrite removed every other record of the type. Store
            // them as deleted so their old data does not read as current.
            const kept = canonicalRData(rec.rData);
            for (const old of sameType) {
              if (canonicalRData(old.rData) === kept) continue;
              handles.push(
                await writeZoneRecord(
                  context,
                  { ...old, zone: live.zone },
                  type,
                  "deleted",
                ),
              );
            }
          } else if (match) {
            // Only the TTL differs. A second add of the same record fails
            // for CNAME, so update it in place.
            logInfo(context, "Setting the TTL of a {type} record at {domain}", {
              domain: spec.domain,
              type,
            });
            rec = await updateRecord(g, {
              zone: spec.zone,
              domain: spec.domain,
              type,
              ttl,
              rData: spec.rData,
              newRData: spec.rData,
            });
            action = "updated";
          } else {
            logInfo(context, "Adding {type} record at {domain}", {
              domain: spec.domain,
              type,
            });
            rec = await addRecord(g, { ...spec, type, ttl });
            action = "created";
          }
          handles.push(await writeZoneRecord(context, rec, type, action));
        }
        logInfo(context, "Ensured {count} records", {
          count: args.records.length,
        });
        return { dataHandles: handles };
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
        // Find the live record first: once deleted, the server can no longer
        // say how it names the record, and the data name must match the one
        // record_list wrote. With no match, fall back to the caller's rData.
        const before = await getDomainRecords(g, args.domain, args.zone);
        const target = findRecord(before.records, args.type, args.rData);
        const params: Params = { domain: args.domain, type: args.type };
        if (args.zone) params.zone = args.zone;
        spreadRData(params, args.rData);
        logInfo(context, "Deleting {type} record at {domain}", {
          domain: args.domain,
          type: args.type,
        });
        await apiCall(g, "POST", "/zones/records/delete", params);
        const { zone } = await verifyRecordWrite(
          g,
          "deleted",
          args.domain,
          args.type,
          args.rData,
          args.zone,
          target,
        );
        const name = target?.name ?? args.domain;
        const rData = target?.rData ?? args.rData;
        logInfo(context, "Deleted {type} record at {name}", {
          name,
          type: args.type,
        });
        const handle = await context.writeResource(
          "zoneRecord",
          recordInstanceName(zone, name, args.type, rData),
          {
            zone,
            name,
            type: args.type,
            rData,
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
        logInfo(context, "Adding {domain} to the Allowed zone", {
          domain: args.domain,
        });
        await apiCall(g, "POST", "/allowed/add", { domain: args.domain });
        logInfo(context, "Added {domain} to the Allowed zone", {
          domain: args.domain,
        });
        const handle = await context.writeResource(
          "listEntry",
          dataName("listEntry", `allowed:${dnsKey(args.domain)}`),
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
        logInfo(context, "Removing {domain} from the Allowed zone", {
          domain: args.domain,
        });
        await apiCall(g, "POST", "/allowed/delete", { domain: args.domain });
        logInfo(context, "Removed {domain} from the Allowed zone", {
          domain: args.domain,
        });
        const handle = await context.writeResource(
          "listEntry",
          dataName("listEntry", `allowed:${dnsKey(args.domain)}`),
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
        "List every domain in the built-in Allowed zone, or under `domain` (factory: one `listEntry` per domain). Walks the zone's label tree, one API call per branching node.",
      arguments: ListEntriesArgs,
      execute: async (
        args: z.infer<typeof ListEntriesArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const domains = await listZoneEntries(g, "allowed", args.domain);
        logInfo(context, "Listed {count} domains in the Allowed zone", {
          count: domains.length,
        });
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const d of domains) {
          handles.push(
            await context.writeResource(
              "listEntry",
              dataName("listEntry", `allowed:${dnsKey(d)}`),
              {
                list: "allowed",
                domain: d,
                action: "observed",
                observedAt,
              },
            ),
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
        logInfo(context, "Flushing the Allowed zone");
        await apiCall(g, "POST", "/allowed/flush");
        logInfo(context, "Flushed the Allowed zone");
        const handle = await context.writeResource(
          "operationResult",
          dataName("operationResult", "allowed_flush"),
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
        logInfo(context, "Adding {domain} to the Blocked zone", {
          domain: args.domain,
        });
        await apiCall(g, "POST", "/blocked/add", { domain: args.domain });
        logInfo(context, "Added {domain} to the Blocked zone", {
          domain: args.domain,
        });
        const handle = await context.writeResource(
          "listEntry",
          dataName("listEntry", `blocked:${dnsKey(args.domain)}`),
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
        logInfo(context, "Removing {domain} from the Blocked zone", {
          domain: args.domain,
        });
        await apiCall(g, "POST", "/blocked/delete", { domain: args.domain });
        logInfo(context, "Removed {domain} from the Blocked zone", {
          domain: args.domain,
        });
        const handle = await context.writeResource(
          "listEntry",
          dataName("listEntry", `blocked:${dnsKey(args.domain)}`),
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
        "List every domain in the built-in Blocked zone, or under `domain` (factory: one `listEntry` per domain). Walks the zone's label tree, one API call per branching node.",
      arguments: ListEntriesArgs,
      execute: async (
        args: z.infer<typeof ListEntriesArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const domains = await listZoneEntries(g, "blocked", args.domain);
        logInfo(context, "Listed {count} domains in the Blocked zone", {
          count: domains.length,
        });
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const d of domains) {
          handles.push(
            await context.writeResource(
              "listEntry",
              dataName("listEntry", `blocked:${dnsKey(d)}`),
              {
                list: "blocked",
                domain: d,
                action: "observed",
                observedAt,
              },
            ),
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
        logInfo(context, "Flushing the Blocked zone");
        await apiCall(g, "POST", "/blocked/flush");
        logInfo(context, "Flushed the Blocked zone");
        const handle = await context.writeResource(
          "operationResult",
          dataName("operationResult", "blocked_flush"),
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
        logInfo(context, "Resolving {domain} {type} via {server}", {
          domain: args.domain,
          type: args.type,
          server: args.server,
        });
        const r = await apiCall(g, "GET", "/dnsClient/resolve", {
          server: args.server,
          domain: args.domain,
          type: args.type,
          protocol: args.protocol,
          // The API's name for the flag; `dnssecValidation` is only this method's argument.
          dnssec: args.dnssecValidation,
        });
        // The parsed DNS datagram (RCODE, Answer, ...) is nested under `result`.
        const result = (pick(r, "result") as Json | undefined) ?? r;
        const rcode = asString(pick(result, "RCODE", "rcode"));
        logInfo(context, "Resolved {domain}: {rcode}", {
          domain: args.domain,
          rcode,
        });
        const handle = await context.writeResource(
          "dnsResponse",
          dataName("dnsResponse", `${dnsKey(args.domain)}:${args.type}`),
          {
            server: args.server,
            domain: args.domain,
            type: args.type,
            protocol: args.protocol,
            rcode,
            answer:
              (pick(result, "Answer", "answer") as unknown[] | undefined) ??
                undefined,
            result: r.result,
            rawResponses: Array.isArray(r.rawResponses)
              ? r.rawResponses
              : undefined,
            observedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ----- logs_ ----------------------------------------------------------
    logs_query: {
      description:
        "Query recent DNS query logs, one page per call (factory: one `queryLog` per entry, keyed on its content, plus a `queryLogPage` with the page and the totals). Requires the Query Logs (Sqlite) DNS app to be installed.",
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
          rcode: args.rcode,
          qname: args.qname,
          qtype: args.qtype,
          qclass: args.qclass,
        });
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        const seen = new Set<string>();
        for (const e of coerceArray(r, "entries")) {
          const { rowNumber, ...entry } = {
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
          };
          // The log has no entry id, and `rowNumber` is only the position in
          // this query's results, so the entry is keyed on its own content:
          // the same entry gets the same name whichever query returns it.
          const key = shortHash(JSON.stringify(entry));
          // Two entries identical to the millisecond are the same fact, and a
          // second write under one name in one run would fail.
          if (seen.has(key)) continue;
          seen.add(key);
          handles.push(
            await context.writeResource(
              "queryLog",
              dataName("queryLog", key),
              { rowNumber, ...entry, observedAt },
            ),
          );
        }
        // Only one page is read, so record how much the query matched in all.
        const page = {
          pageNumber: asNumber(pick(r, "pageNumber")),
          totalPages: asNumber(pick(r, "totalPages")),
          totalEntries: asNumber(pick(r, "totalEntries")),
          entriesOnPage: handles.length,
          observedAt,
        };
        handles.push(
          await context.writeResource(
            "queryLogPage",
            dataName("queryLogPage"),
            page,
          ),
        );
        logInfo(
          context,
          "Read {entriesOnPage} query-log entries: page {pageNumber} of {totalPages}, {totalEntries} matching",
          page,
        );
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
        logInfo(context, "Flushing the DNS cache");
        await apiCall(g, "POST", "/cache/flush");
        logInfo(context, "Flushed the DNS cache");
        const handle = await context.writeResource(
          "operationResult",
          dataName("operationResult", "cache_flush"),
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
            await context.writeResource(
              "cacheEntry",
              dataName("cacheEntry", `zone:${dnsKey(n)}`),
              {
                name: n,
                kind: "zone",
                action: "observed",
                observedAt,
              },
            ),
          );
        }
        for (const n of namesFrom(r, "records")) {
          handles.push(
            await context.writeResource(
              "cacheEntry",
              dataName("cacheEntry", `record:${dnsKey(n)}`),
              {
                name: n,
                kind: "record",
                action: "observed",
                observedAt,
              },
            ),
          );
        }
        logInfo(context, "Listed {count} cache entries", {
          count: handles.length,
        });
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
        logInfo(context, "Deleting {domain} from the DNS cache", {
          domain: args.domain,
        });
        await apiCall(g, "POST", "/cache/delete", { domain: args.domain });
        logInfo(context, "Deleted {domain} from the DNS cache", {
          domain: args.domain,
        });
        const handle = await context.writeResource(
          "operationResult",
          dataName("operationResult", `cache_delete:${dnsKey(args.domain)}`),
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
        logInfo(context, "Read {range} stats: {totalQueries} queries", {
          range: args.type,
          totalQueries: asNumber(pick(s, "totalQueries")),
        });
        const handle = await context.writeResource(
          "stats",
          dataName("stats", args.type),
          {
            range: args.type,
            // Stored so two Custom ranges, which share one name, can be told apart.
            start: args.start,
            end: args.end,
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
        const flags = settingsSectionFlags(BACKUP_DEFAULTS, args.options);
        logInfo(context, "Downloading a settings backup");
        const bytes = await apiDownload(g, "/settings/backup", flags);
        logInfo(context, "Downloaded a {bytes}-byte settings backup", {
          bytes: bytes.length,
        });
        const writer = context.createFileWriter(
          "backup",
          dataName("backup", new Date().toISOString()),
        );
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
          ...settingsSectionFlags(RESTORE_DEFAULTS, args.options),
          deleteExistingFiles: args.deleteExistingFiles ?? false,
        };
        const bytes = new Uint8Array(await readFile(args.filePath));
        // Refuse anything that is not a zip before sending it, as
        // settings_backup refuses one on download.
        if (!isZip(bytes)) {
          throw new Error(`${args.filePath} is not a zip file`);
        }
        logInfo(context, "Restoring settings from {filePath} ({bytes} bytes)", {
          filePath: args.filePath,
          bytes: bytes.length,
        });
        await apiUpload(g, "/settings/restore", flags, bytes, "backup.zip");
        logInfo(context, "Restored settings from {filePath}", {
          filePath: args.filePath,
        });
        const handle = await context.writeResource(
          "operationResult",
          dataName("operationResult", "settings_restore"),
          opResult("settings_restore", true, args.filePath),
        );
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
