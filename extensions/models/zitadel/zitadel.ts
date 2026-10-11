import { z } from "npm:zod@4";
// Type-only imports, erased at compile time and never bundled. The
// `satisfies ModelDefinition<typeof GlobalArgs>` clause uses them so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";
// Signing uses the Web Crypto API (the `crypto.subtle` global) with no `node:`
// import, so the extension has no dependencies and resolves no `@types/node` at
// doc-lint time (a `node:` import makes some `deno doc` sandboxes fetch the floating
// @types/node → undici-types, which can break scoring). Zitadel issues PKCS#1
// ("RSA PRIVATE KEY") keys and Web Crypto imports only PKCS#8, so `signAssertion`
// wraps PKCS#1 → PKCS#8 (a fixed DER envelope) before importing the key.

/**
 * `@thomas/zitadel`: non-destructive administration of a Zitadel instance over
 * its Management API (v1 REST).
 *
 * Scope: this holds an org admin credential (an org manager such as ORG_OWNER),
 * so its methods are limited. It never deletes a project, application or user;
 * those are disabled with the reversible deactivate/reactivate pair. Two methods
 * do delete: `role_remove`, because a role has no deactivate state (it also
 * revokes every grant that uses the role), and `pat_revoke`, because revoking a
 * token removes it. Both verify the target first. It creates machine identities
 * only (service users and their PATs, keys and secrets). It can grant roles to,
 * and deactivate, any user, but never creates a human user or changes a
 * password or MFA. Every secret it creates is returned once in the method
 * output, marked sensitive, and never logged.
 *
 * Auth: a JWT private-key service account. The model holds a machine-user key
 * JSON (`keyJson`); per run it signs a short-lived RS256 assertion and exchanges
 * it at `/oauth/v2/token` (jwt-bearer grant, `urn:zitadel:iam:org:project:id:zitadel:aud`
 * scope) for an access token, then sends that as a Bearer token to the Management
 * API. No long-lived bearer token is stored.
 *
 * Idempotency: ensure methods find-or-create by human name (project name, app
 * name, username, role key) and return an `action` of created/updated/unchanged.
 * `oidc_app_ensure`, `role_ensure` and `grant_ensure` also converge an existing
 * object's config; `project_ensure`, `api_app_ensure` and `machine_user_ensure`
 * only find or create, and leave an existing object as it is.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  apiUrl: z.string().describe(
    "Zitadel base URL / issuer, e.g. https://zitadel.example.com. Plain http " +
      "sends the access token unencrypted; methods log a warning for it.",
  ),
  keyJson: z.string().meta({ sensitive: true }).describe(
    "Service-user machine key JSON (the whole blob downloaded from Zitadel; " +
      "contains keyId, key (PKCS#1 PEM), userId). Supply via vault: " +
      "${{ vault.get(<vault>, zitadel-admin/key_json) }}",
  ),
  orgId: z.string().optional().describe(
    "Target org id (x-zitadel-orgid header). Omit to use the service user's own org.",
  ),
  httpTimeoutMs: z.coerce.number().int().positive().default(30000).describe(
    "Per-request timeout (ms) for token exchange and API calls",
  ),
  // An OAuth scope string, not a secret.
  // swamp-quality-ignore credentials-sensitive-field
  tokenScope: z.string().default(
    "openid profile urn:zitadel:iam:org:project:id:zitadel:aud",
  ).describe(
    "OAuth scope requested for the API token (advanced). The project:id:zitadel:aud " +
      "scope is what grants access to Zitadel's own Management API.",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type", so
// it must not appear on the public API (the exported `CallerFn` seam uses the
// loose `Json` instead; see below).
type GlobalArgsT = z.infer<typeof GlobalArgs>;

/** The set of outcomes a method reports in its `action` field. */
const Action = z.enum([
  "created",
  "unchanged",
  "updated",
  "rotated",
  "revoked",
  "deactivated",
  "reactivated",
  "removed",
  "observed",
]);

// ─────────────────────────── friendly ⇆ zitadel enums ───────────────────────────

/** Friendly OIDC application type → Zitadel enum. */
const APP_TYPE: Record<string, string> = {
  web: "OIDC_APP_TYPE_WEB",
  spa: "OIDC_APP_TYPE_USER_AGENT",
  native: "OIDC_APP_TYPE_NATIVE",
};
/** Friendly OIDC auth method → Zitadel enum. */
const AUTH_METHOD: Record<string, string> = {
  basic: "OIDC_AUTH_METHOD_TYPE_BASIC",
  post: "OIDC_AUTH_METHOD_TYPE_POST",
  none: "OIDC_AUTH_METHOD_TYPE_NONE",
  jwt: "OIDC_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT",
};
/** Friendly API-app auth method → Zitadel enum. */
const API_AUTH_METHOD: Record<string, string> = {
  basic: "API_AUTH_METHOD_TYPE_BASIC",
  jwt: "API_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT",
};
/** Friendly OIDC grant type → Zitadel enum. */
const GRANT_TYPE: Record<string, string> = {
  authorization_code: "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
  implicit: "OIDC_GRANT_TYPE_IMPLICIT",
  refresh_token: "OIDC_GRANT_TYPE_REFRESH_TOKEN",
  device_code: "OIDC_GRANT_TYPE_DEVICE_CODE",
};
/** Friendly OIDC response type → Zitadel enum. */
const RESPONSE_TYPE: Record<string, string> = {
  code: "OIDC_RESPONSE_TYPE_CODE",
  id_token: "OIDC_RESPONSE_TYPE_ID_TOKEN",
  id_token_token: "OIDC_RESPONSE_TYPE_ID_TOKEN_TOKEN",
};
/** Friendly access-token type → Zitadel enum. */
const ACCESS_TOKEN_TYPE: Record<string, string> = {
  bearer: "OIDC_TOKEN_TYPE_BEARER",
  jwt: "OIDC_TOKEN_TYPE_JWT",
};

/** Invert a friendly→Zitadel enum map for read-shaping (Zitadel enum → friendly). */
function invertEnum(m: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(m).map(([k, v]) => [v, k]));
}
/** Reverse maps: round-trip-safe read-shaping for fields the write path maps. */
const APP_TYPE_REV = invertEnum(APP_TYPE);
const ACCESS_TOKEN_TYPE_REV = invertEnum(ACCESS_TOKEN_TYPE);
const RESPONSE_TYPE_REV = invertEnum(RESPONSE_TYPE);
const GRANT_TYPE_REV = invertEnum(GRANT_TYPE);

/** Reverse-map a wire enum array to friendly values (friendlyState fallback). */
function friendlyEnumArr(
  v: unknown,
  rev: Record<string, string>,
): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v.map((e) =>
    typeof e === "string" ? (rev[e] ?? friendlyState(e)) : String(e)
  );
}

function mapEnum(
  m: Record<string, string>,
  v: string,
  label: string,
): string {
  const out = m[v];
  if (!out) {
    throw new Error(
      `Invalid ${label} ${JSON.stringify(v)}; allowed: ${
        Object.keys(m).join(", ")
      }`,
    );
  }
  return out;
}

/** Reduce a Zitadel state enum (e.g. `APP_STATE_ACTIVE`) to `active`/`inactive`/… */
function friendlyState(s: unknown): string {
  if (typeof s !== "string" || !s) return "unknown";
  const parts = s.split("_");
  return parts[parts.length - 1].toLowerCase();
}

// ─────────────────────────── resource schemas ───────────────────────────

const OrgInfo = z.object({
  id: z.string(),
  name: z.string(),
  state: z.string(),
  primaryDomain: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const ProjectInfo = z.object({
  id: z.string(),
  name: z.string(),
  state: z.string(),
  // Authorization flags. Without `roleAssertion`, granted project roles do not
  // appear in the user's tokens/userinfo.
  roleAssertion: z.boolean().optional().describe(
    "Assert the user's project roles into their tokens/userinfo",
  ),
  roleCheck: z.boolean().optional().describe(
    "Require the user to hold a project role to authenticate",
  ),
  hasProjectCheck: z.boolean().optional().describe(
    "Require the user's org to have the project granted to authenticate",
  ),
  action: Action,
  timestamp: z.string(),
});

const RoleInfo = z.object({
  projectId: z.string(),
  key: z.string().describe(
    "The role key (stable identifier; goes into tokens)",
  ),
  displayName: z.string().optional(),
  group: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const GrantInfo = z.object({
  grantId: z.string(),
  userId: z.string(),
  projectId: z.string(),
  roleKeys: z.array(z.string()),
  state: z.string(),
  displayName: z.string().optional().describe(
    "The granted user's display name",
  ),
  action: Action,
  timestamp: z.string(),
});

const AppInfo = z.object({
  projectId: z.string(),
  appId: z.string(),
  name: z.string(),
  state: z.string(),
  kind: z.string().describe("oidc | api | saml | unknown"),
  clientId: z.string().optional(),
  appType: z.string().optional(),
  accessTokenType: z.string().optional().describe(
    "OIDC access-token type: bearer | jwt (effective value, defaults normalized)",
  ),
  authMethod: z.string().optional(),
  redirectUris: z.array(z.string()).optional(),
  postLogoutUris: z.array(z.string()).optional(),
  responseTypes: z.array(z.string()).optional(),
  grantTypes: z.array(z.string()).optional(),
  devMode: z.boolean().optional(),
  action: Action,
  timestamp: z.string(),
});

const AppCredential = z.object({
  projectId: z.string(),
  appId: z.string(),
  name: z.string().optional(),
  clientId: z.string().optional(),
  // Present only on create/rotate, returned exactly once.
  clientSecret: z.string().meta({ sensitive: true }).optional(),
  kind: z.string(),
  action: Action,
  timestamp: z.string(),
});

const OidcRedirectResult = z.object({
  projectId: z.string(),
  appId: z.string(),
  name: z.string().optional(),
  previousRedirectUris: z.array(z.string()),
  redirectUris: z.array(z.string()),
  action: Action,
  timestamp: z.string(),
});

const UserInfo = z.object({
  userId: z.string(),
  username: z.string().optional(),
  type: z.string().describe("machine | human | unknown"),
  state: z.string(),
  displayName: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const MachineCredential = z.object({
  userId: z.string(),
  clientId: z.string().optional(),
  clientSecret: z.string().meta({ sensitive: true }).optional(),
  tokenId: z.string().optional(),
  // A PAT, returned exactly once.
  token: z.string().meta({ sensitive: true }).optional(),
  keyId: z.string().optional(),
  // The downloadable machine-key JSON, returned exactly once.
  keyDetails: z.string().meta({ sensitive: true }).optional(),
  expirationDate: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const ManagerInfo = z.object({
  userId: z.string(),
  displayName: z.string().optional(),
  roles: z.array(z.string()),
  action: Action,
  timestamp: z.string(),
});

const StateResult = z.object({
  kind: z.string().describe("app | user"),
  id: z.string(),
  state: z.string(),
  action: Action,
  timestamp: z.string(),
});

// ─────────────────────────── HTTP / auth seam ───────────────────────────

/** A JSON object: the resolved global args or an API body. */
export type Json = Record<string, unknown>;

/** One Management-API request: method + path (relative to `apiUrl`) + optional JSON body. */
export interface ApiCall {
  /** HTTP verb. */
  method: "GET" | "POST" | "PUT" | "DELETE";
  /** Path relative to `apiUrl`, e.g. `/management/v1/projects/_search`. */
  path: string;
  /** Optional JSON request body. */
  body?: unknown;
}

/** The parsed result of an {@link ApiCall}. */
export interface ApiResult {
  /** HTTP status code. */
  status: number;
  /** Parsed JSON response body (`{}` when empty). */
  body: Json;
}

/**
 * The authenticated-call seam the methods use, swappable for unit tests. The
 * global args are typed loosely as {@link Json} so this EXPORTED type passes
 * "fast-check" (referencing the zod-inferred `GlobalArgsT` would put a slow type
 * on the public API). The real implementation re-narrows.
 */
export type CallerFn = (g: Json, call: ApiCall) => Promise<ApiResult>;

let _callerOverride: CallerFn | null = null;

/** Test-only seam: substitute the API caller. Pass `null` to restore the real one. */
export function __setCaller(fn: CallerFn | null): void {
  _callerOverride = fn;
}

/** Parsed Zitadel machine-key JSON. */
interface KeyJson {
  keyId: string;
  key: string;
  userId?: string;
  clientId?: string;
}

function parseKeyJson(raw: string): KeyJson {
  let k: Partial<KeyJson>;
  try {
    k = JSON.parse(raw) as Partial<KeyJson>;
  } catch {
    throw new Error("keyJson is not valid JSON");
  }
  const subject = k.userId ?? k.clientId;
  if (!k.keyId || !k.key || !subject) {
    throw new Error("keyJson missing required keyId / key / userId");
  }
  return { keyId: k.keyId, key: k.key, userId: k.userId, clientId: k.clientId };
}

function b64url(input: Uint8Array | string): string {
  const bytes = typeof input === "string"
    ? new TextEncoder().encode(input)
    : input;
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function baseUrl(g: GlobalArgsT): string {
  return g.apiUrl.replace(/\/+$/, "");
}

/**
 * Build the JWT-bearer assertion claims for the service account. Pure (no crypto)
 * so it is unit-testable: `iss`/`sub` are the service user, `aud` is the issuer,
 * and the token lives ≤ 1 hour. Exported for tests.
 */
export function jwtAssertionClaims(
  keyJson: Json,
  apiUrl: string,
  nowSec: number,
): Json {
  const k = parseKeyJson(JSON.stringify(keyJson));
  const subject = k.userId ?? k.clientId;
  return {
    iss: subject,
    sub: subject,
    aud: apiUrl.replace(/\/+$/, ""),
    iat: nowSec,
    exp: nowSec + 3600,
  };
}

/** Decode a PEM block's base64 body to DER bytes; flags whether it's PKCS#8. */
function pemToDer(pem: string): { der: Uint8Array; isPkcs8: boolean } {
  const isPkcs8 = /BEGIN PRIVATE KEY/.test(pem);
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return { der, isPkcs8 };
}

/** DER length octets for a content length (short form < 128, else long form). */
function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 0xff);
  return [0x80 | out.length, ...out];
}

/**
 * Wrap a PKCS#1 `RSAPrivateKey` DER in the PKCS#8 `PrivateKeyInfo` envelope
 * (`SEQUENCE { version 0, AlgorithmIdentifier rsaEncryption, OCTET STRING pkcs1 }`),
 * so Web Crypto's `importKey("pkcs8", …)` accepts a Zitadel-issued PKCS#1 key.
 * Pure byte manipulation, deterministic, no dependencies.
 */
function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  // AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }
  const algId = [
    0x30,
    0x0d,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
  ];
  const version = [0x02, 0x01, 0x00];
  const octet = [0x04, ...derLen(pkcs1.length), ...pkcs1];
  const body = [...version, ...algId, ...octet];
  return new Uint8Array([0x30, ...derLen(body.length), ...body]);
}

/**
 * Import a PEM RSA private key (PKCS#1 or PKCS#8) as an RS256 signing key via
 * Web Crypto. Exported for tests. Zitadel keys are PKCS#1 → wrapped to PKCS#8.
 */
export async function importSigningKey(pemKey: string): Promise<CryptoKey> {
  const { der, isPkcs8 } = pemToDer(pemKey);
  const pkcs8 = isPkcs8 ? der : pkcs1ToPkcs8(der);
  // Back the key bytes with a plain ArrayBuffer: a Uint8Array<ArrayBufferLike>
  // is not accepted as BufferSource (it could be SharedArrayBuffer-backed).
  const buf = new ArrayBuffer(pkcs8.byteLength);
  new Uint8Array(buf).set(pkcs8);
  return await crypto.subtle.importKey(
    "pkcs8",
    buf,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function signAssertion(
  k: KeyJson,
  apiUrl: string,
  nowSec: number,
): Promise<string> {
  const header = b64url(
    JSON.stringify({ alg: "RS256", kid: k.keyId, typ: "JWT" }),
  );
  const payload = b64url(
    JSON.stringify(jwtAssertionClaims({ ...k }, apiUrl, nowSec)),
  );
  const input = `${header}.${payload}`;
  const key = await importSigningKey(k.key);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(input),
  );
  return `${input}.${b64url(new Uint8Array(sig))}`;
}

interface CachedToken {
  token: string;
  expSec: number;
}
const _tokenCache = new Map<string, CachedToken>();

/**
 * Fetch and read the whole body under one timeout. The body read is inside the
 * timer because a server can send headers promptly and then stall the body.
 */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<{ status: number; text: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    return { status: res.status, text: await res.text() };
  } finally {
    clearTimeout(t);
  }
}

async function getToken(g: GlobalArgsT): Promise<string> {
  const k = parseKeyJson(g.keyJson);
  const nowSec = Math.floor(Date.now() / 1000);
  const cached = _tokenCache.get(k.keyId);
  if (cached && cached.expSec - 60 > nowSec) return cached.token;
  const assertion = await signAssertion(k, g.apiUrl, nowSec);
  const form = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    scope: g.tokenScope,
    assertion,
  });
  const res = await fetchWithTimeout(
    `${baseUrl(g)}/oauth/v2/token`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    },
    g.httpTimeoutMs,
  );
  const { status, text } = res;
  if (status >= 400) {
    throw new Error(
      `Zitadel token exchange failed: HTTP ${status}: ${text}`,
    );
  }
  // A proxy in front of Zitadel can answer 200 with an HTML page.
  let j: { access_token?: string; expires_in?: number };
  try {
    j = JSON.parse(text);
  } catch {
    throw new Error(
      `Zitadel token exchange returned non-JSON (HTTP ${status}): ${
        text.slice(0, 200)
      }`,
    );
  }
  if (!j.access_token) {
    throw new Error("token exchange returned no access_token");
  }
  _tokenCache.set(k.keyId, {
    token: j.access_token,
    expSec: nowSec + (j.expires_in ?? 3600),
  });
  return j.access_token;
}

/** The real fetch-backed implementation behind {@link call}. */
async function realCaller(g: GlobalArgsT, c: ApiCall): Promise<ApiResult> {
  const token = await getToken(g);
  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
    accept: "application/json",
  };
  if (g.orgId) headers["x-zitadel-orgid"] = g.orgId;
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
  const { status, text } = res;
  let parsed: Json = {};
  if (text) {
    try {
      parsed = JSON.parse(text) as Json;
    } catch {
      parsed = { raw: text };
    }
  }
  if (status >= 400) {
    const msg = typeof parsed.message === "string" ? parsed.message : text;
    throw new Error(
      `Zitadel API ${c.method} ${c.path} -> HTTP ${status}: ${msg}`,
    );
  }
  return { status, body: parsed };
}

function call(g: GlobalArgsT, c: ApiCall): Promise<ApiResult> {
  return (_callerOverride ?? realCaller)(g, c);
}

// ─────────────────────────── helpers ───────────────────────────

type Ctx = MethodContext<GlobalArgsT>;

function logInfo(
  context: Pick<Ctx, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.info?.(message, props ?? {});
}

/**
 * The method's global args. Warns when `apiUrl` is plain http, because the
 * signed assertion and the access token then cross the network unencrypted.
 * Only a warning: a test instance on a private network may run without TLS.
 */
function globalsOf(context: Pick<Ctx, "globalArgs" | "logger">): GlobalArgsT {
  const g = context.globalArgs;
  if (/^http:\/\//i.test(g.apiUrl)) {
    context.logger?.warn?.(
      "apiUrl {apiUrl} is plain http: the access token is sent unencrypted",
      { apiUrl: g.apiUrl },
    );
  }
  return g;
}

/**
 * Read the new object's id from a create response. The object already exists
 * by then, so a missing id must fail loudly rather than be recorded as "".
 */
function requireId(body: Json, field: string, op: string): string {
  const id = body[field];
  if (typeof id !== "string" || !id) {
    throw new Error(`${op} returned no ${field}`);
  }
  return id;
}

function mgmt(path: string): string {
  return `/management/v1${path}`;
}

function asArray(v: unknown): Json[] {
  return Array.isArray(v) ? (v as Json[]) : [];
}

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * The data name for a record: `<spec>:<key>`. swamp keys stored data by model +
 * name, not spec, so without the prefix `user_list` would overwrite the client
 * secret `machine_secret_generate` stored under the same user id.
 *
 * swamp rejects `/`, `\`, `..` and NUL in a name, and a role key is free text,
 * so the key is percent-escaped. `%` is escaped first, so the mapping is
 * reversible and two different keys never share a name. Zitadel ids are
 * digits and pass through unchanged.
 */
function dataName(spec: string, key: string): string {
  const safeKey = key
    .replaceAll("%", "%25")
    .replaceAll("/", "%2F")
    .replaceAll("\\", "%5C")
    .replaceAll("\0", "%00")
    .replaceAll("..", ".%2E");
  return `${spec}:${safeKey}`;
}

/**
 * Page through a Zitadel `_search` endpoint and return all results (not just the
 * first page). Zitadel returns `details.totalResult` as a string; we loop on
 * offset until the accumulated count reaches it or a short page is returned.
 */
async function searchAll(
  g: GlobalArgsT,
  path: string,
  queries?: Json[],
): Promise<Json[]> {
  const limit = 100;
  let offset = 0;
  const all: Json[] = [];
  // Capped at 1000 pages; normally stops on a short page or once the total is reached.
  for (let guard = 0; guard < 1000; guard++) {
    const body: Json = { query: { offset, limit, asc: true } };
    if (queries && queries.length) body.queries = queries;
    const r = await call(g, { method: "POST", path, body });
    const page = asArray(r.body.result);
    all.push(...page);
    const details = (r.body.details ?? {}) as Json;
    const total = Number(details.totalResult);
    offset += page.length;
    if (page.length < limit) break;
    if (Number.isFinite(total) && all.length >= total) break;
    if (page.length === 0) break;
  }
  return all;
}

/** Find a project by exact name; returns the raw project object or null. */
async function findProjectByName(
  g: GlobalArgsT,
  name: string,
): Promise<Json | null> {
  const r = await call(g, {
    method: "POST",
    path: mgmt("/projects/_search"),
    body: {
      queries: [{
        nameQuery: { name, method: "TEXT_QUERY_METHOD_EQUALS" },
      }],
    },
  });
  return asArray(r.body.result).find((p) => p.name === name) ?? null;
}

/** Find an application by exact name within a project; returns it or null. */
async function findAppByName(
  g: GlobalArgsT,
  projectId: string,
  name: string,
): Promise<Json | null> {
  const r = await call(g, {
    method: "POST",
    path: mgmt(`/projects/${encodeURIComponent(projectId)}/apps/_search`),
    body: {
      queries: [{
        nameQuery: { name, method: "TEXT_QUERY_METHOD_EQUALS" },
      }],
    },
  });
  const result = asArray(r.body.result);
  return result.find((a) => a.name === name) ?? null;
}

/** Find a machine user by exact username; returns it or null. */
async function findMachineUserByUsername(
  g: GlobalArgsT,
  userName: string,
): Promise<Json | null> {
  const r = await call(g, {
    method: "POST",
    path: mgmt("/users/_search"),
    body: {
      // Machine users only, so a human with the same username is never taken
      // for one.
      queries: [
        { userNameQuery: { userName, method: "TEXT_QUERY_METHOD_EQUALS" } },
        { typeQuery: { type: "TYPE_MACHINE" } },
      ],
    },
  });
  return asArray(r.body.result).find((u) =>
    u.userName === userName && u.machine !== undefined
  ) ?? null;
}

/** A plain numeric Zitadel id is used as-is; anything else is treated as a username. */
function looksLikeId(s: string): boolean {
  return /^[0-9]+$/.test(s);
}

/** Resolve a machine-user reference (numeric id OR username) to a user id. */
async function resolveMachineUserId(
  g: GlobalArgsT,
  userRef: string,
): Promise<string> {
  if (looksLikeId(userRef)) return userRef;
  const u = await findMachineUserByUsername(g, userRef);
  // ListUsers result objects use `id`; AddMachineUser returns `userId`. Accept either.
  const uid = u ? (u.id ?? u.userId) : undefined;
  if (typeof uid !== "string") {
    throw new Error(
      `No machine user found with username ${JSON.stringify(userRef)}`,
    );
  }
  return uid;
}

/**
 * Resolve any user by numeric id or login name, falling back to a machine
 * user's username, which is how the grant methods were first called.
 */
async function resolveUserId(g: GlobalArgsT, userRef: string): Promise<string> {
  if (looksLikeId(userRef)) return userRef;
  const r = await call(g, {
    method: "POST",
    path: mgmt("/users/_search"),
    body: {
      queries: [{
        loginNameQuery: {
          loginName: userRef,
          method: "TEXT_QUERY_METHOD_EQUALS",
        },
      }],
    },
  });
  const u = asArray(r.body.result).find((x) =>
    x.preferredLoginName === userRef ||
    (Array.isArray(x.loginNames) && x.loginNames.includes(userRef))
  );
  if (typeof u?.id === "string") return u.id;
  const machine = await findMachineUserByUsername(g, userRef);
  const machineId = machine ? (machine.id ?? machine.userId) : undefined;
  if (typeof machineId !== "string") {
    throw new Error(
      `No user found with id, login name or machine username ${
        JSON.stringify(userRef)
      }`,
    );
  }
  return machineId;
}

/** Find a project role by exact key within a project; returns it or null. */
async function findRoleByKey(
  g: GlobalArgsT,
  projectId: string,
  roleKey: string,
): Promise<Json | null> {
  const r = await call(g, {
    method: "POST",
    path: mgmt(`/projects/${encodeURIComponent(projectId)}/roles/_search`),
    body: {
      queries: [{
        keyQuery: { key: roleKey, method: "TEXT_QUERY_METHOD_EQUALS" },
      }],
    },
  });
  // Role-search results key on `key`; the query is already EQUALS, and this
  // keeps the match exact if the server ever widens it.
  return asArray(r.body.result).find((ro) => ro.key === roleKey) ?? null;
}

/** Find a user grant by (userId, projectId); returns the raw grant or null. */
async function findGrant(
  g: GlobalArgsT,
  userId: string,
  projectId: string,
): Promise<Json | null> {
  const r = await call(g, {
    method: "POST",
    path: mgmt("/users/grants/_search"),
    body: {
      queries: [
        { userIdQuery: { userId } },
        { projectIdQuery: { projectId } },
      ],
    },
  });
  return asArray(r.body.result).find((gr) =>
    gr.userId === userId && gr.projectId === projectId
  ) ?? null;
}

/** Shape a raw user-grant record into {@link GrantInfo}. */
function shapeGrant(gr: Json, action: z.infer<typeof Action>, ts: string) {
  return {
    grantId: String(gr.id ?? ""),
    userId: String(gr.userId ?? ""),
    projectId: String(gr.projectId ?? ""),
    roleKeys: Array.isArray(gr.roleKeys) ? (gr.roleKeys as string[]) : [],
    state: friendlyState(gr.state),
    displayName: typeof gr.displayName === "string"
      ? gr.displayName
      : undefined,
    action,
    timestamp: ts,
  };
}

/** Shape an application's search/get record into {@link AppInfo} (no secrets). */
function shapeApp(
  projectId: string,
  a: Json,
  action: z.infer<typeof Action>,
  ts: string,
) {
  const oidc = (a.oidcConfig ?? {}) as Json;
  const api = (a.apiConfig ?? {}) as Json;
  const kind = a.oidcConfig
    ? "oidc"
    : a.apiConfig
    ? "api"
    : a.samlConfig
    ? "saml"
    : "unknown";
  const clientId = (oidc.clientId ?? api.clientId) as string | undefined;
  return {
    projectId,
    appId: String(a.id ?? ""),
    name: String(a.name ?? ""),
    state: friendlyState(a.state),
    kind,
    clientId,
    // OIDC config fields use proto3 zero-value omission: appType=web,
    // accessTokenType=bearer and devMode=false come back absent. Normalise to
    // the effective default for OIDC apps so reads show the complete config and
    // a read-then-converge changes only what's intended. Left undefined for
    // non-OIDC (api/saml) apps, where these fields don't apply.
    appType: a.oidcConfig
      ? (typeof oidc.appType === "string"
        ? (APP_TYPE_REV[oidc.appType] ?? friendlyState(oidc.appType))
        : "web")
      : undefined,
    accessTokenType: a.oidcConfig
      ? (typeof oidc.accessTokenType === "string"
        ? (ACCESS_TOKEN_TYPE_REV[oidc.accessTokenType] ??
          friendlyState(oidc.accessTokenType))
        : "bearer")
      : undefined,
    // BASIC is enum value 0 for both OIDC and API apps, so it is omitted too.
    authMethod: a.oidcConfig || a.apiConfig
      ? (typeof (oidc.authMethodType ?? api.authMethodType) === "string"
        ? friendlyState(oidc.authMethodType ?? api.authMethodType)
        : "basic")
      : undefined,
    redirectUris: Array.isArray(oidc.redirectUris)
      ? (oidc.redirectUris as string[])
      : undefined,
    postLogoutUris: Array.isArray(oidc.postLogoutRedirectUris)
      ? (oidc.postLogoutRedirectUris as string[])
      : undefined,
    responseTypes: friendlyEnumArr(oidc.responseTypes, RESPONSE_TYPE_REV),
    grantTypes: friendlyEnumArr(oidc.grantTypes, GRANT_TYPE_REV),
    devMode: a.oidcConfig
      ? (typeof oidc.devMode === "boolean" ? oidc.devMode : false)
      : undefined,
    action,
    timestamp: ts,
  };
}

// ─────────────────────────── method argument schemas ───────────────────────────

/**
 * An array argument that also accepts a JSON-encoded string (so the raw CLI
 * `--input key=["a","b"]` works); a real array (from CEL/workflows) passes through.
 */
function jsonArray<T extends z.ZodTypeAny>(item: T): z.ZodType<z.infer<T>[]> {
  return z.preprocess((v) => {
    if (typeof v === "string") {
      const s = v.trim();
      if (s.startsWith("[")) {
        try {
          return JSON.parse(s);
        } catch {
          return v;
        }
      }
    }
    return v;
  }, z.array(item)) as z.ZodType<z.infer<T>[]>;
}

const Empty = z.object({});

const AppListArgs = z.object({
  projectId: z.string().describe("Project id to list applications for"),
});

const AppGetArgs = z.object({
  projectId: z.string(),
  appId: z.string(),
});

const OidcAppRedirectSetArgs = z.object({
  projectId: z.string().describe("Project id (from app_list / project_list)"),
  appId: z.string().describe("Application id (from app_list)"),
  add: jsonArray(z.string()).default([]).describe(
    "Redirect URIs that must be present (idempotent append)",
  ),
  remove: jsonArray(z.string()).default([]).describe(
    "Redirect URIs that must be absent (for cleanup)",
  ),
}).refine(
  (a) => a.add.length > 0 || a.remove.length > 0,
  { message: "provide add and/or remove" },
);

const UserListArgs = z.object({
  type: z.enum(["machine", "human", "any"]).default("any").describe(
    "Filter by user type",
  ),
});

const ProjectEnsureArgs = z.object({
  name: z.string().describe("Project name (find-or-create by exact name)"),
});

const OidcAppEnsureArgs = z.object({
  project: z.string().describe(
    "Project name (created if absent) or project id",
  ),
  name: z.string().describe(
    "Application name (find-or-create within the project)",
  ),
  // No schema defaults: they would read as explicit values and reset an
  // existing app. OIDC_APP_DEFAULTS applies on create.
  redirectUris: jsonArray(z.string()).optional().describe(
    "Allowed redirect URIs",
  ),
  postLogoutUris: jsonArray(z.string()).optional().describe(
    "Allowed post-logout redirect URIs",
  ),
  appType: z.enum(["web", "spa", "native"]).optional(),
  authMethod: z.enum(["basic", "post", "none", "jwt"]).optional()
    .describe(
      "OIDC client auth method. Use `none` for public PKCE (SPA/native).",
    ),
  grantTypes: jsonArray(
    z.enum(["authorization_code", "implicit", "refresh_token", "device_code"]),
  ).optional(),
  responseTypes: jsonArray(z.enum(["code", "id_token", "id_token_token"]))
    .optional(),
  accessTokenType: z.enum(["bearer", "jwt"]).optional(),
  devMode: z.boolean().optional().describe(
    "Relax redirect-URI checks (non-https/localhost). Test only.",
  ),
});

/** What a new OIDC app gets for each config field the caller leaves out. */
const OIDC_APP_DEFAULTS = {
  redirectUris: [] as string[],
  postLogoutUris: [] as string[],
  appType: "web",
  authMethod: "basic",
  grantTypes: ["authorization_code", "refresh_token"],
  responseTypes: ["code"],
  accessTokenType: "bearer",
  devMode: false,
};

/**
 * Every field Zitadel's oidc_config update accepts. The update replaces all of
 * them, so an existing app's body starts from its current values for these.
 */
const OIDC_UPDATE_FIELDS = [
  "redirectUris",
  "responseTypes",
  "grantTypes",
  "appType",
  "authMethodType",
  "postLogoutRedirectUris",
  "devMode",
  "accessTokenType",
  "accessTokenRoleAssertion",
  "idTokenRoleAssertion",
  "idTokenUserinfoAssertion",
  "clockSkew",
  "additionalOrigins",
  "skipNativeAppSuccessPage",
  "backChannelLogoutUri",
  "loginVersion",
  "ios",
  "android",
];

/** Map the config fields that were passed onto Zitadel's wire names. */
function oidcWireConfig(
  a: Partial<typeof OIDC_APP_DEFAULTS>,
): Json {
  const cfg: Json = {};
  if (a.redirectUris !== undefined) cfg.redirectUris = a.redirectUris;
  if (a.postLogoutUris !== undefined) {
    cfg.postLogoutRedirectUris = a.postLogoutUris;
  }
  if (a.responseTypes !== undefined) {
    cfg.responseTypes = a.responseTypes.map((t) =>
      mapEnum(RESPONSE_TYPE, t, "responseType")
    );
  }
  if (a.grantTypes !== undefined) {
    cfg.grantTypes = a.grantTypes.map((t) =>
      mapEnum(GRANT_TYPE, t, "grantType")
    );
  }
  if (a.appType !== undefined) {
    cfg.appType = mapEnum(APP_TYPE, a.appType, "appType");
  }
  if (a.authMethod !== undefined) {
    cfg.authMethodType = mapEnum(AUTH_METHOD, a.authMethod, "authMethod");
  }
  if (a.accessTokenType !== undefined) {
    cfg.accessTokenType = mapEnum(
      ACCESS_TOKEN_TYPE,
      a.accessTokenType,
      "accessTokenType",
    );
  }
  if (a.devMode !== undefined) cfg.devMode = a.devMode;
  return cfg;
}

const ApiAppEnsureArgs = z.object({
  project: z.string(),
  name: z.string(),
  authMethod: z.enum(["basic", "jwt"]).default("jwt"),
});

const AppSecretRotateArgs = z.object({
  projectId: z.string(),
  appId: z.string(),
  // No default: the kind is read from the app. A passed kind is checked
  // against it.
  kind: z.enum(["oidc", "api"]).optional().describe(
    "Optional check: the method refuses if the app is not of this kind",
  ),
});

const MachineUserEnsureArgs = z.object({
  username: z.string().describe("Login name (find-or-create)"),
  name: z.string().describe("Display name"),
  description: z.string().optional(),
  accessTokenType: z.enum(["bearer", "jwt"]).default("bearer"),
});

const PatCreateArgs = z.object({
  user: z.string().describe("Machine user id or username"),
  expirationDate: z.string().optional().describe(
    "RFC3339 expiry, e.g. 2027-01-01T00:00:00Z (omit for none)",
  ),
});

const PatRevokeArgs = z.object({
  user: z.string().describe("Machine user id or username"),
  tokenId: z.string().describe(
    "PAT id to revoke (verified to belong to the user first)",
  ),
});

const MachineKeyCreateArgs = z.object({
  user: z.string().describe("Machine user id or username"),
  expirationDate: z.string().optional(),
});

const MachineSecretArgs = z.object({
  user: z.string().describe("Machine user id or username"),
});

const AppSetStateArgs = z.object({
  projectId: z.string(),
  appId: z.string(),
  state: z.enum(["active", "inactive"]),
});

const UserSetStateArgs = z.object({
  userId: z.string(),
  state: z.enum(["active", "inactive"]),
});

const RoleListArgs = z.object({
  projectId: z.string().describe("Project id to list roles for"),
});

const RoleEnsureArgs = z.object({
  project: z.string().describe(
    "Project name (created if absent) or project id",
  ),
  key: z.string().describe("Role key (stable identifier; find-or-create)"),
  displayName: z.string().optional().describe("Human-readable role name"),
  group: z.string().optional().describe("Optional grouping label for the role"),
});

const RoleRemoveArgs = z.object({
  projectId: z.string(),
  key: z.string().describe("Role key to remove (verified to exist first)"),
});

const GrantListArgs = z.object({
  user: z.string().optional().describe(
    "Filter by user id or login name (omit for all users)",
  ),
  projectId: z.string().optional().describe(
    "Filter by project id (omit for all projects)",
  ),
});

const GrantEnsureArgs = z.object({
  user: z.string().describe(
    "User id or login name (e.g. alice@example.com) to grant roles to",
  ),
  project: z.string().describe(
    "Project name or project id (the project must exist)",
  ),
  // No default: an empty default would read as "strip every role" on a re-run.
  roleKeys: jsonArray(z.string()).optional().describe(
    "The exact set of role keys the user should hold on this project (converged). " +
      "Omit to keep an existing grant's roles as they are; a new grant gets none.",
  ),
});

const GrantSetStateArgs = z.object({
  user: z.string().describe("User id or login name the grant belongs to"),
  grantId: z.string().describe(
    "Grant id (verified to belong to the user first)",
  ),
  state: z.enum(["active", "inactive"]),
});

const ProjectAuthzSetArgs = z.object({
  project: z.string().describe("Project name or project id"),
  roleAssertion: z.boolean().optional().describe(
    "Assert project roles into tokens/userinfo (the flag that surfaces grants)",
  ),
  roleCheck: z.boolean().optional().describe(
    "Require a project role to authenticate",
  ),
  hasProjectCheck: z.boolean().optional().describe(
    "Require the user's org to have the project granted",
  ),
});

// ─────────────────────────── model ───────────────────────────

/**
 * The `@thomas/zitadel` model definition. See the file header for the scope
 * guarantee. Read methods never emit secrets; mutating methods are idempotent
 * where possible and emit minted secrets exactly once as sensitive output. The
 * only deletes are `role_remove` and `pat_revoke`, both verify-first.
 */
export const model = {
  type: "@thomas/zitadel",
  version: "2026.10.11.1",
  globalArguments: GlobalArgs,
  upgrades: [
    {
      toVersion: "2026.10.11.1",
      description:
        "httpTimeoutMs must now be positive; a zero or negative value is dropped so the 30000 ms default applies. Stored data is renamed to <spec>:<key> (or <spec>); records under the old names are left as they are and are not migrated.",
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
  ],
  checks: {
    "reachable": {
      description:
        "Verify the instance is reachable and the service-account key authenticates (token exchange)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        // Checks get globalArgs without the schema's defaults; parse to apply them.
        const parsed = GlobalArgs.safeParse(context.globalArgs);
        if (!parsed.success) {
          return { pass: false, errors: [z.prettifyError(parsed.error)] };
        }
        const g = parsed.data;
        try {
          await getToken(g);
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Cannot authenticate to Zitadel at ${g.apiUrl}: ${
                (e as Error).message
              }`,
            ],
          };
        }
      },
    },
  },
  resources: {
    "org": {
      description: "An organization record",
      schema: OrgInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "project": {
      description: "A project record / ensure result",
      schema: ProjectInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "app": {
      description: "An application record (config only; never a secret)",
      schema: AppInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "oidc-redirect-result": {
      description: "Result of an oidc_app_redirect_set change",
      schema: OidcRedirectResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "app-credential": {
      description:
        "Result of creating/rotating an app (clientId + clientSecret once)",
      schema: AppCredential,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "user": {
      description: "A user record / ensure result",
      schema: UserInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "machine-credential": {
      description:
        "Result of minting a machine credential (PAT / key / secret); secret once",
      schema: MachineCredential,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "manager": {
      description: "An org manager (member) and their roles",
      schema: ManagerInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "role": {
      description: "A project role (key/displayName/group)",
      schema: RoleInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "grant": {
      description: "A user grant: which roles a user holds on a project",
      schema: GrantInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "state-result": {
      description: "Result of a reversible deactivate/reactivate",
      schema: StateResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    // ───────────── read / audit ─────────────
    org_get: {
      description:
        "Get the caller's organization (id/name/state/domain). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = globalsOf(context);
        logInfo(context, "Reading the service user's org");
        const r = await call(g, { method: "GET", path: mgmt("/orgs/me") });
        const o = (r.body.org ?? {}) as Json;
        logInfo(context, "Read org {name} ({id})", { name: o.name, id: o.id });
        const handle = await context.writeResource(
          "org",
          dataName("org", String(o.id ?? "me")),
          {
            id: String(o.id ?? ""),
            name: String(o.name ?? ""),
            state: friendlyState(o.state),
            primaryDomain: typeof o.primaryDomain === "string"
              ? o.primaryDomain
              : undefined,
            action: "observed",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    project_list: {
      description:
        "List projects (factory: one `project` per project). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = globalsOf(context);
        logInfo(context, "Listing projects");
        const result = await searchAll(g, mgmt("/projects/_search"));
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const p of result) {
          handles.push(
            await context.writeResource(
              "project",
              dataName("project", String(p.id)),
              {
                id: String(p.id ?? ""),
                name: String(p.name ?? ""),
                state: friendlyState(p.state),
                // The API omits a false flag (proto3 zero value), so absent
                // means false, as in project_authz_set.
                roleAssertion: p.projectRoleAssertion === true,
                roleCheck: p.projectRoleCheck === true,
                hasProjectCheck: p.hasProjectCheck === true,
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Listed {count} projects", { count: handles.length });
        return { dataHandles: handles };
      },
    },
    app_list: {
      description:
        "List applications in a project with their OIDC/API config (no secrets). Read-only.",
      arguments: AppListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AppListArgs.parse(rawArgs);
        const g = globalsOf(context);
        logInfo(context, "Listing apps in project {projectId}", {
          projectId: a.projectId,
        });
        const result = await searchAll(
          g,
          mgmt(`/projects/${encodeURIComponent(a.projectId)}/apps/_search`),
        );
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const app of result) {
          handles.push(
            await context.writeResource(
              "app",
              dataName("app", String(app.id)),
              shapeApp(a.projectId, app, "observed", ts),
            ),
          );
        }
        logInfo(context, "Listed {count} apps", { count: handles.length });
        return { dataHandles: handles };
      },
    },
    app_get: {
      description: "Get one application's full config (no secret). Read-only.",
      arguments: AppGetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AppGetArgs.parse(rawArgs);
        const g = globalsOf(context);
        logInfo(context, "Reading app {appId} in project {projectId}", {
          appId: a.appId,
          projectId: a.projectId,
        });
        const r = await call(g, {
          method: "GET",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }`,
          ),
        });
        const app = (r.body.app ?? {}) as Json;
        logInfo(context, "Read app {name}", { name: app.name });
        const handle = await context.writeResource(
          "app",
          dataName("app", a.appId),
          shapeApp(a.projectId, app, "observed", nowIso()),
        );
        return { dataHandles: [handle] };
      },
    },
    oidc_app_redirect_set: {
      description:
        "Add and/or remove redirect URIs on an OIDC app's allowlist via read-modify-" +
        "write: fetches the live oidc_config and re-PUTs it with only redirectUris " +
        "changed, preserving every other field (PKCE/auth method/response types/…). " +
        "Safe on shared clients where a full converge would risk clobbering. Idempotent.",
      arguments: OidcAppRedirectSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = OidcAppRedirectSetArgs.parse(rawArgs);
        const g = globalsOf(context);
        const ts = nowIso();
        logInfo(context, "Reading the redirect URIs of app {appId}", {
          appId: a.appId,
        });

        const got = await call(g, {
          method: "GET",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }`,
          ),
        });
        const app = (got.body.app ?? {}) as Json;
        const oidc = app.oidcConfig as Json | undefined;
        if (!oidc) {
          throw new Error(
            `app ${a.appId} has no oidcConfig (not an OIDC app)`,
          );
        }

        const prev = asArray(oidc.redirectUris).map(String);
        const removeSet = new Set(a.remove);
        const next = prev.filter((u) => !removeSet.has(u));
        for (const u of a.add) if (!next.includes(u)) next.push(u);

        const name = typeof app.name === "string" ? app.name : undefined;
        if (
          next.length === prev.length && next.every((u, i) => u === prev[i])
        ) {
          logInfo(context, "Redirect URIs of app {appId} already match", {
            appId: a.appId,
          });
          const handle = await context.writeResource(
            "oidc-redirect-result",
            dataName("oidc-redirect-result", a.appId),
            {
              projectId: a.projectId,
              appId: a.appId,
              name,
              previousRedirectUris: prev,
              redirectUris: prev,
              action: "unchanged",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        }

        // The update replaces every field, so the body starts from the current
        // config (raw API enum values round-trip on PUT) and only redirectUris
        // changes. Read-only fields (clientId, complianceProblems) are not sent.
        const body: Json = {};
        for (const k of OIDC_UPDATE_FIELDS) {
          if (oidc[k] !== undefined) body[k] = oidc[k];
        }
        body.redirectUris = next;

        logInfo(context, "Setting redirect URIs of app {appId}: {*}", {
          appId: a.appId,
          added: a.add,
          removed: a.remove,
        });
        await call(g, {
          method: "PUT",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }/oidc_config`,
          ),
          body,
        });

        const after = await call(g, {
          method: "GET",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }`,
          ),
        });
        const afterOidc = ((after.body.app ?? {}) as Json).oidcConfig as
          | Json
          | undefined;
        const handle = await context.writeResource(
          "oidc-redirect-result",
          dataName("oidc-redirect-result", a.appId),
          {
            projectId: a.projectId,
            appId: a.appId,
            name,
            previousRedirectUris: prev,
            redirectUris: asArray(afterOidc?.redirectUris).map(String),
            action: "updated",
            timestamp: ts,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    user_list: {
      description:
        "List users, optionally filtered by type (factory: one `user` each). Read-only.",
      arguments: UserListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = UserListArgs.parse(rawArgs);
        const g = globalsOf(context);
        logInfo(context, "Listing users of type {type}", { type: a.type });
        const queries: Json[] = [];
        if (a.type !== "any") {
          queries.push({
            typeQuery: {
              type: a.type === "machine" ? "TYPE_MACHINE" : "TYPE_HUMAN",
            },
          });
        }
        const result = await searchAll(
          g,
          mgmt("/users/_search"),
          queries.length ? queries : undefined,
        );
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const u of result) {
          const human = (u.human ?? {}) as Json;
          const machine = (u.machine ?? {}) as Json;
          const profile = (human.profile ?? {}) as Json;
          handles.push(
            await context.writeResource(
              "user",
              dataName("user", String(u.userId ?? u.id)),
              {
                userId: String(u.userId ?? u.id ?? ""),
                username: typeof u.userName === "string"
                  ? u.userName
                  : undefined,
                type: u.human ? "human" : u.machine ? "machine" : "unknown",
                state: friendlyState(u.state),
                displayName: (machine.name as string) ??
                  (profile.displayName as string) ?? undefined,
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Listed {count} users", { count: handles.length });
        return { dataHandles: handles };
      },
    },
    manager_audit: {
      description:
        "List org managers (members) and their roles: who can administer this org. Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = globalsOf(context);
        logInfo(context, "Listing org managers");
        const result = await searchAll(g, mgmt("/orgs/me/members/_search"));
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const m of result) {
          handles.push(
            await context.writeResource(
              "manager",
              dataName("manager", String(m.userId)),
              {
                userId: String(m.userId ?? ""),
                displayName: typeof m.displayName === "string"
                  ? m.displayName
                  : undefined,
                roles: Array.isArray(m.roles) ? (m.roles as string[]) : [],
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Listed {count} managers", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    // ───────────── provision ─────────────
    project_ensure: {
      description: "Find-or-create a project by name. Idempotent.",
      arguments: ProjectEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ProjectEnsureArgs.parse(rawArgs);
        const g = globalsOf(context);
        const existing = await findProjectByName(g, a.name);
        let id: string;
        let action: z.infer<typeof Action>;
        let state = "active";
        if (existing && typeof existing.id === "string") {
          id = existing.id;
          state = friendlyState(existing.state);
          action = "unchanged";
          logInfo(context, "Project {name} already exists ({id})", {
            name: a.name,
            id,
          });
        } else {
          const r = await call(g, {
            method: "POST",
            path: mgmt("/projects"),
            body: { name: a.name },
          });
          id = requireId(r.body, "id", "project create");
          action = "created";
          logInfo(context, "Created project {name} ({id})", {
            name: a.name,
            id,
          });
        }
        const handle = await context.writeResource(
          "project",
          dataName("project", id),
          {
            id,
            name: a.name,
            state,
            action,
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    oidc_app_ensure: {
      description:
        "Ensure an OIDC application: find-or-create by name within the project " +
        "(a project name with no match is created), then converge the passed " +
        "config fields. Returns clientId, and clientSecret once on create for " +
        "confidential clients. Refuses a name that belongs to a non-OIDC app.",
      arguments: OidcAppEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = OidcAppEnsureArgs.parse(rawArgs);
        const g = globalsOf(context);
        const projectId = await ensureProjectId(g, a.project, context);
        const existing = await findAppByName(g, projectId, a.name);
        const ts = nowIso();
        if (existing && typeof existing.id === "string") {
          if (!existing.oidcConfig) {
            throw new Error(
              `App ${
                JSON.stringify(a.name)
              } (${existing.id}) is not an OIDC app`,
            );
          }
          // Converge only the fields that were passed. The update replaces
          // every field, so the rest are carried over from the current config.
          const current = (existing.oidcConfig ?? {}) as Json;
          const cfg: Json = {};
          for (const f of OIDC_UPDATE_FIELDS) {
            if (current[f] !== undefined) cfg[f] = current[f];
          }
          Object.assign(cfg, oidcWireConfig(a));
          // Zitadel returns 400 "No changes" when the config already matches;
          // report that as unchanged.
          let action: z.infer<typeof Action> = "updated";
          try {
            await call(g, {
              method: "PUT",
              path: mgmt(
                `/projects/${encodeURIComponent(projectId)}/apps/${
                  encodeURIComponent(existing.id)
                }/oidc_config`,
              ),
              body: cfg,
            });
          } catch (e) {
            if (/no changes/i.test((e as Error).message)) {
              action = "unchanged";
            } else {
              throw e;
            }
          }
          logInfo(context, "Converged OIDC app {name} ({appId}): {action}", {
            name: a.name,
            appId: existing.id,
            action,
          });
          const handle = await context.writeResource(
            "app-credential",
            dataName("app-credential", existing.id),
            {
              projectId,
              appId: existing.id,
              name: a.name,
              clientId: typeof current.clientId === "string"
                ? current.clientId
                : undefined,
              kind: "oidc",
              action,
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        }
        const r = await call(g, {
          method: "POST",
          path: mgmt(`/projects/${encodeURIComponent(projectId)}/apps/oidc`),
          body: {
            name: a.name,
            ...oidcWireConfig({ ...OIDC_APP_DEFAULTS, ...a }),
          },
        });
        const appId = requireId(r.body, "appId", "OIDC app create");
        logInfo(context, "Created OIDC app {name} ({appId})", {
          name: a.name,
          appId,
        });
        const handle = await context.writeResource(
          "app-credential",
          dataName("app-credential", appId),
          {
            projectId,
            appId,
            name: a.name,
            clientId: typeof r.body.clientId === "string"
              ? r.body.clientId
              : undefined,
            clientSecret: typeof r.body.clientSecret === "string"
              ? r.body.clientSecret
              : undefined,
            kind: "oidc",
            action: "created",
            timestamp: ts,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    api_app_ensure: {
      description:
        "Find-or-create an API application (resource server / M2M) by name " +
        "within the project (a project name with no match is created). An " +
        "existing app is left as it is: authMethod applies on create only. " +
        "Returns clientId, and clientSecret once on create for the basic method. " +
        "Refuses a name that belongs to a non-API app.",
      arguments: ApiAppEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ApiAppEnsureArgs.parse(rawArgs);
        const g = globalsOf(context);
        const projectId = await ensureProjectId(g, a.project, context);
        const existing = await findAppByName(g, projectId, a.name);
        const ts = nowIso();
        if (existing && typeof existing.id === "string") {
          if (!existing.apiConfig) {
            throw new Error(
              `App ${
                JSON.stringify(a.name)
              } (${existing.id}) is not an API app`,
            );
          }
          logInfo(context, "API app {name} already exists ({appId})", {
            name: a.name,
            appId: existing.id,
          });
          const api = existing.apiConfig as Json;
          const handle = await context.writeResource(
            "app-credential",
            dataName("app-credential", existing.id),
            {
              projectId,
              appId: existing.id,
              name: a.name,
              clientId: typeof api.clientId === "string"
                ? api.clientId
                : undefined,
              kind: "api",
              action: "unchanged",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        }
        const r = await call(g, {
          method: "POST",
          path: mgmt(`/projects/${encodeURIComponent(projectId)}/apps/api`),
          body: {
            name: a.name,
            authMethodType: mapEnum(
              API_AUTH_METHOD,
              a.authMethod,
              "authMethod",
            ),
          },
        });
        const appId = requireId(r.body, "appId", "API app create");
        logInfo(context, "Created API app {name} ({appId})", {
          name: a.name,
          appId,
        });
        const handle = await context.writeResource(
          "app-credential",
          dataName("app-credential", appId),
          {
            projectId,
            appId,
            name: a.name,
            clientId: typeof r.body.clientId === "string"
              ? r.body.clientId
              : undefined,
            clientSecret: typeof r.body.clientSecret === "string"
              ? r.body.clientSecret
              : undefined,
            kind: "api",
            action: "created",
            timestamp: ts,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── rotate ─────────────
    app_secret_rotate: {
      description:
        "Regenerate an application's client secret. Reads the app first and " +
        "takes its kind (oidc or api) from it. Returns the new secret once.",
      arguments: AppSecretRotateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AppSecretRotateArgs.parse(rawArgs);
        const g = globalsOf(context);
        // Verify-first: confirm the app exists, and read its kind, before
        // mutating. Each kind has its own regenerate endpoint.
        const got = await call(g, {
          method: "GET",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }`,
          ),
        });
        const app = (got.body.app ?? {}) as Json;
        const kind = app.oidcConfig
          ? "oidc"
          : app.apiConfig
          ? "api"
          : undefined;
        if (!kind) {
          throw new Error(
            `App ${a.appId} is neither an OIDC nor an API app; it has no client secret`,
          );
        }
        if (a.kind !== undefined && a.kind !== kind) {
          throw new Error(
            `App ${a.appId} is an ${kind} app, not ${a.kind}; refusing to rotate`,
          );
        }
        logInfo(context, "Rotating the secret of {kind} app {appId}", {
          kind,
          appId: a.appId,
        });
        const cfgPath = kind === "api" ? "api_config" : "oidc_config";
        const r = await call(g, {
          method: "POST",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }/${cfgPath}/_generate_client_secret`,
          ),
          body: {},
        });
        logInfo(context, "Rotated the secret of app {appId}", {
          appId: a.appId,
        });
        const handle = await context.writeResource(
          "app-credential",
          dataName("app-credential", a.appId),
          {
            projectId: a.projectId,
            appId: a.appId,
            clientId: typeof r.body.clientId === "string"
              ? r.body.clientId
              : undefined,
            clientSecret: typeof r.body.clientSecret === "string"
              ? r.body.clientSecret
              : undefined,
            kind,
            action: "rotated",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    machine_user_ensure: {
      description:
        "Find-or-create a machine (service) user by username. Idempotent.",
      arguments: MachineUserEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MachineUserEnsureArgs.parse(rawArgs);
        const g = globalsOf(context);
        const existing = await findMachineUserByUsername(g, a.username);
        const ts = nowIso();
        // ListUsers results use `id`; tolerate `userId` too.
        const existingId = existing
          ? (existing.id ?? existing.userId)
          : undefined;
        if (existing && typeof existingId === "string") {
          logInfo(
            context,
            "Machine user {username} already exists ({userId})",
            {
              username: a.username,
              userId: existingId,
            },
          );
          const handle = await context.writeResource(
            "user",
            dataName("user", existingId),
            {
              userId: existingId,
              username: a.username,
              type: "machine",
              state: friendlyState(existing.state),
              // The user as it is, not the arguments: an existing user is not
              // updated.
              displayName: String(
                (existing.machine as Json | undefined)?.name ?? a.name,
              ),
              action: "unchanged",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        }
        const r = await call(g, {
          method: "POST",
          path: mgmt("/users/machine"),
          body: {
            userName: a.username,
            name: a.name,
            description: a.description,
            accessTokenType: a.accessTokenType === "jwt"
              ? "ACCESS_TOKEN_TYPE_JWT"
              : "ACCESS_TOKEN_TYPE_BEARER",
          },
        });
        const userId = requireId(r.body, "userId", "machine user create");
        logInfo(context, "Created machine user {username} ({userId})", {
          username: a.username,
          userId,
        });
        const handle = await context.writeResource(
          "user",
          dataName("user", userId),
          {
            userId,
            username: a.username,
            type: "machine",
            state: "active",
            displayName: a.name,
            action: "created",
            timestamp: ts,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    pat_create: {
      description:
        "Add a personal access token to a machine user. Returns the token once.",
      arguments: PatCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PatCreateArgs.parse(rawArgs);
        const g = globalsOf(context);
        const userId = await resolveMachineUserId(g, a.user);
        const r = await call(g, {
          method: "POST",
          path: mgmt(`/users/${encodeURIComponent(userId)}/pats`),
          body: a.expirationDate ? { expirationDate: a.expirationDate } : {},
        });
        const tokenId = requireId(r.body, "tokenId", "PAT create");
        logInfo(context, "Created PAT {tokenId} for user {userId}", {
          userId,
          tokenId,
        });
        const handle = await context.writeResource(
          "machine-credential",
          dataName("machine-credential", `pat:${tokenId}`),
          {
            userId,
            tokenId,
            token: typeof r.body.token === "string" ? r.body.token : undefined,
            expirationDate: a.expirationDate,
            action: "created",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    pat_revoke: {
      description:
        "Revoke a PAT. Verify-first: confirms the tokenId belongs to the user before deleting.",
      arguments: PatRevokeArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PatRevokeArgs.parse(rawArgs);
        const g = globalsOf(context);
        const userId = await resolveMachineUserId(g, a.user);
        // Verify-first: the tokenId must exist under this user. Every page is
        // read: one request returns at most the server's query limit.
        const pats = await searchAll(
          g,
          mgmt(`/users/${encodeURIComponent(userId)}/pats/_search`),
        );
        const owned = pats.some((p) => String(p.id) === a.tokenId);
        if (!owned) {
          throw new Error(
            `PAT ${
              JSON.stringify(a.tokenId)
            } not found on user ${userId}; refusing to revoke`,
          );
        }
        await call(g, {
          method: "DELETE",
          path: mgmt(
            `/users/${encodeURIComponent(userId)}/pats/${
              encodeURIComponent(a.tokenId)
            }`,
          ),
        });
        logInfo(context, "Revoked PAT {tokenId} of user {userId}", {
          userId,
          tokenId: a.tokenId,
        });
        const handle = await context.writeResource(
          "machine-credential",
          dataName("machine-credential", `pat:${a.tokenId}`),
          {
            userId,
            tokenId: a.tokenId,
            action: "revoked",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    machine_key_create: {
      description:
        "Add a JSON private key to a machine user. Returns the downloadable key JSON once.",
      arguments: MachineKeyCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MachineKeyCreateArgs.parse(rawArgs);
        const g = globalsOf(context);
        const userId = await resolveMachineUserId(g, a.user);
        const r = await call(g, {
          method: "POST",
          path: mgmt(`/users/${encodeURIComponent(userId)}/keys`),
          body: {
            type: "KEY_TYPE_JSON",
            expirationDate: a.expirationDate,
          },
        });
        const keyId = requireId(r.body, "keyId", "machine key create");
        // keyDetails comes back base64-encoded; decode to the JSON the operator stores.
        let keyDetails: string | undefined;
        if (typeof r.body.keyDetails === "string") {
          try {
            keyDetails = new TextDecoder().decode(
              Uint8Array.from(atob(r.body.keyDetails), (c) => c.charCodeAt(0)),
            );
          } catch {
            keyDetails = r.body.keyDetails;
          }
        }
        logInfo(context, "Created machine key {keyId} for user {userId}", {
          userId,
          keyId,
        });
        const handle = await context.writeResource(
          "machine-credential",
          dataName("machine-credential", `key:${keyId}`),
          {
            userId,
            keyId,
            keyDetails,
            expirationDate: a.expirationDate,
            action: "created",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    machine_secret_generate: {
      description:
        "Generate (rotate) a machine user's client secret. Returns the secret once.",
      arguments: MachineSecretArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MachineSecretArgs.parse(rawArgs);
        const g = globalsOf(context);
        const userId = await resolveMachineUserId(g, a.user);
        const r = await call(g, {
          method: "PUT",
          path: mgmt(`/users/${encodeURIComponent(userId)}/secret`),
          body: {},
        });
        logInfo(context, "Generated a client secret for user {userId}", {
          userId,
        });
        const handle = await context.writeResource(
          "machine-credential",
          dataName("machine-credential", `secret:${userId}`),
          {
            userId,
            clientId: typeof r.body.clientId === "string"
              ? r.body.clientId
              : undefined,
            clientSecret: typeof r.body.clientSecret === "string"
              ? r.body.clientSecret
              : undefined,
            action: "rotated",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── reversible lifecycle ─────────────
    app_set_state: {
      description:
        "Deactivate or reactivate an application (reversible; verify-first; idempotent). No hard delete.",
      arguments: AppSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AppSetStateArgs.parse(rawArgs);
        const g = globalsOf(context);
        const r = await call(g, {
          method: "GET",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }`,
          ),
        });
        const current = friendlyState((r.body.app as Json | undefined)?.state);
        let action: z.infer<typeof Action> = "unchanged";
        // Zitadel refuses to deactivate an inactive app (or reactivate an
        // active one) with PreconditionFailed, so a re-run would fail.
        if (current !== a.state) {
          const verb = a.state === "inactive" ? "_deactivate" : "_reactivate";
          await call(g, {
            method: "POST",
            path: mgmt(
              `/projects/${encodeURIComponent(a.projectId)}/apps/${
                encodeURIComponent(a.appId)
              }/${verb}`,
            ),
            body: {},
          });
          action = a.state === "inactive" ? "deactivated" : "reactivated";
        }
        logInfo(context, "App {appId} is {state}: {action}", {
          appId: a.appId,
          state: a.state,
          action,
        });
        const handle = await context.writeResource(
          "state-result",
          dataName("state-result", `app:${a.appId}`),
          {
            kind: "app",
            id: a.appId,
            state: a.state,
            action,
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    user_set_state: {
      description:
        "Deactivate or reactivate a user (reversible; verify-first; idempotent). " +
        "No hard delete. Refuses to deactivate the model's own service user.",
      arguments: UserSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = UserSetStateArgs.parse(rawArgs);
        const g = globalsOf(context);
        // Zitadel lets a user deactivate itself, and a deactivated service user
        // cannot sign in again to undo it, so this would lock the model out.
        const self = parseKeyJson(g.keyJson);
        if (
          a.state === "inactive" && a.userId === (self.userId ?? self.clientId)
        ) {
          throw new Error(
            `User ${a.userId} is this model's own service user; refusing to deactivate it`,
          );
        }
        const r = await call(g, {
          method: "GET",
          path: mgmt(`/users/${encodeURIComponent(a.userId)}`),
        });
        const current = friendlyState((r.body.user as Json | undefined)?.state);
        let action: z.infer<typeof Action> = "unchanged";
        // As for apps, Zitadel answers PreconditionFailed when the user is
        // already in the target state. Any other state (locked, initial) is
        // left for Zitadel to accept or refuse.
        if (current !== a.state) {
          const verb = a.state === "inactive" ? "_deactivate" : "_reactivate";
          await call(g, {
            method: "POST",
            path: mgmt(`/users/${encodeURIComponent(a.userId)}/${verb}`),
            body: {},
          });
          action = a.state === "inactive" ? "deactivated" : "reactivated";
        }
        logInfo(context, "User {userId} is {state}: {action}", {
          userId: a.userId,
          state: a.state,
          action,
        });
        const handle = await context.writeResource(
          "state-result",
          dataName("state-result", `user:${a.userId}`),
          {
            kind: "user",
            id: a.userId,
            state: a.state,
            action,
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    // ───────────── roles / grants / authorization ─────────────
    role_list: {
      description:
        "List a project's roles (factory: one `role` each). Read-only.",
      arguments: RoleListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleListArgs.parse(rawArgs);
        const g = globalsOf(context);
        logInfo(context, "Listing roles in project {projectId}", {
          projectId: a.projectId,
        });
        const result = await searchAll(
          g,
          mgmt(`/projects/${encodeURIComponent(a.projectId)}/roles/_search`),
        );
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const ro of result) {
          handles.push(
            await context.writeResource(
              "role",
              dataName("role", `${a.projectId}:${String(ro.key ?? "")}`),
              {
                projectId: a.projectId,
                key: String(ro.key ?? ""),
                displayName: typeof ro.displayName === "string"
                  ? ro.displayName
                  : undefined,
                group: typeof ro.group === "string" ? ro.group : undefined,
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        logInfo(context, "Listed {count} roles", { count: handles.length });
        return { dataHandles: handles };
      },
    },
    role_ensure: {
      description:
        "Find-or-create a project role by key; converge displayName/group. Idempotent.",
      arguments: RoleEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleEnsureArgs.parse(rawArgs);
        const g = globalsOf(context);
        const projectId = await ensureProjectId(g, a.project, context);
        const existing = await findRoleByKey(g, projectId, a.key);
        const ts = nowIso();
        let action: z.infer<typeof Action>;
        let displayName: string;
        let group: string | undefined;
        if (existing) {
          // Converge: caller-supplied values win; omitted ones keep the existing.
          displayName = a.displayName ??
            (typeof existing.displayName === "string"
              ? existing.displayName
              : a.key);
          group = a.group ??
            (typeof existing.group === "string" ? existing.group : undefined);
          const sameName = displayName ===
            (typeof existing.displayName === "string"
              ? existing.displayName
              : undefined);
          const sameGroup = (group ?? "") ===
            (typeof existing.group === "string" ? existing.group : "");
          if (sameName && sameGroup) {
            action = "unchanged";
            logInfo(
              context,
              "Role {key} in project {projectId} already matches",
              {
                projectId,
                key: a.key,
              },
            );
          } else {
            await call(g, {
              method: "PUT",
              path: mgmt(
                `/projects/${encodeURIComponent(projectId)}/roles/${
                  encodeURIComponent(a.key)
                }`,
              ),
              body: { displayName, group: group ?? "" },
            });
            action = "updated";
            logInfo(context, "Updated role {key} in project {projectId}", {
              projectId,
              key: a.key,
            });
          }
        } else {
          displayName = a.displayName ?? a.key;
          group = a.group;
          const body: Json = { roleKey: a.key, displayName };
          if (group !== undefined) body.group = group;
          await call(g, {
            method: "POST",
            path: mgmt(`/projects/${encodeURIComponent(projectId)}/roles`),
            body,
          });
          action = "created";
          logInfo(context, "Created role {key} in project {projectId}", {
            projectId,
            key: a.key,
          });
        }
        const handle = await context.writeResource(
          "role",
          dataName("role", `${projectId}:${a.key}`),
          {
            projectId,
            key: a.key,
            displayName,
            group,
            action,
            timestamp: ts,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    role_remove: {
      description:
        "Remove a project role (verify-first DELETE). Roles have no deactivate " +
        "state, so this deletes; it also revokes any grants that use the role.",
      arguments: RoleRemoveArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleRemoveArgs.parse(rawArgs);
        const g = globalsOf(context);
        const existing = await findRoleByKey(g, a.projectId, a.key);
        if (!existing) {
          throw new Error(
            `No role with key ${
              JSON.stringify(a.key)
            } in project ${a.projectId}`,
          );
        }
        await call(g, {
          method: "DELETE",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/roles/${
              encodeURIComponent(a.key)
            }`,
          ),
        });
        logInfo(context, "Removed role {key} from project {projectId}", {
          projectId: a.projectId,
          key: a.key,
        });
        const handle = await context.writeResource(
          "role",
          dataName("role", `${a.projectId}:${a.key}`),
          {
            projectId: a.projectId,
            key: a.key,
            displayName: typeof existing.displayName === "string"
              ? existing.displayName
              : undefined,
            group: typeof existing.group === "string"
              ? existing.group
              : undefined,
            action: "removed",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    grant_list: {
      description:
        "List user grants (which roles users hold on which projects), optionally " +
        "filtered by user and/or project (factory: one `grant` each). Read-only.",
      arguments: GrantListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GrantListArgs.parse(rawArgs);
        const g = globalsOf(context);
        const queries: Json[] = [];
        if (a.user) {
          const userId = await resolveUserId(g, a.user);
          queries.push({ userIdQuery: { userId } });
        }
        if (a.projectId) {
          queries.push({ projectIdQuery: { projectId: a.projectId } });
        }
        logInfo(context, "Listing grants: {*}", {
          user: a.user,
          projectId: a.projectId,
        });
        const result = await searchAll(
          g,
          mgmt("/users/grants/_search"),
          queries.length ? queries : undefined,
        );
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const gr of result) {
          handles.push(
            await context.writeResource(
              "grant",
              dataName("grant", String(gr.id ?? "")),
              shapeGrant(gr, "observed", ts),
            ),
          );
        }
        logInfo(context, "Listed {count} grants", { count: handles.length });
        return { dataHandles: handles };
      },
    },
    grant_ensure: {
      description:
        "Grant a user a set of roles on a project (find-or-create by user+project; " +
        "converge the role-key set). Errors if the project doesn't exist. " +
        "Idempotent. Note: the roles only appear in the " +
        "user's tokens if the project has roleAssertion enabled (see project_authz_set).",
      arguments: GrantEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GrantEnsureArgs.parse(rawArgs);
        const g = globalsOf(context);
        const userId = await resolveUserId(g, a.user);
        // Never creates a project: a grant on a new, role-less project is
        // almost always a typo in the name.
        const projectId = await resolveExistingProjectId(g, a.project);
        const existing = await findGrant(g, userId, projectId);
        const ts = nowIso();
        let grantId: string;
        let action: z.infer<typeof Action>;
        let roleKeys: string[];
        // A new grant is active. An existing one keeps its own state and
        // display name: converging roles does not reactivate a grant that
        // grant_set_state deactivated.
        let state = "active";
        let displayName: string | undefined;
        if (existing && typeof existing.id === "string") {
          grantId = existing.id;
          ({ state, displayName } = shapeGrant(existing, "observed", ts));
          const cur = Array.isArray(existing.roleKeys)
            ? existing.roleKeys as string[]
            : [];
          // The update replaces the whole set, so an omitted roleKeys keeps
          // the current one rather than clearing it.
          roleKeys = a.roleKeys ?? cur;
          const curSorted = [...cur].sort();
          const want = [...roleKeys].sort();
          if (
            curSorted.length === want.length &&
            curSorted.every((r, i) => r === want[i])
          ) {
            action = "unchanged";
            logInfo(context, "Grant {grantId} already holds the roles", {
              grantId,
            });
          } else {
            await call(g, {
              method: "PUT",
              path: mgmt(
                `/users/${encodeURIComponent(userId)}/grants/${
                  encodeURIComponent(grantId)
                }`,
              ),
              body: { roleKeys },
            });
            action = "updated";
            logInfo(context, "Updated grant {grantId}: {*}", {
              userId,
              projectId,
              grantId,
            });
          }
        } else {
          roleKeys = a.roleKeys ?? [];
          const r = await call(g, {
            method: "POST",
            path: mgmt(`/users/${encodeURIComponent(userId)}/grants`),
            body: { projectId, roleKeys },
          });
          grantId = requireId(r.body, "userGrantId", "grant create");
          action = "created";
          logInfo(context, "Created grant {grantId}: {*}", {
            userId,
            projectId,
            grantId,
          });
        }
        const handle = await context.writeResource(
          "grant",
          dataName("grant", grantId),
          {
            grantId,
            userId,
            projectId,
            roleKeys,
            state,
            displayName,
            action,
            timestamp: ts,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    grant_set_state: {
      description:
        "Deactivate or reactivate a user grant (reversible; verify-first; idempotent). No hard delete.",
      arguments: GrantSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GrantSetStateArgs.parse(rawArgs);
        const g = globalsOf(context);
        const userId = await resolveUserId(g, a.user);
        // Verify-first: confirm the grant id actually belongs to this user.
        const owned = await searchAll(g, mgmt("/users/grants/_search"), [
          { userIdQuery: { userId } },
        ]);
        const gr = owned.find((x) => x.id === a.grantId);
        if (!gr) {
          throw new Error(
            `Grant ${
              JSON.stringify(a.grantId)
            } does not belong to user ${userId}`,
          );
        }
        // As for apps and users: a grant already in the target state is
        // reported as unchanged, not as a fresh deactivate/reactivate.
        let action: z.infer<typeof Action> = "unchanged";
        if (friendlyState(gr.state) !== a.state) {
          const verb = a.state === "inactive" ? "_deactivate" : "_reactivate";
          await call(g, {
            method: "POST",
            path: mgmt(
              `/users/${encodeURIComponent(userId)}/grants/${
                encodeURIComponent(a.grantId)
              }/${verb}`,
            ),
            body: {},
          });
          action = a.state === "inactive" ? "deactivated" : "reactivated";
        }
        logInfo(context, "Grant {grantId} is {state}: {action}", {
          userId,
          grantId: a.grantId,
          state: a.state,
          action,
        });
        const handle = await context.writeResource(
          "grant",
          dataName("grant", a.grantId),
          {
            ...shapeGrant(gr, action, nowIso()),
            state: a.state,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    project_authz_set: {
      description:
        "Set the authorization flags on an existing project (roleAssertion / " +
        "roleCheck / hasProjectCheck); errors if the named project doesn't exist " +
        "(never auto-creates). Fetch-merge: omitted flags are left as-is, and name / " +
        "private-labeling are preserved. Reversible (toggle back). roleAssertion is " +
        "what makes granted roles appear in users' tokens.",
      arguments: ProjectAuthzSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ProjectAuthzSetArgs.parse(rawArgs);
        const g = globalsOf(context);
        const projectId = await resolveExistingProjectId(g, a.project);
        const cur = (await call(g, {
          method: "GET",
          path: mgmt(`/projects/${encodeURIComponent(projectId)}`),
        })).body.project as Json ?? {};
        const curAssertion = cur.projectRoleAssertion === true;
        const curCheck = cur.projectRoleCheck === true;
        const curHasCheck = cur.hasProjectCheck === true;
        const want = {
          roleAssertion: a.roleAssertion ?? curAssertion,
          roleCheck: a.roleCheck ?? curCheck,
          hasProjectCheck: a.hasProjectCheck ?? curHasCheck,
        };
        const ts = nowIso();
        let action: z.infer<typeof Action>;
        if (
          want.roleAssertion === curAssertion &&
          want.roleCheck === curCheck &&
          want.hasProjectCheck === curHasCheck
        ) {
          action = "unchanged";
          logInfo(context, "Project {projectId} flags already match", {
            projectId,
          });
        } else {
          await call(g, {
            method: "PUT",
            path: mgmt(`/projects/${encodeURIComponent(projectId)}`),
            body: {
              name: String(cur.name ?? ""),
              projectRoleAssertion: want.roleAssertion,
              projectRoleCheck: want.roleCheck,
              hasProjectCheck: want.hasProjectCheck,
              privateLabelingSetting: typeof cur.privateLabelingSetting ===
                  "string"
                ? cur.privateLabelingSetting
                : "PRIVATE_LABELING_SETTING_UNSPECIFIED",
            },
          });
          action = "updated";
          logInfo(context, "Set project {projectId} flags: {*}", {
            projectId,
            ...want,
          });
        }
        const handle = await context.writeResource(
          "project",
          dataName("project", projectId),
          {
            id: projectId,
            name: String(cur.name ?? ""),
            state: friendlyState(cur.state),
            roleAssertion: want.roleAssertion,
            roleCheck: want.roleCheck,
            hasProjectCheck: want.hasProjectCheck,
            action,
            timestamp: ts,
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;

// ─────────────────────────── post-model helpers ───────────────────────────

/**
 * Look a project reference up by name, falling back to an id. A project's name
 * can be all digits (e.g. `2026`), so a name match wins; an all-digit value
 * that matches no name is taken as an id. Zitadel ids are 18-digit numbers, so
 * a name that is also another project's id is not a practical concern.
 * Returns null for a non-numeric value that matches no name.
 */
async function lookupProjectId(
  g: GlobalArgsT,
  project: string,
): Promise<string | null> {
  const existing = await findProjectByName(g, project);
  if (existing && typeof existing.id === "string") return existing.id;
  return looksLikeId(project) ? project : null;
}

/**
 * Resolve a project reference (name or id) to an id, creating the project when
 * no project has that name. The creation is logged because it is a side effect
 * of a method that is about something else (an app or a role).
 */
async function ensureProjectId(
  g: GlobalArgsT,
  project: string,
  context: Pick<Ctx, "logger">,
): Promise<string> {
  const id = await lookupProjectId(g, project);
  if (id !== null) return id;
  const r = await call(g, {
    method: "POST",
    path: mgmt("/projects"),
    body: { name: project },
  });
  const created = requireId(r.body, "id", "project create");
  logInfo(context, "Created project {name} ({id}): no project had that name", {
    name: project,
    id: created,
  });
  return created;
}

/**
 * Resolve a project reference (name or id) to an id without creating it. Throws
 * if a supplied name doesn't resolve. Used by methods that configure an existing
 * project (`project_authz_set`, `grant_ensure`), where auto-creating on a typo
 * would be a surprising side effect.
 */
async function resolveExistingProjectId(
  g: GlobalArgsT,
  project: string,
): Promise<string> {
  const id = await lookupProjectId(g, project);
  if (id !== null) return id;
  throw new Error(`No project named ${JSON.stringify(project)}`);
}
