import { z } from "npm:zod@4";
// Type-only imports — erased at compile time, never bundled. They anchor the
// `satisfies ModelDefinition<typeof GlobalArgs>` clause so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";
// Signing uses the Web Crypto API (the `crypto.subtle` global) — NO node: import,
// so the extension has zero dependencies AND resolves no `@types/node` at doc-lint
// time (a `node:` import makes some `deno doc` sandboxes fetch the floating
// @types/node → undici-types, which can break scoring). Zitadel issues PKCS#1
// ("RSA PRIVATE KEY") keys and Web Crypto imports only PKCS#8, so `signAssertion`
// wraps PKCS#1 → PKCS#8 (a fixed DER envelope) before importing the key.

/**
 * `@thomas/zitadel` — careful, non-destructive administration of a Zitadel
 * instance over its Management API (v1 REST).
 *
 * SCOPE GUARANTEE (the whole point): this holds a powerful IAM admin credential,
 * so its surface is deliberately narrow and reversible. It NEVER hard-deletes a
 * project, application, or user — the only "off switch" is the reversible
 * deactivate/reactivate pair. The SINGLE exception is `role_remove`: a project
 * role has no deactivate state in Zitadel, so retiring one is a `DELETE` — bounded,
 * verify-first, and effectively reversible (re-create the same key), but it does
 * cascade-revoke grants that reference the role. It manages MACHINE identities only
 * (service users + their PATs / keys / secrets); it does NOT create human users or
 * touch human passwords/MFA. Every secret it mints (client secret, PAT, machine key)
 * is emitted EXACTLY ONCE in the method output and marked sensitive — never logged.
 *
 * Auth: a JWT private-key service account. The model holds a machine-user key
 * JSON (`keyJson`); per run it signs a short-lived RS256 assertion and exchanges
 * it at `/oauth/v2/token` (jwt-bearer grant, `urn:zitadel:iam:org:project:id:zitadel:aud`
 * scope) for an access token, then Bearers that on the Management API. No
 * long-lived bearer token is stored.
 *
 * Method sections (by prefix):
 *   - read/audit: `org_get`, `project_list`, `app_list`, `app_get`, `user_list`,
 *     `manager_audit`, `role_list`, `grant_list`.
 *   - provision: `project_ensure`, `oidc_app_ensure`, `api_app_ensure`.
 *   - rotate: `app_secret_rotate`, `machine_user_ensure`, `pat_create`,
 *     `pat_revoke`, `machine_key_create`, `machine_secret_generate`.
 *   - authorization: `role_ensure`, `role_remove`, `grant_ensure`,
 *     `grant_set_state`, `project_authz_set`.
 *   - reversible lifecycle: `app_set_state`, `user_set_state`.
 *
 * Idempotency: provision/ensure methods find-or-create by human name (project
 * name, app name, username) and converge config in place, returning an `action`
 * of created/updated/unchanged. They accept friendly names, not just opaque IDs.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  apiUrl: z.string().describe(
    "Zitadel base URL / issuer, e.g. https://zitadel.test.smol.cloud",
  ),
  keyJson: z.string().meta({ sensitive: true }).describe(
    "Service-user machine key JSON (the whole blob downloaded from Zitadel; " +
      "contains keyId, key (PKCS#1 PEM), userId). Supply via vault: " +
      "${{ vault.get(<vault>, zitadel-admin/key_json) }}",
  ),
  orgId: z.string().optional().describe(
    "Target org id (x-zitadel-orgid header). Omit to use the service user's own org.",
  ),
  httpTimeoutMs: z.coerce.number().int().default(30000).describe(
    "Per-request timeout (ms) for token exchange and API calls",
  ),
  tokenScope: z.string().default(
    "openid profile urn:zitadel:iam:org:project:id:zitadel:aud",
  ).describe(
    "OAuth scope requested for the API token (advanced). The project:id:zitadel:aud " +
      "scope is what grants access to Zitadel's own Management API.",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type", so
// it must not leak onto the public API (the exported `CallerFn` seam uses the
// loose `Json` instead — see below).
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
  // Authorization flags. `roleAssertion` is the one that matters most: without
  // it, granted project roles do NOT appear in the user's tokens/userinfo.
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
  // Present ONLY on create/rotate, returned exactly once.
  clientSecret: z.string().meta({ sensitive: true }).optional(),
  kind: z.string(),
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
  // A PAT — returned exactly once.
  token: z.string().meta({ sensitive: true }).optional(),
  keyId: z.string().optional(),
  // The downloadable machine-key JSON — returned exactly once.
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

/** A JSON-ish bag — structurally the resolved global args or an API body. */
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
 * The authenticated-call seam the methods use — swappable for unit tests. The
 * global args are typed loosely as {@link Json} so this EXPORTED type stays
 * "fast-check" clean (referencing the zod-inferred `GlobalArgsT` would drag a
 * slow type onto the public API). The real implementation re-narrows.
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
 * Pure byte-surgery, deterministic, no dependencies.
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
  // Back the key bytes with a plain ArrayBuffer — a Uint8Array<ArrayBufferLike>
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
  const text = await res.text();
  if (res.status >= 400) {
    throw new Error(
      `Zitadel token exchange failed: HTTP ${res.status}: ${text}`,
    );
  }
  const j = JSON.parse(text) as { access_token?: string; expires_in?: number };
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
    const msg = typeof parsed.message === "string" ? parsed.message : text;
    throw new Error(
      `Zitadel API ${c.method} ${c.path} -> HTTP ${res.status}: ${msg}`,
    );
  }
  return { status: res.status, body: parsed };
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
 * Page through a Zitadel `_search` endpoint and return ALL results (not just the
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
  // Bounded by Zitadel's 1000-agent-style sanity: stop on a short page or total.
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
  const result = asArray(r.body.result);
  return result.find((p) => p.name === name) ?? result[0] ?? null;
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
      queries: [{
        userNameQuery: { userName, method: "TEXT_QUERY_METHOD_EQUALS" },
      }],
    },
  });
  const result = asArray(r.body.result);
  return result.find((u) => u.userName === userName) ?? result[0] ?? null;
}

/** A plain numeric Zitadel id is used as-is; anything else is treated as a username. */
function looksLikeId(s: string): boolean {
  return /^[0-9]+$/.test(s);
}

/** Resolve a machine-user reference (numeric id OR username) to a user id. */
async function resolveUserId(g: GlobalArgsT, userRef: string): Promise<string> {
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
  // Role-search results key on `key`; match exactly (the query is a contains-ish filter).
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
    appType: oidc.appType ? friendlyState(oidc.appType) : undefined,
    authMethod: (oidc.authMethodType ?? api.authMethodType)
      ? friendlyState(oidc.authMethodType ?? api.authMethodType)
      : undefined,
    redirectUris: Array.isArray(oidc.redirectUris)
      ? (oidc.redirectUris as string[])
      : undefined,
    postLogoutUris: Array.isArray(oidc.postLogoutRedirectUris)
      ? (oidc.postLogoutRedirectUris as string[])
      : undefined,
    responseTypes: Array.isArray(oidc.responseTypes)
      ? (oidc.responseTypes as string[])
      : undefined,
    grantTypes: Array.isArray(oidc.grantTypes)
      ? (oidc.grantTypes as string[])
      : undefined,
    devMode: typeof oidc.devMode === "boolean" ? oidc.devMode : undefined,
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

/** A boolean argument that also accepts the strings "true"/"false" (raw CLI). */
function boolArg(def: boolean): z.ZodType<boolean> {
  return z.preprocess(
    (v) => v === undefined ? def : v === true || v === "true",
    z.boolean(),
  ) as z.ZodType<boolean>;
}

const Empty = z.object({});

const AppListArgs = z.object({
  projectId: z.string().describe("Project id to list applications for"),
});

const AppGetArgs = z.object({
  projectId: z.string(),
  appId: z.string(),
});

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
  redirectUris: jsonArray(z.string()).default([]).describe(
    "Allowed redirect URIs",
  ),
  postLogoutUris: jsonArray(z.string()).default([]).describe(
    "Allowed post-logout redirect URIs",
  ),
  appType: z.enum(["web", "spa", "native"]).default("web"),
  authMethod: z.enum(["basic", "post", "none", "jwt"]).default("basic")
    .describe(
      "OIDC client auth method. Use `none` for public PKCE (SPA/native).",
    ),
  grantTypes: jsonArray(
    z.enum(["authorization_code", "implicit", "refresh_token", "device_code"]),
  ).default(["authorization_code", "refresh_token"]),
  responseTypes: jsonArray(z.enum(["code", "id_token", "id_token_token"]))
    .default(["code"]),
  accessTokenType: z.enum(["bearer", "jwt"]).default("bearer"),
  devMode: boolArg(false).describe(
    "Relax redirect-URI checks (non-https/localhost). Test only.",
  ),
});

const ApiAppEnsureArgs = z.object({
  project: z.string(),
  name: z.string(),
  authMethod: z.enum(["basic", "jwt"]).default("jwt"),
});

const AppSecretRotateArgs = z.object({
  projectId: z.string(),
  appId: z.string(),
  kind: z.enum(["oidc", "api"]).default("oidc"),
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

/**
 * A tri-state boolean argument: accepts true/false (and the strings "true"/
 * "false" from the raw CLI) but leaves `undefined` as `undefined` — so an omitted
 * flag means "leave as-is" rather than "set false".
 */
function optBoolArg(): z.ZodType<boolean | undefined> {
  return z.preprocess(
    (v) => v === undefined ? undefined : v === true || v === "true",
    z.boolean().optional(),
  ) as z.ZodType<boolean | undefined>;
}

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
    "Filter by user id or loginname (omit for all users)",
  ),
  projectId: z.string().optional().describe(
    "Filter by project id (omit for all projects)",
  ),
});

const GrantEnsureArgs = z.object({
  user: z.string().describe("User id or loginname to grant roles to"),
  project: z.string().describe("Project name or project id"),
  roleKeys: jsonArray(z.string()).default([]).describe(
    "The exact set of role keys the user should hold on this project (converged)",
  ),
});

const GrantSetStateArgs = z.object({
  user: z.string().describe("User id or loginname the grant belongs to"),
  grantId: z.string().describe(
    "Grant id (verified to belong to the user first)",
  ),
  state: z.enum(["active", "inactive"]),
});

const ProjectAuthzSetArgs = z.object({
  project: z.string().describe("Project name or project id"),
  roleAssertion: optBoolArg().describe(
    "Assert project roles into tokens/userinfo (the flag that surfaces grants)",
  ),
  roleCheck: optBoolArg().describe(
    "Require a project role to authenticate",
  ),
  hasProjectCheck: optBoolArg().describe(
    "Require the user's org to have the project granted",
  ),
});

// ─────────────────────────── model ───────────────────────────

/**
 * The `@thomas/zitadel` model definition — see the file header for the scope
 * guarantee. Read methods never emit secrets; mutating methods are idempotent
 * where possible and emit minted secrets exactly once as sensitive output; there
 * are deliberately no hard-delete methods.
 */
export const model = {
  type: "@thomas/zitadel",
  version: "2026.06.04.2",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify the instance is reachable and the service-account key authenticates (token exchange)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        const g = context.globalArgs;
        // `swamp model validate` does not resolve vault expressions, so keyJson
        // is still a literal `${{ … }}` there and can't authenticate. Skip; the
        // real check runs at method-run time when the secret is resolved.
        if (/\$\{\{/.test(String(g.keyJson))) return { pass: true };
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
        "Result of minting a machine credential (PAT / key / secret) — secret once",
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
      description: "A user grant — which roles a user holds on a project",
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
        const g = context.globalArgs;
        logInfo(context, "Getting org");
        const r = await call(g, { method: "GET", path: mgmt("/orgs/me") });
        const o = (r.body.org ?? {}) as Json;
        const handle = await context.writeResource(
          "org",
          String(o.id ?? "me"),
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
        const g = context.globalArgs;
        logInfo(context, "Listing projects");
        const result = await searchAll(g, mgmt("/projects/_search"));
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const p of result) {
          handles.push(
            await context.writeResource("project", String(p.id), {
              id: String(p.id ?? ""),
              name: String(p.name ?? ""),
              state: friendlyState(p.state),
              roleAssertion: typeof p.projectRoleAssertion === "boolean"
                ? p.projectRoleAssertion
                : undefined,
              roleCheck: typeof p.projectRoleCheck === "boolean"
                ? p.projectRoleCheck
                : undefined,
              hasProjectCheck: typeof p.hasProjectCheck === "boolean"
                ? p.hasProjectCheck
                : undefined,
              action: "observed",
              timestamp: ts,
            }),
          );
        }
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
        const g = context.globalArgs;
        logInfo(context, "Listing apps", { projectId: a.projectId });
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
              String(app.id),
              shapeApp(a.projectId, app, "observed", ts),
            ),
          );
        }
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
        const g = context.globalArgs;
        const r = await call(g, {
          method: "GET",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }`,
          ),
        });
        const app = (r.body.app ?? {}) as Json;
        const handle = await context.writeResource(
          "app",
          a.appId,
          shapeApp(a.projectId, app, "observed", nowIso()),
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
        const g = context.globalArgs;
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
            await context.writeResource("user", String(u.userId ?? u.id), {
              userId: String(u.userId ?? u.id ?? ""),
              username: typeof u.userName === "string" ? u.userName : undefined,
              type: u.human ? "human" : u.machine ? "machine" : "unknown",
              state: friendlyState(u.state),
              displayName: (machine.name as string) ??
                (profile.displayName as string) ?? undefined,
              action: "observed",
              timestamp: ts,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },
    manager_audit: {
      description:
        "List org managers (members) and their roles — who can administer this org. Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const result = await searchAll(g, mgmt("/orgs/me/members/_search"));
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const m of result) {
          handles.push(
            await context.writeResource("manager", String(m.userId), {
              userId: String(m.userId ?? ""),
              displayName: typeof m.displayName === "string"
                ? m.displayName
                : undefined,
              roles: Array.isArray(m.roles) ? (m.roles as string[]) : [],
              action: "observed",
              timestamp: ts,
            }),
          );
        }
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
        const g = context.globalArgs;
        const existing = await findProjectByName(g, a.name);
        let id: string;
        let action: z.infer<typeof Action>;
        if (existing && typeof existing.id === "string") {
          id = existing.id;
          action = "unchanged";
        } else {
          const r = await call(g, {
            method: "POST",
            path: mgmt("/projects"),
            body: { name: a.name },
          });
          id = String(r.body.id ?? "");
          action = "created";
          logInfo(context, "Created project", { name: a.name, id });
        }
        const handle = await context.writeResource("project", id, {
          id,
          name: a.name,
          state: "active",
          action,
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    oidc_app_ensure: {
      description:
        "Ensure an OIDC application (find-or-create within an ensured project; converge config). " +
        "Returns clientId, and clientSecret ONCE on create for confidential clients.",
      arguments: OidcAppEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = OidcAppEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const projectId = await ensureProjectId(g, a.project);
        const cfg = {
          redirectUris: a.redirectUris,
          postLogoutRedirectUris: a.postLogoutUris,
          responseTypes: a.responseTypes.map((t) =>
            mapEnum(RESPONSE_TYPE, t, "responseType")
          ),
          grantTypes: a.grantTypes.map((t) =>
            mapEnum(GRANT_TYPE, t, "grantType")
          ),
          appType: mapEnum(APP_TYPE, a.appType, "appType"),
          authMethodType: mapEnum(AUTH_METHOD, a.authMethod, "authMethod"),
          accessTokenType: mapEnum(
            ACCESS_TOKEN_TYPE,
            a.accessTokenType,
            "accessTokenType",
          ),
          devMode: a.devMode,
        };
        const existing = await findAppByName(g, projectId, a.name);
        const ts = nowIso();
        if (existing && typeof existing.id === "string") {
          // Converge config in place. Zitadel returns 400 "No changes" when the
          // config already matches — that's an idempotent no-op, not a failure.
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
          const oidc = (existing.oidcConfig ?? {}) as Json;
          logInfo(context, "Converged OIDC app", {
            name: a.name,
            appId: existing.id,
            action,
          });
          const handle = await context.writeResource(
            "app-credential",
            existing.id,
            {
              projectId,
              appId: existing.id,
              name: a.name,
              clientId: typeof oidc.clientId === "string"
                ? oidc.clientId
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
          body: { name: a.name, ...cfg },
        });
        logInfo(context, "Created OIDC app", {
          name: a.name,
          appId: r.body.appId,
        });
        const handle = await context.writeResource(
          "app-credential",
          String(r.body.appId),
          {
            projectId,
            appId: String(r.body.appId ?? ""),
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
        "Ensure an API application (resource server / M2M). Returns clientId, and clientSecret ONCE on create for the basic method.",
      arguments: ApiAppEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ApiAppEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const projectId = await ensureProjectId(g, a.project);
        const existing = await findAppByName(g, projectId, a.name);
        const ts = nowIso();
        if (existing && typeof existing.id === "string") {
          const api = (existing.apiConfig ?? {}) as Json;
          const handle = await context.writeResource(
            "app-credential",
            existing.id,
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
        logInfo(context, "Created API app", {
          name: a.name,
          appId: r.body.appId,
        });
        const handle = await context.writeResource(
          "app-credential",
          String(r.body.appId),
          {
            projectId,
            appId: String(r.body.appId ?? ""),
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
        "Regenerate an application's client secret (verify the app exists first). Returns the new secret ONCE.",
      arguments: AppSecretRotateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AppSecretRotateArgs.parse(rawArgs);
        const g = context.globalArgs;
        // Verify-first: confirm the app exists before mutating.
        await call(g, {
          method: "GET",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }`,
          ),
        });
        const cfgPath = a.kind === "api" ? "api_config" : "oidc_config";
        const r = await call(g, {
          method: "POST",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }/${cfgPath}/_generate_client_secret`,
          ),
          body: {},
        });
        logInfo(context, "Rotated app secret", {
          appId: a.appId,
          kind: a.kind,
        });
        const handle = await context.writeResource("app-credential", a.appId, {
          projectId: a.projectId,
          appId: a.appId,
          clientId: typeof r.body.clientId === "string"
            ? r.body.clientId
            : undefined,
          clientSecret: typeof r.body.clientSecret === "string"
            ? r.body.clientSecret
            : undefined,
          kind: a.kind,
          action: "rotated",
          timestamp: nowIso(),
        });
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
        const g = context.globalArgs;
        const existing = await findMachineUserByUsername(g, a.username);
        const ts = nowIso();
        // ListUsers results use `id`; tolerate `userId` too.
        const existingId = existing
          ? (existing.id ?? existing.userId)
          : undefined;
        if (existing && typeof existingId === "string") {
          const handle = await context.writeResource("user", existingId, {
            userId: existingId,
            username: a.username,
            type: "machine",
            state: friendlyState(existing.state),
            displayName: a.name,
            action: "unchanged",
            timestamp: ts,
          });
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
        logInfo(context, "Created machine user", {
          username: a.username,
          userId: r.body.userId,
        });
        const handle = await context.writeResource(
          "user",
          String(r.body.userId),
          {
            userId: String(r.body.userId ?? ""),
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
        "Add a personal access token to a machine user. Returns the token ONCE.",
      arguments: PatCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PatCreateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const userId = await resolveUserId(g, a.user);
        const r = await call(g, {
          method: "POST",
          path: mgmt(`/users/${encodeURIComponent(userId)}/pats`),
          body: a.expirationDate ? { expirationDate: a.expirationDate } : {},
        });
        logInfo(context, "Created PAT", { userId, tokenId: r.body.tokenId });
        const handle = await context.writeResource(
          "machine-credential",
          String(r.body.tokenId),
          {
            userId,
            tokenId: typeof r.body.tokenId === "string"
              ? r.body.tokenId
              : undefined,
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
        "Revoke a PAT — verify-first: confirms the tokenId belongs to the user before deleting.",
      arguments: PatRevokeArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PatRevokeArgs.parse(rawArgs);
        const g = context.globalArgs;
        const userId = await resolveUserId(g, a.user);
        // Verify-first: the tokenId must exist under this user.
        const list = await call(g, {
          method: "POST",
          path: mgmt(`/users/${encodeURIComponent(userId)}/pats/_search`),
          body: {},
        });
        const owned = asArray(list.body.result).some((p) =>
          String(p.id) === a.tokenId
        );
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
        logInfo(context, "Revoked PAT", { userId, tokenId: a.tokenId });
        const handle = await context.writeResource(
          "machine-credential",
          a.tokenId,
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
        "Add a JSON private key to a machine user. Returns the downloadable key JSON ONCE.",
      arguments: MachineKeyCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MachineKeyCreateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const userId = await resolveUserId(g, a.user);
        const r = await call(g, {
          method: "POST",
          path: mgmt(`/users/${encodeURIComponent(userId)}/keys`),
          body: {
            type: "KEY_TYPE_JSON",
            expirationDate: a.expirationDate,
          },
        });
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
        logInfo(context, "Created machine key", {
          userId,
          keyId: r.body.keyId,
        });
        const handle = await context.writeResource(
          "machine-credential",
          String(r.body.keyId),
          {
            userId,
            keyId: typeof r.body.keyId === "string" ? r.body.keyId : undefined,
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
        "Generate (rotate) a machine user's client secret. Returns the secret ONCE.",
      arguments: MachineSecretArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MachineSecretArgs.parse(rawArgs);
        const g = context.globalArgs;
        const userId = await resolveUserId(g, a.user);
        const r = await call(g, {
          method: "PUT",
          path: mgmt(`/users/${encodeURIComponent(userId)}/secret`),
          body: {},
        });
        logInfo(context, "Generated machine secret", { userId });
        const handle = await context.writeResource(
          "machine-credential",
          userId,
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
        "Deactivate or reactivate an application (reversible; verify-first). No hard delete.",
      arguments: AppSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AppSetStateArgs.parse(rawArgs);
        const g = context.globalArgs;
        await call(g, {
          method: "GET",
          path: mgmt(
            `/projects/${encodeURIComponent(a.projectId)}/apps/${
              encodeURIComponent(a.appId)
            }`,
          ),
        });
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
        const action: z.infer<typeof Action> = a.state === "inactive"
          ? "deactivated"
          : "reactivated";
        logInfo(context, "Set app state", { appId: a.appId, state: a.state });
        const handle = await context.writeResource("state-result", a.appId, {
          kind: "app",
          id: a.appId,
          state: a.state,
          action,
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    user_set_state: {
      description:
        "Deactivate or reactivate a user (reversible). No hard delete.",
      arguments: UserSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = UserSetStateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const verb = a.state === "inactive" ? "_deactivate" : "_reactivate";
        await call(g, {
          method: "POST",
          path: mgmt(`/users/${encodeURIComponent(a.userId)}/${verb}`),
          body: {},
        });
        const action: z.infer<typeof Action> = a.state === "inactive"
          ? "deactivated"
          : "reactivated";
        logInfo(context, "Set user state", {
          userId: a.userId,
          state: a.state,
        });
        const handle = await context.writeResource("state-result", a.userId, {
          kind: "user",
          id: a.userId,
          state: a.state,
          action,
          timestamp: nowIso(),
        });
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
        const g = context.globalArgs;
        logInfo(context, "Listing roles", { projectId: a.projectId });
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
              `${a.projectId}:${String(ro.key ?? "")}`,
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
        const g = context.globalArgs;
        const projectId = await ensureProjectId(g, a.project);
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
            logInfo(context, "Updated role", { projectId, key: a.key });
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
          logInfo(context, "Created role", { projectId, key: a.key });
        }
        const handle = await context.writeResource(
          "role",
          `${projectId}:${a.key}`,
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
        "Remove a project role (verify-first DELETE). This is the SINGLE hard-delete " +
        "in this model — roles have no deactivate state. Cascade-revokes any grants " +
        "that reference the role.",
      arguments: RoleRemoveArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleRemoveArgs.parse(rawArgs);
        const g = context.globalArgs;
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
        logInfo(context, "Removed role", {
          projectId: a.projectId,
          key: a.key,
        });
        const handle = await context.writeResource(
          "role",
          `${a.projectId}:${a.key}`,
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
        "List user grants — which roles users hold on which projects — optionally " +
        "filtered by user and/or project (factory: one `grant` each). Read-only.",
      arguments: GrantListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GrantListArgs.parse(rawArgs);
        const g = context.globalArgs;
        const queries: Json[] = [];
        if (a.user) {
          const userId = await resolveUserId(g, a.user);
          queries.push({ userIdQuery: { userId } });
        }
        if (a.projectId) {
          queries.push({ projectIdQuery: { projectId: a.projectId } });
        }
        logInfo(context, "Listing grants", {
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
              String(gr.id ?? ""),
              shapeGrant(gr, "observed", ts),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    grant_ensure: {
      description:
        "Grant a user a set of roles on a project (find-or-create by user+project; " +
        "converge the role-key set). Idempotent. Note: the roles only appear in the " +
        "user's tokens if the project has roleAssertion enabled (see project_authz_set).",
      arguments: GrantEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GrantEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const userId = await resolveUserId(g, a.user);
        const projectId = await ensureProjectId(g, a.project);
        const existing = await findGrant(g, userId, projectId);
        const ts = nowIso();
        let grantId: string;
        let action: z.infer<typeof Action>;
        if (existing && typeof existing.id === "string") {
          grantId = existing.id;
          const cur = Array.isArray(existing.roleKeys)
            ? [...existing.roleKeys as string[]].sort()
            : [];
          const want = [...a.roleKeys].sort();
          if (
            cur.length === want.length && cur.every((r, i) => r === want[i])
          ) {
            action = "unchanged";
          } else {
            await call(g, {
              method: "PUT",
              path: mgmt(
                `/users/${encodeURIComponent(userId)}/grants/${
                  encodeURIComponent(grantId)
                }`,
              ),
              body: { roleKeys: a.roleKeys },
            });
            action = "updated";
            logInfo(context, "Updated grant", { userId, projectId, grantId });
          }
        } else {
          const r = await call(g, {
            method: "POST",
            path: mgmt(`/users/${encodeURIComponent(userId)}/grants`),
            body: { projectId, roleKeys: a.roleKeys },
          });
          grantId = String(r.body.userGrantId ?? r.body.id ?? "");
          action = "created";
          logInfo(context, "Created grant", { userId, projectId, grantId });
        }
        const handle = await context.writeResource("grant", grantId, {
          grantId,
          userId,
          projectId,
          roleKeys: a.roleKeys,
          state: "active",
          action,
          timestamp: ts,
        });
        return { dataHandles: [handle] };
      },
    },
    grant_set_state: {
      description:
        "Deactivate or reactivate a user grant (reversible; verify-first). No hard delete.",
      arguments: GrantSetStateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GrantSetStateArgs.parse(rawArgs);
        const g = context.globalArgs;
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
        const action: z.infer<typeof Action> = a.state === "inactive"
          ? "deactivated"
          : "reactivated";
        logInfo(context, "Set grant state", {
          userId,
          grantId: a.grantId,
          state: a.state,
        });
        const handle = await context.writeResource("grant", a.grantId, {
          ...shapeGrant(gr, action, nowIso()),
          state: a.state,
        });
        return { dataHandles: [handle] };
      },
    },
    project_authz_set: {
      description:
        "Set the authorization flags on an EXISTING project (roleAssertion / " +
        "roleCheck / hasProjectCheck) — errors if the named project doesn't exist " +
        "(never auto-creates). Fetch-merge: omitted flags are left as-is, and name / " +
        "private-labeling are preserved. Reversible (toggle back). roleAssertion is " +
        "what makes granted roles appear in users' tokens.",
      arguments: ProjectAuthzSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ProjectAuthzSetArgs.parse(rawArgs);
        const g = context.globalArgs;
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
          logInfo(context, "Set project authz", { projectId, ...want });
        }
        const handle = await context.writeResource("project", projectId, {
          id: projectId,
          name: String(cur.name ?? ""),
          state: friendlyState(cur.state),
          roleAssertion: want.roleAssertion,
          roleCheck: want.roleCheck,
          hasProjectCheck: want.hasProjectCheck,
          action,
          timestamp: ts,
        });
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;

// ─────────────────────────── post-model helpers ───────────────────────────

/** Resolve a project reference (name or id) to an id, creating it if a name is absent. */
async function ensureProjectId(
  g: GlobalArgsT,
  project: string,
): Promise<string> {
  if (looksLikeId(project)) return project;
  const existing = await findProjectByName(g, project);
  if (existing && typeof existing.id === "string") return existing.id;
  const r = await call(g, {
    method: "POST",
    path: mgmt("/projects"),
    body: { name: project },
  });
  return String(r.body.id ?? "");
}

/**
 * Resolve a project reference (name or id) to an id WITHOUT creating it — throws
 * if a supplied name doesn't resolve. Used by methods that configure an existing
 * project (e.g. `project_authz_set`), where auto-creating on a typo would be a
 * surprising side effect.
 */
async function resolveExistingProjectId(
  g: GlobalArgsT,
  project: string,
): Promise<string> {
  if (looksLikeId(project)) return project;
  const existing = await findProjectByName(g, project);
  if (existing && typeof existing.id === "string") return existing.id;
  throw new Error(`No project named ${JSON.stringify(project)}`);
}
