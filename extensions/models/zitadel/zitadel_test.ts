/**
 * Unit tests for the load-bearing, security-sensitive logic of `@thomas/zitadel`:
 * the JWT assertion claims, find-or-create idempotency, the friendly→Zitadel enum
 * mapping sent on the wire, the verify-first PAT-revoke guard, secret-once output
 * shape, the role/grant authorization methods (incl. project_authz_set's no-auto-
 * create), and the single-exception hard-delete guarantee (only role_remove). No
 * live server — the API caller is faked via the __setCaller seam.
 */
import {
  __setCaller,
  type ApiCall,
  type ApiResult,
  type CallerFn,
  importSigningKey,
  jwtAssertionClaims,
  model,
} from "./zitadel.ts";

function assertEquals(actual: unknown, expected: unknown, msg?: string): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error(
      `assertEquals failed${
        msg ? ` (${msg})` : ""
      }\n  actual:   ${a}\n  expected: ${e}`,
    );
  }
}
function assert(cond: unknown, msg?: string): void {
  if (!cond) throw new Error(`assert failed${msg ? `: ${msg}` : ""}`);
}
async function rejects(fn: () => Promise<unknown>, re: RegExp): Promise<void> {
  try {
    await fn();
  } catch (e) {
    assert(
      re.test((e as Error).message),
      `expected /${re.source}/, got: ${(e as Error).message}`,
    );
    return;
  }
  throw new Error(`expected rejection matching /${re.source}/`);
}

const GLOBALS = {
  apiUrl: "https://zitadel.test.example.com",
  keyJson: JSON.stringify({ keyId: "kid1", key: "PEM", userId: "u123" }),
  httpTimeoutMs: 30000,
  tokenScope: "openid profile urn:zitadel:iam:org:project:id:zitadel:aud",
};

type Recorded = { method: string; path: string; body?: unknown };

/** A fake API caller. `respond` returns a canned body per (method, path) match. */
function makeFakeApi(
  respond?: (c: ApiCall) => Record<string, unknown> | undefined,
) {
  const calls: Recorded[] = [];
  const caller: CallerFn = (_g, c): Promise<ApiResult> => {
    calls.push({ method: c.method, path: c.path, body: c.body });
    return Promise.resolve({ status: 200, body: respond?.(c) ?? {} });
  };
  return { caller, calls };
}

function makeContext() {
  const written: Array<
    { specName: string; name: string; data: Record<string, unknown> }
  > = [];
  const noop = () => {};
  const context = {
    globalArgs: GLOBALS,
    logger: { info: noop, debug: noop, warning: noop, error: noop },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      const h = { specName, name, data };
      written.push(h);
      return Promise.resolve(h);
    },
  };
  return { context, written };
}

type MethodDef = {
  execute: (
    args: unknown,
    context: unknown,
  ) => Promise<{ dataHandles: unknown[] }>;
};
const method = (name: string): MethodDef =>
  (model.methods as unknown as Record<string, MethodDef>)[name];

// ─────────────────────────── tests ───────────────────────────

Deno.test("jwtAssertionClaims: iss==sub==userId, aud trimmed, 1h life", () => {
  const c = jwtAssertionClaims(
    { keyId: "k", key: "p", userId: "u123" },
    "https://zitadel.test.example.com/",
    1000,
  );
  assertEquals(c.iss, "u123");
  assertEquals(c.sub, "u123");
  assertEquals(
    c.aud,
    "https://zitadel.test.example.com",
    "trailing slash trimmed",
  );
  assertEquals(c.iat, 1000);
  assertEquals(c.exp, 4600, "exp = iat + 3600");
});

// Web Crypto signing: prove importSigningKey works for BOTH a PKCS#8 key and a
// PKCS#1 key (the format Zitadel issues, exercised via the pkcs1ToPkcs8 wrapper),
// by signing with the imported key and verifying against the matching public key.
function derToPem(der: Uint8Array, label: string): string {
  let s = "";
  for (const b of der) s += String.fromCharCode(b);
  return `-----BEGIN ${label}-----\n${btoa(s)}\n-----END ${label}-----`;
}
// Unwrap a PKCS#8 PrivateKeyInfo to its inner PKCS#1 RSAPrivateKey (the final
// OCTET STRING). Web Crypto can only export PKCS#8, so this derives a genuine
// PKCS#1 key to feed back through importSigningKey's wrapper path.
function pkcs8ToPkcs1(pkcs8: Uint8Array): Uint8Array {
  let p = 0;
  const readLen = () => {
    let l = pkcs8[p++];
    if (l & 0x80) {
      const n = l & 0x7f;
      l = 0;
      for (let i = 0; i < n; i++) l = l * 256 + pkcs8[p++];
    }
    return l;
  };
  if (pkcs8[p++] !== 0x30) throw new Error("not a SEQUENCE");
  readLen();
  while (p < pkcs8.length) {
    const tag = pkcs8[p++];
    const len = readLen();
    if (tag === 0x04) return pkcs8.slice(p, p + len);
    p += len;
  }
  throw new Error("no OCTET STRING (PKCS#1) found");
}

Deno.test("importSigningKey: signs verifiably for PKCS#8 and PKCS#1 (wrapper) keys", async () => {
  const kp = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", kp.privateKey),
  );
  const msg = new TextEncoder().encode("header.payload");
  const signsAndVerifies = async (pem: string): Promise<boolean> => {
    const key = await importSigningKey(pem);
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, msg);
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", kp.publicKey, sig, msg);
  };
  assert(
    await signsAndVerifies(derToPem(pkcs8, "PRIVATE KEY")),
    "PKCS#8 branch produces a verifiable RS256 signature",
  );
  assert(
    await signsAndVerifies(derToPem(pkcs8ToPkcs1(pkcs8), "RSA PRIVATE KEY")),
    "PKCS#1 wrapper (pkcs1ToPkcs8) produces a verifiable RS256 signature",
  );
});

Deno.test("jwtAssertionClaims: falls back to clientId when no userId", () => {
  const c = jwtAssertionClaims(
    { keyId: "k", key: "p", clientId: "c789" },
    "https://z",
    0,
  );
  assertEquals(c.iss, "c789");
});

Deno.test("project_list: pages through all results (100 + short page)", async () => {
  const page1 = Array.from({ length: 100 }, (_, i) => ({
    id: `p${i}`,
    name: `proj${i}`,
  }));
  const page2 = [{ id: "p100", name: "proj100" }];
  const { caller, calls } = makeFakeApi((c) => {
    if (!c.path.endsWith("/projects/_search")) return undefined;
    const off = (c.body as Record<string, Record<string, number>>).query
      .offset;
    return off === 0
      ? { result: page1, details: { totalResult: "101" } }
      : { result: page2, details: { totalResult: "101" } };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("project_list").execute({}, context);
    assertEquals(written.length, 101, "all 101 projects across 2 pages");
    const searches = calls.filter((c) => c.path.endsWith("/projects/_search"));
    assertEquals(searches.length, 2, "exactly two pages fetched");
  } finally {
    __setCaller(null);
  }
});

Deno.test("model: role_remove is the ONLY hard-delete; reversible-only otherwise", () => {
  const names = Object.keys(model.methods);
  const deletish = names.filter((n) => /delete|destroy|remove/i.test(n));
  assertEquals(
    deletish,
    ["role_remove"],
    "role_remove is the single, deliberate hard-delete (roles have no deactivate state)",
  );
  assert(names.includes("app_set_state"));
  assert(names.includes("user_set_state"));
  assert(names.includes("grant_set_state"));
});

Deno.test("project_ensure: creates when absent, returns created", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) return { result: [] };
    if (c.path.endsWith("/projects") && c.method === "POST") {
      return { id: "p1" };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("project_ensure").execute({ name: "homelab" }, context);
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.id, "p1");
    assert(
      calls.some((c) => c.method === "POST" && c.path.endsWith("/projects")),
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("project_ensure: idempotent — returns unchanged when present", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p9", name: "homelab" }] };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("project_ensure").execute({ name: "homelab" }, context);
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.id, "p9");
    assert(
      !calls.some((c) => c.method === "POST" && c.path.endsWith("/projects")),
      "must not create when found",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("oidc_app_ensure: maps friendly enums onto the wire + secret once on create", async () => {
  let createBody: Record<string, unknown> | undefined;
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/apps/_search")) return { result: [] };
    if (c.path.endsWith("/apps/oidc") && c.method === "POST") {
      createBody = c.body as Record<string, unknown>;
      return { appId: "a1", clientId: "cid", clientSecret: "shh" };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("oidc_app_ensure").execute({
      project: "homelab",
      name: "grafana",
      redirectUris: ["https://g/cb"],
      appType: "web",
      authMethod: "basic",
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
    }, context);
    assertEquals(createBody?.appType, "OIDC_APP_TYPE_WEB");
    assertEquals(createBody?.authMethodType, "OIDC_AUTH_METHOD_TYPE_BASIC");
    assertEquals(createBody?.responseTypes, ["OIDC_RESPONSE_TYPE_CODE"]);
    assertEquals(createBody?.grantTypes, [
      "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
      "OIDC_GRANT_TYPE_REFRESH_TOKEN",
    ]);
    assertEquals(written[0].data.action, "created");
    assertEquals(
      written[0].data.clientSecret,
      "shh",
      "secret emitted on create",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("oidc_app_ensure: existing app updates config, no secret echoed", async () => {
  let didPut = false;
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/apps/_search")) {
      return {
        result: [{
          id: "a1",
          name: "grafana",
          oidcConfig: { clientId: "cid" },
        }],
      };
    }
    if (c.method === "PUT" && c.path.endsWith("/oidc_config")) {
      didPut = true;
      return {};
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("oidc_app_ensure").execute({
      project: "homelab",
      name: "grafana",
      redirectUris: ["https://g/cb"],
    }, context);
    assert(didPut, "should PUT oidc_config to converge");
    assertEquals(written[0].data.action, "updated");
    assertEquals(
      written[0].data.clientSecret,
      undefined,
      "no secret on update",
    );
    assertEquals(written[0].data.clientId, "cid");
  } finally {
    __setCaller(null);
  }
});

Deno.test("oidc_app_redirect_set: read-modify-write adds/removes, preserves other config", async () => {
  let putBody: Record<string, unknown> | null = null;
  let gets = 0;
  const oidcConfig = {
    clientId: "cid",
    redirectUris: ["https://a/cb", "https://b/cb"],
    responseTypes: ["OIDC_RESPONSE_TYPE_CODE"],
    authMethodType: "OIDC_AUTH_METHOD_TYPE_NONE",
    appType: "OIDC_APP_TYPE_WEB",
    devMode: false,
  };
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/apps/")) {
      gets++;
      const uris = gets >= 2
        ? ["https://b/cb", "https://c/cb"]
        : oidcConfig.redirectUris;
      return { app: { name: "shared", oidcConfig: { ...oidcConfig, redirectUris: uris } } };
    }
    if (c.method === "PUT" && c.path.endsWith("/oidc_config")) {
      putBody = c.body as Record<string, unknown>;
      return {};
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("oidc_app_redirect_set").execute({
      projectId: "p1",
      appId: "a1",
      add: ["https://c/cb"],
      remove: ["https://a/cb"],
    }, context);
    const body = putBody as unknown as Record<string, unknown>;
    assertEquals(body.redirectUris, ["https://b/cb", "https://c/cb"]);
    assertEquals(
      body.authMethodType,
      "OIDC_AUTH_METHOD_TYPE_NONE",
      "must preserve PKCE/auth method",
    );
    assertEquals(body.responseTypes, ["OIDC_RESPONSE_TYPE_CODE"]);
    assertEquals(body.clientId, undefined, "must NOT echo read-only clientId");
    const r = written[0].data;
    assertEquals(r.action, "updated");
    assertEquals(r.previousRedirectUris, ["https://a/cb", "https://b/cb"]);
    assertEquals(r.redirectUris, ["https://b/cb", "https://c/cb"]);
  } finally {
    __setCaller(null);
  }
});

Deno.test("oidc_app_redirect_set: no-op when add present & remove absent", async () => {
  let putCalled = false;
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/apps/")) {
      return { app: { name: "x", oidcConfig: { redirectUris: ["https://a/cb"] } } };
    }
    if (c.method === "PUT") {
      putCalled = true;
      return {};
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("oidc_app_redirect_set").execute({
      projectId: "p1",
      appId: "a1",
      add: ["https://a/cb"],
      remove: ["https://z/cb"],
    }, context);
    assertEquals(putCalled, false, "no PUT when the set is unchanged");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("oidc_app_ensure: treats Zitadel 'No changes' 400 as unchanged", async () => {
  const caller: CallerFn = (_g, c) => {
    if (c.path.endsWith("/projects/_search")) {
      return Promise.resolve({
        status: 200,
        body: { result: [{ id: "p1", name: "homelab" }] },
      });
    }
    if (c.path.endsWith("/apps/_search")) {
      return Promise.resolve({
        status: 200,
        body: {
          result: [{
            id: "a1",
            name: "grafana",
            oidcConfig: { clientId: "cid" },
          }],
        },
      });
    }
    if (c.method === "PUT" && c.path.endsWith("/oidc_config")) {
      // Mirror realCaller's throw on a 4xx with Zitadel's "No changes" body.
      return Promise.reject(
        new Error(
          "Zitadel API PUT …/oidc_config -> HTTP 400: No changes (COMMAND-1m88i)",
        ),
      );
    }
    return Promise.resolve({ status: 200, body: {} });
  };
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("oidc_app_ensure").execute(
      { project: "homelab", name: "grafana", redirectUris: ["https://g/cb"] },
      context,
    );
    assertEquals(
      written[0].data.action,
      "unchanged",
      "No-changes 400 is idempotent",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("machine_user_ensure: resolves an existing user by ListUsers `id`", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/_search")) {
      // ListUsers returns `id` (not `userId`).
      return {
        result: [{
          id: "900",
          userName: "smoke-bot",
          state: "USER_STATE_ACTIVE",
        }],
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("machine_user_ensure").execute(
      { username: "smoke-bot", name: "Smoke Bot" },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.userId, "900", "uses the result's `id` field");
    assert(
      !calls.some((c) =>
        c.path.endsWith("/users/machine") && c.method === "POST"
      ),
      "must not create when found",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("app_secret_rotate: verify-first GET then regenerate, secret once", async () => {
  const seen: string[] = [];
  const { caller } = makeFakeApi((c) => {
    seen.push(`${c.method} ${c.path}`);
    if (c.method === "GET") return { app: { id: "a1" } };
    if (c.path.endsWith("/_generate_client_secret")) {
      return { clientId: "cid", clientSecret: "new-secret" };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("app_secret_rotate").execute(
      { projectId: "p1", appId: "a1", kind: "oidc" },
      context,
    );
    assert(seen[0].startsWith("GET "), "verify-first GET before mutate");
    assert(
      seen.some((s) => s.includes("/oidc_config/_generate_client_secret")),
    );
    assertEquals(written[0].data.action, "rotated");
    assertEquals(written[0].data.clientSecret, "new-secret");
  } finally {
    __setCaller(null);
  }
});

Deno.test("app_get: normalizes proto3-omitted OIDC defaults (web/bearer/false)", async () => {
  // Zitadel omits zero-value fields: a default web app comes back with appType,
  // accessTokenType and devMode ABSENT. The read shape must show effective values.
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET") {
      return {
        app: {
          id: "a1",
          name: "web-app",
          state: "APP_STATE_ACTIVE",
          oidcConfig: { clientId: "cid", redirectUris: ["https://x/cb"] },
        },
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("app_get").execute({ projectId: "p1", appId: "a1" }, context);
    assertEquals(written[0].data.kind, "oidc");
    assertEquals(written[0].data.appType, "web", "default appType surfaced");
    assertEquals(
      written[0].data.accessTokenType,
      "bearer",
      "default accessTokenType surfaced",
    );
    assertEquals(written[0].data.devMode, false, "default devMode surfaced");
  } finally {
    __setCaller(null);
  }
});

Deno.test("app_get: round-trips non-default OIDC enums (spa/jwt) from the wire", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET") {
      return {
        app: {
          id: "a2",
          name: "spa-app",
          state: "APP_STATE_ACTIVE",
          oidcConfig: {
            clientId: "cid2",
            appType: "OIDC_APP_TYPE_USER_AGENT",
            accessTokenType: "OIDC_TOKEN_TYPE_JWT",
            devMode: true,
            responseTypes: ["OIDC_RESPONSE_TYPE_CODE", "OIDC_RESPONSE_TYPE_ID_TOKEN"],
            grantTypes: [
              "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
              "OIDC_GRANT_TYPE_REFRESH_TOKEN",
            ],
          },
        },
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("app_get").execute({ projectId: "p1", appId: "a2" }, context);
    // USER_AGENT must read back as "spa" (the write-path friendly value), NOT
    // friendlyState's "agent" — so a read-then-converge sees no spurious drift.
    assertEquals(written[0].data.appType, "spa");
    assertEquals(written[0].data.accessTokenType, "jwt");
    assertEquals(written[0].data.devMode, true);
    // ID_TOKEN / AUTHORIZATION_CODE / REFRESH_TOKEN would all collapse to the
    // wrong friendlyState value ("token"/"code") — the reverse map fixes them.
    assertEquals(written[0].data.responseTypes, ["code", "id_token"]);
    assertEquals(written[0].data.grantTypes, [
      "authorization_code",
      "refresh_token",
    ]);
  } finally {
    __setCaller(null);
  }
});

Deno.test("app_get: leaves OIDC-only fields undefined for an API app", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET") {
      return {
        app: {
          id: "a3",
          name: "api-app",
          state: "APP_STATE_ACTIVE",
          apiConfig: { clientId: "cid3" },
        },
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("app_get").execute({ projectId: "p1", appId: "a3" }, context);
    assertEquals(written[0].data.kind, "api");
    assertEquals(written[0].data.appType, undefined);
    assertEquals(written[0].data.accessTokenType, undefined);
    assertEquals(written[0].data.devMode, undefined);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pat_revoke: refuses when tokenId not owned by user", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/pats/_search")) return { result: [{ id: "OTHER" }] };
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("pat_revoke").execute(
          { user: "123", tokenId: "MISSING" },
          context,
        ),
      /not found on user/,
    );
    assert(
      !calls.some((c) => c.method === "DELETE"),
      "must not DELETE when token not owned",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("pat_revoke: deletes when tokenId is owned", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/pats/_search")) return { result: [{ id: "T1" }] };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pat_revoke").execute({ user: "123", tokenId: "T1" }, context);
    assert(
      calls.some((c) => c.method === "DELETE" && c.path.includes("/pats/T1")),
    );
    assertEquals(written[0].data.action, "revoked");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pat_create: returns the token once with action created", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/pats") && c.method === "POST") {
      return { tokenId: "T2", token: "pat-secret" };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pat_create").execute({ user: "123" }, context);
    assertEquals(written[0].data.token, "pat-secret");
    assertEquals(written[0].data.action, "created");
  } finally {
    __setCaller(null);
  }
});

Deno.test("machine_key_create: decodes base64 keyDetails to JSON", async () => {
  const keyFile = JSON.stringify({ type: "serviceaccount", keyId: "K9" });
  const b64 = btoa(keyFile);
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/keys") && c.method === "POST") {
      return { keyId: "K9", keyDetails: b64 };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("machine_key_create").execute({ user: "123" }, context);
    assertEquals(
      written[0].data.keyDetails,
      keyFile,
      "base64 decoded to the JSON",
    );
    assertEquals(written[0].data.keyId, "K9");
  } finally {
    __setCaller(null);
  }
});

Deno.test("user_set_state: inactive hits _deactivate and reports deactivated", async () => {
  const { caller, calls } = makeFakeApi(() => ({}));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("user_set_state").execute(
      { userId: "u1", state: "inactive" },
      context,
    );
    assert(calls.some((c) => c.path.endsWith("/users/u1/_deactivate")));
    assertEquals(written[0].data.action, "deactivated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("oidc_app_ensure: arg schema rejects an invalid appType enum", async () => {
  const { caller } = makeFakeApi(() => ({}));
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("oidc_app_ensure").execute(
          { project: "x", name: "y", appType: "bogus" },
          context,
        ),
      /Invalid|bogus|enum|expected/i,
    );
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── roles / grants / authorization ───────────────────────────

Deno.test("role_ensure: creates a role with roleKey when absent", async () => {
  let createBody: Record<string, unknown> | undefined;
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/roles/_search")) return { result: [] };
    if (c.path.endsWith("/projects/p1/roles") && c.method === "POST") {
      createBody = c.body as Record<string, unknown>;
      return {};
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("role_ensure").execute(
      { project: "homelab", key: "viewer", displayName: "Viewer", group: "ro" },
      context,
    );
    assertEquals(createBody?.roleKey, "viewer", "AddProjectRole uses roleKey");
    assertEquals(createBody?.displayName, "Viewer");
    assertEquals(createBody?.group, "ro");
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.key, "viewer");
    assertEquals(written[0].data.projectId, "p1");
  } finally {
    __setCaller(null);
  }
});

Deno.test("role_ensure: idempotent — unchanged when key/displayName/group match", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/roles/_search")) {
      return {
        result: [{ key: "viewer", displayName: "Viewer", group: "ro" }],
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("role_ensure").execute(
      { project: "homelab", key: "viewer", displayName: "Viewer", group: "ro" },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assert(
      !calls.some((c) => c.method === "PUT"),
      "must not PUT when nothing changed",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("role_remove: verify-first — refuses (no DELETE) when role is absent", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/roles/_search")) return { result: [] };
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("role_remove").execute(
          { projectId: "p1", key: "ghost" },
          context,
        ),
      /No role with key/,
    );
    assert(
      !calls.some((c) => c.method === "DELETE"),
      "must not DELETE a role it could not verify",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("role_remove: DELETEs an existing role and reports removed", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/roles/_search")) {
      return { result: [{ key: "viewer", displayName: "Viewer" }] };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("role_remove").execute(
      { projectId: "p1", key: "viewer" },
      context,
    );
    assert(
      calls.some((c) =>
        c.method === "DELETE" && c.path.endsWith("/projects/p1/roles/viewer")
      ),
      "DELETE the role",
    );
    assertEquals(written[0].data.action, "removed");
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_ensure: creates a grant (projectId + roleKeys) when none exists", async () => {
  let createBody: Record<string, unknown> | undefined;
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/users/grants/_search")) return { result: [] };
    if (c.path.endsWith("/users/500/grants") && c.method === "POST") {
      createBody = c.body as Record<string, unknown>;
      return { userGrantId: "g1" };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("grant_ensure").execute(
      { user: "500", project: "homelab", roleKeys: ["viewer"] },
      context,
    );
    assertEquals(createBody?.projectId, "p1");
    assertEquals(createBody?.roleKeys, ["viewer"]);
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.grantId, "g1");
    assertEquals(written[0].data.userId, "500");
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_ensure: unchanged when the role set matches (order-insensitive)", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/users/grants/_search")) {
      return {
        result: [{
          id: "g1",
          userId: "500",
          projectId: "p1",
          roleKeys: ["b", "a"],
        }],
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("grant_ensure").execute(
      { user: "500", project: "homelab", roleKeys: ["a", "b"] },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assert(
      !calls.some((c) => c.method === "PUT"),
      "same role set (reordered) must not PUT",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_ensure: converges the role set via PUT when it differs", async () => {
  let putBody: Record<string, unknown> | undefined;
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/users/grants/_search")) {
      return {
        result: [{ id: "g1", userId: "500", projectId: "p1", roleKeys: ["a"] }],
      };
    }
    if (c.method === "PUT" && c.path.endsWith("/users/500/grants/g1")) {
      putBody = c.body as Record<string, unknown>;
      return {};
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("grant_ensure").execute(
      { user: "500", project: "homelab", roleKeys: ["a", "b"] },
      context,
    );
    assertEquals(putBody?.roleKeys, ["a", "b"]);
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_set_state: refuses when the grant is not owned by the user", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/grants/_search")) {
      return { result: [{ id: "OTHER", userId: "500" }] };
    }
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("grant_set_state").execute(
          { user: "500", grantId: "g1", state: "inactive" },
          context,
        ),
      /does not belong/,
    );
    assert(
      !calls.some((c) => c.path.includes("_deactivate")),
      "must not deactivate a grant it could not verify",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_set_state: deactivates an owned grant and reports deactivated", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/grants/_search")) {
      return {
        result: [{
          id: "g1",
          userId: "500",
          projectId: "p1",
          roleKeys: ["a"],
          state: "USER_GRANT_STATE_ACTIVE",
        }],
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("grant_set_state").execute(
      { user: "500", grantId: "g1", state: "inactive" },
      context,
    );
    assert(
      calls.some((c) => c.path.endsWith("/users/500/grants/g1/_deactivate")),
      "hits _deactivate",
    );
    assertEquals(written[0].data.action, "deactivated");
    assertEquals(written[0].data.state, "inactive");
  } finally {
    __setCaller(null);
  }
});

Deno.test("project_authz_set: refuses to auto-create on an unknown project name", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) return { result: [] };
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("project_authz_set").execute(
          { project: "nope", roleAssertion: true },
          context,
        ),
      /No project named/,
    );
    assert(
      !calls.some((c) => c.method === "POST" && c.path.endsWith("/projects")),
      "must not create the project",
    );
    assert(!calls.some((c) => c.method === "PUT"), "must not PUT");
  } finally {
    __setCaller(null);
  }
});

Deno.test("project_authz_set: sets roleAssertion via PUT, preserving name + labeling", async () => {
  let putBody: Record<string, unknown> | undefined;
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.endsWith("/projects/123")) {
      return {
        project: {
          id: "123",
          name: "homelab",
          state: "PROJECT_STATE_ACTIVE",
          projectRoleAssertion: false,
          projectRoleCheck: false,
          hasProjectCheck: false,
          privateLabelingSetting:
            "PRIVATE_LABELING_SETTING_ENFORCE_PROJECT_RESOURCE_OWNER_POLICY",
        },
      };
    }
    if (c.method === "PUT" && c.path.endsWith("/projects/123")) {
      putBody = c.body as Record<string, unknown>;
      return {};
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("project_authz_set").execute(
      { project: "123", roleAssertion: true },
      context,
    );
    assertEquals(putBody?.projectRoleAssertion, true);
    assertEquals(
      putBody?.projectRoleCheck,
      false,
      "untouched flag stays false",
    );
    assertEquals(putBody?.name, "homelab", "name preserved on merge");
    assertEquals(
      putBody?.privateLabelingSetting,
      "PRIVATE_LABELING_SETTING_ENFORCE_PROJECT_RESOURCE_OWNER_POLICY",
      "labeling preserved on merge",
    );
    assertEquals(written[0].data.action, "updated");
    assertEquals(written[0].data.roleAssertion, true);
  } finally {
    __setCaller(null);
  }
});

Deno.test("project_authz_set: unchanged (no PUT) when the flag already matches", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.endsWith("/projects/123")) {
      return {
        project: { id: "123", name: "homelab", projectRoleAssertion: true },
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("project_authz_set").execute(
      { project: "123", roleAssertion: true },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assert(!calls.some((c) => c.method === "PUT"), "no PUT when already set");
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_list: filters by user + project and is a factory", async () => {
  const queries: unknown[] = [];
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/grants/_search")) {
      const b = c.body as { queries?: unknown[] };
      if (b.queries) queries.push(...b.queries);
      return {
        result: [
          { id: "g1", userId: "500", projectId: "p1", roleKeys: ["a"] },
          { id: "g2", userId: "500", projectId: "p1", roleKeys: ["b"] },
        ],
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("grant_list").execute(
      { user: "500", projectId: "p1" },
      context,
    );
    assertEquals(written.length, 2, "one grant resource per result");
    assertEquals(written[0].data.action, "observed");
    assert(
      JSON.stringify(queries).includes('"userId":"500"'),
      "userIdQuery built",
    );
    assert(
      JSON.stringify(queries).includes('"projectId":"p1"'),
      "projectIdQuery built",
    );
  } finally {
    __setCaller(null);
  }
});
