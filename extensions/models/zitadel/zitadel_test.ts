/**
 * Unit tests for the important, security-sensitive logic of `@thomas/zitadel`:
 * the JWT assertion claims, find-or-create idempotency, the friendly→Zitadel enum
 * mapping sent on the wire, the verify-first PAT-revoke guard, secret-once output
 * shape, the role/grant authorization methods (incl. project_authz_set's no-auto-
 * create), and the hard-delete guarantee (only role_remove and pat_revoke delete).
 * The API caller is faked via the __setCaller seam; the few tests of the real
 * HTTP path stub `fetch`. No live server.
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

/** One logged line: the level, the message template and its properties. */
type Logged = { level: string; message: string; props: unknown };

function makeContext(globalArgs: Record<string, unknown> = GLOBALS) {
  const written: Array<
    { specName: string; name: string; data: Record<string, unknown> }
  > = [];
  // Records every log line, so tests can check what was (and was not) logged.
  const logs: Logged[] = [];
  const record = (level: string) => (message: string, props?: unknown) => {
    logs.push({ level, message, props });
  };
  const context = {
    globalArgs,
    logger: {
      info: record("info"),
      debug: record("debug"),
      warn: record("warn"),
      error: record("error"),
    },
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
  return { context, written, logs };
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

Deno.test("project_ensure: idempotent, returns unchanged when present", async () => {
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
  // Every field UpdateOIDCAppConfigRequest accepts, with non-default values,
  // so a dropped field fails the assertion instead of matching by accident.
  const preserved = {
    responseTypes: ["OIDC_RESPONSE_TYPE_CODE"],
    grantTypes: ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"],
    appType: "OIDC_APP_TYPE_USER_AGENT",
    authMethodType: "OIDC_AUTH_METHOD_TYPE_NONE",
    postLogoutRedirectUris: ["https://a/out"],
    devMode: true,
    accessTokenType: "OIDC_TOKEN_TYPE_JWT",
    accessTokenRoleAssertion: true,
    idTokenRoleAssertion: true,
    idTokenUserinfoAssertion: true,
    clockSkew: "5s",
    additionalOrigins: ["https://origin"],
    skipNativeAppSuccessPage: true,
    backChannelLogoutUri: "https://a/logout",
    loginVersion: { loginV2: { baseUri: "https://login" } },
    ios: { bundleIds: ["io.a"] },
    android: { packageNames: ["io.a"] },
  };
  const oidcConfig = {
    clientId: "cid",
    redirectUris: ["https://a/cb", "https://b/cb"],
    ...preserved,
  };
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/apps/")) {
      gets++;
      const uris = gets >= 2
        ? ["https://b/cb", "https://c/cb"]
        : oidcConfig.redirectUris;
      return {
        app: {
          name: "shared",
          oidcConfig: { ...oidcConfig, redirectUris: uris },
        },
      };
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
    assertEquals(
      body,
      { redirectUris: ["https://b/cb", "https://c/cb"], ...preserved },
      "every writable field must survive, read-only clientId must not be sent",
    );
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
      return {
        app: { name: "x", oidcConfig: { redirectUris: ["https://a/cb"] } },
      };
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

Deno.test("oidc_app_ensure: a new app gets the defaults for fields left out", async () => {
  let createBody: Record<string, unknown> | undefined;
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/apps/_search")) return { result: [] };
    if (c.path.endsWith("/apps/oidc") && c.method === "POST") {
      createBody = c.body as Record<string, unknown>;
      return { appId: "a1", clientId: "cid" };
    }
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("oidc_app_ensure").execute(
      { project: "homelab", name: "grafana", redirectUris: ["https://g/cb"] },
      context,
    );
    assertEquals(createBody, {
      name: "grafana",
      redirectUris: ["https://g/cb"],
      postLogoutRedirectUris: [],
      responseTypes: ["OIDC_RESPONSE_TYPE_CODE"],
      grantTypes: [
        "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
        "OIDC_GRANT_TYPE_REFRESH_TOKEN",
      ],
      appType: "OIDC_APP_TYPE_WEB",
      authMethodType: "OIDC_AUTH_METHOD_TYPE_BASIC",
      accessTokenType: "OIDC_TOKEN_TYPE_BEARER",
      devMode: false,
    });
  } finally {
    __setCaller(null);
  }
});

// Same bug class as forgejo issue #4. Zitadel's update replaces every field,
// so a re-run must carry over what it was not given, including fields this
// method does not model, such as role assertions.
Deno.test("oidc_app_ensure: an existing app keeps every field that was not passed", async () => {
  const current = {
    clientId: "cid",
    // In the order the update body is built, since assertEquals compares JSON.
    redirectUris: ["https://spa/cb", "https://spa/cb2"],
    responseTypes: ["OIDC_RESPONSE_TYPE_CODE"],
    grantTypes: ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"],
    appType: "OIDC_APP_TYPE_USER_AGENT",
    authMethodType: "OIDC_AUTH_METHOD_TYPE_NONE",
    postLogoutRedirectUris: ["https://spa/bye"],
    accessTokenType: "OIDC_TOKEN_TYPE_JWT",
    idTokenRoleAssertion: true,
    additionalOrigins: ["https://spa"],
  };
  let putBody: unknown;
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/apps/_search")) {
      return {
        result: [{ id: "a1", name: "spa", oidcConfig: current }],
      };
    }
    if (c.method === "PUT") {
      putBody = c.body;
      return {};
    }
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("oidc_app_ensure").execute(
      { project: "homelab", name: "spa", devMode: true },
      context,
    );
    const { clientId: _, ...updatable } = current;
    assertEquals(putBody, { ...updatable, devMode: true });
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
          machine: { name: "Smoke Bot" },
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
    if (c.method === "GET") {
      return { app: { id: "a1", oidcConfig: { clientId: "cid" } } };
    }
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
  // accessTokenType and devMode absent. The read shape must show effective values.
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
            responseTypes: [
              "OIDC_RESPONSE_TYPE_CODE",
              "OIDC_RESPONSE_TYPE_ID_TOKEN",
            ],
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
    // friendlyState's "agent", so a read-then-converge reports no false drift.
    assertEquals(written[0].data.appType, "spa");
    assertEquals(written[0].data.accessTokenType, "jwt");
    assertEquals(written[0].data.devMode, true);
    // Through friendlyState, ID_TOKEN / AUTHORIZATION_CODE / REFRESH_TOKEN would
    // all become the wrong value ("token"/"code"); the reverse map avoids that.
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

// BASIC is enum value 0 for both OIDC and API apps, so Zitadel omits it.
Deno.test("app_get: reads an omitted authMethodType as basic", async () => {
  for (
    const config of [
      { oidcConfig: { clientId: "cid" } },
      { apiConfig: { clientId: "cid" } },
    ]
  ) {
    const { caller } = makeFakeApi((c) =>
      c.method === "GET"
        ? { app: { id: "a1", state: "APP_STATE_ACTIVE", ...config } }
        : undefined
    );
    __setCaller(caller);
    try {
      const { context, written } = makeContext();
      await method("app_get").execute(
        { projectId: "p1", appId: "a1" },
        context,
      );
      assertEquals(
        written[0].data.authMethod,
        "basic",
        String(written[0].data.kind),
      );
    } finally {
      __setCaller(null);
    }
  }
});

Deno.test("app_get: leaves authMethod undefined for a SAML app", async () => {
  const { caller } = makeFakeApi((c) =>
    c.method === "GET"
      ? { app: { id: "a1", state: "APP_STATE_ACTIVE", samlConfig: {} } }
      : undefined
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("app_get").execute({ projectId: "p1", appId: "a1" }, context);
    assertEquals(written[0].data.authMethod, undefined);
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
  const { caller, calls } = makeFakeApi((c) =>
    c.method === "GET" ? { user: { id: "u1", state: "USER_STATE_ACTIVE" } } : {}
  );
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

// Zitadel answers PreconditionFailed when the target already has the requested
// state, so a re-run must not send the POST.
Deno.test("user_set_state: unchanged (no POST) when the user is already inactive", async () => {
  const { caller, calls } = makeFakeApi((c) =>
    c.method === "GET"
      ? { user: { id: "u1", state: "USER_STATE_INACTIVE" } }
      : {}
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("user_set_state").execute(
      { userId: "u1", state: "inactive" },
      context,
    );
    assertEquals(calls.map((c) => c.method), ["GET"]);
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.state, "inactive");
  } finally {
    __setCaller(null);
  }
});

Deno.test("app_set_state: deactivates an active app", async () => {
  const { caller, calls } = makeFakeApi((c) =>
    c.method === "GET" ? { app: { id: "a1", state: "APP_STATE_ACTIVE" } } : {}
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("app_set_state").execute(
      { projectId: "p1", appId: "a1", state: "inactive" },
      context,
    );
    assert(calls.some((c) => c.path.endsWith("/apps/a1/_deactivate")));
    assertEquals(written[0].data.action, "deactivated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("app_set_state: unchanged (no POST) when the app already has the state", async () => {
  for (
    const [live, wanted] of [
      ["APP_STATE_INACTIVE", "inactive"],
      ["APP_STATE_ACTIVE", "active"],
    ]
  ) {
    const { caller, calls } = makeFakeApi((c) =>
      c.method === "GET" ? { app: { id: "a1", state: live } } : {}
    );
    __setCaller(caller);
    try {
      const { context, written } = makeContext();
      await method("app_set_state").execute(
        { projectId: "p1", appId: "a1", state: wanted },
        context,
      );
      assertEquals(calls.map((c) => c.method), ["GET"], wanted);
      assertEquals(written[0].data.action, "unchanged", wanted);
    } finally {
      __setCaller(null);
    }
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

Deno.test("role_ensure: idempotent, unchanged when key/displayName/group match", async () => {
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

Deno.test("role_remove: verify-first, refuses (no DELETE) when role is absent", async () => {
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

Deno.test("grant_ensure: re-run without roleKeys keeps the existing roles", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return { result: [{ id: "p1", name: "homelab" }] };
    }
    if (c.path.endsWith("/users/grants/_search")) {
      return {
        result: [{ id: "g1", userId: "500", projectId: "p1", roleKeys: ["a"] }],
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("grant_ensure").execute(
      { user: "500", project: "homelab" },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.roleKeys, ["a"]);
    assert(
      !calls.some((c) => c.method === "PUT"),
      "an omitted roleKeys must not strip the grant's roles",
    );
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

Deno.test("grant_set_state: a grant already in the target state is unchanged", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/grants/_search")) {
      return {
        result: [{
          id: "g1",
          userId: "500",
          projectId: "p1",
          roleKeys: ["a"],
          state: "USER_GRANT_STATE_INACTIVE",
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
      !calls.some((c) => c.path.includes("_deactivate")),
      "must not deactivate an inactive grant again",
    );
    assertEquals(written[0].data.action, "unchanged");
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

// ─────────────────────────── reachable check ───────────────────────────

// A check receives globalArgs without the schema's defaults. An unset
// httpTimeoutMs must not abort the token exchange at once, and an unset
// tokenScope must not be sent as the literal string "undefined".
Deno.test("reachable check applies the schema defaults to globalArgs", async () => {
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
  const pem = derToPem(
    new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)),
    "PRIVATE KEY",
  );
  let scope = null as string | null;
  let abortedInFlight = true;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    scope = new URLSearchParams(String(init?.body)).get("scope");
    // An undefined timeout fires on the next tick, so look after a pause.
    await new Promise((r) => setTimeout(r, 20));
    abortedInFlight = init?.signal?.aborted ?? false;
    return new Response(JSON.stringify({ access_token: "t", expires_in: 60 }));
  };
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: {
        apiUrl: GLOBALS.apiUrl,
        // A keyId of its own, so the module's token cache has no entry for it.
        keyJson: JSON.stringify({
          keyId: "check-defaults",
          key: pem,
          userId: "u123",
        }),
      },
    });
    assertEquals(res.pass, true);
    assertEquals(abortedInFlight, false);
    assert(scope?.startsWith("openid"), `default scope expected, got ${scope}`);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ─────────────────────────── strict booleans ───────────────────────────

// Plain z.boolean() keeps the JSON Schema; the CLI coerces --input x=true
// before the schema sees it, so the schema itself sees only real booleans.
Deno.test("boolean arguments accept only real booleans", () => {
  const schema = (model.methods as unknown as Record<string, {
    arguments: {
      safeParse: (v: unknown) => {
        success: boolean;
        error?: { issues: { path: PropertyKey[] }[] };
      };
    };
  }>)["oidc_app_ensure"].arguments;
  const fieldFails = (v: unknown) => {
    const r = schema.safeParse({ devMode: v });
    return (r.error?.issues ?? []).some((i) => i.path[0] === "devMode");
  };
  for (const bad of ["true", "false", "0", "1", "False", "yes", null]) {
    assert(fieldFails(bad), `devMode=${JSON.stringify(bad)} must be rejected`);
  }
  for (const good of [true, false]) {
    assert(
      !fieldFails(good),
      `devMode=${JSON.stringify(good)} must be accepted`,
    );
  }
});

// ─────────────────────────── user lookup ───────────────────────────

Deno.test("machine_user_ensure: a human with the same username is not taken for a machine", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/_search")) {
      return {
        result: [{ id: "500", userName: "smoke-bot", human: { profile: {} } }],
      };
    }
    if (c.path.endsWith("/users/machine")) return { userId: "901" };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("machine_user_ensure").execute(
      { username: "smoke-bot", name: "Smoke Bot" },
      context,
    );
    assertEquals(written[0].data.action, "created");
    const search = calls.find((c) => c.path.endsWith("/users/_search"));
    assert(
      JSON.stringify(search?.body).includes("TYPE_MACHINE"),
      "the search asks for machine users",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_list: a user can be named by login name", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/_search")) {
      return {
        result: [{
          id: "700",
          preferredLoginName: "alice@example.com",
          loginNames: ["alice@example.com"],
        }],
      };
    }
    if (c.path.endsWith("/users/grants/_search")) return { result: [] };
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("grant_list").execute({ user: "alice@example.com" }, context);
    const search = calls.find((c) => c.path.endsWith("/users/_search"));
    assert(JSON.stringify(search?.body).includes("loginNameQuery"));
    const grants = calls.find((c) => c.path.endsWith("/users/grants/_search"));
    assert(JSON.stringify(grants?.body).includes("700"), "filters on the id");
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_list: a machine username still resolves when no login name matches", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/_search")) {
      const byLoginName = JSON.stringify(c.body).includes("loginNameQuery");
      return byLoginName ? { result: [] } : {
        result: [{ id: "900", userName: "smoke-bot", machine: { name: "x" } }],
      };
    }
    if (c.path.endsWith("/users/grants/_search")) return { result: [] };
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("grant_list").execute({ user: "smoke-bot" }, context);
    const grants = calls.find((c) => c.path.endsWith("/users/grants/_search"));
    assert(
      JSON.stringify(grants?.body).includes("900"),
      "filters on the machine user's id",
    );
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── data names ───────────────────────────

// swamp keys data by model + name, not spec: a user record must never replace
// the client secret generated for the same user id.
Deno.test("data names: a user and its client secret get distinct names", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/900/secret")) {
      return { clientId: "ci", clientSecret: "s3cret" };
    }
    if (c.path.endsWith("/users/_search")) {
      return {
        result: [{ id: "900", userName: "ci", machine: { name: "CI" } }],
        details: { totalResult: "1" },
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("machine_secret_generate").execute({ user: "900" }, context);
    await method("user_list").execute({ type: "machine" }, context);
    assertEquals(written.map((w) => w.name), [
      "machine-credential:secret:900",
      "user:900",
    ]);
  } finally {
    __setCaller(null);
  }
});

Deno.test("data names: role keys are escaped so distinct keys never collide", async () => {
  const keys = ["a/b", "a%2Fb", "a..b", "a.b", "a\\b"];
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/roles/_search")) {
      return {
        result: keys.map((key) => ({ key })),
        details: { totalResult: String(keys.length) },
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("role_list").execute({ projectId: "300" }, context);
    const names = written.map((w) => w.name);
    assertEquals(names, [
      "role:300:a%2Fb",
      "role:300:a%252Fb",
      "role:300:a.%2Eb",
      "role:300:a.b",
      "role:300:a%5Cb",
    ]);
    for (const n of names) {
      assert(!/[\/\\\0]|\.\./.test(n), `${n} is a valid swamp data name`);
    }
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── hard deletes ───────────────────────────

// Arguments that let every method run to completion against `everythingApi`.
// The table must name every method, so a new method cannot skip this check.
const RUN_ALL_ARGS: Record<string, Record<string, unknown>> = {
  org_get: {},
  project_list: {},
  app_list: { projectId: "1" },
  app_get: { projectId: "1", appId: "1" },
  oidc_app_redirect_set: { projectId: "1", appId: "1", add: ["https://x"] },
  user_list: {},
  manager_audit: {},
  project_ensure: { name: "n" },
  oidc_app_ensure: { project: "1", name: "n", devMode: true },
  api_app_ensure: { project: "1", name: "n" },
  app_secret_rotate: { projectId: "1", appId: "1" },
  machine_user_ensure: { username: "n", name: "n" },
  pat_create: { user: "1" },
  pat_revoke: { user: "1", tokenId: "1" },
  machine_key_create: { user: "1" },
  machine_secret_generate: { user: "1" },
  app_set_state: { projectId: "1", appId: "1", state: "inactive" },
  user_set_state: { userId: "1", state: "inactive" },
  role_list: { projectId: "1" },
  role_ensure: { project: "1", key: "k" },
  role_remove: { projectId: "1", key: "k" },
  grant_list: {},
  grant_ensure: { user: "1", project: "1", roleKeys: ["k", "j"] },
  grant_set_state: { user: "1", grantId: "1", state: "inactive" },
  project_authz_set: { project: "1", roleAssertion: true },
};

/** A fake API where every lookup finds one object matching the args above. */
function everythingApi() {
  const item = {
    id: "1",
    name: "n",
    key: "k",
    userId: "1",
    projectId: "1",
    userName: "n",
    roleKeys: ["k"],
    state: "STATE_ACTIVE",
    machine: { name: "n" },
    oidcConfig: { clientId: "c" },
    apiConfig: { clientId: "c" },
  };
  return makeFakeApi(() => ({
    result: [item],
    details: { totalResult: "1" },
    app: item,
    user: item,
    project: item,
    org: item,
    id: "1",
    appId: "1",
    userId: "1",
    tokenId: "1",
    keyId: "1",
    userGrantId: "1",
  }));
}

Deno.test("model: only role_remove and pat_revoke send a DELETE", async () => {
  assertEquals(
    Object.keys(RUN_ALL_ARGS).sort(),
    Object.keys(model.methods).sort(),
    "the table covers every method",
  );
  const deleting: string[] = [];
  for (const [name, args] of Object.entries(RUN_ALL_ARGS)) {
    const { caller, calls } = everythingApi();
    __setCaller(caller);
    try {
      await method(name).execute(args, makeContext().context);
    } finally {
      __setCaller(null);
    }
    if (calls.some((c) => c.method === "DELETE")) deleting.push(name);
  }
  assertEquals(deleting.sort(), ["pat_revoke", "role_remove"]);
});

// ─────────────────────────── stage-3 fixes ───────────────────────────

Deno.test("project_list: an omitted authorization flag reads false", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      return {
        result: [{ id: "1", name: "p", projectRoleAssertion: true }],
        details: { totalResult: "1" },
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("project_list").execute({}, context);
    assertEquals(written[0].data.roleAssertion, true);
    assertEquals(written[0].data.roleCheck, false);
    assertEquals(written[0].data.hasProjectCheck, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("api_app_ensure: refuses a name that is an OIDC app", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/apps/_search")) {
      return { result: [{ id: "a1", name: "web", oidcConfig: {} }] };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("api_app_ensure").execute(
          { project: "1", name: "web" },
          context,
        ),
      /not an API app/,
    );
    assertEquals(written.length, 0);
    assertEquals(calls.filter((c) => c.path.endsWith("/apps/api")).length, 0);
  } finally {
    __setCaller(null);
  }
});

Deno.test("oidc_app_ensure: refuses a name that is an API app (no PUT)", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/apps/_search")) {
      return { result: [{ id: "a1", name: "api", apiConfig: {} }] };
    }
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("oidc_app_ensure").execute(
          { project: "1", name: "api", devMode: true },
          context,
        ),
      /not an OIDC app/,
    );
    assert(!calls.some((c) => c.method === "PUT"), "nothing written");
  } finally {
    __setCaller(null);
  }
});

Deno.test("api_app_ensure: creates with the jwt default and returns the id", async () => {
  let body: unknown;
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/apps/_search")) return { result: [] };
    if (c.path.endsWith("/apps/api")) {
      body = c.body;
      return { appId: "a7", clientId: "cid" };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("api_app_ensure").execute(
      { project: "1", name: "m2m" },
      context,
    );
    assertEquals(body, {
      name: "m2m",
      authMethodType: "API_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT",
    });
    assertEquals(written[0].name, "app-credential:a7");
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.kind, "api");
  } finally {
    __setCaller(null);
  }
});

Deno.test("app_secret_rotate: takes the kind from the app (API app, no kind passed)", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET") return { app: { id: "a1", apiConfig: {} } };
    return { clientId: "cid", clientSecret: "s" };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("app_secret_rotate").execute(
      { projectId: "1", appId: "a1" },
      context,
    );
    assert(
      calls.some((c) => c.path.endsWith("/api_config/_generate_client_secret")),
    );
    assertEquals(written[0].data.kind, "api");
  } finally {
    __setCaller(null);
  }
});

Deno.test("app_secret_rotate: a kind that does not match the app is refused", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET") return { app: { id: "a1", apiConfig: {} } };
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_secret_rotate").execute(
          { projectId: "1", appId: "a1", kind: "oidc" },
          context,
        ),
      /is an api app, not oidc/,
    );
    assertEquals(calls.filter((c) => c.method === "POST").length, 0);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pat_revoke: finds a token beyond the first page", async () => {
  const page1 = Array.from({ length: 100 }, (_, i) => ({ id: `t${i}` }));
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/pats/_search")) {
      const off = (c.body as { query: { offset: number } }).query.offset;
      return {
        result: off === 0 ? page1 : [{ id: "t100" }],
        details: { totalResult: "101" },
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pat_revoke").execute(
      { user: "900", tokenId: "t100" },
      context,
    );
    assert(calls.some((c) => c.method === "DELETE"), "revoked");
    assertEquals(written[0].data.action, "revoked");
  } finally {
    __setCaller(null);
  }
});

Deno.test("grant_ensure: an existing deactivated grant keeps its state", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/users/grants/_search")) {
      return {
        result: [{
          id: "g1",
          userId: "700",
          projectId: "300",
          roleKeys: ["a"],
          state: "USER_GRANT_STATE_INACTIVE",
          displayName: "Alice",
        }],
      };
    }
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("grant_ensure").execute(
      { user: "700", project: "300", roleKeys: ["a", "b"] },
      context,
    );
    assertEquals(written[0].data.action, "updated");
    assertEquals(written[0].data.state, "inactive");
    assertEquals(written[0].data.displayName, "Alice");
  } finally {
    __setCaller(null);
  }
});

Deno.test("role_ensure: logs a project it creates for an unknown name", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) return { result: [] };
    if (c.method === "POST" && c.path.endsWith("/projects")) {
      return { id: "300" };
    }
  });
  __setCaller(caller);
  try {
    const { context, logs } = makeContext();
    await method("role_ensure").execute(
      { project: "homelba", key: "admin" },
      context,
    );
    assert(
      logs.some((l) =>
        l.message.startsWith("Created project") &&
        JSON.stringify(l.props).includes("homelba")
      ),
      "the implicit project creation is logged",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("create methods fail when Zitadel returns no id", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/_search")) return { result: [] };
    return {};
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () => method("project_ensure").execute({ name: "p" }, context),
      /project create returned no id/,
    );
    await rejects(
      () => method("pat_create").execute({ user: "900" }, context),
      /PAT create returned no tokenId/,
    );
    await rejects(
      () =>
        method("grant_ensure").execute(
          { user: "700", project: "300" },
          context,
        ),
      /grant create returned no userGrantId/,
    );
    assertEquals(written.length, 0);
  } finally {
    __setCaller(null);
  }
});

Deno.test("user_set_state: refuses to deactivate the model's own service user", async () => {
  // GLOBALS' keyJson belongs to user u123.
  const { caller, calls } = makeFakeApi(() => ({
    user: { state: "USER_STATE_ACTIVE" },
  }));
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("user_set_state").execute(
          { userId: "u123", state: "inactive" },
          context,
        ),
      /own service user/,
    );
    assertEquals(calls.length, 0);
  } finally {
    __setCaller(null);
  }
});

Deno.test("a plain-http apiUrl logs a warning; https does not", async () => {
  const { caller } = makeFakeApi(() => ({ org: { id: "1", name: "o" } }));
  __setCaller(caller);
  try {
    const http = makeContext({ ...GLOBALS, apiUrl: "http://zitadel.lan" });
    await method("org_get").execute({}, http.context);
    assert(http.logs.some((l) => l.level === "warn"), "warned for http");
    const https = makeContext();
    await method("org_get").execute({}, https.context);
    assert(!https.logs.some((l) => l.level === "warn"), "quiet for https");
  } finally {
    __setCaller(null);
  }
});

Deno.test("httpTimeoutMs must be positive", () => {
  const schema = model.globalArguments;
  const base = { apiUrl: GLOBALS.apiUrl, keyJson: GLOBALS.keyJson };
  assert(!schema.safeParse({ ...base, httpTimeoutMs: 0 }).success, "0");
  assert(!schema.safeParse({ ...base, httpTimeoutMs: -5 }).success, "-5");
  assert(schema.safeParse({ ...base, httpTimeoutMs: 1 }).success, "1");
});

// ─────────────────────────── untested methods ───────────────────────────

Deno.test("org_get: records the org", async () => {
  const { caller } = makeFakeApi(() => ({
    org: {
      id: "1",
      name: "Home",
      state: "ORG_STATE_ACTIVE",
      primaryDomain: "home.example.com",
    },
  }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("org_get").execute({}, context);
    assertEquals(written[0].name, "org:1");
    assertEquals(written[0].data.state, "active");
    assertEquals(written[0].data.primaryDomain, "home.example.com");
  } finally {
    __setCaller(null);
  }
});

Deno.test("user_list: filters by type, shapes both kinds, logs a count", async () => {
  const { caller, calls } = makeFakeApi(() => ({
    result: [
      { id: "1", userName: "bot", machine: { name: "Bot" } },
      { id: "2", userName: "al", human: { profile: { displayName: "Al" } } },
    ],
    details: { totalResult: "2" },
  }));
  __setCaller(caller);
  try {
    const { context, written, logs } = makeContext();
    await method("user_list").execute({ type: "machine" }, context);
    assert(JSON.stringify(calls[0].body).includes("TYPE_MACHINE"));
    assertEquals(written.map((w) => [w.data.type, w.data.displayName]), [
      ["machine", "Bot"],
      ["human", "Al"],
    ]);
    assert(
      logs.some((l) => (l.props as { count?: number }).count === 2),
      "completion count logged",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("manager_audit: records each manager's roles", async () => {
  const { caller } = makeFakeApi(() => ({
    result: [{ userId: "1", displayName: "Root", roles: ["ORG_OWNER"] }],
    details: { totalResult: "1" },
  }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("manager_audit").execute({}, context);
    assertEquals(written[0].name, "manager:1");
    assertEquals(written[0].data.roles, ["ORG_OWNER"]);
  } finally {
    __setCaller(null);
  }
});

Deno.test("machine_secret_generate: returns the secret once under its own name", async () => {
  const { caller, calls } = makeFakeApi(() => ({
    clientId: "ci",
    clientSecret: "s3cret",
  }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("machine_secret_generate").execute({ user: "900" }, context);
    assertEquals(calls[0].method, "PUT");
    assertEquals(written[0].name, "machine-credential:secret:900");
    assertEquals(written[0].data.clientSecret, "s3cret");
    assertEquals(written[0].data.action, "rotated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("no secret a method mints ever reaches the logger", async () => {
  const secret = "SECRET-VALUE-do-not-log";
  const { caller } = makeFakeApi((c) => {
    if (c.path.endsWith("/_search")) return { result: [] };
    if (c.method === "GET") return { app: { id: "1", oidcConfig: {} } };
    return {
      appId: "1",
      tokenId: "1",
      keyId: "1",
      clientId: "c",
      clientSecret: secret,
      token: secret,
      keyDetails: btoa(secret),
    };
  });
  __setCaller(caller);
  try {
    const { context, logs } = makeContext();
    const runs: [string, Record<string, unknown>][] = [
      ["oidc_app_ensure", { project: "1", name: "n" }],
      ["api_app_ensure", { project: "1", name: "n", authMethod: "basic" }],
      ["app_secret_rotate", { projectId: "1", appId: "1" }],
      ["pat_create", { user: "900" }],
      ["machine_key_create", { user: "900" }],
      ["machine_secret_generate", { user: "900" }],
    ];
    for (const [name, args] of runs) await method(name).execute(args, context);
    assert(logs.length > 0, "the methods did log");
    for (const l of logs) {
      assert(
        !JSON.stringify(l).includes(secret),
        `logged a secret: ${l.message}`,
      );
    }
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── real HTTP path ───────────────────────────

/** A real RSA key, so getToken can sign; a fresh keyId skips the token cache. */
async function realKeyJson(): Promise<string> {
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
  const pem = derToPem(
    new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)),
    "PRIVATE KEY",
  );
  return JSON.stringify({ keyId: crypto.randomUUID(), key: pem, userId: "u1" });
}

/** Run org_get through the real caller with `fetch` replaced by `fake`. */
async function orgGetWithFetch(
  fake: typeof fetch,
  extra: Record<string, unknown> = {},
): Promise<unknown> {
  const realFetch = globalThis.fetch;
  globalThis.fetch = fake;
  try {
    const { context } = makeContext({
      ...GLOBALS,
      keyJson: await realKeyJson(),
      ...extra,
    });
    return await method("org_get").execute({}, context);
  } finally {
    globalThis.fetch = realFetch;
  }
}

const tokenOk = () =>
  new Response(JSON.stringify({ access_token: "t", expires_in: 60 }));

Deno.test("realCaller: a non-JSON token response gives a clear error", async () => {
  await rejects(
    () =>
      orgGetWithFetch(() =>
        Promise.resolve(new Response("<html>login</html>", { status: 200 }))
      ),
    /token exchange returned non-JSON/,
  );
});

Deno.test("realCaller: an API error carries method, path, status and message", async () => {
  await rejects(
    () =>
      orgGetWithFetch((url) =>
        Promise.resolve(
          String(url).endsWith("/oauth/v2/token") ? tokenOk() : new Response(
            JSON.stringify({ message: "org not found" }),
            { status: 404 },
          ),
        )
      ),
    /^Zitadel API GET \/management\/v1\/orgs\/me -> HTTP 404: org not found$/,
  );
});

Deno.test("realCaller: the timeout also covers a stalled response body", async () => {
  // Headers arrive at once; the body never does, unless the request is aborted.
  const stalled: typeof fetch = (url, init) => {
    if (String(url).endsWith("/oauth/v2/token")) {
      return Promise.resolve(tokenOk());
    }
    const body = new ReadableStream({
      start(ctrl) {
        init?.signal?.addEventListener("abort", () => {
          ctrl.error(new DOMException("aborted", "AbortError"));
        });
      },
    });
    return Promise.resolve(new Response(body));
  };
  let guard: ReturnType<typeof setTimeout> | undefined;
  const hang = new Promise<string>((resolve) => {
    guard = setTimeout(() => resolve("hung"), 2000);
  });
  try {
    const outcome = await Promise.race([
      orgGetWithFetch(stalled, { httpTimeoutMs: 50 }).then(
        () => "resolved",
        () => "aborted",
      ),
      hang,
    ]);
    assertEquals(outcome, "aborted");
  } finally {
    clearTimeout(guard);
  }
});

// ─────────────────────────── project references ───────────────────────────

Deno.test("grant_ensure: an unknown project name fails and creates nothing", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/_search")) return { result: [] };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("grant_ensure").execute(
          { user: "700", project: "homelba", roleKeys: [] },
          context,
        ),
      /No project named "homelba"/,
    );
    assertEquals(
      calls.filter((c) => c.method === "POST" && !c.path.endsWith("/_search"))
        .length,
      0,
    );
    assertEquals(written.length, 0);
  } finally {
    __setCaller(null);
  }
});

Deno.test("an all-digit project value is looked up by name before it is taken as an id", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/projects/_search")) {
      const asked = JSON.stringify(c.body);
      return {
        result: asked.includes('"2026"') ? [{ id: "999", name: "2026" }] : [],
      };
    }
    if (c.path.endsWith("/roles/_search")) return { result: [] };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("role_ensure").execute({ project: "2026", key: "a" }, context);
    assertEquals(written[0].data.projectId, "999", "found by name");
    await method("role_ensure").execute({ project: "300", key: "a" }, context);
    assertEquals(written[1].data.projectId, "300", "no name match: an id");
    assert(
      !calls.some((c) => c.method === "POST" && c.path.endsWith("/projects")),
      "an all-digit value never creates a project",
    );
  } finally {
    __setCaller(null);
  }
});
