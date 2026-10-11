/**
 * Unit tests for `@thomas/stalwart`: the Prometheus parser, the `reachable`
 * check, the JMAP request envelopes, idempotency and the existence checks before
 * each write, the transport, and the no-destroy guarantee (the module never writes a
 * JMAP `destroy` verb). No live server: the JMAP/REST callers are faked via the
 * __setJmap / __setRest seams.
 */
import { z } from "npm:zod@4";
import {
  __setJmap,
  __setRest,
  type JmapCall,
  type JmapFn,
  type JmapResult,
  model,
  parsePrometheus,
  type RestCall,
  type RestFn,
  type RestResult,
} from "./stalwart.ts";

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
  apiUrl: "https://mail.test.example.com",
  apiKey: "test-key",
  httpTimeoutMs: 30000,
};

type RecordedRest = { method: string; path: string };

function makeFakeRest(
  respond?: (c: RestCall) => Partial<RestResult> | undefined,
) {
  const calls: RecordedRest[] = [];
  const caller: RestFn = (_g, c): Promise<RestResult> => {
    calls.push({ method: c.method, path: c.path });
    const r = respond?.(c);
    return Promise.resolve({ status: 200, body: {}, ...r });
  };
  return { caller, calls };
}

type LogLine = { level: string; message: string; props: Json };

function makeContext(globals: Record<string, unknown> = GLOBALS) {
  const written: Array<
    { specName: string; name: string; data: Record<string, unknown> }
  > = [];
  const logs: LogLine[] = [];
  const log = (level: string) => (message: string, props: Json = {}) =>
    logs.push({ level, message, props });
  const context = {
    globalArgs: globals,
    logger: {
      info: log("info"),
      debug: log("debug"),
      warn: log("warn"),
      error: log("error"),
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

/** A fake JMAP caller. `respond` returns a canned response body per envelope. */
function makeFakeJmap(respond: (c: JmapCall) => Json) {
  const calls: JmapCall[] = [];
  const caller: JmapFn = (_g, c): Promise<JmapResult> => {
    calls.push(c);
    return Promise.resolve({ status: 200, body: respond(c) });
  };
  return { caller, calls };
}
type Json = Record<string, unknown>;

/** Build a JMAP `methodResponses` body for a single method call. */
function jmapOk(name: string, args: Json): Json {
  return { methodResponses: [[name, args, "c0"]], sessionState: "s" };
}

/**
 * A JMAP fake driven by a `type → objects[]` table: `<type>/query` returns the
 * objects' ids (+ total); `<type>/get` returns the objects as `list`; `/set`
 * updates apply each top-level field to the stored object. The table is
 * copied, so a test can reuse it. `onSet`, when given, sees each set after it
 * is applied and may return a response body to send instead. Also sets the
 * REST seam so resolveAccountId() finds accountId `l`.
 */
function makeTypedJmap(
  original: Record<string, Json[]>,
  onSet?: (
    type: string,
    args: Json,
    table: Record<string, Json[]>,
  ) => Json | undefined,
) {
  const table = structuredClone(original);
  __setRest(
    makeFakeRest((c) =>
      c.path === "/.well-known/jmap"
        ? { body: { primaryAccounts: { "urn:stalwart:jmap": "l" } } }
        : {}
    ).caller,
  );
  const setCalls: Array<{ type: string; args: Json }> = [];
  const caller: JmapFn = (_g, c): Promise<JmapResult> => {
    const [name, args] = c.methodCalls[0] as [string, Json];
    const type = name.replace(/\/(query|get|set)$/, "");
    const objs = table[type] ?? [];
    if (name.endsWith("/query")) {
      return Promise.resolve({
        status: 200,
        body: jmapOk(name, {
          ids: objs.map((o) => String(o.id)),
          total: objs.length,
          position: 0,
        }),
      });
    }
    if (name.endsWith("/get")) {
      const want = new Set(
        (args.ids as string[] | undefined) ?? objs.map((o) => String(o.id)),
      );
      return Promise.resolve({
        status: 200,
        body: jmapOk(name, {
          list: objs.filter((o) => want.has(String(o.id))),
        }),
      });
    }
    if (name.endsWith("/set")) {
      setCalls.push({ type, args });
      const out: Json = {};
      const create = args.create as Record<string, Json> | undefined;
      const update = args.update as Record<string, Json> | undefined;
      if (create) {
        out.created = Object.fromEntries(
          Object.keys(create).map((k) => [k, { id: `new-${k}` }]),
        );
      }
      if (update) {
        for (const [id, patch] of Object.entries(update)) {
          const obj = objs.find((o) => String(o.id) === id);
          if (obj) Object.assign(obj, patch);
        }
        out.updated = Object.fromEntries(
          Object.keys(update).map((k) => [k, null]),
        );
      }
      const override = onSet?.(type, args, table);
      return Promise.resolve({
        status: 200,
        body: jmapOk(name, override ?? out),
      });
    }
    return Promise.resolve({ status: 200, body: jmapOk(name, {}) });
  };
  __setJmap(caller);
  return { setCalls };
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

Deno.test("parsePrometheus: labels collapse, comments skipped, non-numeric dropped", () => {
  const text = [
    "# HELP foo a counter",
    "# TYPE foo counter",
    "foo 42",
    'bar{host="a",svc="x"} 3.5',
    'bar{host="b"} 7',
    "baz NaN",
    "garbage line",
  ].join("\n");
  const m = parsePrometheus(text);
  assertEquals(m.foo, 42);
  assertEquals(m.bar, 7, "last sample wins after collapsing labels");
  assert(!("baz" in m), "NaN dropped");
  assert(!("garbage" in m), "non-metric line ignored");
});

Deno.test("reachable: a definition that fails the schema fails without probing", async () => {
  const { caller, calls } = makeFakeRest(() => ({ body: {} }));
  __setRest(caller);
  try {
    const check = (model.checks as unknown as Record<string, {
      execute: (c: unknown) => Promise<{ pass: boolean }>;
    }>).reachable;
    const res = await check.execute({
      globalArgs: { apiUrl: GLOBALS.apiUrl },
    });
    assertEquals(res.pass, false);
    assertEquals(calls.length, 0, "must not probe with an invalid definition");
  } finally {
    __setRest(null);
  }
});

Deno.test("reachable: fails with a clear error when the API is unreachable", async () => {
  const { caller } = makeFakeRest(() => {
    throw new Error("connection refused");
  });
  __setRest(caller);
  try {
    const check = (model.checks as unknown as Record<string, {
      execute: (c: unknown) => Promise<{ pass: boolean; errors?: string[] }>;
    }>).reachable;
    const res = await check.execute({
      globalArgs: { apiUrl: GLOBALS.apiUrl, apiKey: GLOBALS.apiKey },
    });
    assertEquals(res.pass, false);
    assert(
      (res.errors?.[0] ?? "").includes("Cannot reach Stalwart"),
      "error mentions unreachable host",
    );
  } finally {
    __setRest(null);
  }
});

Deno.test("health_status: maps /api/account + prometheus into one health resource", async () => {
  const { caller, calls } = makeFakeRest((c) => {
    if (c.path === "/api/account") {
      return {
        body: {
          edition: "community",
          permissions: ["principal-list", "settings-update"],
        },
      };
    }
    if (c.path === "/metrics/prometheus") {
      return { text: "server_memory_bytes 1234\nqueue_total 5\n", body: {} };
    }
    return {};
  });
  __setRest(caller);
  try {
    const { context, written } = makeContext();
    const out = await method("health_status").execute({}, context);
    assertEquals(out.dataHandles.length, 1);
    const d = written[0].data;
    assertEquals(d.reachable, true);
    assertEquals(d.edition, "community");
    assertEquals(d.action, "observed");
    assertEquals(
      (d.metrics as Record<string, number>).server_memory_bytes,
      1234,
    );
    assert(calls.some((c) => c.path === "/api/account"));
    assert(calls.some((c) => c.path === "/metrics/prometheus"));
  } finally {
    __setRest(null);
  }
});

Deno.test("health_status: survives gated/absent metrics endpoint", async () => {
  const { caller } = makeFakeRest((c) => {
    if (c.path === "/api/account") return { body: { edition: "community" } };
    throw new Error("HTTP 403"); // metrics gated
  });
  __setRest(caller);
  try {
    const { context, written } = makeContext();
    await method("health_status").execute({}, context);
    assertEquals(written[0].data.reachable, true);
    assertEquals(written[0].data.metrics, {}, "no metrics but still healthy");
  } finally {
    __setRest(null);
  }
});

Deno.test("jmap_probe: query→get envelope shape, accountId resolved from session", async () => {
  // The REST seam returns the session discovery for resolveAccountId.
  const fakeRest = makeFakeRest((c) => {
    if (c.path === "/.well-known/jmap") {
      return {
        body: {
          accounts: { acctX: {} },
          primaryAccounts: { "urn:stalwart:jmap": "acctX" },
        },
      };
    }
    return {};
  });
  __setRest(fakeRest.caller);
  const { caller, calls } = makeFakeJmap((c) => {
    const name = (c.methodCalls[0] as unknown[])[0];
    if (name === "Principal/query") {
      return jmapOk("Principal/query", { ids: ["p1"] });
    }
    if (name === "Principal/get") {
      return jmapOk("Principal/get", {
        list: [{ id: "p1", name: "a@x.test" }],
      });
    }
    return jmapOk("x", {});
  });
  __setJmap(caller);
  try {
    const { context, written } = makeContext({
      ...GLOBALS,
      accountId: undefined,
    });
    await method("jmap_probe").execute(
      { type: "Principal", limit: 5 },
      context,
    );
    // Two envelopes: query then get.
    assertEquals(calls.length, 2);
    const q = calls[0].methodCalls[0] as unknown[];
    assertEquals(q[0], "Principal/query");
    assertEquals(
      (q[1] as Json).accountId,
      "acctX",
      "accountId from session primary",
    );
    assertEquals((q[1] as Json).limit, 5);
    assertEquals(calls[0].using, [
      "urn:ietf:params:jmap:core",
      "urn:stalwart:jmap",
    ]);
    const get = calls[1].methodCalls[0] as unknown[];
    assertEquals(get[0], "Principal/get");
    assertEquals((get[1] as Json).ids, ["p1"]);
    // Probe resource captures the sample + count.
    const d = written[0].data;
    assertEquals(d.count, 1);
    assertEquals(d.ids, ["p1"]);
    assert(String(d.sample).includes("a@x.test"), "sample carries the object");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("jmap_probe: a JMAP method-level error is surfaced, not swallowed", async () => {
  __setRest(
    makeFakeRest(() => ({
      body: { primaryAccounts: { "urn:stalwart:jmap": "a" } },
    })).caller,
  );
  const { caller } = makeFakeJmap(() => ({
    methodResponses: [["error", {
      type: "unknownMethod",
      description: "no such type",
    }, "c0"]],
  }));
  __setJmap(caller);
  try {
    const { context } = makeContext();
    let threw = false;
    try {
      await method("jmap_probe").execute({ type: "Bogus", limit: 5 }, context);
    } catch (e) {
      threw = true;
      assert(
        /unknownMethod/.test((e as Error).message),
        `error should carry the JMAP error type, got: ${(e as Error).message}`,
      );
    }
    assert(threw, "expected the method-level error to propagate");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("domain_list: isEnabled maps to state, one resource per domain", async () => {
  makeTypedJmap({
    "x:Domain": [
      { id: "c", name: "example.com", isEnabled: true },
      { id: "b", name: "example.net", isEnabled: false },
    ],
  });
  try {
    const { context, written } = makeContext();
    const out = await method("domain_list").execute({}, context);
    assertEquals(out.dataHandles.length, 2);
    assertEquals(written[0].name, "domain:example.com");
    assertEquals(written[0].data, {
      id: "c",
      name: "example.com",
      state: "active",
      action: "observed",
      timestamp: written[0].data.timestamp,
    });
    assertEquals(
      written[1].data.state,
      "inactive",
      "isEnabled:false → inactive",
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_list: extracts aliases, type, and disabled detection", async () => {
  makeTypedJmap({
    "x:Domain": [{ id: "c", name: "example.com" }],
    "x:Account": [
      {
        id: "l",
        name: "swamp-admin",
        emailAddress: "swamp-admin@example.com",
        domainId: "c",
        "@type": "User",
        // The wire shape: a local part plus a domain id, never a full address.
        aliases: {
          "0": { name: "ops", domainId: "c", enabled: true },
        },
        roles: { "@type": "Admin" },
        permissions: { "@type": "Inherit" },
      },
      {
        id: "m",
        name: "blocked",
        "@type": "User",
        aliases: {},
        roles: { "@type": "User" },
        permissions: {
          "@type": "Replace",
          enabledPermissions: {},
          disabledPermissions: {},
        },
      },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("account_list").execute({}, context);
    assertEquals(written[0].data.name, "swamp-admin");
    assertEquals(written[0].data.email, "swamp-admin@example.com");
    assertEquals(written[0].data.type, "individual", "@type User → individual");
    assertEquals(
      written[0].data.aliases,
      ["ops@example.com"],
      "alias local part joined to its domain name",
    );
    assertEquals(written[0].data.roles, "admin");
    assertEquals(written[0].data.enabled, true);
    assertEquals(
      written[1].data.enabled,
      false,
      "Replace+empty perms → disabled",
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_list: permission/role maps become arrays", async () => {
  makeTypedJmap({
    "x:Role": [{
      id: "b",
      description: "User",
      enabledPermissions: { authenticate: true, emailSend: true },
      disabledPermissions: {},
      roleIds: {},
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("role_list").execute({}, context);
    assertEquals(written[0].data.description, "User");
    assertEquals(written[0].data.enabledPermissions, [
      "authenticate",
      "emailSend",
    ]);
    assertEquals(written[0].data.nestedRoleIds, []);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("alias_list: filters to one account by name or full address", async () => {
  makeTypedJmap({
    "x:Domain": [
      { id: "d1", name: "example.com" },
      { id: "d2", name: "example.net" },
    ],
    "x:Account": [
      {
        id: "l",
        name: "alice",
        emailAddress: "alice@example.com",
        aliases: {
          "0": { name: "a", domainId: "d1" },
          "1": { name: "alice.smith", domainId: "d2" },
        },
      },
      {
        id: "m",
        name: "bob",
        emailAddress: "bob@example.com",
        aliases: { "0": { name: "b", domainId: "d1" } },
      },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("alias_list").execute(
      { account: "alice@example.com" },
      context,
    );
    assertEquals(written.length, 2, "only alice's two aliases");
    assertEquals(written.map((w) => w.data.address).sort(), [
      "a@example.com",
      "alice.smith@example.net",
    ], "each alias carries its own domain, not the account's");
    assertEquals(written[0].data.account, "alice");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("resolveAccountId: two credentials on one URL do not share a cached account", async () => {
  // The fake session returns the account the bearer token names, so a shared
  // cache would give the second credential the first one's account.
  const seen: string[] = [];
  const caller: RestFn = (g, c) => {
    seen.push(String(g.apiKey));
    return Promise.resolve({
      status: 200,
      body: c.path === "/.well-known/jmap"
        ? { primaryAccounts: { "urn:stalwart:jmap": `acct-${g.apiKey}` } }
        : {},
    });
  };
  __setRest(caller);
  const { caller: jmapCaller, calls } = makeFakeJmap((c) => {
    const name = (c.methodCalls[0] as unknown[])[0] as string;
    return jmapOk(name, name.endsWith("/query") ? { ids: [] } : { list: [] });
  });
  __setJmap(jmapCaller);
  try {
    for (const apiKey of ["key-one", "key-two"]) {
      const { context } = makeContext({ ...GLOBALS, apiKey });
      await method("jmap_probe").execute(
        { type: "Principal", limit: 1 },
        context,
      );
    }
    assertEquals(
      seen,
      ["key-one", "key-two"],
      "one session fetch per credential",
    );
    const accountIds = calls.map((c) =>
      ((c.methodCalls[0] as unknown[])[1] as Json).accountId
    );
    assertEquals(accountIds, ["acct-key-one", "acct-key-two"]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_ensure: preset creates a role with the preset's permissions", async () => {
  const { setCalls } = makeTypedJmap({ "x:Role": [] });
  try {
    const { context, written } = makeContext();
    await method("role_ensure").execute(
      { preset: "automated-mailbox" },
      context,
    );
    assertEquals(setCalls.length, 1, "one create");
    const created = (setCalls[0].args.create as Json).new as Json;
    assertEquals(created.description, "Automated Mailbox");
    assertEquals(created.enabledPermissions, {
      authenticate: true,
      authenticateWithAlias: true,
      emailSend: true,
    });
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.enabledPermissions, [
      "authenticate",
      "authenticateWithAlias",
      "emailSend",
    ]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_ensure: idempotent — same permissions → unchanged, no set", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Role": [{
      id: "r1",
      description: "Automated Mailbox",
      enabledPermissions: {
        authenticate: true,
        emailSend: true,
        authenticateWithAlias: true,
      },
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("role_ensure").execute(
      { preset: "automated-mailbox" },
      context,
    );
    assertEquals(setCalls.length, 0, "no mutation when unchanged");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_assign: assigns a custom role by name → Custom union", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Account": [{
      id: "a1",
      name: "admin",
      emailAddress: "admin@example.com",
      roles: { "@type": "User" },
    }],
    "x:Role": [{ id: "r1", description: "Automated Mailbox" }],
  });
  try {
    const { context, written } = makeContext();
    await method("role_assign").execute(
      { account: "Admin@Example.com", role: "Automated Mailbox" },
      context,
    );
    // Named by the server's address, whatever case was typed.
    assertEquals(written[0].name, "state-result:role:admin@example.com");
    assertEquals(setCalls.length, 1);
    assertEquals(setCalls[0].type, "x:Account");
    const upd = (setCalls[0].args.update as Json).a1 as Json;
    assertEquals(upd.roles, { "@type": "Custom", roleIds: { r1: true } });
    assertEquals(written[0].data.action, "updated");
    assertEquals(written[0].data.state, "custom:Automated Mailbox");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_assign: idempotent when the account already holds the role", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Account": [{
      id: "a1",
      name: "admin",
      emailAddress: "admin@example.com",
      roles: { "@type": "Custom", roleIds: { r1: true } },
    }],
    "x:Role": [{ id: "r1", description: "Automated Mailbox" }],
  });
  try {
    const { context, written } = makeContext();
    await method("role_assign").execute(
      { account: "admin@example.com", role: "Automated Mailbox" },
      context,
    );
    assertEquals(setCalls.length, 0, "no mutation when already assigned");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_assign: an unknown account or role throws before any write", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Account": [{ id: "a1", name: "alice", emailAddress: "alice@x.test" }],
    "x:Role": [],
  });
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("role_assign").execute(
          { account: "ghost@x", role: "user" },
          context,
        ),
      /Account not found/,
    );
    await rejects(
      () =>
        method("role_assign").execute(
          { account: "alice@x.test", role: "No Such Role" },
          context,
        ),
      /Role not found: No Such Role/,
    );
    assertEquals(setCalls.length, 0);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_get: reads a singleton and strips the id into settings", async () => {
  makeTypedJmap({
    "x:Http": [{ id: "singleton", usePermissiveCors: true, enableHsts: false }],
  });
  try {
    const { context, written } = makeContext();
    await method("settings_get").execute({ kind: "http" }, context);
    assertEquals(written[0].data.kind, "http");
    assertEquals(written[0].data.id, "singleton");
    assertEquals(written[0].data.settings, {
      usePermissiveCors: true,
      enableHsts: false,
    });
    assertEquals(written[0].data.action, "observed");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_set: unchanged writes nothing but still reloads", async () => {
  // A retry after a failed reload finds nothing to change; the reload must
  // still run, or the saved change never goes live.
  const { setCalls } = makeTypedJmap({
    "x:Http": [{ id: "singleton", usePermissiveCors: true }],
  });
  try {
    const { context, written } = makeContext();
    await method("settings_set").execute(
      { kind: "http", patch: { usePermissiveCors: true } },
      context,
    );
    assertEquals(setCalls.map((c) => c.type), ["x:Action"], "only the reload");
    assertEquals(
      ((setCalls[0].args.create as Json).c0 as Json)["@type"],
      "ReloadSettings",
    );
    assertEquals(written[0].data.action, "unchanged");
    const quiet = makeContext();
    await method("settings_set").execute(
      { kind: "http", patch: { usePermissiveCors: true }, reload: false },
      quiet.context,
    );
    assertEquals(setCalls.length, 1, "reload=false: nothing at all");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_set: changes the field, then reloads", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Http": [{ id: "singleton", usePermissiveCors: false }],
  });
  try {
    const { context, written } = makeContext();
    await method("settings_set").execute(
      { kind: "http", patch: { usePermissiveCors: true } },
      context,
    );
    // One x:Http update + one x:Action ReloadSettings.
    assertEquals(setCalls.map((c) => c.type), ["x:Http", "x:Action"]);
    assertEquals((setCalls[0].args.update as Json).singleton, {
      usePermissiveCors: true,
    });
    const action = (setCalls[1].args.create as Json).c0 as Json;
    assertEquals(action["@type"], "ReloadSettings");
    assertEquals(written[0].data.action, "updated");
    assertEquals((written[0].data.settings as Json).usePermissiveCors, true);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("reload: creates a ReloadSettings action and reports reloaded", async () => {
  const { setCalls } = makeTypedJmap({});
  try {
    const { context, written } = makeContext();
    await method("reload").execute({}, context);
    assertEquals(setCalls[0].type, "x:Action");
    assertEquals(
      ((setCalls[0].args.create as Json).c0 as Json)["@type"],
      "ReloadSettings",
    );
    assertEquals(written[0].data.action, "reloaded");
    assertEquals(written[0].data.kind, "server");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: creates with resolved domain, aliases, role, password", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [],
  });
  try {
    const { context, written } = makeContext();
    await method("account_ensure").execute({
      email: "alice@example.com",
      aliases: ["a@example.com"],
      description: "Alice",
      password: "secret",
    }, context);
    assertEquals(setCalls.length, 1);
    const c = (setCalls[0].args.create as Json).new as Json;
    assertEquals(
      c["@type"],
      "User",
      "account union discriminator required on create",
    );
    assertEquals(c.name, "alice");
    assertEquals(c.domainId, "d1");
    assertEquals(c.aliases, {
      "0": { name: "a", domainId: "d1", enabled: true },
    });
    assertEquals(c.roles, { "@type": "User" }, "defaults to user role");
    assertEquals(c.credentials, {
      "0": { "@type": "Password", secret: "secret" },
    });
    assertEquals(written[0].data.action, "created");
    // Secret-once: the written resource must NOT contain the password.
    assert(
      !JSON.stringify(written[0].data).includes("secret"),
      "no password in output",
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: idempotent when aliases/description already match", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [{
      id: "a1",
      name: "alice",
      emailAddress: "alice@example.com",
      domainId: "d1",
      "@type": "User",
      aliases: { "0": { name: "a", domainId: "d1", enabled: true } },
      roles: { "@type": "User" },
      description: "Alice",
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("account_ensure").execute({
      email: "alice@example.com",
      aliases: ["a@example.com"],
      description: "Alice",
    }, context);
    assertEquals(setCalls.length, 0, "no mutation when unchanged");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: omitting aliases leaves existing aliases untouched", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [{
      id: "a1",
      name: "alice",
      emailAddress: "alice@example.com",
      domainId: "d1",
      "@type": "User",
      aliases: { "0": { name: "a", domainId: "d1", enabled: true } },
      roles: { "@type": "User" },
      description: "Old",
    }],
  });
  try {
    const { context } = makeContext();
    // Update only the description; aliases arg omitted entirely.
    await method("account_ensure").execute(
      { email: "alice@example.com", description: "New" },
      context,
    );
    const patch = (setCalls[0].args.update as Json).a1 as Json;
    assertEquals(patch.description, "New");
    assert(
      !("aliases" in patch),
      "aliases must NOT be in the patch when omitted",
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: unknown domain is rejected before any write", async () => {
  const { setCalls } = makeTypedJmap({ "x:Domain": [], "x:Account": [] });
  try {
    const { context } = makeContext();
    await rejects(
      () => method("account_ensure").execute({ email: "x@nope.tld" }, context),
      /Domain not found/,
    );
    assertEquals(setCalls.length, 0);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: memberOf resolves group addresses to memberGroupIds on create", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [
      {
        id: "g1",
        "@type": "Group",
        name: "gmail",
        emailAddress: "gmail@example.com",
        domainId: "d1",
      },
      {
        id: "g2",
        "@type": "Group",
        name: "outlook",
        emailAddress: "outlook@example.com",
        domainId: "d1",
      },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("account_ensure").execute({
      email: "me@example.com",
      memberOf: ["gmail@example.com", "outlook@example.com"],
    }, context);
    const c = (setCalls[0].args.create as Json).new as Json;
    assertEquals(
      c.memberGroupIds,
      { g1: true, g2: true },
      "set-map of group ids",
    );
    // Group ids, as account_list records them.
    assertEquals(written[0].data.memberOf, ["g1", "g2"]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: memberOf idempotent — same membership → no patch", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [
      {
        id: "g1",
        "@type": "Group",
        name: "gmail",
        emailAddress: "gmail@example.com",
        domainId: "d1",
      },
      {
        id: "a1",
        "@type": "User",
        name: "me",
        emailAddress: "me@example.com",
        domainId: "d1",
        roles: { "@type": "User" },
        memberGroupIds: { g1: true },
      },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("account_ensure").execute(
      { email: "me@example.com", memberOf: ["gmail@example.com"] },
      context,
    );
    assertEquals(
      setCalls.length,
      0,
      "no mutation when membership already matches",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: memberOf rejects a non-group / unknown address before any write", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [
      {
        id: "a2",
        "@type": "User",
        name: "bob",
        emailAddress: "bob@example.com",
        domainId: "d1",
      },
    ],
  });
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("account_ensure").execute(
          { email: "me@example.com", memberOf: ["bob@example.com"] },
          context,
        ),
      /Not a group account/,
    );
    await rejects(
      () =>
        method("account_ensure").execute(
          { email: "me@example.com", memberOf: ["ghost@example.com"] },
          context,
        ),
      /Group not found/,
    );
    assertEquals(setCalls.length, 0);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: refuses an address that belongs to a group, writes nothing", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [
      {
        id: "g1",
        "@type": "Group",
        name: "team",
        emailAddress: "team@example.com",
        domainId: "d1",
        description: "Team",
      },
    ],
  });
  try {
    const { context } = makeContext();
    // With and without `role`: both paths must refuse a group address rather
    // than send individual fields to it.
    for (const extra of [{}, { role: "admin" }]) {
      await rejects(
        () =>
          method("account_ensure").execute(
            { email: "team@example.com", description: "Changed", ...extra },
            context,
          ),
        /group account, not an individual/,
      );
    }
    assertEquals(setCalls.length, 0, "the group must not be touched");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("domain_set_state: flips isEnabled, idempotent when already in state", async () => {
  const t = {
    "x:Domain": [{ id: "d1", name: "example.com", isEnabled: true }],
  };
  let r = makeTypedJmap(t);
  try {
    const { context, written } = makeContext();
    await method("domain_set_state").execute({
      domain: "example.com",
      state: "inactive",
    }, context);
    assertEquals((r.setCalls[0].args.update as Json).d1, { isEnabled: false });
    assertEquals(written[0].data.action, "deactivated");
    assertEquals(written[0].name, "state-result:domain:example.com");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
  r = makeTypedJmap(t);
  try {
    const { context, written } = makeContext();
    // Typed in another case, the domain is still found.
    await method("domain_set_state").execute({
      domain: "Example.COM",
      state: "active",
    }, context);
    assertEquals(r.setCalls.length, 0, "already active → no write");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_set_state: disable replaces permissions with an empty set", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Account": [{
      id: "a1",
      name: "x",
      emailAddress: "x@example.com",
      permissions: { "@type": "Inherit" },
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("account_set_state").execute({
      account: "x@example.com",
      state: "inactive",
    }, context);
    assertEquals((setCalls[0].args.update as Json).a1, {
      permissions: {
        "@type": "Replace",
        enabledPermissions: {},
        disabledPermissions: {},
      },
    });
    assertEquals(written[0].data.action, "deactivated");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("group_list: only @type=Group accounts; mailing_list_list maps recipients", async () => {
  makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "X.test" }, { id: "d2", name: "y.test" }],
    "x:Account": [
      {
        id: "g1",
        name: "team",
        emailAddress: "Team@x.test",
        "@type": "Group",
        description: "Team",
      },
      { id: "u1", name: "u", "@type": "User" },
    ],
    "x:MailingList": [
      {
        id: "m1",
        name: "all",
        domainId: "d1",
        description: "Everyone",
        recipients: { "a@x": true, "b@x": true },
      },
      // Same local part on another domain: must not share a name with m1.
      { id: "m2", name: "all", domainId: "d2", emailAddress: "all@y.test" },
    ],
  });
  try {
    const g = makeContext();
    await method("group_list").execute({}, g.context);
    assertEquals(g.written.length, 1);
    assertEquals(g.written[0].data.name, "team");
    assertEquals(g.written[0].name, "group:team@x.test");

    const m = makeContext();
    await method("mailing_list_list").execute({}, m.context);
    assertEquals(m.written[0].data.recipients, ["a@x", "b@x"]);
    // Named by full address, rebuilt from name + domain when the server
    // leaves emailAddress out, and lowercased.
    assertEquals(m.written.map((w) => w.name), [
      "mailing-list:all@x.test",
      "mailing-list:all@y.test",
    ]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("report_query: reads received reports, with domain and period", async () => {
  // Shapes from upstream DmarcExternalReport / TlsExternalReport. The Internal
  // types (reports Stalwart sends) are in the table to prove they are not read.
  makeTypedJmap({
    "x:DmarcExternalReport": [{
      id: "rep1",
      from: "noreply-dmarc-support@google.com",
      report: {
        orgName: "google.com",
        policyDomain: "example.com",
        dateRangeBegin: "2026-10-09T00:00:00Z",
        dateRangeEnd: "2026-10-10T00:00:00Z",
      },
    }],
    "x:TlsExternalReport": [{
      id: "rep2",
      report: {
        dateRangeStart: "2026-10-09T00:00:00Z",
        dateRangeEnd: "2026-10-10T00:00:00Z",
        policies: { "0": { policyDomain: "example.org" } },
      },
    }],
    "x:DmarcInternalReport": [{ id: "out1", domain: "sent.example" }],
    "x:TlsInternalReport": [{ id: "out2", domain: "sent.example" }],
  });
  try {
    const { context, written } = makeContext();
    await method("report_query").execute({ kind: "all" }, context);
    assertEquals(written.map((w) => w.name), [
      "report:dmarc:rep1",
      "report:tls:rep2",
    ]);
    assertEquals(written[0].data.domain, "example.com");
    assertEquals(written[0].data.rangeStart, "2026-10-09T00:00:00Z");
    assertEquals(written[0].data.rangeEnd, "2026-10-10T00:00:00Z");
    assertEquals(written[1].data.domain, "example.org");
    assertEquals(written[1].data.rangeStart, "2026-10-09T00:00:00Z");
    assertEquals(written[1].data.rangeEnd, "2026-10-10T00:00:00Z");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("report_query: dmarc reports carry a summary, no id leak", async () => {
  makeTypedJmap({
    "x:DmarcExternalReport": [{
      id: "rep1",
      report: { policyDomain: "example.com" },
      count: 5,
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("report_query").execute({ kind: "dmarc" }, context);
    assertEquals(written[0].data.kind, "dmarc");
    assertEquals(written[0].data.domain, "example.com");
    assert(String(written[0].data.summary).includes('"count":5'));
    assert(
      !String(written[0].data.summary).includes('"id"'),
      "id stripped from summary",
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("certificate_install: creates when none exist, reloads, hides the key", async () => {
  const { setCalls } = makeTypedJmap({ "x:Certificate": [] });
  try {
    const { context, written } = makeContext();
    await method("certificate_install").execute(
      { certificate: "-----CERT-----", privateKey: "-----KEY-----" },
      context,
    );
    // create x:Certificate, then ReloadTlsCertificates action.
    assertEquals(setCalls[0].type, "x:Certificate");
    const c = (setCalls[0].args.create as Json).new as Json;
    assertEquals(c.certificate, { "@type": "Text", value: "-----CERT-----" });
    assertEquals(c.privateKey, { "@type": "Text", secret: "-----KEY-----" });
    assertEquals(setCalls[1].type, "x:Action");
    assertEquals(
      ((setCalls[1].args.create as Json).c0 as Json)["@type"],
      "ReloadTlsCertificates",
    );
    assertEquals(written[0].data.action, "created");
    assert(
      !JSON.stringify(written[0].data).includes("KEY"),
      "private key never echoed",
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("certificate_install: updates the sole existing cert; refuses when ambiguous", async () => {
  let r = makeTypedJmap({ "x:Certificate": [{ id: "cert1" }] });
  try {
    const { context, written } = makeContext();
    await method("certificate_install").execute(
      { certificate: "C", privateKey: "K", reload: false },
      context,
    );
    assertEquals((r.setCalls[0].args.update as Json).cert1, {
      certificate: { "@type": "Text", value: "C" },
      privateKey: { "@type": "Text", secret: "K" },
    });
    assert(
      !r.setCalls.some((c) => c.type === "x:Action"),
      "reload=false → no action",
    );
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
  r = makeTypedJmap({ "x:Certificate": [{ id: "a" }, { id: "b" }] });
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("certificate_install").execute({
          certificate: "C",
          privateKey: "K",
        }, context),
      /pass certificateId/,
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("mailing_list_ensure: create sets recipients as a set-map {addr:true}", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:MailingList": [],
  });
  try {
    const { context, written } = makeContext();
    await method("mailing_list_ensure").execute({
      address: "team@example.com",
      recipients: ["a@example.com", "b@example.com"],
      description: "Team",
    }, context);
    const c = (setCalls[0].args.create as Json).new as Json;
    assertEquals(c.name, "team");
    assertEquals(c.domainId, "d1");
    assertEquals(c.recipients, {
      "a@example.com": true,
      "b@example.com": true,
    });
    assertEquals(written[0].data.recipients, [
      "a@example.com",
      "b@example.com",
    ]);
    assertEquals(written[0].data.action, "created");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("group_ensure: creates a Group account with Default roles", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [],
  });
  try {
    const { context, written } = makeContext();
    await method("group_ensure").execute(
      { address: "staff@example.com", description: "Staff" },
      context,
    );
    const c = (setCalls[0].args.create as Json).new as Json;
    assertEquals(c["@type"], "Group");
    assertEquals(c.name, "staff");
    assertEquals(c.domainId, "d1");
    assertEquals(c.roles, { "@type": "Default" });
    assertEquals(written[0].data.action, "created");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("no-destroy guarantee: the module never builds a JMAP destroy", async () => {
  // A JMAP /set removes objects only through a `destroy` property, so the
  // guarantee holds if no code in the module, helpers included, writes one.
  const src = await Deno.readTextFile(
    new URL("./stalwart.ts", import.meta.url),
  );
  const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
  assert(
    !/\bdestroy\s*:|["']destroy["']/.test(code),
    "no `destroy` property anywhere in stalwart.ts",
  );
});

// A check receives globalArgs without the schema's defaults, so an unset
// httpTimeoutMs must be defaulted before it reaches fetch (undefined aborts at once).
Deno.test("reachable: applies the schema defaults to globalArgs", async () => {
  let seenTimeout: unknown;
  __setRest((g) => {
    seenTimeout = g.httpTimeoutMs;
    return Promise.resolve({ status: 200, body: {} });
  });
  try {
    const check = (model.checks as unknown as Record<string, {
      execute: (c: unknown) => Promise<{ pass: boolean }>;
    }>).reachable;
    const res = await check.execute({
      globalArgs: { apiUrl: GLOBALS.apiUrl, apiKey: GLOBALS.apiKey },
    });
    assertEquals(res.pass, true);
    assertEquals(seenTimeout, 30000);
  } finally {
    __setRest(null);
  }
});

// ─────────────────────────── strict booleans ───────────────────────────

Deno.test("boolean arguments reject anything but true/false", () => {
  const schema = (model.methods as unknown as Record<string, {
    arguments: {
      safeParse: (v: unknown) => {
        success: boolean;
        error?: { issues: { path: PropertyKey[] }[] };
      };
    };
  }>)["settings_set"].arguments;
  const fieldFails = (v: unknown) => {
    const r = schema.safeParse({ reload: v });
    return (r.error?.issues ?? []).some((i) => i.path[0] === "reload");
  };
  // Strings are rejected here; the swamp CLI turns `--input reload=true` into
  // a real boolean before the method sees it.
  for (const bad of ["true", "false", "0", "1", "False", "yes", null]) {
    assert(fieldFails(bad), `reload=${JSON.stringify(bad)} must be rejected`);
  }
  for (const good of [true, false]) {
    assert(
      !fieldFails(good),
      `reload=${JSON.stringify(good)} must be accepted`,
    );
  }
});

// ─────────────────────────── recorded state ───────────────────────────

Deno.test("mailing_list_ensure: data is named by full address, so domains do not collide", async () => {
  makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:MailingList": [{
      id: "m1",
      name: "team",
      domainId: "d1",
      recipients: { "x@a.test": true },
      description: "kept",
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("mailing_list_ensure").execute(
      { address: "team@a.test" },
      context,
    );
    assertEquals(written[0].specName, "mailing-list");
    assertEquals(written[0].name, "mailing-list:team@a.test");
    // Not passed, so the list kept them; the record says so.
    assertEquals(written[0].data.recipients, ["x@a.test"]);
    assertEquals(written[0].data.description, "kept");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: aliases not passed are recorded as the account keeps them", async () => {
  makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:Account": [{
      id: "u1",
      "@type": "User",
      name: "me",
      emailAddress: "me@a.test",
      domainId: "d1",
      aliases: { "0": { name: "alt", domainId: "d1", enabled: true } },
      roles: { "@type": "User" },
    }],
  });
  try {
    const { context, written } = makeContext();
    // Typed in mixed case: the record is still named by the lowercase address,
    // the same name account_list uses.
    await method("account_ensure").execute({ email: "Me@a.test" }, context);
    assertEquals(written[0].name, "account:me@a.test");
    assertEquals(written[0].data.email, "me@a.test");
    assertEquals(written[0].data.aliases, ["alt@a.test"]);
    assertEquals(written[0].data.roles, "user");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("data names: two specs with the same key get different names", async () => {
  makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "x.test" }],
    "x:Account": [{
      id: "g1",
      name: "team",
      emailAddress: "team@x.test",
      domainId: "d1",
      "@type": "Group",
    }],
  });
  try {
    // account_list and group_list both record the group under its address.
    const acct = makeContext();
    await method("account_list").execute({}, acct.context);
    const grp = makeContext();
    await method("group_list").execute({}, grp.context);
    assertEquals(acct.written[0].name, "account:team@x.test");
    assertEquals(grp.written[0].name, "group:team@x.test");
  } finally {
    __setJmap(null);
    __setRest(null);
  }

  // health_status and session_dump are one-per-model: named by spec alone.
  __setRest(makeFakeRest(() => ({ body: {} })).caller);
  try {
    const h = makeContext();
    await method("health_status").execute({}, h.context);
    const s = makeContext();
    await method("session_dump").execute({}, s.context);
    assertEquals(h.written[0].name, "health");
    assertEquals(s.written[0].name, "session");
  } finally {
    __setRest(null);
  }
});

Deno.test("data names: characters swamp rejects are encoded without collisions", async () => {
  makeTypedJmap({
    "x:Role": [
      { id: "r1", description: "Read/Write..all" },
      // What r1 would become if only `/` were encoded: must stay distinct.
      { id: "r2", description: "Read%2FWrite%2E.all" },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("role_list").execute({}, context);
    assertEquals(written.map((w) => w.name), [
      "role:Read%2FWrite%2E.all",
      "role:Read%252FWrite%252E.all",
    ]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_get: secret values are redacted, wherever they sit", async () => {
  makeTypedJmap({
    "x:Jmap": [{
      id: "singleton",
      maxMethodCalls: 16,
      // SecretTextOptional, as upstream x:Jmap declares webPushKey.
      webPushKey: { "@type": "Text", secret: "push-key-value" },
      // A SecretKey that only names an env var holds no secret: kept.
      other: { "@type": "EnvironmentVariable", variableName: "PUSH_KEY" },
      nested: [{ inner: { "@type": "Value", secret: "nested-value" } }],
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("settings_get").execute({ kind: "jmap" }, context);
    const stored = JSON.stringify(written[0].data);
    assert(!stored.includes("push-key-value"), "top-level secret redacted");
    assert(!stored.includes("nested-value"), "nested secret redacted");
    const settings = written[0].data.settings as Json;
    assertEquals(settings.webPushKey, {
      "@type": "Text",
      secret: "<redacted>",
    });
    assertEquals(settings.other, {
      "@type": "EnvironmentVariable",
      variableName: "PUSH_KEY",
    });
    assertEquals(settings.maxMethodCalls, 16);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_set: a secret in the patch is sent but not recorded", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Jmap": [{
      id: "singleton",
      webPushKey: { "@type": "Text", secret: "old-value" },
    }],
  });
  try {
    const { context, written } = makeContext();
    const patch = { webPushKey: { "@type": "Text", secret: "new-value" } };
    await method("settings_set").execute(
      { kind: "jmap", patch, reload: false },
      context,
    );
    assertEquals((setCalls[0].args.update as Json).singleton, patch);
    const stored = JSON.stringify(written[0].data);
    assert(!stored.includes("new-value"), "patched secret not recorded");
    assert(!stored.includes("old-value"), "old secret not recorded");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("listAll: more accounts than the server allows in one /get", async () => {
  // Stalwart advertises maxObjectsInGet 500 and rejects a bigger /get. This
  // fake pages /query honestly and enforces that limit on /get.
  __setRest(
    makeFakeRest((c) =>
      c.path === "/.well-known/jmap"
        ? { body: { primaryAccounts: { "urn:stalwart:jmap": "l" } } }
        : {}
    ).caller,
  );
  const accounts = Array.from({ length: 1201 }, (_, i) => ({
    id: `a${i}`,
    name: `user${i}`,
    emailAddress: `user${i}@example.com`,
    "@type": "User",
  }));
  __setJmap((_g, c) => {
    const [name, args] = c.methodCalls[0] as [string, Json];
    if (name === "x:Domain/query" || name === "x:Domain/get") {
      return Promise.resolve({
        status: 200,
        body: jmapOk(name, { ids: [], list: [], total: 0 }),
      });
    }
    if (name === "x:Account/query") {
      const position = Number(args.position ?? 0);
      const limit = Number(args.limit ?? accounts.length);
      const ids = accounts.slice(position, position + limit).map((a) => a.id);
      return Promise.resolve({
        status: 200,
        body: jmapOk(name, { ids, total: accounts.length, position }),
      });
    }
    if (name === "x:Account/get") {
      const ids = args.ids as string[];
      if (ids.length > 500) {
        return Promise.resolve({
          status: 200,
          body: {
            methodResponses: [["error", { type: "requestTooLarge" }, "c0"]],
          },
        });
      }
      const want = new Set(ids);
      return Promise.resolve({
        status: 200,
        body: jmapOk(name, { list: accounts.filter((a) => want.has(a.id)) }),
      });
    }
    throw new Error(`unexpected call ${name}`);
  });
  try {
    const { context, written } = makeContext();
    await method("account_list").execute({}, context);
    assertEquals(written.length, 1201);
    assertEquals(new Set(written.map((w) => w.name)).size, 1201);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_assign and account_set_state: an ambiguous local part is refused", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Account": [
      {
        id: "a1",
        name: "alice",
        emailAddress: "alice@a.test",
        roles: { "@type": "User" },
        permissions: { "@type": "Inherit" },
      },
      {
        id: "a2",
        name: "alice",
        emailAddress: "alice@b.test",
        roles: { "@type": "User" },
        permissions: { "@type": "Inherit" },
      },
    ],
  });
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("role_assign").execute(
          { account: "alice", role: "admin" },
          context,
        ),
      /alice matches 2 accounts \(alice@a\.test, alice@b\.test\); pass the full address/,
    );
    await rejects(
      () =>
        method("account_set_state").execute(
          { account: "Alice", state: "inactive" },
          context,
        ),
      /matches 2 accounts/,
    );
    assertEquals(setCalls.length, 0, "nothing written for an ambiguous name");

    // The full address picks one account.
    const ok = makeContext();
    await method("account_set_state").execute(
      { account: "alice@b.test", state: "inactive" },
      ok.context,
    );
    assertEquals(Object.keys(setCalls[0].args.update as Json), ["a2"]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_assign: a local part only one account has still resolves", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Account": [
      { id: "a1", name: "alice", emailAddress: "alice@a.test" },
      { id: "b1", name: "bob", emailAddress: "bob@a.test" },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("role_assign").execute(
      { account: "bob", role: "admin" },
      context,
    );
    assertEquals(Object.keys(setCalls[0].args.update as Json), ["b1"]);
    assertEquals(written[0].name, "state-result:role:bob@a.test");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("queue_list: records sender, recipients, next retry and size", async () => {
  // Shape from upstream x:QueuedMessage: recipients is keyed by address.
  makeTypedJmap({
    "x:QueuedMessage": [{
      id: "q1",
      returnPath: "sender@example.com",
      recipients: {
        "a@remote.test": { "@type": "Scheduled", retryCount: 0 },
        "b@remote.test": { "@type": "TemporaryFailure", retryCount: 2 },
      },
      nextRetry: "2026-10-11T12:00:00Z",
      size: 2048,
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("queue_list").execute({}, context);
    assertEquals(written[0].name, "queue-item:q1");
    assertEquals(written[0].data.from, "sender@example.com");
    assertEquals(written[0].data.to, ["a@remote.test", "b@remote.test"]);
    assertEquals(written[0].data.nextRetry, "2026-10-11T12:00:00Z");
    assertEquals(written[0].data.size, 2048);
    // Stalwart has only per-recipient status, so the record carries none.
    assertEquals("status" in written[0].data, false);
    assertEquals("status" in model.resources["queue-item"].schema.shape, false);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

// ─────────────────────────── transport ───────────────────────────

/**
 * Replace `fetch` for one test. The fake honours the abort signal, as the
 * real fetch does, so the transport's timeout can be tested.
 */
async function withFetch(
  fake: (url: string, init: RequestInit) => Promise<Response>,
  body: () => Promise<void>,
): Promise<void> {
  const real = globalThis.fetch;
  globalThis.fetch =
    ((url: string, init: RequestInit) =>
      fake(String(url), init)) as typeof fetch;
  try {
    await body();
  } finally {
    globalThis.fetch = real;
  }
}

Deno.test("transport: a body that stalls after the headers times out", async () => {
  // Headers arrive at once; the body never finishes until the request is
  // aborted. A timer that stopped at the headers would leave this hanging.
  await withFetch((_url, init) => {
    const stream = new ReadableStream({
      start(ctrl) {
        ctrl.enqueue(new TextEncoder().encode('{"methodRes'));
        init.signal?.addEventListener("abort", () => {
          ctrl.error(new DOMException("aborted", "AbortError"));
        });
      },
    });
    return Promise.resolve(new Response(stream, { status: 200 }));
  }, async () => {
    const { context } = makeContext({
      ...GLOBALS,
      accountId: "l",
      httpTimeoutMs: 20,
    });
    await rejects(
      () => method("jmap_probe").execute({ type: "x:Domain" }, context),
      /abort/i,
    );
  });
});

Deno.test("transport: HTTP errors carry the status for JMAP and REST", async () => {
  await withFetch((url) =>
    Promise.resolve(
      url.endsWith("/jmap")
        ? new Response("unauthorised", { status: 401 })
        : new Response("down", { status: 503 }),
    ), async () => {
    const { context } = makeContext({ ...GLOBALS, accountId: "l" });
    await rejects(
      () => method("domain_list").execute({}, context),
      /Stalwart JMAP HTTP 401: unauthorised/,
    );
    await rejects(
      () => method("health_status").execute({}, context),
      /Stalwart REST GET \/api\/account -> HTTP 503: down/,
    );
  });
});

Deno.test("listAll: throws rather than return a partial list", async () => {
  // A server that never reports a total and never runs out of ids.
  __setRest(makeFakeRest(() => ({ body: {} })).caller);
  __setJmap((_g, c) => {
    const [name, args] = c.methodCalls[0] as [string, Json];
    const body = name.endsWith("/query")
      ? jmapOk(name, { ids: [`d${args.position}`] })
      : jmapOk(name, { list: [{ id: "d", name: "x.test" }] });
    return Promise.resolve({ status: 200, body });
  });
  try {
    const { context, written } = makeContext({ ...GLOBALS, accountId: "l" });
    await rejects(
      () => method("domain_list").execute({}, context),
      /more than 1000 pages; refusing to return a partial list/,
    );
    assertEquals(written.length, 0);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

// ─────────────────────────── arguments ───────────────────────────

Deno.test("parsePrometheus: a sample with a timestamp is kept", () => {
  const m = parsePrometheus(
    'up 1 1728600000000\nqueue_size{q="a"} 3 -5\n',
  );
  assertEquals(m.up, 1);
  assertEquals(m.queue_size, 3);
});

Deno.test("reachable: a zero or negative httpTimeoutMs is rejected", async () => {
  const { caller, calls } = makeFakeRest(() => ({ body: {} }));
  __setRest(caller);
  try {
    const check = (model.checks as unknown as Record<string, {
      execute: (c: unknown) => Promise<{ pass: boolean }>;
    }>).reachable;
    for (const httpTimeoutMs of [0, -1]) {
      const res = await check.execute({
        globalArgs: { apiUrl: GLOBALS.apiUrl, apiKey: "k", httpTimeoutMs },
      });
      assertEquals(res.pass, false, `httpTimeoutMs=${httpTimeoutMs}`);
    }
    assertEquals(calls.length, 0);
  } finally {
    __setRest(null);
  }
});

Deno.test("settings_set: patch is marked sensitive", () => {
  const shape = (model.methods.settings_set.arguments as unknown as {
    shape: Record<string, z.ZodType>;
  }).shape;
  const meta = z.globalRegistry.get(shape.patch) as
    | { sensitive?: boolean }
    | undefined;
  assertEquals(meta?.sensitive, true);
});

// ─────────────────────────── logging ───────────────────────────

/** Every `{prop}` a message names must be among the props it passes. */
function assertPlaceholdersFilled(logs: LogLine[]): void {
  for (const l of logs) {
    for (const [, name] of l.message.matchAll(/\{(\w+)\}/g)) {
      assert(name in l.props, `"${l.message}" has no prop ${name}`);
    }
  }
}

Deno.test("logging: details are in the message, failures are warnings", async () => {
  const { caller } = makeFakeRest((c) => {
    if (c.path === "/api/account") return { body: { edition: "community" } };
    throw new Error("HTTP 403 forbidden");
  });
  __setRest(caller);
  try {
    const { context, logs } = makeContext();
    await method("health_status").execute({}, context);
    const warn = logs.find((l) => l.level === "warn");
    assertEquals(warn?.message, "Prometheus metrics unavailable: {error}");
    assertEquals(warn?.props.error, "HTTP 403 forbidden");
    assertPlaceholdersFilled(logs);
  } finally {
    __setRest(null);
  }

  makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "example.com" }],
    "x:Account": [],
  });
  try {
    const { context, logs } = makeContext();
    await method("account_ensure").execute(
      { email: "Alice@example.com" },
      context,
    );
    assertEquals(
      logs.map((l) => [l.message, l.props.email]),
      [
        ["Ensuring account {email}", "alice@example.com"],
        ["Account {email}: {action}", "alice@example.com"],
      ],
    );
    assertEquals(logs[1].props.action, "created");
    assertPlaceholdersFilled(logs);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("certificate_install: a failed read-back is logged, not swallowed", async () => {
  // The typed fake sets the REST seam; the JMAP seam is replaced below so
  // that only the read-back /get that follows the update fails.
  makeTypedJmap({});
  let sets = 0;
  const { caller } = makeFakeJmap((c) => {
    const [name] = c.methodCalls[0] as [string];
    if (name === "x:Certificate/query") {
      return jmapOk(name, { ids: ["cert1"], total: 1 });
    }
    if (name === "x:Certificate/set") {
      sets++;
      return jmapOk(name, { updated: { cert1: null } });
    }
    if (name === "x:Certificate/get" && sets > 0) {
      return { methodResponses: [["error", { type: "forbidden" }, "c0"]] };
    }
    return jmapOk(name, { list: [{ id: "cert1" }] });
  });
  __setJmap(caller);
  try {
    const { context, written, logs } = makeContext();
    await method("certificate_install").execute(
      { certificate: "C", privateKey: "K", reload: false },
      context,
    );
    assertEquals(written[0].data.action, "updated");
    const warn = logs.find((l) => l.level === "warn");
    assert(warn, "a warning is logged");
    assertEquals(warn?.props.id, "cert1");
    assert(String(warn?.props.error).includes("forbidden"));
    assertPlaceholdersFilled(logs);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("plain http apiUrl: methods warn that the key is sent unencrypted", async () => {
  __setRest(makeFakeRest(() => ({ body: {} })).caller);
  try {
    const plain = makeContext({ ...GLOBALS, apiUrl: "http://mail.example" });
    await method("session_dump").execute({}, plain.context);
    const warn = plain.logs.find((l) => l.level === "warn");
    assertEquals(warn?.props.apiUrl, "http://mail.example");
    assert(String(warn?.message).includes("unencrypted"));

    const tls = makeContext();
    await method("session_dump").execute({}, tls.context);
    assertEquals(tls.logs.filter((l) => l.level === "warn").length, 0);
  } finally {
    __setRest(null);
  }
});

// ─────────────────────────── recorded results ───────────────────────────

Deno.test("report_query: a cut summary is flagged", async () => {
  makeTypedJmap({
    "x:DmarcExternalReport": [
      { id: "big", report: { records: "x".repeat(3000) } },
      { id: "small", report: { policyDomain: "example.com" } },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("report_query").execute({ kind: "dmarc" }, context);
    assertEquals(String(written[0].data.summary).length, 2000);
    assertEquals(written[0].data.summaryTruncated, true);
    assertEquals(written[1].data.summaryTruncated, false);
    // An uncut summary parses.
    JSON.parse(String(written[1].data.summary));
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: records whether the account is enabled", async () => {
  makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:Account": [{
      id: "u1",
      "@type": "User",
      name: "off",
      emailAddress: "off@a.test",
      domainId: "d1",
      roles: { "@type": "User" },
      permissions: {
        "@type": "Replace",
        enabledPermissions: {},
        disabledPermissions: {},
      },
    }],
  });
  try {
    const off = makeContext();
    await method("account_ensure").execute(
      { email: "off@a.test" },
      off.context,
    );
    assertEquals(off.written[0].data.enabled, false);
    const created = makeContext();
    await method("account_ensure").execute(
      { email: "new@a.test" },
      created.context,
    );
    assertEquals(created.written[0].data.enabled, true);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: a repeated alias is sent once and converges", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:Account": [{
      id: "u1",
      "@type": "User",
      name: "me",
      emailAddress: "me@a.test",
      domainId: "d1",
      aliases: { "0": { name: "alt", domainId: "d1", enabled: true } },
      roles: { "@type": "User" },
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("account_ensure").execute(
      { email: "me@a.test", aliases: ["alt@a.test", "alt@a.test"] },
      context,
    );
    assertEquals(setCalls.length, 0, "the server already has this set");
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.aliases, ["alt@a.test"]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: rewriting the aliases keeps their descriptions", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:Account": [{
      id: "u1",
      "@type": "User",
      name: "me",
      emailAddress: "me@a.test",
      domainId: "d1",
      aliases: {
        "0": {
          name: "alt",
          domainId: "d1",
          enabled: true,
          description: "Old address",
        },
      },
      roles: { "@type": "User" },
    }],
  });
  try {
    const { context } = makeContext();
    await method("account_ensure").execute(
      { email: "me@a.test", aliases: ["alt@a.test", "new@a.test"] },
      context,
    );
    assertEquals((setCalls[0].args.update as Json).u1, {
      aliases: {
        "0": {
          name: "alt",
          domainId: "d1",
          enabled: true,
          description: "Old address",
        },
        "1": { name: "new", domainId: "d1", enabled: true },
      },
    });
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: a password for an existing account is not sent, and warns", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:Account": [{
      id: "u1",
      "@type": "User",
      name: "me",
      emailAddress: "me@a.test",
      domainId: "d1",
      roles: { "@type": "User" },
    }],
  });
  try {
    const { context, written, logs } = makeContext();
    await method("account_ensure").execute(
      { email: "me@a.test", password: "hunter2" },
      context,
    );
    assertEquals(setCalls.length, 0);
    assertEquals(written[0].data.action, "unchanged");
    const warn = logs.find((l) => l.level === "warn");
    assert(String(warn?.message).includes("password was not changed"));
    assert(!JSON.stringify(logs).includes("hunter2"), "password not logged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("mailing_list_ensure: repeated recipients converge; a change updates", async () => {
  const table = {
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:MailingList": [{
      id: "m1",
      name: "team",
      domainId: "d1",
      recipients: { "x@a.test": true },
      description: "Team",
    }],
  };
  let r = makeTypedJmap(table);
  try {
    const { context, written } = makeContext();
    await method("mailing_list_ensure").execute(
      { address: "team@a.test", recipients: ["x@a.test", "x@a.test"] },
      context,
    );
    assertEquals(r.setCalls.length, 0);
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.recipients, ["x@a.test"]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
  r = makeTypedJmap(table);
  try {
    const { context, written } = makeContext();
    await method("mailing_list_ensure").execute(
      { address: "team@a.test", recipients: ["y@a.test"], description: "New" },
      context,
    );
    assertEquals((r.setCalls[0].args.update as Json).m1, {
      recipients: { "y@a.test": true },
      description: "New",
    });
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_ensure and group_ensure: a changed role or description updates", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:Role": [{
      id: "r1",
      description: "Automated Mailbox",
      enabledPermissions: { authenticate: true },
    }],
    "x:Account": [{
      id: "g1",
      "@type": "Group",
      name: "staff",
      domainId: "d1",
      description: "Old",
    }],
  });
  try {
    const role = makeContext();
    await method("role_ensure").execute(
      { preset: "automated-mailbox" },
      role.context,
    );
    assertEquals(role.written[0].data.action, "updated");
    assertEquals((setCalls[0].args.update as Json).r1, {
      enabledPermissions: {
        authenticate: true,
        authenticateWithAlias: true,
        emailSend: true,
      },
    });
    const group = makeContext();
    await method("group_ensure").execute(
      { address: "staff@a.test", description: "Staff" },
      group.context,
    );
    assertEquals(group.written[0].data.action, "updated");
    assertEquals((setCalls[1].args.update as Json).g1, {
      description: "Staff",
    });
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_set_state: re-enabling sets permissions to Inherit", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Account": [{
      id: "a1",
      name: "x",
      emailAddress: "x@example.com",
      permissions: {
        "@type": "Replace",
        enabledPermissions: {},
        disabledPermissions: {},
      },
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("account_set_state").execute(
      { account: "x@example.com", state: "active" },
      context,
    );
    assertEquals((setCalls[0].args.update as Json).a1, {
      permissions: { "@type": "Inherit" },
    });
    assertEquals(written[0].data.action, "reactivated");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("create paths: a refused create throws; a create with no id throws", async () => {
  makeTypedJmap(
    { "x:Role": [] },
    () => ({
      notCreated: {
        new: { type: "invalidProperties", description: "bad permission" },
      },
    }),
  );
  try {
    const { context, written } = makeContext();
    await rejects(
      () => method("role_ensure").execute({ preset: "swamp-admin" }, context),
      /Could not create role Swamp Admin: invalidProperties: bad permission/,
    );
    assertEquals(written.length, 0);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
  // Stalwart answering `created` without an id must not produce a record
  // with an empty name.
  makeTypedJmap(
    { "x:Certificate": [] },
    (type) => type === "x:Certificate" ? { created: { new: {} } } : undefined,
  );
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("certificate_install").execute(
          { certificate: "C", privateKey: "K", reload: false },
          context,
        ),
      /created a certificate but returned no id/,
    );
    assertEquals(written.length, 0);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("certificate_install: certificateId updates that certificate without a lookup", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Certificate": [{ id: "a" }, { id: "b" }],
  });
  try {
    const { context, written } = makeContext();
    await method("certificate_install").execute(
      { certificate: "C", privateKey: "K", certificateId: "b", reload: false },
      context,
    );
    assertEquals(Object.keys(setCalls[0].args.update as Json), ["b"]);
    assertEquals(written[0].name, "certificate:b");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_set: a failed reload says the change is saved and to run reload", async () => {
  makeTypedJmap(
    { "x:Http": [{ id: "singleton", usePermissiveCors: false }] },
    (type) =>
      type === "x:Action"
        ? { notCreated: { c0: { type: "forbidden" } } }
        : undefined,
  );
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("settings_set").execute(
          { kind: "http", patch: { usePermissiveCors: true } },
          context,
        ),
      /http settings are saved but the reload failed.*run the `reload` method/,
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_set: records what the server holds after the update", async () => {
  // Stalwart merges a nested object into the stored one, so the record must
  // come from the server, not from the patch laid over the old value.
  const { setCalls } = makeTypedJmap(
    {
      "x:Http": [{
        id: "singleton",
        rateLimit: { requests: 10, period: "1m" },
      }],
    },
    (type, _args, table) => {
      if (type === "x:Http") {
        table["x:Http"][0].rateLimit = { requests: 20, period: "1m" };
      }
      return undefined;
    },
  );
  try {
    const { context, written } = makeContext();
    await method("settings_set").execute(
      { kind: "http", patch: { rateLimit: { requests: 20 } }, reload: false },
      context,
    );
    assert(!setCalls.some((c) => c.type === "x:Action"), "reload=false");
    assertEquals((written[0].data.settings as Json).rateLimit, {
      requests: 20,
      period: "1m",
    });
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

// ─────────────────────────── decisions 2026-10-11 ───────────────────────────

Deno.test("certificate_install: records the issuer and validity period", async () => {
  makeTypedJmap({
    "x:Certificate": [{
      id: "cert1",
      issuer: "Example CA R1",
      subjectAlternativeNames: { "mail.example.com": true },
      notValidBefore: "2026-10-01T00:00:00Z",
      notValidAfter: "2026-12-30T00:00:00Z",
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("certificate_install").execute(
      { certificate: "C", privateKey: "K", reload: false },
      context,
    );
    const d = written[0].data;
    assertEquals(d.issuer, "Example CA R1");
    assertEquals(d.notBefore, "2026-10-01T00:00:00Z");
    assertEquals(d.notAfter, "2026-12-30T00:00:00Z");
    assertEquals(d.sans, ["mail.example.com"]);
    assertEquals("subject" in d, false);
    assertEquals(
      "subject" in model.resources.certificate.schema.shape,
      false,
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: rewriting the aliases keeps a disabled alias disabled", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:Account": [{
      id: "u1",
      "@type": "User",
      name: "me",
      emailAddress: "me@a.test",
      domainId: "d1",
      aliases: { "0": { name: "off", domainId: "d1", enabled: false } },
      roles: { "@type": "User" },
    }],
  });
  try {
    // Listing the disabled alias alone changes nothing.
    const same = makeContext();
    await method("account_ensure").execute(
      { email: "me@a.test", aliases: ["off@a.test"] },
      same.context,
    );
    assertEquals(setCalls.length, 0);
    assertEquals(same.written[0].data.action, "unchanged");
    // Adding another alias rewrites the list; the disabled one stays so.
    const add = makeContext();
    await method("account_ensure").execute(
      { email: "me@a.test", aliases: ["off@a.test", "new@a.test"] },
      add.context,
    );
    assertEquals((setCalls[0].args.update as Json).u1, {
      aliases: {
        "0": { name: "off", domainId: "d1", enabled: false },
        "1": { name: "new", domainId: "d1", enabled: true },
      },
    });
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_ensure: refuses the built-in role names admin and user", async () => {
  const { setCalls } = makeTypedJmap({ "x:Role": [] });
  try {
    const { context, written } = makeContext();
    for (const name of ["admin", "User"]) {
      await rejects(
        () =>
          method("role_ensure").execute(
            { name, permissions: ["authenticate"] },
            context,
          ),
        /is the name of a built-in role/,
      );
    }
    assertEquals(setCalls.length, 0);
    assertEquals(written.length, 0);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("upgrade 2026.10.11.1: drops a non-positive httpTimeoutMs, keeps the rest", () => {
  const up = model.upgrades[0].upgradeAttributes;
  assertEquals(
    up({ apiUrl: "https://m", apiKey: "k", httpTimeoutMs: 0 }),
    { apiUrl: "https://m", apiKey: "k" },
  );
  assertEquals(
    up({ apiUrl: "https://m", httpTimeoutMs: 5000 }),
    { apiUrl: "https://m", httpTimeoutMs: 5000 },
  );
  assertEquals(up({ apiUrl: "https://m" }), { apiUrl: "https://m" });
});

Deno.test("account_ensure: addresses typed in another case match the server's lowercase", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "a.test" }],
    "x:Account": [{
      id: "u1",
      "@type": "User",
      name: "me",
      emailAddress: "me@a.test",
      domainId: "d1",
      aliases: { "0": { name: "off", domainId: "d1", enabled: false } },
      roles: { "@type": "User" },
    }],
  });
  try {
    // Stalwart stores names lowercased, so "OFF@A.Test" is the alias it has.
    const same = makeContext();
    await method("account_ensure").execute(
      { email: "Me@A.Test", aliases: ["OFF@A.Test"] },
      same.context,
    );
    assertEquals(setCalls.length, 0);
    assertEquals(same.written[0].data.action, "unchanged");
    assertEquals(same.written[0].data.name, "me");
    assertEquals(same.written[0].data.aliases, ["off@a.test"]);
    // A rewrite still finds it, so it stays disabled.
    const add = makeContext();
    await method("account_ensure").execute(
      { email: "me@a.test", aliases: ["OFF@a.test", "New@a.test"] },
      add.context,
    );
    assertEquals((setCalls[0].args.update as Json).u1, {
      aliases: {
        "0": { name: "off", domainId: "d1", enabled: false },
        "1": { name: "new", domainId: "d1", enabled: true },
      },
    });
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("certificate_install: a failed reload says the certificate is saved", async () => {
  makeTypedJmap(
    { "x:Certificate": [{ id: "a" }] },
    (type) =>
      type === "x:Action"
        ? { notCreated: { c0: { type: "forbidden" } } }
        : undefined,
  );
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("certificate_install").execute(
          { certificate: "C", privateKey: "K", reload: true },
          context,
        ),
      /Certificate a is saved but the reload failed.*run `reload_certificates`/,
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});
