/**
 * Unit tests for the spike-independent layer of `@thomas/stalwart`: the
 * Prometheus parser, the `reachable` skip-on-unresolved-secret guard, the
 * REST-only `health_status` method, and the no-destroy guarantee (no method
 * source references the JMAP `destroy` verb). No live server — the JMAP/REST
 * callers are faked via the __setJmap / __setRest seams.
 *
 * JMAP-envelope-shape and idempotency tests are added alongside the Phase 1
 * methods once the discovery spike pins the management type names.
 */
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

function makeContext(globals: Record<string, unknown> = GLOBALS) {
  const written: Array<
    { specName: string; name: string; data: Record<string, unknown> }
  > = [];
  const noop = () => {};
  const context = {
    globalArgs: globals,
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
 * objects' ids (+ total); `<type>/get` returns the objects as `list`. Also wires
 * the REST seam so resolveAccountId() finds accountId `l`.
 */
function makeTypedJmap(table: Record<string, Json[]>) {
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
        body: jmapOk(name, { ids: objs.map((o) => String(o.id)), total: objs.length, position: 0 }),
      });
    }
    if (name.endsWith("/get")) {
      const want = new Set((args.ids as string[] | undefined) ?? objs.map((o) => String(o.id)));
      return Promise.resolve({
        status: 200,
        body: jmapOk(name, { list: objs.filter((o) => want.has(String(o.id))) }),
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
        out.updated = Object.fromEntries(Object.keys(update).map((k) => [k, null]));
      }
      return Promise.resolve({ status: 200, body: jmapOk(name, out) });
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

Deno.test("reachable: skips when apiKey is an unresolved vault expression", async () => {
  // No caller set — if it tried to hit the network it would use realRest.
  __setRest(null);
  const check = (model.checks as unknown as Record<string, {
    execute: (c: unknown) => Promise<{ pass: boolean }>;
  }>).reachable;
  const res = await check.execute({
    globalArgs: {
      ...GLOBALS,
      apiKey: "${{ vault.get(op-homelab, stalwart/api_key) }}",
    },
  });
  assertEquals(res.pass, true, "unresolved secret → skip (pass)");
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
    const res = await check.execute({ globalArgs: GLOBALS });
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
          version: "0.16.7",
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
    assertEquals(d.version, "0.16.7");
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
  // REST seam answers the session discovery for resolveAccountId.
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
      { id: "c", name: "smol.cloud", isEnabled: true },
      { id: "b", name: "clouddesign.co.nz", isEnabled: false },
    ],
  });
  try {
    const { context, written } = makeContext();
    const out = await method("domain_list").execute({}, context);
    assertEquals(out.dataHandles.length, 2);
    assertEquals(written[0].data, {
      id: "c",
      name: "smol.cloud",
      state: "active",
      action: "observed",
      timestamp: written[0].data.timestamp,
    });
    assertEquals(written[1].data.state, "inactive", "isEnabled:false → inactive");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_list: extracts aliases, type, and disabled detection", async () => {
  makeTypedJmap({
    "x:Account": [
      {
        id: "l",
        name: "swamp-admin",
        emailAddress: "swamp-admin@smol.cloud",
        domainId: "c",
        "@type": "User",
        aliases: { "0": { name: "ops@smol.cloud", domainId: "c", enabled: true } },
        roles: { "@type": "Admin" },
        permissions: { "@type": "Inherit" },
      },
      {
        id: "m",
        name: "blocked",
        "@type": "User",
        aliases: {},
        roles: { "@type": "User" },
        permissions: { "@type": "Replace", enabledPermissions: {}, disabledPermissions: {} },
      },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("account_list").execute({}, context);
    assertEquals(written[0].data.name, "swamp-admin");
    assertEquals(written[0].data.email, "swamp-admin@smol.cloud");
    assertEquals(written[0].data.type, "individual", "@type User → individual");
    assertEquals(written[0].data.aliases, ["ops@smol.cloud"]);
    assertEquals(written[0].data.roles, "admin");
    assertEquals(written[0].data.enabled, true);
    assertEquals(written[1].data.enabled, false, "Replace+empty perms → disabled");
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
    assertEquals(written[0].data.enabledPermissions, ["authenticate", "emailSend"]);
    assertEquals(written[0].data.nestedRoleIds, []);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("alias_list: filters to one account by name or full address", async () => {
  makeTypedJmap({
    "x:Account": [
      {
        id: "l",
        name: "alice",
        emailAddress: "alice@smol.cloud",
        aliases: {
          "0": { name: "a@smol.cloud" },
          "1": { name: "alice.smith@smol.cloud" },
        },
      },
      {
        id: "m",
        name: "bob",
        emailAddress: "bob@smol.cloud",
        aliases: { "0": { name: "b@smol.cloud" } },
      },
    ],
  });
  try {
    const { context, written } = makeContext();
    await method("alias_list").execute({ account: "alice@smol.cloud" }, context);
    assertEquals(written.length, 2, "only alice's two aliases");
    assertEquals(written.map((w) => w.data.address).sort(), [
      "a@smol.cloud",
      "alice.smith@smol.cloud",
    ]);
    assertEquals(written[0].data.account, "alice");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_ensure: preset creates a role with the signed-off permissions", async () => {
  const { setCalls } = makeTypedJmap({ "x:Role": [] });
  try {
    const { context, written } = makeContext();
    await method("role_ensure").execute({ preset: "automated-mailbox" }, context);
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
    await method("role_ensure").execute({ preset: "automated-mailbox" }, context);
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
      emailAddress: "admin@smol.cloud",
      roles: { "@type": "User" },
    }],
    "x:Role": [{ id: "r1", description: "Automated Mailbox" }],
  });
  try {
    const { context, written } = makeContext();
    await method("role_assign").execute(
      { account: "admin@smol.cloud", role: "Automated Mailbox" },
      context,
    );
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
      emailAddress: "admin@smol.cloud",
      roles: { "@type": "Custom", roleIds: { r1: true } },
    }],
    "x:Role": [{ id: "r1", description: "Automated Mailbox" }],
  });
  try {
    const { context, written } = makeContext();
    await method("role_assign").execute(
      { account: "admin@smol.cloud", role: "Automated Mailbox" },
      context,
    );
    assertEquals(setCalls.length, 0, "no mutation when already assigned");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("role_assign: verify-before-mutate — unknown account/role throw", async () => {
  makeTypedJmap({ "x:Account": [], "x:Role": [] });
  try {
    const { context } = makeContext();
    await rejects(
      () => method("role_assign").execute({ account: "ghost@x", role: "user" }, context),
      /Account not found/,
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_get: reads a singleton and strips the id into settings", async () => {
  makeTypedJmap({ "x:Http": [{ id: "singleton", usePermissiveCors: true, enableHsts: false }] });
  try {
    const { context, written } = makeContext();
    await method("settings_get").execute({ kind: "http" }, context);
    assertEquals(written[0].data.kind, "http");
    assertEquals(written[0].data.id, "singleton");
    assertEquals(written[0].data.settings, { usePermissiveCors: true, enableHsts: false });
    assertEquals(written[0].data.action, "observed");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("settings_set: idempotent when the field already matches", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Http": [{ id: "singleton", usePermissiveCors: true }],
  });
  try {
    const { context, written } = makeContext();
    await method("settings_set").execute(
      { kind: "http", patch: { usePermissiveCors: true } },
      context,
    );
    assertEquals(setCalls.length, 0, "no write when unchanged");
    assertEquals(written[0].data.action, "unchanged");
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
    assertEquals((setCalls[0].args.update as Json).singleton, { usePermissiveCors: true });
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
    assertEquals(((setCalls[0].args.create as Json).c0 as Json)["@type"], "ReloadSettings");
    assertEquals(written[0].data.action, "reloaded");
    assertEquals(written[0].data.kind, "server");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: creates with resolved domain, aliases, role, password", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "smol.cloud" }],
    "x:Account": [],
  });
  try {
    const { context, written } = makeContext();
    await method("account_ensure").execute({
      email: "alice@smol.cloud",
      aliases: ["a@smol.cloud"],
      description: "Alice",
      password: "secret",
    }, context);
    assertEquals(setCalls.length, 1);
    const c = (setCalls[0].args.create as Json).new as Json;
    assertEquals(c["@type"], "User", "account union discriminator required on create");
    assertEquals(c.name, "alice");
    assertEquals(c.domainId, "d1");
    assertEquals(c.aliases, { "0": { name: "a", domainId: "d1", enabled: true } });
    assertEquals(c.roles, { "@type": "User" }, "defaults to user role");
    assertEquals(c.credentials, { "0": { "@type": "Password", secret: "secret" } });
    assertEquals(written[0].data.action, "created");
    // Secret-once: the written resource must NOT echo the password.
    assert(!JSON.stringify(written[0].data).includes("secret"), "no password in output");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_ensure: idempotent when aliases/description already match", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "smol.cloud" }],
    "x:Account": [{
      id: "a1",
      name: "alice",
      emailAddress: "alice@smol.cloud",
      domainId: "d1",
      aliases: { "0": { name: "a", domainId: "d1", enabled: true } },
      roles: { "@type": "User" },
      description: "Alice",
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("account_ensure").execute({
      email: "alice@smol.cloud",
      aliases: ["a@smol.cloud"],
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
    "x:Domain": [{ id: "d1", name: "smol.cloud" }],
    "x:Account": [{
      id: "a1",
      name: "alice",
      emailAddress: "alice@smol.cloud",
      domainId: "d1",
      aliases: { "0": { name: "a", domainId: "d1", enabled: true } },
      roles: { "@type": "User" },
      description: "Old",
    }],
  });
  try {
    const { context } = makeContext();
    // Update only the description; aliases arg omitted entirely.
    await method("account_ensure").execute(
      { email: "alice@smol.cloud", description: "New" },
      context,
    );
    const patch = (setCalls[0].args.update as Json).a1 as Json;
    assertEquals(patch.description, "New");
    assert(!("aliases" in patch), "aliases must NOT be in the patch when omitted");
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

Deno.test("domain_set_state: flips isEnabled, idempotent when already in state", async () => {
  const t = { "x:Domain": [{ id: "d1", name: "smol.cloud", isEnabled: true }] };
  let r = makeTypedJmap(t);
  try {
    const { context, written } = makeContext();
    await method("domain_set_state").execute({ domain: "smol.cloud", state: "inactive" }, context);
    assertEquals((r.setCalls[0].args.update as Json).d1, { isEnabled: false });
    assertEquals(written[0].data.action, "deactivated");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
  r = makeTypedJmap(t);
  try {
    const { context, written } = makeContext();
    await method("domain_set_state").execute({ domain: "smol.cloud", state: "active" }, context);
    assertEquals(r.setCalls.length, 0, "already active → no write");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("account_set_state: disable replaces permissions with empty (reversible)", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Account": [{
      id: "a1",
      name: "x",
      emailAddress: "x@smol.cloud",
      permissions: { "@type": "Inherit" },
    }],
  });
  try {
    const { context, written } = makeContext();
    await method("account_set_state").execute({ account: "x@smol.cloud", state: "inactive" }, context);
    assertEquals((setCalls[0].args.update as Json).a1, {
      permissions: { "@type": "Replace", enabledPermissions: {}, disabledPermissions: {} },
    });
    assertEquals(written[0].data.action, "deactivated");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("group_list: only @type=Group accounts; mailing_list_list maps recipients", async () => {
  makeTypedJmap({
    "x:Account": [
      { id: "g1", name: "team", "@type": "Group", description: "Team" },
      { id: "u1", name: "u", "@type": "User" },
    ],
    "x:MailingList": [{
      id: "m1",
      name: "all",
      description: "Everyone",
      recipients: { "a@x": true, "b@x": true },
    }],
  });
  try {
    const g = makeContext();
    await method("group_list").execute({}, g.context);
    assertEquals(g.written.length, 1);
    assertEquals(g.written[0].data.name, "team");

    const m = makeContext();
    await method("mailing_list_list").execute({}, m.context);
    assertEquals(m.written[0].data.recipients, ["a@x", "b@x"]);
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("report_query: dmarc reports carry a summary, no id leak", async () => {
  makeTypedJmap({
    "x:DmarcInternalReport": [{ id: "rep1", domain: "smol.cloud", count: 5 }],
  });
  try {
    const { context, written } = makeContext();
    await method("report_query").execute({ kind: "dmarc" }, context);
    assertEquals(written[0].data.kind, "dmarc");
    assertEquals(written[0].data.domain, "smol.cloud");
    assert(String(written[0].data.summary).includes('"count":5'));
    assert(!String(written[0].data.summary).includes('"id"'), "id stripped from summary");
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
    assertEquals(((setCalls[1].args.create as Json).c0 as Json)["@type"], "ReloadTlsCertificates");
    assertEquals(written[0].data.action, "created");
    assert(!JSON.stringify(written[0].data).includes("KEY"), "private key never echoed");
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
    assert(!r.setCalls.some((c) => c.type === "x:Action"), "reload=false → no action");
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
  r = makeTypedJmap({ "x:Certificate": [{ id: "a" }, { id: "b" }] });
  try {
    const { context } = makeContext();
    await rejects(
      () => method("certificate_install").execute({ certificate: "C", privateKey: "K" }, context),
      /pass certificateId/,
    );
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("mailing_list_ensure: create sets recipients as a set-map {addr:true}", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "smol.cloud" }],
    "x:MailingList": [],
  });
  try {
    const { context, written } = makeContext();
    await method("mailing_list_ensure").execute({
      address: "team@smol.cloud",
      recipients: ["a@smol.cloud", "b@smol.cloud"],
      description: "Team",
    }, context);
    const c = (setCalls[0].args.create as Json).new as Json;
    assertEquals(c.name, "team");
    assertEquals(c.domainId, "d1");
    assertEquals(c.recipients, { "a@smol.cloud": true, "b@smol.cloud": true });
    assertEquals(written[0].data.recipients, ["a@smol.cloud", "b@smol.cloud"]);
    assertEquals(written[0].data.action, "created");
  } finally {
    __setJmap(null);
    __setRest(null);
  }
});

Deno.test("group_ensure: creates a Group account with Default roles", async () => {
  const { setCalls } = makeTypedJmap({
    "x:Domain": [{ id: "d1", name: "smol.cloud" }],
    "x:Account": [],
  });
  try {
    const { context, written } = makeContext();
    await method("group_ensure").execute(
      { address: "staff@smol.cloud", description: "Staff" },
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

Deno.test("no-destroy guarantee: no method execute body references the destroy verb", async () => {
  // The transport's jmapSet plumbs `destroy` for completeness, but NO method may
  // pass it. Scan each method's source for a `destroy` reference.
  const methods = model.methods as unknown as Record<
    string,
    { execute: (...a: unknown[]) => unknown }
  >;
  for (const [name, def] of Object.entries(methods)) {
    const src = def.execute.toString();
    assert(
      !/\bdestroy\b/.test(src),
      `method ${name} must not reference destroy`,
    );
  }
  // Keep the JMAP seam import live so an unused-import doesn't mask a regression.
  __setJmap(null);
});
