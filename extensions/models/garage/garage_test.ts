/**
 * Unit tests for the parts of `@thomas/garage` where an unnoticed bug would be
 * costly: idempotent create, delete gating (verify-first), the key_rotate
 * copy-grants composite, the permissions_audit matrix + flags, request-body
 * shaping for allow/deny/alias/update, and keeping secrets out of logs. No live
 * cluster; the Admin API transport is faked via the __setGarageApi seam.
 */
import { __setGarageApi, type ApiFn, type Json, model } from "./garage.ts";

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
  endpoint: "http://garage-host:3903",
  adminToken: "admin-token",
  s3Region: "garage",
  timeoutMs: 30000,
};

type Call = { method: string; op: string; query: Json; body: unknown };

/** A fake Admin API transport. `respond(op, body, query)` returns the canned JSON. */
function makeFakeApi(
  respond?: (op: string, body: unknown, query: Json) => unknown,
) {
  const calls: Call[] = [];
  // Mirror the real transport: a thrown error becomes a REJECTED promise (so
  // `.catch()` in the model works), never a synchronous throw.
  const fn: ApiFn = (_g, method, op, query, body) => {
    calls.push({ method, op, query, body });
    try {
      return Promise.resolve(respond?.(op, body, query));
    } catch (e) {
      return Promise.reject(e);
    }
  };
  return { fn, calls, ops: () => calls.map((c) => c.op) };
}

function makeContext() {
  const written: Array<
    { specName: string; name: string; data: Record<string, unknown> }
  > = [];
  const logs: Array<{ msg: string; props?: unknown }> = [];
  const noop = () => {};
  const context = {
    globalArgs: GLOBALS,
    logger: {
      info: (msg: string, props?: unknown) => logs.push({ msg, props }),
      debug: noop,
      warning: noop,
      error: noop,
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

const call = (calls: Call[], op: string): Call | undefined =>
  calls.find((c) => c.op === op);

// ─────────────────────────── cluster_health ───────────────────────────

Deno.test("cluster_health: GETs GetClusterHealth and shapes the snapshot", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetClusterHealth"
      ? {
        status: "healthy",
        knownNodes: 1,
        connectedNodes: 1,
        storageNodes: 1,
        storageNodesUp: 1,
        partitions: 256,
        partitionsQuorum: 256,
        partitionsAllOk: 256,
      }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("cluster_health").execute({}, context);
    assertEquals(call(fake.calls, "GetClusterHealth")?.method, "GET");
    assertEquals(written[0].data.status, "healthy");
    assertEquals(written[0].data.partitions, 256);
    assertEquals(written[0].data.s3Region, "garage");
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── bucket_create ───────────────────────────

Deno.test("bucket_create: idempotent — existing globalAlias returns unchanged, no CreateBucket", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetBucketInfo"
      ? { id: "abc123", globalAliases: ["media"] }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("bucket_create").execute({ globalAlias: "media" }, context);
    assert(
      !call(fake.calls, "CreateBucket"),
      "must not create when alias exists",
    );
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.id, "abc123");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_create: new globalAlias issues CreateBucket with the alias body", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetBucketInfo") {
      throw new Error("Garage GetBucketInfo failed (HTTP 404): no such bucket");
    }
    if (op === "CreateBucket") return { id: "newid", globalAliases: ["logs"] };
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("bucket_create").execute({ globalAlias: "logs" }, context);
    assertEquals(call(fake.calls, "CreateBucket")?.body, {
      globalAlias: "logs",
    });
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.id, "newid");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_create: localAlias requires localAliasAccessKeyId", async () => {
  const { context } = makeContext();
  await rejects(
    () => method("bucket_create").execute({ localAlias: "x" }, context),
    /localAliasAccessKeyId/,
  );
});

// ─────────────────────────── bucket_update ───────────────────────────

// A bucket with a quota and a website already configured, as GetBucketInfo
// reports it. The update tests check that whatever is not passed survives.
const BUCKET_B1 = {
  id: "b1",
  globalAliases: ["site"],
  quotas: { maxObjects: 100, maxSize: 5000 },
  websiteAccess: true,
  websiteConfig: { indexDocument: "index.html", errorDocument: "404.html" },
};

Deno.test("bucket_update: builds quotas + websiteAccess body, query carries id", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetBucketInfo"
      ? { id: "b1", globalAliases: [], quotas: {}, websiteAccess: false }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("bucket_update").execute(
      {
        id: "b1",
        maxObjects: 100,
        maxSize: 5000,
        websiteEnabled: true,
        indexDocument: "index.html",
      },
      context,
    );
    assertEquals(
      fake.ops(),
      ["GetBucketInfo", "UpdateBucket"],
      "reads current state first",
    );
    const c = call(fake.calls, "UpdateBucket")!;
    assertEquals(c.query, { id: "b1" });
    assertEquals(c.body, {
      quotas: { maxObjects: 100, maxSize: 5000 },
      websiteAccess: {
        enabled: true,
        indexDocument: "index.html",
        errorDocument: null,
      },
    });
  } finally {
    __setGarageApi(null);
  }
});

// Garage replaces the whole quotas object, so a one-quota change used to clear
// the other quota; the website object must not be sent at all.
Deno.test("bucket_update: changing one quota keeps the other and leaves the website alone", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetBucketInfo" ? BUCKET_B1 : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("bucket_update").execute({ id: "b1", maxSize: 9000 }, context);
    assertEquals(call(fake.calls, "UpdateBucket")?.body, {
      quotas: { maxObjects: 100, maxSize: 9000 },
    });
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_update: changing the index document keeps the error document and quotas", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetBucketInfo" ? BUCKET_B1 : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("bucket_update").execute({
      id: "b1",
      indexDocument: "home.html",
    }, context);
    assertEquals(call(fake.calls, "UpdateBucket")?.body, {
      websiteAccess: {
        enabled: true,
        indexDocument: "home.html",
        errorDocument: "404.html",
      },
    });
  } finally {
    __setGarageApi(null);
  }
});

// Garage rejects indexDocument/errorDocument alongside enabled:false.
Deno.test("bucket_update: disabling the website sends no documents", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetBucketInfo" ? BUCKET_B1 : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("bucket_update").execute(
      { id: "b1", websiteEnabled: false },
      context,
    );
    assertEquals(call(fake.calls, "UpdateBucket")?.body, {
      websiteAccess: { enabled: false },
    });
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_update: nothing to update throws", async () => {
  const fake = makeFakeApi(() => undefined);
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("bucket_update").execute({ id: "b1" }, context),
      /nothing to update/,
    );
    assert(fake.calls.length === 0, "must not call the API");
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── bucket_delete (gated) ───────────────────────────

Deno.test("bucket_delete: not found throws, no DeleteBucket", async () => {
  const fake = makeFakeApi((op) => (op === "GetBucketInfo" ? {} : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("bucket_delete").execute({ id: "ghost" }, context),
      /not found/,
    );
    assert(!call(fake.calls, "DeleteBucket"));
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_delete: non-empty refused unless allowNonEmpty", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetBucketInfo"
      ? { id: "b1", objects: 7, globalAliases: ["data"] }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("bucket_delete").execute({ id: "b1" }, context),
      /non-empty/,
    );
    assert(
      !call(fake.calls, "DeleteBucket"),
      "must not delete a non-empty bucket",
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_delete: empty bucket is deleted, action=deleted", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetBucketInfo"
      ? { id: "b1", objects: 0, globalAliases: ["data"] }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("bucket_delete").execute({ id: "b1" }, context);
    assertEquals(call(fake.calls, "DeleteBucket")?.query, { id: "b1" });
    assertEquals(written[0].data.action, "deleted");
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── alias add/remove ───────────────────────────

Deno.test("bucket_alias_add: global vs local body shapes", async () => {
  const fake = makeFakeApi(() => undefined);
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("bucket_alias_add").execute({
      bucketId: "b1",
      globalAlias: "g",
    }, context);
    assertEquals(call(fake.calls, "AddBucketAlias")?.body, {
      bucketId: "b1",
      globalAlias: "g",
    });

    const fake2 = makeFakeApi(() => undefined);
    __setGarageApi(fake2.fn);
    await method("bucket_alias_add").execute(
      { bucketId: "b1", localAlias: "l", accessKeyId: "GK1" },
      context,
    );
    assertEquals(call(fake2.calls, "AddBucketAlias")?.body, {
      bucketId: "b1",
      localAlias: "l",
      accessKeyId: "GK1",
    });
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_alias_add: local alias without accessKeyId is rejected", async () => {
  const { context } = makeContext();
  await rejects(
    () =>
      method("bucket_alias_add").execute(
        { bucketId: "b1", localAlias: "l" },
        context,
      ),
    /accessKeyId/,
  );
});

// ─────────────────────────── key_create (secret handling) ───────────────────────────

Deno.test("key_create: surfaces the one-time secret and never logs it", async () => {
  const fake = makeFakeApi((op) =>
    op === "CreateKey"
      ? { accessKeyId: "GK123", name: "ci", secretAccessKey: "s3cr3t" }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, written, logs } = makeContext();
    await method("key_create").execute(
      { name: "ci", allowCreateBucket: true },
      context,
    );
    assertEquals(call(fake.calls, "CreateKey")?.body, {
      name: "ci",
      allow: { createBucket: true },
      neverExpires: true,
    });
    assertEquals(written[0].data.secretAccessKey, "s3cr3t");
    assertEquals(written[0].data.action, "created");
    assert(
      !logs.some((l) => JSON.stringify(l).includes("s3cr3t")),
      "secret must never be logged",
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_create: with expiration sends expiration, not neverExpires", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "CreateKey" ? { accessKeyId: "GK1" } : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("key_create").execute(
      { name: "tmp", expiration: "2027-01-01T00:00:00Z" },
      context,
    );
    const body = call(fake.calls, "CreateKey")?.body as Record<string, unknown>;
    assertEquals(body.expiration, "2027-01-01T00:00:00Z");
    assert(
      !("neverExpires" in body),
      "neverExpires must be omitted when expiration is set",
    );
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── key_rotate (composite) ───────────────────────────

Deno.test("key_rotate: creates new key, copies grants, returns secret, does NOT delete old", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetKeyInfo") {
      return {
        accessKeyId: "OLD",
        name: "app",
        permissions: { createBucket: true },
        buckets: [
          { id: "b1", permissions: { read: true, write: true, owner: false } },
          { id: "b2", permissions: { read: true, write: false, owner: false } },
        ],
      };
    }
    if (op === "CreateKey") {
      return {
        accessKeyId: "NEW",
        name: "app (rotated)",
        secretAccessKey: "newsecret",
      };
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("key_rotate").execute({ id: "OLD" }, context);

    // new key created mirroring create-bucket permission
    const ck = call(fake.calls, "CreateKey")?.body as Record<string, unknown>;
    assertEquals(ck.allow, { createBucket: true });

    // one AllowBucketKey per old bucket, onto the NEW key
    const allows = fake.calls.filter((c) => c.op === "AllowBucketKey");
    assertEquals(allows.length, 2, "must copy both grants");
    assertEquals(
      (allows[0].body as Record<string, unknown>).accessKeyId,
      "NEW",
    );
    assertEquals((allows[0].body as Record<string, unknown>).permissions, {
      read: true,
      write: true,
      owner: false,
    });

    // secret surfaced, action=rotated, OLD key NOT deleted
    assertEquals(written[0].data.accessKeyId, "NEW");
    assertEquals(written[0].data.secretAccessKey, "newsecret");
    assertEquals(written[0].data.action, "rotated");
    assert(
      !call(fake.calls, "DeleteKey"),
      "rotate must not delete the old key",
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_rotate: missing old key throws before creating anything", async () => {
  const fake = makeFakeApi((op) => (op === "GetKeyInfo" ? {} : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("key_rotate").execute({ id: "nope" }, context),
      /not found/,
    );
    assert(
      !call(fake.calls, "CreateKey"),
      "must not create a key when the old one is missing",
    );
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── key_delete (gated) ───────────────────────────

Deno.test("key_delete: not found throws, no DeleteKey", async () => {
  const fake = makeFakeApi((op) => (op === "GetKeyInfo" ? {} : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("key_delete").execute({ id: "ghost" }, context),
      /not found/,
    );
    assert(!call(fake.calls, "DeleteKey"));
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── key_allow / key_deny ───────────────────────────

Deno.test("key_allow: sends permissions body and records granted", async () => {
  const fake = makeFakeApi(() => undefined);
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("key_allow").execute(
      { bucketId: "b1", accessKeyId: "GK1", read: true, write: true },
      context,
    );
    assertEquals(call(fake.calls, "AllowBucketKey")?.body, {
      bucketId: "b1",
      accessKeyId: "GK1",
      permissions: { read: true, write: true, owner: false },
    });
    assertEquals(written[0].data.action, "granted");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_allow: no permission set is rejected", async () => {
  const { context } = makeContext();
  await rejects(
    () =>
      method("key_allow").execute(
        { bucketId: "b1", accessKeyId: "GK1" },
        context,
      ),
    /at least one/,
  );
});

Deno.test("key_deny: records denied", async () => {
  const fake = makeFakeApi(() => undefined);
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("key_deny").execute({
      bucketId: "b1",
      accessKeyId: "GK1",
      owner: true,
    }, context);
    assertEquals(call(fake.calls, "DenyBucketKey")?.body, {
      bucketId: "b1",
      accessKeyId: "GK1",
      permissions: { read: false, write: false, owner: true },
    });
    assertEquals(written[0].data.action, "denied");
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── permissions_audit ───────────────────────────

Deno.test("permissions_audit: builds matrix and risk flags", async () => {
  const buckets = [{ id: "b1" }, { id: "b2" }];
  const bucketInfo: Record<string, unknown> = {
    b1: {
      id: "b1",
      globalAliases: ["media"],
      websiteAccess: true,
      keys: [
        {
          accessKeyId: "K1",
          name: "app",
          permissions: { read: true, write: true, owner: true },
        },
        {
          accessKeyId: "K2",
          name: "ro",
          permissions: { read: true, write: false, owner: false },
        },
      ],
    },
    b2: {
      id: "b2",
      globalAliases: ["logs"],
      websiteAccess: false,
      keys: [
        {
          accessKeyId: "K1",
          name: "app",
          permissions: { read: true, write: true, owner: true },
        },
      ],
    },
  };
  const keys = [
    { id: "K1", name: "app", expired: false },
    { id: "K2", name: "ro", expired: false },
    { id: "K3", name: "unused", expired: true },
  ];
  const fake = makeFakeApi((op, _body, query) => {
    if (op === "ListBuckets") return buckets;
    if (op === "ListKeys") return keys;
    if (op === "GetBucketInfo") return bucketInfo[String(query.id)];
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("permissions_audit").execute({}, context);
    const d = written[0].data as Record<string, unknown>;
    assertEquals(d.bucketCount, 2);
    assertEquals(d.keyCount, 3);
    assertEquals(d.grantCount, 3); // K1 on b1+b2, K2 on b1
    const flags = d.flags as Record<string, unknown>;
    assertEquals(flags.orphanKeys, ["K3"]); // K3 has no grant
    assertEquals(flags.ownerEverywhere, ["K1"]); // owner on both buckets it touches
    assertEquals(flags.websiteBuckets, ["media"]); // b1 only
    assertEquals(flags.expiredKeys, ["K3"]);
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── reachable check ───────────────────────────

Deno.test("reachable check: a definition that fails the schema fails without probing", async () => {
  const fake = makeFakeApi(() => {
    throw new Error("should not be called");
  });
  __setGarageApi(fake.fn);
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: { endpoint: GLOBALS.endpoint },
    });
    assertEquals(res.pass, false);
    assert(
      fake.calls.length === 0,
      "must not probe with an invalid definition",
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("reachable check: fails with errors when the probe throws", async () => {
  const fake = makeFakeApi(() => {
    throw new Error("connection refused");
  });
  __setGarageApi(fake.fn);
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        {
          execute: (
            c: unknown,
          ) => Promise<{ pass: boolean; errors?: string[] }>;
        }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: {
        endpoint: GLOBALS.endpoint,
        adminToken: GLOBALS.adminToken,
      },
    });
    assertEquals(res.pass, false);
    assert(
      (res.errors ?? []).some((e) => /connection refused/.test(e)),
      "should surface the cause",
    );
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── cluster_status / layout_get ───────────────────────────

// GetNodeInfo?node=self as Garage answers it: a per-node map keyed by node id.
const SELF_N1 = {
  success: { n1: { nodeId: "n1", garageVersion: "v2.3.0" } },
  error: {},
};

Deno.test("cluster_status: shapes node id, version, and per-node role", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetNodeInfo") return SELF_N1;
    if (op === "GetClusterStatus") {
      // GetClusterStatusResponse has layoutVersion and nodes only; no self id.
      return {
        layoutVersion: 1,
        nodes: [
          {
            id: "n1",
            hostname: "garage-ci",
            isUp: true,
            draining: false,
            role: { zone: "dc1", capacity: 1000000000, tags: [] },
          },
        ],
      };
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("cluster_status").execute({}, context);
    assertEquals(call(fake.calls, "GetNodeInfo")?.query, { node: "self" });
    const d = written[0].data as Record<string, unknown>;
    assertEquals(d.node, "n1");
    assertEquals(d.layoutVersion, 1);
    const nodes = d.nodes as Array<Record<string, unknown>>;
    assertEquals(nodes[0].zone, "dc1");
    assertEquals(nodes[0].capacity, 1000000000);
    assertEquals(nodes[0].isUp, true);
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("layout_get: shapes roles + staged changes + zoneRedundancy", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetClusterLayout"
      ? {
        version: 2,
        partitionSize: 1000,
        parameters: { zoneRedundancy: { atLeast: 1 } },
        roles: [{ id: "n1", zone: "dc1", capacity: 1000000000, tags: [] }],
        stagedRoleChanges: [{ id: "n2", remove: true }],
      }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("layout_get").execute({}, context);
    const d = written[0].data as Record<string, unknown>;
    assertEquals(d.version, 2);
    assertEquals(d.zoneRedundancy, "atLeast:1");
    assertEquals((d.roles as unknown[]).length, 1);
    assertEquals(
      (d.stagedChanges as Array<Record<string, unknown>>)[0].remove,
      true,
    );
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── layout_assign ───────────────────────────

const EMPTY_LAYOUT = { version: 0, roles: [], stagedRoleChanges: [] };
const LAYOUT_N1 = {
  version: 2,
  roles: [{ id: "n1", zone: "rack-a", capacity: 1000000000, tags: ["ssd"] }],
  stagedRoleChanges: [],
};

Deno.test("layout_assign: new node — storage body (capacity int), no tags, action staged", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetClusterLayout" ? EMPTY_LAYOUT : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("layout_assign").execute(
      { nodeId: "n1", zone: "dc1", capacity: 1000000000 },
      context,
    );
    assertEquals(call(fake.calls, "UpdateClusterLayout")?.body, {
      roles: [{ id: "n1", zone: "dc1", capacity: 1000000000, tags: [] }],
      parameters: null,
    });
    assertEquals(written[0].data.action, "staged");
  } finally {
    __setGarageApi(null);
  }
});

// A role change is whole-role, so a capacity-only call used to restage the
// node into zone dc1 with no tags.
Deno.test("layout_assign: capacity-only change keeps the node's current zone and tags", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetClusterLayout" ? LAYOUT_N1 : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("layout_assign").execute({
      nodeId: "n1",
      capacity: 2000000000,
    }, context);
    assertEquals(call(fake.calls, "UpdateClusterLayout")?.body, {
      roles: [{
        id: "n1",
        zone: "rack-a",
        capacity: 2000000000,
        tags: ["ssd"],
      }],
      parameters: null,
    });
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("layout_assign: zone-only change keeps the node's current capacity", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetClusterLayout" ? LAYOUT_N1 : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("layout_assign").execute(
      { nodeId: "n1", zone: "rack-b" },
      context,
    );
    const body = call(fake.calls, "UpdateClusterLayout")?.body as Record<
      string,
      unknown
    >;
    assertEquals(body.roles, [{
      id: "n1",
      zone: "rack-b",
      capacity: 1000000000,
      tags: ["ssd"],
    }]);
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("layout_assign: new node without a zone is rejected before staging", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetClusterLayout" ? EMPTY_LAYOUT : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("layout_assign").execute({ nodeId: "n9", capacity: 1 }, context),
      /no role in the current layout; pass zone/,
    );
    assert(
      !call(fake.calls, "UpdateClusterLayout"),
      "must not stage without a zone",
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("layout_assign: gateway (no capacity) sends capacity:null; zoneRedundancy parsed", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetClusterLayout" ? EMPTY_LAYOUT : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("layout_assign").execute(
      { nodeId: "n1", zone: "dc1", zoneRedundancy: "maximum" },
      context,
    );
    const body = call(fake.calls, "UpdateClusterLayout")?.body as Record<
      string,
      unknown
    >;
    assertEquals(
      (body.roles as Array<Record<string, unknown>>)[0].capacity,
      null,
    );
    assertEquals(body.parameters, { zoneRedundancy: "maximum" });
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── layout_apply / layout_revert ───────────────────────────

Deno.test("layout_apply: resolves version to current+1 and applies", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetClusterLayout") {
      return { version: 3, stagedRoleChanges: [{ id: "n1" }] };
    }
    if (op === "ApplyClusterLayout") return { message: ["ok"], layout: {} };
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("layout_apply").execute({}, context);
    assertEquals(call(fake.calls, "ApplyClusterLayout")?.body, { version: 4 });
    assertEquals(written[0].data.applied, true);
    assertEquals(written[0].data.version, 4);
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("layout_apply: nothing staged throws, no apply", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetClusterLayout"
      ? { version: 3, stagedRoleChanges: [] }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("layout_apply").execute({}, context),
      /no staged/,
    );
    assert(!call(fake.calls, "ApplyClusterLayout"));
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("layout_revert: calls RevertClusterLayout, action reverted", async () => {
  const fake = makeFakeApi(() => undefined);
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("layout_revert").execute({}, context);
    assert(call(fake.calls, "RevertClusterLayout"), "must call revert");
    assertEquals(written[0].data.action, "reverted");
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── cluster_init ───────────────────────────

Deno.test("cluster_init: fresh cluster — assigns responding node + applies version+1", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetNodeInfo") return SELF_N1;
    if (op === "GetClusterLayout") {
      return { version: 0, roles: [], stagedRoleChanges: [] };
    }
    if (op === "ApplyClusterLayout") {
      return { message: ["initialized"], layout: {} };
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("cluster_init").execute({ capacity: 1000000000 }, context);
    assertEquals(call(fake.calls, "GetNodeInfo")?.query, { node: "self" });
    assertEquals(
      (call(fake.calls, "UpdateClusterLayout")?.body as Record<string, unknown>)
        .roles,
      [
        { id: "n1", zone: "dc1", capacity: 1000000000, tags: [] },
      ],
    );
    assertEquals(call(fake.calls, "ApplyClusterLayout")?.body, { version: 1 });
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.applied, true);
    assertEquals(written[0].data.nodeId, "n1");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("cluster_init: idempotent — already-initialised layout is unchanged, no writes", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetNodeInfo") return SELF_N1;
    if (op === "GetClusterLayout") {
      return {
        version: 5,
        roles: [{ id: "n1", zone: "dc1", capacity: 1 }],
        stagedRoleChanges: [],
      };
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("cluster_init").execute({ capacity: 1000000000 }, context);
    assert(
      !call(fake.calls, "UpdateClusterLayout"),
      "must not stage when already initialised",
    );
    assert(
      !call(fake.calls, "ApplyClusterLayout"),
      "must not apply when already initialised",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("cluster_init: explicit nodeId skips the self lookup", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetClusterLayout") {
      return { version: 0, roles: [], stagedRoleChanges: [] };
    }
    if (op === "ApplyClusterLayout") return { message: [], layout: {} };
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("cluster_init").execute(
      { nodeId: "n2", capacity: 1 },
      context,
    );
    assert(!call(fake.calls, "GetNodeInfo"), "must not ask which node is self");
    assertEquals(written[0].data.nodeId, "n2");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("cluster_init: self lookup with no answering node throws before any write", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetNodeInfo" ? { success: {}, error: { n1: "timeout" } } : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("cluster_init").execute({ capacity: 1 }, context),
      /returned no node/,
    );
    assert(!call(fake.calls, "UpdateClusterLayout"));
  } finally {
    __setGarageApi(null);
  }
});

// A check receives globalArgs without the schema's defaults, so an unset
// timeoutMs used to become NaN, which aborts the request at once.
Deno.test("reachable check: applies the schema defaults to globalArgs", async () => {
  let seenTimeout: unknown;
  __setGarageApi((g) => {
    seenTimeout = g.timeoutMs;
    return Promise.resolve({ status: "healthy" });
  });
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: {
        endpoint: GLOBALS.endpoint,
        adminToken: GLOBALS.adminToken,
      },
    });
    assertEquals(res.pass, true);
    assertEquals(seenTimeout, 30000);
  } finally {
    __setGarageApi(null);
  }
});
