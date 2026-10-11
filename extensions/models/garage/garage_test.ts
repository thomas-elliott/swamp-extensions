/**
 * Unit tests for the parts of `@thomas/garage` where an unnoticed bug would be
 * costly: idempotent create, delete gating (verify-first), the key_rotate
 * copy-grants composite, the permissions_audit matrix + flags, request-body
 * shaping for allow/deny/alias/update, and keeping secrets out of logs. No live
 * cluster; the Admin API transport is faked via the __setGarageApi seam.
 */
import { z } from "npm:zod@4";
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

/** Throw what the real transport throws for a Garage 404 (NoSuchBucket, NoSuchAccessKey). */
function notFound(op: string): never {
  throw new Error(`Garage ${op} failed (HTTP 404): no such item`);
}

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
    assertEquals(written[0].name, "cluster-health");
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
    assertEquals(written[0].name, "bucket-result:abc123");
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
    assertEquals(
      written[0].name,
      "bucket-result:newid",
      "named by id, not alias",
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_create: an error other than 404 is not taken as a free alias", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetBucketInfo") {
      throw new Error("Garage GetBucketInfo failed (HTTP 403): forbidden");
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("bucket_create").execute({ globalAlias: "logs" }, context),
      /HTTP 403/,
    );
    assert(!call(fake.calls, "CreateBucket"), "must not create");
  } finally {
    __setGarageApi(null);
  }
});

// Garage gives a local alias's key nothing unless the create asks for it.
Deno.test("bucket_create: local alias passes the requested grants to Garage", async () => {
  const fake = makeFakeApi((op) =>
    op === "CreateBucket" ? { id: "nb", globalAliases: [] } : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("bucket_create").execute({
      localAlias: "mine",
      localAliasAccessKeyId: "GK1",
      localAliasRead: true,
      localAliasWrite: true,
    }, context);
    assertEquals(call(fake.calls, "CreateBucket")?.body, {
      localAlias: {
        accessKeyId: "GK1",
        alias: "mine",
        allow: { read: true, write: true, owner: false },
      },
    });
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_create: local-alias grants without a local alias are rejected", async () => {
  const fake = makeFakeApi(() => undefined);
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("bucket_create").execute(
          { globalAlias: "g", localAliasRead: true },
          context,
        ),
      /need localAlias/,
    );
    assertEquals(fake.calls.length, 0);
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

// Garage answers an unknown bucket id with 404. An already-gone bucket is
// the goal of a delete, so a re-run records unchanged instead of failing.
Deno.test("bucket_delete: already gone records unchanged, no DeleteBucket", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetBucketInfo" ? notFound(op) : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("bucket_delete").execute({ id: "ghost" }, context);
    assert(!call(fake.calls, "DeleteBucket"));
    assertEquals(written[0].name, "bucket-result:ghost");
    assertEquals(written[0].data.id, "ghost");
    assertEquals(written[0].data.action, "unchanged");
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

/** A GetBucketInfo answer: global alias "g", and key GK1 with local alias "l". */
function aliasedBucket(op: string): unknown {
  return op === "GetBucketInfo"
    ? {
      id: "b1",
      globalAliases: ["g"],
      keys: [{
        accessKeyId: "GK1",
        permissions: { read: true },
        bucketLocalAliases: ["l"],
      }],
    }
    : undefined;
}

Deno.test("bucket_alias_add: an alias already on the bucket is unchanged, no write", async () => {
  for (
    const args of [
      { bucketId: "b1", globalAlias: "g" },
      { bucketId: "b1", localAlias: "l", accessKeyId: "GK1" },
    ]
  ) {
    const fake = makeFakeApi(aliasedBucket);
    __setGarageApi(fake.fn);
    try {
      const { context, written } = makeContext();
      await method("bucket_alias_add").execute(args, context);
      assertEquals(fake.ops(), ["GetBucketInfo"]);
      assertEquals(written[0].data.action, "unchanged");
    } finally {
      __setGarageApi(null);
    }
  }
});

Deno.test("bucket_alias_remove: removes a present alias", async () => {
  const fake = makeFakeApi(aliasedBucket);
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("bucket_alias_remove").execute(
      { bucketId: "b1", globalAlias: "g" },
      context,
    );
    assertEquals(call(fake.calls, "RemoveBucketAlias")?.body, {
      bucketId: "b1",
      globalAlias: "g",
    });
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_alias_remove: an alias already gone is unchanged, no write", async () => {
  for (
    const args of [
      { bucketId: "b1", globalAlias: "gone" },
      { bucketId: "b1", localAlias: "gone", accessKeyId: "GK1" },
    ]
  ) {
    const fake = makeFakeApi(aliasedBucket);
    __setGarageApi(fake.fn);
    try {
      const { context, written } = makeContext();
      await method("bucket_alias_remove").execute(args, context);
      assertEquals(fake.ops(), ["GetBucketInfo"]);
      assertEquals(written[0].data.action, "unchanged");
    } finally {
      __setGarageApi(null);
    }
  }
});

Deno.test("bucket_alias_remove: a local alias of a key Garage doesn't list goes to Garage", async () => {
  // GK2 has no permission on b1, so GetBucketInfo can't show its aliases.
  const fake = makeFakeApi(aliasedBucket);
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("bucket_alias_remove").execute(
      { bucketId: "b1", localAlias: "x", accessKeyId: "GK2" },
      context,
    );
    assertEquals(fake.ops(), ["GetBucketInfo", "RemoveBucketAlias"]);
    assertEquals(written[0].data.action, "updated");
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
    assertEquals(written[0].name, "key-result:GK123");
    assert(
      !logs.some((l) => JSON.stringify(l).includes("s3cr3t")),
      "secret must never be logged",
    );
  } finally {
    __setGarageApi(null);
  }
});

/**
 * True when a field carries `{ sensitive: true }`, read the way swamp reads it:
 * from the global zod registry, on the field or on any optional/nullable layer.
 */
function isSensitiveField(field: z.ZodType): boolean {
  let current: unknown = field;
  while (current) {
    if (z.globalRegistry.get(current as z.ZodType)?.sensitive) return true;
    current = (current as { _def: { innerType?: unknown } })._def.innerType;
  }
  return false;
}

// sensitiveOutput vaulted every field, so the key id, name and action came back
// as vault references that CEL and the README recipe could not read.
Deno.test("key-result: only secretAccessKey is vaulted", () => {
  const spec = (model.resources as Record<
    string,
    { sensitiveOutput?: boolean; schema: z.ZodObject }
  >)["key-result"];
  assert(!spec.sensitiveOutput, "the whole output must not be vaulted");
  const sensitive = Object.entries(spec.schema.shape)
    .filter(([, field]) => isSensitiveField(field as z.ZodType))
    .map(([name]) => name);
  assertEquals(sensitive, ["secretAccessKey"]);
});

// A new key has no expiry, so neverExpires=false alone used to create a key
// that never expires.
Deno.test("key_create: neverExpires=false without expiration is rejected", async () => {
  const fake = makeFakeApi(() => ({ accessKeyId: "GK1" }));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("key_create").execute(
          { name: "tmp", neverExpires: false },
          context,
        ),
      /neverExpires=false needs expiration/,
    );
    assertEquals(fake.calls.length, 0);
    await method("key_create").execute({
      name: "tmp",
      neverExpires: false,
      expiration: "2027-01-01T00:00:00Z",
    }, context);
    assert(call(fake.calls, "CreateKey"), "false with expiration is fine");
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

Deno.test("key_rotate: the new key keeps the old key's expiry", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetKeyInfo") {
      return {
        accessKeyId: "OLD",
        expiration: "2027-01-01T00:00:00Z",
        permissions: {},
        buckets: [],
      };
    }
    if (op === "CreateKey") return { accessKeyId: "NEW", secretAccessKey: "s" };
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("key_rotate").execute({ id: "OLD" }, context);
    const ck = call(fake.calls, "CreateKey")?.body as Record<string, unknown>;
    assertEquals(ck.expiration, "2027-01-01T00:00:00Z");
    assert(!("neverExpires" in ck), "must not override the expiry");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_rotate: a failed grant copy deletes the new key and fails", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetKeyInfo") {
      return {
        accessKeyId: "OLD",
        permissions: {},
        buckets: [{ id: "b1", permissions: { read: true } }],
      };
    }
    if (op === "CreateKey") return { accessKeyId: "NEW", secretAccessKey: "s" };
    if (op === "AllowBucketKey") {
      throw new Error("Garage AllowBucketKey failed (HTTP 500): boom");
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await rejects(
      () => method("key_rotate").execute({ id: "OLD" }, context),
      /new key was deleted again/,
    );
    assertEquals(call(fake.calls, "DeleteKey")?.query, { id: "NEW" });
    assertEquals(written.length, 0, "no secret is recorded");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_rotate: missing old key throws before creating anything", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetKeyInfo" ? notFound(op) : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("key_rotate").execute({ id: "nope" }, context),
      /^Key "nope" not found$/,
    );
    assert(
      !call(fake.calls, "CreateKey"),
      "must not create a key when the old one is missing",
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_rotate: an expired key is refused before creating anything", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetKeyInfo"
      ? {
        accessKeyId: "GK1",
        expiration: "2020-01-01T00:00:00Z",
        expired: true,
      }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("key_rotate").execute({ id: "GK1" }, context),
      /expired at 2020-01-01T00:00:00Z.*key_update/,
    );
    assert(!call(fake.calls, "CreateKey"));
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── key_delete (gated) ───────────────────────────

Deno.test("key_delete: an already-gone id as typed is escaped in the data name", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetKeyInfo" ? notFound(op) : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("key_delete").execute({ id: "../a/b%" }, context);
    assertEquals(written[0].name, "key-result:.%2E%2Fa%2Fb%25");
    assertEquals(written[0].data.accessKeyId, "../a/b%");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_delete: already gone records unchanged, no DeleteKey", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetKeyInfo" ? notFound(op) : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("key_delete").execute({ id: "ghost" }, context);
    assert(!call(fake.calls, "DeleteKey"));
    assertEquals(written[0].name, "key-result:ghost");
    assertEquals(written[0].data.accessKeyId, "ghost");
    assertEquals(written[0].data.action, "unchanged");
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
    assertEquals(written[0].name, "permission-result:b1:GK1");
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

Deno.test("key_deny: records what the key holds afterwards, not the request", async () => {
  // Denying owner leaves read and write as they were; Garage returns the bucket.
  const fake = makeFakeApi(() => ({
    id: "b1",
    keys: [{
      accessKeyId: "GK1",
      permissions: { read: true, write: true, owner: false },
    }],
  }));
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
    assertEquals(
      [written[0].data.read, written[0].data.write, written[0].data.owner],
      [true, true, false],
    );
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
      // GetClusterStatusResponse has layoutVersion and nodes only: no self id
      // and no top-level garageVersion.
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
    assertEquals(d.garageVersion, "v2.3.0");
    assertEquals(written[0].name, "cluster-status");
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
    assertEquals(written[0].name, "cluster-layout");
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

// Garage keeps one staged change per node and a new one overwrites it, so the
// omitted fields must come from the staged role, not the applied one.
Deno.test("layout_assign: a follow-up call keeps the zone already staged", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetClusterLayout"
      ? {
        ...LAYOUT_N1,
        stagedRoleChanges: [{
          id: "n1",
          zone: "rack-b",
          capacity: 1000000000,
          tags: ["ssd"],
        }],
      }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("layout_assign").execute(
      { nodeId: "n1", capacity: 2000000000 },
      context,
    );
    const body = call(fake.calls, "UpdateClusterLayout")?.body as Record<
      string,
      unknown
    >;
    assertEquals(body.roles, [{
      id: "n1",
      zone: "rack-b",
      capacity: 2000000000,
      tags: ["ssd"],
    }]);
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("layout_assign: a node staged but not applied needs no zone on a tags-only call", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetClusterLayout"
      ? {
        ...EMPTY_LAYOUT,
        stagedRoleChanges: [{
          id: "n9",
          zone: "dc2",
          capacity: null,
          tags: [],
        }],
      }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("layout_assign").execute(
      { nodeId: "n9", tags: ["edge"] },
      context,
    );
    const body = call(fake.calls, "UpdateClusterLayout")?.body as Record<
      string,
      unknown
    >;
    assertEquals(body.roles, [{
      id: "n9",
      zone: "dc2",
      capacity: null,
      tags: ["edge"],
    }]);
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("layout_assign: a staged removal falls back to the applied role", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetClusterLayout"
      ? { ...LAYOUT_N1, stagedRoleChanges: [{ id: "n1", remove: true }] }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("layout_assign").execute(
      { nodeId: "n1", capacity: 2000000000 },
      context,
    );
    const body = call(fake.calls, "UpdateClusterLayout")?.body as Record<
      string,
      unknown
    >;
    assertEquals(body.roles, [{
      id: "n1",
      zone: "rack-a",
      capacity: 2000000000,
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
    assertEquals(written[0].name, "layout-result:apply-4");
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
    assertEquals(written[0].name, "layout-result:revert");
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

// ─────────────────────────── data names ───────────────────────────

Deno.test("data names: specs sharing a Garage id get distinct names", async () => {
  // swamp keys data by model + name, so `key` and `key-result` for the same
  // access key must not share a name (the result would replace the listing).
  const fake = makeFakeApi((op) => {
    if (op === "GetKeyInfo") {
      return { accessKeyId: "GK1", name: "app", buckets: [] };
    }
    if (op === "GetBucketInfo") return { id: "b1", globalAliases: [] };
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("key_get").execute({ id: "GK1" }, context);
    await method("key_update").execute({ id: "GK1", name: "app2" }, context);
    await method("bucket_get").execute({ id: "b1" }, context);
    await method("bucket_update").execute(
      { id: "b1", maxObjects: 5 },
      context,
    );
    assertEquals(written.map((w) => w.name), [
      "key:GK1",
      "key-result:GK1",
      "bucket:b1",
      "bucket-result:b1",
    ]);
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── transport errors ───────────────────────────

/** A context whose globalArgs point at a local test server. */
function contextFor(endpoint: string, timeoutMs: number) {
  const { context } = makeContext();
  return { ...context, globalArgs: { ...GLOBALS, endpoint, timeoutMs } };
}

// The timer used to stop at the headers, so a body that never arrived hung
// the method; and a fetch error did not name the call.
Deno.test("transport: a stalled response body times out and names the call", async () => {
  let body: ReadableStreamDefaultController | undefined;
  const server = Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen() {} },
    // Headers go out at once; the body never comes.
    () => new Response(new ReadableStream({ start: (c) => void (body = c) })),
  );
  let guard: ReturnType<typeof setTimeout> | undefined;
  try {
    const context = contextFor(`http://127.0.0.1:${server.addr.port}`, 100);
    // Without the timeout the method would wait for ever; fail instead.
    const hung = new Promise((_, reject) => {
      guard = setTimeout(() => reject(new Error("hung")), 3000);
    });
    await rejects(
      () => Promise.race([method("cluster_health").execute({}, context), hung]),
      /^Garage GetClusterHealth failed: timed out after 100 ms$/,
    );
  } finally {
    clearTimeout(guard);
    // End the body so the server can shut down even if the client still waits.
    try {
      body?.close();
    } catch { /* already cancelled by the client's abort */ }
    await server.shutdown();
  }
});

Deno.test("transport: a refused connection names the call", async () => {
  // Bind a port, then free it, so nothing is listening there.
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = listener.addr.port;
  listener.close();
  const context = contextFor(`http://127.0.0.1:${port}`, 2000);
  await rejects(
    () => method("cluster_health").execute({}, context),
    /^Garage GetClusterHealth failed: /,
  );
});

// ─────────────────────────── argument validation ───────────────────────────

Deno.test("arguments: more than one selector or alias is rejected before any call", async () => {
  const fake = makeFakeApi(() => ({}));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("bucket_get").execute({ id: "b1", search: "b" }, context),
      /exactly one of id, globalAlias, or search/,
    );
    await rejects(
      () => method("key_get").execute({ id: "GK1", search: "GK" }, context),
      /exactly one of id or search/,
    );
    await rejects(
      () =>
        method("bucket_alias_add").execute({
          bucketId: "b1",
          globalAlias: "g",
          localAlias: "l",
          accessKeyId: "GK1",
        }, context),
      /exactly one of globalAlias or localAlias/,
    );
    assertEquals(fake.calls.length, 0);
  } finally {
    __setGarageApi(null);
  }
});

// Garage stores quotas and capacity as unsigned integers.
Deno.test("arguments: negative sizes are rejected", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetClusterLayout" ? EMPTY_LAYOUT : BUCKET_B1
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("bucket_update").execute({ id: "b1", maxSize: -1 }, context),
      /maxSize/,
    );
    await rejects(
      () =>
        method("layout_assign").execute(
          { nodeId: "n1", zone: "dc1", capacity: -1 },
          context,
        ),
      /capacity/,
    );
    assert(!call(fake.calls, "UpdateBucket"));
    assert(!call(fake.calls, "UpdateClusterLayout"));
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("arguments: zoneRedundancy 0 is not a positive integer", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetClusterLayout" ? EMPTY_LAYOUT : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("layout_assign").execute(
          { nodeId: "n1", zone: "dc1", zoneRedundancy: "0" },
          context,
        ),
      /invalid zoneRedundancy/,
    );
    assert(!call(fake.calls, "UpdateClusterLayout"));
  } finally {
    __setGarageApi(null);
  }
});

// A zero timeout aborts every request at once.
Deno.test("reachable check: a timeoutMs of 0 fails the schema", async () => {
  const fake = makeFakeApi(() => ({ status: "healthy" }));
  __setGarageApi(fake.fn);
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: { ...GLOBALS, timeoutMs: 0 },
    });
    assertEquals(res.pass, false);
    assertEquals(fake.calls.length, 0);
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── bucket_update website ───────────────────────────

Deno.test("bucket_update: documents with websiteEnabled=false are rejected, not dropped", async () => {
  const fake = makeFakeApi((
    op,
  ) => (op === "GetBucketInfo" ? BUCKET_B1 : undefined));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("bucket_update").execute(
          { id: "b1", websiteEnabled: false, indexDocument: "x.html" },
          context,
        ),
      /documents can only be set with websiteEnabled=true/,
    );
    assert(!call(fake.calls, "UpdateBucket"));
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_update: a document for a bucket with the website off is rejected", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetBucketInfo"
      ? { id: "b2", quotas: {}, websiteAccess: false }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("bucket_update").execute(
          { id: "b2", indexDocument: "x.html" },
          context,
        ),
      /website serving is off/,
    );
    assert(!call(fake.calls, "UpdateBucket"));
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("bucket_update: enabling a website with no index document is rejected", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetBucketInfo"
      ? { id: "b2", quotas: {}, websiteAccess: false }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("bucket_update").execute(
          { id: "b2", websiteEnabled: true },
          context,
        ),
      /pass indexDocument to enable the website/,
    );
    assert(!call(fake.calls, "UpdateBucket"));
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── listings ───────────────────────────

// A bucket deleted between ListBuckets and GetBucketInfo answers 404.
Deno.test("bucket_list and permissions_audit: skip a bucket deleted mid-listing", async () => {
  const fake = makeFakeApi((op, _body, query) => {
    if (op === "ListBuckets") return [{ id: "b1" }, { id: "gone" }];
    if (op === "ListKeys") return [];
    if (op === "GetBucketInfo") {
      return query.id === "gone"
        ? notFound(op)
        : { id: "b1", globalAliases: [], keys: [] };
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    await method("bucket_list").execute({}, context);
    assertEquals(written.map((w) => w.name), ["bucket:b1"]);
    await method("permissions_audit").execute({}, context);
    assertEquals(written[1].data.bucketCount, 1);
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── key_update / key_import ───────────────────────────

// Garage reads a missing neverExpires as false, so sending false changes
// nothing; it used to be recorded as an update.
Deno.test("key_update: neverExpires=false is not a change", async () => {
  const fake = makeFakeApi(() => ({ accessKeyId: "GK1", name: "app" }));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("key_update").execute(
          { id: "GK1", neverExpires: false },
          context,
        ),
      /nothing to update/,
    );
    assertEquals(fake.calls.length, 0);
    await method("key_update").execute(
      { id: "GK1", name: "app", neverExpires: false },
      context,
    );
    assertEquals(call(fake.calls, "UpdateKey")?.body, { name: "app" });
  } finally {
    __setGarageApi(null);
  }
});

/** A fake where ImportKey answers 409 and GetKeyInfo returns `existing`. */
function importConflict(existing: () => unknown) {
  return makeFakeApi((op) => {
    if (op === "ImportKey") {
      throw new Error(
        "Garage ImportKey failed (HTTP 409): Key GK1 already exists in data store.",
      );
    }
    if (op === "GetKeyInfo") return existing();
    return undefined;
  });
}

Deno.test("key_import: re-importing the same pair records unchanged", async () => {
  const fake = importConflict(() => ({
    accessKeyId: "GK1",
    name: "app",
    secretAccessKey: "s3cr3t",
  }));
  __setGarageApi(fake.fn);
  try {
    const { context, written, logs } = makeContext();
    await method("key_import").execute(
      { accessKeyId: "GK1", secretAccessKey: "s3cr3t" },
      context,
    );
    assertEquals(call(fake.calls, "GetKeyInfo")?.query, {
      id: "GK1",
      search: undefined,
      showSecretKey: "true",
    });
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.name, "app");
    assert(!("secretAccessKey" in written[0].data), "no secret recorded");
    assert(!JSON.stringify(logs).includes("s3cr3t"), "secret never logged");
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_import: an existing key with another secret fails without showing it", async () => {
  const fake = importConflict(() => ({
    accessKeyId: "GK1",
    secretAccessKey: "other-secret",
  }));
  __setGarageApi(fake.fn);
  try {
    const { context, written } = makeContext();
    let message = "";
    await method("key_import").execute(
      { accessKeyId: "GK1", secretAccessKey: "s3cr3t" },
      context,
    ).catch((e: Error) => message = e.message);
    assert(/already exists with a different secret/.test(message), message);
    assert(!/s3cr3t|other-secret/.test(message), "no secret in the error");
    assertEquals(written.length, 0);
  } finally {
    __setGarageApi(null);
  }
});

// Garage never reuses the id of a deleted key; its own message says so.
Deno.test("key_import: a deleted key's id keeps Garage's conflict error", async () => {
  const fake = importConflict(() => notFound("GetKeyInfo"));
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("key_import").execute(
          { accessKeyId: "GK1", secretAccessKey: "s3cr3t" },
          context,
        ),
      /HTTP 409/,
    );
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── key secrets not recorded ───────────────────────────

/** A context whose writeResource fails, as it does with no vault for the secret. */
function failingWriteContext() {
  const { context } = makeContext();
  return {
    ...context,
    writeResource: () => Promise.reject(new Error("no default vault")),
  };
}

Deno.test("key_create: a failed record names the key that now exists", async () => {
  const fake = makeFakeApi((op) =>
    op === "CreateKey"
      ? { accessKeyId: "GK9", secretAccessKey: "s3cr3t" }
      : undefined
  );
  __setGarageApi(fake.fn);
  try {
    await rejects(
      () => method("key_create").execute({ name: "ci" }, failingWriteContext()),
      /Key GK9 was created in Garage but recording it failed \(no default vault\)/,
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_rotate: a failed record names the new key", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetKeyInfo") {
      return { accessKeyId: "OLD", permissions: {}, buckets: [] };
    }
    if (op === "CreateKey") return { accessKeyId: "NEW", secretAccessKey: "s" };
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    await rejects(
      () => method("key_rotate").execute({ id: "OLD" }, failingWriteContext()),
      /Key NEW was created in Garage but recording it failed/,
    );
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── key_rotate local aliases ───────────────────────────

// Local aliases belong to a key; without a copy, a client addressing the
// bucket by one gets NoSuchBucket under the new key.
Deno.test("key_rotate: copies the old key's local aliases onto the new key", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetKeyInfo") {
      return {
        accessKeyId: "OLD",
        permissions: {},
        buckets: [{
          id: "b1",
          localAliases: ["mine", "also-mine"],
          permissions: { read: true },
        }],
      };
    }
    if (op === "CreateKey") return { accessKeyId: "NEW", secretAccessKey: "s" };
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("key_rotate").execute({ id: "OLD" }, context);
    assertEquals(
      fake.calls.filter((c) => c.op === "AddBucketAlias").map((c) => c.body),
      [
        { bucketId: "b1", localAlias: "mine", accessKeyId: "NEW" },
        { bucketId: "b1", localAlias: "also-mine", accessKeyId: "NEW" },
      ],
    );
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("key_rotate: a failed alias copy deletes the new key", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetKeyInfo") {
      return {
        accessKeyId: "OLD",
        permissions: {},
        buckets: [{ id: "b1", localAliases: ["mine"], permissions: {} }],
      };
    }
    if (op === "CreateKey") return { accessKeyId: "NEW", secretAccessKey: "s" };
    if (op === "AddBucketAlias") {
      throw new Error("Garage AddBucketAlias failed (HTTP 400): bad alias");
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("key_rotate").execute({ id: "OLD" }, context),
      /new key was deleted again/,
    );
    assertEquals(call(fake.calls, "DeleteKey")?.query, { id: "NEW" });
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── layout ───────────────────────────

Deno.test("layout_apply: a staged parameters change alone is applied", async () => {
  const fake = makeFakeApi((op) =>
    op === "GetClusterLayout"
      ? {
        version: 3,
        stagedRoleChanges: [],
        stagedParameters: { zoneRedundancy: "maximum" },
      }
      : { message: [] }
  );
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await method("layout_apply").execute({}, context);
    assertEquals(call(fake.calls, "ApplyClusterLayout")?.body, { version: 4 });
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("cluster_init: a failed apply says the role is still staged", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetClusterLayout") return EMPTY_LAYOUT;
    if (op === "ApplyClusterLayout") {
      throw new Error(
        "Garage ApplyClusterLayout failed (HTTP 400): bad layout",
      );
    }
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("cluster_init").execute({ nodeId: "n1", capacity: 1 }, context),
      /HTTP 400\): bad layout; the role for n1 is still staged: run layout_revert/,
    );
  } finally {
    __setGarageApi(null);
  }
});

// ─────────────────────────── logging ───────────────────────────

Deno.test("logging: the single-item reads log on entry and on completion", async () => {
  const fake = makeFakeApi((op) => {
    if (op === "GetBucketInfo") return { id: "b1" };
    if (op === "GetKeyInfo") return { accessKeyId: "GK1" };
    if (op === "GetClusterLayout") return EMPTY_LAYOUT;
    return undefined;
  });
  __setGarageApi(fake.fn);
  try {
    const { context, logs } = makeContext();
    await method("bucket_get").execute({ id: "b1" }, context);
    await method("key_get").execute({ id: "GK1" }, context);
    await method("layout_get").execute({}, context);
    assertEquals(logs.map((l) => l.msg), [
      "Fetching bucket",
      "Fetched bucket",
      "Fetching key",
      "Fetched key",
      "Fetching cluster layout",
      "Fetched cluster layout",
    ]);
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("logging: a listing logs how many items it wrote", async () => {
  const fake = makeFakeApi((op) =>
    op === "ListKeys" ? [{ id: "GK1" }, { id: "GK2" }] : undefined
  );
  __setGarageApi(fake.fn);
  try {
    const { context, logs } = makeContext();
    await method("key_list").execute({}, context);
    assertEquals(logs.at(-1), { msg: "Listed keys", props: { count: 2 } });
  } finally {
    __setGarageApi(null);
  }
});

Deno.test("upgrade 2026.10.11.1: drops a non-positive timeoutMs, keeps the rest", () => {
  const up = model.upgrades[0].upgradeAttributes;
  assertEquals(
    up({ endpoint: "http://g", adminToken: "t", timeoutMs: 0 }),
    { endpoint: "http://g", adminToken: "t" },
  );
  assertEquals(
    up({ endpoint: "http://g", timeoutMs: 5000 }),
    { endpoint: "http://g", timeoutMs: 5000 },
  );
  assertEquals(up({ endpoint: "http://g" }), { endpoint: "http://g" });
});
