/**
 * Tests for `@thomas/arcane`. The first few cover pure helpers (the envelope
 * unwrap, the service-spec re-point, the health and convergence predicates); the
 * rest run the methods against a scripted Arcane through the transport and
 * validator test seams. No network I/O.
 */
import {
  __setArcaneTransport,
  __setComposeValidator,
  b64,
  coerceList,
  dataName,
  envValues,
  type Json,
  maskValues,
  model,
  projectHealthy,
  pruneResult,
  renderNames,
  repointServiceRefs,
  serviceConvergence,
  streamFailure,
  swarmStackResource,
  swarmTaskResource,
  unwrap,
  volumeResource,
} from "./arcane.ts";

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

Deno.test("unwrap pulls the single-object payload out of {success,data}", () => {
  assertEquals(unwrap({ success: true, data: { id: "abc" } }), { id: "abc" });
  // already-unwrapped object passes through unchanged
  assertEquals(unwrap({ id: "x" }), { id: "x" });
  // a list payload is left wrapped (lists are coerceList's job, not unwrap's)
  assertEquals(unwrap({ success: true, data: [1, 2] }), {
    success: true,
    data: [1, 2],
  });
  // non-objects degrade to {}
  assertEquals(unwrap([1, 2, 3]), {});
  assertEquals(unwrap(null), {});
  assertEquals(unwrap("nope"), {});
});

Deno.test("coerceList unwraps bare, wrapped, and nested list shapes", () => {
  assertEquals(coerceList([{ a: 1 }]), [{ a: 1 }]);
  assertEquals(coerceList({ data: [{ a: 1 }] }), [{ a: 1 }]);
  assertEquals(coerceList({ items: [{ a: 1 }] }), [{ a: 1 }]);
  assertEquals(coerceList({ results: [{ a: 1 }] }), [{ a: 1 }]);
  assertEquals(coerceList({ data: { items: [{ a: 1 }] } }), [{ a: 1 }]);
  // Arcane encodes an empty Go slice as null.
  assertEquals(coerceList({ success: true, data: null }), []);
});

Deno.test("coerceList throws on a shape it does not know, rather than return an empty list", () => {
  for (const resp of [{ nope: 1 }, null, "text", { data: "x" }]) {
    let message = "";
    try {
      coerceList(resp);
    } catch (e) {
      message = (e as Error).message;
    }
    assert(/unrecognised list response/.test(message), JSON.stringify(resp));
  }
});

Deno.test("b64 encodes UTF-8 to base64", () => {
  assertEquals(b64("hunter2"), "aHVudGVyMg==");
  assertEquals(b64(""), "");
});

Deno.test("repointServiceRefs swaps a secret ref by name, keeping the mount path", () => {
  const spec = {
    TaskTemplate: {
      ContainerSpec: {
        Secrets: [
          {
            SecretID: "old1",
            SecretName: "db_pw",
            File: { Name: "db_pw", UID: "0", GID: "0", Mode: 292 },
          },
          { SecretID: "keep", SecretName: "other", File: { Name: "other" } },
        ],
      },
    },
  };
  assertEquals(
    repointServiceRefs(spec, "secret", "db_pw", "new1", "db_pw-v2"),
    1,
  );
  const refs = spec.TaskTemplate.ContainerSpec.Secrets;
  assertEquals(refs[0].SecretID, "new1");
  assertEquals(refs[0].SecretName, "db_pw-v2");
  assertEquals(refs[0].File.Name, "db_pw", "mount path must be preserved");
  assertEquals(refs[1].SecretID, "keep", "unrelated ref untouched");
});

Deno.test("repointServiceRefs handles configs, no-match, and missing structures", () => {
  const spec = {
    TaskTemplate: {
      ContainerSpec: {
        Configs: [{
          ConfigID: "c1",
          ConfigName: "nginx",
          File: { Name: "/etc/nginx.conf" },
        }],
      },
    },
  };
  assertEquals(
    repointServiceRefs(spec, "config", "nginx", "c2", "nginx-v2"),
    1,
  );
  assertEquals(
    spec.TaskTemplate.ContainerSpec.Configs[0].ConfigName,
    "nginx-v2",
  );
  assertEquals(
    spec.TaskTemplate.ContainerSpec.Configs[0].File.Name,
    "/etc/nginx.conf",
  );
  // no matching name -> 0 rewrites
  assertEquals(repointServiceRefs(spec, "config", "absent", "x", "y"), 0);
  // missing ContainerSpec / empty spec -> 0, no throw
  assertEquals(
    repointServiceRefs({ TaskTemplate: {} }, "secret", "a", "b", "c"),
    0,
  );
  assertEquals(repointServiceRefs({}, "secret", "a", "b", "c"), 0);
});

Deno.test("projectHealthy requires running + covered replicas + nothing unhealthy", () => {
  assert(projectHealthy("running", 3, 3, false));
  assert(
    projectHealthy("running", 0, 0, false),
    "zero services is healthy once running",
  );
  assert(
    !projectHealthy("running", 3, 2, false),
    "under-replicated is not healthy",
  );
  assert(!projectHealthy("partially running", 3, 3, false), "wrong status");
  assert(
    !projectHealthy("running", 1, 1, true),
    "an unhealthy service blocks healthy",
  );
});

Deno.test("serviceConvergence classifies rolling-update states", () => {
  assertEquals(
    serviceConvergence(undefined, false, 3, 3, false),
    "converged",
    "no update expected + replicas met",
  );
  assertEquals(serviceConvergence("completed", true, 3, 3, true), "converged");
  assertEquals(serviceConvergence("updating", true, 3, 1, true), "pending");
  assertEquals(serviceConvergence("updating", true, 3, 3, false), "pending");
  assertEquals(
    serviceConvergence("completed", true, 3, 2, true),
    "pending",
    "update done but replicas short",
  );
  assertEquals(serviceConvergence("paused", true, 3, 0, true), "failed");
  assertEquals(
    serviceConvergence("rollback_completed", true, 3, 3, false),
    "failed",
  );
  assertEquals(
    serviceConvergence(undefined, false, undefined, undefined, false),
    "converged",
    "no counts reported",
  );
});

Deno.test("serviceConvergence: after a change, no update status means not started yet", () => {
  // Swarm clears the status on every update, so the old tasks look converged.
  assertEquals(serviceConvergence(undefined, false, 3, 3, true), "pending");
  assertEquals(
    serviceConvergence(undefined, false, 0, 0, true),
    "converged",
    "a service with no replicas has nothing to roll and never gets a status",
  );
});

// --- Orchestration method tests (mocked Arcane transport + compose validator) ---
//
// These exercise the branching of project_deploy and secret_rotate against scripted
// API responses, using the __setArcaneTransport / __setComposeValidator test seams.
// A minimal fake context replaces swamp's runtime (only globalArgs, logger, and
// writeResource are used by these methods). method() parses the arguments
// through the method's schema first, as swamp does, so defaults apply.

type Call = { method: string; path: string; body?: unknown };
type WriteCall = {
  specName: string;
  name: string;
  data: Record<string, unknown>;
};

/** A streamed Arcane operation (up, pull, redeploy) that finished. */
const STREAM_DONE = '{"type":"activity","activityId":"a1"}\n{"done":true}\n';

const TEST_GLOBALS = {
  baseUrl: "https://arcane.test",
  apiKey: "test-key",
  environmentId: "0",
  skipTlsVerify: false,
  syncs: [],
};

function makeContext(globalArgs: Record<string, unknown>) {
  const written: WriteCall[] = [];
  const deleted: string[] = [];
  const seen = new Set<string>();
  const noop = (_m: string, _p?: unknown): void => {};
  const context = {
    globalArgs,
    logger: { info: noop, debug: noop, warning: noop, error: noop },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ): Promise<WriteCall> => {
      // Mirror swamp: instance names must be unique across specs within one execution.
      if (seen.has(name)) {
        return Promise.reject(
          new Error(`Duplicate data instance name '${name}'`),
        );
      }
      seen.add(name);
      const h = { specName, name, data };
      written.push(h);
      return Promise.resolve(h);
    },
    deleteResource: (name: string): Promise<void> => {
      deleted.push(name);
      return Promise.resolve();
    },
  };
  return { context, written, deleted };
}

type MethodDef = {
  arguments: { parse: (v: unknown) => unknown };
  execute: (
    args: unknown,
    context: unknown,
  ) => Promise<{ dataHandles: unknown[] }>;
};
function method(name: string): Pick<MethodDef, "execute"> {
  const m = (model.methods as unknown as Record<string, MethodDef>)[name];
  return {
    execute: (args, context) => m.execute(m.arguments.parse(args), context),
  };
}

const bodyOf = (c: Call): Record<string, unknown> =>
  (c.body ?? {}) as Record<string, unknown>;

Deno.test("project_deploy direct mode: validate → update → redeploy → healthy", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (
        m === "GET" && p === "/environments/0/projects?limit=-1&archived=all"
      ) {
        return Promise.resolve([{ id: "p1", name: "web" }]);
      }
      if (m === "GET" && p === "/environments/0/projects/p1/compose") {
        return Promise.resolve({
          success: true,
          data: {
            composeContent: "old",
            envContent: "",
            status: "running",
            gitOpsManagedBy: "",
          },
        });
      }
      if (m === "PUT" && p === "/environments/0/projects/p1") {
        return Promise.resolve({ success: true, data: {} });
      }
      if (m === "POST" && p === "/environments/0/projects/p1/redeploy") {
        return Promise.resolve(STREAM_DONE);
      }
      if (m === "GET" && p === "/environments/0/projects/p1") {
        return Promise.resolve({
          success: true,
          data: { status: "running", serviceCount: 1, runningCount: 1 },
        });
      }
      if (m === "GET" && p === "/environments/0/projects/p1/runtime") {
        return Promise.resolve({
          success: true,
          data: { runtimeServices: [{ health: "healthy" }] },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("project_deploy").execute(
      {
        name: "web",
        composeContent: "new",
        rollback: true,
        healthTimeoutSec: 5,
        pollIntervalSec: 1,
      },
      context,
    );
    assert(
      calls.some((c) =>
        c.method === "PUT" && c.path === "/environments/0/projects/p1"
      ),
      "update PUT issued",
    );
    assert(
      calls.some((c) => c.method === "POST" && c.path.endsWith("/redeploy")),
      "redeploy issued",
    );
    const health = written.find((w) =>
      w.specName === "operation-result" && w.data.operation === "deploy:health"
    );
    assert(
      health && health.data.success === true,
      "health recorded as success",
    );
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_create sends the project and an empty manifest as multipart fields", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "POST" && p === "/environments/0/projects") {
        return Promise.resolve({
          success: true,
          data: { id: "p1", status: "stopped" },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("project_create").execute(
      { name: "web", composeContent: "services: {}", envContent: "A=1\n" },
      context,
    );
    const body = calls[0].body;
    assert(body instanceof FormData, "body is multipart, not JSON");
    const form = body as FormData;
    assertEquals(JSON.parse(String(form.get("project"))), {
      name: "web",
      composeContent: "services: {}",
      envContent: "A=1\n",
    });
    assertEquals(JSON.parse(String(form.get("manifest"))), {
      fileChanges: [],
    });
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy direct mode: unhealthy deploy rolls back to prior content and throws", async () => {
  const calls: Call[] = [];
  let putCount = 0;
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (
        m === "GET" && p === "/environments/0/projects?limit=-1&archived=all"
      ) {
        return Promise.resolve([{ id: "p1", name: "web" }]);
      }
      if (m === "GET" && p === "/environments/0/projects/p1/compose") {
        return Promise.resolve({
          success: true,
          data: {
            composeContent: "PRIOR",
            envContent: "",
            status: "running",
            gitOpsManagedBy: "",
          },
        });
      }
      if (m === "PUT" && p === "/environments/0/projects/p1") {
        putCount++;
        return Promise.resolve({ success: true, data: {} });
      }
      if (m === "POST" && p === "/environments/0/projects/p1/redeploy") {
        return Promise.resolve(STREAM_DONE);
      }
      if (m === "GET" && p === "/environments/0/projects/p1") {
        // unhealthy until the rollback (2nd) PUT lands, then healthy
        const ok = putCount >= 2;
        return Promise.resolve({
          success: true,
          data: ok
            ? { status: "running", serviceCount: 1, runningCount: 1 }
            : { status: "partially running", serviceCount: 1, runningCount: 0 },
        });
      }
      if (m === "GET" && p === "/environments/0/projects/p1/runtime") {
        return Promise.resolve({
          success: true,
          data: { runtimeServices: [] },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let threw = false;
    let msg = "";
    try {
      await method("project_deploy").execute(
        {
          name: "web",
          composeContent: "NEW",
          rollback: true,
          healthTimeoutSec: 1,
          pollIntervalSec: 1,
        },
        context,
      );
    } catch (e) {
      threw = true;
      msg = e instanceof Error ? e.message : String(e);
    }
    assert(threw, "failed deploy must throw");
    assert(
      msg.includes("rolled back"),
      `error should mention rollback, got: ${msg}`,
    );
    const puts = calls.filter((c) =>
      c.method === "PUT" && c.path === "/environments/0/projects/p1"
    );
    assertEquals(puts.length, 2, "one update PUT + one rollback PUT");
    assertEquals(
      bodyOf(puts[0]).composeContent,
      "NEW",
      "first PUT applies the new content",
    );
    assertEquals(
      bodyOf(puts[1]).composeContent,
      "PRIOR",
      "rollback PUT re-applies prior content",
    );
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy direct mode: a redeploy Arcane rejects (HTTP 400) still rolls back", async () => {
  // An HTTP error from Arcane is a definite answer, so the redeploy throws rather
  // than returning an unhealthy status, and the failed deploy still rolls back.
  const calls: Call[] = [];
  let putCount = 0;
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (
        m === "GET" && p === "/environments/0/projects?limit=-1&archived=all"
      ) {
        return Promise.resolve([{ id: "p1", name: "web" }]);
      }
      if (m === "GET" && p === "/environments/0/projects/p1/compose") {
        return Promise.resolve({
          success: true,
          data: {
            composeContent: "PRIOR",
            envContent: "",
            status: "running",
            gitOpsManagedBy: "",
          },
        });
      }
      if (m === "PUT" && p === "/environments/0/projects/p1") {
        putCount++;
        return Promise.resolve({ success: true, data: {} });
      }
      if (m === "POST" && p === "/environments/0/projects/p1/redeploy") {
        // the broken redeploy is rejected; the rollback redeploy (after the 2nd PUT) succeeds
        return putCount >= 2 ? Promise.resolve(STREAM_DONE) : Promise.reject(
          new Error(
            "Arcane POST /redeploy -> HTTP 400: Project ID is required",
          ),
        );
      }
      if (m === "GET" && p === "/environments/0/projects/p1") {
        return Promise.resolve({
          success: true,
          data: { status: "running", serviceCount: 1, runningCount: 1 },
        });
      }
      if (m === "GET" && p === "/environments/0/projects/p1/runtime") {
        return Promise.resolve({
          success: true,
          data: { runtimeServices: [] },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let msg = "";
    try {
      await method("project_deploy").execute(
        {
          name: "web",
          composeContent: "NEW",
          rollback: true,
          healthTimeoutSec: 5,
          pollIntervalSec: 1,
        },
        context,
      );
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    assert(
      msg.includes("rolled back"),
      `should roll back after a rejected redeploy, got: ${msg}`,
    );
    const puts = calls.filter((c) =>
      c.method === "PUT" && c.path === "/environments/0/projects/p1"
    );
    assertEquals(puts.length, 2, "update PUT then rollback PUT");
    assertEquals(
      bodyOf(puts[1]).composeContent,
      "PRIOR",
      "rollback re-applies prior content after a thrown redeploy",
    );
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy gitops mode rejects inline compose content", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (
        m === "GET" && p === "/environments/0/projects?limit=-1&archived=all"
      ) {
        return Promise.resolve([{ id: "p2", name: "gitweb" }]);
      }
      if (m === "GET" && p === "/environments/0/projects/p2/compose") {
        return Promise.resolve({
          success: true,
          data: {
            composeContent: "x",
            status: "running",
            gitOpsManagedBy: "sync:GitOps",
          },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let msg = "";
    try {
      await method("project_deploy").execute(
        {
          name: "gitweb",
          composeContent: "services: {}",
          rollback: true,
          healthTimeoutSec: 1,
          pollIntervalSec: 1,
        },
        context,
      );
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    assert(
      msg.includes("gitops-managed"),
      `should refuse inline content, got: ${msg}`,
    );
    assert(
      !calls.some((c) => c.method === "PUT" || c.path.endsWith("/redeploy")),
      "must not mutate the gitops-managed project",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

/** A rotation's Arcane: one service `db` using secret `db_pw`, whose update after the PUT is `afterPut`. */
function rotateTransport(calls: Call[], afterPut: Json | undefined) {
  let repointed = false;
  return (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
    calls.push({ method: m, path: p, body: b });
    if (m === "GET" && p === "/environments/0/swarm/status") {
      return Promise.resolve({ success: true, data: { enabled: true } });
    }
    if (m === "GET" && p === "/environments/0/swarm/secrets") {
      return Promise.resolve([{ id: "s1", spec: { Name: "db_pw" } }]);
    }
    if (m === "POST" && p === "/environments/0/swarm/secrets") {
      return Promise.resolve({ success: true, data: { id: "s2" } });
    }
    if (m === "GET" && p === "/environments/0/swarm/services?limit=-1") {
      return Promise.resolve([
        { id: "svc1", name: "db", replicas: 1, runningReplicas: 1 },
      ]);
    }
    if (m === "GET" && p === "/environments/0/swarm/services/svc1") {
      return Promise.resolve({
        success: true,
        data: {
          version: { Index: 42 },
          updateStatus: repointed ? afterPut : undefined,
          spec: {
            TaskTemplate: {
              ContainerSpec: {
                Secrets: [{ SecretID: "s1", SecretName: "db_pw" }],
              },
            },
          },
        },
      });
    }
    if (m === "PUT" && p === "/environments/0/swarm/services/svc1") {
      repointed = true;
      return Promise.resolve({ success: true, data: {} });
    }
    if (m === "DELETE" && p === "/environments/0/swarm/secrets/s1") {
      return Promise.resolve({ success: true, data: { message: "ok" } });
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

Deno.test("secret_rotate keeps the old secret while the service's update has not started", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(rotateTransport(calls, undefined));
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let message = "";
    try {
      await method("secret_rotate").execute(
        { name: "db_pw", value: "v", healthTimeoutSec: 1, pollIntervalSec: 1 },
        context,
      );
    } catch (e) {
      message = (e as Error).message;
    }
    assert(/not all services converged/.test(message), message);
    assert(
      !calls.some((c) => c.method === "DELETE"),
      "the old secret must not be deleted before the rolling update is seen",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("secret_rotate removes the old secret once the service's update completes", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(rotateTransport(calls, { State: "completed" }));
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("secret_rotate").execute(
      { name: "db_pw", value: "v", healthTimeoutSec: 5, pollIntervalSec: 1 },
      context,
    );
    assert(calls.some((c) => c.method === "DELETE"), "old secret removed");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("secret_rotate waits through a failed service read instead of calling it converged", async () => {
  const calls: Call[] = [];
  const base = rotateTransport(calls, { State: "completed" });
  let listReadsAfterPut = 0;
  __setArcaneTransport((g, m, p, b) => {
    const afterPut = calls.some((c) => c.method === "PUT");
    if (
      m === "GET" && p === "/environments/0/swarm/services?limit=-1" && afterPut
    ) {
      // The first summary read after the re-point fails; without the counts the
      // replica check must not pass.
      if (++listReadsAfterPut === 1) {
        calls.push({ method: m, path: p });
        return Promise.reject(
          new Error(`Arcane GET ${p} -> HTTP 502: bad gateway`),
        );
      }
    }
    return base(g, m, p, b);
  });
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("secret_rotate").execute(
      { name: "db_pw", value: "v", healthTimeoutSec: 5, pollIntervalSec: 1 },
      context,
    );
    assertEquals(listReadsAfterPut, 2, "polled again after the failed read");
    assert(calls.some((c) => c.method === "DELETE"), "old secret removed");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("secret_rotate: create v2 → re-point service (mount preserved) → remove v1", async () => {
  const calls: Call[] = [];
  let repointed = false;
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      if (m === "GET" && p === "/environments/0/swarm/secrets") {
        return Promise.resolve([{
          id: "s1",
          spec: { Name: "db_pw", Labels: { app: "db" } },
        }]);
      }
      if (m === "POST" && p === "/environments/0/swarm/secrets") {
        return Promise.resolve({ success: true, data: { id: "s2" } });
      }
      if (m === "GET" && p === "/environments/0/swarm/services?limit=-1") {
        return Promise.resolve([{
          id: "svc1",
          name: "db",
          replicas: 1,
          runningReplicas: 1,
        }]);
      }
      if (m === "GET" && p === "/environments/0/swarm/services/svc1") {
        return Promise.resolve({
          success: true,
          data: {
            version: { Index: 42 },
            updateStatus: repointed ? { State: "completed" } : undefined,
            spec: {
              TaskTemplate: {
                ContainerSpec: {
                  Secrets: [{
                    SecretID: "s1",
                    SecretName: "db_pw",
                    File: { Name: "db_pw" },
                  }],
                },
              },
            },
          },
        });
      }
      if (m === "PUT" && p === "/environments/0/swarm/services/svc1") {
        repointed = true;
        return Promise.resolve({ success: true, data: {} });
      }
      if (m === "DELETE" && p === "/environments/0/swarm/secrets/s1") {
        return Promise.resolve({ success: true, data: { message: "ok" } });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("secret_rotate").execute(
      {
        name: "db_pw",
        value: "s3cr3t",
        removeOld: true,
        healthTimeoutSec: 5,
        pollIntervalSec: 1,
      },
      context,
    );
    const createCall = calls.find((c) =>
      c.method === "POST" && c.path === "/environments/0/swarm/secrets"
    );
    assert(createCall, "new secret version created");
    assert(
      JSON.stringify(createCall!.body).includes(b64("s3cr3t")),
      "value base64-encoded into spec.Data",
    );
    const putCall = calls.find((c) =>
      c.method === "PUT" && c.path === "/environments/0/swarm/services/svc1"
    );
    assert(putCall, "service re-point PUT issued");
    const put = JSON.stringify(putCall!.body);
    assert(put.includes('"SecretID":"s2"'), "re-pointed to the new secret id");
    assert(
      put.includes('"SecretName":"db_pw-v'),
      "re-pointed to the new secret name",
    );
    assert(put.includes('"Name":"db_pw"'), "mount path (File.Name) preserved");
    assert(
      put.includes('"version":42'),
      "service version sent for optimistic update",
    );
    assert(
      calls.some((c) =>
        c.method === "DELETE" && c.path === "/environments/0/swarm/secrets/s1"
      ),
      "old secret removed after convergence",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

// --- swarm_stack_ section ---

Deno.test("renderNames extracts names from strings/objects, tolerates junk", () => {
  assertEquals(renderNames(["a", "b"]), ["a", "b"]);
  assertEquals(
    renderNames([{ name: "s1" }, { Name: "s2" }, { id: "s3" }]),
    ["s1", "s2", "s3"],
  );
  assertEquals(renderNames(["s", { name: "o" }]), ["s", "o"]);
  assertEquals(renderNames(null), []);
  assertEquals(renderNames(undefined), []);
  assertEquals(renderNames("not-an-array"), []);
  // unrecognized items (no name/Name/id, non-strings) are dropped
  assertEquals(renderNames([{ nope: 1 }, 42, null]), []);
});

Deno.test("swarmStackResource shapes a summary, degrades missing fields", () => {
  const r = swarmStackResource(
    {
      id: "abc",
      name: "unifi",
      namespace: "unifi",
      services: 2,
      createdAt: "t0",
      updatedAt: "t1",
    },
    "created",
  );
  assertEquals(r.id, "abc");
  assertEquals(r.name, "unifi");
  assertEquals(r.services, 2);
  assertEquals(r.action, "created");
  const r2 = swarmStackResource({}, "observed");
  assertEquals(r2.name, "unnamed");
  assertEquals(r2.services, undefined);
});

Deno.test("swarm_stack_validate renders and records services/warnings", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      if (m === "POST" && p === "/environments/0/swarm/stacks/config/render") {
        return Promise.resolve({
          success: true,
          data: {
            services: ["unifi", "unifi-db"],
            networks: ["unifi_net"],
            volumes: [],
            secrets: ["mongo_pass"],
            configs: ["init-mongo"],
            warnings: ["a warning"],
          },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("swarm_stack_validate").execute(
      { name: "unifi", composeContent: "services: {}" },
      context,
    );
    const r = written.find((w) => w.specName === "swarm-stack-render");
    assert(r, "render resource written");
    assertEquals(r!.name, "swarm-stack-render:unifi");
    assertEquals(r!.data.valid, true);
    assertEquals(r!.data.services, ["unifi", "unifi-db"]);
    assertEquals(r!.data.warnings, ["a warning"]);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_deploy fails closed: render error aborts before deploy", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      if (m === "POST" && p === "/environments/0/swarm/stacks/config/render") {
        return Promise.reject(
          new Error("Arcane POST -> HTTP 400: bad compose"),
        );
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let threw = false;
    try {
      await method("swarm_stack_deploy").execute(
        {
          name: "unifi",
          composeContent: "bad",
          prune: false,
          convergeTimeoutSec: 1,
          pollIntervalSec: 1,
        },
        context,
      );
    } catch {
      threw = true;
    }
    assert(threw, "deploy threw on render failure");
    assert(
      !calls.some((c) =>
        c.method === "POST" && c.path === "/environments/0/swarm/stacks"
      ),
      "deploy POST was NOT issued — the validation gate held",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_deploy: validate precedes deploy, then converges", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      if (m === "POST" && p === "/environments/0/swarm/stacks/config/render") {
        return Promise.resolve({
          success: true,
          data: { services: ["unifi", "unifi-db"], warnings: [] },
        });
      }
      if (m === "POST" && p === "/environments/0/swarm/stacks") {
        return Promise.resolve({ success: true, data: { name: "unifi" } });
      }
      if (
        m === "GET" &&
        p === "/environments/0/swarm/stacks/unifi/services?limit=-1"
      ) {
        return Promise.resolve({
          success: true,
          data: [
            { id: "a", name: "unifi_unifi", replicas: 1, runningReplicas: 1 },
            {
              id: "b",
              name: "unifi_unifi-db",
              replicas: 1,
              runningReplicas: 1,
            },
          ],
        });
      }
      // An updated service and an unchanged one, which swarm gives no status.
      if (m === "GET" && p === "/environments/0/swarm/services/a") {
        return Promise.resolve({
          success: true,
          data: { updateStatus: { State: "completed" } },
        });
      }
      if (m === "GET" && p === "/environments/0/swarm/services/b") {
        return Promise.resolve({ success: true, data: {} });
      }
      if (m === "GET" && p === "/environments/0/swarm/stacks/unifi") {
        return Promise.resolve({
          success: true,
          data: { name: "unifi", namespace: "unifi", services: 2 },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("swarm_stack_deploy").execute(
      {
        name: "unifi",
        composeContent: "services: {}",
        prune: false,
        convergeTimeoutSec: 5,
        pollIntervalSec: 1,
      },
      context,
    );
    const idxRender = calls.findIndex((c) => c.path.endsWith("/config/render"));
    const idxDeploy = calls.findIndex((c) =>
      c.method === "POST" && c.path === "/environments/0/swarm/stacks"
    );
    assert(idxRender >= 0 && idxDeploy > idxRender, "render precedes deploy");
    const conv = written.find((w) =>
      w.specName === "operation-result" &&
      w.data.operation === "swarm_stack_deploy:converge"
    );
    assert(conv && conv.data.success === true, "converge recorded success");
    assert(
      written.some((w) =>
        w.specName === "swarm-stack" && w.data.action === "created"
      ),
      "stack resource recorded as created",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_deploy waits long for the deploy and says a timeout may still be deploying", async () => {
  let deployTimeout: number | undefined;
  __setArcaneTransport((_g, m, p, _b, timeoutMs) => {
    if (m === "GET" && p === "/environments/0/swarm/status") {
      return Promise.resolve({ success: true, data: { enabled: true } });
    }
    if (m === "POST" && p === "/environments/0/swarm/stacks/config/render") {
      return Promise.resolve({ success: true, data: { services: ["web"] } });
    }
    if (m === "POST" && p === "/environments/0/swarm/stacks") {
      deployTimeout = timeoutMs;
      return Promise.reject(
        new Error(`request timed out after ${timeoutMs} ms`),
      );
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  });
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    let message = "";
    try {
      await method("swarm_stack_deploy").execute(
        {
          name: "web",
          composeContent: "services: {}",
          convergeTimeoutSec: 5,
          pollIntervalSec: 1,
        },
        context,
      );
    } catch (e) {
      message = (e as Error).message;
    }
    assertEquals(deployTimeout, 30 * 60_000);
    assert(/may still be running/.test(message), message);
    const deploy = written.find((w) =>
      w.data.operation === "swarm_stack_deploy:deploy"
    );
    assertEquals([deploy?.data.success, deploy?.data.status], [false, 0]);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_deploy surfaces non-convergence (no force)", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      if (m === "POST" && p === "/environments/0/swarm/stacks/config/render") {
        return Promise.resolve({
          success: true,
          data: { services: ["x"], warnings: [] },
        });
      }
      if (m === "POST" && p === "/environments/0/swarm/stacks") {
        return Promise.resolve({ success: true, data: { name: "x" } });
      }
      if (
        m === "GET" && p === "/environments/0/swarm/stacks/x/services?limit=-1"
      ) {
        return Promise.resolve({
          success: true,
          data: [{ id: "x1", name: "x_x", replicas: 1, runningReplicas: 0 }],
        });
      }
      if (m === "GET" && p === "/environments/0/swarm/services/x1") {
        return Promise.resolve({ success: true, data: {} });
      }
      if (m === "GET" && p === "/environments/0/swarm/stacks/x") {
        return Promise.resolve({ success: true, data: { name: "x" } });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    let threw = false;
    try {
      await method("swarm_stack_deploy").execute(
        {
          name: "x",
          composeContent: "c",
          prune: false,
          convergeTimeoutSec: 1,
          pollIntervalSec: 1,
        },
        context,
      );
    } catch {
      threw = true;
    }
    assert(threw, "non-convergence throws");
    const conv = written.find((w) =>
      w.specName === "operation-result" &&
      w.data.operation === "swarm_stack_deploy:converge"
    );
    assert(conv && conv.data.success === false, "converge recorded failure");
  } finally {
    __setArcaneTransport(null);
  }
});

/** A redeploy of stack `x` whose one service has its old tasks running and the given update status. */
function stackUpdateTransport(updateStatus: Json, calls: Call[] = []) {
  return (_g: unknown, m: string, p: string): Promise<unknown> => {
    calls.push({ method: m, path: p });
    if (m === "GET" && p === "/environments/0/swarm/status") {
      return Promise.resolve({ success: true, data: { enabled: true } });
    }
    if (m === "POST" && p === "/environments/0/swarm/stacks/config/render") {
      return Promise.resolve({ success: true, data: { services: ["x"] } });
    }
    if (m === "POST" && p === "/environments/0/swarm/stacks") {
      return Promise.resolve({ success: true, data: { name: "x" } });
    }
    if (
      m === "GET" && p === "/environments/0/swarm/stacks/x/services?limit=-1"
    ) {
      return Promise.resolve([
        { id: "x1", name: "x_x", replicas: 2, runningReplicas: 2 },
      ]);
    }
    if (m === "GET" && p === "/environments/0/swarm/services/x1") {
      return Promise.resolve({ success: true, data: { updateStatus } });
    }
    if (m === "GET" && p === "/environments/0/swarm/stacks/x") {
      return Promise.resolve({ success: true, data: { name: "x" } });
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

async function stackDeployError(): Promise<string> {
  const { context } = makeContext(TEST_GLOBALS);
  try {
    await method("swarm_stack_deploy").execute(
      { name: "x", composeContent: "c", convergeTimeoutSec: 1 },
      context,
    );
  } catch (e) {
    return (e as Error).message;
  }
  return "";
}

Deno.test("swarm_stack_deploy does not pass an update still rolling on the old tasks", async () => {
  __setArcaneTransport(stackUpdateTransport({ State: "updating" }));
  try {
    const message = await stackDeployError();
    assert(/did not converge.*update=updating/.test(message), message);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_deploy fails at once on an update swarm rolled back", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    stackUpdateTransport({ State: "rollback_completed" }, calls),
  );
  try {
    const message = await stackDeployError();
    assert(/update=rollback_completed/.test(message), message);
    assertEquals(
      calls.filter((c) => c.path.endsWith("/services?limit=-1")).length,
      1,
      "no further polling after a rollback",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_deploy waits before its first look at the services", async () => {
  // Straight after the deploy swarm has not yet set the update status.
  const started = Date.now();
  __setArcaneTransport(stackUpdateTransport({ State: "completed" }));
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("swarm_stack_deploy").execute(
      { name: "x", composeContent: "c", pollIntervalSec: 1 },
      context,
    );
    assert(Date.now() - started >= 900, "first poll waited one interval");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_remove is idempotent on 404", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      // Already gone: the DELETE 404s, and so does the confirming GET poll.
      if (
        (m === "DELETE" || m === "GET") &&
        p === "/environments/0/swarm/stacks/gone"
      ) {
        return Promise.reject(new Error(`Arcane ${m} -> HTTP 404: not found`));
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("swarm_stack_remove").execute({ name: "gone" }, context);
    assert(
      written.some((w) =>
        w.specName === "swarm-stack" && w.data.action === "deleted"
      ),
      "records deleted even when already gone",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_remove re-issues DELETE until the record clears", async () => {
  const calls: Call[] = [];
  let deletes = 0;
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, body?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body });
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      if (m === "DELETE" && p === "/environments/0/swarm/stacks/two") {
        deletes++;
        return Promise.resolve({ success: true });
      }
      if (m === "GET" && p === "/environments/0/swarm/stacks/two") {
        // The record outlives the first DELETE; only the second clears it.
        if (deletes >= 2) {
          return Promise.reject(new Error("Arcane GET -> HTTP 404: not found"));
        }
        return Promise.resolve({
          success: true,
          data: { name: "two", services: 0 },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("swarm_stack_remove").execute(
      { name: "two", pollIntervalSec: 1, removeTimeoutSec: 5 },
      context,
    );
    const stackDeletes = calls.filter((c) =>
      c.method === "DELETE" && c.path === "/environments/0/swarm/stacks/two"
    ).length;
    assertEquals(stackDeletes, 2, "issues a second DELETE to clear the record");
    const rec = written.find((w) =>
      w.specName === "swarm-stack"
    );
    assert(rec, "records the removed stack");
    assertEquals(rec!.data.action, "deleted");
    assertEquals(rec!.data.deletes, 2);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_remove throws if the record never clears within the deadline", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      // DELETE succeeds but the record never disappears: must not loop forever
      // and must not report success.
      if (m === "DELETE" && p === "/environments/0/swarm/stacks/stuck") {
        return Promise.resolve({ success: true });
      }
      if (m === "GET" && p === "/environments/0/swarm/stacks/stuck") {
        return Promise.resolve({ success: true, data: { name: "stuck" } });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let threw = false;
    try {
      await method("swarm_stack_remove").execute(
        { name: "stuck", pollIntervalSec: 1, removeTimeoutSec: 1 },
        context,
      );
    } catch (e) {
      threw = true;
      assert(
        e instanceof Error && /still present/.test(e.message),
        "surfaces the un-cleared record",
      );
    }
    assert(threw, "throws rather than reporting a phantom success");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarmTaskResource surfaces state + error", () => {
  const r = swarmTaskResource({
    id: "t1",
    serviceName: "unifi_unifi",
    slot: 1,
    nodeName: "host-a",
    desiredState: "ready",
    currentState: "rejected",
    error: "bind source path does not exist: /srv/app",
  });
  assertEquals(r.serviceName, "unifi_unifi");
  assertEquals(r.currentState, "rejected");
  assertEquals(r.error, "bind source path does not exist: /srv/app");
});

Deno.test("swarm_stack_tasks: factory + onlyProblems filter", async () => {
  const wire = () =>
    __setArcaneTransport(
      (_g: unknown, m: string, p: string): Promise<unknown> => {
        if (m === "GET" && p === "/environments/0/swarm/status") {
          return Promise.resolve({ success: true, data: { enabled: true } });
        }
        if (
          m === "GET" &&
          p === "/environments/0/swarm/stacks/unifi/tasks?limit=-1"
        ) {
          return Promise.resolve({
            success: true,
            data: [
              {
                id: "ok1",
                serviceName: "unifi_unifi-db",
                currentState: "running",
              },
              {
                id: "bad1",
                serviceName: "unifi_unifi",
                currentState: "rejected",
                error: "no /srv/app",
              },
              {
                id: "old1",
                serviceName: "unifi_unifi",
                currentState: "shutdown",
              },
            ],
          });
        }
        return Promise.reject(new Error(`unexpected ${m} ${p}`));
      },
    );
  wire();
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("swarm_stack_tasks").execute(
      { name: "unifi", onlyProblems: false },
      context,
    );
    assertEquals(written.length, 3);
    assert(
      written.some((w) => w.data.error === "no /srv/app"),
      "error is surfaced on the rejected task",
    );
  } finally {
    __setArcaneTransport(null);
  }
  wire();
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("swarm_stack_tasks").execute(
      { name: "unifi", onlyProblems: true },
      context,
    );
    assertEquals(written.length, 1);
    assertEquals(written[0].data.currentState, "rejected");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_service_force_update bumps ForceUpdate + PUTs with version", async () => {
  const calls: Call[] = [];
  let updated = false;
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "GET" && p === "/environments/0/swarm/status") {
        return Promise.resolve({ success: true, data: { enabled: true } });
      }
      if (m === "GET" && p === "/environments/0/swarm/services?limit=-1") {
        return Promise.resolve([{
          id: "svc1",
          name: "unifi_unifi",
          spec: { Name: "unifi_unifi" },
          replicas: 1,
          runningReplicas: 1,
        }]);
      }
      if (m === "GET" && p === "/environments/0/swarm/services/svc1") {
        return Promise.resolve({
          success: true,
          data: {
            spec: {
              Name: "unifi_unifi",
              TaskTemplate: { ForceUpdate: 2, ContainerSpec: {} },
            },
            version: { Index: 7 },
            updateStatus: updated ? { State: "completed" } : undefined,
          },
        });
      }
      if (m === "PUT" && p === "/environments/0/swarm/services/svc1") {
        updated = true;
        return Promise.resolve({ success: true, data: {} });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("swarm_service_force_update").execute(
      { name: "unifi_unifi", convergeTimeoutSec: 5, pollIntervalSec: 1 },
      context,
    );
    const put = calls.find((c) =>
      c.method === "PUT" && c.path === "/environments/0/swarm/services/svc1"
    );
    assert(put, "PUT issued");
    const body = bodyOf(put!);
    assertEquals(body.version, 7, "service version sent");
    const tt = (body.spec as Record<string, unknown>).TaskTemplate as Record<
      string,
      unknown
    >;
    assertEquals(tt.ForceUpdate, 3, "ForceUpdate bumped 2 -> 3");
    assert(
      written.some((w) =>
        w.specName === "operation-result" && w.data.success === true
      ),
      "force-update recorded success",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("volumeResource + pruneResult shape outputs", () => {
  const v = volumeResource(
    { name: "unifi_dbdata", driver: "local", inUse: false, size: 123 },
    "observed",
  );
  assertEquals(v.name, "unifi_dbdata");
  assertEquals(v.inUse, false);
  assertEquals(v.action, "observed");
  const p = pruneResult("volumes", {
    spaceReclaimed: 2048,
    volumesDeleted: ["unifi_dbdata", "unifi_dbdata2"],
  });
  assertEquals(p.scope, "volumes");
  assertEquals(p.spaceReclaimed, 2048);
  assertEquals(p.deleted, ["unifi_dbdata", "unifi_dbdata2"]);
  assertEquals(p.itemsDeleted, 2);
  // image delete entries are objects ({Untagged}/{Deleted})
  const pi = pruneResult("images", {
    imagesDeleted: [{ Untagged: "img:tag" }, { Deleted: "sha256:abc" }],
  });
  assertEquals(pi.deleted, ["img:tag", "sha256:abc"]);
});

// Arcane answers both cases with a 500 carrying Docker's message.
Deno.test("volume_remove: a gone volume counts as removed, an in-use one is surfaced", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "DELETE" && p.startsWith("/environments/0/volumes/gone")) {
        return Promise.reject(
          new Error("Arcane DELETE -> HTTP 500: no such volume"),
        );
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("volume_remove").execute(
      { name: "gone" },
      context,
    );
    assert(
      written.some((w) =>
        w.specName === "volume" && w.data.action === "deleted"
      ),
      "no such volume treated as already deleted",
    );
  } finally {
    __setArcaneTransport(null);
  }
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "DELETE" && p.startsWith("/environments/0/volumes/busy")) {
        return Promise.reject(
          new Error("Arcane DELETE -> HTTP 500: ... volume is in use - [abc]"),
        );
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let surfaced = false;
    try {
      await method("volume_remove").execute(
        { name: "busy" },
        context,
      );
    } catch (e) {
      surfaced = e instanceof Error && /in use/.test(e.message);
    }
    assert(surfaced, "in-use surfaced as a clear error (not forced)");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("image_prune sends dangling flag + records result", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "POST" && p === "/environments/0/images/prune") {
        return Promise.resolve({
          success: true,
          data: {
            spaceReclaimed: 500,
            imagesDeleted: [{ Deleted: "sha256:z" }],
          },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("image_prune").execute({ dangling: false }, context);
    const call = calls.find((c) => c.path === "/environments/0/images/prune");
    assertEquals(bodyOf(call!).dangling, false);
    const r = written.find((w) => w.specName === "prune-result");
    assertEquals(r!.data.scope, "images");
    assertEquals(r!.data.spaceReclaimed, 500);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("version reads the flat /version body (no envelope) into arcane-version", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "GET" && p === "/version") {
        // /version returns the body directly — no {success,data} envelope (v1 and v2)
        return Promise.resolve({
          currentVersion: "v1.19.4",
          newestVersion: "v2.0.3",
          updateAvailable: true,
          releaseUrl:
            "https://github.com/getarcaneapp/arcane/releases/tag/v2.0.3",
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("version").execute({}, context);
    const r = written.find((w) => w.specName === "arcane-version");
    assert(r, "arcane-version resource written");
    assertEquals(r!.name, "arcane-version");
    assertEquals(r!.data.currentVersion, "v1.19.4");
    assertEquals(r!.data.newestVersion, "v2.0.3");
    assertEquals(r!.data.updateAvailable, true);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_status fans out over all syncs and surfaces the failing one", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "GET" && p === "/environments/0/gitops-syncs?limit=-1") {
        return Promise.resolve({
          success: true,
          data: [{ id: "s1", name: "web" }, { id: "s2", name: "db" }],
        });
      }
      if (m === "GET" && p === "/environments/0/gitops-syncs/s1/status") {
        return Promise.resolve({
          success: true,
          data: {
            id: "s1",
            autoSync: true,
            lastSyncAt: "2026-06-12T10:00:00Z",
            lastSyncStatus: "success",
            lastSyncCommit: "abc1234",
            nextSyncAt: "2026-06-12T10:05:00Z",
          },
        });
      }
      if (m === "GET" && p === "/environments/0/gitops-syncs/s2/status") {
        return Promise.resolve({
          success: true,
          data: {
            id: "s2",
            autoSync: true,
            lastSyncAt: "2026-06-12T10:01:00Z",
            lastSyncStatus: "failed",
            lastSyncError: "invalid compose file: env file not found",
          },
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("gitops_sync_status").execute({ names: [] }, context);
    const statuses = written.filter((w) => w.specName === "sync-status");
    assertEquals(statuses.length, 2);
    const web = statuses.find((w) => w.name === "sync-status:web");
    assertEquals(web!.data.lastSyncStatus, "success");
    assertEquals(web!.data.lastSyncCommit, "abc1234");
    assertEquals(web!.data.lastSyncError, undefined);
    const db = statuses.find((w) => w.name === "sync-status:db");
    assertEquals(db!.data.lastSyncStatus, "failed");
    assertEquals(
      db!.data.lastSyncError,
      "invalid compose file: env file not found",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_status names a missing sync instead of silently skipping it", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "GET" && p === "/environments/0/gitops-syncs?limit=-1") {
        return Promise.resolve({
          success: true,
          data: [{ id: "s1", name: "web" }],
        });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let message = "";
    try {
      await method("gitops_sync_status").execute(
        { names: ["web", "ghost"] },
        context,
      );
    } catch (e) {
      message = e instanceof Error ? e.message : String(e);
    }
    assert(
      message.includes("ghost"),
      "error names the missing sync",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

// ─────────────────────────── reachable check ───────────────────────────

Deno.test("reachable check: a definition that fails the schema fails without probing", async () => {
  let called = false;
  __setArcaneTransport(() => {
    called = true;
    throw new Error("should not be called");
  });
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: { baseUrl: "https://arcane.example:8443" },
    });
    assertEquals(res.pass, false);
    assert(!called, "must not probe with an invalid definition");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("reachable check: fails with errors when the probe throws", async () => {
  __setArcaneTransport(() => {
    throw new Error("connection refused");
  });
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
        baseUrl: "https://arcane.example:8443",
        apiKey: "real-key",
      },
    });
    assertEquals(res.pass, false);
    assert(
      (res.errors ?? []).some((e) => /connection refused/.test(e)),
      "should surface the cause",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("reachable check: probes an authenticated endpoint and applies the schema defaults", async () => {
  const paths: string[] = [];
  let seen: Record<string, unknown> = {};
  __setArcaneTransport((g, _method, path) => {
    seen = g;
    paths.push(path);
    return Promise.resolve({ success: true, data: { id: "u1" } });
  });
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    // A hand-edited definition can omit the defaulted settings; the check
    // must still get them.
    const res = await checks.reachable.execute({
      globalArgs: {
        baseUrl: "https://arcane.example:8443",
        apiKey: "real-key",
      },
    });
    assertEquals(res.pass, true);
    // /version has no auth upstream, so a wrong key would pass it.
    assertEquals(paths, ["/auth/me"], "probes an endpoint that needs the key");
    assertEquals(seen.skipTlsVerify, false);
    assertEquals(seen.environmentId, "0");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("reachable check: a rejected key fails rather than passing", async () => {
  __setArcaneTransport(() => {
    throw new Error(
      "Arcane GET /auth/me -> HTTP 401: Invalid or expired API key",
    );
  });
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
      globalArgs: { baseUrl: "https://arcane.example:8443", apiKey: "wrong" },
    });
    assertEquals(res.pass, false);
    assert((res.errors ?? []).some((e) => /HTTP 401/.test(e)));
  } finally {
    __setArcaneTransport(null);
  }
});

// ─────────────────────────── streaming lifecycle ───────────────────────────

Deno.test("streamFailure: an error line fails, a done line passes, neither means cut short", () => {
  assertEquals(
    streamFailure(
      '{"type":"activity","activityId":"a1"}\n{"log":"pulling"}\n{"error":"service web: image not found"}\n',
    ),
    "service web: image not found",
  );
  assertEquals(
    streamFailure('{"type":"activity","activityId":"a1"}\n{"done":true}\n'),
    undefined,
  );
  const cutShort = /ended without Arcane's done line/;
  assert(
    cutShort.test(
      streamFailure('{"type":"activity","activityId":"a1"}\n') ?? "",
    ),
  );
  // a single-line body arrives already parsed
  assertEquals(streamFailure({ error: "boom" }), "boom");
  assertEquals(streamFailure({ done: true }), undefined);
  assert(cutShort.test(streamFailure(null) ?? ""));
  assert(cutShort.test(streamFailure("not json at all") ?? ""));
});

for (
  const [name, suffix] of [
    ["project_up", "/up"],
    ["project_pull", "/pull"],
    ["project_redeploy", "/redeploy"],
  ]
) {
  Deno.test(`${name}: an error line in the 200 body fails the method`, async () => {
    __setArcaneTransport(
      (_g: unknown, m: string, p: string): Promise<unknown> => {
        if (
          m === "GET" && p === "/environments/0/projects?limit=-1&archived=all"
        ) {
          return Promise.resolve({
            success: true,
            data: [{ id: "p1", name: "web" }],
          });
        }
        if (m === "POST" && p === `/environments/0/projects/p1${suffix}`) {
          // Arcane streams: status 200, then the failure as a body line.
          return Promise.resolve(
            '{"type":"activity","id":"a1"}\n{"error":"pull access denied for ghcr.io/x/y"}\n',
          );
        }
        return Promise.reject(new Error(`unexpected ${m} ${p}`));
      },
    );
    try {
      const { context, written } = makeContext(TEST_GLOBALS);
      let message = "";
      try {
        await method(name).execute({ names: ["web"] }, context);
      } catch (e) {
        message = e instanceof Error ? e.message : String(e);
      }
      assert(/web/.test(message), "names the project");
      assert(/pull access denied/.test(message), "carries Arcane's error");
      assertEquals(
        written.filter((w) => w.specName === "operation-result").length,
        0,
        "no success recorded",
      );
    } finally {
      __setArcaneTransport(null);
    }
  });

  Deno.test(`${name}: a clean streamed body records success`, async () => {
    __setArcaneTransport(
      (_g: unknown, m: string, p: string): Promise<unknown> => {
        if (
          m === "GET" && p === "/environments/0/projects?limit=-1&archived=all"
        ) {
          return Promise.resolve({
            success: true,
            data: [{ id: "p1", name: "web" }],
          });
        }
        if (m === "POST" && p === `/environments/0/projects/p1${suffix}`) {
          return Promise.resolve(
            '{"type":"activity","id":"a1"}\n{"log":"Container web Started"}\n{"done":true}\n',
          );
        }
        return Promise.reject(new Error(`unexpected ${m} ${p}`));
      },
    );
    try {
      const { context, written } = makeContext(TEST_GLOBALS);
      await method(name).execute({ names: ["web"] }, context);
      const r = written.find((w) => w.specName === "operation-result");
      assert(r, "operation-result written");
      assertEquals(r!.data.success, true);
    } finally {
      __setArcaneTransport(null);
    }
  });
}

// ─────────────────────────── gitops ensure methods ───────────────────────────

Deno.test("globalArgs schema accepts Arcane's enum values and rejects the old ones", () => {
  const base = { baseUrl: "https://a", apiKey: "k" };
  const repo = (authType: string) =>
    model.globalArguments.safeParse({
      ...base,
      repository: { name: "r", url: "u", authType },
    }).success;
  assertEquals(repo("http"), true);
  assertEquals(repo("ssh"), true);
  assertEquals(repo("none"), true);
  assertEquals(
    repo("token"),
    false,
    "Arcane rejects token (oneof=none http ssh)",
  );
  const sync = (targetType: string) =>
    model.globalArguments.safeParse({
      ...base,
      syncs: [{ name: "s", composePath: "c.yaml", targetType }],
    }).success;
  assertEquals(sync("project"), true);
  assertEquals(sync("swarm_stack"), true);
  assertEquals(sync("swarm"), false, "Arcane's value is swarm_stack");
});

Deno.test("gitops_repo_ensure: an existing connection keeps authType and enabled when the spec omits them", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, body?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body });
      if (m === "GET" && p === "/customize/git-repositories?limit=-1") {
        return Promise.resolve({
          success: true,
          data: [{
            id: "r1",
            name: "gitops",
            url: "git@h:me/gitops.git",
            authType: "ssh",
            enabled: false,
            description: "set in the UI",
          }],
        });
      }
      if (m === "PUT" && p === "/customize/git-repositories/r1") {
        return Promise.resolve({ success: true, data: { id: "r1" } });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext({
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "git@h:me/gitops.git" },
    });
    await method("gitops_repo_ensure").execute({}, context);
    const put = calls.find((c) => c.method === "PUT")!;
    assertEquals(
      bodyOf(put),
      { name: "gitops", url: "git@h:me/gitops.git" },
      "only what was passed is sent",
    );
    const r = written.find((w) => w.specName === "repository")!;
    assertEquals(r.data.action, "updated");
    assertEquals(r.data.authType, "ssh", "reports the kept auth type");
    assertEquals(r.data.enabled, false, "reports the kept state");
    assertEquals(r.data.description, "set in the UI");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_repo_ensure: a new connection gets authType none and enabled true", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, body?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body });
      if (m === "GET" && p === "/customize/git-repositories?limit=-1") {
        return Promise.resolve({ success: true, data: [] });
      }
      if (m === "POST" && p === "/customize/git-repositories") {
        return Promise.resolve({ success: true, data: { id: "r9" } });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext({
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "https://h/me/gitops.git" },
    });
    await method("gitops_repo_ensure").execute({}, context);
    const post = calls.find((c) => c.method === "POST")!;
    assertEquals(bodyOf(post).authType, "none");
    assertEquals(bodyOf(post).enabled, true);
    const r = written.find((w) => w.specName === "repository")!;
    assertEquals(r.data.action, "created");
    assertEquals(r.data.id, "r9");
    assertEquals(r.data.authType, "none");
    assertEquals(r.data.enabled, true);
  } finally {
    __setArcaneTransport(null);
  }
});

function syncServer(existing: Record<string, unknown>[]) {
  const calls: Call[] = [];
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, body?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body });
      if (m === "GET" && p === "/customize/git-repositories?limit=-1") {
        return Promise.resolve({
          success: true,
          data: [{ id: "r1", name: "gitops" }],
        });
      }
      if (m === "GET" && p === "/environments/0/gitops-syncs?limit=-1") {
        return Promise.resolve({ success: true, data: existing });
      }
      if (m === "PUT" && p.startsWith("/environments/0/gitops-syncs/")) {
        return Promise.resolve({ success: true, data: { id: "s1" } });
      }
      if (m === "POST" && p === "/environments/0/gitops-syncs") {
        return Promise.resolve({ success: true, data: { id: "s2" } });
      }
      if (m === "DELETE" && p.startsWith("/environments/0/gitops-syncs/")) {
        return Promise.resolve({ success: true });
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  return calls;
}

const UI_TUNED_SYNC = {
  id: "s1",
  name: "web",
  branch: "release",
  composePath: "projects/web/compose.yaml",
  repositoryId: "r1",
  projectName: "web",
  autoSync: false,
  syncInterval: 15,
  syncDirectory: false,
  targetType: "swarm_stack",
};

Deno.test("gitops_sync_ensure: settings the spec omits are not drift and are not reset", async () => {
  const calls = syncServer([UI_TUNED_SYNC]);
  try {
    const { context, written } = makeContext({
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "u" },
      syncs: [{ name: "web", composePath: "projects/web/compose.yaml" }],
    });
    await method("gitops_sync_ensure").execute({ prune: false }, context);
    assertEquals(
      calls.filter((c) => c.method === "PUT").length,
      0,
      "a UI-tuned sync is left alone",
    );
    const r = written.find((w) => w.specName === "sync")!;
    assertEquals(r.data.action, "unchanged");
    assertEquals(r.data.syncInterval, 15, "reports the server's interval");
    assertEquals(r.data.branch, "release");
    assertEquals(r.data.targetType, "swarm_stack");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_ensure: a passed setting that differs is updated on its own", async () => {
  const calls = syncServer([UI_TUNED_SYNC]);
  try {
    const { context, written } = makeContext({
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "u" },
      syncs: [{
        name: "web",
        composePath: "projects/web/compose.yaml",
        branch: "main",
      }],
    });
    await method("gitops_sync_ensure").execute({ prune: false }, context);
    const put = calls.find((c) => c.method === "PUT")!;
    assert(put, "drift on a passed field is written");
    assertEquals(bodyOf(put).branch, "main");
    assertEquals(
      bodyOf(put).syncInterval,
      undefined,
      "omitted fields stay out",
    );
    assertEquals(bodyOf(put).autoSync, undefined);
    assertEquals(bodyOf(put).targetType, undefined);
    const r = written.find((w) => w.specName === "sync")!;
    assertEquals(r.data.action, "updated");
    assertEquals(r.data.branch, "main");
    assertEquals(r.data.syncInterval, 15);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_ensure: a new sync gets the create defaults", async () => {
  const calls = syncServer([]);
  try {
    const { context, written } = makeContext({
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "u" },
      syncs: [{ name: "web", composePath: "projects/web/compose.yaml" }],
    });
    await method("gitops_sync_ensure").execute({ prune: false }, context);
    const post = calls.find((c) => c.method === "POST")!;
    assertEquals(bodyOf(post), {
      branch: "main",
      autoSync: true,
      syncInterval: 5,
      syncDirectory: true,
      targetType: "project",
      name: "web",
      composePath: "projects/web/compose.yaml",
      repositoryId: "r1",
      projectName: "web",
    });
    const r = written.find((w) => w.specName === "sync")!;
    assertEquals(r.data.action, "created");
    assertEquals(r.data.id, "s2");
    assertEquals(r.data.targetType, "project");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("volume_list asks Arcane for every volume, not the first page", async () => {
  const paths: string[] = [];
  __setArcaneTransport((_g, _m, p) => {
    paths.push(p);
    return Promise.resolve({ success: true, data: [{ name: "v1" }] });
  });
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("volume_list").execute({}, context);
    assertEquals(paths, ["/environments/0/volumes?limit=-1"]);
    assertEquals(written.length, 1);
  } finally {
    __setArcaneTransport(null);
  }
});

// ─────────────────────────── volume_remove ───────────────────────────

// Arcane wraps every delete failure as a 500 carrying Docker's message.
Deno.test("volume_remove: a volume that is already gone counts as removed", async () => {
  __setArcaneTransport(() => {
    throw new Error(
      "Arcane DELETE /volumes/v1 -> HTTP 500: failed to remove volume: get v1: no such volume",
    );
  });
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("volume_remove").execute({ name: "v1" }, context);
    assertEquals(written[0].data.action, "deleted");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("volume_remove: an in-use volume is refused, not forced", async () => {
  const paths: string[] = [];
  __setArcaneTransport((_g, _m, p) => {
    paths.push(p);
    throw new Error(
      "Arcane DELETE /volumes/v1 -> HTTP 500: failed to remove volume: volume is in use",
    );
  });
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let message = "";
    try {
      await method("volume_remove").execute({ name: "v1" }, context);
    } catch (e) {
      message = (e as Error).message;
    }
    assert(/is in use, so it was not removed/.test(message), message);
    assertEquals(paths, ["/environments/0/volumes/v1"], "no force=true");
  } finally {
    __setArcaneTransport(null);
  }
});

// Docker refuses an in-use volume whatever `force` says, so the argument was
// removed. A definition that still passes it must not reach Arcane as a flag.
Deno.test("volume_remove: has no force argument and never sends force=true", async () => {
  const paths: string[] = [];
  __setArcaneTransport((_g, _m, p) => {
    paths.push(p);
    return Promise.resolve({ success: true });
  });
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("volume_remove").execute({ name: "v1", force: true }, context);
    assertEquals(paths, ["/environments/0/volumes/v1"]);
    const shape = (model.methods as unknown as Record<string, {
      arguments: { shape: Record<string, unknown> };
    }>).volume_remove.arguments.shape;
    assertEquals(Object.keys(shape), ["name"]);
  } finally {
    __setArcaneTransport(null);
  }
});

// ─────────────────────────── timeouts and validation ───────────────────────────

Deno.test("redeploy and lifecycle calls get the long timeout; reads keep the short one", async () => {
  const timeouts: Record<string, number | undefined> = {};
  __setArcaneTransport((_g, m, p, _b, timeoutMs) => {
    timeouts[`${m} ${p}`] = timeoutMs;
    if (p.endsWith("/projects?limit=-1&archived=all")) {
      return Promise.resolve([{ id: "p1", name: "web" }]);
    }
    return Promise.resolve(STREAM_DONE);
  });
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("project_redeploy").execute({ names: ["web"] }, context);
    assertEquals(
      timeouts["GET /environments/0/projects?limit=-1&archived=all"],
      30_000,
    );
    assertEquals(
      timeouts["POST /environments/0/projects/p1/redeploy"],
      30 * 60_000,
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_create always validates; validate:false is not an option", async () => {
  let validated = false;
  __setComposeValidator(() => {
    validated = true;
    return Promise.resolve({ version: "v2.test" });
  });
  __setArcaneTransport(() => Promise.resolve({ data: { id: "p1" } }));
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("project_create").execute(
      { name: "web", composeContent: "services: {}\n", validate: false },
      context,
    );
    assert(validated, "the compose file must be validated");
  } finally {
    __setComposeValidator(null);
    __setArcaneTransport(null);
  }
});

Deno.test("project_restart uses Arcane's restart for each project", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      calls.push({ method: m, path: p });
      if (
        m === "GET" && p === "/environments/0/projects?limit=-1&archived=all"
      ) {
        return Promise.resolve({
          success: true,
          data: [{ id: "p1", name: "web" }],
        });
      }
      return Promise.resolve({
        success: true,
        data: { message: "Project restarted" },
      });
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("project_restart").execute({ names: ["web"] }, context);
    assertEquals(
      calls.filter((c) => c.method === "POST").map((c) => c.path),
      ["/environments/0/projects/p1/restart"],
    );
    assertEquals(
      written.filter((w) => w.specName === "operation-result").length,
      1,
    );
  } finally {
    __setArcaneTransport(null);
  }
});

/** A project_deploy update of `web` (id p1), with the redeploy and runtime answers supplied. */
function deployTransport(
  redeploy: (timeoutMs?: number) => Promise<unknown>,
  health: string | Error,
  calls: Call[] = [],
) {
  return (
    _g: unknown,
    m: string,
    p: string,
    _b?: unknown,
    timeoutMs?: number,
  ): Promise<unknown> => {
    calls.push({ method: m, path: p });
    if (m === "GET" && p === "/environments/0/projects?limit=-1&archived=all") {
      return Promise.resolve([{ id: "p1", name: "web" }]);
    }
    if (m === "GET" && p === "/environments/0/projects/p1/compose") {
      return Promise.resolve({
        success: true,
        data: { composeContent: "PRIOR", status: "running" },
      });
    }
    if (m === "PUT" && p === "/environments/0/projects/p1") {
      return Promise.resolve({ success: true, data: {} });
    }
    if (m === "POST" && p === "/environments/0/projects/p1/redeploy") {
      return redeploy(timeoutMs);
    }
    if (m === "GET" && p === "/environments/0/projects/p1") {
      return Promise.resolve({
        success: true,
        data: { status: "running", serviceCount: 1, runningCount: 1 },
      });
    }
    if (m === "GET" && p === "/environments/0/projects/p1/runtime") {
      if (health instanceof Error) return Promise.reject(health);
      return Promise.resolve({
        success: true,
        data: { runtimeServices: [{ health }] },
      });
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

async function deployError(rollback = false): Promise<string> {
  const { context } = makeContext(TEST_GLOBALS);
  try {
    await method("project_deploy").execute(
      {
        name: "web",
        composeContent: "NEW",
        rollback,
        healthTimeoutSec: 1,
        pollIntervalSec: 1,
      },
      context,
    );
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
  return "";
}

Deno.test("project_deploy does not pass a service whose healthcheck is still starting", async () => {
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    deployTransport(() => Promise.resolve(STREAM_DONE), "starting"),
  );
  try {
    const message = await deployError();
    assert(/health: starting/.test(message), `got: ${message}`);
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy bounds the redeploy call by healthTimeoutSec", async () => {
  let redeployTimeout: number | undefined;
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    deployTransport((timeoutMs) => {
      redeployTimeout = timeoutMs;
      return Promise.reject(
        new Error(`request timed out after ${timeoutMs} ms`),
      );
    }, "healthy"),
  );
  try {
    const message = await deployError();
    assertEquals(redeployTimeout, 1000);
    assert(
      /redeploy did not finish within healthTimeoutSec \(1s\)/.test(message),
      `got: ${message}`,
    );
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy fails on an error line in the redeploy's 200 body", async () => {
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    deployTransport(
      () =>
        Promise.resolve(
          '{"type":"activity","id":"a1"}\n{"error":"pull access denied for ghcr.io/x/y"}\n',
        ),
      "healthy",
    ),
  );
  try {
    const message = await deployError();
    assert(
      /redeploy failed: pull access denied/.test(message),
      `got: ${message}`,
    );
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("the 2026.10.11.1 upgrade maps the retired authType and targetType values", () => {
  const upgrade = model.upgrades.find((u) => u.toVersion === "2026.10.11.1")!;
  const out = upgrade.upgradeAttributes({
    baseUrl: "https://arcane.example.com",
    repository: { name: "r", url: "u", authType: "token" },
    syncs: [
      { name: "a", composePath: "a.yaml", targetType: "swarm" },
      { name: "b", composePath: "b.yaml", targetType: "project" },
      { name: "c", composePath: "c.yaml" },
    ],
  });
  assertEquals((out.repository as Json).authType, "http");
  assertEquals(
    (out.syncs as Json[]).map((s) => s.targetType),
    ["project", "project", undefined],
  );
  assertEquals(out.baseUrl, "https://arcane.example.com");
  assertEquals(upgrade.upgradeAttributes({ baseUrl: "x" }), { baseUrl: "x" });
});

Deno.test("project_deploy refuses a zero healthTimeoutSec, which would switch the timeout off", () => {
  const schema = (model.methods as unknown as Record<string, {
    arguments: { safeParse: (v: unknown) => { success: boolean } };
  }>).project_deploy.arguments;
  assertEquals(
    schema.safeParse({ name: "web", healthTimeoutSec: 0 }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ name: "web", healthTimeoutSec: 30 }).success,
    true,
  );
});

Deno.test("project_deploy does not roll back on top of a redeploy that timed out", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    deployTransport(
      (timeoutMs) =>
        Promise.reject(new Error(`request timed out after ${timeoutMs} ms`)),
      "healthy",
      calls,
    ),
  );
  try {
    const message = await deployError(true);
    assert(/no rollback attempted/.test(message), `got: ${message}`);
    assertEquals(
      calls.filter((c) => c.method === "PUT").length,
      1,
      "only the update PUT, no rollback PUT",
    );
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy keeps waiting when the runtime view fails", async () => {
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    deployTransport(
      () => Promise.resolve(STREAM_DONE),
      new Error("Arcane GET /runtime -> HTTP 500"),
    ),
  );
  try {
    const message = await deployError();
    assert(/runtime view failed/.test(message), `got: ${message}`);
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy keeps polling through a failed project read instead of rolling back", async () => {
  const calls: Call[] = [];
  const base = deployTransport(
    () => Promise.resolve(STREAM_DONE),
    "healthy",
    calls,
  );
  let projectReads = 0;
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport((g, m, p, b, t) => {
    if (
      m === "GET" && p === "/environments/0/projects/p1" && ++projectReads === 1
    ) {
      calls.push({ method: m, path: p });
      return Promise.reject(
        new Error(`Arcane GET ${p} -> HTTP 502: bad gateway`),
      );
    }
    return base(g, m, p, b, t);
  });
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("project_deploy").execute(
      {
        name: "web",
        composeContent: "NEW",
        rollback: true,
        healthTimeoutSec: 10,
        pollIntervalSec: 1,
      },
      context,
    );
    assertEquals(
      calls.filter((c) => c.method === "PUT").length,
      1,
      "only the update PUT, no rollback PUT",
    );
    assert(projectReads >= 3, "the failed read, then two healthy checks");
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

/** A gitops-managed project `web` (sync s1) whose sync succeeds, with the redeploy answer supplied. */
function gitopsDeployTransport(redeploy: () => Promise<unknown>) {
  return (_g: unknown, m: string, p: string): Promise<unknown> => {
    if (m === "GET" && p === "/environments/0/projects?limit=-1&archived=all") {
      return Promise.resolve([{ id: "p1", name: "web" }]);
    }
    if (m === "GET" && p === "/environments/0/projects/p1/compose") {
      return Promise.resolve({
        success: true,
        data: { composeContent: "FROM GIT", gitOpsManagedBy: "s1" },
      });
    }
    if (m === "GET" && p === "/environments/0/gitops-syncs?limit=-1") {
      return Promise.resolve([{ id: "s1", name: "web", projectName: "web" }]);
    }
    if (m === "POST" && p === "/environments/0/gitops-syncs/s1/sync") {
      return Promise.resolve({ success: true });
    }
    if (m === "POST" && p === "/environments/0/projects/p1/redeploy") {
      return redeploy();
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

async function gitopsDeployError(): Promise<string> {
  const { context } = makeContext(TEST_GLOBALS);
  try {
    await method("project_deploy").execute(
      { name: "web", healthTimeoutSec: 1, pollIntervalSec: 1 },
      context,
    );
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
  return "";
}

Deno.test("project_deploy in gitops mode fails on an error line in the redeploy body", async () => {
  __setArcaneTransport(gitopsDeployTransport(() =>
    Promise.resolve(
      '{"type":"activity","activityId":"a1"}\n{"error":"service web: container exited (1)"}\n',
    )
  ));
  try {
    const message = await gitopsDeployError();
    assert(
      /redeploy failed: service web: container exited/.test(message),
      `got: ${message}`,
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_deploy in gitops mode refuses .env content", async () => {
  let redeployed = false;
  __setArcaneTransport(gitopsDeployTransport(() => {
    redeployed = true;
    return Promise.resolve(STREAM_DONE);
  }));
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let message = "";
    try {
      await method("project_deploy").execute(
        {
          name: "web",
          envContent: "A=1",
          healthTimeoutSec: 1,
          pollIntervalSec: 1,
        },
        context,
      );
    } catch (e) {
      message = (e as Error).message;
    }
    assert(/gitops-managed/.test(message), message);
    assert(!redeployed, "must not redeploy");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_deploy in gitops mode says a redeploy with no answer may still be running", async () => {
  __setArcaneTransport(gitopsDeployTransport(() =>
    Promise.reject(
      new Error(
        "Arcane POST /environments/0/projects/p1/redeploy -> HTTP 504: request timed out",
      ),
    )
  ));
  try {
    const message = await gitopsDeployError();
    assert(/may still be running it/.test(message), `got: ${message}`);
    assert(!/redeploy failed/.test(message), `got: ${message}`);
  } finally {
    __setArcaneTransport(null);
  }
});

for (
  const [label, redeploy] of [
    [
      "a broken connection",
      () => Promise.reject(new Error("socket hang up")),
    ],
    [
      "a stream cut short after its started line",
      () => Promise.resolve('{"type":"activity","activityId":"a1"}\n'),
    ],
  ] as [string, () => Promise<unknown>][]
) {
  Deno.test(`project_deploy does not roll back after ${label}`, async () => {
    const calls: Call[] = [];
    __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
    __setArcaneTransport(deployTransport(redeploy, "healthy", calls));
    try {
      const message = await deployError(true);
      assert(/no rollback attempted/.test(message), `got: ${message}`);
      assertEquals(
        calls.filter((c) => c.method === "PUT").length,
        1,
        "only the update PUT, no rollback PUT",
      );
    } finally {
      __setArcaneTransport(null);
      __setComposeValidator(null);
    }
  });
}

// ─────────────────────────── data names ───────────────────────────

Deno.test("dataName: two specs sharing a key get distinct names", () => {
  // swamp keys data by model + name, so the spec must be part of the name.
  assertEquals(dataName("sync", "web"), "sync:web");
  assertEquals(dataName("sync-status", "web"), "sync-status:web");
  assertEquals(dataName("project", "web"), "project:web");
  assertEquals(dataName("arcane-version"), "arcane-version");
});

Deno.test("dataName encodes only what swamp rejects, reversibly", () => {
  // The old slug mapped both of these to `a-b`.
  assert(dataName("volume", "a-b") !== dataName("volume", "a.b"));
  assertEquals(dataName("volume", "a.b"), "volume:a.b");
  assertEquals(
    dataName("validation", "projects/web/compose.yaml"),
    "validation:projects%2Fweb%2Fcompose.yaml",
  );
  for (const key of ["a/b", "a\\b", "a..b", "...", "a:b", "100%", "a\0b"]) {
    const part = dataName("x", key).slice("x:".length);
    assert(!/[/\\\0:]|\.\./.test(part), `unsafe part ${part}`);
    assertEquals(decodeURIComponent(part), key);
  }
  // `:` in a key part is encoded, so a composite key cannot pass for another.
  assert(
    dataName("project-detail", "web:prior") !==
      dataName("project-detail", "web", "prior"),
  );
});

Deno.test("project_validate names its record by the full target path", async () => {
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("project_validate").execute(
      { target: "projects/web/compose.yaml", composeContent: "services: {}" },
      context,
    );
    assertEquals(written.map((w) => w.name), [
      "validation:projects%2Fweb%2Fcompose.yaml",
    ]);
  } finally {
    __setComposeValidator(null);
  }
});

Deno.test("lifecycle methods act once per name, even if a name is repeated", async () => {
  const posts: string[] = [];
  __setArcaneTransport((_g, m, p) => {
    if (p.endsWith("/projects?limit=-1&archived=all")) {
      return Promise.resolve([{ id: "p1", name: "web" }]);
    }
    posts.push(`${m} ${p}`);
    return Promise.resolve(STREAM_DONE);
  });
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("project_up").execute({ names: ["web", "web"] }, context);
    assertEquals(posts, ["POST /environments/0/projects/p1/up"]);
    assertEquals(written.map((w) => w.name), ["operation-result:up:web"]);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_ensure refuses a sync name listed twice", async () => {
  __setArcaneTransport((_g, m, p) =>
    Promise.reject(new Error(`unexpected ${m} ${p}`))
  );
  try {
    const sync = { name: "web", composePath: "web/compose.yaml" };
    const { context } = makeContext({ ...TEST_GLOBALS, syncs: [sync, sync] });
    let message = "";
    try {
      await method("gitops_sync_ensure").execute({}, context);
    } catch (e) {
      message = (e as Error).message;
    }
    assert(/'web' more than once/.test(message), message);
  } finally {
    __setArcaneTransport(null);
  }
});

// ─────────────────────────── gitops deploy path ───────────────────────────

/**
 * A gitops project `web` (id p1) managed by sync id s1, which is named `apps`.
 * `sync` answers the sync POST; every call is logged.
 */
function gitopsTransport(
  sync: (timeoutMs?: number) => Promise<unknown>,
  calls: Call[] = [],
  syncs: Json[] = [{ id: "s1", name: "apps", projectName: "apps" }],
) {
  return (
    _g: unknown,
    m: string,
    p: string,
    _b?: unknown,
    timeoutMs?: number,
  ): Promise<unknown> => {
    calls.push({ method: m, path: p });
    if (m === "GET" && p === "/environments/0/projects?limit=-1&archived=all") {
      return Promise.resolve([{ id: "p1", name: "web" }]);
    }
    if (m === "GET" && p === "/environments/0/projects/p1/compose") {
      return Promise.resolve({
        success: true,
        data: { composeContent: "FROM GIT", gitOpsManagedBy: "s1" },
      });
    }
    if (m === "GET" && p === "/environments/0/gitops-syncs?limit=-1") {
      return Promise.resolve(syncs);
    }
    if (m === "POST" && p.startsWith("/environments/0/gitops-syncs/")) {
      return sync(timeoutMs);
    }
    if (m === "POST" && p === "/environments/0/projects/p1/redeploy") {
      return Promise.resolve(STREAM_DONE);
    }
    if (m === "GET" && p === "/environments/0/projects/p1") {
      return Promise.resolve({
        success: true,
        data: { status: "running", serviceCount: 1, runningCount: 1 },
      });
    }
    if (m === "GET" && p === "/environments/0/projects/p1/runtime") {
      return Promise.resolve({ success: true, data: { runtimeServices: [] } });
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

async function gitopsDeploy(): Promise<
  { message: string; written: WriteCall[] }
> {
  const { context, written } = makeContext(TEST_GLOBALS);
  try {
    await method("project_deploy").execute(
      { name: "web", healthTimeoutSec: 5, pollIntervalSec: 1 },
      context,
    );
  } catch (e) {
    return { message: (e as Error).message, written };
  }
  return { message: "", written };
}

const SYNC_OK = { success: true, data: { success: true, message: "synced" } };

Deno.test("project_deploy gitops: finds the sync by the id in gitOpsManagedBy, not by name", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    gitopsTransport(() => Promise.resolve(SYNC_OK), calls, [
      { id: "s9", name: "web", projectName: "web" },
      { id: "s1", name: "apps", projectName: "apps" },
    ]),
  );
  try {
    const { message, written } = await gitopsDeploy();
    assertEquals(message, "");
    assertEquals(
      calls.filter((c) => c.path.includes("/gitops-syncs/")).map((c) => c.path),
      ["/environments/0/gitops-syncs/s1/sync"],
    );
    const sync = written.find((w) => w.data.operation === "deploy:sync");
    assertEquals(sync?.data.success, true);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_deploy gitops: a managing sync Arcane no longer lists stops the deploy", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    gitopsTransport(() => Promise.resolve(SYNC_OK), calls, [
      { id: "s9", name: "web", projectName: "web" },
    ]),
  );
  try {
    const { message, written } = await gitopsDeploy();
    assert(
      /managed by sync s1, which Arcane no longer lists/.test(message),
      message,
    );
    assert(!calls.some((c) => c.method === "POST"), "no sync, no redeploy");
    const sync = written.find((w) => w.data.operation === "deploy:sync");
    assertEquals(sync?.data.success, false);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_deploy gitops: a sync already in progress is not recorded as success or raced", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    gitopsTransport(
      () =>
        Promise.resolve({
          success: false,
          data: { success: false, message: "sync already in progress" },
        }),
      calls,
    ),
  );
  try {
    const { message, written } = await gitopsDeploy();
    assert(/is already running; wait for it to finish/.test(message), message);
    assert(!calls.some((c) => c.path.endsWith("/redeploy")), "no redeploy");
    const sync = written.find((w) => w.data.operation === "deploy:sync");
    assertEquals(sync?.data.success, false);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_deploy gitops: a failed sync stops the deploy with Arcane's error", async () => {
  __setArcaneTransport(
    gitopsTransport(() =>
      Promise.resolve({
        success: false,
        data: {
          success: false,
          message: "Failed to clone repository",
          error: "authentication required",
        },
      })
    ),
  );
  try {
    const { message } = await gitopsDeploy();
    assert(
      /failed \(Failed to clone repository: authentication required\)/.test(
        message,
      ),
      message,
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_deploy gitops: the sync gets the long timeout, and a timeout stops the deploy", async () => {
  const calls: Call[] = [];
  let syncTimeout: number | undefined;
  __setArcaneTransport(
    gitopsTransport((timeoutMs) => {
      syncTimeout = timeoutMs;
      return Promise.reject(
        new Error(`request timed out after ${timeoutMs} ms`),
      );
    }, calls),
  );
  try {
    const { message } = await gitopsDeploy();
    assertEquals(syncTimeout, 30 * 60_000);
    assert(/Arcane may still be running it/.test(message), message);
    assert(!calls.some((c) => c.path.endsWith("/redeploy")), "no redeploy");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_trigger records a sync Arcane reports failed, and throws", async () => {
  let syncTimeout: number | undefined;
  __setArcaneTransport((_g, m, p, _b, timeoutMs) => {
    if (m === "GET" && p === "/environments/0/gitops-syncs?limit=-1") {
      return Promise.resolve([{ id: "s1", name: "a" }, {
        id: "s2",
        name: "b",
      }]);
    }
    syncTimeout = timeoutMs;
    if (p === "/environments/0/gitops-syncs/s1/sync") {
      return Promise.resolve(SYNC_OK);
    }
    return Promise.resolve({
      success: false,
      data: { success: false, message: "sync already in progress" },
    });
  });
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    let message = "";
    try {
      await method("gitops_sync_trigger").execute({}, context);
    } catch (e) {
      message = (e as Error).message;
    }
    assert(/b \(sync already in progress\)/.test(message), message);
    assertEquals(
      written.map((w) => [w.data.target, w.data.success]),
      [["a", true], ["b", false]],
    );
    assertEquals(syncTimeout, 30 * 60_000);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_trigger records a sync with no answer and carries on to the next", async () => {
  __setArcaneTransport((_g, m, p) => {
    if (m === "GET" && p === "/environments/0/gitops-syncs?limit=-1") {
      return Promise.resolve([{ id: "s1", name: "a" }, {
        id: "s2",
        name: "b",
      }]);
    }
    if (p === "/environments/0/gitops-syncs/s1/sync") {
      return Promise.reject(new Error("request timed out after 1800000 ms"));
    }
    return Promise.resolve(SYNC_OK);
  });
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    let message = "";
    try {
      await method("gitops_sync_trigger").execute({}, context);
    } catch (e) {
      message = (e as Error).message;
    }
    assert(
      /a \(no answer from Arcane.*may still be running/.test(message),
      message,
    );
    assertEquals(
      written.map((w) => [w.data.target, w.data.success, w.data.status]),
      [["a", false, 0], ["b", true, 200]],
    );
  } finally {
    __setArcaneTransport(null);
  }
});

// ─────────────────────────── rollback and sensitive arguments ───────────────────────────

Deno.test("project_deploy rollback empties a .env the failed deploy added", async () => {
  // Arcane omits an empty .env from the project read, so the snapshot has none.
  const calls: Call[] = [];
  const transport = deployTransport(
    () => Promise.resolve(STREAM_DONE),
    "unhealthy",
  );
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport((g, m, p, b, t) => {
    calls.push({ method: m, path: p, body: b });
    return transport(g, m, p, b, t);
  });
  try {
    const { context } = makeContext(TEST_GLOBALS);
    try {
      await method("project_deploy").execute(
        {
          name: "web",
          composeContent: "NEW",
          envContent: "TOKEN=x\n",
          healthTimeoutSec: 1,
          pollIntervalSec: 1,
        },
        context,
      );
    } catch { /* the deploy is meant to fail */ }
    const puts = calls.filter((c) => c.method === "PUT").map(bodyOf);
    assertEquals(puts.length, 2, "update PUT then rollback PUT");
    assertEquals(puts[1], { composeContent: "PRIOR", envContent: "" });
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("every envContent argument is marked sensitive", () => {
  const methods = model.methods as unknown as Record<string, {
    arguments: { shape: Record<string, { meta: () => Json | undefined }> };
  }>;
  const withEnv = Object.entries(methods).filter(([, m]) =>
    m.arguments.shape?.envContent !== undefined
  );
  assertEquals(withEnv.map(([n]) => n).sort(), [
    "project_create",
    "project_deploy",
    "project_update",
    "project_validate",
    "swarm_stack_deploy",
    "swarm_stack_validate",
  ]);
  for (const [name, m] of withEnv) {
    assertEquals(m.arguments.shape.envContent.meta()?.sensitive, true, name);
  }
});

// ─────────────────────────── stage 3: low findings ───────────────────────────

/** Run a method and return its error message, or "" if it succeeded. */
async function errorOf(
  name: string,
  args: Record<string, unknown>,
  globals: Record<string, unknown> = TEST_GLOBALS,
): Promise<{ message: string; written: WriteCall[] }> {
  const { context, written } = makeContext(globals);
  try {
    await method(name).execute(args, context);
  } catch (e) {
    return { message: (e as Error).message, written };
  }
  return { message: "", written };
}

Deno.test("gitops_sync_ensure checks every repository before writing any sync", async () => {
  const calls = syncServer([]);
  try {
    const { message } = await errorOf("gitops_sync_ensure", {}, {
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "u" },
      syncs: [
        { name: "a", composePath: "a/compose.yaml" },
        { name: "b", composePath: "b/compose.yaml", repository: "missing" },
      ],
    });
    assert(/'missing' not found/.test(message), message);
    assertEquals(
      calls.filter((c) => c.method !== "GET").length,
      0,
      "no sync created before the bad repository was found",
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("secret_rotate checks the named services before creating the new secret", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(rotateTransport(calls, { State: "completed" }));
  try {
    const { message } = await errorOf("secret_rotate", {
      name: "db_pw",
      value: "v",
      services: ["dbb"],
    });
    assert(/not found or not referencing secret 'db_pw': dbb/.test(message));
    assert(!calls.some((c) => c.method === "POST"), "no new secret created");
  } finally {
    __setArcaneTransport(null);
  }
});

/** Two services using secret `db_pw`; the PUT to `failPut` is refused. */
function twoServiceRotateTransport(calls: Call[], failPut: string) {
  return (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
    calls.push({ method: m, path: p, body: b });
    if (p === "/environments/0/swarm/status") {
      return Promise.resolve({ data: { enabled: true } });
    }
    if (m === "GET" && p === "/environments/0/swarm/secrets") {
      return Promise.resolve([{ id: "s1", spec: { Name: "db_pw" } }]);
    }
    if (m === "POST" && p === "/environments/0/swarm/secrets") {
      return Promise.resolve({ data: { id: "s2" } });
    }
    if (p === "/environments/0/swarm/services?limit=-1") {
      return Promise.resolve([{ id: "a", name: "app" }, {
        id: "w",
        name: "worker",
      }]);
    }
    if (m === "GET" && p.startsWith("/environments/0/swarm/services/")) {
      return Promise.resolve({
        data: {
          version: { Index: 1 },
          spec: {
            TaskTemplate: {
              ContainerSpec: {
                Secrets: [{ SecretID: "s1", SecretName: "db_pw" }],
              },
            },
          },
        },
      });
    }
    if (m === "PUT") {
      return p.endsWith(`/${failPut}`)
        ? Promise.reject(
          new Error(`Arcane PUT ${p} -> HTTP 500: out of sequence`),
        )
        : Promise.resolve({ data: {} });
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

Deno.test("secret_rotate: a failed re-point says what already changed", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(twoServiceRotateTransport(calls, "w"));
  try {
    const { message, written } = await errorOf("secret_rotate", {
      name: "db_pw",
      value: "v",
      newName: "db_pw-v2",
    });
    assert(/re-pointing service 'worker' failed/.test(message), message);
    assert(/Created secret 'db_pw-v2'; already re-pointed: app/.test(message));
    assert(!calls.some((c) => c.method === "DELETE"), "old secret kept");
    const failed = written.find((w) =>
      w.data.operation === "secret_rotate:repoint" && w.data.target === "worker"
    );
    assertEquals(failed?.data.success, false);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("secret_rotate: an old secret still in use (400 from swarm) is left in place, not forced", async () => {
  const calls: Call[] = [];
  const base = rotateTransport(calls, { State: "completed" });
  let deletes = 0;
  __setArcaneTransport((g, m, p, b) => {
    if (m !== "DELETE") return base(g, m, p, b);
    deletes++;
    // Swarm's InvalidArgument text, which Arcane maps to 400.
    return Promise.reject(
      new Error(
        `Arcane DELETE ${p} -> HTTP 400: secret 'db_pw' is in use by the following service: worker`,
      ),
    );
  });
  try {
    const { message, written } = await errorOf("secret_rotate", {
      name: "db_pw",
      value: "v",
      healthTimeoutSec: 5,
      pollIntervalSec: 1,
    });
    assertEquals(message, "");
    const removeOld = written.find((w) =>
      w.data.operation === "secret_rotate:remove-old"
    );
    assertEquals(removeOld?.data.success, false);
    assertEquals(removeOld?.data.status, 400);
    assertEquals(deletes, 1, "one DELETE, never forced or retried");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("secret_rotate re-points only the services named in `services`", async () => {
  const calls: Call[] = [];
  const base = twoServiceRotateTransport(calls, "none");
  __setArcaneTransport((g, m, p, b) => {
    // Both services report a completed update once re-pointed.
    if (m === "GET" && /\/swarm\/services\/[aw]$/.test(p)) {
      return (base(g, m, p, b) as Promise<Json>).then((r) => ({
        data: { ...(r.data as Json), updateStatus: { State: "completed" } },
      }));
    }
    if (m === "DELETE") return Promise.resolve({ data: {} });
    return base(g, m, p, b);
  });
  try {
    const { message } = await errorOf("secret_rotate", {
      name: "db_pw",
      value: "v",
      services: ["app"],
      removeOld: false,
      healthTimeoutSec: 5,
      pollIntervalSec: 1,
    });
    assertEquals(message, "");
    assertEquals(
      calls.filter((c) => c.method === "PUT").map((c) => c.path),
      ["/environments/0/swarm/services/a"],
    );
  } finally {
    __setArcaneTransport(null);
  }
});

/** A force-update of service `svc1` whose update status reads `status(n)` on the n-th inspect after the PUT. */
function forceUpdateTransport(status: (n: number) => Json | undefined) {
  let afterPut = 0;
  let put = false;
  return (_g: unknown, m: string, p: string): Promise<unknown> => {
    if (p === "/environments/0/swarm/status") {
      return Promise.resolve({ data: { enabled: true } });
    }
    if (p === "/environments/0/swarm/services?limit=-1") {
      return Promise.resolve([
        { id: "svc1", name: "web", replicas: 1, runningReplicas: 1 },
      ]);
    }
    if (m === "GET" && p === "/environments/0/swarm/services/svc1") {
      const updateStatus = put ? status(++afterPut) : undefined;
      return Promise.resolve({
        data: {
          spec: { TaskTemplate: {} },
          version: { Index: 1 },
          updateStatus,
        },
      });
    }
    if (m === "PUT") {
      put = true;
      return Promise.resolve({ data: {} });
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

Deno.test("swarm_service_force_update takes a last look at the deadline instead of sleeping past it", async () => {
  // Not started on the first look, completed on the second.
  __setArcaneTransport(
    forceUpdateTransport((n) => n === 1 ? undefined : { State: "completed" }),
  );
  const started = Date.now();
  try {
    const { message } = await errorOf("swarm_service_force_update", {
      name: "web",
      convergeTimeoutSec: 1,
      pollIntervalSec: 3,
    });
    assertEquals(message, "");
    assert(Date.now() - started < 2500, "slept no further than the deadline");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_service_force_update fails at once on an update swarm rolled back", async () => {
  let looks = 0;
  __setArcaneTransport(
    forceUpdateTransport(() => {
      looks++;
      return { State: "rollback_completed" };
    }),
  );
  try {
    const { message } = await errorOf("swarm_service_force_update", {
      name: "web",
      convergeTimeoutSec: 30,
      pollIntervalSec: 1,
    });
    assert(/did not converge: updateState=rollback_completed/.test(message));
    assertEquals(looks, 1);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_remove stops at its deadline, not a whole interval past it", async () => {
  __setArcaneTransport((_g, m, p) => {
    if (p === "/environments/0/swarm/status") {
      return Promise.resolve({ data: { enabled: true } });
    }
    if (m === "DELETE") return Promise.resolve({ success: true });
    return Promise.resolve({ data: { name: "stuck" } });
  });
  const started = Date.now();
  try {
    const { message } = await errorOf("swarm_stack_remove", {
      name: "stuck",
      removeTimeoutSec: 1,
      pollIntervalSec: 5,
    });
    assert(/still present/.test(message), message);
    assert(Date.now() - started < 2500, "gave up near the deadline");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("swarm_stack_remove: a first DELETE that answers 404 with the record still there is re-issued", async () => {
  // Arcane answers 404 for a not-found error from an early step, before it
  // deletes its stored record.
  let deletes = 0;
  __setArcaneTransport((_g, m, p) => {
    if (p === "/environments/0/swarm/status") {
      return Promise.resolve({ data: { enabled: true } });
    }
    if (m === "DELETE") {
      deletes++;
      return deletes === 1
        ? Promise.reject(new Error(`Arcane DELETE ${p} -> HTTP 404: not found`))
        : Promise.resolve({ success: true });
    }
    return deletes >= 2
      ? Promise.reject(new Error(`Arcane GET ${p} -> HTTP 404: not found`))
      : Promise.resolve({ data: { name: "two", services: 0 } });
  });
  try {
    const { message, written } = await errorOf("swarm_stack_remove", {
      name: "two",
      removeTimeoutSec: 5,
      pollIntervalSec: 1,
    });
    assertEquals(message, "");
    assertEquals(written[0].data.deletes, 2);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("timeouts are capped at a day, like healthTimeoutSec", () => {
  const methods = model.methods as unknown as Record<string, {
    arguments: { safeParse: (v: unknown) => { success: boolean } };
  }>;
  const cases: [string, Json][] = [
    ["swarm_service_force_update", { name: "s", convergeTimeoutSec: 86_401 }],
    ["swarm_stack_deploy", { name: "s", convergeTimeoutSec: 86_401 }],
    ["swarm_stack_remove", { name: "s", removeTimeoutSec: 86_401 }],
    ["secret_rotate", { name: "s", value: "v", healthTimeoutSec: 86_401 }],
    ["config_rotate", { name: "s", value: "v", healthTimeoutSec: 86_401 }],
  ];
  for (const [name, args] of cases) {
    assertEquals(methods[name].arguments.safeParse(args).success, false, name);
  }
});

Deno.test("a create answered without an id fails instead of recording an empty id", async () => {
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  // Swarm is enabled; every create answers without an id.
  __setArcaneTransport(() =>
    Promise.resolve({ success: true, data: { enabled: true } })
  );
  try {
    const project = await errorOf("project_create", {
      name: "web",
      composeContent: "services: {}",
    });
    assert(
      /created project 'web' but its answer had no id/.test(project.message),
    );
    assertEquals(project.written.length, 0);
    const secret = await errorOf("secret_create", { name: "s", value: "v" });
    assert(/created secret 's' but its answer had no id/.test(secret.message));
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

/** A first deploy of `web`: the create answers `create`, and the redeploy `redeploy`. */
function firstDeployTransport(
  calls: Call[],
  create: () => Promise<unknown>,
  redeploy: () => Promise<unknown>,
) {
  return (_g: unknown, m: string, p: string, _b?: unknown, t?: number) => {
    calls.push({ method: m, path: p, body: t });
    if (p === "/environments/0/projects?limit=-1&archived=all") {
      return Promise.resolve({ success: true, data: [] });
    }
    if (m === "POST" && p === "/environments/0/projects") return create();
    if (p === "/environments/0/projects/p1/redeploy") return redeploy();
    if (m === "DELETE") return Promise.resolve({ success: true });
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

const deployArgs = {
  name: "web",
  composeContent: "services: {}",
  healthTimeoutSec: 1,
  pollIntervalSec: 1,
};

Deno.test("project_deploy: a failed first deploy destroys the half-up project", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(firstDeployTransport(
    calls,
    () => Promise.resolve({ data: { id: "p1" } }),
    () => Promise.resolve('{"error":"image not found"}\n'),
  ));
  try {
    const { message } = await errorOf("project_deploy", deployArgs);
    assert(
      /first deploy of 'web' failed.*destroyed the half-up project/.test(
        message,
      ),
    );
    const destroy = calls.find((c) => c.method === "DELETE");
    assertEquals(destroy?.path, "/environments/0/projects/p1/destroy");
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy: a first deploy whose redeploy outcome is unknown is not destroyed", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(firstDeployTransport(
    calls,
    () => Promise.resolve({ data: { id: "p1" } }),
    () => Promise.reject(new Error("socket hang up")),
  ));
  try {
    const { message } = await errorOf("project_deploy", deployArgs);
    assert(/no rollback attempted/.test(message), message);
    assert(!calls.some((c) => c.method === "DELETE"), "nothing destroyed");
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy: a first deploy whose create has no id says a project may exist", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(firstDeployTransport(
    calls,
    () => Promise.resolve({ success: true, data: {} }),
    () => Promise.resolve(STREAM_DONE),
  ));
  try {
    const { message, written } = await errorOf("project_deploy", deployArgs);
    assert(/answer had no id/.test(message), message);
    const rollback = written.find((w) =>
      w.data.operation === "deploy:rollback"
    );
    assert(/half-created project/.test(String(rollback?.data.detail)));
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy with rollback:false leaves the failed state", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    deployTransport(() => Promise.resolve(STREAM_DONE), "unhealthy", calls),
  );
  try {
    const message = await deployError(false);
    assert(/rollback disabled, left as-is/.test(message), message);
    assertEquals(calls.filter((c) => c.method === "PUT").length, 1);
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy: a rollback whose redeploy outcome is unknown is not called failed", async () => {
  let redeploys = 0;
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(deployTransport(() => {
    redeploys++;
    return redeploys === 1
      ? Promise.resolve('{"error":"container exited (1)"}\n')
      : Promise.reject(new Error("socket hang up"));
  }, "healthy"));
  try {
    const message = await deployError(true);
    assert(/ROLLBACK OUTCOME UNKNOWN/.test(message), message);
    assert(!/ROLLBACK FAILED/.test(message), message);
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

for (const status of [502, 503, 504]) {
  Deno.test(`project_deploy treats an HTTP ${status} on the redeploy as outcome unknown`, async () => {
    const calls: Call[] = [];
    __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
    __setArcaneTransport(deployTransport(
      () =>
        Promise.reject(
          new Error(`Arcane POST /redeploy -> HTTP ${status}: Bad Gateway`),
        ),
      "healthy",
      calls,
    ));
    try {
      const message = await deployError(true);
      assert(/no rollback attempted/.test(message), message);
      assertEquals(calls.filter((c) => c.method === "PUT").length, 1);
    } finally {
      __setArcaneTransport(null);
      __setComposeValidator(null);
    }
  });
}

Deno.test("project_deploy gitops: a 502 on the sync is no answer, not a failure", async () => {
  __setArcaneTransport(
    gitopsTransport(() =>
      Promise.reject(
        new Error("Arcane POST /sync -> HTTP 502: Proxy request failed"),
      )
    ),
  );
  try {
    const { message } = await gitopsDeploy();
    assert(/gave no answer/.test(message), message);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_deploy refuses an archived project instead of trying to create it", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport((_g, m, p) => {
    calls.push({ method: m, path: p });
    if (p === "/environments/0/projects?limit=-1&archived=all") {
      return Promise.resolve({
        data: [{ id: "p1", name: "web", isArchived: true }],
      });
    }
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  });
  try {
    const { message } = await errorOf("project_deploy", deployArgs);
    assert(/'web' is archived in Arcane; unarchive it/.test(message), message);
    assertEquals(calls.length, 1);
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("project_destroy deletes each project with the long timeout", async () => {
  const calls: Call[] = [];
  __setArcaneTransport((_g, m, p, _b, t) => {
    calls.push({ method: m, path: p, body: t });
    if (p === "/environments/0/projects?limit=-1&archived=all") {
      return Promise.resolve({ data: [{ id: "p1", name: "web" }] });
    }
    return Promise.resolve({ success: true });
  });
  try {
    const { message, written } = await errorOf("project_destroy", {
      names: ["web"],
    });
    assertEquals(message, "");
    const del = calls.find((c) => c.method === "DELETE");
    assertEquals(del?.path, "/environments/0/projects/p1/destroy");
    assertEquals(del?.body, 30 * 60_000);
    assertEquals(written[0].name, "operation-result:destroy:web");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_ensure prune deletes only syncs not in globalArgs.syncs", async () => {
  const calls = syncServer([
    UI_TUNED_SYNC,
    { id: "s7", name: "old", composePath: "old/compose.yaml" },
  ]);
  try {
    const { message, written } = await errorOf("gitops_sync_ensure", {
      prune: true,
    }, {
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "u" },
      syncs: [{ name: "web", composePath: "projects/web/compose.yaml" }],
    });
    assertEquals(message, "");
    assertEquals(
      calls.filter((c) => c.method === "DELETE").map((c) => c.path),
      ["/environments/0/gitops-syncs/s7"],
    );
    assertEquals(
      written.map((w) => [w.name, w.data.action]),
      [["sync:web", "unchanged"], ["sync:old", "deleted"]],
    );
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("reachable check: a rejected key is reported as rejected, not unreachable", async () => {
  __setArcaneTransport(() => {
    throw new Error(
      "Arcane GET /auth/me -> HTTP 401: Invalid or expired API key",
    );
  });
  try {
    const checks = (model as unknown as {
      checks: Record<string, {
        execute: (c: unknown) => Promise<{ pass: boolean; errors?: string[] }>;
      }>;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: { baseUrl: "https://arcane.example.com", apiKey: "wrong" },
    });
    assertEquals(res.pass, false);
    assert(/rejected the API key/.test(res.errors?.[0] ?? ""), res.errors?.[0]);
    assert(!/Cannot reach/.test(res.errors?.[0] ?? ""));
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("pruneResult reports zero deletions as 0, not as missing", () => {
  assertEquals(pruneResult("volumes", { spaceReclaimed: 0 }).itemsDeleted, 0);
});

Deno.test("a sync interval must be positive", () => {
  const parse = (syncInterval: number) =>
    model.globalArguments.safeParse({
      baseUrl: "https://a",
      apiKey: "k",
      syncs: [{ name: "s", composePath: "c.yaml", syncInterval }],
    }).success;
  assertEquals(parse(0), false);
  assertEquals(parse(-5), false);
  assertEquals(parse(5), true);
});

Deno.test("swarm_service_get records the update state from the service's inspect", async () => {
  __setArcaneTransport((_g, _m, p) => {
    if (p === "/environments/0/swarm/status") {
      return Promise.resolve({ data: { enabled: true } });
    }
    if (p === "/environments/0/swarm/services?limit=-1") {
      return Promise.resolve([{ id: "svc1", name: "web", replicas: 1 }]);
    }
    return Promise.resolve({
      data: { updateStatus: { State: "rollback_completed" } },
    });
  });
  try {
    const { message, written } = await errorOf("swarm_service_get", {
      name: "web",
    });
    assertEquals(message, "");
    assertEquals(written[0].data.updateState, "rollback_completed");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("volume_remove records the volume's name as its id", async () => {
  __setArcaneTransport(() => Promise.resolve({ success: true }));
  try {
    const { written } = await errorOf("volume_remove", { name: "v1" });
    assertEquals(written[0].data.id, "v1");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("read methods log when they start and finish, with placeholders for their props", async () => {
  __setArcaneTransport((_g, m, p) => {
    if (p === "/environments/0/swarm/status") {
      return Promise.resolve({ data: { enabled: true } });
    }
    if (p.endsWith("/projects?limit=-1&archived=all")) {
      return Promise.resolve([{ id: "p1", name: "web" }]);
    }
    if (p === "/environments/0/swarm/services?limit=-1") {
      return Promise.resolve([{ id: "svc1", name: "web" }]);
    }
    if (p === "/environments/0/swarm/secrets") {
      return Promise.resolve([{ id: "s1", spec: { Name: "web" } }]);
    }
    if (p.endsWith("?limit=-1")) return Promise.resolve([]);
    if (m === "POST" && p.endsWith("/up")) return Promise.resolve(STREAM_DONE);
    return Promise.resolve({ data: { name: "web" } });
  });
  const cases: [string, Json][] = [
    ["project_get", { name: "web" }],
    ["project_up", { names: ["web"] }],
    ["swarm_service_list", {}],
    ["swarm_service_get", { name: "web" }],
    ["swarm_service_rollback", { name: "web" }],
    ["swarm_stack_list", {}],
    ["swarm_stack_get", { name: "web" }],
    ["swarm_stack_tasks", { name: "web" }],
    ["secret_list", {}],
    ["secret_get", { name: "web" }],
    ["volume_list", {}],
  ];
  try {
    for (const [name, args] of cases) {
      const logs: [string, Json][] = [];
      const { context } = makeContext(TEST_GLOBALS);
      context.logger.info = (message: string, props?: unknown) => {
        logs.push([message, (props ?? {}) as Json]);
      };
      await method(name).execute(args, context);
      assert(logs.length >= 2, `${name} logs its start and its end`);
      for (const [message, props] of logs) {
        for (const [, key] of message.matchAll(/\{(\w+)\}/g)) {
          assert(key in props, `${name}: "${message}" has no ${key} prop`);
        }
      }
    }
  } finally {
    __setArcaneTransport(null);
  }
});

// ─────────────────────────── stage 3: decisions ───────────────────────────

Deno.test("project_deploy deletes the step records an earlier run left and this run did not reach", async () => {
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    deployTransport(() => Promise.resolve(STREAM_DONE), "healthy"),
  );
  try {
    const { context, written, deleted } = makeContext(TEST_GLOBALS);
    await method("project_deploy").execute(
      {
        name: "web",
        composeContent: "NEW",
        healthTimeoutSec: 5,
        pollIntervalSec: 1,
      },
      context,
    );
    const steps = written.filter((w) => w.specName === "operation-result")
      .map((w) => w.name);
    assertEquals(steps, [
      "operation-result:deploy:validate:web",
      "operation-result:deploy:update:web",
      "operation-result:deploy:redeploy:web",
      "operation-result:deploy:health:web",
    ]);
    assertEquals(deleted.sort(), [
      "operation-result:deploy:apply:web",
      "operation-result:deploy:create:web",
      "operation-result:deploy:rollback:web",
      "operation-result:deploy:sync:web",
    ]);
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("swarm_stack_deploy that fails at render deletes every step record of earlier runs", async () => {
  __setArcaneTransport((_g, _m, p) =>
    p === "/environments/0/swarm/status"
      ? Promise.resolve({ data: { enabled: true } })
      : Promise.reject(new Error(`Arcane POST ${p} -> HTTP 400: bad compose`))
  );
  try {
    const { context, deleted } = makeContext(TEST_GLOBALS);
    try {
      await method("swarm_stack_deploy").execute(
        { name: "x", composeContent: "c" },
        context,
      );
    } catch { /* the render is meant to fail */ }
    assertEquals(deleted.sort(), [
      "operation-result:swarm_stack_deploy:converge:x",
      "operation-result:swarm_stack_deploy:deploy:x",
      "operation-result:swarm_stack_deploy:validate:x",
    ]);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("secret_rotate keys its step records by the secret and deletes the ones it did not reach", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(twoServiceRotateTransport(calls, "w"));
  try {
    const { context, written, deleted } = makeContext(TEST_GLOBALS);
    try {
      await method("secret_rotate").execute(
        { name: "db_pw", value: "v", newName: "db_pw-v2" },
        context,
      );
    } catch { /* the second re-point is meant to fail */ }
    assertEquals(
      written.filter((w) => w.specName === "operation-result").map((w) =>
        w.name
      ),
      [
        "operation-result:secret_rotate:db_pw:create",
        "operation-result:secret_rotate:db_pw:repoint:app",
        "operation-result:secret_rotate:db_pw:repoint:worker",
      ],
    );
    assertEquals(deleted.sort(), [
      "operation-result:secret_rotate:db_pw:converge:app",
      "operation-result:secret_rotate:db_pw:converge:worker",
      "operation-result:secret_rotate:db_pw:remove-old",
      "operation-result:secret_rotate:db_pw:repoint",
    ]);
  } finally {
    __setArcaneTransport(null);
  }
});

/** Arcane's syncs: a deploy sync, one with no mode (deploy), and a backup sync. */
const MIXED_SYNCS = [
  { id: "s1", name: "web", mode: "deploy" },
  { id: "s2", name: "api" },
  { id: "s3", name: "nightly-backup", mode: "backup" },
];

function triggerTransport(posts: string[]) {
  return (_g: unknown, m: string, p: string): Promise<unknown> => {
    if (p === "/environments/0/gitops-syncs?limit=-1") {
      return Promise.resolve(MIXED_SYNCS);
    }
    posts.push(`${m} ${p}`);
    return Promise.resolve(SYNC_OK);
  };
}

Deno.test("gitops_sync_trigger with no names runs only the deploy syncs", async () => {
  const posts: string[] = [];
  __setArcaneTransport(triggerTransport(posts));
  try {
    const { message } = await errorOf("gitops_sync_trigger", {});
    assertEquals(message, "");
    assertEquals(posts, [
      "POST /environments/0/gitops-syncs/s1/sync",
      "POST /environments/0/gitops-syncs/s2/sync",
    ]);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_trigger runs a backup sync named explicitly", async () => {
  const posts: string[] = [];
  __setArcaneTransport(triggerTransport(posts));
  try {
    const { message } = await errorOf("gitops_sync_trigger", {
      names: ["nightly-backup"],
    });
    assertEquals(message, "");
    assertEquals(posts, ["POST /environments/0/gitops-syncs/s3/sync"]);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_ensure prune leaves backup syncs alone", async () => {
  const calls = syncServer([
    UI_TUNED_SYNC,
    { id: "s8", name: "nightly-backup", mode: "backup" },
  ]);
  try {
    const { message } = await errorOf("gitops_sync_ensure", { prune: true }, {
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "u" },
      syncs: [{ name: "web", composePath: "projects/web/compose.yaml" }],
    });
    assertEquals(message, "");
    assertEquals(calls.filter((c) => c.method === "DELETE").length, 0);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_sync_ensure keeps an existing sync's project name when the spec omits it", async () => {
  const calls = syncServer([{
    ...UI_TUNED_SYNC,
    projectName: "renamed-in-ui",
  }]);
  try {
    const { written } = await errorOf("gitops_sync_ensure", {}, {
      ...TEST_GLOBALS,
      repository: { name: "gitops", url: "u" },
      syncs: [{
        name: "web",
        composePath: "projects/web/compose.yaml",
        branch: "main",
      }],
    });
    const put = calls.find((c) => c.method === "PUT")!;
    assertEquals(bodyOf(put).projectName, undefined, "not sent when omitted");
    assertEquals(written[0].data.projectName, "renamed-in-ui");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("envValues and maskValues hide .env values in text", () => {
  const env = [
    "# comment",
    "PORT=80",
    "export TOKEN=hunter2zz",
    'QUOTED="s3cret value"',
    "EMPTY=",
  ].join("\n");
  assertEquals(envValues(env), ["hunter2zz", "s3cret value"]);
  assertEquals(
    maskValues("invalid containerPort: hunter2zz on 80", envValues(env)),
    "invalid containerPort: [redacted] on 80",
  );
});

Deno.test("project_validate masks .env values out of a validator error", async () => {
  __setComposeValidator(() =>
    Promise.reject(
      new Error("compose validation failed: invalid containerPort: hunter2zz"),
    )
  );
  try {
    const { message } = await errorOf("project_validate", {
      composeContent: "services: {}",
      envContent: "PORT_SECRET=hunter2zz\n",
    });
    assert(/invalid containerPort: \[redacted\]/.test(message), message);
    assert(!message.includes("hunter2zz"));
  } finally {
    __setComposeValidator(null);
  }
});

Deno.test("project_deploy masks .env values in its records and its error", async () => {
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(deployTransport(
    () => Promise.resolve('{"error":"invalid containerPort: hunter2zz"}\n'),
    "healthy",
  ));
  try {
    const { message, written } = await errorOf("project_deploy", {
      name: "web",
      composeContent: "NEW",
      envContent: "PORT_SECRET=hunter2zz\n",
      rollback: false,
      healthTimeoutSec: 1,
      pollIntervalSec: 1,
    });
    assert(/\[redacted\]/.test(message) && !message.includes("hunter2zz"));
    for (const w of written) {
      assert(!JSON.stringify(w.data).includes("hunter2zz"), w.name);
    }
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

/** Arcane with repository connection `gitops` (r1); `syncs` lists this environment's syncs. */
function repoDeleteTransport(
  calls: Call[],
  syncs: Json[],
  del: () => Promise<unknown> = () => Promise.resolve({ success: true }),
) {
  return (_g: unknown, m: string, p: string): Promise<unknown> => {
    calls.push({ method: m, path: p });
    if (p === "/customize/git-repositories?limit=-1") {
      return Promise.resolve({
        data: [{ id: "r1", name: "gitops", url: "https://h/gitops.git" }],
      });
    }
    if (p === "/environments/0/gitops-syncs?limit=-1") {
      return Promise.resolve({ data: syncs });
    }
    if (m === "DELETE" && p === "/customize/git-repositories/r1") return del();
    return Promise.reject(new Error(`unexpected ${m} ${p}`));
  };
}

Deno.test("gitops_repo_delete deletes an unused connection", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    repoDeleteTransport(calls, [{ name: "x", repositoryId: "r9" }]),
  );
  try {
    const { message, written } = await errorOf("gitops_repo_delete", {
      name: "gitops",
    });
    assertEquals(message, "");
    assert(calls.some((c) => c.method === "DELETE"));
    assertEquals(written[0].name, "repository:gitops");
    assertEquals(written[0].data.action, "deleted");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_repo_delete counts a connection that is already gone as deleted", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(repoDeleteTransport(calls, []));
  try {
    const gone = await errorOf("gitops_repo_delete", { name: "absent" });
    assertEquals(gone.message, "");
    assertEquals(gone.written[0].data.action, "deleted");
    assert(!calls.some((c) => c.method === "DELETE"), "nothing to delete");
  } finally {
    __setArcaneTransport(null);
  }
  // Deleted between the list and the DELETE: Arcane answers 404.
  __setArcaneTransport(
    repoDeleteTransport(
      [],
      [],
      () => Promise.reject(new Error("Arcane DELETE -> HTTP 404: not found")),
    ),
  );
  try {
    const raced = await errorOf("gitops_repo_delete", { name: "gitops" });
    assertEquals(raced.message, "");
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_repo_delete refuses a connection a sync uses, without deleting", async () => {
  const calls: Call[] = [];
  __setArcaneTransport(
    repoDeleteTransport(calls, [{ name: "web", repositoryId: "r1" }]),
  );
  try {
    const { message } = await errorOf("gitops_repo_delete", { name: "gitops" });
    assert(/is used by sync\(s\) web/.test(message), message);
    assert(!calls.some((c) => c.method === "DELETE"));
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("gitops_repo_delete surfaces Arcane's refusal with its likely reason", async () => {
  __setArcaneTransport(repoDeleteTransport([], [], () =>
    Promise.reject(
      new Error("Arcane DELETE -> HTTP 500: Failed to delete git repository"),
    )));
  try {
    const { message } = await errorOf("gitops_repo_delete", { name: "gitops" });
    assert(/HTTP 500/.test(message) && /any sync uses/.test(message), message);
  } finally {
    __setArcaneTransport(null);
  }
});

Deno.test("project_deploy needs two healthy checks in a row", async () => {
  // Healthy, then crashed, then healthy twice.
  const answers = ["running", "partially running", "running", "running"];
  let looks = 0;
  const base = deployTransport(() => Promise.resolve(STREAM_DONE), "healthy");
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport((g, m, p, b, t) => {
    if (m === "GET" && p === "/environments/0/projects/p1") {
      const status = answers[Math.min(looks++, answers.length - 1)];
      return Promise.resolve({
        data: { status, serviceCount: 1, runningCount: 1 },
      });
    }
    return base(g, m, p, b, t);
  });
  try {
    const { message } = await errorOf("project_deploy", {
      name: "web",
      composeContent: "NEW",
      healthTimeoutSec: 10,
      pollIntervalSec: 1,
    });
    assertEquals(message, "");
    assertEquals(looks, 4, "healthy only on the second check in a row");
  } finally {
    __setArcaneTransport(null);
    __setComposeValidator(null);
  }
});

Deno.test("reachable check warns when the base URL is http", async () => {
  __setArcaneTransport(() => Promise.resolve({ data: { id: "u1" } }));
  const warnings: string[] = [];
  try {
    const checks = (model as unknown as {
      checks: Record<string, {
        execute: (c: unknown) => Promise<{ pass: boolean }>;
      }>;
    }).checks;
    const logger = { warn: (m: string) => warnings.push(m) };
    const http = await checks.reachable.execute({
      globalArgs: { baseUrl: "http://arcane.example.com", apiKey: "k" },
      logger,
    });
    assertEquals(http.pass, true, "a warning, not a failure");
    assertEquals(warnings.length, 1);
    assert(/clear text/.test(warnings[0]));
    await checks.reachable.execute({
      globalArgs: { baseUrl: "https://arcane.example.com", apiKey: "k" },
      logger,
    });
    assertEquals(warnings.length, 1, "no warning over https");
  } finally {
    __setArcaneTransport(null);
  }
});
