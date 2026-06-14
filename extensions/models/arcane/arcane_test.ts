/**
 * Unit tests for the pure logic of `@thomas/arcane`. These cover the bits where a
 * silent bug would be costly: the `{success,data}` envelope unwrap, the swarm
 * service-spec re-point (the heart of secret/config rotation), base64 encoding,
 * and the deploy/rotation health & convergence predicates. No network I/O.
 */
import {
  __setArcaneTransport,
  __setComposeValidator,
  b64,
  coerceList,
  model,
  projectHealthy,
  pruneResult,
  renderNames,
  repointServiceRefs,
  serviceConvergence,
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
  assertEquals(coerceList({ nope: 1 }), []);
  assertEquals(coerceList(null), []);
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
    serviceConvergence(undefined, false, 3, 3),
    "converged",
    "no update + replicas met",
  );
  assertEquals(serviceConvergence("completed", true, 3, 3), "converged");
  assertEquals(serviceConvergence("updating", true, 3, 1), "pending");
  assertEquals(
    serviceConvergence("completed", true, 3, 2),
    "pending",
    "update done but replicas short",
  );
  assertEquals(serviceConvergence("paused", true, 3, 0), "failed");
  assertEquals(serviceConvergence("rollback_completed", true, 3, 3), "failed");
  assertEquals(
    serviceConvergence(undefined, false, undefined, undefined),
    "converged",
    "no counts reported",
  );
});

// --- Orchestration method tests (mocked Arcane transport + compose validator) ---
//
// These exercise the branching of project_deploy and secret_rotate against scripted
// API responses, using the __setArcaneTransport / __setComposeValidator test seams.
// A minimal fake context stands in for swamp's runtime (only globalArgs, logger, and
// writeResource are used by these methods). Note: calling execute() directly bypasses
// the zod argument parsing swamp does at runtime, so defaults (rollback, removeOld,
// timeouts) are passed explicitly here.

type Call = { method: string; path: string; body?: unknown };
type WriteCall = {
  specName: string;
  name: string;
  data: Record<string, unknown>;
};

const TEST_GLOBALS = {
  baseUrl: "https://arcane.test",
  apiKey: "test-key",
  environmentId: "0",
  skipTlsVerify: false,
  syncs: [],
};

function makeContext(globalArgs: Record<string, unknown>) {
  const written: WriteCall[] = [];
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
  };
  return { context, written };
}

type MethodDef = {
  execute: (
    args: unknown,
    context: unknown,
  ) => Promise<{ dataHandles: unknown[] }>;
};
function method(name: string): MethodDef {
  return (model.methods as unknown as Record<string, MethodDef>)[name];
}

const bodyOf = (c: Call): Record<string, unknown> =>
  (c.body ?? {}) as Record<string, unknown>;

Deno.test("project_deploy direct mode: validate → update → redeploy → healthy", async () => {
  const calls: Call[] = [];
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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
        return Promise.resolve({ success: true, data: { message: "ok" } });
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

Deno.test("project_deploy direct mode: unhealthy deploy rolls back to prior content and throws", async () => {
  const calls: Call[] = [];
  let putCount = 0;
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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
        return Promise.resolve({ success: true, data: {} });
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
  // Arcane rejects bad deploys synchronously (a container that exits → HTTP 400), so the
  // redeploy throws rather than returning an unhealthy status. The failed deploy must
  // still roll back to prior content — this is the path the live smoke test exposed.
  const calls: Call[] = [];
  let putCount = 0;
  __setComposeValidator(() => Promise.resolve({ version: "v2.test" }));
  __setArcaneTransport(
    (_g: unknown, m: string, p: string, b?: unknown): Promise<unknown> => {
      calls.push({ method: m, path: p, body: b });
      if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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
        return putCount >= 2
          ? Promise.resolve({ success: true, data: {} })
          : Promise.reject(
            new Error(
              "Arcane POST /redeploy -> HTTP 400: container exited (1)",
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
      if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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

Deno.test("secret_rotate: create v2 → re-point service (mount preserved) → remove v1", async () => {
  const calls: Call[] = [];
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
            { name: "unifi_unifi", replicas: 1, runningReplicas: 1 },
            { name: "unifi_unifi-db", replicas: 1, runningReplicas: 1 },
          ],
        });
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
          data: [{ name: "x_x", replicas: 1, runningReplicas: 0 }],
        });
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

Deno.test("swarm_stack_remove re-issues DELETE until the record clears (teardown two-call bug)", async () => {
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
        // Arcane keeps the stored record after the first `docker stack rm`
        // (services:0); only the second DELETE clears it.
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
      { name: "two", pollIntervalSec: 0, removeTimeoutSec: 5 },
      context,
    );
    const stackDeletes = calls.filter((c) =>
      c.method === "DELETE" && c.path === "/environments/0/swarm/stacks/two"
    ).length;
    assertEquals(stackDeletes, 2, "issues a second DELETE to clear the record");
    const rec = written.find((w) => w.specName === "swarm-stack");
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
      // DELETE "succeeds" but the record never disappears — must not loop forever
      // and must not report a phantom success.
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
        { name: "stuck", pollIntervalSec: 0, removeTimeoutSec: 0 },
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
    error: "bind source path does not exist: /docker/unifi",
  });
  assertEquals(r.serviceName, "unifi_unifi");
  assertEquals(r.currentState, "rejected");
  assertEquals(r.error, "bind source path does not exist: /docker/unifi");
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
              { id: "ok1", serviceName: "unifi_unifi-db", currentState: "running" },
              { id: "bad1", serviceName: "unifi_unifi", currentState: "rejected", error: "no /docker/unifi" },
              { id: "old1", serviceName: "unifi_unifi", currentState: "shutdown" },
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
      written.some((w) => w.data.error === "no /docker/unifi"),
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
          },
        });
      }
      if (m === "PUT" && p === "/environments/0/swarm/services/svc1") {
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

Deno.test("volume_remove: idempotent on 404, surfaces 409", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "DELETE" && p.startsWith("/environments/0/volumes/gone")) {
        return Promise.reject(
          new Error("Arcane DELETE -> HTTP 404: no such volume"),
        );
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context, written } = makeContext(TEST_GLOBALS);
    await method("volume_remove").execute(
      { name: "gone", force: false },
      context,
    );
    assert(
      written.some((w) =>
        w.specName === "volume" && w.data.action === "deleted"
      ),
      "404 treated as already-deleted",
    );
  } finally {
    __setArcaneTransport(null);
  }
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "DELETE" && p.startsWith("/environments/0/volumes/busy")) {
        // Arcane returns the in-use error as HTTP 500 (not 409) in practice
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
        { name: "busy", force: false },
        context,
      );
    } catch (e) {
      surfaced = e instanceof Error && /in use/.test(e.message);
    }
    assert(surfaced, "409 surfaced as a clear in-use error (not forced)");
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
          data: { spaceReclaimed: 500, imagesDeleted: [{ Deleted: "sha256:z" }] },
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
          releaseUrl: "https://github.com/getarcaneapp/arcane/releases/tag/v2.0.3",
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
    assertEquals(r!.name, "arcane");
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
      if (m === "GET" && p === "/environments/0/gitops-syncs") {
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
    const web = statuses.find((w) => w.name === "web");
    assertEquals(web!.data.lastSyncStatus, "success");
    assertEquals(web!.data.lastSyncCommit, "abc1234");
    assertEquals(web!.data.lastSyncError, undefined);
    const db = statuses.find((w) => w.name === "db");
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
      if (m === "GET" && p === "/environments/0/gitops-syncs") {
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
