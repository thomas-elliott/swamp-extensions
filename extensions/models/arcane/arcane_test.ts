/**
 * Unit tests for the pure logic of `@thomas/arcane`. These cover the code where an
 * unnoticed bug would be costly: the `{success,data}` envelope unwrap, the swarm
 * service-spec re-point (the core step of secret/config rotation), base64 encoding,
 * and the deploy/rotation health & convergence predicates. No network I/O.
 */
import {
  __setArcaneTransport,
  __setComposeValidator,
  b64,
  coerceList,
  type Json,
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
        return putCount >= 2 ? Promise.resolve(STREAM_DONE) : Promise.reject(
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
              {
                id: "ok1",
                serviceName: "unifi_unifi-db",
                currentState: "running",
              },
              {
                id: "bad1",
                serviceName: "unifi_unifi",
                currentState: "rejected",
                error: "no /docker/unifi",
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
        if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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
        if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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
    assert(/is in use — not removed/.test(message), message);
    assertEquals(paths, ["/environments/0/volumes/v1"], "no force=true");
  } finally {
    __setArcaneTransport(null);
  }
});

// ─────────────────────────── timeouts and validation ───────────────────────────

Deno.test("redeploy and lifecycle calls get the long timeout; reads keep the short one", async () => {
  const timeouts: Record<string, number | undefined> = {};
  __setArcaneTransport((_g, m, p, _b, timeoutMs) => {
    timeouts[`${m} ${p}`] = timeoutMs;
    if (p.endsWith("/projects?limit=-1")) {
      return Promise.resolve([{ id: "p1", name: "web" }]);
    }
    return Promise.resolve(STREAM_DONE);
  });
  try {
    const { context } = makeContext(TEST_GLOBALS);
    await method("project_redeploy").execute({ names: ["web"] }, context);
    assertEquals(timeouts["GET /environments/0/projects?limit=-1"], 30_000);
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
      if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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
    if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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

Deno.test("project_deploy in gitops mode fails on an error line in the redeploy body", async () => {
  __setArcaneTransport(
    (_g: unknown, m: string, p: string): Promise<unknown> => {
      if (m === "GET" && p === "/environments/0/projects?limit=-1") {
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
        return Promise.resolve(
          '{"type":"activity","activityId":"a1"}\n{"error":"service web: container exited (1)"}\n',
        );
      }
      return Promise.reject(new Error(`unexpected ${m} ${p}`));
    },
  );
  try {
    const { context } = makeContext(TEST_GLOBALS);
    let message = "";
    try {
      await method("project_deploy").execute(
        { name: "web", healthTimeoutSec: 1, pollIntervalSec: 1 },
        context,
      );
    } catch (e) {
      message = e instanceof Error ? e.message : String(e);
    }
    assert(
      /redeploy failed: service web: container exited/.test(message),
      `got: ${message}`,
    );
  } finally {
    __setArcaneTransport(null);
  }
});
