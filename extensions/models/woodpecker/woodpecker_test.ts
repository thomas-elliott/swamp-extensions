/**
 * Unit tests for the important, security-sensitive logic of `@thomas/woodpecker`:
 * repo_enable find-or-activate idempotency, the trusted-object merge (partial
 * trust must not overwrite capabilities it omits), the create-vs-update secret
 * upsert, the secret-value-never-stored guarantee (value is sent on the wire but
 * never written to a resource), and the idempotent delete-on-404. No live
 * server: the API caller is faked via the __setCaller seam.
 */
import { z } from "npm:zod@4";
import {
  __setCaller,
  type ApiCall,
  type ApiResult,
  type CallerFn,
  dataName,
  model,
} from "./woodpecker.ts";

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
  apiUrl: "https://woodpecker.test.example.com:8443",
  token: "test-token",
  httpTimeoutMs: 30000,
};

type Recorded = { method: string; path: string; body?: unknown };

/**
 * A fake API caller. `respond` returns either a body or a `{status, body}` per
 * (method, path) match; a bare body implies status 200, undefined implies a 404
 * empty result (so existence probes can be exercised). The one exception is
 * `GET /api/repos/1`, which falls back to {@link repoObj}: most tests address
 * repo `1`, and methods fetch it to store its full name.
 */
function makeFakeApi(
  respond?: (
    c: ApiCall,
  ) => Record<string, unknown> | {
    status: number;
    body: Record<string, unknown>;
  } | undefined,
) {
  const calls: Recorded[] = [];
  const caller: CallerFn = (_g, c): Promise<ApiResult> => {
    calls.push({ method: c.method, path: c.path, body: c.body });
    const r = respond?.(c) ??
      (c.method === "GET" && c.path === "/api/repos/1" ? repoObj() : undefined);
    if (r === undefined) return Promise.resolve({ status: 404, body: {} });
    if (typeof r === "object" && r !== null && "status" in r && "body" in r) {
      return Promise.resolve(r as ApiResult);
    }
    return Promise.resolve({ status: 200, body: r as Record<string, unknown> });
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
    logger: { info: noop, debug: noop, warn: noop, error: noop },
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

// A realistic enabled-repo object as the server returns it.
function repoObj(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 1,
    full_name: "octo-org/web",
    owner: "octo-org",
    name: "web",
    forge_remote_id: "586125582",
    active: true,
    trusted: { network: false, volumes: false, security: false },
    timeout: 60,
    visibility: "private",
    require_approval: "forks",
    default_branch: "main",
    ...over,
  };
}

// ─────────────────────────── tests ───────────────────────────

Deno.test("repo_enable: not-yet-active repo is activated via forge_remote_id", async () => {
  const calls: Recorded[] = [];
  const caller: CallerFn = (_g, c) => {
    calls.push({ method: c.method, path: c.path, body: c.body });
    if (c.path.startsWith("/api/repos/lookup/")) {
      return Promise.resolve({ status: 404, body: {} }); // not active yet
    }
    if (c.path === "/api/user/repos?all=true") {
      // this endpoint returns a JSON array
      return Promise.resolve({
        status: 200,
        body: ([{
          full_name: "octo-org/web",
          forge_remote_id: "586125582",
          active: false,
        }] as unknown) as Record<string, unknown>,
      });
    }
    if (
      c.method === "POST" && c.path.startsWith("/api/repos?forge_remote_id=")
    ) {
      return Promise.resolve({ status: 200, body: repoObj() });
    }
    return Promise.resolve({ status: 200, body: {} });
  };
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_enable").execute(
      { repo: "octo-org/web" },
      context,
    );
    const post = calls.find((c) =>
      c.method === "POST" &&
      c.path === "/api/repos?forge_remote_id=586125582"
    );
    assert(post, "issued the activate POST with the resolved forge_remote_id");
    assertEquals(written[0].data.action, "enabled");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_enable: already-active + no settings -> unchanged, no PATCH", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/repos/lookup/")) return repoObj();
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_enable").execute(
      { repo: "octo-org/web" },
      context,
    );
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "no PATCH when nothing changed",
    );
    assert(
      !calls.some((c) => c.method === "POST"),
      "no activate POST when already active",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_enable: a disabled repo (lookup active:false) is re-activated", async () => {
  // Upstream keeps a disabled repo's row with active=false, and the lookup
  // returns it; PostRepo re-activates such a repo (`enabledOnce`).
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/repos/lookup/")) {
      return repoObj({ active: false });
    }
    if (c.path === "/api/user/repos?all=true") {
      return {
        status: 200,
        body: ([{
          full_name: "octo-org/web",
          forge_remote_id: "586125582",
          active: false,
        }] as unknown) as Record<string, unknown>,
      };
    }
    if (c.method === "POST") return repoObj();
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_enable").execute({ repo: "octo-org/web" }, context);
    assert(
      calls.some((c) =>
        c.method === "POST" &&
        c.path === "/api/repos?forge_remote_id=586125582"
      ),
      "issued the activate POST",
    );
    assertEquals(written[0].data.action, "enabled");
    assertEquals(written[0].data.active, true);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_enable: requireApproval takes upstream's all_events, not all", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/repos/lookup/")) return repoObj();
    if (c.method === "PATCH") {
      return repoObj({ require_approval: "all_events" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("repo_enable").execute(
          { repo: "octo-org/web", requireApproval: "all" },
          context,
        ),
      /invalid option/i,
    );
    assertEquals(calls.length, 0, "rejected before any API call");
    await method("repo_enable").execute(
      { repo: "octo-org/web", requireApproval: "all_events" },
      context,
    );
    assertEquals(
      calls.find((c) => c.method === "PATCH")?.body,
      { require_approval: "all_events" },
    );
    assertEquals(written[0].data.requireApproval, "all_events");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_enable: trusted=true sets all three; partial trust merges", async () => {
  let patchBody: Record<string, unknown> | undefined;
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/repos/lookup/")) {
      return repoObj({
        trusted: { network: true, volumes: false, security: false },
      });
    }
    if (c.method === "PATCH") {
      patchBody = c.body as Record<string, unknown>;
      return repoObj({
        trusted: { network: true, volumes: true, security: true },
      });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    // Only flip volumes; network already true must be preserved in the merge.
    await method("repo_enable").execute(
      { repo: "octo-org/web", trustedVolumes: true },
      context,
    );
    assertEquals(
      patchBody?.trusted,
      { network: true, volumes: true, security: false },
      "partial trust merged over current, network preserved",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_update: timeout change issues a PATCH; same value is unchanged", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1") return repoObj({ timeout: 60 });
    if (c.method === "PATCH") return repoObj({ timeout: 30 });
    return undefined;
  });
  __setCaller(caller);
  try {
    // change
    let { context, written } = makeContext();
    await method("repo_update").execute({ repo: "1", timeout: 30 }, context);
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.body, { timeout: 30 });
    assertEquals(written[0].data.action, "updated");
    // no-op
    calls.length = 0;
    ({ context, written } = makeContext());
    await method("repo_update").execute({ repo: "1", timeout: 60 }, context);
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "no PATCH when timeout matches",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("org_secret_set: 404 probe -> POST create; sends value but never stores it", async () => {
  let postBody: Record<string, unknown> | undefined;
  const caller: CallerFn = (_g, c) => {
    if (c.path === "/api/orgs/lookup/octo-org") {
      return Promise.resolve({ status: 200, body: { id: 1, is_user: true } });
    }
    if (c.method === "GET" && c.path.endsWith("/secrets/ghcr_token")) {
      return Promise.resolve({ status: 404, body: {} }); // does not exist
    }
    if (c.method === "POST" && c.path === "/api/orgs/1/secrets") {
      postBody = c.body as Record<string, unknown>;
      return Promise.resolve({
        status: 200,
        body: {
          id: 9,
          name: "ghcr_token",
          events: ["push", "tag"],
          images: [],
        },
      });
    }
    return Promise.resolve({ status: 200, body: {} });
  };
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("org_secret_set").execute(
      { owner: "octo-org", name: "ghcr_token", value: "SUPER_SECRET" },
      context,
    );
    assertEquals(postBody?.value, "SUPER_SECRET", "value sent on the wire");
    assertEquals(postBody?.events, ["push", "tag"], "default events on create");
    assertEquals(postBody?.images, [], "default images on create");
    assertEquals(written[0].data.action, "created");
    assert(
      !("value" in (written[0].data as Record<string, unknown>)),
      "secret value is NEVER written to the data model",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("org_secret_set: existing secret -> PATCH update", async () => {
  const calls: string[] = [];
  const caller: CallerFn = (_g, c) => {
    calls.push(`${c.method} ${c.path}`);
    if (c.path === "/api/orgs/lookup/octo-org") {
      return Promise.resolve({ status: 200, body: { id: 1 } });
    }
    if (c.method === "GET" && c.path.endsWith("/secrets/ghcr_token")) {
      return Promise.resolve({
        status: 200,
        body: { id: 9, name: "ghcr_token" },
      });
    }
    return Promise.resolve({
      status: 200,
      body: { id: 9, name: "ghcr_token" },
    });
  };
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("org_secret_set").execute(
      { owner: "octo-org", name: "ghcr_token", value: "v" },
      context,
    );
    assert(
      calls.some((s) => s === "PATCH /api/orgs/1/secrets/ghcr_token"),
      "updates via PATCH when it already exists",
    );
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

// Same bug class as forgejo issue #4: rotating a value must not reset the
// secret's events or widen it to every image.
Deno.test("org_secret_set: PATCH sends only the fields that were passed", async () => {
  const patches: unknown[] = [];
  const caller: CallerFn = (_g, c) => {
    if (c.path === "/api/orgs/lookup/octo-org") {
      return Promise.resolve({ status: 200, body: { id: 1 } });
    }
    if (c.method === "PATCH") patches.push(c.body);
    return Promise.resolve({
      status: 200,
      body: { id: 9, name: "ghcr_token" },
    });
  };
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("org_secret_set").execute(
      { owner: "octo-org", name: "ghcr_token", value: "v" },
      context,
    );
    await method("org_secret_set").execute(
      {
        owner: "octo-org",
        name: "ghcr_token",
        value: "v",
        images: ["woodpeckerci/plugin-docker-buildx"],
      },
      context,
    );
    assertEquals(patches, [
      { name: "ghcr_token", value: "v" },
      {
        name: "ghcr_token",
        value: "v",
        images: ["woodpeckerci/plugin-docker-buildx"],
      },
    ]);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_secret_delete: already-absent is an idempotent no-op (no DELETE)", async () => {
  const calls: string[] = [];
  const caller: CallerFn = (_g, c) => {
    calls.push(`${c.method} ${c.path}`);
    if (c.path === "/api/repos/1") {
      return Promise.resolve({ status: 200, body: repoObj() });
    }
    if (c.method === "GET" && c.path.endsWith("/secrets/gone")) {
      return Promise.resolve({ status: 404, body: {} });
    }
    return Promise.resolve({ status: 200, body: {} });
  };
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_secret_delete").execute(
      { repo: "1", name: "gone" },
      context,
    );
    assert(
      !calls.some((s) => s.startsWith("DELETE")),
      "no DELETE on a 404 probe",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("resolveRepoId: bare name (no slash, non-numeric) is rejected", async () => {
  const { caller } = makeFakeApi(() => undefined);
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("repo_get").execute({ repo: "web" }, context),
      /numeric id or "owner\/name"/,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_available: instance name is the spec plus the escaped full name", async () => {
  const caller: CallerFn = (_g, c) => {
    if (c.path === "/api/user/repos?all=true") {
      return Promise.resolve({
        status: 200,
        body: ([{
          full_name: "octo-org/web",
          forge_remote_id: "1",
          active: true,
        }] as unknown) as Record<string, unknown>,
      });
    }
    return Promise.resolve({ status: 200, body: {} });
  };
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_available").execute({}, context);
    // swamp rejects '/' in instance names, so the data name escapes it,
    // while the stored fullName field keeps the real slash.
    assertEquals(written[0].name, "available-repo:octo-org%2Fweb");
    assertEquals(written[0].data.fullName, "octo-org/web");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_secret_list: secret instance name uses the repo id", async () => {
  const caller: CallerFn = (_g, c) => {
    if (c.path === "/api/repos/1") {
      return Promise.resolve({ status: 200, body: repoObj() });
    }
    if (c.path.startsWith("/api/repos/1/secrets?")) {
      return Promise.resolve({
        status: 200,
        body: ([{
          id: 1,
          name: "ghcr_token",
          events: ["push"],
          images: [],
        }] as unknown) as Record<string, unknown>,
      });
    }
    return Promise.resolve({ status: 200, body: {} });
  };
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_secret_list").execute({ repo: "1" }, context);
    assertEquals(written[0].name, "secret:repo:1:ghcr_token");
    assertEquals(written[0].data.owner, "octo-org/web");
  } finally {
    __setCaller(null);
  }
});

Deno.test("model: no value field on the secret schema; deletes are reversible-only", () => {
  // The secret resource schema must not carry a value.
  const secretShape = JSON.stringify(model.resources.secret.schema);
  assert(!/"value"/.test(secretShape), "secret schema has no value field");
  // Destructive method names are limited to the documented reversible set.
  const names = Object.keys(model.methods);
  const deletish = names.filter((n) => /delete|disable/i.test(n));
  assertEquals(
    deletish.sort(),
    ["cron_delete", "org_secret_delete", "repo_disable", "repo_secret_delete"],
    "only the reversible disable/secret-delete methods exist",
  );
});

// ─────────────────────────── observability ───────────────────────────

// A pipeline with one workflow + two steps (one passed, one failed).
function pipelineWithSteps(
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    number: 5,
    status: "failure",
    workflows: [{
      name: "woodpecker",
      children: [
        { id: 10, name: "go", state: "success", exit_code: 0 },
        { id: 11, name: "build", state: "failure", exit_code: 1, error: "" },
      ],
    }],
    ...over,
  };
}

Deno.test("pipeline_steps: number omitted -> resolves latest, then flattens steps", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    // "latest" must list the most-recent of ANY event (perPage=1), NOT the
    // /pipelines/latest endpoint (which silently excludes tag pipelines).
    if (c.path === "/api/repos/1/pipelines?perPage=1") {
      return {
        status: 200,
        body: ([{ number: 5 }] as unknown) as Record<string, unknown>,
      };
    }
    if (c.path === "/api/repos/1/pipelines/5") return pipelineWithSteps();
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_steps").execute({ repo: "1" }, context);
    assert(
      calls.some((c) => c.path === "/api/repos/1/pipelines?perPage=1"),
      "resolves latest via list (includes tag pipelines)",
    );
    assert(
      !calls.some((c) => c.path === "/api/repos/1/pipelines/latest"),
      "must NOT use /pipelines/latest (excludes tags)",
    );
    assertEquals(written.length, 2, "one resource per step");
    assertEquals(written[0].data.name, "go");
    assertEquals(written[0].data.state, "success");
    assertEquals(written[1].data.state, "failure");
    assertEquals(
      written.map((w) => w.name),
      ["pipeline-step:1:5:10", "pipeline-step:1:5:11"],
    );
    assertEquals(written[1].data.stepId, 11);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_logs: decodes base64 lines, finds step by name, tails", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") return pipelineWithSteps();
    if (c.path === "/api/repos/1/logs/5/10") {
      return {
        status: 200,
        body: ([
          { data: btoa("hello") },
          { data: btoa("world") },
        ] as unknown) as Record<string, unknown>,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_logs").execute(
      { repo: "1", number: 5, step: "go" },
      context,
    );
    assertEquals(written[0].data.stepId, 10, "resolved step id by name");
    assertEquals(written[0].data.text, "hello\nworld", "decoded + joined");
    assertEquals(written[0].data.truncated, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_logs: unknown step rejects", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") return pipelineWithSteps();
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("pipeline_logs").execute(
          { repo: "1", number: 5, step: "nope" },
          context,
        ),
      /step "nope" not found/,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_wait: terminal on first poll -> no wait, writes pipeline + steps", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") {
      return pipelineWithSteps({ status: "success" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_wait").execute(
      { repo: "1", number: 5 },
      context,
    );
    // exactly one status fetch (already terminal, so no re-poll)
    assertEquals(
      calls.filter((c) => c.path === "/api/repos/1/pipelines/5").length,
      1,
    );
    assertEquals(written[0].specName, "pipeline");
    assertEquals(written[0].data.status, "success");
    // failed step is surfaced
    assert(
      written.some((w) =>
        w.specName === "pipeline-step" && w.data.state === "failure"
      ),
      "failed step written",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("status_all: per-repo latest; no pipelines -> status 'none'", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/repos?")) {
      return {
        status: 200,
        body: ([
          { id: 1, full_name: "o/a" },
          { id: 2, full_name: "o/b" },
        ] as unknown) as Record<string, unknown>,
      };
    }
    if (c.path === "/api/repos/1/pipelines?perPage=1") {
      return {
        status: 200,
        body: ([{
          status: "success",
          number: 3,
          event: "push",
          branch: "main",
        }] as unknown) as Record<string, unknown>,
      };
    }
    if (c.path === "/api/repos/2/pipelines?perPage=1") {
      // empty list -> repo has never run
      return { status: 200, body: ([] as unknown) as Record<string, unknown> };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("status_all").execute({}, context);
    assertEquals(written.length, 2);
    assertEquals(written[0].data.status, "success");
    assertEquals(written[1].data.status, "none", "no pipelines -> none");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── run control ───────────────────────────

Deno.test("pipeline_cancel: already-finished is a no-op (no cancel POST)", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") {
      return pipelineWithSteps({ status: "success" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_cancel").execute({ repo: "1", number: 5 }, context);
    assert(
      !calls.some((c) => c.path.endsWith("/cancel")),
      "no cancel POST on a finished pipeline",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_restart: POSTs to the pipeline; action 'restarted'", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "POST" && c.path === "/api/repos/1/pipelines/5") {
      return { number: 6, status: "pending" };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_restart").execute({ repo: "1", number: 5 }, context);
    assert(
      calls.some((c) =>
        c.method === "POST" && c.path === "/api/repos/1/pipelines/5"
      ),
      "issued restart POST",
    );
    assertEquals(written[0].data.action, "restarted");
    assertEquals(written[0].data.number, 6, "new run number");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── cron ───────────────────────────

Deno.test("cron_set: no existing -> POST create; identical -> unchanged (no write)", async () => {
  // create
  let { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.startsWith("/api/repos/1/cron?")) {
      return { status: 200, body: ([] as unknown) as Record<string, unknown> };
    }
    if (c.method === "POST" && c.path === "/api/repos/1/cron") {
      return { id: 7, name: "nightly", schedule: "@daily" };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_set").execute(
      { repo: "1", name: "nightly", schedule: "@daily" },
      context,
    );
    assert(
      calls.some((c) => c.method === "POST" && c.path === "/api/repos/1/cron"),
      "creates via POST",
    );
    assertEquals(written[0].data.action, "created");
  } finally {
    __setCaller(null);
  }
  // unchanged
  ({ caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.startsWith("/api/repos/1/cron?")) {
      return {
        status: 200,
        body: ([{
          id: 7,
          name: "nightly",
          schedule: "@daily",
          branch: "",
        }] as unknown) as Record<string, unknown>,
      };
    }
    return undefined;
  }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_set").execute(
      { repo: "1", name: "nightly", schedule: "@daily" },
      context,
    );
    assert(
      !calls.some((c) => c.method === "POST" || c.method === "PATCH"),
      "no write when schedule/branch already match",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("cron_set: create sends enabled:true (v3.13+ binds an omitted field to false)", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.startsWith("/api/repos/1/cron?")) {
      return { status: 200, body: ([] as unknown) as Record<string, unknown> };
    }
    if (c.method === "POST" && c.path === "/api/repos/1/cron") {
      return { id: 7, name: "nightly", schedule: "@daily", enabled: true };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_set").execute(
      { repo: "1", name: "nightly", schedule: "@daily" },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.body, {
      name: "nightly",
      schedule: "@daily",
      enabled: true,
    });
    assertEquals(written[0].data.enabled, true);
  } finally {
    __setCaller(null);
  }
});

Deno.test("cron_set: a disabled cron with a matching schedule is re-enabled by PATCH", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.startsWith("/api/repos/1/cron?")) {
      return {
        status: 200,
        body: ([{
          id: 7,
          name: "nightly",
          schedule: "@daily",
          branch: "",
          enabled: false,
        }] as unknown) as Record<string, unknown>,
      };
    }
    if (c.method === "PATCH" && c.path === "/api/repos/1/cron/7") {
      return { id: 7, name: "nightly", schedule: "@daily", enabled: true };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_set").execute(
      { repo: "1", name: "nightly", schedule: "@daily" },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      (patch?.body as Record<string, unknown> | undefined)?.enabled,
      true,
    );
    assertEquals(written[0].data.action, "updated");
    assertEquals(written[0].data.enabled, true);
  } finally {
    __setCaller(null);
  }
});

/** A fake API whose repo 1 holds the given crons; POST and PATCH echo the body. */
function fakeCronApi(crons: Record<string, unknown>[]) {
  return makeFakeApi((c) => {
    if (c.method === "GET" && c.path.startsWith("/api/repos/1/cron?")) {
      return {
        status: 200,
        body: (crons as unknown) as Record<string, unknown>,
      };
    }
    if (c.method === "POST" && c.path === "/api/repos/1/cron") {
      return { id: 7, ...(c.body as Record<string, unknown>) };
    }
    if (c.method === "PATCH" && c.path === "/api/repos/1/cron/7") {
      return { ...(c.body as Record<string, unknown>) };
    }
    return undefined;
  });
}

Deno.test("cron_set: enabled=false creates the cron disabled", async () => {
  const { caller, calls } = fakeCronApi([]);
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_set").execute(
      { repo: "1", name: "nightly", schedule: "@daily", enabled: false },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(
      (post?.body as Record<string, unknown> | undefined)?.enabled,
      false,
    );
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.enabled, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("cron_set: enabled=false leaves a disabled cron unchanged", async () => {
  const { caller, calls } = fakeCronApi([
    { id: 7, name: "nightly", schedule: "@daily", branch: "", enabled: false },
  ]);
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_set").execute(
      { repo: "1", name: "nightly", schedule: "@daily", enabled: false },
      context,
    );
    assert(
      !calls.some((c) => c.method === "POST" || c.method === "PATCH"),
      "no write when the cron is already disabled",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("cron_set: enabled=false disables an enabled cron by PATCH", async () => {
  const { caller, calls } = fakeCronApi([
    { id: 7, name: "nightly", schedule: "@daily", branch: "", enabled: true },
  ]);
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_set").execute(
      { repo: "1", name: "nightly", schedule: "@daily", enabled: false },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      (patch?.body as Record<string, unknown> | undefined)?.enabled,
      false,
    );
    assertEquals(written[0].data.action, "updated");
    assertEquals(written[0].data.enabled, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("cron_delete: already-absent is an idempotent no-op (no DELETE)", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.startsWith("/api/repos/1/cron?")) {
      return { status: 200, body: ([] as unknown) as Record<string, unknown> };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_delete").execute(
      { repo: "1", name: "gone" },
      context,
    );
    assert(
      !calls.some((c) => c.method === "DELETE"),
      "no DELETE when the cron is already absent",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("server_info: healthz 503 -> healthy:false, version surfaced", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/version") return { version: "3.15.0", source: "x" };
    if (c.path === "/healthz") return { status: 503, body: {} };
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("server_info").execute({}, context);
    assertEquals(written[0].data.version, "3.15.0");
    assertEquals(written[0].data.healthy, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_enable: a cross-forge repo explains the forge binding", async () => {
  // /api/user/repos is scoped to the forge the token's user authenticated
  // against, so a repo on the server's OTHER forge is absent from it and a bare
  // not-found suggests the repo does not exist.
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/repos/lookup/")) return undefined; // 404
    if (c.path === "/api/user/repos?all=true") {
      return {
        status: 200,
        body: ([{
          full_name: "octo-org/web",
          forge_remote_id: "586125582",
          forge_id: 1,
          active: false,
        }] as unknown) as Record<string, unknown>,
      };
    }
    if (c.path === "/api/user") return { login: "octo-org", forge_id: 1 };
    if (c.path.startsWith("/api/forges?")) {
      return {
        status: 200,
        body: ([
          { id: 1, type: "github", url: "https://github.com" },
          { id: 2, type: "forgejo", url: "https://forgejo.example.com" },
        ] as unknown) as Record<string, unknown>,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("repo_enable").execute({ repo: "other-org/web" }, context),
      /bound to the forge it authenticated against.*octo-org on forge 1 \(github/s,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_enable: a broken diagnostic never masks the real error", async () => {
  // forgeBindingHint runs on the error path; if /api/user itself fails, the
  // caller must still get the not-found error rather than the probe's.
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/user/repos?all=true") {
      return { status: 200, body: ([] as unknown) as Record<string, unknown> };
    }
    return undefined; // lookup 404s, and so does /api/user
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("repo_enable").execute({ repo: "other-org/web" }, context),
      /not found among forge repos the token can access\. .*admin of it on the forge\.$/,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("forge_list: flags the token's own forge", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/user") return { login: "octo-user", forge_id: 2 };
    if (c.path.startsWith("/api/forges?")) {
      return {
        status: 200,
        body: ([
          { id: 1, type: "github", url: "https://github.com" },
          { id: 2, type: "forgejo", url: "https://forgejo.example.com" },
        ] as unknown) as Record<string, unknown>,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("forge_list").execute({}, context);
    assertEquals(written.map((w) => w.data.isTokenForge), [false, true]);
    assertEquals(written[1].data.type, "forgejo");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_available: carries forge_id through to the resource", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/user/repos?all=true") {
      return {
        status: 200,
        body: ([{
          full_name: "octo-org/web",
          forge_remote_id: "42",
          forge_id: 2,
          active: false,
        }] as unknown) as Record<string, unknown>,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_available").execute({}, context);
    assertEquals(written[0].data.forgeId, 2);
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── reachable check ───────────────────────────

// A check receives globalArgs without the schema's defaults, so an unset
// httpTimeoutMs must not reach fetch as undefined (that aborts at once).
Deno.test("reachable check applies the schema defaults to globalArgs", async () => {
  let seenTimeout: unknown;
  __setCaller((g) => {
    seenTimeout = g.httpTimeoutMs;
    return Promise.resolve({ status: 200, body: { login: "bot" } });
  });
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: { apiUrl: GLOBALS.apiUrl, token: GLOBALS.token },
    });
    assertEquals(res.pass, true);
    assertEquals(seenTimeout, 30000);
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── pagination ───────────────────────────

Deno.test("repo_secret_list: walks pages until a short one (52 secrets over 2 pages)", async () => {
  const secret = (i: number) => ({ id: i, name: `s${i}`, events: ["push"] });
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1") return repoObj();
    const m = c.path.match(/^\/api\/repos\/1\/secrets\?page=(\d+)&perPage=50$/);
    if (m) {
      const page = Number(m[1]);
      const body = page === 1
        ? Array.from({ length: 50 }, (_, i) => secret(i + 1))
        : page === 2
        ? [secret(51), secret(52)]
        : [];
      return { status: 200, body: body as unknown as Record<string, unknown> };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_secret_list").execute({ repo: "1" }, context);
    const pages = calls.filter((c) => c.path.includes("/secrets?")).map((c) =>
      c.path
    );
    assertEquals(pages, [
      "/api/repos/1/secrets?page=1&perPage=50",
      "/api/repos/1/secrets?page=2&perPage=50",
    ], "page 2 was short, so no page 3");
    assertEquals(written.length, 52);
    assertEquals(written[51].data.name, "s52", "the 52nd secret is visible");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_list: limit above 50 spans pages and is trimmed exactly", async () => {
  const pipe = (n: number) => ({ number: n, status: "success", event: "push" });
  const { caller, calls } = makeFakeApi((c) => {
    const m = c.path.match(
      /^\/api\/repos\/1\/pipelines\?page=(\d+)&perPage=(\d+)$/,
    );
    if (m) {
      // Upstream `paginate`: the offset is perPage * (page - 1).
      const page = Number(m[1]);
      const perPage = Number(m[2]);
      const start = (page - 1) * perPage;
      const body = Array.from(
        { length: perPage },
        (_, i) => pipe(start + i + 1),
      );
      return { status: 200, body: body as unknown as Record<string, unknown> };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_list").execute({ repo: "1", limit: 60 }, context);
    assertEquals(calls.map((c) => c.path), [
      "/api/repos/1", // the repo's full name, for the records
      "/api/repos/1/pipelines?page=1&perPage=50",
      "/api/repos/1/pipelines?page=2&perPage=50",
    ]);
    assertEquals(
      written.map((w) => w.data.number),
      Array.from({ length: 60 }, (_, i) => i + 1),
      "pipelines 1-60, each once",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_list: a limit below 1 is rejected", async () => {
  const { caller, calls } = makeFakeApi(() => undefined);
  __setCaller(caller);
  try {
    const { context } = makeContext();
    for (const limit of [0, -5]) {
      await rejects(
        () => method("pipeline_list").execute({ repo: "1", limit }, context),
        /expected number to be >=1/i,
      );
    }
    assertEquals(calls.length, 0, "rejected before any API call");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── statuses ───────────────────────────

Deno.test("pipeline_cancel: blocked (awaiting approval) is cancellable upstream, so POST", async () => {
  let cancelled = false;
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.endsWith("/cancel")) {
      cancelled = true;
      return {};
    }
    if (c.path === "/api/repos/1/pipelines/5") {
      return pipelineWithSteps({ status: cancelled ? "killed" : "blocked" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_cancel").execute({ repo: "1", number: 5 }, context);
    assert(calls.some((c) => c.path.endsWith("/cancel")), "cancel POSTed");
    assertEquals(written[0].data.action, "cancelled");
    assertEquals(written[0].data.status, "killed");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_wait: a cancelled pipeline reports killed and stops on the first poll", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") {
      return pipelineWithSteps({ status: "killed" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_wait").execute(
      { repo: "1", number: 5, timeoutSec: 1 },
      context,
    );
    assertEquals(
      calls.filter((c) => c.path === "/api/repos/1/pipelines/5").length,
      1,
    );
    assertEquals(written[0].data.status, "killed");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_wait: a pipeline cancelled before it started (canceled) stops on the first poll", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") {
      return pipelineWithSteps({ status: "canceled" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_wait").execute(
      { repo: "1", number: 5, timeoutSec: 1 },
      context,
    );
    assertEquals(
      calls.filter((c) => c.path === "/api/repos/1/pipelines/5").length,
      1,
    );
    assertEquals(written[0].data.status, "canceled");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── strict booleans ───────────────────────────

Deno.test("trusted flags: strings are rejected, not coerced", async () => {
  const { caller, calls } = makeFakeApi(() => repoObj());
  __setCaller(caller);
  try {
    const { context } = makeContext();
    // swamp turns `--input trusted=true` into a boolean before execute runs,
    // so a string reaching execute is never valid.
    for (const bad of ["0", "False", "1", "yes", "true", "false", null]) {
      await rejects(
        () =>
          method("repo_update").execute(
            { repo: "1", trustedVolumes: bad },
            context,
          ),
        /expected boolean/,
      );
    }
    assertEquals(calls.length, 0, "rejected before any API call");
    const { context: ctx2 } = makeContext();
    await method("repo_update").execute(
      { repo: "1", trusted: false, trustedVolumes: true },
      ctx2,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("model: every method's arguments convert to JSON Schema", () => {
  // A .transform() cannot be converted, and swamp then drops every
  // description, default and enum for that method.
  for (const [name, m] of Object.entries(model.methods)) {
    const schema = z.toJSONSchema(m.arguments);
    assert(schema.$schema, `${name}: arguments have no JSON Schema`);
  }
});

Deno.test("model: the apiUrl example is a placeholder host, not a real one", () => {
  const description = model.globalArguments.shape.apiUrl.description ?? "";
  assert(
    description.includes("https://woodpecker.example.com"),
    `apiUrl example should use example.com: ${description}`,
  );
  assert(!description.includes(".ts.net"), "no tailnet hostname");
});

// ─────────────────────────── data names ───────────────────────────

Deno.test("dataName: spec prefix keeps specs that share a key apart", () => {
  assertEquals(dataName("repo", "1"), "repo:1");
  assertEquals(dataName("repo-status", "1"), "repo-status:1");
  assertEquals(dataName("server"), "server");
});

Deno.test("dataName: escaping is reversible, so different keys never share a name", () => {
  assertEquals(dataName("cron", "1:a/b"), "cron:1:a%2Fb");
  assertEquals(dataName("cron", "1:a%2Fb"), "cron:1:a%252Fb");
  assertEquals(dataName("cron", "1:a..b"), "cron:1:a.%2Eb");
  assertEquals(dataName("cron", "1:a\\b"), "cron:1:a%5Cb");
  for (const key of ["a..b", "a...b", "a/b", "x\\y", "n\0ul"]) {
    const name = dataName("cron", key);
    assert(!/[\\/\0]|\.\./.test(name), `unsafe name ${name}`);
  }
});

Deno.test("repo_get and status_all write the same repo id under distinct names", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1") return repoObj();
    if (c.path.startsWith("/api/repos?active=true")) {
      return (c.path.includes("page=1")
        ? [repoObj()]
        : []) as unknown as Record<
          string,
          unknown
        >;
    }
    if (c.path === "/api/repos/1/pipelines?perPage=1") {
      return { status: 200, body: [] as unknown as Record<string, unknown> };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_get").execute({ repo: "1" }, context);
    await method("status_all").execute({}, context);
    assertEquals(written.map((w) => w.name), ["repo:1", "repo-status:1"]);
  } finally {
    __setCaller(null);
  }
});

// A matrix pipeline: two workflows with the same name and the same step names.
function matrixPipeline(): Record<string, unknown> {
  return {
    number: 5,
    status: "success",
    workflows: [
      { name: "build", children: [{ id: 20, name: "test", state: "success" }] },
      { name: "build", children: [{ id: 21, name: "test", state: "failure" }] },
    ],
  };
}

Deno.test("pipeline_steps: matrix workflows with the same step name get distinct names", async () => {
  const { caller } = makeFakeApi((c) =>
    c.path === "/api/repos/1/pipelines/5" ? matrixPipeline() : undefined
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_steps").execute({ repo: "1", number: 5 }, context);
    assertEquals(
      written.map((w) => w.name),
      ["pipeline-step:1:5:20", "pipeline-step:1:5:21"],
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_logs: a step id picks the exact matrix step and names the log by id", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") return matrixPipeline();
    if (c.path === "/api/repos/1/logs/5/21") {
      return {
        status: 200,
        body: [{ data: btoa("x") }] as unknown as Record<string, unknown>,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_logs").execute(
      { repo: "1", number: 5, step: "21" },
      context,
    );
    assert(calls.some((c) => c.path === "/api/repos/1/logs/5/21"));
    assertEquals(written[0].name, "pipeline-log:1:5:21");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── upstream behaviour ───────────────────────────

Deno.test("pipeline_trigger without a branch uses the repo's default branch", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path === "/api/repos/1") return repoObj();
    if (c.method === "POST") return { number: 7, status: "pending" };
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("pipeline_trigger").execute({ repo: "1" }, context);
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.body, { branch: "main" });
  } finally {
    __setCaller(null);
  }
});

Deno.test("cron_set without a branch is unchanged when the schedule matches", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/repos/1/cron")) {
      const crons = c.path.includes("page=1")
        ? [{ id: 3, name: "nightly", schedule: "@daily", branch: "release" }]
        : [];
      return crons as unknown as Record<string, unknown>;
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_set").execute(
      { repo: "1", name: "nightly", schedule: "@daily" },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(calls.some((c) => c.method === "PATCH"), false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_list asks for enabled repos only", async () => {
  const { caller, calls } = makeFakeApi((c) =>
    (c.path.startsWith("/api/repos?active=true") && c.path.includes("page=1")
      ? [repoObj()]
      : []) as unknown as Record<string, unknown>
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_list").execute({}, context);
    assertEquals(written.length, 1);
    assert(calls[0].path.startsWith("/api/repos?active=true&"));
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── stage 3 (low findings) ───────────────────────────

Deno.test("repo_disable: an already-disabled repo is unchanged, with no second DELETE", async () => {
  // Upstream keeps a disabled repo's row with active=false, so the lookup and
  // GET still find it.
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1") return repoObj({ active: false });
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_disable").execute({ repo: "1" }, context);
    assert(!calls.some((c) => c.method === "DELETE"), "no DELETE sent");
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.active, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_disable: an active repo is deleted and reported disabled", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1") return repoObj();
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_disable").execute({ repo: "1" }, context);
    assert(
      calls.some((c) => c.method === "DELETE" && c.path === "/api/repos/1"),
      "DELETE sent",
    );
    assertEquals(written[0].data.action, "disabled");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_wait: a pollIntervalSec below 1 is rejected", async () => {
  const { caller, calls } = makeFakeApi(() => pipelineWithSteps());
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("pipeline_wait").execute(
          { repo: "1", number: 5, pollIntervalSec: 0 },
          context,
        ),
      /pollIntervalSec|>=1|too small/i,
    );
    assertEquals(calls.length, 0, "rejected before any API call");
  } finally {
    __setCaller(null);
  }
});

Deno.test("reachable check rejects an httpTimeoutMs below 1", async () => {
  __setCaller(() => Promise.resolve({ status: 200, body: { login: "bot" } }));
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: { ...GLOBALS, httpTimeoutMs: 0 },
    });
    assertEquals(res.pass, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_update: cancelPreviousPipelineEvents takes only Woodpecker's events", async () => {
  const { caller, calls } = makeFakeApi(() => repoObj());
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("repo_update").execute(
          { repo: "1", cancelPreviousPipelineEvents: ["push", "pull-request"] },
          context,
        ),
      /pull_request/,
    );
    assertEquals(calls.length, 0, "rejected before any API call");
    await method("repo_update").execute(
      { repo: "1", cancelPreviousPipelineEvents: ["push", "pull_request"] },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      (patch?.body as Record<string, unknown>)
        ?.cancel_previous_pipeline_events,
      ["push", "pull_request"],
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_wait: a timeout is recorded as timedOut: true", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") {
      return pipelineWithSteps({ status: "running" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    // timeoutSec 0: the deadline has passed by the first poll, so no sleep.
    await method("pipeline_wait").execute(
      { repo: "1", number: 5, timeoutSec: 0 },
      context,
    );
    assertEquals(written[0].data.status, "running");
    assertEquals(written[0].data.timedOut, true);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_wait: a finished pipeline is recorded as timedOut: false", async () => {
  const { caller } = makeFakeApi(() =>
    pipelineWithSteps({ status: "success" })
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_wait").execute({ repo: "1", number: 5 }, context);
    assertEquals(written[0].data.timedOut, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_trigger: a response with no number fails instead of naming a record 'undefined'", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "POST") return { status: "pending" };
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("pipeline_trigger").execute(
          { repo: "1", branch: "main" },
          context,
        ),
      /no pipeline number/,
    );
    assertEquals(written.length, 0, "nothing written");
  } finally {
    __setCaller(null);
  }
});

Deno.test("org_get: a lookup with no id fails instead of naming a record 'undefined'", async () => {
  const { caller } = makeFakeApi(() => ({ name: "octo-org" }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () => method("org_get").execute({ owner: "octo-org" }, context),
      /no id for org octo-org/,
    );
    assertEquals(written.length, 0, "nothing written");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_logs: a line that is not base64 is marked, not blanked", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") return pipelineWithSteps();
    if (c.path === "/api/repos/1/logs/5/10") {
      return {
        status: 200,
        body: ([
          { data: btoa("before") },
          { data: "not base64!" },
          { data: btoa("after") },
        ] as unknown) as Record<string, unknown>,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_logs").execute(
      { repo: "1", number: 5, step: "go" },
      context,
    );
    assertEquals(
      written[0].data.text,
      "before\n[undecodable log line]\nafter",
    );
  } finally {
    __setCaller(null);
  }
});

// A context whose logger records each info message, for the logging tests.
function makeLoggingContext() {
  const { context, written } = makeContext();
  const infos: Array<{ message: string; props: Record<string, unknown> }> = [];
  context.logger.info = ((
    message: string,
    props: Record<string, unknown>,
  ) => {
    infos.push({ message, props });
  }) as typeof context.logger.info;
  return { context, written, infos };
}

Deno.test("read methods log what they are about to do", async () => {
  // Every call answers 200 with a bare id, which is enough for each method to
  // get past its first log line; a later failure does not matter here.
  __setCaller(() => Promise.resolve({ status: 200, body: { id: 1 } }));
  try {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["repo_get", { repo: "1" }],
      ["org_get", { owner: "octo-org" }],
      ["org_secret_list", { owner: "1" }],
      ["repo_secret_list", { repo: "1" }],
      ["pipeline_list", { repo: "1" }],
      ["pipeline_last", { repo: "1" }],
      ["pipeline_steps", { repo: "1", number: 5 }],
      ["pipeline_logs", { repo: "1", number: 5, step: "go" }],
      ["repo_update", { repo: "1" }],
      ["queue_info", {}],
      ["server_info", {}],
      ["cron_list", { repo: "1" }],
    ];
    for (const [name, args] of cases) {
      const { context, infos } = makeLoggingContext();
      await method(name).execute(args, context).catch(() => {});
      assert(infos.length > 0, `${name} logged nothing`);
    }
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_update: logs the PATCH body before sending it", async () => {
  const { caller } = makeFakeApi(() => repoObj());
  __setCaller(caller);
  try {
    const { context, infos } = makeLoggingContext();
    await method("repo_update").execute(
      { repo: "1", trustedVolumes: true },
      context,
    );
    const update = infos.find((i) => i.message === "Updating repo settings");
    assert(update, "logged the update");
    assertEquals(
      (update?.props.body as Record<string, unknown>).trusted,
      { network: false, volumes: true, security: false },
    );
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── approve / decline ───────────────────────────

Deno.test("pipeline_approve: a numbered pipeline that is not blocked is unchanged, no POST", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") {
      return pipelineWithSteps({ status: "success" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_approve").execute({ repo: "1", number: 5 }, context);
    assert(!calls.some((c) => c.method === "POST"), "no approve POST");
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.number, 5);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_approve: a numbered blocked pipeline is approved", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines/5") {
      return pipelineWithSteps({ status: "blocked" });
    }
    if (c.method === "POST" && c.path === "/api/repos/1/pipelines/5/approve") {
      return pipelineWithSteps({ status: "pending" });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_approve").execute({ repo: "1", number: 5 }, context);
    assert(
      calls.some((c) => c.path === "/api/repos/1/pipelines/5/approve"),
      "approve POST sent",
    );
    assertEquals(written[0].data.action, "approved");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_decline: without a number, targets the newest blocked pipeline, not the newest", async () => {
  // Pipeline 5 is a later push that succeeded; 4 is waiting for approval.
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines?status=blocked&perPage=1") {
      return {
        status: 200,
        body: ([{ number: 4, status: "blocked" }] as unknown) as Record<
          string,
          unknown
        >,
      };
    }
    if (c.path === "/api/repos/1/pipelines?perPage=1") {
      return {
        status: 200,
        body: ([{ number: 5, status: "success" }] as unknown) as Record<
          string,
          unknown
        >,
      };
    }
    if (c.method === "POST" && c.path === "/api/repos/1/pipelines/4/decline") {
      return { number: 4, status: "declined" };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_decline").execute({ repo: "1" }, context);
    assert(
      calls.some((c) => c.path === "/api/repos/1/pipelines/4/decline"),
      "declined pipeline 4",
    );
    assertEquals(written[0].data.action, "declined");
    assertEquals(written[0].data.number, 4);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_approve: without a number and nothing blocked, reports the newest unchanged", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines?status=blocked&perPage=1") {
      return { status: 200, body: ([] as unknown) as Record<string, unknown> };
    }
    if (c.path === "/api/repos/1/pipelines?perPage=1") {
      return {
        status: 200,
        body: ([{ number: 5, status: "success" }] as unknown) as Record<
          string,
          unknown
        >,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_approve").execute({ repo: "1" }, context);
    assert(!calls.some((c) => c.method === "POST"), "no approve POST");
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.number, 5);
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── plain-http warning ───────────────────────────

Deno.test("every run warns when apiUrl is plain http, and not when it is https", async () => {
  __setCaller(() => Promise.resolve({ status: 200, body: { version: "x" } }));
  try {
    const warnings = (apiUrl: string) => {
      const { context } = makeContext();
      const seen: string[] = [];
      context.globalArgs = { ...GLOBALS, apiUrl };
      context.logger.warn = ((message: string) => {
        seen.push(message);
      }) as typeof context.logger.warn;
      return { context, seen };
    };
    const http = warnings("http://woodpecker.example.com:8000");
    await method("server_info").execute({}, http.context);
    assertEquals(http.seen.length, 1);
    assert(/not https/.test(http.seen[0]), http.seen[0]);
    const https = warnings("https://woodpecker.example.com");
    await method("server_info").execute({}, https.context);
    assertEquals(https.seen.length, 0);
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── stored references ───────────────────────────

Deno.test("pipeline records store the repo's full name when an id is passed", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/repos/1/pipelines?perPage=1") {
      return {
        status: 200,
        body: ([{ number: 5, status: "success" }] as unknown) as Record<
          string,
          unknown
        >,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pipeline_last").execute({ repo: "1" }, context);
    assertEquals(written[0].data.repo, "octo-org/web");
  } finally {
    __setCaller(null);
  }
});

Deno.test("cron records store the repo's full name when an id is passed", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/repos/1/cron?")) {
      return {
        status: 200,
        body: ([{
          id: 3,
          name: "nightly",
          schedule: "@daily",
        }] as unknown) as Record<string, unknown>,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("cron_list").execute({ repo: "1" }, context);
    assertEquals(written[0].data.repo, "octo-org/web");
  } finally {
    __setCaller(null);
  }
});

Deno.test("org secrets store the org's name when an id is passed", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/orgs/7") return { id: 7, name: "octo-org" };
    if (c.path.startsWith("/api/orgs/7/secrets?")) {
      return {
        status: 200,
        body: ([{ id: 1, name: "ghcr_token" }] as unknown) as Record<
          string,
          unknown
        >,
      };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("org_secret_list").execute({ owner: "7" }, context);
    assert(calls.some((c) => c.path === "/api/orgs/7"), "fetched the org");
    assertEquals(written[0].data.owner, "octo-org");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── publish review, 2026-10-11 ───────────────────────────

Deno.test("a server that stalls mid-body fails at httpTimeoutMs instead of hanging", async () => {
  // Headers and the first byte arrive at once; the rest never does.
  const server = Deno.serve(
    { port: 0, hostname: "127.0.0.1", onListen: () => {} },
    () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("{"));
          },
        }),
        { headers: { "content-type": "application/json" } },
      ),
  );
  try {
    const { context } = makeContext();
    const stalled = {
      ...context,
      globalArgs: {
        ...GLOBALS,
        apiUrl: `http://127.0.0.1:${server.addr.port}`,
        httpTimeoutMs: 200,
      },
    };
    await rejects(
      () => method("server_info").execute({}, stalled),
      /timed out after 200 ms/,
    );
  } finally {
    await server.shutdown();
  }
});

Deno.test("org_get: a numeric owner is fetched by id, not looked up as a login", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/orgs/7") {
      return { id: 7, name: "octo-org", is_user: false };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("org_get").execute({ owner: "7" }, context);
    assertEquals(calls.map((c) => c.path), ["/api/orgs/7"]);
    assertEquals(written[0].name, "org:7");
    assertEquals(written[0].data.name, "octo-org");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pipeline_restart: a response without a number fails instead of overwriting the old run", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "POST" && c.path === "/api/repos/1/pipelines/5") {
      return { status: "pending" };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("pipeline_restart").execute({ repo: "1", number: 5 }, context),
      /no pipeline number/,
    );
    assertEquals(written.length, 0, "nothing written");
  } finally {
    __setCaller(null);
  }
});
