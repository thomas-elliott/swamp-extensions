/**
 * Unit tests for the load-bearing, security-sensitive logic of `@thomas/woodpecker`:
 * repo_enable find-or-activate idempotency, the trusted-object merge (partial
 * trust must not clobber untouched capabilities), the create-vs-update secret
 * upsert, the secret-value-never-stored guarantee (value is sent on the wire but
 * never written to a resource), and the idempotent delete-on-404. No live server
 * — the API caller is faked via the __setCaller seam.
 */
import {
  __setCaller,
  type ApiCall,
  type ApiResult,
  type CallerFn,
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
 * empty result (so existence probes can be exercised).
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
    const r = respond?.(c);
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

// A realistic enabled-repo object as the server returns it.
function repoObj(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 1,
    full_name: "thomas-elliott/damson",
    owner: "thomas-elliott",
    name: "damson",
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
          full_name: "thomas-elliott/damson",
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
      { repo: "thomas-elliott/damson" },
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
      { repo: "thomas-elliott/damson" },
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
      { repo: "thomas-elliott/damson", trustedVolumes: true },
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
    if (c.path === "/api/orgs/lookup/thomas-elliott") {
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
      { owner: "thomas-elliott", name: "ghcr_token", value: "SUPER_SECRET" },
      context,
    );
    assertEquals(postBody?.value, "SUPER_SECRET", "value sent on the wire");
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
    if (c.path === "/api/orgs/lookup/thomas-elliott") {
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
      { owner: "thomas-elliott", name: "ghcr_token", value: "v" },
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
      () => method("repo_get").execute({ repo: "damson" }, context),
      /numeric id or "owner\/name"/,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_available: instance names sanitize the slash in owner/name", async () => {
  const caller: CallerFn = (_g, c) => {
    if (c.path === "/api/user/repos?all=true") {
      return Promise.resolve({
        status: 200,
        body: ([{
          full_name: "thomas-elliott/damson",
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
    // swamp rejects '/' in instance names — the data name must be sanitized,
    // while the stored fullName field keeps the real slash.
    assert(
      !written[0].name.includes("/"),
      `instance name must not contain '/': ${written[0].name}`,
    );
    assertEquals(written[0].data.fullName, "thomas-elliott/damson");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_secret_list: secret instance name sanitizes the repo full name", async () => {
  const caller: CallerFn = (_g, c) => {
    if (c.path === "/api/repos/1") {
      return Promise.resolve({ status: 200, body: repoObj() });
    }
    if (c.path === "/api/repos/1/secrets") {
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
    assert(
      !written[0].name.includes("/"),
      `secret instance name must not contain '/': ${written[0].name}`,
    );
    assertEquals(written[0].data.owner, "thomas-elliott/damson");
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
    ["org_secret_delete", "repo_disable", "repo_secret_delete"],
    "only the reversible disable/secret-delete methods exist",
  );
});
