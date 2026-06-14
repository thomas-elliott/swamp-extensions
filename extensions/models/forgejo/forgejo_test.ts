/**
 * Unit tests for the load-bearing, safety-sensitive logic of `@thomas/forgejo`:
 * the find-or-create idempotency of org_ensure/repo_ensure/mirror_ensure, the
 * empty-shell-repo detection (report, never delete), the mirror source-drift
 * refusal, the authToken-never-stored guarantee (sent on the wire to
 * /repos/migrate but never written to a resource), archive/unarchive
 * idempotency, pagination, and mirror staleness math. No live server — the
 * API caller is faked via the __setCaller seam.
 */
import {
  __setCaller,
  type ApiCall,
  type ApiResult,
  type CallerFn,
  model,
} from "./forgejo.ts";

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
  apiUrl: "https://git.test.example.com",
  token: "test-token",
  httpTimeoutMs: 30000,
};

type Recorded = { method: string; path: string; body?: unknown };

/**
 * A fake API caller. `respond` returns either a body or a `{status, body}`
 * per (method, path) match; a bare body/array implies status 200, undefined
 * implies a 404 empty result (so existence probes can be exercised).
 */
function makeFakeApi(
  respond?: (
    c: ApiCall,
  ) =>
    | Record<string, unknown>
    | Array<Record<string, unknown>>
    | { status: number; body: Record<string, unknown> }
    | undefined,
) {
  const calls: Recorded[] = [];
  const caller: CallerFn = (_g, c): Promise<ApiResult> => {
    calls.push({ method: c.method, path: c.path, body: c.body });
    const r = respond?.(c);
    if (r === undefined) return Promise.resolve({ status: 404, body: {} });
    if (
      !Array.isArray(r) && typeof r === "object" && r !== null &&
      "status" in r && "body" in r
    ) {
      return Promise.resolve(r as ApiResult);
    }
    return Promise.resolve(
      { status: 200, body: r as unknown as Record<string, unknown> },
    );
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

// A realistic repo object as the server returns it.
function repoObj(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 7,
    name: "damson",
    full_name: "apps/damson",
    owner: { login: "apps" },
    private: true,
    archived: false,
    empty: false,
    mirror: false,
    fork: false,
    default_branch: "main",
    description: "",
    html_url: "https://git.test.example.com/apps/damson",
    size: 1024,
    has_wiki: true,
    has_issues: true,
    has_pull_requests: true,
    has_releases: true,
    ...over,
  };
}

function mirrorObj(over: Record<string, unknown> = {}): Record<
  string,
  unknown
> {
  return repoObj({
    id: 9,
    name: "scrappy",
    full_name: "mirrors/scrappy",
    owner: { login: "mirrors" },
    mirror: true,
    original_url: "https://github.com/thomas-elliott/scrappy.git",
    mirror_interval: "8h0m0s",
    mirror_updated: new Date(Date.now() - 3600 * 1000).toISOString(),
    ...over,
  });
}

// ─────────────────────────── org_ensure ───────────────────────────

Deno.test("org_ensure creates the org when absent", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET") return undefined; // 404 probe
    return { id: 3, name: "mirrors", visibility: "private" };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("org_ensure").execute(
      { name: "mirrors", visibility: "private" },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/orgs");
    assertEquals((post?.body as Record<string, unknown>).username, "mirrors");
    assertEquals(written[0].data.action, "created");
  } finally {
    __setCaller(null);
  }
});

Deno.test("org_ensure is unchanged when already converged", async () => {
  const { caller, calls } = makeFakeApi(() => ({
    id: 3,
    name: "mirrors",
    visibility: "private",
    description: "GitHub mirrors",
  }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("org_ensure").execute(
      { name: "mirrors", visibility: "private", description: "GitHub mirrors" },
      context,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("org_ensure patches only the drifted field", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "PATCH") {
      return { id: 3, name: "mirrors", visibility: "private", description: "new" };
    }
    return { id: 3, name: "mirrors", visibility: "private", description: "old" };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("org_ensure").execute(
      { name: "mirrors", visibility: "private", description: "new" },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.path, "/api/v1/orgs/mirrors");
    assertEquals(patch?.body, { description: "new" });
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── repo_ensure ───────────────────────────

Deno.test("repo_ensure creates under the org namespace", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path === "/api/v1/repos/apps/damson") {
      return undefined; // 404
    }
    if (c.method === "GET" && c.path === "/api/v1/user") {
      return { login: "swamp-admin" };
    }
    return repoObj();
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_ensure").execute(
      { owner: "apps", name: "damson", private: true },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/orgs/apps/repos");
    assertEquals(written[0].data.action, "created");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_ensure creates under /user/repos for the token user", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.startsWith("/api/v1/repos/")) {
      return undefined;
    }
    if (c.method === "GET" && c.path === "/api/v1/user") {
      return { login: "swamp-admin" };
    }
    return repoObj({ owner: { login: "swamp-admin" } });
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("repo_ensure").execute(
      { owner: "swamp-admin", name: "damson" },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/user/repos");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_ensure is unchanged when settings match", async () => {
  const { caller, calls } = makeFakeApi(() => repoObj());
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_ensure").execute(
      { owner: "apps", name: "damson", private: true, hasWiki: true },
      context,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_ensure patches only drifted settings", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "PATCH") return repoObj({ has_wiki: false });
    return repoObj();
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_ensure").execute(
      { owner: "apps", name: "damson", private: true, hasWiki: false },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.body, { has_wiki: false });
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── mirror_ensure ───────────────────────────

Deno.test("mirror_ensure migrates when absent; authToken on the wire, never stored", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET") return undefined; // 404 probe
    return mirrorObj();
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "scrappy",
        cloneAddr: "https://github.com/thomas-elliott/scrappy.git",
        authToken: "ghp_SECRET",
      },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/repos/migrate");
    const body = post?.body as Record<string, unknown>;
    assertEquals(body.mirror, true);
    assertEquals(body.service, "github");
    assertEquals(body.auth_token, "ghp_SECRET");
    assertEquals(body.lfs, true);
    // The guarantee: the token never lands in the data model.
    assert(
      !JSON.stringify(written).includes("ghp_SECRET"),
      "authToken must never be written to a resource",
    );
    assertEquals(written[0].specName, "mirror");
    assertEquals(written[0].data.action, "created");
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure omits auth_token when not supplied", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET") return undefined;
    return mirrorObj();
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "scrappy",
        cloneAddr: "https://github.com/thomas-elliott/scrappy.git",
      },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(
      !("auth_token" in (post?.body as Record<string, unknown>)),
      "auth_token key must be absent",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure reports the empty shell repo and never deletes", async () => {
  const { caller, calls } = makeFakeApi(() =>
    repoObj({ empty: true, mirror: false })
  );
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("mirror_ensure").execute(
          {
            owner: "apps",
            name: "damson",
            cloneAddr: "https://github.com/x/damson.git",
          },
          context,
        ),
      /EMPTY non-mirror shell.*Delete it manually/s,
    );
    assert(
      !calls.some((c) => c.method === "DELETE"),
      "must never issue a DELETE",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure refuses a non-mirror name collision", async () => {
  const { caller } = makeFakeApi(() => repoObj({ mirror: false }));
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("mirror_ensure").execute(
          {
            owner: "apps",
            name: "damson",
            cloneAddr: "https://github.com/x/damson.git",
          },
          context,
        ),
      /NOT a mirror/,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure refuses source-URL drift", async () => {
  const { caller } = makeFakeApi(() => mirrorObj());
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("mirror_ensure").execute(
          {
            owner: "mirrors",
            name: "scrappy",
            cloneAddr: "https://github.com/someone-else/scrappy.git",
          },
          context,
        ),
      /already mirrors .* cannot be changed in place/s,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure tolerates equivalent source URLs (.git / case)", async () => {
  const { caller, calls } = makeFakeApi(() => mirrorObj());
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "scrappy",
        cloneAddr: "https://github.com/Thomas-Elliott/scrappy",
      },
      context,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure reconciles a drifted interval (semantic compare)", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "PATCH") return mirrorObj({ mirror_interval: "24h0m0s" });
    return mirrorObj({ mirror_interval: "8h0m0s" });
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "scrappy",
        cloneAddr: "https://github.com/thomas-elliott/scrappy.git",
        mirrorInterval: "24h",
      },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      (patch?.body as Record<string, unknown>).mirror_interval,
      "24h",
    );
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure treats 8h == 8h0m0s as unchanged", async () => {
  const { caller, calls } = makeFakeApi(() => mirrorObj());
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "scrappy",
        cloneAddr: "https://github.com/thomas-elliott/scrappy.git",
        mirrorInterval: "8h",
      },
      context,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── mirror_sync_now ───────────────────────────

Deno.test("mirror_sync_now posts mirror-sync for a mirror", async () => {
  const { caller, calls } = makeFakeApi(() => mirrorObj());
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_sync_now").execute(
      { owner: "mirrors", name: "scrappy" },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/repos/mirrors/scrappy/mirror-sync");
    assertEquals(written[0].data.action, "triggered");
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_sync_now refuses a non-mirror", async () => {
  const { caller } = makeFakeApi(() => repoObj());
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("mirror_sync_now").execute(
          { owner: "apps", name: "damson" },
          context,
        ),
      /not a mirror/,
    );
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── archive / unarchive ───────────────────────────

Deno.test("repo_archive patches archived=true and is idempotent", async () => {
  // First run: not archived -> PATCH.
  let fake = makeFakeApi((c) => {
    if (c.method === "PATCH") return repoObj({ archived: true });
    return repoObj({ archived: false });
  });
  __setCaller(fake.caller);
  try {
    const { context, written } = makeContext();
    await method("repo_archive").execute(
      { owner: "apps", name: "damson" },
      context,
    );
    const patch = fake.calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.body, { archived: true });
    assertEquals(written[0].data.action, "archived");
  } finally {
    __setCaller(null);
  }
  // Second run: already archived -> no PATCH.
  fake = makeFakeApi(() => repoObj({ archived: true }));
  __setCaller(fake.caller);
  try {
    const { context, written } = makeContext();
    await method("repo_archive").execute(
      { owner: "apps", name: "damson" },
      context,
    );
    assert(!fake.calls.some((c) => c.method === "PATCH"), "no second PATCH");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_unarchive reverses repo_archive", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "PATCH") return repoObj({ archived: false });
    return repoObj({ archived: true });
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_unarchive").execute(
      { owner: "apps", name: "damson" },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.body, { archived: false });
    assertEquals(written[0].data.action, "unarchived");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── listings / pagination ───────────────────────────

Deno.test("repo_list paginates the search endpoint and unwraps {data}", async () => {
  const pageOf = (n: number, count: number) =>
    Array.from({ length: count }, (_, i) => ({
      id: n * 1000 + i,
      name: `r${n}-${i}`,
      full_name: `apps/r${n}-${i}`,
      owner: { login: "apps" },
    }));
  const { caller, calls } = makeFakeApi((c) => {
    const page = Number(new URLSearchParams(c.path.split("?")[1]).get("page"));
    return {
      ok: true,
      data: page === 1 ? pageOf(1, 50) : pageOf(2, 3),
    } as unknown as Record<string, unknown>;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_list").execute({}, context);
    assertEquals(calls.length, 2, "fetches until a short page");
    assert(calls[0].path.startsWith("/api/v1/repos/search?"));
    assertEquals(written.length, 53);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_list falls back to the user listing for a non-org owner", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/v1/orgs/thomas") return undefined; // 404 -> a user
    return [repoObj({ owner: { login: "thomas" }, full_name: "thomas/x" })] as
      unknown as Record<string, unknown>;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_list").execute({ owner: "thomas" }, context);
    assert(
      calls.some((c) => c.path.startsWith("/api/v1/users/thomas/repos?")),
      "uses the users listing",
    );
    assertEquals(written.length, 1);
  } finally {
    __setCaller(null);
  }
});

Deno.test("user_list maps admin users without any credential material", async () => {
  const { caller } = makeFakeApi(() =>
    [
      {
        id: 1,
        login: "thomas",
        email: "t@example.com",
        is_admin: true,
        last_login: "2026-06-12T08:00:00Z",
      },
      {
        id: 2,
        login: "swamp-admin",
        is_admin: true,
        last_login: "0001-01-01T00:00:00Z",
      },
    ] as unknown as Record<string, unknown>
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("user_list").execute({}, context);
    assertEquals(written.length, 2);
    assertEquals(written[0].data.isAdmin, true);
    assertEquals(written[1].data.lastLogin, undefined, "zero time elided");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── mirror_status / staleness ───────────────────────────

Deno.test("mirror_status flags a stale mirror and passes a fresh one", async () => {
  const fresh = mirrorObj();
  const stale = mirrorObj({
    name: "old",
    full_name: "mirrors/old",
    mirror_updated: new Date(Date.now() - 30 * 3600 * 1000).toISOString(),
  });
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return { ok: true, data: [fresh, stale] } as unknown as Record<
        string,
        unknown
      >;
    }
    return c.path.endsWith("/old") ? stale : fresh;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_status").execute({}, context);
    assertEquals(written.length, 2);
    assertEquals(written[0].data.stale, false, "1h ago vs 8h interval");
    assertEquals(written[1].data.stale, true, "30h ago vs 8h interval");
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_status: interval 0s means periodic sync off, not stale", async () => {
  const manual = mirrorObj({
    mirror_interval: "0s",
    mirror_updated: new Date(Date.now() - 300 * 3600 * 1000).toISOString(),
  });
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return { ok: true, data: [manual] } as unknown as Record<
        string,
        unknown
      >;
    }
    return manual;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_status").execute({}, context);
    assertEquals(written[0].data.stale, false);
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── health ───────────────────────────

Deno.test("health combines version and healthz", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/v1/version") return { version: "15.0.3" };
    return { status: 200, body: { status: "pass" } };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("health").execute({}, context);
    assertEquals(written[0].data.version, "15.0.3");
    assertEquals(written[0].data.healthy, true);
  } finally {
    __setCaller(null);
  }
});

Deno.test("health survives a failing healthz (healthy=false, no throw)", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path === "/api/v1/version") return { version: "15.0.3" };
    return { status: 503, body: { status: "fail" } };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("health").execute({}, context);
    assertEquals(written[0].data.healthy, false);
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── error surfacing ───────────────────────────

Deno.test("API errors surface with method, path, status, and message", async () => {
  const { caller } = makeFakeApi(() => ({
    status: 422,
    body: { message: "private addresses are not allowed" },
  }));
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("org_list").execute({}, context),
      /GET \/api\/v1\/orgs.*422.*private addresses/s,
    );
  } finally {
    __setCaller(null);
  }
});
