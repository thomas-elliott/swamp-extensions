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
      return {
        id: 3,
        name: "mirrors",
        visibility: "private",
        description: "new",
      };
    }
    return {
      id: 3,
      name: "mirrors",
      visibility: "private",
      description: "old",
    };
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
    return [
      repoObj({ owner: { login: "thomas" }, full_name: "thomas/x" }),
    ] as unknown as Record<string, unknown>;
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

// ─────────────────────────── pull requests ───────────────────────────

// A realistic PR object as the server returns it.
function prObj(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    number: 4,
    title: "Add the thing",
    body: "why",
    state: "open",
    draft: false,
    merged: false,
    mergeable: true,
    html_url: "https://git.test.example.com/apps/damson/pulls/4",
    user: { login: "telliott" },
    head: { ref: "feat/thing", sha: "abc123def456", repo: repoObj() },
    base: { ref: "main", sha: "999", repo: repoObj() },
    comments: 0,
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-01T00:00:00Z",
    ...over,
  };
}

/**
 * Fake covering the PR endpoints. `open` is the open-PR listing; `detail` the
 * single-PR fetch; `ci` the combined-status state ("" ⇒ no statuses).
 */
function prApi(opts: {
  open?: Array<Record<string, unknown>>;
  detail?: Record<string, unknown>;
  ci?: string;
  onMerge?: () => { status: number; body: Record<string, unknown> };
}) {
  return makeFakeApi((c) => {
    if (c.path.includes("/commits/") && c.path.endsWith("/status")) {
      return opts.ci === undefined ? {} : { state: opts.ci };
    }
    if (c.method === "POST" && c.path.endsWith("/merge")) {
      return opts.onMerge?.() ?? { status: 200, body: {} };
    }
    if (c.method === "GET" && c.path.includes("/pulls?state=")) {
      return opts.open ?? [];
    }
    if (c.method === "GET" && /\/pulls\/\d+$/.test(c.path)) {
      return opts.detail;
    }
    if (c.method === "POST" && c.path.endsWith("/pulls")) return prObj();
    if (c.method === "PATCH") return prObj({ title: "Renamed" });
    return undefined;
  });
}

Deno.test("pr_ensure opens a PR when no matching open one exists", async () => {
  const { caller, calls } = prApi({ open: [] });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_ensure").execute(
      {
        owner: "apps",
        name: "damson",
        head: "feat/thing",
        base: "main",
        title: "Add the thing",
      },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/repos/apps/damson/pulls");
    assertEquals((post?.body as Record<string, unknown>).base, "main");
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].name, "apps:damson#4");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_ensure is a no-op when an identical open PR exists", async () => {
  const { caller, calls } = prApi({ open: [prObj()] });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_ensure").execute(
      {
        owner: "apps",
        name: "damson",
        head: "feat/thing",
        base: "main",
        title: "Add the thing",
        body: "why",
      },
      context,
    );
    assert(
      !calls.some((c) => c.method === "POST" || c.method === "PATCH"),
      "must not write when nothing differs",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_ensure converges the title of an existing open PR", async () => {
  const { caller, calls } = prApi({ open: [prObj()] });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_ensure").execute(
      {
        owner: "apps",
        name: "damson",
        head: "feat/thing",
        base: "main",
        title: "Renamed",
      },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.path, "/api/v1/repos/apps/damson/pulls/4");
    assertEquals((patch?.body as Record<string, unknown>).title, "Renamed");
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_ensure matches a fork head (owner:branch) against the bare ref", async () => {
  const { caller, calls } = prApi({ open: [prObj()] });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_ensure").execute(
      {
        owner: "apps",
        name: "damson",
        head: "someone:feat/thing",
        base: "main",
        title: "Add the thing",
        body: "why",
      },
      context,
    );
    assert(
      !calls.some((c) => c.method === "POST"),
      "a qualified head must still match the existing PR, not duplicate it",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_get reports ciState none when the head carries no status", async () => {
  const { caller } = prApi({ detail: prObj(), ci: "" });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_get").execute(
      { owner: "apps", name: "damson", index: 4 },
      context,
    );
    assertEquals(written[0].data.ciState, "none");
    assertEquals(written[0].data.mergeable, true);
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_merge refuses a draft, a closed PR, and an already-merged PR", async () => {
  for (
    const [over, re] of [
      [{ draft: true }, /is a draft/],
      [{ state: "closed" }, /not open/],
      [{ merged: true }, /already merged/],
    ] as Array<[Record<string, unknown>, RegExp]>
  ) {
    const { caller, calls } = prApi({ detail: prObj(over), ci: "success" });
    __setCaller(caller);
    try {
      const { context } = makeContext();
      await rejects(
        () =>
          method("pr_merge").execute(
            { owner: "apps", name: "damson", index: 4 },
            context,
          ),
        re,
      );
      assert(
        !calls.some((c) => c.path.endsWith("/merge")),
        `must not call merge for ${JSON.stringify(over)}`,
      );
    } finally {
      __setCaller(null);
    }
  }
});

Deno.test("pr_merge refuses a PR the server says is not mergeable", async () => {
  const { caller, calls } = prApi({
    detail: prObj({ mergeable: false }),
    ci: "success",
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("pr_merge").execute(
          { owner: "apps", name: "damson", index: 4, force: true },
          context,
        ),
      /not mergeable/,
    );
    assert(
      !calls.some((c) => c.path.endsWith("/merge")),
      "force must not override a conflicting PR",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_merge refuses a non-green head unless forced", async () => {
  const { caller, calls } = prApi({ detail: prObj(), ci: "failure" });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("pr_merge").execute(
          { owner: "apps", name: "damson", index: 4 },
          context,
        ),
      /CI state "failure"/,
    );
    assert(!calls.some((c) => c.path.endsWith("/merge")), "must not merge");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_merge with no CI status at all is refused unless forced", async () => {
  const { caller } = prApi({ detail: prObj(), ci: "" });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("pr_merge").execute(
          { owner: "apps", name: "damson", index: 4 },
          context,
        ),
      /CI state "none"/,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_merge sends the strategy as Do and records merged", async () => {
  // The detail fetch happens twice: the pre-merge guard must see an open PR,
  // the post-merge re-fetch a merged one.
  let merged = false;
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.includes("/commits/")) return { state: "success" };
    if (c.method === "POST" && c.path.endsWith("/merge")) {
      merged = true;
      return {};
    }
    if (c.method === "GET" && /\/pulls\/\d+$/.test(c.path)) {
      return prObj(merged ? { merged: true, state: "closed" } : {});
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_merge").execute(
      {
        owner: "apps",
        name: "damson",
        index: 4,
        strategy: "squash",
        deleteBranch: true,
      },
      context,
    );
    const merge = calls.find((c) => c.path.endsWith("/merge"));
    assertEquals(merge?.path, "/api/v1/repos/apps/damson/pulls/4/merge");
    const body = merge?.body as Record<string, unknown>;
    assertEquals(body.Do, "squash");
    assertEquals(body.delete_branch_after_merge, true);
    assertEquals(written[0].data.action, "merged");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────── narrow-token compatibility ───────────────────────

type CheckDef = {
  execute: (
    context: { globalArgs: typeof GLOBALS },
  ) => Promise<{ pass: boolean; errors?: string[] }>;
};
const check = (name: string): CheckDef =>
  (model.checks as unknown as Record<string, CheckDef>)[name];

Deno.test("reachable: a scope-rejection 403 passes — the token authenticated", async () => {
  const { caller } = makeFakeApi(() => ({
    status: 403,
    body: {
      message:
        "token does not have at least one of required scope(s): [read:user]",
    },
  }));
  __setCaller(caller);
  try {
    const r = await check("reachable").execute({ globalArgs: GLOBALS });
    assertEquals(r.pass, true);
  } finally {
    __setCaller(null);
  }
});

Deno.test("reachable: a 401 still fails — a bad token must not pass", async () => {
  const { caller } = makeFakeApi(() => ({
    status: 401,
    body: { message: "unauthorized" },
  }));
  __setCaller(caller);
  try {
    const r = await check("reachable").execute({ globalArgs: GLOBALS });
    assertEquals(r.pass, false);
    assert(
      /401/.test((r.errors ?? []).join(" ")),
      "the failure must name the status",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("reachable: a non-scope 403 still fails", async () => {
  const { caller } = makeFakeApi(() => ({
    status: 403,
    body: { message: "user is not allowed to log in" },
  }));
  __setCaller(caller);
  try {
    const r = await check("reachable").execute({ globalArgs: GLOBALS });
    assertEquals(r.pass, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_list: a refused org probe falls through to the user path", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/orgs/telliott")) {
      return {
        status: 403,
        body: {
          message:
            "token does not have at least one of required scope(s): [read:organization]",
        },
      };
    }
    if (c.path.startsWith("/api/v1/users/telliott/repos")) {
      return [
        repoObj({ full_name: "telliott/swamp", owner: { login: "telliott" } }),
      ];
    }
    return undefined;
  });
  const { context, written } = makeContext();
  __setCaller(caller);
  try {
    await method("repo_list").execute({ owner: "telliott" }, context);
    assertEquals(written.length, 1);
    assertEquals(written[0].data.fullName, "telliott/swamp");
    assert(
      calls.some((c) => c.path.startsWith("/api/v1/orgs/telliott")),
      "the org probe must still be attempted first",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_list: names the missing scopes when both probes are refused", async () => {
  const { caller } = makeFakeApi(() => ({
    status: 403,
    body: {
      message:
        "token does not have at least one of required scope(s): [read:user]",
    },
  }));
  const { context } = makeContext();
  __setCaller(caller);
  try {
    await rejects(
      () => method("repo_list").execute({ owner: "telliott" }, context),
      /read:organization nor read:user/,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_list: a genuinely absent owner is still a 404, not a scope error", async () => {
  const { caller } = makeFakeApi(() => undefined);
  const { context } = makeContext();
  __setCaller(caller);
  try {
    await rejects(
      () => method("repo_list").execute({ owner: "nobody" }, context),
      /No user "nobody"/,
    );
  } finally {
    __setCaller(null);
  }
});

// ───────────── collaborator_ensure ─────────────

const COLLAB_ARGS = {
  owner: "telliott",
  name: "agent-scratch",
  user: "factory-agents",
  permission: "write",
};

Deno.test("collaborator_ensure grants access when the user has none", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET") return undefined; // 404 = not a collaborator
    return {};
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("collaborator_ensure").execute(COLLAB_ARGS, context);
    const put = calls.find((c) => c.method === "PUT");
    assertEquals(
      put?.path,
      "/api/v1/repos/telliott/agent-scratch/collaborators/factory-agents",
    );
    assertEquals((put?.body as Record<string, unknown>).permission, "write");
    assertEquals(written[0].data.action, "created");
  } finally {
    __setCaller(null);
  }
});

Deno.test("collaborator_ensure is unchanged at the same permission", async () => {
  const { caller, calls } = makeFakeApi(() => ({ permission: "write" }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("collaborator_ensure").execute(COLLAB_ARGS, context);
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("collaborator_ensure reports an existing grant as updated", async () => {
  const { caller } = makeFakeApi((c) =>
    c.method === "GET" ? { permission: "read" } : {}
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("collaborator_ensure").execute(COLLAB_ARGS, context);
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("collaborator_ensure refuses to touch the repo owner", async () => {
  const { caller, calls } = makeFakeApi(() => ({ permission: "owner" }));
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("collaborator_ensure").execute(
          { ...COLLAB_ARGS, user: "telliott" },
          context,
        ),
      /owns telliott\/agent-scratch/,
    );
    assert(!calls.some((c) => c.method !== "GET"), "must not mutate");
  } finally {
    __setCaller(null);
  }
});

// ───────────── branch_protection_ensure ─────────────

Deno.test("branch_protection_ensure creates a PR-only rule", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET") return undefined;
    return { rule_name: "main", enable_push: false, required_approvals: 0 };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("branch_protection_ensure").execute(
      {
        owner: "telliott",
        name: "agent-scratch",
        rule: "main",
        enablePush: false,
        applyToAdmins: false,
      },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(
      post?.path,
      "/api/v1/repos/telliott/agent-scratch/branch_protections",
    );
    const body = post?.body as Record<string, unknown>;
    assertEquals(body.rule_name, "main");
    assertEquals(body.enable_push, false);
    // A supplied-but-false field must still be sent on create — omitting it
    // would let the server default decide.
    assertEquals(body.apply_to_admins, false);
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].data.enablePush, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_ensure patches only what differs", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET") {
      return {
        rule_name: "agents/*",
        enable_push: true,
        enable_push_whitelist: true,
        push_whitelist_usernames: ["factory-agents"],
        protected_file_patterns: "",
      };
    }
    return {
      rule_name: "agents/*",
      protected_file_patterns: ".woodpecker.yml",
    };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("branch_protection_ensure").execute(
      {
        owner: "telliott",
        name: "agent-scratch",
        rule: "agents/*",
        enablePush: true,
        enablePushWhitelist: true,
        pushWhitelistUsernames: ["factory-agents"],
        protectedFilePatterns: ".woodpecker.yml",
      },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      patch?.path,
      "/api/v1/repos/telliott/agent-scratch/branch_protections/agents%2F*",
    );
    assertEquals(Object.keys(patch?.body as Record<string, unknown>), [
      "protected_file_patterns",
    ]);
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_ensure is unchanged when converged", async () => {
  const { caller, calls } = makeFakeApi(() => ({
    rule_name: "main",
    enable_push: false,
    required_approvals: 1,
  }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("branch_protection_ensure").execute(
      {
        owner: "telliott",
        name: "agent-scratch",
        rule: "main",
        enablePush: false,
        requiredApprovals: 1,
      },
      context,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_ensure converges a whitelist as an exact set", async () => {
  const { caller, calls } = makeFakeApi((c) =>
    c.method === "GET"
      ? {
        rule_name: "agents/*",
        push_whitelist_usernames: ["factory-agents", "stale-account"],
      }
      : { rule_name: "agents/*" }
  );
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("branch_protection_ensure").execute(
      {
        owner: "telliott",
        name: "agent-scratch",
        rule: "agents/*",
        pushWhitelistUsernames: ["factory-agents"],
      },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      (patch?.body as Record<string, unknown>).push_whitelist_usernames,
      ["factory-agents"],
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_list writes one resource per rule", async () => {
  const { caller } = makeFakeApi(() => [
    { rule_name: "main", enable_push: false },
    { rule_name: "agents/*", enable_push: true },
  ]);
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("branch_protection_list").execute(
      { owner: "telliott", name: "agent-scratch" },
      context,
    );
    assertEquals(written.length, 2);
    assertEquals(written[0].name, "telliott:agent-scratch:main");
    assertEquals(written[1].data.action, "observed");
  } finally {
    __setCaller(null);
  }
});
