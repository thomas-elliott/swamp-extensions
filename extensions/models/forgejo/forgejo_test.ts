/**
 * Unit tests for the important, safety-sensitive logic of `@thomas/forgejo`:
 * the find-or-create idempotency of org_ensure/repo_ensure/mirror_ensure, the
 * empty-shell-repo detection (report, never delete), the mirror source-drift
 * refusal, the authToken-never-stored guarantee (sent to /repos/migrate but
 * never written to a resource), archive/unarchive idempotency, pagination,
 * and mirror staleness math. No live server; the API caller is faked via the
 * __setCaller seam.
 */
import {
  __setCaller,
  type ApiCall,
  type ApiResult,
  type CallerFn,
  dataName,
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
    // Every list fits on page 1; later pages are empty, as a real server's
    // are once the items run out. Lists come bare or wrapped as {data: [...]}.
    const page = Number(/[?&]page=(\d+)/.exec(c.path)?.[1] ?? 1);
    if (page > 1 && Array.isArray(r)) {
      return Promise.resolve({
        status: 200,
        body: [] as unknown as Record<string, unknown>,
      });
    }
    if (page > 1 && Array.isArray((r as Record<string, unknown>).data)) {
      return Promise.resolve({ status: 200, body: { ...r, data: [] } });
    }
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
  // Info and warning lines are kept so tests can check what was logged, and
  // that no credential was.
  const logs: Array<
    { level: string; message: string; props: Record<string, unknown> }
  > = [];
  const record =
    (level: string) => (message: string, props?: Record<string, unknown>) =>
      logs.push({ level, message, props: props ?? {} });
  const noop = () => {};
  const context = {
    globalArgs: GLOBALS,
    logger: {
      info: record("info"),
      debug: noop,
      warn: record("warn"),
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

// A realistic repo object as the server returns it.
function repoObj(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 7,
    name: "web",
    full_name: "apps/web",
    owner: { login: "apps" },
    private: true,
    archived: false,
    empty: false,
    mirror: false,
    fork: false,
    default_branch: "main",
    description: "",
    html_url: "https://git.test.example.com/apps/web",
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
    name: "widget",
    full_name: "mirrors/widget",
    owner: { login: "mirrors" },
    mirror: true,
    original_url: "https://github.com/octo-org/widget.git",
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
    if (c.method === "GET" && c.path === "/api/v1/repos/apps/web") {
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
      { owner: "apps", name: "web", private: true },
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
      { owner: "swamp-admin", name: "web" },
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
      { owner: "apps", name: "web", private: true, hasWiki: true },
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
      { owner: "apps", name: "web", private: true, hasWiki: false },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.body, { has_wiki: false });
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_ensure matches the token user case-insensitively", async () => {
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
      { owner: "Swamp-Admin", name: "web" },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/user/repos");
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_ensure explains a missing org instead of a bare 404", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path === "/api/v1/user") {
      return { login: "swamp-admin" };
    }
    if (c.method === "POST") {
      return { status: 404, body: { message: "GetOrgByName" } };
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("repo_ensure").execute({ owner: "bob", name: "web" }, context),
      /No organization "bob".*admin endpoint/s,
    );
  } finally {
    __setCaller(null);
  }
});

// Forgejo keeps the old default branch, without an error, when the new one
// does not exist on a non-empty repo.
Deno.test("repo_ensure fails when Forgejo keeps the old default branch", async () => {
  const { caller } = makeFakeApi(() => repoObj());
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("repo_ensure").execute(
          { owner: "apps", name: "web", defaultBranch: "develop" },
          context,
        ),
      /kept default branch "main" instead of "develop"/,
    );
    assertEquals(written.length, 0);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_ensure accepts a default branch Forgejo applied", async () => {
  const { caller } = makeFakeApi((c) =>
    c.method === "PATCH" ? repoObj({ default_branch: "develop" }) : repoObj()
  );
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_ensure").execute(
      { owner: "apps", name: "web", defaultBranch: "develop" },
      context,
    );
    assertEquals(written[0].data.action, "updated");
    assertEquals(written[0].data.defaultBranch, "develop");
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
        name: "widget",
        cloneAddr: "https://github.com/octo-org/widget.git",
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
    // The token is never written to the data model.
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
        name: "widget",
        cloneAddr: "https://github.com/octo-org/widget.git",
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
            name: "web",
            cloneAddr: "https://github.com/x/web.git",
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
            name: "web",
            cloneAddr: "https://github.com/x/web.git",
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
            name: "widget",
            cloneAddr: "https://github.com/someone-else/widget.git",
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
        name: "widget",
        cloneAddr: "https://github.com/Octo-Org/widget",
      },
      context,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure creates private with an 8h interval when neither is passed", async () => {
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
        name: "widget",
        cloneAddr: "https://github.com/octo-org/widget.git",
      },
      context,
    );
    const body = calls.find((c) => c.method === "POST")?.body as Record<
      string,
      unknown
    >;
    assertEquals(body.private, true);
    assertEquals(body.mirror_interval, "8h0m0s");
  } finally {
    __setCaller(null);
  }
});

// Issue #4: re-running for an unrelated reason must not reset visibility or
// interval that the caller did not pass.
Deno.test("mirror_ensure leaves visibility and interval alone when not passed", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "PATCH") {
      return mirrorObj({
        private: false,
        mirror_interval: "24h0m0s",
        description: "new",
      });
    }
    return mirrorObj({ private: false, mirror_interval: "24h0m0s" });
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "widget",
        cloneAddr: "https://github.com/octo-org/widget.git",
        description: "new",
      },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.body, { description: "new" });
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure still converges visibility when it is passed", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "PATCH") return mirrorObj({ private: true });
    return mirrorObj({ private: false });
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "widget",
        cloneAddr: "https://github.com/octo-org/widget.git",
        private: true,
      },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.body, { private: true });
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
        name: "widget",
        cloneAddr: "https://github.com/octo-org/widget.git",
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
        name: "widget",
        cloneAddr: "https://github.com/octo-org/widget.git",
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

// A token embedded in cloneAddr must never reach a log line or an error, and
// Forgejo stores the source without it, so it must not read as drift either.
const PAT = "ghp_notarealtoken123";

Deno.test("mirror_ensure keeps a cloneAddr token out of the create log", async () => {
  const { caller } = makeFakeApi((c) =>
    c.method === "GET" ? undefined : mirrorObj()
  );
  __setCaller(caller);
  try {
    const { context, logs } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "widget",
        cloneAddr: `https://bot:${PAT}@github.com/octo-org/widget.git`,
      },
      context,
    );
    assert(logs.length > 0, "the create is logged");
    assert(!JSON.stringify(logs).includes(PAT), "token leaked into a log");
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure compares a credentialled cloneAddr without its credentials", async () => {
  // original_url is what Forgejo reports: sanitised, no user info.
  const { caller, calls } = makeFakeApi(() => mirrorObj());
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_ensure").execute(
      {
        owner: "mirrors",
        name: "widget",
        cloneAddr: `https://bot:${PAT}@github.com/octo-org/widget.git`,
      },
      context,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("mirror_ensure source-drift error never shows a cloneAddr token", async () => {
  const { caller } = makeFakeApi(() => mirrorObj());
  __setCaller(caller);
  try {
    const { context } = makeContext();
    let msg = "";
    try {
      await method("mirror_ensure").execute(
        {
          owner: "mirrors",
          name: "widget",
          cloneAddr: `https://bot:${PAT}@github.com/other-org/widget.git`,
        },
        context,
      );
    } catch (e) {
      msg = (e as Error).message;
    }
    assert(/cannot be changed in place/.test(msg), `unexpected: ${msg}`);
    assert(!msg.includes(PAT), "token leaked into an error message");
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
      { owner: "mirrors", name: "widget" },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/repos/mirrors/widget/mirror-sync");
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
          { owner: "apps", name: "web" },
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
      { owner: "apps", name: "web" },
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
      { owner: "apps", name: "web" },
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
      { owner: "apps", name: "web" },
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

// The server caps `limit` at its MAX_RESPONSE_ITEMS (30 here), so a short page
// is not the last one; only an empty page is.
Deno.test("repo_list reads every page, past a capped one, and unwraps {data}", async () => {
  const pageOf = (n: number, count: number) =>
    Array.from({ length: count }, (_, i) => ({
      id: n * 1000 + i,
      name: `r${n}-${i}`,
      full_name: `apps/r${n}-${i}`,
      owner: { login: "apps" },
    }));
  // Its own fake: the shared one serves every list on page 1 only.
  const calls: string[] = [];
  __setCaller((_g, c) => {
    calls.push(c.path);
    const page = Number(new URLSearchParams(c.path.split("?")[1]).get("page"));
    const items = page === 1 ? pageOf(1, 30) : page === 2 ? pageOf(2, 5) : [];
    return Promise.resolve({
      status: 200,
      body: { ok: true, data: items } as unknown as Record<string, unknown>,
    });
  });
  try {
    const { context, written } = makeContext();
    await method("repo_list").execute({}, context);
    assertEquals(calls.length, 3, "stops at the first empty page");
    assert(calls[0].startsWith("/api/v1/repos/search?"));
    assertEquals(written.length, 35);
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

Deno.test("a listing whose server ignores page fails instead of looping", async () => {
  // Every page returns the same repo, as a proxy that drops `page` would.
  const { caller } = makeFakeApi(() => ({
    status: 200,
    body: { data: [repoObj()] },
  }));
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("repo_list").execute({}, context),
      /same items for page 2 as for page 1/,
    );
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

// Search results carry mirror_interval and mirror_updated, so a per-repo
// fetch is wasted, and a mirror deleted mid-audit would fail it with a 404.
Deno.test("mirror_status reads mirror fields from the search alone", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return { ok: true, data: [mirrorObj()] } as unknown as Record<
        string,
        unknown
      >;
    }
    return undefined; // any per-repo GET would 404
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("mirror_status").execute({}, context);
    assert(
      calls.every((c) => c.path.startsWith("/api/v1/repos/search")),
      "only the search is called",
    );
    assertEquals(written.length, 1);
    assertEquals(written[0].data.interval, "8h0m0s");
    assertEquals(written[0].data.neverSynced, false);
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
    html_url: "https://git.test.example.com/apps/web/pulls/4",
    user: { login: "alice" },
    head: { ref: "feat/thing", sha: "abc123def456", repo: repoObj() },
    base: { ref: "main", sha: "999", repo: repoObj() },
    comments: 0,
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-01T00:00:00Z",
    ...over,
  };
}

/**
 * One page of the combined-status endpoint, as Forgejo pages it: page N holds
 * the latest status of the Nth group of contexts, and past the last group the
 * server answers `{}`. `pages` gives each page's state ("" ⇒ no statuses).
 */
function ciStatusPage(
  c: ApiCall,
  pages: string[],
): Record<string, unknown> {
  const page = Number(/[?&]page=(\d+)/.exec(c.path)?.[1] ?? 1);
  const state = pages[page - 1] ?? "";
  return state === ""
    ? {}
    : { state, statuses: [{ status: state, context: `ci-${page}` }] };
}

/**
 * Fake covering the PR endpoints. `open` is the open-PR listing; `detail` the
 * single-PR fetch; `ci` the combined-status state ("" ⇒ no statuses), or one
 * state per page.
 */
function prApi(opts: {
  open?: Array<Record<string, unknown>>;
  detail?: Record<string, unknown>;
  ci?: string | string[];
  onMerge?: () => { status: number; body: Record<string, unknown> };
}) {
  return makeFakeApi((c) => {
    if (/\/commits\/[^/]+\/status\?/.test(c.path)) {
      const ci = opts.ci ?? "";
      return ciStatusPage(c, typeof ci === "string" ? [ci] : ci);
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
        name: "web",
        head: "feat/thing",
        base: "main",
        title: "Add the thing",
      },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(post?.path, "/api/v1/repos/apps/web/pulls");
    assertEquals((post?.body as Record<string, unknown>).base, "main");
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].name, "pull_request:apps:web:4");
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
        name: "web",
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
        name: "web",
        head: "feat/thing",
        base: "main",
        title: "Renamed",
      },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.path, "/api/v1/repos/apps/web/pulls/4");
    assertEquals((patch?.body as Record<string, unknown>).title, "Renamed");
    assertEquals(written[0].data.action, "updated");
  } finally {
    __setCaller(null);
  }
});

// A PR from someone's fork: the API reports the bare branch, and the fork's
// owner only on head.repo.
const forkPr = () =>
  prObj({
    head: {
      ref: "feat/thing",
      sha: "abc123def456",
      repo: repoObj({ full_name: "someone/web", owner: { login: "someone" } }),
    },
  });

Deno.test("pr_ensure matches a fork head (owner:branch) against the bare ref", async () => {
  const { caller, calls } = prApi({ open: [forkPr()] });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_ensure").execute(
      {
        owner: "apps",
        name: "web",
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

Deno.test("pr_ensure does not match a same-named branch from another repo", async () => {
  // Each request names a head that is NOT the open PR's head repo, so each
  // must open a new PR rather than rewrite the existing one's title.
  for (
    const [head, open] of [
      ["someone:feat/thing", prObj()], // fork head vs a same-repo PR
      ["feat/thing", forkPr()], // same-repo head vs a fork PR
      ["bob:feat/thing", forkPr()], // bob's fork vs someone's fork
    ] as const
  ) {
    const { caller, calls } = prApi({ open: [open] });
    __setCaller(caller);
    try {
      const { context, written } = makeContext();
      await method("pr_ensure").execute(
        { owner: "apps", name: "web", head, base: "main", title: "Other" },
        context,
      );
      assert(
        calls.some((c) => c.method === "POST"),
        `${head} must open its own PR`,
      );
      assert(!calls.some((c) => c.method === "PATCH"), `${head}: no PATCH`);
      assertEquals(written[0].data.action, "created");
    } finally {
      __setCaller(null);
    }
  }
});

Deno.test("pr_ensure compares the head owner case-insensitively", async () => {
  const { caller, calls } = prApi({ open: [forkPr()] });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_ensure").execute(
      {
        owner: "apps",
        name: "web",
        head: "SomeOne:feat/thing",
        base: "main",
        title: "Add the thing",
      },
      context,
    );
    assert(!calls.some((c) => c.method === "POST"), "must match, not create");
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
      { owner: "apps", name: "web", index: 4 },
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
            { owner: "apps", name: "web", index: 4 },
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
          { owner: "apps", name: "web", index: 4, force: true },
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
          { owner: "apps", name: "web", index: 4 },
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
          { owner: "apps", name: "web", index: 4 },
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
    if (c.path.includes("/commits/")) return ciStatusPage(c, ["success"]);
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
        name: "web",
        index: 4,
        strategy: "squash",
        deleteBranch: true,
      },
      context,
    );
    const merge = calls.find((c) => c.path.endsWith("/merge"));
    assertEquals(merge?.path, "/api/v1/repos/apps/web/pulls/4/merge");
    const body = merge?.body as Record<string, unknown>;
    assertEquals(body.Do, "squash");
    assertEquals(body.delete_branch_after_merge, true);
    assertEquals(written[0].data.action, "merged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_merge refuses when a failing context sits on a later status page", async () => {
  // Forgejo combines statuses one page of contexts at a time, so page 1 can
  // read "success" while page 2 fails.
  const { caller, calls } = prApi({
    detail: prObj(),
    ci: ["success", "failure"],
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("pr_merge").execute(
          { owner: "apps", name: "web", index: 4 },
          context,
        ),
      /CI state "failure"/,
    );
    assert(!calls.some((c) => c.path.endsWith("/merge")), "must not merge");
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_get combines the CI state across every status page", async () => {
  for (
    const [pages, want] of [
      [["success", "success"], "success"],
      [["success", "pending"], "pending"],
      [["pending", "failure", "success"], "failure"],
      [["success", "skipped"], "success"],
      [["success", "mystery"], "mystery"],
    ] as Array<[string[], string]>
  ) {
    const { caller } = prApi({ detail: prObj(), ci: pages });
    __setCaller(caller);
    try {
      const { context, written } = makeContext();
      await method("pr_get").execute(
        { owner: "apps", name: "web", index: 4 },
        context,
      );
      assertEquals(written[0].data.ciState, want, pages.join(","));
    } finally {
      __setCaller(null);
    }
  }
});

Deno.test("pr_merge pins the merge to the head commit it checked", async () => {
  const { caller, calls } = prApi({ detail: prObj(), ci: "success" });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("pr_merge").execute(
      { owner: "apps", name: "web", index: 4 },
      context,
    );
    const merge = calls.find((c) => c.path.endsWith("/merge"));
    assertEquals(
      (merge?.body as Record<string, unknown>).head_commit_id,
      "abc123def456",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("pr_merge reports a head that moved before the merge as retryable", async () => {
  const { caller } = prApi({
    detail: prObj(),
    ci: "success",
    onMerge: () => ({ status: 409, body: { message: "head out of date" } }),
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("pr_merge").execute(
          { owner: "apps", name: "web", index: 4 },
          context,
        ),
      /head moved past abc123de .*Re-run pr_merge/,
    );
    assertEquals(written.length, 0);
  } finally {
    __setCaller(null);
  }
});

// The merge cannot be undone, so a failed re-read afterwards must not report
// the method as failed: a retry would only say "already merged".
Deno.test("pr_merge records the merge even when the re-fetch fails", async () => {
  let merged = false;
  const { caller } = makeFakeApi((c) => {
    if (c.path.includes("/commits/")) return ciStatusPage(c, ["success"]);
    if (c.method === "POST" && c.path.endsWith("/merge")) {
      merged = true;
      return {};
    }
    if (c.method === "GET" && /\/pulls\/\d+$/.test(c.path)) {
      return merged
        ? { status: 502, body: { message: "bad gateway" } }
        : prObj();
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written, logs } = makeContext();
    await method("pr_merge").execute(
      { owner: "apps", name: "web", index: 4 },
      context,
    );
    assertEquals(written[0].data.action, "merged");
    assertEquals(written[0].data.merged, true);
    assertEquals(written[0].data.state, "closed");
    assert(
      logs.some((l) => l.level === "warn" && /re-read/.test(l.message)),
      "the failed re-read is logged as a warning",
    );
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────── narrow-token compatibility ───────────────────────

type CheckDef = {
  execute: (
    context: { globalArgs: Record<string, unknown> },
  ) => Promise<{ pass: boolean; errors?: string[] }>;
};
const check = (name: string): CheckDef =>
  (model.checks as unknown as Record<string, CheckDef>)[name];
// Checks get globalArgs without the schema's defaults, so these leave them out.
const CHECK_GLOBALS = { apiUrl: GLOBALS.apiUrl, token: GLOBALS.token };

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
    const r = await check("reachable").execute({ globalArgs: CHECK_GLOBALS });
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
    const r = await check("reachable").execute({ globalArgs: CHECK_GLOBALS });
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
    const r = await check("reachable").execute({ globalArgs: CHECK_GLOBALS });
    assertEquals(r.pass, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("repo_list: a refused org probe falls through to the user path", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/orgs/alice")) {
      return {
        status: 403,
        body: {
          message:
            "token does not have at least one of required scope(s): [read:organization]",
        },
      };
    }
    if (c.path.startsWith("/api/v1/users/alice/repos")) {
      return [
        repoObj({ full_name: "alice/swamp", owner: { login: "alice" } }),
      ];
    }
    return undefined;
  });
  const { context, written } = makeContext();
  __setCaller(caller);
  try {
    await method("repo_list").execute({ owner: "alice" }, context);
    assertEquals(written.length, 1);
    assertEquals(written[0].data.fullName, "alice/swamp");
    assert(
      calls.some((c) => c.path.startsWith("/api/v1/orgs/alice")),
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
      () => method("repo_list").execute({ owner: "alice" }, context),
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
  owner: "alice",
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
      "/api/v1/repos/alice/agent-scratch/collaborators/factory-agents",
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

Deno.test("collaborator_ensure grants write to a new collaborator when no permission is passed", async () => {
  const { caller, calls } = makeFakeApi((c) =>
    c.method === "GET" ? undefined : {}
  );
  __setCaller(caller);
  try {
    const { context } = makeContext();
    const { permission: _, ...args } = COLLAB_ARGS;
    await method("collaborator_ensure").execute(args, context);
    const put = calls.find((c) => c.method === "PUT");
    assertEquals(put?.body, { permission: "write" });
  } finally {
    __setCaller(null);
  }
});

// Same bug class as issue #4: an omitted permission must not reset an
// existing collaborator's level to the default.
Deno.test("collaborator_ensure keeps an existing level when no permission is passed", async () => {
  const { caller, calls } = makeFakeApi(() => ({ permission: "admin" }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    const { permission: _, ...args } = COLLAB_ARGS;
    await method("collaborator_ensure").execute(args, context);
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.permission, "admin");
  } finally {
    __setCaller(null);
  }
});

// The permission probe reports the effective mode, and everyone can read a
// public repo, so "read" alone must not pass for an existing collaboration.
Deno.test("collaborator_ensure adds a non-collaborator who can already read a public repo", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.endsWith("/permission")) {
      return { permission: "read" };
    }
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
      "/api/v1/repos/alice/agent-scratch/collaborators/factory-agents",
    );
    assertEquals(put?.body, { permission: "write" });
    assertEquals(written[0].data.action, "created");
  } finally {
    __setCaller(null);
  }
});

Deno.test("collaborator_ensure is unchanged for a collaborator already at read", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.endsWith("/permission")) {
      return { permission: "read" };
    }
    return { status: 204, body: {} };
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("collaborator_ensure").execute(
      { ...COLLAB_ARGS, permission: "read" },
      context,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
    assertEquals(written[0].data.action, "unchanged");
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
          { ...COLLAB_ARGS, user: "alice" },
          context,
        ),
      /owns alice\/agent-scratch/,
    );
    assert(!calls.some((c) => c.method !== "GET"), "must not mutate");
  } finally {
    __setCaller(null);
  }
});

// The permission probe reads "owner" for a site admin (and an owner of the
// owning org), who is not the repo owner and can be a collaborator.
Deno.test("collaborator_ensure grants a site admin who is not the owner", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.endsWith("/permission")) {
      return { permission: "owner" };
    }
    if (c.method === "GET") return undefined; // not a collaborator
    return {};
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("collaborator_ensure").execute(
      { ...COLLAB_ARGS, user: "site-admin-bot" },
      context,
    );
    const put = calls.find((c) => c.method === "PUT");
    assertEquals(put?.body, { permission: "write" });
    assertEquals(written[0].data.action, "created");
  } finally {
    __setCaller(null);
  }
});

Deno.test("collaborator_ensure refuses the owner whatever the case", async () => {
  const { caller, calls } = makeFakeApi(() => ({ permission: "owner" }));
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("collaborator_ensure").execute(
          { ...COLLAB_ARGS, user: "Alice" },
          context,
        ),
      /owns alice\/agent-scratch/,
    );
    assertEquals(calls.length, 0, "refused before any call");
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
        owner: "alice",
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
      "/api/v1/repos/alice/agent-scratch/branch_protections",
    );
    const body = post?.body as Record<string, unknown>;
    assertEquals(body.rule_name, "main");
    assertEquals(body.enable_push, false);
    // A supplied-but-false field must still be sent on create; omitting it
    // would apply the server default.
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
        owner: "alice",
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
      "/api/v1/repos/alice/agent-scratch/branch_protections/agents%2F*",
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
        owner: "alice",
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

// Forgejo reads enable_push_whitelist only inside its enable_push handling,
// so a whitelist flag sent on its own is dropped and reported as drift on every run.
Deno.test("branch_protection_ensure sends enable_push alongside a whitelist on update", async () => {
  const { caller, calls } = makeFakeApi((c) =>
    c.method === "GET"
      ? {
        rule_name: "agents/*",
        enable_push: true,
        enable_push_whitelist: false,
        push_whitelist_usernames: [],
      }
      : { rule_name: "agents/*" }
  );
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("branch_protection_ensure").execute(
      {
        owner: "alice",
        name: "agent-scratch",
        rule: "agents/*",
        enablePushWhitelist: true,
        pushWhitelistUsernames: ["factory-agents"],
      },
      context,
    );
    const body = calls.find((c) => c.method === "PATCH")?.body as Record<
      string,
      unknown
    >;
    assertEquals(body.enable_push, true);
    assertEquals(body.enable_push_whitelist, true);
    assertEquals(body.push_whitelist_usernames, ["factory-agents"]);
    assertEquals(Object.keys(body).length, 3);
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_ensure implies enable_push when creating with a whitelist", async () => {
  const { caller, calls } = makeFakeApi((c) =>
    c.method === "GET" ? undefined : { rule_name: "agents/*" }
  );
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("branch_protection_ensure").execute(
      {
        owner: "alice",
        name: "agent-scratch",
        rule: "agents/*",
        enablePushWhitelist: true,
        pushWhitelistUsernames: ["factory-agents"],
      },
      context,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals((post?.body as Record<string, unknown>).enable_push, true);
    assertEquals(
      (post?.body as Record<string, unknown>).enable_push_whitelist,
      true,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_ensure refuses a whitelist with enablePush=false", async () => {
  const { caller, calls } = makeFakeApi(() => undefined);
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("branch_protection_ensure").execute(
          {
            owner: "alice",
            name: "agent-scratch",
            rule: "main",
            enablePush: false,
            enablePushWhitelist: true,
          },
          context,
        ),
      /needs enablePush/,
    );
    assert(!calls.some((c) => c.method !== "GET"), "no mutation expected");
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
        owner: "alice",
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
      { owner: "alice", name: "agent-scratch" },
      context,
    );
    assertEquals(written.length, 2);
    assertEquals(written[0].name, "branch_protection:alice:agent-scratch:main");
    // A `/` in a rule pattern is escaped, never dropped.
    assertEquals(
      written[1].name,
      "branch_protection:alice:agent-scratch:agents%2F*",
    );
    assertEquals(written[1].data.action, "observed");
  } finally {
    __setCaller(null);
  }
});

// Forgejo returns whitelist logins in its own order, so the order and case
// the caller used must not read as drift.
Deno.test("branch_protection_ensure compares lists as sets", async () => {
  const { caller, calls } = makeFakeApi(() => ({
    rule_name: "main",
    enable_push: true,
    enable_push_whitelist: true,
    push_whitelist_usernames: ["amy", "zed"],
    enable_status_check: true,
    status_check_contexts: ["ci/lint", "ci/test"],
  }));
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("branch_protection_ensure").execute(
      {
        owner: "alice",
        name: "agent-scratch",
        rule: "main",
        enablePushWhitelist: true,
        pushWhitelistUsernames: ["Zed", "amy"],
        statusCheckContexts: ["ci/test", "ci/lint"],
      },
      context,
    );
    assert(!calls.some((c) => c.method === "PATCH"), "no PATCH expected");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_ensure still sees a changed status-check context", async () => {
  // Contexts are matched exactly by Forgejo, so case is a real difference.
  const { caller, calls } = makeFakeApi((c) =>
    c.method === "GET"
      ? { rule_name: "main", status_check_contexts: ["ci/test"] }
      : { rule_name: "main" }
  );
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("branch_protection_ensure").execute(
      {
        owner: "alice",
        name: "agent-scratch",
        rule: "main",
        statusCheckContexts: ["CI/test"],
      },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      (patch?.body as Record<string, unknown>).status_check_contexts,
      ["CI/test"],
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_list records the merge and approval constraints", async () => {
  const { caller } = makeFakeApi(() => [{
    rule_name: "main",
    push_whitelist_teams: ["release"],
    push_whitelist_deploy_keys: true,
    enable_merge_whitelist: true,
    merge_whitelist_usernames: ["amy"],
    merge_whitelist_teams: ["owners"],
    enable_approvals_whitelist: true,
    // Forgejo's JSON name is singular for this one list.
    approvals_whitelist_username: ["zed"],
    approvals_whitelist_teams: ["reviewers"],
    dismiss_stale_approvals: true,
    ignore_stale_approvals: true,
    block_on_official_review_requests: true,
    unprotected_file_patterns: "docs/**",
  }]);
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("branch_protection_list").execute(
      { owner: "alice", name: "agent-scratch" },
      context,
    );
    const d = written[0].data;
    assertEquals(d.pushWhitelistTeams, ["release"]);
    assertEquals(d.pushWhitelistDeployKeys, true);
    assertEquals(d.enableMergeWhitelist, true);
    assertEquals(d.mergeWhitelistUsernames, ["amy"]);
    assertEquals(d.mergeWhitelistTeams, ["owners"]);
    assertEquals(d.enableApprovalsWhitelist, true);
    assertEquals(d.approvalsWhitelistUsernames, ["zed"]);
    assertEquals(d.approvalsWhitelistTeams, ["reviewers"]);
    assertEquals(d.dismissStaleApprovals, true);
    assertEquals(d.ignoreStaleApprovals, true);
    assertEquals(d.blockOnOfficialReviewRequests, true);
    assertEquals(d.unprotectedFilePatterns, "docs/**");
  } finally {
    __setCaller(null);
  }
});

Deno.test("branch_protection_ensure rejects a negative requiredApprovals", async () => {
  const { caller, calls } = makeFakeApi(() => undefined);
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("branch_protection_ensure").execute(
          {
            owner: "alice",
            name: "agent-scratch",
            rule: "main",
            requiredApprovals: -1,
          },
          context,
        ),
      /requiredApprovals|>=0|too_small/,
    );
    assertEquals(calls.length, 0);
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── webhooks ───────────────────────────

const OLD_CI = "https://old-ci.example.net:8443/api/hook";
// Woodpecker appends a per-repo JWT to the hook URL; the fixtures carry one
// so the tests use the real URL format.
const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiaG9vayJ9.sig";
const NEW_CI = "http://ci.example.net/api/hook";

function hookObj(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 3,
    type: "forgejo",
    active: true,
    events: ["push", "pull_request"],
    branch_filter: "main",
    authorization_header: "Bearer hook-token",
    created_at: "2026-06-19T00:00:00Z",
    updated_at: "2026-06-19T00:00:00Z",
    // The real API never returns `secret`; it is included here so the tests
    // check it is dropped if a future version starts to return it.
    config: { url: OLD_CI, content_type: "json", secret: "s3cr3t" },
    ...over,
  };
}

Deno.test("webhook_audit flags drift against expectedUrl", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return c.path.includes("page=1")
        ? [
          repoObj({
            full_name: "alice/widget",
            owner: { login: "alice" },
            name: "widget",
          }),
        ]
        : [];
    }
    if (c.path.includes("/hooks?")) {
      return [hookObj(), hookObj({ id: 4, config: { url: NEW_CI } })];
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_audit").execute({ expectedUrl: NEW_CI }, context);
    assertEquals(written.length, 2);
    assertEquals(
      written[0].data.matchesExpected,
      false,
      "hook on the old host is drift",
    );
    assertEquals(
      written[1].data.matchesExpected,
      true,
      "hook on the new host matches",
    );
    assertEquals(written[0].name, "webhook:alice:widget:3");
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_audit omits matchesExpected when no expectation given", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return c.path.includes("page=1") ? [repoObj()] : [];
    }
    if (c.path.includes("/hooks?")) return [hookObj()];
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_audit").execute({}, context);
    // Held as `undefined`, per the file's convention for optional fields. It
    // must not be stored as `false`, which would report drift that the caller
    // did not ask about.
    const persisted = JSON.parse(JSON.stringify(written[0].data));
    assert(!("matchesExpected" in persisted), "should be absent, not false");
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_audit never emits the secret", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return c.path.includes("page=1") ? [repoObj()] : [];
    }
    if (c.path.includes("/hooks?")) return [hookObj()];
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_audit").execute({}, context);
    assert(
      !JSON.stringify(written[0].data).includes("s3cr3t"),
      "webhook secret leaked into the data model",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_audit skips a repo whose hooks it may not read", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return c.path.includes("page=1")
        ? [
          repoObj({ full_name: "a/one", owner: { login: "a" }, name: "one" }),
          repoObj({ full_name: "b/two", owner: { login: "b" }, name: "two" }),
        ]
        : [];
    }
    if (c.path.startsWith("/api/v1/repos/a/one/hooks?")) {
      return { status: 403, body: { message: "forbidden" } };
    }
    if (c.path.startsWith("/api/v1/repos/b/two/hooks?")) return [hookObj()];
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_audit").execute({}, context);
    assertEquals(written.length, 1, "the readable repo still audits");
    assertEquals(written[0].data.repo, "b/two");
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_audit --owner lists that owner's repos, not the whole server", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.path === "/api/v1/orgs/a") return { username: "a" };
    if (c.path.startsWith("/api/v1/orgs/a/repos")) {
      return [
        repoObj({ full_name: "a/one", owner: { login: "a" }, name: "one" }),
      ];
    }
    if (c.path.startsWith("/api/v1/repos/a/one/hooks?")) return [hookObj()];
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_audit").execute({ owner: "a" }, context);
    assertEquals(written.length, 1);
    assert(
      !calls.some((c) => c.path.startsWith("/api/v1/repos/search")),
      "must not search every repo",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_audit rejects name without owner", async () => {
  const { caller } = makeFakeApi(() => undefined);
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("webhook_audit").execute({ name: "widget" }, context),
      /requires `owner`/,
    );
  } finally {
    __setCaller(null);
  }
});

// Forgejo's editHook resets events, branch_filter and authorization_header
// on any PATCH that leaves them out, so they must be sent with the new URL.
Deno.test("webhook_retarget changes only the URL, carrying events, branch filter and auth header", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) return [hookObj()];
    if (c.method === "PATCH") return hookObj({ config: { url: NEW_CI } });
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_retarget").execute(
      { owner: "alice", name: "widget", url: NEW_CI },
      context,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(patch?.path, "/api/v1/repos/alice/widget/hooks/3");
    assertEquals(patch?.body, {
      config: { url: NEW_CI },
      events: ["push", "pull_request"],
      branch_filter: "main",
      authorization_header: "Bearer hook-token",
    });
    assert(
      !JSON.stringify(patch?.body).includes("secret"),
      "must not send a secret key — that could clear the stored one",
    );
    assertEquals(written[0].data.action, "updated");
    assertEquals(written[0].data.url, NEW_CI);
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget is a no-op when already correct", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) {
      return [hookObj({ config: { url: NEW_CI } })];
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_retarget").execute(
      { owner: "alice", name: "widget", url: NEW_CI },
      context,
    );
    assertEquals(calls.filter((c) => c.method === "PATCH").length, 0);
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget refuses to guess between several hooks", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) {
      return [
        hookObj(),
        hookObj({ id: 4, config: { url: "https://other.example/hook" } }),
      ];
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("webhook_retarget").execute(
          { owner: "alice", name: "widget", url: NEW_CI },
          context,
        ),
      /refusing to guess/,
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget picks the one hook matchUrl identifies", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) {
      return [
        hookObj(),
        hookObj({ id: 4, config: { url: "https://other.example/hook" } }),
      ];
    }
    if (c.method === "PATCH") return hookObj({ config: { url: NEW_CI } });
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("webhook_retarget").execute(
      {
        owner: "alice",
        name: "widget",
        url: NEW_CI,
        matchUrl: "old-ci.example.net",
      },
      context,
    );
    assertEquals(
      calls.find((c) => c.method === "PATCH")?.path,
      "/api/v1/repos/alice/widget/hooks/3",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget never creates a hook when none exists", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) return [];
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("webhook_retarget").execute(
          { owner: "alice", name: "widget", url: NEW_CI },
          context,
        ),
      /does not create one/,
    );
    assertEquals(calls.filter((c) => c.method === "POST").length, 0);
  } finally {
    __setCaller(null);
  }
});

// The query string on a CI hook URL is a credential. These tests check that
// it is never output and never removed.

Deno.test("webhook_audit redacts the access token from the URL", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return c.path.includes("page=1") ? [repoObj()] : [];
    }
    if (c.path.includes("/hooks?")) {
      return [
        hookObj({ config: { url: `${NEW_CI}?access_token=${TOKEN}` } }),
      ];
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_audit").execute({}, context);
    const blob = JSON.stringify(written[0].data);
    assert(
      !blob.includes(TOKEN),
      "hook access token leaked into the data model",
    );
    assertEquals(written[0].data.url, `${NEW_CI}?access_token=REDACTED`);
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_audit matches on the target, ignoring the token query", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return c.path.includes("page=1") ? [repoObj()] : [];
    }
    if (c.path.includes("/hooks?")) {
      return [
        hookObj({ config: { url: `${NEW_CI}?access_token=${TOKEN}` } }),
        hookObj({ id: 4, config: { url: `${OLD_CI}?access_token=${TOKEN}` } }),
      ];
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_audit").execute({ expectedUrl: NEW_CI }, context);
    assertEquals(
      written[0].data.matchesExpected,
      true,
      "a correct hook must not read as drift merely for carrying its token",
    );
    assertEquals(written[1].data.matchesExpected, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget carries the access token over to the new host", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) {
      return [hookObj({ config: { url: `${OLD_CI}?access_token=${TOKEN}` } })];
    }
    if (c.method === "PATCH") return hookObj();
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await method("webhook_retarget").execute(
      { owner: "alice", name: "widget", url: NEW_CI },
      context,
    );
    const body = calls.find((c) => c.method === "PATCH")?.body as
      | { config: { url: string } }
      | undefined;
    assertEquals(
      body?.config.url,
      `${NEW_CI}?access_token=${TOKEN}`,
      "dropping the token would de-authenticate a hook that still fires",
    );
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget is a no-op when only the token differs", async () => {
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) {
      return [
        hookObj({ config: { url: `${NEW_CI}?access_token=${TOKEN}` } }),
      ];
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_retarget").execute(
      { owner: "alice", name: "widget", url: NEW_CI },
      context,
    );
    assertEquals(calls.filter((c) => c.method === "PATCH").length, 0);
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget error messages never show the token", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) {
      return [
        hookObj({ config: { url: `${OLD_CI}?access_token=${TOKEN}` } }),
        hookObj({
          id: 4,
          config: { url: `${NEW_CI}?access_token=${TOKEN}` },
        }),
      ];
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    let msg = "";
    try {
      await method("webhook_retarget").execute(
        { owner: "alice", name: "widget", url: NEW_CI },
        context,
      );
    } catch (e) {
      msg = (e as Error).message;
    }
    assert(/refusing to guess/.test(msg), `unexpected message: ${msg}`);
    assert(!msg.includes(TOKEN), "token leaked into an error message");
    assert(msg.includes("REDACTED"), "should show the redacted form");
  } finally {
    __setCaller(null);
  }
});

// The hook listing is paginated: a hook past page 1 must still be seen.
function pagedHooks(c: ApiCall, pages: Array<Record<string, unknown>[]>) {
  const page = Number(/[?&]page=(\d+)/.exec(c.path)?.[1] ?? 1);
  return {
    status: 200,
    body: (pages[page - 1] ?? []) as unknown as Record<string, unknown>,
  };
}

Deno.test("webhook_audit reads hooks past the first page", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return c.path.includes("page=1") ? [repoObj()] : [];
    }
    if (c.path.includes("/hooks?")) {
      return pagedHooks(c, [[hookObj()], [hookObj({ id: 4 })]]);
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("webhook_audit").execute({}, context);
    assertEquals(written.map((w) => w.data.id), [3, 4]);
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget sees a hook past the first page", async () => {
  // Page 2 holds a second match, so the method must refuse to guess rather
  // than treat the page-1 hook as the only one.
  const { caller, calls } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) {
      return pagedHooks(c, [[hookObj()], [hookObj({ id: 4 })]]);
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("webhook_retarget").execute(
          { owner: "alice", name: "widget", url: NEW_CI },
          context,
        ),
      /2 webhooks match/,
    );
    assertEquals(calls.filter((c) => c.method === "PATCH").length, 0);
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_audit warns about a skipped repo and counts it", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return c.path.includes("page=1")
        ? [
          repoObj({ full_name: "a/one", owner: { login: "a" }, name: "one" }),
          repoObj({ full_name: "b/two", owner: { login: "b" }, name: "two" }),
        ]
        : [];
    }
    if (c.path.startsWith("/api/v1/repos/a/one/hooks?")) {
      return { status: 403, body: { message: "forbidden" } };
    }
    if (c.path.startsWith("/api/v1/repos/b/two/hooks?")) return [hookObj()];
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, logs } = makeContext();
    await method("webhook_audit").execute({}, context);
    assert(
      logs.some((l) => l.level === "warn" && l.props.repo === "a/one"),
      "the skipped repo is a warning",
    );
    const done = logs.find((l) => l.message === "Webhook audit done");
    assertEquals(done?.props.skippedRepos, 1);
  } finally {
    __setCaller(null);
  }
});

// Forgejo lists events by group name but reads a group name back as the whole
// group, so a hook set to part of a group comes back wider. The method cannot
// prevent it, so it must at least say so.
Deno.test("webhook_retarget warns when Forgejo changes the hook's events", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) {
      return [hookObj({ events: ["issues"] })];
    }
    if (c.method === "PATCH") {
      return hookObj({
        config: { url: NEW_CI },
        events: ["issues", "issue_assign", "issue_label"],
      });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, logs } = makeContext();
    await method("webhook_retarget").execute(
      { owner: "alice", name: "widget", url: NEW_CI },
      context,
    );
    const warning = logs.find((l) => l.level === "warn");
    assert(warning, "a change of events must be warned about");
    assertEquals(warning?.props.after, [
      "issues",
      "issue_assign",
      "issue_label",
    ]);
  } finally {
    __setCaller(null);
  }
});

Deno.test("webhook_retarget does not warn when the events survive", async () => {
  const { caller } = makeFakeApi((c) => {
    if (c.method === "GET" && c.path.includes("/hooks?")) return [hookObj()];
    if (c.method === "PATCH") {
      // Same events, in another order.
      return hookObj({
        config: { url: NEW_CI },
        events: ["pull_request", "push"],
      });
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, logs } = makeContext();
    await method("webhook_retarget").execute(
      { owner: "alice", name: "widget", url: NEW_CI },
      context,
    );
    assert(!logs.some((l) => l.level === "warn"), "no warning expected");
  } finally {
    __setCaller(null);
  }
});

// ─────────────────────────── reachable check ───────────────────────────

// Issue #3: a check receives globalArgs without the schema's defaults, so an
// unset httpTimeoutMs used to reach fetch as undefined and abort at once.
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

Deno.test("reachable: a 200 that is not a Forgejo user fails", async () => {
  // e.g. apiUrl pointing at a web page that answers every path with HTML.
  const { caller } = makeFakeApi(() => ({
    status: 200,
    body: { raw: "<html>welcome</html>" },
  }));
  __setCaller(caller);
  try {
    const r = await check("reachable").execute({ globalArgs: CHECK_GLOBALS });
    assertEquals(r.pass, false);
  } finally {
    __setCaller(null);
  }
});

Deno.test("httpTimeoutMs must be positive", () => {
  const schema = model.globalArguments as unknown as {
    safeParse: (v: unknown) => { success: boolean };
  };
  assertEquals(
    schema.safeParse({ ...GLOBALS, httpTimeoutMs: 0 }).success,
    false,
  );
  assertEquals(
    schema.safeParse({ ...GLOBALS, httpTimeoutMs: 1 }).success,
    true,
  );
});

// ─────────────────────────── strict booleans ───────────────────────────

Deno.test("boolean arguments reject anything but true/false", () => {
  const schema = (model.methods as unknown as Record<string, {
    arguments: {
      safeParse: (v: unknown) => {
        success: boolean;
        error?: { issues: { path: PropertyKey[] }[] };
      };
    };
  }>)["branch_protection_ensure"].arguments;
  const fieldFails = (v: unknown) => {
    const r = schema.safeParse({ enablePush: v });
    return (r.error?.issues ?? []).some((i) => i.path[0] === "enablePush");
  };
  for (const bad of ["0", "1", "False", "True", "yes", null]) {
    assert(
      fieldFails(bad),
      `enablePush=${JSON.stringify(bad)} must be rejected`,
    );
  }
  // Strings are rejected too: the CLI turns `--input enablePush=true` into a
  // real boolean before the schema sees it.
  for (const bad of ["true", "false"]) {
    assert(
      fieldFails(bad),
      `enablePush=${JSON.stringify(bad)} must be rejected`,
    );
  }
  for (const good of [true, false]) {
    assert(
      !fieldFails(good),
      `enablePush=${JSON.stringify(good)} must be accepted`,
    );
  }
});

// ─────────────────────────── data names ───────────────────────────

Deno.test("repo_list and mirror_status write distinct names for one repo", async () => {
  const mirror = mirrorObj({
    full_name: "Mirrors/Widget",
    owner: { login: "Mirrors" },
  });
  const { caller } = makeFakeApi((c) => {
    if (c.path.startsWith("/api/v1/repos/search")) {
      return { ok: true, data: [mirror] } as unknown as Record<
        string,
        unknown
      >;
    }
    return mirror;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("repo_list").execute({}, context);
    await method("mirror_status").execute({}, context);
    // Same repo, two specs: the spec prefix keeps the records apart, and the
    // owner/name are lowercased because Forgejo treats them case-insensitively.
    assertEquals(written.map((w) => w.name), [
      "repo:mirrors:widget",
      "mirror:mirrors:widget",
    ]);
  } finally {
    __setCaller(null);
  }
});

Deno.test("dataName escapes so distinct keys never share a name", () => {
  assertEquals(dataName("server"), "server");
  assertEquals(dataName("repo", "apps", "web"), "repo:apps:web");
  // `a/b` and `a:b` as one part must not collide with each other or with two
  // parts `a`,`b`; `..` must never reach swamp.
  const names = [
    dataName("branch_protection", "o", "r", "a/b"),
    dataName("branch_protection", "o", "r", "a:b"),
    dataName("branch_protection", "o", "r", "a", "b"),
    dataName("branch_protection", "o", "r", "a%2Fb"),
  ];
  assertEquals(new Set(names).size, names.length);
  for (const n of [...names, dataName("x", "a..b\\c\0")]) {
    assert(!/[\/\\\0]|\.\./.test(n), `${n} contains a banned sequence`);
  }
});

Deno.test("upgrade to 2026.10.11.1 drops only a non-positive timeout", () => {
  const up = model.upgrades.find((u) => u.toVersion === "2026.10.11.1")!;
  const base = { apiUrl: "https://git.example.com", token: "t" };
  assertEquals(up.upgradeAttributes({ ...base, httpTimeoutMs: 0 }), base);
  assertEquals(up.upgradeAttributes({ ...base, httpTimeoutMs: -5 }), base);
  assertEquals(up.upgradeAttributes({ ...base, httpTimeoutMs: 5000 }), {
    ...base,
    httpTimeoutMs: 5000,
  });
  assertEquals(up.upgradeAttributes(base), base);
  const expr = { ...base, httpTimeoutMs: "${{ inputs.timeout }}" };
  assertEquals(up.upgradeAttributes(expr), expr);
});

Deno.test("pr_merge with deleteBranch records the merged branch, not refs/pull/N/head", async () => {
  // After the head branch is deleted, Forgejo's re-read reports the head as
  // the PR's own ref.
  let merged = false;
  const { caller } = makeFakeApi((c) => {
    if (c.path.includes("/commits/")) return ciStatusPage(c, ["success"]);
    if (c.method === "POST" && c.path.endsWith("/merge")) {
      merged = true;
      return {};
    }
    if (c.method === "GET" && /\/pulls\/\d+$/.test(c.path)) {
      return merged
        ? prObj({
          merged: true,
          state: "closed",
          head: { ref: "refs/pull/4/head", sha: "abc123def456", repo: null },
        })
        : prObj();
    }
    return undefined;
  });
  __setCaller(caller);
  try {
    const { context, written } = makeContext();
    await method("pr_merge").execute(
      { owner: "apps", name: "web", index: 4, deleteBranch: true },
      context,
    );
    assertEquals(written[0].data.head, "feat/thing");
    assertEquals(written[0].data.merged, true);
  } finally {
    __setCaller(null);
  }
});

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
      () => method("health").execute({}, stalled),
      /timed out after 200 ms/,
    );
  } finally {
    await server.shutdown();
  }
});
