import { z } from "npm:zod@4";
// Type-only imports — erased at compile time, never bundled. They anchor the
// `satisfies ModelDefinition<typeof GlobalArgs>` clause so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";

/**
 * `@thomas/forgejo` — careful administration of a Forgejo (or Gitea) server
 * over its `/api/v1` REST API, authenticated with a scoped access token.
 *
 * PURPOSE (the repeatable kit): provision repositories and organizations, and
 * run GitHub pull-mirrors, as repeatable idempotent operations instead of
 * one-off UI clicks — find-or-create an org, find-or-create a repo and
 * converge its settings, find-or-create a pull-mirror of a GitHub repo, and
 * audit every mirror's sync health in one call.
 *
 * SCOPE GUARANTEE: mutations are find-or-create (`*_ensure`) or reversible
 * (`repo_archive` / `repo_unarchive`). There are NO delete methods — removing
 * a repo, org, or mirror stays a deliberate manual act in the UI. A failed
 * migration's empty shell repo is DETECTED and reported by `mirror_ensure`,
 * never auto-deleted. Mirror source credentials (`authToken` for private
 * GitHub sources) are write-only: supplied via a vault reference, sent once
 * to `/repos/migrate`, and never read back or written to the data model.
 *
 * Auth: a Forgejo access token (Settings → Applications), sent per request as
 * `Authorization: token <t>`. Scopes for the full surface:
 * `write:repository, write:organization, read:admin, read:misc, read:user`
 * (`read:admin` is only exercised by `user_list`; `read:misc` by `health`).
 * The token's user must be a site admin for `user_list` and for the listing
 * methods to see private repos across all owners. NB (proven 2026-06-13):
 * token CRUD (`/users/{u}/tokens`) is basic-auth-only — this model never
 * mints or revokes tokens.
 *
 * Method sections (by prefix):
 *   - read/audit: `health`, `org_list`, `repo_list`, `user_list`,
 *     `mirror_status`.
 *   - idempotent provisioning: `org_ensure`, `repo_ensure`, `mirror_ensure`,
 *     `mirror_sync_now`.
 *   - reversible lifecycle: `repo_archive`, `repo_unarchive`.
 *
 * Idempotency: every `*_ensure` probes by name first (404 ⇒ create, else
 * converge the supplied settings in place via PATCH) and reports an `action`
 * of created/updated/unchanged so a re-run is a no-op when nothing changed.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  apiUrl: z.string().describe(
    "Forgejo base URL, e.g. https://git.smol.cloud (no trailing /api/v1).",
  ),
  token: z.string().meta({ sensitive: true }).describe(
    "Forgejo access token (Settings → Applications). Supply via vault: " +
      "${{ vault.get(<vault>, forgejo/api_token) }}",
  ),
  httpTimeoutMs: z.coerce.number().int().default(30000).describe(
    "Per-request timeout (ms) for API calls.",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type",
// so it must not leak onto the public API (the exported `CallerFn` seam uses
// the loose `Json` instead — see below).
type GlobalArgsT = z.infer<typeof GlobalArgs>;

/** The set of outcomes a method reports in its `action` field. */
const Action = z.enum([
  "created",
  "updated",
  "unchanged",
  "archived",
  "unarchived",
  "triggered",
  "observed",
]);

// ─────────────────────────── resource schemas ───────────────────────────

const ServerStatus = z.object({
  version: z.string().describe("Forgejo version string."),
  healthy: z.boolean().describe("True if /api/healthz reports pass."),
  action: Action,
  timestamp: z.string(),
});

const OrgInfo = z.object({
  id: z.number(),
  name: z.string().describe("Org login name."),
  fullName: z.string().optional().describe("Display name."),
  visibility: z.string().describe("public | limited | private"),
  description: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const RepoInfo = z.object({
  id: z.number(),
  fullName: z.string(),
  owner: z.string(),
  name: z.string(),
  private: z.boolean(),
  archived: z.boolean(),
  empty: z.boolean().describe(
    "True when the repo has no git content (a failed migration leaves an " +
      "empty shell).",
  ),
  mirror: z.boolean().describe("True when the repo is a pull-mirror."),
  fork: z.boolean(),
  defaultBranch: z.string().optional(),
  description: z.string().optional(),
  htmlUrl: z.string().optional(),
  sizeKb: z.number().optional().describe("Repo size in KiB as reported."),
  action: Action,
  timestamp: z.string(),
});

const UserInfo = z.object({
  id: z.number(),
  login: z.string(),
  email: z.string().optional(),
  fullName: z.string().optional(),
  isAdmin: z.boolean(),
  restricted: z.boolean().optional(),
  prohibitLogin: z.boolean().optional(),
  lastLogin: z.string().optional(),
  created: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const MirrorInfo = z.object({
  fullName: z.string(),
  owner: z.string(),
  name: z.string(),
  private: z.boolean(),
  originalUrl: z.string().optional().describe(
    "The source URL the mirror pulls from (as recorded at migration time).",
  ),
  interval: z.string().describe(
    'Sync interval as a Go duration (e.g. "8h0m0s"); "0s" disables periodic ' +
      "sync.",
  ),
  lastSynced: z.string().optional().describe(
    "When the mirror last synced (absent if it never has).",
  ),
  neverSynced: z.boolean().describe("True if the mirror has never synced."),
  stale: z.boolean().describe(
    "True when the last sync is older than staleFactor × interval (or the " +
      "mirror never synced while periodic sync is enabled).",
  ),
  action: Action,
  timestamp: z.string(),
});

// ─────────────────────────── HTTP / auth seam ───────────────────────────

/** A JSON-ish bag — structurally the resolved global args or an API body. */
export type Json = Record<string, unknown>;

/** One REST request: method + path (relative to `apiUrl`) + optional JSON body. */
export interface ApiCall {
  /** HTTP verb. */
  method: "GET" | "POST" | "PATCH" | "DELETE";
  /** Path relative to `apiUrl`, e.g. `/api/v1/orgs`. */
  path: string;
  /** Optional JSON request body. */
  body?: unknown;
}

/** The parsed result of an {@link ApiCall}. */
export interface ApiResult {
  /** HTTP status code. */
  status: number;
  /** Parsed JSON response body (`{}` when empty / non-JSON). */
  body: Json;
}

/**
 * The authenticated-call seam the methods use — swappable for unit tests. The
 * global args are typed loosely as {@link Json} so this EXPORTED type stays
 * "fast-check" clean (referencing the zod-inferred `GlobalArgsT` would drag a
 * slow type onto the public API). The real implementation re-narrows. It
 * returns the result for ALL HTTP statuses (it only throws on a
 * network/transport error); status-based control flow lives in
 * {@link call}/{@link callTolerant}.
 */
export type CallerFn = (g: Json, call: ApiCall) => Promise<ApiResult>;

let _callerOverride: CallerFn | null = null;

/** Test-only seam: substitute the API caller. Pass `null` to restore the real one. */
export function __setCaller(fn: CallerFn | null): void {
  _callerOverride = fn;
}

function baseUrl(g: GlobalArgsT): string {
  return g.apiUrl.replace(/\/+$/, "");
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

/** The real fetch-backed implementation behind {@link rawCall}. */
async function realCaller(g: GlobalArgsT, c: ApiCall): Promise<ApiResult> {
  const headers: Record<string, string> = {
    authorization: `token ${g.token}`,
    accept: "application/json",
  };
  let body: string | undefined;
  if (c.body !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(c.body);
  }
  const res = await fetchWithTimeout(
    `${baseUrl(g)}${c.path}`,
    { method: c.method, headers, body },
    g.httpTimeoutMs,
  );
  const text = await res.text();
  let parsed: Json = {};
  if (text) {
    try {
      parsed = JSON.parse(text) as Json;
    } catch {
      parsed = { raw: text };
    }
  }
  return { status: res.status, body: parsed };
}

/** Dispatch through the test override if set, else the real fetch caller. */
function rawCall(g: GlobalArgsT, c: ApiCall): Promise<ApiResult> {
  return (_callerOverride ?? realCaller)(g, c);
}

function errMsg(r: ApiResult): string {
  const b = r.body;
  if (typeof b.message === "string") return b.message;
  if (typeof b.error === "string") return b.error;
  if (typeof b.raw === "string") return b.raw;
  return JSON.stringify(b);
}

/** Call and throw on any HTTP error (status ≥ 400). */
async function call(g: GlobalArgsT, c: ApiCall): Promise<ApiResult> {
  const r = await rawCall(g, c);
  if (r.status >= 400) {
    throw new Error(
      `Forgejo API ${c.method} ${c.path} -> HTTP ${r.status}: ${errMsg(r)}`,
    );
  }
  return r;
}

/**
 * Call but tolerate a set of otherwise-error statuses (e.g. `404` for an
 * existence probe), returning the result for the caller to branch on.
 */
async function callTolerant(
  g: GlobalArgsT,
  c: ApiCall,
  allow: number[],
): Promise<ApiResult> {
  const r = await rawCall(g, c);
  if (r.status >= 400 && !allow.includes(r.status)) {
    throw new Error(
      `Forgejo API ${c.method} ${c.path} -> HTTP ${r.status}: ${errMsg(r)}`,
    );
  }
  return r;
}

// ─────────────────────────── helpers ───────────────────────────

type Ctx = MethodContext<GlobalArgsT>;

function logInfo(
  context: Pick<Ctx, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.info?.(message, props ?? {});
}

function nowIso(): string {
  return new Date().toISOString();
}

function asArray(v: unknown): Json[] {
  return Array.isArray(v) ? (v as Json[]) : [];
}

/**
 * Make a string safe as a swamp data instance name — swamp rejects names
 * containing `/`, `\`, `..`, or null bytes (path-traversal guard), but a repo
 * full name like `owner/name` naturally contains a slash.
 */
function safeName(s: string): string {
  return s.replace(/[\\/]/g, ":").replace(/\.\./g, "_").replace(/\0/g, "");
}

function enc(s: string): string {
  return encodeURIComponent(s);
}

function repoPath(owner: string, name: string): string {
  return `/api/v1/repos/${enc(owner)}/${enc(name)}`;
}

/**
 * Items from a Forgejo list response: either a bare array (most endpoints) or
 * a `{ ok, data: [...] }` envelope (the search endpoints).
 */
function listItems(body: Json): Json[] {
  if (Array.isArray(body)) return body as unknown as Json[];
  return asArray(body.data);
}

/** Page size used for every paginated listing (search caps at 50). */
const PAGE_LIMIT = 50;

/**
 * Fetch every page of a paginated listing. `path` may already contain a query
 * string; `limit`/`page` are appended with the right separator. Stops when a
 * page comes back short.
 */
async function pageAll(g: GlobalArgsT, path: string): Promise<Json[]> {
  const sep = path.includes("?") ? "&" : "?";
  const out: Json[] = [];
  for (let page = 1;; page++) {
    const r = await call(g, {
      method: "GET",
      path: `${path}${sep}limit=${PAGE_LIMIT}&page=${page}`,
    });
    const items = listItems(r.body);
    out.push(...items);
    if (items.length < PAGE_LIMIT) break;
  }
  return out;
}

/** Fetch a repo by `owner/name`, or null when it does not exist. */
async function getRepoOrNull(
  g: GlobalArgsT,
  owner: string,
  name: string,
): Promise<Json | null> {
  const r = await callTolerant(g, {
    method: "GET",
    path: repoPath(owner, name),
  }, [404]);
  return r.status === 404 ? null : r.body;
}

/** The login of the user the token belongs to. */
async function whoami(g: GlobalArgsT): Promise<string> {
  const r = await call(g, { method: "GET", path: "/api/v1/user" });
  return String(r.body.login ?? "");
}

/** Normalise a raw repo object from the API into the {@link RepoInfo} shape. */
function toRepoInfo(r: Json, action: z.infer<typeof Action>): z.infer<
  typeof RepoInfo
> {
  const owner = (r.owner ?? {}) as Json;
  return {
    id: Number(r.id ?? 0),
    fullName: String(r.full_name ?? ""),
    owner: String(owner.login ?? ""),
    name: String(r.name ?? ""),
    private: Boolean(r.private),
    archived: Boolean(r.archived),
    empty: Boolean(r.empty),
    mirror: Boolean(r.mirror),
    fork: Boolean(r.fork),
    defaultBranch: typeof r.default_branch === "string" && r.default_branch
      ? r.default_branch
      : undefined,
    description: typeof r.description === "string" && r.description
      ? r.description
      : undefined,
    htmlUrl: typeof r.html_url === "string" ? r.html_url : undefined,
    sizeKb: r.size != null ? Number(r.size) : undefined,
    action,
    timestamp: nowIso(),
  };
}

/** Normalise a raw org object into the {@link OrgInfo} shape. */
function toOrgInfo(o: Json, action: z.infer<typeof Action>): z.infer<
  typeof OrgInfo
> {
  return {
    id: Number(o.id ?? 0),
    name: String(o.name ?? o.username ?? ""),
    fullName: typeof o.full_name === "string" && o.full_name
      ? o.full_name
      : undefined,
    visibility: String(o.visibility ?? "public"),
    description: typeof o.description === "string" && o.description
      ? o.description
      : undefined,
    action,
    timestamp: nowIso(),
  };
}

/** A Go zero time (and absent values) — "never happened" in the API. */
function isZeroTime(v: unknown): boolean {
  return v == null || String(v).startsWith("0001-01-01");
}

/**
 * Parse a Go duration string (e.g. "8h0m0s", "30m") to seconds, or null when
 * it cannot be parsed.
 */
function goDurationSeconds(s: string): number | null {
  const m = s.trim().match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
  if (!m || (m[1] === undefined && m[2] === undefined && m[3] === undefined)) {
    return null;
  }
  return Number(m[1] ?? 0) * 3600 + Number(m[2] ?? 0) * 60 + Number(m[3] ?? 0);
}

/**
 * Derive a mirror's sync-health record from its repo object. A mirror is
 * stale when its last sync is older than `staleFactor × interval`, or when it
 * has never synced while periodic sync is enabled. With periodic sync
 * disabled (interval "0s") only never-synced counts as stale.
 */
function toMirrorInfo(
  r: Json,
  staleFactor: number,
  action: z.infer<typeof Action>,
): z.infer<typeof MirrorInfo> {
  const owner = (r.owner ?? {}) as Json;
  const interval = String(r.mirror_interval ?? "");
  const intervalSec = goDurationSeconds(interval);
  const neverSynced = isZeroTime(r.mirror_updated);
  const periodic = intervalSec !== null && intervalSec > 0;
  let stale = false;
  if (neverSynced) {
    stale = periodic;
  } else if (periodic) {
    const last = Date.parse(String(r.mirror_updated));
    stale = Number.isFinite(last) &&
      (Date.now() - last) / 1000 > intervalSec * staleFactor;
  }
  return {
    fullName: String(r.full_name ?? ""),
    owner: String(owner.login ?? ""),
    name: String(r.name ?? ""),
    private: Boolean(r.private),
    originalUrl: typeof r.original_url === "string" && r.original_url
      ? r.original_url
      : undefined,
    interval,
    lastSynced: neverSynced ? undefined : String(r.mirror_updated),
    neverSynced,
    stale,
    action,
    timestamp: nowIso(),
  };
}

/** Normalise clone URLs for drift comparison (.git suffix, trailing /, case). */
function normalizeCloneUrl(u: string): string {
  return u.trim().replace(/\.git$/i, "").replace(/\/+$/, "").toLowerCase();
}

/**
 * Build a PATCH body containing only the supplied fields that differ from the
 * current repo object. Returns the body plus whether anything differs.
 */
function buildRepoPatch(
  current: Json,
  desired: {
    private?: boolean;
    description?: string;
    defaultBranch?: string;
    hasWiki?: boolean;
    hasIssues?: boolean;
    hasPullRequests?: boolean;
    hasReleases?: boolean;
  },
): { body: Json; changed: boolean } {
  const body: Json = {};
  const diff = (key: string, want: unknown, cur: unknown) => {
    if (want !== undefined && want !== cur) body[key] = want;
  };
  diff("private", desired.private, Boolean(current.private));
  diff("description", desired.description, String(current.description ?? ""));
  diff(
    "default_branch",
    desired.defaultBranch,
    String(current.default_branch ?? ""),
  );
  diff("has_wiki", desired.hasWiki, Boolean(current.has_wiki));
  diff("has_issues", desired.hasIssues, Boolean(current.has_issues));
  diff(
    "has_pull_requests",
    desired.hasPullRequests,
    Boolean(current.has_pull_requests),
  );
  diff("has_releases", desired.hasReleases, Boolean(current.has_releases));
  return { body, changed: Object.keys(body).length > 0 };
}

// ─────────────────────────── argument schemas ───────────────────────────

const Empty = z.object({});

const RepoTarget = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
});

const RepoListArgs = z.object({
  owner: z.string().optional().describe(
    "Restrict to one org/user's repos. Omit to list every repo the token " +
      "can see (site admin: all repos, incl. private).",
  ),
});

const MirrorStatusArgs = z.object({
  staleFactor: z.coerce.number().default(2).describe(
    "A mirror is stale when its last sync is older than staleFactor × its " +
      "sync interval.",
  ),
});

const OrgEnsureArgs = z.object({
  name: z.string().describe("Org login name (find-or-create key)."),
  description: z.string().optional().describe("Org description to converge."),
  visibility: z.enum(["public", "limited", "private"]).optional().describe(
    "Org visibility to converge (Forgejo default: public).",
  ),
  fullName: z.string().optional().describe("Display name to converge."),
});

/** The repo settings `repo_ensure` converges (all optional — only supplied ones). */
const RepoSettingsShape = {
  private: z.coerce.boolean().optional().describe("Repo visibility."),
  description: z.string().optional().describe("Repo description."),
  defaultBranch: z.string().optional().describe("Default branch name."),
  hasWiki: z.coerce.boolean().optional().describe("Enable the wiki unit."),
  hasIssues: z.coerce.boolean().optional().describe("Enable the issues unit."),
  hasPullRequests: z.coerce.boolean().optional().describe(
    "Enable the pull-requests unit.",
  ),
  hasReleases: z.coerce.boolean().optional().describe(
    "Enable the releases unit.",
  ),
};

const RepoEnsureArgs = z.object({
  owner: z.string().describe(
    "Owning org or user login (an org must already exist — see org_ensure).",
  ),
  name: z.string().describe("Repository name (find-or-create key)."),
  ...RepoSettingsShape,
});

const MirrorEnsureArgs = z.object({
  owner: z.string().describe("Owning org or user login for the mirror."),
  name: z.string().describe("Mirror repository name (find-or-create key)."),
  cloneAddr: z.string().describe(
    "Source clone URL, e.g. https://github.com/<owner>/<repo>.git",
  ),
  service: z.enum(["github", "gitea", "gitlab", "forgejo", "git"]).default(
    "github",
  ).describe("Source service type (drives metadata migration)."),
  authToken: z.string().optional().meta({ sensitive: true }).describe(
    "Source-side token for private sources (write-only; sent once to " +
      "/repos/migrate, never read back). Supply via vault: " +
      "${{ vault.get(<vault>, <item>/<field>) }}",
  ),
  mirrorInterval: z.string().default("8h0m0s").describe(
    'Periodic sync interval as a Go duration (e.g. "8h0m0s"; "0s" disables ' +
      "periodic sync).",
  ),
  lfs: z.coerce.boolean().default(true).describe("Mirror LFS objects too."),
  private: z.coerce.boolean().default(true).describe("Mirror visibility."),
  description: z.string().optional().describe("Mirror repo description."),
});

const MirrorSyncArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Mirror repository name."),
});

// ─────────────────────────── model ───────────────────────────

/**
 * `@thomas/forgejo` model — administer a Forgejo server over its REST API
 * with a scoped token. Mutations are find-or-create or reversible; there are
 * no delete methods; mirror source credentials are write-only. See the file
 * header for the full scope guarantee.
 */
export const model = {
  type: "@thomas/forgejo",
  version: "2026.06.13.1",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify the server is reachable and the token authenticates (GET /api/v1/user).",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        const g = context.globalArgs;
        // `swamp model validate` does not resolve vault expressions, so token
        // is still a literal `${{ … }}` there. Skip; the real check runs at
        // method time when the secret is resolved.
        if (/\$\{\{/.test(String(g.token))) return { pass: true };
        try {
          const r = await rawCall(g, { method: "GET", path: "/api/v1/user" });
          if (r.status >= 400) {
            return {
              pass: false,
              errors: [`GET /api/v1/user -> HTTP ${r.status}: ${errMsg(r)}`],
            };
          }
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Cannot reach Forgejo at ${g.apiUrl}: ${(e as Error).message}`,
            ],
          };
        }
      },
    },
  },
  resources: {
    "server": {
      description: "Server version and health.",
      schema: ServerStatus,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "org": {
      description: "An organization and its visibility/description.",
      schema: OrgInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "repo": {
      description: "A repository and its settings.",
      schema: RepoInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "user": {
      description: "A user account (admin view — never any credential).",
      schema: UserInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "mirror": {
      description: "A pull-mirror's sync health.",
      schema: MirrorInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  methods: {
    // ───────────── read / audit ─────────────
    health: {
      description:
        "Server version (/api/v1/version) + health (/api/healthz). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const v = await call(g, { method: "GET", path: "/api/v1/version" });
        const hz = await callTolerant(g, {
          method: "GET",
          path: "/api/healthz",
        }, [503]);
        const handle = await context.writeResource("server", "status", {
          version: String(v.body.version ?? "unknown"),
          healthy: hz.status < 400,
          action: "observed",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    org_list: {
      description:
        "List organizations (factory; a site-admin token sees all). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Listing organizations");
        const orgs = await pageAll(g, "/api/v1/orgs");
        const handles: DataHandle[] = [];
        for (const o of orgs) {
          handles.push(
            await context.writeResource(
              "org",
              safeName(String(o.name ?? o.username ?? o.id)),
              toOrgInfo(o, "observed"),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    repo_list: {
      description:
        "List repositories — all the token can see, or one owner's (factory). " +
        "Read-only.",
      arguments: RepoListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoListArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Listing repositories", { owner: a.owner ?? "(all)" });
        let repos: Json[];
        if (a.owner === undefined) {
          repos = await pageAll(g, "/api/v1/repos/search");
        } else {
          // An owner is an org or a user — probe the org listing first.
          const org = await callTolerant(g, {
            method: "GET",
            path: `/api/v1/orgs/${enc(a.owner)}`,
          }, [404]);
          repos = org.status === 404
            ? await pageAll(g, `/api/v1/users/${enc(a.owner)}/repos`)
            : await pageAll(g, `/api/v1/orgs/${enc(a.owner)}/repos`);
        }
        const handles: DataHandle[] = [];
        for (const r of repos) {
          handles.push(
            await context.writeResource(
              "repo",
              safeName(String(r.full_name ?? r.id)),
              toRepoInfo(r, "observed"),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    user_list: {
      description:
        "List user accounts via the admin API (factory; requires read:admin " +
        "and a site-admin token). Read-only — never any credential.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Listing users (admin)");
        const users = await pageAll(g, "/api/v1/admin/users");
        const handles: DataHandle[] = [];
        for (const u of users) {
          handles.push(
            await context.writeResource(
              "user",
              safeName(String(u.login ?? u.id)),
              {
                id: Number(u.id ?? 0),
                login: String(u.login ?? ""),
                email: typeof u.email === "string" && u.email
                  ? u.email
                  : undefined,
                fullName: typeof u.full_name === "string" && u.full_name
                  ? u.full_name
                  : undefined,
                isAdmin: Boolean(u.is_admin),
                restricted: typeof u.restricted === "boolean"
                  ? u.restricted
                  : undefined,
                prohibitLogin: typeof u.prohibit_login === "boolean"
                  ? u.prohibit_login
                  : undefined,
                lastLogin: isZeroTime(u.last_login)
                  ? undefined
                  : String(u.last_login),
                created: u.created != null ? String(u.created) : undefined,
                action: "observed",
                timestamp: nowIso(),
              },
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    mirror_status: {
      description:
        "Audit every pull-mirror's sync health: last sync, interval, and a " +
        "stale flag (factory). Read-only.",
      arguments: MirrorStatusArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MirrorStatusArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Auditing mirrors");
        const found = await pageAll(g, "/api/v1/repos/search?mode=mirror");
        const handles: DataHandle[] = [];
        for (const m of found) {
          // The search payload omits mirror fields — fetch the full repo.
          const owner = String(((m.owner ?? {}) as Json).login ?? "");
          const name = String(m.name ?? "");
          const r = await call(g, {
            method: "GET",
            path: repoPath(owner, name),
          });
          handles.push(
            await context.writeResource(
              "mirror",
              safeName(String(r.body.full_name ?? `${owner}/${name}`)),
              toMirrorInfo(r.body, a.staleFactor, "observed"),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },

    // ───────────── idempotent provisioning ─────────────
    org_ensure: {
      description:
        "Find-or-create an organization and converge its description/" +
        "visibility/display name. Idempotent — reports created/updated/" +
        "unchanged.",
      arguments: OrgEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = OrgEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const probe = await callTolerant(g, {
          method: "GET",
          path: `/api/v1/orgs/${enc(a.name)}`,
        }, [404]);
        let org: Json;
        let action: z.infer<typeof Action>;
        if (probe.status === 404) {
          logInfo(context, "Creating org", { name: a.name });
          const r = await call(g, {
            method: "POST",
            path: "/api/v1/orgs",
            body: {
              username: a.name,
              description: a.description,
              visibility: a.visibility,
              full_name: a.fullName,
            },
          });
          org = r.body;
          action = "created";
        } else {
          const cur = probe.body;
          const body: Json = {};
          if (
            a.description !== undefined &&
            a.description !== String(cur.description ?? "")
          ) body.description = a.description;
          if (
            a.visibility !== undefined &&
            a.visibility !== String(cur.visibility ?? "public")
          ) body.visibility = a.visibility;
          if (
            a.fullName !== undefined &&
            a.fullName !== String(cur.full_name ?? "")
          ) body.full_name = a.fullName;
          if (Object.keys(body).length > 0) {
            logInfo(context, "Updating org", { name: a.name, body });
            const r = await call(g, {
              method: "PATCH",
              path: `/api/v1/orgs/${enc(a.name)}`,
              body,
            });
            org = { ...cur, ...r.body };
            action = "updated";
          } else {
            org = cur;
            action = "unchanged";
          }
        }
        const handle = await context.writeResource(
          "org",
          safeName(a.name),
          toOrgInfo({ ...org, name: org.name ?? a.name }, action),
        );
        return { dataHandles: [handle] };
      },
    },
    repo_ensure: {
      description:
        "Find-or-create a repository under an org or user and converge the " +
        "supplied settings (visibility/description/default branch/units). " +
        "Idempotent — reports created/updated/unchanged. Never touches git " +
        "content.",
      arguments: RepoEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        let repo = await getRepoOrNull(g, a.owner, a.name);
        let action: z.infer<typeof Action>;
        if (repo === null) {
          // Create under the right namespace: the token user's own account
          // uses /user/repos, anything else is an org.
          const me = await whoami(g);
          const path = a.owner === me
            ? "/api/v1/user/repos"
            : `/api/v1/orgs/${enc(a.owner)}/repos`;
          logInfo(context, "Creating repo", { repo: `${a.owner}/${a.name}` });
          const r = await call(g, {
            method: "POST",
            path,
            body: {
              name: a.name,
              private: a.private ?? true,
              description: a.description,
              default_branch: a.defaultBranch,
            },
          });
          repo = r.body;
          action = "created";
          // Unit toggles are not part of the create payload — converge them
          // with a follow-up PATCH when any were supplied.
          const { body, changed } = buildRepoPatch(repo, a);
          if (changed) {
            const p = await call(g, {
              method: "PATCH",
              path: repoPath(a.owner, a.name),
              body,
            });
            repo = p.body;
          }
        } else {
          const { body, changed } = buildRepoPatch(repo, a);
          if (changed) {
            logInfo(context, "Updating repo", {
              repo: `${a.owner}/${a.name}`,
              body,
            });
            const r = await call(g, {
              method: "PATCH",
              path: repoPath(a.owner, a.name),
              body,
            });
            repo = r.body;
            action = "updated";
          } else {
            action = "unchanged";
          }
        }
        const handle = await context.writeResource(
          "repo",
          safeName(String(repo.full_name ?? `${a.owner}/${a.name}`)),
          toRepoInfo(repo, action!),
        );
        return { dataHandles: [handle] };
      },
    },
    mirror_ensure: {
      description:
        "Find-or-create a pull-mirror of an external repo (GitHub by default) " +
        "via /repos/migrate, or converge an existing mirror's interval/" +
        "visibility/description. Detects-and-reports a failed migration's " +
        "empty shell repo (never auto-deletes). The source authToken is " +
        "write-only.",
      arguments: MirrorEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MirrorEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const existing = await getRepoOrNull(g, a.owner, a.name);
        let repo: Json;
        let action: z.infer<typeof Action>;
        if (existing === null) {
          logInfo(context, "Creating pull-mirror", {
            repo: `${a.owner}/${a.name}`,
            source: a.cloneAddr,
          });
          const body: Json = {
            clone_addr: a.cloneAddr,
            repo_owner: a.owner,
            repo_name: a.name,
            mirror: true,
            service: a.service,
            mirror_interval: a.mirrorInterval,
            lfs: a.lfs,
            private: a.private,
            description: a.description,
          };
          if (a.authToken !== undefined) body.auth_token = a.authToken;
          const r = await call(g, {
            method: "POST",
            path: "/api/v1/repos/migrate",
            body,
          });
          repo = r.body;
          action = "created";
        } else if (!existing.mirror) {
          if (existing.empty) {
            throw new Error(
              `${a.owner}/${a.name} exists as an EMPTY non-mirror shell — ` +
                "almost certainly the leftover of a failed migration, and it " +
                "blocks re-running this mirror. Delete it manually in the " +
                "Forgejo UI (this model never deletes), then re-run " +
                "mirror_ensure.",
            );
          }
          throw new Error(
            `${a.owner}/${a.name} exists and is NOT a mirror — refusing to ` +
              "touch it. Pick a different name or remove the repo manually.",
          );
        } else {
          // Existing mirror: the source URL is fixed at migration time — a
          // different requested source is unreconcilable drift, not a PATCH.
          const orig = String(existing.original_url ?? "");
          if (
            orig && normalizeCloneUrl(orig) !== normalizeCloneUrl(a.cloneAddr)
          ) {
            throw new Error(
              `${a.owner}/${a.name} already mirrors ${orig}, not ` +
                `${a.cloneAddr}. A mirror's source cannot be changed in ` +
                "place — delete the mirror manually in the UI and re-run, " +
                "or use a different repo name.",
            );
          }
          const body: Json = {};
          const curSec = goDurationSeconds(
            String(existing.mirror_interval ?? ""),
          );
          const wantSec = goDurationSeconds(a.mirrorInterval);
          const intervalDiffers = curSec !== null && wantSec !== null
            ? curSec !== wantSec
            : String(existing.mirror_interval ?? "") !== a.mirrorInterval;
          if (intervalDiffers) body.mirror_interval = a.mirrorInterval;
          if (a.private !== Boolean(existing.private)) body.private = a.private;
          if (
            a.description !== undefined &&
            a.description !== String(existing.description ?? "")
          ) body.description = a.description;
          if (Object.keys(body).length > 0) {
            logInfo(context, "Reconciling mirror", {
              repo: `${a.owner}/${a.name}`,
              body,
            });
            const r = await call(g, {
              method: "PATCH",
              path: repoPath(a.owner, a.name),
              body,
            });
            repo = r.body;
            action = "updated";
          } else {
            repo = existing;
            action = "unchanged";
          }
        }
        const handle = await context.writeResource(
          "mirror",
          safeName(String(repo.full_name ?? `${a.owner}/${a.name}`)),
          toMirrorInfo(repo, 2, action),
        );
        return { dataHandles: [handle] };
      },
    },
    mirror_sync_now: {
      description:
        "Queue an immediate pull-sync of a mirror (POST /mirror-sync). " +
        "Additive — queues work, changes no settings.",
      arguments: MirrorSyncArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = MirrorSyncArgs.parse(rawArgs);
        const g = context.globalArgs;
        const repo = await getRepoOrNull(g, a.owner, a.name);
        if (repo === null) {
          throw new Error(`${a.owner}/${a.name} does not exist`);
        }
        if (!repo.mirror) {
          throw new Error(
            `${a.owner}/${a.name} is not a mirror — nothing to sync`,
          );
        }
        logInfo(context, "Queueing mirror sync", {
          repo: `${a.owner}/${a.name}`,
        });
        await call(g, {
          method: "POST",
          path: `${repoPath(a.owner, a.name)}/mirror-sync`,
        });
        const handle = await context.writeResource(
          "mirror",
          safeName(String(repo.full_name ?? `${a.owner}/${a.name}`)),
          toMirrorInfo(repo, 2, "triggered"),
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── reversible lifecycle ─────────────
    repo_archive: {
      description:
        "Archive a repository (read-only on the server). REVERSIBLE — undo " +
        "with repo_unarchive. Idempotent: already-archived is a no-op.",
      arguments: RepoTarget,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        return await setArchived(rawArgs, context, true);
      },
    },
    repo_unarchive: {
      description:
        "Unarchive a repository. REVERSIBLE — undo with repo_archive. " +
        "Idempotent: already-active is a no-op.",
      arguments: RepoTarget,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        return await setArchived(rawArgs, context, false);
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;

/** Shared implementation of repo_archive / repo_unarchive. */
async function setArchived(
  rawArgs: unknown,
  context: Ctx,
  archived: boolean,
): Promise<{ dataHandles: DataHandle[] }> {
  const a = RepoTarget.parse(rawArgs);
  const g = context.globalArgs;
  const r = await call(g, { method: "GET", path: repoPath(a.owner, a.name) });
  let repo = r.body;
  let action: z.infer<typeof Action> = "unchanged";
  if (Boolean(repo.archived) !== archived) {
    logInfo(context, archived ? "Archiving repo" : "Unarchiving repo", {
      repo: `${a.owner}/${a.name}`,
    });
    const p = await call(g, {
      method: "PATCH",
      path: repoPath(a.owner, a.name),
      body: { archived },
    });
    repo = p.body;
    action = archived ? "archived" : "unarchived";
  }
  const handle = await context.writeResource(
    "repo",
    safeName(String(repo.full_name ?? `${a.owner}/${a.name}`)),
    toRepoInfo(repo, action),
  );
  return { dataHandles: [handle] };
}
