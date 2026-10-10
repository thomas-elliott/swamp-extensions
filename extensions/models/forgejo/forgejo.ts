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
 * PURPOSE (the repeatable kit): provision repositories and organizations, run
 * GitHub pull-mirrors, and drive pull requests, as repeatable idempotent
 * operations instead of one-off UI clicks — find-or-create an org, find-or-create
 * a repo and converge its settings, find-or-create a pull-mirror of a GitHub
 * repo, audit every mirror's sync health in one call, and open / inspect /
 * merge a pull request.
 *
 * SCOPE GUARANTEE: mutations are find-or-create (`*_ensure`) or reversible
 * (`repo_archive` / `repo_unarchive`), with ONE deliberate exception:
 * `pr_merge` writes to the base branch and cannot be undone from here. It is
 * guarded — it refuses a PR that is closed, already merged, draft, or that the
 * server does not report as mergeable, and `force` must be set explicitly to
 * merge while CI is failing.
 *
 * There are NO delete methods — removing a repo, org, or mirror stays a
 * deliberate manual act in the UI. A failed migration's empty shell repo is
 * DETECTED and reported by `mirror_ensure`, never auto-deleted. Mirror source
 * credentials (`authToken` for private GitHub sources) are write-only:
 * supplied via a vault reference, sent once to `/repos/migrate`, and never
 * read back or written to the data model.
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
 *     `mirror_status`, `pr_list`, `pr_get`, `branch_protection_list`,
 *     `webhook_audit`.
 *   - idempotent provisioning: `org_ensure`, `repo_ensure`,
 *     `collaborator_ensure`, `branch_protection_ensure`, `mirror_ensure`,
 *     `mirror_sync_now`, `pr_ensure`, `webhook_retarget`.
 *   - reversible lifecycle: `repo_archive`, `repo_unarchive`.
 *   - irreversible: `pr_merge`.
 *
 * Idempotency: every `*_ensure` probes by name first (404 ⇒ create, else
 * converge the supplied settings in place via PATCH) and reports an `action`
 * of created/updated/unchanged so a re-run is a no-op when nothing changed.
 *
 * WEBHOOKS are read and repointed, never created — which is why the retarget
 * method is not named `*_ensure`. A CI webhook carries a shared secret only
 * the CI server knows, so registering one belongs to that server (Woodpecker:
 * `repo_repair`). What this model adds is the part the CI server cannot:
 * telling you WHERE every hook currently points, so a stale target is visible
 * instead of silently undelivered. `webhook_retarget` therefore writes
 * `config.url` alone and never sends a `secret` key, which would overwrite
 * the stored one.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  apiUrl: z.string().describe(
    "Forgejo base URL, e.g. https://git.example.com (no trailing /api/v1).",
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
  "merged",
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

const CollaboratorInfo = z.object({
  repo: z.string().describe("Repo full name, owner/name."),
  user: z.string().describe("Collaborator login."),
  permission: z.string().describe("none | read | write | admin | owner"),
  action: Action,
  timestamp: z.string(),
});

const BranchProtectionInfo = z.object({
  repo: z.string().describe("Repo full name, owner/name."),
  ruleName: z.string().describe(
    "The rule's branch name or glob (e.g. main, agents/*, *).",
  ),
  enablePush: z.boolean().describe(
    "False = nobody may push directly; the branch is PR-only.",
  ),
  enablePushWhitelist: z.boolean().describe(
    "True = direct push is limited to the whitelists below.",
  ),
  pushWhitelistUsernames: z.array(z.string()).describe(
    "Logins allowed to push directly (only meaningful with the whitelist on).",
  ),
  requiredApprovals: z.number().describe(
    "Approving reviews needed before a PR into this branch may merge.",
  ),
  requireSignedCommits: z.boolean(),
  applyToAdmins: z.boolean().describe(
    "True = repo admins are bound by this rule too. False leaves an admin " +
      "able to push straight through it.",
  ),
  blockOnRejectedReviews: z.boolean(),
  blockOnOutdatedBranch: z.boolean(),
  enableStatusCheck: z.boolean(),
  statusCheckContexts: z.array(z.string()),
  protectedFilePatterns: z.string().describe(
    "Semicolon-separated globs that may not be changed on this branch even " +
      "by a whitelisted pusher — the CI-config guard.",
  ),
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

const PrInfo = z.object({
  index: z.number().describe("PR number within the repo."),
  repo: z.string().describe("Owning repo full name, owner/name."),
  title: z.string(),
  state: z.string().describe("open | closed"),
  draft: z.boolean(),
  merged: z.boolean(),
  mergeable: z.boolean().optional().describe(
    "Server's verdict on whether it can merge cleanly. Only populated on a " +
      "single-PR fetch — absent in listings.",
  ),
  head: z.string().describe("Source branch ref."),
  headSha: z.string().optional().describe("Head commit SHA."),
  base: z.string().describe("Target branch ref."),
  author: z.string().optional().describe("Login of the PR author."),
  ciState: z.string().optional().describe(
    "Combined commit status of the head SHA: success | pending | failure | " +
      "error | none (no statuses reported). Only populated on a single-PR fetch.",
  ),
  htmlUrl: z.string().optional(),
  additions: z.number().optional(),
  deletions: z.number().optional(),
  changedFiles: z.number().optional(),
  comments: z.number().optional(),
  created: z.string().optional(),
  updated: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const WebhookInfo = z.object({
  repo: z.string().describe("Owning repo full name, owner/name."),
  id: z.number().describe("Hook id, unique within the repo."),
  type: z.string().describe("Hook driver: gitea | forgejo | slack | ..."),
  url: z.string().describe(
    "The target the hook POSTs to, with every query-string VALUE redacted. " +
      "This is the field that silently rots — a CI server whose address " +
      "changed leaves every repo pointing at the old one, and a hook that " +
      "cannot be delivered fails quietly. Redacted because the query string " +
      "is credential-bearing: Woodpecker authenticates its hooks with an " +
      "`?access_token=<JWT>` on the URL itself, so the raw URL is a secret.",
  ),
  contentType: z.string().optional().describe("json | form."),
  events: z.array(z.string()).describe("Event names that trigger the hook."),
  active: z.boolean(),
  matchesExpected: z.boolean().optional().describe(
    "Only present when the caller supplied `expectedUrl`: true when this " +
      "hook's URL equals it. False is the drift signal.",
  ),
  created: z.string().optional(),
  updated: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

// ─────────────────────────── HTTP / auth seam ───────────────────────────

/** A JSON-ish bag — structurally the resolved global args or an API body. */
export type Json = Record<string, unknown>;

/** One REST request: method + path (relative to `apiUrl`) + optional JSON body. */
export interface ApiCall {
  /** HTTP verb. */
  method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
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

function hooksPath(owner: string, name: string): string {
  return `${repoPath(owner, name)}/hooks`;
}

/**
 * A webhook URL split into the part that identifies the target and the part
 * that must never be shown.
 *
 * Proven against Woodpecker (2026-09-04): it registers its hooks as
 * `<host>/api/hook?access_token=<JWT>`, so the query string is a CREDENTIAL,
 * not metadata. Two consequences, and both are easy to get wrong:
 *   - `redacted` is the only form safe to store or print.
 *   - `target` (scheme+host+path, no query) is the only sound thing to compare
 *     an expected URL against; comparing raw URLs reports every hook as
 *     drifted because no caller can supply the per-repo token.
 */
function splitHookUrl(raw: string): { target: string; redacted: string } {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    // Not parseable as absolute — nothing safe to split out, so treat the
    // whole string as opaque rather than risk printing a token inside it.
    return { target: raw, redacted: raw };
  }
  const target = `${u.origin}${u.pathname}`;
  const keys = [...u.searchParams.keys()];
  const redacted = keys.length === 0
    ? target
    : `${target}?${keys.map((k) => `${k}=REDACTED`).join("&")}`;
  return { target, redacted };
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

/**
 * Normalise a raw hook object into the {@link WebhookInfo} shape.
 *
 * The `secret` in `config` is deliberately dropped rather than mapped: Forgejo
 * does not return it, and nothing here should ever put a webhook secret into
 * the data model even if a future version starts to.
 */
function toWebhookInfo(
  repoFullName: string,
  h: Json,
  expectedUrl: string | undefined,
  action: z.infer<typeof Action>,
): z.infer<typeof WebhookInfo> {
  const config = (h.config ?? {}) as Json;
  const { target, redacted } = splitHookUrl(String(config.url ?? ""));
  return {
    repo: repoFullName,
    id: Number(h.id ?? 0),
    type: String(h.type ?? ""),
    url: redacted,
    contentType: typeof config.content_type === "string"
      ? config.content_type
      : undefined,
    events: Array.isArray(h.events) ? h.events.map(String) : [],
    active: Boolean(h.active),
    // Compared on the target only — see splitHookUrl. The caller cannot know
    // the per-repo token, so an expectedUrl is always query-free.
    matchesExpected: expectedUrl === undefined
      ? undefined
      : target === splitHookUrl(expectedUrl).target,
    created: typeof h.created_at === "string" ? h.created_at : undefined,
    updated: typeof h.updated_at === "string" ? h.updated_at : undefined,
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

/** Normalise a raw branch-protection object into {@link BranchProtectionInfo}. */
function toProtectionInfo(
  repo: string,
  p: Json,
  action: z.infer<typeof Action>,
): z.infer<typeof BranchProtectionInfo> {
  const strs = (v: unknown): string[] =>
    Array.isArray(v) ? v.map((x) => String(x)) : [];
  return {
    repo,
    ruleName: String(p.rule_name ?? p.branch_name ?? ""),
    enablePush: Boolean(p.enable_push),
    enablePushWhitelist: Boolean(p.enable_push_whitelist),
    pushWhitelistUsernames: strs(p.push_whitelist_usernames),
    requiredApprovals: Number(p.required_approvals ?? 0),
    requireSignedCommits: Boolean(p.require_signed_commits),
    applyToAdmins: Boolean(p.apply_to_admins),
    blockOnRejectedReviews: Boolean(p.block_on_rejected_reviews),
    blockOnOutdatedBranch: Boolean(p.block_on_outdated_branch),
    enableStatusCheck: Boolean(p.enable_status_check),
    statusCheckContexts: strs(p.status_check_contexts),
    protectedFilePatterns: String(p.protected_file_patterns ?? ""),
    action,
    timestamp: nowIso(),
  };
}

/**
 * Build a branch-protection payload from the supplied fields only, mapping
 * camelCase args to the API's snake_case. `include` decides which keys are
 * emitted: a create needs every supplied field, an update only the differing
 * ones.
 */
function protectionBody(
  desired: ProtectionDesired,
  current: Json | null,
): { body: Json; changed: boolean } {
  const body: Json = {};
  const same = (a: unknown, b: unknown): boolean =>
    Array.isArray(a) && Array.isArray(b)
      ? a.length === b.length && a.every((x, i) => String(x) === String(b[i]))
      : a === b;
  const diff = (key: string, want: unknown, cur: unknown) => {
    if (want === undefined) return;
    if (current !== null && same(want, cur)) return;
    body[key] = want;
  };
  // Forgejo only reads enable_push_whitelist inside its enable_push handling
  // (create ANDs the two; edit skips the whitelist when enable_push is absent),
  // so a whitelist without enable_push is dropped and reported as drift on
  // every run. A whitelist request implies enable_push; combined with an
  // explicit enablePush=false it is a contradiction we refuse rather than
  // let Forgejo resolve silently.
  if (desired.enablePushWhitelist && desired.enablePush === false) {
    throw new Error(
      "enablePushWhitelist needs enablePush: Forgejo turns the whitelist " +
        "off on a branch nobody may push to.",
    );
  }
  const enablePush = desired.enablePush ??
    (desired.enablePushWhitelist ? true : undefined);
  diff("enable_push", enablePush, Boolean(current?.enable_push));
  diff(
    "enable_push_whitelist",
    desired.enablePushWhitelist,
    Boolean(current?.enable_push_whitelist),
  );
  if (current !== null && "enable_push_whitelist" in body) {
    body.enable_push = enablePush ?? Boolean(current.enable_push);
  }
  diff(
    "push_whitelist_usernames",
    desired.pushWhitelistUsernames,
    Array.isArray(current?.push_whitelist_usernames)
      ? current.push_whitelist_usernames
      : [],
  );
  diff(
    "required_approvals",
    desired.requiredApprovals,
    Number(current?.required_approvals ?? 0),
  );
  diff(
    "require_signed_commits",
    desired.requireSignedCommits,
    Boolean(current?.require_signed_commits),
  );
  diff(
    "apply_to_admins",
    desired.applyToAdmins,
    Boolean(current?.apply_to_admins),
  );
  diff(
    "block_on_rejected_reviews",
    desired.blockOnRejectedReviews,
    Boolean(current?.block_on_rejected_reviews),
  );
  diff(
    "block_on_outdated_branch",
    desired.blockOnOutdatedBranch,
    Boolean(current?.block_on_outdated_branch),
  );
  diff(
    "enable_status_check",
    desired.enableStatusCheck,
    Boolean(current?.enable_status_check),
  );
  diff(
    "status_check_contexts",
    desired.statusCheckContexts,
    Array.isArray(current?.status_check_contexts)
      ? current.status_check_contexts
      : [],
  );
  diff(
    "protected_file_patterns",
    desired.protectedFilePatterns,
    String(current?.protected_file_patterns ?? ""),
  );
  return { body, changed: Object.keys(body).length > 0 };
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

function prPath(owner: string, name: string, index?: number): string {
  const base = `${repoPath(owner, name)}/pulls`;
  return index === undefined ? base : `${base}/${index}`;
}

/**
 * Normalise a raw pull-request object into the {@link PrInfo} shape.
 * `detail` fields (`mergeable`, `ciState`) are only meaningful on a single-PR
 * fetch; pass them through explicitly rather than trusting a listing payload.
 */
function toPrInfo(
  p: Json,
  action: z.infer<typeof Action>,
  detail?: { mergeable?: boolean; ciState?: string },
): z.infer<typeof PrInfo> {
  const head = (p.head ?? {}) as Json;
  const base = (p.base ?? {}) as Json;
  const headRepo = (head.repo ?? {}) as Json;
  const baseRepo = (base.repo ?? {}) as Json;
  const user = (p.user ?? {}) as Json;
  const str = (v: unknown): string | undefined =>
    typeof v === "string" && v ? v : undefined;
  const num = (v: unknown): number | undefined =>
    v != null ? Number(v) : undefined;
  return {
    index: Number(p.number ?? p.index ?? 0),
    repo: String(baseRepo.full_name ?? headRepo.full_name ?? ""),
    title: String(p.title ?? ""),
    state: String(p.state ?? ""),
    draft: Boolean(p.draft),
    merged: Boolean(p.merged),
    mergeable: detail?.mergeable,
    head: String(head.ref ?? ""),
    headSha: str(head.sha),
    base: String(base.ref ?? ""),
    author: str(user.login),
    ciState: detail?.ciState,
    htmlUrl: str(p.html_url),
    additions: num(p.additions),
    deletions: num(p.deletions),
    changedFiles: num(p.changed_files),
    comments: num(p.comments),
    created: str(p.created_at),
    updated: str(p.updated_at),
    action,
    timestamp: nowIso(),
  };
}

/**
 * Combined CI state of a commit, from its statuses. Returns `"none"` when the
 * commit carries no status at all (which is NOT a pass — a repo with CI
 * disabled and a repo whose pipeline never started look identical here).
 */
async function combinedCiState(
  g: GlobalArgsT,
  owner: string,
  name: string,
  sha: string,
): Promise<string> {
  const r = await callTolerant(g, {
    method: "GET",
    path: `${repoPath(owner, name)}/commits/${enc(sha)}/status`,
  }, [404]);
  if (r.status === 404) return "none";
  const state = String(r.body.state ?? "");
  return state === "" ? "none" : state;
}

/** Fetch one PR by index, or null when it does not exist. */
async function getPrOrNull(
  g: GlobalArgsT,
  owner: string,
  name: string,
  index: number,
): Promise<Json | null> {
  const r = await callTolerant(g, {
    method: "GET",
    path: prPath(owner, name, index),
  }, [404]);
  return r.status === 404 ? null : r.body;
}

/**
 * Strip a cross-repo `owner:branch` qualifier down to the bare branch name, so
 * a requested head matches the `head.ref` the API reports.
 */
function bareRef(ref: string): string {
  const i = ref.indexOf(":");
  return i === -1 ? ref : ref.slice(i + 1);
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

const WebhookAuditArgs = z.object({
  owner: z.string().optional().describe(
    "Restrict to one org/user's repos. Omit to audit every repo the token " +
      "can see.",
  ),
  name: z.string().optional().describe(
    "Audit a single repository. Requires `owner`.",
  ),
  expectedUrl: z.string().optional().describe(
    "The URL every hook is supposed to point at. Supplying it populates " +
      "`matchesExpected`, turning the audit into a drift check.",
  ),
});

const WebhookRetargetArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
  url: z.string().describe("The URL the matched hook(s) should POST to."),
  matchUrl: z.string().optional().describe(
    "Substring identifying WHICH hook to repoint (matched against the " +
      "current URL) — e.g. the old CI host. Omit only when the repo has " +
      "exactly one hook; with several, an ambiguous match is refused rather " +
      "than guessed.",
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

const CollaboratorEnsureArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
  user: z.string().describe("Login of the user to grant access to."),
  // No schema default: it would read as an explicit value and reset an
  // existing collaborator. A new grant gets "write" in the method.
  permission: z.enum(["read", "write", "admin"]).optional().describe(
    'Access level to converge. A new grant defaults to "write"; when ' +
      "omitted, an existing collaborator keeps their level.",
  ),
});

/** The branch-protection settings the ensure method converges. */
const ProtectionSettingsShape = {
  enablePush: z.coerce.boolean().optional().describe(
    "Allow direct pushes. False makes the branch PR-only.",
  ),
  enablePushWhitelist: z.coerce.boolean().optional().describe(
    "Limit direct push to the whitelist (requires enablePush).",
  ),
  pushWhitelistUsernames: z.array(z.string()).optional().describe(
    "Logins allowed to push directly. Converged as an exact set.",
  ),
  requiredApprovals: z.coerce.number().int().optional().describe(
    "Approving reviews required before merge.",
  ),
  requireSignedCommits: z.coerce.boolean().optional(),
  applyToAdmins: z.coerce.boolean().optional().describe(
    "Bind repo admins to the rule too. Without this an admin bypasses it.",
  ),
  blockOnRejectedReviews: z.coerce.boolean().optional(),
  blockOnOutdatedBranch: z.coerce.boolean().optional(),
  enableStatusCheck: z.coerce.boolean().optional(),
  statusCheckContexts: z.array(z.string()).optional(),
  protectedFilePatterns: z.string().optional().describe(
    "Semicolon-separated globs that may not be changed on this branch, e.g. " +
      '".woodpecker.yml;.woodpecker/**". Applies even to whitelisted pushers.',
  ),
};

type ProtectionDesired = {
  enablePush?: boolean;
  enablePushWhitelist?: boolean;
  pushWhitelistUsernames?: string[];
  requiredApprovals?: number;
  requireSignedCommits?: boolean;
  applyToAdmins?: boolean;
  blockOnRejectedReviews?: boolean;
  blockOnOutdatedBranch?: boolean;
  enableStatusCheck?: boolean;
  statusCheckContexts?: string[];
  protectedFilePatterns?: string;
};

const BranchProtectionEnsureArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
  rule: z.string().describe(
    "Branch name or glob the rule applies to (find-or-create key), e.g. " +
      "main, agents/*, or * for everything.",
  ),
  ...ProtectionSettingsShape,
});

const BranchProtectionListArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
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
  // No schema defaults: they would read as explicit values and reset an
  // existing mirror. The create branch applies them.
  mirrorInterval: z.string().optional().describe(
    'Periodic sync interval as a Go duration (e.g. "8h0m0s"; "0s" disables ' +
      'periodic sync). Defaults to "8h0m0s" on create; when omitted, an ' +
      "existing mirror keeps its interval.",
  ),
  lfs: z.coerce.boolean().default(true).describe("Mirror LFS objects too."),
  private: z.coerce.boolean().optional().describe(
    "Mirror visibility. Defaults to private on create; when omitted, an " +
      "existing mirror keeps its visibility.",
  ),
  description: z.string().optional().describe("Mirror repo description."),
});

const MirrorSyncArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Mirror repository name."),
});

const PrListArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
  state: z.enum(["open", "closed", "all"]).default("open").describe(
    "Which pull requests to list.",
  ),
});

const PrGetArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
  index: z.coerce.number().int().describe("PR number within the repo."),
});

const PrEnsureArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
  head: z.string().describe(
    "Source branch. Use owner:branch for a cross-repo (fork) PR.",
  ),
  base: z.string().describe("Target branch, e.g. main."),
  title: z.string().describe("PR title (converged on an existing open PR)."),
  body: z.string().optional().describe(
    "PR description (converged on an existing open PR).",
  ),
});

const PrMergeArgs = z.object({
  owner: z.string().describe("Owning org or user login."),
  name: z.string().describe("Repository name."),
  index: z.coerce.number().int().describe("PR number within the repo."),
  strategy: z.enum(["merge", "rebase", "rebase-merge", "squash"]).default(
    "squash",
  ).describe("Merge strategy (Forgejo's `Do`)."),
  title: z.string().optional().describe("Merge commit title override."),
  message: z.string().optional().describe("Merge commit message override."),
  deleteBranch: z.coerce.boolean().default(false).describe(
    "Delete the head branch after a successful merge.",
  ),
  force: z.coerce.boolean().default(false).describe(
    "Merge even when the head commit's combined CI state is failure/error/" +
      "pending. Without this, a non-green PR is refused.",
  ),
});

// ─────────────────────────── model ───────────────────────────

/**
 * `@thomas/forgejo` model — administer a Forgejo server over its REST API
 * with a scoped token. Mutations are find-or-create or reversible apart from
 * the guarded `pr_merge`; there are no delete methods; mirror source
 * credentials are write-only. See the file header for the full scope guarantee.
 */
export const model = {
  type: "@thomas/forgejo",
  version: "2026.09.04.2",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify the server is reachable and the token authenticates " +
        "(GET /api/v1/user). A scope-rejection 403 passes: the token was " +
        "accepted, it merely lacks read:user.",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        // Checks get globalArgs without the schema's defaults; parse to apply them.
        const g = GlobalArgs.parse(context.globalArgs);
        // Older swamp left the token as an unresolved `${{ … }}` here. Skip then;
        // the method run checks it.
        if (/\$\{\{/.test(String(g.token))) return { pass: true };
        try {
          const r = await rawCall(g, { method: "GET", path: "/api/v1/user" });
          if (r.status === 403 && /scope/i.test(errMsg(r))) {
            return { pass: true };
          }
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
    "collaborator": {
      description: "A user's access level on a repository.",
      schema: CollaboratorInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "branch_protection": {
      description: "A branch-protection rule and the constraints it enforces.",
      schema: BranchProtectionInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "mirror": {
      description: "A pull-mirror's sync health.",
      schema: MirrorInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "pull_request": {
      description: "A pull request: state, mergeability, and head CI status.",
      schema: PrInfo,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "webhook": {
      description:
        "A repository webhook: where it posts, what triggers it, whether it " +
        "matches the expected target. Never the secret.",
      schema: WebhookInfo,
      lifetime: "infinite",
      garbageCollection: 50,
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
          }, [403, 404]);
          if (org.status < 400) {
            repos = await pageAll(g, `/api/v1/orgs/${enc(a.owner)}/repos`);
          } else {
            const user = await callTolerant(g, {
              method: "GET",
              path: `/api/v1/users/${enc(a.owner)}/repos?limit=1&page=1`,
            }, [403, 404]);
            if (user.status === 403) {
              throw new Error(
                `Cannot list repositories for owner "${a.owner}": this token ` +
                  `holds neither read:organization nor read:user, and Forgejo ` +
                  `requires one of them to resolve an owner. Drop --owner to ` +
                  `list via /repos/search, which read:repository covers.`,
              );
            }
            if (user.status === 404) {
              throw new Error(
                `No user "${a.owner}" on ${g.apiUrl}` +
                  (org.status === 403
                    ? `, and the org probe was refused for lack of ` +
                      `read:organization — an organization of that name could ` +
                      `not be ruled out.`
                    : `, and no organization of that name either.`),
              );
            }
            repos = await pageAll(g, `/api/v1/users/${enc(a.owner)}/repos`);
          }
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

    webhook_audit: {
      description:
        "List every repository's webhooks and where they point (factory). " +
        "Supply expectedUrl to flag drift. Read-only; never reads the secret.",
      arguments: WebhookAuditArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = WebhookAuditArgs.parse(rawArgs);
        const g = context.globalArgs;
        if (a.name && !a.owner) {
          throw new Error("`name` requires `owner` — pass both or neither.");
        }

        // One repo, one owner's repos, or everything the token can see.
        let repos: Json[];
        if (a.name && a.owner) {
          const r = await getRepoOrNull(g, a.owner, a.name);
          if (!r) throw new Error(`No such repo: ${a.owner}/${a.name}`);
          repos = [r];
        } else {
          repos = await pageAll(
            g,
            a.owner
              ? `/api/v1/repos/search?q=&uid=0&owner=${enc(a.owner)}`
              : "/api/v1/repos/search?q=",
          );
          if (a.owner) {
            // The search `owner` filter is a uid in some versions and ignored
            // in others, so filter client-side too rather than trust it.
            repos = repos.filter((r) =>
              String(((r.owner ?? {}) as Json).login ?? "") === a.owner
            );
          }
        }

        logInfo(context, "Auditing webhooks", { repos: repos.length });
        const handles: DataHandle[] = [];
        for (const r of repos) {
          const owner = String(((r.owner ?? {}) as Json).login ?? "");
          const name = String(r.name ?? "");
          const full = String(r.full_name ?? `${owner}/${name}`);
          // A token without admin on a repo cannot list its hooks; that is a
          // gap in the audit, not a failure of it — skip, having said so.
          const res = await callTolerant(g, {
            method: "GET",
            path: hooksPath(owner, name),
          }, [403, 404]);
          if (res.status >= 400) {
            logInfo(context, "Skipping repo: hooks not readable", {
              repo: full,
              status: res.status,
            });
            continue;
          }
          for (const h of listItems(res.body)) {
            const info = toWebhookInfo(full, h, a.expectedUrl, "observed");
            handles.push(
              await context.writeResource(
                "webhook",
                safeName(`${full}:${info.id}`),
                info,
              ),
            );
          }
        }
        return { dataHandles: handles };
      },
    },

    // ───────────── idempotent provisioning ─────────────
    webhook_retarget: {
      description:
        "Repoint an existing webhook at a new scheme/host/path. CONVERGE-ONLY: " +
        "it never creates a hook, never sends or clears the stored secret, and " +
        "carries the existing query string over verbatim (a CI hook's " +
        "?access_token= is what authenticates it). Idempotent — " +
        "already-correct is a no-op.",
      arguments: WebhookRetargetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = WebhookRetargetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const full = `${a.owner}/${a.name}`;

        const listed = await call(g, {
          method: "GET",
          path: hooksPath(a.owner, a.name),
        });
        const hooks = listItems(listed.body);
        if (hooks.length === 0) {
          throw new Error(
            `${full} has no webhooks to retarget. This method deliberately ` +
              `does not create one: a CI hook needs a shared secret that only ` +
              `the CI server knows, so let the CI server register it (for ` +
              `Woodpecker: repo_repair) instead of hand-building one here.`,
          );
        }

        // Match on the TARGET, never the raw URL — the query string holds a
        // per-repo token, so matching it would be both useless and unsafe.
        const hookUrl = (h: Json) =>
          String(((h.config ?? {}) as Json).url ?? "");
        const candidates = a.matchUrl
          ? hooks.filter((h) =>
            splitHookUrl(hookUrl(h)).target.includes(a.matchUrl!)
          )
          : hooks;
        const listRedacted = (hs: Json[]) =>
          hs.map((h) => `#${h.id} ${splitHookUrl(hookUrl(h)).redacted}`)
            .join(", ");
        if (candidates.length === 0) {
          throw new Error(
            `${full}: no webhook whose URL contains ${a.matchUrl}. ` +
              `Existing: ${listRedacted(hooks)}`,
          );
        }
        if (candidates.length > 1) {
          throw new Error(
            `${full}: ${candidates.length} webhooks match — refusing to ` +
              `guess. Narrow it with matchUrl. Matched: ${
                listRedacted(candidates)
              }`,
          );
        }

        const hook = candidates[0];
        const current = hookUrl(hook);
        const currentTarget = splitHookUrl(current).target;
        const wantTarget = splitHookUrl(a.url).target;
        let action: z.infer<typeof Action> = "unchanged";
        let updated = hook;
        if (currentTarget !== wantTarget) {
          // CARRY THE QUERY STRING OVER VERBATIM. Woodpecker authenticates its
          // hooks with an `?access_token=<JWT>` on the URL, so writing the
          // caller's query-free URL would silently de-authenticate the hook —
          // it would still fire, and every delivery would be rejected.
          const query = current.includes("?")
            ? current.slice(current.indexOf("?"))
            : "";
          logInfo(context, "Retargeting webhook", {
            repo: full,
            hook: Number(hook.id),
            from: currentTarget,
            to: wantTarget,
            carriedQuery: query !== "",
          });
          // `config` is a partial map: Forgejo applies only the keys present,
          // so omitting `secret` leaves the stored one intact. Sending the
          // whole config back would risk clearing it. The other three fields
          // are the opposite: Forgejo's editHook overwrites events (push only
          // when absent), branch_filter and authorization_header on every
          // PATCH, so the hook's own values go back with the new URL.
          const body: Json = { config: { url: `${wantTarget}${query}` } };
          if (Array.isArray(hook.events)) body.events = hook.events;
          if (typeof hook.branch_filter === "string") {
            body.branch_filter = hook.branch_filter;
          }
          if (typeof hook.authorization_header === "string") {
            body.authorization_header = hook.authorization_header;
          }
          const r = await call(g, {
            method: "PATCH",
            path: `${hooksPath(a.owner, a.name)}/${Number(hook.id)}`,
            body,
          });
          updated = r.body;
          action = "updated";
        }

        return {
          dataHandles: [
            await context.writeResource(
              "webhook",
              safeName(`${full}:${Number(hook.id)}`),
              toWebhookInfo(full, updated, a.url, action),
            ),
          ],
        };
      },
    },

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
    collaborator_ensure: {
      description:
        "Grant a user access to a repository at a given permission level, or " +
        "converge an existing grant. Converges the collaboration row: a user " +
        "who is not a collaborator is added even when they can already read " +
        "the repo (public repos grant everyone read). Idempotent — reports " +
        "created/updated/unchanged. Never removes a collaborator.",
      arguments: CollaboratorEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = CollaboratorEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const full = `${a.owner}/${a.name}`;
        const collabPath = `${repoPath(a.owner, a.name)}/collaborators/${
          enc(a.user)
        }`;
        // The permission probe reports the EFFECTIVE access mode, so a
        // non-collaborator reads as "read" on a public repo and the owner as
        // "owner", which no PUT can produce and must never be downgraded.
        const probe = await callTolerant(g, {
          method: "GET",
          path: `${collabPath}/permission`,
        }, [404]);
        const effective = probe.status === 404
          ? "none"
          : String(probe.body.permission ?? "none");
        if (effective === "owner") {
          throw new Error(
            `${a.user} owns ${full} — a collaborator grant cannot apply to ` +
              "the repo owner.",
          );
        }
        // Membership is a separate question: 204 for a collaborator, 404 for
        // anyone else. Only a collaborator has a row to leave alone.
        const membership = await callTolerant(g, {
          method: "GET",
          path: collabPath,
        }, [404]);
        const isCollaborator = membership.status < 300;
        const current = isCollaborator ? effective : "none";
        const want = a.permission ?? (isCollaborator ? current : "write");
        let action: z.infer<typeof Action>;
        if (isCollaborator && current === want) {
          action = "unchanged";
        } else {
          logInfo(context, "Setting collaborator permission", {
            repo: full,
            user: a.user,
            from: current,
            to: want,
          });
          await call(g, {
            method: "PUT",
            path: `${repoPath(a.owner, a.name)}/collaborators/${enc(a.user)}`,
            body: { permission: want },
          });
          action = isCollaborator ? "updated" : "created";
        }
        const handle = await context.writeResource(
          "collaborator",
          safeName(`${full}:${a.user}`),
          {
            repo: full,
            user: a.user,
            permission: want,
            action,
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    branch_protection_ensure: {
      description:
        "Find-or-create a branch-protection rule for a branch or glob and " +
        "converge the supplied constraints. Idempotent — reports created/" +
        "updated/unchanged. Never deletes a rule.",
      arguments: BranchProtectionEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BranchProtectionEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const full = `${a.owner}/${a.name}`;
        const base = `${repoPath(a.owner, a.name)}/branch_protections`;
        const probe = await callTolerant(g, {
          method: "GET",
          path: `${base}/${enc(a.rule)}`,
        }, [404]);
        let rule: Json;
        let action: z.infer<typeof Action>;
        if (probe.status === 404) {
          const { body } = protectionBody(a, null);
          logInfo(context, "Creating branch protection", {
            repo: full,
            rule: a.rule,
          });
          const r = await call(g, {
            method: "POST",
            path: base,
            body: { ...body, rule_name: a.rule },
          });
          rule = r.body;
          action = "created";
        } else {
          const { body, changed } = protectionBody(a, probe.body);
          if (changed) {
            logInfo(context, "Updating branch protection", {
              repo: full,
              rule: a.rule,
              body,
            });
            const r = await call(g, {
              method: "PATCH",
              path: `${base}/${enc(a.rule)}`,
              body,
            });
            rule = r.body;
            action = "updated";
          } else {
            rule = probe.body;
            action = "unchanged";
          }
        }
        const handle = await context.writeResource(
          "branch_protection",
          safeName(`${full}:${a.rule}`),
          toProtectionInfo(full, rule, action),
        );
        return { dataHandles: [handle] };
      },
    },
    branch_protection_list: {
      description:
        "List every branch-protection rule on a repository — the audit view " +
        "of what a branch actually enforces.",
      arguments: BranchProtectionListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BranchProtectionListArgs.parse(rawArgs);
        const g = context.globalArgs;
        const full = `${a.owner}/${a.name}`;
        const r = await call(g, {
          method: "GET",
          path: `${repoPath(a.owner, a.name)}/branch_protections`,
        });
        const handles: DataHandle[] = [];
        for (const rule of listItems(r.body)) {
          const info = toProtectionInfo(full, rule, "observed");
          handles.push(
            await context.writeResource(
              "branch_protection",
              safeName(`${full}:${info.ruleName}`),
              info,
            ),
          );
        }
        logInfo(context, "Listed branch protections", {
          repo: full,
          count: handles.length,
        });
        return { dataHandles: handles };
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
            mirror_interval: a.mirrorInterval ?? "8h0m0s",
            lfs: a.lfs,
            private: a.private ?? true,
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
          // Converge only the settings the caller passed.
          const body: Json = {};
          if (a.mirrorInterval !== undefined) {
            const curSec = goDurationSeconds(
              String(existing.mirror_interval ?? ""),
            );
            const wantSec = goDurationSeconds(a.mirrorInterval);
            const intervalDiffers = curSec !== null && wantSec !== null
              ? curSec !== wantSec
              : String(existing.mirror_interval ?? "") !== a.mirrorInterval;
            if (intervalDiffers) body.mirror_interval = a.mirrorInterval;
          }
          if (
            a.private !== undefined && a.private !== Boolean(existing.private)
          ) body.private = a.private;
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

    // ───────────── pull requests ─────────────
    pr_list: {
      description:
        "List a repository's pull requests with head/base, author and draft " +
        "state (factory). Read-only. Mergeability and CI state are NOT in a " +
        "listing — use pr_get for those.",
      arguments: PrListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PrListArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Listing pull requests", {
          repo: `${a.owner}/${a.name}`,
          state: a.state,
        });
        const prs = await pageAll(
          g,
          `${prPath(a.owner, a.name)}?state=${a.state}`,
        );
        const handles: DataHandle[] = [];
        for (const p of prs) {
          handles.push(
            await context.writeResource(
              "pull_request",
              safeName(`${a.owner}/${a.name}#${p.number ?? p.id}`),
              toPrInfo(p, "observed"),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    pr_get: {
      description:
        "Get one pull request including the server's mergeable verdict and " +
        "the combined CI state of its head commit. Read-only.",
      arguments: PrGetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PrGetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const pr = await getPrOrNull(g, a.owner, a.name, a.index);
        if (pr === null) {
          throw new Error(`${a.owner}/${a.name}#${a.index} does not exist`);
        }
        const head = (pr.head ?? {}) as Json;
        const sha = String(head.sha ?? "");
        const ciState = sha
          ? await combinedCiState(g, a.owner, a.name, sha)
          : "none";
        const handle = await context.writeResource(
          "pull_request",
          safeName(`${a.owner}/${a.name}#${a.index}`),
          toPrInfo(pr, "observed", {
            mergeable: typeof pr.mergeable === "boolean"
              ? pr.mergeable
              : undefined,
            ciState,
          }),
        );
        return { dataHandles: [handle] };
      },
    },
    pr_ensure: {
      description:
        "Find-or-create a pull request for a head→base branch pair, and " +
        "converge its title/body. Idempotent — a re-run against an existing " +
        "open PR reports updated/unchanged instead of failing on a duplicate.",
      arguments: PrEnsureArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PrEnsureArgs.parse(rawArgs);
        const g = context.globalArgs;
        const wantHead = bareRef(a.head);
        const open = await pageAll(
          g,
          `${prPath(a.owner, a.name)}?state=open`,
        );
        const existing = open.find((p) => {
          const h = (p.head ?? {}) as Json;
          const b = (p.base ?? {}) as Json;
          return String(h.ref ?? "") === wantHead &&
            String(b.ref ?? "") === a.base;
        });
        let pr: Json;
        let action: z.infer<typeof Action>;
        if (existing === undefined) {
          logInfo(context, "Opening pull request", {
            repo: `${a.owner}/${a.name}`,
            head: a.head,
            base: a.base,
          });
          const r = await call(g, {
            method: "POST",
            path: prPath(a.owner, a.name),
            body: { head: a.head, base: a.base, title: a.title, body: a.body },
          });
          pr = r.body;
          action = "created";
        } else {
          const body: Json = {};
          if (a.title !== String(existing.title ?? "")) body.title = a.title;
          if (a.body !== undefined && a.body !== String(existing.body ?? "")) {
            body.body = a.body;
          }
          if (Object.keys(body).length > 0) {
            const index = Number(existing.number ?? 0);
            logInfo(context, "Updating pull request", {
              repo: `${a.owner}/${a.name}`,
              index,
            });
            const r = await call(g, {
              method: "PATCH",
              path: prPath(a.owner, a.name, index),
              body,
            });
            pr = r.body;
            action = "updated";
          } else {
            pr = existing;
            action = "unchanged";
          }
        }
        const handle = await context.writeResource(
          "pull_request",
          safeName(`${a.owner}/${a.name}#${pr.number ?? 0}`),
          toPrInfo(pr, action),
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── irreversible ─────────────
    pr_merge: {
      description:
        "Merge a pull request. NOT REVERSIBLE — this writes to the base " +
        "branch. Refuses a PR that is closed, already merged, draft, or not " +
        "mergeable; refuses a non-green head unless force=true. Verifies the " +
        "PR before acting.",
      arguments: PrMergeArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PrMergeArgs.parse(rawArgs);
        const g = context.globalArgs;
        const ref = `${a.owner}/${a.name}#${a.index}`;
        const pr = await getPrOrNull(g, a.owner, a.name, a.index);
        if (pr === null) throw new Error(`${ref} does not exist`);
        if (pr.merged) {
          throw new Error(`${ref} is already merged — nothing to do`);
        }
        if (String(pr.state ?? "") !== "open") {
          throw new Error(
            `${ref} is ${String(pr.state ?? "?")}, not open — reopen it first`,
          );
        }
        if (pr.draft) {
          throw new Error(`${ref} is a draft — mark it ready before merging`);
        }
        if (pr.mergeable === false) {
          throw new Error(
            `${ref} is not mergeable (conflicts, or a branch protection is ` +
              "unsatisfied). Resolve it on the branch — this model will not " +
              "force past it.",
          );
        }
        const head = (pr.head ?? {}) as Json;
        const sha = String(head.sha ?? "");
        const ciState = sha
          ? await combinedCiState(g, a.owner, a.name, sha)
          : "none";
        if (ciState !== "success" && !a.force) {
          throw new Error(
            `${ref} head ${sha.slice(0, 8)} has CI state "${ciState}", not ` +
              'success. Re-run with force=true to merge anyway. ("none" means ' +
              "the commit carries no status at all — CI may never have run.)",
          );
        }
        logInfo(context, "Merging pull request", {
          repo: `${a.owner}/${a.name}`,
          index: a.index,
          strategy: a.strategy,
          ciState,
        });
        await call(g, {
          method: "POST",
          path: `${prPath(a.owner, a.name, a.index)}/merge`,
          body: {
            Do: a.strategy,
            MergeTitleField: a.title,
            MergeMessageField: a.message,
            delete_branch_after_merge: a.deleteBranch,
          },
        });
        // Re-fetch: the merge response carries no body, and the merged PR's
        // recorded state is the point of the data output.
        const after = await getPrOrNull(g, a.owner, a.name, a.index) ?? pr;
        const handle = await context.writeResource(
          "pull_request",
          safeName(ref),
          toPrInfo(after, "merged", { ciState }),
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
