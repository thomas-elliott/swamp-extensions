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
 * `@thomas/woodpecker` — careful administration of a Woodpecker CI server over
 * its REST API, authenticated with a personal access token.
 *
 * PURPOSE (the repeatable kit): onboarding and configuring repositories on a
 * self-hosted Woodpecker instance without clicking through the UI per repo —
 * enable a repo, mark it trusted, set its timeout, and promote shared CI
 * credentials to org-level secrets, all idempotently from swamp.
 *
 * SCOPE GUARANTEE: this holds an admin PAT, so its surface is deliberately
 * narrow and its mutations are additive or reversible. It enables/configures
 * repos and manages secrets; the only "off switches" are the reversible
 * `repo_disable` (re-enable to undo) and secret deletes (re-create to undo).
 * Secret VALUES are write-only — supplied via a vault reference, sent once, and
 * NEVER read back or emitted (Woodpecker's API does not return them either).
 *
 * Auth: a Woodpecker personal access token (Settings → CLI and API). Per request
 * it is sent as `Authorization: Bearer <token>`. No token is minted or stored by
 * the model beyond the global argument (resolved from a vault).
 *
 * Method sections (by prefix):
 *   - read/audit: `repo_list`, `repo_get`, `repo_available`, `org_get`,
 *     `org_secret_list`, `repo_secret_list`, `pipeline_list`, `pipeline_last`.
 *   - observability: `pipeline_steps`, `pipeline_logs`, `pipeline_wait`,
 *     `status_all` (fleet dashboard).
 *   - provision: `repo_enable`, `repo_update`, `repo_repair`,
 *     `org_secret_set`, `repo_secret_set`.
 *   - reversible lifecycle: `repo_disable`, `org_secret_delete`,
 *     `repo_secret_delete`, `cron_delete`.
 *   - run control: `pipeline_trigger`, `pipeline_restart`, `pipeline_cancel`,
 *     `pipeline_approve`, `pipeline_decline`.
 *   - infra/health: `agent_list`, `queue_info`, `server_info`.
 *   - scheduled pipelines: `cron_list`, `cron_set`, `cron_delete`.
 *
 * Idempotency: `repo_enable` finds-or-activates by `owner/name` and converges
 * the supplied settings in place; the `*_secret_set` methods create-or-update by
 * name. Each reports an `action` of created/updated/unchanged/… so a re-run is a
 * no-op when nothing changed.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  apiUrl: z.string().describe(
    "Woodpecker server base URL, e.g. https://tylo.ghost-eagle.ts.net:8443 " +
      "(no trailing /api).",
  ),
  token: z.string().meta({ sensitive: true }).describe(
    "Woodpecker personal access token (Settings → CLI and API). Supply via " +
      "vault: ${{ vault.get(<vault>, woodpecker/api_token) }}",
  ),
  httpTimeoutMs: z.coerce.number().int().default(30000).describe(
    "Per-request timeout (ms) for API calls.",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type", so
// it must not leak onto the public API (the exported `CallerFn` seam uses the
// loose `Json` instead — see below).
type GlobalArgsT = z.infer<typeof GlobalArgs>;

/** The set of outcomes a method reports in its `action` field. */
const Action = z.enum([
  "created",
  "unchanged",
  "updated",
  "enabled",
  "disabled",
  "repaired",
  "deleted",
  "triggered",
  "restarted",
  "cancelled",
  "approved",
  "declined",
  "observed",
]);

// ─────────────────────────── resource schemas ───────────────────────────

/** The three independently-grantable trust capabilities on a repo (v3). */
const TrustedSchema = z.object({
  network: z.boolean(),
  volumes: z.boolean(),
  security: z.boolean(),
});

const RepoInfo = z.object({
  id: z.number(),
  fullName: z.string(),
  owner: z.string(),
  name: z.string(),
  forgeRemoteId: z.string().optional(),
  active: z.boolean(),
  trusted: TrustedSchema,
  timeout: z.number().describe("Pipeline timeout in minutes."),
  visibility: z.string().describe("public | private | internal"),
  requireApproval: z.string().optional().describe(
    "none | forks | pull_requests | all",
  ),
  defaultBranch: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const AvailableRepo = z.object({
  fullName: z.string(),
  forgeRemoteId: z.string().optional(),
  active: z.boolean().describe("Already enabled on this Woodpecker server."),
  action: Action,
  timestamp: z.string(),
});

const OrgInfo = z.object({
  id: z.number(),
  name: z.string(),
  isUser: z.boolean(),
  action: Action,
  timestamp: z.string(),
});

const SecretInfo = z.object({
  scope: z.string().describe("org | repo"),
  owner: z.string().describe(
    "org name or repo full name the secret belongs to",
  ),
  id: z.number().optional(),
  name: z.string(),
  events: z.array(z.string()),
  images: z.array(z.string()),
  // The value is NEVER stored or returned — Woodpecker's API does not expose it.
  action: Action,
  timestamp: z.string(),
});

const PipelineInfo = z.object({
  repo: z.string(),
  number: z.number(),
  status: z.string(),
  event: z.string().optional(),
  branch: z.string().optional(),
  commit: z.string().optional(),
  message: z.string().optional(),
  createdAt: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const PipelineStepInfo = z.object({
  repo: z.string(),
  pipelineNumber: z.number(),
  workflow: z.string().describe("Parent workflow name."),
  name: z.string().describe("Step name."),
  state: z.string().describe(
    "pending | running | success | failure | skipped | killed | …",
  ),
  exitCode: z.number().optional(),
  error: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const PipelineLogInfo = z.object({
  repo: z.string(),
  pipelineNumber: z.number(),
  step: z.string().describe("Step name."),
  stepId: z.number(),
  lineCount: z.number().describe("Number of log lines returned."),
  truncated: z.boolean().describe(
    "True if older lines were dropped (tailLines).",
  ),
  text: z.string().describe("Decoded log text (the last `tailLines` lines)."),
  action: Action,
  timestamp: z.string(),
});

const RepoStatusInfo = z.object({
  repo: z.string(),
  repoId: z.number(),
  status: z.string().describe(
    "The repo's latest pipeline status, or 'none' if it never ran.",
  ),
  number: z.number().optional(),
  event: z.string().optional(),
  branch: z.string().optional(),
  finishedAt: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const AgentInfo = z.object({
  id: z.number(),
  name: z.string().optional(),
  online: z.boolean().optional().describe(
    "Derived: contacted within the last 2 minutes.",
  ),
  lastContact: z.string().optional(),
  version: z.string().optional(),
  capacity: z.number().optional(),
  noSchedule: z.boolean().optional(),
  action: Action,
  timestamp: z.string(),
});

const QueueStats = z.object({
  paused: z.boolean().optional(),
  pending: z.number(),
  waitingOnDeps: z.number(),
  running: z.number(),
  completed: z.number(),
  workerCount: z.number(),
  action: Action,
  timestamp: z.string(),
});

const ServerStatus = z.object({
  version: z.string(),
  source: z.string().optional(),
  healthy: z.boolean(),
  action: Action,
  timestamp: z.string(),
});

const CronInfo = z.object({
  repo: z.string(),
  id: z.number().optional(),
  name: z.string(),
  schedule: z.string().describe("Cron expression or @hourly/@daily/… macro."),
  branch: z.string().optional(),
  nextExec: z.string().optional(),
  createdAt: z.string().optional(),
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
  /** Path relative to `apiUrl`, e.g. `/api/repos`. */
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
 * slow type onto the public API). The real implementation re-narrows. It returns
 * the result for ALL HTTP statuses (it only throws on a network/transport
 * error); status-based control flow lives in {@link call}/{@link callTolerant}.
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
    authorization: `Bearer ${g.token}`,
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
      `Woodpecker API ${c.method} ${c.path} -> HTTP ${r.status}: ${errMsg(r)}`,
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
      `Woodpecker API ${c.method} ${c.path} -> HTTP ${r.status}: ${errMsg(r)}`,
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

function looksLikeId(s: string): boolean {
  return /^\d+$/.test(s.trim());
}

/**
 * Make a string safe as a swamp data instance name — swamp rejects names
 * containing `/`, `\`, `..`, or null bytes (path-traversal guard), but a repo
 * full name like `owner/name` naturally contains a slash.
 */
function safeName(s: string): string {
  return s.replace(/[\\/]/g, ":").replace(/\.\./g, "_").replace(/\0/g, "");
}

/** Normalise a raw repo object from the API into the {@link RepoInfo} shape. */
function toRepoInfo(r: Json, action: z.infer<typeof Action>): z.infer<
  typeof RepoInfo
> {
  const t = (r.trusted ?? {}) as Json;
  return {
    id: Number(r.id ?? 0),
    fullName: String(r.full_name ?? ""),
    owner: String(r.owner ?? ""),
    name: String(r.name ?? ""),
    forgeRemoteId: r.forge_remote_id != null
      ? String(r.forge_remote_id)
      : undefined,
    active: Boolean(r.active),
    trusted: {
      network: Boolean(t.network),
      volumes: Boolean(t.volumes),
      security: Boolean(t.security),
    },
    timeout: Number(r.timeout ?? 0),
    visibility: String(r.visibility ?? ""),
    requireApproval: typeof r.require_approval === "string"
      ? r.require_approval
      : undefined,
    defaultBranch: typeof r.default_branch === "string"
      ? r.default_branch
      : undefined,
    action,
    timestamp: nowIso(),
  };
}

/**
 * Resolve a repo reference to its numeric Woodpecker id. Accepts a numeric id
 * or an `owner/name` full name (looked up on the server). Throws if the repo is
 * not enabled (use `repo_enable` for that) or the reference is malformed.
 */
async function resolveRepoId(g: GlobalArgsT, repo: string): Promise<number> {
  const ref = repo.trim();
  if (looksLikeId(ref)) return Number(ref);
  if (!ref.includes("/")) {
    throw new Error(
      `repo ${JSON.stringify(repo)} must be a numeric id or "owner/name"`,
    );
  }
  const r = await callTolerant(g, {
    method: "GET",
    path: `/api/repos/lookup/${
      ref.split("/").map(encodeURIComponent).join("/")
    }`,
  }, [404]);
  if (r.status === 404 || !r.body.id) {
    throw new Error(
      `repo ${JSON.stringify(repo)} is not enabled on this server ` +
        `(run repo_enable first)`,
    );
  }
  return Number(r.body.id);
}

/** Fetch the full repo object by id. */
async function getRepo(g: GlobalArgsT, id: number): Promise<Json> {
  const r = await call(g, { method: "GET", path: `/api/repos/${id}` });
  return r.body;
}

/**
 * Resolve an org reference to its numeric id. Accepts a numeric id or an org /
 * user login (looked up via `/api/orgs/lookup`).
 */
async function resolveOrgId(g: GlobalArgsT, owner: string): Promise<number> {
  const ref = owner.trim();
  if (looksLikeId(ref)) return Number(ref);
  const r = await call(g, {
    method: "GET",
    path: `/api/orgs/lookup/${encodeURIComponent(ref)}`,
  });
  if (!r.body.id) throw new Error(`org ${JSON.stringify(owner)} not found`);
  return Number(r.body.id);
}

/** Find a forge repo's `forge_remote_id` by full name (case-insensitive). */
async function findForgeRemoteId(
  g: GlobalArgsT,
  fullName: string,
): Promise<{ forgeRemoteId: string; active: boolean } | null> {
  const r = await call(g, { method: "GET", path: "/api/user/repos?all=true" });
  const want = fullName.toLowerCase();
  for (const repo of asArray(r.body)) {
    if (String(repo.full_name ?? "").toLowerCase() === want) {
      return {
        forgeRemoteId: String(repo.forge_remote_id ?? ""),
        active: Boolean(repo.active),
      };
    }
  }
  return null;
}

/**
 * Build the settings half of a repo PATCH body from the desired-config args,
 * merging `trusted` over the repo's current trust object so partial trust
 * changes don't clobber the untouched capabilities. Returns the body plus
 * whether it differs from `current` (so callers can report unchanged).
 */
function buildRepoPatch(
  current: Json,
  args: RepoConfigArgs,
): { body: Json; changed: boolean } {
  const body: Json = {};
  const curTrusted = (current.trusted ?? {}) as Json;
  const anyTrust = args.trusted !== undefined ||
    args.trustedNetwork !== undefined || args.trustedVolumes !== undefined ||
    args.trustedSecurity !== undefined;
  if (anyTrust) {
    const all = args.trusted;
    const next = {
      network: args.trustedNetwork ?? all ?? Boolean(curTrusted.network),
      volumes: args.trustedVolumes ?? all ?? Boolean(curTrusted.volumes),
      security: args.trustedSecurity ?? all ?? Boolean(curTrusted.security),
    };
    if (
      next.network !== Boolean(curTrusted.network) ||
      next.volumes !== Boolean(curTrusted.volumes) ||
      next.security !== Boolean(curTrusted.security)
    ) body.trusted = next;
  }
  if (args.timeout !== undefined && args.timeout !== Number(current.timeout)) {
    body.timeout = args.timeout;
  }
  if (
    args.visibility !== undefined &&
    args.visibility !== String(current.visibility)
  ) body.visibility = args.visibility;
  if (
    args.requireApproval !== undefined &&
    args.requireApproval !== String(current.require_approval)
  ) body.require_approval = args.requireApproval;
  if (
    args.cancelPreviousPipelineEvents !== undefined
  ) {
    const cur = asArray(current.cancel_previous_pipeline_events).map(String);
    const next = args.cancelPreviousPipelineEvents;
    if (JSON.stringify([...cur].sort()) !== JSON.stringify([...next].sort())) {
      body.cancel_previous_pipeline_events = next;
    }
  }
  return { body, changed: Object.keys(body).length > 0 };
}

/** Write one secret (metadata only — never a value) into the data model. */
async function writeSecret(
  context: Ctx,
  scope: "org" | "repo",
  owner: string,
  raw: Json,
  action: z.infer<typeof Action>,
): Promise<DataHandle> {
  return await context.writeResource(
    "secret",
    safeName(`${scope}:${owner}:${raw.name}`),
    {
      scope,
      owner,
      id: raw.id != null ? Number(raw.id) : undefined,
      name: String(raw.name ?? ""),
      events: asArray(raw.events).map(String),
      images: asArray(raw.images).map(String),
      action,
      timestamp: nowIso(),
    },
  );
}

/**
 * Create-or-update a secret at a scope's `/secrets` collection idempotently:
 * probe by name (404 ⇒ create via POST, else update via PATCH). The value is
 * write-only and is never read back or stored.
 */
async function upsertSecret(
  g: GlobalArgsT,
  collectionPath: string,
  args: SecretSetArgs,
): Promise<{ raw: Json; action: "created" | "updated" }> {
  const probe = await callTolerant(g, {
    method: "GET",
    path: `${collectionPath}/${encodeURIComponent(args.name)}`,
  }, [404]);
  const payload: Json = {
    name: args.name,
    value: args.value,
    events: args.events,
    images: args.images,
  };
  if (probe.status === 404) {
    const r = await call(g, {
      method: "POST",
      path: collectionPath,
      body: payload,
    });
    return { raw: r.body, action: "created" };
  }
  const r = await call(g, {
    method: "PATCH",
    path: `${collectionPath}/${encodeURIComponent(args.name)}`,
    body: payload,
  });
  return { raw: r.body, action: "updated" };
}

/** Normalise a raw pipeline object into {@link PipelineInfo}. */
function toPipelineInfo(
  repo: string,
  p: Json,
  action: z.infer<typeof Action>,
): z.infer<typeof PipelineInfo> {
  const created = p.created != null ? Number(p.created) : undefined;
  return {
    repo,
    number: Number(p.number ?? 0),
    status: String(p.status ?? "unknown"),
    event: typeof p.event === "string" ? p.event : undefined,
    branch: typeof p.branch === "string" ? p.branch : undefined,
    commit: typeof p.commit === "string"
      ? p.commit
      : (typeof p.commit_sha === "string" ? p.commit_sha : undefined),
    message: typeof p.message === "string" ? p.message : undefined,
    createdAt: created !== undefined && Number.isFinite(created)
      ? new Date(created * 1000).toISOString()
      : undefined,
    action,
    timestamp: nowIso(),
  };
}

/** Decode a base64 log payload to UTF-8 text (non-fatal: bad bytes → U+FFFD). */
function b64decode(s: string): string {
  try {
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Terminal pipeline statuses — a wait loop stops on any of these. */
const TERMINAL = new Set([
  "success",
  "failure",
  "error",
  "killed",
  "declined",
  "blocked",
  "skipped",
]);
function isTerminal(status: string): boolean {
  return TERMINAL.has(status);
}

/** Convert a unix-seconds timestamp to ISO, or undefined if absent/zero. */
function unixToIso(v: unknown): string | undefined {
  if (v == null) return undefined;
  const n = Number(v);
  return Number.isFinite(n) && n > 0
    ? new Date(n * 1000).toISOString()
    : undefined;
}

/**
 * The most recent pipeline for a repo, of ANY event (returns null if the repo
 * has never run). NB: the dedicated `/pipelines/latest` endpoint only considers
 * the DEFAULT BRANCH and silently excludes tag pipelines, so a just-cut release
 * would be invisible — list-most-recent instead.
 */
async function latestPipeline(
  g: GlobalArgsT,
  repoId: number,
): Promise<Json | null> {
  const r = await call(g, {
    method: "GET",
    path: `/api/repos/${repoId}/pipelines?perPage=1`,
  });
  return asArray(r.body)[0] ?? null;
}

/** Resolve a pipeline number: the given one, or the repo's most recent run. */
async function resolveNumber(
  g: GlobalArgsT,
  repoId: number,
  number?: number,
): Promise<number> {
  if (number !== undefined) return number;
  const p = await latestPipeline(g, repoId);
  if (!p) throw new Error(`repo ${repoId} has no pipelines yet`);
  return Number(p.number ?? 0);
}

/** Fetch one pipeline (with its workflows/steps) by number. */
async function getPipeline(
  g: GlobalArgsT,
  repoId: number,
  number: number,
): Promise<Json> {
  const r = await call(g, {
    method: "GET",
    path: `/api/repos/${repoId}/pipelines/${number}`,
  });
  return r.body;
}

/** Flatten a pipeline's workflows[].children[] into step records. */
function toSteps(
  repo: string,
  pipelineNumber: number,
  pipeline: Json,
  action: z.infer<typeof Action>,
): Array<z.infer<typeof PipelineStepInfo>> {
  const out: Array<z.infer<typeof PipelineStepInfo>> = [];
  const ts = nowIso();
  for (const wf of asArray(pipeline.workflows)) {
    const wfName = String(wf.name ?? "");
    for (const child of asArray(wf.children)) {
      out.push({
        repo,
        pipelineNumber,
        workflow: wfName,
        name: String(child.name ?? ""),
        state: String(child.state ?? "unknown"),
        exitCode: child.exit_code != null ? Number(child.exit_code) : undefined,
        error: typeof child.error === "string" && child.error
          ? child.error
          : undefined,
        action,
        timestamp: ts,
      });
    }
  }
  return out;
}

/** Find a step (by name or numeric id) within a pipeline's workflows. */
function findStep(
  pipeline: Json,
  step: string,
): { id: number; name: string } | null {
  const want = step.trim();
  for (const wf of asArray(pipeline.workflows)) {
    for (const child of asArray(wf.children)) {
      if (
        String(child.name ?? "") === want || String(child.id ?? "") === want
      ) {
        return { id: Number(child.id ?? 0), name: String(child.name ?? "") };
      }
    }
  }
  return null;
}

/** Normalise a raw agent object into {@link AgentInfo}, deriving `online`. */
function toAgent(a: Json): z.infer<typeof AgentInfo> {
  const lc = a.last_contact != null ? Number(a.last_contact) : 0;
  const online = Number.isFinite(lc) && lc > 0
    ? (Date.now() / 1000 - lc) < 120
    : undefined;
  return {
    id: Number(a.id ?? 0),
    name: typeof a.name === "string" ? a.name : undefined,
    online,
    lastContact: unixToIso(a.last_contact),
    version: typeof a.version === "string" ? a.version : undefined,
    capacity: a.capacity != null ? Number(a.capacity) : undefined,
    noSchedule: typeof a.no_schedule === "boolean" ? a.no_schedule : undefined,
    action: "observed",
    timestamp: nowIso(),
  };
}

/** Normalise a raw cron object into {@link CronInfo}. */
function toCron(
  repo: string,
  c: Json,
  action: z.infer<typeof Action>,
): z.infer<typeof CronInfo> {
  return {
    repo,
    id: c.id != null ? Number(c.id) : undefined,
    name: String(c.name ?? ""),
    schedule: String(c.schedule ?? ""),
    branch: typeof c.branch === "string" && c.branch ? c.branch : undefined,
    nextExec: unixToIso(c.next_exec),
    createdAt: unixToIso(c.created),
    action,
    timestamp: nowIso(),
  };
}

// ─────────────────────────── argument schemas ───────────────────────────

const Empty = z.object({});

const RepoRef = z.object({
  repo: z.string().describe(
    'Repo reference: numeric id or "owner/name" (e.g. thomas-elliott/damson).',
  ),
});

const RepoAvailableArgs = z.object({
  match: z.string().optional().describe(
    "Case-insensitive substring filter on the repo full name.",
  ),
});

/** The shared repo-settings fields used by enable/update. */
const RepoConfigShape = {
  trusted: z.coerce.boolean().optional().describe(
    "Convenience: set ALL three trust capabilities (network/volumes/security) " +
      "to this value. Needed for steps that mount the host docker socket. " +
      "Granular flags below override it.",
  ),
  trustedNetwork: z.coerce.boolean().optional().describe(
    "Trust capability: host network access.",
  ),
  trustedVolumes: z.coerce.boolean().optional().describe(
    "Trust capability: host volume mounts (e.g. /var/run/docker.sock).",
  ),
  trustedSecurity: z.coerce.boolean().optional().describe(
    "Trust capability: relaxed security options.",
  ),
  timeout: z.coerce.number().int().optional().describe(
    "Pipeline timeout in MINUTES (a hang backstop).",
  ),
  visibility: z.enum(["public", "private", "internal"]).optional().describe(
    "Repo visibility on Woodpecker.",
  ),
  requireApproval: z.enum(["none", "forks", "pull_requests", "all"]).optional()
    .describe("Which pipelines require manual approval before running."),
  cancelPreviousPipelineEvents: z.array(z.string()).optional().describe(
    "Events for which a new pipeline cancels the previous running one.",
  ),
};

const RepoEnableArgs = z.object({
  repo: z.string().describe('Repo to enable, as "owner/name".'),
  ...RepoConfigShape,
});

const RepoUpdateArgs = z.object({
  repo: z.string().describe('Repo reference: numeric id or "owner/name".'),
  ...RepoConfigShape,
});

// Internal config-arg shape shared by buildRepoPatch (kept unexported — slow type).
type RepoConfigArgs = z.infer<typeof RepoEnableArgs>;

const OrgRef = z.object({
  owner: z.string().describe("Org / user login or numeric org id."),
});

const SecretSetShape = {
  name: z.string().describe("Secret name (referenced as from_secret in CI)."),
  value: z.string().meta({ sensitive: true }).describe(
    "Secret value (write-only; never read back). Supply via vault: " +
      "${{ vault.get(<vault>, <item>/<field>) }}",
  ),
  events: z.array(z.string()).default(["push", "tag"]).describe(
    "Pipeline events the secret is available to.",
  ),
  images: z.array(z.string()).default([]).describe(
    "Restrict the secret to these step images (empty = all).",
  ),
};

/** Just the create-or-update secret fields, shared by org + repo scopes. */
const SecretSetCore = z.object(SecretSetShape);

const OrgSecretSetArgs = z.object({
  owner: z.string().describe("Org / user login or numeric org id."),
  ...SecretSetShape,
});

const OrgSecretDeleteArgs = z.object({
  owner: z.string().describe("Org / user login or numeric org id."),
  name: z.string().describe("Secret name to delete (reversible: re-create)."),
});

const RepoSecretSetArgs = z.object({
  repo: z.string().describe('Repo reference: numeric id or "owner/name".'),
  ...SecretSetShape,
});

const RepoSecretDeleteArgs = z.object({
  repo: z.string().describe('Repo reference: numeric id or "owner/name".'),
  name: z.string().describe("Secret name to delete (reversible: re-create)."),
});

/** Internal secret-set arg shape (kept unexported — slow type). */
type SecretSetArgs = z.infer<typeof SecretSetCore>;

const PipelineListArgs = z.object({
  repo: z.string().describe('Repo reference: numeric id or "owner/name".'),
  limit: z.coerce.number().int().default(10).describe(
    "Max number of recent pipelines to return.",
  ),
});

const PipelineTriggerArgs = z.object({
  repo: z.string().describe('Repo reference: numeric id or "owner/name".'),
  branch: z.string().optional().describe(
    "Branch to run (defaults to the repo's default branch).",
  ),
});

/** A pipeline reference: repo + an optional number (defaults to latest). */
const PipelineRef = z.object({
  repo: z.string().describe('Repo reference: numeric id or "owner/name".'),
  number: z.coerce.number().int().optional().describe(
    "Pipeline number (defaults to the repo's latest pipeline).",
  ),
});

const PipelineLogsArgs = PipelineRef.extend({
  step: z.string().describe("Step name (e.g. 'dotnet') or numeric step id."),
  tailLines: z.coerce.number().int().default(200).describe(
    "Return only the last N decoded log lines (0 = all).",
  ),
});

const PipelineWaitArgs = PipelineRef.extend({
  timeoutSec: z.coerce.number().int().default(600).describe(
    "Give up waiting after this many seconds (returns the non-terminal state).",
  ),
  pollIntervalSec: z.coerce.number().int().default(5).describe(
    "Seconds between status polls.",
  ),
});

const StatusAllArgs = z.object({
  match: z.string().optional().describe(
    "Case-insensitive substring filter on the repo full name.",
  ),
});

const CronSetArgs = z.object({
  repo: z.string().describe('Repo reference: numeric id or "owner/name".'),
  name: z.string().describe("Cron job name (unique within the repo)."),
  schedule: z.string().describe(
    "Schedule: a cron expression or an @hourly/@daily/@weekly/… macro.",
  ),
  branch: z.string().optional().describe(
    "Branch to run (defaults to the repo's default branch).",
  ),
});

const CronDeleteArgs = z.object({
  repo: z.string().describe('Repo reference: numeric id or "owner/name".'),
  name: z.string().describe("Cron job name to delete (reversible: re-create)."),
});

// ─────────────────────────── model ───────────────────────────

/**
 * `@thomas/woodpecker` model — administer a Woodpecker CI server over its REST
 * API with an admin PAT. Mutations are additive or reversible; secret values are
 * write-only. See the file header for the full scope guarantee.
 */
export const model = {
  type: "@thomas/woodpecker",
  version: "2026.06.04.3",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify the server is reachable and the token authenticates (GET /api/user).",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        const g = context.globalArgs;
        // `swamp model validate` does not resolve vault expressions, so token is
        // still a literal `${{ … }}` there. Skip; the real check runs at method
        // time when the secret is resolved.
        if (/\$\{\{/.test(String(g.token))) return { pass: true };
        try {
          const r = await rawCall(g, { method: "GET", path: "/api/user" });
          if (r.status >= 400) {
            return {
              pass: false,
              errors: [`GET /api/user -> HTTP ${r.status}: ${errMsg(r)}`],
            };
          }
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Cannot reach Woodpecker at ${g.apiUrl}: ${(e as Error).message}`,
            ],
          };
        }
      },
    },
  },
  resources: {
    "repo": {
      description: "An enabled repository and its CI settings.",
      schema: RepoInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "available-repo": {
      description: "A forge repo the token can access (enabled or not).",
      schema: AvailableRepo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "org": {
      description: "An organization / user record.",
      schema: OrgInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "secret": {
      description:
        "A secret's metadata (name/events/images) — never its value.",
      schema: SecretInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "pipeline": {
      description: "A pipeline run's status.",
      schema: PipelineInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "pipeline-step": {
      description: "One step of a pipeline run and its state.",
      schema: PipelineStepInfo,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "pipeline-log": {
      description: "Decoded logs for one pipeline step.",
      schema: PipelineLogInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "repo-status": {
      description: "A repo's latest pipeline status (the fleet dashboard).",
      schema: RepoStatusInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "agent": {
      description: "A Woodpecker build agent and its health.",
      schema: AgentInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "queue": {
      description: "Server build-queue statistics.",
      schema: QueueStats,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "server": {
      description: "Server version and health.",
      schema: ServerStatus,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "cron": {
      description: "A repo's scheduled-pipeline (cron) job.",
      schema: CronInfo,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  methods: {
    // ───────────── read / audit ─────────────
    repo_list: {
      description:
        "List enabled repositories with their CI settings (factory). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Listing enabled repos");
        const r = await call(g, { method: "GET", path: "/api/repos" });
        const handles: DataHandle[] = [];
        for (const repo of asArray(r.body)) {
          handles.push(
            await context.writeResource(
              "repo",
              String(repo.id),
              toRepoInfo(repo, "observed"),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    repo_get: {
      description: "Get one enabled repository and its settings. Read-only.",
      arguments: RepoRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const repo = await getRepo(g, id);
        const handle = await context.writeResource(
          "repo",
          String(id),
          toRepoInfo(repo, "observed"),
        );
        return { dataHandles: [handle] };
      },
    },
    repo_available: {
      description:
        "List repos the token can access on the forge, with whether each is " +
        "already enabled (factory). Read-only.",
      arguments: RepoAvailableArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoAvailableArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Listing available forge repos");
        const r = await call(g, {
          method: "GET",
          path: "/api/user/repos?all=true",
        });
        const match = a.match?.toLowerCase();
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const repo of asArray(r.body)) {
          const full = String(repo.full_name ?? "");
          if (match && !full.toLowerCase().includes(match)) continue;
          handles.push(
            await context.writeResource("available-repo", safeName(full), {
              fullName: full,
              forgeRemoteId: repo.forge_remote_id != null
                ? String(repo.forge_remote_id)
                : undefined,
              active: Boolean(repo.active),
              action: "observed",
              timestamp: ts,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },
    org_get: {
      description: "Look up an org / user by login. Read-only.",
      arguments: OrgRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = OrgRef.parse(rawArgs);
        const g = context.globalArgs;
        const r = await call(g, {
          method: "GET",
          path: `/api/orgs/lookup/${encodeURIComponent(a.owner)}`,
        });
        const o = r.body;
        const handle = await context.writeResource("org", String(o.id), {
          id: Number(o.id ?? 0),
          name: String(o.name ?? a.owner),
          isUser: Boolean(o.is_user),
          action: "observed",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    org_secret_list: {
      description:
        "List an org's secrets (names/events/images only — never values; " +
        "factory). Read-only.",
      arguments: OrgRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = OrgRef.parse(rawArgs);
        const g = context.globalArgs;
        const orgId = await resolveOrgId(g, a.owner);
        const r = await call(g, {
          method: "GET",
          path: `/api/orgs/${orgId}/secrets`,
        });
        const handles: DataHandle[] = [];
        for (const s of asArray(r.body)) {
          handles.push(
            await writeSecret(context, "org", a.owner, s, "observed"),
          );
        }
        return { dataHandles: handles };
      },
    },
    repo_secret_list: {
      description:
        "List a repo's secrets (names/events/images only — never values; " +
        "factory). Read-only.",
      arguments: RepoRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const repo = await getRepo(g, id);
        const full = String(repo.full_name ?? a.repo);
        const r = await call(g, {
          method: "GET",
          path: `/api/repos/${id}/secrets`,
        });
        const handles: DataHandle[] = [];
        for (const s of asArray(r.body)) {
          handles.push(await writeSecret(context, "repo", full, s, "observed"));
        }
        return { dataHandles: handles };
      },
    },
    pipeline_list: {
      description: "List recent pipelines for a repo (factory). Read-only.",
      arguments: PipelineListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineListArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const r = await call(g, {
          method: "GET",
          path: `/api/repos/${id}/pipelines?perPage=${a.limit}`,
        });
        const handles: DataHandle[] = [];
        for (const p of asArray(r.body)) {
          handles.push(
            await context.writeResource(
              "pipeline",
              `${id}:${p.number}`,
              toPipelineInfo(a.repo, p, "observed"),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    pipeline_last: {
      description:
        "Get the most recent pipeline for a repo, of any event (incl. tags). " +
        "Read-only.",
      arguments: RepoRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const p = await latestPipeline(g, id);
        if (!p) throw new Error(`repo ${a.repo} has no pipelines yet`);
        const handle = await context.writeResource(
          "pipeline",
          `${id}:${p.number}`,
          toPipelineInfo(a.repo, p, "observed"),
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── observability ─────────────
    pipeline_steps: {
      description:
        "List a pipeline's steps and their states (factory; defaults to the " +
        "repo's latest pipeline). Read-only.",
      arguments: PipelineRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const number = await resolveNumber(g, id, a.number);
        const pipe = await getPipeline(g, id, number);
        const handles: DataHandle[] = [];
        for (const step of toSteps(a.repo, number, pipe, "observed")) {
          handles.push(
            await context.writeResource(
              "pipeline-step",
              safeName(`${id}:${number}:${step.workflow}:${step.name}`),
              step,
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    pipeline_logs: {
      description:
        "Fetch and decode the logs for one pipeline step (by step name or id; " +
        "defaults to the repo's latest pipeline), returning the last `tailLines` " +
        "lines. Read-only.",
      arguments: PipelineLogsArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineLogsArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const number = await resolveNumber(g, id, a.number);
        const pipe = await getPipeline(g, id, number);
        const step = findStep(pipe, a.step);
        if (!step) {
          throw new Error(
            `step ${JSON.stringify(a.step)} not found in ${a.repo} ` +
              `pipeline #${number}`,
          );
        }
        const r = await call(g, {
          method: "GET",
          path: `/api/repos/${id}/logs/${number}/${step.id}`,
        });
        const lines = asArray(r.body)
          .map((e) => b64decode(String((e as Json).data ?? "")))
          .join("\n")
          .split("\n");
        const kept = a.tailLines > 0 ? lines.slice(-a.tailLines) : lines;
        const handle = await context.writeResource(
          "pipeline-log",
          safeName(`${id}:${number}:${step.name}`),
          {
            repo: a.repo,
            pipelineNumber: number,
            step: step.name,
            stepId: step.id,
            lineCount: kept.length,
            truncated: kept.length < lines.length,
            text: kept.join("\n"),
            action: "observed",
            timestamp: nowIso(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    pipeline_wait: {
      description:
        "Poll a pipeline until it reaches a terminal state (success/failure/…), " +
        "then write its final status plus every step (so the failed step is " +
        "visible). Defaults to the repo's latest pipeline; bounded by `timeoutSec`.",
      arguments: PipelineWaitArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineWaitArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const number = await resolveNumber(g, id, a.number);
        const deadline = Date.now() + a.timeoutSec * 1000;
        let pipe: Json = {};
        let status = "pending";
        for (;;) {
          pipe = await getPipeline(g, id, number);
          status = String(pipe.status ?? "pending");
          if (isTerminal(status)) break;
          if (Date.now() >= deadline) {
            logInfo(context, "Pipeline wait timed out", {
              repo: a.repo,
              number,
              status,
            });
            break;
          }
          logInfo(context, "Waiting for pipeline", {
            repo: a.repo,
            number,
            status,
          });
          await sleep(a.pollIntervalSec * 1000);
        }
        const handles: DataHandle[] = [
          await context.writeResource(
            "pipeline",
            `${id}:${number}`,
            toPipelineInfo(a.repo, pipe, "observed"),
          ),
        ];
        for (const step of toSteps(a.repo, number, pipe, "observed")) {
          handles.push(
            await context.writeResource(
              "pipeline-step",
              safeName(`${id}:${number}:${step.workflow}:${step.name}`),
              step,
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    status_all: {
      description:
        "Fleet dashboard: the latest pipeline status for every enabled repo " +
        "(factory) — one call to see what's red. Read-only.",
      arguments: StatusAllArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = StatusAllArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Collecting fleet pipeline status");
        const r = await call(g, { method: "GET", path: "/api/repos" });
        const match = a.match?.toLowerCase();
        const ts = nowIso();
        const handles: DataHandle[] = [];
        for (const repo of asArray(r.body)) {
          const full = String(repo.full_name ?? "");
          if (match && !full.toLowerCase().includes(match)) continue;
          const repoId = Number(repo.id ?? 0);
          const p = (await latestPipeline(g, repoId)) ?? {};
          const ran = p.number != null;
          handles.push(
            await context.writeResource(
              "repo-status",
              safeName(full || String(repoId)),
              {
                repo: full,
                repoId,
                status: ran ? String(p.status ?? "unknown") : "none",
                number: p.number != null ? Number(p.number) : undefined,
                event: typeof p.event === "string" ? p.event : undefined,
                branch: typeof p.branch === "string" ? p.branch : undefined,
                finishedAt: unixToIso(p.finished),
                action: "observed",
                timestamp: ts,
              },
            ),
          );
        }
        return { dataHandles: handles };
      },
    },

    // ───────────── provision ─────────────
    repo_enable: {
      description:
        "Onboard a repo: activate it from the forge if needed, then converge " +
        "the supplied settings (trusted/timeout/visibility/…). Idempotent — a " +
        "re-run with the same settings is a no-op.",
      arguments: RepoEnableArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoEnableArgs.parse(rawArgs);
        const g = context.globalArgs;
        if (!a.repo.includes("/")) {
          throw new Error(
            `repo ${JSON.stringify(a.repo)} must be "owner/name"`,
          );
        }
        // Already enabled? (lookup tolerates 404 for not-yet-active repos.)
        const lookup = await callTolerant(g, {
          method: "GET",
          path: `/api/repos/lookup/${
            a.repo.split("/").map(encodeURIComponent).join("/")
          }`,
        }, [404]);
        let repo: Json;
        let enabled = false;
        if (lookup.status === 404 || !lookup.body.id) {
          const forge = await findForgeRemoteId(g, a.repo);
          if (!forge || !forge.forgeRemoteId) {
            throw new Error(
              `repo ${
                JSON.stringify(a.repo)
              } not found among forge repos the ` +
                `token can access`,
            );
          }
          logInfo(context, "Enabling repo", { repo: a.repo });
          const r = await call(g, {
            method: "POST",
            path: `/api/repos?forge_remote_id=${
              encodeURIComponent(forge.forgeRemoteId)
            }`,
          });
          repo = r.body;
          enabled = true;
        } else {
          repo = lookup.body;
        }
        // Converge settings.
        const id = Number(repo.id);
        const { body, changed } = buildRepoPatch(repo, a);
        if (changed) {
          logInfo(context, "Updating repo settings", { repo: a.repo, body });
          const r = await call(g, {
            method: "PATCH",
            path: `/api/repos/${id}`,
            body,
          });
          repo = r.body;
        }
        const action: z.infer<typeof Action> = enabled
          ? "enabled"
          : (changed ? "updated" : "unchanged");
        const handle = await context.writeResource(
          "repo",
          String(id),
          toRepoInfo(repo, action),
        );
        return { dataHandles: [handle] };
      },
    },
    repo_update: {
      description:
        "Update settings on an already-enabled repo (trusted/timeout/" +
        "visibility/…). Idempotent: reports unchanged when nothing differs.",
      arguments: RepoUpdateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoUpdateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const current = await getRepo(g, id);
        const { body, changed } = buildRepoPatch(current, a);
        let repo = current;
        if (changed) {
          const r = await call(g, {
            method: "PATCH",
            path: `/api/repos/${id}`,
            body,
          });
          repo = r.body;
        }
        const handle = await context.writeResource(
          "repo",
          String(id),
          toRepoInfo(repo, changed ? "updated" : "unchanged"),
        );
        return { dataHandles: [handle] };
      },
    },
    repo_repair: {
      description:
        "Repair a repo's forge webhook + deploy key (idempotent; fixes a stale " +
        "hook after the server URL changed).",
      arguments: RepoRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        logInfo(context, "Repairing repo webhook", { repo: a.repo });
        await call(g, { method: "POST", path: `/api/repos/${id}/repair` });
        const repo = await getRepo(g, id);
        const handle = await context.writeResource(
          "repo",
          String(id),
          toRepoInfo(repo, "repaired"),
        );
        return { dataHandles: [handle] };
      },
    },
    org_secret_set: {
      description:
        "Create-or-update an org-level secret (inherited by all the org's " +
        "repos). The value is write-only — supply it via a vault reference.",
      arguments: OrgSecretSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = OrgSecretSetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const orgId = await resolveOrgId(g, a.owner);
        logInfo(context, "Setting org secret", {
          owner: a.owner,
          name: a.name,
        });
        const { raw, action } = await upsertSecret(
          g,
          `/api/orgs/${orgId}/secrets`,
          a,
        );
        const handle = await writeSecret(context, "org", a.owner, {
          ...raw,
          name: a.name,
        }, action);
        return { dataHandles: [handle] };
      },
    },
    repo_secret_set: {
      description:
        "Create-or-update a repo-scoped secret. The value is write-only — " +
        "supply it via a vault reference.",
      arguments: RepoSecretSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoSecretSetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const repo = await getRepo(g, id);
        const full = String(repo.full_name ?? a.repo);
        logInfo(context, "Setting repo secret", { repo: full, name: a.name });
        const { raw, action } = await upsertSecret(
          g,
          `/api/repos/${id}/secrets`,
          a,
        );
        const handle = await writeSecret(context, "repo", full, {
          ...raw,
          name: a.name,
        }, action);
        return { dataHandles: [handle] };
      },
    },

    // ───────────── reversible lifecycle ─────────────
    repo_disable: {
      description:
        "Deactivate a repo (stops its CI; removes the webhook). REVERSIBLE — " +
        "re-run repo_enable to restore. Verifies the repo first.",
      arguments: RepoRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const current = await getRepo(g, id); // verify before mutating
        logInfo(context, "Disabling repo", {
          repo: current.full_name,
          id,
        });
        await call(g, { method: "DELETE", path: `/api/repos/${id}` });
        const handle = await context.writeResource(
          "repo",
          String(id),
          toRepoInfo({ ...current, active: false }, "disabled"),
        );
        return { dataHandles: [handle] };
      },
    },
    org_secret_delete: {
      description:
        "Delete an org-level secret. REVERSIBLE — re-create with org_secret_set. " +
        "Verifies it exists first.",
      arguments: OrgSecretDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = OrgSecretDeleteArgs.parse(rawArgs);
        const g = context.globalArgs;
        const orgId = await resolveOrgId(g, a.owner);
        const probe = await callTolerant(g, {
          method: "GET",
          path: `/api/orgs/${orgId}/secrets/${encodeURIComponent(a.name)}`,
        }, [404]);
        if (probe.status === 404) {
          // Already absent — idempotent no-op (re-runs must not fail a pipeline).
          logInfo(context, "Org secret already absent", {
            owner: a.owner,
            name: a.name,
          });
          const handle = await writeSecret(context, "org", a.owner, {
            name: a.name,
          }, "unchanged");
          return { dataHandles: [handle] };
        }
        logInfo(context, "Deleting org secret", {
          owner: a.owner,
          name: a.name,
        });
        await call(g, {
          method: "DELETE",
          path: `/api/orgs/${orgId}/secrets/${encodeURIComponent(a.name)}`,
        });
        const handle = await writeSecret(context, "org", a.owner, {
          ...probe.body,
          name: a.name,
        }, "deleted");
        return { dataHandles: [handle] };
      },
    },
    repo_secret_delete: {
      description: "Delete a repo-scoped secret. REVERSIBLE — re-create with " +
        "repo_secret_set. Verifies it exists first.",
      arguments: RepoSecretDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoSecretDeleteArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const repo = await getRepo(g, id);
        const full = String(repo.full_name ?? a.repo);
        const probe = await callTolerant(g, {
          method: "GET",
          path: `/api/repos/${id}/secrets/${encodeURIComponent(a.name)}`,
        }, [404]);
        if (probe.status === 404) {
          // Already absent — idempotent no-op (re-runs must not fail a pipeline).
          logInfo(context, "Repo secret already absent", {
            repo: full,
            name: a.name,
          });
          const handle = await writeSecret(context, "repo", full, {
            name: a.name,
          }, "unchanged");
          return { dataHandles: [handle] };
        }
        logInfo(context, "Deleting repo secret", { repo: full, name: a.name });
        await call(g, {
          method: "DELETE",
          path: `/api/repos/${id}/secrets/${encodeURIComponent(a.name)}`,
        });
        const handle = await writeSecret(context, "repo", full, {
          ...probe.body,
          name: a.name,
        }, "deleted");
        return { dataHandles: [handle] };
      },
    },

    // ───────────── action ─────────────
    pipeline_trigger: {
      description:
        "Trigger a new pipeline for a repo on the given branch (defaults to the " +
        "repo's default branch).",
      arguments: PipelineTriggerArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineTriggerArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const body: Json = {};
        if (a.branch) body.branch = a.branch;
        logInfo(context, "Triggering pipeline", {
          repo: a.repo,
          branch: a.branch,
        });
        const r = await call(g, {
          method: "POST",
          path: `/api/repos/${id}/pipelines`,
          body,
        });
        const handle = await context.writeResource(
          "pipeline",
          `${id}:${r.body.number}`,
          toPipelineInfo(a.repo, r.body, "triggered"),
        );
        return { dataHandles: [handle] };
      },
    },
    pipeline_restart: {
      description:
        "Restart (re-run) a pipeline — e.g. after fixing infra, instead of an " +
        "empty commit. Defaults to the repo's latest. Creates a NEW run.",
      arguments: PipelineRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const number = await resolveNumber(g, id, a.number);
        logInfo(context, "Restarting pipeline", { repo: a.repo, number });
        const r = await call(g, {
          method: "POST",
          path: `/api/repos/${id}/pipelines/${number}`,
        });
        const newNum = Number(r.body.number ?? number);
        const handle = await context.writeResource(
          "pipeline",
          `${id}:${newNum}`,
          toPipelineInfo(a.repo, r.body, "restarted"),
        );
        return { dataHandles: [handle] };
      },
    },
    pipeline_cancel: {
      description:
        "Cancel a running pipeline (defaults to the repo's latest). Verifies it " +
        "first; cancelling an already-finished run is a no-op.",
      arguments: PipelineRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const number = await resolveNumber(g, id, a.number);
        const before = await getPipeline(g, id, number);
        const status = String(before.status ?? "");
        if (isTerminal(status)) {
          logInfo(context, "Pipeline already finished; nothing to cancel", {
            repo: a.repo,
            number,
            status,
          });
          const handle = await context.writeResource(
            "pipeline",
            `${id}:${number}`,
            toPipelineInfo(a.repo, before, "unchanged"),
          );
          return { dataHandles: [handle] };
        }
        logInfo(context, "Cancelling pipeline", { repo: a.repo, number });
        await call(g, {
          method: "POST",
          path: `/api/repos/${id}/pipelines/${number}/cancel`,
        });
        const after = await getPipeline(g, id, number);
        const handle = await context.writeResource(
          "pipeline",
          `${id}:${number}`,
          toPipelineInfo(a.repo, after, "cancelled"),
        );
        return { dataHandles: [handle] };
      },
    },
    pipeline_approve: {
      description:
        "Approve a pipeline blocked pending approval (require_approval). " +
        "Defaults to the repo's latest.",
      arguments: PipelineRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const number = await resolveNumber(g, id, a.number);
        logInfo(context, "Approving pipeline", { repo: a.repo, number });
        const r = await call(g, {
          method: "POST",
          path: `/api/repos/${id}/pipelines/${number}/approve`,
        });
        const handle = await context.writeResource(
          "pipeline",
          `${id}:${number}`,
          toPipelineInfo(a.repo, r.body, "approved"),
        );
        return { dataHandles: [handle] };
      },
    },
    pipeline_decline: {
      description:
        "Decline a pipeline blocked pending approval (defaults to the repo's " +
        "latest). To undo, restart it.",
      arguments: PipelineRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PipelineRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const number = await resolveNumber(g, id, a.number);
        logInfo(context, "Declining pipeline", { repo: a.repo, number });
        const r = await call(g, {
          method: "POST",
          path: `/api/repos/${id}/pipelines/${number}/decline`,
        });
        const handle = await context.writeResource(
          "pipeline",
          `${id}:${number}`,
          toPipelineInfo(a.repo, r.body, "declined"),
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── infra / health ─────────────
    agent_list: {
      description:
        "List the server's build agents and their health (last contact, version, " +
        "capacity; factory). Admin read.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Listing agents");
        const r = await call(g, { method: "GET", path: "/api/agents" });
        const handles: DataHandle[] = [];
        for (const ag of asArray(r.body)) {
          handles.push(
            await context.writeResource(
              "agent",
              String(ag.id ?? ""),
              toAgent(ag),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    queue_info: {
      description:
        "Server build-queue statistics (pending/running/worker counts; paused). " +
        "Admin read.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const r = await call(g, { method: "GET", path: "/api/queue/info" });
        const b = r.body;
        const stats = (b.stats ?? {}) as Json;
        const handle = await context.writeResource("queue", "queue", {
          paused: typeof b.paused === "boolean" ? b.paused : undefined,
          pending: Number(stats.pending_count ?? asArray(b.pending).length),
          waitingOnDeps: Number(
            stats.waiting_on_deps_count ?? asArray(b.waiting_on_deps).length,
          ),
          running: Number(stats.running_count ?? asArray(b.running).length),
          completed: Number(stats.completed_count ?? 0),
          workerCount: Number(stats.worker_count ?? 0),
          action: "observed",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },
    server_info: {
      description:
        "Server version and health (GET /version + /healthz). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        // /version and /healthz live OUTSIDE the /api prefix — the /api/* forms
        // are swallowed by the SPA catch-all and return HTML, not JSON.
        const ver = await call(g, { method: "GET", path: "/version" });
        const health = await callTolerant(g, {
          method: "GET",
          path: "/healthz",
        }, [500, 503]);
        const handle = await context.writeResource("server", "server", {
          version: String(ver.body.version ?? "unknown"),
          source: typeof ver.body.source === "string"
            ? ver.body.source
            : undefined,
          healthy: health.status < 400,
          action: "observed",
          timestamp: nowIso(),
        });
        return { dataHandles: [handle] };
      },
    },

    // ───────────── scheduled pipelines (cron) ─────────────
    cron_list: {
      description:
        "List a repo's scheduled-pipeline (cron) jobs (factory). Read-only.",
      arguments: RepoRef,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RepoRef.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const r = await call(g, {
          method: "GET",
          path: `/api/repos/${id}/cron`,
        });
        const handles: DataHandle[] = [];
        for (const c of asArray(r.body)) {
          handles.push(
            await context.writeResource(
              "cron",
              safeName(`${id}:${c.name}`),
              toCron(a.repo, c, "observed"),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },
    cron_set: {
      description:
        "Create-or-update a scheduled-pipeline (cron) job by name (idempotent: " +
        "reports unchanged when the schedule/branch already match).",
      arguments: CronSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = CronSetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const list = await call(g, {
          method: "GET",
          path: `/api/repos/${id}/cron`,
        });
        const existing = asArray(list.body).find((c) =>
          String(c.name ?? "") === a.name
        );
        const payload: Json = { name: a.name, schedule: a.schedule };
        if (a.branch) payload.branch = a.branch;
        let raw: Json;
        let action: "created" | "updated" | "unchanged";
        if (!existing) {
          logInfo(context, "Creating cron", { repo: a.repo, name: a.name });
          const r = await call(g, {
            method: "POST",
            path: `/api/repos/${id}/cron`,
            body: payload,
          });
          raw = r.body;
          action = "created";
        } else if (
          String(existing.schedule ?? "") === a.schedule &&
          String(existing.branch ?? "") === (a.branch ?? "")
        ) {
          raw = existing;
          action = "unchanged";
        } else {
          logInfo(context, "Updating cron", { repo: a.repo, name: a.name });
          const r = await call(g, {
            method: "PATCH",
            path: `/api/repos/${id}/cron/${existing.id}`,
            body: { id: existing.id, ...payload },
          });
          raw = r.body;
          action = "updated";
        }
        const handle = await context.writeResource(
          "cron",
          safeName(`${id}:${a.name}`),
          toCron(a.repo, { ...raw, name: a.name }, action),
        );
        return { dataHandles: [handle] };
      },
    },
    cron_delete: {
      description:
        "Delete a scheduled-pipeline (cron) job by name. REVERSIBLE — re-create " +
        "with cron_set. Idempotent: already-absent is a no-op.",
      arguments: CronDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = CronDeleteArgs.parse(rawArgs);
        const g = context.globalArgs;
        const id = await resolveRepoId(g, a.repo);
        const list = await call(g, {
          method: "GET",
          path: `/api/repos/${id}/cron`,
        });
        const existing = asArray(list.body).find((c) =>
          String(c.name ?? "") === a.name
        );
        if (!existing) {
          logInfo(context, "Cron already absent", {
            repo: a.repo,
            name: a.name,
          });
          const handle = await context.writeResource(
            "cron",
            safeName(`${id}:${a.name}`),
            toCron(a.repo, { name: a.name, schedule: "" }, "unchanged"),
          );
          return { dataHandles: [handle] };
        }
        logInfo(context, "Deleting cron", { repo: a.repo, name: a.name });
        await call(g, {
          method: "DELETE",
          path: `/api/repos/${id}/cron/${existing.id}`,
        });
        const handle = await context.writeResource(
          "cron",
          safeName(`${id}:${a.name}`),
          toCron(a.repo, { ...existing, name: a.name }, "deleted"),
        );
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
