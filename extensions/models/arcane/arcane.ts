import { z } from "npm:zod@4";
// Type-only imports, erased at compile time and never bundled. The
// `satisfies ModelDefinition<typeof GlobalArgs>` clause on `model` (and the
// factory return types) uses them so every method's `execute` is contextually
// typed without an explicit `any` on its parameters. See swamp-extension typing.md.
import type {
  DataHandle,
  MethodContext,
  MethodDefinition,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";
import https from "node:https";
import http from "node:http";
import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * `@thomas/arcane` manages an Arcane Docker instance entirely through Arcane's
 * REST API (X-API-Key auth). Every mutation goes through Arcane; the one local
 * subprocess is read-only compose validation (`docker compose config`).
 *
 * Direct (API) mode and gitops mode are both supported, chosen per project. In
 * gitops mode a failed deploy is reported, and the git revert is left to the user.
 *
 * The extension only uses an API key; it never touches the Arcane
 * container. Mint the key however suits your install (`ADMIN_STATIC_API_KEY` env
 * for declarative setups, or Settings → API Keys), store it in a vault, and
 * reference it from `apiKey`.
 */

const RepositorySpec = z.object({
  name: z.string().describe("Display name of the git repository connection"),
  url: z.string().describe("Clone URL, e.g. git@github.com:me/gitops.git"),
  // No schema defaults for authType and enabled: they would read as explicit
  // values and reset an existing connection. gitops_repo_ensure applies them
  // on create only.
  authType: z.enum(["none", "http", "ssh"]).optional().describe(
    "Arcane auth type: none | http (username + token) | ssh. A new connection " +
      "defaults to none; when omitted, an existing connection keeps its auth type.",
  ),
  enabled: z.boolean().optional().describe(
    "A new connection defaults to enabled; when omitted, an existing " +
      "connection keeps its state.",
  ),
  description: z.string().optional(),
  token: z.string().optional().meta({ sensitive: true }).describe(
    "PAT for token auth. Secret: supply via vault. Sent only when present.",
  ),
  username: z.string().optional(),
  sshKey: z.string().optional().meta({ sensitive: true }).describe(
    "SSH private key for ssh auth. Secret: supply via vault. Sent only when present.",
  ),
  sshHostKeyVerification: z.string().optional(),
});

const SyncSpec = z.object({
  name: z.string().describe(
    "Sync name; also the project directory Arcane creates",
  ),
  composePath: z.string().describe(
    "Path to the compose file relative to repo root, e.g. projects/homepage/compose.yaml",
  ),
  // No schema defaults below: they would read as explicit values, count as
  // drift against a sync tuned in the UI, and reset it. gitops_sync_ensure
  // applies them on create only.
  branch: z.string().optional().describe(
    'Branch to sync. A new sync defaults to "main"; when omitted, an existing ' +
      "sync keeps its branch.",
  ),
  projectName: z.string().optional().describe(
    "Deployed project name. A new sync defaults to `name`; when omitted, an " +
      "existing sync keeps its project name.",
  ),
  repository: z.string().optional().describe(
    "Repository connection name to resolve the id from; defaults to globalArgs.repository.name",
  ),
  autoSync: z.boolean().optional().describe(
    "A new sync defaults to true; when omitted, an existing sync keeps its setting.",
  ),
  // Arcane stores 0 or a negative interval but schedules it as 1 minute.
  syncInterval: z.number().int().positive().optional().describe(
    "Auto-sync interval in minutes. A new sync defaults to 5; when omitted, an " +
      "existing sync keeps its interval.",
  ),
  syncDirectory: z.boolean().optional().describe(
    "The 'Sync Files' toggle: pull sibling files alongside the compose file. A " +
      "new sync defaults to true; when omitted, an existing sync keeps its setting.",
  ),
  targetType: z.enum(["project", "swarm_stack"]).optional().describe(
    "project (compose) | swarm_stack. A new sync defaults to project; when " +
      "omitted, an existing sync keeps its target type.",
  ),
});

/**
 * Whether an Arcane sync is a backup sync, which commits to git rather than
 * deploying from it. Arcane treats a missing mode as deploy.
 */
function isBackupSync(sync: Json): boolean {
  return pick(sync, "mode") === "backup";
}

/** Settings Arcane gives a new sync when the spec leaves them out. */
const SYNC_CREATE_DEFAULTS = {
  branch: "main",
  autoSync: true,
  syncInterval: 5,
  syncDirectory: true,
  targetType: "project",
};

const GlobalArgs = z.object({
  baseUrl: z.string().describe(
    "Arcane base URL including port, e.g. https://arcane.example.com:8443. Use https; over http the API key is sent in clear text.",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "Arcane API key (X-API-Key). Supply via vault: ${{ vault.get(name, key) }}",
  ),
  environmentId: z.string().default("0").describe(
    "Arcane environment id; 0 is the local Docker environment",
  ),
  skipTlsVerify: z.boolean().default(false).describe(
    "Accept self-signed certs (default false: a valid cert is expected)",
  ),
  repository: RepositorySpec.optional().describe(
    "Desired git repository connection, reconciled by gitops_repo_ensure",
  ),
  syncs: z.array(SyncSpec).default([]).describe(
    "Desired GitOps sync entries, reconciled by gitops_sync_ensure",
  ),
});

const Action = z.enum([
  "created",
  "updated",
  "unchanged",
  "deleted",
  "observed",
]);

const RepositoryResource = z.object({
  id: z.string(),
  name: z.string(),
  url: z.string(),
  authType: z.string().optional(),
  enabled: z.boolean().optional(),
  description: z.string().optional(),
  action: Action,
  observedAt: z.string(),
});

const SyncResource = z.object({
  id: z.string(),
  name: z.string(),
  branch: z.string().optional(),
  composePath: z.string().optional(),
  repositoryId: z.string().optional(),
  projectName: z.string().optional(),
  autoSync: z.boolean().optional(),
  syncInterval: z.number().optional(),
  syncDirectory: z.boolean().optional(),
  targetType: z.string().optional(),
  action: Action,
  observedAt: z.string(),
});

const SyncStatusResource = z.object({
  id: z.string(),
  name: z.string(),
  autoSync: z.boolean().optional(),
  nextSyncAt: z.string().optional().describe(
    "Estimated time of the next automatic sync (autoSync only)",
  ),
  lastSyncAt: z.string().optional(),
  lastSyncStatus: z.string().optional().describe(
    "Outcome of the last sync attempt (e.g. success/failed)",
  ),
  lastSyncError: z.string().optional().describe(
    "Error from the last sync if it failed; empty on success",
  ),
  lastSyncCommit: z.string().optional().describe(
    "Commit hash of the last successful sync",
  ),
  observedAt: z.string(),
});

const VersionResource = z.object({
  currentVersion: z.string(),
  newestVersion: z.string().optional(),
  updateAvailable: z.boolean().optional(),
  releaseUrl: z.string().optional(),
  observedAt: z.string(),
});

const ProjectResource = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string().default("unknown"),
  observedAt: z.string(),
});

const OperationResultResource = z.object({
  operation: z.string(),
  target: z.string(),
  status: z.number().describe(
    "HTTP status of the operation, or 0 when no HTTP answer came (a timeout or broken connection)",
  ),
  success: z.boolean(),
  detail: z.string().optional(),
  timestamp: z.string(),
});

const ProjectDetailResource = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string().default("unknown"),
  gitOpsManagedBy: z.string().optional().describe(
    "Non-empty when the project is managed by an Arcane GitOps sync (mode indicator)",
  ),
  serviceCount: z.number().optional(),
  runningCount: z.number().optional(),
  composeContent: z.string().optional().describe(
    "Current compose file content",
  ),
  envContent: z.string().optional().meta({ sensitive: true }).describe(
    ".env content (may carry secrets, so marked sensitive)",
  ),
  observedAt: z.string(),
});

const ValidationResource = z.object({
  target: z.string().describe(
    "Project name or compose source that was validated",
  ),
  valid: z.boolean(),
  composeVersion: z.string().describe(
    "Local `docker compose` version used (surfaced so version skew vs Arcane stays visible)",
  ),
  detail: z.string().optional(),
  timestamp: z.string(),
});

const SwarmObjectResource = z.object({
  id: z.string(),
  name: z.string(),
  versionIndex: z.number().optional(),
  createdAt: z.string().optional(),
  action: Action,
  observedAt: z.string(),
});

const SwarmServiceResource = z.object({
  id: z.string(),
  name: z.string(),
  mode: z.string().optional(),
  replicas: z.number().optional(),
  runningReplicas: z.number().optional(),
  image: z.string().optional(),
  updateState: z.string().optional().describe(
    "State of the last rolling update (e.g. updating, completed, rollback_completed). " +
      "Set by swarm_service_get only; the list Arcane returns does not carry it.",
  ),
  action: Action,
  observedAt: z.string(),
});

const SwarmStackResource = z.object({
  id: z.string().optional(),
  name: z.string(),
  namespace: z.string().optional(),
  services: z.number().optional().describe("Number of services in the stack"),
  deletes: z.number().int().optional().describe(
    "Number of objects removed when the stack was deleted",
  ),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
  action: Action,
  observedAt: z.string(),
});

const SwarmStackRenderResource = z.object({
  name: z.string(),
  valid: z.boolean(),
  services: z.array(z.string()).default([]),
  networks: z.array(z.string()).default([]),
  volumes: z.array(z.string()).default([]),
  secrets: z.array(z.string()).default([]),
  configs: z.array(z.string()).default([]),
  warnings: z.array(z.string()).default([]),
  observedAt: z.string(),
});

const SwarmTaskResource = z.object({
  id: z.string(),
  serviceName: z.string(),
  slot: z.number().optional(),
  nodeName: z.string().optional(),
  desiredState: z.string().optional(),
  currentState: z.string().optional(),
  error: z.string().optional().describe(
    "Rejection/failure reason, when present (e.g. missing bind path, non-zero exit)",
  ),
  image: z.string().optional(),
  updatedAt: z.string().optional(),
  observedAt: z.string(),
});

const VolumeResource = z.object({
  id: z.string(),
  name: z.string(),
  driver: z.string().optional(),
  mountpoint: z.string().optional(),
  size: z.number().optional(),
  inUse: z.boolean().optional(),
  scope: z.string().optional(),
  action: Action,
  observedAt: z.string(),
});

const PruneResultResource = z.object({
  scope: z.string().describe("What was pruned: images | networks | volumes"),
  spaceReclaimed: z.number().optional().describe("Bytes reclaimed"),
  itemsDeleted: z.number().optional(),
  deleted: z.array(z.string()).default([]),
  observedAt: z.string(),
});

const API = "/api";
const REQUEST_TIMEOUT_MS = 30_000;
// Up, down, redeploy, pull, destroy and a GitOps sync answer only when Docker
// has finished, so they get longer than the 30 s an ordinary request gets.
// Arcane allows 10 min per image pull and 10 min for compose to come up, and 5
// min for a whole sync. Images are pulled one at a time and an operation can
// queue for an activity slot first, so a project with many images can still
// outlast this limit; the call then fails while Arcane carries on.
// project_deploy bounds its redeploys by healthTimeoutSec instead.
const OPERATION_TIMEOUT_MS = 30 * 60_000;

/**
 * A redeploy whose outcome is unknown: the call timed out, the connection broke,
 * a proxy answered instead of Arcane, or the stream ended without a done or
 * error line. Arcane may still be running it.
 */
class RedeployOutcomeUnknown extends Error {}

/**
 * Whether an error from `arcane()` is Arcane's own refusal, so the operation
 * did not go ahead. A 502, 503 or 504 is not: a reverse proxy sends them, and so
 * does Arcane when its call to a remote environment's agent fails, while the
 * operation may still be running. Nor is a timeout or a broken connection.
 */
function isDefiniteAnswer(message: string): boolean {
  const status = /-> HTTP (\d{3})/.exec(message)?.[1];
  return status !== undefined && !["502", "503", "504"].includes(status);
}

type GlobalArgsT = z.infer<typeof GlobalArgs>;
/** A parsed JSON object. */
export type Json = Record<string, unknown>;
type HttpResult = { status: number; body: string };
/** An HTTP verb used by the Arcane transport. */
export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

/** Low-level HTTPS/HTTP request returning the raw status and body text. */
function httpRequest(
  opts: https.RequestOptions,
  secure: boolean,
  timeoutMs: number,
  body?: string,
): Promise<HttpResult> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const transport = secure ? https : http;
  // Kept outside the response handler so a timeout can say what had arrived.
  const chunks: Buffer[] = [];
  return new Promise<HttpResult>((resolve, reject) => {
    const req = transport.request(opts, (res) => {
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString("utf8"),
        }));
      res.on("error", reject);
    });
    req.on("error", reject);
    // A limit on the whole request, not an idle one: up, pull and redeploy
    // stream progress lines, which would keep resetting an idle timer.
    timer = setTimeout(() => {
      // The last streamed line shows how far a long operation got.
      const lastLine = Buffer.concat(chunks).toString("utf8").trim()
        .split("\n").pop()?.slice(0, 500);
      req.destroy(
        new Error(
          `request timed out after ${timeoutMs} ms${
            lastLine ? `; last line received: ${lastLine}` : ""
          }`,
        ),
      );
    }, timeoutMs);
    if (body) req.write(body);
    req.end();
  }).finally(() => clearTimeout(timer));
}

/** Parse a JSON body, returning null for an empty body and the raw string if it isn't JSON. */
function safeJson(body: string): unknown {
  if (!body) return null;
  try {
    return JSON.parse(body);
  } catch {
    return body;
  }
}

/**
 * Why a streamed (NDJSON) Arcane operation failed, or undefined if it finished.
 * Arcane's project up, pull and redeploy answer 200 at once, then end the body
 * with `{"done":true}` on success or `{"error":"..."}` on failure, so the body
 * has to be read to know whether it worked. A body with neither was cut short.
 */
export function streamFailure(body: unknown): string | undefined {
  const end = streamEnd(body);
  if (end === undefined) return "the response ended without Arcane's done line";
  return end.error;
}

/** How a streamed Arcane body ended: done, an error line, or neither (undefined). */
function streamEnd(body: unknown): { error?: string } | undefined {
  const lines = typeof body === "string" ? body.split("\n") : [body];
  let done = false;
  for (const line of lines) {
    const obj = typeof line === "string" ? safeJson(line.trim()) : line;
    if (!obj || typeof obj !== "object") continue;
    if (typeof (obj as Json).error === "string") {
      return { error: (obj as Json).error as string };
    }
    if ((obj as Json).done === true) done = true;
  }
  return done ? {} : undefined;
}

/** Signature of the Arcane HTTP transport, swappable via {@link __setArcaneTransport}. */
export type ArcaneFn = (
  g: Json,
  method: HttpMethod,
  path: string,
  body?: unknown,
  timeoutMs?: number,
) => Promise<unknown>;

let _arcaneOverride: ArcaneFn | null = null;

/** Test-only seam: substitute the Arcane HTTP transport. Pass `null` to restore the real one. */
export function __setArcaneTransport(fn: ArcaneFn | null): void {
  _arcaneOverride = fn;
}

/**
 * Call an Arcane API path (relative to `/api`), throwing on any 4xx/5xx.
 * Returns the parsed JSON body (or null for empty responses). Routes through the
 * test seam when one is installed, otherwise the real HTTP transport.
 */
function arcane(
  g: GlobalArgsT,
  method: HttpMethod,
  path: string,
  body?: unknown,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<unknown> {
  return (_arcaneOverride ?? arcaneReal)(g, method, path, body, timeoutMs);
}

/** The real HTTP implementation behind `arcane()`. */
async function arcaneReal(
  g: GlobalArgsT,
  method: HttpMethod,
  path: string,
  body?: unknown,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<unknown> {
  const u = new URL(g.baseUrl.replace(/\/+$/, "") + API + path);
  const secure = u.protocol === "https:";
  let payload: string | undefined;
  let contentType = "application/json";
  if (body instanceof FormData) {
    // Response serialises the form and picks the boundary for the header.
    const form = new Response(body);
    payload = await form.text();
    contentType = form.headers.get("content-type") ?? "";
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
  }
  const headers: Record<string, string> = {
    "X-API-Key": g.apiKey,
    "Accept": "application/json",
  };
  if (payload) {
    headers["Content-Type"] = contentType;
    headers["Content-Length"] = String(Buffer.byteLength(payload));
  }
  const res = await httpRequest(
    {
      hostname: u.hostname,
      port: u.port ? parseInt(u.port, 10) : (secure ? 443 : 80),
      path: u.pathname + u.search,
      method,
      headers,
      rejectUnauthorized: !g.skipTlsVerify,
    },
    secure,
    timeoutMs,
    payload,
  );
  if (res.status >= 400) {
    throw new Error(
      `Arcane ${method} ${path} -> HTTP ${res.status}: ${res.body}`,
    );
  }
  return safeJson(res.body);
}

/**
 * Create a direct-mode project. `body` is `{name, composeContent, envContent?}`.
 * Arcane's project-create endpoint reads its JSON from multipart form fields (it
 * shares the workspace-upload form) and rejects a JSON body with 422. The empty
 * `manifest` says there are no extra workspace files to upload.
 */
async function createProject(g: GlobalArgsT, body: Json): Promise<Json> {
  const form = new FormData();
  form.append("project", JSON.stringify(body));
  form.append("manifest", JSON.stringify({ fileChanges: [] }));
  return unwrap(await arcane(g, "POST", `${ENV(g)}/projects`, form));
}

/** DELETE that treats 404 (already gone) as success, for idempotent pruning. */
async function deleteIfPresent(
  g: GlobalArgsT,
  path: string,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<void> {
  try {
    await arcane(g, "DELETE", path, undefined, timeoutMs);
  } catch (e) {
    if (e instanceof Error && /HTTP 404/.test(e.message)) return;
    throw e;
  }
}

/**
 * Extract an array from an Arcane list response that may be bare or wrapped.
 * Throws on any other shape: read as an empty list, a changed response would
 * make an ensure create duplicates and a lookup report "not found".
 */
export function coerceList(resp: unknown): Json[] {
  if (Array.isArray(resp)) return resp as Json[];
  if (resp && typeof resp === "object") {
    const o = resp as Record<string, unknown>;
    for (const k of ["data", "items", "results"]) {
      if (Array.isArray(o[k])) return o[k] as Json[];
    }
    // Arcane's envelope encodes an empty Go slice as `"data": null`.
    if (o.data === null) return [];
    if (o.data && typeof o.data === "object") {
      const d = o.data as Record<string, unknown>;
      for (const k of ["items", "results"]) {
        if (Array.isArray(d[k])) return d[k] as Json[];
      }
    }
  }
  throw new Error(
    `unrecognised list response from Arcane: ${
      JSON.stringify(resp)?.slice(0, 200)
    }`,
  );
}

/**
 * The id from a create response. Throws when there is none, because the object
 * may exist in Arcane even so, and an empty id would point later calls at the
 * wrong path.
 */
function createdId(created: Json, what: string): string {
  const id = asString(pick(created, "id", "ID"));
  if (!id) {
    throw new Error(
      `Arcane created ${what} but its answer had no id; check Arcane before retrying`,
    );
  }
  return id;
}

/**
 * Unwrap Arcane's `{ success, data }` envelope for single-object responses.
 * List responses are handled by `coerceList`; this is for create/get/inspect
 * where the payload (and its `id`) lives under `data`. Tolerates already-unwrapped
 * bodies (returns them unchanged).
 */
export function unwrap(resp: unknown): Json {
  if (resp && typeof resp === "object" && !Array.isArray(resp)) {
    const o = resp as Json;
    if (
      "data" in o && o.data && typeof o.data === "object" &&
      !Array.isArray(o.data)
    ) {
      return o.data as Json;
    }
    return o;
  }
  return {};
}

/** First defined value among the given keys (tolerates camelCase / snake_case drift). */
function pick(o: Json, ...keys: string[]): unknown {
  for (const k of keys) {
    if (o[k] !== undefined && o[k] !== null) return o[k];
  }
  return undefined;
}

function asString(v: unknown): string | undefined {
  return v === undefined || v === null ? undefined : String(v);
}

function asNumber(v: unknown): number | undefined {
  if (typeof v === "number") return v;
  if (typeof v === "string" && v.trim() !== "" && !Number.isNaN(Number(v))) {
    return Number(v);
  }
  return undefined;
}

/**
 * Data instance name for a record: `<spec>` for a single-instance record, else
 * `<spec>:<part>:<part>...`. swamp keys stored data by model + name, not spec,
 * so the spec goes into the name or two specs sharing a key overwrite each other.
 */
export function dataName(spec: string, ...keyParts: string[]): string {
  return [spec, ...keyParts.map(encodeKeyPart)].join(":");
}

/**
 * Percent-encode what swamp rejects in a name (`/`, `\`, `..`, NUL) and the `:`
 * separator. `%` is encoded too, so the mapping is reversible: two different
 * keys never share a name (unlike a slug, where `a-b` and `a.b` collide).
 */
function encodeKeyPart(s: string): string {
  return s
    .replace(
      /[%:\/\\\0]/g,
      (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`,
    )
    .replace(/\.(?=\.)/g, "%2E");
}

/** Structured info log when a logger is present (no-op otherwise). Never pass secrets. */
function logInfo(
  context: Pick<MethodContext<GlobalArgsT>, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.info?.(message, props ?? {});
}

const ENV = (g: GlobalArgsT): string => `/environments/${g.environmentId}`;

/** Managed fields of a sync, normalized for drift comparison. */
function syncView(o: Json): Record<string, unknown> {
  return {
    branch: pick(o, "branch"),
    composePath: pick(o, "composePath", "compose_path"),
    repositoryId: asString(pick(o, "repositoryId", "repository_id")),
    projectName: pick(o, "projectName", "project_name"),
    autoSync: pick(o, "autoSync", "auto_sync"),
    syncInterval: pick(o, "syncInterval", "sync_interval"),
    syncDirectory: pick(o, "syncDirectory", "sync_directory"),
    targetType: pick(o, "targetType", "target_type"),
  };
}

const sleep = (ms: number): Promise<void> =>
  new Promise((r) => setTimeout(r, ms));

type CmdResult = { code: number; stdout: string; stderr: string };

/** Run a local subprocess, capturing stdout/stderr and the exit code (never throws on non-zero). */
function runCommand(
  cmd: string,
  args: string[],
  cwd?: string,
): Promise<CmdResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, cwd ? { cwd } : {});
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => stdout += c.toString("utf8"));
    child.stderr.on("data", (c: Buffer) => stderr += c.toString("utf8"));
    child.on("error", reject);
    child.on(
      "close",
      (code: number | null) => resolve({ code: code ?? -1, stdout, stderr }),
    );
  });
}

/** Local `docker compose version --short`, or "unknown" if docker/compose is unavailable. */
async function dockerComposeVersion(): Promise<string> {
  try {
    const r = await runCommand("docker", ["compose", "version", "--short"]);
    return r.code === 0 ? r.stdout.trim() : "unknown";
  } catch {
    return "unknown";
  }
}

/** Signature of the local compose validator, swappable via {@link __setComposeValidator}. */
export type ValidateFn = (
  composeContent: string,
  envContent?: string,
) => Promise<{ version: string }>;

let _validateOverride: ValidateFn | null = null;

/** Test-only seam: substitute the local compose validator. Pass `null` to restore the real one. */
export function __setComposeValidator(fn: ValidateFn | null): void {
  _validateOverride = fn;
}

/**
 * Validate compose content with `docker compose config -q` on the swamp host,
 * never over SSH. Any non-zero exit throws with the validator's stderr. Returns
 * the local compose version, because it can differ from the version Arcane
 * deploys with and that difference should stay visible. Routes
 * through the test seam when one is installed.
 */
function composeConfigValidate(
  composeContent: string,
  envContent?: string,
): Promise<{ version: string }> {
  return (_validateOverride ?? composeConfigValidateReal)(
    composeContent,
    envContent,
  );
}

/** The real `docker compose config` implementation behind `composeConfigValidate()`. */
async function composeConfigValidateReal(
  composeContent: string,
  envContent?: string,
): Promise<{ version: string }> {
  const dir = await mkdtemp(join(tmpdir(), "arcane-validate-"));
  try {
    const composeFile = join(dir, "compose.yaml");
    await writeFile(composeFile, composeContent, "utf8");
    if (envContent !== undefined) {
      await writeFile(join(dir, ".env"), envContent, "utf8");
    }
    let r: CmdResult;
    try {
      r = await runCommand("docker", [
        "compose",
        "-f",
        composeFile,
        "config",
        "-q",
      ], dir);
    } catch (e) {
      throw new Error(
        `compose validation could not run (is the docker CLI with the compose v2 plugin installed on the swamp host?): ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
    if (r.code !== 0) {
      throw new Error(
        `compose validation failed: \`docker compose config\` exited ${r.code}\n${
          (r.stderr || r.stdout).trim()
        }`,
      );
    }
    return { version: await dockerComposeVersion() };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * Resolve a `{ composePath?|composeContent?, envPath?|envContent? }` argument set
 * into concrete content. Exactly one of composePath/composeContent must be present;
 * env is optional. Local file reads only (no remote I/O).
 */
async function resolveComposeInput(
  args: {
    composePath?: string;
    composeContent?: string;
    envPath?: string;
    envContent?: string;
  },
): Promise<{ composeContent: string; envContent?: string }> {
  let composeContent: string;
  if (args.composeContent !== undefined && args.composePath !== undefined) {
    throw new Error("provide either composePath or composeContent, not both");
  } else if (args.composeContent !== undefined) {
    composeContent = args.composeContent;
  } else if (args.composePath !== undefined) {
    composeContent = await readFile(args.composePath, "utf8");
  } else {
    throw new Error("one of composePath or composeContent is required");
  }
  let envContent: string | undefined;
  if (args.envContent !== undefined && args.envPath !== undefined) {
    throw new Error("provide either envPath or envContent, not both");
  } else if (args.envContent !== undefined) {
    envContent = args.envContent;
  } else if (args.envPath !== undefined) {
    envContent = await readFile(args.envPath, "utf8");
  }
  return { composeContent, envContent };
}

/**
 * Every project, archived ones included. Arcane's list leaves archived projects
 * out by default, so a lookup by name would call one "not found", and a deploy
 * would try to create it again.
 */
const ALL_PROJECTS = "/projects?limit=-1&archived=all";

/**
 * The values in `.env` content, so they can be masked out of error and record
 * text: `docker compose` and Arcane quote an interpolated value in some errors
 * (`invalid containerPort: <value>`). Values shorter than four characters are
 * left alone, because masking a `1` or `80` would garble every message.
 */
export function envValues(envContent: string): string[] {
  const values: string[] = [];
  for (const raw of envContent.split("\n")) {
    const line = raw.trim().replace(/^export\s+/, "");
    const eq = line.indexOf("=");
    if (line.startsWith("#") || eq < 1) continue;
    let value = line.slice(eq + 1).trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.endsWith(quote)) {
      value = value.slice(1, -1);
    }
    if (value.length >= 4) values.push(value);
  }
  return values;
}

/** Replace each of `values` in `text` with `[redacted]`, longest first. */
export function maskValues(text: string, values: string[]): string {
  return [...values].sort((a, b) => b.length - a.length)
    .reduce((t, v) => t.replaceAll(v, "[redacted]"), text);
}

/** A masker for the `.env` a method was given inline or by path. */
async function envMasker(
  args: { envContent?: string; envPath?: string },
): Promise<(text: string) => string> {
  const content = args.envContent ??
    (args.envPath !== undefined ? await readFile(args.envPath, "utf8") : "");
  const values = envValues(content);
  return (text) => maskValues(text, values);
}

/**
 * Wrap a method that takes `.env` content so any error it throws has the
 * `.env` values masked out, since swamp shows and stores the error text.
 */
function maskingEnv<A extends { envContent?: string; envPath?: string }>(
  execute: (
    args: A,
    context: MethodContext<GlobalArgsT>,
  ) => Promise<{ dataHandles: DataHandle[] }>,
): (
  args: A,
  context: MethodContext<GlobalArgsT>,
) => Promise<{ dataHandles: DataHandle[] }> {
  return async (args, context) => {
    try {
      return await execute(args, context);
    } catch (e) {
      const mask = await envMasker(args);
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(mask(msg));
    }
  };
}

/** Find a project by name; returns the raw Arcane project object or undefined. */
async function findProject(
  g: GlobalArgsT,
  name: string,
): Promise<Json | undefined> {
  const projects = coerceList(
    await arcane(g, "GET", `${ENV(g)}${ALL_PROJECTS}`),
  );
  return projects.find((p) => asString(pick(p, "name")) === name);
}

/** Resolve a project name to its id, throwing a clear error if absent. */
async function resolveProjectId(g: GlobalArgsT, name: string): Promise<string> {
  const p = await findProject(g, name);
  const id = p && asString(pick(p, "id"));
  if (!id) throw new Error(`project '${name}' not found in Arcane`);
  return id;
}

/** Shape an Arcane project-detail (`/projects/{id}/compose`) response into a `project-detail` resource. */
function projectDetail(
  name: string,
  id: string,
  d: Json,
): Record<string, unknown> {
  return {
    id,
    name,
    status: asString(pick(d, "status", "state")) ?? "unknown",
    gitOpsManagedBy: asString(pick(d, "gitOpsManagedBy", "gitops_managed_by")),
    serviceCount: asNumber(pick(d, "serviceCount", "service_count")),
    runningCount: asNumber(pick(d, "runningCount", "running_count")),
    composeContent: asString(pick(d, "composeContent", "compose_content")),
    envContent: asString(pick(d, "envContent", "env_content")),
    observedAt: new Date().toISOString(),
  };
}

type HealthResult = { healthy: boolean; status: string; detail: string };

/**
 * Pure predicate: is a compose project healthy? Status must be `running`, no runtime
 * service may report `unhealthy` or `starting`, and (when Arcane reports counts)
 * runningCount must cover serviceCount. Separate from the poller so it can be unit-tested.
 */
export function projectHealthy(
  status: string,
  serviceCount: number,
  runningCount: number,
  anyNotHealthy: boolean,
): boolean {
  return status === "running" && !anyNotHealthy &&
    (serviceCount === 0 || runningCount >= serviceCount);
}

/**
 * Poll a project until its containers are running (status `running` and, when
 * Arcane reports counts, runningCount >= serviceCount) on two checks in a row,
 * or the timeout elapses. A service whose healthcheck reports `unhealthy` or is
 * still `starting` keeps it waiting, so a container crash-looping behind a slow
 * healthcheck does not pass. The second check catches a container with no
 * healthcheck that is caught running between restarts. Returns the last
 * observed state.
 */
async function pollProjectHealthy(
  g: GlobalArgsT,
  id: string,
  timeoutSec: number,
  intervalSec: number,
): Promise<HealthResult> {
  const deadline = Date.now() + timeoutSec * 1000;
  let last: HealthResult;
  let healthyChecks = 0;
  while (true) {
    // A failed read says nothing about the deploy, so it counts as not healthy
    // and the poll carries on to the deadline rather than failing (which would
    // roll back a deploy that may be fine).
    let p: Json = {};
    let projectError: string | undefined;
    try {
      p = unwrap(await arcane(g, "GET", `${ENV(g)}/projects/${id}`));
    } catch (e) {
      projectError = e instanceof Error ? e.message : String(e);
    }
    const status = asString(pick(p, "status", "state")) ?? "unknown";
    const serviceCount = Number(pick(p, "serviceCount") ?? 0);
    const runningCount = Number(pick(p, "runningCount") ?? 0);
    let notHealthy: string[] = [];
    let runtimeError: string | undefined;
    try {
      const rt = unwrap(
        await arcane(g, "GET", `${ENV(g)}/projects/${id}/runtime`),
      );
      const services = Array.isArray(pick(rt, "runtimeServices"))
        ? (pick(rt, "runtimeServices") as Json[])
        : [];
      notHealthy = services
        .map((s) => asString(pick(s, "health")) ?? "")
        .filter((h) => h === "unhealthy" || h === "starting");
    } catch (e) {
      // Without the runtime view the healthchecks are unknown, so keep waiting.
      runtimeError = e instanceof Error ? e.message : String(e);
    }
    const healthyNow = projectError === undefined &&
      runtimeError === undefined &&
      projectHealthy(status, serviceCount, runningCount, notHealthy.length > 0);
    healthyChecks = healthyNow ? healthyChecks + 1 : 0;
    last = {
      healthy: healthyChecks >= 2,
      status,
      detail: `status=${status} running=${runningCount}/${serviceCount}${
        notHealthy.length > 0 ? ` (health: ${notHealthy.join(", ")})` : ""
      }${projectError ? ` (project read failed: ${projectError})` : ""}${
        runtimeError ? ` (runtime view failed: ${runtimeError})` : ""
      }${healthyChecks === 1 ? " (healthy once, not yet confirmed)" : ""}`,
    };
    if (last.healthy || Date.now() >= deadline) return last;
    await sleep(Math.min(intervalSec * 1000, deadline - Date.now()));
  }
}

/**
 * Redeploy a project, then poll it until healthy, all within `timeoutSec`. Arcane
 * holds the redeploy open until compose finishes, which can be never (a
 * `depends_on: service_healthy` that never comes), so the call shares the budget
 * instead of getting its own. Arcane may still be running compose after the call
 * gives up.
 */
async function redeployAndPoll(
  g: GlobalArgsT,
  id: string,
  timeoutSec: number,
  intervalSec: number,
): Promise<HealthResult> {
  const deadline = Date.now() + timeoutSec * 1000;
  let body: unknown;
  try {
    body = await arcane(
      g,
      "POST",
      `${ENV(g)}/projects/${id}/redeploy`,
      undefined,
      timeoutSec * 1000,
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (isDefiniteAnswer(msg)) throw e;
    throw new RedeployOutcomeUnknown(
      /request timed out/.test(msg)
        ? `redeploy did not finish within healthTimeoutSec (${timeoutSec}s); Arcane may still be running it (${msg})`
        : `redeploy got no answer from Arcane (${msg}); Arcane may still be running it`,
    );
  }
  const end = streamEnd(body);
  if (end === undefined) {
    throw new RedeployOutcomeUnknown(
      "redeploy response ended without a done or error line; Arcane may still be running it",
    );
  }
  if (end.error !== undefined) throw new Error(`redeploy failed: ${end.error}`);
  const leftSec = Math.max(0, (deadline - Date.now()) / 1000);
  return await pollProjectHealthy(g, id, leftSec, intervalSec);
}

/**
 * Run one GitOps sync and return why it failed, or undefined if it succeeded.
 * Arcane runs the sync (git pull, and a redeploy when the content changed)
 * inside the request and answers 200 even when the sync fails or another run of
 * it is already in progress, so the body's `success` decides, not the status.
 */
async function runSync(
  g: GlobalArgsT,
  id: string,
): Promise<string | undefined> {
  const result = unwrap(
    await arcane(
      g,
      "POST",
      `${ENV(g)}/gitops-syncs/${id}/sync`,
      undefined,
      OPERATION_TIMEOUT_MS,
    ),
  );
  if (pick(result, "success") === true) return undefined;
  const message = asString(pick(result, "message")) ?? "sync failed";
  const error = asString(pick(result, "error"));
  return error ? `${message}: ${error}` : message;
}

/** swamp's `deleteResource`, which the pinned swamp-testing types predate. */
type CanDeleteResource = {
  deleteResource: (instanceName: string) => Promise<void>;
};

/**
 * Delete the step records in `candidates` that this run did not write. Each
 * step has its own record, so without this the latest records would mix this
 * run's steps with steps an earlier run reached and this one did not.
 */
async function deleteUnreachedSteps(
  context: unknown,
  candidates: string[],
  written: Set<string>,
): Promise<void> {
  for (const name of candidates) {
    if (!written.has(name)) {
      await (context as CanDeleteResource).deleteResource(name);
    }
  }
}

/** Every step `project_deploy` can record. */
const DEPLOY_STEPS = [
  "validate",
  "sync",
  "create",
  "update",
  "redeploy",
  "health",
  "apply",
  "rollback",
];

/** Every step `swarm_stack_deploy` can record. */
const STACK_DEPLOY_STEPS = ["validate", "deploy", "converge"];

/** UTF-8 → base64, for the write-only `Data` field of a swarm secret/config spec. */
export const b64 = (s: string): string =>
  Buffer.from(s, "utf8").toString("base64");

/**
 * Confirm the target environment is swarm-enabled before a swarm operation.
 * Arcane also enforces manager rights (a non-manager mutation returns 403, which
 * `arcane()` surfaces); this check fails earlier with a clearer message.
 */
async function ensureSwarmManager(g: GlobalArgsT): Promise<void> {
  let enabled = false;
  try {
    const s = unwrap(await arcane(g, "GET", `${ENV(g)}/swarm/status`));
    enabled = pick(s, "enabled") === true;
  } catch (e) {
    throw new Error(
      `could not read swarm status for environment ${g.environmentId}: ${
        e instanceof Error ? e.message : String(e)
      }`,
    );
  }
  if (!enabled) {
    throw new Error(
      `environment ${g.environmentId} is not swarm-enabled; point environmentId at a swarm-manager environment. ` +
        "Arcane stores this flag and refreshes it only at startup, so a swarm created outside Arcane needs an Arcane restart first.",
    );
  }
}

/** Find a swarm secret/config by its spec Name; returns the raw summary or undefined. */
async function findSwarmObject(
  g: GlobalArgsT,
  plural: "secrets" | "configs",
  name: string,
): Promise<Json | undefined> {
  const rows = coerceList(await arcane(g, "GET", `${ENV(g)}/swarm/${plural}`));
  return rows.find((r) => {
    const spec = (pick(r, "spec") as Json) ?? {};
    return asString(pick(spec, "Name", "name")) === name ||
      asString(pick(r, "name", "Name")) === name;
  });
}

/** Find a swarm service by name; returns the raw summary or undefined. */
async function findSwarmService(
  g: GlobalArgsT,
  name: string,
): Promise<Json | undefined> {
  const rows = coerceList(
    await arcane(g, "GET", `${ENV(g)}/swarm/services?limit=-1`),
  );
  return rows.find((r) => asString(pick(r, "name")) === name);
}

/** Shape a swarm secret/config summary into a `swarm-secret`/`swarm-config` resource. */
function swarmObjectResource(o: Json, action: string): Record<string, unknown> {
  const spec = (pick(o, "spec") as Json) ?? {};
  const version = pick(o, "version") as Json | undefined;
  return {
    id: asString(pick(o, "id", "ID")) ?? "",
    name: asString(pick(spec, "Name", "name")) ?? asString(pick(o, "name")) ??
      "unnamed",
    versionIndex: version
      ? asNumber(pick(version, "Index", "index"))
      : undefined,
    createdAt: asString(pick(o, "createdAt", "created_at")),
    action,
    observedAt: new Date().toISOString(),
  };
}

/**
 * Shape a swarm service summary into a `swarm-service` resource. A summary has
 * no update status; pass the service's inspect answer as `inspect` to fill
 * `updateState`.
 */
function swarmServiceResource(
  o: Json,
  action: string,
  inspect?: Json,
): Record<string, unknown> {
  const updateStatus = inspect
    ? pick(inspect, "updateStatus") as Json | undefined
    : undefined;
  return {
    id: asString(pick(o, "id", "ID")) ?? "",
    name: asString(pick(o, "name")) ?? "unnamed",
    mode: asString(pick(o, "mode")),
    replicas: asNumber(pick(o, "replicas")),
    runningReplicas: asNumber(pick(o, "runningReplicas", "running_replicas")),
    image: asString(pick(o, "image")),
    updateState: updateStatus
      ? asString(pick(updateStatus, "State", "state"))
      : undefined,
    action,
    observedAt: new Date().toISOString(),
  };
}

/**
 * Re-point a swarm ServiceSpec's references to a rotated object from the old name to
 * the new id+name, preserving the mount target (`File.Name`). Mutates `spec` in place.
 * Returns how many references were rewritten. Pure (no I/O); unit-tested.
 */
export function repointServiceRefs(
  spec: Json,
  kind: "secret" | "config",
  oldName: string,
  newId: string,
  newName: string,
): number {
  const refs = serviceRefs(spec, kind, oldName);
  for (const ref of refs) {
    ref[kind === "secret" ? "SecretID" : "ConfigID"] = newId;
    ref[kind === "secret" ? "SecretName" : "ConfigName"] = newName;
  }
  return refs.length;
}

/** The references in a swarm ServiceSpec to the secret or config named `name`. */
function serviceRefs(
  spec: Json,
  kind: "secret" | "config",
  name: string,
): Json[] {
  const nameKey = kind === "secret" ? "SecretName" : "ConfigName";
  const tt = pick(spec, "TaskTemplate") as Json | undefined;
  const cs = tt ? (pick(tt, "ContainerSpec") as Json | undefined) : undefined;
  const refs = cs
    ? pick(cs, kind === "secret" ? "Secrets" : "Configs")
    : undefined;
  if (!Array.isArray(refs)) return [];
  return (refs as Json[]).filter((ref) =>
    asString(pick(ref, nameKey)) === name
  );
}

type ConvergeResult = { converged: boolean; detail: string };

/**
 * Pure predicate: how is a swarm service's rolling update going? `failed` for a
 * paused/rolled-back update; `converged` when the update `completed` and replicas
 * are satisfied; otherwise `pending`.
 *
 * Swarm clears a service's update status on every update and sets it again only
 * once the rolling update starts, so straight after a change there is no status
 * while the old tasks still run. With `updateExpected`, no status therefore means
 * the update has not started yet. A service with no replicas is the exception:
 * it has no tasks to replace, so swarm never sets a status for it. Unit-tested.
 */
export function serviceConvergence(
  state: string | undefined,
  hasUpdateStatus: boolean,
  replicas: number | undefined,
  running: number | undefined,
  updateExpected: boolean,
): "converged" | "failed" | "pending" {
  if (
    state === "paused" || state === "rollback_completed" ||
    state === "rollback_paused"
  ) {
    return "failed";
  }
  const updateOk = hasUpdateStatus
    ? state === "completed"
    : !updateExpected || replicas === 0;
  const replicasOk = replicas === undefined ||
    (running !== undefined && running >= replicas);
  return updateOk && replicasOk ? "converged" : "pending";
}

/**
 * Poll a swarm service, just changed by a PUT, until its rolling update
 * completes and replicas are running, or the timeout elapses. Converged =
 * `State == completed` and (when the summary reports counts) runningReplicas >=
 * replicas; see {@link serviceConvergence} for why no status is not enough. A
 * paused/rolled-back update returns not-converged immediately.
 */
async function pollServiceConverged(
  g: GlobalArgsT,
  serviceId: string,
  timeoutSec: number,
  intervalSec: number,
): Promise<ConvergeResult> {
  const deadline = Date.now() + timeoutSec * 1000;
  let detail: string;
  while (true) {
    // A failed read says nothing about the update, so it counts as pending and
    // the poll carries on to the deadline. Without the summary the replica
    // counts are unknown, which would otherwise pass the replica check.
    let readError: string | undefined;
    let insp: Json = {};
    try {
      insp = unwrap(
        await arcane(g, "GET", `${ENV(g)}/swarm/services/${serviceId}`),
      );
    } catch (e) {
      readError = e instanceof Error ? e.message : String(e);
    }
    const us = pick(insp, "updateStatus") as Json | undefined;
    const state = us ? asString(pick(us, "State", "state")) : undefined;
    let replicas: number | undefined;
    let running: number | undefined;
    try {
      const list = coerceList(
        await arcane(g, "GET", `${ENV(g)}/swarm/services?limit=-1`),
      );
      const svc = list.find((s) => asString(pick(s, "id", "ID")) === serviceId);
      if (svc) {
        replicas = asNumber(pick(svc, "replicas"));
        running = asNumber(pick(svc, "runningReplicas", "running_replicas"));
      }
    } catch (e) {
      readError ??= e instanceof Error ? e.message : String(e);
    }
    detail = `updateState=${state ?? "none"} running=${running ?? "?"}/${
      replicas ?? "?"
    }${readError ? ` (read failed: ${readError})` : ""}`;
    const verdict = readError !== undefined
      ? "pending"
      : serviceConvergence(state, !!us, replicas, running, true);
    if (verdict === "failed") return { converged: false, detail };
    if (verdict === "converged") return { converged: true, detail };
    if (Date.now() >= deadline) return { converged: false, detail };
    // Stop at the deadline rather than sleep past it, so a long interval still
    // gets a last look.
    await sleep(Math.min(intervalSec * 1000, deadline - Date.now()));
  }
}

/** Shape a swarm stack summary/inspect object into a `swarm-stack` resource. */
export function swarmStackResource(
  o: Json,
  action: string,
): Record<string, unknown> {
  return {
    id: asString(pick(o, "id", "ID")),
    name: asString(pick(o, "name", "Name")) ?? "unnamed",
    namespace: asString(pick(o, "namespace")),
    services: asNumber(pick(o, "services")),
    createdAt: asString(pick(o, "createdAt", "created_at")),
    updatedAt: asString(pick(o, "updatedAt", "updated_at")),
    action,
    observedAt: new Date().toISOString(),
  };
}

/** Shape a swarm task object into a `swarm-task` resource (state + error for deploy debugging). */
export function swarmTaskResource(o: Json): Record<string, unknown> {
  return {
    id: asString(pick(o, "id", "ID")) ?? "",
    serviceName: asString(pick(o, "serviceName", "service_name")) ?? "unknown",
    slot: asNumber(pick(o, "slot")),
    nodeName: asString(pick(o, "nodeName", "node_name")),
    desiredState: asString(pick(o, "desiredState", "desired_state")),
    currentState: asString(pick(o, "currentState", "current_state")),
    error: asString(pick(o, "error")),
    image: asString(pick(o, "image")),
    updatedAt: asString(pick(o, "updatedAt", "updated_at")),
    observedAt: new Date().toISOString(),
  };
}

/** Shape a docker volume object into a `volume` resource. */
export function volumeResource(
  o: Json,
  action: string,
): Record<string, unknown> {
  return {
    id: asString(pick(o, "id", "ID", "name", "Name")) ?? "",
    name: asString(pick(o, "name", "Name")) ?? "unnamed",
    driver: asString(pick(o, "driver", "Driver")),
    mountpoint: asString(pick(o, "mountpoint", "Mountpoint")),
    size: asNumber(pick(o, "size", "Size")),
    inUse: pick(o, "inUse", "InUse") as boolean | undefined,
    scope: asString(pick(o, "scope", "Scope")),
    action,
    observedAt: new Date().toISOString(),
  };
}

/** Shape a docker prune response into a `prune-result` resource (space + deleted names). */
export function pruneResult(scope: string, raw: Json): Record<string, unknown> {
  const names: string[] = [];
  for (
    const k of [
      "volumesDeleted",
      "imagesDeleted",
      "networksDeleted",
      "containersDeleted",
      "deleted",
    ]
  ) {
    const v = pick(raw, k);
    if (Array.isArray(v)) {
      for (const it of v) {
        if (typeof it === "string") names.push(it);
        else if (it && typeof it === "object") {
          const n = asString(
            pick(it as Json, "name", "Name", "id", "ID", "Deleted", "Untagged"),
          );
          if (n) names.push(n);
        }
      }
    }
  }
  return {
    scope,
    spaceReclaimed: asNumber(pick(raw, "spaceReclaimed", "space_reclaimed")),
    itemsDeleted: names.length,
    deleted: names,
    observedAt: new Date().toISOString(),
  };
}

/**
 * Extract names from a swarm-stack render-result array whose items may be plain
 * strings (e.g. warnings) or objects ({Name}/{name}/{id}). Tolerates null.
 */
export function renderNames(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item === "string") {
      out.push(item);
    } else if (item && typeof item === "object") {
      const n = asString(pick(item as Json, "name", "Name", "id", "ID"));
      if (n) out.push(n);
    }
  }
  return out;
}

type StackConvergeResult = { converged: boolean; detail: string };

/**
 * Poll a swarm stack's services, just deployed, until each has runningReplicas >=
 * replicas and no rolling update still running, or the timeout elapses. Reads GET
 * /swarm/stacks/{name}/services for the counts and inspects each service for its
 * update status, which the summaries lack. A paused or rolled-back update returns
 * not-converged at once. A stack with no services reported yet counts as
 * not-converged. Returns the last observed state.
 *
 * Arcane updates every existing service on a redeploy, and swarm clears each
 * one's update status until its rolling update starts, so the first look waits
 * one interval: straight after the deploy the old tasks would pass. An unchanged
 * service never gets a status, so after that wait no status means nothing to roll.
 */
async function pollStackConverged(
  g: GlobalArgsT,
  stackName: string,
  timeoutSec: number,
  intervalSec: number,
): Promise<StackConvergeResult> {
  const deadline = Date.now() + timeoutSec * 1000;
  const enc = encodeURIComponent(stackName);
  let detail = "no observation";
  await sleep(Math.min(intervalSec * 1000, timeoutSec * 1000));
  while (true) {
    const services = coerceList(
      await arcane(g, "GET", `${ENV(g)}/swarm/stacks/${enc}/services?limit=-1`),
    );
    if (services.length === 0) {
      detail = "no services reported yet";
    } else {
      const parts: string[] = [];
      let allUp = true;
      for (const s of services) {
        const name = asString(pick(s, "name", "Name")) ?? "?";
        const replicas = asNumber(pick(s, "replicas"));
        const running = asNumber(
          pick(s, "runningReplicas", "running_replicas"),
        );
        const id = asString(pick(s, "id", "ID")) ?? "";
        const insp = unwrap(
          await arcane(g, "GET", `${ENV(g)}/swarm/services/${id}`),
        );
        const us = pick(insp, "updateStatus") as Json | undefined;
        const state = us ? asString(pick(us, "State", "state")) : undefined;
        parts.push(
          `${name} ${running ?? "?"}/${replicas ?? "?"}${
            state ? ` update=${state}` : ""
          }`,
        );
        const verdict = serviceConvergence(
          state,
          !!us,
          replicas,
          running,
          false,
        );
        if (verdict === "failed") {
          return { converged: false, detail: parts.join(", ") };
        }
        if (
          verdict === "pending" || replicas === undefined ||
          running === undefined
        ) {
          allUp = false;
        }
      }
      detail = parts.join(", ");
      if (allUp) return { converged: true, detail };
    }
    if (Date.now() >= deadline) return { converged: false, detail };
    await sleep(Math.min(intervalSec * 1000, deadline - Date.now()));
  }
}

/** True if Arcane no longer has a stored record for the stack (GET → 404). */
async function stackGone(g: GlobalArgsT, path: string): Promise<boolean> {
  try {
    await arcane(g, "GET", path);
    return false;
  } catch (e) {
    if (e instanceof Error && /HTTP 404/.test(e.message)) return true;
    throw e;
  }
}

/**
 * Remove a swarm stack and confirm the record is actually cleared, returning the
 * number of DELETEs issued. Arcane deletes its stored stack record last and answers
 * 404 for a not-found error from any earlier step, so the first DELETE can answer
 * 404 with the stack still listed. This function therefore DELETEs, checks the stack
 * GET, and re-issues DELETE until the GET 404s. A non-404 DELETE error (e.g. an
 * in-use conflict) propagates immediately and is never forced. If the record is
 * still present at the deadline it throws rather than report success.
 */
async function pollStackRemoved(
  g: GlobalArgsT,
  name: string,
  timeoutSec: number,
  intervalSec: number,
): Promise<number> {
  const path = `${ENV(g)}/swarm/stacks/${encodeURIComponent(name)}`;
  const deadline = Date.now() + timeoutSec * 1000;
  let deletes = 0;
  while (true) {
    await deleteIfPresent(g, path);
    deletes++;
    if (await stackGone(g, path)) return deletes;
    if (Date.now() >= deadline) {
      throw new Error(
        `Swarm stack "${name}" record still present after ${deletes} delete(s) ` +
          `within ${timeoutSec}s; Arcane did not clear it.`,
      );
    }
    await sleep(Math.min(intervalSec * 1000, deadline - Date.now()));
  }
}

// ---------------------------------------------------------------------------
// Per-method argument schemas.
//
// Each method's `arguments` schema is named here and used for both the method's
// `arguments:` field and its `execute` parameter type (`z.infer<typeof ...>`).
// Swamp validates `args` against the schema before calling `execute`, so the
// inferred type matches the validated input.
// ---------------------------------------------------------------------------

/** Shared: a single required `name`. */
const NameArg = z.object({ name: z.string() });

const GitopsSyncEnsureArgs = z.object({
  prune: z.boolean().default(false).describe(
    "Delete existing deploy syncs whose name is not in globalArgs.syncs (destructive). Backup syncs are never pruned.",
  ),
});

const GitopsSyncTriggerArgs = z.object({
  names: z.array(z.string()).default([]).describe(
    "Sync names to trigger; empty means every deploy sync (a backup sync runs only when named)",
  ),
});

const GitopsRepoDeleteArgs = z.object({
  name: z.string().describe("Name of the git repository connection to delete"),
});

const GitopsSyncStatusArgs = z.object({
  names: z.array(z.string()).default([]).describe(
    "Sync names to check; empty means all",
  ),
});

const ProjectValidateArgs = z.object({
  target: z.string().optional().describe(
    "Label for the result (defaults to composePath or 'inline')",
  ),
  composePath: z.string().optional().describe("Path to a local compose file"),
  composeContent: z.string().optional().describe(
    "Inline compose content (instead of composePath). Not sensitive: put secrets in envContent and reference them as ${VAR}",
  ),
  envPath: z.string().optional().describe("Path to a local .env file"),
  envContent: z.string().optional().meta({ sensitive: true }).describe(
    "Inline .env content (instead of envPath); may carry secrets, so it is marked sensitive",
  ),
});

const ProjectGetArgs = z.object({
  name: z.string().describe("Project name"),
});

const ProjectCreateArgs = z.object({
  name: z.string().describe("Project name"),
  composePath: z.string().optional(),
  composeContent: z.string().optional(),
  envPath: z.string().optional(),
  envContent: z.string().optional().meta({ sensitive: true }),
});

const ProjectUpdateArgs = z.object({
  name: z.string().describe("Project name"),
  composePath: z.string().optional(),
  composeContent: z.string().optional(),
  envPath: z.string().optional(),
  envContent: z.string().optional().meta({ sensitive: true }),
});

const ProjectDeployArgs = z.object({
  name: z.string().describe("Project name"),
  composePath: z.string().optional().describe(
    "Direct mode: new compose file to deploy",
  ),
  composeContent: z.string().optional().describe(
    "Direct mode: inline compose content. Not sensitive: put secrets in envContent and reference them as ${VAR}",
  ),
  envPath: z.string().optional(),
  envContent: z.string().optional().meta({ sensitive: true }),
  rollback: z.boolean().default(true).describe(
    "Roll back to prior state on failure (direct mode). false = stop and report, leaving the failed state for inspection.",
  ),
  healthTimeoutSec: z.number().int().positive().max(86_400).default(300)
    .describe(
      "How long the redeploy and the wait for the project to become healthy may take together. A rollback gets the same time again.",
    ),
  pollIntervalSec: z.number().int().positive().max(3600).default(5),
});

const SwarmServiceForceUpdateArgs = z.object({
  name: z.string().describe("Swarm service name (e.g. unifi_unifi)"),
  convergeTimeoutSec: z.number().int().positive().max(86_400).default(180),
  pollIntervalSec: z.number().int().positive().max(3600).default(5),
});

const SwarmStackValidateArgs = z.object({
  name: z.string().describe("Stack name"),
  composePath: z.string().optional(),
  composeContent: z.string().optional(),
  envPath: z.string().optional(),
  envContent: z.string().optional().meta({ sensitive: true }),
});

const SwarmStackDeployArgs = z.object({
  name: z.string().describe("Stack name"),
  composePath: z.string().optional(),
  composeContent: z.string().optional(),
  envPath: z.string().optional(),
  envContent: z.string().optional().meta({ sensitive: true }),
  prune: z.boolean().default(false).describe(
    "Remove services no longer present in the compose file",
  ),
  convergeTimeoutSec: z.number().int().positive().max(86_400).default(180),
  pollIntervalSec: z.number().int().positive().max(3600).default(5),
});

const SwarmStackRemoveArgs = z.object({
  name: z.string(),
  removeTimeoutSec: z.number().int().positive().max(86_400).default(30)
    .describe(
      "Max seconds to keep re-issuing DELETE until the stack record 404s",
    ),
  pollIntervalSec: z.number().int().positive().max(3600).default(2),
});

const SwarmStackTasksArgs = z.object({
  name: z.string().describe("Stack name"),
  onlyProblems: z.boolean().default(false).describe(
    "Emit only tasks whose currentState is rejected/failed/orphaned (the error-bearing ones)",
  ),
});

// No `force`: Docker refuses an in-use volume before it looks at the flag, so
// it could not do what callers would expect. A stale `force` is stripped.
const VolumeRemoveArgs = z.object({
  name: z.string(),
});

const ImagePruneArgs = z.object({
  dangling: z.boolean().default(true).describe(
    "true = only dangling layers (safe); false = all unused images",
  ),
});

const LifecycleArgs = z.object({
  names: z.array(z.string()).min(1).describe("Project names to operate on"),
});

/** The `@thomas/arcane` swamp model: schema, methods, and lifecycle for managing Docker via Arcane. */
export const model = {
  type: "@thomas/arcane",
  version: "2026.10.11.1",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify the Arcane API authenticates (GET /auth/me with the X-API-Key). Warns when baseUrl is http://, which sends the key in clear text.",
      labels: ["live"],
      execute: async (
        context:
          & Pick<MethodContext<GlobalArgsT>, "globalArgs">
          & Partial<Pick<MethodContext<GlobalArgsT>, "logger">>,
      ) => {
        // Checks get globalArgs without the schema's defaults; parse to apply them.
        const parsed = GlobalArgs.safeParse(context.globalArgs);
        if (!parsed.success) {
          return { pass: false, errors: [z.prettifyError(parsed.error)] };
        }
        const g = parsed.data;
        // Not a failure: a test bed on a trusted network may use http.
        if (/^http:\/\//i.test(g.baseUrl)) {
          context.logger?.warn(
            "Arcane base URL {baseUrl} uses http, so the API key is sent in clear text",
            { baseUrl: g.baseUrl },
          );
        }
        try {
          // /version is registered without security in Arcane, so it would pass
          // with a wrong key. /auth/me needs a valid key and no permission.
          await arcane(g, "GET", "/auth/me");
          return { pass: true };
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          // A 401 or 403 means Arcane answered and turned the key down.
          const rejected = /-> HTTP 40[13]\b/.test(msg);
          return {
            pass: false,
            errors: [
              rejected
                ? `Arcane at ${g.baseUrl} rejected the API key: ${msg}`
                : `Cannot reach Arcane at ${g.baseUrl}: ${msg}`,
            ],
          };
        }
      },
    },
  },
  upgrades: [
    {
      toVersion: "2026.05.21.1",
      description: "No change to global arguments or stored data.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.05.22.1",
      description: "No change to global arguments or stored data.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.05.23.1",
      description: "No change to global arguments or stored data.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.05.24.1",
      description: "No change to global arguments or stored data.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.06.12.1",
      description: "No change to global arguments or stored data.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.06.24.1",
      description: "No change to global arguments or stored data.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.10.11.1",
      description:
        "Map the retired enum values: repository.authType token → http; syncs[].targetType swarm → project, since Arcane ran anything but swarm_stack as a compose project.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => {
        const out = { ...old };
        const repo = out.repository as Record<string, unknown> | undefined;
        if (repo?.authType === "token") {
          out.repository = { ...repo, authType: "http" };
        }
        if (Array.isArray(out.syncs)) {
          out.syncs = out.syncs.map((s: Record<string, unknown>) =>
            s?.targetType === "swarm" ? { ...s, targetType: "project" } : s
          );
        }
        return out;
      },
    },
  ],
  resources: {
    "repository": {
      description: "An Arcane git repository connection",
      schema: RepositoryResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "sync": {
      description: "An Arcane GitOps sync entry (one project pulled from git)",
      schema: SyncResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "sync-status": {
      description:
        "A GitOps sync's last/next run state (lastSyncStatus/lastSyncError/lastSyncCommit): the gitops health view",
      schema: SyncStatusResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "arcane-version": {
      description:
        "Arcane's reported version (current + newest available), for checks before and after an upgrade",
      schema: VersionResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "project": {
      description: "An Arcane compose project",
      schema: ProjectResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "operation-result": {
      description:
        "Result of a mutating Arcane operation (sync trigger, project lifecycle)",
      schema: OperationResultResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "project-detail": {
      description:
        "A compose project's full detail incl. compose/env content (rollback snapshot)",
      schema: ProjectDetailResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "validation": {
      description:
        "Result of a local compose validation (`docker compose config`)",
      schema: ValidationResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "swarm-secret": {
      description: "A swarm secret (immutable; rotate via secret_rotate)",
      schema: SwarmObjectResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "swarm-config": {
      description: "A swarm config (immutable; rotate via config_rotate)",
      schema: SwarmObjectResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "swarm-service": {
      description: "A swarm service summary",
      schema: SwarmServiceResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "swarm-stack": {
      description: "A swarm stack (a deployed compose stack)",
      schema: SwarmStackResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "swarm-stack-render": {
      description:
        "Result of Arcane's swarm-stack config render: the mandatory pre-deploy validation gate",
      schema: SwarmStackRenderResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "swarm-task": {
      description:
        "A swarm task (a replica placement attempt) with state + error: the deploy debug view",
      schema: SwarmTaskResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "volume": {
      description: "A docker volume (incl. inUse, for spotting orphans)",
      schema: VolumeResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "prune-result": {
      description: "Result of a docker prune (space reclaimed + deleted items)",
      schema: PruneResultResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    version: {
      description:
        "Read Arcane's version (GET /version); use it before and after upgrading the manager",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Reading Arcane version");
        const v = unwrap(await arcane(g, "GET", "/version"));
        const currentVersion =
          asString(pick(v, "currentVersion", "current_version")) ?? "unknown";
        const handle = await context.writeResource(
          "arcane-version",
          dataName("arcane-version"),
          {
            currentVersion,
            newestVersion: asString(pick(v, "newestVersion", "newest_version")),
            updateAvailable: pick(v, "updateAvailable", "update_available") as
              | boolean
              | undefined,
            releaseUrl: asString(pick(v, "releaseUrl", "release_url")),
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Read Arcane version {currentVersion}", {
          currentVersion,
        });
        return { dataHandles: [handle] };
      },
    },

    gitops_repo_list: {
      description:
        "List Arcane git repository connections (factory: one `repository` per entry, named `repository:<name>`)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing Arcane git repositories");
        const rows = coerceList(
          await arcane(g, "GET", "/customize/git-repositories?limit=-1"),
        );
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const name = asString(pick(r, "name")) ?? "unnamed";
          handles.push(
            await context.writeResource(
              "repository",
              dataName("repository", name),
              {
                id: asString(pick(r, "id")) ?? "",
                name,
                url: asString(pick(r, "url")) ?? "",
                authType: asString(pick(r, "authType", "auth_type")),
                enabled: pick(r, "enabled") as boolean | undefined,
                description: asString(pick(r, "description")),
                action: "observed",
                observedAt,
              },
            ),
          );
        }
        logInfo(context, "Listed {count} Arcane git repositories", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    gitops_repo_ensure: {
      description:
        "Reconcile the git repository connection from globalArgs.repository (create or update). Secrets are sent only when present in the spec.",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const desired = g.repository;
        if (!desired) {
          throw new Error(
            "globalArgs.repository is not set; nothing to reconcile",
          );
        }
        logInfo(context, "Reconciling Arcane git repository {name}", {
          name: desired.name,
        });
        const existing = coerceList(
          await arcane(g, "GET", "/customize/git-repositories?limit=-1"),
        )
          .find((r) => asString(pick(r, "name")) === desired.name);

        // Arcane's update keeps any field the body leaves out, so send only
        // what the spec sets; a new connection gets the documented defaults.
        const payload: Json = { name: desired.name, url: desired.url };
        if (desired.authType !== undefined) payload.authType = desired.authType;
        if (desired.enabled !== undefined) payload.enabled = desired.enabled;
        if (desired.description !== undefined) {
          payload.description = desired.description;
        }
        if (desired.username !== undefined) payload.username = desired.username;
        if (desired.token !== undefined) payload.token = desired.token;
        if (desired.sshKey !== undefined) payload.sshKey = desired.sshKey;
        if (desired.sshHostKeyVerification !== undefined) {
          payload.sshHostKeyVerification = desired.sshHostKeyVerification;
        }

        let id: string;
        let action: "created" | "updated";
        if (existing) {
          id = asString(pick(existing, "id")) ?? "";
          await arcane(g, "PUT", `/customize/git-repositories/${id}`, payload);
          action = "updated";
        } else {
          payload.authType ??= "none";
          payload.enabled ??= true;
          const created = unwrap(
            await arcane(g, "POST", "/customize/git-repositories", payload),
          );
          id = createdId(created, `repository connection '${desired.name}'`);
          action = "created";
        }
        // What the connection holds now: the spec's values over the current ones.
        const current = existing ?? {};
        const handle = await context.writeResource(
          "repository",
          dataName("repository", desired.name),
          {
            id,
            name: desired.name,
            url: desired.url,
            authType: asString(
              payload.authType ?? pick(current, "authType", "auth_type"),
            ),
            enabled: (payload.enabled ?? pick(current, "enabled")) as
              | boolean
              | undefined,
            description: asString(
              payload.description ?? pick(current, "description"),
            ),
            action,
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Reconciled Arcane git repository {name}: {action}", {
          name: desired.name,
          action,
        });
        return { dataHandles: [handle] };
      },
    },

    gitops_repo_delete: {
      description:
        "Delete a git repository connection by name. Idempotent: a connection that is already gone counts as deleted. " +
        "Refuses a connection a sync in this environment uses; Arcane itself refuses one any sync uses, in any environment.",
      arguments: GitopsRepoDeleteArgs,
      execute: async (
        args: z.infer<typeof GitopsRepoDeleteArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Deleting Arcane git repository {name}", {
          name: args.name,
        });
        const found = coerceList(
          await arcane(g, "GET", "/customize/git-repositories?limit=-1"),
        ).find((r) => asString(pick(r, "name")) === args.name);
        const id = found ? asString(pick(found, "id")) ?? "" : "";
        if (found && !id) {
          throw new Error(
            `Arcane lists repository connection '${args.name}' without an id, so it cannot be deleted by id`,
          );
        }
        if (found) {
          const users = coerceList(
            await arcane(g, "GET", `${ENV(g)}/gitops-syncs?limit=-1`),
          ).filter((s) =>
            asString(pick(s, "repositoryId", "repository_id")) === id
          )
            .map((s) => asString(pick(s, "name")) ?? "unnamed");
          if (users.length > 0) {
            throw new Error(
              `repository connection '${args.name}' is used by sync(s) ${
                users.join(", ")
              }; delete them or point them at another repository first`,
            );
          }
          try {
            await deleteIfPresent(g, `/customize/git-repositories/${id}`);
          } catch (e) {
            // Arcane answers a refusal with a bare 500, dropping its reason.
            const msg = e instanceof Error ? e.message : String(e);
            throw new Error(
              `Arcane would not delete repository connection '${args.name}' (${msg}). ` +
                "It refuses one that any sync uses, in any environment.",
            );
          }
        }
        const handle = await context.writeResource(
          "repository",
          dataName("repository", args.name),
          {
            id,
            name: args.name,
            url: found ? asString(pick(found, "url")) ?? "" : "",
            action: "deleted",
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Deleted Arcane git repository {name}", {
          name: args.name,
        });
        return { dataHandles: [handle] };
      },
    },

    gitops_sync_list: {
      description:
        "List Arcane GitOps syncs (factory: one `sync` per entry, named `sync:<name>`)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing Arcane GitOps syncs");
        const rows = coerceList(
          await arcane(g, "GET", `${ENV(g)}/gitops-syncs?limit=-1`),
        );
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const s of rows) {
          const name = asString(pick(s, "name")) ?? "unnamed";
          const v = syncView(s);
          handles.push(
            await context.writeResource("sync", dataName("sync", name), {
              id: asString(pick(s, "id")) ?? "",
              name,
              branch: asString(v.branch),
              composePath: asString(v.composePath),
              repositoryId: asString(v.repositoryId),
              projectName: asString(v.projectName),
              autoSync: v.autoSync as boolean | undefined,
              syncInterval: typeof v.syncInterval === "number"
                ? v.syncInterval
                : undefined,
              syncDirectory: v.syncDirectory as boolean | undefined,
              targetType: asString(v.targetType),
              action: "observed",
              observedAt,
            }),
          );
        }
        logInfo(context, "Listed {count} Arcane GitOps syncs", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    gitops_sync_ensure: {
      description:
        "Reconcile GitOps syncs from globalArgs.syncs against Arcane (create missing, update drifted). With prune=true, deletes deploy syncs not in the desired list; backup syncs are left alone.",
      arguments: GitopsSyncEnsureArgs,
      execute: async (
        args: z.infer<typeof GitopsSyncEnsureArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(
          context,
          "Reconciling {desired} Arcane GitOps syncs (prune: {prune})",
          {
            desired: g.syncs.length,
            prune: args.prune ?? false,
          },
        );
        // Each sync is looked up and recorded by name, so a repeated name would
        // create two syncs and write the same record twice.
        const seenNames = new Set<string>();
        for (const desired of g.syncs) {
          if (seenNames.has(desired.name)) {
            throw new Error(
              `globalArgs.syncs lists '${desired.name}' more than once`,
            );
          }
          seenNames.add(desired.name);
        }
        const repos = coerceList(
          await arcane(g, "GET", "/customize/git-repositories?limit=-1"),
        );
        const existing = coerceList(
          await arcane(g, "GET", `${ENV(g)}/gitops-syncs?limit=-1`),
        );
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];

        const repoId = (repoName: string | undefined): string => {
          const wanted = repoName ?? g.repository?.name;
          if (!wanted) {
            throw new Error(
              "sync has no repository and globalArgs.repository.name is unset",
            );
          }
          const match = repos.find((r) => asString(pick(r, "name")) === wanted);
          const id = match && asString(pick(match, "id"));
          if (!id) {
            throw new Error(
              `repository connection '${wanted}' not found in Arcane; run gitops_repo_ensure first`,
            );
          }
          return id;
        };
        // Resolve every repository before the first write, so a bad one late
        // in the list does not leave the syncs before it changed.
        const repositoryIds = g.syncs.map((desired) =>
          repoId(desired.repository)
        );

        for (const [i, desired] of g.syncs.entries()) {
          const repositoryId = repositoryIds[i];
          // Arcane's update keeps any field the body leaves out, so the payload
          // carries only what the spec sets. Anything else stays as the server
          // has it, including an interval tuned in the UI.
          const payload: Json = {
            name: desired.name,
            composePath: desired.composePath,
            repositoryId,
          };
          if (desired.projectName !== undefined) {
            payload.projectName = desired.projectName;
          }
          for (const key of Object.keys(SYNC_CREATE_DEFAULTS)) {
            const v = desired[key as keyof typeof SYNC_CREATE_DEFAULTS];
            if (v !== undefined) payload[key] = v;
          }
          const found = existing.find((s) =>
            asString(pick(s, "name")) === desired.name
          );

          let id: string;
          let action: "created" | "updated" | "unchanged";
          // The spec's values over the current ones: what the sync holds after
          // this run, and what drift is measured against.
          let want: Record<string, unknown>;
          if (found) {
            id = asString(pick(found, "id")) ?? "";
            want = syncView({ ...found, ...payload });
            const drifted = JSON.stringify(syncView(found)) !==
              JSON.stringify(want);
            if (drifted) {
              await arcane(g, "PUT", `${ENV(g)}/gitops-syncs/${id}`, payload);
              action = "updated";
            } else {
              action = "unchanged";
            }
          } else {
            const body = {
              ...SYNC_CREATE_DEFAULTS,
              ...payload,
              projectName: desired.projectName ?? desired.name,
            };
            want = syncView(body);
            const created = unwrap(
              await arcane(g, "POST", `${ENV(g)}/gitops-syncs`, body),
            );
            id = createdId(created, `sync '${desired.name}'`);
            action = "created";
          }
          handles.push(
            await context.writeResource(
              "sync",
              dataName("sync", desired.name),
              {
                id,
                name: desired.name,
                branch: asString(want.branch),
                composePath: desired.composePath,
                repositoryId,
                projectName: asString(want.projectName),
                autoSync: want.autoSync as boolean | undefined,
                syncInterval: asNumber(want.syncInterval),
                syncDirectory: want.syncDirectory as boolean | undefined,
                targetType: asString(want.targetType),
                action,
                observedAt,
              },
            ),
          );
          logInfo(context, "Reconciled sync {name}: {action}", {
            name: desired.name,
            action,
          });
        }

        if (args.prune) {
          const desiredNames = new Set(g.syncs.map((s) => s.name));
          for (const s of existing) {
            const name = asString(pick(s, "name"));
            if (!name || desiredNames.has(name)) continue;
            // A backup sync pushes to git and is set up in Arcane's UI;
            // globalArgs.syncs only describes deploy syncs, so leave it be.
            if (isBackupSync(s)) continue;
            const id = asString(pick(s, "id")) ?? "";
            await deleteIfPresent(g, `${ENV(g)}/gitops-syncs/${id}`);
            handles.push(
              await context.writeResource("sync", dataName("sync", name), {
                id,
                name,
                action: "deleted",
                observedAt,
              }),
            );
            logInfo(context, "Pruned sync {name}", { name });
          }
        }

        logInfo(
          context,
          "Reconciled Arcane GitOps syncs; wrote {written} records",
          {
            written: handles.length,
          },
        );
        return { dataHandles: handles };
      },
    },

    gitops_sync_trigger: {
      description:
        "Run the named syncs (fan-out): git pull, and a redeploy when the content changed. Empty `names` triggers every deploy sync; a backup sync runs only when named. Waits for each sync to finish; records every result, then throws if Arcane reported any sync failed or already in progress.",
      arguments: GitopsSyncTriggerArgs,
      execute: async (
        args: z.infer<typeof GitopsSyncTriggerArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Triggering Arcane syncs {names}", {
          names: args.names ?? [],
        });
        const existing = coerceList(
          await arcane(g, "GET", `${ENV(g)}/gitops-syncs?limit=-1`),
        );
        const wanted: string[] = args.names ?? [];
        // A backup sync commits to git, so "all" means the deploy syncs; a
        // backup sync runs only when named.
        const targets = wanted.length === 0
          ? existing.filter((s) => !isBackupSync(s))
          : existing.filter((s) =>
            wanted.includes(asString(pick(s, "name")) ?? "")
          );
        if (wanted.length > 0 && targets.length !== wanted.length) {
          const found = new Set(targets.map((s) => asString(pick(s, "name"))));
          const missing = wanted.filter((n) => !found.has(n));
          throw new Error(`sync(s) not found in Arcane: ${missing.join(", ")}`);
        }
        const timestamp = new Date().toISOString();
        const handles: DataHandle[] = [];
        const failed: string[] = [];
        for (const s of targets) {
          const name = asString(pick(s, "name")) ?? "unnamed";
          const id = asString(pick(s, "id")) ?? "";
          let failure: string | undefined;
          let status = 200;
          try {
            failure = await runSync(g, id);
          } catch (e) {
            // Record this sync and carry on to the next, as for a failure
            // Arcane reports, rather than stopping the fan-out here.
            const msg = e instanceof Error ? e.message : String(e);
            status = Number(/-> HTTP (\d{3})/.exec(msg)?.[1] ?? 0);
            failure = isDefiniteAnswer(msg)
              ? msg
              : `no answer from Arcane (${msg}); the sync may still be running`;
          }
          if (failure !== undefined) failed.push(`${name} (${failure})`);
          handles.push(
            await context.writeResource(
              "operation-result",
              dataName("operation-result", "sync", name),
              {
                operation: "sync",
                target: name,
                status,
                success: failure === undefined,
                detail: failure,
                timestamp,
              },
            ),
          );
        }
        if (failed.length > 0) {
          throw new Error(`Arcane reported failed syncs: ${failed.join("; ")}`);
        }
        logInfo(context, "Triggered {count} Arcane syncs", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    gitops_sync_status: {
      description:
        "Read last/next run state for the named syncs (fan-out: one `sync-status` per sync, named `sync-status:<name>`). Empty `names` checks all syncs. Surfaces lastSyncStatus/lastSyncError/lastSyncCommit, the missing gitops health view.",
      arguments: GitopsSyncStatusArgs,
      execute: async (
        args: z.infer<typeof GitopsSyncStatusArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Reading Arcane sync status for {names}", {
          names: args.names ?? [],
        });
        const existing = coerceList(
          await arcane(g, "GET", `${ENV(g)}/gitops-syncs?limit=-1`),
        );
        const wanted: string[] = args.names ?? [];
        const targets = wanted.length === 0
          ? existing
          : existing.filter((s) =>
            wanted.includes(asString(pick(s, "name")) ?? "")
          );
        if (wanted.length > 0 && targets.length !== wanted.length) {
          const found = new Set(targets.map((s) => asString(pick(s, "name"))));
          const missing = wanted.filter((n) => !found.has(n));
          throw new Error(`sync(s) not found in Arcane: ${missing.join(", ")}`);
        }
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const s of targets) {
          const name = asString(pick(s, "name")) ?? "unnamed";
          const id = asString(pick(s, "id")) ?? "";
          const st = unwrap(
            await arcane(g, "GET", `${ENV(g)}/gitops-syncs/${id}/status`),
          );
          handles.push(
            await context.writeResource(
              "sync-status",
              dataName("sync-status", name),
              {
                id: asString(pick(st, "id")) ?? id,
                name,
                autoSync: pick(st, "autoSync", "auto_sync") as
                  | boolean
                  | undefined,
                nextSyncAt: asString(pick(st, "nextSyncAt", "next_sync_at")),
                lastSyncAt: asString(pick(st, "lastSyncAt", "last_sync_at")),
                lastSyncStatus: asString(
                  pick(st, "lastSyncStatus", "last_sync_status"),
                ),
                lastSyncError: asString(
                  pick(st, "lastSyncError", "last_sync_error"),
                ),
                lastSyncCommit: asString(
                  pick(st, "lastSyncCommit", "last_sync_commit"),
                ),
                observedAt,
              },
            ),
          );
        }
        logInfo(context, "Read the status of {count} Arcane syncs", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    project_list: {
      description:
        "List Arcane compose projects (factory: one `project` per entry, named `project:<name>`)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing Arcane projects");
        const rows = coerceList(
          await arcane(g, "GET", `${ENV(g)}/projects?limit=-1`),
        );
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const p of rows) {
          const name = asString(pick(p, "name")) ?? "unnamed";
          handles.push(
            await context.writeResource("project", dataName("project", name), {
              id: asString(pick(p, "id")) ?? "",
              name,
              status: asString(pick(p, "status", "state")) ?? "unknown",
              observedAt,
            }),
          );
        }
        logInfo(context, "Listed {count} Arcane projects", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    project_validate: {
      description:
        "Validate compose content LOCALLY with `docker compose config` (fail-closed and read-only: no Arcane mutation). Takes composePath/envPath or inline composeContent/envContent.",
      arguments: ProjectValidateArgs,
      execute: maskingEnv(async (
        args: z.infer<typeof ProjectValidateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const { composeContent, envContent } = await resolveComposeInput(args);
        const target = args.target ?? args.composePath ?? "inline";
        logInfo(context, "Validating compose content {target}", { target });
        const { version } = await composeConfigValidate(
          composeContent,
          envContent,
        );
        const handle = await context.writeResource(
          "validation",
          dataName("validation", target),
          {
            target,
            valid: true,
            composeVersion: version,
            detail: `validated with docker compose ${version}`,
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(
          context,
          "Compose content {target} valid (docker compose {composeVersion})",
          {
            target,
            composeVersion: version,
          },
        );
        return { dataHandles: [handle] };
      }),
    },

    project_get: {
      description:
        "Read a compose project's full detail (compose + env content, status, gitOps mode) into a `project-detail` resource. Used for rollback snapshots.",
      arguments: ProjectGetArgs,
      execute: async (
        args: z.infer<typeof ProjectGetArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Reading Arcane project detail {name}", {
          name: args.name,
        });
        const id = await resolveProjectId(g, args.name);
        const d = unwrap(
          await arcane(g, "GET", `${ENV(g)}/projects/${id}/compose`),
        );
        const handle = await context.writeResource(
          "project-detail",
          dataName("project-detail", args.name),
          projectDetail(args.name, id, d),
        );
        logInfo(context, "Read Arcane project detail {name}", {
          name: args.name,
        });
        return { dataHandles: [handle] };
      },
    },

    project_create: {
      description:
        "Create a compose project in Arcane (direct mode), pushing compose content via the API. Validates locally first and stops if validation fails or cannot run.",
      arguments: ProjectCreateArgs,
      execute: maskingEnv(async (
        args: z.infer<typeof ProjectCreateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const { composeContent, envContent } = await resolveComposeInput(args);
        await composeConfigValidate(composeContent, envContent);
        const body: Json = { name: args.name, composeContent };
        if (envContent !== undefined) body.envContent = envContent;
        logInfo(context, "Creating Arcane project {name}", { name: args.name });
        const created = await createProject(g, body);
        const id = createdId(created, `project '${args.name}'`);
        const handle = await context.writeResource(
          "project",
          dataName("project", args.name),
          {
            id,
            name: args.name,
            status: asString(pick(created, "status", "state")) ?? "unknown",
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Created Arcane project {name} ({id})", {
          name: args.name,
          id,
        });
        return { dataHandles: [handle] };
      }),
    },

    project_update: {
      description:
        "Update a compose project's content in Arcane (direct mode). Validates locally first and stops if validation fails or cannot run. Does NOT redeploy; use project_redeploy or project_deploy.",
      arguments: ProjectUpdateArgs,
      execute: maskingEnv(async (
        args: z.infer<typeof ProjectUpdateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const id = await resolveProjectId(g, args.name);
        const { composeContent, envContent } = await resolveComposeInput(args);
        await composeConfigValidate(composeContent, envContent);
        const body: Json = { composeContent };
        if (envContent !== undefined) body.envContent = envContent;
        logInfo(context, "Updating Arcane project {name} ({id})", {
          name: args.name,
          id,
        });
        const updated = unwrap(
          await arcane(g, "PUT", `${ENV(g)}/projects/${id}`, body),
        );
        const handle = await context.writeResource(
          "project",
          dataName("project", args.name),
          {
            id,
            name: args.name,
            status: asString(pick(updated, "status", "state")) ?? "unknown",
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Updated Arcane project {name}", { name: args.name });
        return { dataHandles: [handle] };
      }),
    },

    project_deploy: {
      description:
        "Validated, mode-aware deploy of a compose project. Snapshots prior state, applies, polls health, and rolls back by default on failure. " +
        "Direct mode: validate -> create/update compose -> redeploy -> on failure re-apply prior content (or destroy a failed first deploy). " +
        "GitOps mode: run the sync named by the project's gitOpsManagedBy (stops if Arcane no longer lists it, reports the sync failed, or another run of it is in progress) -> redeploy -> on failure report (git revert is left to the user). " +
        "Healthy means every service running on two checks in a row, so a project with a service that exits on purpose (an init or migration job) never passes.",
      arguments: ProjectDeployArgs,
      execute: maskingEnv(async (
        args: z.infer<typeof ProjectDeployArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const name: string = args.name;
        const handles: DataHandle[] = [];
        const stepName = (operation: string) =>
          dataName("operation-result", "deploy", operation, name);
        const written = new Set<string>();
        const mask = await envMasker(args);
        const record = async (
          operation: string,
          success: boolean,
          status: number,
          detail: string,
        ) => {
          handles.push(
            await context.writeResource(
              "operation-result",
              stepName(operation),
              {
                operation: `deploy:${operation}`,
                target: name,
                status,
                success,
                detail: mask(detail),
                timestamp: new Date().toISOString(),
              },
            ),
          );
          written.add(stepName(operation));
        };
        try {
          // Snapshot the prior state; gitOpsManagedBy tells the two modes apart.
          const existing = await findProject(g, name);
          if (existing && pick(existing, "isArchived") === true) {
            throw new Error(
              `project '${name}' is archived in Arcane; unarchive it before deploying`,
            );
          }
          const isFirstDeploy = !existing;
          let id = existing ? (asString(pick(existing, "id")) ?? "") : "";
          let prior: Json = {};
          let gitOpsManagedBy: string | undefined;
          if (existing) {
            prior = unwrap(
              await arcane(g, "GET", `${ENV(g)}/projects/${id}/compose`),
            );
            gitOpsManagedBy = asString(
              pick(prior, "gitOpsManagedBy", "gitops_managed_by"),
            );
            handles.push(
              await context.writeResource(
                "project-detail",
                dataName("project-detail", name, "prior"),
                projectDetail(name, id, prior),
              ),
            );
          }
          const gitops = !!gitOpsManagedBy && gitOpsManagedBy.length > 0;
          logInfo(
            context,
            "Deploying project {name} ({mode} mode, first deploy: {firstDeploy})",
            {
              name,
              mode: gitops ? "gitops" : "direct",
              firstDeploy: isFirstDeploy,
            },
          );

          // GitOps mode: never push inline content; the content comes from git via the sync.
          if (gitops) {
            if (
              args.composePath !== undefined ||
              args.composeContent !== undefined ||
              args.envPath !== undefined ||
              args.envContent !== undefined
            ) {
              throw new Error(
                `project '${name}' is gitops-managed (${gitOpsManagedBy}); commit to git and let the sync deliver content, rather than passing compose or .env content to project_deploy`,
              );
            }
            // gitOpsManagedBy holds the managing sync's id, not its name.
            const syncs = coerceList(
              await arcane(g, "GET", `${ENV(g)}/gitops-syncs?limit=-1`),
            );
            const sync = syncs.find((s) =>
              asString(pick(s, "id")) === gitOpsManagedBy
            );
            if (!sync) {
              const reason =
                `project '${name}' is managed by sync ${gitOpsManagedBy}, which Arcane no longer lists`;
              await record("sync", false, 0, reason);
              throw new Error(
                `${reason}; not redeploying content that git did not deliver`,
              );
            }
            const syncName = asString(pick(sync, "name")) ?? gitOpsManagedBy;
            let syncFailure: string | undefined;
            try {
              syncFailure = await runSync(g, asString(pick(sync, "id")) ?? "");
            } catch (e) {
              const msg = e instanceof Error ? e.message : String(e);
              await record("sync", false, 0, msg);
              // Without Arcane's answer the sync, and the redeploy it runs when
              // the content changed, may still be going: a redeploy now would race it.
              throw new Error(
                isDefiniteAnswer(msg)
                  ? `sync ${syncName} for '${name}' failed (${msg}); not redeploying`
                  : `sync ${syncName} for '${name}' gave no answer (${msg}); Arcane may still be running it, so not redeploying`,
              );
            }
            if (syncFailure !== undefined) {
              await record("sync", false, 200, syncFailure);
              throw new Error(
                /already in progress/.test(syncFailure)
                  ? `sync ${syncName} for '${name}' is already running; wait for it to finish, then re-run project_deploy`
                  : `sync ${syncName} for '${name}' failed (${syncFailure}); not redeploying`,
              );
            }
            await record("sync", true, 200, `ran sync ${syncName}`);
            const health = await redeployAndPoll(
              g,
              id,
              args.healthTimeoutSec,
              args.pollIntervalSec,
            );
            await record(
              "health",
              health.healthy,
              health.healthy ? 200 : 503,
              health.detail,
            );
            if (!health.healthy) {
              throw new Error(
                `gitops deploy of '${name}' did not become healthy (${health.detail}). Auto git rollback is not enabled; revert the commit and re-sync manually.`,
              );
            }
            logInfo(context, "GitOps deploy of {name} healthy", { name });
            return { dataHandles: handles };
          }

          // Direct mode needs new content, and validation must pass first.
          if (
            args.composePath === undefined && args.composeContent === undefined
          ) {
            throw new Error(
              `direct-mode deploy of '${name}' requires composePath or composeContent`,
            );
          }
          const { composeContent, envContent } = await resolveComposeInput(
            args,
          );
          const { version } = await composeConfigValidate(
            composeContent,
            envContent,
          );
          await record(
            "validate",
            true,
            200,
            `compose valid (docker compose ${version})`,
          );

          // Apply, redeploy and wait for health, catching any failure. A failed
          // redeploy throws (an HTTP error, or an error line in its streamed 200
          // body) and takes the same rollback path as an unhealthy result.
          let failReason: string | undefined;
          let outcomeUnknown = false;
          let healthy = false;
          try {
            if (isFirstDeploy) {
              const body: Json = { name, composeContent };
              if (envContent !== undefined) body.envContent = envContent;
              const created = await createProject(g, body);
              id = createdId(created, `project '${name}'`);
              await record("create", true, 200, `created project ${id}`);
            } else {
              const body: Json = { composeContent };
              if (envContent !== undefined) body.envContent = envContent;
              await arcane(g, "PUT", `${ENV(g)}/projects/${id}`, body);
              await record("update", true, 200, "updated compose content");
            }
            const health = await redeployAndPoll(
              g,
              id,
              args.healthTimeoutSec,
              args.pollIntervalSec,
            );
            await record("redeploy", true, 200, "redeploy completed");
            await record(
              "health",
              health.healthy,
              health.healthy ? 200 : 503,
              health.detail,
            );
            healthy = health.healthy;
            if (!healthy) failReason = `unhealthy: ${health.detail}`;
          } catch (e) {
            failReason = e instanceof Error ? e.message : String(e);
            outcomeUnknown = e instanceof RedeployOutcomeUnknown;
            await record("apply", false, 0, failReason);
          }

          if (healthy) {
            handles.push(
              await context.writeResource(
                "project",
                dataName("project", name),
                {
                  id,
                  name,
                  status: "running",
                  observedAt: new Date().toISOString(),
                },
              ),
            );
            logInfo(context, "Direct deploy of {name} healthy", { name });
            return { dataHandles: handles };
          }

          // Roll back by default, but not on top of a redeploy Arcane may still
          // be running: the two would race.
          if (outcomeUnknown) {
            await record(
              "rollback",
              false,
              0,
              "redeploy outcome unknown and may still be running; no rollback attempted",
            );
            throw new Error(
              `deploy of '${name}' failed (${failReason}); no rollback attempted while it may still be running. Check the project in Arcane`,
            );
          }
          if (args.rollback === false) {
            await record(
              "rollback",
              false,
              0,
              "rollback disabled (rollback:false); left in failed state",
            );
            throw new Error(
              `deploy of '${name}' failed (${failReason}); rollback disabled, left as-is for inspection`,
            );
          }
          if (isFirstDeploy) {
            if (id) {
              await deleteIfPresent(
                g,
                `${ENV(g)}/projects/${id}/destroy`,
                OPERATION_TIMEOUT_MS,
              );
              await record(
                "rollback",
                true,
                200,
                "first deploy failed; destroyed the half-up project",
              );
            } else {
              // Either the create failed, or Arcane answered it without an id;
              // in the second case the project may exist.
              await record(
                "rollback",
                true,
                200,
                "first deploy failed with no project id, so nothing was torn down; check Arcane for a half-created project",
              );
            }
            throw new Error(
              `first deploy of '${name}' failed (${failReason})${
                id ? "; destroyed the half-up project" : ""
              }`,
            );
          }
          const priorCompose = asString(
            pick(prior, "composeContent", "compose_content"),
          );
          const priorEnv = asString(pick(prior, "envContent", "env_content"));
          if (!priorCompose) {
            await record(
              "rollback",
              false,
              0,
              "no prior compose content captured; cannot auto-roll back",
            );
            throw new Error(
              `deploy of '${name}' failed (${failReason}) and no prior compose content was available to roll back to; manual recovery required`,
            );
          }
          let rbResult: string;
          try {
            const rb: Json = { composeContent: priorCompose };
            // Arcane leaves out an empty .env when it reads the project, and keeps
            // the current .env when an update leaves envContent out. So a deploy
            // that added a .env must send an empty one back to undo it.
            if (priorEnv !== undefined) rb.envContent = priorEnv;
            else if (envContent !== undefined) rb.envContent = "";
            await arcane(g, "PUT", `${ENV(g)}/projects/${id}`, rb);
            const rbHealth = await redeployAndPoll(
              g,
              id,
              args.healthTimeoutSec,
              args.pollIntervalSec,
            );
            await record(
              "rollback",
              rbHealth.healthy,
              rbHealth.healthy ? 200 : 503,
              `rolled back to prior content: ${rbHealth.detail}`,
            );
            rbResult = rbHealth.healthy
              ? "healthy again"
              : "STILL UNHEALTHY; manual recovery required";
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            // The rollback's own redeploy can end with its outcome unknown, which
            // is not a failure: Arcane may still be bringing the prior content up.
            const unknown = e instanceof RedeployOutcomeUnknown;
            await record(
              "rollback",
              false,
              0,
              unknown
                ? `rollback redeploy outcome unknown: ${msg}`
                : `rollback re-apply failed: ${msg}`,
            );
            rbResult = unknown
              ? `ROLLBACK OUTCOME UNKNOWN (${msg}); check the project in Arcane`
              : `ROLLBACK FAILED (${msg}); manual recovery required`;
          }
          throw new Error(
            `deploy of '${name}' failed (${failReason}); rolled back to prior content (${rbResult})`,
          );
        } finally {
          await deleteUnreachedSteps(
            context,
            DEPLOY_STEPS.map(stepName),
            written,
          );
        }
      }),
    },

    project_up: makeLifecycle(
      "up",
      "POST",
      "/up",
      "Start the named projects (compose up). Fails if Arcane's streamed answer ends in an error.",
    ),
    project_down: makeLifecycle(
      "down",
      "POST",
      "/down",
      "Stop the named projects and remove their containers (compose down). The project files and volumes stay.",
    ),
    project_redeploy: makeLifecycle(
      "redeploy",
      "POST",
      "/redeploy",
      "Pull the named projects' images and run compose up again. A container whose image and config are unchanged keeps running; use project_restart to restart it.",
    ),
    project_restart: makeLifecycle(
      "restart",
      "POST",
      "/restart",
      "Restart the named projects' containers in place. Does not start a project that is down, or pick up compose changes.",
    ),
    project_pull: makeLifecycle(
      "pull",
      "POST",
      "/pull",
      "Pull the named projects' images without restarting anything.",
    ),
    // Arcane's destroy deletes the project directory unless told otherwise.
    project_destroy: makeLifecycle(
      "destroy",
      "DELETE",
      "/destroy",
      "Destroy the named projects: take them down, remove them from Arcane, and delete each project's directory on the host, including its compose file and .env. Volumes are kept.",
    ),

    // --- swarm secret_ / config_ CRUD (rotation lives in secret_rotate / config_rotate) ---
    ...makeSwarmObject("secret"),
    ...makeSwarmObject("config"),
    ...makeRotate("secret"),
    ...makeRotate("config"),

    swarm_service_list: {
      description:
        "List swarm services (factory: one `swarm-service` per entry, named `swarm-service:<name>`)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing swarm services");
        await ensureSwarmManager(g);
        const rows = coerceList(
          await arcane(g, "GET", `${ENV(g)}/swarm/services?limit=-1`),
        );
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const res = swarmServiceResource(r, "observed");
          handles.push(
            await context.writeResource(
              "swarm-service",
              dataName("swarm-service", res.name as string),
              res,
            ),
          );
        }
        logInfo(context, "Listed {count} swarm services", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    swarm_service_get: {
      description: "Get a single swarm service by name",
      arguments: NameArg,
      execute: async (
        args: z.infer<typeof NameArg>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Reading swarm service {name}", { name: args.name });
        await ensureSwarmManager(g);
        const found = await findSwarmService(g, args.name);
        if (!found) throw new Error(`swarm service '${args.name}' not found`);
        // The summary has no update status; the inspect answer does.
        const id = asString(pick(found, "id", "ID")) ?? "";
        const insp = unwrap(
          await arcane(g, "GET", `${ENV(g)}/swarm/services/${id}`),
        );
        const res = swarmServiceResource(found, "observed", insp);
        const handle = await context.writeResource(
          "swarm-service",
          dataName("swarm-service", res.name as string),
          res,
        );
        logInfo(context, "Read swarm service {name}", { name: args.name });
        return { dataHandles: [handle] };
      },
    },

    swarm_service_rollback: {
      description:
        "Roll a swarm service back to its previous spec (Arcane POST .../rollback)",
      arguments: NameArg,
      execute: async (
        args: z.infer<typeof NameArg>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const found = await findSwarmService(g, args.name);
        if (!found) throw new Error(`swarm service '${args.name}' not found`);
        const id = asString(pick(found, "id", "ID")) ?? "";
        logInfo(context, "Rolling back swarm service {name}", {
          name: args.name,
        });
        await arcane(g, "POST", `${ENV(g)}/swarm/services/${id}/rollback`);
        const handle = await context.writeResource(
          "operation-result",
          dataName("operation-result", "swarm_service_rollback", args.name),
          {
            operation: "swarm_service_rollback",
            target: args.name,
            status: 200,
            success: true,
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Rolled back swarm service {name}", {
          name: args.name,
        });
        return { dataHandles: [handle] };
      },
    },

    swarm_service_force_update: {
      description:
        "Force-redeploy a swarm service via Arcane (bumps spec.TaskTemplate.ForceUpdate + PUT), which recreates its tasks without changing config. Useful after a dependency (e.g. its DB) becomes ready post-deploy. Polls convergence; throws if it does not converge.",
      arguments: SwarmServiceForceUpdateArgs,
      execute: async (
        args: z.infer<typeof SwarmServiceForceUpdateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const found = await findSwarmService(g, args.name);
        if (!found) throw new Error(`swarm service '${args.name}' not found`);
        const id = asString(pick(found, "id", "ID")) ?? "";
        const insp = unwrap(
          await arcane(g, "GET", `${ENV(g)}/swarm/services/${id}`),
        );
        const spec = pick(insp, "spec") as Json | undefined;
        if (!spec) {
          throw new Error(`could not read spec for service '${args.name}'`);
        }
        const tt = (pick(spec, "TaskTemplate") as Json) ?? {};
        tt.ForceUpdate = (asNumber(pick(tt, "ForceUpdate")) ?? 0) + 1;
        spec.TaskTemplate = tt;
        const versionObj = (pick(insp, "version") as Json) ?? {};
        const versionIndex = asNumber(pick(versionObj, "Index", "index"));
        const body: Json = { spec };
        if (versionIndex !== undefined) body.version = versionIndex;
        logInfo(context, "Force-updating swarm service {name}", {
          name: args.name,
        });
        await arcane(g, "PUT", `${ENV(g)}/swarm/services/${id}`, body);
        const conv = await pollServiceConverged(
          g,
          id,
          args.convergeTimeoutSec,
          args.pollIntervalSec,
        );
        const handle = await context.writeResource(
          "operation-result",
          dataName("operation-result", "swarm_service_force_update", args.name),
          {
            operation: "swarm_service_force_update",
            target: args.name,
            status: conv.converged ? 200 : 503,
            success: conv.converged,
            detail: conv.detail,
            timestamp: new Date().toISOString(),
          },
        );
        if (!conv.converged) {
          throw new Error(
            `swarm service '${args.name}' force-update did not converge: ${conv.detail}`,
          );
        }
        logInfo(context, "Force-updated swarm service {name}", {
          name: args.name,
        });
        return { dataHandles: [handle] };
      },
    },

    // --- swarm_stack_ section: validate (render, fail-closed) + deploy + list/get/remove ---
    swarm_stack_list: {
      description:
        "List swarm stacks (factory: one `swarm-stack` per entry, named `swarm-stack:<name>`)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing swarm stacks");
        await ensureSwarmManager(g);
        const rows = coerceList(
          await arcane(g, "GET", `${ENV(g)}/swarm/stacks?limit=-1`),
        );
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const res = swarmStackResource(r, "observed");
          handles.push(
            await context.writeResource(
              "swarm-stack",
              dataName("swarm-stack", res.name as string),
              res,
            ),
          );
        }
        logInfo(context, "Listed {count} swarm stacks", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    swarm_stack_get: {
      description: "Get a single swarm stack by name",
      arguments: NameArg,
      execute: async (
        args: z.infer<typeof NameArg>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Reading swarm stack {name}", { name: args.name });
        await ensureSwarmManager(g);
        const d = unwrap(
          await arcane(
            g,
            "GET",
            `${ENV(g)}/swarm/stacks/${encodeURIComponent(args.name)}`,
          ),
        );
        const res = swarmStackResource(d, "observed");
        const handle = await context.writeResource(
          "swarm-stack",
          dataName("swarm-stack", args.name),
          res,
        );
        logInfo(context, "Read swarm stack {name}", { name: args.name });
        return { dataHandles: [handle] };
      },
    },

    swarm_stack_validate: {
      description:
        "Validate a swarm stack via Arcane's config render (POST /swarm/stacks/config/render). " +
        "Fails closed: any render error (4xx) aborts. Records the rendered services/networks/volumes/secrets/configs + warnings.",
      arguments: SwarmStackValidateArgs,
      execute: maskingEnv(async (
        args: z.infer<typeof SwarmStackValidateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const { composeContent, envContent } = await resolveComposeInput(args);
        const body: Json = { name: args.name, composeContent };
        if (envContent !== undefined) body.envContent = envContent;
        logInfo(context, "Rendering swarm stack {name} to validate it", {
          name: args.name,
        });
        const rendered = unwrap(
          await arcane(g, "POST", `${ENV(g)}/swarm/stacks/config/render`, body),
        );
        const warnings = renderNames(pick(rendered, "warnings"));
        const res = {
          name: args.name,
          valid: true,
          services: renderNames(pick(rendered, "services")),
          networks: renderNames(pick(rendered, "networks")),
          volumes: renderNames(pick(rendered, "volumes")),
          secrets: renderNames(pick(rendered, "secrets")),
          configs: renderNames(pick(rendered, "configs")),
          warnings,
          observedAt: new Date().toISOString(),
        };
        const handle = await context.writeResource(
          "swarm-stack-render",
          dataName("swarm-stack-render", args.name),
          res,
        );
        logInfo(
          context,
          "Swarm stack {name} render valid: {services} services, {warnings} warnings",
          {
            name: args.name,
            services: res.services.length,
            warnings: warnings.length,
          },
        );
        return { dataHandles: [handle] };
      }),
    },

    swarm_stack_deploy: {
      description:
        "Validated deploy of a swarm stack: render (any render error stops the deploy) -> POST the stack -> poll service convergence. " +
        "Records per-step operation-results + a swarm-stack resource. A non-converging deploy is surfaced (not force-removed, not auto-rolled-back).",
      arguments: SwarmStackDeployArgs,
      execute: maskingEnv(async (
        args: z.infer<typeof SwarmStackDeployArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const name: string = args.name;
        const handles: DataHandle[] = [];
        const stepName = (operation: string) =>
          dataName("operation-result", "swarm_stack_deploy", operation, name);
        const written = new Set<string>();
        const mask = await envMasker(args);
        const record = async (
          operation: string,
          success: boolean,
          status: number,
          detail: string,
        ) => {
          handles.push(
            await context.writeResource(
              "operation-result",
              stepName(operation),
              {
                operation: `swarm_stack_deploy:${operation}`,
                target: name,
                status,
                success,
                detail: mask(detail),
                timestamp: new Date().toISOString(),
              },
            ),
          );
          written.add(stepName(operation));
        };
        try {
          const { composeContent, envContent } = await resolveComposeInput(
            args,
          );

          // Validate via render; it must pass before the deploy. A render error
          // throws from arcane() (4xx) and aborts the deploy.
          const renderBody: Json = { name, composeContent };
          if (envContent !== undefined) renderBody.envContent = envContent;
          const rendered = unwrap(
            await arcane(
              g,
              "POST",
              `${ENV(g)}/swarm/stacks/config/render`,
              renderBody,
            ),
          );
          const svcNames = renderNames(pick(rendered, "services"));
          const warnings = renderNames(pick(rendered, "warnings"));
          await record(
            "validate",
            true,
            200,
            `rendered ${svcNames.length} service(s)${
              warnings.length
                ? `; ${warnings.length} warning(s): ${warnings.join("; ")}`
                : ""
            }`,
          );

          const body: Json = { name, composeContent };
          if (envContent !== undefined) body.envContent = envContent;
          if (args.prune) body.prune = true;
          logInfo(context, "Deploying swarm stack {name}", { name });
          // Arcane deploys the stack inside the request, with a registry
          // lookup per service, so a large stack can take minutes.
          try {
            await arcane(
              g,
              "POST",
              `${ENV(g)}/swarm/stacks`,
              body,
              OPERATION_TIMEOUT_MS,
            );
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            if (isDefiniteAnswer(msg)) throw e;
            const detail =
              `no answer from Arcane (${msg}); the stack deploy may still be running. Check with swarm_stack_get before re-deploying.`;
            await record(
              "deploy",
              false,
              Number(/-> HTTP (\d{3})/.exec(msg)?.[1] ?? 0),
              detail,
            );
            throw new Error(`swarm stack '${name}': ${mask(detail)}`);
          }
          await record("deploy", true, 200, "stack deploy issued");

          const conv = await pollStackConverged(
            g,
            name,
            args.convergeTimeoutSec,
            args.pollIntervalSec,
          );
          await record(
            "converge",
            conv.converged,
            conv.converged ? 200 : 503,
            conv.detail,
          );

          // Record the stack; the inspect for counts and timestamps is best-effort.
          let stackRes: Record<string, unknown>;
          try {
            const insp = unwrap(
              await arcane(
                g,
                "GET",
                `${ENV(g)}/swarm/stacks/${encodeURIComponent(name)}`,
              ),
            );
            stackRes = swarmStackResource(
              insp,
              conv.converged ? "created" : "observed",
            );
          } catch {
            stackRes = {
              name,
              action: conv.converged ? "created" : "observed",
              observedAt: new Date().toISOString(),
            };
          }
          handles.push(
            await context.writeResource(
              "swarm-stack",
              dataName("swarm-stack", name),
              stackRes,
            ),
          );

          if (!conv.converged) {
            throw new Error(
              `swarm stack '${name}' was deployed but did not converge within ${args.convergeTimeoutSec}s (${conv.detail}). ` +
                `Left in place for inspection: not force-removed, not auto-rolled-back. Inspect with swarm_stack_get / swarm_service_list, then re-deploy or swarm_stack_remove.`,
            );
          }
          logInfo(context, "Swarm stack {name} deployed and converged", {
            name,
          });
          return { dataHandles: handles };
        } finally {
          await deleteUnreachedSteps(
            context,
            STACK_DEPLOY_STEPS.map(stepName),
            written,
          );
        }
      }),
    },

    swarm_stack_remove: {
      description:
        "Remove a swarm stack by name (docker stack rm via Arcane) and confirm the stored record is cleared. " +
        "Arcane's first DELETE can answer 404 with the stack record still there, so this re-issues DELETE until GET answers 404. " +
        "In-use conflicts are surfaced by Arcane, never forced.",
      arguments: SwarmStackRemoveArgs,
      execute: async (
        args: z.infer<typeof SwarmStackRemoveArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        logInfo(context, "Removing swarm stack {name}", { name: args.name });
        const deletes = await pollStackRemoved(
          g,
          args.name,
          args.removeTimeoutSec,
          args.pollIntervalSec,
        );
        const handle = await context.writeResource(
          "swarm-stack",
          dataName("swarm-stack", args.name),
          {
            name: args.name,
            action: "deleted",
            deletes,
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Removed swarm stack {name} after {deletes} deletes", {
          name: args.name,
          deletes,
        });
        return { dataHandles: [handle] };
      },
    },

    swarm_stack_tasks: {
      description:
        "List a swarm stack's tasks (factory: one `swarm-task` per task, named `swarm-task:<task id>`) with per-task currentState + error: the deploy debug view that surfaces rejected/failed reasons (missing bind path, non-zero exit, placement). " +
        "NOTE: Arcane exposes no container/service log endpoint, so crash stderr is NOT available here; use the host's docker logs / a log viewer for that.",
      arguments: SwarmStackTasksArgs,
      execute: async (
        args: z.infer<typeof SwarmStackTasksArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing tasks of swarm stack {name}", {
          name: args.name,
        });
        await ensureSwarmManager(g);
        const rows = coerceList(
          await arcane(
            g,
            "GET",
            `${ENV(g)}/swarm/stacks/${
              encodeURIComponent(args.name)
            }/tasks?limit=-1`,
          ),
        );
        const problemStates = ["rejected", "failed", "orphaned"];
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const res = swarmTaskResource(r);
          if (
            args.onlyProblems &&
            !problemStates.includes(String(res.currentState))
          ) {
            continue;
          }
          handles.push(
            await context.writeResource(
              "swarm-task",
              dataName("swarm-task", res.id as string),
              res,
            ),
          );
        }
        logInfo(context, "Listed {count} tasks of swarm stack {name}", {
          name: args.name,
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    // --- volume_ / prune cleanup (docker-level; works on any env, not swarm-only) ---
    volume_list: {
      description:
        "List docker volumes (factory: one `volume` per entry, named `volume:<name>`). Includes `inUse` so orphaned volumes are visible.",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing volumes");
        const rows = coerceList(
          await arcane(g, "GET", `${ENV(g)}/volumes?limit=-1`),
        );
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const res = volumeResource(r, "observed");
          handles.push(
            await context.writeResource(
              "volume",
              dataName("volume", res.name as string),
              res,
            ),
          );
        }
        logInfo(context, "Listed {count} volumes", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    volume_remove: {
      description:
        "Remove a docker volume by name. Idempotent: a volume that is already gone counts as removed. An in-use volume is refused and left in place; stop or remove the containers using it first.",
      arguments: VolumeRemoveArgs,
      execute: async (
        args: z.infer<typeof VolumeRemoveArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Removing volume {name}", { name: args.name });
        try {
          await arcane(
            g,
            "DELETE",
            `${ENV(g)}/volumes/${encodeURIComponent(args.name)}`,
          );
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          // Arcane returns every delete failure as a 500 carrying Docker's
          // message, so the message is the only way to tell the cases apart.
          if (/no such volume/i.test(msg)) {
            // already gone
          } else if (/in use/i.test(msg)) {
            throw new Error(
              `volume '${args.name}' is in use, so it was not removed. Stop or remove the containers using it first. ${msg}`,
            );
          } else {
            throw e;
          }
        }
        const handle = await context.writeResource(
          "volume",
          dataName("volume", args.name),
          {
            // Docker identifies a volume by its name.
            id: args.name,
            name: args.name,
            action: "deleted",
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Removed volume {name}", { name: args.name });
        return { dataHandles: [handle] };
      },
    },

    volume_prune: {
      description:
        "Prune UNUSED anonymous docker volumes (Docker default: named volumes are NOT removed). Removes only volumes no container references. For a specific named volume use volume_remove.",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Pruning unused volumes");
        const raw = unwrap(await arcane(g, "POST", `${ENV(g)}/volumes/prune`));
        const res = pruneResult("volumes", raw);
        const handle = await context.writeResource(
          "prune-result",
          dataName("prune-result", "volumes"),
          res,
        );
        logInfo(context, "Pruned volumes: {itemsDeleted} deleted", {
          itemsDeleted: res.itemsDeleted ?? 0,
        });
        return { dataHandles: [handle] };
      },
    },

    network_prune: {
      description:
        "Prune unused docker networks (no attached containers). Safe: only removes networks nothing is using.",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Pruning unused networks");
        const raw = unwrap(await arcane(g, "POST", `${ENV(g)}/networks/prune`));
        const res = pruneResult("networks", raw);
        const handle = await context.writeResource(
          "prune-result",
          dataName("prune-result", "networks"),
          res,
        );
        logInfo(context, "Pruned networks: {itemsDeleted} deleted", {
          itemsDeleted: res.itemsDeleted ?? 0,
        });
        return { dataHandles: [handle] };
      },
    },

    image_prune: {
      description:
        "Prune unused images. dangling:true (default) removes only dangling layers; dangling:false removes ALL images not referenced by a container.",
      arguments: ImagePruneArgs,
      execute: async (
        args: z.infer<typeof ImagePruneArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Pruning images (dangling only: {dangling})", {
          dangling: !!args.dangling,
        });
        const raw = unwrap(
          await arcane(g, "POST", `${ENV(g)}/images/prune`, {
            dangling: args.dangling,
          }),
        );
        const res = pruneResult("images", raw);
        const handle = await context.writeResource(
          "prune-result",
          dataName("prune-result", "images"),
          res,
        );
        logInfo(context, "Pruned images: {itemsDeleted} deleted", {
          itemsDeleted: res.itemsDeleted ?? 0,
        });
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;

/** Project endpoints that answer with an NDJSON stream ending in a done or error line. */
const STREAMED_OPERATIONS = new Set(["/up", "/pull", "/redeploy"]);

/**
 * Build a fan-out project-lifecycle method. Resolves each name to a project id,
 * issues the action, and records an operation-result per target. The argument
 * schema requires at least one name, so there is no "all projects" form.
 */
function makeLifecycle(
  operation: string,
  httpMethod: HttpMethod,
  suffix: string,
  description: string,
): MethodDefinition<z.ZodTypeAny, GlobalArgsT> {
  return {
    description: `${description} Fans out over a list of project names.`,
    arguments: LifecycleArgs,
    execute: async (
      args: z.infer<typeof LifecycleArgs>,
      context,
    ): Promise<{ dataHandles: DataHandle[] }> => {
      const g: GlobalArgsT = context.globalArgs;
      // A repeated name would run the action twice and write its record twice.
      const names: string[] = [...new Set<string>(args.names)];
      logInfo(context, "Running project {operation} on {names}", {
        operation,
        names,
      });
      const projects = coerceList(
        await arcane(g, "GET", `${ENV(g)}${ALL_PROJECTS}`),
      );
      const byName = new Map(
        projects.map((p) => [asString(pick(p, "name")), p] as const),
      );
      const missing = names.filter((n) => !byName.has(n));
      if (missing.length > 0) {
        throw new Error(
          `project(s) not found in Arcane: ${missing.join(", ")}`,
        );
      }
      const timestamp = new Date().toISOString();
      const handles: DataHandle[] = [];
      for (const name of names) {
        const id = asString(pick(byName.get(name)!, "id")) ?? "";
        const path = `${ENV(g)}/projects/${id}${suffix}`;
        if (httpMethod === "DELETE") {
          await deleteIfPresent(g, path, OPERATION_TIMEOUT_MS);
        } else {
          const body = await arcane(
            g,
            httpMethod,
            path,
            undefined,
            OPERATION_TIMEOUT_MS,
          );
          // up, pull and redeploy stream NDJSON, so the 200 alone shows nothing;
          // down and restart answer plain JSON and fail with an HTTP error.
          const failure = STREAMED_OPERATIONS.has(suffix)
            ? streamFailure(body)
            : undefined;
          if (failure !== undefined) {
            throw new Error(
              `Arcane ${operation} of '${name}' failed: ${failure}`,
            );
          }
        }
        handles.push(
          await context.writeResource(
            "operation-result",
            dataName("operation-result", operation, name),
            {
              operation,
              target: name,
              status: 200,
              success: true,
              timestamp,
            },
          ),
        );
      }
      logInfo(context, "Completed project {operation} on {count} projects", {
        operation,
        count: handles.length,
      });
      return { dataHandles: handles };
    },
  };
}

/**
 * Build the CRUD methods for a swarm secret or config (their APIs are symmetric).
 * Rotation is separate (see `makeRotate`) because swarm secrets/configs are immutable.
 */
function makeSwarmObject(
  kind: "secret" | "config",
): Record<string, MethodDefinition<z.ZodTypeAny, GlobalArgsT>> {
  const plural = kind === "secret" ? "secrets" : "configs";
  const resourceName = kind === "secret" ? "swarm-secret" : "swarm-config";
  const base = (g: GlobalArgsT): string => `${ENV(g)}/swarm/${plural}`;
  const createArgs = z.object({
    name: z.string().describe(`${kind} name`),
    value: z.string().meta({ sensitive: true }).describe(
      "Value. Supply via vault: ${{ vault.get(name, key) }}; never inline a secret",
    ),
    labels: z.record(z.string(), z.string()).optional().describe(
      "Optional spec labels",
    ),
  });
  return {
    [`${kind}_list`]: {
      description:
        `List swarm ${plural} (factory: one \`${resourceName}\` per entry, named \`${resourceName}:<name>\`)`,
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing swarm {plural}", { plural });
        await ensureSwarmManager(g);
        const rows = coerceList(await arcane(g, "GET", base(g)));
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const res = swarmObjectResource(r, "observed");
          handles.push(
            await context.writeResource(
              resourceName,
              dataName(resourceName, res.name as string),
              res,
            ),
          );
        }
        logInfo(context, "Listed {count} swarm {plural}", {
          plural,
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },
    [`${kind}_get`]: {
      description: `Get a single swarm ${kind} by name`,
      arguments: NameArg,
      execute: async (
        args: z.infer<typeof NameArg>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Reading swarm {kind} {name}", {
          kind,
          name: args.name,
        });
        await ensureSwarmManager(g);
        const found = await findSwarmObject(g, plural, args.name);
        if (!found) throw new Error(`swarm ${kind} '${args.name}' not found`);
        const res = swarmObjectResource(found, "observed");
        const handle = await context.writeResource(
          resourceName,
          dataName(resourceName, res.name as string),
          res,
        );
        logInfo(context, "Read swarm {kind} {name}", { kind, name: args.name });
        return { dataHandles: [handle] };
      },
    },
    [`${kind}_create`]: {
      description:
        `Create a swarm ${kind}. The value is supplied via vault (sensitive) and base64-encoded into spec.Data. ` +
        `Swarm ${plural} are immutable; to change a value, use ${kind}_rotate. ` +
        `Fails if the name already exists (Arcane answers 409): swarm never returns a stored value, so this cannot tell whether a re-run would be a no-op.`,
      arguments: createArgs,
      execute: async (
        args: z.infer<typeof createArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const spec: Json = { Name: args.name, Data: b64(args.value) };
        if (args.labels) spec.Labels = args.labels;
        logInfo(context, "Creating swarm {kind} {name}", {
          kind,
          name: args.name,
        });
        const created = unwrap(await arcane(g, "POST", base(g), { spec }));
        const id = createdId(created, `${kind} '${args.name}'`);
        const handle = await context.writeResource(
          resourceName,
          dataName(resourceName, args.name),
          {
            id,
            name: args.name,
            action: "created",
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Created swarm {kind} {name} ({id})", {
          kind,
          name: args.name,
          id,
        });
        return { dataHandles: [handle] };
      },
    },
    [`${kind}_remove`]: {
      description:
        `Remove a swarm ${kind} by name. Swarm blocks removal of an in-use ${kind} (Arcane answers 400, "in use by the following service"); that error is surfaced, never forced.`,
      arguments: NameArg,
      execute: async (
        args: z.infer<typeof NameArg>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Removing swarm {kind} {name}", {
          kind,
          name: args.name,
        });
        await ensureSwarmManager(g);
        const found = await findSwarmObject(g, plural, args.name);
        if (!found) throw new Error(`swarm ${kind} '${args.name}' not found`);
        const id = asString(pick(found, "id", "ID")) ?? "";
        await arcane(g, "DELETE", `${base(g)}/${id}`);
        const handle = await context.writeResource(
          resourceName,
          dataName(resourceName, args.name),
          {
            id,
            name: args.name,
            action: "deleted",
            observedAt: new Date().toISOString(),
          },
        );
        logInfo(context, "Removed swarm {kind} {name}", {
          kind,
          name: args.name,
        });
        return { dataHandles: [handle] };
      },
    },
  };
}

/**
 * Build the rotation method for a swarm secret or config. Swarm secrets/configs are
 * immutable, so rotation is: find the services that reference v1, create v2,
 * re-point those services to it (keeping the same mount path), wait for
 * convergence, then remove v1 (never forced; skipped if the old object is still
 * referenced or `removeOld:false`).
 */
function makeRotate(
  kind: "secret" | "config",
): Record<string, MethodDefinition<z.ZodTypeAny, GlobalArgsT>> {
  const plural = kind === "secret" ? "secrets" : "configs";
  const resourceName = kind === "secret" ? "swarm-secret" : "swarm-config";
  const rotateArgs = z.object({
    name: z.string().describe(`Existing ${kind} name to rotate`),
    value: z.string().meta({ sensitive: true }).describe(
      "New value. Supply via vault",
    ),
    newName: z.string().optional().describe(
      `Name for the new ${kind} version (default: <name>-v<UTC timestamp>)`,
    ),
    services: z.array(z.string()).optional().describe(
      "Service names to re-point (default: every service referencing the old name)",
    ),
    removeOld: z.boolean().default(true).describe(
      `Remove the old ${kind} after successful convergence`,
    ),
    healthTimeoutSec: z.number().int().positive().max(86_400).default(180),
    pollIntervalSec: z.number().int().positive().max(3600).default(5),
  });
  return {
    [`${kind}_rotate`]: {
      description:
        `Rotate a swarm ${kind} (they are immutable). Creates a new version, re-points referencing ` +
        `services to it (same mount path), waits for convergence, then removes the old ${kind} ` +
        `(unless still referenced or removeOld:false). Never forces an in-use removal.`,
      arguments: rotateArgs,
      execute: async (
        args: z.infer<typeof rotateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const handles: DataHandle[] = [];
        // Step records are keyed by the object being rotated, plus the
        // service for the per-service steps.
        const stepName = (operation: string, service?: string) =>
          dataName(
            "operation-result",
            `${kind}_rotate`,
            args.name,
            operation,
            ...(service !== undefined ? [service] : []),
          );
        const written = new Set<string>();
        const record = async (
          operation: string,
          target: string,
          success: boolean,
          status: number,
          detail: string,
          service?: string,
        ) => {
          handles.push(
            await context.writeResource(
              "operation-result",
              stepName(operation, service),
              {
                operation: `${kind}_rotate:${operation}`,
                target,
                status,
                success,
                detail,
                timestamp: new Date().toISOString(),
              },
            ),
          );
          written.add(stepName(operation, service));
        };
        // Every service seen, for deleting their step records from earlier runs.
        let serviceNames: string[] = [];
        try {
          const oldObj = await findSwarmObject(g, plural, args.name);
          if (!oldObj) {
            throw new Error(`swarm ${kind} '${args.name}' not found`);
          }
          const oldId = asString(pick(oldObj, "id", "ID")) ?? "";

          // Find the services to re-point before creating anything, so a
          // misspelt service name stops the rotation without leaving a new
          // version behind.
          const allServices = coerceList(
            await arcane(g, "GET", `${ENV(g)}/swarm/services?limit=-1`),
          );
          serviceNames = allServices.map((s) => asString(pick(s, "name")) ?? "")
            .filter((n) => n !== "");
          const wantSet = args.services
            ? new Set<string>(args.services)
            : undefined;
          const targets = [];
          for (const summary of allServices) {
            const sname = asString(pick(summary, "name"));
            if (wantSet && (!sname || !wantSet.has(sname))) continue;
            const sid = asString(pick(summary, "id", "ID")) ?? "";
            if (!sid) continue;
            const insp = unwrap(
              await arcane(g, "GET", `${ENV(g)}/swarm/services/${sid}`),
            );
            const fullSpec = pick(insp, "spec") as Json | undefined;
            if (!fullSpec) continue;
            const refs = serviceRefs(fullSpec, kind, args.name).length;
            if (refs > 0) {
              targets.push({
                sid,
                sname: sname ?? sid,
                insp,
                spec: fullSpec,
                refs,
              });
            }
          }
          if (wantSet) {
            const foundNames = new Set(targets.map((t) => t.sname));
            const missing = [...wantSet].filter((n) => !foundNames.has(n));
            if (missing.length) {
              throw new Error(
                `requested services not found or not referencing ${kind} '${args.name}': ${
                  missing.join(", ")
                }`,
              );
            }
          }

          // Create the new version, carrying over the old labels.
          const stamp = new Date().toISOString().replace(/[-:T.Z]/g, "").slice(
            0,
            14,
          );
          const newName: string = args.newName ?? `${args.name}-v${stamp}`;
          const spec: Json = { Name: newName, Data: b64(args.value) };
          const oldSpec = (pick(oldObj, "spec") as Json) ?? {};
          const oldLabels = pick(oldSpec, "Labels");
          if (oldLabels && typeof oldLabels === "object") {
            spec.Labels = oldLabels;
          }
          const created = unwrap(
            await arcane(g, "POST", `${ENV(g)}/swarm/${plural}`, { spec }),
          );
          const newId = createdId(created, `${kind} '${newName}'`);
          await record(
            "create",
            newName,
            true,
            200,
            `created ${kind} ${newName} (${newId})`,
          );
          handles.push(
            await context.writeResource(
              resourceName,
              dataName(resourceName, newName),
              {
                id: newId,
                name: newName,
                action: "created",
                observedAt: new Date().toISOString(),
              },
            ),
          );
          if (targets.length === 0) {
            await record(
              "repoint",
              args.name,
              true,
              200,
              `no services reference ${kind} '${args.name}'`,
            );
          }

          // Re-point each service: PUT its full spec with the version it was read at.
          const repointed: string[] = [];
          for (const t of targets) {
            repointServiceRefs(t.spec, kind, args.name, newId, newName);
            const versionObj = (pick(t.insp, "version") as Json) ?? {};
            const versionIndex = asNumber(pick(versionObj, "Index", "index"));
            const body: Json = { spec: t.spec };
            if (versionIndex !== undefined) body.version = versionIndex;
            try {
              await arcane(g, "PUT", `${ENV(g)}/swarm/services/${t.sid}`, body);
            } catch (e) {
              // Say what has already changed, since the rotation stops half done.
              const msg = e instanceof Error ? e.message : String(e);
              await record("repoint", t.sname, false, 0, msg, t.sname);
              throw new Error(
                `rotation of ${kind} '${args.name}' stopped: re-pointing service '${t.sname}' failed (${msg}). ` +
                  `Created ${kind} '${newName}'; already re-pointed: ${
                    repointed.length ? repointed.join(", ") : "none"
                  }; old ${kind} left in place.`,
              );
            }
            repointed.push(t.sname);
            await record(
              "repoint",
              t.sname,
              true,
              200,
              `re-pointed ${t.refs} ref(s)`,
              t.sname,
            );
          }

          // Wait for every rolling update to complete.
          let allConverged = true;
          for (const t of targets) {
            const c = await pollServiceConverged(
              g,
              t.sid,
              args.healthTimeoutSec,
              args.pollIntervalSec,
            );
            await record(
              "converge",
              t.sname,
              c.converged,
              c.converged ? 200 : 503,
              c.detail,
              t.sname,
            );
            if (!c.converged) allConverged = false;
          }
          if (!allConverged) {
            throw new Error(
              `rotation of ${kind} '${args.name}' → '${newName}': not all services converged; old ${kind} left in place. Investigate, then re-run or swarm_service_rollback`,
            );
          }

          // Remove the old version. Never forced: an in-use conflict is recorded.
          if (args.removeOld !== false) {
            try {
              await arcane(g, "DELETE", `${ENV(g)}/swarm/${plural}/${oldId}`);
              await record(
                "remove-old",
                args.name,
                true,
                200,
                `removed old ${kind} ${args.name}`,
              );
              handles.push(
                await context.writeResource(
                  resourceName,
                  dataName(resourceName, args.name),
                  {
                    id: oldId,
                    name: args.name,
                    action: "deleted",
                    observedAt: new Date().toISOString(),
                  },
                ),
              );
            } catch (e) {
              const msg = e instanceof Error ? e.message : String(e);
              // Swarm refuses an in-use object as InvalidArgument, which Arcane
              // answers with 400, so match swarm's text, not a status.
              if (/in use/i.test(msg)) {
                await record(
                  "remove-old",
                  args.name,
                  false,
                  Number(/-> HTTP (\d{3})/.exec(msg)?.[1] ?? 0),
                  `old ${kind} still in use; left in place (not forced)`,
                );
              } else {
                throw e;
              }
            }
          } else {
            await record(
              "remove-old",
              args.name,
              true,
              200,
              `removeOld:false; old ${kind} retained`,
            );
          }

          logInfo(
            context,
            "Rotated swarm {kind} {from} to {to} ({services} services)",
            {
              kind,
              from: args.name,
              to: newName,
              services: targets.length,
            },
          );
          return { dataHandles: handles };
        } finally {
          const candidates = ["create", "repoint", "remove-old"].map((op) =>
            stepName(op)
          );
          for (const service of serviceNames) {
            candidates.push(
              stepName("repoint", service),
              stepName("converge", service),
            );
          }
          await deleteUnreachedSteps(context, candidates, written);
        }
      },
    },
  };
}
