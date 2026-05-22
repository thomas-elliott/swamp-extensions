import { z } from "npm:zod@4";
// Type-only imports — erased at compile time, never bundled. They anchor the
// `satisfies ModelDefinition<typeof GlobalArgs>` clause on `model` (and the
// factory return types) so every method's `execute` is contextually typed
// without an explicit `any` on its parameters. See swamp-extension typing.md.
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
 * `@thomas/arcane` — management of an Arcane Docker instance, fronted entirely
 * by Arcane's REST API (X-API-Key auth). Every mutation goes through Arcane; the
 * one local subprocess is read-only compose validation (`docker compose config`).
 *
 * Method sections (by prefix):
 *   - `gitops_*` — set up + drive Arcane Git Sync (repo connection, syncs, triggers).
 *   - `project_*` — compose projects: list/lifecycle plus direct-API authoring
 *     (`project_create`/`project_update` push compose content) and a validated,
 *     mode-aware `project_deploy` orchestration.
 *   - `secret_*` / `config_*` / `swarm_service_*` — swarm secret/config CRUD and the
 *     rotation orchestrations (`secret_rotate`/`config_rotate`).
 *
 * GitOps is one supported deployment mode, not the extension's identity: direct
 * (API) mode and gitops mode are both first-class, chosen per project.
 *
 * The extension only ever *consumes* an API key — it never touches the Arcane
 * container. Mint the key however suits your install (`ADMIN_STATIC_API_KEY` env
 * for declarative setups, or Settings → API Keys), store it in a vault, and
 * reference it from `apiKey`.
 */

const RepositorySpec = z.object({
  name: z.string().describe("Display name of the git repository connection"),
  url: z.string().describe("Clone URL, e.g. git@github.com:me/gitops.git"),
  authType: z.string().default("none").describe(
    "Arcane auth type: none | token | ssh (verify accepted values for your version)",
  ),
  enabled: z.boolean().default(true),
  description: z.string().optional(),
  token: z.string().optional().meta({ sensitive: true }).describe(
    "PAT for token auth — secret; supply via vault. Sent only when present.",
  ),
  username: z.string().optional(),
  sshKey: z.string().optional().meta({ sensitive: true }).describe(
    "SSH private key for ssh auth — secret; supply via vault. Sent only when present.",
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
  branch: z.string().default("main"),
  projectName: z.string().optional().describe(
    "Deployed project name; defaults to `name`",
  ),
  repository: z.string().optional().describe(
    "Repository connection name to resolve the id from; defaults to globalArgs.repository.name",
  ),
  autoSync: z.boolean().default(true),
  syncInterval: z.number().int().default(5).describe(
    "Auto-sync interval in minutes",
  ),
  syncDirectory: z.boolean().default(true).describe(
    "The 'Sync Files' toggle: pull sibling files alongside the compose file",
  ),
  targetType: z.string().default("project").describe(
    "project (compose) | swarm",
  ),
});

const GlobalArgs = z.object({
  baseUrl: z.string().describe(
    "Arcane base URL including port, e.g. https://arcane-tylo.smol.cloud:8443",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "Arcane API key (X-API-Key). Supply via vault: ${{ vault.get(name, key) }}",
  ),
  environmentId: z.string().default("0").describe(
    "Arcane environment id; 0 is the local Docker environment",
  ),
  skipTlsVerify: z.boolean().default(false).describe(
    "Accept self-signed certs (default false — a valid cert is expected)",
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

const ProjectResource = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string().default("unknown"),
  observedAt: z.string(),
});

const OperationResultResource = z.object({
  operation: z.string(),
  target: z.string(),
  status: z.number().describe("HTTP status of the operation"),
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
    ".env content (may carry secrets — marked sensitive)",
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
  updateState: z.string().optional(),
  action: Action,
  observedAt: z.string(),
});

const SwarmStackResource = z.object({
  id: z.string().optional(),
  name: z.string(),
  namespace: z.string().optional(),
  services: z.number().optional().describe("Number of services in the stack"),
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

type GlobalArgsT = z.infer<typeof GlobalArgs>;
type Json = Record<string, unknown>;
type HttpResult = { status: number; body: string };
type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

/** Low-level HTTPS/HTTP request returning the raw status and body text. */
function httpRequest(
  opts: https.RequestOptions,
  secure: boolean,
  body?: string,
): Promise<HttpResult> {
  const transport = secure ? https : http;
  return new Promise((resolve, reject) => {
    const req = transport.request(opts, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString("utf8"),
        }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(
      REQUEST_TIMEOUT_MS,
      () => req.destroy(new Error("request timed out")),
    );
    if (body) req.write(body);
    req.end();
  });
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

type ArcaneFn = (
  g: GlobalArgsT,
  method: HttpMethod,
  path: string,
  body?: unknown,
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
): Promise<unknown> {
  return (_arcaneOverride ?? arcaneReal)(g, method, path, body);
}

/** The real HTTP implementation behind `arcane()`. */
async function arcaneReal(
  g: GlobalArgsT,
  method: HttpMethod,
  path: string,
  body?: unknown,
): Promise<unknown> {
  const u = new URL(g.baseUrl.replace(/\/+$/, "") + API + path);
  const secure = u.protocol === "https:";
  const payload = body !== undefined ? JSON.stringify(body) : undefined;
  const headers: Record<string, string> = {
    "X-API-Key": g.apiKey,
    "Accept": "application/json",
  };
  if (payload) {
    headers["Content-Type"] = "application/json";
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
    payload,
  );
  if (res.status >= 400) {
    throw new Error(
      `Arcane ${method} ${path} -> HTTP ${res.status}: ${res.body}`,
    );
  }
  return safeJson(res.body);
}

/** DELETE that treats 404 (already gone) as success, for idempotent pruning. */
async function deleteIfPresent(g: GlobalArgsT, path: string): Promise<void> {
  try {
    await arcane(g, "DELETE", path);
  } catch (e) {
    if (e instanceof Error && /HTTP 404/.test(e.message)) return;
    throw e;
  }
}

/** Extract an array from an Arcane list response that may be bare or wrapped. */
export function coerceList(resp: unknown): Json[] {
  if (Array.isArray(resp)) return resp as Json[];
  if (resp && typeof resp === "object") {
    const o = resp as Record<string, unknown>;
    for (const k of ["data", "items", "results"]) {
      if (Array.isArray(o[k])) return o[k] as Json[];
    }
    if (o.data && typeof o.data === "object") {
      const d = o.data as Record<string, unknown>;
      for (const k of ["items", "results"]) {
        if (Array.isArray(d[k])) return d[k] as Json[];
      }
    }
  }
  return [];
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
 * Slugify an arbitrary label into a safe swamp data instance name. swamp rejects
 * instance names containing `/`, `..`, `\`, or null bytes (path-traversal guard),
 * so a compose path like `projects/web/compose.yaml` must be flattened.
 */
function slug(s: string): string {
  const out = s.replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  return out.length > 0 ? out : "validation";
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

type ValidateFn = (
  composeContent: string,
  envContent?: string,
) => Promise<{ version: string }>;

let _validateOverride: ValidateFn | null = null;

/** Test-only seam: substitute the local compose validator. Pass `null` to restore the real one. */
export function __setComposeValidator(fn: ValidateFn | null): void {
  _validateOverride = fn;
}

/**
 * Validate compose content LOCALLY with `docker compose config -q` (guardrail #9b:
 * read-only, on the swamp host, never via SSH). Fails closed — any non-zero exit
 * throws with the validator's stderr. Returns the local compose version so
 * version skew vs Arcane's deployer (an accepted risk, §3) stays visible. Routes
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

/** Find a project by name; returns the raw Arcane project object or undefined. */
async function findProject(
  g: GlobalArgsT,
  name: string,
): Promise<Json | undefined> {
  const projects = coerceList(
    await arcane(g, "GET", `${ENV(g)}/projects?limit=-1`),
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
 * service may report `unhealthy`, and (when Arcane reports counts) runningCount must
 * cover serviceCount. Extracted from the poller so it can be unit-tested.
 */
export function projectHealthy(
  status: string,
  serviceCount: number,
  runningCount: number,
  anyUnhealthy: boolean,
): boolean {
  return status === "running" && !anyUnhealthy &&
    (serviceCount === 0 || runningCount >= serviceCount);
}

/**
 * Poll a project until its containers are running (status `running` and, when
 * Arcane reports counts, runningCount >= serviceCount) or the timeout elapses.
 * No runtime service reporting `unhealthy` is tolerated. Returns the last observed state.
 */
async function pollProjectHealthy(
  g: GlobalArgsT,
  id: string,
  timeoutSec: number,
  intervalSec: number,
): Promise<HealthResult> {
  const deadline = Date.now() + timeoutSec * 1000;
  let last: HealthResult = {
    healthy: false,
    status: "unknown",
    detail: "no observation",
  };
  while (Date.now() < deadline) {
    const p = unwrap(await arcane(g, "GET", `${ENV(g)}/projects/${id}`));
    const status = asString(pick(p, "status", "state")) ?? "unknown";
    const serviceCount = Number(pick(p, "serviceCount") ?? 0);
    const runningCount = Number(pick(p, "runningCount") ?? 0);
    let unhealthy = false;
    try {
      const rt = unwrap(
        await arcane(g, "GET", `${ENV(g)}/projects/${id}/runtime`),
      );
      const services = Array.isArray(pick(rt, "runtimeServices"))
        ? (pick(rt, "runtimeServices") as Json[])
        : [];
      unhealthy = services.some((s) =>
        asString(pick(s, "health")) === "unhealthy"
      );
    } catch { /* runtime view is best-effort */ }
    last = {
      healthy: projectHealthy(status, serviceCount, runningCount, unhealthy),
      status,
      detail: `status=${status} running=${runningCount}/${serviceCount}${
        unhealthy ? " (a service is unhealthy)" : ""
      }`,
    };
    if (last.healthy) return last;
    await sleep(intervalSec * 1000);
  }
  return last;
}

/** UTF-8 → base64, for the write-only `Data` field of a swarm secret/config spec. */
export const b64 = (s: string): string =>
  Buffer.from(s, "utf8").toString("base64");

/**
 * Confirm the target environment is swarm-enabled before a swarm operation.
 * (Manager rights are enforced by Arcane — a non-manager mutation returns 403,
 * which `arcane()` surfaces — so this is the early, friendly guard.)
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
      `environment ${g.environmentId} is not swarm-enabled — point environmentId at a swarm-manager environment`,
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
  return rows.find((r) => {
    const spec = (pick(r, "spec") as Json) ?? {};
    return asString(pick(r, "name")) === name ||
      asString(pick(spec, "Name", "name")) === name;
  });
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

/** Shape a swarm service summary into a `swarm-service` resource. */
function swarmServiceResource(
  o: Json,
  action: string,
): Record<string, unknown> {
  const spec = (pick(o, "spec") as Json) ?? {};
  const updateStatus = pick(o, "updateStatus") as Json | undefined;
  return {
    id: asString(pick(o, "id", "ID")) ?? "",
    name: asString(pick(o, "name")) ?? asString(pick(spec, "Name", "name")) ??
      "unnamed",
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
 * Returns how many references were rewritten. Pure (no I/O) — unit-tested.
 */
export function repointServiceRefs(
  spec: Json,
  kind: "secret" | "config",
  oldName: string,
  newId: string,
  newName: string,
): number {
  const idKey = kind === "secret" ? "SecretID" : "ConfigID";
  const nameKey = kind === "secret" ? "SecretName" : "ConfigName";
  const arrKey = kind === "secret" ? "Secrets" : "Configs";
  const tt = pick(spec, "TaskTemplate") as Json | undefined;
  const cs = tt ? (pick(tt, "ContainerSpec") as Json | undefined) : undefined;
  const refs = cs ? pick(cs, arrKey) : undefined;
  if (!Array.isArray(refs)) return 0;
  let count = 0;
  for (const ref of refs as Json[]) {
    if (asString(pick(ref, nameKey)) === oldName) {
      ref[idKey] = newId;
      ref[nameKey] = newName;
      count++;
    }
  }
  return count;
}

type ConvergeResult = { converged: boolean; detail: string };

/**
 * Pure predicate: how is a swarm service's rolling update going? `failed` for a
 * paused/rolled-back update; `converged` when there is no in-progress update (or it
 * `completed`) and replicas are satisfied; otherwise `pending`. Unit-tested.
 */
export function serviceConvergence(
  state: string | undefined,
  hasUpdateStatus: boolean,
  replicas: number | undefined,
  running: number | undefined,
): "converged" | "failed" | "pending" {
  if (
    state === "paused" || state === "rollback_completed" ||
    state === "rollback_paused"
  ) {
    return "failed";
  }
  const updateOk = !hasUpdateStatus || state === "completed";
  const replicasOk = replicas === undefined ||
    (running !== undefined && running >= replicas);
  return updateOk && replicasOk ? "converged" : "pending";
}

/**
 * Poll a swarm service until its rolling update completes and replicas are running,
 * or the timeout elapses. Converged = no `updateStatus` (or `State == completed`) and
 * (when the summary reports counts) runningReplicas >= replicas. A paused/rolled-back
 * update returns not-converged immediately.
 */
async function pollServiceConverged(
  g: GlobalArgsT,
  serviceId: string,
  timeoutSec: number,
  intervalSec: number,
): Promise<ConvergeResult> {
  const deadline = Date.now() + timeoutSec * 1000;
  let detail = "no observation";
  while (Date.now() < deadline) {
    const insp = unwrap(
      await arcane(g, "GET", `${ENV(g)}/swarm/services/${serviceId}`),
    );
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
    } catch { /* summary counts are best-effort */ }
    detail = `updateState=${state ?? "none"} running=${running ?? "?"}/${
      replicas ?? "?"
    }`;
    const verdict = serviceConvergence(state, !!us, replicas, running);
    if (verdict === "failed") return { converged: false, detail };
    if (verdict === "converged") return { converged: true, detail };
    await sleep(intervalSec * 1000);
  }
  return { converged: false, detail };
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
    itemsDeleted: names.length || undefined,
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
 * Poll a swarm stack's services until each has runningReplicas >= replicas, or the
 * timeout elapses (reads GET /swarm/stacks/{name}/services). A stack with no services
 * reported yet counts as not-converged. Returns the last observed state.
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
  while (Date.now() < deadline) {
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
        parts.push(`${name} ${running ?? "?"}/${replicas ?? "?"}`);
        if (
          replicas === undefined || running === undefined || running < replicas
        ) {
          allUp = false;
        }
      }
      detail = parts.join(", ");
      if (allUp) return { converged: true, detail };
    }
    await sleep(intervalSec * 1000);
  }
  return { converged: false, detail };
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
 * number of DELETEs issued. Arcane's first DELETE tears down the running services
 * (`docker stack rm`) but RETAINS its stored stack record — `swarm_stack_get` still
 * returns it (with `services:0`) and `swarm_stack_list` still shows it — so a single
 * DELETE leaves the stack half-removed. We therefore DELETE, poll the stack GET, and
 * re-issue DELETE until the record 404s. A non-404 DELETE error (e.g. an in-use
 * conflict) propagates immediately — we never force around it (guardrail #5). If the
 * record is still present at the deadline we throw rather than silently report success.
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
          `within ${timeoutSec}s — Arcane did not clear it.`,
      );
    }
    await sleep(intervalSec * 1000);
  }
}

// ---------------------------------------------------------------------------
// Per-method argument schemas.
//
// Each method's `arguments` schema is named here so it is the single source of
// truth: it is referenced both by the method's `arguments:` field and by its
// `execute` parameter type via `z.infer<typeof ...>`. Swamp validates `args`
// against the schema before calling `execute`, so the inferred type is an
// accurate, zero-cost compile-time narrowing of the already-validated input.
// ---------------------------------------------------------------------------

/** Shared: a single required `name`. */
const NameArg = z.object({ name: z.string() });

const GitopsSyncEnsureArgs = z.object({
  prune: z.boolean().default(false).describe(
    "Delete existing syncs whose name is not in globalArgs.syncs (destructive)",
  ),
});

const GitopsSyncTriggerArgs = z.object({
  names: z.array(z.string()).default([]).describe(
    "Sync names to trigger; empty means all",
  ),
});

const ProjectValidateArgs = z.object({
  target: z.string().optional().describe(
    "Label for the result (defaults to composePath or 'inline')",
  ),
  composePath: z.string().optional().describe("Path to a local compose file"),
  composeContent: z.string().optional().describe(
    "Inline compose content (instead of composePath)",
  ),
  envPath: z.string().optional().describe("Path to a local .env file"),
  envContent: z.string().optional().describe(
    "Inline .env content (instead of envPath)",
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
  envContent: z.string().optional(),
  validate: z.boolean().default(true).describe(
    "Run local compose validation before pushing (fail-closed)",
  ),
});

const ProjectUpdateArgs = z.object({
  name: z.string().describe("Project name"),
  composePath: z.string().optional(),
  composeContent: z.string().optional(),
  envPath: z.string().optional(),
  envContent: z.string().optional(),
  validate: z.boolean().default(true),
});

const ProjectDeployArgs = z.object({
  name: z.string().describe("Project name"),
  composePath: z.string().optional().describe(
    "Direct mode: new compose file to deploy",
  ),
  composeContent: z.string().optional().describe(
    "Direct mode: inline compose content",
  ),
  envPath: z.string().optional(),
  envContent: z.string().optional(),
  rollback: z.boolean().default(true).describe(
    "Roll back to prior state on failure (direct mode). false = stop and report, leaving the failed state for inspection.",
  ),
  healthTimeoutSec: z.number().int().default(120).describe(
    "How long to wait for the project to become healthy",
  ),
  pollIntervalSec: z.number().int().default(5),
});

const SwarmServiceForceUpdateArgs = z.object({
  name: z.string().describe("Swarm service name (e.g. unifi_unifi)"),
  convergeTimeoutSec: z.number().int().default(180),
  pollIntervalSec: z.number().int().default(5),
});

const SwarmStackValidateArgs = z.object({
  name: z.string().describe("Stack name"),
  composePath: z.string().optional(),
  composeContent: z.string().optional(),
  envPath: z.string().optional(),
  envContent: z.string().optional(),
});

const SwarmStackDeployArgs = z.object({
  name: z.string().describe("Stack name"),
  composePath: z.string().optional(),
  composeContent: z.string().optional(),
  envPath: z.string().optional(),
  envContent: z.string().optional(),
  prune: z.boolean().default(false).describe(
    "Remove services no longer present in the compose file",
  ),
  convergeTimeoutSec: z.number().int().default(180),
  pollIntervalSec: z.number().int().default(5),
});

const SwarmStackRemoveArgs = z.object({
  name: z.string(),
  removeTimeoutSec: z.number().int().default(30).describe(
    "Max seconds to keep re-issuing DELETE until the stack record 404s",
  ),
  pollIntervalSec: z.number().int().default(2),
});

const SwarmStackTasksArgs = z.object({
  name: z.string().describe("Stack name"),
  onlyProblems: z.boolean().default(false).describe(
    "Emit only tasks whose currentState is rejected/failed/orphaned (the error-bearing ones)",
  ),
});

const VolumeRemoveArgs = z.object({
  name: z.string(),
  force: z.boolean().default(false).describe(
    "Force removal even if Docker reports the volume in use (discouraged)",
  ),
});

const ImagePruneArgs = z.object({
  dangling: z.boolean().default(true).describe(
    "true = only dangling layers (safe); false = all unused images",
  ),
});

const LifecycleArgs = z.object({
  names: z.array(z.string()).min(1).describe("Project names to operate on"),
});

export const model = {
  type: "@thomas/arcane",
  version: "2026.05.22.1",
  globalArguments: GlobalArgs,
  upgrades: [
    {
      toVersion: "2026.05.21.1",
      description:
        "Rename methods to the gitops_/project_ prefix convention and add the Phase 2 (direct compose + deploy) and Phase 3 (swarm secret/config + rotation) methods/resources. globalArguments schema is unchanged, so this is a no-op data migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.05.22.1",
      description:
        "Add the swarm_stack_ section (swarm_stack_validate via config/render [fail-closed], swarm_stack_deploy, _list, _get, _remove, _tasks), swarm_service_force_update, volume_list/_remove/_prune, network_prune, image_prune, plus swarm-stack / swarm-stack-render / swarm-task / volume / prune-result resources. globalArguments schema is unchanged, so this is a no-op data migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
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
        "Result of Arcane's swarm-stack config render — the mandatory pre-deploy validation gate",
      schema: SwarmStackRenderResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "swarm-task": {
      description:
        "A swarm task (a replica placement attempt) with state + error — the deploy debug view",
      schema: SwarmTaskResource,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "volume": {
      description: "A docker volume (incl. inUse — for spotting orphans)",
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
    gitops_repo_list: {
      description:
        "List Arcane git repository connections (factory: one `repository` per entry, keyed by name)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing Arcane git repositories");
        const rows = coerceList(
          await arcane(g, "GET", "/customize/git-repositories"),
        );
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const name = asString(pick(r, "name")) ?? "unnamed";
          handles.push(
            await context.writeResource("repository", name, {
              id: asString(pick(r, "id")) ?? "",
              name,
              url: asString(pick(r, "url")) ?? "",
              authType: asString(pick(r, "authType", "auth_type")),
              enabled: pick(r, "enabled") as boolean | undefined,
              description: asString(pick(r, "description")),
              action: "observed",
              observedAt,
            }),
          );
        }
        logInfo(context, "Listed Arcane git repositories", {
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
            "globalArgs.repository is not set — nothing to reconcile",
          );
        }
        logInfo(context, "Reconciling Arcane git repository", {
          name: desired.name,
        });
        const existing = coerceList(
          await arcane(g, "GET", "/customize/git-repositories"),
        )
          .find((r) => asString(pick(r, "name")) === desired.name);

        const payload: Json = {
          name: desired.name,
          url: desired.url,
          authType: desired.authType,
          enabled: desired.enabled,
        };
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
          const created = unwrap(
            await arcane(g, "POST", "/customize/git-repositories", payload),
          );
          id = asString(pick(created, "id")) ?? "";
          action = "created";
        }
        const handle = await context.writeResource("repository", desired.name, {
          id,
          name: desired.name,
          url: desired.url,
          authType: desired.authType,
          enabled: desired.enabled,
          description: desired.description,
          action,
          observedAt: new Date().toISOString(),
        });
        logInfo(context, "Reconciled Arcane git repository", {
          name: desired.name,
          action,
        });
        return { dataHandles: [handle] };
      },
    },

    gitops_sync_list: {
      description:
        "List Arcane GitOps syncs (factory: one `sync` per entry, keyed by name)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Listing Arcane GitOps syncs");
        const rows = coerceList(
          await arcane(g, "GET", `${ENV(g)}/gitops-syncs`),
        );
        const observedAt = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const s of rows) {
          const name = asString(pick(s, "name")) ?? "unnamed";
          const v = syncView(s);
          handles.push(
            await context.writeResource("sync", name, {
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
        logInfo(context, "Listed Arcane GitOps syncs", {
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    gitops_sync_ensure: {
      description:
        "Reconcile GitOps syncs from globalArgs.syncs against Arcane (create missing, update drifted). With prune=true, deletes syncs not in the desired list.",
      arguments: GitopsSyncEnsureArgs,
      execute: async (
        args: z.infer<typeof GitopsSyncEnsureArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Reconciling Arcane GitOps syncs", {
          desired: g.syncs.length,
          prune: args.prune ?? false,
        });
        const repos = coerceList(
          await arcane(g, "GET", "/customize/git-repositories"),
        );
        const existing = coerceList(
          await arcane(g, "GET", `${ENV(g)}/gitops-syncs`),
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
              `repository connection '${wanted}' not found in Arcane — run gitops_repo_ensure first`,
            );
          }
          return id;
        };

        for (const desired of g.syncs) {
          const repositoryId = repoId(desired.repository);
          const payload: Json = {
            name: desired.name,
            branch: desired.branch,
            composePath: desired.composePath,
            repositoryId,
            projectName: desired.projectName ?? desired.name,
            autoSync: desired.autoSync,
            syncInterval: desired.syncInterval,
            syncDirectory: desired.syncDirectory,
            targetType: desired.targetType,
          };
          const found = existing.find((s) =>
            asString(pick(s, "name")) === desired.name
          );

          let id: string;
          let action: "created" | "updated" | "unchanged";
          if (found) {
            id = asString(pick(found, "id")) ?? "";
            const drifted = JSON.stringify(syncView(found)) !==
              JSON.stringify(syncView({ ...payload }));
            if (drifted) {
              await arcane(g, "PUT", `${ENV(g)}/gitops-syncs/${id}`, payload);
              action = "updated";
            } else {
              action = "unchanged";
            }
          } else {
            const created = unwrap(
              await arcane(g, "POST", `${ENV(g)}/gitops-syncs`, payload),
            );
            id = asString(pick(created, "id")) ?? "";
            action = "created";
          }
          handles.push(
            await context.writeResource("sync", desired.name, {
              id,
              name: desired.name,
              branch: desired.branch,
              composePath: desired.composePath,
              repositoryId,
              projectName: desired.projectName ?? desired.name,
              autoSync: desired.autoSync,
              syncInterval: desired.syncInterval,
              syncDirectory: desired.syncDirectory,
              targetType: desired.targetType,
              action,
              observedAt,
            }),
          );
          logInfo(context, "Reconciled sync", { name: desired.name, action });
        }

        if (args.prune) {
          const desiredNames = new Set(g.syncs.map((s) => s.name));
          for (const s of existing) {
            const name = asString(pick(s, "name"));
            if (!name || desiredNames.has(name)) continue;
            const id = asString(pick(s, "id")) ?? "";
            await deleteIfPresent(g, `${ENV(g)}/gitops-syncs/${id}`);
            handles.push(
              await context.writeResource("sync", name, {
                id,
                name,
                action: "deleted",
                observedAt,
              }),
            );
            logInfo(context, "Pruned sync", { name });
          }
        }

        logInfo(context, "Reconciled Arcane GitOps syncs", {
          written: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    gitops_sync_trigger: {
      description:
        "Trigger a git pull for the named syncs (fan-out). Empty `names` triggers all syncs.",
      arguments: GitopsSyncTriggerArgs,
      execute: async (
        args: z.infer<typeof GitopsSyncTriggerArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        logInfo(context, "Triggering Arcane syncs", {
          names: args.names ?? [],
        });
        const existing = coerceList(
          await arcane(g, "GET", `${ENV(g)}/gitops-syncs`),
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
        const timestamp = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const s of targets) {
          const name = asString(pick(s, "name")) ?? "unnamed";
          const id = asString(pick(s, "id")) ?? "";
          await arcane(g, "POST", `${ENV(g)}/gitops-syncs/${id}/sync`);
          handles.push(
            await context.writeResource("operation-result", `sync-${name}`, {
              operation: "sync",
              target: name,
              status: 200,
              success: true,
              timestamp,
            }),
          );
        }
        logInfo(context, "Triggered Arcane syncs", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    project_list: {
      description:
        "List Arcane compose projects (factory: one `project` per entry, keyed by name)",
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
            await context.writeResource("project", name, {
              id: asString(pick(p, "id")) ?? "",
              name,
              status: asString(pick(p, "status", "state")) ?? "unknown",
              observedAt,
            }),
          );
        }
        logInfo(context, "Listed Arcane projects", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    project_validate: {
      description:
        "Validate compose content LOCALLY with `docker compose config` (fail-closed, read-only — no Arcane mutation). Takes composePath/envPath or inline composeContent/envContent.",
      arguments: ProjectValidateArgs,
      execute: async (
        args: z.infer<typeof ProjectValidateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const { composeContent, envContent } = await resolveComposeInput(args);
        const target = args.target ?? args.composePath ?? "inline";
        logInfo(context, "Validating compose content", { target });
        const { version } = await composeConfigValidate(
          composeContent,
          envContent,
        );
        const handle = await context.writeResource("validation", slug(target), {
          target,
          valid: true,
          composeVersion: version,
          detail: `validated with docker compose ${version}`,
          timestamp: new Date().toISOString(),
        });
        logInfo(context, "Compose content valid", {
          target,
          composeVersion: version,
        });
        return { dataHandles: [handle] };
      },
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
        const id = await resolveProjectId(g, args.name);
        const d = unwrap(
          await arcane(g, "GET", `${ENV(g)}/projects/${id}/compose`),
        );
        const handle = await context.writeResource(
          "project-detail",
          args.name,
          projectDetail(args.name, id, d),
        );
        logInfo(context, "Read Arcane project detail", { name: args.name });
        return { dataHandles: [handle] };
      },
    },

    project_create: {
      description:
        "Create a compose project in Arcane (direct mode), pushing compose content via the API. Validates locally first (fail-closed unless validate:false).",
      arguments: ProjectCreateArgs,
      execute: async (
        args: z.infer<typeof ProjectCreateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const { composeContent, envContent } = await resolveComposeInput(args);
        if (args.validate !== false) {
          await composeConfigValidate(composeContent, envContent);
        }
        const body: Json = { name: args.name, composeContent };
        if (envContent !== undefined) body.envContent = envContent;
        logInfo(context, "Creating Arcane project", { name: args.name });
        const created = unwrap(
          await arcane(g, "POST", `${ENV(g)}/projects`, body),
        );
        const id = asString(pick(created, "id")) ?? "";
        const handle = await context.writeResource("project", args.name, {
          id,
          name: args.name,
          status: asString(pick(created, "status", "state")) ?? "unknown",
          observedAt: new Date().toISOString(),
        });
        logInfo(context, "Created Arcane project", { name: args.name, id });
        return { dataHandles: [handle] };
      },
    },

    project_update: {
      description:
        "Update a compose project's content in Arcane (direct mode). Validates locally first (fail-closed unless validate:false). Does NOT redeploy — use project_redeploy or project_deploy.",
      arguments: ProjectUpdateArgs,
      execute: async (
        args: z.infer<typeof ProjectUpdateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const id = await resolveProjectId(g, args.name);
        const { composeContent, envContent } = await resolveComposeInput(args);
        if (args.validate !== false) {
          await composeConfigValidate(composeContent, envContent);
        }
        const body: Json = { composeContent };
        if (envContent !== undefined) body.envContent = envContent;
        logInfo(context, "Updating Arcane project", { name: args.name, id });
        const updated = unwrap(
          await arcane(g, "PUT", `${ENV(g)}/projects/${id}`, body),
        );
        const handle = await context.writeResource("project", args.name, {
          id,
          name: args.name,
          status: asString(pick(updated, "status", "state")) ?? "unknown",
          observedAt: new Date().toISOString(),
        });
        logInfo(context, "Updated Arcane project", { name: args.name });
        return { dataHandles: [handle] };
      },
    },

    project_deploy: {
      description:
        "Validated, mode-aware deploy of a compose project. Snapshots prior state, applies, polls health, and rolls back by default on failure. " +
        "Direct mode: validate -> create/update compose -> redeploy -> on failure re-apply prior content (or destroy a failed first deploy). " +
        "GitOps mode: trigger sync -> redeploy -> on failure report (git revert is left to the user; auto git rollback needs the gitops authoring helpers).",
      arguments: ProjectDeployArgs,
      execute: async (
        args: z.infer<typeof ProjectDeployArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const name: string = args.name;
        const handles: DataHandle[] = [];
        const record = async (
          operation: string,
          success: boolean,
          status: number,
          detail: string,
        ) => {
          handles.push(
            await context.writeResource(
              "operation-result",
              `deploy-${name}-${operation}`,
              {
                operation: `deploy:${operation}`,
                target: name,
                status,
                success,
                detail,
                timestamp: new Date().toISOString(),
              },
            ),
          );
        };

        // 1. Resolve + snapshot prior state; detect mode via gitOpsManagedBy.
        const existing = await findProject(g, name);
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
              `${name}-prior`,
              projectDetail(name, id, prior),
            ),
          );
        }
        const gitops = !!gitOpsManagedBy && gitOpsManagedBy.length > 0;
        logInfo(context, "Deploying project", {
          name,
          mode: gitops ? "gitops" : "direct",
          firstDeploy: isFirstDeploy,
        });

        // 2a. GitOps mode — never push inline content (don't fight the sync).
        if (gitops) {
          if (
            args.composePath !== undefined || args.composeContent !== undefined
          ) {
            throw new Error(
              `project '${name}' is gitops-managed (${gitOpsManagedBy}); commit to git and let the sync deliver content — do not pass compose content to project_deploy`,
            );
          }
          const syncs = coerceList(
            await arcane(g, "GET", `${ENV(g)}/gitops-syncs`),
          );
          const sync = syncs.find((s) =>
            asString(pick(s, "projectName", "project_name")) === name ||
            asString(pick(s, "name")) === name
          );
          if (sync) {
            const sid = asString(pick(sync, "id")) ?? "";
            await arcane(g, "POST", `${ENV(g)}/gitops-syncs/${sid}/sync`);
            await record(
              "sync",
              true,
              200,
              `triggered sync ${asString(pick(sync, "name"))}`,
            );
          } else {
            await record(
              "sync",
              true,
              200,
              "no matching sync found; redeploying current content",
            );
          }
          await arcane(g, "POST", `${ENV(g)}/projects/${id}/redeploy`);
          const health = await pollProjectHealthy(
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
              `gitops deploy of '${name}' did not become healthy (${health.detail}). Auto git rollback is not enabled — revert the commit and re-sync manually.`,
            );
          }
          logInfo(context, "GitOps deploy healthy", { name });
          return { dataHandles: handles };
        }

        // 2b. Direct mode — requires new content; validate fail-closed.
        if (
          args.composePath === undefined && args.composeContent === undefined
        ) {
          throw new Error(
            `direct-mode deploy of '${name}' requires composePath or composeContent`,
          );
        }
        const { composeContent, envContent } = await resolveComposeInput(args);
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

        // 3. Apply (create/update) → redeploy → health, capturing ANY failure. Arcane
        //    rejects a bad deploy synchronously (a container that exits is returned as
        //    HTTP 400, not a 200 + async failure), so the redeploy can throw — that must
        //    route to the same rollback path as a returned-unhealthy poll.
        let failReason: string | undefined;
        let healthy = false;
        try {
          if (isFirstDeploy) {
            const body: Json = { name, composeContent };
            if (envContent !== undefined) body.envContent = envContent;
            const created = unwrap(
              await arcane(g, "POST", `${ENV(g)}/projects`, body),
            );
            id = asString(pick(created, "id")) ?? "";
            await record("create", true, 200, `created project ${id}`);
          } else {
            const body: Json = { composeContent };
            if (envContent !== undefined) body.envContent = envContent;
            await arcane(g, "PUT", `${ENV(g)}/projects/${id}`, body);
            await record("update", true, 200, "updated compose content");
          }
          await arcane(g, "POST", `${ENV(g)}/projects/${id}/redeploy`);
          await record("redeploy", true, 200, "redeploy issued");
          const health = await pollProjectHealthy(
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
          healthy = health.healthy;
          if (!healthy) failReason = `unhealthy: ${health.detail}`;
        } catch (e) {
          failReason = e instanceof Error ? e.message : String(e);
          await record("apply", false, 0, failReason);
        }

        if (healthy) {
          handles.push(
            await context.writeResource("project", name, {
              id,
              name,
              status: "running",
              observedAt: new Date().toISOString(),
            }),
          );
          logInfo(context, "Direct deploy healthy", { name });
          return { dataHandles: handles };
        }

        // 4. Failure path — roll back by default.
        if (args.rollback === false) {
          await record(
            "rollback",
            false,
            0,
            "rollback disabled (rollback:false) — left in failed state",
          );
          throw new Error(
            `deploy of '${name}' failed (${failReason}); rollback disabled, left as-is for inspection`,
          );
        }
        if (isFirstDeploy) {
          if (id) {
            await deleteIfPresent(g, `${ENV(g)}/projects/${id}/destroy`);
            await record(
              "rollback",
              true,
              200,
              "first deploy failed; destroyed the half-up project",
            );
          } else {
            await record(
              "rollback",
              true,
              200,
              "first deploy failed before the project was created; nothing to tear down",
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
            `deploy of '${name}' failed (${failReason}) and no prior compose content was available to roll back to — manual recovery required`,
          );
        }
        let rbResult: string;
        try {
          const rb: Json = { composeContent: priorCompose };
          if (priorEnv !== undefined) rb.envContent = priorEnv;
          await arcane(g, "PUT", `${ENV(g)}/projects/${id}`, rb);
          await arcane(g, "POST", `${ENV(g)}/projects/${id}/redeploy`);
          const rbHealth = await pollProjectHealthy(
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
            : "STILL UNHEALTHY — manual recovery required";
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          await record(
            "rollback",
            false,
            0,
            `rollback re-apply failed: ${msg}`,
          );
          rbResult = `ROLLBACK FAILED (${msg}) — manual recovery required`;
        }
        throw new Error(
          `deploy of '${name}' failed (${failReason}); rolled back to prior content (${rbResult})`,
        );
      },
    },

    project_up: makeLifecycle("up", "POST", "/up"),
    project_down: makeLifecycle("down", "POST", "/down"),
    project_redeploy: makeLifecycle("redeploy", "POST", "/redeploy"),
    project_pull: makeLifecycle("pull", "POST", "/pull"),
    project_destroy: makeLifecycle("destroy", "DELETE", "/destroy", true),

    // --- swarm secret_ / config_ CRUD (rotation lives in secret_rotate / config_rotate) ---
    ...makeSwarmObject("secret"),
    ...makeSwarmObject("config"),
    ...makeRotate("secret"),
    ...makeRotate("config"),

    swarm_service_list: {
      description:
        "List swarm services (factory: one `swarm-service` per entry, keyed by name)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
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
              res.name as string,
              res,
            ),
          );
        }
        logInfo(context, "Listed swarm services", { count: handles.length });
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
        await ensureSwarmManager(g);
        const found = await findSwarmService(g, args.name);
        if (!found) throw new Error(`swarm service '${args.name}' not found`);
        const res = swarmServiceResource(found, "observed");
        const handle = await context.writeResource(
          "swarm-service",
          res.name as string,
          res,
        );
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
        logInfo(context, "Rolling back swarm service", { name: args.name });
        await arcane(g, "POST", `${ENV(g)}/swarm/services/${id}/rollback`);
        const handle = await context.writeResource(
          "operation-result",
          `rollback-${args.name}`,
          {
            operation: "swarm_service_rollback",
            target: args.name,
            status: 200,
            success: true,
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    swarm_service_force_update: {
      description:
        "Force-redeploy a swarm service via Arcane (bumps spec.TaskTemplate.ForceUpdate + PUT) — recreates its tasks without changing config. Useful after a dependency (e.g. its DB) becomes ready post-deploy. Polls convergence; throws if it does not converge.",
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
        logInfo(context, "Force-updating swarm service", { name: args.name });
        await arcane(g, "PUT", `${ENV(g)}/swarm/services/${id}`, body);
        const conv = await pollServiceConverged(
          g,
          id,
          args.convergeTimeoutSec,
          args.pollIntervalSec,
        );
        const handle = await context.writeResource(
          "operation-result",
          `force-update-${args.name}`,
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
        logInfo(context, "Force-updated swarm service", { name: args.name });
        return { dataHandles: [handle] };
      },
    },

    // --- swarm_stack_ section: validate (render, fail-closed) + deploy + list/get/remove ---
    swarm_stack_list: {
      description:
        "List swarm stacks (factory: one `swarm-stack` per entry, keyed by name)",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const rows = coerceList(
          await arcane(g, "GET", `${ENV(g)}/swarm/stacks?limit=-1`),
        );
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const res = swarmStackResource(r, "observed");
          handles.push(
            await context.writeResource("swarm-stack", res.name as string, res),
          );
        }
        logInfo(context, "Listed swarm stacks", { count: handles.length });
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
          args.name,
          res,
        );
        return { dataHandles: [handle] };
      },
    },

    swarm_stack_validate: {
      description:
        "Validate a swarm stack via Arcane's config render (POST /swarm/stacks/config/render). " +
        "Fails closed — any render error (4xx) aborts. Records the rendered services/networks/volumes/secrets/configs + warnings.",
      arguments: SwarmStackValidateArgs,
      execute: async (
        args: z.infer<typeof SwarmStackValidateArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const { composeContent, envContent } = await resolveComposeInput(args);
        const body: Json = { name: args.name, composeContent };
        if (envContent !== undefined) body.envContent = envContent;
        logInfo(context, "Rendering swarm stack (validate)", {
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
          slug(args.name),
          res,
        );
        logInfo(context, "Swarm stack render valid", {
          name: args.name,
          services: res.services.length,
          warnings: warnings.length,
        });
        return { dataHandles: [handle] };
      },
    },

    swarm_stack_deploy: {
      description:
        "Validated deploy of a swarm stack: render (fail-closed, guardrail #2) -> POST the stack -> poll service convergence. " +
        "Records per-step operation-results + a swarm-stack resource. A non-converging deploy is surfaced (not force-removed, not auto-rolled-back).",
      arguments: SwarmStackDeployArgs,
      execute: async (
        args: z.infer<typeof SwarmStackDeployArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const name: string = args.name;
        const handles: DataHandle[] = [];
        const record = async (
          operation: string,
          success: boolean,
          status: number,
          detail: string,
        ) => {
          handles.push(
            await context.writeResource(
              "operation-result",
              `stack-deploy-${name}-${operation}`,
              {
                operation: `swarm_stack_deploy:${operation}`,
                target: name,
                status,
                success,
                detail,
                timestamp: new Date().toISOString(),
              },
            ),
          );
        };

        const { composeContent, envContent } = await resolveComposeInput(args);

        // 1. Validate via render — MUST pass before deploy (guardrail #2). A render
        //    error throws from arcane() (4xx) and aborts the deploy.
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

        // 2. Deploy.
        const body: Json = { name, composeContent };
        if (envContent !== undefined) body.envContent = envContent;
        if (args.prune) body.prune = true;
        logInfo(context, "Deploying swarm stack", { name });
        await arcane(g, "POST", `${ENV(g)}/swarm/stacks`, body);
        await record("deploy", true, 200, "stack deploy issued");

        // 3. Poll service convergence.
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

        // 4. Record the stack (best-effort inspect for counts/timestamps).
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
          await context.writeResource("swarm-stack", name, stackRes),
        );

        if (!conv.converged) {
          throw new Error(
            `swarm stack '${name}' was deployed but did not converge within ${args.convergeTimeoutSec}s (${conv.detail}). ` +
              `Left in place for inspection — not force-removed, not auto-rolled-back. Inspect with swarm_stack_get / swarm_service_list, then re-deploy or swarm_stack_remove.`,
          );
        }
        logInfo(context, "Swarm stack deployed + converged", { name });
        return { dataHandles: handles };
      },
    },

    swarm_stack_remove: {
      description:
        "Remove a swarm stack by name (docker stack rm via Arcane) and confirm the stored record is cleared. " +
        "Arcane's first DELETE tears down services but RETAINS the stack record, so this polls GET until 404, re-issuing DELETE until the record is gone (the teardown two-call bug). " +
        "In-use conflicts are surfaced by Arcane, never forced (guardrail #5).",
      arguments: SwarmStackRemoveArgs,
      execute: async (
        args: z.infer<typeof SwarmStackRemoveArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        logInfo(context, "Removing swarm stack", { name: args.name });
        const deletes = await pollStackRemoved(
          g,
          args.name,
          args.removeTimeoutSec,
          args.pollIntervalSec,
        );
        const handle = await context.writeResource("swarm-stack", args.name, {
          name: args.name,
          action: "deleted",
          deletes,
          observedAt: new Date().toISOString(),
        });
        logInfo(context, "Removed swarm stack", { name: args.name, deletes });
        return { dataHandles: [handle] };
      },
    },

    swarm_stack_tasks: {
      description:
        "List a swarm stack's tasks (factory: one `swarm-task` per task) with per-task currentState + error — the deploy debug view that surfaces rejected/failed reasons (missing bind path, non-zero exit, placement). " +
        "NOTE: Arcane exposes no container/service log endpoint, so crash stderr is NOT available here — use the host's docker logs / a log viewer for that.",
      arguments: SwarmStackTasksArgs,
      execute: async (
        args: z.infer<typeof SwarmStackTasksArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
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
              `${res.serviceName}-${res.id}`,
              res,
            ),
          );
        }
        logInfo(context, "Listed swarm stack tasks", {
          name: args.name,
          count: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    // --- volume_ / prune cleanup (docker-level; works on any env, not swarm-only) ---
    volume_list: {
      description:
        "List docker volumes (factory: one `volume` per entry, keyed by name). Includes `inUse` so orphaned volumes are visible.",
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const rows = coerceList(await arcane(g, "GET", `${ENV(g)}/volumes`));
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const res = volumeResource(r, "observed");
          handles.push(
            await context.writeResource("volume", res.name as string, res),
          );
        }
        logInfo(context, "Listed volumes", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    volume_remove: {
      description:
        "Remove a docker volume by name. Idempotent (404 = already gone). An in-use volume returns 409 and is surfaced, NOT forced — unless force:true, which bypasses the in-use guard (discouraged, guardrail #5 — risks data loss).",
      arguments: VolumeRemoveArgs,
      execute: async (
        args: z.infer<typeof VolumeRemoveArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        const q = args.force ? "?force=true" : "";
        logInfo(context, "Removing volume", {
          name: args.name,
          force: !!args.force,
        });
        try {
          await arcane(
            g,
            "DELETE",
            `${ENV(g)}/volumes/${encodeURIComponent(args.name)}${q}`,
          );
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          if (/HTTP 404/.test(msg)) {
            // already gone — idempotent success
          } else if (/HTTP 409/.test(msg) || /in use/i.test(msg)) {
            // Arcane surfaces "volume is in use" as 409 OR 500 — treat both as the
            // in-use guard (often a stopped container still references it).
            throw new Error(
              `volume '${args.name}' is in use — not removed (set force:true only if you are certain it is safe). ${msg}`,
            );
          } else {
            throw e;
          }
        }
        const handle = await context.writeResource("volume", args.name, {
          id: "",
          name: args.name,
          action: "deleted",
          observedAt: new Date().toISOString(),
        });
        logInfo(context, "Removed volume", { name: args.name });
        return { dataHandles: [handle] };
      },
    },

    volume_prune: {
      description:
        "Prune UNUSED anonymous docker volumes (Docker default — named volumes are NOT removed). Removes only volumes no container references. For a specific named volume use volume_remove.",
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
          "volumes",
          res,
        );
        logInfo(context, "Pruned volumes", {
          itemsDeleted: res.itemsDeleted ?? 0,
        });
        return { dataHandles: [handle] };
      },
    },

    network_prune: {
      description:
        "Prune unused docker networks (no attached containers). Safe — only removes networks nothing is using.",
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
          "networks",
          res,
        );
        logInfo(context, "Pruned networks", {
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
        logInfo(context, "Pruning images", { dangling: !!args.dangling });
        const raw = unwrap(
          await arcane(g, "POST", `${ENV(g)}/images/prune`, {
            dangling: args.dangling,
          }),
        );
        const res = pruneResult("images", raw);
        const handle = await context.writeResource(
          "prune-result",
          "images",
          res,
        );
        logInfo(context, "Pruned images", {
          itemsDeleted: res.itemsDeleted ?? 0,
        });
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;

/**
 * Build a fan-out project-lifecycle method. Resolves each name to a project id,
 * issues the action, and records an operation-result per target. Destructive
 * actions require an explicit, non-empty name list (no wildcard).
 */
function makeLifecycle(
  operation: string,
  httpMethod: HttpMethod,
  suffix: string,
  destructive = false,
): MethodDefinition<z.ZodTypeAny, GlobalArgsT> {
  return {
    description:
      `${operation} the named projects (fan-out over a list of project names)`,
    arguments: LifecycleArgs,
    execute: async (
      args: z.infer<typeof LifecycleArgs>,
      context,
    ): Promise<{ dataHandles: DataHandle[] }> => {
      const g: GlobalArgsT = context.globalArgs;
      const names: string[] = args.names;
      if (destructive && names.length === 0) {
        throw new Error(`${operation} requires explicit project names`);
      }
      logInfo(context, `Running project ${operation}`, { names });
      const projects = coerceList(
        await arcane(g, "GET", `${ENV(g)}/projects?limit=-1`),
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
        if (destructive && httpMethod === "DELETE") {
          await deleteIfPresent(g, path);
        } else {
          await arcane(g, httpMethod, path);
        }
        handles.push(
          await context.writeResource(
            "operation-result",
            `${operation}-${name}`,
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
      logInfo(context, `Completed project ${operation}`, {
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
      "Value — supply via vault: ${{ vault.get(name, key) }}; never inline a secret",
    ),
    labels: z.record(z.string(), z.string()).optional().describe(
      "Optional spec labels",
    ),
  });
  return {
    [`${kind}_list`]: {
      description:
        `List swarm ${plural} (factory: one \`${resourceName}\` per entry, keyed by name)`,
      arguments: z.object({}),
      execute: async (
        _args,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const rows = coerceList(await arcane(g, "GET", base(g)));
        const handles: DataHandle[] = [];
        for (const r of rows) {
          const res = swarmObjectResource(r, "observed");
          handles.push(
            await context.writeResource(resourceName, res.name as string, res),
          );
        }
        logInfo(context, `Listed swarm ${plural}`, { count: handles.length });
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
        await ensureSwarmManager(g);
        const found = await findSwarmObject(g, plural, args.name);
        if (!found) throw new Error(`swarm ${kind} '${args.name}' not found`);
        const res = swarmObjectResource(found, "observed");
        const handle = await context.writeResource(
          resourceName,
          res.name as string,
          res,
        );
        return { dataHandles: [handle] };
      },
    },
    [`${kind}_create`]: {
      description:
        `Create a swarm ${kind}. The value is supplied via vault (sensitive) and base64-encoded into spec.Data. ` +
        `Swarm ${plural} are immutable — to change a value, use ${kind}_rotate.`,
      arguments: createArgs,
      execute: async (
        args: z.infer<typeof createArgs>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const spec: Json = { Name: args.name, Data: b64(args.value) };
        if (args.labels) spec.Labels = args.labels;
        logInfo(context, `Creating swarm ${kind}`, { name: args.name });
        const created = unwrap(await arcane(g, "POST", base(g), { spec }));
        const id = asString(pick(created, "id", "ID")) ?? "";
        const handle = await context.writeResource(resourceName, args.name, {
          id,
          name: args.name,
          action: "created",
          observedAt: new Date().toISOString(),
        });
        logInfo(context, `Created swarm ${kind}`, { name: args.name, id });
        return { dataHandles: [handle] };
      },
    },
    [`${kind}_remove`]: {
      description:
        `Remove a swarm ${kind} by name. Docker blocks removal of an in-use ${kind} (409); that conflict is surfaced, never forced (guardrail #5).`,
      arguments: NameArg,
      execute: async (
        args: z.infer<typeof NameArg>,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g: GlobalArgsT = context.globalArgs;
        await ensureSwarmManager(g);
        const found = await findSwarmObject(g, plural, args.name);
        if (!found) throw new Error(`swarm ${kind} '${args.name}' not found`);
        const id = asString(pick(found, "id", "ID")) ?? "";
        await arcane(g, "DELETE", `${base(g)}/${id}`);
        const handle = await context.writeResource(resourceName, args.name, {
          id,
          name: args.name,
          action: "deleted",
          observedAt: new Date().toISOString(),
        });
        logInfo(context, `Removed swarm ${kind}`, { name: args.name });
        return { dataHandles: [handle] };
      },
    },
  };
}

/**
 * Build the rotation method for a swarm secret or config. Swarm secrets/configs are
 * immutable, so rotation is: create v2 → re-point referencing services (keeping the
 * same mount path) → wait for convergence → remove v1 (never forced; skipped if the
 * old object is still referenced or `removeOld:false`).
 */
function makeRotate(
  kind: "secret" | "config",
): Record<string, MethodDefinition<z.ZodTypeAny, GlobalArgsT>> {
  const plural = kind === "secret" ? "secrets" : "configs";
  const resourceName = kind === "secret" ? "swarm-secret" : "swarm-config";
  const rotateArgs = z.object({
    name: z.string().describe(`Existing ${kind} name to rotate`),
    value: z.string().meta({ sensitive: true }).describe(
      "New value — supply via vault",
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
    healthTimeoutSec: z.number().int().default(180),
    pollIntervalSec: z.number().int().default(5),
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
        const record = async (
          operation: string,
          target: string,
          success: boolean,
          status: number,
          detail: string,
        ) => {
          handles.push(
            await context.writeResource(
              "operation-result",
              `${kind}_rotate-${target}-${operation}`,
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
        };

        // 1. Old must exist.
        const oldObj = await findSwarmObject(g, plural, args.name);
        if (!oldObj) throw new Error(`swarm ${kind} '${args.name}' not found`);
        const oldId = asString(pick(oldObj, "id", "ID")) ?? "";

        // 2. Create v2 (carry over old labels).
        const stamp = new Date().toISOString().replace(/[-:T.Z]/g, "").slice(
          0,
          14,
        );
        const newName: string = args.newName ?? `${args.name}-v${stamp}`;
        const spec: Json = { Name: newName, Data: b64(args.value) };
        const oldSpec = (pick(oldObj, "spec") as Json) ?? {};
        const oldLabels = pick(oldSpec, "Labels");
        if (oldLabels && typeof oldLabels === "object") spec.Labels = oldLabels;
        const created = unwrap(
          await arcane(g, "POST", `${ENV(g)}/swarm/${plural}`, { spec }),
        );
        const newId = asString(pick(created, "id", "ID")) ?? "";
        await record(
          "create",
          newName,
          true,
          200,
          `created ${kind} ${newName} (${newId})`,
        );
        handles.push(
          await context.writeResource(resourceName, newName, {
            id: newId,
            name: newName,
            action: "created",
            observedAt: new Date().toISOString(),
          }),
        );

        // 3. Find + rewrite referencing services (in memory).
        const allServices = coerceList(
          await arcane(g, "GET", `${ENV(g)}/swarm/services?limit=-1`),
        );
        const wantSet = args.services
          ? new Set<string>(args.services)
          : undefined;
        const targets = [];
        for (const summary of allServices) {
          const sspec = (pick(summary, "spec") as Json) ?? {};
          const sname = asString(pick(summary, "name")) ??
            asString(pick(sspec, "Name", "name"));
          if (wantSet && (!sname || !wantSet.has(sname))) continue;
          const sid = asString(pick(summary, "id", "ID")) ?? "";
          if (!sid) continue;
          const insp = unwrap(
            await arcane(g, "GET", `${ENV(g)}/swarm/services/${sid}`),
          );
          const fullSpec = pick(insp, "spec") as Json | undefined;
          if (!fullSpec) continue;
          const n = repointServiceRefs(
            fullSpec,
            kind,
            args.name,
            newId,
            newName,
          );
          if (n > 0) {
            targets.push({
              sid,
              sname: sname ?? sid,
              insp,
              spec: fullSpec,
              refs: n,
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
        if (targets.length === 0) {
          await record(
            "repoint",
            args.name,
            true,
            200,
            `no services reference ${kind} '${args.name}'`,
          );
        }

        // 4. Re-point each service (PUT full spec + version).
        for (const t of targets) {
          const versionObj = (pick(t.insp, "version") as Json) ?? {};
          const versionIndex = asNumber(pick(versionObj, "Index", "index"));
          const body: Json = { spec: t.spec };
          if (versionIndex !== undefined) body.version = versionIndex;
          await arcane(g, "PUT", `${ENV(g)}/swarm/services/${t.sid}`, body);
          await record(
            "repoint",
            t.sname,
            true,
            200,
            `re-pointed ${t.refs} ref(s)`,
          );
        }

        // 5. Wait for convergence.
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
          );
          if (!c.converged) allConverged = false;
        }
        if (!allConverged) {
          throw new Error(
            `rotation of ${kind} '${args.name}' → '${newName}': not all services converged; old ${kind} left in place — investigate, then re-run or swarm_service_rollback`,
          );
        }

        // 6. Remove old (never forced; surface in-use 409).
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
              await context.writeResource(resourceName, args.name, {
                id: oldId,
                name: args.name,
                action: "deleted",
                observedAt: new Date().toISOString(),
              }),
            );
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            if (/HTTP 409/.test(msg)) {
              await record(
                "remove-old",
                args.name,
                false,
                409,
                `old ${kind} still in use — left in place (not forced)`,
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
            `removeOld:false — old ${kind} retained`,
          );
        }

        logInfo(context, `Rotated swarm ${kind}`, {
          from: args.name,
          to: newName,
          services: targets.length,
        });
        return { dataHandles: handles };
      },
    },
  };
}
