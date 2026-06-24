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
 * `@thomas/truenas` — administration of a TrueNAS SCALE host via its JSON-RPC 2.0
 * API over a WebSocket (`wss://<host>/api/current`), authenticated with an API key.
 * Targets 25.04 ("Fangtooth"), where the REST API is gone and the WebSocket RPC is
 * the durable surface.
 *
 * SCOPE: built for the homelab **service-exposure** hardening (R28) — read what is
 * published where, then tighten it. The mutating surface is deliberately narrow:
 *   - app port binding (`app_set_port_bind`) — flip a catalog app's port between
 *     `published` (on the host) and `exposed` (container-internal only); the lever
 *     that closes lldap's plaintext LDAP/LDAPS ports.
 *   - NFS share access (`nfs_share_set_access`) — set the per-share authorized
 *     `networks`/`hosts` allowlist (the one supported per-client gate).
 *   - SMB share access (`smb_share_set_access`) — set per-share `hostsallow`/`hostsdeny`.
 *   - SMB/NFS share delete (`smb_share_delete`, `nfs_share_delete`) — remove a share
 *     definition (the dataset/data is left untouched); the removed config is recorded
 *     so it can be re-created.
 * It does NOT touch pools, datasets, users, snapshots, replication, or service
 * start/stop (a stopped ssh/nfs service is a lockout/outage risk — left an explicit
 * gap). Every mutating verb verifies its target by id/name first (CLAUDE.md rule 5);
 * the set-access verbs are reversible (re-run with the prior values) and the delete
 * verbs record the removed config so the share can be re-created.
 *
 * Method sections (by prefix):
 *   - read/audit: `system_info`, `app_list`, `nfs_share_list`, `smb_share_list`,
 *     `service_list`, `network_info`, `exposure_audit` (the R28 report data source).
 *   - mutate: `app_set_port_bind`, `app_set_networks`, `nfs_share_set_access`,
 *     `smb_share_set_access`, `nfs_share_delete`, `smb_share_delete`.
 *
 * TRANSPORT SAFETY: TrueNAS **permanently revokes an API key the instant it is sent
 * over a non-TLS transport** (plain `ws://`/`http://`). This model therefore refuses
 * any non-`wss` endpoint *by construction* — {@link websocketUrl} throws before a
 * socket is opened, and never downgrades `https→ws`. The NAS ships a self-signed
 * cert (`CN=localhost`); `insecureSkipTlsVerify` is a best-effort request to skip cert
 * *validation*, but in swamp's managed Deno runtime it is effectively inert in-process
 * (skip-verify is only honoured process-wide via --unsafely-ignore-certificate-errors)
 * — so the supported path is a trusted cert on the host. Either way the transport stays
 * TLS-encrypted, which is what keeps the key alive.
 *
 * Secrets: `apiKey` is supplied via a vault expression, e.g.
 * `${{ vault.get(<vault>, truenas/credential) }}`. It is marked sensitive and
 * redacted from every error this model throws.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  endpoint: z.string().default("wss://nas.example.com/api/current").describe(
    "TrueNAS host or wss:// base URL, e.g. nas.example.com or " +
      "wss://nas.example.com/api/current. A bare host becomes " +
      "wss://<host>/api/current. NON-TLS (ws://, http://) is REJECTED — TrueNAS " +
      "revokes an API key sent over cleartext.",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "TrueNAS API key (Credentials → Users → API keys). Supply via vault: " +
      "${{ vault.get(<vault>, truenas/credential) }}",
  ),
  insecureSkipTlsVerify: z.coerce.boolean().default(false).describe(
    "Best-effort request to skip TLS certificate VALIDATION (the NAS uses a " +
      "self-signed CN=localhost cert). In swamp's managed Deno runtime this flag is " +
      "effectively inert in-process: skip-verify is only honoured process-wide, when " +
      "the runtime is started with --unsafely-ignore-certificate-errors. The supported " +
      "path is a trusted cert on the host; the transport always stays TLS-encrypted, " +
      "which is what keeps the API key alive.",
  ),
  timeoutMs: z.coerce.number().int().default(30000).describe(
    "Per-call timeout in milliseconds (also the job-wait budget)",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type", so it
// must not leak onto the public API — the exported {@link RpcFn}/{@link SessionFactory}
// seams use the loose {@link Json} instead (mirrors `@thomas/garage`).
type GlobalArgsT = z.infer<typeof GlobalArgs>;

/** Lifecycle outcome recorded on result/observation resources. */
const Action = z.enum([
  "observed",
  "updated",
  "unchanged",
  "deleted",
  // delete verbs are idempotent: a target that's already gone records "absent".
  "absent",
]);

// ─────────────────────────── resource schemas ───────────────────────────

const SystemInfo = z.object({
  hostname: z.string(),
  version: z.string(),
  uptimeSeconds: z.number().nullable().optional(),
  loadAvg: z.array(z.number()).optional(),
  physmem: z.number().nullable().optional(),
  model: z.string().optional(),
  cores: z.number().nullable().optional(),
  action: Action,
  timestamp: z.string(),
});

/** One published/exposed port binding on an app (from config.network.<key>). */
const PortBinding = z.object({
  portKey: z.string().describe('Config key, e.g. "ldap_port" / "admin_port"'),
  portNumber: z.number(),
  protocol: z.string().describe("tcp | udp (best-effort; tcp if unknown)"),
  bindMode: z.string().describe("published | exposed"),
  hostIps: z.array(z.string()).describe(
    'Host IPs the port publishes on; "0.0.0.0" = all interfaces',
  ),
  published: z.boolean().describe("bindMode === published"),
  exposedToAll: z.boolean().describe(
    'published AND hostIps includes "0.0.0.0"',
  ),
});

const AppInfo = z.object({
  name: z.string(),
  state: z.string().describe("RUNNING | STOPPED | DEPLOYING | …"),
  customApp: z.boolean(),
  version: z.string().optional(),
  humanVersion: z.string().optional(),
  hostNetwork: z.boolean().describe(
    "Whether the app runs on the host network (ports are not individually bound)",
  ),
  portBindings: z.array(PortBinding),
  action: Action,
  timestamp: z.string(),
});

const NfsShare = z.object({
  id: z.number(),
  path: z.string(),
  comment: z.string().optional(),
  enabled: z.boolean(),
  ro: z.boolean(),
  networks: z.array(z.string()).describe(
    "Authorized networks (CIDR). EMPTY = ALL networks allowed.",
  ),
  hosts: z.array(z.string()).describe(
    "Authorized hosts/IPs. EMPTY = ALL hosts allowed.",
  ),
  unrestricted: z.boolean().describe(
    "True when both networks and hosts are empty (reachable by any client)",
  ),
  action: Action,
  timestamp: z.string(),
});

const SmbShare = z.object({
  id: z.number(),
  name: z.string(),
  path: z.string(),
  comment: z.string().optional(),
  enabled: z.boolean(),
  ro: z.boolean(),
  hostsallow: z.array(z.string()).describe(
    "Allowed hosts. EMPTY = all allowed.",
  ),
  hostsdeny: z.array(z.string()).describe("Denied hosts."),
  purpose: z.string().describe(
    "TrueNAS 25.04 share purpose preset. DEFAULT_SHARE/VEEAM_REPOSITORY_SHARE LOCK " +
      "hostsallow/hostsdeny to empty — a host allowlist can't be applied without first " +
      "moving the share to NO_PRESET (smb_share_set_access does this automatically).",
  ),
  unrestricted: z.boolean().describe(
    "True when hostsallow is empty (no host allowlist in force)",
  ),
  action: Action,
  timestamp: z.string(),
});

const ServiceInfo = z.object({
  service: z.string(),
  state: z.string().describe("RUNNING | STOPPED"),
  enable: z.boolean().describe("Starts on boot"),
  running: z.boolean(),
  action: Action,
  timestamp: z.string(),
});

/** One IP that an app port can bind to (a host interface alias). */
const BindableIp = z.object({
  address: z.string(),
  netmask: z.number().nullable().optional(),
  interface: z.string().optional(),
});

const NetworkInfo = z.object({
  bindableIps: z.array(BindableIp).describe(
    'IPs an app port can publish on (interface.ip_in_use). "0.0.0.0" is always ' +
      "implicitly available; a tailscale IP appears ONLY if tailscale0 is a host " +
      "interface (it is not on this NAS — the tailscale app owns it).",
  ),
  interfaces: z.array(z.object({
    name: z.string(),
    type: z.string().optional(),
    addresses: z.array(z.string()),
  })),
  guiAddresses: z.array(z.string()).describe(
    "system.general ui_address bind list",
  ),
  action: Action,
  timestamp: z.string(),
});

/** One published port across the estate, for the exposure roll-up. */
const ExposedPort = z.object({
  source: z.string().describe("app:<name> | service:<name>"),
  portNumber: z.number(),
  protocol: z.string(),
  hostIps: z.array(z.string()),
  detail: z.string().optional().describe("e.g. the app port key"),
});

const ExposureAudit = z.object({
  hostname: z.string(),
  version: z.string(),
  /** Every app port with bindMode=published. */
  publishedPorts: z.array(ExposedPort),
  /** NFS shares with no networks AND no hosts restriction. */
  unrestrictedNfsShares: z.array(z.string()),
  /** Enabled SMB shares with an empty hostsallow. */
  unrestrictedSmbShares: z.array(z.string()),
  flags: z.object({
    /** Published ports bound to 0.0.0.0 (reachable on every interface incl. tailnet). */
    portsOnAllInterfaces: z.array(z.number()),
    /** Plaintext LDAP (389) published anywhere. */
    plaintextLdapPublished: z.boolean(),
    /** Bindable host IPs other than 0.0.0.0 (the host-IP selector contents). */
    nonWildcardBindableIps: z.array(z.string()),
  }),
  appCount: z.number(),
  nfsShareCount: z.number(),
  smbShareCount: z.number(),
  action: Action,
  timestamp: z.string(),
});

/** Result of an app port-bind change (re-read after the update). */
const AppPortResult = z.object({
  app: z.string(),
  portKey: z.string(),
  portNumber: z.number(),
  previousBindMode: z.string(),
  previousHostIps: z.array(z.string()),
  bindMode: z.string(),
  hostIps: z.array(z.string()),
  action: Action,
  timestamp: z.string(),
});

/** Result of an app_set_networks change. */
const AppNetworksResult = z.object({
  app: z.string(),
  previousNetworks: z.array(z.string()),
  networks: z.array(z.string()),
  action: Action,
  timestamp: z.string(),
});

/** Default per-network config TrueNAS stores for an attached docker network. */
const DEFAULT_NETWORK_CONFIG = {
  aliases: [] as string[],
  gw_priority: null,
  interface_name: "",
  ipv4_address: "",
  ipv6_address: "",
  mac_address: "",
  priority: null,
};

/** Result of an NFS share access change. */
const NfsShareResult = z.object({
  id: z.number(),
  path: z.string(),
  previousNetworks: z.array(z.string()),
  previousHosts: z.array(z.string()),
  networks: z.array(z.string()),
  hosts: z.array(z.string()),
  action: Action,
  timestamp: z.string(),
});

/** Result of an SMB share access change. */
const SmbShareResult = z.object({
  id: z.number(),
  name: z.string(),
  previousHostsallow: z.array(z.string()),
  previousHostsdeny: z.array(z.string()),
  hostsallow: z.array(z.string()),
  hostsdeny: z.array(z.string()),
  previousPurpose: z.string().describe(
    "The share's purpose preset before the change",
  ),
  purpose: z.string().describe(
    "The share's purpose preset after the change (flipped to NO_PRESET when a " +
      "host allowlist had to be applied to a preset that locks hostsallow)",
  ),
  action: Action,
  timestamp: z.string(),
});

/**
 * SMB purpose presets that LOCK `hostsallow`/`hostsdeny` to empty: TrueNAS re-applies
 * the preset's empty host lists on every `sharing.smb.update`, silently discarding any
 * allowlist. To enforce host rules on such a share it must move to `NO_PRESET` (which
 * applies no preset overrides) in the same update. Discovered on SCALE 25.04 via
 * `sharing.smb.presets`.
 */
const HOST_LOCKING_PURPOSES = new Set([
  "DEFAULT_SHARE",
  "VEEAM_REPOSITORY_SHARE",
]);

// ─────────────────────────── transport seam ───────────────────────────

/** A JSON-ish bag — structurally the resolved global args. */
export type Json = Record<string, unknown>;

/**
 * An authenticated JSON-RPC session over one WebSocket. {@link call} issues one RPC
 * (bounded by the per-call timeout, API key redacted from errors); {@link close}
 * shuts the socket. Methods open a session, do their reads/writes, and close it in a
 * `finally`.
 */
export interface RpcSession {
  /** Issue one JSON-RPC call. */
  call(method: string, params: unknown[]): Promise<unknown>;
  /** Close the underlying WebSocket. Safe to call more than once. */
  close(): void;
}

/**
 * Opens an authenticated {@link RpcSession} from the resolved global args. Typed
 * loosely as {@link Json} so this EXPORTED seam stays "fast-check" clean (a
 * zod-inferred arg type would drag a slow type onto the public API).
 */
export type SessionFactory = (g: Json) => Promise<RpcSession>;

let _sessionOverride: SessionFactory | null = null;

/** Test-only seam: substitute the session transport. Pass `null` to restore the real one. */
export function __setTruenasSession(fn: SessionFactory | null): void {
  _sessionOverride = fn;
}

/**
 * Build the `wss://<host>/api/current` URL from an operator endpoint. Accepts a bare
 * host, `wss://…`, or `https://…` (upgraded to `wss`). **Throws** on `ws://`/`http://`
 * or any other scheme — sending the API key over a non-TLS transport gets it revoked.
 */
export function websocketUrl(endpoint: string): string {
  let raw = String(endpoint).trim();
  if (!raw) throw new Error("endpoint is empty");
  if (!/^[a-z]+:\/\//i.test(raw)) raw = `wss://${raw}`;
  const u = new URL(raw);
  if (u.protocol === "https:") u.protocol = "wss:";
  if (u.protocol !== "wss:") {
    throw new Error(
      `refusing non-TLS endpoint ${
        JSON.stringify(endpoint)
      }: TrueNAS revokes an ` +
        "API key sent over cleartext — use wss:// (or https://), never ws:///http://",
    );
  }
  if (u.pathname === "/" || u.pathname === "") u.pathname = "/api/current";
  return u.toString();
}

/** Redact an API key from a string (defence-in-depth for thrown errors/logs). */
function redact(s: string, secret: string): string {
  if (!secret) return s;
  return s.split(secret).join("***");
}

/** Race a promise against a cleared timeout so no timer leaks past resolution. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`TrueNAS ${label} timed out after ${ms}ms`)),
      ms,
    );
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/** Minimal JSON-RPC 2.0 client over a single WebSocket. Resolves calls by id. */
class JsonRpcSocket {
  #ws: WebSocket;
  #nextId = 1;
  #pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();
  #closed: Error | null = null;
  readonly #secret: string;
  readonly ready: Promise<void>;

  constructor(url: string, secret: string) {
    this.#secret = secret;
    this.#ws = new WebSocket(url);
    this.ready = new Promise((resolve, reject) => {
      this.#ws.onopen = () => resolve();
      this.#ws.onerror = () =>
        reject(new Error("TrueNAS WebSocket connection failed"));
    });
    this.#ws.onmessage = (ev) => this.#onMessage(ev);
    this.#ws.onclose = () => this.#fail(new Error("TrueNAS WebSocket closed"));
  }

  #onMessage(ev: MessageEvent): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(typeof ev.data === "string" ? ev.data : "");
    } catch {
      return; // tolerate non-JSON job-progress noise
    }
    const id = msg.id;
    if (typeof id !== "number") return; // notifications/progress
    const waiter = this.#pending.get(id);
    if (!waiter) return;
    this.#pending.delete(id);
    if (msg.error) {
      const detail = redact(JSON.stringify(msg.error), this.#secret);
      waiter.reject(new Error(`TrueNAS JSON-RPC error: ${detail}`));
    } else {
      waiter.resolve(msg.result);
    }
  }

  #fail(err: Error): void {
    if (this.#closed) return;
    this.#closed = err;
    for (const waiter of this.#pending.values()) waiter.reject(err);
    this.#pending.clear();
  }

  call(method: string, params: unknown[]): Promise<unknown> {
    if (this.#closed) return Promise.reject(this.#closed);
    const id = this.#nextId++;
    const frame = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      try {
        this.#ws.send(frame);
      } catch (err) {
        this.#pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  close(): void {
    try {
      this.#ws.close();
    } catch {
      // already closing
    }
  }
}

/** The real WebSocket-backed session factory behind {@link openSession}. */
const realSessionFactory: SessionFactory = async (g) => {
  const url = websocketUrl(String(g.endpoint));
  const secret = String(g.apiKey);
  const timeoutMs = Number(g.timeoutMs) || 30000;
  const sock = new JsonRpcSocket(url, secret);
  try {
    await withTimeout(sock.ready, timeoutMs, "connection");
    const authed = await withTimeout(
      sock.call("auth.login_with_api_key", [secret]),
      timeoutMs,
      "login",
    );
    if (authed !== true) throw new Error("TrueNAS api-key login rejected");
  } catch (err) {
    sock.close();
    throw new Error(
      redact(err instanceof Error ? err.message : String(err), secret),
    );
  }
  return {
    async call(method, params) {
      try {
        return await withTimeout(
          sock.call(method, params),
          timeoutMs,
          `call ${method}`,
        );
      } catch (err) {
        throw new Error(
          redact(err instanceof Error ? err.message : String(err), secret),
        );
      }
    },
    close() {
      sock.close();
    },
  };
};

/** Open a session through the test override when set, else the real transport. */
function openSession(g: GlobalArgsT): Promise<RpcSession> {
  return (_sessionOverride ?? realSessionFactory)(g as unknown as Json);
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

function asObj(v: unknown): Record<string, unknown> {
  return (v && typeof v === "object" && !Array.isArray(v))
    ? v as Record<string, unknown>
    : {};
}
function asArr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function asBool(v: unknown): boolean {
  return v === true;
}
function asStr(v: unknown): string | undefined {
  return v === null || v === undefined ? undefined : String(v);
}
function asNum(v: unknown): number | undefined {
  if (v === null || v === undefined) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}
function nullableNum(v: unknown): number | null | undefined {
  if (v === undefined) return undefined;
  if (v === null) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
function strArr(v: unknown): string[] {
  return asArr(v).map((x) => String(x));
}

/** Terminal TrueNAS job states. */
const JOB_DONE = new Set(["SUCCESS", "FAILED", "ABORTED"]);

/**
 * Submit a job-returning RPC (`app.update` & friends) and wait for it to finish by
 * polling `core.get_jobs`. Returns the job's `result`; throws (with the job error) on
 * a FAILED/ABORTED terminal state or if the wait budget is exhausted.
 */
async function callJob(
  session: RpcSession,
  method: string,
  params: unknown[],
  timeoutMs: number,
): Promise<unknown> {
  const jobIdRaw = await session.call(method, params);
  const jobId = asNum(jobIdRaw);
  if (jobId === undefined) {
    throw new Error(
      `${method} did not return a job id (got ${JSON.stringify(jobIdRaw)})`,
    );
  }
  const deadline = Date.now() + timeoutMs;
  // Poll until terminal. Interval is short; the per-call timeout still bounds each poll.
  while (true) {
    const jobs = asArr(
      await session.call("core.get_jobs", [[["id", "=", jobId]]]),
    );
    const job = asObj(jobs[0]);
    const state = String(job.state ?? "");
    if (JOB_DONE.has(state)) {
      if (state !== "SUCCESS") {
        const err = asObj(job.exc_info).type ?? job.error ?? state;
        throw new Error(`${method} job ${jobId} ${state}: ${String(err)}`);
      }
      return job.result;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `${method} job ${jobId} did not finish within ${timeoutMs}ms (state=${state})`,
      );
    }
    await new Promise((r) => setTimeout(r, 750));
  }
}

// ─────────────────────────── shaping ───────────────────────────

/** Known protocol hints per app port key (config.network rarely carries protocol). */
function shapePortBindings(
  network: Record<string, unknown>,
): z.infer<typeof PortBinding>[] {
  const out: z.infer<typeof PortBinding>[] = [];
  for (const [key, val] of Object.entries(network)) {
    const p = asObj(val);
    // A port object has port_number + bind_mode; skip scalars like host_network/networks.
    if (p.port_number === undefined || p.bind_mode === undefined) continue;
    const hostIps = strArr(p.host_ips);
    const bindMode = String(p.bind_mode);
    const published = bindMode === "published";
    out.push({
      portKey: key,
      portNumber: asNum(p.port_number) ?? 0,
      protocol: String(p.protocol ?? "tcp"),
      bindMode,
      hostIps,
      published,
      exposedToAll: published && hostIps.includes("0.0.0.0"),
    });
  }
  return out.sort((a, b) => a.portNumber - b.portNumber);
}

function shapeApp(raw: unknown, ts: string): z.infer<typeof AppInfo> {
  const a = asObj(raw);
  const config = asObj(a.config);
  const network = asObj(config.network);
  return {
    name: String(a.name ?? ""),
    state: String(a.state ?? "UNKNOWN"),
    customApp: asBool(a.custom_app),
    version: asStr(a.version),
    humanVersion: asStr(a.human_version),
    hostNetwork: asBool(network.host_network),
    portBindings: shapePortBindings(network),
    action: "observed",
    timestamp: ts,
  };
}

function shapeNfs(raw: unknown, ts: string): z.infer<typeof NfsShare> {
  const s = asObj(raw);
  const networks = strArr(s.networks);
  const hosts = strArr(s.hosts);
  return {
    id: asNum(s.id) ?? 0,
    path: String(s.path ?? ""),
    comment: asStr(s.comment),
    enabled: asBool(s.enabled),
    ro: asBool(s.ro),
    networks,
    hosts,
    unrestricted: networks.length === 0 && hosts.length === 0,
    action: "observed",
    timestamp: ts,
  };
}

function shapeSmb(raw: unknown, ts: string): z.infer<typeof SmbShare> {
  const s = asObj(raw);
  const hostsallow = strArr(s.hostsallow);
  return {
    id: asNum(s.id) ?? 0,
    name: String(s.name ?? ""),
    path: String(s.path ?? ""),
    comment: asStr(s.comment),
    enabled: asBool(s.enabled),
    ro: asBool(s.ro),
    hostsallow,
    hostsdeny: strArr(s.hostsdeny),
    purpose: String(s.purpose ?? ""),
    unrestricted: hostsallow.length === 0,
    action: "observed",
    timestamp: ts,
  };
}

function shapeService(raw: unknown, ts: string): z.infer<typeof ServiceInfo> {
  const s = asObj(raw);
  const state = String(s.state ?? "UNKNOWN");
  return {
    service: String(s.service ?? ""),
    state,
    enable: asBool(s.enable),
    running: state === "RUNNING",
    action: "observed",
    timestamp: ts,
  };
}

// ─────────────────────────── method argument schemas ───────────────────────────

const Empty = z.object({});

const AppSetPortBindArgs = z.object({
  app: z.string().describe("App name (from app_list)"),
  portKey: z.string().optional().describe(
    'Port config key, e.g. "ldap_port", "admin_port" (preferred; from app_list portBindings)',
  ),
  portNumber: z.coerce.number().int().optional().describe(
    "Alternatively select the port by its current number",
  ),
  bindMode: z.enum(["published", "exposed"]).optional().describe(
    "published = bound on the host; exposed = container-internal only (closes the " +
      "host port). Omit to leave the mode unchanged and only edit hostIps.",
  ),
  hostIps: z.array(z.string()).optional().describe(
    'Host IPs to publish on (e.g. ["192.0.2.252"]); only meaningful when ' +
      "published. Omit to leave unchanged.",
  ),
}).refine(
  (a) => !!(a.portKey || a.portNumber !== undefined),
  { message: "provide portKey or portNumber" },
).refine(
  (a) => a.bindMode !== undefined || a.hostIps !== undefined,
  { message: "provide bindMode and/or hostIps (nothing to change otherwise)" },
);

const AppSetNetworksArgs = z.object({
  app: z.string().describe("App name (from app_list)"),
  networks: z.array(z.string()).describe(
    "The COMPLETE desired set of docker network names to attach the app to (e.g. " +
      '["ix-scrutiny_default","ix-lldap_default"]). Existing entries are preserved ' +
      "(their config kept); entries not listed are detached. Reversible: re-run with " +
      "the prior set. Use to attach a reverse-proxy app to other apps' bridges.",
  ),
});

const NfsShareSetAccessArgs = z.object({
  id: z.coerce.number().int().optional().describe(
    "NFS share id (from nfs_share_list)",
  ),
  path: z.string().optional().describe(
    "Alternatively select the share by export path",
  ),
  networks: z.array(z.string()).optional().describe(
    'Authorized networks in CIDR, e.g. ["192.0.2.161/32"]. Empty array CLEARS ' +
      "the restriction (all networks). Omit to leave networks unchanged.",
  ),
  hosts: z.array(z.string()).optional().describe(
    "Authorized hosts/IPs. Empty array clears. Omit to leave hosts unchanged.",
  ),
}).refine(
  (a) => !!(a.id !== undefined || a.path),
  { message: "provide id or path" },
).refine(
  (a) => a.networks !== undefined || a.hosts !== undefined,
  { message: "provide networks and/or hosts" },
);

const NfsShareDeleteArgs = z.object({
  id: z.coerce.number().int().optional().describe(
    "NFS share id (from nfs_share_list)",
  ),
  path: z.string().optional().describe(
    "Alternatively select the share by export path",
  ),
  confirmPath: z.string().optional().describe(
    "Safety guard: when set, must exactly equal the resolved share's export path " +
      "or the delete is refused (guards against deleting the wrong share by a mistyped id).",
  ),
}).refine(
  (a) => !!(a.id !== undefined || a.path),
  { message: "provide id or path" },
);

const SmbShareSetAccessArgs = z.object({
  id: z.coerce.number().int().optional().describe(
    "SMB share id (from smb_share_list)",
  ),
  name: z.string().optional().describe(
    "Alternatively select the share by name",
  ),
  hostsallow: z.array(z.string()).optional().describe(
    "Allowed hosts/subnets. Empty array clears the allowlist. Omit to leave unchanged.",
  ),
  hostsdeny: z.array(z.string()).optional().describe(
    'Denied hosts/subnets (e.g. ["ALL"] with an allowlist). Omit to leave unchanged.',
  ),
}).refine(
  (a) => !!(a.id !== undefined || a.name),
  { message: "provide id or name" },
).refine(
  (a) => a.hostsallow !== undefined || a.hostsdeny !== undefined,
  { message: "provide hostsallow and/or hostsdeny" },
);

const SmbShareDeleteArgs = z.object({
  id: z.coerce.number().int().optional().describe(
    "SMB share id (from smb_share_list)",
  ),
  name: z.string().optional().describe(
    "Alternatively select the share by name",
  ),
  confirmName: z.string().optional().describe(
    "Safety guard: when set, must exactly equal the resolved share's name " +
      "or the delete is refused (guards against deleting the wrong share by a mistyped id).",
  ),
}).refine(
  (a) => !!(a.id !== undefined || a.name),
  { message: "provide id or name" },
);

// ─────────────────────────── resolve helpers (verify-first) ───────────────────────────

/** Find an app by name; throws if absent. */
async function resolveApp(
  session: RpcSession,
  name: string,
): Promise<Record<string, unknown>> {
  const apps = asArr(
    await session.call("app.query", [[["name", "=", name]], {
      extra: { retrieve_config: true },
    }]),
  );
  const app = apps.find((a) => String(asObj(a).name) === name);
  if (!app) throw new Error(`app ${JSON.stringify(name)} not found`);
  return asObj(app);
}

/** Find an NFS share by id or path; throws if absent/ambiguous. */
async function resolveNfs(
  session: RpcSession,
  a: { id?: number; path?: string },
): Promise<Record<string, unknown>> {
  const filter = a.id !== undefined
    ? [["id", "=", a.id]]
    : [["path", "=", a.path]];
  const rows = asArr(await session.call("sharing.nfs.query", [filter]));
  if (rows.length === 0) {
    throw new Error(`NFS share ${JSON.stringify(a.id ?? a.path)} not found`);
  }
  if (rows.length > 1) {
    throw new Error(
      `NFS selector ${
        JSON.stringify(a.id ?? a.path)
      } is ambiguous (${rows.length} matches) — use id`,
    );
  }
  return asObj(rows[0]);
}

/** Find an SMB share by id or name; throws if absent/ambiguous. */
async function resolveSmb(
  session: RpcSession,
  a: { id?: number; name?: string },
): Promise<Record<string, unknown>> {
  const filter = a.id !== undefined
    ? [["id", "=", a.id]]
    : [["name", "=", a.name]];
  const rows = asArr(await session.call("sharing.smb.query", [filter]));
  if (rows.length === 0) {
    throw new Error(`SMB share ${JSON.stringify(a.id ?? a.name)} not found`);
  }
  if (rows.length > 1) {
    throw new Error(
      `SMB selector ${
        JSON.stringify(a.id ?? a.name)
      } is ambiguous (${rows.length} matches) — use id`,
    );
  }
  return asObj(rows[0]);
}

/**
 * Like {@link resolveNfs} but returns `null` when no share matches (idempotent
 * delete path) — still throws on an AMBIGUOUS selector, since deleting one of
 * several matches blindly is unsafe.
 */
async function resolveNfsOrNull(
  session: RpcSession,
  a: { id?: number; path?: string },
): Promise<Record<string, unknown> | null> {
  const filter = a.id !== undefined
    ? [["id", "=", a.id]]
    : [["path", "=", a.path]];
  const rows = asArr(await session.call("sharing.nfs.query", [filter]));
  if (rows.length === 0) return null;
  if (rows.length > 1) {
    throw new Error(
      `NFS selector ${
        JSON.stringify(a.id ?? a.path)
      } is ambiguous (${rows.length} matches) — use id`,
    );
  }
  return asObj(rows[0]);
}

/**
 * Like {@link resolveSmb} but returns `null` when no share matches (idempotent
 * delete path) — still throws on an AMBIGUOUS selector.
 */
async function resolveSmbOrNull(
  session: RpcSession,
  a: { id?: number; name?: string },
): Promise<Record<string, unknown> | null> {
  const filter = a.id !== undefined
    ? [["id", "=", a.id]]
    : [["name", "=", a.name]];
  const rows = asArr(await session.call("sharing.smb.query", [filter]));
  if (rows.length === 0) return null;
  if (rows.length > 1) {
    throw new Error(
      `SMB selector ${
        JSON.stringify(a.id ?? a.name)
      } is ambiguous (${rows.length} matches) — use id`,
    );
  }
  return asObj(rows[0]);
}

// ─────────────────────────── model ───────────────────────────

/**
 * The `@thomas/truenas` model definition: read/audit methods over apps, NFS/SMB
 * shares, services, and network exposure, plus a narrow reversible mutating surface
 * (app port bind mode, NFS/SMB share access). See the module header for scope and the
 * transport-safety guarantee.
 */
export const model = {
  type: "@thomas/truenas",
  version: "2026.06.16.1",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify the TrueNAS API authenticates (wss login + system.info)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        const g = context.globalArgs;
        // `swamp model validate` does NOT resolve vault expressions before checks, so
        // the key is still a literal `${{ … }}` and a probe can't auth. Skip then —
        // real reachability is exercised at method-run time.
        if (/\$\{\{/.test(String(g.apiKey))) return { pass: true };
        let session: RpcSession | undefined;
        try {
          session = await openSession(g);
          await session.call("system.info", []);
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Cannot reach TrueNAS at ${g.endpoint}: ${(e as Error).message}`,
            ],
          };
        } finally {
          session?.close();
        }
      },
    },
  },
  resources: {
    "system-info": {
      description: "Host system info (hostname, version, uptime, memory)",
      schema: SystemInfo,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "app": {
      description: "An installed app with its published/exposed port bindings",
      schema: AppInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "nfs-share": {
      description: "An NFS export with its networks/hosts allowlist",
      schema: NfsShare,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "smb-share": {
      description: "An SMB share with its hostsallow/hostsdeny",
      schema: SmbShare,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "service": {
      description: "A system service (state + boot-enable)",
      schema: ServiceInfo,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "network-info": {
      description: "Bindable host IPs + interfaces + GUI bind addresses",
      schema: NetworkInfo,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "exposure-audit": {
      description:
        "Service-exposure roll-up across apps/shares/services (R28 source)",
      schema: ExposureAudit,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "app-port-result": {
      description: "Result of an app_set_port_bind change",
      schema: AppPortResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "app-networks-result": {
      description: "Result of an app_set_networks change",
      schema: AppNetworksResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "nfs-share-result": {
      description: "Result of an nfs_share_set_access change",
      schema: NfsShareResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "smb-share-result": {
      description: "Result of an smb_share_set_access change",
      schema: SmbShareResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    // ───────────── read / audit ─────────────
    system_info: {
      description:
        "Fetch host system info (hostname, version, uptime). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const session = await openSession(g);
        try {
          logInfo(context, "Fetching system.info");
          const raw = asObj(await session.call("system.info", []));
          const ts = new Date().toISOString();
          const handle = await context.writeResource("system-info", "main", {
            hostname: String(raw.hostname ?? "unknown"),
            version: String(raw.version ?? "unknown"),
            uptimeSeconds: nullableNum(raw.uptime_seconds),
            loadAvg: Array.isArray(raw.loadavg)
              ? raw.loadavg.map((n) => asNum(n) ?? 0)
              : undefined,
            physmem: nullableNum(raw.physmem),
            model: asStr(raw.model),
            cores: nullableNum(raw.cores),
            action: "observed",
            timestamp: ts,
          });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    app_list: {
      description:
        "List installed apps with their port bindings (factory: one `app` per app). " +
        "Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const session = await openSession(g);
        try {
          logInfo(context, "Querying apps");
          const apps = asArr(
            await session.call("app.query", [[], {
              extra: { retrieve_config: true },
            }]),
          );
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const raw of apps) {
            const shaped = shapeApp(raw, ts);
            if (!shaped.name) continue;
            handles.push(
              await context.writeResource("app", shaped.name, shaped),
            );
          }
          return { dataHandles: handles };
        } finally {
          session.close();
        }
      },
    },

    nfs_share_list: {
      description:
        "List NFS exports with their networks/hosts allowlist (factory). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const session = await openSession(g);
        try {
          logInfo(context, "Querying NFS shares");
          const rows = asArr(await session.call("sharing.nfs.query", [[]]));
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const raw of rows) {
            const shaped = shapeNfs(raw, ts);
            handles.push(
              await context.writeResource(
                "nfs-share",
                String(shaped.id),
                shaped,
              ),
            );
          }
          return { dataHandles: handles };
        } finally {
          session.close();
        }
      },
    },

    smb_share_list: {
      description:
        "List SMB shares with their hostsallow/hostsdeny (factory). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const session = await openSession(g);
        try {
          logInfo(context, "Querying SMB shares");
          const rows = asArr(await session.call("sharing.smb.query", [[]]));
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const raw of rows) {
            const shaped = shapeSmb(raw, ts);
            handles.push(
              await context.writeResource(
                "smb-share",
                String(shaped.id),
                shaped,
              ),
            );
          }
          return { dataHandles: handles };
        } finally {
          session.close();
        }
      },
    },

    service_list: {
      description:
        "List system services with state + boot-enable (factory). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const session = await openSession(g);
        try {
          logInfo(context, "Querying services");
          const rows = asArr(await session.call("service.query", [[]]));
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const raw of rows) {
            const shaped = shapeService(raw, ts);
            if (!shaped.service) continue;
            handles.push(
              await context.writeResource("service", shaped.service, shaped),
            );
          }
          return { dataHandles: handles };
        } finally {
          session.close();
        }
      },
    },

    network_info: {
      description:
        "Report bindable host IPs (the app port-bind selector contents), interfaces, " +
        "and GUI bind addresses. Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const session = await openSession(g);
        try {
          logInfo(context, "Querying network interfaces");
          const inUse = asArr(
            await session.call("interface.ip_in_use", [
              {
                ipv4: true,
                ipv6: false,
                loopback: false,
                any: false,
                static: false,
              },
            ]),
          );
          const ifaces = asArr(await session.call("interface.query", [[]]));
          const general = asObj(
            await session.call("system.general.config", []),
          );
          const ts = new Date().toISOString();
          const bindableIps = inUse.map((r) => {
            const o = asObj(r);
            return {
              address: String(o.address ?? ""),
              netmask: nullableNum(o.netmask),
              interface: asStr(o.interface),
            };
          });
          const interfaces = ifaces.map((r) => {
            const o = asObj(r);
            const state = asObj(o.state);
            const addrs = asArr(state.aliases)
              .map((al) => asStr(asObj(al).address))
              .filter((x): x is string => !!x);
            return {
              name: String(o.name ?? o.id ?? ""),
              type: asStr(o.type),
              addresses: addrs,
            };
          });
          const handle = await context.writeResource("network-info", "main", {
            bindableIps,
            interfaces,
            guiAddresses: strArr(general.ui_address),
            action: "observed",
            timestamp: ts,
          });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    exposure_audit: {
      description:
        "Roll up service exposure across apps/NFS/SMB/services into one report " +
        "(published ports, unrestricted shares, 0.0.0.0 binds, plaintext-LDAP flag). " +
        "Read-only — the R28 data source.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const session = await openSession(g);
        try {
          logInfo(context, "Building exposure audit");
          const info = asObj(await session.call("system.info", []));
          const apps = asArr(
            await session.call("app.query", [[], {
              extra: { retrieve_config: true },
            }]),
          );
          const nfs = asArr(await session.call("sharing.nfs.query", [[]]));
          const smb = asArr(await session.call("sharing.smb.query", [[]]));
          const inUse = asArr(
            await session.call("interface.ip_in_use", [
              {
                ipv4: true,
                ipv6: false,
                loopback: false,
                any: false,
                static: false,
              },
            ]),
          );
          const ts = new Date().toISOString();

          const publishedPorts: z.infer<typeof ExposedPort>[] = [];
          const portsOnAll = new Set<number>();
          let plaintextLdap = false;
          for (const raw of apps) {
            const shaped = shapeApp(raw, ts);
            for (const pb of shaped.portBindings) {
              if (!pb.published) continue;
              publishedPorts.push({
                source: `app:${shaped.name}`,
                portNumber: pb.portNumber,
                protocol: pb.protocol,
                hostIps: pb.hostIps,
                detail: pb.portKey,
              });
              if (pb.hostIps.includes("0.0.0.0")) portsOnAll.add(pb.portNumber);
              if (pb.portNumber === 389) plaintextLdap = true;
            }
          }
          publishedPorts.sort((a, b) => a.portNumber - b.portNumber);

          const unrestrictedNfs = nfs.map((r) => shapeNfs(r, ts))
            .filter((s) => s.unrestricted).map((s) => s.path);
          const unrestrictedSmb = smb.map((r) => shapeSmb(r, ts))
            .filter((s) => s.enabled && s.unrestricted).map((s) => s.name);
          const nonWildcard = inUse
            .map((r) => String(asObj(r).address ?? ""))
            .filter((a) => a && a !== "0.0.0.0");

          const handle = await context.writeResource("exposure-audit", "main", {
            hostname: String(info.hostname ?? "unknown"),
            version: String(info.version ?? "unknown"),
            publishedPorts,
            unrestrictedNfsShares: unrestrictedNfs,
            unrestrictedSmbShares: unrestrictedSmb,
            flags: {
              portsOnAllInterfaces: [...portsOnAll].sort((a, b) => a - b),
              plaintextLdapPublished: plaintextLdap,
              nonWildcardBindableIps: nonWildcard,
            },
            appCount: apps.length,
            nfsShareCount: nfs.length,
            smbShareCount: smb.length,
            action: "observed",
            timestamp: ts,
          });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    // ───────────── mutate (verify-first, reversible) ─────────────
    app_set_port_bind: {
      description:
        "Change one app port's bind mode (published↔exposed) and/or host IPs. " +
        "Verifies the app + port first, sends the full reconstructed port object so " +
        "port_number/certificate_id survive, then waits for the app.update job. " +
        "Reversible: re-run with the prior bindMode/hostIps.",
      arguments: AppSetPortBindArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const a = AppSetPortBindArgs.parse(rawArgs);
        const session = await openSession(g);
        try {
          const app = await resolveApp(session, a.app);
          const cfg = asObj(app.config);

          // Some apps store ports as a LIST (config.ports: [{port_number,bind_mode,
          // host_ips,…}]) instead of the keyed config.network map (e.g. kopia, custom
          // apps). Handle that form in a dedicated branch — list entries have no key,
          // so they're selected by portNumber.
          const portsList = asArr(cfg.ports).map((p) => asObj(p));
          const inNetworkMap = a.portKey
            ? asObj(cfg.network)[a.portKey] !== undefined
            : Object.values(asObj(cfg.network)).some(
              (v) => asNum(asObj(v).port_number) === a.portNumber,
            );
          if (portsList.length > 0 && !inNetworkMap) {
            const idx = portsList.findIndex(
              (p) =>
                a.portNumber !== undefined &&
                asNum(p.port_number) === a.portNumber,
            );
            if (idx < 0) {
              throw new Error(
                `port ${
                  JSON.stringify(a.portNumber ?? a.portKey)
                } not found in ` +
                  `config.ports of ${a.app} (list-form ports select by portNumber)`,
              );
            }
            const cur = portsList[idx];
            const pkLabel = String(
              asNum(cur.port_number) ?? a.portNumber ?? "",
            );
            const prevMode = String(cur.bind_mode ?? "published");
            const prevIps = strArr(cur.host_ips);
            const newMode = a.bindMode ?? prevMode;
            const newIps = a.hostIps ?? prevIps;
            const lts = new Date().toISOString();

            if (newMode === prevMode && sameStrArr(newIps, prevIps)) {
              const handle = await context.writeResource(
                "app-port-result",
                `${a.app}:${pkLabel}`,
                {
                  app: a.app,
                  portKey: pkLabel,
                  portNumber: asNum(cur.port_number) ?? 0,
                  previousBindMode: prevMode,
                  previousHostIps: prevIps,
                  bindMode: newMode,
                  hostIps: newIps,
                  action: "unchanged",
                  timestamp: lts,
                },
              );
              return { dataHandles: [handle] };
            }

            const newList = portsList.map((p, i) =>
              i === idx ? { ...p, bind_mode: newMode, host_ips: newIps } : p
            );
            logInfo(context, "Updating app port binding (ports-list)", {
              app: a.app,
              portNumber: cur.port_number,
              from: prevMode,
              to: newMode,
            });
            await callJob(
              session,
              "app.update",
              [a.app, { values: { ports: newList } }],
              Number(g.timeoutMs) || 30000,
            );

            const afterList = asArr(
              asObj((await resolveApp(session, a.app)).config).ports,
            )
              .map((p) => asObj(p));
            const applied = afterList.find(
              (p) =>
                asNum(p.port_number) ===
                  (asNum(cur.port_number) ?? a.portNumber),
            ) ?? {};
            const handle = await context.writeResource(
              "app-port-result",
              `${a.app}:${pkLabel}`,
              {
                app: a.app,
                portKey: pkLabel,
                portNumber: asNum(applied.port_number ?? cur.port_number) ?? 0,
                previousBindMode: prevMode,
                previousHostIps: prevIps,
                bindMode: String(applied.bind_mode ?? newMode),
                hostIps: strArr(applied.host_ips ?? newIps),
                action: "updated",
                timestamp: lts,
              },
            );
            return { dataHandles: [handle] };
          }

          const network = asObj(cfg.network);
          // Locate the target port object in config.network.
          let portKey = a.portKey;
          if (!portKey) {
            for (const [k, v] of Object.entries(network)) {
              const p = asObj(v);
              if (
                p.port_number !== undefined &&
                asNum(p.port_number) === a.portNumber
              ) {
                portKey = k;
                break;
              }
            }
          }
          if (!portKey || network[portKey] === undefined) {
            throw new Error(
              `port ${
                JSON.stringify(a.portKey ?? a.portNumber)
              } not found on app ${a.app}`,
            );
          }
          const current = asObj(network[portKey]);
          if (
            current.port_number === undefined || current.bind_mode === undefined
          ) {
            throw new Error(
              `${a.app}.${portKey} is not a bindable port object`,
            );
          }
          const prevBindMode = String(current.bind_mode);
          const prevHostIps = strArr(current.host_ips);
          const newBindMode = a.bindMode ?? prevBindMode;
          const newHostIps = a.hostIps ?? prevHostIps;

          // Reconstruct the FULL port object so no field (port_number,
          // certificate_id, …) is dropped, then send the ENTIRE network map with only
          // this port changed. Sending the whole `network` sidesteps any ambiguity in
          // how app.update merges nested values — sibling ports (http_port, ldaps_port)
          // can't be lost regardless of merge depth.
          const portObj: Record<string, unknown> = { ...current };
          portObj.bind_mode = newBindMode;
          portObj.host_ips = newHostIps;
          const networkPatch: Record<string, unknown> = {
            ...network,
            [portKey]: portObj,
          };

          const ts = new Date().toISOString();
          if (
            newBindMode === prevBindMode && sameStrArr(newHostIps, prevHostIps)
          ) {
            logInfo(
              context,
              "Port binding already at desired state — no change",
              {
                app: a.app,
                portKey,
              },
            );
            const handle = await context.writeResource(
              "app-port-result",
              `${a.app}:${portKey}`,
              {
                app: a.app,
                portKey,
                portNumber: asNum(current.port_number) ?? 0,
                previousBindMode: prevBindMode,
                previousHostIps: prevHostIps,
                bindMode: newBindMode,
                hostIps: newHostIps,
                action: "unchanged",
                timestamp: ts,
              },
            );
            return { dataHandles: [handle] };
          }

          logInfo(context, "Updating app port binding", {
            app: a.app,
            portKey,
            from: prevBindMode,
            to: newBindMode,
          });
          await callJob(
            session,
            "app.update",
            [a.app, { values: { network: networkPatch } }],
            Number(g.timeoutMs) || 30000,
          );

          // Re-read to confirm the applied state.
          const after = asObj(
            asObj((await resolveApp(session, a.app)).config).network,
          );
          const applied = asObj(after[portKey]);
          const handle = await context.writeResource(
            "app-port-result",
            `${a.app}:${portKey}`,
            {
              app: a.app,
              portKey,
              portNumber: asNum(applied.port_number ?? current.port_number) ??
                0,
              previousBindMode: prevBindMode,
              previousHostIps: prevHostIps,
              bindMode: String(applied.bind_mode ?? newBindMode),
              hostIps: strArr(applied.host_ips ?? newHostIps),
              action: "updated",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    app_set_networks: {
      description:
        "Attach an app to a set of docker networks (e.g. join a reverse-proxy app to " +
        "other apps' `ix-<app>_default` bridges so it can reach them by service name " +
        "without host-published ports). Verifies the app first; preserves the config of " +
        "already-attached networks; reversible by re-running with the prior set.",
      arguments: AppSetNetworksArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const a = AppSetNetworksArgs.parse(rawArgs);
        const session = await openSession(g);
        try {
          const app = await resolveApp(session, a.app);
          const cfg = asObj(app.config);
          const current = asArr(cfg.networks).map((n) => asObj(n));
          const prevNames = current.map((n) => String(n.name));
          const ts = new Date().toISOString();

          if (sameStrArr(a.networks, prevNames)) {
            const handle = await context.writeResource(
              "app-networks-result",
              a.app,
              {
                app: a.app,
                previousNetworks: prevNames,
                networks: prevNames,
                action: "unchanged",
                timestamp: ts,
              },
            );
            return { dataHandles: [handle] };
          }

          // Build the new list: keep each desired net's existing entry (preserving its
          // config) or add a fresh entry with the default config. Order follows the arg.
          const byName = new Map(current.map((n) => [String(n.name), n]));
          const newList = a.networks.map((name) =>
            byName.get(name) ?? { name, config: { ...DEFAULT_NETWORK_CONFIG } }
          );

          logInfo(context, "Updating app networks", {
            app: a.app,
            from: prevNames,
            to: a.networks,
          });
          await callJob(
            session,
            "app.update",
            [a.app, { values: { networks: newList } }],
            Number(g.timeoutMs) || 30000,
          );

          const after = asArr(
            asObj((await resolveApp(session, a.app)).config).networks,
          )
            .map((n) => String(asObj(n).name));
          const handle = await context.writeResource(
            "app-networks-result",
            a.app,
            {
              app: a.app,
              previousNetworks: prevNames,
              networks: after,
              action: "updated",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    nfs_share_set_access: {
      description:
        "Set an NFS export's authorized networks/hosts allowlist (the per-client " +
        "gate). Verifies the share first. An EMPTY array clears that restriction. " +
        "Reversible: re-run with the prior values.",
      arguments: NfsShareSetAccessArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const a = NfsShareSetAccessArgs.parse(rawArgs);
        const session = await openSession(g);
        try {
          const share = await resolveNfs(session, a);
          const id = asNum(share.id) ?? 0;
          const prevNetworks = strArr(share.networks);
          const prevHosts = strArr(share.hosts);
          const newNetworks = a.networks ?? prevNetworks;
          const newHosts = a.hosts ?? prevHosts;
          const ts = new Date().toISOString();

          if (
            sameStrArr(newNetworks, prevNetworks) &&
            sameStrArr(newHosts, prevHosts)
          ) {
            const handle = await context.writeResource(
              "nfs-share-result",
              String(id),
              {
                id,
                path: String(share.path ?? ""),
                previousNetworks: prevNetworks,
                previousHosts: prevHosts,
                networks: newNetworks,
                hosts: newHosts,
                action: "unchanged",
                timestamp: ts,
              },
            );
            return { dataHandles: [handle] };
          }

          logInfo(context, "Updating NFS share access", {
            id,
            path: share.path,
          });
          await session.call("sharing.nfs.update", [id, {
            networks: newNetworks,
            hosts: newHosts,
          }]);
          const after = await resolveNfs(session, { id });
          const handle = await context.writeResource(
            "nfs-share-result",
            String(id),
            {
              id,
              path: String(after.path ?? share.path ?? ""),
              previousNetworks: prevNetworks,
              previousHosts: prevHosts,
              networks: strArr(after.networks),
              hosts: strArr(after.hosts),
              action: "updated",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    nfs_share_delete: {
      description:
        "DELETE an NFS export rule (e.g. a now-unused share). Verifies the share " +
        "first and records its removed config (path/networks/hosts) so it can be " +
        "re-created. Idempotent: a share that's already gone records action=absent " +
        "instead of failing. Removes ONLY the export rule — the underlying " +
        "dataset/data is untouched. Pass confirmPath to guard against deleting the wrong share.",
      arguments: NfsShareDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const a = NfsShareDeleteArgs.parse(rawArgs);
        const session = await openSession(g);
        try {
          const share = await resolveNfsOrNull(session, a);
          if (share === null) {
            // Already gone — idempotent success. The confirmPath guard only
            // protects against deleting the WRONG existing share, so it doesn't
            // apply when there's nothing to delete.
            const ats = new Date().toISOString();
            const handle = await context.writeResource(
              "nfs-share-result",
              String(a.id ?? a.path),
              {
                id: a.id ?? 0,
                path: a.path ?? "",
                previousNetworks: [],
                previousHosts: [],
                networks: [],
                hosts: [],
                action: "absent",
                timestamp: ats,
              },
            );
            return { dataHandles: [handle] };
          }
          const id = asNum(share.id) ?? 0;
          const path = String(share.path ?? "");
          const ts = new Date().toISOString();

          if (a.confirmPath !== undefined && a.confirmPath !== path) {
            throw new Error(
              `confirmPath ${
                JSON.stringify(a.confirmPath)
              } does not match the ` +
                `resolved export path ${
                  JSON.stringify(path)
                } — refusing to delete`,
            );
          }

          logInfo(context, "Deleting NFS export", { id, path });
          await session.call("sharing.nfs.delete", [id]);

          // The removed config is captured in previous* so the export can be re-created.
          const handle = await context.writeResource(
            "nfs-share-result",
            String(id),
            {
              id,
              path,
              previousNetworks: strArr(share.networks),
              previousHosts: strArr(share.hosts),
              networks: [],
              hosts: [],
              action: "deleted",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    smb_share_set_access: {
      description:
        "Set an SMB share's hostsallow/hostsdeny. Verifies the share first. An EMPTY " +
        "hostsallow clears the allowlist. Reversible: re-run with the prior values.",
      arguments: SmbShareSetAccessArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const a = SmbShareSetAccessArgs.parse(rawArgs);
        const session = await openSession(g);
        try {
          const share = await resolveSmb(session, a);
          const id = asNum(share.id) ?? 0;
          const prevAllow = strArr(share.hostsallow);
          const prevDeny = strArr(share.hostsdeny);
          const prevPurpose = String(share.purpose ?? "");
          const newAllow = a.hostsallow ?? prevAllow;
          const newDeny = a.hostsdeny ?? prevDeny;
          const ts = new Date().toISOString();

          // A preset that locks hostsallow/hostsdeny silently discards them on update;
          // release to NO_PRESET (only when we're actually applying host rules) so the
          // allowlist sticks. Clearing rules needs no purpose change.
          const wantHostRules = newAllow.length > 0 || newDeny.length > 0;
          const releaseLock = wantHostRules &&
            HOST_LOCKING_PURPOSES.has(prevPurpose);
          const newPurpose = releaseLock ? "NO_PRESET" : prevPurpose;

          if (
            sameStrArr(newAllow, prevAllow) && sameStrArr(newDeny, prevDeny) &&
            newPurpose === prevPurpose
          ) {
            const handle = await context.writeResource(
              "smb-share-result",
              String(id),
              {
                id,
                name: String(share.name ?? ""),
                previousHostsallow: prevAllow,
                previousHostsdeny: prevDeny,
                hostsallow: newAllow,
                hostsdeny: newDeny,
                previousPurpose: prevPurpose,
                purpose: newPurpose,
                action: "unchanged",
                timestamp: ts,
              },
            );
            return { dataHandles: [handle] };
          }

          logInfo(context, "Updating SMB share access", {
            id,
            name: share.name,
            releaseLock,
          });
          // Echo name+path: sharing.smb.update marks them required in its schema, so
          // include the verified values to be safe even though the update is partial.
          // Include purpose only when releasing a host-locking preset, so non-locked
          // shares keep their existing preset untouched.
          const payload: Record<string, unknown> = {
            name: String(share.name ?? ""),
            path: String(share.path ?? ""),
            hostsallow: newAllow,
            hostsdeny: newDeny,
          };
          if (releaseLock) payload.purpose = "NO_PRESET";
          await session.call("sharing.smb.update", [id, payload]);
          const after = await resolveSmb(session, { id });
          const handle = await context.writeResource(
            "smb-share-result",
            String(id),
            {
              id,
              name: String(after.name ?? share.name ?? ""),
              previousHostsallow: prevAllow,
              previousHostsdeny: prevDeny,
              hostsallow: strArr(after.hostsallow),
              hostsdeny: strArr(after.hostsdeny),
              previousPurpose: prevPurpose,
              purpose: String(after.purpose ?? newPurpose),
              action: "updated",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    smb_share_delete: {
      description:
        "DELETE an SMB share (e.g. a now-unused share). Verifies the share first " +
        "and records its removed config (name/path/hostsallow/hostsdeny/purpose) so it " +
        "can be re-created. Idempotent: a share that's already gone records action=absent " +
        "instead of failing. Removes ONLY the share definition — the underlying " +
        "dataset/data is untouched. Pass confirmName to guard against deleting the wrong share.",
      arguments: SmbShareDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const a = SmbShareDeleteArgs.parse(rawArgs);
        const session = await openSession(g);
        try {
          const share = await resolveSmbOrNull(session, a);
          if (share === null) {
            // Already gone — idempotent success. The confirmName guard only
            // protects against deleting the WRONG existing share, so it doesn't
            // apply when there's nothing to delete.
            const ats = new Date().toISOString();
            const handle = await context.writeResource(
              "smb-share-result",
              String(a.id ?? a.name),
              {
                id: a.id ?? 0,
                name: a.name ?? "",
                previousHostsallow: [],
                previousHostsdeny: [],
                hostsallow: [],
                hostsdeny: [],
                previousPurpose: "",
                purpose: "",
                action: "absent",
                timestamp: ats,
              },
            );
            return { dataHandles: [handle] };
          }
          const id = asNum(share.id) ?? 0;
          const name = String(share.name ?? "");
          const ts = new Date().toISOString();

          if (a.confirmName !== undefined && a.confirmName !== name) {
            throw new Error(
              `confirmName ${
                JSON.stringify(a.confirmName)
              } does not match the ` +
                `resolved share name ${
                  JSON.stringify(name)
                } — refusing to delete`,
            );
          }

          logInfo(context, "Deleting SMB share", { id, name });
          await session.call("sharing.smb.delete", [id]);

          // The removed config is captured in previous* so the share can be re-created.
          const handle = await context.writeResource(
            "smb-share-result",
            String(id),
            {
              id,
              name,
              previousHostsallow: strArr(share.hostsallow),
              previousHostsdeny: strArr(share.hostsdeny),
              hostsallow: [],
              hostsdeny: [],
              previousPurpose: String(share.purpose ?? ""),
              purpose: String(share.purpose ?? ""),
              action: "deleted",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;

/** Order-insensitive set equality for two string arrays (used by the no-op fast paths). */
function sameStrArr(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  return sa.every((x, i) => x === sb[i]);
}
