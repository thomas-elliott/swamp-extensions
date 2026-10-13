import { z } from "npm:zod@4";
// Type-only imports: erased at compile time, never bundled. The
// `satisfies ModelDefinition<typeof GlobalArgs>` clause uses them so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";

/**
 * `@thomas/truenas`: administration of a TrueNAS SCALE host via its JSON-RPC 2.0
 * API over a WebSocket (`wss://<host>/api/current`), authenticated with an API key.
 * Supports 25.04 ("Fangtooth") and 25.10 ("Goldeye"); the WebSocket RPC is the
 * supported API. Of the calls this model makes, only the SMB share schema differs
 * between the two: 25.10 moved the host lists under `options` (see {@link smbAccessUpdate}).
 *
 * Scope: read what a TrueNAS host exposes, then restrict it. The mutating methods
 * are deliberately few and limited to app port binds, app docker networks, and NFS/SMB
 * share access and deletion; each method's description says what it changes.
 * It does not change pools, datasets, users, snapshots, replication, or service
 * start/stop. `filesystem_list` reads a directory and `replication_list` reads task
 * definitions; neither writes, and no verb runs or edits a replication task. Service
 * start/stop is an explicit gap because a stopped ssh/nfs service risks a lockout or
 * outage. Every mutating verb verifies its target by id/name first and records the
 * prior state on its result.
 *
 * Transport safety: TrueNAS **permanently revokes an API key the instant it is sent
 * over a non-TLS transport** (plain `ws://`/`http://`). This model therefore refuses
 * any non-`wss` endpoint: {@link websocketUrl} throws before a socket is opened, and
 * never downgrades `https→ws`. The certificate is always validated: Deno skips
 * validation only process-wide (--unsafely-ignore-certificate-errors), never per
 * connection, so a NAS on its self-signed `CN=localhost` cert needs a trusted one.
 *
 * Secrets: `apiKey` is supplied via a vault expression, e.g.
 * `${{ vault.get(<vault>, truenas/credential) }}`. It is marked sensitive and
 * redacted from every error this model throws.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  // Required: a placeholder default would send a real API key to a host that
  // is not the user's NAS.
  endpoint: z.string().min(1).describe(
    "TrueNAS host or wss:// base URL (required), e.g. nas.example.com or " +
      "wss://nas.example.com/api/current. A bare host becomes " +
      "wss://<host>/api/current (the server's newest API version). " +
      "Non-TLS endpoints (ws://, http://) are rejected: TrueNAS " +
      "revokes an API key sent over cleartext.",
  ),
  apiKey: z.string().min(1).meta({ sensitive: true }).describe(
    "TrueNAS API key (Credentials → Users → API keys). Supply via vault: " +
      "${{ vault.get(<vault>, truenas/credential) }}",
  ),
  timeoutMs: z.coerce.number().int().positive().default(30000).describe(
    "Per-call timeout in milliseconds (also the job-wait budget)",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type", so it
// must not appear on the public API. The exported {@link RpcFn}/{@link SessionFactory}
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

/**
 * One published/exposed port binding on an app: a catalog app's keyed
 * config.network.<key>, or an entry of a custom app's config.ports list.
 */
const PortBinding = z.object({
  portKey: z.string().describe(
    'Config key, e.g. "ldap_port" / "admin_port"; "ports[<i>]" for an entry ' +
      "of a custom app's config.ports list (select those by portNumber)",
  ),
  portNumber: z.number(),
  protocol: z.string().describe("tcp | udp (best-effort; tcp if unknown)"),
  bindMode: z.string().describe("published | exposed"),
  hostIps: z.array(z.string()).describe(
    'Host IPs the port publishes on; empty, "0.0.0.0" or "::" = all interfaces',
  ),
  published: z.boolean().describe("bindMode === published"),
  exposedToAll: z.boolean().describe(
    'published, and hostIps is empty or includes "0.0.0.0" or "::"',
  ),
});

const AppInfo = z.object({
  name: z.string(),
  state: z.string().describe("RUNNING | STOPPED | DEPLOYING | …"),
  customApp: z.boolean(),
  version: z.string().optional(),
  humanVersion: z.string().optional(),
  hostNetwork: z.boolean().describe(
    "Whether the app runs on the host network (ports are not individually bound). " +
      "Read from config.network.host_network (catalog apps) or config.host_network " +
      "(custom apps)",
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
    "Authorized networks (CIDR). Empty (with hosts empty too) = all networks allowed.",
  ),
  hosts: z.array(z.string()).describe(
    "Authorized hosts/IPs. Empty (with networks empty too) = all hosts allowed.",
  ),
  unrestricted: z.boolean().describe(
    "True when any client can mount it: networks and hosts both empty, or an " +
      'entry that admits everyone (networks "0.0.0.0/0" or "::/0", hosts "*")',
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
  ro: z.boolean().describe("Read-only (`readonly` on 25.10)"),
  hostsallow: z.array(z.string()).describe(
    "Allowed hosts. Empty = all allowed. On 25.10 a purpose with no host lists " +
      "(EXTERNAL_SHARE, VEEAM_REPOSITORY_SHARE, and all but LEGACY_SHARE on 25.10.0) " +
      "reads as empty.",
  ),
  hostsdeny: z.array(z.string()).describe("Denied hosts."),
  purpose: z.string().describe(
    "Share purpose preset. Some presets hold no host lists: DEFAULT_SHARE and " +
      "VEEAM_REPOSITORY_SHARE on 25.04, all but LEGACY_SHARE on 25.10.0. To apply host " +
      "rules, smb_share_set_access moves a DEFAULT_SHARE to NO_PRESET (25.04) or " +
      "LEGACY_SHARE (25.10) and does not move it back; it refuses any other preset " +
      "without host lists.",
  ),
  unrestricted: z.boolean().describe(
    "True when hostsallow is empty (no host allowlist in force). hostsdeny does " +
      "not count: it still admits every host it does not name.",
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

/** One entry in a directory listing (`filesystem.listdir` row). */
const DirEntry = z.object({
  name: z.string(),
  type: z.string().describe("DIRECTORY | FILE | SYMLINK | OTHER"),
  size: z.number().nullable().optional(),
  isMountpoint: z.boolean().describe(
    "The entry is a mountpoint — for /mnt/<pool> children, a child dataset " +
      "rather than a plain directory",
  ),
});

const DirListing = z.object({
  path: z.string(),
  exists: z.boolean().describe(
    "False when the path is absent (or not a directory) — recorded instead of " +
      "failing, so a missing backup/app source path is data, not an error",
  ),
  entryCount: z.number().describe("Entries returned (after any truncation)"),
  truncated: z.boolean().describe("More entries exist than maxEntries"),
  entries: z.array(DirEntry),
  error: z.string().optional().describe("The listdir error when exists=false"),
  action: Action,
  timestamp: z.string(),
});

/** One host-path bind an app mounts (a `host_path` entry in the app's config). */
const HostPathMount = z.object({
  configPath: z.string().describe(
    "Where it sits in the app config, e.g. storage.additional_storage[1]",
  ),
  mountPath: z.string().describe("Path inside the container"),
  hostPath: z.string().describe("Path on the NAS"),
  readOnly: z.boolean(),
});

const AppStorage = z.object({
  app: z.string(),
  mountCount: z.number(),
  mounts: z.array(HostPathMount),
  action: Action,
  timestamp: z.string(),
});

const ReplicationTask = z.object({
  id: z.number(),
  name: z.string(),
  direction: z.string().describe("PUSH | PULL"),
  transport: z.string().describe("LOCAL | SSH | SSH+NETCAT"),
  enabled: z.boolean(),
  auto: z.boolean().describe("Runs on its schedule (vs manual-only)"),
  recursive: z.boolean().describe(
    "Child datasets ride along — the difference between a source's children " +
      "being replicated and silently skipped",
  ),
  sourceDatasets: z.array(z.string()),
  targetDataset: z.string(),
  schedule: z.string().optional().describe(
    "cron-ish minute hour dom month dow, or absent when not scheduled",
  ),
  readonlyPolicy: z.string().optional().describe(
    "TrueNAS readonly policy for the destination (SET/REQUIRE/IGNORE). SET " +
      "rewrites the destination's readonly property, which remounts it.",
  ),
  sendsProperties: z.boolean().describe(
    "Replicates dataset properties (incl. mountpoint/readonly) — a property " +
      "change on receive can unmount/remount the destination dataset",
  ),
  state: z.string().optional().describe("Last run state (FINISHED/ERROR/…)"),
  lastRunAt: z.string().optional(),
  lastError: z.string().optional(),
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
      "implicitly available. A Tailscale IP appears only if tailscale0 is a host " +
      "interface, which it is not when the Tailscale app provides it.",
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
  source: z.string().describe("app:<name>"),
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
  hostNetworkApps: z.array(z.string()).describe(
    "Apps on the host network. They bind no individual ports, so publishedPorts " +
      "cannot list them, but every port they open is on the host.",
  ),
  /** Enabled NFS shares any client can mount (see `nfs-share` `unrestricted`). */
  unrestrictedNfsShares: z.array(z.string()),
  /** Enabled SMB shares with an empty hostsallow. */
  unrestrictedSmbShares: z.array(z.string()),
  flags: z.object({
    /**
     * Published ports reachable on every interface: host IPs empty (the apps
     * library then binds 0.0.0.0 and ::), or including 0.0.0.0 or ::.
     */
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
  id: z.number().nullable().describe(
    "Share id; null when the share was already absent and was selected by path",
  ),
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
  id: z.number().nullable().describe(
    "Share id; null when the share was already absent and was selected by name",
  ),
  name: z.string(),
  path: z.string().describe(
    "The shared path; empty when the share was already absent",
  ),
  previousHostsallow: z.array(z.string()),
  previousHostsdeny: z.array(z.string()),
  hostsallow: z.array(z.string()),
  hostsdeny: z.array(z.string()),
  previousPurpose: z.string().describe(
    "The share's purpose preset before the change",
  ),
  purpose: z.string().describe(
    "The share's purpose preset after the change (a DEFAULT_SHARE given host " +
      "rules moves to NO_PRESET on 25.04 or LEGACY_SHARE on 25.10)",
  ),
  action: Action,
  timestamp: z.string(),
});

/** A share row's host lists: top-level on 25.04, under `options` on 25.10. */
function smbHostLists(
  share: Record<string, unknown>,
): { allow: string[]; deny: string[] } {
  const src = share.options === undefined ? share : asObj(share.options);
  return { allow: strArr(src.hostsallow), deny: strArr(src.hostsdeny) };
}

/** The error for a share whose purpose can't hold host rules and must not be moved. */
function cannotHoldHostRules(name: unknown, purpose: string): Error {
  return new Error(
    `SMB share ${
      JSON.stringify(name)
    } has purpose ${purpose}, which holds no ` +
      "host lists on this TrueNAS version. Moving it to one that does would drop " +
      "the features that purpose provides, so nothing was changed. Change the " +
      "purpose in the TrueNAS UI first if that is what you want.",
  );
}

/**
 * The `sharing.smb.update` payload that sets a share's host lists, and the purpose the
 * share ends up on. Throws, before anything is sent, when host rules can't be applied.
 *
 * A DEFAULT_SHARE that gets host rules moves to the preset-free purpose (NO_PRESET on
 * 25.04, LEGACY_SHARE on 25.10), which renders the same share. Any other purpose that
 * holds no host lists is refused, as moving it would drop what it is for (Veeam's
 * `block size`, Time Machine, WORM, per-user datasets).
 *
 * 25.04: the update patches top-level lists. DEFAULT_SHARE and VEEAM_REPOSITORY_SHARE
 * re-apply empty lists on every update, discarding any allowlist without an error.
 *
 * 25.10: the lists sit in `options`, only for purposes that have them (LEGACY_SHARE on
 * 25.10.0, most from 25.10.1). The update needs `purpose` with `options` and replaces
 * the whole `options`, defaulting unsent fields, so the existing options are merged.
 */
function smbAccessUpdate(
  share: Record<string, unknown>,
  allow: string[],
  deny: string[],
): { purpose: string; payload: Record<string, unknown> } {
  const purpose = String(share.purpose ?? "");
  const wantHostRules = allow.length > 0 || deny.length > 0;

  if (share.options === undefined) {
    // 25.04. Clearing rules needs no purpose change.
    if (wantHostRules && purpose === "DEFAULT_SHARE") {
      return {
        purpose: "NO_PRESET",
        payload: { hostsallow: allow, hostsdeny: deny, purpose: "NO_PRESET" },
      };
    }
    if (wantHostRules && purpose === "VEEAM_REPOSITORY_SHARE") {
      throw cannotHoldHostRules(share.name, purpose);
    }
    return { purpose, payload: { hostsallow: allow, hostsdeny: deny } };
  }

  const options = asObj(share.options);
  if ("hostsallow" in options) {
    return {
      purpose,
      payload: {
        purpose,
        options: { ...options, hostsallow: allow, hostsdeny: deny },
      },
    };
  }
  // This purpose holds no host lists, so there are none to clear.
  if (!wantHostRules) return { purpose, payload: {} };
  if (purpose === "DEFAULT_SHARE") {
    return {
      purpose: "LEGACY_SHARE",
      payload: {
        purpose: "LEGACY_SHARE",
        options: {
          aapl_name_mangling: options.aapl_name_mangling ?? false,
          hostsallow: allow,
          hostsdeny: deny,
        },
      },
    };
  }
  throw cannotHoldHostRules(share.name, purpose);
}

// ─────────────────────────── transport seam ───────────────────────────

/** A loosely typed JSON object; structurally the resolved global args. */
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
 * loosely as {@link Json} so this exported seam stays "fast-check" clean (a
 * zod-inferred arg type would put a slow type on the public API).
 */
export type SessionFactory = (g: Json) => Promise<RpcSession>;

let _sessionOverride: SessionFactory | null = null;

/** Test-only seam: substitute the session transport. Pass `null` to restore the real one. */
export function __setTruenasSession(fn: SessionFactory | null): void {
  _sessionOverride = fn;
}

/**
 * The API path a bare host or `https://host` resolves to: the server's own newest API
 * version, so the model reads the schema the server actually stores.
 */
const DEFAULT_API_PATH = "/api/current";

/**
 * Build the `wss://<host>/api/current` URL from an operator endpoint. Accepts a bare
 * host, `wss://…`, or `https://…` (upgraded to `wss`). **Throws** on `ws://`/`http://`
 * or any other scheme, because TrueNAS revokes an API key sent over a non-TLS transport.
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
        "API key sent over cleartext — use wss:// (or https://), never ws:// or http://",
    );
  }
  if (u.pathname === "/" || u.pathname === "") u.pathname = DEFAULT_API_PATH;
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

/**
 * The error for a socket that never opened. The WebSocket API reports no cause, and a
 * certificate the host name does not match (TrueNAS ships a self-signed one) is the
 * likeliest when the host is up, so say so.
 */
function connectionFailed(): Error {
  return new Error(
    "TrueNAS WebSocket connection failed. If the host is up, check that its TLS " +
      "certificate is valid for this host name (see the README's TLS note), and " +
      "that the NAS serves the endpoint's API path (a bare host uses /api/current).",
  );
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
  #rejectReady: (e: Error) => void = () => {};
  readonly #secret: string;
  readonly ready: Promise<void>;

  constructor(url: string, secret: string) {
    this.#secret = secret;
    this.#ws = new WebSocket(url);
    this.ready = new Promise((resolve, reject) => {
      this.#rejectReady = reject;
      this.#ws.onopen = () => resolve();
      this.#ws.onerror = () => reject(connectionFailed());
    });
    this.#ws.onmessage = (ev) => this.#onMessage(ev);
    this.#ws.onclose = () => this.#fail(new Error("TrueNAS WebSocket closed"));
  }

  #onMessage(ev: MessageEvent): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(typeof ev.data === "string" ? ev.data : "");
    } catch {
      return; // ignore non-JSON job-progress messages
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
    // A socket can close before it opens without an error event; without this the
    // connection would wait out the full timeout. A no-op once `ready` has resolved.
    this.#rejectReady(connectionFailed());
    for (const waiter of this.#pending.values()) waiter.reject(err);
    this.#pending.clear();
  }

  /**
   * Issue one call, rejected after `timeoutMs`. A timed-out call is also dropped from
   * the pending map, so a late reply is ignored and the map does not grow over a
   * long session.
   */
  call(
    method: string,
    params: unknown[],
    timeoutMs: number,
    label = `call ${method}`,
  ): Promise<unknown> {
    if (this.#closed) return Promise.reject(this.#closed);
    const id = this.#nextId++;
    const frame = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`TrueNAS ${label} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.#pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      try {
        this.#ws.send(frame);
      } catch (err) {
        clearTimeout(timer);
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
    const authed = await sock.call(
      "auth.login_with_api_key",
      [secret],
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
        return await sock.call(method, params, timeoutMs);
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
 * Appended when a change call's outcome is unknown: TrueNAS carries on after a
 * timeout or a dropped socket, so a caller must not assume nothing changed.
 */
const MAY_YET_APPLY =
  "The change may yet apply: re-read the target before retrying or reverting.";

/**
 * Make one call that changes state. A JSON-RPC error is passed on as it is: usually
 * TrueNAS refusing the change, though a failure after its database write (a service
 * reload, say) also answers this way. Any other failure (a timeout, a closed socket)
 * leaves the outcome unknown, so the error says the change may yet apply.
 */
async function callChange(
  session: RpcSession,
  method: string,
  params: unknown[],
): Promise<unknown> {
  try {
    return await session.call(method, params);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("JSON-RPC error")) throw err;
    throw new Error(`${method}: ${message}. ${MAY_YET_APPLY}`);
  }
}

/**
 * Submit a job-returning RPC (such as `app.update`) and wait for it to finish by
 * polling `core.get_jobs`. Returns the job's `result`; throws (with the job error) on
 * a FAILED/ABORTED terminal state or if the wait times out. A timed-out job keeps
 * running on TrueNAS.
 */
async function callJob(
  session: RpcSession,
  method: string,
  params: unknown[],
  timeoutMs: number,
): Promise<unknown> {
  const jobIdRaw = await callChange(session, method, params);
  const jobId = asNum(jobIdRaw);
  if (jobId === undefined) {
    throw new Error(
      `${method} did not return a job id (got ${JSON.stringify(jobIdRaw)})`,
    );
  }
  const deadline = Date.now() + timeoutMs;
  // Poll until terminal. Interval is short; the per-call timeout still bounds each poll.
  while (true) {
    let jobsRaw: unknown;
    try {
      jobsRaw = await session.call("core.get_jobs", [[["id", "=", jobId]]]);
    } catch (err) {
      // The job was submitted, so any poll failure leaves its outcome unknown.
      throw new Error(
        `${method} job ${jobId}: polling failed (${
          err instanceof Error ? err.message : String(err)
        }). ${MAY_YET_APPLY}`,
      );
    }
    const jobs = asArr(jobsRaw);
    if (jobs.length === 0) {
      throw new Error(`${method} job ${jobId} not found in core.get_jobs`);
    }
    const job = asObj(jobs[0]);
    const state = String(job.state ?? "");
    if (JOB_DONE.has(state)) {
      if (state !== "SUCCESS") {
        // `error` carries the reason (for a validation failure, each field and
        // why); `exc_info.type` is only the class, e.g. VALIDATION.
        const excInfo = asObj(job.exc_info);
        const reason = asStr(job.error) ?? asStr(excInfo.repr) ?? state;
        const type = asStr(excInfo.type);
        throw new Error(
          `${method} job ${jobId} ${state}: ${
            type ? `${type}: ${reason}` : reason
          }`,
        );
      }
      return job.result;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `${method} job ${jobId} did not finish within ${timeoutMs}ms ` +
          `(state=${state}). The job is still running on TrueNAS. ${MAY_YET_APPLY}`,
      );
    }
    await new Promise((r) => setTimeout(r, 750));
  }
}

// ─────────────────────────── shaping ───────────────────────────

/**
 * Whether a published port listens on every interface. The apps library binds
 * an empty host_ips list to ["0.0.0.0", "::"] (truenas/apps
 * library/<v>/container.py add_port), and "::" alone covers every IPv6
 * interface, so all three count.
 */
function bindsAllInterfaces(hostIps: string[]): boolean {
  return hostIps.length === 0 || hostIps.includes("0.0.0.0") ||
    hostIps.includes("::");
}

function shapePortBinding(
  portKey: string,
  p: Record<string, unknown>,
): z.infer<typeof PortBinding> {
  const hostIps = strArr(p.host_ips);
  const bindMode = String(p.bind_mode);
  const published = bindMode === "published";
  return {
    portKey,
    portNumber: asNum(p.port_number) ?? 0,
    protocol: String(p.protocol ?? "tcp"),
    bindMode,
    hostIps,
    published,
    exposedToAll: published && bindsAllInterfaces(hostIps),
  };
}

/**
 * Port bindings in both config forms: catalog apps key each port object under
 * config.network, custom (ix-app) apps keep an unkeyed config.ports list.
 */
function shapePortBindings(
  config: Record<string, unknown>,
): z.infer<typeof PortBinding>[] {
  const out: z.infer<typeof PortBinding>[] = [];
  for (const [key, val] of Object.entries(asObj(config.network))) {
    const p = asObj(val);
    // A port object has port_number + bind_mode; skip scalars like host_network/networks.
    if (p.port_number === undefined || p.bind_mode === undefined) continue;
    out.push(shapePortBinding(key, p));
  }
  asArr(config.ports).forEach((val, i) => {
    const p = asObj(val);
    if (p.port_number === undefined || p.bind_mode === undefined) return;
    out.push(shapePortBinding(`ports[${i}]`, p));
  });
  return out.sort((a, b) => a.portNumber - b.portNumber);
}

function shapeApp(raw: unknown, ts: string): z.infer<typeof AppInfo> {
  const a = asObj(raw);
  const config = asObj(a.config);
  return {
    name: String(a.name ?? ""),
    state: String(a.state ?? "UNKNOWN"),
    customApp: asBool(a.custom_app),
    version: asStr(a.version),
    humanVersion: asStr(a.human_version),
    hostNetwork: asBool(asObj(config.network).host_network) ||
      asBool(config.host_network),
    portBindings: shapePortBindings(config),
    action: "observed",
    timestamp: ts,
  };
}

/**
 * Entries that admit every client. TrueNAS treats empty lists as `0.0.0.0/0` plus
 * `::/0`, and a `*` host as "everybody" (middleware plugins/nfs.py), so a share
 * listing one of these is as open as one with no restriction at all.
 */
const NFS_OPEN_NETWORKS = new Set(["0.0.0.0/0", "::/0"]);

function shapeNfs(raw: unknown, ts: string): z.infer<typeof NfsShare> {
  const s = asObj(raw);
  const networks = strArr(s.networks);
  const hosts = strArr(s.hosts);
  // An export admits a client that matches any entry, so one open entry opens it.
  const unrestricted = (networks.length === 0 && hosts.length === 0) ||
    networks.some((n) => NFS_OPEN_NETWORKS.has(n)) || hosts.includes("*");
  return {
    id: asNum(s.id) ?? 0,
    path: String(s.path ?? ""),
    comment: asStr(s.comment),
    enabled: asBool(s.enabled),
    ro: asBool(s.ro),
    networks,
    hosts,
    unrestricted,
    action: "observed",
    timestamp: ts,
  };
}

function shapeSmb(raw: unknown, ts: string): z.infer<typeof SmbShare> {
  const s = asObj(raw);
  const hosts = smbHostLists(s);
  return {
    id: asNum(s.id) ?? 0,
    name: String(s.name ?? ""),
    path: String(s.path ?? ""),
    comment: asStr(s.comment),
    enabled: asBool(s.enabled),
    ro: asBool(s.readonly ?? s.ro),
    hostsallow: hosts.allow,
    hostsdeny: hosts.deny,
    purpose: String(s.purpose ?? ""),
    unrestricted: hosts.allow.length === 0,
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

function shapeDirEntry(raw: unknown): z.infer<typeof DirEntry> {
  const e = asObj(raw);
  return {
    name: String(e.name ?? ""),
    type: String(e.type ?? "OTHER"),
    size: nullableNum(e.size),
    isMountpoint: asBool(e.is_mountpoint),
  };
}

/**
 * Collect every host-path bind in an app's config. Catalog apps place these
 * differently (`storage.data`, `storage.additional_storage[]`, per-app keys…), so
 * this walks the config for the shape TrueNAS always uses (an object with a
 * `host_path_config.path`, or `type: "host_path"` + `path`) rather than assuming
 * one layout. `configPath` records where each was found.
 */
function collectHostPaths(
  config: unknown,
  breadcrumb: string,
  out: z.infer<typeof HostPathMount>[],
): void {
  if (Array.isArray(config)) {
    config.forEach((v, i) => collectHostPaths(v, `${breadcrumb}[${i}]`, out));
    return;
  }
  if (!config || typeof config !== "object") return;
  const o = config as Record<string, unknown>;
  const hpc = asObj(o.host_path_config);
  const hostPath = asStr(hpc.path) ??
    (String(o.type ?? "") === "host_path" ? asStr(o.path) : undefined);
  if (hostPath) {
    out.push({
      configPath: breadcrumb || "config",
      mountPath: asStr(o.mount_path) ?? "",
      hostPath,
      readOnly: asBool(o.read_only) || asBool(hpc.read_only),
    });
  }
  for (const [k, v] of Object.entries(o)) {
    if (k === "host_path_config") continue;
    collectHostPaths(v, breadcrumb ? `${breadcrumb}.${k}` : k, out);
  }
}

/**
 * TrueNAS timestamps arrive either as an ISO string or as `{"$date": <epoch ms>}`.
 * Normalise to ISO; undefined when neither form is present.
 */
function isoDate(v: unknown): string | undefined {
  if (v === null || v === undefined) return undefined;
  if (typeof v === "string") return v;
  const epoch = asNum(asObj(v).$date);
  return epoch === undefined ? undefined : new Date(epoch).toISOString();
}

function shapeReplication(
  raw: unknown,
  ts: string,
): z.infer<typeof ReplicationTask> {
  const r = asObj(raw);
  const sched = asObj(r.schedule);
  const state = asObj(r.state);
  const scheduleStr = r.schedule
    ? [sched.minute, sched.hour, sched.dom, sched.month, sched.dow]
      .map((f) => String(f ?? "*")).join(" ")
    : undefined;
  return {
    id: asNum(r.id) ?? 0,
    name: String(r.name ?? ""),
    direction: String(r.direction ?? ""),
    transport: String(r.transport ?? ""),
    enabled: asBool(r.enabled),
    auto: asBool(r.auto),
    recursive: asBool(r.recursive),
    sourceDatasets: strArr(r.source_datasets),
    targetDataset: String(r.target_dataset ?? ""),
    schedule: scheduleStr,
    readonlyPolicy: asStr(r.readonly),
    sendsProperties: asBool(r.properties),
    state: asStr(state.state),
    lastRunAt: isoDate(state.datetime),
    lastError: asStr(state.error),
    action: "observed",
    timestamp: ts,
  };
}

/**
 * The data name for a record: `<spec>` for one record per model, `<spec>:<key>`
 * for a keyed one. swamp keys stored data by model + name, not by spec, so the
 * spec has to be in the name or two specs overwrite each other.
 *
 * swamp rejects `/`, `\`, `..` and NUL in a name. A path can hold all of them,
 * and any other character too (`:`, `-` and `%` included), so no plain
 * substitution is safe. Instead they are percent-escaped, and `%` itself is
 * escaped first: every `%` in the result then starts an escape, so the name
 * decodes back to exactly one key and two keys never share a name.
 * `/mnt/Backup` becomes `dir-listing:%2Fmnt%2FBackup`.
 */
function dataName(spec: string, key?: string | number): string {
  if (key === undefined) return spec;
  const safe = String(key)
    .replaceAll("%", "%25")
    .replaceAll("/", "%2F")
    .replaceAll("\\", "%5C")
    .replaceAll("\0", "%00")
    .replaceAll("..", ".%2E");
  return `${spec}:${safe}`;
}

// ─────────────────────────── method argument schemas ───────────────────────────

const Empty = z.object({});

const AppSetPortBindArgs = z.object({
  app: z.string().describe("App name (from app_list)"),
  portKey: z.string().optional().describe(
    'Port config key, e.g. "ldap_port", "admin_port" (preferred; from app_list ' +
      'portBindings). A custom app\'s list-form port ("ports[<i>]" in app_list) ' +
      "has no key: select it by portNumber.",
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

const FilesystemListArgs = z.object({
  // `--input path='["/a","/b"]'` arrives as a string (the CLI only decodes JSON for
  // a declared array type, and this field also accepts a bare path). Decode a
  // leading-`[` string here, or the whole JSON string is listed as one path name.
  path: z.preprocess((v) => {
    if (typeof v === "string" && v.trimStart().startsWith("[")) {
      try {
        return JSON.parse(v);
      } catch { /* not JSON after all — treat it as a literal path */ }
    }
    return v;
  }, z.union([z.string(), z.array(z.string())])).describe(
    "Absolute path to list, e.g. /mnt/Backup, or a JSON list of paths to list in " +
      'one run, e.g. \'["/mnt/Backup","/mnt/Backup/apps"]\' (host paths, not ' +
      "container paths)",
  ),
  // 0 is allowed: it records whether the path exists without its entries.
  maxEntries: z.coerce.number().int().nonnegative().default(500).describe(
    "Cap on entries recorded (a media dataset can hold thousands); 0 records " +
      "only whether the path exists",
  ),
});

const AppStorageArgs = z.object({
  app: z.string().optional().describe(
    "App name (from app_list). Omit to report every app's host-path binds.",
  ),
});

const AppSetNetworksArgs = z.object({
  app: z.string().describe("App name (from app_list)"),
  networks: z.array(z.string()).describe(
    "The complete desired set of docker network names to attach the app to (e.g. " +
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
    'Authorized networks in CIDR, e.g. ["192.0.2.161/32"]. Empty array clears ' +
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

/**
 * Refuse an app installed from compose YAML (`custom_app: true`). Its `app.update`
 * takes a whole compose file and ignores `values` (middleware plugins/apps/crud.py
 * `update_internal`), so the value edits the app methods make cannot apply and the
 * job would fail with a confusing "custom_compose_config required". The UI's
 * "Custom App" is not one of these: it is the `ix-app` catalog app and takes values.
 */
function refuseComposeApp(app: Record<string, unknown>, method: string): void {
  if (app.custom_app !== true) return;
  throw new Error(
    `app ${JSON.stringify(app.name)} was installed from compose YAML ` +
      `(custom_app), which ${method} cannot edit: such an app takes a whole ` +
      "compose file on update. Nothing was changed.",
  );
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
 * delete path). Still throws on an ambiguous selector, because it cannot tell which
 * of several matches to delete.
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
 * delete path). Still throws on an ambiguous selector.
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
 * shares, services, and network exposure, plus a few mutating methods. See the module
 * header for scope and the transport-safety guarantee.
 */
export const model = {
  type: "@thomas/truenas",
  version: "2026.10.11.1",
  globalArguments: GlobalArgs,
  upgrades: [
    {
      toVersion: "2026.10.11.1",
      description:
        "insecureSkipTlsVerify is removed; the certificate is always validated. timeoutMs must now be positive; a zero or negative value is dropped so the 30000 ms default applies. Stored data is renamed to <spec>:<key> (or <spec>); records under the old names are left as they are and are not migrated. Several methods change behaviour; see the README's Breaking changes.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => {
        // It never worked: Deno cannot skip certificate checks per connection.
        const { insecureSkipTlsVerify: _, ...rest } = old;
        // Zero or negative used to mean 30000 silently, so dropping it keeps that.
        if (Number(rest.timeoutMs) <= 0) {
          const { timeoutMs: _t, ...withoutTimeout } = rest;
          return withoutTimeout;
        }
        return rest;
      },
    },
  ],
  checks: {
    "reachable": {
      description:
        "Verify the TrueNAS API authenticates (wss login + system.info)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        // Checks get globalArgs without the schema's defaults; parse to apply them.
        const parsed = GlobalArgs.safeParse(context.globalArgs);
        if (!parsed.success) {
          return { pass: false, errors: [z.prettifyError(parsed.error)] };
        }
        const g = parsed.data;
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
    // Observations of apps and shares expire after an hour, like `service`: nothing
    // deletes the record of an app or share that is gone, so a longer-lived one would
    // go on reporting it as live.
    "app": {
      description: "An installed app with its published/exposed port bindings",
      schema: AppInfo,
      lifetime: "1h",
      garbageCollection: 10,
    },
    "nfs-share": {
      description: "An NFS export with its networks/hosts allowlist",
      schema: NfsShare,
      lifetime: "1h",
      garbageCollection: 10,
    },
    "smb-share": {
      description: "An SMB share with its hostsallow/hostsdeny",
      schema: SmbShare,
      lifetime: "1h",
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
    "dir-listing": {
      description: "One directory's entries (existence + children)",
      schema: DirListing,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "app-storage": {
      description: "An app's host-path binds (container path ← NAS path)",
      schema: AppStorage,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "replication-task": {
      description:
        "A replication task (source/target datasets, schedule, last run)",
      schema: ReplicationTask,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "exposure-audit": {
      description: "Exposure roll-up across apps and NFS/SMB shares",
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
          const handle = await context.writeResource(
            "system-info",
            dataName("system-info"),
            {
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
            },
          );
          logInfo(context, "Recorded system info");
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
              await context.writeResource(
                "app",
                dataName("app", shaped.name),
                shaped,
              ),
            );
          }
          logInfo(context, "Recorded apps", { count: handles.length });
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
                dataName("nfs-share", shaped.id),
                shaped,
              ),
            );
          }
          logInfo(context, "Recorded NFS shares", { count: handles.length });
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
                dataName("smb-share", shaped.id),
                shaped,
              ),
            );
          }
          logInfo(context, "Recorded SMB shares", { count: handles.length });
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
              await context.writeResource(
                "service",
                dataName("service", shaped.service),
                shaped,
              ),
            );
          }
          logInfo(context, "Recorded services", { count: handles.length });
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
          // ip_in_use does not say which interface holds an address, so look
          // it up in the interface list.
          const interfaceOf = new Map(
            interfaces.flatMap((i) => i.addresses.map((a) => [a, i.name])),
          );
          const bindableIps = inUse.map((r) => {
            const o = asObj(r);
            const address = String(o.address ?? "");
            return {
              address,
              netmask: nullableNum(o.netmask),
              interface: interfaceOf.get(address),
            };
          });
          const handle = await context.writeResource(
            "network-info",
            dataName("network-info"),
            {
              bindableIps,
              interfaces,
              guiAddresses: strArr(general.ui_address),
              action: "observed",
              timestamp: ts,
            },
          );
          logInfo(context, "Recorded network info", {
            bindableIps: bindableIps.length,
            interfaces: interfaces.length,
          });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    filesystem_list: {
      description:
        "List directories on the NAS (`filesystem.listdir`) — entries with type/size " +
        "and a mountpoint flag (a child dataset). Read-only. Takes one path or a list " +
        "of paths and writes one `dir-listing` each (fan-out: one session, one model " +
        "lock). A path that is absent records exists=false instead of failing, so this " +
        'answers "does this backup/app source path still exist?" in one call.',
      arguments: FilesystemListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const a = FilesystemListArgs.parse(rawArgs);
        // Deduplicated: a path listed twice would write the same data name twice.
        const paths = [...new Set(Array.isArray(a.path) ? a.path : [a.path])];
        const session = await openSession(g);
        try {
          const handles: DataHandle[] = [];
          for (const path of paths) {
            logInfo(context, "Listing directory", { path });
            const ts = new Date().toISOString();
            let rows: unknown[];
            try {
              rows = asArr(await session.call("filesystem.listdir", [path]));
            } catch (e) {
              // ENOENT / ENOTDIR is a valid result here, not a failure.
              const message = (e as Error).message;
              if (
                !/ENOENT|ENOTDIR|does not exist|not a directory/i.test(message)
              ) {
                throw e;
              }
              handles.push(
                await context.writeResource(
                  "dir-listing",
                  dataName("dir-listing", path),
                  {
                    path,
                    exists: false,
                    entryCount: 0,
                    truncated: false,
                    entries: [],
                    error: message,
                    action: "observed",
                    timestamp: ts,
                  },
                ),
              );
              continue;
            }
            // Sort before truncating, so the entries kept under maxEntries are
            // deterministic rather than dependent on listdir order.
            const all = rows.map(shapeDirEntry)
              .sort((x, y) => x.name.localeCompare(y.name));
            const entries = all.slice(0, a.maxEntries);
            handles.push(
              await context.writeResource(
                "dir-listing",
                dataName("dir-listing", path),
                {
                  path,
                  exists: true,
                  entryCount: entries.length,
                  truncated: all.length > entries.length,
                  entries,
                  action: "observed",
                  timestamp: ts,
                },
              ),
            );
          }
          logInfo(context, "Recorded directory listings", {
            count: handles.length,
          });
          return { dataHandles: handles };
        } finally {
          session.close();
        }
      },
    },

    app_storage: {
      description:
        "List an app's host-path binds — container mount path ← NAS path, plus where " +
        "each sits in the app config (factory: one `app-storage` per app; omit `app` " +
        "for all apps). Read-only. Shows whether an app mounts one parent directory or " +
        "each source individually — the difference that decides whether child datasets " +
        "mounted under it are visible inside the container.",
      arguments: AppStorageArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const a = AppStorageArgs.parse(rawArgs);
        const session = await openSession(g);
        try {
          logInfo(context, "Querying app storage", { app: a.app ?? "(all)" });
          const filter = a.app ? [["name", "=", a.app]] : [];
          const apps = asArr(
            await session.call("app.query", [filter, {
              extra: { retrieve_config: true },
            }]),
          );
          if (a.app && apps.length === 0) {
            throw new Error(`app ${JSON.stringify(a.app)} not found`);
          }
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const raw of apps) {
            const app = asObj(raw);
            const name = String(app.name ?? "");
            if (!name) continue;
            const mounts: z.infer<typeof HostPathMount>[] = [];
            collectHostPaths(app.config, "", mounts);
            mounts.sort((x, y) => x.mountPath.localeCompare(y.mountPath));
            handles.push(
              await context.writeResource(
                "app-storage",
                dataName("app-storage", name),
                {
                  app: name,
                  mountCount: mounts.length,
                  mounts,
                  action: "observed",
                  timestamp: ts,
                },
              ),
            );
          }
          logInfo(context, "Recorded app storage", { count: handles.length });
          return { dataHandles: handles };
        } finally {
          session.close();
        }
      },
    },

    replication_list: {
      description:
        "List replication tasks with their source/target datasets, recursive flag, " +
        "schedule, readonly + send-properties policy, and last-run state (factory: one " +
        "`replication-task` each). Read-only — it never creates, edits, or runs a task. " +
        "Answers which task writes into a destination dataset and when (a receive can " +
        "remount the destination, which invalidates a container's bind mount of it).",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const session = await openSession(g);
        try {
          logInfo(context, "Querying replication tasks");
          const rows = asArr(await session.call("replication.query", [[]]));
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const raw of rows) {
            const shaped = shapeReplication(raw, ts);
            handles.push(
              await context.writeResource(
                "replication-task",
                dataName("replication-task", shaped.id),
                shaped,
              ),
            );
          }
          logInfo(context, "Recorded replication tasks", {
            count: handles.length,
          });
          return { dataHandles: handles };
        } finally {
          session.close();
        }
      },
    },

    exposure_audit: {
      description:
        "Roll up exposure across apps and NFS/SMB shares into one report (published " +
        "app ports, host-network apps, unrestricted shares, all-interface binds, " +
        "plaintext-LDAP flag). Read-only. System services (SSH, SMB, NFS, the web " +
        "UI) are not covered: use service_list.",
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
          const hostNetworkApps: string[] = [];
          const portsOnAll = new Set<number>();
          let plaintextLdap = false;
          for (const raw of apps) {
            const shaped = shapeApp(raw, ts);
            if (shaped.hostNetwork) hostNetworkApps.push(shaped.name);
            for (const pb of shaped.portBindings) {
              if (!pb.published) continue;
              publishedPorts.push({
                source: `app:${shaped.name}`,
                portNumber: pb.portNumber,
                protocol: pb.protocol,
                hostIps: pb.hostIps,
                detail: pb.portKey,
              });
              if (pb.exposedToAll) portsOnAll.add(pb.portNumber);
              if (pb.portNumber === 389) plaintextLdap = true;
            }
          }
          publishedPorts.sort((a, b) => a.portNumber - b.portNumber);

          const unrestrictedNfs = nfs.map((r) => shapeNfs(r, ts))
            .filter((s) => s.enabled && s.unrestricted).map((s) => s.path);
          const unrestrictedSmb = smb.map((r) => shapeSmb(r, ts))
            .filter((s) => s.enabled && s.unrestricted).map((s) => s.name);
          const nonWildcard = inUse
            .map((r) => String(asObj(r).address ?? ""))
            .filter((a) => a && a !== "0.0.0.0");

          const handle = await context.writeResource(
            "exposure-audit",
            dataName("exposure-audit"),
            {
              hostname: String(info.hostname ?? "unknown"),
              version: String(info.version ?? "unknown"),
              publishedPorts,
              hostNetworkApps: hostNetworkApps.sort(),
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
            },
          );
          logInfo(context, "Recorded exposure audit", {
            publishedPorts: publishedPorts.length,
            unrestrictedNfsShares: unrestrictedNfs.length,
            unrestrictedSmbShares: unrestrictedSmb.length,
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
        "A portNumber that matches more than one port is refused, as is an app " +
        "installed from compose YAML. Reversible: re-run with the prior " +
        "bindMode/hostIps.",
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
          refuseComposeApp(app, "app_set_port_bind");
          const cfg = asObj(app.config);

          // Some apps store ports as a list (config.ports: [{port_number,bind_mode,
          // host_ips,…}]) instead of the keyed config.network map (e.g. kopia, custom
          // apps). That form is handled in its own branch; list entries have no key,
          // so they're selected by portNumber.
          const portsList = asArr(cfg.ports).map((p) => asObj(p));
          const inNetworkMap = a.portKey
            ? asObj(cfg.network)[a.portKey] !== undefined
            : Object.values(asObj(cfg.network)).some(
              (v) => asNum(asObj(v).port_number) === a.portNumber,
            );
          if (portsList.length > 0 && !inNetworkMap) {
            // A portKey names no list entry (they have none), so one given here
            // matched nothing. Refuse rather than drop it and act on the number.
            if (a.portKey) {
              throw new Error(
                `portKey ${JSON.stringify(a.portKey)} is not a key of ` +
                  `config.network on ${a.app}. Its config.ports list entries ` +
                  "have no key: select one by portNumber alone.",
              );
            }
            const matches = portsList.filter((p) =>
              asNum(p.port_number) === a.portNumber
            );
            // The list can hold one number twice (say tcp and udp); changing only
            // the first would be a guess.
            if (matches.length > 1) {
              throw new Error(
                `portNumber ${a.portNumber} matches ${matches.length} entries in ` +
                  `config.ports of ${a.app}, so the port to change is ambiguous.`,
              );
            }
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
                dataName("app-port-result", `${a.app}:${pkLabel}`),
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
              logInfo(
                context,
                "Port binding already at desired state — no change",
                { app: a.app, portKey: pkLabel },
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
              dataName("app-port-result", `${a.app}:${pkLabel}`),
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
            logInfo(context, "App port binding updated", {
              app: a.app,
              portKey: pkLabel,
            });
            return { dataHandles: [handle] };
          }

          const network = asObj(cfg.network);
          // Locate the target port object in config.network.
          let portKey = a.portKey;
          if (!portKey) {
            const keys = Object.entries(network)
              .filter(([_, v]) => asNum(asObj(v).port_number) === a.portNumber)
              .map(([k]) => k);
            if (keys.length > 1) {
              throw new Error(
                `portNumber ${a.portNumber} matches ${keys.length} ports on ` +
                  `${a.app} (${keys.join(", ")}): select one by portKey.`,
              );
            }
            portKey = keys[0];
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

          // Reconstruct the full port object so no field (port_number,
          // certificate_id, …) is dropped, then send the entire network map with only
          // this port changed. Sending the whole `network` avoids depending on how
          // app.update merges nested values, so sibling ports (http_port, ldaps_port)
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
              dataName("app-port-result", `${a.app}:${portKey}`),
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
            dataName("app-port-result", `${a.app}:${portKey}`),
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
          logInfo(context, "App port binding updated", { app: a.app, portKey });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    app_set_networks: {
      description:
        "Attach a custom app to a set of docker networks (e.g. join a reverse-proxy " +
        "app to other apps' `ix-<app>_default` bridges so it can reach them by service " +
        "name without host-published ports). Custom apps only: an app with no " +
        "top-level `networks` list in its config (a catalog app) or one installed " +
        "from compose YAML is refused and nothing is written. Verifies the app first; preserves the config of " +
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
          refuseComposeApp(app, "app_set_networks");
          const cfg = asObj(app.config);
          // Only custom (ix-app) apps keep a top-level `networks` list. Catalog apps
          // keep theirs at `network.networks` with per-container entries; writing a
          // top-level list to one is accepted and stored but joins nothing, so refuse
          // before any update is sent.
          if (!Array.isArray(cfg.networks)) {
            throw new Error(
              `app ${
                JSON.stringify(a.app)
              } has no top-level networks list in its config, so it is not a ` +
                "custom app: app_set_networks supports custom apps only (catalog " +
                "apps keep networks under network.networks). Nothing was changed.",
            );
          }
          const current = asArr(cfg.networks).map((n) => asObj(n));
          const prevNames = current.map((n) => String(n.name));
          const ts = new Date().toISOString();

          if (sameStrArr(a.networks, prevNames)) {
            const handle = await context.writeResource(
              "app-networks-result",
              dataName("app-networks-result", a.app),
              {
                app: a.app,
                previousNetworks: prevNames,
                networks: prevNames,
                action: "unchanged",
                timestamp: ts,
              },
            );
            logInfo(
              context,
              "App networks already at desired set — no change",
              {
                app: a.app,
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
            dataName("app-networks-result", a.app),
            {
              app: a.app,
              previousNetworks: prevNames,
              networks: after,
              action: "updated",
              timestamp: ts,
            },
          );
          logInfo(context, "App networks updated", {
            app: a.app,
            networks: after,
          });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    nfs_share_set_access: {
      description:
        "Set an NFS export's authorized networks/hosts allowlist (the per-client " +
        "gate). Verifies the share first. An empty array clears that restriction. " +
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
              dataName("nfs-share-result", id),
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
            logInfo(
              context,
              "NFS share access already at desired state — no change",
              {
                id,
              },
            );
            return { dataHandles: [handle] };
          }

          logInfo(context, "Updating NFS share access", {
            id,
            path: share.path,
          });
          await callChange(session, "sharing.nfs.update", [id, {
            networks: newNetworks,
            hosts: newHosts,
          }]);
          const after = await resolveNfs(session, { id });
          const handle = await context.writeResource(
            "nfs-share-result",
            dataName("nfs-share-result", id),
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
          logInfo(context, "NFS share access updated", { id });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    nfs_share_delete: {
      description:
        "Delete an NFS export rule (e.g. a now-unused share). Verifies the share " +
        "first and records its removed config (path/networks/hosts) so it can be " +
        "re-created. Idempotent: a share that's already gone records action=absent " +
        "instead of failing. Removes only the export rule — the underlying " +
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
            // Already gone: idempotent success. The confirmPath guard only
            // protects against deleting the wrong existing share, so it doesn't
            // apply when there's nothing to delete.
            const ats = new Date().toISOString();
            // Named `absent:<selector>`, never the deleted record's `<id>`, so a
            // rerun after a delete leaves the removed config as `data.latest`. A path
            // is tagged `path:` so it can never take the name of a share id.
            const handle = await context.writeResource(
              "nfs-share-result",
              dataName(
                "nfs-share-result",
                "absent:" + (a.id ?? `path:${a.path ?? ""}`),
              ),
              {
                // null, not 0: there is no share, and 0 reads like a real id.
                id: a.id ?? null,
                path: a.path ?? "",
                previousNetworks: [],
                previousHosts: [],
                networks: [],
                hosts: [],
                action: "absent",
                timestamp: ats,
              },
            );
            logInfo(context, "NFS share already absent — nothing to delete", {
              selector: a.id ?? a.path,
            });
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
          await callChange(session, "sharing.nfs.delete", [id]);

          // The removed config is captured in previous* so the export can be re-created.
          const handle = await context.writeResource(
            "nfs-share-result",
            dataName("nfs-share-result", id),
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
          logInfo(context, "NFS export deleted", { id, path });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    smb_share_set_access: {
      description:
        "Set an SMB share's hostsallow/hostsdeny. Verifies the share first. An empty " +
        "hostsallow clears the allowlist. Re-running with the prior values restores " +
        "them, but not the purpose preset: a DEFAULT_SHARE moves to NO_PRESET on " +
        "25.04 or LEGACY_SHARE on 25.10 when host rules are applied, and stays " +
        "there. Any other purpose that holds no host lists (VEEAM_REPOSITORY_SHARE " +
        "on 25.04) is refused, as moving it would drop its features. The result " +
        "records previousPurpose.",
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
          const prev = smbHostLists(share);
          const prevAllow = prev.allow;
          const prevDeny = prev.deny;
          const prevPurpose = String(share.purpose ?? "");
          const newAllow = a.hostsallow ?? prevAllow;
          const newDeny = a.hostsdeny ?? prevDeny;
          const ts = new Date().toISOString();

          // Throws, before any write, for a purpose that can't hold host rules.
          // An empty payload (no lists to clear) is caught by the no-op check below.
          const { purpose: newPurpose, payload } = smbAccessUpdate(
            share,
            newAllow,
            newDeny,
          );

          if (
            sameStrArr(newAllow, prevAllow) && sameStrArr(newDeny, prevDeny) &&
            newPurpose === prevPurpose
          ) {
            const handle = await context.writeResource(
              "smb-share-result",
              dataName("smb-share-result", id),
              {
                id,
                name: String(share.name ?? ""),
                path: String(share.path ?? ""),
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
            logInfo(
              context,
              "SMB share access already at desired state — no change",
              {
                id,
              },
            );
            return { dataHandles: [handle] };
          }

          logInfo(context, "Updating SMB share access", {
            id,
            name: share.name,
            purpose: newPurpose,
          });
          await callChange(session, "sharing.smb.update", [id, payload]);
          const after = await resolveSmb(session, { id });
          const afterLists = smbHostLists(after);
          const handle = await context.writeResource(
            "smb-share-result",
            dataName("smb-share-result", id),
            {
              id,
              name: String(after.name ?? share.name ?? ""),
              path: String(after.path ?? share.path ?? ""),
              previousHostsallow: prevAllow,
              previousHostsdeny: prevDeny,
              hostsallow: afterLists.allow,
              hostsdeny: afterLists.deny,
              previousPurpose: prevPurpose,
              purpose: String(after.purpose ?? newPurpose),
              action: "updated",
              timestamp: ts,
            },
          );
          logInfo(context, "SMB share access updated", { id });
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    smb_share_delete: {
      description:
        "Delete an SMB share (e.g. a now-unused share). Verifies the share first " +
        "and records its removed config (name/path/hostsallow/hostsdeny/purpose) so it " +
        "can be re-created. Idempotent: a share that's already gone records action=absent " +
        "instead of failing. Removes only the share definition — the underlying " +
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
            // Already gone: idempotent success. The confirmName guard only
            // protects against deleting the wrong existing share, so it doesn't
            // apply when there's nothing to delete.
            const ats = new Date().toISOString();
            // Named `absent:<selector>`, never the deleted record's `<id>`, so a
            // rerun after a delete leaves the removed config as `data.latest`. A
            // share name is tagged `name:` so a share called "6" can never take the
            // name of share id 6.
            const handle = await context.writeResource(
              "smb-share-result",
              dataName(
                "smb-share-result",
                "absent:" + (a.id ?? `name:${a.name ?? ""}`),
              ),
              {
                // null, not 0: there is no share, and 0 reads like a real id.
                id: a.id ?? null,
                name: a.name ?? "",
                path: "",
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
            logInfo(context, "SMB share already absent — nothing to delete", {
              selector: a.id ?? a.name,
            });
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
          await callChange(session, "sharing.smb.delete", [id]);

          // The removed config is captured in previous* so the share can be re-created.
          const removed = smbHostLists(share);
          const handle = await context.writeResource(
            "smb-share-result",
            dataName("smb-share-result", id),
            {
              id,
              name,
              path: String(share.path ?? ""),
              previousHostsallow: removed.allow,
              previousHostsdeny: removed.deny,
              hostsallow: [],
              hostsdeny: [],
              previousPurpose: String(share.purpose ?? ""),
              purpose: String(share.purpose ?? ""),
              action: "deleted",
              timestamp: ts,
            },
          );
          logInfo(context, "SMB share deleted", { id, name });
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
