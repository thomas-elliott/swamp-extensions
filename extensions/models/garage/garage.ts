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
 * `@thomas/garage` — administration of a Garage (S3-compatible object store)
 * cluster via its **Admin API v2** (`/v2/…`, bearer-token auth). Targets Garage
 * v2.1+ where bucket/key selectors are query parameters (`?id=`, `?globalAlias=`);
 * see the README for the v2.0 path-parameter caveat.
 *
 * SCOPE: this holds the cluster's `admin_token`, so the surface is deliberately
 * the *control plane only* — buckets, access keys, and key↔bucket permissions. It
 * never touches S3 object data (no GET/PUT/list of objects), and the only
 * destructive verbs (`bucket_delete`, `key_delete`) pre-verify the target by id
 * first (CLAUDE.md rule 5). Garage itself refuses to delete a non-empty bucket.
 *
 * Method sections (by prefix):
 *   - read/audit: `cluster_health`, `bucket_list`, `bucket_get`, `key_list`,
 *     `key_get`, `permissions_audit` (the report data source).
 *   - buckets: `bucket_create`, `bucket_update`, `bucket_delete`,
 *     `bucket_alias_add`, `bucket_alias_remove`.
 *   - keys: `key_create`, `key_import`, `key_update`, `key_rotate`, `key_delete`.
 *   - permissions: `key_allow`, `key_deny`.
 *   - cluster/layout (first-boot lifecycle): `cluster_status`, `layout_get`,
 *     `layout_assign`, `layout_apply`, `layout_revert`, `cluster_init`.
 *
 * Secrets: `adminToken` is supplied via a vault expression, e.g.
 * `${{ vault.get(<vault>, garage/admin_token) }}`. Newly created/rotated key
 * secrets are returned ONCE by Garage and surfaced on the `key-result` resource
 * (`secretAccessKey`, marked sensitive) — capture them and store in 1Password;
 * they cannot be retrieved again except via `key_get --showSecretKey`.
 */

// ─────────────────────────── global arguments ───────────────────────────

const GlobalArgs = z.object({
  endpoint: z.string().describe(
    "Base URL of the Garage Admin API, e.g. http://garage-host:3903 or an HTTPS " +
      "reverse-proxy URL. No trailing /v2 — it is added per call.",
  ),
  adminToken: z.string().meta({ sensitive: true }).describe(
    "Garage [admin] admin_token (Bearer). Supply via vault: " +
      "${{ vault.get(<vault>, garage/admin_token) }}",
  ),
  s3Region: z.string().default("garage").describe(
    "S3 region label this cluster advertises (informational; echoed in output)",
  ),
  timeoutMs: z.coerce.number().int().default(30000).describe(
    "Per-request timeout in milliseconds (AbortController)",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type", so it
// must not leak onto the public API — the exported {@link ApiFn} seam uses the
// loose {@link Json} instead (mirrors the pattern in `@thomas/postgres-admin`).
type GlobalArgsT = z.infer<typeof GlobalArgs>;

/** Lifecycle outcome recorded on result resources. */
const Action = z.enum([
  "created",
  "unchanged",
  "updated",
  "deleted",
  "granted",
  "denied",
  "rotated",
  "imported",
  "staged",
  "applied",
  "reverted",
  "observed",
]);

// ─────────────────────────── resource schemas ───────────────────────────

const ClusterHealth = z.object({
  status: z.string().describe("healthy | degraded | unavailable"),
  knownNodes: z.number(),
  connectedNodes: z.number(),
  storageNodes: z.number(),
  storageNodesUp: z.number(),
  partitions: z.number(),
  partitionsQuorum: z.number(),
  partitionsAllOk: z.number(),
  s3Region: z.string(),
  timestamp: z.string(),
});

/** One key's effective permissions on a bucket (from GetBucketInfo.keys[]). */
const BucketKeyPerm = z.object({
  accessKeyId: z.string(),
  name: z.string().optional(),
  read: z.boolean(),
  write: z.boolean(),
  owner: z.boolean(),
  localAliases: z.array(z.string()).optional(),
});

const BucketInfo = z.object({
  id: z.string(),
  globalAliases: z.array(z.string()),
  created: z.string().optional(),
  objects: z.number().optional(),
  bytes: z.number().optional(),
  unfinishedUploads: z.number().optional(),
  quotaMaxObjects: z.number().nullable().optional(),
  quotaMaxSize: z.number().nullable().optional(),
  websiteAccess: z.boolean().optional(),
  keys: z.array(BucketKeyPerm),
  action: Action,
  timestamp: z.string(),
});

/** A bucket a key can access (from GetKeyInfo.buckets[]). */
const KeyBucketAccess = z.object({
  id: z.string(),
  globalAliases: z.array(z.string()).optional(),
  localAliases: z.array(z.string()).optional(),
  read: z.boolean(),
  write: z.boolean(),
  owner: z.boolean(),
});

const KeyInfo = z.object({
  accessKeyId: z.string(),
  name: z.string().optional(),
  created: z.string().nullable().optional(),
  expiration: z.string().nullable().optional(),
  expired: z.boolean().optional(),
  canCreateBucket: z.boolean().optional(),
  buckets: z.array(KeyBucketAccess).optional(),
  // Present ONLY on key_create / key_rotate output, or key_get with showSecretKey.
  secretAccessKey: z.string().nullable().optional(),
  action: Action,
  timestamp: z.string(),
});

/** One cell of the key×bucket permission matrix. */
const PermissionEntry = z.object({
  bucketId: z.string(),
  bucketAlias: z.string().optional(),
  accessKeyId: z.string(),
  keyName: z.string().optional(),
  read: z.boolean(),
  write: z.boolean(),
  owner: z.boolean(),
});

const PermissionAudit = z.object({
  entries: z.array(PermissionEntry),
  bucketCount: z.number(),
  keyCount: z.number(),
  grantCount: z.number(),
  flags: z.object({
    /** Keys that exist but have no grant on any bucket. */
    orphanKeys: z.array(z.string()),
    /** Keys holding `owner` on every bucket they touch (and >1 bucket). */
    ownerEverywhere: z.array(z.string()),
    /** Buckets with static website serving enabled (publicly readable). */
    websiteBuckets: z.array(z.string()),
    /** Keys past their expiration. */
    expiredKeys: z.array(z.string()),
  }),
  s3Region: z.string(),
  timestamp: z.string(),
});

const BucketResult = z.object({
  id: z.string().optional(),
  alias: z.string().optional(),
  action: Action,
  timestamp: z.string(),
});

const KeyResult = z.object({
  accessKeyId: z.string().optional(),
  name: z.string().optional(),
  /** Returned ONCE by Garage on create/rotate — sensitive; persisted here so you can
   * capture it. Move it to 1Password and GC this artifact. */
  secretAccessKey: z.string().nullable().optional(),
  action: Action,
  timestamp: z.string(),
});

const PermissionResult = z.object({
  bucketId: z.string(),
  accessKeyId: z.string(),
  read: z.boolean(),
  write: z.boolean(),
  owner: z.boolean(),
  action: Action,
  timestamp: z.string(),
});

/** One node in the cluster (id + reachability + assigned role, if any). */
const NodeStatus = z.object({
  id: z.string(),
  hostname: z.string().nullable().optional(),
  addr: z.string().nullable().optional(),
  isUp: z.boolean(),
  draining: z.boolean().optional(),
  zone: z.string().optional(),
  capacity: z.number().nullable().optional(),
  tags: z.array(z.string()).optional(),
});

const ClusterStatus = z.object({
  node: z.string(),
  garageVersion: z.string().optional(),
  layoutVersion: z.number().optional(),
  nodes: z.array(NodeStatus),
  action: Action,
  timestamp: z.string(),
});

/** An assigned role in the cluster layout. */
const LayoutRole = z.object({
  id: z.string(),
  zone: z.string().optional(),
  capacity: z.number().nullable().optional(),
  tags: z.array(z.string()).optional(),
});

/** A not-yet-applied (staged) layout change. */
const StagedChange = z.object({
  id: z.string(),
  remove: z.boolean().optional(),
  zone: z.string().optional(),
  capacity: z.number().nullable().optional(),
  tags: z.array(z.string()).optional(),
});

const ClusterLayout = z.object({
  version: z.number(),
  partitionSize: z.number().optional(),
  zoneRedundancy: z.string().optional(),
  roles: z.array(LayoutRole),
  stagedChanges: z.array(StagedChange),
  action: Action,
  timestamp: z.string(),
});

const LayoutResult = z.object({
  version: z.number().optional(),
  staged: z.boolean().optional(),
  applied: z.boolean().optional(),
  nodeId: z.string().optional(),
  messages: z.array(z.string()).optional(),
  action: Action,
  timestamp: z.string(),
});

// ─────────────────────────── api seam ───────────────────────────

/** A JSON-ish bag — structurally the resolved global args / request bodies. */
export type Json = Record<string, unknown>;

/**
 * Low-level Admin API call seam. `g` is typed loosely as {@link Json} so this
 * EXPORTED type stays "fast-check" clean (referencing the zod-inferred global-args
 * type would drag a slow type onto the public API). Returns the parsed JSON body
 * (or `undefined` for empty 2xx responses); throws on a non-2xx status.
 */
export type ApiFn = (
  g: Json,
  method: string,
  op: string,
  query: Record<string, unknown>,
  body: unknown,
) => Promise<unknown>;

let _apiOverride: ApiFn | null = null;

/** Test-only seam: substitute the Admin API transport. Pass `null` to restore the real one. */
export function __setGarageApi(fn: ApiFn | null): void {
  _apiOverride = fn;
}

/** Build a `/v2/<op>` URL with a query string, dropping null/undefined params. */
function buildUrl(
  endpoint: string,
  op: string,
  query: Record<string, unknown>,
): string {
  const base = endpoint.replace(/\/+$/, "");
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    qs.set(k, String(v));
  }
  const tail = qs.toString();
  return `${base}/v2/${op}${tail ? `?${tail}` : ""}`;
}

/** The real `fetch`-backed implementation behind {@link api}. */
async function realApi(
  g: GlobalArgsT,
  method: string,
  op: string,
  query: Record<string, unknown>,
  body: unknown,
): Promise<unknown> {
  const url = buildUrl(g.endpoint, op, query);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Number(g.timeoutMs));
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: {
        "authorization": `Bearer ${g.adminToken}`,
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  const text = await res.text();
  if (!res.ok) {
    let detail = text;
    try {
      const j = JSON.parse(text) as { code?: string; message?: string };
      detail = j.message ?? j.code ?? text;
    } catch { /* non-JSON error body — use raw text */ }
    throw new Error(`Garage ${op} failed (HTTP ${res.status}): ${detail}`);
  }
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Dispatch through the test override when set, else the real transport. */
function api(
  g: GlobalArgsT,
  method: string,
  op: string,
  query: Record<string, unknown> = {},
  body?: unknown,
): Promise<unknown> {
  return (_apiOverride ?? realApi as ApiFn)(g, method, op, query, body);
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
  return (v && typeof v === "object") ? v as Record<string, unknown> : {};
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

/** Shape a raw GetBucketInfo / CreateBucketResponse object into a {@link BucketInfo}. */
function shapeBucket(
  raw: unknown,
  action: z.infer<typeof Action>,
  ts: string,
): z.infer<typeof BucketInfo> {
  const b = asObj(raw);
  const quotas = asObj(b.quotas);
  const keys = asArr(b.keys).map((k) => {
    const kk = asObj(k);
    const p = asObj(kk.permissions);
    return {
      accessKeyId: String(kk.accessKeyId ?? ""),
      name: asStr(kk.name),
      read: asBool(p.read),
      write: asBool(p.write),
      owner: asBool(p.owner),
      localAliases: asArr(kk.bucketLocalAliases).map(String),
    };
  });
  return {
    id: String(b.id ?? ""),
    globalAliases: asArr(b.globalAliases).map(String),
    created: asStr(b.created),
    objects: asNum(b.objects),
    bytes: asNum(b.bytes),
    unfinishedUploads: asNum(b.unfinishedUploads),
    quotaMaxObjects: nullableNum(quotas.maxObjects),
    quotaMaxSize: nullableNum(quotas.maxSize),
    websiteAccess: b.websiteAccess === undefined
      ? undefined
      : asBool(b.websiteAccess),
    keys,
    action,
    timestamp: ts,
  };
}

/** Shape a raw GetKeyInfo / CreateKeyResponse object into a {@link KeyInfo}. */
function shapeKey(
  raw: unknown,
  action: z.infer<typeof Action>,
  ts: string,
): z.infer<typeof KeyInfo> {
  const k = asObj(raw);
  const perm = asObj(k.permissions);
  const buckets = asArr(k.buckets).map((b) => {
    const bb = asObj(b);
    const p = asObj(bb.permissions);
    return {
      id: String(bb.id ?? ""),
      globalAliases: asArr(bb.globalAliases).map(String),
      localAliases: asArr(bb.localAliases).map(String),
      read: asBool(p.read),
      write: asBool(p.write),
      owner: asBool(p.owner),
    };
  });
  return {
    accessKeyId: String(k.accessKeyId ?? ""),
    name: asStr(k.name),
    created: k.created === undefined ? undefined : asStr(k.created) ?? null,
    expiration: k.expiration === undefined
      ? undefined
      : asStr(k.expiration) ?? null,
    expired: k.expired === undefined ? undefined : asBool(k.expired),
    canCreateBucket: asBool(perm.createBucket),
    buckets,
    secretAccessKey: k.secretAccessKey === undefined
      ? undefined
      : asStr(k.secretAccessKey) ?? null,
    action,
    timestamp: ts,
  };
}

// ─────────────────────────── method argument schemas ───────────────────────────

const Empty = z.object({});

const BucketGetArgs = z.object({
  id: z.string().optional().describe("Bucket id (exact)"),
  globalAlias: z.string().optional().describe("Global alias to look up"),
  search: z.string().optional().describe("Partial id/alias to search"),
}).refine(
  (a) => !!(a.id || a.globalAlias || a.search),
  { message: "provide one of id, globalAlias, or search" },
);

const KeyGetArgs = z.object({
  id: z.string().optional().describe("Access key id (exact)"),
  search: z.string().optional().describe("Partial id/name to search"),
  showSecretKey: z.boolean().default(false).describe(
    "Include the secret access key in output (sensitive — persisted to swamp data)",
  ),
}).refine(
  (a) => !!(a.id || a.search),
  { message: "provide id or search" },
);

const BucketCreateArgs = z.object({
  globalAlias: z.string().optional().describe(
    "Global alias for the new bucket (the usual case)",
  ),
  localAlias: z.string().optional().describe(
    "Local alias name (requires localAliasAccessKeyId)",
  ),
  localAliasAccessKeyId: z.string().optional().describe(
    "Access key the local alias belongs to",
  ),
}).refine(
  (a) => !!(a.globalAlias || a.localAlias),
  { message: "provide globalAlias or localAlias" },
).refine(
  (a) => !a.localAlias || !!a.localAliasAccessKeyId,
  { message: "localAlias requires localAliasAccessKeyId" },
);

const BucketUpdateArgs = z.object({
  id: z.string().describe("Bucket id to update"),
  maxObjects: z.coerce.number().int().nullable().optional().describe(
    "Object-count quota; null clears it",
  ),
  maxSize: z.coerce.number().int().nullable().optional().describe(
    "Size quota in bytes; null clears it",
  ),
  websiteEnabled: z.boolean().optional().describe(
    "Enable/disable static website serving",
  ),
  indexDocument: z.string().optional().describe("Website index document key"),
  errorDocument: z.string().optional().describe("Website error document key"),
});

const BucketDeleteArgs = z.object({
  id: z.string().describe("Bucket id to delete (verified to exist first)"),
  allowNonEmpty: z.boolean().default(false).describe(
    "Attempt deletion even if the bucket reports objects (Garage will still refuse a non-empty bucket)",
  ),
});

const AliasArgs = z.object({
  bucketId: z.string().describe("Bucket id"),
  globalAlias: z.string().optional().describe("Global alias to add/remove"),
  localAlias: z.string().optional().describe("Local alias to add/remove"),
  accessKeyId: z.string().optional().describe(
    "Access key the local alias belongs to (required for localAlias)",
  ),
}).refine(
  (a) => !!(a.globalAlias || a.localAlias),
  { message: "provide globalAlias or localAlias" },
).refine(
  (a) => !a.localAlias || !!a.accessKeyId,
  { message: "localAlias requires accessKeyId" },
);

const KeyCreateArgs = z.object({
  name: z.string().optional().describe("Human-readable key name"),
  allowCreateBucket: z.boolean().default(false).describe(
    "Permit this key to create buckets",
  ),
  expiration: z.string().optional().describe(
    "RFC 3339 expiry timestamp (omit + neverExpires=true for no expiry)",
  ),
  neverExpires: z.boolean().default(true).describe("Key never expires"),
});

const KeyImportArgs = z.object({
  accessKeyId: z.string().describe("Existing access key id to import"),
  secretAccessKey: z.string().meta({ sensitive: true }).describe(
    "Matching secret access key",
  ),
  name: z.string().optional().describe("Human-readable key name"),
});

const KeyUpdateArgs = z.object({
  id: z.string().describe("Access key id to update"),
  name: z.string().optional().describe("New name"),
  allowCreateBucket: z.boolean().optional().describe(
    "Set/clear the create-bucket permission",
  ),
  expiration: z.string().optional().describe("New RFC 3339 expiry"),
  neverExpires: z.boolean().optional().describe("Clear expiry"),
});

const KeyRotateArgs = z.object({
  id: z.string().describe("Access key id to rotate (the OLD key)"),
  name: z.string().optional().describe(
    "Name for the new key; defaults to the old key's name + ' (rotated)'",
  ),
});

const KeyDeleteArgs = z.object({
  id: z.string().describe("Access key id to delete (verified to exist first)"),
});

const PermArgs = z.object({
  bucketId: z.string().describe("Bucket id"),
  accessKeyId: z.string().describe("Access key id"),
  read: z.boolean().default(false).describe("Read permission"),
  write: z.boolean().default(false).describe("Write permission"),
  owner: z.boolean().default(false).describe(
    "Owner permission (manage aliases, quotas, website)",
  ),
}).refine(
  (a) => a.read || a.write || a.owner,
  { message: "set at least one of read/write/owner" },
);

const LayoutAssignArgs = z.object({
  nodeId: z.string().describe(
    "Node id to assign a role to (from cluster_status)",
  ),
  zone: z.string().default("dc1").describe(
    "Zone/datacenter label for the node",
  ),
  capacity: z.coerce.number().int().nullable().optional().describe(
    "Storage capacity in BYTES (e.g. 1000000000 = 1 GB). Omit/null = gateway (no storage).",
  ),
  tags: z.array(z.string()).default([]).describe("Optional node tags"),
  zoneRedundancy: z.string().optional().describe(
    'Cluster zone redundancy: "maximum" or a positive integer (atLeast N). Omit to leave unchanged.',
  ),
});

const LayoutApplyArgs = z.object({
  version: z.coerce.number().int().optional().describe(
    "Layout version to apply; defaults to current + 1 (the staged version)",
  ),
});

const ClusterInitArgs = z.object({
  nodeId: z.string().optional().describe(
    "Node to configure; defaults to the responding node (correct for a single-node cluster)",
  ),
  zone: z.string().default("dc1").describe("Zone/datacenter label"),
  capacity: z.coerce.number().int().describe(
    "Storage capacity in BYTES for the node (e.g. 1000000000 = 1 GB). Required.",
  ),
  tags: z.array(z.string()).default([]).describe("Optional node tags"),
  zoneRedundancy: z.string().optional().describe(
    '"maximum" or a positive integer (atLeast N); omit for the cluster default',
  ),
  force: z.boolean().default(false).describe(
    "Re-initialise even if the layout already has assigned roles",
  ),
});

/** Parse a zoneRedundancy arg ("maximum" or a positive integer) into the API shape. */
function parseZoneRedundancy(s: string): "maximum" | { atLeast: number } {
  if (s === "maximum") return "maximum";
  if (/^\d+$/.test(s)) return { atLeast: Number(s) };
  throw new Error(
    `invalid zoneRedundancy ${
      JSON.stringify(s)
    }: use "maximum" or a positive integer`,
  );
}

/** Render a raw zoneRedundancy value (string or `{atLeast}`) to a display string. */
function zrToStr(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string") return v;
  const o = asObj(v);
  return o.atLeast !== undefined ? `atLeast:${asNum(o.atLeast)}` : undefined;
}

/** Shape a raw GetClusterStatus response into a {@link ClusterStatus}. */
function shapeStatus(
  raw: unknown,
  action: z.infer<typeof Action>,
  ts: string,
): z.infer<typeof ClusterStatus> {
  const s = asObj(raw);
  const nodes = asArr(s.nodes).map((n) => {
    const nn = asObj(n);
    const role = asObj(nn.role);
    return {
      id: String(nn.id ?? ""),
      hostname: nn.hostname === undefined
        ? undefined
        : asStr(nn.hostname) ?? null,
      addr: nn.addr === undefined ? undefined : asStr(nn.addr) ?? null,
      isUp: asBool(nn.isUp),
      draining: nn.draining === undefined ? undefined : asBool(nn.draining),
      zone: asStr(role.zone),
      capacity: nullableNum(role.capacity),
      tags: Array.isArray(role.tags) ? role.tags.map(String) : undefined,
    };
  });
  return {
    node: String(s.node ?? ""),
    garageVersion: asStr(s.garageVersion),
    layoutVersion: asNum(s.layoutVersion),
    nodes,
    action,
    timestamp: ts,
  };
}

/** Shape a raw GetClusterLayout response into a {@link ClusterLayout}. */
function shapeLayout(
  raw: unknown,
  action: z.infer<typeof Action>,
  ts: string,
): z.infer<typeof ClusterLayout> {
  const l = asObj(raw);
  const roles = asArr(l.roles).map((r) => {
    const rr = asObj(r);
    return {
      id: String(rr.id ?? ""),
      zone: asStr(rr.zone),
      capacity: nullableNum(rr.capacity),
      tags: Array.isArray(rr.tags) ? rr.tags.map(String) : undefined,
    };
  });
  const stagedChanges = asArr(l.stagedRoleChanges).map((c) => {
    const cc = asObj(c);
    return {
      id: String(cc.id ?? ""),
      remove: cc.remove === undefined ? undefined : asBool(cc.remove),
      zone: asStr(cc.zone),
      capacity: nullableNum(cc.capacity),
      tags: Array.isArray(cc.tags) ? cc.tags.map(String) : undefined,
    };
  });
  return {
    version: asNum(l.version) ?? 0,
    partitionSize: asNum(l.partitionSize),
    zoneRedundancy: zrToStr(asObj(l.parameters).zoneRedundancy),
    roles,
    stagedChanges,
    action,
    timestamp: ts,
  };
}

// ─────────────────────────── shared executors ───────────────────────────

/** GetBucketInfo by id/alias/search → raw object (throws if not found). */
async function getBucketRaw(
  g: GlobalArgsT,
  sel: { id?: string; globalAlias?: string; search?: string },
): Promise<Record<string, unknown>> {
  const raw = await api(g, "GET", "GetBucketInfo", {
    id: sel.id,
    globalAlias: sel.globalAlias,
    search: sel.search,
  });
  return asObj(raw);
}

/** GetKeyInfo by id/search → raw object. */
async function getKeyRaw(
  g: GlobalArgsT,
  sel: { id?: string; search?: string; showSecretKey?: boolean },
): Promise<Record<string, unknown>> {
  const raw = await api(g, "GET", "GetKeyInfo", {
    id: sel.id,
    search: sel.search,
    showSecretKey: sel.showSecretKey ? "true" : undefined,
  });
  return asObj(raw);
}

// ─────────────────────────── model ───────────────────────────

/**
 * The `@thomas/garage` model definition: control-plane administration of a Garage
 * S3 cluster (buckets, access keys, key↔bucket permissions) over the Admin API v2.
 * See the file header for the scope guarantee.
 */
export const model = {
  type: "@thomas/garage",
  version: "2026.06.01.1",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify the Garage Admin API is reachable (GET /v2/GetClusterHealth)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        const g = context.globalArgs;
        // `swamp model validate` does NOT resolve vault expressions before running
        // checks, so the token is still a literal `${{ … }}` and a probe can't
        // authenticate. Skip then — real reachability is exercised at method-run time.
        if (/\$\{\{/.test(String(g.adminToken))) return { pass: true };
        try {
          await api(g, "GET", "GetClusterHealth");
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Cannot reach Garage Admin API at ${g.endpoint}: ${
                (e as Error).message
              }`,
            ],
          };
        }
      },
    },
  },
  resources: {
    "cluster-health": {
      description: "Cluster health snapshot (status, node + partition counts)",
      schema: ClusterHealth,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "bucket": {
      description: "A bucket (aliases, usage, quotas, and per-key permissions)",
      schema: BucketInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "key": {
      description: "An access key (attributes + the buckets it can reach)",
      schema: KeyInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "permission-audit": {
      description: "Full key×bucket permission matrix plus risk flags",
      schema: PermissionAudit,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "bucket-result": {
      description: "Result of a bucket create/update/delete/alias operation",
      schema: BucketResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "key-result": {
      description:
        "Result of a key create/import/update/rotate/delete (may carry the one-time secret)",
      schema: KeyResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "permission-result": {
      description: "Result of a key allow/deny on a bucket",
      schema: PermissionResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "cluster-status": {
      description:
        "Cluster status (this node id, version, and all nodes/roles)",
      schema: ClusterStatus,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "cluster-layout": {
      description: "Current cluster layout (assigned roles + staged changes)",
      schema: ClusterLayout,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "layout-result": {
      description: "Result of a layout stage/apply/revert or cluster_init",
      schema: LayoutResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    // ───────────── read / audit ─────────────
    cluster_health: {
      description:
        "Fetch cluster health (status, node + partition counts). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Fetching cluster health");
        const raw = asObj(await api(g, "GET", "GetClusterHealth"));
        const ts = new Date().toISOString();
        const handle = await context.writeResource("cluster-health", "main", {
          status: String(raw.status ?? "unknown"),
          knownNodes: asNum(raw.knownNodes) ?? 0,
          connectedNodes: asNum(raw.connectedNodes) ?? 0,
          storageNodes: asNum(raw.storageNodes) ?? 0,
          storageNodesUp: asNum(raw.storageNodesUp) ?? 0,
          partitions: asNum(raw.partitions) ?? 0,
          partitionsQuorum: asNum(raw.partitionsQuorum) ?? 0,
          partitionsAllOk: asNum(raw.partitionsAllOk) ?? 0,
          s3Region: g.s3Region,
          timestamp: ts,
        });
        return { dataHandles: [handle] };
      },
    },

    bucket_list: {
      description:
        "List buckets, enriched with usage/quotas/per-key permissions (factory: one " +
        "`bucket` per bucket; fans out GetBucketInfo internally). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Listing buckets");
        const list = asArr(await api(g, "GET", "ListBuckets"));
        const ts = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const item of list) {
          const id = String(asObj(item).id ?? "");
          if (!id) continue;
          const raw = await getBucketRaw(g, { id });
          handles.push(
            await context.writeResource(
              "bucket",
              id,
              shapeBucket(raw, "observed", ts),
            ),
          );
        }
        return { dataHandles: handles };
      },
    },

    bucket_get: {
      description:
        "Get one bucket by id, globalAlias, or search (full detail). Read-only.",
      arguments: BucketGetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BucketGetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const raw = await getBucketRaw(g, a);
        const shaped = shapeBucket(raw, "observed", new Date().toISOString());
        const handle = await context.writeResource("bucket", shaped.id, shaped);
        return { dataHandles: [handle] };
      },
    },

    key_list: {
      description:
        "List access keys (id/name/expiry; factory: one `key` per key). Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Listing keys");
        const list = asArr(await api(g, "GET", "ListKeys"));
        const ts = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const item of list) {
          const k = asObj(item);
          const id = String(k.id ?? "");
          if (!id) continue;
          handles.push(
            await context.writeResource("key", id, {
              accessKeyId: id,
              name: asStr(k.name),
              created: k.created === undefined
                ? undefined
                : asStr(k.created) ?? null,
              expiration: k.expiration === undefined
                ? undefined
                : asStr(k.expiration) ?? null,
              expired: k.expired === undefined ? undefined : asBool(k.expired),
              buckets: [],
              action: "observed",
              timestamp: ts,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },

    key_get: {
      description:
        "Get one access key by id or search, with the buckets it can reach. " +
        "Set showSecretKey to reveal the secret (sensitive). Read-only.",
      arguments: KeyGetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyGetArgs.parse(rawArgs);
        const g = context.globalArgs;
        const raw = await getKeyRaw(g, a);
        const shaped = shapeKey(raw, "observed", new Date().toISOString());
        const handle = await context.writeResource(
          "key",
          shaped.accessKeyId,
          shaped,
        );
        return { dataHandles: [handle] };
      },
    },

    permissions_audit: {
      description:
        "Build the full key×bucket permission matrix and risk flags (orphan keys, " +
        "owner-everywhere, website-exposed buckets, expired keys). Read-only. The " +
        "data source for the garage-audit report.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Auditing permissions");
        const buckets = asArr(await api(g, "GET", "ListBuckets"));
        const keys = asArr(await api(g, "GET", "ListKeys"));
        const ts = new Date().toISOString();

        const entries: z.infer<typeof PermissionEntry>[] = [];
        const websiteBuckets: string[] = [];
        const keysWithGrant = new Set<string>();
        // accessKeyId -> {total grants, owner grants}
        const ownerTally = new Map<string, { total: number; owner: number }>();

        for (const b of buckets) {
          const id = String(asObj(b).id ?? "");
          if (!id) continue;
          const raw = await getBucketRaw(g, { id });
          const alias = asArr(raw.globalAliases).map(String)[0];
          if (asBool(raw.websiteAccess)) websiteBuckets.push(alias ?? id);
          for (const k of asArr(raw.keys)) {
            const kk = asObj(k);
            const akid = String(kk.accessKeyId ?? "");
            if (!akid) continue;
            const p = asObj(kk.permissions);
            const read = asBool(p.read),
              write = asBool(p.write),
              owner = asBool(p.owner);
            if (!(read || write || owner)) continue;
            entries.push({
              bucketId: id,
              bucketAlias: alias,
              accessKeyId: akid,
              keyName: asStr(kk.name),
              read,
              write,
              owner,
            });
            keysWithGrant.add(akid);
            const t = ownerTally.get(akid) ?? { total: 0, owner: 0 };
            t.total += 1;
            if (owner) t.owner += 1;
            ownerTally.set(akid, t);
          }
        }

        const allKeyIds = keys.map((k) => String(asObj(k).id ?? "")).filter(
          Boolean,
        );
        const orphanKeys = allKeyIds.filter((id) => !keysWithGrant.has(id));
        const ownerEverywhere = [...ownerTally.entries()]
          .filter(([, t]) => t.total > 1 && t.owner === t.total)
          .map(([id]) => id);
        const expiredKeys = keys
          .filter((k) => asBool(asObj(k).expired))
          .map((k) => String(asObj(k).id ?? ""))
          .filter(Boolean);

        const handle = await context.writeResource("permission-audit", "main", {
          entries,
          bucketCount: buckets.length,
          keyCount: keys.length,
          grantCount: entries.length,
          flags: { orphanKeys, ownerEverywhere, websiteBuckets, expiredKeys },
          s3Region: g.s3Region,
          timestamp: ts,
        });
        return { dataHandles: [handle] };
      },
    },

    // ───────────── buckets (mutating) ─────────────
    bucket_create: {
      description:
        "Create a bucket with a global (or local) alias. Idempotent on globalAlias: " +
        "an existing one is returned as `unchanged`.",
      arguments: BucketCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BucketCreateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const ts = new Date().toISOString();

        if (a.globalAlias) {
          const existing = await api(g, "GET", "GetBucketInfo", {
            globalAlias: a.globalAlias,
          }).catch(() => undefined);
          if (existing && asObj(existing).id) {
            logInfo(context, "Bucket alias already exists; unchanged", {
              globalAlias: a.globalAlias,
            });
            const handle = await context.writeResource(
              "bucket-result",
              a.globalAlias,
              {
                id: String(asObj(existing).id),
                alias: a.globalAlias,
                action: "unchanged",
                timestamp: ts,
              },
            );
            return { dataHandles: [handle] };
          }
        }

        const body: Json = {};
        if (a.globalAlias) body.globalAlias = a.globalAlias;
        if (a.localAlias) {
          body.localAlias = {
            accessKeyId: a.localAliasAccessKeyId,
            alias: a.localAlias,
          };
        }
        logInfo(context, "Creating bucket", {
          globalAlias: a.globalAlias,
          localAlias: a.localAlias,
        });
        const raw = asObj(await api(g, "POST", "CreateBucket", {}, body));
        const handle = await context.writeResource(
          "bucket-result",
          a.globalAlias ?? a.localAlias ?? String(raw.id ?? "bucket"),
          {
            id: asStr(raw.id),
            alias: a.globalAlias ?? a.localAlias,
            action: "created",
            timestamp: ts,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    bucket_update: {
      description:
        "Update a bucket's quotas and/or static-website config (UpdateBucket).",
      arguments: BucketUpdateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BucketUpdateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const body: Json = {};
        if (a.maxObjects !== undefined || a.maxSize !== undefined) {
          body.quotas = {
            maxObjects: a.maxObjects ?? null,
            maxSize: a.maxSize ?? null,
          };
        }
        if (a.websiteEnabled !== undefined) {
          body.websiteAccess = {
            enabled: a.websiteEnabled,
            indexDocument: a.indexDocument ?? null,
            errorDocument: a.errorDocument ?? null,
          };
        }
        if (Object.keys(body).length === 0) {
          throw new Error(
            "nothing to update: provide maxObjects/maxSize or websiteEnabled",
          );
        }
        logInfo(context, "Updating bucket", { id: a.id });
        await api(g, "POST", "UpdateBucket", { id: a.id }, body);
        const handle = await context.writeResource("bucket-result", a.id, {
          id: a.id,
          action: "updated",
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    bucket_delete: {
      description:
        "Delete a bucket BY ID (verified to exist first; refuses a non-empty bucket " +
        "unless allowNonEmpty, and Garage itself also refuses non-empty). Destructive.",
      arguments: BucketDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BucketDeleteArgs.parse(rawArgs);
        const g = context.globalArgs;
        const raw = await getBucketRaw(g, { id: a.id });
        if (!raw.id) {
          throw new Error(`Bucket ${JSON.stringify(a.id)} not found`);
        }
        const objects = asNum(raw.objects) ?? 0;
        if (objects > 0 && !a.allowNonEmpty) {
          throw new Error(
            `Refusing to delete non-empty bucket ${a.id} (${objects} objects); ` +
              `set allowNonEmpty to override (Garage may still refuse).`,
          );
        }
        logInfo(context, "Deleting bucket", { id: a.id, objects });
        await api(g, "POST", "DeleteBucket", { id: a.id });
        const handle = await context.writeResource("bucket-result", a.id, {
          id: a.id,
          alias: asArr(raw.globalAliases).map(String)[0],
          action: "deleted",
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    bucket_alias_add: {
      description: "Add a global or local alias to a bucket (AddBucketAlias).",
      arguments: AliasArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AliasArgs.parse(rawArgs);
        const g = context.globalArgs;
        const body: Json = a.globalAlias
          ? { bucketId: a.bucketId, globalAlias: a.globalAlias }
          : {
            bucketId: a.bucketId,
            localAlias: a.localAlias,
            accessKeyId: a.accessKeyId,
          };
        logInfo(context, "Adding bucket alias", body);
        await api(g, "POST", "AddBucketAlias", {}, body);
        const handle = await context.writeResource(
          "bucket-result",
          a.bucketId,
          {
            id: a.bucketId,
            alias: a.globalAlias ?? a.localAlias,
            action: "updated",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    bucket_alias_remove: {
      description:
        "Remove a global or local alias from a bucket (RemoveBucketAlias).",
      arguments: AliasArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AliasArgs.parse(rawArgs);
        const g = context.globalArgs;
        const body: Json = a.globalAlias
          ? { bucketId: a.bucketId, globalAlias: a.globalAlias }
          : {
            bucketId: a.bucketId,
            localAlias: a.localAlias,
            accessKeyId: a.accessKeyId,
          };
        logInfo(context, "Removing bucket alias", body);
        await api(g, "POST", "RemoveBucketAlias", {}, body);
        const handle = await context.writeResource(
          "bucket-result",
          a.bucketId,
          {
            id: a.bucketId,
            alias: a.globalAlias ?? a.localAlias,
            action: "updated",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── keys (mutating) ─────────────
    key_create: {
      description:
        "Create a new access key; the secret is returned ONCE on `key-result` " +
        "(sensitive). Capture it and store in 1Password.",
      arguments: KeyCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyCreateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const body: Json = {
          name: a.name,
          allow: { createBucket: a.allowCreateBucket },
        };
        if (a.expiration) body.expiration = a.expiration;
        else body.neverExpires = a.neverExpires;
        logInfo(context, "Creating key", { name: a.name }); // never logs the secret
        const raw = asObj(await api(g, "POST", "CreateKey", {}, body));
        const handle = await context.writeResource(
          "key-result",
          String(raw.accessKeyId ?? a.name ?? "key"),
          {
            accessKeyId: asStr(raw.accessKeyId),
            name: asStr(raw.name) ?? a.name,
            secretAccessKey: asStr(raw.secretAccessKey) ?? null,
            action: "created",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    key_import: {
      description:
        "Import a pre-existing access key pair (ImportKey) — e.g. to recreate a key " +
        "with a known secret after a cluster rebuild.",
      arguments: KeyImportArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyImportArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Importing key", { accessKeyId: a.accessKeyId }); // never logs the secret
        const raw = asObj(
          await api(g, "POST", "ImportKey", {}, {
            accessKeyId: a.accessKeyId,
            secretAccessKey: a.secretAccessKey,
            name: a.name,
          }),
        );
        const handle = await context.writeResource(
          "key-result",
          String(raw.accessKeyId ?? a.accessKeyId),
          {
            accessKeyId: asStr(raw.accessKeyId) ?? a.accessKeyId,
            name: asStr(raw.name) ?? a.name,
            action: "imported",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    key_update: {
      description:
        "Update a key's name, create-bucket permission, and/or expiry (UpdateKey).",
      arguments: KeyUpdateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyUpdateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const body: Json = {};
        if (a.name !== undefined) body.name = a.name;
        if (a.allowCreateBucket !== undefined) {
          body.allow = { createBucket: a.allowCreateBucket };
          body.deny = { createBucket: !a.allowCreateBucket };
        }
        if (a.expiration !== undefined) body.expiration = a.expiration;
        if (a.neverExpires !== undefined) body.neverExpires = a.neverExpires;
        if (Object.keys(body).length === 0) {
          throw new Error(
            "nothing to update: provide name, allowCreateBucket, expiration, or neverExpires",
          );
        }
        logInfo(context, "Updating key", { id: a.id });
        const raw = asObj(
          await api(g, "POST", "UpdateKey", { id: a.id }, body),
        );
        const handle = await context.writeResource("key-result", a.id, {
          accessKeyId: a.id,
          name: asStr(raw.name) ?? a.name,
          action: "updated",
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    key_rotate: {
      description:
        "Rotate a key: create a NEW key, copy the OLD key's bucket grants onto it, " +
        "and return the new secret ONCE (sensitive). Does NOT delete the old key — " +
        "update consumers, then call key_delete on the old id. The headline method.",
      arguments: KeyRotateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyRotateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const ts = new Date().toISOString();

        const oldKey = await getKeyRaw(g, { id: a.id });
        if (!oldKey.accessKeyId) {
          throw new Error(`Key ${JSON.stringify(a.id)} not found`);
        }
        const oldName = asStr(oldKey.name);
        const oldPerm = asObj(oldKey.permissions);

        // 1. create the replacement key (mirror create-bucket permission).
        logInfo(context, "Rotating key: creating replacement", { oldId: a.id });
        const created = asObj(
          await api(g, "POST", "CreateKey", {}, {
            name: a.name ?? `${oldName ?? a.id} (rotated)`,
            allow: { createBucket: asBool(oldPerm.createBucket) },
            neverExpires: true,
          }),
        );
        const newId = String(created.accessKeyId ?? "");
        if (!newId) {
          throw new Error("Rotation failed: no new accessKeyId returned");
        }

        // 2. copy each bucket grant from the old key to the new one.
        let copied = 0;
        for (const b of asArr(oldKey.buckets)) {
          const bb = asObj(b);
          const bucketId = String(bb.id ?? "");
          if (!bucketId) continue;
          const p = asObj(bb.permissions);
          await api(g, "POST", "AllowBucketKey", {}, {
            bucketId,
            accessKeyId: newId,
            permissions: {
              read: asBool(p.read),
              write: asBool(p.write),
              owner: asBool(p.owner),
            },
          });
          copied += 1;
        }
        logInfo(context, "Rotation: copied grants", { newId, grants: copied });

        const handle = await context.writeResource("key-result", newId, {
          accessKeyId: newId,
          name: asStr(created.name),
          secretAccessKey: asStr(created.secretAccessKey) ?? null,
          action: "rotated",
          timestamp: ts,
        });
        return { dataHandles: [handle] };
      },
    },

    key_delete: {
      description:
        "Delete an access key BY ID (verified to exist first). Destructive — any " +
        "client using it loses access immediately.",
      arguments: KeyDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyDeleteArgs.parse(rawArgs);
        const g = context.globalArgs;
        const raw = await getKeyRaw(g, { id: a.id });
        if (!raw.accessKeyId) {
          throw new Error(`Key ${JSON.stringify(a.id)} not found`);
        }
        logInfo(context, "Deleting key", { id: a.id });
        await api(g, "POST", "DeleteKey", { id: a.id });
        const handle = await context.writeResource("key-result", a.id, {
          accessKeyId: a.id,
          name: asStr(raw.name),
          action: "deleted",
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    // ───────────── permissions ─────────────
    key_allow: {
      description:
        "Grant read/write/owner on a bucket to a key (AllowBucketKey). Idempotent.",
      arguments: PermArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PermArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Allowing key on bucket", {
          bucketId: a.bucketId,
          accessKeyId: a.accessKeyId,
        });
        await api(g, "POST", "AllowBucketKey", {}, {
          bucketId: a.bucketId,
          accessKeyId: a.accessKeyId,
          permissions: { read: a.read, write: a.write, owner: a.owner },
        });
        const handle = await context.writeResource(
          "permission-result",
          `${a.bucketId}-${a.accessKeyId}`,
          {
            bucketId: a.bucketId,
            accessKeyId: a.accessKeyId,
            read: a.read,
            write: a.write,
            owner: a.owner,
            action: "granted",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    key_deny: {
      description:
        "Revoke read/write/owner on a bucket from a key (DenyBucketKey). Each flag " +
        "set true denies that permission. Idempotent.",
      arguments: PermArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PermArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Denying key on bucket", {
          bucketId: a.bucketId,
          accessKeyId: a.accessKeyId,
        });
        await api(g, "POST", "DenyBucketKey", {}, {
          bucketId: a.bucketId,
          accessKeyId: a.accessKeyId,
          permissions: { read: a.read, write: a.write, owner: a.owner },
        });
        const handle = await context.writeResource(
          "permission-result",
          `${a.bucketId}-${a.accessKeyId}`,
          {
            bucketId: a.bucketId,
            accessKeyId: a.accessKeyId,
            read: a.read,
            write: a.write,
            owner: a.owner,
            action: "denied",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── cluster / layout (first-boot lifecycle) ─────────────
    cluster_status: {
      description:
        "Cluster status: this node's id, Garage version, layout version, and every " +
        "node with its role/up state. Read-only. Use it to find node ids for layout.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Fetching cluster status");
        const raw = await api(g, "GET", "GetClusterStatus");
        const handle = await context.writeResource(
          "cluster-status",
          "main",
          shapeStatus(raw, "observed", new Date().toISOString()),
        );
        return { dataHandles: [handle] };
      },
    },

    layout_get: {
      description:
        "Get the current cluster layout — assigned roles plus any staged changes. Read-only.",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        const raw = await api(g, "GET", "GetClusterLayout");
        const handle = await context.writeResource(
          "cluster-layout",
          "main",
          shapeLayout(raw, "observed", new Date().toISOString()),
        );
        return { dataHandles: [handle] };
      },
    },

    layout_assign: {
      description:
        "STAGE a role for a node (zone + storage capacity, or gateway when capacity is " +
        "omitted). Stages only — review with layout_get, then commit with layout_apply.",
      arguments: LayoutAssignArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = LayoutAssignArgs.parse(rawArgs);
        const g = context.globalArgs;
        const body: Json = {
          roles: [{
            id: a.nodeId,
            zone: a.zone,
            capacity: a.capacity ?? null,
            tags: a.tags,
          }],
          parameters: a.zoneRedundancy
            ? { zoneRedundancy: parseZoneRedundancy(a.zoneRedundancy) }
            : null,
        };
        logInfo(context, "Staging layout role", {
          nodeId: a.nodeId,
          zone: a.zone,
        });
        await api(g, "POST", "UpdateClusterLayout", {}, body);
        const handle = await context.writeResource("layout-result", a.nodeId, {
          nodeId: a.nodeId,
          staged: true,
          applied: false,
          action: "staged",
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    layout_apply: {
      description:
        "Commit staged layout changes (ApplyClusterLayout). Defaults to the current " +
        "version + 1; errors if nothing is staged.",
      arguments: LayoutApplyArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = LayoutApplyArgs.parse(rawArgs);
        const g = context.globalArgs;
        const layout = asObj(await api(g, "GET", "GetClusterLayout"));
        const staged = asArr(layout.stagedRoleChanges);
        if (staged.length === 0 && a.version === undefined) {
          throw new Error("no staged layout changes to apply");
        }
        const version = a.version ?? (asNum(layout.version) ?? 0) + 1;
        logInfo(context, "Applying layout", { version });
        const res = asObj(
          await api(g, "POST", "ApplyClusterLayout", {}, { version }),
        );
        const handle = await context.writeResource(
          "layout-result",
          String(version),
          {
            version,
            staged: false,
            applied: true,
            messages: asArr(res.message).map(String),
            action: "applied",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    layout_revert: {
      description:
        "Discard all staged (un-applied) layout changes (RevertClusterLayout).",
      arguments: Empty,
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Reverting staged layout changes");
        await api(g, "POST", "RevertClusterLayout");
        const handle = await context.writeResource("layout-result", "revert", {
          staged: false,
          applied: false,
          action: "reverted",
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    cluster_init: {
      description:
        "First-boot convenience: assign a storage role to the node (defaults to the " +
        "responding node — correct for single-node) and APPLY it in one call, making a " +
        "fresh cluster usable without the CLI. Idempotent: skips if the layout already " +
        "has roles unless force. Composes UpdateClusterLayout + ApplyClusterLayout.",
      arguments: ClusterInitArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ClusterInitArgs.parse(rawArgs);
        const g = context.globalArgs;
        const ts = new Date().toISOString();

        const status = asObj(await api(g, "GET", "GetClusterStatus"));
        const nodeId = a.nodeId ?? String(status.node ?? "");
        if (!nodeId) {
          throw new Error("could not determine nodeId; pass nodeId explicitly");
        }

        const layout = asObj(await api(g, "GET", "GetClusterLayout"));
        if (asArr(layout.roles).length > 0 && !a.force) {
          logInfo(context, "Layout already initialised; unchanged", { nodeId });
          const handle = await context.writeResource("layout-result", nodeId, {
            version: asNum(layout.version),
            applied: false,
            nodeId,
            action: "unchanged",
            timestamp: ts,
          });
          return { dataHandles: [handle] };
        }

        logInfo(context, "Initialising cluster layout", {
          nodeId,
          zone: a.zone,
          capacity: a.capacity,
        });
        await api(g, "POST", "UpdateClusterLayout", {}, {
          roles: [{
            id: nodeId,
            zone: a.zone,
            capacity: a.capacity,
            tags: a.tags,
          }],
          parameters: a.zoneRedundancy
            ? { zoneRedundancy: parseZoneRedundancy(a.zoneRedundancy) }
            : null,
        });
        const version = (asNum(layout.version) ?? 0) + 1;
        const res = asObj(
          await api(g, "POST", "ApplyClusterLayout", {}, { version }),
        );
        const handle = await context.writeResource("layout-result", nodeId, {
          version,
          staged: false,
          applied: true,
          nodeId,
          messages: asArr(res.message).map(String),
          action: "created",
          timestamp: ts,
        });
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
