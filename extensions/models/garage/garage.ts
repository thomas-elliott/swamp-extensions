import { z } from "npm:zod@4";
// Type-only imports, erased at compile time and never bundled. The
// `satisfies ModelDefinition<typeof GlobalArgs>` clause uses them so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";

/**
 * `@thomas/garage`: administration of a Garage (S3-compatible object store)
 * cluster via its **Admin API v2** (`/v2/…`, bearer-token auth). The README
 * lists the Garage versions it works with.
 *
 * SCOPE: this holds the cluster's `admin_token`, so the methods cover the
 * control plane only: buckets, access keys, and key↔bucket permissions. It
 * never touches S3 object data (no GET/PUT/list of objects), and the only
 * destructive verbs (`bucket_delete`, `key_delete`) verify the target by id
 * first.
 *
 * Secrets: `adminToken` is supplied via a vault expression, e.g.
 * `${{ vault.get(<vault>, garage/admin_token) }}`. A created, imported or
 * rotated key's secret is surfaced on the `key-result` resource as
 * `secretAccessKey`. That one field is marked sensitive, so swamp stores the
 * value in a vault and keeps only a vault reference in the data; the other
 * fields stay plain so they can be read and wired with CEL.
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
  timeoutMs: z.coerce.number().int().positive().default(30000).describe(
    "Per-request timeout in milliseconds (AbortController)",
  ),
});

// Resolved global-argument shape. Kept internal: `z.infer` is a "slow type", so it
// must not appear on the public API. The exported {@link ApiFn} seam uses the
// loose {@link Json} instead (same pattern as `@thomas/postgres-admin`).
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

// ─────────────────────────── data names ───────────────────────────

/**
 * Data name for a record. swamp keys stored data by model + name, not by spec,
 * so every name starts with its spec: otherwise `bucket` and `bucket-result` for
 * the same bucket id would overwrite each other. Keys are usually Garage's hex
 * ids, but a delete of an id that is already gone records the id as typed, so
 * the characters swamp rejects are percent-escaped.
 */
function dataName(spec: string, key?: string): string {
  if (key === undefined) return spec;
  const safeKey = key
    .replaceAll("%", "%25")
    .replaceAll("/", "%2F")
    .replaceAll("\\", "%5C")
    .replaceAll("\0", "%00")
    .replaceAll("..", ".%2E");
  return `${spec}:${safeKey}`;
}

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
  buckets: z.array(KeyBucketAccess).optional().describe(
    "Buckets this key can reach (populated only by key_get; key_list leaves it empty)",
  ),
  // Present only on key_get with showSecretKey; vaulted like key-result's.
  secretAccessKey: z.string().meta({ sensitive: true }).nullable().optional(),
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
  /** Set on create, import and rotate. Sensitive: swamp stores the value in a
   * vault and persists only the vault reference here. */
  secretAccessKey: z.string().meta({ sensitive: true }).nullable().optional(),
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

/** A JSON object: the resolved global args or a request body. */
export type Json = Record<string, unknown>;

/**
 * Low-level Admin API call seam. `g` is typed loosely as {@link Json} so this
 * EXPORTED type passes "fast-check" (referencing the zod-inferred global-args
 * type would put a slow type on the public API). Returns the parsed JSON body
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
  const timeoutMs = Number(g.timeoutMs);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res: Response;
  let text: string;
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
    // The body is read under the same timer: a server that sends its headers
    // and then stalls would otherwise hang the method.
    text = await res.text();
  } catch (e) {
    // A bare fetch error ("signal has been aborted", a TypeError) does not
    // say which call failed or that it was our timeout.
    const cause = ctrl.signal.aborted
      ? `timed out after ${timeoutMs} ms`
      : (e as Error).message;
    throw new Error(`Garage ${op} failed: ${cause}`);
  } finally {
    clearTimeout(timer);
  }
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

/**
 * A key's permissions on a bucket, read from the bucket that AllowBucketKey and
 * DenyBucketKey return. Those calls leave a permission unchanged when its flag
 * is false, so the request alone does not say what the key now holds. A key
 * missing from the bucket's list holds nothing.
 */
function keyPermsOn(
  bucket: unknown,
  accessKeyId: string,
): { read: boolean; write: boolean; owner: boolean } {
  const key = asArr(asObj(bucket).keys).map(asObj)
    .find((k) => k.accessKeyId === accessKeyId);
  const p = asObj(key?.permissions);
  return {
    read: asBool(p.read),
    write: asBool(p.write),
    owner: asBool(p.owner),
  };
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

/** True when `e` is an Admin API error with this HTTP status (see {@link realApi}). */
function isHttpStatus(e: unknown, status: number): boolean {
  return (e as Error)?.message?.includes(`(HTTP ${status})`) ?? false;
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
  // Garage rejects more than one selector.
  (a) => [a.id, a.globalAlias, a.search].filter(Boolean).length === 1,
  { message: "provide exactly one of id, globalAlias, or search" },
);

const KeyGetArgs = z.object({
  id: z.string().optional().describe("Access key id (exact)"),
  search: z.string().optional().describe("Partial id/name to search"),
  showSecretKey: z.boolean().default(false).describe(
    "Include the secret access key in output (sensitive: stored in a vault, the data keeps a reference)",
  ),
}).refine(
  // Garage rejects both together.
  (a) => [a.id, a.search].filter(Boolean).length === 1,
  { message: "provide exactly one of id or search" },
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
  localAliasRead: z.boolean().default(false).describe(
    "Grant the local alias's key read on the new bucket",
  ),
  localAliasWrite: z.boolean().default(false).describe(
    "Grant the local alias's key write on the new bucket",
  ),
  localAliasOwner: z.boolean().default(false).describe(
    "Grant the local alias's key owner on the new bucket",
  ),
}).refine(
  (a) => !!(a.globalAlias || a.localAlias),
  { message: "provide globalAlias or localAlias" },
).refine(
  (a) => !a.localAlias || !!a.localAliasAccessKeyId,
  { message: "localAlias requires localAliasAccessKeyId" },
).refine(
  // Without a local alias there is no key to grant to.
  (a) =>
    !!a.localAlias ||
    !(a.localAliasRead || a.localAliasWrite || a.localAliasOwner),
  { message: "localAliasRead/Write/Owner need localAlias" },
);

const BucketUpdateArgs = z.object({
  id: z.string().describe("Bucket id to update"),
  maxObjects: z.coerce.number().int().nonnegative().nullable().optional()
    .describe(
      "Object-count quota; null clears it",
    ),
  maxSize: z.coerce.number().int().nonnegative().nullable().optional().describe(
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
  // With both, one would be silently ignored.
  (a) => [a.globalAlias, a.localAlias].filter(Boolean).length === 1,
  { message: "provide exactly one of globalAlias or localAlias" },
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
  neverExpires: z.boolean().default(true).describe(
    "Key never expires. false needs expiration: a new key has no expiry otherwise.",
  ),
}).refine(
  // A new key has no expiry until one is set, so false alone would still
  // create a key that never expires.
  (a) => a.neverExpires || !!a.expiration,
  { message: "neverExpires=false needs expiration" },
);

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
  neverExpires: z.boolean().optional().describe(
    "true clears the expiry. false does nothing; set expiration instead.",
  ),
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
  zone: z.string().optional().describe(
    "Zone/datacenter label for the node. Omit to keep the node's current zone " +
      "(required for a node that has no role yet).",
  ),
  capacity: z.coerce.number().int().nonnegative().nullable().optional()
    .describe(
      "Storage capacity in BYTES (e.g. 1000000000 = 1 GB). null = gateway (no storage). " +
        "Omit to keep the node's current capacity (gateway for a node with no role yet).",
    ),
  tags: z.array(z.string()).optional().describe(
    "Node tags. Omit to keep the node's current tags (none for a node with no role yet).",
  ),
  zoneRedundancy: z.string().optional().describe(
    'Cluster zone redundancy: "maximum" or a positive integer (atLeast N). Omit to leave unchanged.',
  ),
});

const LayoutApplyArgs = z.object({
  version: z.coerce.number().int().nonnegative().optional().describe(
    "Layout version to apply; defaults to current + 1 (the staged version)",
  ),
});

const ClusterInitArgs = z.object({
  nodeId: z.string().optional().describe(
    "Node to configure; defaults to the responding node (correct for a single-node cluster)",
  ),
  zone: z.string().default("dc1").describe("Zone/datacenter label"),
  capacity: z.coerce.number().int().nonnegative().describe(
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
  if (/^[1-9]\d*$/.test(s)) return { atLeast: Number(s) };
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

/**
 * Id and Garage version of the node answering our requests. GetClusterStatus
 * lists every node but does not say which one we are talking to, and has no
 * top-level version; GetNodeInfo?node=self has both, as a per-node response
 * map keyed by node id.
 */
async function selfNodeInfo(
  g: GlobalArgsT,
): Promise<{ id: string; garageVersion?: string }> {
  const raw = asObj(await api(g, "GET", "GetNodeInfo", { node: "self" }));
  const info = asObj(Object.values(asObj(raw.success))[0]);
  const id = asStr(info.nodeId);
  if (!id) {
    throw new Error(
      `GetNodeInfo?node=self returned no node: ${
        JSON.stringify(raw.error ?? raw)
      }`,
    );
  }
  return { id, garageVersion: asStr(info.garageVersion) };
}

/** Shape a raw GetClusterStatus response into a {@link ClusterStatus}. */
function shapeStatus(
  raw: unknown,
  self: { id: string; garageVersion?: string },
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
    node: self.id,
    garageVersion: self.garageVersion,
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

/**
 * GetBucketInfo by id for a bucket just seen in ListBuckets, or `undefined` if
 * it has been deleted since (Garage answers 404). One bucket going away during
 * a listing must not fail the whole listing.
 */
async function getListedBucketRaw(
  g: GlobalArgsT,
  id: string,
): Promise<Record<string, unknown> | undefined> {
  return await getBucketRaw(g, { id }).catch((e: Error) => {
    if (isHttpStatus(e, 404)) return undefined;
    throw e;
  });
}

/**
 * Whether an alias is on a bucket, judged from its GetBucketInfo. Garage
 * lists a key on a bucket only when the key has a permission there, so a local
 * alias of a key with none is invisible: that case is "unknown", and the
 * caller lets Garage decide.
 */
function aliasOnBucket(
  bucket: Record<string, unknown>,
  a: { globalAlias?: string; localAlias?: string; accessKeyId?: string },
): "present" | "absent" | "unknown" {
  if (a.globalAlias) {
    return asArr(bucket.globalAliases).map(String).includes(a.globalAlias)
      ? "present"
      : "absent";
  }
  const key = asArr(bucket.keys).map(asObj).find((k) =>
    k.accessKeyId === a.accessKeyId
  );
  if (!key) return "unknown";
  return asArr(key.bucketLocalAliases).map(String).includes(
      a.localAlias ?? "",
    )
    ? "present"
    : "absent";
}

/**
 * The error for a key that Garage created but swamp failed to record (for
 * example, no vault for the secret). The key exists and works, so the caller
 * needs its id to recover the secret or remove the key.
 */
function keyNotRecorded(accessKeyId: string, cause: Error): Error {
  return new Error(
    `Key ${accessKeyId} was created in Garage but recording it failed ` +
      `(${cause.message}). Read its secret with key_get id=${accessKeyId} ` +
      "showSecretKey=true, or remove it with key_delete.",
  );
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
  version: "2026.10.11.1",
  globalArguments: GlobalArgs,
  upgrades: [
    {
      toVersion: "2026.10.11.1",
      description:
        "timeoutMs must now be positive; a zero or negative value is dropped so the 30000 ms default applies. Stored data is renamed to <spec>:<id> (or <spec>); the four specs that shared `main` and the specs that shared a bare id now have names of their own. Records under the old names are left as they are and are not migrated. key-result vaults only secretAccessKey; its other fields are plain values.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => {
        // Zero or negative aborted every request at once, so nobody relied on it.
        if (Number(old.timeoutMs) <= 0) {
          const { timeoutMs: _, ...rest } = old;
          return rest;
        }
        return old;
      },
    },
  ],
  checks: {
    "reachable": {
      description:
        "Verify the Garage Admin API is reachable (GET /v2/GetClusterHealth)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        // Checks get globalArgs without the schema's defaults; parse to apply them.
        const parsed = GlobalArgs.safeParse(context.globalArgs);
        if (!parsed.success) {
          return { pass: false, errors: [z.prettifyError(parsed.error)] };
        }
        const g = parsed.data;
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
        "Result of a key create/import/update/rotate/delete (may carry the secret, vaulted)",
      // Only secretAccessKey is secret, and its field-level sensitive mark
      // vaults it. Marking the whole output sensitive would also turn the key
      // id, name and action into vault references, which CEL and scripts
      // cannot read, and would need a vault for writes that carry no secret.
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
        const handle = await context.writeResource(
          "cluster-health",
          dataName("cluster-health"),
          {
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
          },
        );
        logInfo(context, "Fetched cluster health", {
          status: String(raw.status ?? "unknown"),
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
          const raw = await getListedBucketRaw(g, id);
          if (!raw) continue;
          handles.push(
            await context.writeResource(
              "bucket",
              dataName("bucket", id),
              shapeBucket(raw, "observed", ts),
            ),
          );
        }
        logInfo(context, "Listed buckets", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    bucket_get: {
      description:
        "Get one bucket by exactly one of id, globalAlias or search (full detail). Read-only.",
      arguments: BucketGetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BucketGetArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Fetching bucket", a);
        const raw = await getBucketRaw(g, a);
        const shaped = shapeBucket(raw, "observed", new Date().toISOString());
        const handle = await context.writeResource(
          "bucket",
          dataName("bucket", shaped.id),
          shaped,
        );
        logInfo(context, "Fetched bucket", { id: shaped.id });
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
            await context.writeResource("key", dataName("key", id), {
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
        logInfo(context, "Listed keys", { count: handles.length });
        return { dataHandles: handles };
      },
    },

    key_get: {
      description:
        "Get one access key by exactly one of id or search, with the buckets it can reach. " +
        "Set showSecretKey to reveal the secret (sensitive). Read-only.",
      arguments: KeyGetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyGetArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Fetching key", { id: a.id, search: a.search });
        const raw = await getKeyRaw(g, a);
        const shaped = shapeKey(raw, "observed", new Date().toISOString());
        const handle = await context.writeResource(
          "key",
          dataName("key", shaped.accessKeyId),
          shaped,
        );
        logInfo(context, "Fetched key", { id: shaped.accessKeyId });
        return { dataHandles: [handle] };
      },
    },

    permissions_audit: {
      description:
        "Build the full key×bucket permission matrix and risk flags (orphan keys, " +
        "owner-everywhere, website-exposed buckets, expired keys). Read-only.",
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
        // Buckets deleted between ListBuckets and GetBucketInfo are left out,
        // so count the ones actually audited.
        let bucketCount = 0;

        for (const b of buckets) {
          const id = String(asObj(b).id ?? "");
          if (!id) continue;
          const raw = await getListedBucketRaw(g, id);
          if (!raw) continue;
          bucketCount += 1;
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

        const handle = await context.writeResource(
          "permission-audit",
          dataName("permission-audit"),
          {
            entries,
            bucketCount,
            keyCount: keys.length,
            grantCount: entries.length,
            flags: { orphanKeys, ownerEverywhere, websiteBuckets, expiredKeys },
            s3Region: g.s3Region,
            timestamp: ts,
          },
        );
        logInfo(context, "Audited permissions", {
          buckets: bucketCount,
          keys: keys.length,
          grants: entries.length,
        });
        return { dataHandles: [handle] };
      },
    },

    // ───────────── buckets (mutating) ─────────────
    bucket_create: {
      description:
        "Create a bucket with a global (or local) alias. Idempotent on globalAlias: " +
        "an existing one is returned as `unchanged`. A local alias's key gets " +
        "only the permissions set with localAliasRead/Write/Owner (none by default).",
      arguments: BucketCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BucketCreateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const ts = new Date().toISOString();

        if (a.globalAlias) {
          // Garage answers an unknown alias with 404 NoSuchBucket; any other
          // error is a real failure and must not look like "free to create".
          const existing = await api(g, "GET", "GetBucketInfo", {
            globalAlias: a.globalAlias,
          }).catch((e: Error) => {
            if (isHttpStatus(e, 404)) return undefined;
            throw e;
          });
          if (existing && asObj(existing).id) {
            logInfo(context, "Bucket alias already exists; unchanged", {
              globalAlias: a.globalAlias,
            });
            const handle = await context.writeResource(
              "bucket-result",
              dataName("bucket-result", String(asObj(existing).id)),
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
            // Garage grants the alias's key nothing unless asked.
            allow: {
              read: a.localAliasRead,
              write: a.localAliasWrite,
              owner: a.localAliasOwner,
            },
          };
        }
        logInfo(context, "Creating bucket", {
          globalAlias: a.globalAlias,
          localAlias: a.localAlias,
        });
        const raw = asObj(await api(g, "POST", "CreateBucket", {}, body));
        const handle = await context.writeResource(
          "bucket-result",
          // Named by id, not alias: a local alias is only unique per key.
          dataName("bucket-result", String(raw.id)),
          {
            id: asStr(raw.id),
            alias: a.globalAlias ?? a.localAlias,
            action: "created",
            timestamp: ts,
          },
        );
        logInfo(context, "Created bucket", { id: asStr(raw.id) });
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
        const quotaChange = a.maxObjects !== undefined ||
          a.maxSize !== undefined;
        const websiteChange = a.websiteEnabled !== undefined ||
          a.indexDocument !== undefined || a.errorDocument !== undefined;
        if (!quotaChange && !websiteChange) {
          throw new Error(
            "nothing to update: provide maxObjects/maxSize or websiteEnabled",
          );
        }

        // Garage replaces the whole quotas object and the whole websiteAccess
        // object when either is present in the body, so an argument the caller
        // left out has to be refilled from the bucket's current state or it is
        // silently cleared.
        const current = await getBucketRaw(g, { id: a.id });
        const body: Json = {};
        if (quotaChange) {
          const q = asObj(current.quotas);
          body.quotas = {
            maxObjects: a.maxObjects !== undefined
              ? a.maxObjects
              : nullableNum(q.maxObjects) ?? null,
            maxSize: a.maxSize !== undefined
              ? a.maxSize
              : nullableNum(q.maxSize) ?? null,
          };
        }
        if (websiteChange) {
          const enabled = a.websiteEnabled ?? asBool(current.websiteAccess);
          if (enabled) {
            const w = asObj(current.websiteConfig);
            const indexDocument = a.indexDocument ?? asStr(w.indexDocument);
            // Garage refuses to enable a website without an index document.
            if (!indexDocument) {
              throw new Error(
                `bucket ${a.id} has no index document; pass indexDocument to enable the website`,
              );
            }
            body.websiteAccess = {
              enabled: true,
              indexDocument,
              errorDocument: a.errorDocument ?? asStr(w.errorDocument) ?? null,
            };
          } else {
            // Garage rejects documents on a disable, and dropping them
            // silently would hide that they were not set.
            if (
              a.indexDocument !== undefined || a.errorDocument !== undefined
            ) {
              throw new Error(
                `website serving is off for bucket ${a.id}; documents can only be ` +
                  "set with websiteEnabled=true",
              );
            }
            body.websiteAccess = { enabled: false };
          }
        }
        logInfo(context, "Updating bucket", { id: a.id });
        await api(g, "POST", "UpdateBucket", { id: a.id }, body);
        const handle = await context.writeResource(
          "bucket-result",
          dataName("bucket-result", a.id),
          {
            id: a.id,
            action: "updated",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Updated bucket", { id: a.id });
        return { dataHandles: [handle] };
      },
    },

    bucket_delete: {
      description:
        "Delete a bucket BY ID (verified to exist first; refuses a non-empty bucket " +
        "unless allowNonEmpty, and Garage itself also refuses non-empty). A bucket " +
        "that is already gone is recorded as `unchanged`. Destructive.",
      arguments: BucketDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = BucketDeleteArgs.parse(rawArgs);
        const g = context.globalArgs;
        const raw = await getBucketRaw(g, { id: a.id }).catch((e: Error) => {
          if (isHttpStatus(e, 404)) return undefined;
          throw e;
        });
        // Already gone: the goal of the call holds, so a re-run succeeds.
        // The record carries the id, so a mistyped one still shows.
        if (!raw) {
          logInfo(context, "Bucket already gone; unchanged", { id: a.id });
          const handle = await context.writeResource(
            "bucket-result",
            dataName("bucket-result", a.id),
            {
              id: a.id,
              action: "unchanged",
              timestamp: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
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
        const handle = await context.writeResource(
          "bucket-result",
          dataName("bucket-result", a.id),
          {
            id: a.id,
            alias: asArr(raw.globalAliases).map(String)[0],
            action: "deleted",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Deleted bucket", { id: a.id });
        return { dataHandles: [handle] };
      },
    },

    bucket_alias_add: {
      description:
        "Add a global or local alias to a bucket (AddBucketAlias). An alias " +
        "already on the bucket records `unchanged`.",
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
        // Garage accepts a repeat add silently, so check first to report it.
        const bucket = await getBucketRaw(g, { id: a.bucketId });
        const present = aliasOnBucket(bucket, a) === "present";
        if (present) {
          logInfo(context, "Bucket alias already present", body);
        } else {
          logInfo(context, "Adding bucket alias", body);
          await api(g, "POST", "AddBucketAlias", {}, body);
          logInfo(context, "Added bucket alias", { bucketId: a.bucketId });
        }
        const handle = await context.writeResource(
          "bucket-result",
          dataName("bucket-result", a.bucketId),
          {
            id: a.bucketId,
            alias: a.globalAlias ?? a.localAlias,
            action: present ? "unchanged" : "updated",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    bucket_alias_remove: {
      description:
        "Remove a global or local alias from a bucket (RemoveBucketAlias). " +
        "An alias already gone records `unchanged`, except a local alias of " +
        "a key with no permission on the bucket, which Garage does not show: " +
        "that fails with Garage's error.",
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
        // An alias already gone succeeds, like bucket_delete of a gone bucket.
        // Garage answers that case with a 500, so check first instead.
        const bucket = await getBucketRaw(g, { id: a.bucketId });
        const absent = aliasOnBucket(bucket, a) === "absent";
        if (absent) {
          logInfo(context, "Bucket alias already absent", body);
        } else {
          logInfo(context, "Removing bucket alias", body);
          await api(g, "POST", "RemoveBucketAlias", {}, body);
          logInfo(context, "Removed bucket alias", { bucketId: a.bucketId });
        }
        const handle = await context.writeResource(
          "bucket-result",
          dataName("bucket-result", a.bucketId),
          {
            id: a.bucketId,
            alias: a.globalAlias ?? a.localAlias,
            action: absent ? "unchanged" : "updated",
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ───────────── keys (mutating) ─────────────
    key_create: {
      description:
        "Create a new access key. The secret is returned on `key-result` " +
        "(sensitive, vaulted); later it can be read only with key_get " +
        "showSecretKey. Capture it and store it in 1Password.",
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
        const accessKeyId = String(raw.accessKeyId);
        const handle = await context.writeResource(
          "key-result",
          dataName("key-result", accessKeyId),
          {
            accessKeyId,
            name: asStr(raw.name) ?? a.name,
            secretAccessKey: asStr(raw.secretAccessKey) ?? null,
            action: "created",
            timestamp: new Date().toISOString(),
          },
        ).catch((e: Error) => {
          throw keyNotRecorded(accessKeyId, e);
        });
        logInfo(context, "Created key", { accessKeyId });
        return { dataHandles: [handle] };
      },
    },

    key_import: {
      description:
        "Import a pre-existing access key pair (ImportKey) — e.g. to recreate a key " +
        "with a known secret after a cluster rebuild. Idempotent: a key that " +
        "already exists with the same secret is returned as `unchanged`.",
      arguments: KeyImportArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyImportArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Importing key", { accessKeyId: a.accessKeyId }); // never logs the secret
        let action: "imported" | "unchanged" = "imported";
        const raw = asObj(
          await api(g, "POST", "ImportKey", {}, {
            accessKeyId: a.accessKeyId,
            secretAccessKey: a.secretAccessKey,
            name: a.name,
          }).catch(async (e: Error) => {
            // Garage answers 409 for an id it already holds. If it holds the
            // same pair, a re-run of this import is already done. A deleted
            // key also answers 409 (its id can never be reused), but
            // GetKeyInfo then says 404; Garage's own error explains that.
            if (!isHttpStatus(e, 409)) throw e;
            const existing = await getKeyRaw(g, {
              id: a.accessKeyId,
              showSecretKey: true,
            }).catch((lookup: Error) => {
              throw isHttpStatus(lookup, 404) ? e : lookup;
            });
            if (existing.secretAccessKey !== a.secretAccessKey) {
              throw new Error(
                `Key ${a.accessKeyId} already exists with a different secret`,
              );
            }
            action = "unchanged";
            // The secret stays here: key-result records none for an import.
            return { accessKeyId: existing.accessKeyId, name: existing.name };
          }),
        );
        const handle = await context.writeResource(
          "key-result",
          dataName("key-result", String(raw.accessKeyId ?? a.accessKeyId)),
          {
            accessKeyId: asStr(raw.accessKeyId) ?? a.accessKeyId,
            name: asStr(raw.name) ?? a.name,
            action,
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Imported key", {
          accessKeyId: a.accessKeyId,
          action,
        });
        return { dataHandles: [handle] };
      },
    },

    key_update: {
      description:
        "Update a key's name, create-bucket permission, and/or expiry (UpdateKey). " +
        "neverExpires=true clears the expiry; neverExpires=false does nothing.",
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
        // Garage reads a missing neverExpires as false, which changes nothing,
        // so false is not a change and must not count as one below.
        if (a.neverExpires) body.neverExpires = true;
        if (Object.keys(body).length === 0) {
          throw new Error(
            "nothing to update: provide name, allowCreateBucket, expiration, or neverExpires",
          );
        }
        logInfo(context, "Updating key", { id: a.id });
        const raw = asObj(
          await api(g, "POST", "UpdateKey", { id: a.id }, body),
        );
        const handle = await context.writeResource(
          "key-result",
          dataName("key-result", a.id),
          {
            accessKeyId: a.id,
            name: asStr(raw.name) ?? a.name,
            action: "updated",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Updated key", { id: a.id });
        return { dataHandles: [handle] };
      },
    },

    key_rotate: {
      description:
        "Rotate a key: create a NEW key, copy the OLD key's bucket grants and " +
        "local aliases onto it, and return the new secret (sensitive, vaulted). " +
        "The new key keeps the old key's expiry, so an expired key is refused. If a grant or alias cannot be " +
        "copied, the new key is deleted again and the method fails. Does NOT " +
        "delete the old key: update consumers, then call key_delete on the old id.",
      arguments: KeyRotateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyRotateArgs.parse(rawArgs);
        const g = context.globalArgs;
        const ts = new Date().toISOString();

        const oldKey = await getKeyRaw(g, { id: a.id }).catch((e: Error) => {
          if (isHttpStatus(e, 404)) {
            throw new Error(`Key ${JSON.stringify(a.id)} not found`);
          }
          throw e;
        });
        const oldName = asStr(oldKey.name);
        const oldPerm = asObj(oldKey.permissions);
        const oldExpiration = asStr(oldKey.expiration);
        // The new key takes the old key's expiry, so it would be born expired.
        if (asBool(oldKey.expired)) {
          throw new Error(
            `Key ${a.id} expired at ${oldExpiration}; its replacement would ` +
              "be expired too. Give it a new expiration with key_update first.",
          );
        }

        logInfo(context, "Rotating key: creating replacement", { oldId: a.id });
        const created = asObj(
          await api(g, "POST", "CreateKey", {}, {
            name: a.name ?? `${oldName ?? a.id} (rotated)`,
            allow: { createBucket: asBool(oldPerm.createBucket) },
            ...(oldExpiration
              ? { expiration: oldExpiration }
              : { neverExpires: true }),
          }),
        );
        const newId = String(created.accessKeyId ?? "");
        if (!newId) {
          throw new Error("Rotation failed: no new accessKeyId returned");
        }

        let copied = 0;
        let aliases = 0;
        try {
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
            // Local aliases belong to a key, so a client that addresses the
            // bucket by one would get NoSuchBucket under the new key.
            for (const localAlias of asArr(bb.localAliases).map(String)) {
              await api(g, "POST", "AddBucketAlias", {}, {
                bucketId,
                localAlias,
                accessKeyId: newId,
              });
              aliases += 1;
            }
          }
        } catch (e) {
          // No one holds the new key yet, and it carries only part of the old
          // key's access. Remove it rather than leave a half-copied key.
          const cleanup = await api(g, "POST", "DeleteKey", { id: newId })
            .then(() => "the new key was deleted again")
            .catch((d: Error) =>
              `deleting the new key ${newId} also failed (${d.message}); ` +
              "delete it by hand"
            );
          throw new Error(
            `Rotation failed copying grants and aliases: ${
              (e as Error).message
            }; ${cleanup}`,
          );
        }
        logInfo(context, "Rotation: copied grants and aliases", {
          newId,
          grants: copied,
          localAliases: aliases,
        });

        const handle = await context.writeResource(
          "key-result",
          dataName("key-result", newId),
          {
            accessKeyId: newId,
            name: asStr(created.name),
            secretAccessKey: asStr(created.secretAccessKey) ?? null,
            action: "rotated",
            timestamp: ts,
          },
        ).catch((e: Error) => {
          throw keyNotRecorded(newId, e);
        });
        logInfo(context, "Rotated key", { oldId: a.id, newId });
        return { dataHandles: [handle] };
      },
    },

    key_delete: {
      description:
        "Delete an access key BY ID (verified to exist first). A key that is " +
        "already gone is recorded as `unchanged`. Destructive — any client using " +
        "it loses access immediately.",
      arguments: KeyDeleteArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = KeyDeleteArgs.parse(rawArgs);
        const g = context.globalArgs;
        const raw = await getKeyRaw(g, { id: a.id }).catch((e: Error) => {
          if (isHttpStatus(e, 404)) return undefined;
          throw e;
        });
        // Already gone: as for bucket_delete, a re-run succeeds and the
        // record carries the id.
        if (!raw) {
          logInfo(context, "Key already gone; unchanged", { id: a.id });
          const handle = await context.writeResource(
            "key-result",
            dataName("key-result", a.id),
            {
              accessKeyId: a.id,
              action: "unchanged",
              timestamp: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        }
        logInfo(context, "Deleting key", { id: a.id });
        await api(g, "POST", "DeleteKey", { id: a.id });
        const handle = await context.writeResource(
          "key-result",
          dataName("key-result", a.id),
          {
            accessKeyId: a.id,
            name: asStr(raw.name),
            action: "deleted",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Deleted key", { id: a.id });
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
        const bucket = await api(g, "POST", "AllowBucketKey", {}, {
          bucketId: a.bucketId,
          accessKeyId: a.accessKeyId,
          permissions: { read: a.read, write: a.write, owner: a.owner },
        });
        const held = keyPermsOn(bucket, a.accessKeyId);
        const handle = await context.writeResource(
          "permission-result",
          dataName("permission-result", `${a.bucketId}:${a.accessKeyId}`),
          {
            bucketId: a.bucketId,
            accessKeyId: a.accessKeyId,
            ...held,
            action: "granted",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Allowed key on bucket", held);
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
        const bucket = await api(g, "POST", "DenyBucketKey", {}, {
          bucketId: a.bucketId,
          accessKeyId: a.accessKeyId,
          permissions: { read: a.read, write: a.write, owner: a.owner },
        });
        const held = keyPermsOn(bucket, a.accessKeyId);
        const handle = await context.writeResource(
          "permission-result",
          dataName("permission-result", `${a.bucketId}:${a.accessKeyId}`),
          {
            bucketId: a.bucketId,
            accessKeyId: a.accessKeyId,
            ...held,
            action: "denied",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Denied key on bucket", held);
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
        const self = await selfNodeInfo(g);
        const handle = await context.writeResource(
          "cluster-status",
          dataName("cluster-status"),
          shapeStatus(raw, self, "observed", new Date().toISOString()),
        );
        logInfo(context, "Fetched cluster status", {
          node: self.id,
          nodes: asArr(asObj(raw).nodes).length,
        });
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
        logInfo(context, "Fetching cluster layout");
        const raw = await api(g, "GET", "GetClusterLayout");
        const layout = shapeLayout(raw, "observed", new Date().toISOString());
        const handle = await context.writeResource(
          "cluster-layout",
          dataName("cluster-layout"),
          layout,
        );
        logInfo(context, "Fetched cluster layout", {
          version: layout.version,
          roles: layout.roles.length,
          staged: layout.stagedChanges.length,
        });
        return { dataHandles: [handle] };
      },
    },

    layout_assign: {
      description:
        "STAGE a role for a node (zone, storage capacity in bytes or null for gateway, " +
        "tags). Anything omitted keeps the node's current value, staged or applied; " +
        "a node with no role yet needs a zone and defaults to gateway. Stages only — " +
        "review with layout_get, then commit with layout_apply.",
      arguments: LayoutAssignArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = LayoutAssignArgs.parse(rawArgs);
        const g = context.globalArgs;

        // A role change replaces the node's whole role (zone, capacity and
        // tags together), so whatever the caller left out is taken from the
        // role the node holds now. Garage keeps one staged change per node and
        // a new one overwrites it, so a role already staged for the node wins
        // over its applied role; otherwise a second call would silently undo
        // the first. A staged removal carries no role, so it falls through to
        // the applied one. A node with no role at all has nothing to carry
        // over: it needs a zone, and omitted capacity means gateway.
        const layout = asObj(await api(g, "GET", "GetClusterLayout"));
        const stagedRole = asArr(layout.stagedRoleChanges).map(asObj).find((
          c,
        ) => c.id === a.nodeId && c.remove !== true);
        const role = stagedRole ??
          asArr(layout.roles).map(asObj).find((r) => r.id === a.nodeId);
        const zone = a.zone ?? (role ? asStr(role.zone) : undefined);
        if (!zone) {
          throw new Error(
            `node ${a.nodeId} has no role in the current layout; pass zone`,
          );
        }
        const capacity = a.capacity !== undefined
          ? a.capacity
          : (role ? nullableNum(role.capacity) ?? null : null);
        const tags = a.tags ?? (role ? asArr(role.tags).map(String) : []);
        const body: Json = {
          roles: [{ id: a.nodeId, zone, capacity, tags }],
          parameters: a.zoneRedundancy
            ? { zoneRedundancy: parseZoneRedundancy(a.zoneRedundancy) }
            : null,
        };
        logInfo(context, "Staging layout role", { nodeId: a.nodeId, zone });
        await api(g, "POST", "UpdateClusterLayout", {}, body);
        const handle = await context.writeResource(
          "layout-result",
          dataName("layout-result", a.nodeId),
          {
            nodeId: a.nodeId,
            staged: true,
            applied: false,
            action: "staged",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Staged layout role", { nodeId: a.nodeId });
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
        // A zoneRedundancy change is staged on its own, with no role change.
        const staged = asArr(layout.stagedRoleChanges).length > 0 ||
          (layout.stagedParameters !== undefined &&
            layout.stagedParameters !== null);
        if (!staged && a.version === undefined) {
          throw new Error("no staged layout changes to apply");
        }
        const version = a.version ?? (asNum(layout.version) ?? 0) + 1;
        logInfo(context, "Applying layout", { version });
        const res = asObj(
          await api(g, "POST", "ApplyClusterLayout", {}, { version }),
        );
        const handle = await context.writeResource(
          "layout-result",
          // "apply-" keeps a version number apart from a node id.
          dataName("layout-result", `apply-${version}`),
          {
            version,
            staged: false,
            applied: true,
            messages: asArr(res.message).map(String),
            action: "applied",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Applied layout", { version });
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
        const handle = await context.writeResource(
          "layout-result",
          dataName("layout-result", "revert"),
          {
            staged: false,
            applied: false,
            action: "reverted",
            timestamp: new Date().toISOString(),
          },
        );
        logInfo(context, "Reverted staged layout changes");
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

        const nodeId = a.nodeId ?? (await selfNodeInfo(g)).id;

        const layout = asObj(await api(g, "GET", "GetClusterLayout"));
        if (asArr(layout.roles).length > 0 && !a.force) {
          logInfo(context, "Layout already initialised; unchanged", { nodeId });
          const handle = await context.writeResource(
            "layout-result",
            dataName("layout-result", nodeId),
            {
              version: asNum(layout.version),
              applied: false,
              nodeId,
              action: "unchanged",
              timestamp: ts,
            },
          );
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
          await api(g, "POST", "ApplyClusterLayout", {}, { version }).catch(
            (e: Error) => {
              // The role was staged above and stays staged after a failed
              // apply; say so, or a later layout change would carry it along.
              throw new Error(
                `${e.message}; the role for ${nodeId} is still staged: run ` +
                  "layout_revert to discard it or layout_apply to retry",
              );
            },
          ),
        );
        const handle = await context.writeResource(
          "layout-result",
          dataName("layout-result", nodeId),
          {
            version,
            staged: false,
            applied: true,
            nodeId,
            messages: asArr(res.message).map(String),
            action: "created",
            timestamp: ts,
          },
        );
        logInfo(context, "Initialised cluster layout", { nodeId, version });
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
