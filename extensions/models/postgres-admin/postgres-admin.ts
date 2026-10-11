import { z } from "npm:zod@4";
// Type-only imports, erased at compile time and never bundled. They type the
// `satisfies ModelDefinition<typeof GlobalArgs>` clause so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";
// `pg` ships no bundled types; point the type-checker (and `deno doc`, which the
// quality scorer runs) at the DefinitelyTyped package so it can resolve them.
// @ts-types="npm:@types/pg@8.21.0"
import pg from "npm:pg@8.21.0";

/**
 * `@thomas/postgres-admin`: non-destructive PostgreSQL administration over a
 * direct TCP connection (node-postgres).
 *
 * Scope: the extension holds an admin credential, so its methods are limited
 * and leave data alone. It never reads or writes table rows (no
 * SELECT/INSERT/UPDATE/DELETE against user tables), never drops a database or
 * role, never truncates, and has no arbitrary-SQL method. Every method issues
 * author-controlled DDL or catalog reads (pg_catalog / information_schema)
 * only. Read methods also run under `default_transaction_read_only = on`, so
 * the server rejects any write.
 *
 * Connection: one short-lived `pg.Client` per method run (connect → work →
 * `end()` in a `finally`); no pool, because swamp already serialises runs per model.
 *
 * Identifier safety: identifiers (db/role/schema/table names) are validated
 * against `identifierPattern` AND escaped via `client.escapeIdentifier`; the role
 * password verifier is embedded only via `client.escapeLiteral` (DDL can't parameterise an
 * identifier or a PASSWORD literal). Filter VALUES in catalog reads use bound `$1`
 * params. Passwords are marked sensitive, never logged, never echoed in output.
 * A role password is hashed here to a SCRAM-SHA-256 verifier before it is sent,
 * so the plain text is never on the wire, in `pg_stat_activity` or in a server
 * statement log.
 *
 * Secrets: `adminPassword` (and per-call role passwords) are supplied via vault
 * expressions, e.g. `${{ vault.get(<vault>, postgres/admin_password) }}`.
 */

// ─────────────────────────── global arguments ───────────────────────────

const SslConfig = z.object({
  mode: z.enum(["disable", "require", "verify-ca", "verify-full"]).default(
    "disable",
  ).describe(
    "disable = plaintext TCP (the default). require = encrypt, no " +
      "cert verify. verify-ca = encrypt + verify the cert chain against `ca`, " +
      "not the host name. verify-full = verify-ca plus the host name.",
  ),
  ca: z.string().optional().describe(
    "PEM CA bundle for verify-ca/verify-full",
  ),
  rejectUnauthorized: z.boolean().optional().describe(
    "Override cert verification; derived from `mode` when omitted",
  ),
}).default({ mode: "disable" });

const GlobalArgs = z.object({
  host: z.string().describe(
    "Postgres host or IP, e.g. postgres-host or 192.0.2.10",
  ),
  port: z.coerce.number().int().min(1).max(65535).default(5432).describe(
    "Postgres TCP port",
  ),
  adminUser: z.string().default("postgres").describe(
    "Admin/superuser login role used for every connection",
  ),
  adminPassword: z.string().meta({ sensitive: true }).describe(
    "Admin password. Supply via vault: ${{ vault.get(<vault>, postgres/admin_password) }}",
  ),
  maintenanceDb: z.string().default("postgres").describe(
    "DB to connect to for cluster-wide ops (CREATE DATABASE, role/db catalog reads)",
  ),
  ssl: SslConfig,
  statementTimeoutMs: z.coerce.number().int().min(0).default(30000).describe(
    "statement_timeout (ms) applied per session as a guardrail; 0 turns it off",
  ),
  identifierPattern: z.string().default("^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    .describe(
      "Safe-identifier regex enforced (in addition to escaping) before any DDL",
    ),
});

// Resolved global-argument shape (connection target + safety settings). Kept
// internal: `z.infer` is a "slow type", so it must not appear on the public API
// (the exported `ConnectFn` seam uses the loose `Json` instead; see below).
type GlobalArgsT = z.infer<typeof GlobalArgs>;

const Action = z.enum([
  "created",
  "unchanged",
  "updated",
  "granted",
  "revoked",
  "rotated",
  "observed",
]);

/** Grantable privileges this extension will emit. Bounds the `privileges` arg
 * (Zod rejects anything outside it). TRUNCATE and ALL are excluded on purpose. */
const Privilege = z.enum([
  "CONNECT",
  "CREATE",
  "TEMP",
  "TEMPORARY",
  "USAGE",
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "REFERENCES",
  "TRIGGER",
]);

/** Table-level privileges: the allowed set for app_provision's `tablePrivs`. */
const TablePrivilege = z.enum([
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "REFERENCES",
  "TRIGGER",
]);

// ─────────────────────────── resource schemas ───────────────────────────

const DatabaseInfo = z.object({
  name: z.string(),
  owner: z.string(),
  encoding: z.string(),
  collate: z.string().optional(),
  ctype: z.string().optional(),
  sizeBytes: z.number().optional(),
  isTemplate: z.boolean().optional(),
  allowConn: z.boolean().optional(),
  action: Action,
  timestamp: z.string(),
});

const RoleInfo = z.object({
  name: z.string(),
  login: z.boolean(),
  superuser: z.boolean(),
  createDb: z.boolean(),
  createRole: z.boolean(),
  replication: z.boolean().optional(),
  bypassRls: z.boolean().optional(),
  connLimit: z.number(),
  validUntil: z.string().optional(),
  memberOf: z.array(z.string()),
  action: Action,
  timestamp: z.string(),
});

const TableGrant = z.object({
  schema: z.string(),
  name: z.string(),
  privilege: z.string(),
  // Without these, an all-roles audit shows one identical-looking row per
  // grantee and cannot say who holds a grant.
  grantee: z.string(),
  grantor: z.string(),
  grantable: z.boolean().optional(),
});

const SchemaPriv = z.object({
  schema: z.string(),
  usage: z.boolean(),
  create: z.boolean(),
});

const DefaultPriv = z.object({
  schema: z.string().optional(),
  ownerRole: z.string(),
  objectType: z.string(),
  acl: z.string(),
});

const PermissionsAudit = z.object({
  database: z.string(),
  role: z.string().optional(),
  // Effective privileges of `role`; left out when no role is given, where an
  // empty list would read as "none".
  databasePrivileges: z.array(z.string()).optional(),
  schemaPrivileges: z.array(SchemaPriv).optional(),
  tableGrants: z.array(TableGrant),
  usageGrants: z.array(TableGrant),
  // information_schema leaves sequences out of table grants, so their
  // SELECT/UPDATE grants would otherwise appear nowhere.
  sequenceGrants: z.array(TableGrant),
  defaultPrivileges: z.array(DefaultPriv),
  action: Action,
  timestamp: z.string(),
});

const Column = z.object({
  name: z.string(),
  type: z.string(),
  nullable: z.boolean(),
  default: z.string().optional(),
  position: z.number(),
});

const IndexInfo = z.object({ name: z.string(), definition: z.string() });
const ConstraintInfo = z.object({
  name: z.string(),
  type: z.string(),
  definition: z.string(),
});

const TableInfo = z.object({
  database: z.string(),
  schema: z.string(),
  table: z.string(),
  owner: z.string(),
  columns: z.array(Column),
  primaryKey: z.array(z.string()),
  indexes: z.array(IndexInfo),
  constraints: z.array(ConstraintInfo),
  action: Action,
  timestamp: z.string(),
});

const ConnectionInfo = z.object({
  pid: z.number(),
  // Tells client sessions apart from the server's own processes (checkpointer,
  // walwriter, ...), which have no user or database.
  backendType: z.string().optional(),
  user: z.string().optional(),
  db: z.string().optional(),
  state: z.string().optional(),
  clientAddr: z.string().optional(),
  backendAgeSec: z.number().optional(),
  waitEventType: z.string().optional(),
  waitEvent: z.string().optional(),
  query: z.string().optional(),
  timestamp: z.string(),
});

const ExtensionInfo = z.object({
  database: z.string(),
  name: z.string(),
  version: z.string(),
  schema: z.string().optional(),
  timestamp: z.string(),
});

const GrantResult = z.object({
  database: z.string(),
  scope: z.string(),
  role: z.string(),
  privileges: z.array(z.string()),
  objects: z.array(z.string()),
  schema: z.string().optional(),
  includeFuture: z.boolean(),
  action: Action,
  timestamp: z.string(),
});

const RoleResult = z.object({
  role: z.string(),
  action: Action,
  passwordSet: z.boolean(),
  timestamp: z.string(),
});

const AppProvisionResult = z.object({
  database: z.string(),
  role: z.string(),
  schema: z.string(),
  owner: z.string(),
  privilegesGranted: z.array(z.string()),
  defaultPrivileges: z.boolean(),
  databaseAction: Action,
  roleAction: Action,
  action: Action,
  timestamp: z.string(),
});

// ─────────────────────────── connection seam ───────────────────────────

/** The query functions the methods use; unit tests substitute a fake. */
export interface Querier {
  /** Run a parameterised SQL statement; filter values go in `params` as bound `$n`. */
  query(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: Array<Record<string, unknown>> }>;
  /** Quote an SQL identifier (db/role/schema/table name) safely for interpolation. */
  escapeIdentifier(s: string): string;
  /** Quote a string literal (e.g. a role PASSWORD) safely for interpolation. */
  escapeLiteral(s: string): string;
}
/** A live connection plus its closer. */
export interface Conn {
  /** The querier bound to this connection. */
  q: Querier;
  /** Close the underlying socket; always called in a `finally`. */
  end(): Promise<void>;
}
/** A JSON object; in practice, the resolved global args. */
export type Json = Record<string, unknown>;
/**
 * Open a connection to `database` on the configured server. The global args are
 * typed loosely as {@link Json} so this exported seam type stays "fast-check"
 * clean. Referencing the zod-inferred `GlobalArgsT` would put a slow type on
 * the public API. The real implementation re-narrows to the validated shape.
 */
export type ConnectFn = (g: Json, database: string) => Promise<Conn>;

let _connectOverride: ConnectFn | null = null;

/** Test-only seam: substitute the pg connector. Pass `null` to restore the real one. */
export function __setPgConnect(fn: ConnectFn | null): void {
  _connectOverride = fn;
}

/** The resolved `ssl` global argument. */
export interface SslSettings {
  /** disable, require, verify-ca or verify-full, as libpq's `sslmode`. */
  mode: "disable" | "require" | "verify-ca" | "verify-full";
  /** PEM CA bundle for the verify modes. */
  ca?: string;
  /** Overrides the certificate check that `mode` implies. */
  rejectUnauthorized?: boolean;
}

/** Map the `ssl` global argument to node-pg's `ssl` option. Exported for tests. */
export function sslToPg(s: SslSettings): boolean | Record<string, unknown> {
  switch (s.mode) {
    case "disable":
      return false;
    case "require":
      return { rejectUnauthorized: s.rejectUnauthorized ?? false };
    case "verify-ca":
      // Node's TLS checks the host name unless told not to, which would make
      // verify-ca the same as verify-full. libpq's verify-ca checks only the
      // chain, so a server reached by IP with a DNS-named cert still connects.
      return {
        ca: s.ca,
        rejectUnauthorized: s.rejectUnauthorized ?? true,
        checkServerIdentity: () => undefined,
      };
    case "verify-full":
      return { ca: s.ca, rejectUnauthorized: s.rejectUnauthorized ?? true };
  }
}

/** The real pg-backed implementation behind {@link connect}. */
async function realConnect(g: GlobalArgsT, database: string): Promise<Conn> {
  const client = new pg.Client({
    host: g.host,
    port: g.port,
    user: g.adminUser,
    password: g.adminPassword,
    database,
    ssl: sslToPg(g.ssl),
    application_name: "swamp-postgres-admin",
  });
  await client.connect();
  const q: Querier = {
    query: (sql, params) => client.query(sql, params),
    escapeIdentifier: (s) => client.escapeIdentifier(s),
    escapeLiteral: (s) => client.escapeLiteral(s),
  };
  return { q, end: () => client.end() };
}

function connect(g: GlobalArgsT, database: string): Promise<Conn> {
  return (_connectOverride ?? realConnect)(g, database);
}

/**
 * Connect to `database`, apply session guardrails, run `fn`, and always close
 * the socket, on the error path too. Read methods pass `readOnly: true` which
 * sets `default_transaction_read_only = on`, so the server rejects any
 * accidental write. Mutating methods pass `readOnly: false`.
 */
async function withConn<T>(
  g: GlobalArgsT,
  database: string,
  readOnly: boolean,
  fn: (q: Querier) => Promise<T>,
): Promise<T> {
  const { q, end } = await connect(g, database);
  let result: T;
  try {
    await q.query(`SET statement_timeout = ${Number(g.statementTimeoutMs)}`);
    if (readOnly) await q.query("SET default_transaction_read_only = on");
    result = await fn(q);
  } catch (e) {
    // On a broken connection end() can fail too; that error must not replace
    // the one that says why the method failed.
    await end().catch(() => {});
    throw e;
  }
  await end();
  return result;
}

// ─────────────────────────── helpers ───────────────────────────

type Ctx = MethodContext<GlobalArgsT>;

/**
 * Log at info level. swamp prints only the props named as `{placeholders}` in
 * the message, so name every prop worth reading there. Never pass a secret.
 */
function logInfo(
  context: Pick<Ctx, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.info?.(message, props ?? {});
}

/** As {@link logInfo}, at warning level. */
function logWarning(
  context: Pick<Ctx, "logger">,
  message: string,
  props?: Record<string, unknown>,
): void {
  context.logger?.warn?.(message, props ?? {});
}

/**
 * The stored-data name for a record: `<spec>` or `<spec>:<key>:...`. swamp keys
 * data by model + name, not by spec, so the spec prefix keeps two specs from
 * overwriting each other. Each key part is percent-escaped for `%`, `:`, `/`,
 * `\\` and `.` (swamp rejects `/`, `\\` and `..`; `:` is the separator), so two
 * different keys can never produce the same name.
 */
export function dataName(spec: string, ...keys: string[]): string {
  const escape = (k: string) =>
    k.replace(
      /[%:/\\.]/g,
      (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"),
    );
  return [spec, ...keys.map(escape)].join(":");
}

/** Validate an identifier against the configured pattern. Separate from `ident`
 * so a method can reject every identifier it was given before it runs any DDL,
 * rather than failing part-way through a multi-statement change. */
function checkIdent(g: GlobalArgsT, name: string, label: string): void {
  if (!new RegExp(g.identifierPattern).test(name)) {
    throw new Error(
      `Invalid ${label} identifier ${
        JSON.stringify(name)
      }: must match ${g.identifierPattern}`,
    );
  }
}

/** Validate an identifier against the configured pattern (defence-in-depth on top
 * of escaping), then return its safely-escaped form. Throws on a bad identifier. */
function ident(
  g: GlobalArgsT,
  q: Querier,
  name: string,
  label: string,
): string {
  checkIdent(g, name, label);
  return q.escapeIdentifier(name);
}

/** Run `fn` inside one transaction so a multi-statement change is applied in
 * full or not at all. A half-applied change is worse than a failed one here: the next
 * run sees the role (or a grant) already present and skips the rest. */
async function inTransaction<T>(
  q: Querier,
  fn: () => Promise<T>,
): Promise<T> {
  await q.query("BEGIN");
  try {
    const result = await fn();
    await q.query("COMMIT");
    return result;
  } catch (e) {
    // On a broken connection ROLLBACK fails too (and the server rolls back
    // anyway); report the statement's error, not that one.
    await q.query("ROLLBACK").catch(() => {});
    throw e;
  }
}

function asBool(v: unknown): boolean {
  return v === true || v === "t" || v === "true";
}
function asNum(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}
function asStr(v: unknown): string | undefined {
  return v === null || v === undefined ? undefined : String(v);
}
/** A `timestamptz` as node-pg returns it, written as an ISO 8601 string.
 * node-pg parses the value into a Date (String() of which is not ISO), and
 * `infinity`/`-infinity` into the numbers Infinity/-Infinity. */
function asTimestamp(v: unknown): string | undefined {
  if (v instanceof Date) return v.toISOString();
  if (v === Infinity) return "infinity";
  if (v === -Infinity) return "-infinity";
  return asStr(v);
}

// pg_database_size needs CONNECT on the database or pg_read_all_stats, and
// otherwise fails the whole query. A non-superuser admin often lacks CONNECT
// on some database, so its size is left out (null) instead.
const DATABASE_SIZE = `CASE WHEN has_database_privilege(d.oid, 'CONNECT')
                              OR pg_has_role('pg_read_all_stats', 'USAGE')
                            THEN pg_database_size(d.oid) END`;

/** Read one database's catalog row into a DatabaseInfo (minus action/timestamp). */
async function readDatabase(
  q: Querier,
  name: string,
): Promise<Record<string, unknown> | null> {
  const r = await q.query(
    `SELECT d.datname AS name, pg_get_userbyid(d.datdba) AS owner,
            pg_encoding_to_char(d.encoding) AS encoding,
            d.datcollate AS collate, d.datctype AS ctype,
            ${DATABASE_SIZE} AS size_bytes,
            d.datistemplate AS is_template, d.datallowconn AS allow_conn
       FROM pg_database d WHERE d.datname = $1`,
    [name],
  );
  return r.rows[0] ?? null;
}

function shapeDatabase(
  row: Record<string, unknown>,
  action: z.infer<typeof Action>,
  ts: string,
) {
  return {
    name: String(row.name),
    owner: String(row.owner),
    encoding: String(row.encoding),
    collate: asStr(row.collate),
    ctype: asStr(row.ctype),
    sizeBytes: row.size_bytes === null || row.size_bytes === undefined
      ? undefined
      : asNum(row.size_bytes),
    isTemplate: asBool(row.is_template),
    allowConn: asBool(row.allow_conn),
    action,
    timestamp: ts,
  };
}

async function roleExists(q: Querier, name: string): Promise<boolean> {
  const r = await q.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [name]);
  return r.rows.length > 0;
}

async function databaseExists(q: Querier, name: string): Promise<boolean> {
  const r = await q.query("SELECT 1 FROM pg_database WHERE datname = $1", [
    name,
  ]);
  return r.rows.length > 0;
}

/**
 * Whether `role` holds any direct schema-scoped grant that app_provision
 * makes: USAGE or CREATE on `schema`, any privilege on a table or sequence in
 * `schema`, or a default-privilege entry for `schema`. app_provision uses this
 * as its "provisioned in this schema before" marker. Phase B runs in one
 * transaction, so a failed first run leaves none of these behind. Any one of
 * them counts, so that revoking a single privilege by hand does not make the
 * next run treat the role as new and grant everything back.
 *
 * CONNECT on the database does not count: it is database-wide, so counting it
 * would make app_provision for a second schema in the same database grant
 * nothing there.
 *
 * Only direct grants count (aclexplode lists ACL entries, not inherited or
 * PUBLIC privileges): by default the `public` schema grants USAGE to PUBLIC,
 * so an effective-privilege check would call every role provisioned there. An
 * owner's own ACL entry does count; that errs towards granting less, never
 * more.
 */
async function holdsProvisionGrant(
  q: Querier,
  schema: string,
  role: string,
): Promise<boolean> {
  const grantee = "(SELECT oid FROM pg_roles WHERE rolname = $2)";
  const probes = [
    `SELECT 1 FROM pg_namespace n, aclexplode(n.nspacl) a
      WHERE n.nspname = $1 AND a.privilege_type IN ('USAGE', 'CREATE')
        AND a.grantee = ${grantee}`,
    `SELECT 1 FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace,
            aclexplode(c.relacl) a
      WHERE n.nspname = $1 AND a.grantee = ${grantee} LIMIT 1`,
    `SELECT 1 FROM pg_default_acl d
       JOIN pg_namespace n ON n.oid = d.defaclnamespace,
            aclexplode(d.defaclacl) a
      WHERE n.nspname = $1 AND a.grantee = ${grantee} LIMIT 1`,
  ];
  for (const sql of probes) {
    const r = await q.query(sql, [schema, role]);
    if (r.rows.length > 0) return true;
  }
  return false;
}

// SASLprep (RFC 4013) mapping step, as PostgreSQL's saslprep.c applies it:
// non-ASCII spaces become U+0020 and "commonly mapped to nothing" characters
// are dropped.
const NON_ASCII_SPACE = /[\u00A0\u1680\u2000-\u200B\u202F\u205F\u3000]/g;
const MAPPED_TO_NOTHING =
  /[\u00AD\u034F\u1806\u180B-\u180D\u200C\u200D\u2060\uFE00-\uFE0F\uFEFF]/g;

/**
 * Normalise a password the way libpq and the server do before SCRAM hashing,
 * so a verifier built here matches the one the server would have built from
 * the plain text. ASCII passes through unchanged, as in PostgreSQL. Otherwise
 * this applies the SASLprep mapping and NFKC, but not its prohibited-character
 * and bidi checks: when those fail, PostgreSQL hashes the raw password, so a
 * non-ASCII password holding such a character may not match. See the README.
 */
function saslPrep(password: string): string {
  // deno-lint-ignore no-control-regex
  if (/^[\x00-\x7F]*$/.test(password)) return password;
  return password.replace(NON_ASCII_SPACE, " ").replace(MAPPED_TO_NOTHING, "")
    .normalize("NFKC");
}

/** PostgreSQL's default `scram_iterations`, and what libpq uses. */
const SCRAM_ITERATIONS = 4096;

function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

async function hmacSha256(
  key: ArrayBuffer,
  message: string,
): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(message));
}

/**
 * Hash `password` into a SCRAM-SHA-256 verifier (RFC 5802/7677, stored in
 * PostgreSQL's RFC 5803 form), as psql's `\password` does. The server stores a
 * value in this shape as it is, so the plain text never leaves this process:
 * not on the wire, not in `pg_stat_activity`, not in a statement log.
 * `salt` is for tests only; leave it out to get 16 random bytes, as libpq does.
 */
export async function scramSha256Verifier(
  password: string,
  salt: Uint8Array<ArrayBuffer> = crypto.getRandomValues(new Uint8Array(16)),
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(saslPrep(password)),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const saltedPassword = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: SCRAM_ITERATIONS },
    key,
    256,
  );
  const clientKey = await hmacSha256(saltedPassword, "Client Key");
  const storedKey = await crypto.subtle.digest("SHA-256", clientKey);
  const serverKey = await hmacSha256(saltedPassword, "Server Key");
  return `SCRAM-SHA-256$${SCRAM_ITERATIONS}:${toBase64(salt)}$${
    toBase64(storedKey)
  }:${toBase64(serverKey)}`;
}

/** The `PASSWORD '<verifier>'` clause for a role: hashed here, never plain. */
async function passwordClause(q: Querier, password: string): Promise<string> {
  return `PASSWORD ${q.escapeLiteral(await scramSha256Verifier(password))}`;
}

/** Join an already-validated privilege list into a SQL fragment (enum-bounded, safe). */
function privList(privs: string[]): string {
  return privs.map((p) => p.toUpperCase()).join(", ");
}

// ─────────────────────────── method argument schemas ───────────────────────────

const DatabaseListArgs = z.object({
  includeTemplates: z.boolean()
    .default(false)
    .describe("Include template databases (template0/template1)"),
});

const PermissionsAuditArgs = z.object({
  database: z.string().describe("Database to audit (connects to it)"),
  role: z.string().optional().describe(
    "Role to scope the audit to; omit to list every role's table/usage grants " +
      "in the db. System schemas (pg_*, information_schema) and collations " +
      "are left out.",
  ),
});

// pg_class.relkind values that have columns worth describing: ordinary and
// partitioned tables, views, materialised views and foreign tables.
const TABLE_LIKE_KINDS = ["r", "p", "v", "m", "f"];
const RELKIND_NAMES: Record<string, string> = {
  i: "an index",
  I: "a partitioned index",
  S: "a sequence",
  c: "a composite type",
  t: "a TOAST table",
};

const TableInspectArgs = z.object({
  database: z.string().describe("Database holding the table (connects to it)"),
  schema: z.string().default("public").describe("Schema of the table"),
  table: z.string().describe("Table, view or foreign table to describe"),
});

const ConnectionsListArgs = z.object({
  database: z.string().optional().describe("Filter to one database's backends"),
  includeQuery: z.boolean()
    .default(false)
    .describe(
      "Include the current `query` text, cut to its first 2,000 characters. " +
        "Off by default: query text can contain literal row data, which would " +
        "break the no-data-reads guarantee.",
    ),
});

const ExtensionListArgs = z.object({
  database: z.string().optional().describe(
    "One database; omit to fan out across all connectable databases",
  ),
});

const DatabaseCreateArgs = z.object({
  name: z.string().describe("Database to create"),
  owner: z.string().optional().describe(
    "Owning role; defaults to the admin login",
  ),
  encoding: z.string().optional().describe(
    "Only emitted when set; a non-default encoding usually needs template0",
  ),
  template: z.string().optional().describe(
    "Template database to copy; defaults to template1",
  ),
  locale: z.string().optional().describe(
    "Sets both LC_COLLATE and LC_CTYPE, e.g. en_GB.UTF-8",
  ),
});

const RoleCreateArgs = z.object({
  name: z.string().describe("Role to create"),
  login: z.boolean()
    .default(true)
    .describe("LOGIN (a user) when true, NOLOGIN (a group role) when false"),
  // min(1): PostgreSQL reads PASSWORD '' as PASSWORD NULL, so an empty
  // value (say, a vault expression that resolved to nothing) would make a
  // LOGIN role with no password. Omit the field for a role without one.
  password: z.string().min(1).optional().meta({ sensitive: true }).describe(
    "Supply via vault expression. Sent only as a SCRAM-SHA-256 verifier, never logged/echoed. Must not be empty",
  ),
  connLimit: z.coerce.number().int().default(-1).describe(
    "CONNECTION LIMIT; -1 means no limit",
  ),
  validUntil: z.string().optional().describe(
    "e.g. 2027-01-01 (a timestamp literal)",
  ),
  createDb: z.boolean()
    .default(false)
    .describe("Give the role CREATEDB"),
  createRole: z.boolean()
    .default(false)
    .describe("Give the role CREATEROLE"),
  memberOf: z.array(z.string()).default([]).describe(
    "Parent roles to GRANT to this role",
  ),
});

const GrantScope = z.enum(["database", "schema", "table", "sequence"]);

const GrantArgs = z.object({
  database: z.string().describe(
    "Database the privileges apply in (or to, for database scope)",
  ),
  scope: GrantScope.describe("Kind of object the privileges are on"),
  privileges: z.array(Privilege).min(1).describe(
    "Privileges to grant or revoke; TRUNCATE and ALL are not allowed",
  ),
  role: z.string().describe("Role that receives (or loses) the privileges"),
  schema: z.string().optional().describe(
    "Required for schema/table/sequence scope",
  ),
  objects: z.array(z.string()).default([]).describe(
    "Specific table/sequence names. Leave empty when allInSchema=true",
  ),
  allInSchema: z.boolean()
    .default(false)
    .describe(
      "Target every existing table/sequence in `schema` instead of `objects`",
    ),
  includeFuture: z.boolean()
    .default(false)
    .describe(
      "Also ALTER DEFAULT PRIVILEGES for future objects in the schema. " +
        "Table and sequence scope only",
    ),
  defaultForRole: z.string().optional().describe(
    "FOR ROLE in ALTER DEFAULT PRIVILEGES: the role whose future objects the " +
      "grant covers (the one that will create the tables). Required when " +
      "includeFuture is set: PostgreSQL would otherwise alter the connecting " +
      "admin role's own defaults, which only affect objects the admin creates.",
  ),
});

const RolePasswordSetArgs = z.object({
  name: z.string().describe("Existing role whose password to set"),
  // min(1): PASSWORD '' clears the password rather than setting one.
  password: z.string().min(1).meta({ sensitive: true }).describe(
    "New password; supply via vault expression. Sent only as a SCRAM-SHA-256 verifier. Must not be empty",
  ),
});

const AppProvisionArgs = z.object({
  database: z.string().describe("Database to create (or reuse) for the app"),
  role: z.string().describe("Login role to create (or reuse) for the app"),
  // min(1): see RoleCreateArgs.password.
  password: z.string().min(1).optional().meta({ sensitive: true }).describe(
    "Login password for a NEW role (ignored if the role already exists). Must not be empty",
  ),
  owner: z.string().optional().describe(
    "Database/schema owner; defaults to `role`",
  ),
  schema: z.string().default("public").describe(
    "Schema the role is provisioned in",
  ),
  createSchema: z.boolean()
    .default(false)
    .describe("CREATE SCHEMA IF NOT EXISTS, owned by `owner` (not for public)"),
  // No schema defaults: GRANT only adds, so a default re-applied on a re-run
  // would widen a role provisioned with less. The method applies them only
  // when the role has not been provisioned in the schema before.
  tablePrivs: z.array(TablePrivilege).optional().describe(
    "Table privileges to grant. Defaults to SELECT, INSERT, UPDATE, DELETE " +
      "until the role holds a grant in this schema from an earlier run; omitted on " +
      "a later run, table grants are left as they are.",
  ),
  includeFuture: z.boolean().optional().describe(
    "Also grant on future tables and sequences. Defaults to true until the " +
      "role holds a grant in this schema from an earlier run; omitted on a later " +
      "run, default privileges are left as they are.",
  ),
  connLimit: z.coerce.number().int().default(-1).describe(
    "CONNECTION LIMIT for a new role; -1 means no limit. Ignored if the role exists",
  ),
});

// ─────────────────────────── model ───────────────────────────

/**
 * The `@thomas/postgres-admin` model definition: non-destructive PostgreSQL
 * administration (create db/role, grant/revoke, password rotation, composite
 * app provisioning) plus read-only audits. See the file header for the full
 * data-safety scope guarantee.
 */
export const model = {
  type: "@thomas/postgres-admin",
  version: "2026.10.11.1",
  globalArguments: GlobalArgs,
  upgrades: [
    {
      toVersion: "2026.10.11.1",
      description:
        "No change to the global arguments' shape: port must now be 1-65535 and statementTimeoutMs at least 0, which PostgreSQL already required. Data names are now <spec>:<key>, so data written by earlier versions stays under its old names and is not migrated.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
  ],
  checks: {
    "reachable": {
      description:
        "Verify the Postgres server is reachable (SELECT 1 to maintenanceDb)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        // Checks get globalArgs without the schema's defaults; parse to apply them.
        const parsed = GlobalArgs.safeParse(context.globalArgs);
        if (!parsed.success) {
          return { pass: false, errors: [z.prettifyError(parsed.error)] };
        }
        const g = parsed.data;
        try {
          await withConn(g, g.maintenanceDb, true, async (q) => {
            await q.query("SELECT 1");
          });
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Cannot reach Postgres at ${g.host}:${g.port}: ${
                (e as Error).message
              }`,
            ],
          };
        }
      },
    },
  },
  resources: {
    "database": {
      description: "A database catalog record (owner/encoding/size)",
      schema: DatabaseInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "role": {
      description:
        "A role/user record (attributes + memberships); no password is ever read",
      schema: RoleInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "permissions-audit": {
      description:
        "Privilege audit for a database (optionally scoped to a role)",
      schema: PermissionsAudit,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "table": {
      description:
        "A table's structure (columns/PK/indexes/constraints) — catalog only, no row data",
      schema: TableInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "connection": {
      description: "A backend from pg_stat_activity (point-in-time)",
      schema: ConnectionInfo,
      lifetime: "1h",
      garbageCollection: 5,
    },
    "extension": {
      description: "An installed extension in a database",
      schema: ExtensionInfo,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "grant-result": {
      description: "Result of a grant/revoke operation",
      schema: GrantResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "role-result": {
      description: "Result of a role create / password rotation",
      schema: RoleResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "app-provision": {
      description: "Result of the composite app_provision (db + role + grants)",
      schema: AppProvisionResult,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    // ───────────── read / audit ─────────────
    database_list: {
      description:
        "List databases with owner/encoding/size (factory: one `database` per db). Read-only.",
      arguments: DatabaseListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = DatabaseListArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Listing databases");
        return await withConn(g, g.maintenanceDb, true, async (q) => {
          const r = await q.query(
            `SELECT d.datname AS name, pg_get_userbyid(d.datdba) AS owner,
                    pg_encoding_to_char(d.encoding) AS encoding,
                    d.datcollate AS collate, d.datctype AS ctype,
                    ${DATABASE_SIZE} AS size_bytes,
                    d.datistemplate AS is_template, d.datallowconn AS allow_conn
               FROM pg_database d
              WHERE $1 OR NOT d.datistemplate
              ORDER BY d.datname`,
            [a.includeTemplates],
          );
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const row of r.rows) {
            handles.push(
              await context.writeResource(
                "database",
                dataName("database", String(row.name)),
                shapeDatabase(row, "observed", ts),
              ),
            );
          }
          logInfo(context, "Listed {count} databases", {
            count: handles.length,
          });
          return { dataHandles: handles };
        });
      },
    },

    role_list: {
      description:
        "List roles with attributes + memberships (factory: one `role` per role). Read-only; never reads passwords.",
      arguments: z.object({}),
      execute: async (
        _rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const g = context.globalArgs;
        logInfo(context, "Listing roles");
        return await withConn(g, g.maintenanceDb, true, async (q) => {
          // `::text`: node-pg parses a text[] into an array but leaves a
          // name[] as the raw string "{a,b}". DISTINCT: PostgreSQL 16+ keeps
          // one membership row per grantor, so a parent can appear twice.
          const r = await q.query(
            `SELECT r.rolname AS name, r.rolcanlogin AS login, r.rolsuper AS superuser,
                    r.rolcreatedb AS create_db, r.rolcreaterole AS create_role,
                    r.rolreplication AS replication, r.rolbypassrls AS bypass_rls,
                    r.rolconnlimit AS conn_limit, r.rolvaliduntil AS valid_until,
                    ARRAY(SELECT DISTINCT g.rolname::text FROM pg_auth_members m
                            JOIN pg_roles g ON g.oid = m.roleid
                           WHERE m.member = r.oid ORDER BY 1) AS member_of
               FROM pg_roles r ORDER BY r.rolname`,
          );
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const row of r.rows) {
            if (!Array.isArray(row.member_of)) {
              throw new Error(
                `role_list: memberOf for role ${
                  JSON.stringify(row.name)
                } came back as ${typeof row.member_of}, not an array`,
              );
            }
            handles.push(
              await context.writeResource(
                "role",
                dataName("role", String(row.name)),
                {
                  name: String(row.name),
                  login: asBool(row.login),
                  superuser: asBool(row.superuser),
                  createDb: asBool(row.create_db),
                  createRole: asBool(row.create_role),
                  replication: asBool(row.replication),
                  bypassRls: asBool(row.bypass_rls),
                  connLimit: asNum(row.conn_limit),
                  validUntil: asTimestamp(row.valid_until),
                  memberOf: row.member_of.map(String),
                  action: "observed",
                  timestamp: ts,
                },
              ),
            );
          }
          logInfo(context, "Listed {count} roles", { count: handles.length });
          return { dataHandles: handles };
        });
      },
    },

    permissions_audit: {
      description:
        "Audit privileges for a database (optionally a single role). databasePrivileges and " +
        "schemaPrivileges are effective privileges (including PUBLIC and role membership), " +
        "present only when `role` is given. tableGrants, usageGrants and sequenceGrants are " +
        "direct grants, with grantee and grantor; sequenceGrants lists every privilege on " +
        "sequences, USAGE included. Also lists default privileges. System schemas and " +
        "collations are left out. Catalog reads only.",
      arguments: PermissionsAuditArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = PermissionsAuditArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Auditing permissions", {
          database: a.database,
          role: a.role ?? "(all)",
        });
        return await withConn(g, a.database, true, async (q) => {
          let databasePrivileges: string[] | undefined;
          let schemaPrivileges: Array<z.infer<typeof SchemaPriv>> | undefined;

          if (a.role) {
            databasePrivileges = [];
            schemaPrivileges = [];
            const dbr = await q.query(
              `SELECT p AS priv, has_database_privilege($1, $2, p) AS granted
                 FROM unnest(ARRAY['CONNECT','CREATE','TEMP']) AS p`,
              [a.role, a.database],
            );
            for (const row of dbr.rows) {
              if (asBool(row.granted)) {
                databasePrivileges.push(String(row.priv));
              }
            }

            const scr = await q.query(
              `SELECT n.nspname AS schema,
                      has_schema_privilege($1, n.nspname, 'USAGE') AS usage,
                      has_schema_privilege($1, n.nspname, 'CREATE') AS create
                 FROM pg_namespace n
                WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
                ORDER BY n.nspname`,
              [a.role],
            );
            for (const row of scr.rows) {
              schemaPrivileges.push({
                schema: String(row.schema),
                usage: asBool(row.usage),
                create: asBool(row.create),
              });
            }
          }

          // System schemas are left out: their grants are the same on every
          // server, and unscoped they ran to thousands of rows that buried
          // the database's own. Collations are left out because every one
          // carries an implicit USAGE to PUBLIC. COALESCE keeps foreign data
          // wrappers and servers, which belong to no schema.
          const tg = await q.query(
            `SELECT table_schema AS schema, table_name AS name, privilege_type AS privilege,
                    grantee, grantor, is_grantable
               FROM information_schema.role_table_grants
              WHERE ($1::text IS NULL OR grantee = $1)
                AND table_schema NOT LIKE 'pg\\_%' AND table_schema <> 'information_schema'
              ORDER BY table_schema, table_name, privilege_type, grantee, grantor`,
            [a.role ?? null],
          );
          const tableGrants = tg.rows.map((row) => ({
            schema: String(row.schema),
            name: String(row.name),
            privilege: String(row.privilege),
            grantee: String(row.grantee),
            grantor: String(row.grantor),
            grantable: asBool(row.is_grantable),
          }));

          const ug = await q.query(
            `SELECT object_schema AS schema, object_name AS name, privilege_type AS privilege,
                    grantee, grantor, is_grantable
               FROM information_schema.role_usage_grants
              WHERE ($1::text IS NULL OR grantee = $1)
                AND COALESCE(object_schema, '') NOT LIKE 'pg\\_%'
                AND COALESCE(object_schema, '') <> 'information_schema'
                AND object_type <> 'COLLATION'
              ORDER BY object_schema, object_name, privilege_type, grantee, grantor`,
            [a.role ?? null],
          );
          const usageGrants = ug.rows.map((row) => ({
            schema: asStr(row.schema) ?? "",
            name: asStr(row.name) ?? "",
            privilege: String(row.privilege),
            grantee: String(row.grantee),
            grantor: String(row.grantor),
            grantable: asBool(row.is_grantable),
          }));

          // Read from the ACL itself: information_schema.table_privileges
          // has no sequences. A NULL relacl means the built-in default (the
          // owner holds everything), which acldefault spells out. Grantee 0
          // is PUBLIC.
          const sg = await q.query(
            `SELECT schema, name, privilege, grantee, grantor, is_grantable
               FROM (SELECT n.nspname AS schema, c.relname AS name,
                            a.privilege_type AS privilege,
                            CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                                 ELSE pg_get_userbyid(a.grantee) END AS grantee,
                            pg_get_userbyid(a.grantor) AS grantor,
                            a.is_grantable
                       FROM pg_class c
                       JOIN pg_namespace n ON n.oid = c.relnamespace,
                            aclexplode(COALESCE(c.relacl, acldefault('s', c.relowner))) a
                      WHERE c.relkind = 'S'
                        AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema') s
              WHERE ($1::text IS NULL OR grantee = $1)
              ORDER BY schema, name, privilege, grantee, grantor`,
            [a.role ?? null],
          );
          const sequenceGrants = sg.rows.map((row) => ({
            schema: String(row.schema),
            name: String(row.name),
            privilege: String(row.privilege),
            grantee: String(row.grantee),
            grantor: String(row.grantor),
            grantable: asBool(row.is_grantable),
          }));

          const dp = await q.query(
            `SELECT n.nspname AS schema, pg_get_userbyid(d.defaclrole) AS owner_role,
                    CASE d.defaclobjtype WHEN 'r' THEN 'table' WHEN 'S' THEN 'sequence'
                         WHEN 'f' THEN 'function' WHEN 'T' THEN 'type' WHEN 'n' THEN 'schema'
                         ELSE d.defaclobjtype::text END AS object_type,
                    array_to_string(d.defaclacl, E'\\n') AS acl
               FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
              ORDER BY n.nspname, object_type`,
          );
          const defaultPrivileges = dp.rows.map((row) => ({
            schema: asStr(row.schema),
            ownerRole: String(row.owner_role),
            objectType: String(row.object_type),
            acl: asStr(row.acl) ?? "",
          }));

          const ts = new Date().toISOString();
          const handle = await context.writeResource(
            "permissions-audit",
            // No role = the audit of all roles; one key part fewer, so no role
            // name (not even "all") can collide with it.
            a.role === undefined
              ? dataName("permissions-audit", a.database)
              : dataName("permissions-audit", a.database, a.role),
            {
              database: a.database,
              role: a.role,
              databasePrivileges,
              schemaPrivileges,
              tableGrants,
              usageGrants,
              sequenceGrants,
              defaultPrivileges,
              action: "observed",
              timestamp: ts,
            },
          );
          logInfo(
            context,
            "Audited permissions: {tableGrants} table and {usageGrants} usage grants",
            {
              tableGrants: tableGrants.length,
              usageGrants: usageGrants.length,
            },
          );
          return { dataHandles: [handle] };
        });
      },
    },

    table_inspect: {
      description:
        "Describe a table (or view, materialised view, foreign table): columns, primary key, " +
        "indexes, constraints, owner. Catalog only; never reads table rows.",
      arguments: TableInspectArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = TableInspectArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Inspecting table", {
          database: a.database,
          schema: a.schema,
          table: a.table,
        });
        return await withConn(g, a.database, true, async (q) => {
          const found = await q.query(
            `SELECT c.relkind AS kind FROM pg_class c
              WHERE c.oid = to_regclass(format('%I.%I', $1::text, $2::text))`,
            [a.schema, a.table],
          );
          if (found.rows.length === 0) {
            throw new Error(
              `Table ${a.schema}.${a.table} does not exist in database ${a.database}`,
            );
          }
          // to_regclass also finds indexes, sequences and composite types,
          // which have no columns here; describing one would look like an
          // empty table.
          const kind = String(found.rows[0].kind);
          if (!TABLE_LIKE_KINDS.includes(kind)) {
            throw new Error(
              `${a.schema}.${a.table} in database ${a.database} is ${
                RELKIND_NAMES[kind] ?? `relkind ${kind}`
              }, not a table or view`,
            );
          }

          const cols = await q.query(
            // format_type gives the declared type (text[], my_enum,
            // varchar(40)) where data_type says only ARRAY or USER-DEFINED.
            `SELECT c.column_name AS name, c.is_nullable AS nullable,
                    (SELECT format_type(t.atttypid, t.atttypmod) FROM pg_attribute t
                      WHERE t.attrelid = format('%I.%I', $1::text, $2::text)::regclass
                        AND t.attname = c.column_name) AS type,
                    c.column_default AS def, c.ordinal_position AS position
               FROM information_schema.columns c
              WHERE c.table_schema = $1 AND c.table_name = $2
              ORDER BY c.ordinal_position`,
            [a.schema, a.table],
          );
          const columns = cols.rows.map((row) => ({
            name: String(row.name),
            type: String(row.type),
            nullable: row.nullable === "YES",
            default: asStr(row.def),
            position: asNum(row.position),
          }));

          const pk = await q.query(
            `SELECT a.attname AS col
               FROM pg_index i
               JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
              WHERE i.indrelid = format('%I.%I', $1::text, $2::text)::regclass AND i.indisprimary
              ORDER BY array_position(i.indkey, a.attnum)`,
            [a.schema, a.table],
          );
          const primaryKey = pk.rows.map((row) => String(row.col));

          const idx = await q.query(
            "SELECT indexname AS name, indexdef AS def FROM pg_indexes WHERE schemaname = $1 AND tablename = $2 ORDER BY indexname",
            [a.schema, a.table],
          );
          const indexes = idx.rows.map((row) => ({
            name: String(row.name),
            definition: String(row.def),
          }));

          const cons = await q.query(
            `SELECT conname AS name,
                    CASE contype WHEN 'p' THEN 'primary key' WHEN 'f' THEN 'foreign key'
                         WHEN 'u' THEN 'unique' WHEN 'c' THEN 'check' WHEN 'x' THEN 'exclusion'
                         WHEN 'n' THEN 'not null' WHEN 't' THEN 'trigger'
                         ELSE contype::text END AS type,
                    pg_get_constraintdef(oid) AS def
               FROM pg_constraint
              WHERE conrelid = format('%I.%I', $1::text, $2::text)::regclass
              ORDER BY conname`,
            [a.schema, a.table],
          );
          const constraints = cons.rows.map((row) => ({
            name: String(row.name),
            type: String(row.type),
            definition: String(row.def),
          }));

          const own = await q.query(
            `SELECT pg_get_userbyid(c.relowner) AS owner
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = $1 AND c.relname = $2`,
            [a.schema, a.table],
          );

          const ts = new Date().toISOString();
          const handle = await context.writeResource(
            "table",
            dataName("table", a.database, a.schema, a.table),
            {
              database: a.database,
              schema: a.schema,
              table: a.table,
              owner: asStr(own.rows[0]?.owner) ?? "",
              columns,
              primaryKey,
              indexes,
              constraints,
              action: "observed",
              timestamp: ts,
            },
          );
          logInfo(context, "Inspected table: {columns} columns", {
            columns: columns.length,
          });
          return { dataHandles: [handle] };
        });
      },
    },

    connections_list: {
      description:
        "List backends from pg_stat_activity (factory: one `connection` per pid), " +
        "including the server's own processes; `backendType` tells them apart. The " +
        "`query` column is left out unless includeQuery=true (it can contain row data).",
      arguments: ConnectionsListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ConnectionsListArgs.parse(rawArgs);
        const g = context.globalArgs;
        logInfo(context, "Listing connections", {
          includeQuery: a.includeQuery,
        });
        return await withConn(g, g.maintenanceDb, true, async (q) => {
          const r = await q.query(
            `SELECT pid, backend_type, usename AS "user", datname AS db, state,
                    host(client_addr) AS client_addr,
                    EXTRACT(EPOCH FROM (now() - backend_start))::int AS backend_age_sec,
                    wait_event_type, wait_event,
                    CASE WHEN $1 THEN left(query, 2000) ELSE NULL END AS query
               FROM pg_stat_activity
              WHERE ($2::text IS NULL OR datname = $2)
              ORDER BY backend_age_sec DESC NULLS LAST`,
            [a.includeQuery, a.database ?? null],
          );
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const row of r.rows) {
            handles.push(
              await context.writeResource(
                "connection",
                dataName("connection", String(row.pid)),
                {
                  pid: asNum(row.pid),
                  backendType: asStr(row.backend_type),
                  user: asStr(row.user),
                  db: asStr(row.db),
                  state: asStr(row.state),
                  clientAddr: asStr(row.client_addr),
                  backendAgeSec: row.backend_age_sec === null
                    ? undefined
                    : asNum(row.backend_age_sec),
                  waitEventType: asStr(row.wait_event_type),
                  waitEvent: asStr(row.wait_event),
                  query: asStr(row.query),
                  timestamp: ts,
                },
              ),
            );
          }
          logInfo(context, "Listed {count} connections", {
            count: handles.length,
          });
          return { dataHandles: handles };
        });
      },
    },

    extension_list: {
      description:
        "List installed extensions per database (factory: one `extension` per db+ext). " +
        "Omit `database` to fan out across all connectable databases.",
      arguments: ExtensionListArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = ExtensionListArgs.parse(rawArgs);
        const g = context.globalArgs;

        let dbs: string[];
        if (a.database) {
          dbs = [a.database];
        } else {
          dbs = await withConn(g, g.maintenanceDb, true, async (q) => {
            const r = await q.query(
              "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname",
            );
            return r.rows.map((row) => String(row.datname));
          });
        }
        logInfo(context, "Listing extensions", { databases: dbs.length });

        // Read every database before writing anything: a database that
        // refuses the connection late in the list must fail the run without
        // leaving the earlier databases' records behind as a partial result.
        const found: Array<{ db: string; rows: Record<string, unknown>[] }> =
          [];
        for (const db of dbs) {
          const rows = await withConn(g, db, true, async (q) => {
            const r = await q.query(
              `SELECT e.extname AS name, e.extversion AS version, n.nspname AS schema
                 FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
                ORDER BY e.extname`,
            );
            return r.rows;
          });
          found.push({ db, rows });
        }

        const ts = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const { db, rows } of found) {
          for (const row of rows) {
            handles.push(
              await context.writeResource(
                "extension",
                dataName("extension", db, String(row.name)),
                {
                  database: db,
                  name: String(row.name),
                  version: String(row.version),
                  schema: asStr(row.schema),
                  timestamp: ts,
                },
              ),
            );
          }
        }
        logInfo(context, "Listed {records} extensions", {
          records: handles.length,
        });
        return { dataHandles: handles };
      },
    },

    // ───────────── mutating (admin DDL, data-safe) ─────────────
    database_create: {
      description:
        "Create a database (idempotent: returns the existing one as `unchanged`, not altered; " +
        "a warning names any arguments not applied). Never drops.",
      arguments: DatabaseCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = DatabaseCreateArgs.parse(rawArgs);
        const g = context.globalArgs;
        return await withConn(g, g.maintenanceDb, false, async (q) => {
          const ts = new Date().toISOString();
          if (await databaseExists(q, a.name)) {
            logInfo(context, "Database {name} already exists; unchanged", {
              name: a.name,
            });
            // An existing database is not compared or altered, so say which
            // requested settings were not applied rather than drop them quietly.
            const ignored =
              (["owner", "encoding", "template", "locale"] as const)
                .filter((k) => a[k] !== undefined);
            if (ignored.length > 0) {
              logWarning(
                context,
                "Database {name} exists, so these arguments were not applied: {ignored}",
                { name: a.name, ignored: ignored.join(", ") },
              );
            }
            const row = await readDatabase(q, a.name);
            const handle = await context.writeResource(
              "database",
              dataName("database", a.name),
              shapeDatabase(row!, "unchanged", ts),
            );
            return { dataHandles: [handle] };
          }
          const parts = [`CREATE DATABASE ${ident(g, q, a.name, "database")}`];
          if (a.owner) parts.push(`OWNER ${ident(g, q, a.owner, "owner")}`);
          if (a.template) {
            parts.push(`TEMPLATE ${ident(g, q, a.template, "template")}`);
          }
          if (a.encoding) parts.push(`ENCODING ${q.escapeLiteral(a.encoding)}`);
          if (a.locale) parts.push(`LOCALE ${q.escapeLiteral(a.locale)}`);
          logInfo(context, "Creating database", { name: a.name });
          await q.query(parts.join(" ")); // outside a transaction: CREATE DATABASE cannot run in one
          const row = await readDatabase(q, a.name);
          const handle = await context.writeResource(
            "database",
            dataName("database", a.name),
            shapeDatabase(row!, "created", ts),
          );
          logInfo(context, "Created database {name}", { name: a.name });
          return { dataHandles: [handle] };
        });
      },
    },

    role_create: {
      description:
        "Create a login/group role (idempotent: existing role returned as `unchanged`, not altered; " +
        "a warning names any arguments not applied). Never drops.",
      arguments: RoleCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleCreateArgs.parse(rawArgs);
        const g = context.globalArgs;
        // Reject every identifier before any statement runs: a bad second
        // parent found after CREATE ROLE would leave a half-granted role that
        // the next run reports as unchanged.
        checkIdent(g, a.name, "role");
        for (const parent of a.memberOf) checkIdent(g, parent, "parent role");
        return await withConn(g, g.maintenanceDb, false, async (q) => {
          const ts = new Date().toISOString();
          if (await roleExists(q, a.name)) {
            logInfo(context, "Role {name} already exists; unchanged", {
              name: a.name,
            });
            // An existing role is not compared or altered. Name the requested
            // settings that were not applied (never their values: one may be
            // the password). Defaults are left out, as the caller may not
            // have asked for them.
            const ignored = [
              a.login ? "" : "login",
              a.password === undefined ? "" : "password",
              a.connLimit === -1 ? "" : "connLimit",
              a.validUntil === undefined ? "" : "validUntil",
              a.createDb ? "createDb" : "",
              a.createRole ? "createRole" : "",
              a.memberOf.length === 0 ? "" : "memberOf",
            ].filter((k) => k !== "");
            if (ignored.length > 0) {
              logWarning(
                context,
                "Role {name} exists, so these arguments were not applied: {ignored}",
                { name: a.name, ignored: ignored.join(", ") },
              );
            }
            const handle = await context.writeResource(
              "role-result",
              dataName("role-result", a.name),
              {
                role: a.name,
                action: "unchanged",
                passwordSet: false,
                timestamp: ts,
              },
            );
            return { dataHandles: [handle] };
          }
          const parts = [`CREATE ROLE ${ident(g, q, a.name, "role")}`];
          parts.push(a.login ? "LOGIN" : "NOLOGIN");
          if (a.createDb) parts.push("CREATEDB");
          if (a.createRole) parts.push("CREATEROLE");
          parts.push(`CONNECTION LIMIT ${Number(a.connLimit)}`);
          if (a.password) parts.push(await passwordClause(q, a.password));
          if (a.validUntil) {
            parts.push(`VALID UNTIL ${q.escapeLiteral(a.validUntil)}`);
          }
          logInfo(context, "Creating role", { name: a.name, login: a.login }); // never logs password
          // One transaction: a parent that does not exist must not leave the
          // role created without its memberships.
          await inTransaction(q, async () => {
            await q.query(parts.join(" "));
            for (const parent of a.memberOf) {
              await q.query(
                `GRANT ${ident(g, q, parent, "parent role")} TO ${
                  ident(g, q, a.name, "role")
                }`,
              );
            }
          });
          const handle = await context.writeResource(
            "role-result",
            dataName("role-result", a.name),
            {
              role: a.name,
              action: "created",
              passwordSet: !!a.password,
              timestamp: ts,
            },
          );
          logInfo(
            context,
            "Created role {name} with {memberships} memberships",
            {
              name: a.name,
              memberships: a.memberOf.length,
            },
          );
          return { dataHandles: [handle] };
        });
      },
    },

    role_password_set: {
      description:
        "Set/rotate a role's password (ALTER ROLE … PASSWORD) from a vault value. Never echoes it.",
      arguments: RolePasswordSetArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RolePasswordSetArgs.parse(rawArgs);
        const g = context.globalArgs;
        return await withConn(g, g.maintenanceDb, false, async (q) => {
          if (!(await roleExists(q, a.name))) {
            throw new Error(`Role ${JSON.stringify(a.name)} does not exist`);
          }
          logInfo(context, "Rotating role password", { name: a.name }); // never logs the value
          await q.query(
            `ALTER ROLE ${ident(g, q, a.name, "role")} ${await passwordClause(
              q,
              a.password,
            )}`,
          );
          const handle = await context.writeResource(
            "role-result",
            dataName("role-result", a.name),
            {
              role: a.name,
              action: "rotated",
              passwordSet: true,
              timestamp: new Date().toISOString(),
            },
          );
          logInfo(context, "Rotated the password of role {name}", {
            name: a.name,
          });
          return { dataHandles: [handle] };
        });
      },
    },

    grant: {
      description:
        "GRANT privileges on a database/schema/table/sequence to a role (optionally ALTER DEFAULT " +
        "PRIVILEGES for future objects). Privileges are bounded by an allow-list. Idempotent.",
      arguments: GrantArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GrantArgs.parse(rawArgs);
        return await runGrant(a, false, context);
      },
    },

    revoke: {
      description:
        "REVOKE privileges (mirror of grant). Idempotent (revoking an absent grant is a no-op). " +
        "With includeFuture it removes only default privileges set for this schema and " +
        "defaultForRole; a default set without IN SCHEMA, or for another role, is left in place.",
      arguments: GrantArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = GrantArgs.parse(rawArgs);
        return await runGrant(a, true, context);
      },
    },

    app_provision: {
      description:
        "Composite, idempotent 'new application' setup: create database + login role (vault password) + " +
        "grant CONNECT, schema USAGE/CREATE, table/sequence privileges, and (default) future-object " +
        "privileges. Once the role directly holds any of the schema-scoped grants (schema " +
        "USAGE/CREATE, table or sequence privileges, default privileges for the schema), a " +
        "re-run grants only the table privileges and future-object privileges it is given, so " +
        "it never widens a role narrowed by hand. CONNECT does not count, so a second schema " +
        "in the same database gets the full set. Revoking every schema-scoped grant resets the " +
        "role to unprovisioned in that schema. Never drops.",
      arguments: AppProvisionArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AppProvisionArgs.parse(rawArgs);
        const g = context.globalArgs;
        const owner = a.owner ?? a.role;
        const ts = new Date().toISOString();

        // Reject every identifier before Phase A creates anything, so a bad
        // schema name cannot leave a role and database behind with no grants.
        checkIdent(g, a.database, "database");
        checkIdent(g, a.role, "role");
        checkIdent(g, owner, "owner");
        checkIdent(g, a.schema, "schema");

        // Phase A: role + database, on the maintenance DB.
        const phaseA = await withConn(g, g.maintenanceDb, false, async (q) => {
          let roleAction: z.infer<typeof Action> = "unchanged";
          if (!(await roleExists(q, a.role))) {
            const parts = [
              `CREATE ROLE ${ident(g, q, a.role, "role")} LOGIN`,
              `CONNECTION LIMIT ${Number(a.connLimit)}`,
            ];
            if (a.password) {
              parts.push(await passwordClause(q, a.password));
            }
            logInfo(context, "app_provision: creating role", { role: a.role });
            await q.query(parts.join(" "));
            roleAction = "created";
          }
          let dbAction: z.infer<typeof Action> = "unchanged";
          if (!(await databaseExists(q, a.database))) {
            logInfo(context, "app_provision: creating database", {
              database: a.database,
              owner,
            });
            await q.query(
              `CREATE DATABASE ${ident(g, q, a.database, "database")} OWNER ${
                ident(g, q, owner, "owner")
              }`,
            );
            dbAction = "created";
          }
          return { roleAction, dbAction };
        });

        // Phase B: schema + object + default privileges, on the target DB.
        const phaseB = await withConn(g, a.database, false, async (q) => {
          // The defaults (SELECT/INSERT/UPDATE/DELETE, future objects) apply
          // only when the role has not been provisioned in this schema before.
          // "Before" is read from the catalog, not from whether this run
          // created the role: a first run that failed after Phase A leaves the
          // role and database in place, and keying on creation would then
          // grant nothing on every re-run. See holdsProvisionGrant for why
          // any one direct schema-scoped grant is the marker. CONNECT and the
          // schema grants are issued only before that point, so a re-run
          // cannot put back a privilege someone revoked to narrow the role.
          const provisioned = await holdsProvisionGrant(q, a.schema, a.role);
          const tablePrivs = a.tablePrivs ??
            (provisioned ? [] : ["SELECT", "INSERT", "UPDATE", "DELETE"]);
          const includeFuture = a.includeFuture ?? !provisioned;
          logInfo(
            context,
            "app_provision: granting in schema {schema} (provisioned before: {provisioned})",
            { schema: a.schema, provisioned },
          );

          const sc = ident(g, q, a.schema, "schema");
          const ro = ident(g, q, a.role, "role");
          await inTransaction(q, async () => {
            if (a.createSchema && a.schema !== "public") {
              await q.query(
                `CREATE SCHEMA IF NOT EXISTS ${sc} AUTHORIZATION ${
                  ident(g, q, owner, "owner")
                }`,
              );
            }
            if (!provisioned) {
              // Database privileges are cluster-wide, so this works from here.
              await q.query(
                `GRANT CONNECT ON DATABASE ${
                  ident(g, q, a.database, "database")
                } TO ${ro}`,
              );
              await q.query(`GRANT USAGE, CREATE ON SCHEMA ${sc} TO ${ro}`);
            }
            const tp = privList(tablePrivs);
            if (tablePrivs.length > 0) {
              await q.query(
                `GRANT ${tp} ON ALL TABLES IN SCHEMA ${sc} TO ${ro}`,
              );
              // Inserting into a serial column needs the sequence too.
              await q.query(
                `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${sc} TO ${ro}`,
              );
            }
            if (includeFuture) {
              // FOR ROLE owner: the owner creates the tables, so its defaults
              // are the ones that decide what the app role gets on them.
              const fr = ident(g, q, owner, "owner");
              if (tablePrivs.length > 0) {
                await q.query(
                  `ALTER DEFAULT PRIVILEGES FOR ROLE ${fr} IN SCHEMA ${sc} GRANT ${tp} ON TABLES TO ${ro}`,
                );
              }
              await q.query(
                `ALTER DEFAULT PRIVILEGES FOR ROLE ${fr} IN SCHEMA ${sc} GRANT USAGE, SELECT ON SEQUENCES TO ${ro}`,
              );
            }
          });
          return {
            provisioned,
            includeFuture,
            privsGranted: [
              ...(provisioned ? [] : ["CONNECT", "USAGE", "CREATE"]),
              ...tablePrivs.map((p) => String(p)),
            ],
          };
        });
        const { includeFuture, privsGranted } = phaseB;

        // "granted" marks a run that issued any grant to a role and database
        // that already existed: the first grants (a re-run after a partial
        // failure, or a role made by role_create), or the table and
        // future-object privileges passed to a provisioned role. "unchanged"
        // would hide that it did work.
        const issuedGrants = !phaseB.provisioned ||
          privsGranted.length > 0 || includeFuture;
        const overall: z.infer<typeof Action> =
          phaseA.roleAction === "created" || phaseA.dbAction === "created"
            ? "created"
            : issuedGrants
            ? "granted"
            : "unchanged";
        const handle = await context.writeResource(
          "app-provision",
          dataName("app-provision", a.database, a.role),
          {
            database: a.database,
            role: a.role,
            schema: a.schema,
            owner,
            privilegesGranted: Array.from(new Set(privsGranted)),
            defaultPrivileges: includeFuture,
            databaseAction: phaseA.dbAction,
            roleAction: phaseA.roleAction,
            action: overall,
            timestamp: ts,
          },
        );
        logInfo(
          context,
          "app_provision: {action}, granted {privilegesGranted}",
          {
            action: overall,
            privilegesGranted: privsGranted,
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;

/** Shared grant/revoke executor. `revoke=true` flips GRANT→REVOKE and TO→FROM. */
async function runGrant(
  a: z.infer<typeof GrantArgs>,
  revoke: boolean,
  context: Ctx,
): Promise<{ dataHandles: DataHandle[] }> {
  const g = context.globalArgs;
  // database-scope grants are cluster-level (work from the maintenance DB);
  // schema/table/sequence grants live in the target database's catalog.
  const connDb = a.scope === "database" ? g.maintenanceDb : a.database;
  const verb = revoke ? "REVOKE" : "GRANT";
  const dir = revoke ? "FROM" : "TO";
  const byName = a.scope !== "database" && a.scope !== "schema" &&
    !a.allInSchema;

  // Default privileges exist only for tables and sequences here. Accepting
  // includeFuture for another scope recorded `includeFuture: true` while
  // nothing future-facing changed.
  if (a.includeFuture && (a.scope === "database" || a.scope === "schema")) {
    throw new Error(
      `includeFuture applies only to table and sequence scope, not ${a.scope}`,
    );
  }
  // allInSchema used to ignore `objects` without a word.
  if (a.allInSchema && a.objects.length > 0) {
    throw new Error("pass either objects[] or allInSchema=true, not both");
  }
  // Without FOR ROLE, ALTER DEFAULT PRIVILEGES targets the current role, which
  // here is the admin login. That silently does nothing for the app's own
  // tables, so refuse rather than guess whose objects the caller meant.
  if (a.includeFuture && !a.defaultForRole) {
    throw new Error(
      "defaultForRole is required when includeFuture is set: name the role " +
        "that will create the future objects. Earlier versions used the admin " +
        `login without saying so; pass defaultForRole=${g.adminUser} to keep ` +
        "that behaviour.",
    );
  }
  // Reject every bad argument before any statement runs, so a call cannot
  // grant on the objects and then fail on the default-privilege step.
  checkIdent(g, a.role, "role");
  if (a.scope === "database") {
    checkIdent(g, a.database, "database");
  } else {
    if (!a.schema) {
      throw new Error(
        `schema is required for ${a.scope}-scope ${verb.toLowerCase()}`,
      );
    }
    checkIdent(g, a.schema, "schema");
  }
  if (byName) {
    if (a.objects.length === 0) {
      throw new Error(
        `provide objects[] or set allInSchema=true for ${a.scope}-scope ${verb.toLowerCase()}`,
      );
    }
    for (const o of a.objects) checkIdent(g, o, a.scope);
  }
  if (a.defaultForRole) checkIdent(g, a.defaultForRole, "defaultForRole");

  logInfo(context, "{verb} {privileges} on {scope} in {database} for {role}", {
    verb,
    privileges: a.privileges.join(", "),
    scope: a.scope,
    database: a.database,
    role: a.role,
  });

  return await withConn(g, connDb, false, async (q) => {
    const ro = ident(g, q, a.role, "role");
    const privs = privList(a.privileges);
    const objects: string[] = [];

    // One transaction: if the default-privilege step fails (say, the
    // defaultForRole role does not exist), the object grant must not stay.
    await inTransaction(q, async () => {
      if (a.scope === "database") {
        const db = ident(g, q, a.database, "database");
        await q.query(`${verb} ${privs} ON DATABASE ${db} ${dir} ${ro}`);
        objects.push(a.database);
        return;
      }
      const schema = a.schema!; // checked above
      const sc = ident(g, q, schema, "schema");
      if (a.scope === "schema") {
        await q.query(`${verb} ${privs} ON SCHEMA ${sc} ${dir} ${ro}`);
        objects.push(schema);
        return;
      }
      const kw = a.scope === "table" ? "TABLE" : "SEQUENCE";
      const kwAll = a.scope === "table" ? "TABLES" : "SEQUENCES";
      if (byName) {
        const list = a.objects.map((o) => `${sc}.${ident(g, q, o, a.scope)}`)
          .join(", ");
        await q.query(`${verb} ${privs} ON ${kw} ${list} ${dir} ${ro}`);
        objects.push(...a.objects.map((o) => `${schema}.${o}`));
      } else {
        await q.query(
          `${verb} ${privs} ON ALL ${kwAll} IN SCHEMA ${sc} ${dir} ${ro}`,
        );
        objects.push(`ALL ${kwAll} IN ${schema}`);
      }
      if (a.includeFuture && a.defaultForRole) {
        const fr = ident(g, q, a.defaultForRole, "defaultForRole");
        await q.query(
          `ALTER DEFAULT PRIVILEGES FOR ROLE ${fr} IN SCHEMA ${sc} ${verb} ${privs} ON ${kwAll} ${dir} ${ro}`,
        );
      }
    });

    const handle = await context.writeResource(
      "grant-result",
      dataName("grant-result", a.database, a.scope, a.role),
      {
        database: a.database,
        scope: a.scope,
        role: a.role,
        privileges: a.privileges.map((p) => String(p)),
        objects,
        schema: a.schema,
        includeFuture: a.includeFuture,
        action: revoke ? "revoked" : "granted",
        timestamp: new Date().toISOString(),
      },
    );
    logInfo(context, "{verb} done on {objects}", {
      verb,
      objects: objects.join(", "),
    });
    return { dataHandles: [handle] };
  });
}
