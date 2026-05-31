import { z } from "npm:zod@4";
// Type-only imports — erased at compile time, never bundled. They anchor the
// `satisfies ModelDefinition<typeof GlobalArgs>` clause so each method's
// `execute` is contextually typed without an explicit `any`.
import type {
  DataHandle,
  MethodContext,
  ModelDefinition,
} from "jsr:@systeminit/swamp-testing@0.20260521.16";
// `pg` ships no bundled types; point the type-checker (and `deno doc`, which the
// quality scorer runs) at the DefinitelyTyped package so it can resolve them.
// @ts-types="npm:@types/pg@8.20.0"
import pg from "npm:pg@8.21.0";

/**
 * `@thomas/postgres-admin` — non-destructive PostgreSQL administration over a
 * direct TCP connection (node-postgres).
 *
 * SCOPE GUARANTEE (the whole point of this extension): it holds a powerful admin
 * credential, so its surface is deliberately narrow and DATA-SAFE. It NEVER reads
 * or writes table rows (no SELECT/INSERT/UPDATE/DELETE against user tables), NEVER
 * DROPs a database or role, NEVER TRUNCATEs, and exposes NO arbitrary-SQL method.
 * Every method issues author-controlled DDL or catalog reads (pg_catalog /
 * information_schema) only. Read methods additionally run under
 * `default_transaction_read_only = on` as a hard backstop.
 *
 * Method sections (by prefix):
 *   - read/audit: `database_list`, `role_list`, `permissions_audit`,
 *     `table_inspect`, `connections_list`, `extension_list`.
 *   - mutating (admin DDL): `database_create`, `role_create`, `grant`, `revoke`,
 *     `role_password_set`, and the composite `app_provision`.
 *
 * Connection: one short-lived `pg.Client` per method run (connect → work →
 * `end()` in a `finally`); no pool — swamp already serialises per-model.
 *
 * Identifier safety: identifiers (db/role/schema/table names) are validated
 * against `identifierPattern` AND escaped via `client.escapeIdentifier`; the role
 * password is embedded only via `client.escapeLiteral` (DDL can't parameterise an
 * identifier or a PASSWORD literal). Filter VALUES in catalog reads use bound `$1`
 * params. Passwords are marked sensitive, never logged, never echoed in output.
 * CAVEAT: if the server runs `log_statement = ddl|all`, a `CREATE/ALTER ROLE …
 * PASSWORD '…'` lands in the SERVER log — that's a server-side setting outside
 * this extension's control; it does not try to mutate it to hide the password.
 *
 * Secrets: `adminPassword` (and per-call role passwords) are supplied via vault
 * expressions, e.g. `${{ vault.get(<vault>, postgres/admin_password) }}`.
 */

// ─────────────────────────── global arguments ───────────────────────────

const SslConfig = z.object({
  mode: z.enum(["disable", "require", "verify-ca", "verify-full"]).default(
    "disable",
  ).describe(
    "disable = plaintext TCP (homelab tailnet default). require = encrypt, no " +
      "cert verify. verify-ca/verify-full = encrypt + verify (needs `ca`).",
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
    "Postgres host or IP, e.g. postgres-host or 10.0.0.5",
  ),
  port: z.coerce.number().int().default(5432).describe("Postgres TCP port"),
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
  statementTimeoutMs: z.coerce.number().int().default(30000).describe(
    "statement_timeout (ms) applied per session as a guardrail",
  ),
  identifierPattern: z.string().default("^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")
    .describe(
      "Safe-identifier regex enforced (in addition to escaping) before any DDL",
    ),
});

// Resolved global-argument shape (connection target + safety knobs). Kept
// internal: `z.infer` is a "slow type", so it must not leak onto the public API
// (the exported `ConnectFn` seam uses the loose `Json` instead — see below).
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
 * (Zod rejects anything outside it) — TRUNCATE / ALL are intentionally excluded. */
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

/** Table-level privileges valid as app_provision defaults. */
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
  databasePrivileges: z.array(z.string()),
  schemaPrivileges: z.array(SchemaPriv),
  tableGrants: z.array(TableGrant),
  usageGrants: z.array(TableGrant),
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

/** Minimal querier surface the methods use — swappable for unit tests. */
export interface Querier {
  /** Run a parameterised SQL statement; filter VALUES go in `params` as bound `$n`. */
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
/** A JSON-ish bag — structurally the resolved global args. */
export type Json = Record<string, unknown>;
/**
 * Open a connection to `database` on the configured server. The global args are
 * typed loosely as {@link Json} so this EXPORTED seam type stays "fast-check"
 * clean — referencing the zod-inferred `GlobalArgsT` would drag a slow type onto
 * the public API. The real implementation re-narrows to the validated shape.
 */
export type ConnectFn = (g: Json, database: string) => Promise<Conn>;

let _connectOverride: ConnectFn | null = null;

/** Test-only seam: substitute the pg connector. Pass `null` to restore the real one. */
export function __setPgConnect(fn: ConnectFn | null): void {
  _connectOverride = fn;
}

function sslToPg(s: GlobalArgsT["ssl"]): boolean | Record<string, unknown> {
  switch (s.mode) {
    case "disable":
      return false;
    case "require":
      return { rejectUnauthorized: s.rejectUnauthorized ?? false };
    case "verify-ca":
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
 * Connect to `database`, apply session guardrails, run `fn`, and ALWAYS close the
 * socket (error path included). Read methods pass `readOnly: true` which sets
 * `default_transaction_read_only = on` — a hard backstop against any accidental
 * mutation. Mutating methods pass `readOnly: false`.
 */
async function withConn<T>(
  g: GlobalArgsT,
  database: string,
  readOnly: boolean,
  fn: (q: Querier) => Promise<T>,
): Promise<T> {
  const { q, end } = await connect(g, database);
  try {
    await q.query(`SET statement_timeout = ${Number(g.statementTimeoutMs)}`);
    if (readOnly) await q.query("SET default_transaction_read_only = on");
    return await fn(q);
  } finally {
    await end();
  }
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

/** Validate an identifier against the configured pattern (defence-in-depth on top
 * of escaping), then return its safely-escaped form. Throws on a bad identifier. */
function ident(
  g: GlobalArgsT,
  q: Querier,
  name: string,
  label: string,
): string {
  if (!new RegExp(g.identifierPattern).test(name)) {
    throw new Error(
      `Invalid ${label} identifier ${
        JSON.stringify(name)
      }: must match ${g.identifierPattern}`,
    );
  }
  return q.escapeIdentifier(name);
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

/** Read one database's catalog row into a DatabaseInfo (minus action/timestamp). */
async function readDatabase(
  q: Querier,
  name: string,
): Promise<Record<string, unknown> | null> {
  const r = await q.query(
    `SELECT d.datname AS name, pg_get_userbyid(d.datdba) AS owner,
            pg_encoding_to_char(d.encoding) AS encoding,
            d.datcollate AS collate, d.datctype AS ctype,
            pg_database_size(d.datname) AS size_bytes,
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

/** Join an already-validated privilege list into a SQL fragment (enum-bounded, safe). */
function privList(privs: string[]): string {
  return privs.map((p) => p.toUpperCase()).join(", ");
}

// ─────────────────────────── method argument schemas ───────────────────────────

const DatabaseListArgs = z.object({
  includeTemplates: z.preprocess((v) => v === true || v === "true", z.boolean())
    .default(false)
    .describe("Include template databases (template0/template1)"),
});

const PermissionsAuditArgs = z.object({
  database: z.string().describe("Database to audit (connects to it)"),
  role: z.string().optional().describe(
    "Role to scope the audit to; omit to list all table/usage grants in the db",
  ),
});

const TableInspectArgs = z.object({
  database: z.string(),
  schema: z.string().default("public"),
  table: z.string(),
});

const ConnectionsListArgs = z.object({
  database: z.string().optional().describe("Filter to one database's backends"),
  includeQuery: z.preprocess((v) => v === true || v === "true", z.boolean())
    .default(false)
    .describe(
      "Include the current `query` text. OFF by default — query text can contain " +
        "literal row data, which would violate the no-data-reads guarantee.",
    ),
});

const ExtensionListArgs = z.object({
  database: z.string().optional().describe(
    "One database; omit to fan out across all connectable databases",
  ),
});

const DatabaseCreateArgs = z.object({
  name: z.string(),
  owner: z.string().optional(),
  encoding: z.string().optional().describe(
    "Only emitted when set; a non-default encoding usually needs template0",
  ),
  template: z.string().optional(),
  locale: z.string().optional(),
});

const RoleCreateArgs = z.object({
  name: z.string(),
  login: z.preprocess(
    (v) => v === undefined ? true : v === true || v === "true",
    z.boolean(),
  )
    .default(true),
  password: z.string().optional().meta({ sensitive: true }).describe(
    "Supply via vault expression; embedded via escapeLiteral, never logged/echoed",
  ),
  connLimit: z.coerce.number().int().default(-1),
  validUntil: z.string().optional().describe(
    "e.g. 2027-01-01 (a timestamp literal)",
  ),
  createDb: z.preprocess((v) => v === true || v === "true", z.boolean())
    .default(false),
  createRole: z.preprocess((v) => v === true || v === "true", z.boolean())
    .default(false),
  memberOf: z.array(z.string()).default([]).describe(
    "Parent roles to GRANT to this role",
  ),
});

const GrantScope = z.enum(["database", "schema", "table", "sequence"]);

const GrantArgs = z.object({
  database: z.string(),
  scope: GrantScope,
  privileges: z.array(Privilege).min(1),
  role: z.string(),
  schema: z.string().optional().describe(
    "Required for schema/table/sequence scope",
  ),
  objects: z.array(z.string()).default([]).describe(
    "Specific table/sequence names; empty + allInSchema=true targets ALL in schema",
  ),
  allInSchema: z.preprocess((v) => v === true || v === "true", z.boolean())
    .default(false),
  includeFuture: z.preprocess((v) => v === true || v === "true", z.boolean())
    .default(false)
    .describe("Also ALTER DEFAULT PRIVILEGES for future objects in the schema"),
  defaultForRole: z.string().optional().describe(
    "FOR ROLE in ALTER DEFAULT PRIVILEGES (the object-creating role); defaults to the schema owner's future objects",
  ),
});

const RolePasswordSetArgs = z.object({
  name: z.string(),
  password: z.string().meta({ sensitive: true }),
});

const AppProvisionArgs = z.object({
  database: z.string(),
  role: z.string(),
  password: z.string().optional().meta({ sensitive: true }).describe(
    "Login password for a NEW role (ignored if the role already exists)",
  ),
  owner: z.string().optional().describe(
    "Database/schema owner; defaults to `role`",
  ),
  schema: z.string().default("public"),
  createSchema: z.preprocess((v) => v === true || v === "true", z.boolean())
    .default(false),
  tablePrivs: z.array(TablePrivilege).default([
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
  ]),
  includeFuture: z.preprocess(
    (v) => v === undefined ? true : v === true || v === "true",
    z.boolean(),
  )
    .default(true),
  connLimit: z.coerce.number().int().default(-1),
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
  version: "2026.06.01.1",
  globalArguments: GlobalArgs,
  checks: {
    "reachable": {
      description:
        "Verify the Postgres server is reachable (SELECT 1 to maintenanceDb)",
      labels: ["live"],
      execute: async (context: Pick<Ctx, "globalArgs">) => {
        const g = context.globalArgs;
        // `swamp model validate` does NOT resolve vault expressions before running
        // checks, so the password is still a literal `${{ … }}` string there and a
        // probe can't authenticate. Skip in that case — the real connectivity check
        // runs at method-run time, where the secret is resolved.
        if (/\$\{\{/.test(String(g.adminPassword))) return { pass: true };
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
                    pg_database_size(d.datname) AS size_bytes,
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
                String(row.name),
                shapeDatabase(row, "observed", ts),
              ),
            );
          }
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
          const r = await q.query(
            `SELECT r.rolname AS name, r.rolcanlogin AS login, r.rolsuper AS superuser,
                    r.rolcreatedb AS create_db, r.rolcreaterole AS create_role,
                    r.rolreplication AS replication, r.rolbypassrls AS bypass_rls,
                    r.rolconnlimit AS conn_limit, r.rolvaliduntil AS valid_until,
                    ARRAY(SELECT g.rolname FROM pg_auth_members m
                            JOIN pg_roles g ON g.oid = m.roleid
                           WHERE m.member = r.oid ORDER BY g.rolname) AS member_of
               FROM pg_roles r ORDER BY r.rolname`,
          );
          const ts = new Date().toISOString();
          const handles: DataHandle[] = [];
          for (const row of r.rows) {
            handles.push(
              await context.writeResource("role", String(row.name), {
                name: String(row.name),
                login: asBool(row.login),
                superuser: asBool(row.superuser),
                createDb: asBool(row.create_db),
                createRole: asBool(row.create_role),
                replication: asBool(row.replication),
                bypassRls: asBool(row.bypass_rls),
                connLimit: asNum(row.conn_limit),
                validUntil: asStr(row.valid_until),
                memberOf: (row.member_of as string[] | null) ?? [],
                action: "observed",
                timestamp: ts,
              }),
            );
          }
          return { dataHandles: handles };
        });
      },
    },

    permissions_audit: {
      description:
        "Audit privileges for a database (optionally a single role): database/schema privileges, " +
        "table & usage grants, and default privileges. Catalog reads only.",
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
          const databasePrivileges: string[] = [];
          const schemaPrivileges: Array<z.infer<typeof SchemaPriv>> = [];

          if (a.role) {
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

          const tg = await q.query(
            `SELECT table_schema AS schema, table_name AS name, privilege_type AS privilege, is_grantable
               FROM information_schema.role_table_grants
              WHERE ($1::text IS NULL OR grantee = $1)
              ORDER BY table_schema, table_name, privilege_type`,
            [a.role ?? null],
          );
          const tableGrants = tg.rows.map((row) => ({
            schema: String(row.schema),
            name: String(row.name),
            privilege: String(row.privilege),
            grantable: asBool(row.is_grantable),
          }));

          const ug = await q.query(
            `SELECT object_schema AS schema, object_name AS name, privilege_type AS privilege, is_grantable
               FROM information_schema.role_usage_grants
              WHERE ($1::text IS NULL OR grantee = $1)
              ORDER BY object_schema, object_name, privilege_type`,
            [a.role ?? null],
          );
          const usageGrants = ug.rows.map((row) => ({
            schema: asStr(row.schema) ?? "",
            name: asStr(row.name) ?? "",
            privilege: String(row.privilege),
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
            `${a.database}-${a.role ?? "all"}`,
            {
              database: a.database,
              role: a.role,
              databasePrivileges,
              schemaPrivileges,
              tableGrants,
              usageGrants,
              defaultPrivileges,
              action: "observed",
              timestamp: ts,
            },
          );
          return { dataHandles: [handle] };
        });
      },
    },

    table_inspect: {
      description:
        "Describe a table: columns, primary key, indexes, constraints, owner. Catalog only — NEVER reads table rows.",
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
          const exists = await q.query(
            "SELECT to_regclass(format('%I.%I', $1::text, $2::text)) IS NOT NULL AS present",
            [a.schema, a.table],
          );
          if (!asBool(exists.rows[0]?.present)) {
            throw new Error(
              `Table ${a.schema}.${a.table} does not exist in database ${a.database}`,
            );
          }

          const cols = await q.query(
            `SELECT column_name AS name, data_type AS type, is_nullable AS nullable,
                    column_default AS def, ordinal_position AS position
               FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2
              ORDER BY ordinal_position`,
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
            `${a.database}-${a.schema}-${a.table}`,
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
          return { dataHandles: [handle] };
        });
      },
    },

    connections_list: {
      description:
        "List backends from pg_stat_activity (factory: one `connection` per pid). The `query` " +
        "column is OMITTED unless includeQuery=true (it can contain row data).",
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
            `SELECT pid, usename AS "user", datname AS db, state, client_addr::text AS client_addr,
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
              await context.writeResource("connection", String(row.pid), {
                pid: asNum(row.pid),
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
              }),
            );
          }
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

        const ts = new Date().toISOString();
        const handles: DataHandle[] = [];
        for (const db of dbs) {
          await withConn(g, db, true, async (q) => {
            const r = await q.query(
              `SELECT e.extname AS name, e.extversion AS version, n.nspname AS schema
                 FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
                ORDER BY e.extname`,
            );
            for (const row of r.rows) {
              handles.push(
                await context.writeResource(
                  "extension",
                  `${db}-${String(row.name)}`,
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
          });
        }
        return { dataHandles: handles };
      },
    },

    // ───────────── mutating (admin DDL, data-safe) ─────────────
    database_create: {
      description:
        "Create a database (idempotent: returns the existing one as `unchanged`). Never drops.",
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
            logInfo(context, "Database already exists; unchanged", {
              name: a.name,
            });
            const row = await readDatabase(q, a.name);
            const handle = await context.writeResource(
              "database",
              a.name,
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
          await q.query(parts.join(" ")); // bare statement — CREATE DATABASE cannot run in a txn
          const row = await readDatabase(q, a.name);
          const handle = await context.writeResource(
            "database",
            a.name,
            shapeDatabase(row!, "created", ts),
          );
          return { dataHandles: [handle] };
        });
      },
    },

    role_create: {
      description:
        "Create a login/group role (idempotent: existing role returned as `unchanged`, not altered). Never drops.",
      arguments: RoleCreateArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = RoleCreateArgs.parse(rawArgs);
        const g = context.globalArgs;
        return await withConn(g, g.maintenanceDb, false, async (q) => {
          const ts = new Date().toISOString();
          if (await roleExists(q, a.name)) {
            logInfo(context, "Role already exists; unchanged", {
              name: a.name,
            });
            const handle = await context.writeResource("role-result", a.name, {
              role: a.name,
              action: "unchanged",
              passwordSet: false,
              timestamp: ts,
            });
            return { dataHandles: [handle] };
          }
          const parts = [`CREATE ROLE ${ident(g, q, a.name, "role")}`];
          parts.push(a.login ? "LOGIN" : "NOLOGIN");
          if (a.createDb) parts.push("CREATEDB");
          if (a.createRole) parts.push("CREATEROLE");
          parts.push(`CONNECTION LIMIT ${Number(a.connLimit)}`);
          if (a.password) parts.push(`PASSWORD ${q.escapeLiteral(a.password)}`);
          if (a.validUntil) {
            parts.push(`VALID UNTIL ${q.escapeLiteral(a.validUntil)}`);
          }
          logInfo(context, "Creating role", { name: a.name, login: a.login }); // never logs password
          await q.query(parts.join(" "));
          for (const parent of a.memberOf) {
            await q.query(
              `GRANT ${ident(g, q, parent, "parent role")} TO ${
                ident(g, q, a.name, "role")
              }`,
            );
          }
          const handle = await context.writeResource("role-result", a.name, {
            role: a.name,
            action: "created",
            passwordSet: !!a.password,
            timestamp: ts,
          });
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
            `ALTER ROLE ${ident(g, q, a.name, "role")} PASSWORD ${
              q.escapeLiteral(a.password)
            }`,
          );
          const handle = await context.writeResource("role-result", a.name, {
            role: a.name,
            action: "rotated",
            passwordSet: true,
            timestamp: new Date().toISOString(),
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
        "REVOKE privileges (mirror of grant). Idempotent (revoking an absent grant is a no-op).",
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
        "privileges. Re-running converges. The headline method. Never drops.",
      arguments: AppProvisionArgs,
      execute: async (
        rawArgs,
        context,
      ): Promise<{ dataHandles: DataHandle[] }> => {
        const a = AppProvisionArgs.parse(rawArgs);
        const g = context.globalArgs;
        const owner = a.owner ?? a.role;
        const ts = new Date().toISOString();

        // Phase A — role + database + CONNECT, on the maintenance DB.
        const phaseA = await withConn(g, g.maintenanceDb, false, async (q) => {
          let roleAction: z.infer<typeof Action> = "unchanged";
          if (!(await roleExists(q, a.role))) {
            const parts = [
              `CREATE ROLE ${ident(g, q, a.role, "role")} LOGIN`,
              `CONNECTION LIMIT ${Number(a.connLimit)}`,
            ];
            if (a.password) {
              parts.push(`PASSWORD ${q.escapeLiteral(a.password)}`);
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
          await q.query(
            `GRANT CONNECT ON DATABASE ${
              ident(g, q, a.database, "database")
            } TO ${ident(g, q, a.role, "role")}`,
          );
          return { roleAction, dbAction };
        });

        // Phase B — schema + object + default privileges, on the target DB.
        const privsGranted = await withConn(g, a.database, false, async (q) => {
          const sc = ident(g, q, a.schema, "schema");
          const ro = ident(g, q, a.role, "role");
          if (a.createSchema && a.schema !== "public") {
            await q.query(
              `CREATE SCHEMA IF NOT EXISTS ${sc} AUTHORIZATION ${
                ident(g, q, owner, "owner")
              }`,
            );
          }
          await q.query(`GRANT USAGE, CREATE ON SCHEMA ${sc} TO ${ro}`);
          const tp = privList(a.tablePrivs);
          await q.query(`GRANT ${tp} ON ALL TABLES IN SCHEMA ${sc} TO ${ro}`);
          await q.query(
            `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${sc} TO ${ro}`,
          );
          if (a.includeFuture) {
            const fr = ident(g, q, owner, "owner");
            await q.query(
              `ALTER DEFAULT PRIVILEGES FOR ROLE ${fr} IN SCHEMA ${sc} GRANT ${tp} ON TABLES TO ${ro}`,
            );
            await q.query(
              `ALTER DEFAULT PRIVILEGES FOR ROLE ${fr} IN SCHEMA ${sc} GRANT USAGE, SELECT ON SEQUENCES TO ${ro}`,
            );
          }
          return [
            "CONNECT",
            "USAGE",
            "CREATE",
            ...a.tablePrivs.map((p) => String(p)),
          ];
        });

        const overall: z.infer<typeof Action> =
          phaseA.roleAction === "created" || phaseA.dbAction === "created"
            ? "created"
            : "unchanged";
        const handle = await context.writeResource(
          "app-provision",
          a.database,
          {
            database: a.database,
            role: a.role,
            schema: a.schema,
            owner,
            privilegesGranted: Array.from(new Set(privsGranted)),
            defaultPrivileges: a.includeFuture,
            databaseAction: phaseA.dbAction,
            roleAction: phaseA.roleAction,
            action: overall,
            timestamp: ts,
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

  return await withConn(g, connDb, false, async (q) => {
    const ro = ident(g, q, a.role, "role");
    const privs = privList(a.privileges);
    const objects: string[] = [];

    if (a.scope === "database") {
      const db = ident(g, q, a.database, "database");
      await q.query(`${verb} ${privs} ON DATABASE ${db} ${dir} ${ro}`);
      objects.push(a.database);
    } else {
      if (!a.schema) {
        throw new Error(
          `schema is required for ${a.scope}-scope ${verb.toLowerCase()}`,
        );
      }
      const sc = ident(g, q, a.schema, "schema");
      if (a.scope === "schema") {
        await q.query(`${verb} ${privs} ON SCHEMA ${sc} ${dir} ${ro}`);
        objects.push(a.schema);
      } else {
        const kw = a.scope === "table" ? "TABLE" : "SEQUENCE";
        const kwAll = a.scope === "table" ? "TABLES" : "SEQUENCES";
        if (a.allInSchema) {
          await q.query(
            `${verb} ${privs} ON ALL ${kwAll} IN SCHEMA ${sc} ${dir} ${ro}`,
          );
          objects.push(`ALL ${kwAll} IN ${a.schema}`);
        } else {
          if (a.objects.length === 0) {
            throw new Error(
              `provide objects[] or set allInSchema=true for ${a.scope}-scope ${verb.toLowerCase()}`,
            );
          }
          const list = a.objects.map((o) => `${sc}.${ident(g, q, o, a.scope)}`)
            .join(", ");
          await q.query(`${verb} ${privs} ON ${kw} ${list} ${dir} ${ro}`);
          objects.push(...a.objects.map((o) => `${a.schema}.${o}`));
        }
        if (a.includeFuture) {
          const forRole = a.defaultForRole
            ? `FOR ROLE ${ident(g, q, a.defaultForRole, "defaultForRole")} `
            : "";
          await q.query(
            `ALTER DEFAULT PRIVILEGES ${forRole}IN SCHEMA ${sc} ${verb} ${privs} ON ${kwAll} ${dir} ${ro}`,
          );
        }
      }
    }

    const handle = await context.writeResource(
      "grant-result",
      `${a.database}-${a.scope}-${a.role}`,
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
    return { dataHandles: [handle] };
  });
}
