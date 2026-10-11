/**
 * Unit tests for the security-sensitive logic of `@thomas/postgres-admin`,
 * where an unnoticed bug would be costly:
 * identifier escaping, password hashing (SCRAM verifier + no leakage), connection-DB
 * routing, idempotency, connections_list redaction, the read-only backstop, and
 * connection cleanup on the error path. No live DB: the pg connector is faked via
 * the __setPgConnect seam.
 */
import {
  __setPgConnect,
  type Conn,
  type ConnectFn,
  dataName,
  model,
  type Querier,
  scramSha256Verifier,
  sslToPg,
} from "./postgres-admin.ts";

function assertEquals(actual: unknown, expected: unknown, msg?: string): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error(
      `assertEquals failed${
        msg ? ` (${msg})` : ""
      }\n  actual:   ${a}\n  expected: ${e}`,
    );
  }
}
function assert(cond: unknown, msg?: string): void {
  if (!cond) throw new Error(`assert failed${msg ? `: ${msg}` : ""}`);
}
async function rejects(fn: () => Promise<unknown>, re: RegExp): Promise<void> {
  try {
    await fn();
  } catch (e) {
    assert(
      re.test((e as Error).message),
      `expected /${re.source}/, got: ${(e as Error).message}`,
    );
    return;
  }
  throw new Error(`expected rejection matching /${re.source}/`);
}

const GLOBALS = {
  host: "192.0.2.10",
  port: 5433,
  adminUser: "postgres",
  adminPassword: "admin-pw",
  maintenanceDb: "postgres",
  ssl: { mode: "disable" as const },
  statementTimeoutMs: 30000,
  identifierPattern: "^[a-zA-Z_][a-zA-Z0-9_]{0,62}$",
};

type Recorded = { db: string; sql: string; params?: unknown[] };

/** A fake pg connector. `rowsFor` returns canned rows for a SQL (substring match). */
function makeFakeDb(
  rowsFor?: (
    sql: string,
    params?: unknown[],
  ) => Record<string, unknown>[] | undefined,
) {
  const queries: Recorded[] = [];
  const connectDbs: string[] = [];
  let endCount = 0;
  const connect: ConnectFn = (_g, database): Promise<Conn> => {
    connectDbs.push(database);
    const q: Querier = {
      query: (sql, params) => {
        queries.push({ db: database, sql, params });
        return Promise.resolve({ rows: rowsFor?.(sql, params) ?? [] });
      },
      // Deterministic stand-ins for libpq's routines, enough to assert "was escaped".
      escapeIdentifier: (s) => '"' + s.replace(/"/g, '""') + '"',
      escapeLiteral: (s) => "'" + s.replace(/'/g, "''") + "'",
    };
    return Promise.resolve({
      q,
      end: () => {
        endCount++;
        return Promise.resolve();
      },
    });
  };
  return { connect, queries, connectDbs, endCount: () => endCount };
}

type LogCall = { msg: string; props?: unknown };
function makeContext() {
  const written: Array<
    { specName: string; name: string; data: Record<string, unknown> }
  > = [];
  const logs: LogCall[] = [];
  const warnings: LogCall[] = [];
  const noop = () => {};
  const context = {
    globalArgs: GLOBALS,
    logger: {
      info: (msg: string, props?: unknown) => logs.push({ msg, props }),
      debug: noop,
      warn: (msg: string, props?: unknown) => warnings.push({ msg, props }),
      error: noop,
    },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      // Validate against the spec's schema, as a stored record would be read:
      // a wrong-typed field must fail the test, not slip through.
      const spec = (model.resources as unknown as Record<
        string,
        { schema: { parse: (v: unknown) => unknown } }
      >)[specName];
      spec.schema.parse(data);
      const h = { specName, name, data };
      written.push(h);
      return Promise.resolve(h);
    },
  };
  return { context, written, logs, warnings };
}

type MethodDef = {
  execute: (
    args: unknown,
    context: unknown,
  ) => Promise<{ dataHandles: unknown[] }>;
};
const method = (name: string): MethodDef =>
  (model.methods as unknown as Record<string, MethodDef>)[name];

const sqls = (qs: Recorded[]) => qs.map((q) => q.sql);
const hasSql = (qs: Recorded[], re: RegExp) => qs.some((q) => re.test(q.sql));

// ─────────────────────────── database_create ───────────────────────────

Deno.test("database_create: escapes identifiers, runs bare CREATE DATABASE, action=created", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_database WHERE datname/.test(sql)
      ? []
      : /pg_get_userbyid/.test(sql)
      ? [{ name: "myapp", owner: "ownr", encoding: "UTF8" }]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("database_create").execute(
      { name: "myapp", owner: "ownr" },
      context,
    );
    assert(
      hasSql(fake.queries, /^CREATE DATABASE "myapp" OWNER "ownr"$/),
      `CREATE not as expected: ${JSON.stringify(sqls(fake.queries))}`,
    );
    assertEquals(
      fake.connectDbs[0],
      "postgres",
      "must connect to maintenanceDb",
    );
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].name, "database:myapp");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("database_create: idempotent — existing db is unchanged, no CREATE issued", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_database WHERE datname/.test(sql)
      ? [{ "?column?": 1 }]
      : /pg_get_userbyid/.test(sql)
      ? [{ name: "myapp", owner: "ownr", encoding: "UTF8" }]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("database_create").execute({ name: "myapp" }, context);
    assert(
      !hasSql(fake.queries, /CREATE DATABASE/),
      "must not CREATE when it exists",
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("database_create: rejects an unsafe identifier before any DDL", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("database_create").execute(
          { name: "bad-name; DROP DATABASE x" },
          context,
        ),
      /Invalid database identifier/,
    );
    assert(
      !hasSql(fake.queries, /CREATE DATABASE/),
      "no DDL on a rejected identifier",
    );
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── role_create (password handling) ───────────────────────────

// What a hashed PASSWORD clause looks like: iterations, salt, StoredKey:ServerKey.
const SCRAM_CLAUSE =
  /PASSWORD 'SCRAM-SHA-256\$4096:[A-Za-z0-9+\/]{22}==\$[A-Za-z0-9+\/]{43}=:[A-Za-z0-9+\/]{43}='/;

Deno.test("role_create: password sent only as a SCRAM verifier, never logged or echoed", async () => {
  const SENTINEL = "S3CRET-SENTINEL";
  const fake = makeFakeDb((sql) =>
    /FROM pg_roles WHERE rolname/.test(sql) ? [] : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written, logs } = makeContext();
    await method("role_create").execute({
      name: "appuser",
      password: SENTINEL,
      memberOf: ["readers"],
    }, context);

    // CREATE ROLE carries a SCRAM verifier, and the plain text is in no statement.
    assert(
      hasSql(
        fake.queries,
        /CREATE ROLE "appuser" LOGIN CONNECTION LIMIT -1 /,
      ) &&
        hasSql(fake.queries, SCRAM_CLAUSE),
      `CREATE ROLE shape: ${JSON.stringify(sqls(fake.queries))}`,
    );
    assert(
      !JSON.stringify(fake.queries).includes(SENTINEL),
      "plain-text password sent to the server",
    );
    // membership grant is escaped, and runs in the same transaction as CREATE ROLE
    assert(
      hasSql(fake.queries, /GRANT "readers" TO "appuser"/),
      "member_of GRANT",
    );
    const order = sqls(fake.queries);
    assert(
      order.indexOf("BEGIN") < order.findIndex((s) => /CREATE ROLE/.test(s)),
      "BEGIN before CREATE ROLE",
    );
    assert(
      order.findIndex((s) => /GRANT "readers"/.test(s)) <
        order.indexOf("COMMIT"),
      "GRANT before COMMIT",
    );
    // the password must NOT appear in any log line or in any written resource
    assert(
      !JSON.stringify(logs).includes(SENTINEL),
      "password leaked into logs",
    );
    assert(
      !JSON.stringify(written).includes(SENTINEL),
      "password leaked into a resource",
    );
    assertEquals(written[0].data.passwordSet, true);
    assertEquals(written[0].data.action, "created");
  } finally {
    __setPgConnect(null);
  }
});

// A parent checked only when its GRANT came round used to leave the role
// created with the earlier memberships, and the next run called it unchanged.
Deno.test("role_create: a bad second parent is rejected before CREATE ROLE runs", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_roles WHERE rolname/.test(sql) ? [] : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("role_create").execute({
          name: "appuser",
          memberOf: ["readers", "bad;role"],
        }, context),
      /Invalid parent role identifier/,
    );
    assertEquals(fake.queries.length, 0, "no statement issued");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("role_password_set: ALTER ROLE … PASSWORD with a SCRAM verifier; rejects missing role", async () => {
  const SENTINEL = "rot-pw'with'quote";
  const fake = makeFakeDb((sql) =>
    /FROM pg_roles WHERE rolname/.test(sql) ? [{ x: 1 }] : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written, logs } = makeContext();
    await method("role_password_set").execute({
      name: "appuser",
      password: SENTINEL,
    }, context);
    assert(
      hasSql(fake.queries, /ALTER ROLE "appuser" PASSWORD 'SCRAM-SHA-256\$/) &&
        hasSql(fake.queries, SCRAM_CLAUSE),
      `ALTER shape: ${JSON.stringify(sqls(fake.queries))}`,
    );
    assert(
      !JSON.stringify(fake.queries).includes("rot-pw"),
      "plain-text password sent to the server",
    );
    assert(
      !JSON.stringify(logs).includes(SENTINEL) &&
        !JSON.stringify(written).includes(SENTINEL),
      "rotation password leaked",
    );
    assertEquals(written[0].data.action, "rotated");
  } finally {
    __setPgConnect(null);
  }
  // missing role → throws before ALTER
  const fake2 = makeFakeDb(() => []);
  __setPgConnect(fake2.connect);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("role_password_set").execute(
          { name: "ghost", password: "x" },
          context,
        ),
      /does not exist/,
    );
    assert(!hasSql(fake2.queries, /ALTER ROLE/), "no ALTER for a missing role");
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── grant routing + escaping ───────────────────────────

Deno.test("grant: table scope connects to target db, escapes, and adds default privileges", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("grant").execute({
      database: "myapp",
      scope: "table",
      privileges: ["SELECT", "INSERT"],
      role: "appuser",
      schema: "public",
      allInSchema: true,
      includeFuture: true,
      defaultForRole: "appowner",
    }, context);
    assertEquals(
      fake.connectDbs[0],
      "myapp",
      "table-scope grant connects to the target db",
    );
    assert(
      hasSql(
        fake.queries,
        /GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA "public" TO "appuser"/,
      ),
      `GRANT: ${JSON.stringify(sqls(fake.queries))}`,
    );
    assert(
      hasSql(
        fake.queries,
        /ALTER DEFAULT PRIVILEGES FOR ROLE "appowner" IN SCHEMA "public" GRANT SELECT, INSERT ON TABLES TO "appuser"/,
      ),
      "default privileges name the creating role",
    );
    assertEquals(written[0].data.action, "granted");
    assertEquals(written[0].name, "grant-result:myapp:table:appuser");
  } finally {
    __setPgConnect(null);
  }
});

// Without FOR ROLE, ALTER DEFAULT PRIVILEGES changes the connecting admin's
// own defaults, which never touch the app owner's tables.
Deno.test("grant: includeFuture without defaultForRole is refused before any SQL", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("grant").execute({
          database: "myapp",
          scope: "table",
          privileges: ["SELECT"],
          role: "appuser",
          schema: "public",
          allInSchema: true,
          includeFuture: true,
        }, context),
      /defaultForRole is required.*defaultForRole=postgres/,
    );
    assertEquals(fake.queries.length, 0, "no statement issued");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("grant: database scope connects to maintenanceDb; revoke flips verb/direction", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await method("grant").execute({
      database: "myapp",
      scope: "database",
      privileges: ["CONNECT"],
      role: "appuser",
    }, context);
    assertEquals(
      fake.connectDbs[0],
      "postgres",
      "database-scope grant connects to maintenanceDb",
    );
    assert(
      hasSql(fake.queries, /GRANT CONNECT ON DATABASE "myapp" TO "appuser"/),
      "grant on database",
    );
  } finally {
    __setPgConnect(null);
  }
  const fake2 = makeFakeDb(() => []);
  __setPgConnect(fake2.connect);
  try {
    const { context, written } = makeContext();
    await method("revoke").execute({
      database: "myapp",
      scope: "schema",
      privileges: ["USAGE"],
      role: "appuser",
      schema: "public",
    }, context);
    assert(
      hasSql(fake2.queries, /REVOKE USAGE ON SCHEMA "public" FROM "appuser"/),
      "revoke flips to FROM",
    );
    assertEquals(written[0].data.action, "revoked");
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── app_provision (composite) ───────────────────────────

// Role and database exist, and the role already holds the schema grant: a
// completed earlier provision.
const everythingExists = (sql: string) =>
  /FROM pg_roles WHERE rolname/.test(sql) ||
    /FROM pg_database WHERE datname/.test(sql) || /aclexplode/.test(sql)
    ? [{ x: 1 }]
    : undefined;

// Role and database exist but the role holds no schema grant: Phase A ran,
// Phase B did not complete. The probe's subselect also reads pg_roles, so answer
// it first.
const existsUnprovisioned = (sql: string) =>
  /aclexplode/.test(sql) ? [] : /FROM pg_roles WHERE rolname/.test(sql) ||
      /FROM pg_database WHERE datname/.test(sql)
    ? [{ x: 1 }]
    : undefined;

Deno.test("app_provision: idempotent — a provisioned role gets only the grants passed, two-phase routing", async () => {
  const fake = makeFakeDb(everythingExists);
  __setPgConnect(fake.connect);
  try {
    const { context, written, logs } = makeContext();
    await method("app_provision").execute(
      {
        database: "myapp",
        role: "myapp",
        password: "SENT",
        tablePrivs: ["SELECT", "INSERT", "UPDATE", "DELETE"],
        includeFuture: true,
      },
      context,
    );
    assert(
      !hasSql(fake.queries, /CREATE ROLE/) &&
        !hasSql(fake.queries, /CREATE DATABASE/),
      "nothing created when both exist",
    );
    // CONNECT and the schema grants are not issued again, so a privilege
    // revoked by hand stays revoked.
    assert(!hasSql(fake.queries, /GRANT CONNECT/), "no CONNECT");
    assert(!hasSql(fake.queries, /ON SCHEMA/), "no schema grant");
    assert(
      hasSql(
        fake.queries,
        /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "public" TO "myapp"/,
      ),
      "tables",
    );
    assert(
      hasSql(
        fake.queries,
        /ALTER DEFAULT PRIVILEGES FOR ROLE "myapp" IN SCHEMA "public" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "myapp"/,
      ),
      "default privs",
    );
    // two-phase: phase A on maintenanceDb, phase B on the target db
    assertEquals(fake.connectDbs, ["postgres", "myapp"]);
    // It issued grants, so it must not report "unchanged".
    assertEquals(written[0].data.action, "granted");
    assert(!JSON.stringify(logs).includes("SENT"), "password leaked");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("app_provision: creates role+db when absent ⇒ action=created", async () => {
  const fake = makeFakeDb(() => []); // nothing exists
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("app_provision").execute({
      database: "fresh",
      role: "fresh",
      // The dash keeps it from turning up by chance in base64 output.
      password: "SENT-plain",
    }, context);
    assert(
      hasSql(
        fake.queries,
        /CREATE ROLE "fresh" LOGIN CONNECTION LIMIT -1 PASSWORD 'SCRAM-SHA-256\$/,
      ) && hasSql(fake.queries, SCRAM_CLAUSE),
      "role created with a SCRAM verifier",
    );
    assert(
      !JSON.stringify(fake.queries).includes("SENT-plain"),
      "plain-text password sent to the server",
    );
    assert(
      hasSql(fake.queries, /CREATE DATABASE "fresh" OWNER "fresh"/),
      "db created",
    );
    assert(
      hasSql(
        fake.queries,
        /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "public" TO "fresh"/,
      ),
      "default table privs",
    );
    assert(
      hasSql(
        fake.queries,
        /ALTER DEFAULT PRIVILEGES FOR ROLE "fresh" IN SCHEMA "public" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES/,
      ),
      "default future privs",
    );
    assert(
      hasSql(fake.queries, /GRANT CONNECT ON DATABASE "fresh" TO "fresh"/),
      "CONNECT on a first run",
    );
    assertEquals(written[0].data.action, "created");
    assertEquals(written[0].name, "app-provision:fresh:fresh");
  } finally {
    __setPgConnect(null);
  }
});

// Same bug class as forgejo issue #4: GRANT only adds, so a re-run that
// re-applied the default privileges would widen a read-only role.
Deno.test("app_provision: re-run without tablePrivs/includeFuture grants nothing", async () => {
  const fake = makeFakeDb(everythingExists);
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("app_provision").execute({
      database: "reports",
      role: "reader",
    }, context);
    assert(!hasSql(fake.queries, /\bGRANT\b/), "no grant of any kind");
    assert(
      !hasSql(fake.queries, /ALTER DEFAULT PRIVILEGES/),
      "no default privileges",
    );
    assertEquals(written[0].data.defaultPrivileges, false);
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setPgConnect(null);
  }
});

// A first run that failed after Phase A leaves the role and database behind
// with no grants. Keying the defaults on "did this run create the role" made
// every re-run grant nothing; the catalog says whether it was provisioned.
Deno.test("app_provision: re-run after a partial failure (role+db exist, no schema grant) applies the defaults", async () => {
  const fake = makeFakeDb(existsUnprovisioned);
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("app_provision").execute(
      { database: "myapp", role: "myapp" },
      context,
    );
    assert(
      !hasSql(fake.queries, /CREATE ROLE/) &&
        !hasSql(fake.queries, /CREATE DATABASE/),
      "nothing created",
    );
    assert(
      hasSql(
        fake.queries,
        /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "public" TO "myapp"/,
      ),
      "default table privs",
    );
    assert(
      hasSql(
        fake.queries,
        /ALTER DEFAULT PRIVILEGES FOR ROLE "myapp" IN SCHEMA "public" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "myapp"/,
      ),
      "default future privs",
    );
    assertEquals(written[0].data.defaultPrivileges, true);
    assertEquals(written[0].data.action, "granted");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("app_provision: a bad schema identifier is rejected before Phase A creates anything", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_provision").execute({
          database: "myapp",
          role: "myapp",
          schema: "bad schema",
        }, context),
      /Invalid schema identifier/,
    );
    assertEquals(fake.connectDbs.length, 0, "no connection opened");
  } finally {
    __setPgConnect(null);
  }
});

// Phase B is one transaction so the schema grant can serve as the
// "provisioned" marker: a failure part-way must leave none of it behind.
Deno.test("app_provision: a failing Phase B statement rolls the whole phase back", async () => {
  const fake = makeFakeDb(existsUnprovisioned);
  __setPgConnect(async (g, database) => {
    const conn = await fake.connect(g, database);
    const inner = conn.q.query;
    conn.q.query = (sql, params) => {
      if (/ON ALL TABLES/.test(sql)) {
        return Promise.reject(new Error("permission denied for table legacy"));
      }
      return inner(sql, params);
    };
    return conn;
  });
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_provision").execute(
          { database: "myapp", role: "myapp" },
          context,
        ),
      /permission denied/,
    );
    const phaseB = fake.queries.filter((r) => r.db === "myapp").map((r) =>
      r.sql
    );
    assert(
      phaseB.includes("BEGIN") && phaseB.includes("ROLLBACK"),
      `expected BEGIN + ROLLBACK, got ${JSON.stringify(phaseB)}`,
    );
    assert(!phaseB.includes("COMMIT"), "no COMMIT after a failure");
    assertEquals(fake.endCount(), 2, "both connections closed");
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── read-only backstop + redaction + cleanup ───────────────────────────

Deno.test("read methods set default_transaction_read_only; mutators do not; both set statement_timeout", async () => {
  const fakeRead = makeFakeDb(() => []);
  __setPgConnect(fakeRead.connect);
  try {
    const { context } = makeContext();
    await method("role_list").execute({}, context);
    assert(
      hasSql(fakeRead.queries, /SET statement_timeout = 30000/),
      "statement_timeout (read)",
    );
    assert(
      hasSql(fakeRead.queries, /SET default_transaction_read_only = on/),
      "read-only backstop on a read",
    );
  } finally {
    __setPgConnect(null);
  }
  const fakeWrite = makeFakeDb((sql) =>
    /FROM pg_database WHERE datname/.test(sql)
      ? [{ x: 1 }]
      : /pg_get_userbyid/.test(sql)
      ? [{ name: "d", owner: "o", encoding: "UTF8" }]
      : undefined
  );
  __setPgConnect(fakeWrite.connect);
  try {
    const { context } = makeContext();
    await method("database_create").execute({ name: "d" }, context);
    assert(
      hasSql(fakeWrite.queries, /SET statement_timeout = 30000/),
      "statement_timeout (mutator)",
    );
    assert(
      !hasSql(fakeWrite.queries, /default_transaction_read_only/),
      "mutators must NOT be read-only",
    );
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("connections_list: query column gated by includeQuery flag (bound param)", async () => {
  for (const include of [false, true]) {
    const fake = makeFakeDb(() => []);
    __setPgConnect(fake.connect);
    try {
      const { context } = makeContext();
      await method("connections_list").execute(
        { includeQuery: include },
        context,
      );
      const q = fake.queries.find((r) => /pg_stat_activity/.test(r.sql))!;
      assertEquals(
        q.params?.[0],
        include,
        `includeQuery=${include} must be bound as param[0]`,
      );
      assertEquals(fake.connectDbs[0], "postgres");
    } finally {
      __setPgConnect(null);
    }
  }
});

Deno.test("connection is always closed — even when the method throws", async () => {
  // table_inspect: the existence probe finds nothing ⇒ throws after connecting.
  const fake = makeFakeDb((sql) => /to_regclass/.test(sql) ? [] : undefined);
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("table_inspect").execute(
          { database: "myapp", table: "ghost" },
          context,
        ),
      /does not exist/,
    );
    assertEquals(fake.endCount(), 1, "end() must run on the error path");
  } finally {
    __setPgConnect(null);
  }
});

// A check receives globalArgs without the schema's defaults, so an unset port,
// adminUser, maintenanceDb or ssl used to reach the connection as undefined.
Deno.test("reachable check applies the schema defaults to globalArgs", async () => {
  const fake = makeFakeDb();
  let seen: Record<string, unknown> = {};
  __setPgConnect((g, database) => {
    seen = g;
    return fake.connect(g, database);
  });
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        { execute: (c: unknown) => Promise<{ pass: boolean }> }
      >;
    }).checks;
    const res = await checks.reachable.execute({
      globalArgs: { host: GLOBALS.host, adminPassword: GLOBALS.adminPassword },
    });
    assertEquals(res.pass, true);
    assertEquals(fake.connectDbs, ["postgres"]);
    assertEquals(seen.port, 5432);
    assertEquals(seen.adminUser, "postgres");
    assertEquals(seen.ssl, { mode: "disable" });
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── strict booleans ───────────────────────────

Deno.test("boolean arguments reject anything but true/false", () => {
  const schema = (model.methods as unknown as Record<string, {
    arguments: {
      safeParse: (v: unknown) => {
        success: boolean;
        error?: { issues: { path: PropertyKey[] }[] };
      };
    };
  }>)["role_create"].arguments;
  const fieldFails = (v: unknown) => {
    const r = schema.safeParse({ name: "x", login: v });
    return (r.error?.issues ?? []).some((i) => i.path[0] === "login");
  };
  // swamp coerces `--input login=true` to a boolean before execute, so a
  // string reaching the schema is a caller error.
  for (const bad of ["true", "false", "0", "1", "False", "yes", null]) {
    assert(fieldFails(bad), `login=${JSON.stringify(bad)} must be rejected`);
  }
  for (const good of [true, false]) {
    assert(!fieldFails(good), `login=${JSON.stringify(good)} must be accepted`);
  }
});

Deno.test('role_create: execute rejects the string "true" for a boolean', async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("role_create").execute({ name: "x", login: "true" }, context),
      /boolean/,
    );
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── data names ───────────────────────────

Deno.test("dataName: specs sharing a key get distinct names", () => {
  // database `myapp` and role `myapp` used to share the name `myapp`.
  assertEquals(dataName("database", "myapp"), "database:myapp");
  assertEquals(dataName("role", "myapp"), "role:myapp");
  assertEquals(dataName("role-result", "myapp"), "role-result:myapp");
  assert(dataName("database", "myapp") !== dataName("role", "myapp"));
});

Deno.test("dataName: escaping keeps distinct keys distinct and names valid", () => {
  // `a-b`/`a.b` must not merge; a `:` inside a part must not look like a separator.
  assert(dataName("table", "a-b") !== dataName("table", "a.b"));
  assert(
    dataName("extension", "a:b", "c") !== dataName("extension", "a", "b:c"),
  );
  assertEquals(dataName("extension", "a:b", "c"), "extension:a%3Ab:c");
  assertEquals(dataName("table", "x%2Fy"), "table:x%252Fy");
  const n = dataName("database", "../a/b\\c");
  assert(!/[/\\]|\.\./.test(n), `name ${n} has a character swamp rejects`);
});

Deno.test("permissions_audit: the all-roles audit cannot collide with a role named all", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("permissions_audit").execute({ database: "db" }, context);
    await method("permissions_audit").execute(
      { database: "db", role: "all" },
      context,
    );
    assertEquals(written.map((w) => w.name), [
      "permissions-audit:db",
      "permissions-audit:db:all",
    ]);
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── role_list ───────────────────────────

// node-pg leaves a name[] unparsed, so memberOf was stored as "{a,b}".
Deno.test("role_list: memberOf is read as text[] and written as an array", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_roles r/.test(sql)
      ? [{
        name: "pg_monitor",
        login: false,
        superuser: false,
        create_db: false,
        create_role: false,
        replication: false,
        bypass_rls: false,
        conn_limit: -1,
        valid_until: null,
        member_of: ["pg_read_all_settings", "pg_read_all_stats"],
      }]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("role_list").execute({}, context);
    assert(
      hasSql(fake.queries, /ARRAY\(SELECT DISTINCT g\.rolname::text/),
      "memberOf must be selected as text[]",
    );
    assertEquals(written[0].data.memberOf, [
      "pg_read_all_settings",
      "pg_read_all_stats",
    ]);
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("role_list: an unparsed array string is refused, not written", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_roles r/.test(sql)
      ? [{ name: "pg_monitor", conn_limit: -1, member_of: "{a,b}" }]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await rejects(
      () => method("role_list").execute({}, context),
      /memberOf .* not an array/,
    );
    assertEquals(written.length, 0, "nothing written");
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── empty passwords ───────────────────────────

// PostgreSQL reads PASSWORD '' as PASSWORD NULL: role_password_set cleared the
// password and reported it rotated; the other two made a passwordless LOGIN role.
Deno.test("an empty password is rejected before any SQL, in all three methods", async () => {
  const calls: Array<[string, Record<string, unknown>]> = [
    ["role_password_set", { name: "appuser", password: "" }],
    ["role_create", { name: "appuser", password: "" }],
    ["app_provision", { database: "myapp", role: "myapp", password: "" }],
  ];
  for (const [name, args] of calls) {
    const fake = makeFakeDb(() => [{ x: 1 }]);
    __setPgConnect(fake.connect);
    try {
      const { context, written } = makeContext();
      await rejects(() => method(name).execute(args, context), /password/);
      assertEquals(fake.queries.length, 0, `${name}: no statement issued`);
      assertEquals(written.length, 0, `${name}: nothing written`);
    } finally {
      __setPgConnect(null);
    }
  }
});

// ─────────────────────────── permissions_audit ───────────────────────────

// Unscoped, the audit returned every pg_catalog/information_schema grant and
// every collation's PUBLIC usage (2,576 rows on an empty database), with no
// grantee to tell the rows apart.
Deno.test("permissions_audit: grants carry grantee and grantor; system schemas and collations are left out", async () => {
  const fake = makeFakeDb((sql) =>
    /role_table_grants/.test(sql)
      ? [{
        schema: "public",
        name: "orders",
        privilege: "SELECT",
        grantee: "reader",
        grantor: "owner",
        is_grantable: "NO",
      }]
      : /role_usage_grants/.test(sql)
      ? [{
        schema: "public",
        name: "orders_id_seq",
        privilege: "USAGE",
        grantee: "writer",
        grantor: "owner",
        is_grantable: "NO",
      }]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("permissions_audit").execute({ database: "db" }, context);
    for (const view of ["role_table_grants", "role_usage_grants"]) {
      const q = fake.queries.find((r) => r.sql.includes(view))!.sql;
      assert(/NOT LIKE 'pg\\_%'/.test(q), `${view}: pg_* schemas excluded`);
      assert(
        /<> 'information_schema'/.test(q),
        `${view}: information_schema excluded`,
      );
    }
    assert(
      hasSql(fake.queries, /object_type <> 'COLLATION'/),
      "collations excluded",
    );
    const data = written[0].data as {
      tableGrants: Record<string, unknown>[];
      usageGrants: Record<string, unknown>[];
    };
    assertEquals(data.tableGrants[0].grantee, "reader");
    assertEquals(data.tableGrants[0].grantor, "owner");
    assertEquals(data.usageGrants[0].grantee, "writer");
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── SCRAM-SHA-256 verifier ───────────────────────────

function fromBase64(s: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
async function hmac(
  key: Uint8Array<ArrayBuffer>,
  msg: string,
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(
    await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg)),
  );
}

// The RFC 7677 §3 exchange (user "user", password "pencil"). The server checks
// the client's proof and signs its reply using only StoredKey and ServerKey,
// so if our verifier for that password and salt lets this exchange succeed,
// a real SCRAM login with the password will succeed against it.
Deno.test("scramSha256Verifier: passes the RFC 7677 test exchange", async () => {
  const salt = fromBase64("W22ZaJ0SNY7soEsUEjb6gQ==");
  const verifier = await scramSha256Verifier("pencil", salt);
  const m = verifier.match(
    /^SCRAM-SHA-256\$4096:W22ZaJ0SNY7soEsUEjb6gQ==\$([^:]+):(.+)$/,
  );
  assert(m, `verifier shape: ${verifier.slice(0, 40)}...`);
  const storedKey = fromBase64(m![1]);
  const serverKey = fromBase64(m![2]);

  const nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
  const authMessage = [
    "n=user,r=rOprNGfwEbeRWgbNEkqO",
    `r=${nonce},s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`,
    `c=biws,r=${nonce}`,
  ].join(",");
  const proof = fromBase64("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");

  // Server side: ClientKey = proof XOR HMAC(StoredKey, AuthMessage), and
  // SHA-256(ClientKey) must equal StoredKey.
  const clientSignature = await hmac(storedKey, authMessage);
  const clientKey = proof.map((b, i) => b ^ clientSignature[i]);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientKey),
  );
  assertEquals(Array.from(digest), Array.from(storedKey), "client proof");

  const serverSignature = await hmac(serverKey, authMessage);
  assertEquals(
    btoa(String.fromCharCode(...serverSignature)),
    "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
    "server signature",
  );
});

Deno.test("scramSha256Verifier: a fresh 16-byte salt each time", async () => {
  const a = await scramSha256Verifier("same-password");
  const b = await scramSha256Verifier("same-password");
  assert(a !== b, "two verifiers for one password must differ by salt");
  const salt = a.split("$")[1].split(":")[1];
  assertEquals(fromBase64(salt).length, 16);
});

// PostgreSQL leaves ASCII alone and applies SASLprep to anything else, so a
// verifier must be built from the same normalised form or the login fails.
Deno.test("scramSha256Verifier: applies the SASLprep mapping and NFKC to non-ASCII", async () => {
  const salt = new Uint8Array(16);
  const v = (p: string) => scramSha256Verifier(p, salt);
  // U+2168 ROMAN NUMERAL NINE is "IX" under NFKC; U+00AD SOFT HYPHEN maps to
  // nothing; U+00A0 NO-BREAK SPACE maps to a space.
  assertEquals(await v("pw\u2168\u00AD\u00A0x"), await v("pwIX x"));
  // An ASCII password, control characters included, is used as it is.
  assert(await v("a\tb") !== await v("a b"), "ASCII is not normalised");
});

// ─────────────────────────── app_provision marker ───────────────────────────

// Which marker probe a statement is, by the catalog it reads.
const MARKERS: Array<[string, RegExp]> = [
  ["USAGE or CREATE on the schema", /pg_namespace n, aclexplode/],
  ["a privilege on a table or sequence", /FROM pg_class c/],
  ["a default-privilege entry", /FROM pg_default_acl d/],
];

// The marker used to be schema USAGE alone, so revoking USAGE by hand made the
// next run grant CONNECT, USAGE, CREATE and the table defaults back.
Deno.test("app_provision: any one remaining direct grant marks the role provisioned", async () => {
  for (const [label, probe] of MARKERS) {
    const fake = makeFakeDb((sql) =>
      /aclexplode/.test(sql)
        ? (probe.test(sql) ? [{ x: 1 }] : [])
        : /FROM pg_roles WHERE rolname/.test(sql) ||
            /FROM pg_database WHERE datname/.test(sql)
        ? [{ x: 1 }]
        : undefined
    );
    __setPgConnect(fake.connect);
    try {
      const { context, written } = makeContext();
      await method("app_provision").execute(
        { database: "reports", role: "reports" },
        context,
      );
      assert(
        !hasSql(fake.queries, /\bGRANT\b/),
        `${label} alone: no grant expected, got ${
          JSON.stringify(sqls(fake.queries).filter((q) => /GRANT/.test(q)))
        }`,
      );
      assertEquals(written[0].data.action, "unchanged", label);
    } finally {
      __setPgConnect(null);
    }
  }
});

Deno.test("app_provision: the marker probes read the target database, schema and role", async () => {
  const fake = makeFakeDb(existsUnprovisioned);
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await method("app_provision").execute(
      { database: "reports", role: "app", schema: "sales" },
      context,
    );
    for (const [label, probe] of MARKERS) {
      const q = fake.queries.find((r) => probe.test(r.sql));
      assert(q, `${label}: probe not run`);
      assertEquals(q!.db, "reports", `${label}: connection`);
      assertEquals(q!.params, ["sales", "app"], `${label}: params`);
    }
  } finally {
    __setPgConnect(null);
  }
});

// CONNECT is database-wide. Counting it made app_provision for a second schema
// in the same database grant nothing in that schema.
Deno.test("app_provision: CONNECT on the database alone does not mark a new schema provisioned", async () => {
  const fake = makeFakeDb((sql) =>
    // The role holds CONNECT (from provisioning schema A), nothing in B.
    /pg_database d, aclexplode/.test(sql)
      ? [{ x: 1 }]
      : /aclexplode/.test(sql)
      ? []
      : /FROM pg_roles WHERE rolname/.test(sql) ||
          /FROM pg_database WHERE datname/.test(sql)
      ? [{ x: 1 }]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("app_provision").execute(
      { database: "reports", role: "app", schema: "b", createSchema: true },
      context,
    );
    assert(
      hasSql(fake.queries, /GRANT USAGE, CREATE ON SCHEMA "b" TO "app"/),
      `schema grants expected, got ${JSON.stringify(sqls(fake.queries))}`,
    );
    assert(
      hasSql(
        fake.queries,
        /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "b" TO "app"/,
      ),
      "default table privileges",
    );
    assertEquals(written[0].data.action, "granted");
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── grant / revoke ───────────────────────────

// defaultForRole was checked only when its statement was built, after the
// object GRANT had already run outside any transaction.
Deno.test("grant: a bad defaultForRole is rejected before any statement", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("grant").execute({
          database: "myapp",
          scope: "table",
          privileges: ["SELECT"],
          role: "appuser",
          schema: "public",
          allInSchema: true,
          includeFuture: true,
          defaultForRole: "app-owner",
        }, context),
      /Invalid defaultForRole identifier/,
    );
    assertEquals(fake.queries.length, 0, "no statement issued");
    assertEquals(written.length, 0, "nothing written");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("grant: a failing default-privilege step rolls back the object grant", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(async (g, database) => {
    const conn = await fake.connect(g, database);
    const inner = conn.q.query;
    conn.q.query = (sql, params) =>
      /ALTER DEFAULT PRIVILEGES/.test(sql)
        ? Promise.reject(new Error('role "ghost" does not exist'))
        : inner(sql, params);
    return conn;
  });
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("grant").execute({
          database: "myapp",
          scope: "table",
          privileges: ["SELECT"],
          role: "appuser",
          schema: "public",
          allInSchema: true,
          includeFuture: true,
          defaultForRole: "ghost",
        }, context),
      /does not exist/,
    );
    const order = sqls(fake.queries);
    const grantAt = order.findIndex((q) =>
      /^GRANT SELECT ON ALL TABLES/.test(q)
    );
    assert(
      order.indexOf("BEGIN") < grantAt && order.includes("ROLLBACK"),
      `expected BEGIN, GRANT, ROLLBACK, got ${JSON.stringify(order)}`,
    );
    assert(!order.includes("COMMIT"), "no COMMIT after a failure");
    assertEquals(written.length, 0, "nothing written");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("grant: named objects are each validated and escaped", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("grant").execute({
      database: "myapp",
      scope: "sequence",
      privileges: ["USAGE"],
      role: "appuser",
      schema: "sales",
      objects: ["orders_id_seq", "Items_id_seq"],
    }, context);
    assert(
      hasSql(
        fake.queries,
        /GRANT USAGE ON SEQUENCE "sales"\."orders_id_seq", "sales"\."Items_id_seq" TO "appuser"/,
      ),
      `object list: ${JSON.stringify(sqls(fake.queries))}`,
    );
    assertEquals(written[0].data.objects, [
      "sales.orders_id_seq",
      "sales.Items_id_seq",
    ]);
  } finally {
    __setPgConnect(null);
  }
  const fake2 = makeFakeDb(() => []);
  __setPgConnect(fake2.connect);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("grant").execute({
          database: "myapp",
          scope: "table",
          privileges: ["SELECT"],
          role: "appuser",
          schema: "sales",
          objects: ["ok", 'bad"; DROP TABLE x; --'],
        }, context),
      /Invalid table identifier/,
    );
    assertEquals(fake2.queries.length, 0, "no statement issued");
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("revoke: includeFuture revokes the default privileges for defaultForRole", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context } = makeContext();
    await method("revoke").execute({
      database: "myapp",
      scope: "table",
      privileges: ["INSERT"],
      role: "appuser",
      schema: "public",
      allInSchema: true,
      includeFuture: true,
      defaultForRole: "appowner",
    }, context);
    assert(
      hasSql(
        fake.queries,
        /^REVOKE INSERT ON ALL TABLES IN SCHEMA "public" FROM "appuser"$/,
      ),
      "object revoke",
    );
    assert(
      hasSql(
        fake.queries,
        /^ALTER DEFAULT PRIVILEGES FOR ROLE "appowner" IN SCHEMA "public" REVOKE INSERT ON TABLES FROM "appuser"$/,
      ),
      `default revoke: ${JSON.stringify(sqls(fake.queries))}`,
    );
  } finally {
    __setPgConnect(null);
  }
});

// grant used to log nothing at all.
Deno.test("grant: logs what it is about to do and what it did", async () => {
  const fake = makeFakeDb(() => []);
  __setPgConnect(fake.connect);
  try {
    const { context, logs } = makeContext();
    await method("grant").execute({
      database: "myapp",
      scope: "schema",
      privileges: ["USAGE"],
      role: "appuser",
      schema: "sales",
    }, context);
    const start = logs.find((l) => /\{verb\}.*\{scope\}/.test(l.msg));
    assert(start, `no start log in ${JSON.stringify(logs)}`);
    assertEquals(start!.props, {
      verb: "GRANT",
      privileges: "USAGE",
      scope: "schema",
      database: "myapp",
      role: "appuser",
    });
    assert(
      logs.some((l) => /done/.test(l.msg)),
      `no completion log in ${JSON.stringify(logs)}`,
    );
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── create on an existing object ───────────────────────────

// An existing role is returned unchanged; the supplied password used to be
// dropped without a word.
Deno.test("role_create: an existing role is unchanged, and a warning names the arguments not applied", async () => {
  const SENTINEL = "unused-SENTINEL-pw";
  const fake = makeFakeDb((sql) =>
    /FROM pg_roles WHERE rolname/.test(sql) ? [{ x: 1 }] : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written, warnings } = makeContext();
    await method("role_create").execute({
      name: "appuser",
      password: SENTINEL,
      memberOf: ["readers"],
    }, context);
    assert(!hasSql(fake.queries, /CREATE ROLE|GRANT/), "no DDL");
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.passwordSet, false);
    assertEquals(warnings.length, 1, "one warning");
    assertEquals(
      (warnings[0].props as { ignored: string }).ignored,
      "password, memberOf",
    );
    assert(
      !JSON.stringify(warnings).includes(SENTINEL),
      "the password value must not be logged",
    );
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("role_create: no warning when only defaults were passed for an existing role", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_roles WHERE rolname/.test(sql) ? [{ x: 1 }] : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, warnings } = makeContext();
    await method("role_create").execute({ name: "appuser" }, context);
    assertEquals(warnings.length, 0);
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("database_create: an existing database warns about the arguments not applied", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_database WHERE datname/.test(sql)
      ? [{ x: 1 }]
      : /pg_get_userbyid/.test(sql)
      ? [{ name: "myapp", owner: "someone", encoding: "UTF8" }]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, warnings } = makeContext();
    await method("database_create").execute(
      { name: "myapp", owner: "ownr", locale: "en_GB.UTF-8" },
      context,
    );
    assertEquals(
      (warnings[0]?.props as { ignored: string } | undefined)?.ignored,
      "owner, locale",
    );
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── read-method row shaping ───────────────────────────

// pg_database_size fails the whole query for a database the admin cannot
// CONNECT to, unless it has pg_read_all_stats.
Deno.test("database_list: size is read only where permitted, and rows are shaped", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_database d/.test(sql)
      ? [
        {
          name: "myapp",
          owner: "app",
          encoding: "UTF8",
          collate: "en_GB.UTF-8",
          ctype: "en_GB.UTF-8",
          size_bytes: "8000000", // bigint arrives as a string
          is_template: false,
          allow_conn: true,
        },
        {
          name: "locked",
          owner: "other",
          encoding: "UTF8",
          collate: "C",
          ctype: "C",
          size_bytes: null, // no CONNECT for the admin
          is_template: false,
          allow_conn: true,
        },
      ]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("database_list").execute({}, context);
    const q = fake.queries.find((r) => /FROM pg_database d/.test(r.sql))!.sql;
    assert(
      /CASE WHEN has_database_privilege\(d\.oid, 'CONNECT'\)\s+OR pg_has_role\('pg_read_all_stats', 'USAGE'\)\s+THEN pg_database_size/
        .test(q),
      `size not guarded: ${q}`,
    );
    assertEquals(written.map((w) => w.name), [
      "database:myapp",
      "database:locked",
    ]);
    assertEquals(written[0].data.sizeBytes, 8000000);
    assertEquals(written[1].data.sizeBytes, undefined);
  } finally {
    __setPgConnect(null);
  }
});

// node-pg parses timestamptz into a Date and infinity into Infinity; String()
// of either is not a timestamp a CEL comparison can use.
Deno.test("role_list: validUntil is written as ISO 8601, and infinity as infinity", async () => {
  const role = (name: string, valid_until: unknown) => ({
    name,
    login: true,
    superuser: false,
    create_db: false,
    create_role: false,
    replication: false,
    bypass_rls: false,
    conn_limit: -1,
    valid_until,
    member_of: [],
  });
  const fake = makeFakeDb((sql) =>
    /FROM pg_roles r/.test(sql)
      ? [
        role("expires", new Date("2027-01-01T00:00:00Z")),
        role("forever", Infinity),
        role("unset", null),
      ]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("role_list").execute({}, context);
    assertEquals(written.map((w) => w.data.validUntil), [
      "2027-01-01T00:00:00.000Z",
      "infinity",
      undefined,
    ]);
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("connections_list: client address without netmask, and backendType recorded", async () => {
  const fake = makeFakeDb((sql) =>
    /pg_stat_activity/.test(sql)
      ? [
        {
          pid: 101,
          backend_type: "client backend",
          user: "app",
          db: "myapp",
          state: "idle",
          client_addr: "192.0.2.7",
          backend_age_sec: 12,
          wait_event_type: null,
          wait_event: null,
          query: null,
        },
        {
          pid: 7,
          backend_type: "checkpointer",
          user: null,
          db: null,
          state: null,
          client_addr: null,
          backend_age_sec: 900,
          wait_event_type: "Activity",
          wait_event: "CheckpointerMain",
          query: null,
        },
      ]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("connections_list").execute({}, context);
    const q = fake.queries.find((r) => /pg_stat_activity/.test(r.sql))!.sql;
    assert(/host\(client_addr\)/.test(q), "host() drops the /32");
    assert(/backend_type/.test(q), "backend_type selected");
    assertEquals(written[0].data.backendType, "client backend");
    assertEquals(written[0].data.clientAddr, "192.0.2.7");
    assertEquals(written[1].data.backendType, "checkpointer");
    assertEquals(written[1].data.user, undefined);
  } finally {
    __setPgConnect(null);
  }
});

Deno.test("table_inspect: declared column types and named constraint kinds", async () => {
  const fake = makeFakeDb((sql) =>
    /to_regclass/.test(sql)
      ? [{ kind: "r" }]
      : /information_schema\.columns/.test(sql)
      ? [
        { name: "id", type: "bigint", nullable: "NO", def: null, position: 1 },
        {
          name: "tags",
          type: "text[]",
          nullable: "YES",
          def: null,
          position: 2,
        },
      ]
      : /pg_index i/.test(sql)
      ? [{ col: "id" }]
      : /FROM pg_constraint/.test(sql)
      ? [{ name: "t_id_not_null", type: "not null", def: "NOT NULL id" }]
      : /pg_get_userbyid\(c\.relowner\)/.test(sql)
      ? [{ owner: "app" }]
      : undefined
  );
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("table_inspect").execute(
      { database: "myapp", table: "t" },
      context,
    );
    const cols = fake.queries.find((r) =>
      /information_schema\.columns/.test(r.sql)
    )!
      .sql;
    assert(/format_type\(t\.atttypid, t\.atttypmod\)/.test(cols), cols);
    assert(
      hasSql(fake.queries, /WHEN 'n' THEN 'not null'/),
      "PostgreSQL 18 not-null constraints are named",
    );
    const d = written[0].data as {
      columns: Array<{ type: string }>;
      primaryKey: string[];
      owner: string;
    };
    assertEquals(d.columns.map((c) => c.type), ["bigint", "text[]"]);
    assertEquals(d.primaryKey, ["id"]);
    assertEquals(d.owner, "app");
    assertEquals(written[0].name, "table:myapp:public:t");
  } finally {
    __setPgConnect(null);
  }
});

// to_regclass also finds an index, which then "existed" with no columns.
Deno.test("table_inspect: an index or sequence is refused, not described as an empty table", async () => {
  for (const [kind, label] of [["i", "an index"], ["S", "a sequence"]]) {
    const fake = makeFakeDb((sql) =>
      /to_regclass/.test(sql) ? [{ kind }] : undefined
    );
    __setPgConnect(fake.connect);
    try {
      const { context, written } = makeContext();
      await rejects(
        () =>
          method("table_inspect").execute(
            { database: "myapp", table: "t_pkey" },
            context,
          ),
        new RegExp(`is ${label}, not a table or view`),
      );
      assertEquals(written.length, 0);
    } finally {
      __setPgConnect(null);
    }
  }
});

// Records for the first databases were written before a later one failed.
Deno.test("extension_list: a database that refuses the connection fails the run with nothing written", async () => {
  const fake = makeFakeDb((sql) =>
    /FROM pg_database WHERE datallowconn/.test(sql)
      ? [{ datname: "alpha" }, { datname: "zulu" }]
      : /FROM pg_extension/.test(sql)
      ? [{ name: "plpgsql", version: "1.0", schema: "pg_catalog" }]
      : undefined
  );
  __setPgConnect((g, database) =>
    database === "zulu"
      ? Promise.reject(new Error('no pg_hba.conf entry for database "zulu"'))
      : fake.connect(g, database)
  );
  try {
    const { context, written } = makeContext();
    await rejects(
      () => method("extension_list").execute({}, context),
      /pg_hba/,
    );
    assertEquals(written.length, 0, "no partial result");
  } finally {
    __setPgConnect(null);
  }
  // And with every database reachable, each one's records are written.
  const ok = makeFakeDb((sql) =>
    /FROM pg_database WHERE datallowconn/.test(sql)
      ? [{ datname: "alpha" }, { datname: "zulu" }]
      : /FROM pg_extension/.test(sql)
      ? [{ name: "plpgsql", version: "1.0", schema: "pg_catalog" }]
      : undefined
  );
  __setPgConnect(ok.connect);
  try {
    const { context, written } = makeContext();
    await method("extension_list").execute({}, context);
    assertEquals(written.map((w) => w.name), [
      "extension:alpha:plpgsql",
      "extension:zulu:plpgsql",
    ]);
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── cleanup errors ───────────────────────────

// A failing ROLLBACK or end() used to replace the error that said what went wrong.
Deno.test("a failing ROLLBACK or end() does not hide the original error", async () => {
  const fake = makeFakeDb(existsUnprovisioned);
  __setPgConnect(async (g, database) => {
    const conn = await fake.connect(g, database);
    const inner = conn.q.query;
    conn.q.query = (sql, params) =>
      /ON ALL TABLES/.test(sql)
        ? Promise.reject(new Error("permission denied for table legacy"))
        : sql === "ROLLBACK"
        ? Promise.reject(new Error("Connection terminated"))
        : inner(sql, params);
    if (database === "myapp") {
      conn.end = () => Promise.reject(new Error("socket already closed"));
    }
    return conn;
  });
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_provision").execute(
          { database: "myapp", role: "myapp" },
          context,
        ),
      /permission denied for table legacy/,
    );
  } finally {
    __setPgConnect(null);
  }
});

// ─────────────────────────── globals and TLS ───────────────────────────

Deno.test("reachable check fails cleanly when the server cannot be reached", async () => {
  __setPgConnect(() => Promise.reject(new Error("ECONNREFUSED")));
  try {
    const checks = (model as unknown as {
      checks: Record<
        string,
        {
          execute: (
            c: unknown,
          ) => Promise<{ pass: boolean; errors?: string[] }>;
        }
      >;
    }).checks;
    const res = await checks.reachable.execute({ globalArgs: GLOBALS });
    assertEquals(res.pass, false);
    assert(
      /Cannot reach Postgres at 192\.0\.2\.10:5433: ECONNREFUSED/.test(
        res.errors?.[0] ?? "",
      ),
      `errors: ${JSON.stringify(res.errors)}`,
    );
  } finally {
    __setPgConnect(null);
  }
});

// `--global-arg port=` coerced to 0 and was accepted.
Deno.test("global args: port and statementTimeoutMs are bounded", () => {
  const g = model.globalArguments;
  const ok = (over: Record<string, unknown>) =>
    g.safeParse({ ...GLOBALS, ...over }).success;
  assert(ok({}), "the fixture parses");
  for (const port of [0, -1, 65536, ""]) {
    assert(!ok({ port }), `port=${JSON.stringify(port)} must be rejected`);
  }
  assert(ok({ port: 1 }) && ok({ port: 65535 }), "port bounds are inclusive");
  assert(!ok({ statementTimeoutMs: -1 }), "negative timeout rejected");
  assert(ok({ statementTimeoutMs: 0 }), "0 (no timeout) accepted");
});

// Node's TLS checks the host name by default, so verify-ca acted as verify-full.
Deno.test("sslToPg: verify-ca skips the host-name check; verify-full keeps it", () => {
  const ca = "-----BEGIN CERTIFICATE-----\n...";
  const vca = sslToPg({ mode: "verify-ca", ca }) as Record<string, unknown>;
  assertEquals(vca.rejectUnauthorized, true);
  assertEquals(vca.ca, ca);
  assertEquals(typeof vca.checkServerIdentity, "function");
  assertEquals(
    (vca.checkServerIdentity as () => unknown)(),
    undefined,
    "a no-op check accepts any host name",
  );
  const vfull = sslToPg({ mode: "verify-full", ca }) as Record<string, unknown>;
  assertEquals(vfull.rejectUnauthorized, true);
  assert(!("checkServerIdentity" in vfull), "verify-full uses Node's check");
  assertEquals(sslToPg({ mode: "disable" }), false);
});

// ─────────────────────────── decisions 10 and 14 ───────────────────────────

// includeFuture did nothing for database/schema scope but was recorded as
// true; objects were silently ignored when allInSchema was set.
Deno.test("grant: includeFuture outside table/sequence scope, and objects with allInSchema, are refused", async () => {
  const base = {
    database: "myapp",
    privileges: ["USAGE"],
    role: "appuser",
    schema: "public",
  };
  const cases: Array<[Record<string, unknown>, RegExp]> = [
    [
      { scope: "schema", includeFuture: true, defaultForRole: "owner" },
      /includeFuture applies only to table and sequence scope, not schema/,
    ],
    [
      {
        scope: "database",
        privileges: ["CONNECT"],
        includeFuture: true,
        defaultForRole: "owner",
      },
      /not database/,
    ],
    [
      { scope: "table", allInSchema: true, objects: ["orders"] },
      /either objects\[\] or allInSchema=true, not both/,
    ],
  ];
  for (const [over, re] of cases) {
    for (const name of ["grant", "revoke"]) {
      const fake = makeFakeDb(() => []);
      __setPgConnect(fake.connect);
      try {
        const { context, written } = makeContext();
        await rejects(
          () => method(name).execute({ ...base, ...over }, context),
          re,
        );
        assertEquals(fake.queries.length, 0, `${name}: no statement issued`);
        assertEquals(written.length, 0, `${name}: nothing written`);
      } finally {
        __setPgConnect(null);
      }
    }
  }
});

// information_schema has no sequence SELECT/UPDATE grants, and the two
// effective-privilege arrays were empty (reading as "none") without a role.
Deno.test("permissions_audit: sequence grants come from the ACL; effective arrays only with a role", async () => {
  const rows = (sql: string) =>
    /aclexplode/.test(sql)
      ? [{
        schema: "public",
        name: "orders_id_seq",
        privilege: "SELECT",
        grantee: "writer",
        grantor: "owner",
        is_grantable: false,
      }]
      : undefined;
  const fake = makeFakeDb(rows);
  __setPgConnect(fake.connect);
  try {
    const { context, written } = makeContext();
    await method("permissions_audit").execute({ database: "db" }, context);
    const q = fake.queries.find((r) => /aclexplode/.test(r.sql))!;
    assert(/relkind = 'S'/.test(q.sql), "sequences only");
    assert(/acldefault\('s', c\.relowner\)/.test(q.sql), "NULL ACL = default");
    assertEquals(q.params, [null], "unscoped: no grantee filter");
    const d = written[0].data;
    assertEquals(d.sequenceGrants, [{
      schema: "public",
      name: "orders_id_seq",
      privilege: "SELECT",
      grantee: "writer",
      grantor: "owner",
      grantable: false,
    }]);
    assert(!("databasePrivileges" in d) || d.databasePrivileges === undefined);
    assert(!("schemaPrivileges" in d) || d.schemaPrivileges === undefined);
  } finally {
    __setPgConnect(null);
  }
  const fake2 = makeFakeDb(rows);
  __setPgConnect(fake2.connect);
  try {
    const { context, written } = makeContext();
    await method("permissions_audit").execute(
      { database: "db", role: "writer" },
      context,
    );
    const q = fake2.queries.find((r) => /aclexplode/.test(r.sql))!;
    assertEquals(q.params, ["writer"]);
    assertEquals(written[0].data.databasePrivileges, []);
    assertEquals(written[0].data.schemaPrivileges, []);
  } finally {
    __setPgConnect(null);
  }
});
