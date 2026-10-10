/**
 * Unit tests for the security-sensitive logic of `@thomas/postgres-admin`,
 * where an unnoticed bug would be costly:
 * identifier escaping, password routing (escapeLiteral + no leakage), connection-DB
 * routing, idempotency, connections_list redaction, the read-only backstop, and
 * connection cleanup on the error path. No live DB: the pg connector is faked via
 * the __setPgConnect seam.
 */
import {
  __setPgConnect,
  type Conn,
  type ConnectFn,
  model,
  type Querier,
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
  host: "10.0.0.5",
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
  const noop = () => {};
  const context = {
    globalArgs: GLOBALS,
    logger: {
      info: (msg: string, props?: unknown) => logs.push({ msg, props }),
      debug: noop,
      warning: noop,
      error: noop,
    },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      const h = { specName, name, data };
      written.push(h);
      return Promise.resolve(h);
    },
  };
  return { context, written, logs };
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

Deno.test("role_create: password routed via escapeLiteral, never logged or echoed", async () => {
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

    // CREATE ROLE carries the password ONLY as an escapeLiteral'd literal.
    assert(
      hasSql(
        fake.queries,
        new RegExp(
          `CREATE ROLE "appuser" LOGIN CONNECTION LIMIT -1 PASSWORD '${SENTINEL}'`,
        ),
      ),
      `CREATE ROLE shape: ${JSON.stringify(sqls(fake.queries))}`,
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

Deno.test("role_password_set: ALTER ROLE … PASSWORD via escapeLiteral; rejects missing role", async () => {
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
    // escapeLiteral doubles the single quotes
    assert(
      hasSql(
        fake.queries,
        /ALTER ROLE "appuser" PASSWORD 'rot-pw''with''quote'/,
      ),
      `ALTER shape: ${JSON.stringify(sqls(fake.queries))}`,
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
    assertEquals(written[0].data.action, "unchanged");
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
      password: "SENT",
    }, context);
    assert(
      hasSql(
        fake.queries,
        /CREATE ROLE "fresh" LOGIN CONNECTION LIMIT -1 PASSWORD 'SENT'/,
      ),
      "role created",
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
  // table_inspect: existence probe returns present=false ⇒ throws after connecting.
  const fake = makeFakeDb((sql) =>
    /to_regclass/.test(sql) ? [{ present: false }] : undefined
  );
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
    const r = schema.safeParse({ login: v });
    return (r.error?.issues ?? []).some((i) => i.path[0] === "login");
  };
  for (const bad of ["0", "1", "False", "True", "yes", null]) {
    assert(fieldFails(bad), `login=${JSON.stringify(bad)} must be rejected`);
  }
  for (const good of [true, false, "true", "false"]) {
    assert(!fieldFails(good), `login=${JSON.stringify(good)} must be accepted`);
  }
});
