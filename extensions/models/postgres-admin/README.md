# @thomas/postgres-admin

Non-destructive **PostgreSQL administration** for swamp, over a direct TCP
connection (node-postgres). Built for the common task of standing up a new
application's database, login role, and permissions — plus auditing what's
already there — without ever touching table data.

## Scope guarantee (read this first)

This extension holds a powerful admin credential, so its surface is deliberately
narrow and **data-safe**:

- ❌ **Never reads or writes table rows** — no `SELECT`/`INSERT`/`UPDATE`/`DELETE`
  against user tables. Every query hits `pg_catalog` / `information_schema` only.
- ❌ **Never `DROP`s** a database or role, **never `TRUNCATE`s**.
- ❌ **No arbitrary-SQL method** — all SQL is author-controlled inside the methods.
- ✅ Read methods additionally run under `default_transaction_read_only = on`.

If you need data access or destructive operations, this is intentionally the
wrong tool.

## Install

```bash
swamp extension pull @thomas/postgres-admin
```

## Configure

Create a model instance and supply the admin password from a vault (never inline):

```bash
swamp model create @thomas/postgres-admin pg \
  --global-arg host=postgres-host \
  --global-arg port=5432 \
  --global-arg adminUser=postgres \
  --global-arg maintenanceDb=postgres \
  --global-arg 'adminPassword=${{ vault.get(<vault>, postgres/admin_password) }}'
```

| Global arg          | Default                         | Notes                                                            |
| ------------------- | ------------------------------- | ---------------------------------------------------------------- |
| `host`              | —                               | Postgres host or IP.                                             |
| `port`              | `5432`                          | TCP port.                                                        |
| `adminUser`         | `postgres`                      | Admin/superuser login used for every connection.                 |
| `adminPassword`     | — (sensitive)                   | Supply via `${{ vault.get(...) }}`. Never logged or echoed.      |
| `maintenanceDb`     | `postgres`                      | DB for cluster-wide ops (CREATE DATABASE) + db/role catalog reads.|
| `ssl.mode`          | `disable`                       | `disable`/`require`/`verify-ca`/`verify-full`.                   |
| `statementTimeoutMs`| `30000`                         | Per-session `statement_timeout`.                                 |
| `identifierPattern` | `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$` | Identifiers must match this (in addition to being escaped).      |

## Methods

### Read / audit (read-only)

| Method              | What it does                                                                |
| ------------------- | --------------------------------------------------------------------------- |
| `database_list`     | Databases with owner / encoding / size.                                     |
| `role_list`         | Roles with attributes (LOGIN/SUPERUSER/…) and memberships. No passwords.     |
| `permissions_audit` | DB/schema/table/sequence grants + default privileges for a db (±a role).    |
| `table_inspect`     | A table's columns, primary key, indexes, constraints, owner. Catalog only.  |
| `connections_list`  | `pg_stat_activity`. The `query` column is omitted unless `includeQuery=true`.|
| `extension_list`    | Installed extensions per database (fans out across all dbs if none given).  |

### Mutating (admin DDL, data-safe)

| Method              | What it does                                                                |
| ------------------- | --------------------------------------------------------------------------- |
| `database_create`   | `CREATE DATABASE` (idempotent → `unchanged` if it exists).                  |
| `role_create`       | `CREATE ROLE` (LOGIN, vault password, conn limit, memberships). Idempotent. |
| `grant`             | GRANT on database/schema/table/sequence (+ optional future-object privs).   |
| `revoke`            | Mirror of `grant`.                                                          |
| `role_password_set` | Rotate a role's password from a vault value.                                |
| `app_provision`     | **Headline composite**: db + login role + standard grants in one, idempotent.|

### Example — provision a new app

```bash
swamp model method run pg app_provision \
  --input database=myapp \
  --input role=myapp \
  --input 'password=${{ vault.get(<vault>, myapp/db_password) }}'
```

Creates the `myapp` database owned by a new `myapp` login role, grants `CONNECT`,
schema `USAGE`/`CREATE`, `SELECT/INSERT/UPDATE/DELETE` on existing tables and
`USAGE/SELECT` on sequences, plus matching **default privileges** for future
objects. Re-running converges (returns `unchanged`).

## Safety notes

- **Identifiers** (db/role/schema/table names) are validated against
  `identifierPattern` *and* escaped via `escapeIdentifier`. **Filter values** in
  catalog reads use bound parameters. The **role password** is embedded only via
  `escapeLiteral` (DDL can't parameterise a `PASSWORD` literal), and is never
  logged or written to a result.
- **Server-log caveat:** if the server runs `log_statement = ddl` or `all`, a
  `CREATE/ALTER ROLE … PASSWORD '…'` statement (with the literal) lands in the
  Postgres **server log**. That's a server-side setting outside this extension's
  control; it does not attempt to mutate `log_statement` to hide the password.
- Pre-flight **`reachable`** check (label `live`) fails fast if the server can't
  be reached before a mutating method runs.
