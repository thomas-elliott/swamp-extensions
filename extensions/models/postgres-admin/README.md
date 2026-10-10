# @thomas/postgres-admin

Non-destructive **PostgreSQL administration** for swamp, over a direct TCP
connection (node-postgres). It creates a new application's database, login
role, and permissions, and audits existing ones, without reading or writing
table data.

## Scope guarantee (read this first)

This extension holds an admin credential, so its methods are limited and
**data-safe**:

- ❌ **Never reads or writes table rows**: no `SELECT`/`INSERT`/`UPDATE`/`DELETE`
  against user tables. Every query reads `pg_catalog` / `information_schema` only.
- ❌ **Never `DROP`s** a database or role, **never `TRUNCATE`s**.
- ❌ **No arbitrary-SQL method**: all SQL is author-controlled inside the methods.
- ✅ Read methods also run under `default_transaction_read_only = on`.

This extension does not support data access or destructive operations. Use
another tool for those.

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
| `app_provision`     | **Composite**: db + login role + standard grants in one, idempotent.       |

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
objects (`ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`, so they cover the tables the
owner creates). Those table and default privileges are what the role gets when
`tablePrivs` / `includeFuture` are not passed and the role does not yet hold the
schema grant, which is also how a re-run after a failed first attempt finishes
provisioning (it returns `granted`). Once the role holds the schema grant, re-running
returns `unchanged` and re-issues only the grants it is given, so it never widens
a role that was provisioned with less. The grants run in one transaction.

`grant`/`revoke` with `includeFuture` need `defaultForRole`: the role that will
create the future objects. PostgreSQL applies default privileges per creating
role, and without `FOR ROLE` it would alter the admin login's own defaults.

## Breaking changes

- **`grant` and `revoke` with `includeFuture` now require `defaultForRole`.**
  Earlier versions ran `ALTER DEFAULT PRIVILEGES` without `FOR ROLE`, which
  changes the defaults of the admin login only. That did nothing for tables
  created by any other role, such as the app's own, and the argument's
  description wrongly said it defaulted to the schema owner. If your admin login
  does create the tables, pass `defaultForRole: <adminUser>` to keep the old
  behaviour.

## Safety notes

- **Identifiers** (db/role/schema/table names) are validated against
  `identifierPattern` *and* escaped via `escapeIdentifier`. **Filter values** in
  catalog reads use bound parameters. The **role password** is embedded only via
  `escapeLiteral` (DDL can't parameterise a `PASSWORD` literal), and is never
  logged or written to a result.
- **Server-log caveat:** if the server runs `log_statement = ddl` or `all`, a
  `CREATE/ALTER ROLE … PASSWORD '…'` statement (with the literal) is written to the
  Postgres **server log**. That's a server-side setting outside this extension's
  control; it does not attempt to mutate `log_statement` to hide the password.
- Pre-flight **`reachable`** check (label `live`) fails before a mutating method
  runs if the server can't be reached.
