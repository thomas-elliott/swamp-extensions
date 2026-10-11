# @thomas/postgres-admin

Non-destructive **PostgreSQL administration** for swamp, over a direct TCP
connection (node-postgres). It creates a new application's database, login role,
and permissions, and audits existing ones, without reading or writing table
data.

## Scope

This extension holds an admin credential, so its methods are limited and leave
data alone:

- It never reads or writes table rows: no `SELECT`/`INSERT`/`UPDATE`/`DELETE`
  against user tables. Every query reads `pg_catalog` / `information_schema`
  only.
- It never drops a database or role, and never truncates.
- It has no arbitrary-SQL method: all SQL is written into the methods.
- Read methods also run under `default_transaction_read_only = on`.

This extension does not support data access or destructive operations. Use
another tool for those.

## Install

```bash
swamp extension pull @thomas/postgres-admin
```

## Configure

Create a model instance and supply the admin password from a vault (never
inline):

```bash
swamp model create @thomas/postgres-admin pg \
  --global-arg host=postgres-host \
  --global-arg port=5432 \
  --global-arg adminUser=postgres \
  --global-arg maintenanceDb=postgres \
  --global-arg 'adminPassword=${{ vault.get(<vault>, postgres/admin_password) }}'
```

| Global arg               | Default                         | Notes                                                                     |
| ------------------------ | ------------------------------- | ------------------------------------------------------------------------- |
| `host`                   | —                               | Postgres host or IP.                                                      |
| `port`                   | `5432`                          | TCP port.                                                                 |
| `adminUser`              | `postgres`                      | Admin/superuser login used for every connection.                          |
| `adminPassword`          | — (sensitive)                   | Supply via `${{ vault.get(...) }}`. Never logged or echoed.               |
| `maintenanceDb`          | `postgres`                      | DB for cluster-wide ops (CREATE DATABASE) + db/role catalog reads.        |
| `ssl.mode`               | `disable`                       | `disable`/`require`/`verify-ca`/`verify-full`. Use `require` or stronger. |
| `ssl.ca`                 | —                               | PEM CA bundle; needed for `verify-ca` and `verify-full`.                  |
| `ssl.rejectUnauthorized` | from `ssl.mode`                 | Overrides the certificate check that `ssl.mode` implies.                  |
| `statementTimeoutMs`     | `30000`                         | Per-session `statement_timeout`.                                          |
| `identifierPattern`      | `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$` | Identifiers must match this (in addition to being escaped).               |

Set `ssl.mode=require` (or `verify-full` with `ssl.ca`) wherever the server
supports TLS. As in libpq, `verify-ca` checks the certificate chain against
`ssl.ca` but not the host name; `verify-full` checks both. Role passwords are
hashed before they are sent, but with `disable` everything else, including the
admin login's SCRAM exchange and every catalog read, crosses the network
unencrypted.

## Methods

### Read / audit (read-only)

| Method              | What it does                                                                     |
| ------------------- | -------------------------------------------------------------------------------- |
| `database_list`     | Databases with owner / encoding / size.                                          |
| `role_list`         | Roles with attributes (LOGIN/SUPERUSER/…) and memberships. No passwords.         |
| `permissions_audit` | DB/schema privileges; table, usage and sequence grants (with grantee); defaults. |
| `table_inspect`     | A table's (or view's) columns, primary key, indexes, constraints, owner.         |
| `connections_list`  | `pg_stat_activity`, with `backendType`. `query` only with `includeQuery=true`.   |
| `extension_list`    | Installed extensions per database (fans out across all dbs if none given).       |

In `permissions_audit`, `databasePrivileges` and `schemaPrivileges` are
effective privileges (they include `PUBLIC` and role membership) and are present
only when `role` is given. `tableGrants`, `usageGrants` and `sequenceGrants` are
direct grants. `sequenceGrants` lists every privilege on sequences, `USAGE`
included, so a sequence's `USAGE` also shows in `usageGrants`.

### Mutating (admin DDL, no data access)

| Method              | What it does                                                                |
| ------------------- | --------------------------------------------------------------------------- |
| `database_create`   | `CREATE DATABASE` (idempotent → `unchanged` if it exists).                  |
| `role_create`       | `CREATE ROLE` (LOGIN, vault password, conn limit, memberships). Idempotent. |
| `grant`             | GRANT on database/schema/table/sequence (+ optional future-object privs).   |
| `revoke`            | Mirror of `grant`.                                                          |
| `role_password_set` | Rotate a role's password from a vault value.                                |
| `app_provision`     | Composite: db + login role + standard grants in one, idempotent.            |

### Example — provision a new app

```bash
swamp model method run pg app_provision \
  --input database=myapp \
  --input role=myapp \
  --input 'password=${{ vault.get(<vault>, myapp/db_password) }}'
```

Creates the `myapp` database owned by a new `myapp` login role, grants
`CONNECT`, schema `USAGE`/`CREATE`, `SELECT/INSERT/UPDATE/DELETE` on existing
tables and `USAGE/SELECT` on sequences, plus matching **default privileges** for
future objects (`ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`, so they cover the
tables the owner creates). Those table and default privileges are what the role
gets when `tablePrivs` / `includeFuture` are not passed and the role holds none
of the grants `app_provision` makes, which is also how a re-run after a failed
first attempt finishes provisioning (it returns `granted`). The grants run in
one transaction, so a failed attempt leaves none of them behind.

The role counts as provisioned in a schema while it directly holds any one of
the schema-scoped grants: USAGE or CREATE on the schema, any privilege on a
table or sequence in the schema, or a default-privilege entry for the schema.
CONNECT on the database does not count, because it covers the whole database: a
second `app_provision` run for another schema in the same database gets the full
set in that schema. A re-run on a provisioned role issues only the table and
default privileges it is given. CONNECT and the schema grants are not issued
again, so a privilege revoked by hand stays revoked. Revoking schema USAGE alone
does not reset the role; revoking all of the schema-scoped grants does, and the
next run grants the full set again, CONNECT included.

A re-run returns `granted` if it issued any grant and `unchanged` if it issued
none.

`grant`/`revoke` with `includeFuture` need `defaultForRole`: the role that will
create the future objects. PostgreSQL applies default privileges per creating
role, and without `FOR ROLE` it would alter the admin login's own defaults.

### Data names

Each record is named after its spec, then its key parts, joined by `:`:

| Spec                | Name                                                 |
| ------------------- | ---------------------------------------------------- |
| `database`          | `database:<db>`                                      |
| `role`              | `role:<role>`                                        |
| `permissions-audit` | `permissions-audit:<db>` (all roles) or `...:<role>` |
| `table`             | `table:<db>:<schema>:<table>`                        |
| `connection`        | `connection:<pid>`                                   |
| `extension`         | `extension:<db>:<extension>`                         |
| `role-result`       | `role-result:<role>`                                 |
| `grant-result`      | `grant-result:<db>:<scope>:<role>`                   |
| `app-provision`     | `app-provision:<db>:<role>`                          |

Within a key part, `%`, `:`, `/`, `\` and `.` are written as `%25`, `%3A`,
`%2F`, `%5C` and `%2E`. Ordinary identifiers are unchanged. For example:

```bash
swamp data query 'modelName == "pg" && name == "database:myapp"' --json
```

```yaml
owner: ${{ data.latest("pg", "app-provision:myapp:myapp").attributes.owner }}
```

## Breaking changes

- **Data names now start with the spec name**, as listed under
  [Data names](#data-names): for example `database:myapp`, not `myapp`. swamp
  keys data by model and name, not by spec, so earlier versions let a role
  record overwrite the database record of the same name. `app-provision` is now
  keyed by database and role. Records written by earlier versions keep their old
  names and are not migrated.

- **`grant` and `revoke` with `includeFuture` now require `defaultForRole`.**
  Earlier versions ran `ALTER DEFAULT PRIVILEGES` without `FOR ROLE`, which
  changes the defaults of the admin login only. That did nothing for tables
  created by any other role, such as the app's own, and the argument's
  description wrongly said it defaulted to the schema owner. If your admin login
  does create the tables, pass `defaultForRole: <adminUser>` to keep the old
  behaviour.
- **Boolean arguments accept only `true`/`false`.** Earlier versions read
  anything else, including `"True"`, `"1"` and `"yes"`, as false. From the CLI,
  `--input x=true` and `--input x=false` work as before, but a method called
  directly with the string `"true"` or `"false"` now rejects it.
- **Re-running `app_provision` on a provisioned role no longer grants CONNECT,
  schema USAGE/CREATE or sequence access again.** It issues only the table and
  default privileges it is given, and sequence access only alongside table
  privileges. A privilege revoked by hand stays revoked; grant it back with
  `grant` if that was not intended.
- **Empty passwords are rejected.** `role_password_set`, `role_create` and
  `app_provision` now refuse `password: ""` before running any SQL. PostgreSQL
  reads `PASSWORD ''` as `PASSWORD NULL`, so `role_password_set` used to clear
  the password while reporting `rotated`, and the other two made a login role
  with no password. Leave `password` out to create a role without one.
- **`permissions_audit` leaves out system schemas and collations, and names the
  grantee.** Table and usage grants in `pg_*` schemas and `information_schema`,
  and the implicit `PUBLIC` usage on collations, are no longer listed. Each
  entry in `tableGrants` and `usageGrants` now has `grantee` and `grantor`.
- **Role passwords are always stored as SCRAM-SHA-256.** They are now hashed
  before they are sent, so the server's `password_encryption` setting no longer
  applies to them. A client that only supports md5 authentication cannot log in
  as a role whose password this extension set; PostgreSQL 14 and later default
  to SCRAM, and libpq has supported it since PostgreSQL 10.
- **`app_provision` treats a role as provisioned in a schema while it holds any
  direct schema-scoped grant that `app_provision` makes** (schema USAGE/CREATE,
  a table or sequence privilege, or a default-privilege entry), not only schema
  USAGE. Revoking USAGE by hand no longer makes the next run grant everything
  back. CONNECT on the database does not count, so `app_provision` for a second
  schema in the same database still grants the full set there.
- **`role_list` writes `memberOf` as a list of role names.** Earlier versions
  stored PostgreSQL's array text, such as `"{a,b}"`, so a CEL `in` test did not
  work on it.
- **`role_list` writes `validUntil` as an ISO 8601 timestamp**, such as
  `2027-01-01T00:00:00.000Z`, or `infinity`. Earlier versions wrote a JavaScript
  date string, such as `Fri Jan 01 2027 00:00:00 GMT+0000 (...)`, and
  `Infinity`.
- **`app_provision` returns `granted`, not `unchanged`, when a re-run on a
  provisioned role issues grants** (the `tablePrivs` or `includeFuture` passed
  to it). `unchanged` now means no grant was issued.
- **`ssl.mode=verify-ca` no longer checks the server's host name**, as in libpq.
  Earlier versions checked it, so `verify-ca` behaved like `verify-full`. Use
  `verify-full` to keep the host-name check.
- **`table_inspect` reports declared column types and refuses non-tables.** A
  column's `type` is now the declared type, such as `text[]`, `varchar(40)` or
  an enum's name, where earlier versions wrote `ARRAY`, `character varying` or
  `USER-DEFINED`. PostgreSQL 18 not-null constraints are typed `not null`, not
  `n`. Naming an index, sequence or composite type now fails; earlier versions
  described it as a table with no columns. Views, materialised views and foreign
  tables still work.
- **`connections_list` writes `clientAddr` without a netmask** (`192.0.2.7`, not
  `192.0.2.7/32`), and adds `backendType`, which tells client sessions apart
  from the server's own processes.
- **`grant` and `revoke` check every argument before running any statement, and
  run their statements in one transaction.** A bad `defaultForRole` or object
  name, or a failing default-privilege step, used to leave the object grant in
  place; now nothing is applied.
- **`grant` and `revoke` refuse `includeFuture` for database and schema scope,
  and `objects` together with `allInSchema=true`.** Earlier versions ignored
  `includeFuture` there (while recording it as `true`) and ignored `objects`
  when `allInSchema` was set.
- **`permissions_audit` adds `sequenceGrants`, and leaves out
  `databasePrivileges` and `schemaPrivileges` when no `role` is given.** Earlier
  versions wrote both as empty lists, which read as "no privileges", and listed
  no sequence `SELECT`/`UPDATE` grants anywhere.
- **`extension_list` writes nothing if any database fails.** Earlier versions
  wrote the records of the databases read before the failure.
- **`database_list` and `database_create` leave `sizeBytes` out** for a database
  the admin login cannot connect to (unless it has `pg_read_all_stats`). Earlier
  versions failed the whole call.
- **`port` must be 1 to 65535 and `statementTimeoutMs` 0 or more.** Earlier
  versions accepted any integer, so an empty `--global-arg port=` became port 0.

## Safety notes

- **Identifiers** (db/role/schema/table names) are validated against
  `identifierPattern` _and_ escaped via `escapeIdentifier`. **Filter values** in
  catalog reads use bound parameters.
- **Role passwords never leave the process in plain text.** `role_create`,
  `role_password_set` and `app_provision` hash the password to a SCRAM-SHA-256
  verifier first, as psql's `\password` does (PBKDF2-SHA-256, 4,096 iterations,
  a random 16-byte salt), and send `PASSWORD 'SCRAM-SHA-256$…'`. The server
  stores that verifier as it is. The plain text is not on the wire, in
  `pg_stat_activity`, or in the server log under `log_statement = ddl`. The
  password is never logged or written to a result.
- **Non-ASCII passwords** are normalised as PostgreSQL does (SASLprep: NFKC,
  plus its space and "mapped to nothing" rules), so they log in the same as
  before. One gap: where SASLprep rejects a password (control, private-use or
  unassigned characters, which include most emoji, or mixed-direction text),
  PostgreSQL hashes the raw password instead, and this extension does not, so
  such a password may fail to log in. ASCII passwords, such as generated ones,
  are never affected.
- Pre-flight **`reachable`** check (label `live`) fails before a mutating method
  runs if the server can't be reached.
