# @thomas/zitadel

Non-destructive **Zitadel administration** for swamp, over the Zitadel
**Management API (v1 REST)**. It covers common homelab tasks without using the
console: creating a new application's OIDC client, setting up service accounts,
and rotating credentials.

## Scope guarantee

This extension holds an **org admin** credential (an org manager such as
`ORG_OWNER`), so its methods are limited and **reversible**:

- **No deletes of projects, applications or users**: the only way to disable one
  is the reversible `app_set_state` / `user_set_state` / `grant_set_state`
  (deactivate ⇄ reactivate). Two methods do delete, both verify-first:
  `role_remove`, because a project role has no deactivate state (it also revokes
  any grants that use the role), and `pat_revoke`, because revoking a token
  removes it.
- **Creates machine identities only**: it creates service users and their
  PATs/keys/secrets. It does **not** create human users or change passwords or
  MFA. It can grant roles to, and deactivate, any user (`grant_ensure`,
  `user_set_state`), but `user_set_state` refuses to deactivate the model's own
  service user.
- **Secrets once**: every credential it creates (app client secret, PAT, machine
  key, machine client secret) is returned exactly once in the method output and
  marked `sensitive`; never logged. swamp stores a sensitive value in a vault,
  so if that write fails (the vault is locked or a prompt times out), the object
  exists but its secret is lost, and a re-run of the ensure method reports
  `unchanged` with no secret. Recover an app's secret with `app_secret_rotate`;
  for a machine user, create a new PAT or key, or run `machine_secret_generate`
  again.
- **Verify-before-mutate**: `app_secret_rotate`, `pat_revoke`, `role_remove`,
  `grant_set_state` and the `*_set_state` methods first read the target (and,
  for `pat_revoke` and `grant_set_state`, check it belongs to the user).
  `pat_create`, `machine_key_create` and `machine_secret_generate` look up a
  username, but pass a numeric user id straight to Zitadel, which refuses a
  human user itself.

If you need human-user management or destructive operations, use the Zitadel
console. They are out of scope here.

## Authentication: JWT private-key service account

The model authenticates as a **service user with a JSON private key** (not a
long-lived bearer token). Per run it signs a short-lived RS256 assertion and
exchanges it at `/oauth/v2/token` for an access token. One-time setup:

1. In the Zitadel console: **Users → New → Service User** (e.g. `swamp-admin`).
2. On that user: **Keys → New → JSON** → download the key JSON (shown once).
3. Grant it a manager role: **Org → Managers → Add** with **ORG_OWNER** (enough
   for org-scoped project/app/user management).
4. Store the key JSON in your vault (the whole JSON document in one field).

## Install

```bash
swamp extension pull @thomas/zitadel
```

## Configure

```bash
swamp model create @thomas/zitadel zitadel \
  --global-arg apiUrl=https://zitadel.example.com \
  --global-arg 'keyJson=${{ vault.get(<vault>, zitadel-admin/key_json) }}'
```

Optional global args: `orgId` (x-zitadel-orgid; defaults to the service user's
org), `httpTimeoutMs` (default 30000; must be positive), `tokenScope`
(advanced).

Use an `https://` `apiUrl`. With plain `http://` the access token crosses the
network unencrypted, and every method logs a warning.

## Methods

**Read / audit (never emit secrets):** `org_get`, `project_list` (includes the
authorization flags), `app_list`, `app_get`, `user_list`, `manager_audit`,
`role_list`, `grant_list`.

**Provision (idempotent on name):**

```bash
# Find-or-create the project, create/update the OIDC client, get clientId (+ secret once)
swamp model method run zitadel oidc_app_ensure \
  --input project=homelab --input name=grafana \
  --input 'redirectUris=["https://grafana.example.com/login/generic_oauth"]' \
  --input appType=web --input authMethod=basic
```

- `project_ensure`: find-or-create a project by name. An existing project is
  left as it is.
- `oidc_app_ensure`: ensure an OIDC client (redirect/post-logout URIs, appType
  `web|spa|native`, authMethod `basic|post|none|jwt`, grant/response types,
  devMode). Re-running updates only the fields it is given
  (`action: unchanged|updated`); everything else, including settings this method
  doesn't model, keeps its current value.
- `api_app_ensure`: find-or-create an API app (M2M resource server). An existing
  app is left as it is; `authMethod` applies on create only.
- `oidc_app_redirect_set`: add/remove redirect URIs on an existing OIDC app
  (set-based, idempotent), preserving every other field of its OIDC config (auth
  method, response/grant types, PKCE, devMode).
- `machine_user_ensure`: find-or-create a machine user by username. An existing
  user is left as it is.

`oidc_app_ensure`, `api_app_ensure` and `role_ensure` take a project name or id.
A name with no matching project **creates** that project, and the method logs
it. `grant_ensure` and `project_authz_set` never create a project: a name with
no match fails. A value that is all digits is looked up as a name first and
otherwise taken as a project id, so a project named `2026` can be addressed by
name.

**Credentials:** `app_secret_rotate` (rotate), `pat_create`, `pat_revoke`,
`machine_key_create`, `machine_secret_generate` (rotate).

**Authorization (roles, grants, role-in-token):**

```bash
# Define a role, grant it to a user, and make roles appear in that project's tokens
swamp model method run zitadel role_ensure \
  --input project=homelab --input key=admin --input displayName=Admin
swamp model method run zitadel grant_ensure \
  --input user=alice@example.com --input project=homelab --input 'roleKeys=["admin"]'
swamp model method run zitadel project_authz_set \
  --input project=homelab --input roleAssertion=true
```

- `role_ensure`: find-or-create a project role by `key`; update `displayName`/
  `group` (`action: created|unchanged|updated`).
- `role_remove`: verify-first `DELETE` of a role (also revokes grants that use
  it).
- `grant_ensure`: grant a user (id or login name, e.g. `alice@example.com`) a
  **set** of role keys on a project; re-running sets the grant to exactly that
  set (order does not matter). Omit `roleKeys` to keep an existing grant's roles
  as they are. An existing grant keeps its state: a deactivated grant stays
  deactivated.
- `grant_set_state`: deactivate/reactivate a grant (verify-first, reversible).
- `project_authz_set`: toggle a project's `roleAssertion` / `roleCheck` /
  `hasProjectCheck` on an **existing** project (reads the project and merges the
  change; never creates a project). Without `roleAssertion`, granted roles do
  **not** appear in users' tokens.

**Reversible lifecycle:** `app_set_state` (active/inactive), `user_set_state`
(active/inactive), `grant_set_state` (active/inactive). Each reads the current
state first; when it already matches, nothing is sent and the action is
`unchanged`.

Each method writes one resource per entity (a list method writes one per item)
carrying the entity plus an `action`
(`created|unchanged|updated|rotated|revoked|deactivated|reactivated|removed|observed`)
and a `timestamp`.

## Data names

Each record is named `<spec>:<key>`, so two specs never share a name (swamp keys
data by model and name, not by spec). Zitadel ids are used as keys:

| Spec                   | Name                                                                                                       |
| ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| `org`                  | `org:<orgId>`                                                                                              |
| `project`              | `project:<projectId>`                                                                                      |
| `app`                  | `app:<appId>`                                                                                              |
| `app-credential`       | `app-credential:<appId>`                                                                                   |
| `oidc-redirect-result` | `oidc-redirect-result:<appId>`                                                                             |
| `user`                 | `user:<userId>`                                                                                            |
| `manager`              | `manager:<userId>`                                                                                         |
| `machine-credential`   | `machine-credential:pat:<tokenId>`, `machine-credential:key:<keyId>`, `machine-credential:secret:<userId>` |
| `state-result`         | `state-result:app:<appId>`, `state-result:user:<userId>`                                                   |
| `role`                 | `role:<projectId>:<roleKey>`                                                                               |
| `grant`                | `grant:<grantId>`                                                                                          |

A role key is free text, so `%`, `/`, `\`, `..` and NUL in it are
percent-escaped (`%25`, `%2F`, `%5C`, `.%2E`, `%00`). For example, to read a
machine user's client secret after `machine_secret_generate`:

```bash
swamp data query 'modelName == "zitadel" && name == "machine-credential:secret:<userId>"' \
  --single --json --select attributes.clientId
```

## Notes

- Zero dependencies and no `node:` imports: JWT signing uses the Web Crypto API
  (`crypto.subtle`). Zitadel issues PKCS#1 RSA keys, which are wrapped to PKCS#8
  (a fixed DER envelope) before importing, since Web Crypto imports only PKCS#8.
- Targets the stable Management v1 API. For very large user bases Zitadel
  recommends the v2 User API; a future version may switch user methods to it.

## Breaking changes

- **Data names are now `<spec>:<key>`** (see [Data names](#data-names)), for
  example `user:<userId>` and `machine-credential:secret:<userId>`. Earlier
  versions used the bare id, so a `user_list` could replace the client secret
  stored for the same user. Records written by earlier versions keep their old
  names and are not migrated.
- **Boolean arguments are plain booleans.** From the CLI, `--input x=true` and
  `--input x=false` still work and anything else is rejected, as before. A
  caller that passes the strings `"true"` / `"false"` straight to a method (not
  through the CLI) is now rejected; pass real booleans. Earlier versions read
  `"True"`, `"1"`, `"yes"` and `null` as false.
- **`machine_user_ensure`, `pat_*` and `machine_*` find machine users only.** A
  human user with the same username is no longer taken for one.
- **`grant_ensure` without `roleKeys` keeps the grant's roles.** It used to
  remove them all.
- **`app_set_state`, `user_set_state` and `grant_set_state` succeed when the
  state already matches**, writing `action: "unchanged"`. The first two used to
  fail with Zitadel's PreconditionFailed error; `grant_set_state` repeated the
  call and reported `deactivated` or `reactivated` again. `user_set_state` now
  reads the user first, so an unknown user id fails on that read.
- **`authMethod` reads `basic` for basic-auth apps.** Zitadel omits the basic
  method on the wire, and earlier versions left `authMethod` empty for it in
  `app_list` and `app_get`.
- **`project_list` always writes the three authorization flags.** Zitadel omits
  a false flag, and earlier versions left it out of the record; it now reads
  `false`.
- **`oidc_app_ensure` and `api_app_ensure` refuse a name that belongs to an app
  of the other kind.** `api_app_ensure` used to report an OIDC app as an
  unchanged API app; `oidc_app_ensure` failed with a server error on an API app.
- **`app_secret_rotate` takes the app's kind from the app.** `kind` no longer
  defaults to `oidc`: omit it, or pass it as a check that fails on a mismatch.
  Rotating an API app's secret without `kind=api` used to fail.
- **`grant_ensure` records the grant's real state and display name.** It used to
  write `state: "active"` for an existing grant even when it was deactivated.
- **`user_set_state` refuses to deactivate the model's own service user**, which
  would lock the model out with no way back through swamp.
- **`httpTimeoutMs` must be a positive number.** `0` used to abort every request
  at once.
- **A create that returns no id fails.** Earlier versions recorded an empty id
  after the object was created.
- **`grant_ensure` no longer creates a project.** A project name with no match
  fails, as in `project_authz_set`. It used to create the project silently and
  grant on it.
- **An all-digit project value is looked up by name first.** In
  `oidc_app_ensure`, `api_app_ensure`, `role_ensure`, `grant_ensure` and
  `project_authz_set`, a project named `2026` is now found by name; a value that
  matches no name is still taken as a project id. This costs one extra lookup
  per call when an id is passed.
