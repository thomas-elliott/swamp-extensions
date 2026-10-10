# @thomas/zitadel

Non-destructive **Zitadel administration** for swamp, over the Zitadel
**Management API (v1 REST)**. It covers common homelab tasks without using the
console: creating a new application's OIDC client, setting up service accounts,
and rotating credentials.

## Scope guarantee (read this first)

This extension holds an **IAM admin** credential, so its methods are limited and
**reversible**:

- ❌ **No hard deletes**: never deletes a project, application, or user. The
  only way to disable one is the reversible `app_set_state` / `user_set_state` /
  `grant_set_state` (deactivate ⇄ reactivate). The **one** exception is
  `role_remove`: a project role has no deactivate state in Zitadel, so removing
  one is a verify-first `DELETE`. It affects only that role and can effectively
  be undone by re-creating the same key, but it also revokes any grants that
  reference the role.
- ❌ **Machine identities only**: manages service users and their
  PATs/keys/secrets; it does **not** create human users or change human
  passwords/MFA.
- ✅ **Secrets once**: every credential it creates (client secret, PAT, machine
  key) is returned exactly once in the method output and marked `sensitive`;
  never logged.
- ✅ **Verify-before-mutate**: rotations/revocations first confirm the target
  exists (and, for `pat_revoke`, that the token belongs to the user).

If you need human-user management or destructive operations, use the Zitadel
console. They are out of scope here.

## Authentication — JWT private-key service account

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
org), `httpTimeoutMs` (default 30000), `tokenScope` (advanced).

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

- `project_ensure` — find-or-create a project by name.
- `oidc_app_ensure` — ensure an OIDC client (redirect/post-logout URIs, appType
  `web|spa|native`, authMethod `basic|post|none|jwt`, grant/response types,
  devMode). Re-running updates only the fields it is given
  (`action: unchanged|updated`); everything else, including settings this method
  doesn't model, keeps its current value.
- `api_app_ensure` — ensure an API app (M2M resource server).
- `oidc_app_redirect_set` — add/remove redirect URIs on an existing OIDC app
  (set-based, idempotent), preserving every other field of its OIDC config (auth
  method, response/grant types, PKCE, devMode).

**Rotate:** `app_secret_rotate`, `machine_user_ensure`, `pat_create`,
`pat_revoke`, `machine_key_create`, `machine_secret_generate`.

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

- `role_ensure` — find-or-create a project role by `key`; update `displayName`/
  `group` (`action: created|unchanged|updated`).
- `role_remove` — verify-first `DELETE` of a role (the only hard delete; also
  revokes grants that reference it).
- `grant_ensure` — grant a user (id or loginname) a **set** of role keys on a
  project; re-running sets the grant to exactly that set (order does not
  matter). Omit `roleKeys` to keep an existing grant's roles as they are.
- `grant_set_state` — deactivate/reactivate a grant (verify-first, reversible).
- `project_authz_set` — toggle a project's `roleAssertion` / `roleCheck` /
  `hasProjectCheck` on an **existing** project (reads the project and merges the
  change; never creates a project). Without `roleAssertion`, granted roles do
  **not** appear in users' tokens.

**Reversible lifecycle:** `app_set_state` (active/inactive), `user_set_state`
(active/inactive), `grant_set_state` (active/inactive).

Every method writes one resource carrying the entity plus an `action`
(`created|unchanged|updated|rotated|revoked|deactivated|reactivated|removed|observed`)
and a `timestamp`.

## Notes

- Zero dependencies and no `node:` imports: JWT signing uses the Web Crypto API
  (`crypto.subtle`). Zitadel issues PKCS#1 RSA keys, which are wrapped to PKCS#8
  (a fixed DER envelope) before importing, since Web Crypto imports only PKCS#8.
- Targets the stable Management v1 API. For very large user bases Zitadel
  recommends the v2 User API; a future version may switch user methods to it.
