# @thomas/zitadel

Careful, non-destructive **Zitadel administration** for swamp, over the Zitadel
**Management API (v1 REST)**. Built for the common homelab tasks — standing up a
new application's OIDC client, wiring service accounts, and rotating credentials
— without the console click-through.

## Scope guarantee (read this first)

This extension holds a powerful **IAM admin** credential, so its surface is
deliberately narrow and **reversible**:

- ❌ **No hard deletes** — never deletes a project, application, or user. The
  only "off switch" is the reversible `app_set_state` / `user_set_state` /
  `grant_set_state` (deactivate ⇄ reactivate). The **one** exception is
  `role_remove`: a project role has no deactivate state in Zitadel, so retiring
  one is a verify-first `DELETE` — bounded and effectively reversible (re-create
  the same key), but it does cascade-revoke any grants referencing the role.
- ❌ **Machine identities only** — manages service users + their
  PATs/keys/secrets; it does **not** create human users or touch human
  passwords/MFA.
- ✅ **Secrets once** — every credential it mints (client secret, PAT, machine
  key) is emitted exactly once in the method output and marked `sensitive`;
  never logged.
- ✅ **Verify-before-mutate** — rotations/revocations confirm the target exists
  (and, for `pat_revoke`, that the token belongs to the user) first.

If you need human-user management or destructive operations, use the Zitadel
console — that's intentionally out of scope here.

## Authentication — JWT private-key service account

The model authenticates as a **service user with a JSON private key** (not a
long-lived bearer). Per run it signs a short-lived RS256 assertion and exchanges
it at `/oauth/v2/token` for an access token. Bootstrap once:

1. In the Zitadel console: **Users → New → Service User** (e.g. `swamp-admin`).
2. On that user: **Keys → New → JSON** → download the key JSON (shown once).
3. Grant it a manager role: **Org → Managers → Add** with **ORG_OWNER** (enough
   for org-scoped project/app/user management).
4. Store the key JSON in your vault (the whole blob in one field).

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
  --arg project=homelab --arg name=grafana \
  --arg 'redirectUris=["https://grafana.example.com/login/generic_oauth"]' \
  --arg appType=web --arg authMethod=basic
```

- `project_ensure` — find-or-create a project by name.
- `oidc_app_ensure` — ensure an OIDC client (redirect/post-logout URIs, appType
  `web|spa|native`, authMethod `basic|post|none|jwt`, grant/response types,
  devMode). Re-running converges config (`action: unchanged|updated`).
- `api_app_ensure` — ensure an API app (M2M resource server).

**Rotate:** `app_secret_rotate`, `machine_user_ensure`, `pat_create`,
`pat_revoke`, `machine_key_create`, `machine_secret_generate`.

**Authorization (roles, grants, role-in-token):**

```bash
# Define a role, grant it to a user, and make roles appear in that project's tokens
swamp model method run zitadel role_ensure \
  --arg project=homelab --arg key=admin --arg displayName=Admin
swamp model method run zitadel grant_ensure \
  --arg user=thomas@smol.cloud --arg project=homelab --arg 'roleKeys=["admin"]'
swamp model method run zitadel project_authz_set \
  --arg project=homelab --arg roleAssertion=true
```

- `role_ensure` — find-or-create a project role by `key`; converge
  `displayName`/ `group` (`action: created|unchanged|updated`).
- `role_remove` — verify-first `DELETE` of a role (the one hard delete; cascade-
  revokes grants that reference it).
- `grant_ensure` — grant a user (id or loginname) a **set** of role keys on a
  project; re-running converges the set (order-insensitive).
- `grant_set_state` — deactivate/reactivate a grant (verify-first, reversible).
- `project_authz_set` — toggle a project's `roleAssertion` / `roleCheck` /
  `hasProjectCheck` on an **existing** project (fetch-merge, never
  auto-creates). Without `roleAssertion`, granted roles do **not** appear in
  users' tokens.

**Reversible lifecycle:** `app_set_state` (active/inactive), `user_set_state`
(active/inactive), `grant_set_state` (active/inactive).

Every method writes one resource carrying the entity plus an `action`
(`created|unchanged|updated|rotated|revoked|deactivated|reactivated|removed|observed`)
and a `timestamp`.

## Notes

- Zero npm dependencies — JWT signing uses the runtime's `node:crypto` (Zitadel
  issues PKCS#1 RSA keys, signed natively).
- Targets the stable Management v1 API. For very large user bases the v2 User
  API is Zitadel's recommended surface; a future version may switch user methods
  over.
