# `@thomas/garage`

Control-plane administration of a [Garage](https://garagehq.deuxfleurs.fr/)
(S3-compatible object store) cluster through its **Admin API v2** (`/v2/…`,
bearer-token auth). Audit permissions, manage buckets, and create / rotate /
revoke access keys from swamp.

This model holds the cluster's `admin_token`, so it covers the **control plane
only**: buckets, access keys, and key↔bucket permissions. It never reads or
writes S3 object data, and the destructive verbs (`bucket_delete`, `key_delete`)
verify the target by id first. Garage itself refuses to delete a non-empty
bucket.

It has **no object-level visibility**, because the Admin API does not provide
it. You get per-bucket object counts and byte totals; listing or verifying
individual objects needs the S3 data API.

## Configuration

```yaml
type: "@thomas/garage"
globalArguments:
  endpoint: http://garage-host:3903 # Admin API base URL; no trailing /v2
  adminToken: ${{ vault.get(<vault>, garage/admin_token) }}
  s3Region: garage # informational; echoed in output
  timeoutMs: 30000
```

The Admin API must be reachable from where swamp runs. Garage binds it per
`garage.toml` `[admin] api_bind_addr`. Set it to `0.0.0.0:3903` (or publish the
container port) so swamp can reach it, and keep it **token-gated and private**
(don't expose the admin API publicly). Plain HTTP on a trusted/encrypted network
is fine, and **an HTTPS reverse proxy works too**: point `endpoint` at the proxy
and `/v2/…` is appended per call.

**Instance naming:** if a compose/stack project shares the cluster's name, give
the swamp model instance a distinct name (e.g. `garage-<env>-admin`) to avoid
confusion. The names do not actually conflict.

> **Version note.** Needs Garage **v2.0 or later**, the first release with the
> Admin API v2. Garage v1 has only the older `/v1` API, which this model does
> not speak. Check `cluster_health` works before relying on it.

## Methods

### Read / audit (safe)

| Method              | Purpose                                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------- |
| `cluster_health`    | Status + node/partition counts (`GetClusterHealth`).                                                        |
| `bucket_list`       | All buckets, each enriched with usage/quotas/per-key permissions.                                           |
| `bucket_get`        | One bucket by exactly one of `id`, `globalAlias` or `search`.                                               |
| `key_list`          | All access keys (id/name/expiry).                                                                           |
| `key_get`           | One key by exactly one of `id` or `search`; `showSecretKey` reveals the secret.                             |
| `permissions_audit` | Full key×bucket matrix + risk flags (orphan keys, owner-everywhere, website-exposed buckets, expired keys). |

### Buckets

| Method                                     | Purpose                                                                                                                                                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `bucket_create`                            | Create a bucket with a global (or local) alias. Idempotent on `globalAlias`. A local alias's key gets only the grants set with `localAliasRead`/`localAliasWrite`/`localAliasOwner` (none by default). |
| `bucket_update`                            | Set quotas (`maxObjects`/`maxSize`) and/or static-website config.                                                                                                                                      |
| `bucket_delete`                            | Delete **by id** (verified; refuses non-empty unless `allowNonEmpty`). An already-gone bucket is `unchanged`.                                                                                          |
| `bucket_alias_add` / `bucket_alias_remove` | Manage global/local aliases (one alias per call).                                                                                                                                                      |

### Keys

| Method       | Purpose                                                                                                                                               |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `key_create` | New key; the secret goes to a vault, referenced from `key-result` (see [Secret handling](#secret-handling)). `neverExpires=false` needs `expiration`. |
| `key_import` | Import a known `accessKeyId` + `secretAccessKey` pair. Idempotent: the same pair again is `unchanged`.                                                |
| `key_update` | Rename, toggle create-bucket, change expiry (`neverExpires=true` clears it; `false` does nothing).                                                    |
| `key_rotate` | Create a replacement key, copy the old key's grants and local aliases onto it, return the new secret. Does **not** delete the old key.                |
| `key_delete` | Delete a key **by id** (verified). An already-gone key is `unchanged`.                                                                                |

### Permissions

| Method      | Purpose                                                               |
| ----------- | --------------------------------------------------------------------- |
| `key_allow` | Grant `read`/`write`/`owner` on a bucket to a key.                    |
| `key_deny`  | Revoke `read`/`write`/`owner` (each flag set = deny that permission). |

### Cluster / first-boot lifecycle

| Method           | Purpose                                                                                                                                                                                                                                                  |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cluster_status` | This node's id, Garage version, layout version, and every node's role/up-state. Read-only; use it to find node ids.                                                                                                                                      |
| `layout_get`     | Current layout: assigned roles + staged (un-applied) changes. Read-only.                                                                                                                                                                                 |
| `cluster_init`   | **First boot in one call:** assign a storage role to the node (defaults to the responding node, which is correct for single-node) and apply it, making a fresh cluster usable without the CLI. Idempotent (skips if already initialised unless `force`). |
| `layout_assign`  | Stage a node role (zone, `capacity` in bytes or `null` for gateway, tags). Anything omitted keeps the node's current value (a change already staged for it, else its applied role); a node with no role yet needs a zone and defaults to gateway.        |
| `layout_apply`   | Commit staged changes, role or `zoneRedundancy` (defaults to current version + 1).                                                                                                                                                                       |
| `layout_revert`  | Discard staged changes.                                                                                                                                                                                                                                  |

`cluster_init` replaces the manual `garage layout` CLI step. A new single-node
cluster that is running but has no layout becomes usable with:

```bash
# capacity is in BYTES (1000000000 = 1 GB)
swamp model method run garage cluster_init --input capacity=1000000000
swamp model method run garage cluster_status   # confirm the node is up + assigned
```

For multi-node, run the steps separately: `cluster_status` → `layout_assign` per
node → `layout_get` to review → `layout_apply`.

## Secret handling

`key_create`, `key_import` and `key_rotate` put the key's secret on the
`key-result` resource as `secretAccessKey`. That field is marked sensitive, so
swamp stores the value in one of the repository's vaults under an auto-generated
key, and the stored data holds only a reference of the form
`${{ vault.get('<vault>', '<key>') }}`. The other fields (`accessKeyId`, `name`,
`action`, `timestamp`) are stored as plain values. Deleting the data does
**not** remove the vault entry. Garage can also return the secret later, through
`key_get --input showSecretKey=true`. The admin token and key secrets are never
written to logs.

**Capture → named vault entry.** To give a consumer a stable vault key, create
the key, then copy the secret from the auto-generated entry:

```bash
# 1. create the key; the result is named key-result:<accessKeyId>
NAME=$(swamp model method run garage key_create --input name=myapp --json \
  | jq -r '.dataArtifacts[0].name')
AKID=${NAME#key-result:}

# 2. find the auto-generated vault entry from the reference in the data
REF=$(swamp data query "model(\"garage\") && name == \"$NAME\"" \
  --single --json --select content | jq -r '.secretAccessKey')
VAULT=$(sed -E "s/.*vault\.get\('([^']+)', '([^']+)'\).*/\1/" <<<"$REF")
KEY=$(sed -E "s/.*vault\.get\('([^']+)', '([^']+)'\).*/\2/" <<<"$REF")

# 3. copy both to named entries (the secret through a pipe, so it never
#    appears in a process list), then remove the auto-generated entry and data
swamp vault put <vault> "garage/myapp/access_key_id" "$AKID"
swamp vault read-secret "$VAULT" "$KEY" --json | jq -r '.value' \
  | swamp vault put <vault> "garage/myapp/secret_access_key"
swamp vault delete "$VAULT" "$KEY"
swamp data delete garage "$NAME" --json
```

A small swamp **workflow** (key_create → vault put → grant) would make this a
single command per consumer. It is not built yet.

**Importing a key.** `key_import` takes the secret as an argument, and
`--input secretAccessKey=…` would leave it in shell history. Pipe it in instead:

```bash
swamp vault read-secret <vault> "garage/myapp/secret_access_key" --json \
  | jq '{accessKeyId: "GK…", secretAccessKey: .value}' \
  | swamp model method run garage key_import --stdin
```

## Data names

swamp keys stored data by model and name, not by spec, so every name starts with
its spec:

| Spec                                                                     | Name                                                                                |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `cluster-health`, `cluster-status`, `cluster-layout`, `permission-audit` | the spec name alone                                                                 |
| `bucket`, `bucket-result`                                                | `<spec>:<bucketId>`                                                                 |
| `key`, `key-result`                                                      | `<spec>:<accessKeyId>`                                                              |
| `permission-result`                                                      | `permission-result:<bucketId>:<accessKeyId>`                                        |
| `layout-result`                                                          | `layout-result:<nodeId>`, `layout-result:apply-<version>` or `layout-result:revert` |

Garage's ids never need escaping. An id typed for a delete of something already
gone is recorded as typed, with `%`, `/`, `\` and `..` percent-escaped.

Read one with, for example,
`swamp data query 'model("garage") && name == "cluster-health"' --select content`,
or in CEL with `data.latest("garage", "bucket:<bucketId>")`.

## Breaking changes

- **Data names now start with their spec** (see [Data names](#data-names)).
  Before, four specs shared the name `main`, `bucket`/`bucket-result` and
  `key`/`key-result` shared the bare id, and `bucket_create` named its result by
  alias. Records written by earlier versions keep their old names and are not
  migrated; update any `data.latest(...)` expression or script that used the old
  names.
- **`key-result` vaults only `secretAccessKey`.** Before, the whole output was
  marked sensitive, so `accessKeyId`, `name`, `action` and `timestamp` were also
  stored as vault references, and every key method needed a vault even when it
  returned no secret. They are now plain values; a script or CEL expression that
  resolved them through the vault can read them directly.
- **`layout_assign` takes omitted fields from a change already staged for the
  node** before falling back to its applied role. Before, a second call restaged
  the applied values and silently undid the first, and a node that was staged
  but not yet applied needed `zone` again.
- **`cluster_status` now reports `garageVersion`** (of the node that answered).
  It was always empty before.
- **`bucket_delete` and `key_delete` of a target that is already gone succeed**
  and record `unchanged` with the id. Before, they failed with Garage's
  not-found error.
- **`key_create` rejects `neverExpires=false` without `expiration`.** Before, it
  created a key that never expires.
- **`bucket_create` takes `localAliasRead`, `localAliasWrite` and
  `localAliasOwner`** to grant the local alias's key on the new bucket. They
  default to false, which is the old behaviour; setting one without `localAlias`
  is an error.
- **Arguments Garage would refuse are now rejected before any call:** more than
  one selector on `bucket_get`/`key_get`, both aliases on `bucket_alias_add`/
  `bucket_alias_remove` (one used to be silently ignored), negative quotas,
  capacities or versions, `zoneRedundancy` `0`, and a `timeoutMs` of 0 or less.
- **`bucket_update` no longer drops website documents silently.** Documents with
  `websiteEnabled=false`, or for a bucket whose website is off, are an error,
  and so is enabling a website when the bucket has no index document.
- **`key_update` ignores `neverExpires=false`.** It never changed anything; on
  its own it is now "nothing to update" rather than a recorded `updated`.
- **`bucket_alias_add` and `bucket_alias_remove` read the bucket first.** An
  alias already on the bucket records `unchanged` (before: `updated`), and
  removing one already gone records `unchanged` (before: Garage's 500). One gap
  remains: Garage lists a key on a bucket only when the key has a permission
  there, so a local alias of a key with none is invisible, and removing a
  missing one still fails with Garage's error.
- **`key_import` of a key that already exists with the same secret succeeds** as
  `unchanged`. A different secret is still an error.
- **`key_rotate` also copies the old key's local aliases** to the new key.
- **`key_rotate` refuses an expired key.** The new key takes the old key's
  expiry, so before it created a key that was already expired. Set a new
  expiration with `key_update`, then rotate.
- **`layout_apply` applies a staged `zoneRedundancy` change on its own**;
  before, it needed an explicit `version`.
- **`bucket_list` and `permissions_audit` skip a bucket deleted while they
  run**, and `bucketCount` counts the buckets actually audited.
- **Network errors and timeouts read `Garage <op> failed: <cause>`**, and the
  timeout now also covers reading the response body.

## Credential rotation

Garage has no in-place rotate. `key_rotate` does the safe sequence: create a new
key → copy the old key's bucket grants and local aliases → return the new
secret. Update your consumers to the new key, verify, then `key_delete` the old
id as a separate step.

## Example

```bash
swamp model method run garage cluster_health
swamp model method run garage permissions_audit
swamp model method run garage bucket_create --input globalAlias=backups
swamp model method run garage key_create --input name=backup-writer --input allowCreateBucket=false
swamp model method run garage key_allow \
  --input bucketId=<id> --input accessKeyId=<GK…> --input read=true --input write=true
```

## License

MIT — see [LICENSE.txt](LICENSE.txt).
