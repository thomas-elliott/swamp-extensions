# `@thomas/garage`

Control-plane administration of a [Garage](https://garagehq.deuxfleurs.fr/)
(S3-compatible object store) cluster through its **Admin API v2** (`/v2/…`,
bearer-token auth). Audit permissions, manage buckets, and create / rotate /
revoke access keys from swamp.

This model holds the cluster's `admin_token`, so its surface is the **control
plane only** — buckets, access keys, and key↔bucket permissions. It never reads
or writes S3 object data, and the destructive verbs (`bucket_delete`,
`key_delete`) verify the target by id first. Garage itself refuses to delete a
non-empty bucket.

It has **no object-level visibility** (an Admin-API limitation, not a model one):
you get per-bucket object counts and byte totals, but listing or verifying
individual objects goes through the S3 data API, not this model.

## Configuration

```yaml
type: "@thomas/garage"
globalArguments:
  endpoint: http://garage-host:3903   # Admin API base URL; no trailing /v2
  adminToken: ${{ vault.get(<vault>, garage/admin_token) }}
  s3Region: garage                    # informational; echoed in output
  timeoutMs: 30000
```

The Admin API must be reachable from where swamp runs. Garage binds it per
`garage.toml` `[admin] api_bind_addr` — set it to `0.0.0.0:3903` (or publish the
container port) so swamp can reach it, and keep it **token-gated and private**
(don't expose the admin API publicly). Plain HTTP on a trusted/encrypted network
is fine, and **an HTTPS reverse proxy works too** — point `endpoint` at the front
door and `/v2/…` is appended per call.

**Instance naming:** if a compose/stack project shares the cluster's name, give the
swamp model instance a distinct name (e.g. `garage-<env>-admin`) to avoid
confusion — the namespaces don't actually collide.

> **Version note.** Targets Garage **v2.1+**, where bucket/key selectors are
> query parameters (`?id=`, `?globalAlias=`, `?search=`). Garage v2.0 used path
> parameters (`/v2/DeleteBucket/{id}`) for a handful of verbs — on v2.0 the
> mutating-by-id calls would 404. Check `cluster_health` works, then upgrade the
> cluster if needed.

## Methods

### Read / audit (safe)
| Method | Purpose |
| --- | --- |
| `cluster_health` | Status + node/partition counts (`GetClusterHealth`). |
| `bucket_list` | All buckets, each enriched with usage/quotas/per-key permissions. |
| `bucket_get` | One bucket by `id`, `globalAlias`, or `search`. |
| `key_list` | All access keys (id/name/expiry). |
| `key_get` | One key by `id`/`search`; `showSecretKey` reveals the secret. |
| `permissions_audit` | Full key×bucket matrix + risk flags (orphan keys, owner-everywhere, website-exposed buckets, expired keys). |

### Buckets
| Method | Purpose |
| --- | --- |
| `bucket_create` | Create a bucket with a global (or local) alias. Idempotent on `globalAlias`. |
| `bucket_update` | Set quotas (`maxObjects`/`maxSize`) and/or static-website config. |
| `bucket_delete` | Delete **by id** (verified; refuses non-empty unless `allowNonEmpty`). |
| `bucket_alias_add` / `bucket_alias_remove` | Manage global/local aliases. |

### Keys
| Method | Purpose |
| --- | --- |
| `key_create` | New key; the secret is returned **once** on `key-result` (sensitive). |
| `key_import` | Import a known `accessKeyId` + `secretAccessKey` pair. |
| `key_update` | Rename, toggle create-bucket, change expiry. |
| `key_rotate` | Create a replacement key, copy the old key's grants onto it, return the new secret. Does **not** delete the old key. |
| `key_delete` | Delete a key **by id** (verified). |

### Permissions
| Method | Purpose |
| --- | --- |
| `key_allow` | Grant `read`/`write`/`owner` on a bucket to a key. |
| `key_deny` | Revoke `read`/`write`/`owner` (each flag set = deny that permission). |

### Cluster / first-boot lifecycle
| Method | Purpose |
| --- | --- |
| `cluster_status` | This node's id, Garage version, layout version, and every node's role/up-state. Read-only — use it to find node ids. |
| `layout_get` | Current layout: assigned roles + staged (un-applied) changes. Read-only. |
| `cluster_init` | **First boot in one call:** assign a storage role to the node (defaults to the responding node — correct for single-node) and apply it, making a fresh cluster usable without the CLI. Idempotent (skips if already initialised unless `force`). |
| `layout_assign` | Stage a node role (zone + `capacity` in bytes, or gateway when capacity omitted). |
| `layout_apply` | Commit staged changes (defaults to current version + 1). |
| `layout_revert` | Discard staged changes. |

`cluster_init` removes the last manual `garage layout` CLI step — a brand-new
single-node cluster goes from "running but unusable" to "ready" with:

```bash
# capacity is in BYTES (1000000000 = 1 GB)
swamp model method run garage cluster_init --arg capacity=1000000000
swamp model method run garage cluster_status   # confirm the node is up + assigned
```

For multi-node, drive it granularly: `cluster_status` → `layout_assign` per node →
`layout_get` to review → `layout_apply`.

## Secret handling

Garage returns a new key's `secretAccessKey` **once**. `key_create` and
`key_rotate` surface it on the `key-result` resource (`secretAccessKey`, marked
sensitive). It is persisted to swamp's data store — capture it, store it in your
secret manager, and garbage-collect the artifact. The admin token and key secrets
are never written to logs.

**Capture → vault pattern.** The model can't write a vault itself (that's outside
a model's scope), so onboarding a new consumer is two steps — create the key, then
stash the result:

```bash
# 1. create the key and read its one-time secret out of the artifact
swamp model method run garage key_create --arg name=myapp --json
AKID=$(swamp data get garage key-result --json | jq -r '.content.accessKeyId')
SECRET=$(swamp data get garage key-result --json | jq -r '.content.secretAccessKey')

# 2. write both into your vault (item/field path, same form as vault.get), then GC
swamp vault put <vault> "garage/myapp/access_key_id" "$AKID"
swamp vault put <vault> "garage/myapp/secret_access_key" "$SECRET"
swamp data delete garage key-result --json
```

A small swamp **workflow** (key_create → vault put → grant) would make this a
one-shot per consumer; not built yet.

## Credential rotation

Garage has no in-place rotate. `key_rotate` does the safe sequence: create a new
key → copy the old key's bucket grants → return the new secret. Update your
consumers to the new key, verify, then `key_delete` the old id as a separate
step.

## Example

```bash
swamp model method run garage cluster_health
swamp model method run garage permissions_audit
swamp model method run garage bucket_create --arg globalAlias=backups
swamp model method run garage key_create --arg name=backup-writer --arg allowCreateBucket=false
swamp model method run garage key_allow \
  --arg bucketId=<id> --arg accessKeyId=<GK…> --arg read=true --arg write=true
```

## License

MIT — see [LICENSE.txt](LICENSE.txt).
