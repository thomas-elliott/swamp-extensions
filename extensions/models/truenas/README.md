# `@thomas/truenas`

Administration of a [TrueNAS SCALE](https://www.truenas.com/) host (25.04+) through
its **JSON-RPC 2.0 API over a WebSocket** (`wss://<host>/api/current`, API-key auth).
Audit what each app/share/service exposes, then restrict it. Built for the homelab
**service-exposure** hardening (R28).

Only three kinds of change are supported, and each is reversible:

- **App port binding:** switch a catalog app's port between `published` (bound on the
  host) and `exposed` (container-internal only). This closes a service's ports
  (e.g. lldap's plaintext LDAP `389` / LDAPS `636`) without uninstalling it.
- **NFS share access:** set the per-share authorized `networks`/`hosts` allowlist
  (the only supported per-client access control on TrueNAS).
- **SMB share access:** set per-share `hostsallow`/`hostsdeny`.

It does **not** touch pools, datasets, users, snapshots, replication, or service
start/stop. Service start/stop is left as an explicit gap because a stopped
`ssh`/`nfs` service risks a lockout or outage. Every mutating verb verifies its target by id/name first and is reversible by
re-running with the prior values.

## ⚠️ Transport safety — never send the key over cleartext

TrueNAS SCALE **permanently revokes an API key as soon as it receives that key
over a non-TLS transport** (plain `ws://`/`http://`). A single cleartext request
revokes the key; it is not rate-limited.

This model rejects any non-`wss` endpoint: `websocketUrl` throws
before opening a socket and never downgrades `https→ws`. Always use `wss://` (or a
bare host / `https://`, both of which resolve to `wss://<host>/api/current`).

## Configuration

```yaml
type: "@thomas/truenas"
globalArguments:
  endpoint: wss://nas.example.com/api/current   # bare host or https:// also accepted
  apiKey: ${{ vault.get(<vault>, truenas/credential) }}
  timeoutMs: 30000
```

Create an API key under **Credentials → Users → API keys**, bound to a user with the
roles you need (read-only roles suffice for the audit methods; the mutating methods
need `APP_WRITE` / `SHARING_NFS_WRITE` / `SHARING_SMB_WRITE`).

### TLS note (important)

TrueNAS ships a **self-signed certificate** (`CN=localhost`), which fails both chain
*and* hostname validation for `nas.example.com`. This model always validates the
certificate: Deno's `WebSocket` skips validation only when the whole **process** runs
with `--unsafely-ignore-certificate-errors`, with no per-connection switch, so there
is nothing for the model to turn off. The fix is to **install a certificate valid
for the host's name** on the TrueNAS UI (the WebSocket API uses the same `:443`
listener):

1. Issue/obtain a cert for the host name (e.g. the existing `*.example.com` wildcard).
2. **System Settings → Certificates** → import the cert+key.
3. **System Settings → GUI → GUI SSL Certificate** → select it; the UI reloads.

After that the `wss://` handshake validates normally. Replacing the self-signed cert
also improves the host's security.

## Methods

### Read / audit (safe)
| Method | Purpose |
| --- | --- |
| `system_info` | Host hostname, version, uptime, memory (`system.info`). |
| `app_list` | Every installed app + its port bindings (key, number, `published`/`exposed`, host IPs). Factory: one `app` per app. |
| `nfs_share_list` | NFS exports with their `networks`/`hosts` allowlist; flags `unrestricted` shares. |
| `smb_share_list` | SMB shares with `hostsallow`/`hostsdeny`; flags `unrestricted`. |
| `service_list` | System services (state + boot-enable). |
| `network_info` | Bindable host IPs (the app port-bind selector contents), interfaces, GUI bind addresses. |
| `filesystem_list` | Directory entries (`filesystem.listdir`) with type/size and a mountpoint flag (= a child dataset). Takes one path or a JSON list (fan-out: one session per run). An absent path records `exists=false` rather than failing, so it can check whether a backup or app source path has gone missing. |
| `app_storage` | An app's host-path binds — container mount path ← NAS path, and where each sits in the app config. Shows whether an app mounts one parent directory or each source individually. |
| `replication_list` | Replication tasks: source/target datasets, `recursive`, schedule, destination readonly policy, whether dataset **properties** are sent, and last-run state. Read-only; never runs or edits a task. Shows what writes into a destination dataset and when. A receive remounts the destination, which invalidates any container bind-mount of it. |
| `exposure_audit` | A single summary of published ports across all apps, ports on `0.0.0.0`, unrestricted NFS/SMB shares, a plaintext-LDAP flag, and the non-wildcard bindable IPs. The R28 data source. |

### Mutate (verify-first, reversible)
| Method | Purpose |
| --- | --- |
| `app_set_port_bind` | Set one app port's `bindMode` (`published`/`exposed`) and/or `hostIps`. Sends the **full** `network` map (siblings preserved), waits for the `app.update` job, re-reads. |
| `nfs_share_set_access` | Set a share's `networks`/`hosts` (empty array clears the restriction). |
| `smb_share_set_access` | Set a share's `hostsallow`/`hostsdeny` (empty `hostsallow` clears the allowlist). |

## Examples

```bash
# Audit exposure (read-only)
swamp model method run nas exposure_audit
swamp data get nas exposure-audit --json | jq '.content.flags'

# Does a backup source path still exist? (read-only; one path or a JSON list)
swamp model method run nas filesystem_list --input path=/mnt/Backup
swamp model method run nas filesystem_list --input path='["/mnt/Backup","/mnt/Backup/apps"]'
swamp data get nas mnt-Backup --json | jq '.content | {exists, entries: [.entries[].name]}'

# What replicates into a destination dataset, and how? (read-only)
swamp model method run nas replication_list
swamp data query nas 'attributes.targetDataset.startsWith("Backup/")'

# Close lldap's plaintext LDAP + LDAPS (no consumers) — container-internal only
swamp model method run nas app_set_port_bind --input app=lldap --input portKey=ldap_port  --input bindMode=exposed
swamp model method run nas app_set_port_bind --input app=lldap --input portKey=ldaps_port --input bindMode=exposed

# Restrict an NFS export to specific hosts
swamp model method run nas nfs_share_set_access \
  --input id=6 --input networks='["192.0.2.161/32","192.0.2.162/32"]'

# Revert (re-run with the previous values captured on the result resource)
```

## Selecting a port

`app_set_port_bind` takes either `portKey` (the config key, e.g. `ldap_port`,
`admin_port` — preferred, from `app_list`) or `portNumber` (the current number). Only
**catalog apps** expose individually-bindable ports; host-network apps and custom
(compose) apps don't, and `app_list` reports `hostNetwork`/`portBindings` so you can
tell.

## Breaking changes

- **`insecureSkipTlsVerify` is removed.** It never had any effect: Deno cannot
  skip certificate validation for a single connection, so the model always
  validated. A definition that still sets it fails validation with "Unknown
  global argument(s)". Delete the line; nothing else changes. If your NAS still
  uses its self-signed certificate, see the TLS note above.
- **`endpoint` is required.** It used to default to the placeholder
  `wss://nas.example.com/api/current`. Set it to your NAS.

## Known limitations

- **No tailnet bind.** `interface.ip_in_use` only offers real host-interface aliases
  (the LAN IP). The tailscale IP belongs to the tailscale *app*, so it isn't selectable
  as a port `host_ip`, so app port binding cannot create a tailnet-only bind.
- **No service start/stop, no pool/dataset/user/snapshot management.** These are out of
  scope by design, to limit the damage a mistake can cause.
- `app.update` is asynchronous (a job); the method polls `core.get_jobs` until terminal
  within `timeoutMs`.
