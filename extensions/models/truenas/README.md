# `@thomas/truenas`

Administration of a [TrueNAS SCALE](https://www.truenas.com/) host (25.04 or
25.10) through its **JSON-RPC 2.0 API over a WebSocket**
(`wss://<host>/api/current`, API-key auth). Audit what each app/share/service
exposes, then restrict it.

These are the only changes it makes:

- **App port binding:** switch an app's port between `published` (bound on the
  host) and `exposed` (container-internal only). This closes a service's ports
  (e.g. lldap's plaintext LDAP `389` / LDAPS `636`) without uninstalling it.
- **NFS share access:** set the per-share authorized `networks`/`hosts`
  allowlist (the only supported per-client access control on TrueNAS).
- **SMB share access:** set per-share `hostsallow`/`hostsdeny`.
- **App networks:** set the docker networks a custom app joins, for example to
  let a reverse proxy reach other apps' bridges.
- **Share delete:** remove an NFS or SMB share definition. The dataset and its
  data are left alone, and the removed configuration is recorded so the share
  can be re-created.

It does **not** touch pools, datasets, users, snapshots, replication, or service
start/stop. Service start/stop is left as an explicit gap because a stopped
`ssh`/`nfs` service risks a lockout or outage. Every mutating verb verifies its
target by id/name first. The access changes are reversible by re-running with
the prior values, with one exception: when `smb_share_set_access` applies host
rules to a share on a preset that holds none, it moves the share to `NO_PRESET`
(25.04) or `LEGACY_SHARE` (25.10), and re-running with the prior values does not
move it back. See [SMB presets](#smb-presets). The result records
`previousPurpose`; restore it in the TrueNAS UI if you need to.

## Transport safety: never send the key over cleartext

TrueNAS SCALE **permanently revokes an API key as soon as it receives that key
over a non-TLS transport** (plain `ws://`/`http://`). A single cleartext request
revokes the key; it is not rate-limited.

This model rejects any non-`wss` endpoint: `websocketUrl` throws before opening
a socket and never downgrades `https→ws`. Always use `wss://` (or a bare host /
`https://`, both of which resolve to `wss://<host>/api/current`).

## Configuration

```yaml
type: "@thomas/truenas"
globalArguments:
  endpoint: wss://nas.example.com/api/current # bare host or https:// also accepted
  apiKey: ${{ vault.get(<vault>, truenas/credential) }}
  timeoutMs: 30000
```

### API version

A bare host or `https://` endpoint resolves to `/api/current`, the NAS's own
newest API version. The model supports every 25.04 and 25.10 release. Of the
calls it makes, only the SMB share schema differs between them, and the model
reads which one it has from the share itself. Do not point `endpoint` at an
older versioned path such as `/api/v25.04.2` on a 25.10 NAS: 25.10 refuses many
of this model's calls there, the login included.

### SMB presets

An SMB share's purpose preset decides whether it can hold host rules:

- **25.04:** `DEFAULT_SHARE` and `VEEAM_REPOSITORY_SHARE` discard host rules.
  `smb_share_set_access` moves a `DEFAULT_SHARE` to `NO_PRESET` in the same
  update, which renders the same share. A `VEEAM_REPOSITORY_SHARE` is refused:
  `NO_PRESET` would drop the `block size` setting that Veeam Fast Clone needs.
- **25.10:** host rules sit under the share's `options`. On 25.10.0 only
  `LEGACY_SHARE` has them; from 25.10.1 most presets do. `smb_share_set_access`
  moves a `DEFAULT_SHARE` to `LEGACY_SHARE` (the replacement for `NO_PRESET`)
  and keeps its one setting. Any other preset without host rules is refused,
  because moving it would drop what the preset is for (Time Machine, WORM,
  per-user datasets); change it in the TrueNAS UI first if you mean to.
- Upgrading 25.04 to 25.10 turns `NO_PRESET` shares into `LEGACY_SHARE` with
  their host rules kept.

Create an API key under **Credentials → Users → API keys**, bound to a user with
the roles you need (read-only roles suffice for the audit methods; the mutating
methods need `APPS_WRITE` / `SHARING_NFS_WRITE` / `SHARING_SMB_WRITE`).

### TLS note

TrueNAS ships a **self-signed certificate** (`CN=localhost`), which fails both
chain _and_ hostname validation for `nas.example.com`. This model always
validates the certificate: Deno's `WebSocket` skips validation only when the
whole **process** runs with `--unsafely-ignore-certificate-errors`, with no
per-connection switch, so there is nothing for the model to turn off. The fix is
to **install a certificate valid for the host's name** on the TrueNAS UI (the
WebSocket API uses the same `:443` listener):

1. Issue/obtain a cert for the host name (e.g. the existing `*.example.com`
   wildcard).
2. **System Settings → Certificates** → import the cert+key.
3. **System Settings → GUI → GUI SSL Certificate** → select it; the UI reloads.

After that the `wss://` handshake validates normally. Replacing the self-signed
cert also improves the host's security.

## Methods

### Read / audit (safe)

| Method             | Purpose                                                                                                                                                                                                                                                                                                                                         |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `system_info`      | Host hostname, version, uptime, memory (`system.info`).                                                                                                                                                                                                                                                                                         |
| `app_list`         | Every installed app + its port bindings (key, number, `published`/`exposed`, host IPs). Factory: one `app` per app.                                                                                                                                                                                                                             |
| `nfs_share_list`   | NFS exports with their `networks`/`hosts` allowlist; flags `unrestricted` shares.                                                                                                                                                                                                                                                               |
| `smb_share_list`   | SMB shares with `hostsallow`/`hostsdeny`; flags `unrestricted`.                                                                                                                                                                                                                                                                                 |
| `service_list`     | System services (state + boot-enable).                                                                                                                                                                                                                                                                                                          |
| `network_info`     | Bindable host IPs (the app port-bind selector contents), interfaces, GUI bind addresses.                                                                                                                                                                                                                                                        |
| `filesystem_list`  | Directory entries (`filesystem.listdir`) with type/size and a mountpoint flag (= a child dataset). Takes one path or a JSON list (fan-out: one session per run). An absent path records `exists=false` rather than failing, so it can check whether a backup or app source path has gone missing.                                               |
| `app_storage`      | An app's host-path binds — container mount path ← NAS path, and where each sits in the app config. Shows whether an app mounts one parent directory or each source individually.                                                                                                                                                                |
| `replication_list` | Replication tasks: source/target datasets, `recursive`, schedule, destination readonly policy, whether dataset **properties** are sent, and last-run state. Read-only; never runs or edits a task. Shows what writes into a destination dataset and when. A receive remounts the destination, which invalidates any container bind-mount of it. |
| `exposure_audit`   | A single summary of published ports across all apps, host-network apps, ports on every interface, unrestricted NFS/SMB shares, a plaintext-LDAP flag, and the non-wildcard bindable IPs. System services (SSH, SMB, NFS, the web UI) are not included; use `service_list`.                                                                      |

### Mutate (verify-first)

| Method                 | Purpose                                                                                                                                                                                                                 |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app_set_port_bind`    | Set one app port's `bindMode` (`published`/`exposed`) and/or `hostIps`. Sends the whole `network` map, or the whole `ports` list for a list-form app (other ports preserved), waits for the `app.update` job, re-reads. |
| `nfs_share_set_access` | Set a share's `networks`/`hosts` (empty array clears the restriction).                                                                                                                                                  |
| `smb_share_set_access` | Set a share's `hostsallow`/`hostsdeny` (empty `hostsallow` clears the allowlist). May move the share's preset to `NO_PRESET` or `LEGACY_SHARE`, one way; see [SMB presets](#smb-presets).                               |
| `app_set_networks`     | Set the docker networks a custom app joins (existing entries keep their config). Custom apps only: a catalog app is refused and nothing is written.                                                                     |
| `nfs_share_delete`     | Delete an NFS export rule (the dataset is untouched); records the removed config. A share already gone records `absent`.                                                                                                |
| `smb_share_delete`     | Delete an SMB share definition (the dataset is untouched); records the removed config. A share already gone records `absent`.                                                                                           |

## Examples

```bash
# Audit exposure (read-only)
swamp model method run nas exposure_audit
swamp data query 'modelName == "nas" && name == "exposure-audit"' --single --json --select attributes.flags

# Does a backup source path still exist? (read-only; one path or a JSON list)
swamp model method run nas filesystem_list --input path=/mnt/Backup
swamp model method run nas filesystem_list --input path='["/mnt/Backup","/mnt/Backup/apps"]'
# The path is percent-escaped in the data name: /mnt/Backup -> dir-listing:%2Fmnt%2FBackup
swamp data query 'modelName == "nas" && name == "dir-listing:%2Fmnt%2FBackup"' --single --json \
  --select '{"exists": attributes.exists, "entries": attributes.entries.map(e, e.name)}'

# What replicates into a destination dataset, and how? (read-only)
swamp model method run nas replication_list
swamp data query 'modelName == "nas" && attributes.targetDataset.startsWith("Backup/")'

# Close lldap's plaintext LDAP + LDAPS — container-internal only
swamp model method run nas app_set_port_bind --input app=lldap --input portKey=ldap_port  --input bindMode=exposed
swamp model method run nas app_set_port_bind --input app=lldap --input portKey=ldaps_port --input bindMode=exposed

# Restrict an NFS export to specific hosts
swamp model method run nas nfs_share_set_access \
  --input id=6 --input networks='["192.0.2.161/32","192.0.2.162/32"]'

# Revert: read the previous values off the result record, then re-run with them
swamp data query 'modelName == "nas" && name == "nfs-share-result:6"' --single --json \
  --select '{"networks": attributes.previousNetworks, "hosts": attributes.previousHosts}'
swamp model method run nas nfs_share_set_access \
  --input id=6 --input networks='["192.0.2.0/24"]' --input hosts='[]'
```

## Selecting a port

`app_set_port_bind` takes either `portKey` (the config key, e.g. `ldap_port`,
`admin_port` — preferred, from `app_list`) or `portNumber` (the current number).
Catalog apps key each port in `config.network`. Custom apps keep an unkeyed
`config.ports` list; `app_list` shows those entries as `ports[<i>]`, and
`app_set_port_bind` selects them by `portNumber` alone, and refuses a `portKey`
for such an app. A `portNumber` that more than one port uses (say the same
number over tcp and udp) is refused; pick a keyed port by `portKey` instead.
`app_set_port_bind` and `app_set_networks` refuse apps installed from compose
YAML (`customApp: true` in `app_list`): those take a whole compose file on
update. Host-network apps bind no individual ports; `app_list` reports
`hostNetwork`, and `exposure_audit` lists them under `hostNetworkApps`.

A published port counts as reachable on every interface (`exposedToAll`, and
`exposure_audit`'s `portsOnAllInterfaces`) when its host IPs are empty, or
include `0.0.0.0` or `::`. TrueNAS binds an empty list to both `0.0.0.0` and
`::`.

## Breaking changes

- **`insecureSkipTlsVerify` is removed.** It never had any effect: Deno cannot
  skip certificate validation for a single connection, so the model always
  validated. The upgrade to this version removes it from existing definitions. A
  definition without a `typeVersion` is not upgraded and fails validation with
  "Unknown global argument(s)"; delete the line by hand. If your NAS still uses
  its self-signed certificate, see the TLS note above.
- **`endpoint` is required.** It used to default to the placeholder
  `wss://nas.example.com/api/current`. Set it to your NAS.
- **Every data name now starts with its spec.** swamp keys data by model and
  name, not by spec, so `system_info`, `network_info` and `exposure_audit` (all
  written as `main`) overwrote each other, as did other specs sharing a name. A
  keyed record is now `<spec>:<key>` and a one-per-model record is `<spec>`:
  - `system-info`, `network-info`, `exposure-audit`
  - `app:<name>`, `service:<name>`, `app-storage:<app>`,
    `app-networks-result:<app>`, `app-port-result:<app>:<portKey>` (for a
    list-form app, `<portKey>` is the port number, not `ports[<i>]`)
  - `nfs-share:<id>`, `smb-share:<id>`, `replication-task:<id>`,
    `nfs-share-result:<id>`, `smb-share-result:<id>`
  - `dir-listing:<path>`, with the path percent-escaped (`/` → `%2F`, `\` →
    `%5C`, `..` → `.%2E`, `%` → `%25`), so `/mnt/Backup` is
    `dir-listing:%2Fmnt%2FBackup`.
  - A delete of a share that is already gone is `nfs-share-result:absent:<id>` /
    `smb-share-result:absent:<id>`, or `nfs-share-result:absent:path:<path>` /
    `smb-share-result:absent:name:<name>` (escaped the same way). It never takes
    a real delete's `<id>` name, so re-running a delete leaves the removed
    configuration as the latest record.

  Records written by earlier versions keep their old names and are not migrated.
  A CEL expression that reads one by its old name needs the new one.
- **`exposure_audit` lists only enabled NFS shares** as unrestricted, as it
  already did for SMB.
- **Custom apps' ports now appear.** `app_list` and `exposure_audit` used to
  read only the catalog form (`config.network.<key>`), so a custom app's
  `config.ports` list and its top-level `host_network` were missed. They now
  appear as `portBindings` with `portKey` `ports[<i>]`, and in `publishedPorts`.
- **More ports count as reachable on every interface.** `exposedToAll` and
  `portsOnAllInterfaces` used to require `0.0.0.0` in the host IPs. They now
  also count an empty list (the TrueNAS default, which binds `0.0.0.0` and `::`)
  and `::`.

- **`app_set_networks` refuses catalog apps.** It writes the custom-app
  `networks` list. A catalog app keeps its networks under `network.networks`, so
  on one the method used to report success and change nothing. It now throws for
  any app without a top-level `networks` list, before sending an update.
- **`app_set_port_bind` and `app_set_networks` refuse compose apps.** An app
  installed from compose YAML (`custom_app`) used to fail inside the
  `app.update` job with a validation error; it is now refused before any update.
- **`app_set_port_bind` refuses an ambiguous selection.** A `portNumber` that
  matches more than one port used to change the first match; a `portKey` that
  matched no key on an app with a `config.ports` list used to be ignored in
  favour of `portNumber`. Both now throw before any update.
- **Argument bounds.** `apiKey` must not be empty, `timeoutMs` must be above 0
  (0 used to mean 30000 silently), and `filesystem_list`'s `maxEntries` must not
  be negative (0 records only whether the path exists).
- **NFS shares open to everyone count as unrestricted.** `unrestricted` and
  `exposure_audit`'s `unrestrictedNfsShares` used to require empty `networks`
  and `hosts`. A share listing `0.0.0.0/0`, `::/0` or the host `*` now counts
  too.
- **`exposure_audit` has a `hostNetworkApps` list**, and no longer claims to
  cover system services; it never queried them.
- **An absent-share delete result has `id: null`.** When `nfs_share_delete` or
  `smb_share_delete` finds no share, selected by path or name, the result used
  to record `id: 0`, which reads like a real share id. It now records `null`. A
  share selected by id keeps that id.
- **App and share observations expire after an hour.** `app`, `nfs-share` and
  `smb-share` records used to live for ever, so an app or share removed since
  the last list (including by `nfs_share_delete` or `smb_share_delete`) went on
  reading as live. They now have the same 1-hour lifetime as `service`; re-run
  the list method for current data.
- **Failed-job errors carry the reason.** They used to end in the exception type
  alone (`FAILED: VALIDATION`); they now include TrueNAS's message.
- **`smb_share_set_access` refuses a 25.04 `VEEAM_REPOSITORY_SHARE`.** It used
  to move the share to `NO_PRESET`, which silently dropped Veeam's `block size`
  setting. See [SMB presets](#smb-presets).
- **`smb-share-result` records the share's `path`**, so a deleted share's record
  says where it pointed after the share list has expired.

## Known limitations

- **No tailnet bind.** `interface.ip_in_use` only offers real host-interface
  aliases (the LAN IP). The tailscale IP belongs to the tailscale _app_, so it
  isn't selectable as a port `host_ip`, so app port binding cannot create a
  tailnet-only bind.
- **No service start/stop, no pool/dataset/user/snapshot management.** These are
  out of scope by design, to limit the damage a mistake can cause.
- **A change that times out may still apply.** `app.update` is asynchronous (a
  job); the method polls `core.get_jobs` until terminal within `timeoutMs`.
  Giving up does not cancel the job. The same holds when any change call (an app
  update, a share update or delete) times out or loses its connection. In each
  case the error says so and no result is recorded: re-read the target before
  retrying or reverting.
- **25.10.1+ Veeam shares may not apply host rules.** Read from the TrueNAS
  source, not tested: it accepts `hostsallow`/`hostsdeny` for a
  `VEEAM_REPOSITORY_SHARE` but does not read them back or apply them. If so,
  `smb_share_set_access` reports `updated` with empty lists, and every re-run
  updates again.
- **No "none" bind mode.** Catalog apps also offer a third mode that neither
  publishes nor exposes a port; `bindMode` accepts only `published` and
  `exposed`.
- **`dir-listing` names follow the path.** swamp stores each data name as a
  directory. On a case-insensitive disk (the macOS default), `/mnt/Backup` and
  `/mnt/backup` share one record. A very long path, once escaped, can exceed the
  255-byte file-name limit.
