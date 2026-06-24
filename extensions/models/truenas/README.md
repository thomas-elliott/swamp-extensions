# `@thomas/truenas`

Administration of a [TrueNAS SCALE](https://www.truenas.com/) host (25.04+) through
its **JSON-RPC 2.0 API over a WebSocket** (`wss://<host>/api/current`, API-key auth).
Audit what each app/share/service exposes, then tighten it — built for the homelab
**service-exposure** hardening (R28).

The mutating surface is deliberately narrow and reversible:

- **App port binding** — flip a catalog app's port between `published` (bound on the
  host) and `exposed` (container-internal only). The lever that closes a service's
  ports (e.g. lldap's plaintext LDAP `389` / LDAPS `636`) without uninstalling it.
- **NFS share access** — set the per-share authorized `networks`/`hosts` allowlist
  (the one supported per-client gate on TrueNAS).
- **SMB share access** — set per-share `hostsallow`/`hostsdeny`.

It does **not** touch pools, datasets, users, snapshots, replication, or service
start/stop — a stopped `ssh`/`nfs` service is a lockout/outage risk, left an explicit
gap. Every mutating verb verifies its target by id/name first and is reversible by
re-running with the prior values.

## ⚠️ Transport safety — never send the key over cleartext

TrueNAS SCALE **permanently revokes an API key the instant it sees that key
transmitted over a non-TLS transport** (plain `ws://`/`http://`). One cleartext send
and the key is dead — not rate-limited, *revoked*.

This model refuses any non-`wss` endpoint **by construction**: `websocketUrl` throws
before opening a socket and never downgrades `https→ws`. Always use `wss://` (or a
bare host / `https://`, both of which resolve to `wss://<host>/api/current`).

## Configuration

```yaml
type: "@thomas/truenas"
globalArguments:
  endpoint: wss://nas.example.com/api/current   # bare host or https:// also accepted
  apiKey: ${{ vault.get(<vault>, truenas/credential) }}
  insecureSkipTlsVerify: false                  # see TLS note
  timeoutMs: 30000
```

Create an API key under **Credentials → Users → API keys**, bound to a user with the
roles you need (read-only roles suffice for the audit methods; the mutating methods
need `APP_WRITE` / `SHARING_NFS_WRITE` / `SHARING_SMB_WRITE`).

### TLS note (important)

TrueNAS ships a **self-signed certificate** (`CN=localhost`), which fails both chain
*and* hostname validation for `nas.example.com`. Deno's `WebSocket` honours a
skip-verify only when the **process** runs with `--unsafely-ignore-certificate-errors`
— there is no per-connection switch — so `insecureSkipTlsVerify` cannot take effect
inside swamp's managed runtime. The supported fix is to **install a certificate valid
for the host's name** on the TrueNAS UI (the WebSocket API rides the same `:443`
listener):

1. Issue/obtain a cert for the host name (e.g. the existing `*.example.com` wildcard).
2. **System Settings → Certificates** → import the cert+key.
3. **System Settings → GUI → GUI SSL Certificate** → select it; the UI reloads.

After that the `wss://` handshake validates normally and `insecureSkipTlsVerify` stays
`false`. (Replacing the self-signed cert is itself a hardening win.)

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
| `exposure_audit` | One roll-up: published ports across all apps, ports on `0.0.0.0`, unrestricted NFS/SMB shares, a plaintext-LDAP flag, and the non-wildcard bindable IPs. The R28 data source. |

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

## Known limitations

- **No tailnet bind.** `interface.ip_in_use` only offers real host-interface aliases
  (the LAN IP). The tailscale IP belongs to the tailscale *app*, so it isn't selectable
  as a port `host_ip` — a tailnet-only bind is not achievable through app port binding.
- **No service start/stop, no pool/dataset/user/snapshot management** — out of scope by
  design (blast-radius containment).
- `app.update` is asynchronous (a job); the method polls `core.get_jobs` until terminal
  within `timeoutMs`.
