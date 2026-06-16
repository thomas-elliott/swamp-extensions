# @thomas/technitium

Management of a [Technitium DNS Server](https://technitium.com/dns/) via its
HTTP API. Every operation goes through the API; the extension never touches the
server host.

Covers built-in ad-blocking control, authoritative zone + record lifecycle, the
built-in Allowed/Blocked custom-domain zones, dashboard statistics, DNS-client
and query-log debugging, cache flush, and settings backup/restore.

> Blocking methods target Technitium's **built-in** blocking (the server
> settings), not the separate Advanced Blocking app.

## Installation

```sh
swamp extension pull @thomas/technitium
```

## Authentication

Create a **permanent API token** in Technitium (Administration → Sessions →
_Create Token_, or via `/api/user/createToken`) and store it in a vault — never
inline it. The token is sent both as an `Authorization: Bearer` header
(Technitium ≥ 15) and as the legacy `?token=` query parameter, so it works
across versions and reverse proxies.

```sh
swamp vault put technitium api_token '<your-permanent-token>'
```

## Configuration

| Global arg      | Notes                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------ |
| `baseUrl`       | Base URL incl. port, e.g. `https://dns.example:5380`                                             |
| `apiToken`      | Permanent API token. **Supply via vault:** `${{ vault.get(technitium, api_token) }}` (sensitive) |
| `skipTlsVerify` | Accept self-signed certs (default `false`)                                                       |

```yaml
type: "@thomas/technitium"
name: dns-home
globalArguments:
  baseUrl: "https://dns.example:5380"
  apiToken: "${{ vault.get(technitium, api_token) }}"
  skipTlsVerify: false
```

## Usage

```sh
# Temporarily turn off blocking for 30 minutes
swamp model method run dns-home blocking_temporary_disable --input '{"minutes":30}'

# Point blocking at a new set of block lists (comma-joined internally)
swamp model method run dns-home blocking_set_lists \
  --input '{"blockListUrls":["https://big.oisd.nl"]}'

# Create a zone and add an A record
swamp model method run dns-home zone_create --input '{"zone":"lab.example.com","type":"Primary"}'
swamp model method run dns-home record_add \
  --input '{"zone":"lab.example.com","domain":"nas.lab.example.com","type":"A","ttl":300,"rData":{"ipAddress":"192.0.2.5"}}'

# Debug a resolution and flush the cache
swamp model method run dns-home client_resolve --input '{"domain":"example.com","type":"A"}'
swamp model method run dns-home cache_flush
```

## Method sections

- **`blocking_*`** — built-in blocking: `blocking_get_settings`,
  `blocking_set_state` (enable/disable), `blocking_temporary_disable`,
  `blocking_set_lists` (block/allow list URLs), `blocking_force_update_lists`.
- **`zone_*`** — `zone_list`, `zone_create`, `zone_delete`, `zone_enable`,
  `zone_disable`.
- **`record_*`** — `record_list`, `record_get`, `record_add`, `record_update`,
  `record_delete`. Type-specific fields go in `rData` (e.g. `{ipAddress}` for A,
  `{cname}` for CNAME, `{exchange, preference}` for MX). Updates carry the new
  values in `newRData`. For **APP** records, put the application payload in
  `rData.data` (the same key `record_list`/`record_get` read it back under) — it
  is written via Technitium's `recordData` param, and updates set the new payload
  directly (APP records have no `new*` scheme and only one exists per name).
  `record_get` reads a **single** domain's records live from the server (use it
  for ground truth — `record_list` walks the whole zone). Every `record_add` /
  `record_update` / `record_delete` **reads the record back and asserts the live
  state** afterwards, failing loudly if Technitium reported success but the change
  did not take (e.g. an APP record left with empty data).
- **`allowed_*` / `blocked_*`** — manage the built-in Allowed/Blocked zones:
  `_add`, `_delete`, `_list`, `_flush`.
- **`client_resolve`** — resolve a name through the server's DNS client for
  debugging. Output is **ephemeral**.
- **`logs_query`** — structured recent query logs. **Requires the _Query Logs
  (Sqlite)_ DNS app** installed on the server (override `appName`/`classPath` if
  yours differs). Raw server log files (`/api/logs/list` + `/download`) are not
  wrapped in this version.
- **`cache_*`** — `cache_flush`, `cache_list`, `cache_delete`.
- **`dashboard_stats`** — query statistics for `LastHour`…`LastYear`/`Custom`.
- **`settings_*`** — `settings_backup` (downloads a zip into a `backup` file;
  **may contain secrets** — short-lived) and `settings_restore` (multipart
  upload of a local zip; verify the file first).

## Data model

Read methods are factories that persist one resource per item (`zone`,
`zoneRecord`, `listEntry`, `cacheEntry`, `queryLog`), so you can reference them
from CEL expressions in workflows. Only **blocking-relevant** settings fields
are surfaced — the full settings blob is intentionally not stored, to avoid
leaking secrets such as TLS certificate passwords.

`zoneRecord` instances are a **refreshable cache of live server state, not the
source of truth** (the Technitium server is). Every record method — `record_add`,
`record_update`, `record_delete`, `record_list`, `record_get` — addresses a
record by a deterministic identity name derived from `(zone, name, type, rData)`,
so the same record is one instance regardless of which method wrote it, and two
records at one name (e.g. two A records) stay distinct. A re-`record_list` writes
a **new version** of an unchanged record rather than a duplicate. Because swamp
does not auto-prune instances, `zoneRecord` carries a finite **30-day lifetime**:
records that still exist refresh their timer on each list/get, while records that
were deleted or had their value changed stop being refreshed and age out. For
point-in-time ground truth on a single name, use `record_get` (a live read);
`swamp data gc` / `swamp data delete` clean up persisted entries on demand.

## License

MIT — see [LICENSE.txt](./LICENSE.txt).
