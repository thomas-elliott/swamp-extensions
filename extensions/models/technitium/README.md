# @thomas/technitium

Manages a [Technitium DNS Server](https://technitium.com/dns/) through its HTTP
API. Every operation goes through the API; the extension never touches the
server host.

Covers built-in ad-blocking control, authoritative zone + record lifecycle, the
built-in Allowed/Blocked custom-domain zones, dashboard statistics, DNS-client
and query-log debugging, cache flush, settings backup/restore, and the admin web
service's TLS and DNSSEC validation settings.

> Blocking methods target Technitium's **built-in** blocking (the server
> settings), not the separate Advanced Blocking app.

## Installation

```sh
swamp extension pull @thomas/technitium
```

## Authentication

Create a **permanent API token** in Technitium (Administration → Sessions →
_Create Token_, or via `/api/user/createToken`) and store it in a vault. Never
inline it. The token is sent only as an `Authorization: Bearer` header, never in
the URL, so it stays out of proxy and access logs. This needs Technitium 15 or
later; earlier versions are not supported.

```sh
swamp vault put technitium api_token '<your-permanent-token>'
```

## Configuration

| Global arg      | Notes                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------ |
| `baseUrl`       | Base URL incl. port, e.g. `https://dns.example:5380`                                             |
| `apiToken`      | Permanent API token. **Supply via vault:** `${{ vault.get(technitium, api_token) }}` (sensitive) |
| `skipTlsVerify` | Turn off TLS certificate verification (default `false`); accepts any cert, for any hostname      |

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
  `blocking_set_lists` rejects a URL containing a comma and any URL starting
  with `!`: Technitium keeps both lists in one comma-separated setting and marks
  allow lists with a leading `!`, so such a URL would be stored as something
  else.
- **Security settings** — `web_service_set_tls` installs a PKCS#12 certificate
  for the admin web service and sets its HTTPS listener, port, self-signed
  fallback and HTTP→HTTPS redirect; only the fields you pass change. A
  `certificatePassword` without `certificatePath` applies to the certificate
  already configured (the method sends the current path with it, because
  Technitium ignores a password on its own); with no certificate configured it
  is an error. `dnssec_validation_set` turns DNSSEC validation of upstream
  answers on or off.
- **`zone_*`** — `zone_list`, `zone_create`, `zone_delete`, `zone_enable`,
  `zone_disable`. `zone_create` takes an optional `catalog`: the name of an
  existing catalog zone to join, so secondaries provision the new zone
  automatically instead of it existing only on the primary. It creates Primary
  and Catalog zones; `zone_list` reports membership. `zone_create` stores the
  zone under the name Technitium gives it, so `192.0.2.0/24` is stored as
  `2.0.192.in-addr.arpa`. `zone_enable`, `zone_disable` and `zone_delete` store
  the whole zone (type, catalog, DNSSEC status), read from the server. Both are
  safe to rerun: `zone_create` on an existing zone of the same type reports it
  `unchanged` (another type, or a `catalog` it is not in, is still an error),
  and `zone_delete` on a zone that does not exist reports it `deleted`.
- **`record_*`** — `record_list`, `record_get`, `record_add`, `record_update`,
  `record_delete`. Type-specific fields go in `rData` (e.g. `{ipAddress}` for A,
  `{cname}` for CNAME, `{exchange, preference}` for MX), under the parameter
  names Technitium's add endpoint takes (`uriPriority` for URI, `naptrOrder` for
  NAPTR). Updates carry the new values in `newRData`. For **CNAME** and
  **DNAME**, `newRData.cname`/`newRData.dname` is the new target. For **APP**
  records, put the application payload in `rData.data` (the same key
  `record_list`/`record_get` read it back under). It is written via Technitium's
  `recordData` param, and updates set the new payload directly (APP records have
  no `new*` scheme and only one exists per name). `record_update` reads the
  record first and sends its current `ttl`, `disable`, `comments` and
  `expiryTtl` back unless you pass new ones, because Technitium resets any of
  those it is not sent (TTL to the server default, a disabled record back to
  enabled). `record_get` reads a **single** domain's records live from the
  server (use it for the current server state; `record_list` reads the whole
  zone). Every `record_add` / `record_update` / `record_delete` **reads the
  record back and checks the live state** afterwards, and fails with an error if
  Technitium reported success but the change was not applied (e.g. an APP record
  left with empty data). The check compares the record the server says it wrote
  with the live one, so values Technitium normalises (a trailing dot, IPv6
  written in full, hex case) do not fail it. `record_update` and `record_delete`
  find the existing record from your `rData` after the same normalising. DS,
  SSHFP and TLSA enum fields (e.g. DS `algorithm`, TLSA `tlsaSelector`) can be
  given as a number or a name; Technitium reads them back as names, and a number
  is matched to its name. A FWD record's `proxyPassword` is never stored.
- **`allowed_*` / `blocked_*`** — manage the built-in Allowed/Blocked zones:
  `_add`, `_delete`, `_list`, `_flush`. `_list` returns every domain in the
  zone, or under `domain` if you pass one. Technitium's list endpoint shows one
  level of the zone's label tree at a time, so `_list` makes one call per
  branching node.
- **`client_resolve`** — resolve a name through the server's DNS client for
  debugging. Output is **ephemeral**.
- **`logs_query`** — structured recent query logs. **Requires the _Query Logs
  (Sqlite)_ DNS app** installed on the server (override `appName`/`classPath` if
  yours differs). It reads one page per call (`pageNumber`, `entriesPerPage`)
  and writes a `queryLogPage` record with the page number and how many entries
  and pages the query matched in all. Entries are named from their content, so
  the same entry keeps its name whichever query returns it. Raw server log files
  (`/api/logs/list` + `/download`) are not wrapped in this version.
- **`cache_*`** — `cache_flush`, `cache_list`, `cache_delete`.
- **`dashboard_stats`** — query statistics for `LastHour`…`LastYear`/`Custom`.
- **`settings_*`** — `settings_backup` (downloads a zip into a `backup` file;
  **may contain secrets** — short-lived) and `settings_restore` (multipart
  upload of a local zip; verify the file first; a file that is not a zip is
  refused before upload). Both send every section flag the API knows explicitly
  (`authConfig`, `clusterConfig`, `webServiceSettings`, `dnsSettings`,
  `logSettings`, `zones`, `allowedZones`, `blockedZones`, `blockLists`, `apps`,
  `scopes`, `stats`, `logs`); an unknown name in `options` is rejected with an
  error rather than ignored. Backup defaults to every configuration section
  (logs and stats off). Restore defaults leave `authConfig`, `clusterConfig` and
  `webServiceSettings` off, because those replace the users and tokens
  (including the one making the call), the web service port/TLS, and cluster
  membership; pass them in `options` to restore them.

## Data model

Read methods are factories that persist one resource per item (`zone`,
`zoneRecord`, `listEntry`, `cacheEntry`, `queryLog`), so you can reference them
from CEL expressions in workflows. Only a named subset of the server settings is
stored: blocking, web-service TLS, DNSSEC validation and DNS-over-TLS. The full
settings object is not stored, so secrets such as TLS certificate passwords are
not persisted.

### Data names

swamp keys stored data by model and name, not by spec, so every name starts with
its spec. A keyed record is `<spec>:<key>`; a record kept once per model is
`<spec>` alone. DNS names in a key are lowercased, lose a trailing dot, and keep
their dots; `%`, `:`, `/` and `\` are percent-escaped (`%25`, `%3A`, `%2F`,
`%5C`).

| Spec              | Name                                                                |
| ----------------- | ------------------------------------------------------------------- |
| `settings`        | `settings`                                                          |
| `zone`            | `zone:<zone>`, e.g. `zone:lab.example.com`                          |
| `zoneRecord`      | `zoneRecord:<zone>:<name>:<TYPE>:<rData hash>`                      |
| `listEntry`       | `listEntry:allowed:<domain>`, `listEntry:blocked:<domain>`          |
| `cacheEntry`      | `cacheEntry:zone:<name>`, `cacheEntry:record:<name>`                |
| `dnsResponse`     | `dnsResponse:<domain>:<type>`                                       |
| `queryLog`        | `queryLog:<hash of the entry>`                                      |
| `queryLogPage`    | `queryLogPage`                                                      |
| `stats`           | `stats:<range>`, e.g. `stats:LastHour`                              |
| `operationResult` | `operationResult:<method>`, `operationResult:cache_delete:<domain>` |
| `backup` (file)   | `backup:<ISO timestamp>`                                            |

```sh
# Every record a model holds for one zone
swamp data query 'modelName == "dns-home" && name.startsWith("zoneRecord:lab.example.com:")' --json
```

`zoneRecord` instances are a **copy of live server state, refreshed on each
read**. The Technitium server holds the authoritative state. A DNS record has no
id, so its name is built from the record itself: zone, name, type and a hash of
its rData. Every record method names it from the record **as Technitium returns
it**, not from the `rData` you passed. `record_add` and `record_update` use the
record they read back; `record_delete` reads the record before deleting it. So
the same record is one instance whichever method wrote it (without a `zone`
argument, the zone is the one Technitium reports as holding the record), and two
records at one name (e.g. two A records) stay distinct. If `record_delete` finds
no live record matching your `rData`, it names the data from your `rData`. A
re-`record_list` writes a **new version** of an unchanged record rather than a
duplicate. Because swamp does not auto-prune instances, `zoneRecord` carries a
finite **30-day lifetime**: records that still exist refresh their timer on each
list/get, while records that were deleted or had their value changed stop being
refreshed and expire. `zone` and `listEntry` have the same 30-day lifetime,
refreshed by `zone_list` and `allowed_list`/`blocked_list`. For the current
state of a single name, use `record_get` (a live read); `swamp data gc` /
`swamp data delete` clean up persisted entries on demand.

## Breaking changes

- **The API token is sent only in the `Authorization` header.** Earlier versions
  also put it in the URL as `?token=`. Technitium before 15 needs the URL form
  and is no longer supported.
- **`logs_query` names entries from their content** (`queryLog:<hash>`), not by
  their position in the result (`queryLog:0`, `queryLog:1`, …), and also writes
  a `queryLogPage` record with the page and the totals. Old position-named
  entries expire within 7 days.
- **`zone` and `listEntry` data now expire after 30 days** unless
  `zone_list`/`_list` refreshes them. They used to be kept forever, so a zone or
  entry removed outside swamp read as current.
- **`zone_create` on an existing zone of the same type succeeds** with action
  `unchanged`, unless `catalog` names a catalog the zone is not in, and
  **`zone_delete` on a missing zone succeeds** with action `deleted`. Both used
  to fail.
- **`web_service_set_tls` with only `certificatePassword` now changes the
  password** of the configured certificate. Earlier versions reported success
  and changed nothing; with no certificate configured it is now an error.
- **Data names are now `<spec>:<key>`, or `<spec>` for a once-per-model record**
  (see [Data names](#data-names)), for example `settings`,
  `zone:lab.example.com` and `listEntry:allowed:ads.example.com`. Names no
  longer flatten dots to `-`, so `a-b.example.com` and `a.b.example.com` are
  separate records, and `record_add` / `record_update` / `record_delete` now
  name a record the way `record_list` does. Records written by earlier versions
  keep their old names (`current`, `zone-…`, `rec-…`, `allowed-…`) and are not
  migrated. Old `zoneRecord`, `stats` and other finite-lifetime records expire;
  remove the rest (`settings`, `zone`, `listEntry`, `operationResult`) with
  `swamp data delete`.
- **`allowed_list` and `blocked_list` return every listed domain.** They used to
  return one level of the zone's label tree (`com`, `net` at the root), so they
  wrote `listEntry:allowed:com` and missed the real entries. `domain` now limits
  the list to that domain and the domains under it.
- **`record_update` on a CNAME or DNAME now changes the target.** Pass the new
  target in `newRData.cname`/`newRData.dname`. Earlier versions sent it as
  `newCname`, which Technitium ignores, and then failed the read-back.
- **`settings_restore` no longer restores users and tokens, web service settings
  or cluster settings by default.** Set `authConfig`, `webServiceSettings` or
  `clusterConfig` to true in `options` to include them. `settings_backup` now
  includes every section.
- **`zone_create` creates Primary and Catalog zones only.** The other types need
  arguments it does not take.
- **`blocking_set_lists` now changes allow lists.** Technitium keeps allow lists
  in `blockListUrls` with a `!` prefix; earlier versions sent a parameter it
  ignores. An empty list clears that side.
- **A record written without `zone` is filed under the zone Technitium reports**
  (`example.com`), not under the record's own name, so it matches what
  `record_list` writes.
- **A reply without a Technitium `status`, such as a proxy's login page, is an
  error**, and so is a backup download that is not a zip file.
  `settings_restore` refuses a file that is not a zip before uploading it.
- **`blocking_set_lists` rejects a URL with a comma, and any URL starting with
  `!`.** Earlier versions stored a comma URL as two entries, a `!` block URL as
  an allow list, and a `!` allow URL as `!!…`. Pass allow-list URLs without the
  `!`.
- **`zone_create` stores the zone under the name Technitium gives it.** For an
  IP address or CIDR range that is the reverse zone (`2.0.192.in-addr.arpa`),
  not `192.0.2.0/24`.
- **`record_list` stores `zone` as Technitium names the zone** (lower case, no
  trailing dot), as the other record methods do, not as you typed it.
- **FWD records are stored without `proxyPassword`.** A FWD record with proxy
  credentials gets a new data name, since the name hashes the stored rData.

## License

MIT — see [LICENSE.txt](./LICENSE.txt).
