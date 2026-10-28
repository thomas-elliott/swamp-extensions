# @thomas/stalwart

**Non-destructive** administration of a [Stalwart](https://stalw.art) mail
server (0.16 and v1) for swamp, over its
**JMAP-over-HTTP management API**. Use it to create mailboxes and aliases,
configure groups/lists/roles, check server health and DMARC/TLS reports, change
server settings (including the spam classifier's) and run maintenance actions
(reload settings, install/reload certificates) without using the web UI.

## Scope

This extension holds a mail-admin credential, so what it can do is limited:

- **No deletes.** It never deletes an account, domain, group or list. No method
  sends the JMAP `destroy` verb, and the transport has no way to send one.
  Domains and accounts are disabled and re-enabled with the `*_set_state`
  methods instead.
- **Not every change can be undone from here.** `certificate_install` replaces
  the stored certificate and key without keeping a copy. `settings_set`
  overwrites the values it is given. `role_ensure` removes permissions that are
  not in its list. `role_assign` replaces all of an account's roles with one.
  Re-enabling an account with `account_set_state` drops any permission list of
  its own.
- **Secrets are sent once.** Account passwords and certificate private keys are
  write-only method arguments: sent to Stalwart once, never read back into a
  resource, never logged.
- **Idempotent.** `*_ensure` methods find or create by name and update config in
  place, reporting `action: created | updated | unchanged`.
- **Targets are checked first.** Every method that changes something looks up
  its target before writing.

> **Stalwart 0.16 note.** 0.16 removed the legacy REST `/api/*` management tree;
> all management is now JMAP (`POST /jmap`). A small `/api/*` set remains for
> introspection (`/api/account`, `/api/schema`) and metrics
> (`/metrics/prometheus`), which this extension uses for `health_status`.

## Authentication — scoped API key

Stalwart 0.16 supports API keys scoped to specific management permissions.
Create one with the fallback admin account, store it in a vault, and never
inline it:

```bash
swamp model create @thomas/stalwart stalwart \
  --global-arg apiUrl=https://mail.example.com \
  --global-arg 'apiKey=${{ vault.get(<vault>, stalwart/api_key) }}'
```

| Global arg      | Required | Notes                                                                                                                                   |
| --------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `apiUrl`        | yes      | Base URL, e.g. `https://mail.example.com` (no trailing `/jmap`). Plain `http` works but logs a warning, as the key is sent unencrypted. |
| `apiKey`        | yes      | Scoped admin API key (Bearer). Supply via vault.                                                                                        |
| `accountId`     | no       | JMAP management accountId; omit to use the session's primary.                                                                           |
| `httpTimeoutMs` | no       | Per-request timeout in ms, covering the whole response (default 30000).                                                                 |

## Methods

**Read-only:**

- `domain_list`, `account_list`, `alias_list`, `role_list`, `group_list`,
  `mailing_list_list`: one resource per object. Group membership is stored on
  each member's account, not on the group.
- `queue_list`: queued outbound messages, with sender, recipients, next retry
  and size.
- `report_query`: DMARC/TLS aggregate reports that other servers sent you, with
  the policy domain and reported period. `summary` holds the report as JSON, cut
  to 2000 characters; `summaryTruncated` is true when it was cut, and a cut
  summary does not parse. Reports Stalwart generates and sends are not listed.
- `settings_get`: one server settings singleton (http, system, spam-classifier,
  …). Secret values are recorded as `"<redacted>"`.
- `health_status`: edition and permissions (`/api/account`) plus every metric in
  `/metrics/prometheus`.
- `session_dump` and `jmap_probe`: discovery tools. `session_dump` records the
  JMAP session's capabilities and accounts; `jmap_probe` runs `<type>/query`
  then `<type>/get` for one JMAP object type and records the response shape
  (ids + a sample object). Use them to check the `USING` / `JMAP_TYPES`
  constants against a new Stalwart version.

**Create or update (idempotent, never delete):**

- `account_ensure`: an individual mailbox with its `aliases`, role, group
  membership (`memberOf`) and description. An optional password is set once, on
  create; for an existing account it is ignored and a warning is logged. When
  the alias list is rewritten, an alias the account already has keeps its
  description and its enabled flag; a new alias is enabled.
- `group_ensure`, `mailing_list_ensure`: by address.
- `role_ensure`: by name, from a `preset` (`swamp-admin` | `automated-mailbox`)
  or an explicit permission list. The names `admin` and `user` are refused,
  because `role_assign` and `account_ensure` read them as the built-in roles.
- `role_assign`: give an account one role: `admin`, `user` or a custom role. It
  replaces the roles the account held. Re-run with the previous role to revert;
  an account that held several custom roles cannot be restored this way.
- `settings_set`: set the top-level fields in `patch` on a settings singleton,
  then reload. With `reload` true (the default) it reloads even when nothing
  changed, so re-running it after a failed reload makes the change live. Fields
  not in `patch` are kept; a list or map value is replaced whole. The record
  shows the singleton as the server holds it afterwards, with secret values as
  `"<redacted>"`. A patch holding a secret is refused. Set `jmap`'s Web Push key
  with the sensitive `webPushKey` argument, from a vault reference; it is sent
  on every run. `includeSecrets: true` for `system` is refused.
- `certificate_install`: install a PEM certificate and key, then reload
  certificates. Your ACME tooling issues the certificate; this method only
  installs it. The record holds the certificate's `issuer`, `sans`, `notBefore`
  and `notAfter`.

`role_assign` and `account_set_state` take a full address, or a bare local part
when only one account has it. A local part shared by accounts on different
domains is refused.

**Reversible state changes:** `domain_set_state`, `account_set_state`.

**Maintenance:** `reload`, `reload_certificates`.

```bash
# Check the server is healthy and see what the API key can do.
swamp model method run stalwart health_status

# Record the response shape of the x:Domain type.
swamp model method run stalwart jmap_probe --input type=x:Domain --input limit=5
```

## Data names

Every record is named `<spec>:<key>`, or `<spec>` alone when there is one per
model. Addresses and domains are lowercased, because Stalwart treats them as
case-insensitive.

| Spec           | Name                                                                                                                                                       |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `domain`       | `domain:example.com`                                                                                                                                       |
| `account`      | `account:alice@example.com` (groups too, from `account_list`)                                                                                              |
| `group`        | `group:staff@example.com`                                                                                                                                  |
| `mailing-list` | `mailing-list:team@example.com`                                                                                                                            |
| `alias`        | `alias:ops@example.com`                                                                                                                                    |
| `role`         | `role:<role name>`                                                                                                                                         |
| `queue-item`   | `queue-item:<id>`                                                                                                                                          |
| `report`       | `report:dmarc:<id>`, `report:tls:<id>`                                                                                                                     |
| `settings`     | `settings:<kind>`, e.g. `settings:http`                                                                                                                    |
| `certificate`  | `certificate:<id>`                                                                                                                                         |
| `probe`        | `probe:<type>`, e.g. `probe:x:Domain`                                                                                                                      |
| `state-result` | `state-result:domain:<domain>`, `state-result:account:<address>`, `state-result:role:<address>`, `state-result:reload`, `state-result:reload-certificates` |
| `health`       | `health`                                                                                                                                                   |
| `session`      | `session`                                                                                                                                                  |

A `/`, `\`, `%`, NUL or repeated `.` in a key is percent-encoded (`/` becomes
`%2F`), since swamp does not allow some of them in a name.

```bash
# Read the latest record for one account.
swamp data query 'modelName == "stalwart" && name == "account:alice@example.com"' --json
```

In CEL: `data.latest("stalwart", "account:alice@example.com").attributes.roles`.

> Stalwart does not publish its JMAP management method and type names. They were
> confirmed against live 0.16 and v1 servers and are pinned in the `USING` /
> `JMAP_TYPES` constants in `stalwart.ts`. To check them against another
> version, run `session_dump` and `jmap_probe` there.

## Stalwart v1

Every method has been run against a live v1 server. v1 renamed some fields (see
[`SCHEMA_CHANGES.md`](https://github.com/stalwartlabs/stalwart-migrate/blob/main/SCHEMA_CHANGES.md)
in `stalwart-migrate`), and the extension handles the ones it uses:

- A domain's on/off flag is `isEnabled` in 0.16 and `enable` in v1. The
  `domain_*` methods use whichever name the server returns.
- An alias's on/off flag is `enabled` in 0.16 and `enable` in v1.
  `account_ensure` keeps it under the name the server sent.
- A DMARC report's range start is `dateRangeBegin` in 0.16 and `dateRangeStart`
  in v1. `report_query` reads either. The v1 name is checked against the schema
  only: the test server had no reports.
- A v1 settings reload can return warnings, sent as a set of strings.
  `settings_set` and `reload` log each one as a warning.

`settings_set` passes `patch` to Stalwart unchanged, so a patch must use the
field names of the server's version. In v1, for example, `http`'s
`useXForwarded` is now `clientIpSource`, and `imap`'s `timeoutIdle` is now
`idleTimeout`. v1 does not recognise the old names.

## Breaking changes

- **`settings_set` refuses a secret in `patch`; use `webPushKey`.** `patch` is
  no longer marked sensitive, because swamp then masked every field name and
  value in it, so the settings record showed `"***"` in place of the fields that
  were set. A patch holding a secret (any `{"secret": …}` value) is now refused.
  The one secret setting, `jmap`'s Web Push key, has its own sensitive argument,
  `webPushKey`: pass it as a vault reference.
- **`settings_set` refuses `includeSecrets: true` for `system`.** In Stalwart v1
  it makes every management API reply carry passwords and keys in clear.
- **The `swamp-admin` preset no longer grants `sysSpamTrainingSampleUpdate`.**
  Stalwart v1 removed that permission. On 0.16, re-running `role_ensure` with
  the preset removes it from the role. No method in this extension needs it.

- **Data names are now `<spec>:<key>`** (or `<spec>` alone for `health` and
  `session`), with addresses and domains lowercased; see
  [Data names](#data-names). Before, two specs could share a name (`health` and
  `session` both wrote `current`; `account_list` and `group_list` both wrote a
  group's address), so one overwrote the other. `mailing_list_list` now names
  lists by full address, as `mailing_list_ensure` does. Records written by
  earlier versions keep their old names and are not migrated; update any CEL
  expression that reads one.
- **Boolean arguments accept only `true`/`false`.** From the CLI nothing
  changes: `--input reload=true` still works, and anything else is rejected. A
  caller that passes the strings `"true"` / `"false"` straight to a method is
  now rejected. Earlier versions read `"0"`, `"False"` and any other non-empty
  string as true.
- **Aliases are full addresses.** `AccountInfo.aliases` and `alias_list` used to
  report the local part only.
- **`mailing_list_ensure` and `group_ensure` name their data by full address**
  (now `mailing-list:team@example.com`, not `team`), so lists and groups with
  the same local part on different domains no longer overwrite each other.
- **`account_ensure` records the account as it is afterwards.** `memberOf` holds
  group ids, as `account_list` records it (it used to hold the addresses
  passed), and aliases, role and description that were not passed show what the
  account kept instead of empty values.
- **`account_ensure` refuses an address that belongs to a group.**
- **`settings` records no longer hold secrets.** `settings_get` and
  `settings_set` replace the value of every secret (any `{"secret": …}` object,
  such as jmap `webPushKey`) with `"<redacted>"`. Earlier versions stored it in
  clear. A `settings` record written by an earlier version still holds it;
  delete it with `swamp data delete <model> <name>`.
- **`report_query` lists received reports.** It used to read the reports
  Stalwart generates for other domains (`x:DmarcInternalReport`,
  `x:TlsInternalReport`); it now reads the ones it receives
  (`x:DmarcExternalReport`, `x:TlsExternalReport`), as its description always
  said. `domain`, `rangeStart` and `rangeEnd` are now filled in, and `summary`
  holds the received report's fields.
- **`queue_list` records the sender, recipients, next retry and size.** It used
  to look for fields Stalwart does not send, so `to` was always empty and `from`
  and `status` were never set. `status` is removed from `queue-item`: Stalwart
  keeps a status per recipient, not one per message, so there is no single value
  to record.
- **`role_assign` and `account_set_state` refuse an ambiguous local part.** When
  a bare local part such as `alice` matches accounts on more than one domain,
  they now throw instead of acting on the first match. Pass the full address.
- **`health` records have no `version`.** Stalwart's `/api/account` does not
  report one, so it was always empty.
- **`settings_set` records the singleton as the server holds it after the
  update.** It used to lay `patch` over the old value, which was wrong for a
  partial nested object, which Stalwart merges into the stored one.
- **`httpTimeoutMs` must be a positive number.** `0` used to abort every request
  at once.
- **`certificate` records have `issuer` instead of `subject`.** `subject` held
  the issuer's name all along; Stalwart reports no subject. `notBefore` is new.
- **`settings_set` reloads even when nothing changed** (unless `reload` is
  false). It used to skip the reload, so a retry after a failed reload never
  made the change live.
- **`account_ensure` keeps an alias's enabled flag.** Rewriting the alias list
  used to enable every alias in it, including ones disabled elsewhere.
- **Addresses passed to the `_ensure` methods are lowercased**, as Stalwart
  stores them. An alias typed in another case used to be rewritten on every run,
  and re-enabled if it was disabled.
- **`role_ensure` refuses the names `admin` and `user`.** A custom role with
  either name could never be assigned by name.

## License

MIT — see [LICENSE.txt](./LICENSE.txt).
