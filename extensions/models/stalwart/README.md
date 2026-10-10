# @thomas/stalwart

**Non-destructive** administration of a [Stalwart](https://stalw.art) mail
server (v0.16+) for swamp, over its **JMAP-over-HTTP management API**. Use it to
create mailboxes and aliases, configure groups/lists/roles, check server health
and DMARC/TLS reports, and run maintenance actions (reload settings,
install/reload certificates, adjust the spam filter) without using the web UI.

## Scope guarantee (read this first)

This extension holds a mail-admin credential, so it has few methods and every
change it makes is **reversible**:

- ❌ **No hard deletes.** It never deletes an account, domain, group, or list.
  **No** method sends the JMAP `destroy` verb, and the transport has no way to
  send one. The only way to disable something is the reversible `*_set_state`
  (deactivate ⇄ reactivate) pair.
- ✅ **Secrets once.** Account passwords and certificate private keys are write-
  only method arguments: sent to Stalwart exactly once, never read back into a
  resource, never logged.
- ✅ **Idempotent.** `*_ensure` methods find or create by name and update
  config in place, reporting `action: created | updated | unchanged`.
- ✅ **Verify-before-mutate.** Every mutating method resolves the target first.

> **Stalwart 0.16 note.** 0.16 removed the legacy REST `/api/*` management tree;
> all management is now JMAP (`POST /jmap`). A small `/api/*` set remains for
> introspection (`/api/account`, `/api/schema`) and metrics
> (`/metrics/prometheus`), which this extension uses for `health_status`.

## Authentication — scoped API key

Stalwart 0.16 supports API keys scoped to specific management permissions. Create
one with the fallback admin account, store it in a vault, and never inline it:

```bash
swamp model create @thomas/stalwart stalwart \
  --global-arg apiUrl=https://mail.example.com \
  --global-arg 'apiKey=${{ vault.get(op-homelab, stalwart/api_key) }}'
```

| Global arg | Required | Notes |
| --- | --- | --- |
| `apiUrl` | yes | Base URL, e.g. `https://mail.example.com` (no trailing `/jmap`). |
| `apiKey` | yes | Scoped admin API key (Bearer). Supply via vault. |
| `accountId` | no | JMAP management accountId; omit to use the session's primary. |
| `httpTimeoutMs` | no | Per-request timeout (default 30000). |

## Methods

**Read-only:**

- `domain_list`, `account_list`, `alias_list`, `role_list`, `group_list`,
  `mailing_list_list`: one resource per object. Group membership is stored on
  each member's account, not on the group.
- `queue_list`: queued outbound messages.
- `report_query`: received DMARC/TLS aggregate reports.
- `settings_get`: one server settings singleton (http, system,
  spam-classifier, …).
- `health_status`: edition / version / permissions (`/api/account`) plus selected
  gauges (`/metrics/prometheus`).
- `session_dump` and `jmap_probe`: discovery tools. `session_dump` records the
  JMAP session's capabilities and accounts; `jmap_probe` runs `<type>/query`
  then `<type>/get` for one JMAP object type and records the response shape
  (ids + a sample object). Use them to check the `USING` / `JMAP_TYPES`
  constants against a new Stalwart version.

**Create or update (idempotent, never delete):**

- `account_ensure`: an individual mailbox with its `aliases`, role,
  group membership (`memberOf`) and description. An optional password is
  set once, on create.
- `group_ensure`, `mailing_list_ensure`: by address.
- `role_ensure`: by name, from a `preset` (`swamp-admin` | `automated-mailbox`)
  or an explicit permission list.
- `role_assign`: assign `admin`, `user` or a custom role to an account. Re-run
  with the previous role to revert.
- `settings_set`: merge `patch` into a settings singleton, then reload.
- `certificate_install`: install a PEM certificate and key, then reload
  certificates. Your ACME tooling issues the certificate; this method only
  installs it.

**Reversible state changes:** `domain_set_state`, `account_set_state`.

**Maintenance:** `reload`, `reload_certificates`.

```bash
# Check the server is healthy and see what the API key can do.
swamp model method run stalwart health_status

# Record the response shape of the Principal type.
swamp model method run stalwart jmap_probe --input type=Principal --input limit=5
```

**Not built yet:** `group_set_state`, `spam_config_ensure`, and `spam_train`
(only if Stalwart has a JMAP train method).

> Stalwart does not publish its JMAP management method and type names. They were
> confirmed against a live 0.16 server and are pinned in the `USING` /
> `JMAP_TYPES` constants in `stalwart.ts`.

## License

MIT — see [LICENSE.txt](./LICENSE.txt).
