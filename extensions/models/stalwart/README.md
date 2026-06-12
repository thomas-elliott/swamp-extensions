# @thomas/stalwart

Careful, **non-destructive** administration of a [Stalwart](https://stalw.art)
mail server (v0.16+) for swamp, over its **JMAP-over-HTTP management API** — for
standing up mailboxes and aliases, configuring groups/lists/roles, checking
server health and DMARC/TLS reports, and running maintenance actions (reload
settings, install/reload certificates, tune the spam filter) without the web-UI
click-through.

## Scope guarantee (read this first)

This extension holds a powerful mail-admin credential, so its surface is
deliberately narrow and **reversible**:

- ❌ **No hard deletes.** It never deletes an account, domain, group, or list.
  The JMAP `destroy` verb is plumbed through the transport for completeness but
  is reachable from **no** method. The only "off switch" is the reversible
  `*_set_state` (deactivate ⇄ reactivate) pair.
- ✅ **Secrets once.** Account passwords and certificate private keys are write-
  only method arguments — sent to Stalwart exactly once, never read back into a
  resource, never logged.
- ✅ **Idempotent.** `*_ensure` methods find-or-create by name and converge
  config in place, reporting `action: created | updated | unchanged`.
- ✅ **Verify-before-mutate.** Every mutating method resolves the target first.

> **Stalwart 0.16 note.** 0.16 removed the legacy REST `/api/*` management tree;
> all management is now JMAP (`POST /jmap`). A small `/api/*` set survives for
> introspection (`/api/account`, `/api/schema`) and metrics
> (`/metrics/prometheus`), which this extension uses for `health_status`.

## Authentication — scoped API key

Stalwart 0.16 supports API keys scoped to specific management permissions. Mint
one (bootstrapped via the fallback admin), store it in a vault, and never inline
it:

```bash
swamp model create @thomas/stalwart stalwart \
  --global-arg apiUrl=https://mail.smol.cloud \
  --global-arg 'apiKey=${{ vault.get(op-homelab, stalwart/api_key) }}'
```

| Global arg | Required | Notes |
| --- | --- | --- |
| `apiUrl` | yes | Base URL, e.g. `https://mail.smol.cloud` (no trailing `/jmap`). |
| `apiKey` | yes | Scoped admin API key (Bearer). Supply via vault. |
| `accountId` | no | JMAP management accountId; omit to use the session's primary. |
| `httpTimeoutMs` | no | Per-request timeout (default 30000). |

## Methods

**Read / health (available now):**

- `health_status` — edition / version / permissions (`/api/account`) plus curated
  gauges (`/metrics/prometheus`). Read-only.
- `jmap_probe` — the Phase 0 discovery tool: runs `<type>/query` then
  `<type>/get` for one JMAP object type and captures the wire shape (ids + a
  sample object), so the management type names can be pinned before the Phase 1
  methods are built. Read-only.

```bash
# Check the server is healthy and see what the API key can do.
swamp model method run stalwart health_status

# Probe the wire shape of the Principal type (drives Phase 0 discovery).
swamp model method run stalwart jmap_probe --input type=Principal --input limit=5
```

**Phase 1 (pending the live JMAP discovery spike):** `domain_list`,
`account_list`, `alias_list`, `group_list`, `report_query`, `queue_list`,
`reload`, `reload_certificates`, `account_ensure` (aliases via `emails[]`),
`account_set_state` (reversible).

**Phase 2:** `group_ensure`, `group_set_state`, `mailing_list_ensure`,
`role_assign`, `spam_config_ensure`, `spam_train` (only if the JMAP train method
exists), `certificate_install` (writes the certificate object + reloads;
issuance stays with cert-orchestrator — this is the install+reload tool).

> The JMAP management method/type names are not published by Stalwart and are
> pinned against the live server during a one-time discovery spike (see the
> `USING` / `JMAP_TYPES` constants in `stalwart.ts`). The transport layer,
> resource schemas, and `health_status` are independent of that.

## License

MIT — see [LICENSE.txt](./LICENSE.txt).
