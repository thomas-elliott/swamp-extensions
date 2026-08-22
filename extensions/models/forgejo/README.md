# @thomas/forgejo

Careful administration of a self-hosted **[Forgejo](https://forgejo.org)** (or
Gitea) server for swamp, over its **`/api/v1` REST API**. Built for three
repeatable tasks: **provisioning repositories/organizations**, **running
GitHub pull-mirrors**, and **driving pull requests** — find-or-create an org,
find-or-create a repo and converge its settings, mirror a GitHub repo, audit
every mirror's sync health in one call, and open/inspect/merge a PR, without
the per-repo UI click-through.

## Scope guarantee (read this first)

This extension can hold an admin-scoped token, so its surface is deliberately
narrow and its mutations are **find-or-create or reversible**, with one
guarded exception (`pr_merge`):

- ✅ **No delete methods.** Removing a repo, org, or mirror stays a deliberate
  manual act in the Forgejo UI. The leftover **empty shell repo** of a failed
  migration is **detected and reported** by `mirror_ensure` with a clear
  message — never auto-deleted.
- ✅ **Reversible lifecycle** — the only "off switch" is `repo_archive`
  (undo with `repo_unarchive`). Both are idempotent no-ops when already in the
  requested state.
- ✅ **Idempotent provisioning** — every `*_ensure` probes by name first
  (absent ⇒ create, present ⇒ converge the supplied settings via PATCH) and
  reports `action: created/updated/unchanged`, so re-runs are safe in a
  pipeline.
- ✅ **Write-only source credentials** — `mirror_ensure`'s `authToken` (for
  private GitHub sources) is supplied via a vault reference, sent once to
  `/repos/migrate`, and **never read back, stored in the data model, or
  logged**.
- ✅ **Refuses unreconcilable drift** — a mirror's source URL is fixed at
  migration time; asking `mirror_ensure` for a different source on an existing
  mirror is an error, not a silent ignore. A name collision with a non-mirror
  repo is likewise refused.
- ⚠️ **`pr_merge` is the one irreversible mutation** — it writes to the base
  branch. It refuses a PR that is closed, already merged, draft, or that the
  server does not report as mergeable, and refuses a head whose combined CI
  state is not `success` unless `force=true` is passed. `force` overrides the
  CI gate **only** — it never overrides a conflicting PR.

## Authentication — scoped access token

The model authenticates with a **Forgejo access token** (your avatar →
**Settings → Applications**), sent as `Authorization: token <t>`. Scopes for
the full surface:

```
write:repository, write:organization, read:admin, read:misc, read:user
```

`read:admin` is only exercised by `user_list`; `read:misc` only by `health`.
The token's user must be a **site admin** for `user_list` and for the listing
methods to see private repos across all owners.

Known Forgejo gotchas this model designs around:

- Token CRUD (`/users/{u}/tokens`) is **basic-auth-only** — this model never
  mints or revokes tokens.
- `migrations.ALLOW_LOCALNETWORKS=false` (a common hardening) makes
  private-address mirror sources fail with HTTP 422; GitHub sources are
  unaffected.

## Install

```bash
swamp extension pull @thomas/forgejo
```

## Configure

```bash
swamp model create @thomas/forgejo forgejo \
  --global-arg apiUrl=https://git.example.com \
  --global-arg 'token=${{ vault.get(<vault>, forgejo/api_token) }}'
```

Optional global arg: `httpTimeoutMs` (default 30000).

## Methods

**Read / audit:** `health` (version + healthz), `org_list`, `repo_list`
(all repos or one owner's), `user_list` (admin view; never any credential),
`mirror_status` (every mirror's last sync, interval, and a `stale` flag),
`branch_protection_list` (what each branch actually enforces).

```bash
# Mirror fleet audit — is anything failing to sync?
swamp model method run forgejo mirror_status --input '{}'

# A mirror is "stale" when its last sync is older than staleFactor × interval.
swamp model method run forgejo mirror_status --input staleFactor=3
```

**Idempotent provisioning:**

```bash
# Find-or-create an org.
swamp model method run forgejo org_ensure \
  --input name=mirrors --input visibility=private

# Find-or-create a repo and converge its settings.
swamp model method run forgejo repo_ensure \
  --input owner=apps --input name=damson \
  --input private=true --input hasWiki=false

# Grant a user access to a repo (never removes a collaborator; refuses the owner).
swamp model method run forgejo collaborator_ensure \
  --input owner=apps --input name=damson \
  --input user=ci-bot --input permission=write

# Make a branch PR-only, and bind admins to the rule too.
swamp model method run forgejo branch_protection_ensure \
  --input owner=apps --input name=damson --input rule=main \
  --input enablePush=false --input applyToAdmins=true

# Let one account push to a namespace, but never to the CI config.
swamp model method run forgejo branch_protection_ensure \
  --input owner=apps --input name=damson --input 'rule=agents/*' \
  --input enablePush=true --input enablePushWhitelist=true \
  --input 'pushWhitelistUsernames=["ci-bot"]' \
  --input 'protectedFilePatterns=.woodpecker.yml;.woodpecker/**'

# Find-or-create a GitHub pull-mirror (the workhorse).
swamp model method run forgejo mirror_ensure \
  --input owner=mirrors --input name=scrappy \
  --input cloneAddr=https://github.com/me/scrappy.git \
  --input 'authToken=${{ vault.get(<vault>, github/mirror_pat) }}'

# Queue an immediate pull-sync.
swamp model method run forgejo mirror_sync_now \
  --input owner=mirrors --input name=scrappy
```

`mirror_ensure` defaults: `service=github`, `mirrorInterval=8h0m0s`,
`lfs=true`, `private=true`. On an existing mirror it reconciles
interval/visibility/description only (interval compare is semantic — `8h`
equals `8h0m0s`).

**Reversible lifecycle:** `repo_archive` / `repo_unarchive`.

**Pull requests:**

```bash
# Open a PR — find-or-create on the head→base pair, so a re-run converges the
# title/body instead of failing on a duplicate.
swamp model method run forgejo pr_ensure \
  --input owner=apps --input name=damson \
  --input head=feat/thing --input base=main --input title='Add the thing'

# List open PRs (state: open | closed | all).
swamp model method run forgejo pr_list --input owner=apps --input name=damson

# One PR, with the mergeable verdict and the head commit's CI state.
swamp model method run forgejo pr_get \
  --input owner=apps --input name=damson --input index=4

# Merge (strategy: squash | merge | rebase | rebase-merge; squash is default).
swamp model method run forgejo pr_merge \
  --input owner=apps --input name=damson --input index=4 \
  --input deleteBranch=true
```

`mergeable` and `ciState` come from a **single-PR fetch only** — a listing
carries neither, so `pr_list` leaves both absent rather than reporting a
value it cannot stand behind. `ciState: "none"` means the head commit carries
no status at all, which is **not** a pass: a repo with CI disabled and a
pipeline that never started are indistinguishable here.

## Data model

| Resource | What it holds |
| --- | --- |
| `server` | Version + healthz result. |
| `org` | Org visibility/description. |
| `repo` | Repo settings incl. `empty`/`mirror`/`archived` flags. |
| `user` | Admin user listing (id, login, email, isAdmin, lastLogin). |
| `collaborator` | A user's access level on a repo. |
| `branch_protection` | A rule and the constraints it enforces. |
| `mirror` | Pull-mirror sync health (`lastSynced`, `interval`, `stale`). |
| `pull_request` | PR state, head/base, `mergeable`, and head `ciState`. |

Data instance names replace `/` with `:` (swamp rejects slashes), so
`mirrors/scrappy` is stored as `mirrors:scrappy` and PR 4 on `apps/damson` as
`apps:damson#4`.

## Design notes

- All listings paginate at 50 (Forgejo's search cap) until a short page.
- Search responses (`{ok, data}`) and bare-array responses are both handled.
- Repo paths on disk are lowercased by Forgejo while API names keep display
  case — instance names follow the API's display case.
- A PR's head may be qualified (`owner:branch`) for a fork; find-or-create
  matches on the bare branch name, since that is what the API reports back.
- Push-mirrors (Forgejo → GitHub), webhooks, teams, deploy keys, branch
  protection, and PR review/comment endpoints are deliberately out of scope —
  file an issue when a real use-case lands.
