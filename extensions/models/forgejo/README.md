# @thomas/forgejo

Administration of a self-hosted **[Forgejo](https://forgejo.org)** (or Gitea)
server for swamp, over its **`/api/v1` REST API**. Built for three repeatable
tasks: **provisioning repositories/organizations**, **running GitHub
pull-mirrors**, and **managing pull requests**: find-or-create an org,
find-or-create a repo and converge its settings, mirror a GitHub repo, audit
every mirror's sync health in one call, and open/inspect/merge a PR, without
working through the UI one repo at a time.

## Scope guarantee

This extension can hold an admin-scoped token, so it has a small set of methods
and its mutations are **find-or-create or reversible**, with one guarded
exception (`pr_merge`):

- **No delete methods.** Removing a repo, org, or mirror is done manually in the
  Forgejo UI. The leftover empty repo of a failed migration is detected and
  reported by `mirror_ensure` with a clear message and never deleted
  automatically.
- **Reversible lifecycle.** The only way to disable a repo is `repo_archive`
  (undo with `repo_unarchive`). Both are idempotent no-ops when already in the
  requested state.
- **Idempotent provisioning.** Every `*_ensure` probes by name first (absent ⇒
  create, present ⇒ converge the supplied settings via PATCH) and reports
  `action: created/updated/unchanged`, so re-runs are safe in a pipeline.
- **Write-only source credentials.** `mirror_ensure`'s `authToken` (for private
  GitHub sources) is supplied via a vault reference, sent once to
  `/repos/migrate`, and never read back, stored in the data model, or logged.
  Credentials written into `cloneAddr` itself (`https://user:token@…`) are sent
  to `/repos/migrate` too, but are stripped from every log line and error.
- **Refuses unreconcilable drift.** A mirror's source URL is fixed at migration
  time; asking `mirror_ensure` for a different source on an existing mirror is
  an error; it is not ignored. A name collision with a non-mirror repo is
  likewise refused.
- **Webhooks are read and repointed, never created, and no credential is ever
  emitted.** `webhook_audit` reports where every hook posts; `webhook_retarget`
  changes `config.url` alone, sending the hook's own events, branch filter and
  authorization header back with it because Forgejo resets all three on any edit
  that leaves them out. Neither sends a `secret` key, because that would
  overwrite the shared secret the CI server uses. Creating a hook is left to the
  CI server that owns that secret (Woodpecker: `repo_repair`).
- **A hook URL's query string is treated as a credential.** Woodpecker
  authenticates its hooks with an `?access_token=<JWT>` on the URL itself, so
  the raw URL is a secret. Every reported `url` has its query values redacted,
  including in error messages; `matchesExpected` compares scheme/host/path only;
  and `webhook_retarget` carries the existing query over verbatim, because a URL
  without the query would leave a hook that still fires but no longer
  authenticates.
- **`pr_merge` is the one irreversible mutation.** It writes to the base branch.
  It refuses a PR that is closed, already merged, draft, or that the server does
  not report as mergeable, and refuses a head whose combined CI state is not
  `success` unless `force=true` is passed. The CI state is the worst across
  every status context of the head, not just the first page the server returns.
  The merge is pinned to the head commit that was checked: if someone pushes in
  between, nothing is merged and the method fails with a message to re-run.
  `force` overrides the CI gate only; it never overrides a conflicting PR or a
  moved head.

## Authentication — scoped access token

The model authenticates with a **Forgejo access token** (your avatar →
**Settings → Applications**), sent as `Authorization: token <t>`. Scopes needed
by every method:

```
write:repository, write:organization, read:admin, read:misc, read:user
```

`read:admin` is only used by `user_list`; `read:misc` only by `health`. The
token's user must be a **site admin** for `user_list` and for the listing
methods to see private repos across all owners.

Known Forgejo limitations this model works around:

- Token CRUD (`/users/{u}/tokens`) is **basic-auth-only**, so this model never
  creates or revokes tokens.
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

**Read / audit:** `health` (version + healthz), `org_list`, `repo_list` (all
repos or one owner's), `user_list` (admin view; never any credential),
`mirror_status` (every mirror's last sync, interval, and a `stale` flag),
`branch_protection_list` (what each branch enforces), `webhook_audit` (where
every hook posts, and whether it matches the URL you expected).

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

# Find-or-create a repo and converge its settings. A new repo is private
# unless private=false is passed.
swamp model method run forgejo repo_ensure \
  --input owner=apps --input name=web \
  --input private=true --input hasWiki=false

# Grant a user access to a repo (never removes a collaborator; refuses the
# owning user).
swamp model method run forgejo collaborator_ensure \
  --input owner=apps --input name=web \
  --input user=ci-bot --input permission=write

# Make a branch PR-only, and bind admins to the rule too.
swamp model method run forgejo branch_protection_ensure \
  --input owner=apps --input name=web --input rule=main \
  --input enablePush=false --input applyToAdmins=true

# Let one account push to a namespace, but never to the CI config.
swamp model method run forgejo branch_protection_ensure \
  --input owner=apps --input name=web --input 'rule=agents/*' \
  --input enablePush=true --input enablePushWhitelist=true \
  --input 'pushWhitelistUsernames=["ci-bot"]' \
  --input 'protectedFilePatterns=.woodpecker.yml;.woodpecker/**'

# Find-or-create a GitHub pull-mirror (the workhorse).
swamp model method run forgejo mirror_ensure \
  --input owner=mirrors --input name=widget \
  --input cloneAddr=https://github.com/octo-org/widget.git \
  --input 'authToken=${{ vault.get(<vault>, github/mirror_pat) }}'

# Queue an immediate pull-sync.
swamp model method run forgejo mirror_sync_now \
  --input owner=mirrors --input name=widget
```

`mirror_ensure` creates with `service=github`, `mirrorInterval=8h0m0s`,
`lfs=true`, `private=true` unless other values are passed. On an existing mirror
it reconciles interval/visibility/description, and only those it was passed:
leaving one out keeps the mirror's current value (intervals are compared as
durations, so `8h` equals `8h0m0s`).

**Reversible lifecycle:** `repo_archive` / `repo_unarchive`.

**Pull requests:**

```bash
# Open a PR — find-or-create on the head→base pair, so a re-run converges the
# title/body instead of failing on a duplicate.
swamp model method run forgejo pr_ensure \
  --input owner=apps --input name=web \
  --input head=feat/thing --input base=main --input title='Add the thing'

# List open PRs (state: open | closed | all).
swamp model method run forgejo pr_list --input owner=apps --input name=web

# One PR, with the mergeable verdict and the head commit's CI state.
swamp model method run forgejo pr_get \
  --input owner=apps --input name=web --input index=4

# Merge (strategy: squash | merge | rebase | rebase-merge; squash is default).
swamp model method run forgejo pr_merge \
  --input owner=apps --input name=web --input index=4 \
  --input deleteBranch=true
```

**Webhooks** (audit and repoint only; see the scope guarantee):

```bash
# Where does every repo's webhook actually post? Supply the URL you expect and
# each hook comes back with matchesExpected — false is the drift.
swamp model method run forgejo webhook_audit \
  --input owner=alice \
  --input expectedUrl=http://ci.internal.example/api/hook

# Repoint one hook that drifted. Converge-only: it never creates a hook, and it
# never sends the secret, so the shared secret survives untouched.
swamp model method run forgejo webhook_retarget \
  --input owner=alice --input name=widget \
  --input matchUrl=old-ci.example \
  --input url=http://ci.internal.example/api/hook
```

`expectedUrl` and `matchUrl` are matched against **scheme/host/path only**, so
pass them without a query string. You cannot know a hook's per-repo token, and
comparing full URLs would report every hook as drifted.

A repo with several hooks needs `matchUrl` to say which one; an ambiguous match
is **refused**; the model does not pick one. A repo with no hooks is an error
rather than a create — see the scope guarantee.

`webhook_retarget` sends the hook's events back as Forgejo lists them, and
Forgejo cannot take them back exactly: it lists events by group (`issues`,
`pull_request`) but reads a group name as "every event in the group", and the
API has no way to say "send everything". So a hook set to part of a group comes
back with the whole group, and a "send everything" hook comes back with a fixed
list. Hooks registered by Woodpecker are not affected. When the events change,
the method logs a warning with the before and after lists.

`repo_ensure` with a `defaultBranch` that does not exist on a non-empty repo
fails: Forgejo ignores such a value without an error, so the method would
otherwise report `updated` on every run. Push the branch first.

`collaborator_ensure` moves toward the user's effective permission level, which
includes access through teams, because Forgejo's API does not expose the
collaborator's own level. When team access is above the requested level, the
method sends the requested level again (a repeat PUT) and reports `updated` on
every run. The PUT is harmless; it only sets the collaborator's own level.

`mergeable` and `ciState` come from a **single-PR fetch only**. The list
endpoint returns neither, so `pr_list` leaves both absent. `ciState: "none"`
means the head commit carries no status at all, which is **not** a pass: a repo
with CI disabled and a pipeline that never started are indistinguishable here.

## Data model

| Resource            | What it holds                                                         |
| ------------------- | --------------------------------------------------------------------- |
| `server`            | Version + healthz result.                                             |
| `org`               | Org visibility/description.                                           |
| `repo`              | Repo settings incl. `empty`/`mirror`/`archived` flags.                |
| `user`              | Admin user listing (id, login, email, isAdmin, lastLogin).            |
| `collaborator`      | A user's access level on a repo.                                      |
| `branch_protection` | A rule and the constraints it enforces.                               |
| `mirror`            | Pull-mirror sync health (`lastSynced`, `interval`, `stale`).          |
| `pull_request`      | PR state, head/base, `mergeable`, and head `ciState`.                 |
| `webhook`           | Hook target URL, events, active, `matchesExpected`. Never the secret. |

Data instance names are `<spec>:<key>`, because swamp keys stored data by model
and name, not by spec. Without the prefix a mirror's `repo` and `mirror` records
would overwrite each other. Key parts are joined with `:`, and owner, repo and
user names are lowercased (Forgejo treats them case-insensitively):

| Record                         | Instance name                                  |
| ------------------------------ | ---------------------------------------------- |
| server health                  | `server`                                       |
| repo / mirror `Mirrors/Widget` | `repo:mirrors:widget`, `mirror:mirrors:widget` |
| PR 4 on `apps/web`             | `pull_request:apps:web:4`                      |
| hook 3 on `apps/web`           | `webhook:apps:web:3`                           |
| user `alice` on `apps/web`     | `collaborator:apps:web:alice`                  |
| rule `agents/*` on `apps/web`  | `branch_protection:apps:web:agents%2F*`        |

Rule names keep their case. A `%`, `:`, `/`, `\` or NUL inside a key part is
written as `%XX`, and `..` as `.%2E`, so two keys never share a name. List them
with `swamp data query 'modelName == "<model>"'`.

## Design notes

- All listings read page after page until an empty one, so a server with a lower
  `MAX_RESPONSE_ITEMS` is still read in full.
- Search responses (`{ok, data}`) and bare-array responses are both handled.
- Forgejo keeps display case in API names; instance names are lowercased so
  `Apps/Web` and `apps/web` land on one record.
- A PR's head may be qualified (`owner:branch`) for a fork. The API reports the
  bare branch name, so find-or-create matches on that and on the owner of the
  head's repo: an unqualified head is a branch in the PR's own repo, and never
  matches a fork's PR from a branch of the same name.
- `webhook_audit` needs admin on a repo to read its hooks. A repo it cannot read
  is **skipped with a warning** and the audit continues; the final log line
  counts the skipped repos. A partial audit is still useful, but do not read a
  clean result as "every hook is correct" unless that count is 0.
- A server or proxy that ignores the `page` parameter would return the same page
  forever. Listings detect this and fail rather than loop.
- Push-mirrors (Forgejo → GitHub), teams, deploy keys, and PR review/comment
  endpoints are out of scope; file an issue when there is a real use-case.
  Webhook _creation_ is excluded by design (see the scope guarantee), not for
  lack of a use-case.

## Breaking changes

- **Data instance names are now `<spec>:<key>`** (or `<spec>` alone for
  `server`), lowercased for owner, repo and user names, and PR names use `:`
  instead of `#` (see "Data model"). Records written by earlier versions keep
  their old names (`mirrors:widget`, `apps:web#4`, `status`) and are not
  migrated; re-run the list methods to write the new ones.
- **Boolean arguments accept only `true`/`false`.** They are plain JSON
  booleans, so the schema now carries their descriptions and defaults. Earlier
  versions read `"0"`, `"False"` and any other non-empty string as true. From
  the CLI, `--input force=true` is still converted to a boolean.
- **`pr_merge` merges only the head commit it checked**, with or without
  `force`. If the branch moves between the check and the merge, it now fails
  with "head moved … Re-run pr_merge" instead of merging the new head.
- **`ciState` covers every status context.** `pr_get` and `pr_merge` read all
  pages of the combined status, so a head with more contexts than one page can
  now read `failure` or `pending` where it used to read `success`.
- **`collaborator_ensure` with `permission` omitted keeps an existing
  collaborator's level.** Earlier versions reset it to `write`. A new
  collaborator still gets `write`.
- **`mirror_ensure` with `mirrorInterval` or `private` omitted keeps an existing
  mirror's value.** Earlier versions reset them to `8h0m0s` and private. A new
  mirror still gets those defaults.
- **`collaborator_ensure` refuses only the owning user.** Earlier versions also
  refused a site admin, or an owner of the owning org, as "owns the repo"; they
  are now granted access like anyone else.
- **`pr_ensure` matches the head's repo, not only its branch name.** Earlier
  versions matched `alice:fix` against any open PR from a branch `fix`, in this
  repo or another fork, and rewrote that PR's title. Now such a request opens a
  new PR.
- **`repo_ensure` fails when the default branch cannot be set** (see above),
  instead of reporting `updated` while the old branch stays.
- **The `reachable` check needs a user object.** An `apiUrl` that answers 200
  with something other than a Forgejo user (a web page, say) now fails.
- **`httpTimeoutMs` must be positive.** `0` used to abort every request at once;
  it is now rejected.
