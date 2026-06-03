# @thomas/woodpecker

Careful administration of a self-hosted
**[Woodpecker CI](https://woodpecker-ci.org)** server for swamp, over its **REST
API**. Built for the repeatable task of moving repos onto a self-hosted
Woodpecker — enable a repo, mark it trusted, set its timeout, and promote shared
CI credentials to org-level secrets — without the UI click-through, per repo.

## Scope guarantee (read this first)

This extension holds an **admin PAT**, so its surface is deliberately narrow and
its mutations are additive or **reversible**:

- ✅ **Write-only secrets** — secret values are supplied via a vault reference,
  sent to the server once, and **never read back, stored in the data model, or
  logged** (Woodpecker's API does not expose them either).
- ✅ **Reversible lifecycle** — the only "off switches" are `repo_disable`
  (re-run `repo_enable` to restore) and the secret deletes (re-create with
  `*_secret_set`). Deletes are idempotent: removing something already gone is a
  no-op, not an error.
- ✅ **Idempotent** — `repo_enable` finds-or-activates and converges settings in
  place; `*_secret_set` create-or-update by name. Re-runs report
  `action: unchanged` when nothing differs, so they're safe in a pipeline.
- ✅ **Verify-before-mutate** — `repo_disable` fetches the repo first; the
  secret deletes probe for existence first.

## Authentication — personal access token

The model authenticates with a **Woodpecker personal access token**. Get one
from the Woodpecker UI: your avatar → **Settings → CLI and API** (the token
shown for `woodpecker-cli` use). Store it in your vault.

## Install

```bash
swamp extension pull @thomas/woodpecker
```

## Configure

```bash
swamp model create @thomas/woodpecker woodpecker \
  --global-arg apiUrl=https://woodpecker.example.com \
  --global-arg 'token=${{ vault.get(<vault>, woodpecker/api_token) }}'
```

Optional global arg: `httpTimeoutMs` (default 30000).

## Methods

**Read / audit (never emit secret values):** `repo_list`, `repo_get`,
`repo_available` (forge repos + whether each is enabled), `org_get`,
`org_secret_list`, `repo_secret_list`, `pipeline_list`, `pipeline_last`.

**Onboard a repo (the one-liner):**

```bash
# Activate the repo from the forge, mark it trusted (for docker.sock steps),
# and set a 30-minute hang backstop — all idempotently. Method arguments are
# passed as one JSON object via --input (vault references resolve server-side).
swamp model method run woodpecker repo_enable \
  --input '{"repo":"thomas-elliott/damson","trusted":true,"timeout":30}'
```

- `repo_enable` — activate (if needed) + converge settings. `trusted=true` sets
  all three trust capabilities; `trustedNetwork` / `trustedVolumes` /
  `trustedSecurity` override individually (merged over current, so a partial
  change never clobbers the others). Also accepts `timeout` (minutes),
  `visibility` (`public|private|internal`), `requireApproval`
  (`none|forks|pull_requests|all`), `cancelPreviousPipelineEvents`.
- `repo_update` — same settings on an already-enabled repo.
- `repo_repair` — repair a stale forge webhook (e.g. after the server URL
  moved).

**Promote shared credentials to org-level secrets:**

```bash
# One ghcr push token inherited by every repo in the org. The value is a vault
# reference — it resolves server-side and never appears on the command line.
swamp model method run woodpecker org_secret_set \
  --input '{"owner":"thomas-elliott","name":"ghcr_token","value":"${{ vault.get(<vault>, woodpecker/ghcr_token) }}","events":["push","tag"]}'
```

- `org_secret_set` / `repo_secret_set` — create-or-update a secret (value
  write-only). `events` defaults to `["push","tag"]`; `images` restricts the
  secret to named step images.

**Reversible lifecycle:** `repo_disable`, `org_secret_delete`,
`repo_secret_delete`.

**Action:** `pipeline_trigger` (run a pipeline on a branch).

Every method writes one resource carrying the entity plus an `action`
(`created|unchanged|updated|enabled|disabled|repaired|deleted|triggered|observed`)
and a `timestamp`.

## Notes

- **Zero npm dependencies** — uses the runtime `fetch` only.
- **`trusted` is an object** in Woodpecker v3 (`network` / `volumes` /
  `security`), not a boolean — the `trusted=true` convenience flag fans out to
  all three.
- A repo reference is a numeric id or `owner/name`. Enabling resolves the forge
  `forge_remote_id` by name from `/api/user/repos?all=true`.
- **Method arguments go through `--input`** (a `key=value` pair or a JSON
  object), not `--arg`. `${{ vault.get(...) }}` references inside an `--input`
  value resolve server-side, so secret values never reach the command line.
- Targets the Woodpecker **v3** REST API.
