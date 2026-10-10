# @thomas/woodpecker

Administration of a self-hosted
**[Woodpecker CI](https://woodpecker-ci.org)** server for swamp, over its **REST
API**. It moves repos onto a self-hosted Woodpecker without using the UI for
each repo: enable a repo, mark it trusted, set its timeout, and promote shared
CI credentials to org-level secrets.

## Scope guarantee (read this first)

This extension holds an **admin PAT**, so it has few methods, and every change it
makes is additive or **reversible**:

- ✅ **Write-only secrets.** Secret values are supplied via a vault reference,
  sent to the server once, and **never read back, stored in the data model, or
  logged** (Woodpecker's API does not expose them either).
- ✅ **Reversible lifecycle.** The only disabling operations are `repo_disable`
  (re-run `repo_enable` to restore) and the secret deletes (re-create with
  `*_secret_set`). Deletes are idempotent: removing something already gone is a
  no-op, not an error.
- ✅ **Idempotent.** `repo_enable` activates the repo if needed and updates its
  settings in place; `*_secret_set` create-or-update by name. Re-runs report
  `action: unchanged` when nothing differs, so they're safe in a pipeline.
- ✅ **Verify-before-mutate.** `repo_disable` fetches the repo first; the
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
`forge_list` (the server's forges, flagging the token's own), `repo_available`
(forge repos + whether each is enabled), `org_get`, `org_secret_list`,
`repo_secret_list`, `pipeline_list`, `pipeline_last`.

**Observability (day-to-day use):**

```bash
# Fleet dashboard — last pipeline status for every enabled repo, in one call.
swamp model method run woodpecker status_all --input '{}'

# Watch a run to completion (defaults to the repo's latest); writes the final
# status plus every step, so the failed step is right there.
swamp model method run woodpecker pipeline_wait \
  --input '{"repo":"thomas-elliott/taskmanager"}'

# Per-step states for a pipeline (defaults to latest).
swamp model method run woodpecker pipeline_steps \
  --input '{"repo":"thomas-elliott/taskmanager"}'

# Decoded logs for one step (by name or id), last N lines — no curl + base64.
swamp model method run woodpecker pipeline_logs \
  --input '{"repo":"thomas-elliott/taskmanager","step":"dotnet","tailLines":50}'
```

- `status_all`: one `repo-status` per enabled repo (`status`, last
  number/event/ branch; `none` if it never ran). Optional `match` substring
  filter.
- `pipeline_steps`: `{workflow, name, state, exitCode, error}` per step.
- `pipeline_logs`: fetches and **decodes** a step's logs (base64 handled
  server-side), returning the last `tailLines` (default 200; `0` = all).
- `pipeline_wait`: polls until the pipeline finishes (success/failure/error/killed/declined/
  blocked); `timeoutSec` (default 600) and `pollIntervalSec` (default 5).

**Run control:**

- `pipeline_restart`: re-run a pipeline (creates a new run), for example after
  fixing infrastructure, instead of pushing an empty commit.
- `pipeline_cancel`: stop a running, pending or blocked pipeline (no-op if
  already finished).
- `pipeline_approve` / `pipeline_decline`: release a pipeline blocked by
  `require_approval`.

All four default to the repo's latest pipeline; pass `number` to target a
specific run.

**Infra / health (admin reads):**

- `agent_list`: build agents + health (`online` = contacted in the last 2 min,
  `version`, `capacity`, `lastContact`).
- `queue_info`: server build-queue stats (pending/running/worker counts;
  paused).
- `server_info`: server version + health.

**Scheduled pipelines (cron):**

- `cron_list`: a repo's cron jobs.
- `cron_set`: create-or-update a cron by name (idempotent). `schedule` is a
  cron expression or an `@daily`/`@hourly`/… macro; optional `branch`.
- `cron_delete`: delete a cron by name (reversible: re-create with `cron_set`;
  already-absent is a no-op).

**Onboard a repo (one command):**

```bash
# Activate the repo from the forge, mark it trusted (for docker.sock steps),
# and set a 30-minute hang backstop — all idempotently. Method arguments are
# passed as one JSON object via --input (vault references resolve server-side).
swamp model method run woodpecker repo_enable \
  --input '{"repo":"thomas-elliott/damson","trusted":true,"timeout":30}'
```

- `repo_enable`: activate (if needed) and update settings. `trusted=true` sets
  all three trust capabilities; `trustedNetwork` / `trustedVolumes` /
  `trustedSecurity` override individually (merged with the current values, so a
  partial change keeps the capabilities it does not mention). Also accepts `timeout` (minutes),
  `visibility` (`public|private|internal`), `requireApproval`
  (`none|forks|pull_requests|all`), `cancelPreviousPipelineEvents`.
- `repo_update`: same settings on an already-enabled repo.
- `repo_repair`: repair an outdated forge webhook (for example after the
  server URL changes).

**Promote shared credentials to org-level secrets:**

```bash
# One ghcr push token inherited by every repo in the org. The value is a vault
# reference — it resolves server-side and never appears on the command line.
swamp model method run woodpecker org_secret_set \
  --input '{"owner":"thomas-elliott","name":"ghcr_token","value":"${{ vault.get(<vault>, woodpecker/ghcr_token) }}","events":["push","tag"]}'
```

- `org_secret_set` / `repo_secret_set`: create-or-update a secret (value
  write-only). `images` restricts the secret to named step images. A new
  secret gets `events: ["push","tag"]` and all images unless the call sets
  them; an existing secret keeps whichever of the two you leave out, so
  rotating a value never extends it to more events or images.

**Reversible lifecycle:** `repo_disable`, `org_secret_delete`,
`repo_secret_delete`.

**Action:** `pipeline_trigger` (run a pipeline on a branch).

Every method writes one resource carrying the entity plus an `action`
(`created|unchanged|updated|enabled|disabled|repaired|deleted|triggered|restarted|cancelled|approved|declined|observed`)
and a `timestamp`.

## Notes

- **No npm dependencies.** Uses the runtime `fetch` only.
- **`trusted` is an object** in Woodpecker v3 (`network` / `volumes` /
  `security`), not a boolean. The `trusted=true` flag sets all three.
- A repo reference is a numeric id or `owner/name`. Enabling resolves the forge
  `forge_remote_id` by name from `/api/user/repos?all=true`.
- **On a multi-forge server, onboarding is single-forge.** A Woodpecker user
  record is bound to the forge it authenticated against, so `/api/user/*` (and
  therefore `repo_available` and the activation half of `repo_enable`) only
  sees that forge. No argument changes this; the token determines the forge.
  Use a token created while logged in to the other forge (a second model
  instance is the simplest way), or enable the repo in the UI. `forge_list`
  shows which forges exist and which one the current token belongs to, and
  `repo_enable` includes this in its error instead of only "not found".
  Everything after onboarding (`repo_list`, `repo_get`, `repo_update`,
  `repo_secret_*`, every `pipeline_*`) goes through the admin `/api/repos`
  endpoints and already works across forges with one token.
- **Method arguments go through `--input`** (a `key=value` pair or a JSON
  object), not `--arg`. `${{ vault.get(...) }}` references inside an `--input`
  value resolve server-side, so secret values never reach the command line.
- Targets the Woodpecker **v3** REST API.
