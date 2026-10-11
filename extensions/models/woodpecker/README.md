# @thomas/woodpecker

Administration of a self-hosted **[Woodpecker CI](https://woodpecker-ci.org)**
server for swamp, over its **REST API**. It moves repos onto a self-hosted
Woodpecker without using the UI for each repo: enable a repo, mark it trusted,
set its timeout, and promote shared CI credentials to org-level secrets.

## Scope guarantee

This extension holds an **admin PAT**, so it has few methods, and every change
it makes is additive or **reversible**:

- **Write-only secrets.** Secret values are supplied via a vault reference, sent
  to the server once, and **never read back, stored in the data model, or
  logged** (Woodpecker's API does not expose them either).
- **Reversible lifecycle.** The only disabling operations are `repo_disable`
  (re-run `repo_enable` to restore), the secret deletes (re-create with
  `*_secret_set`) and `cron_delete` (re-create with `cron_set`). Deletes are
  idempotent: removing something already gone is a no-op, not an error.
- **Idempotent.** `repo_enable` activates the repo if needed and updates its
  settings in place; `*_secret_set` and `cron_set` create-or-update by name.
  Re-runs report `action: unchanged` when nothing differs, so they're safe in a
  pipeline. The exception is `*_secret_set` on an existing secret: the value
  cannot be read back to compare, so it is always sent and reported `updated`.
- **Verify-before-mutate.** `repo_disable` fetches the repo first and does
  nothing to one that is already disabled; the secret and cron deletes check
  that the item exists first.

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

Use an `https://` `apiUrl`. Over plain http the admin token travels unencrypted,
and every method run logs a warning saying so. There is no setting to turn the
warning off.

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
  --input '{"repo":"octo-org/api"}'

# Per-step states for a pipeline (defaults to latest).
swamp model method run woodpecker pipeline_steps \
  --input '{"repo":"octo-org/api"}'

# Decoded logs for one step (by name or id), last N lines — no curl + base64.
swamp model method run woodpecker pipeline_logs \
  --input '{"repo":"octo-org/api","step":"dotnet","tailLines":50}'
```

- `status_all`: one `repo-status` per enabled repo (`status`, last number/event/
  branch; `none` if it never ran). Optional `match` substring filter.
- `pipeline_steps`: `{workflow, name, stepId, state, exitCode, error}` per step.
- `pipeline_logs`: fetches and **decodes** a step's logs (the extension decodes
  the base64; a line that is not valid base64 reads `[undecodable log line]`),
  returning the last `tailLines` (default 200; `0` = all). A step name can
  repeat across workflows (a matrix pipeline), and then the first match wins;
  pass the numeric `stepId` from `pipeline_steps` to pick one exactly.
- `pipeline_wait`: polls until the pipeline finishes
  (success/failure/error/killed/canceled/declined/blocked/skipped); `timeoutSec`
  (default 600) and `pollIntervalSec` (default 5, at least 1). On a timeout it
  still succeeds, writing the unfinished status with `timedOut: true`.

**Run control:**

- `pipeline_restart`: re-run a pipeline (creates a new run), for example after
  fixing infrastructure, instead of pushing an empty commit.
- `pipeline_cancel`: stop a running, pending or blocked pipeline (no-op if
  already finished).
- `pipeline_approve` / `pipeline_decline`: release a pipeline blocked by
  `require_approval`. Without `number` they target the repo's newest **blocked**
  pipeline, so a later push does not hide the one waiting for approval. A
  pipeline that is not blocked, or a repo with nothing blocked, is a no-op
  reported `unchanged`.

`pipeline_restart` and `pipeline_cancel` default to the repo's latest pipeline;
pass `number` to target a specific run.

**Infra / health (admin reads):**

- `agent_list`: build agents + health (`online` = contacted in the last 2 min,
  `version`, `capacity`, `lastContact`).
- `queue_info`: server build-queue stats (pending/running/worker counts;
  paused).
- `server_info`: server version + health.

**Scheduled pipelines (cron):**

- `cron_list`: a repo's cron jobs.
- `cron_set`: create-or-update a cron by name (idempotent). `schedule` is a cron
  expression or an `@daily`/`@hourly`/… macro; optional `branch`. `enabled`
  defaults to `true`, which re-enables a cron disabled in the UI; pass
  `enabled=false` to create it disabled or keep it disabled.
- `cron_delete`: delete a cron by name (reversible: re-create with `cron_set`;
  already-absent is a no-op).

**Onboard a repo (one command):**

```bash
# Activate the repo from the forge, mark it trusted (for docker.sock steps),
# and set a 30-minute hang backstop — all idempotently. Method arguments are
# passed as one JSON object via --input (vault references resolve inside swamp).
swamp model method run woodpecker repo_enable \
  --input '{"repo":"octo-org/web","trusted":true,"timeout":30}'
```

- `repo_enable`: activate (if needed) and update settings. `trusted=true` sets
  all three trust capabilities; `trustedNetwork` / `trustedVolumes` /
  `trustedSecurity` override individually (merged with the current values, so a
  partial change keeps the capabilities it does not mention). Also accepts
  `timeout` (minutes), `visibility` (`public|private|internal`),
  `requireApproval` (`none|forks|pull_requests|all_events`),
  `cancelPreviousPipelineEvents` (a list of `push`, `pull_request`,
  `pull_request_closed`, `pull_request_metadata`, `tag`, `release`,
  `deployment`, `cron`, `manual`).
- `repo_update`: same settings on an already-enabled repo.
- `repo_repair`: repair an outdated forge webhook (for example after the server
  URL changes).

**Promote shared credentials to org-level secrets:**

```bash
# One ghcr push token inherited by every repo in the org. The value is a vault
# reference — it resolves inside swamp and never appears on the command line.
swamp model method run woodpecker org_secret_set \
  --input '{"owner":"octo-org","name":"ghcr_token","value":"${{ vault.get(<vault>, woodpecker/ghcr_token) }}","events":["push","tag"]}'
```

- `org_secret_set` / `repo_secret_set`: create-or-update a secret (value
  write-only). `images` restricts the secret to named step images. A new secret
  gets `events: ["push","tag"]` and all images unless the call sets them; an
  existing secret keeps whichever of the two you leave out, so rotating a value
  never extends it to more events or images.

**Reversible lifecycle:** `repo_disable`, `org_secret_delete`,
`repo_secret_delete`, `cron_delete`.

**Action:** `pipeline_trigger` (run a pipeline on a branch).

Every method writes one resource carrying the entity plus an `action`
(`created|unchanged|updated|enabled|disabled|repaired|deleted|triggered|restarted|cancelled|approved|declined|observed`)
and a `timestamp`.

## Data names

swamp keys stored data by model and name, not by spec, so every name starts with
its spec. The key after it is unique within that spec:

| Spec                            | Name                                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------------- |
| `repo`, `repo-status`           | `repo:<repoId>`, `repo-status:<repoId>`                                               |
| `available-repo`                | `available-repo:<owner>%2F<name>`                                                     |
| `forge`, `org`, `agent`         | `forge:<id>`, `org:<id>`, `agent:<id>`                                                |
| `secret`                        | `secret:org:<orgId>:<name>`, `secret:repo:<repoId>:<name>`                            |
| `pipeline`                      | `pipeline:<repoId>:<number>`                                                          |
| `pipeline-step`, `pipeline-log` | `pipeline-step:<repoId>:<number>:<stepId>`, `pipeline-log:<repoId>:<number>:<stepId>` |
| `cron`                          | `cron:<repoId>:<cronName>`                                                            |
| `queue`, `server`               | `queue`, `server`                                                                     |

swamp does not allow `/`, `\`, `..` or NUL in a name, so those are
percent-escaped (`/` is `%2F`, `%` itself is `%25`). For example:

```bash
swamp data query 'modelName == "woodpecker" && name == "repo-status:12"' \
  --select content
```

## Notes

- **No npm dependencies.** Uses the runtime `fetch` only.
- **`trusted` is an object** in Woodpecker v3 (`network` / `volumes` /
  `security`), not a boolean. The `trusted=true` flag sets all three.
- A repo reference is a numeric id or `owner/name`. Enabling resolves the forge
  `forge_remote_id` by name from `/api/user/repos?all=true`. Records always
  store the repo's full name (and secrets the org's name), whichever form you
  pass.
- **On a multi-forge server, onboarding is single-forge.** A Woodpecker user
  record is bound to the forge it authenticated against, so `/api/user/*` (and
  therefore `repo_available` and the activation half of `repo_enable`) only sees
  that forge. No argument changes this; the token determines the forge. Use a
  token created while logged in to the other forge (a second model instance is
  the simplest way), or enable the repo in the UI. `forge_list` shows which
  forges exist and which one the current token belongs to, and `repo_enable`
  includes this in its error instead of only "not found". Everything after
  onboarding (`repo_list`, `repo_get`, `repo_update`, `repo_secret_*`, every
  `pipeline_*`) goes through the admin `/api/repos` endpoints and already works
  across forges with one token.
- **Method arguments go through `--input`** (a `key=value` pair or a JSON
  object), not `--arg`. `${{ vault.get(...) }}` references inside an `--input`
  value resolve inside swamp, so secret values never reach the command line.
- Targets the Woodpecker **v3** REST API.

## Breaking changes

- **Data names are now `<spec>:<key>`** (or `<spec>` alone for `queue` and
  `server`); see [Data names](#data-names). `repo-status` is keyed by repo id
  instead of full name, secrets by org or repo id instead of the name you
  passed, and `pipeline-step` / `pipeline-log` by step id instead of step name
  (step names repeat in matrix pipelines). Records written by earlier versions
  keep their old names and are not migrated.
- **The `trusted*` flags accept only booleans.** From the CLI nothing changes:
  `--input trusted=true` and `false` work, and anything else fails with
  "expected boolean". A JSON input or workflow that passes the strings `"true"`
  / `"false"` should pass real booleans instead. Earlier versions read `"0"`,
  `"False"` and any other non-empty string as true, which on these flags grants
  host network and Docker socket access.
- **`repo_list` and `status_all` cover enabled repos only**, as their
  descriptions always said; disabled repos were included before.
- **The `queue` resource has no `completed` field.** Woodpecker does not report
  one; it was always 0.
- **`requireApproval` takes `all_events`, not `all`.** Woodpecker rejects `all`
  with HTTP 400, so it never worked; `all_events` is the upstream value for
  approving every event.
- **`repo_enable` re-activates a repo that `repo_disable` turned off.** It used
  to report `unchanged` and leave the repo inactive with no webhook; it now
  reports `enabled`.
- **`cron_set` takes an `enabled` argument and always sends it.** On Woodpecker
  v3.13 and later, crons created by earlier versions were stored disabled and
  never ran; a re-run now reports `updated` and turns them on. The default
  `true` also re-enables a cron disabled in the UI, unless you pass
  `enabled=false`. The `cron` resource gains an `enabled` field.
- **`pipeline_wait` stops on `canceled`**, the status Woodpecker v3.14 and later
  give a pipeline cancelled before any workflow started. It used to poll until
  `timeoutSec`.
- **`pipeline_list` returns the pipelines asked for.** With `limit` above 50,
  the second page re-read earlier pipelines and the rest were missing. `limit`
  must now be at least 1.
- **`repo_disable` on a repo that is already disabled reports `unchanged`** and
  sends nothing. It used to send the DELETE again and report `disabled`.
- **`cancelPreviousPipelineEvents` takes only Woodpecker's event names** (listed
  under `repo_enable`). Woodpecker stored any string, so a misspelt event was
  saved and never matched; it now fails before any API call.
- **`pollIntervalSec` and `httpTimeoutMs` must be at least 1.** Zero polled the
  API in a tight loop, and a timeout of zero or less aborted every request.
- **`pipeline_logs` marks a line that is not valid base64** with
  `[undecodable log line]`. It used to leave a blank line.
- **`pipeline_approve` and `pipeline_decline` report `unchanged` for a pipeline
  that is not blocked** instead of failing with HTTP 400. Without `number` they
  target the newest blocked pipeline rather than the newest pipeline; with
  nothing blocked they report the newest pipeline `unchanged`.
- **The `repo` field of `pipeline`, `pipeline-step`, `pipeline-log` and `cron`
  records, and the `owner` field of org `secret` records, hold the full name**
  even when you pass a numeric id. They used to hold the argument as passed, so
  `repo=1` stored `"1"`. Passing an id now costs one extra API call.
- **`httpTimeoutMs` covers the whole response, body included.** A server that
  sent headers and then stalled used to hang the method; it now fails with
  "timed out after N ms".
- **`org_get` takes a numeric org id** as well as a login, as its argument
  always said. It used to look the number up as a login.
- **`pipeline_restart` fails if Woodpecker's answer has no pipeline number**,
  instead of writing the new run over the old run's record.
