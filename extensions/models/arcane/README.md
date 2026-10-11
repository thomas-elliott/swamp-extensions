# @thomas/arcane

Manages an [Arcane](https://getarcane.app) Docker instance entirely through
Arcane's REST API (`X-API-Key` auth). GitOps is one of two supported deployment
modes; direct API mode is the other.

Every mutation goes through Arcane's API. The only local action is **read-only
compose validation** (`docker compose config`); the extension never SSHes to a
host or touches the Arcane container; it only uses an API key.

## Installation

```sh
swamp extension pull @thomas/arcane
```

## Configuration

| Global arg            | Notes                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------ |
| `baseUrl`             | Arcane base URL incl. port, e.g. `https://arcane.example.com:8443`                         |
| `apiKey`              | `X-API-Key`. **Supply via vault:** `${{ vault.get(arcane, api_key) }}` (sensitive)         |
| `environmentId`       | Arcane environment id; `0` = local Docker. Swarm methods need a swarm-manager environment. |
| `skipTlsVerify`       | Accept self-signed certs (default `false`)                                                 |
| `repository`, `syncs` | Desired GitOps repo connection + sync list, reconciled by `gitops_*`                       |

## Usage

Define a model instance pointing at your Arcane (read the API key from a vault;
never inline it):

```yaml
type: "@thomas/arcane"
name: arcane-prod
globalArguments:
  baseUrl: "https://arcane.example.com"
  apiKey: "${{ vault.get(arcane, api_key) }}"
  environmentId: "0" # 0 = local Docker; a swarm-manager env for swarm_* methods
  skipTlsVerify: false
  syncs: []
```

Then run methods through the CLI:

```sh
# Validate a swarm stack (fail-closed render), deploy it, and poll convergence
swamp model method run arcane-prod swarm_stack_deploy \
  --input '{"name":"unifi","composePath":"./unifi.stack.yml"}'

# Tear it down — re-issues DELETE until Arcane's stored record is gone
swamp model method run arcane-prod swarm_stack_remove --input '{"name":"unifi"}'
```

## Method sections

- **`version`** — read Arcane's version (current + newest available). Use it
  before and after an upgrade.
- **`gitops_*`** — drive Arcane Git Sync: `gitops_repo_list` /
  `gitops_repo_ensure`, `gitops_sync_list` / `gitops_sync_ensure`,
  `gitops_sync_trigger`, and `gitops_sync_status` (fan-out health view: per-sync
  `lastSyncStatus` / `lastSyncError` / `lastSyncCommit` / `nextSyncAt`; use it
  to find a sync whose scheduled runs are failing without anyone noticing).
- **`project_*`** — compose projects. Lifecycle: `project_list`, `project_get`,
  `project_up` / `project_down` / `project_redeploy` / `project_restart` /
  `project_pull` / `project_destroy`. `project_redeploy` is pull + compose up,
  which leaves an unchanged container running; `project_restart` restarts the
  containers in place (it does not start a project that is down, or pick up
  compose changes). Direct (API) authoring: `project_validate`,
  `project_create`, `project_update`. Orchestration: `project_deploy`
  (validated, mode-aware, rolls back by default).
- **`secret_*` / `config_*`** — swarm secret/config CRUD plus `secret_rotate` /
  `config_rotate` (create-v2 → re-point services → wait converged → remove-v1).
- **`swarm_service_*`** — `swarm_service_list` / `swarm_service_get` /
  `swarm_service_rollback` / `swarm_service_force_update` (bump
  `spec.TaskTemplate.ForceUpdate` to recreate tasks without a config change,
  e.g. to restart a service once its DB dependency is ready).
- **`swarm_stack_*`** — full swarm-stack lifecycle: `swarm_stack_list` /
  `swarm_stack_get`, `swarm_stack_validate` (render gate, fail-closed),
  `swarm_stack_deploy` (validate → deploy → poll convergence),
  `swarm_stack_remove` (DELETE then poll `GET → 404`, re-issuing DELETE until
  Arcane's stored record is cleared, because the first DELETE can answer 404
  with the record still there), and `swarm_stack_tasks` (the deploy **debug
  view** — per-task `currentState` + error, with `onlyProblems` to show just the
  rejected/failed ones).
- **`volume_*` / `*_prune`** — cleanup: `volume_list`, `volume_remove`
  (idempotent, refuses in-use), `volume_prune`, `network_prune`, `image_prune`.
  Docker-level, so they work on any environment, not swarm-only.

### Two deploy modes (chosen per project)

- **Direct (API) mode** — `project_create` / `project_update` push compose
  content to Arcane; `project_deploy` validates locally, updates, redeploys,
  polls health, and re-applies the prior content on failure (or tears down a
  failed first deploy).
- **GitOps mode** — content lives in a git repo pulled by Arcane Git Sync.
  `project_deploy` triggers the sync and redeploys; it refuses inline content,
  because in this mode the content comes from git through the sync. Auto git
  rollback is **not** implemented; on failure it reports the error and leaves
  the `git revert` to you.

`project_deploy` detects the mode from Arcane's `gitOpsManagedBy` field.

In both modes, `healthTimeoutSec` (default 300) covers the redeploy and the
health wait together. Healthy means status `running`, every service running, and
no healthcheck reporting `unhealthy` or still `starting`. Arcane keeps running a
redeploy after the call gives up, so when the redeploy runs out of time, its
connection breaks, or its response ends without a done or error line,
`project_deploy` does not roll back on top of it: it fails and leaves the
project for you to check in Arcane. An HTTP error or an error line from Arcane
is a definite failure and is rolled back.

Swarm methods need Arcane to see the environment as swarm-enabled. Arcane stores
that flag and refreshes it only at startup, so after `docker swarm init` outside
Arcane, restart Arcane before using them.

## Validation gate (fail-closed)

There is no Arcane validation endpoint for compose projects, so
`project_validate` (and the validate step inside `project_create` /
`project_update` / `project_deploy`) runs **`docker compose config -q` locally**
against the content about to be pushed. Any non-zero exit aborts the operation —
validation never silently passes.

**Requirements & caveats**

- The **docker CLI with the compose v2 plugin** must be installed on the swamp
  host. `docker compose config` does _not_ require a running daemon.
- Running the validator uses a subprocess, which trips swamp's safety-analyzer
  subprocess warning (prompted, not blocked).
- **Compose-version skew (accepted risk):** the local `docker compose` version
  may differ from Arcane's deployer, so a file that validates locally could
  still behave differently when Arcane deploys it. The local version is surfaced
  in the validation output, and the post-deploy health check and rollback are
  the remaining safeguard.

## Swarm stack deploy

`swarm_stack_deploy` is the swarm equivalent of `project_deploy`, against
Arcane's `/swarm/stacks` API:

1. **Validate (fail-closed)** — `POST /swarm/stacks/config/render`. Any render
   error (4xx) throws and aborts _before_ anything is deployed.
   `swarm_stack_validate` exposes this step on its own (returns the rendered
   services/networks/volumes/ secrets/configs + warnings).
2. **Deploy** — `POST /swarm/stacks` with the compose content (optional `prune`
   to drop services no longer in the file, `envContent` for a `.env`).
3. **Poll convergence** — waits up to `convergeTimeoutSec` (default 180s) for
   the stack's services to reach their target replica counts.

A stack that deploys but **does not converge is left in place** and the method
throws. It is **not** force-removed and **not** auto-rolled-back. Inspect with
`swarm_stack_tasks` / `swarm_service_list`, then re-deploy or
`swarm_stack_remove`. Each step records an `operation-result`; the stack itself
is recorded as a `swarm-stack` resource.

**Two Arcane API limitations to know when deploying a stack:**

- **No log endpoint exists.** Arcane exposes task _state_ + error (which
  `swarm_stack_tasks` returns; that is enough to diagnose missing-bind-path,
  non-zero-exit, and placement failures), but **not** a container's stderr. A
  crash-looping container's logs must come from the host (`docker service logs`
  / a log viewer). The extension will not SSH to get them.
- **Stack deploy does not add compose service-name network aliases.** Unlike
  `docker stack deploy`, Arcane-deployed services come up with `aliases=[]`, so
  resolving another service by its short name fails. Declare aliases
  **explicitly** in the compose (`networks.<net>.aliases: [<service-name>]`);
  Arcane applies those.

## Swarm rotation notes

- Swarm secrets/configs are **immutable**, so values are rotated, never updated
  in place: `secret_rotate` / `config_rotate` create a new version, re-point
  every referencing service's spec (preserving the mount path), wait for
  convergence, then remove the old object.
- Secret/config **values must come from a vault** — never inline them.
- An in-use object is **never force-removed**; if Docker returns 409 the old
  object is left in place and the conflict is surfaced.
- Swarm methods require `environmentId` to point at a **swarm-manager**
  environment; against a non-swarm/worker environment Arcane returns 409/403.

## Cleanup (volumes & prune)

Docker-level housekeeping via Arcane (works on any environment, not swarm-only):

- `volume_list` includes an `inUse` flag so orphaned volumes are visible.
- `volume_remove` is **idempotent**: a volume that is already gone counts as
  removed. An in-use volume is **reported and left in place**. Arcane returns
  every delete failure as **HTTP 500** with Docker's message, so the method
  matches on the message text. `force:true` bypasses Docker's in-use check but
  risks data loss.
- `volume_prune` removes only **unused anonymous** volumes (Docker's default; it
  does **not** touch named volumes). To remove a specific named volume use
  `volume_remove`.
- `network_prune` removes networks with no attached containers; `image_prune`
  removes dangling layers by default (`dangling:false` removes all unreferenced
  images).

**Known gap:** there is no `container_prune` / all-in-one `system_prune` method.
Arcane's `system/prune` requires an undocumented bare-string `mode` field (no
enum), and the extension does not call a destructive endpoint with a guessed
value. A named volume held by a _stopped_ (not removed) container therefore
can't be cleared until that container is removed (e.g. swarm task-history
rotation); the per-type prunes above cover the rest.

## Breaking changes

- **`project_create` and `project_update` no longer take `validate`.** Both
  always validate the compose file locally and stop if validation fails or
  cannot run. A `validate: false` still passed is ignored.
- **`authType` accepts `none`, `http` or `ssh`, and `targetType` `project` or
  `swarm_stack`**, the values Arcane documents. Arcane stored the old `token`
  and `swarm` without checking them, then ran a `token` repository without
  authentication and a `swarm` sync as a compose project. The model upgrade
  rewrites them to `http` and `project` in existing definitions.
- **Time arguments must be positive**, and `healthTimeoutSec` at most a day.
  `healthTimeoutSec: 0` used to switch the timeout off.
- **`healthTimeoutSec` defaults to 300** (was 120), since it now covers the
  image pull as well as the health wait.

## Fixes

- **`project_create`, and `project_deploy` on a first deploy, send a multipart
  form.** Arcane's project-create endpoint takes its fields as
  `multipart/form-data` (a `project` field holding the JSON, and a `manifest`
  field listing extra files to upload, here none). It rejects a JSON body with
  422, so creating a project through the API failed before this change.
- **`project_deploy` waits out `starting` healthchecks.** A container still at
  `health: starting` used to count as healthy, so one crash-looping behind a
  slow healthcheck deployed as healthy. Deploys of services with slow
  healthchecks now take until those checks pass.
- **`project_deploy`'s `healthTimeoutSec` bounds the redeploy call.** The
  redeploy used to get a fixed limit of its own, so a compose `depends_on` that
  never became healthy held the deploy (and the model lock) past the timeout.
- **Streamed operations must finish.** Arcane answers up, pull and redeploy with
  200 at once and ends the body with a done line or an error line (an image that
  can't be pulled and isn't cached, say). `project_deploy` used to ignore the
  body and could report the old containers as a healthy deploy; it and
  `project_up`/`project_pull`/`project_redeploy` now fail on an error line or a
  body cut short.
- **A redeploy with an unknown outcome is not rolled back.** After a timeout, a
  broken connection or a cut-short response, Arcane may still be running it, and
  a rollback would race it.
- **Request time limits cover the whole request.** They used to reset whenever
  data arrived, so a streamed operation printing progress could run past them.
  Long operations get 30 minutes, more than Arcane's own limits.
- **New `project_restart`**, using Arcane's restart, since `project_redeploy`
  does not restart an unchanged project.
