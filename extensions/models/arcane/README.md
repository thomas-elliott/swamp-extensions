# @thomas/arcane

Management of an [Arcane](https://getarcane.app) Docker instance, fronted entirely
by Arcane's REST API (`X-API-Key` auth). This is an Arcane **management** extension —
GitOps is one supported deployment mode, not the extension's identity.

Every mutation goes through Arcane's API. The only local action is **read-only compose
validation** (`docker compose config`); the extension never SSHes to a host or touches
the Arcane container — it only consumes an API key.

## Installation

```sh
swamp extension pull @thomas/arcane
```

## Configuration

| Global arg | Notes |
|---|---|
| `baseUrl` | Arcane base URL incl. port, e.g. `https://arcane.example.com:8443` |
| `apiKey` | `X-API-Key`. **Supply via vault:** `${{ vault.get(arcane, api_key) }}` (sensitive) |
| `environmentId` | Arcane environment id; `0` = local Docker. Swarm methods need a swarm-manager environment. |
| `skipTlsVerify` | Accept self-signed certs (default `false`) |
| `repository`, `syncs` | Desired GitOps repo connection + sync list, reconciled by `gitops_*` |

## Usage

Define a model instance pointing at your Arcane (the API key comes from a vault —
never inline it):

```yaml
type: '@thomas/arcane'
name: arcane-prod
globalArguments:
  baseUrl: 'https://arcane.example.com'
  apiKey: '${{ vault.get(arcane, api_key) }}'
  environmentId: '0' # 0 = local Docker; a swarm-manager env for swarm_* methods
  skipTlsVerify: false
  syncs: []
```

Then drive it through the CLI:

```sh
# Validate a swarm stack (fail-closed render), deploy it, and poll convergence
swamp model method run arcane-prod swarm_stack_deploy \
  --input '{"name":"unifi","composePath":"./unifi.stack.yml"}'

# Tear it down — re-issues DELETE until Arcane's stored record is gone
swamp model method run arcane-prod swarm_stack_remove --input '{"name":"unifi"}'
```

## Method sections

- **`version`** — read Arcane's version (current + newest available; the endpoint is
  identical on v1.19.x and v2.0.x) — upgrade preflight/post-check.
- **`gitops_*`** — drive Arcane Git Sync: `gitops_repo_list` / `gitops_repo_ensure`,
  `gitops_sync_list` / `gitops_sync_ensure`, `gitops_sync_trigger`, and
  `gitops_sync_status` (fan-out health view: per-sync `lastSyncStatus` /
  `lastSyncError` / `lastSyncCommit` / `nextSyncAt` — how you find a sync that has
  been failing silently on the scheduler).
- **`project_*`** — compose projects. Lifecycle: `project_list`, `project_get`,
  `project_up` / `project_down` / `project_redeploy` / `project_pull` / `project_destroy`.
  Direct (API) authoring: `project_validate`, `project_create`, `project_update`.
  Orchestration: `project_deploy` (validated, mode-aware, rolls back by default).
- **`secret_*` / `config_*`** — swarm secret/config CRUD plus `secret_rotate` /
  `config_rotate` (create-v2 → re-point services → wait converged → remove-v1).
- **`swarm_service_*`** — `swarm_service_list` / `swarm_service_get` /
  `swarm_service_rollback` / `swarm_service_force_update` (bump
  `spec.TaskTemplate.ForceUpdate` to recreate tasks without a config change — e.g.
  restart a service once its DB dependency is ready).
- **`swarm_stack_*`** — full swarm-stack lifecycle: `swarm_stack_list` /
  `swarm_stack_get`, `swarm_stack_validate` (render gate, fail-closed),
  `swarm_stack_deploy` (validate → deploy → poll convergence), `swarm_stack_remove`
  (DELETE then poll `GET → 404`, re-issuing DELETE until Arcane's stored record is
  actually cleared — a single DELETE leaves the record behind),
  and `swarm_stack_tasks` (the deploy **debug view** — per-task `currentState` +
  error, with `onlyProblems` to show just the rejected/failed ones).
- **`volume_*` / `*_prune`** — cleanup: `volume_list`, `volume_remove` (idempotent,
  refuses in-use), `volume_prune`, `network_prune`, `image_prune`. Docker-level —
  work on any environment, not swarm-only.

### Two deploy modes (chosen per project)

- **Direct (API) mode** — `project_create` / `project_update` push compose content to
  Arcane; `project_deploy` validates locally, updates, redeploys, polls health, and
  re-applies the prior content on failure (or tears down a failed first deploy).
- **GitOps mode** — content lives in a git repo pulled by Arcane Git Sync.
  `project_deploy` triggers the sync and redeploys; it refuses inline content (so it
  doesn't fight the sync). Auto git rollback is **not** implemented — on failure it
  reports and leaves the `git revert` to you.

`project_deploy` detects the mode from Arcane's `gitOpsManagedBy` field.

## Validation gate (fail-closed)

There is no Arcane validation endpoint for compose projects, so `project_validate`
(and the validate step inside `project_create` / `project_update` / `project_deploy`)
runs **`docker compose config -q` locally** against the content about to be pushed.
Any non-zero exit aborts the operation — validation never silently passes.

**Requirements & caveats**

- The **docker CLI with the compose v2 plugin** must be installed on the swamp host.
  `docker compose config` does *not* require a running daemon.
- Running the validator uses a subprocess, which trips swamp's safety-analyzer
  subprocess warning (prompted, not blocked).
- **Compose-version skew (accepted risk):** the local `docker compose` version may
  differ from Arcane's deployer, so a file that validates locally could still behave
  differently when Arcane deploys it. The local version is surfaced in the validation
  output; the post-deploy health check + rollback is the backstop.

## Swarm stack deploy

`swarm_stack_deploy` is the swarm analogue of `project_deploy`, against Arcane's
`/swarm/stacks` API:

1. **Validate (fail-closed)** — `POST /swarm/stacks/config/render`. Any render
   error (4xx) throws and aborts *before* anything is deployed. `swarm_stack_validate`
   exposes this step on its own (returns the rendered services/networks/volumes/
   secrets/configs + warnings).
2. **Deploy** — `POST /swarm/stacks` with the compose content (optional `prune` to
   drop services no longer in the file, `envContent` for a `.env`).
3. **Poll convergence** — waits up to `convergeTimeoutSec` (default 180s) for the
   stack's services to reach their target replica counts.

A stack that deploys but **does not converge is left in place** and the method
throws — it is **not** force-removed and **not** auto-rolled-back (guardrail #5).
Inspect with `swarm_stack_tasks` / `swarm_service_list`, then re-deploy or
`swarm_stack_remove`. Each step records an `operation-result`; the stack itself is
recorded as a `swarm-stack` resource.

**Two Arcane API limitations to know when deploying a stack:**

- **No log endpoint exists.** Arcane exposes task *state* + error (which
  `swarm_stack_tasks` surfaces — enough for missing-bind-path, non-zero-exit, and
  placement failures), but **not** a container's stderr. A crash-looping container's
  logs must come from the host (`docker service logs` / a log viewer). The extension
  will not SSH to get them.
- **Stack deploy does not add compose service-name network aliases.** Unlike
  `docker stack deploy`, Arcane-deployed services come up with `aliases=[]`, so
  resolving another service by its short name fails. Declare aliases **explicitly**
  in the compose (`networks.<net>.aliases: [<service-name>]`) — Arcane honors those.

## Swarm rotation notes

- Swarm secrets/configs are **immutable**, so values are rotated, never
  updated in place: `secret_rotate` / `config_rotate` create a new version, re-point
  every referencing service's spec (preserving the mount path), wait for convergence,
  then remove the old object.
- Secret/config **values must come from a vault** — never inline them.
- An in-use object is **never force-removed**; if Docker returns 409 the old object is
  left in place and the conflict is surfaced.
- Swarm methods require `environmentId` to point at a **swarm-manager** environment;
  against a non-swarm/worker environment Arcane returns 409/403.

## Cleanup (volumes & prune)

Docker-level housekeeping via Arcane (works on any environment, not swarm-only):

- `volume_list` includes an `inUse` flag so orphaned volumes are visible.
- `volume_remove` is **idempotent** (a 404 is treated as already-gone). An in-use
  volume is **surfaced, not forced** — Arcane reports in-use as **HTTP 500** (not the
  409 the Docker API uses), so the method matches on the message text as well as the
  status. `force:true` bypasses the in-use guard but is discouraged (risks data loss,
  guardrail #5).
- `volume_prune` removes only **unused anonymous** volumes (Docker's default — it does
  **not** touch named volumes). To remove a specific named volume use `volume_remove`.
- `network_prune` removes networks with no attached containers; `image_prune` removes
  dangling layers by default (`dangling:false` removes all unreferenced images).

**Known gap:** there is no `container_prune` / all-in-one `system_prune` method —
Arcane's `system/prune` requires an undocumented bare-string `mode` field (no enum),
so it isn't wrapped rather than guess into a destructive call. A named volume held by
a *stopped* (not removed) container therefore can't be cleared until that container is
reaped (e.g. swarm task-history rotation); the per-type prunes above cover the rest.
