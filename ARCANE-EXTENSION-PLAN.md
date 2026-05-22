# Arcane Extension Family — Plan & Guardrails

**Status:** design (2026-05-21). `@thomas/arcane` core (gitops-sync setup + compose
project lifecycle) is built and validated live on tylo; the broader Arcane-management
surface below is planned.

**Canonical home (deferred):** the public `swamp-extensions` GitHub repo. Until
that exists, code lives in `~/Projects/swamp/extensions/`. When `swamp-extensions`
is created, the **Non-negotiable guardrails** below MUST be copied into that
repo's `CLAUDE.md` "Rules" section so they bind every coding agent.

---

## 1. Architecture (LOCKED — do not relitigate without the user)

- **Identity: this is an Arcane *management* extension, NOT a "gitops extension".**
  Its job is to provision/configure an Arcane instance and manage its projects and
  Docker/swarm surface through the API. GitOps is **one supported deployment mode**,
  not the extension's identity — it must be equally usable for non-gitops projects.
- **One extension family, fronted entirely by Arcane's REST API.** A single
  `@thomas/arcane` model type with method sections (prefixes), plus workflows and
  reports in the same repo. Auth = `X-API-Key` from vault; the extension only ever
  *consumes* a key.
- **Arcane is the single control plane.** Every operation goes through Arcane's
  HTTP API. We accept the tradeoff that operations are unavailable when Arcane is
  down — that is intentional, not a problem to "fix" by adding a side channel.
- **No runtime docker extension, and arcane depends on none.** `@local/docker-swarm`
  (direct docker CLI over SSH) may persist as an *unrelated* migration-teardown
  tool; `@thomas/arcane` neither imports nor calls it.
- **No compose/stack schema model.** We do NOT model docker-compose / swarm-stack
  file *contents* as swamp data. Compose lives either in a gitops repo (gitops mode)
  or is pushed straight to Arcane (direct mode); either way the schema is owned by
  docker and validated by external tools (§3).
- **Two deployment modes, the user's choice per project:**
  - **Direct (API) mode** — compose content managed through Arcane's project API
    (`create`/`update`/`redeploy`); Arcane stores it, no external git.
  - **GitOps mode** — compose in a git repo, pulled via Arcane Git Sync; the
    extension manages the repo connection + syncs and *triggers* syncs.
  The extension is mode-aware: deploy and rollback follow whichever mode a project
  uses. GitOps-authoring helpers (write compose into a local repo, commit, push) are
  **optional and preference-gated**, never the default path.

## 2. Non-negotiable guardrails (agent-binding rules)

> A coding agent hitting a roadblock will be tempted to work around these. Do NOT.
> If a rule blocks the task, STOP and surface the gap to the user — do not bypass.

1. **Never bypass Arcane for a mutation.** Do not shell out to `docker`, SSH to a
   host, or hit the docker socket to perform an operation Arcane should perform. If
   Arcane lacks the endpoint, that is a documented gap (§3/§7), not a license to go
   around it. (Read-only *validation* via external tools is allowed — see §3.)
2. **Validation before deploy is mandatory and FAILS CLOSED.** If the validation
   path for a target exists, it MUST run and pass before deploy. If the validator
   is unavailable/errors, the deploy MUST NOT proceed. Never disable, skip, or
   stub validation to make a deploy succeed.
3. **Never swallow an Arcane or validator error to proceed.** Surface it. A failed
   `config render`, a 4xx, or a non-zero `docker compose config` aborts the action.
4. **Never reimplement the compose/stack schema** in TypeScript. Delegate
   validation to the owning tools (§3). No hand-rolled compose parsers/validators.
5. **Respect Docker's in-use constraints; never force around them.** Do not
   force-remove a secret/config/network/volume that is in use to make a step pass.
   Use the rotation/teardown *workflow* ordering instead (§6).
6. **Never weaken safety to force a deploy through** — no removing healthchecks,
   no `--force` to skip validation, no reducing replicas to dodge a constraint.
7. **Secrets:** only via vault references; never inline a secret value in code,
   model instance, manifest, or committed file. Mark sensitive schema fields.
8. **Don't add fallbacks for impossible states or "temporary" bypasses.** If a
   capability isn't supported yet, leave the gap explicit; don't paper over it.
9. **Extension I/O boundary — no SSH, no remote sockets to managed hosts.** Allowed
   outbound I/O: (a) Arcane's HTTP API; (b) LOCAL read-only validation subprocesses
   (`docker compose config`) against the local gitops working copy; (c) — ONLY when
   the user opts into the gitops-authoring helpers — local git on the gitops working
   copy + `git push` to the git remote. NEVER SSH, hit a remote docker socket, or
   otherwise reach a *managed host* directly — even for validation. If a check would
   require reaching a server, it is an uncoverable gap (§3), not a reason to add SSH.

## 3. Validation policy & honest gap matrix

Goal: catch errors **before** deploy, because the deploy → fail → fix loop is slow
and the failure cost is real (downtime, data loss). We delegate to the tools that
own validation, cover as much as we honestly can, and **name the gaps** rather than
pretend they're covered.

### Validation layers (run in order; all must pass — fail closed)

| Layer | Compose project | Swarm stack |
|---|---|---|
| **Syntax / schema / interpolation** | `docker compose -f <file> config -q` | Arcane `POST /swarm/stacks/config/render` |
| **External-ref existence** (networks/volumes/secrets/configs declared `external`) | cross-check refs vs Arcane `list` endpoints for the target environment | same |
| **Image resolvable** (optional, costly) | Arcane image check / `docker manifest inspect` | same |
| **Post-deploy health** | healthcheck poll in the deploy workflow + rollback | service convergence + rollback |

### Known gaps (cannot validate pre-deploy — accept + mitigate)

| Gap | Why | Mitigation |
|---|---|---|
| **No Arcane validator for compose projects** | Arcane exposes render/validate only for *swarm* stacks | use `docker compose config` as the external validator; this is the primary compose gap-filler, not a "bypass" |
| **Compose-spec version skew** | local validator's compose version differs from Arcane's deployer (we validate locally, by design — guardrail #9) | ACCEPTED RISK (see callout above): surface the local version, pin/document it, lean on post-deploy health + rollback |
| **Runtime conflicts** (port clashes, resource limits) | only surface at deploy | caught at deploy; keep blast radius small (one project at a time) |
| **Secret/config in-use removal (409)** | runtime constraint | rotation workflow ordering (§6) never deletes an in-use object |
| **Actual application health** | can't know until it runs | post-deploy healthcheck verify + automatic rollback in the deploy workflow |
| **External-ref existence for non-Arcane-visible resources** | Arcane only sees its environment | cross-check is best-effort; document that host-level resources outside Arcane's view aren't checked |

**Where compose validation runs (DECIDED): locally only.** `docker compose config`
(and any `docker manifest inspect`) runs on the swamp host, against the **local
gitops working copy** — i.e. it validates what you are about to commit/push, which
is the correct pre-deploy gate. This is read-only validation, not a control-plane
mutation, so it does not violate guardrail #1. It must NOT run via SSH on a server
(guardrail #9) — keeping this extension SSH-free is a deliberate constraint.

> **⚠ ACCEPTED RISK — compose-version skew.** The local `docker compose` may be a
> different version from Arcane's deployer, so a file that validates locally could
> still behave differently when Arcane deploys it (or vice-versa). We accept this
> rather than SSH to the server. Mitigations: surface the local compose version in
> the validation output so divergence is visible; pin/document a target version;
> the post-deploy health check + rollback (§6) is the backstop for anything the
> local validator misses. This risk MUST stay visible — do not silently "fix" it
> by adding server-side validation.

## 4. Capability sections — `@thomas/arcane` model methods (PROPOSED, iterating)

One model type; method-name prefixes give visual sections in `describe`. `[built]`
marks what exists today (may be renamed to the prefix convention).

- **project_** (compose, **direct API mode**) — `project_list` `[built]`,
  `project_up/down/redeploy/destroy/pull` `[built]`, `project_create`/`project_update`
  (push compose content via API), `project_validate` (delegated, §3), `project_build`
- **gitops_** (**gitops mode** — set up + drive Arcane Git Sync) —
  `gitops_repo_ensure` `[built: ensure_repository]`, `gitops_repo_list` `[built]`,
  `gitops_sync_ensure` `[built: ensure_syncs]`, `gitops_sync_list` `[built]`,
  `gitops_sync_trigger` `[built: sync]`
- **gitops_author_** (OPTIONAL, preference-gated, touches local git — guardrail #9c) —
  `gitops_author_write` (render a stack into the local gitops repo),
  `gitops_author_commit_push`
- **swarm_stack_** — `list`, `get`, `validate` (config/render), `deploy`, `remove`, `source_get/update`
- **swarm_service_** — `list`, `get`, `scale`, `rollback`, `force_update`, `tasks`
- **swarm_node_** — `list`, `get`, `drain`, `activate`, `promote`, `demote`, `remove`, `tasks`
- **swarm_cluster_** — `status`, `info`, `init`, `join`, `leave`, `unlock`, `tokens`
- **secret_** (swarm) — `list`, `get`, `create`, `remove`  (rotation = workflow §6)
- **config_** (swarm) — `list`, `get`, `create`, `remove`  (rotation = workflow §6)
- **network_** — `list`, `get`, `create`, `remove`, `prune`, `topology`
- **volume_** — `list`, `get`, `create`, `remove`, `prune`, `backup`, `restore`, `browse`
- **image_** — `list`, `pull`, `build`, `remove`, `prune`, `update_check`, `vuln_scan`
- **container_** — `list`, `get`, `start`, `stop`, `restart`, `redeploy`, `update`, `remove`
- **system_** — `prune`, `docker_info`, `convert` (docker run→compose), `upgrade_check`
- **admin_** — `health`, `version`, `update`, `notifications_*`, `users_*`, `apikeys_*`, `registries_*`, `settings_*`
- **env_** (fleet) — `list`, `create`, `pair`, `remove`, `test`

**DECIDED: one model type, sectioned by method prefix.** No splitting `swarm_*` /
`admin_*` into separate types — single connection config, one place to look.

## 5. Reports (read-only analysis pipelines)

- **arcane_security** — vulnerabilities + image-update status + outdated images
- **arcane_health** — per-environment health / load / error summary (dashboard + events)
- **arcane_audit** — event-log / who-did-what summary

## 6. Workflows (orchestration where ordering & verification matter)

- **deploy_project** (validated, **mode-aware**) — validate (§3, fail closed) →
  capture prior state → apply (gitops mode: optional author push/commit →
  `gitops_sync_trigger` → `project_redeploy`; direct mode: `project_update` →
  `project_redeploy`) → poll healthy → **roll back by default on failure** (override
  `rollback: false` to stop-and-report). **Rollback follows the mode:** gitops-managed
  → gitops rollback (revert to prior commit → re-sync → redeploy); direct-managed →
  re-apply the prior compose via the API; first deploy with no prior state → tear down
  the half-up project. In gitops mode the revert+push happens only if the user opted
  into the authoring helpers (guardrail #9c); otherwise the workflow reports and leaves
  the `git revert` to the user.
- **deploy_swarm_stack** (validated) — `swarm_stack_validate` → deploy → converge → rollback
- **rotate_swarm_secret** — create v2 → update referencing services to mount v2 →
  wait healthy → remove v1 (never deletes an in-use secret)
- **rotate_swarm_config** — same shape for configs
- **rotate_compose_secret** (gitops-backed) — write new secret file in gitops repo →
  commit → push → `gitops_sync_trigger` → `project_redeploy` → verify → remove old file

## 7. Build phases (priority — migration-relevant first)

1. **[done]** gitops_ + project_ lifecycle.
2. **project_validate + project_create/update (direct mode) + deploy_project
   workflow** — closes the validation gap for the compose migration target and gives
   the non-gitops path. Highest priority given §3.
3. **secret_/config_ + rotation workflows** — the high-value orchestrations.
4. **swarm_*** — coverage for laythe's existing swarm + teardown.
5. **network_/volume_/image_/container_/system_** — day-2 ops.
6. **admin_ + reports**.

## 8. Open decisions

Resolved 2026-05-21: **identity = Arcane management, gitops is one mode** (§1);
**two deploy modes** (direct API / gitops), user's choice per project; **one model
type** (§4); **validation runs locally**, never via SSH (§3, guardrail #9),
version-skew accepted as a visible risk; **rollback follows the mode** — gitops
rollback for gitops-managed, project-level re-apply for direct-managed, tear-down for
a failed first deploy (§6); **`deploy_project` rolls back by default** (`rollback:
false` to override).

Still open:

- **Subprocess at push time.** Running `docker compose config` uses a subprocess,
  which trips the safety analyzer's `Deno.Command` *warning* (prompted, not blocked)
  and is worth a README note for anyone publishing the extension.
- **Prior-state capture for rollback.** How `deploy_project` snapshots the prior
  compose/commit before redeploy so it can re-apply on failure (per mode).
