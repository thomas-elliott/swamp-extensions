# swamp-extensions

Custom [swamp](https://github.com/systeminit/swamp) extensions by **@thomas**.

## Extensions

| Extension | Type | Status | Docs |
|---|---|---|---|
| [`@thomas/arcane`](./extensions/models/arcane/README.md) | model | Built, live-validated, publish-ready (`2026.05.22.1`, 41 methods) | [README](./extensions/models/arcane/README.md) |
| [`@thomas/technitium`](./extensions/models/technitium/README.md) | model | Built, unit-tested; pending live smoke test (`2026.05.23.1`, 28 methods) | [README](./extensions/models/technitium/README.md) |

`@thomas/arcane` manages an [Arcane](https://getarcane.app) Docker instance entirely through Arcane's REST API.
See its [README](./extensions/models/arcane/README.md) for installation, configuration, and every method section.

`@thomas/technitium` manages a [Technitium DNS Server](https://technitium.com/dns/) through its HTTP API —
built-in blocking, zone/record lifecycle, allow/block lists, DNS-client + query-log debugging, cache, and
settings backup/restore. See its [README](./extensions/models/technitium/README.md).

## Roadmap

What `@thomas/arcane` does **not** cover yet. The deploy and rotation *orchestration*
already ship inside methods (`project_deploy`, `swarm_stack_deploy`,
`secret_rotate`/`config_rotate`), so the gaps below are mostly additional API coverage
rather than new workflows.

**Method sections not yet built:**

- `swarm_node_` — list/get/drain/activate/promote/demote/remove/tasks
- `swarm_cluster_` — status/info/init/join/leave/unlock/tokens
- `container_` — list/get/start/stop/restart/redeploy/update/remove
- `system_` — docker_info, run→compose convert, upgrade_check. (`system_prune` is
  **deliberately skipped**: its required `mode` field is an undocumented bare string
  with no enum — the per-type prunes cover it without guessing into a destructive call.)
- `admin_` — health/version/update, notifications, users, apikeys, registries, settings
- `env_` (fleet) — list/create/pair/remove/test additional Arcane environments
- `gitops_author_` — write a rendered stack into the local gitops repo, commit, push
  (the optional, preference-gated authoring path)
- Extra ops on existing sections: `project_build`; `network_` create/topology;
  `volume_` create/backup/restore/browse; `image_` build/vuln_scan/update_check

**Reports (read-only analysis pipelines), none built:**

- `arcane_security` — vulnerabilities + image-update status + outdated images
- `arcane_health` — per-environment health/load/error summary
- `arcane_audit` — event-log / who-did-what summary

**Workflows:**

- `rotate_compose_secret` (gitops-backed) — write a new secret file into the gitops
  repo → commit → push → trigger sync → redeploy → verify → remove the old file. Needs
  the `gitops_author_` helpers above.

**Known API limitations (documented, not roadmap):** Arcane exposes no
container/service **log** endpoint (crash stderr must come from the host); and swarm
stack deploy does not add compose service-name network aliases (declare them explicitly
in the compose). Both are detailed in the extension README.

## Repository layout

```
extensions/models/arcane/   @thomas/arcane (arcane.ts, arcane_test.ts, README.md,
                            LICENSE.txt, manifest.yaml)
CLAUDE.md                   repo rules + the locked guardrails & validation policy
README.md                   this file
LICENSE                     MIT
```

This is an initialized swamp repository (`.swamp.yaml`). Extensions are published with
the `swamp extension push` workflow.

## License

[MIT](./LICENSE)
