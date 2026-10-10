# swamp-extensions

Custom [swamp](https://github.com/systeminit/swamp) extensions by **@thomas**.

## Extensions

| Extension | Manages |
|---|---|
| [`@thomas/arcane`](./extensions/models/arcane/README.md) | An [Arcane](https://getarcane.app) Docker instance through its REST API: GitOps sync, compose projects, swarm stacks, secret/config rotation |
| [`@thomas/forgejo`](./extensions/models/forgejo/README.md) | A [Forgejo](https://forgejo.org) (or Gitea) server: organisations, repositories, GitHub pull-mirrors, pull requests |
| [`@thomas/garage`](./extensions/models/garage/README.md) | A [Garage](https://garagehq.deuxfleurs.fr/) object-store cluster through its Admin API: buckets, access keys, permissions |
| [`@thomas/postgres-admin`](./extensions/models/postgres-admin/README.md) | PostgreSQL databases, roles and grants, without reading or writing table data |
| [`@thomas/stalwart`](./extensions/models/stalwart/README.md) | A [Stalwart](https://stalw.art) mail server: domains, accounts, aliases, groups, roles, certificates |
| [`@thomas/technitium`](./extensions/models/technitium/README.md) | A [Technitium DNS Server](https://technitium.com/dns/): blocking, zones and records, debugging, settings backup |
| [`@thomas/truenas`](./extensions/models/truenas/README.md) | A [TrueNAS SCALE](https://www.truenas.com/) host: app port exposure, NFS/SMB share access |
| [`@thomas/woodpecker`](./extensions/models/woodpecker/README.md) | A [Woodpecker CI](https://woodpecker-ci.org) server: repository onboarding, secrets, pipelines |
| [`@thomas/zitadel`](./extensions/models/zitadel/README.md) | A [Zitadel](https://zitadel.com) instance: OIDC/API applications, service users, roles and grants |

Each extension's README covers installation, configuration and its methods. The
current version is in its `manifest.yaml`.

## Roadmap (`@thomas/arcane`)

What `@thomas/arcane` does **not** cover yet. The deploy and rotation *orchestration*
already ship inside methods (`project_deploy`, `swarm_stack_deploy`,
`secret_rotate`/`config_rotate`), so the gaps below are mostly additional API coverage
rather than new workflows.

**Method sections not yet built:**

- `swarm_node_` — list/get/drain/activate/promote/demote/remove/tasks
- `swarm_cluster_` — status/info/init/join/leave/unlock/tokens
- `container_` — list/get/start/stop/restart/redeploy/update/remove
- `system_` — docker_info, run→compose convert, upgrade_check. (`system_prune` is
  **skipped on purpose**: its required `mode` field is an undocumented bare string
  with no enum, so calling it means guessing a value for a destructive call. The
  per-type prunes cover the same cleanup.)
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
extensions/models/<name>/   one directory per extension: <name>.ts, <name>_test.ts,
                            README.md, LICENSE.txt, manifest.yaml
CLAUDE.md                   repo rules + the locked guardrails & validation policy
README.md                   this file
LICENSE                     MIT
```

This is an initialized swamp repository (`.swamp.yaml`). Extensions are published with
the `swamp extension push` workflow.

## License

[MIT](./LICENSE)
