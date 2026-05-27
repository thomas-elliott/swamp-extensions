<!-- BEGIN swamp managed section - DO NOT EDIT -->
# Project

This repository is managed with [swamp](https://github.com/systeminit/swamp).

## Rules

1. **Search before you build.** When automating AWS, APIs, or any external service: (a) search local types with `swamp model type search <query>`, (b) search community extensions with `swamp extension search <query>`, (c) if a community extension exists, install it with `swamp extension pull <package>` instead of building from scratch, (d) only create a custom extension model in `extensions/models/` if nothing exists. Use the `swamp-extension` skill for guidance. The `command/shell` model is ONLY for ad-hoc one-off shell commands, NEVER for wrapping CLI tools or building integrations.
2. **Extend, don't be clever.** When a model covers the domain but lacks the method you need, extend it with `export const extension` — don't bypass it with shell scripts, CLI tools, or multi-step hacks. One method, one purpose. Use `swamp model type describe <type> --json` to check available methods.
3. **Use the data model.** Once data exists in a model (via `lookup`, `start`, `sync`, etc.), reference it with CEL expressions. Don't re-fetch data that's already available.
4. **CEL expressions everywhere.** Wire models together with CEL expressions. Always prefer `data.latest("<name>", "<dataName>").attributes.<field>` over the deprecated `model.<name>.resource.<spec>.<instance>.attributes.<field>` pattern.
5. **Verify before destructive operations.** Always `swamp model get <name> --json` and verify resource IDs before running delete/stop/destroy methods.
6. **Prefer fan-out methods over loops.** When operating on multiple targets, use a single method that handles all targets internally (factory pattern) rather than looping N separate `swamp model method run` calls against the same model. Multiple parallel calls against the same model contend on the per-model lock, causing timeouts. A single fan-out method acquires the lock once and produces all outputs in one execution. Check `swamp model type describe` for methods that accept filters or produce multiple outputs.
7. **Extension npm deps are bundled, not lockfile-tracked.** Swamp's bundler inlines all npm packages (except zod) into extension bundles at bundle time. `deno.lock` and `package.json` do NOT cover extension model dependencies — this is by design. Always pin explicit versions in `npm:` import specifiers (e.g., `npm:lodash-es@4.17.21`).
8. **Reports for reusable data pipelines.** When the task involves building a repeatable pipeline to transform, aggregate, or analyze model output (security reports, cost analysis, compliance checks, summaries), create a report extension. Use the `swamp-report` skill for guidance.

## Skills

**IMPORTANT:** Always load swamp skills, even when in plan mode. The skills provide
essential context for working with this repository.

- `swamp-getting-started` - Interactive onboarding for new swamp users
- `swamp-model` - Work with swamp models (creating, editing, validating)
- `swamp-workflow` - Work with workflows (creating, editing, running)
- `swamp-vault` - Manage secrets and credentials
- `swamp-data` - Manage model data lifecycle and query with CEL
- `swamp-report` - Run and configure reports for models and workflows
- `swamp-repo` - Repository management
- `swamp-extension` - Create custom extensions (models, vaults, drivers, datastores, reports)
- `swamp-extension-publish` - Publish extensions to the registry
- `swamp-issue` - Submit bug reports and feature requests
- `swamp-troubleshooting` - Diagnose swamp problems and verify swamp's health

## Getting Started

**IMPORTANT:** At the start of every conversation, run
`swamp model search --json`. If no models are returned (empty result), you MUST
immediately invoke the `swamp-getting-started` skill before doing anything else.
This walks new users through an interactive onboarding tutorial.

If models already exist, start by using the `swamp-model` skill to work with
swamp models.

## Commands

Use `swamp --help` to see available commands. For a machine-readable JSON
schema of the CLI (commands, options, arguments) intended for agent
consumption, run `swamp help [<command>...]` — e.g. `swamp help` returns
the full tree, and `swamp help model method run` scopes to a subtree.
<!-- END swamp managed section -->

# swamp-extensions — repository rules

This repository is the canonical home of the **`@thomas/arcane`** extension family
(an Arcane Docker *management* extension). The design rationale and roadmap live in
[`README.md`](./README.md), and the extension's own docs in
[`extensions/models/arcane/README.md`](./extensions/models/arcane/README.md) — read
them before extending arcane. The rules below are **LOCKED**: a coding agent hitting a
roadblock will be tempted to work around them. Do NOT. If a rule blocks the task, STOP
and surface the gap to the user — do not bypass.

## Non-negotiable guardrails (`@thomas/arcane`)

1. **Never bypass Arcane for a mutation.** Do not shell out to `docker`, SSH to a
   host, or hit the docker socket to perform an operation Arcane should perform. A
   missing Arcane endpoint is a documented gap, not a license to go around it.
   (Read-only *validation* via external tools is allowed — see the validation policy.)
2. **Validation before deploy is mandatory and FAILS CLOSED.** If a validation path
   exists for a target it MUST run and pass before deploy. If the validator is
   unavailable/errors, the deploy MUST NOT proceed. Never disable, skip, or stub
   validation to make a deploy succeed.
3. **Never swallow an Arcane or validator error to proceed.** Surface it — a failed
   `config render`, a 4xx, or a non-zero `docker compose config` aborts the action.
4. **Never reimplement the compose/stack schema** in TypeScript. Delegate validation
   to the owning tools. No hand-rolled compose parsers/validators.
5. **Respect Docker's in-use constraints; never force around them.** Do not
   force-remove a secret/config/network/volume that is in use to make a step pass.
   Use the rotation/teardown workflow ordering instead.
6. **Never weaken safety to force a deploy through** — no removing healthchecks, no
   `--force` to skip validation, no reducing replicas to dodge a constraint.
7. **Secrets only via vault references.** Never inline a secret value in code, a model
   instance, the manifest, or a committed file. Mark sensitive schema fields.
8. **Don't add fallbacks for impossible states or "temporary" bypasses.** If a
   capability isn't supported yet, leave the gap explicit; don't paper over it.
9. **Extension I/O boundary — no SSH, no remote sockets to managed hosts.** Allowed
   outbound I/O: (a) Arcane's HTTP API; (b) LOCAL read-only validation subprocesses
   (`docker compose config`) against the local working copy; (c) — ONLY when the user
   opts into the gitops-authoring helpers — local git + `git push` to the git remote.
   NEVER SSH or reach a managed host directly, even for validation. If a check would
   require reaching a server, it is an uncoverable gap, not a reason to add SSH.

## Validation policy

Catch errors **before** deploy (the deploy → fail → fix loop is slow and the failure
cost is real). Delegate to the tools that own validation, cover what we honestly can,
and **name the gaps** rather than pretend they're covered. Compose validation runs
**locally only** (`docker compose config` against the local working copy) — never via
SSH. The local compose version may differ from Arcane's deployer (**accepted risk**):
surface the local version, lean on post-deploy health + rollback as the backstop, and
keep this risk visible — do not "fix" it by adding server-side validation.

## Authoring conventions (all extensions in this repo)

These keep `swamp extension quality` at **14/14 (100%)** — proven on `@thomas/arcane`,
`@thomas/technitium`, and `@thomas/postgres-admin`. Apply them to every new extension.

1. **zod + `fast-check` — never leak a `z.infer` type onto the public API.** The
   `fast-check` ("no slow types") factor FAILS if an **exported** symbol references a
   `z.infer<typeof Schema>` alias (zod-inferred types are "slow types"). Pattern: keep
   `type GlobalArgsT = z.infer<typeof GlobalArgs>` **unexported**; the EXPORTED test-seam
   function type takes the resolved args as the loose **`Json` (`Record<string,unknown>`)**,
   while a private dispatcher + the real implementation keep the precise `g: GlobalArgsT`
   (which widens to `Json` at the call site, so no cast). See `ArcaneFn` (arcane), `TechFn`
   (technitium), `ConnectFn` (postgres-admin). Symptom if you slip: `deno doc --lint` →
   `private-type-ref: public type 'X' references private type ...`.
2. **Untyped npm deps break `deno doc` — add a `@ts-types` directive.** A package that
   ships no types (e.g. `pg`) makes the quality scorer's `deno doc --json` HARD-FAIL with
   `Could not resolve 'npm:<pkg>'`. Fix: put `// @ts-types="npm:@types/<pkg>@<ver>"`
   directly above the `import`. It resolves types for both `deno doc` and `deno check`; the
   `@types/*` package is type-only (erased), so it does not change rule 7's bundling.
3. **Document every exported symbol** (interfaces, their members, type aliases, and
   `export const model`) with JSDoc — `fast-check` requires it.
4. **Self-check before publish:** `deno check` → `deno doc --lint <file>` (ignore the
   `@types/node` resolution warnings — only `<file>`-pointed errors matter) →
   `deno test` → `swamp extension fmt --check` → `swamp extension quality` (expect
   `allPassed: true`).

