# PR titles

Enforced by `.github/workflows/pr-validation.yml` (`amannn/action-semantic-pull-request`) on the **PR title**, not local commits — a bad title fails CI even with clean commits.

Format: `type(scope): description` — scope optional (`requireScope: false`), no `!` breaking marker in use.

Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`.

House style (from merged PRs):

- Lowercase description, written in full sentences: `fix(cache): stop corrupting non-ASCII bytes in oversized cache keys`, not `fix: cache bug`.
- Scope = the subsystem in lowercase: `dns`, `dnssec`, `cache`, `auth`, `api`, `query-log`, `block-filter`, `docker`, `config`. Omit only when the change is repo-wide.
- `build(deps): ...` is reserved for Dependabot; `ci: ...` for workflow changes; hand-written chores use plain `chore: ...`.
- Breaking changes: the workflow greps the head commit message for `BREAKING CHANGE` and demands CHANGELOG + migration guide + MAJOR bump. Don't mark a PR breaking accidentally.
- `size/*` labels are auto-assigned by `codelytv/pr-size-labeler` — never set them manually.

Body: follow `.github/PULL_REQUEST_TEMPLATE/pull_request_template.md`.
