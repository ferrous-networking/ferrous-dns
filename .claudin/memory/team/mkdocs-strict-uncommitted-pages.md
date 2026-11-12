---
name: mkdocs-strict-uncommitted-pages
description: A local `mkdocs build --strict` fails while new docs pages are still uncommitted, because the git-revision-date plugin warns that they have no git history; check them with a search-only INHERIT config; `mkdocs serve` serves under /ferrous-dns/
type: project
---

While new pages under `docs/` are uncommitted, a local `mkdocs build --strict` aborts. The git-revision-date plugin in `mkdocs.yml` warns that each of those pages has no git history, and `--strict` turns the warnings into a failure. That hides any real warnings, such as broken links or bad snippet includes. Once the pages are committed, the plugin is quiet, so CI does not hit this.

**Why:** seen 2026-11-04 on the #363 branch (7 new `docs/operations/` pages). The strict build only went clean with the plugin left out.

**How to apply:**
- Before committing new pages, check them with a throwaway config that drops the plugin, and delete the file afterwards:
  ```bash
  printf 'INHERIT: mkdocs.yml\nplugins:\n  - search\n' > .mkdocs-check.yml
  mkdocs build --strict -f .mkdocs-check.yml -d /some/scratch/site
  rm .mkdocs-check.yml
  ```
- `mkdocs serve` puts the site under `/ferrous-dns/`, because of `site_url`: `http://127.0.0.1:<port>/ferrous-dns/<page>/`. The bare root answers 404.
