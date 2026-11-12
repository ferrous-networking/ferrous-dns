---
name: ci-success-abandoned-jobs
description: CI Success failing on `"abandoned" != "success"` with Build jobs missing from the run means a GitHub Actions incident dropped them, not a code failure; `gh run rerun <id> --failed` recovers them in ~10 min without redoing the ~2 h coverage
type: project
---

**Symptom:** the `CI Success` job fails, and its log shows `[ "abandoned" != "success" ]` for one of the `needs`. On PR #384 (2026-11-09) it was `needs.build.result`. Every job in the run passed, but the `Build (Linux x86_64)` and `Build (Linux ARM64)` matrix jobs are not in the run at all.

**Cause:** an outage on GitHub's side. Test finished at 18:08:48Z, and the Build jobs it unlocks were never created. GitHub's "Incident with Actions and Checks API" ran from 18:12 to 18:59Z. The push run for `69d6aa39` (#378's merge) on main ended `failure` the same way: all its jobs passed and it has no CI Success job. A rerun of that one was offered on 2026-11-09 but not done.

**Check:**
- `gh api 'repos/ferrous-networking/ferrous-dns/actions/runs/<id>/jobs?filter=all&per_page=100'` lists the jobs that ran. A missing job name is the tell.
- `https://www.githubstatus.com/api/v2/incidents.json` lists the incidents with times.

**Fix:** `gh run rerun <id> --failed`. It created the abandoned Build jobs plus a new CI Success as attempt 2, and the run went green in about 9 minutes. Code Coverage was not executed again.

**Why it matters:** Code Coverage (tarpaulin) takes about 2 hours, and CI Success waits for it. So this red check shows up about 2 hours after the push. A full rerun would wait those 2 hours again.

**How to apply:** when CI Success fails, read its log before blaming the PR. `abandoned`, or a needed job missing from the run, means you rerun the failed jobs; you don't fix code.
