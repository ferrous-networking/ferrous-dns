---
name: gh-write-ops-use-rest
description: gh pr review / gh issue create can fail with a phantom "API rate limit already exceeded" from GraphQL while every primary limit reads 5000/5000 — post via the REST API instead
type: reference
---

`gh pr review` and `gh pr create` go through GitHub's GraphQL API, which can
return `GraphQL: API rate limit already exceeded for user ID <id>` while
`gh api rate_limit` reports every resource at `used: 0, remaining: 5000`. That
is a *secondary* (content-creation) limit, which the `/rate_limit` endpoint does
not report, so there is nothing to wait for and no counter to read.

The REST equivalents are not affected and work immediately:

```
gh api --method POST repos/<owner>/<repo>/pulls/<n>/reviews \
  -f event=APPROVE -F body=@/tmp/review.md \
  --jq '{id: .id, state: .state, url: .html_url}'

gh api --method POST repos/<owner>/<repo>/issues \
  -f title="..." -F body=@/tmp/issue.md \
  --jq '{number: .number, url: .html_url}'
```

`-F body=@<file>` reads the file as the field value, which also sidesteps the
shell-quoting problem with a markdown body containing backticks, `$` and
apostrophes. Always confirm afterwards with
`gh api repos/<owner>/<repo>/pulls/<n>/reviews --jq '.[] | {user: .user.login, state: .state}'` —
a failed GraphQL write leaves nothing behind, but you want that on the record
before telling anyone it posted.
