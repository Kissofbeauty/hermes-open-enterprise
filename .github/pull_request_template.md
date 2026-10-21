## What and why

<!-- Short description. Link issues: Closes #123 -->

## Type

- [ ] feat · [ ] fix · [ ] docs · [ ] refactor · [ ] test · [ ] ci/chore · [ ] security

## Checklist

- [ ] Branch `feature/<name>` → `uat`; title follows Conventional Commits
- [ ] **No secrets or real data** (no `.env`, keys, tokens, password hashes, real names/emails/domains/IPs) —
      checked `git diff` and ran a secret scan
- [ ] No files from `Users/` (except `_template/`), `Archive/`, `Logs/`, `Backups/` or generated files
- [ ] `shellcheck`, org-guard unit tests and `docker compose config` pass locally
- [ ] `Organization-Knowledge/**/Skills/` changed: reviewed by the content owner (wording) **and** the
      sysadmin team (links, commands, requests to send data out) — CI job `skills-review` lists them
- [ ] Security-relevant: `SECURITY.md`/tests updated and `Infrastructure/hermes/tests/live-check.sh` run on a dev stage
- [ ] Docs and `CHANGELOG.md` (*Unreleased*) updated

## How it was tested

<!-- Commands run, stage (dev), results -->
