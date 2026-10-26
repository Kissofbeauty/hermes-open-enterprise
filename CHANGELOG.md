# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Simple production setup, run as the admin account (in the `docker` group) without sudo:
  `git clone … && cd hermes-open-enterprise` → `cp .env.example .env && nano .env` → `docker compose up -d` →
  `./ohermes create …`. The admin account owns the checkout and is root-equivalent through the `docker` group
  (accepted trade-off, documented); employee secrets stay root-only.
- `ohermes` re-runs itself with `sudo` when a command needs root (Linux): always for `create`, `update`, `rm`,
  `restore`, `repasswd`, `model`, `sync`, `reconf`; for `ls`, `check` and `reconf --dry-run` only when the
  employee files are not readable; never for `--help`, `install`, `uninstall`. Arguments are passed unchanged,
  nothing else crosses the sudo boundary; a loop guard stops if sudo does not give root.
- `create`, `repasswd`, `restore` and `update -e` end with a prominent
  `Dashboard login → username: <server name> (NOT the email)` line; `ohermes ls` labels the column
  `USERNAME (LOGIN)`; README and the admin guide say the login is the server name, never the email.
- `ohermes install` / `ohermes uninstall`: the `ohermes` command for all users (`/usr/local/bin/ohermes` → the
  checkout). The first interactive run offers it once (`n` is remembered in the git-ignored
  `.ohermes-no-install`); never asked without a terminal, in CI or on Windows/macOS; a link to another checkout is
  never replaced.
- `Config/ohermes.conf` `[organization-knowledge] manage_folders = on|off` (default `on`). With `off`
  (Organization-Knowledge kept in its own repository) `create`, `update -d`, `rm`, `restore` and `sync` never
  create, move, archive or chmod anything in `Organization-Knowledge/`; they warn with the folder paths to create
  or move there. `ohermes check` validates the section; `ohermes ls` has an `ORG` column (`ok` / `missing`).

### Changed
- The dashboard login (`HERMES_DASHBOARD_BASIC_AUTH_*`) moved from `Users/<name>/.env` to
  `Users/<name>/secrets.env` (root only, 0600), mounted read-only and exported by `start.sh` at container start
  (no longer visible in `docker inspect`). `Users/<name>/.env` keeps only `EMP_*` and is readable by the admin's
  group, so `docker compose` works as the admin account. `repasswd` recreates the employee's container.
- Owners and modes on Linux: `Users/`, `Archive/`, `Backups/`, `Logs/` and employee folders are
  `root:<admin group>` 0750 (`.env`/`compose.yml`/`config.yaml` 0640; `secrets.env`, `model/`, `data/`,
  `Backups/daily|weekly|archive` root only); the root `.env` is set to 0600. Files `ohermes` creates where the
  admin works (Organization-Knowledge folders, `docker-compose.override.yml`, generated Caddy/egress files) belong
  to the checkout owner. A root-owned checkout keeps working.
- The `chmod 700 Backups Archive` install step is gone (`ohermes` does it).
- Website rules moved from `ohermes.conf` to `Config/ohermes.conf`. For one release `ohermes` still reads
  `./ohermes.conf` (with a warning) when `Config/ohermes.conf` is missing; `ohermes sync` moves it.
- Employee containers mount only `Config/defaults.yaml`, `Config/enforced.yaml` and `Config/SOUL.md` (not the
  whole `Config/` folder); `ohermes sync` regenerates older `Users/<name>/compose.yml` files.
- `deploy.sh`: a change to `Config/ohermes.conf` alone no longer restarts every employee (reconf only).

- Documentation: English admin and deploy guides in `guides/` (install, Cloudflare, `ohermes`, web rules,
  locked settings, org-guard, backups, upgrades, troubleshooting, GitOps, GitHub repository settings checklist).
- `ohermes` derives the egress host for every API-key provider of Hermes v0.22.2 (fireworks, novita, alibaba,
  zai, kimi-coding, minimax, nvidia, huggingface, …) and warns when none is known.

### Upgrade notes
- Run `ohermes sync` (or `sudo ./ohermes sync`) before `docker compose up -d`: `Users/<name>/compose.yml` gets the
  `secrets.env` mount and the login moves out of `Users/<name>/.env`. Moving an existing root-owned checkout to
  the admin account is optional: `guides/admin.md` section 12.
- Run `sudo ./ohermes sync` then `sudo docker compose up -d`: every `Users/<name>/compose.yml` is regenerated
  (network alias `<name>.employee.internal`, read-only shell start files and models.dev catalog, `pids`, `PATH`,
  `PYTHONNOUSERSITE`;
  the old file is kept as `compose.yml.old`) and `Infrastructure/caddy/generated/routes.caddy` is created.
- Production: add a catch-all Cloudflare Access application for `*.<domain>` (see `guides/admin.md`).

### Security
- Caddy serves only the exact employee hosts in the generated, git-ignored `Infrastructure/caddy/generated/routes.caddy`
  (rebuilt by `ohermes create/update -s/rm/restore/sync`, applied with a graceful reload) and proxies to
  `<name>.employee.internal`; any other host (container/service names, an old subdomain) gets 404.
- Shell start files in the agent's home (`.profile`, `.bash_profile`, `.bash_login`, `.bashrc`, `.bash_logout`,
  `.inputrc`) are empty read-only mounts; `terminal.auto_source_bashrc: false`; `PYTHONNOUSERSITE=1`; `PATH` no
  longer puts `/opt/data/.local/bin` before system folders. org-guard blocks writes to shell/tool start files
  (`.gitconfig`, `.npmrc`, `.ssh/`, `.config/git`, Python user site, `sitecustomize.py`, `*.pth`) and
  `git config --global`, `npm config set`, `pip install --user`.
- org-guard: every tool except a local allowlist is outbound (PII and Organization-Knowledge checks now cover
  `vision_analyze`, `text_to_speech`, image/video tools, MCP tools); results of URL-fetching tools are wrapped as
  untrusted.
- org-guard and `approvals.deny`: reading `/opt/enterprise/runtime` (`hermes.env`), `/opt/enterprise/model`, the
  s6 environment or `/proc/*/environ` is blocked.
- Provider lock fails closed: provider tables are read from the image in a child that opens no agent file, a
  root-owned last good copy (`runtime/provider-facts.json`) is used on failure, and with neither setup stops;
  any error parsing the agent-writable models.dev cache is ignored; the local-skills walk is bounded.
- The models.dev catalog (Hermes' provider definitions) is fetched by `setup.py` at every start and mounted
  read-only at `/opt/data/models_dev_cache.json`; Hermes' refresh URL is pinned to a closed local port
  (`models_dev.url` in `Config/enforced.yaml`) and every catalog provider except the active one is disabled —
  an agent can no longer define a provider with its own base URL. Under `default deny`, allow `models.dev`.
- org-guard log lines go to the container's stderr (not writable by the agent) and are signed with a per-process
  key; `Infrastructure/hermes/verify_guard_log.py` checks them.
- `pids` limits for every service, size-capped tmpfs for Hermes, at most 200 egress connections per agent.
- `deploy.sh` refuses symlinked or foreign-owned `Logs/deploy` entries and makes the folder root-owned 0750.
- CI: gitleaks secret scan (pinned by digest), stricter "no runtime files committed" check, a job that flags
  Organization-Knowledge `Skills/` changes; `.github/dependabot.yml`; CODEOWNERS requires sysadmin review for
  `Organization-Knowledge/**/Skills/`.
- Optional host firewall helper `Infrastructure/host/firewall.sh` (iptables `INPUT` + `DOCKER-USER`).
- org-guard: shell `cd`/`pushd` into `memories/`, `skills/`, `plugins/`, `hooks/`, `profiles/` and non-read-only
  commands run from there (the terminal's per-session cwd) are blocked; writes naming `MEMORY.md`, `USER.md`,
  `SKILL.md` and other instruction files are blocked anywhere; wildcards are expanded before the check.
- org-guard: relative file-tool paths are resolved like Hermes does (session cwd) before the approval check;
  hard-linked files need approval; `text_to_speech` output paths are checked.
- org-guard: creating FIFOs/device files from the shell is blocked; `setup.py` quarantines a non-regular
  `SKILL.md` (or non-regular entry in `memories/`) at start.
- org-guard: URL checks decode `+` as a space and repeated `%xx` encoding (query strings, form bodies).

## [0.6.0] - 2026-10-21

First public release.

### Added
- Docker Compose deployment of Hermes Agent (pinned `v0.22.2` image) for a whole organization:
  one container, one `internal` /28 network and one subdomain per employee.
- `ohermes` CLI: `create`, `update`, `rm` (archive, never delete), `restore`, `repasswd`, `ls`, `check`,
  `reconf`, `model`, `sync`; generated `docker-compose.override.yml` keeps the git checkout clean.
- Organization-Knowledge with three-level assignment (organization → department → person), mounted
  read-only one folder at a time, with skill-name precedence and the `org-navigator` skill.
- Locked Hermes configuration generated at every start (`defaults → per-user → AI model → enforced`),
  mounted read-only; Hermes profiles disabled; AI provider locked to the admin-set one.
- Central or per-employee AI model and key (`ohermes model`).
- `org-guard` plugin: fail-closed checks for secrets, key formats, canary markers, personal data and
  verbatim knowledge on outbound tools; approval for uploads, form submits and memory/skill writes;
  invisible-Unicode stripping and untrusted-content marking.
- Egress proxy (Squid) with website rules per organization/department/person from `ohermes.conf`;
  raw-IP and private destinations denied; no DNS side channel for denied names.
- Two login gates: Cloudflare Access + per-employee Hermes password; Caddy origin-secret check in production.
- Hardened containers: image digests, `cap_drop: ALL`, read-only root filesystem for Hermes.
- `ops` container: daily log collection/archiving and nightly backups with optional age encryption.
- Optional GitOps auto-deploy (GitHub Actions → SSH forced command → `deploy.sh` with rolling restart).
- CI: shellcheck, org-guard unit tests, compose/Caddy/Squid config validation, committed-secret check.
- Docs: README, SECURITY.md, admin and deploy guides (Thai), security review, QA report.

### Known limitations
- org-guard is pattern-based; a shared AI key is readable by every agent; the AI provider host is always
  allowed; not yet verified behind a real Cloudflare tunnel. See SECURITY.md.

[Unreleased]: https://github.com/Kissofbeauty/hermes-open-enterprise/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Kissofbeauty/hermes-open-enterprise/releases/tag/v0.6.0
