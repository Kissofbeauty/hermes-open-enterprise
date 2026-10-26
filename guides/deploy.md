# Automatic deploy (GitHub → server) and repository settings

A merge into `main` → GitHub Actions (`.github/workflows/deploy.yml`) connects to the server over SSH with a key
that can do one thing only → the server runs one fixed command, `Infrastructure/deploy/deploy.sh` → `git` fast-
forward + `docker compose up -d` + `ohermes reconf`. Off until you enable it (section 2.5).

```
PR ─► review (CODEOWNERS) + CI ─► merge main ─► workflow "deploy" ─► (approval in environment "production")
   ─► ssh hermes-deploy@server ─► forced command: sudo -n /usr/local/sbin/hermes-deploy /srv/hermes-open-enterprise
```

## Contents

1. [What deploy.sh does](#1-what-deploysh-does)
2. [One-time server setup](#2-one-time-server-setup)
3. [GitHub repository settings after the first push](#3-github-repository-settings-after-the-first-push)
4. [Rollback](#4-rollback)
5. [What stays manual](#5-what-stays-manual)
6. [Test the setup](#6-test-the-setup)

## 1. What deploy.sh does

| Step | On failure |
|---|---|
| 1. Opens `Logs/deploy/` safely (no symlinks, made root-owned 0750) and takes a lock — one deploy at a time | exit 2 / 75, nothing changed |
| 2. Must be on `main`, no local changes to tracked files, no local commits missing from `origin/main` | stops, nothing changed |
| 3. `git fetch` + `git merge --ff-only origin/main` (as the owner of the checkout) | stops, nothing changed |
| 4. `ohermes check` → `ohermes sync` (employee list, Caddy routes, runtime files) → `docker compose config` → `docker compose pull --ignore-buildable` | **files go back to the previous commit** (`git reset --keep`); no container touched |
| 5. `docker compose up -d --build` — recreates only changed services; **no `--remove-orphans`** | exit ≠ 0; other services keep running |
| 6. `Infrastructure/caddy/` changed → `caddy reload` (validated first; a bad config keeps the old one) | exit ≠ 0 |
| 7. `Config/` (except `ohermes.conf`), `Infrastructure/hermes/` or `Users/_template/` changed → **rolling restart of every employee**, waiting until each is healthy (120 s max each) | failures are logged, the rest continue, exit ≠ 0; `Logs/deploy/.restart-pending` makes the next run retry |
| 8. `ohermes reconf` (web rules; a bad file keeps the old rules) | exit ≠ 0 |

- Log: `Logs/deploy/<YYYY-MM-DD>.log` and the GitHub Actions log.
- `.env` on the server is not in git: change it by hand, then `docker compose up -d`.
- Timing: `DEPLOY_HEALTH_TIMEOUT` (120) and `DEPLOY_HEALTH_STABLE` (10) seconds.
- Organization-Knowledge content is visible to agents right after the merge (read-only mounts, no restart).

## 2. One-time server setup

Examples use `/srv/hermes-open-enterprise` and the user `hermes-deploy` — change them consistently.

### 2.1 Clone (as the admin account)

The checkout belongs to the admin account that runs `docker compose` and `ohermes` (in the `docker` group, see
[admin.md](admin.md) section 2.2). The folder only has to be fixed, because the sudoers line names it:

```bash
sudo install -d -o "$USER" -g "$USER" /srv/hermes-open-enterprise
git clone git@github.com:<org>/<private-repo>.git /srv/hermes-open-enterprise
cd /srv/hermes-open-enterprise && git checkout main
```

- **The checkout owner must be an account you treat as root.** deploy.sh runs as root inside it; whoever owns
  the folder can change what root runs (and could plant symlinks or change `.git` for root to follow). The
  admin account qualifies — being in the `docker` group, it is root-equivalent already. Never let the checkout
  belong to `hermes-deploy` or to anyone without root. deploy.sh runs git as the checkout owner (file ownership
  in the repo never changes), keeps `Logs/deploy` root-owned 0750 and refuses symlinked or foreign-owned entries
  there; `ohermes` keeps `Users/`, `Archive/`, `Backups/` and `Logs/` root-owned.
- A root-owned checkout (older installs) keeps working unchanged.
- Use a **read-only** GitHub deploy key for `git fetch` (a different key from the one GitHub uses to reach the
  server).
- Commits made on Windows: check that `ohermes` and `*.sh` are executable (`git ls-files -s ohermes` → `100755`;
  fix with `git update-index --chmod=+x ohermes`).

### 2.2 Deploy user (not root, not in the docker group)

```bash
sudo useradd --create-home --shell /bin/sh hermes-deploy
sudo passwd -l hermes-deploy
```

> The `docker` group is root-equivalent. `hermes-deploy` gets **one script with fixed arguments** through sudo
> instead (employee `.env` files are root-only anyway).

### 2.3 Install the script outside the repo + sudoers

```bash
cd /srv/hermes-open-enterprise
sudo install -m 755 -o root -g root Infrastructure/deploy/deploy.sh /usr/local/sbin/hermes-deploy
sudo visudo -cf Infrastructure/deploy/sudoers.example \
  && sudo install -m 440 -o root -g root Infrastructure/deploy/sudoers.example /etc/sudoers.d/hermes-deploy
sudo -u hermes-deploy sudo -n -l     # must list only /usr/local/sbin/hermes-deploy /srv/hermes-open-enterprise
```

- A commit that changes `deploy.sh` does not run as root until an admin re-installs it (the log warns
  `differs from Infrastructure/deploy/deploy.sh`).
- Still: `docker compose up` uses the repository's compose files, template and scripts, so **anyone who can merge
  into `main` effectively has root on the server**. Protect `main` (section 3) and require reviewers on the
  `production` environment.

### 2.4 SSH key for GitHub (deploy only)

```bash
ssh-keygen -t ed25519 -N '' -C github-actions-deploy -f ./hermes-deploy-key        # on the admin's machine
sudo install -d -m 700 -o hermes-deploy /home/hermes-deploy/.ssh
sudo install -m 600 -o hermes-deploy /dev/null /home/hermes-deploy/.ssh/authorized_keys
sudoedit /home/hermes-deploy/.ssh/authorized_keys     # one line as in Infrastructure/deploy/authorized_keys.example
ssh-keyscan -p 22 <server> > known_hosts.txt          # compare with: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

- `command="…"` + `restrict`: no shell, no forwarding; the client's command is only logged.
- Add `hermes-deploy` to `AllowUsers`/`AllowGroups` if sshd uses them.
- GitHub-hosted runners come from wide IP ranges; to avoid exposing port 22 use a self-hosted runner or SSH
  through a bastion / Cloudflare Access (adapt the workflow).
- Delete `hermes-deploy-key` from the admin machine after storing it in GitHub. Rotate = new key in
  `authorized_keys` and in the secret.

### 2.5 GitHub environment, secrets and variable

Settings → Environments → **New environment `production`**:

- Deployment branches: selected branches → `main` only
- **Required reviewers (mandatory)**: the sysadmin team — every deploy runs repository code as root
- Environment secrets:

| Secret | Value |
|---|---|
| `DEPLOY_HOST` | server name/IP |
| `DEPLOY_PORT` | SSH port (default 22) |
| `DEPLOY_USER` | `hermes-deploy` |
| `DEPLOY_SSH_KEY` | the whole private key file `hermes-deploy-key` |
| `DEPLOY_KNOWN_HOSTS` | `known_hosts.txt` (fingerprint checked) — the workflow uses `StrictHostKeyChecking=yes` |

Settings → Secrets and variables → Actions → **Variables**: `DEPLOY_ENABLED` = `true` (unset = the deploy
workflow is skipped).

## 3. GitHub repository settings after the first push

Do these right after pushing the repository (public template or private organization copy):

- [ ] **Security → Private vulnerability reporting: enable** (SECURITY.md and the issue template link to it).
- [ ] **Security → Secret scanning + Push protection: enable** (CI also runs gitleaks, job `secret-scan`).
- [ ] **Dependabot alerts and security updates: enable** (`.github/dependabot.yml` updates pinned Actions and
      image digests).
- [ ] **Rules → Rulesets (or branch protection) for `main`**:
  - Require a pull request; ≥ 1 approval; **Require review from Code Owners**; dismiss stale approvals; require
    approval of the most recent push
  - Require status checks: **`lint`** and **`secret-scan`** (workflow `ci`); branches up to date
  - Require signed commits; block force pushes; restrict deletions
  - No bypass (not even admins), or as few people as possible
  - Optional: 2 approvals for `Organization-Knowledge/**/Skills/**` (content owner **and** sysadmin)
- [ ] **CODEOWNERS**: replace `@Kissofbeauty` in `.github/CODEOWNERS` with your teams (sysadmins for system paths
      and `Skills/`, content owners for the rest of `Organization-Knowledge/`); the teams need write access.
- [ ] **Actions → General**: workflow permissions = **Read repository contents**; do not allow Actions to create
      or approve pull requests; **require approval for workflows from outside contributors** (all outside
      contributors for a public repository); allow only GitHub-owned and verified actions (or an explicit list).
- [ ] **Environments**: `production` as in section 2.5 (only for copies that deploy).
- [ ] Collaborators/teams: least privilege; 2FA required for the organization.

## 4. Rollback

Never edit files on the server (the next deploy stops on "local changes"):

```bash
git revert <bad commit>      # or "Revert" on the PR → review → merge → automatic deploy
```

- Re-run without a new commit: Actions → deploy → **Run workflow** (main).
- A deploy that failed at step 4 already restored the previous files; see `Logs/deploy/<date>.log`.
- Image versions live in `.env` on the server; a git revert does not change them.

## 5. What stays manual

| Task | How |
|---|---|
| Add/remove/move employees, passwords | `ohermes create / update / rm / restore / repasswd` on the server (sudo is automatic) |
| Personal AI model | `ohermes model -u <name>` |
| `.env` (secrets, image versions) | edit on the server → `docker compose up -d` |
| Update the deploy script that runs as root | re-install (section 2.3) |
| Cloudflare Access applications | Cloudflare dashboard (see [admin.md](admin.md), section 2.3) |

The employee list (`docker-compose.override.yml`) and the Caddy routes (`Infrastructure/caddy/generated/`) are
generated from `Users/` and git-ignored, so the checkout stays clean; deploy.sh runs `ohermes sync` before
`up -d`. Never set `COMPOSE_FILE` in `.env`.

## 6. Test the setup

```bash
sudo -u hermes-deploy sudo -n /usr/local/sbin/hermes-deploy /srv/hermes-open-enterprise   # on the server
ssh -i hermes-deploy-key hermes-deploy@<server> whoami        # must print the deploy output, not "hermes-deploy"
ssh -i hermes-deploy-key -L 9000:localhost:80 hermes-deploy@<server>   # forwarding must be refused
```
