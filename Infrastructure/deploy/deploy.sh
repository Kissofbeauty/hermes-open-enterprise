#!/usr/bin/env bash
# deploy.sh — bring the server up to date with origin/main. Started by GitHub Actions over SSH
# (forced command, see authorized_keys.example and guides/deploy.md); can also be run by hand.
#
#   sudo /usr/local/sbin/hermes-deploy /srv/hermes-open-enterprise
#
# Steps: lock → refuse local changes / other branch / diverged history → fast-forward to origin/main
#        → ohermes check → ohermes sync → docker compose config → pull images → up -d → caddy reload (if changed)
#        → rolling restart of every employee if Config/ (except ohermes.conf), Infrastructure/hermes/
#          or Users/_template/ changed
#        → ohermes reconf. Exit code ≠ 0 on any failure.
# Failure before `up -d` puts the working tree back on the previous commit: nothing running changes.
# Never removes containers: no --remove-orphans (employees are added on the server by `ohermes create`).
#
# Runs as root (employee .env files are root-only and docker access is root-equivalent anyway).
# git runs as the owner of the checkout, so file ownership in the repo never changes.
#
# Environment (optional): DEPLOY_BRANCH (main) · DEPLOY_REMOTE (origin)
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash (dev/testing on Windows): don't rewrite /paths

# Everything lives in main(): bash has then read the whole file before `git merge`
# can replace it on disk (a deploy that updates this script must not run half old, half new).
main() {
  local self root branch remote
  self="$(readlink -f "${BASH_SOURCE[0]}")"
  root="${1:-$(cd "$(dirname "$self")/../.." && pwd)}"
  branch="${DEPLOY_BRANCH:-main}"
  remote="${DEPLOY_REMOTE:-origin}"

  [[ -d "$root/.git" && -f "$root/docker-compose.yml" && -f "$root/ohermes" ]] \
    || { echo "deploy: $root is not a Hermes Open Enterprise checkout" >&2; return 2; }
  cd "$root"

  # ---- log: Logs/deploy/<date>.log (and stdout for the GitHub Actions log)
  # The checkout should belong to root (guides/deploy.md). If it does not, its owner could plant
  # symlinks in Logs/ for root to follow (security review R5-07), so: Logs/deploy is made root-owned
  # 0750, entered with `cd -P` and checked there; the log and lock files are opened relative to that
  # directory (no path through a folder someone else controls) and never through a symlink.
  open_log_dir || return 2
  local logname; logname="$(date +%F).log"
  exec > >(tee -a -- "$logname") 2>&1

  # ---- one deploy at a time
  if command -v flock >/dev/null 2>&1; then
    exec 9>>.lock
    flock -n 9 || { log "another deploy is running — stopped"; return 75; }
  else # no flock (e.g. Git Bash): mkdir is atomic too
    mkdir .lock.d 2>/dev/null || { log "another deploy is running (Logs/deploy/.lock.d) — stopped"; return 75; }
    trap 'rmdir "'"$PWD"'/.lock.d" 2>/dev/null || true' EXIT
  fi
  cd "$root"

  log "==== deploy start (user $(id -un), host $(hostname))$(requested_by)"
  [[ "$self" == "$root/Infrastructure/deploy/deploy.sh" ]] || cmp -s "$self" "$root/Infrastructure/deploy/deploy.sh" \
    || log "WARNING: $self differs from Infrastructure/deploy/deploy.sh in the repo — reinstall it (guides/deploy.md)"

  # ---- git: main only, clean tree, fast-forward only
  local current prev new
  current="$(git_ symbolic-ref --quiet --short HEAD || true)"
  [[ "$current" == "$branch" ]] || fail "checkout is on '${current:-detached HEAD}', not '$branch' — nothing changed"
  if [[ -n "$(git_ status --porcelain --untracked-files=no)" ]]; then
    git_ status --short --untracked-files=no
    fail "local changes to tracked files (above) — commit them through a PR or discard them; nothing changed"
  fi
  prev="$(git_ rev-parse HEAD)"
  git_ fetch --quiet --prune "$remote" "$branch" || fail "git fetch failed — nothing changed"
  git_ merge-base --is-ancestor HEAD "$remote/$branch" \
    || fail "local '$branch' has commits that are not on $remote/$branch (diverged) — fix by hand; nothing changed"
  git_ merge --ff-only --quiet "$remote/$branch" || fail "fast-forward failed — nothing changed"
  new="$(git_ rev-parse HEAD)"
  if [[ "$prev" == "$new" ]]; then
    log "already at ${new:0:12} — re-applying"
  else
    log "updated ${prev:0:12} → ${new:0:12}:"
    git_ --no-pager log --oneline "$prev..$new" | sed 's/^/    /'
  fi

  # ---- checks: a failure here restores the previous commit (nothing running has changed)
  bash ./ohermes check || undo "$prev" "Config/ohermes.conf is not valid"
  # employee list + per-employee files (docker-compose.override.yml, Users/<name>/…) — no restart by itself
  bash ./ohermes sync || undo "$prev" "ohermes sync failed"
  docker compose config --quiet || undo "$prev" "docker compose config failed"
  docker compose pull --quiet --ignore-buildable || undo "$prev" "docker compose pull failed"

  # ---- apply: only services whose definition/image changed are recreated; nothing is removed
  docker compose up -d --build \
    || fail "docker compose up failed — services not shown as recreated above keep running; fix with a new commit (git revert) or by hand"

  if [[ "$prev" != "$new" ]]; then
    local changed; changed="$(git_ diff --name-only "$prev" "$new")"
    if grep -q '^Infrastructure/caddy/' <<<"$changed"; then
      # graceful: Caddy validates first and keeps the old config on error
      docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile \
        || fail "caddy reload failed — Caddy keeps the previous config"
      log "caddy reloaded"
    fi
    # read only at Hermes start (setup.py merges Config/ at every start) → restart every employee;
    # Config/ohermes.conf is applied by `ohermes reconf` below, without any restart
    local settings; settings="$(grep -E "$RESTART_PATHS" <<<"$changed" | grep -vxF "$NO_RESTART" || true)"
    if [[ -n "$settings" ]]; then
      log "Hermes settings changed: $(cut -d/ -f1-2 <<<"$settings" | sort -u | tr '\n' ' ')"
      touch "$RESTART_PENDING"
    fi
  fi
  # pending until every employee came back healthy, so a re-run (Actions → Run workflow) retries it
  if [[ -f "$RESTART_PENDING" ]]; then
    log "restarting employees one at a time"
    if restart_employees; then rm -f "$RESTART_PENDING"; else restart_failed=1; fi
  fi

  run_reconf || fail "ohermes reconf failed — the previous web rules stay active"
  (( restart_failed == 0 )) || fail "deploy applied at ${new:0:12}, but some employees did not come back healthy (see above)"
  log "==== deploy OK at ${new:0:12}"
}

# Changes that only take effect when an employee's Hermes container starts
RESTART_PATHS='^(Config/|Infrastructure/hermes/|Users/_template/)'
NO_RESTART='Config/ohermes.conf'                  # website rules: ohermes reconf, no restart
HEALTH_TIMEOUT="${DEPLOY_HEALTH_TIMEOUT:-120}"   # seconds per employee
HEALTH_STABLE="${DEPLOY_HEALTH_STABLE:-10}"      # running this long without a restart = up (no healthcheck)
RESTART_PENDING=Logs/deploy/.restart-pending      # relative to the checkout
restart_failed=0

# Running employee services = containers of this compose project with the label hermes.username
# (set in Users/_template/compose.yml) — works wherever the employee list is included from.
employee_services() {
  local ids; ids="$(docker compose ps -q --status running)" || return 1
  [[ -n "$ids" ]] || return 0
  # shellcheck disable=SC2086
  docker inspect --format '{{index .Config.Labels "hermes.username"}} {{index .Config.Labels "com.docker.compose.service"}}' $ids \
    | awk 'NF == 2 { print $2 }' | sort
}

# Rolling restart: one employee at a time; a failure is logged and the next one continues.
restart_employees() {
  local services svc n=0 bad=0
  services="$(employee_services)" || { log "could not list employee containers"; return 1; }
  [[ -n "$services" ]] || { log "no running employee containers"; return 0; }
  for svc in $services; do
    n=$((n + 1))
    if docker compose restart "$svc" >/dev/null && wait_healthy "$svc"; then
      log "restart $svc: OK"
    else
      log "restart $svc: FAILED — check: docker compose logs $svc"; bad=$((bad + 1))
    fi
  done
  log "restarted $((n - bad))/$n employee(s)"
  (( bad == 0 ))
}

# healthy = healthcheck reports healthy, or (no healthcheck) running for HEALTH_STABLE s without restarting
wait_healthy() {
  local svc="$1" id state seen="" since=0 waited=0
  while (( waited < HEALTH_TIMEOUT )); do
    id="$(docker compose ps -q "$svc")"
    state="$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.RestartCount}}' "$id" 2>/dev/null)" || state="missing"
    case "$state" in
      "running healthy "*) return 0 ;;
      "running none "*)   # stable = same state (incl. restart count) for HEALTH_STABLE seconds
        if [[ "$state" != "$seen" ]]; then seen="$state"; since=$waited
        elif (( waited - since >= HEALTH_STABLE )); then return 0; fi ;;
      *) seen="" ;;
    esac
    sleep 2; waited=$((waited + 2))
  done
  log "restart $svc: not healthy after ${HEALTH_TIMEOUT}s (last state: $state)"
  return 1
}

# cd into Logs/deploy safely (see main): no symlink on the way, root-owned 0750 when run as root on
# Linux, no symlink or non-file among the files deploy.sh writes there. Leaves the shell inside it.
open_log_dir() {
  local d="$PWD/Logs/deploy" f
  if [[ -L Logs || -L Logs/deploy ]]; then
    echo "deploy: Logs/ or Logs/deploy is a symlink — refusing (the checkout must belong to root, guides/deploy.md)" >&2
    return 1
  fi
  mkdir -p Logs/deploy
  cd -P -- Logs/deploy || return 1
  [[ "$(pwd -P)" == "$(cd -P -- "$d/.." && pwd -P)/deploy" ]] || { echo "deploy: Logs/deploy moved while opening it — refusing" >&2; return 1; }
  if [[ $EUID -eq 0 && "$(uname -s)" == Linux ]]; then
    chown root:root . && chmod 0750 . || return 1
    [[ "$(stat -c %u .)" == 0 ]] || { echo "deploy: Logs/deploy is not owned by root — refusing" >&2; return 1; }
  fi
  for f in "$(date +%F).log" .lock .restart-pending; do
    if [[ -L "$f" || ( -e "$f" && ! -f "$f" ) ]]; then
      echo "deploy: Logs/deploy/$f is a symlink or not a plain file — refusing" >&2
      return 1
    fi
  done
}

log()  { printf '%s deploy: %s\n' "$(date '+%F %T')" "$*"; }
fail() { log "FAILED: $*"; exit 1; }

# put the working tree back on <commit>, then fail
undo() {
  git_ reset --quiet --keep "$1" || log "could not restore ${1:0:12} — run: git reset --keep $1"
  fail "$2 — restored ${1:0:12}, nothing running changed"
}

# git as the owner of the checkout (keeps file ownership; uses that user's read-only deploy key)
git_() {
  local owner; owner="$(stat -c %U . 2>/dev/null || id -un)"
  if [[ $EUID -eq 0 && "$owner" != root && "$owner" != "$(id -un)" ]]; then
    sudo -u "$owner" -H git "$@"
  else
    git "$@"
  fi
}

# ohermes reconf needs root on Linux
run_reconf() {
  if [[ $EUID -eq 0 || "$(uname -s)" != Linux ]]; then bash ./ohermes reconf; else sudo -n "$PWD/ohermes" reconf; fi
}

# commit sent by the workflow (`ssh … deploy <sha>`); logged only — the deploy always takes origin/main
requested_by() {
  local c="${SSH_ORIGINAL_COMMAND:-}"
  [[ "$c" =~ ^deploy\ ([0-9a-f]{40})$ ]] && printf ' — requested for %s' "${BASH_REMATCH[1]:0:12}"
  return 0
}

main "$@"
exit $?
