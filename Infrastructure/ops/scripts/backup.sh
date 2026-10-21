#!/usr/bin/env bash
# Daily (02:00):
#   - every active employee folder (/users/<name>) → /backups/daily|weekly/<name>-<ts>.tar.gz[.age]
#     (Sundays → weekly). Includes .env (login hash + API key) so a restore is complete.
#   - Organization-Knowledge (/org: organization, department and personal skills/KPI/knowledge)
#     → /backups/daily|weekly/organization-knowledge-<ts>.tar.gz[.age]
#   - every archived employee (/archive/<name>_<date>) → /backups/archive/ once (it never changes)
#   - encrypted with age when BACKUP_AGE_RECIPIENT is set (recommended)
# Backups are taken while Hermes runs; at 02:00 there is normally no activity.
set -euo pipefail

B=/backups
ts="$(date +%Y%m%d-%H%M%S)"
kind=daily; [[ "$(date +%u)" == 7 ]] && kind=weekly
KEEP_D="${BACKUP_KEEP_DAILY:-7}"
KEEP_W="${BACKUP_KEEP_WEEKLY:-4}"
RCPT="${BACKUP_AGE_RECIPIENT:-}"
log() { printf '[ops/backup %s] %s\n' "$(date '+%F %T')" "$*"; }

umask 077
mkdir -p "$B/daily" "$B/weekly" "$B/archive"
[[ -z "$RCPT" ]] && log "WARNING: BACKUP_AGE_RECIPIENT is empty — backups are NOT encrypted"

archive_dir() { # <parent> <name> <dest-without-ext>
  if [[ -n "$RCPT" ]]; then
    tar -C "$1" --numeric-owner --warning=no-file-ignored -cz "$2" | age -r "$RCPT" > "$3.tar.gz.age"
    echo "$3.tar.gz.age"
  else
    tar -C "$1" --numeric-owner --warning=no-file-ignored -czf "$3.tar.gz" "$2"
    echo "$3.tar.gz"
  fi
}

for d in /users/*/; do
  name="$(basename "$d")"
  [[ "$name" == _* ]] && continue
  f="$(archive_dir /users "$name" "$B/$kind/$name-$ts")" || { log "$name: backup FAILED"; continue; }
  log "$name → ${f#"$B"/} ($(du -h "$f" | cut -f1))"
done

if [[ -d /org ]]; then
  if f="$(archive_dir / org "$B/$kind/organization-knowledge-$ts")"; then
    log "Organization-Knowledge → ${f#"$B"/} ($(du -h "$f" | cut -f1))"
  else
    log "Organization-Knowledge: backup FAILED"
  fi
fi

for d in /archive/*/; do
  [[ -d "$d" ]] || continue
  name="$(basename "$d")"
  ls "$B/archive/$name".tar.gz* >/dev/null 2>&1 && continue
  f="$(archive_dir /archive "$name" "$B/archive/$name")" || { log "archive $name: backup FAILED"; continue; }
  log "archived $name → ${f#"$B"/}"
done

prune() { # <dir> <keep>
  local n
  for n in $(ls -1 "$1" 2>/dev/null | sed -E 's/-[0-9]{8}-[0-9]{6}\.tar\.gz(\.age)?$//' | sort -u); do
    ls -1t "$1/$n"-[0-9]*.tar.gz* 2>/dev/null | tail -n +"$(( $2 + 1 ))" | xargs -r rm -f
  done
}
prune "$B/daily" "$KEEP_D"
prune "$B/weekly" "$KEEP_W"
log "done"
