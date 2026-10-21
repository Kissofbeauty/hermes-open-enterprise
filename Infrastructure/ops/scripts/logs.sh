#!/usr/bin/env bash
# Daily (00:15):
#   1) yesterday's Docker logs of this project's containers → /logs/docker/<service>/<date>.log.gz
#      (read from the Docker log files, mounted read-only — no Docker socket needed)
#   2) caddy + egress + docker logs older than LOG_RETENTION_DAYS → /logs/archive (or delete)
#      (egress renames its access.log to access-<date>.log every night itself)
#   3) archive older than LOG_ARCHIVE_KEEP_DAYS → delete (0 = keep forever)
set -euo pipefail

L=/logs
SRC=/docker-containers
PROJECT="${COMPOSE_PROJECT:-hermes-open-enterprise}"
RET="${LOG_RETENTION_DAYS:-30}"
ACTION="${LOG_ARCHIVE_ACTION:-move}"
KEEP="${LOG_ARCHIVE_KEEP_DAYS:-365}"
log() { printf '[ops/logs %s] %s\n' "$(date '+%F %T')" "$*"; }

[[ "$RET" =~ ^[0-9]+$ && "$KEEP" =~ ^[0-9]+$ ]] || { log "invalid retention settings"; exit 1; }
mkdir -p "$L/docker" "$L/archive" "$L/caddy" "$L/egress"

day="${1:-$(date -d yesterday +%F)}"
start="$(date -u -d "$day 00:00" +%Y-%m-%dT%H:%M:%S)"
end="$(date -u -d "$day 00:00 +1 day" +%Y-%m-%dT%H:%M:%S)"

if [[ -d "$SRC" ]]; then
  for dir in "$SRC"/*/; do
    cfg="$dir/config.v2.json"
    [[ -f "$cfg" ]] || continue
    proj="$(jq -r '.Config.Labels["com.docker.compose.project"] // ""' "$cfg")"
    [[ "$proj" == "$PROJECT" ]] || continue
    svc="$(jq -r '.Config.Labels["com.docker.compose.service"] // "unknown"' "$cfg")"
    [[ "$svc" =~ ^[a-z0-9_.-]+$ ]] || continue
    out="$L/docker/$svc/$day.log.gz"
    [[ -f "$out" ]] && continue
    mkdir -p "$L/docker/$svc"
    # rotated files first (oldest), then the live file
    files=$(ls -1r "$dir"*-json.log* 2>/dev/null || true)
    [[ -n "$files" ]] || continue
    # shellcheck disable=SC2086
    cat $files | jq -r --arg s "$start" --arg e "$end" \
      'select(.time >= $s and .time < $e) | "\(.time) \(.stream) \(.log | rtrimstr("\n"))"' \
      | gzip -9 > "$out"
    chmod 640 "$out"
  done
  log "collected docker logs for $day"
else
  log "no $SRC mount — skipping docker logs"
fi

# Move/delete old logs (never the files Caddy/Squid are writing to)
count=0
while IFS= read -r -d '' f; do
  if [[ "$ACTION" == "delete" ]]; then
    rm -f "$f"
  else
    rel="${f#"$L"/}"
    mkdir -p "$L/archive/$(dirname "$rel")"
    mv "$f" "$L/archive/$rel"
  fi
  count=$((count + 1))
done < <(find "$L/caddy" "$L/egress" "$L/docker" -type f -mtime +"$RET" ! -name access.log ! -name caddy.log ! -name cache.log -print0)
log "$count file(s) older than $RET days → $ACTION"

if (( KEEP > 0 )); then
  find "$L/archive" -type f -mtime +"$KEEP" -delete
  find "$L/archive" -mindepth 1 -type d -empty -delete
fi
