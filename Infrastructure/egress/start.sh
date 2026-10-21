#!/bin/sh
# Entrypoint of the egress container (Squid).
#  - first boot without generated/rules.conf → run with the include removed (deny everything)
#    and leave a marker; `ohermes reconf` sees it and restarts egress once the rules exist
#  - rename access.log once a day (00:00 in $TZ) and let Squid reopen its logs
set -eu

CONF=/etc/squid/hermes/squid.conf
RULES=/etc/squid/hermes/generated/rules.conf
LOGS=/var/log/squid
MARKER=/run/hermes-first-boot

# Logs/egress holds full URLs (query strings included): root-only on the host. Folder root:proxy
# 0750; Squid (user proxy) only appends to files created for it here (proxy, 0640).
# (root has CHOWN but not FOWNER here: take the file, chmod it, hand it back to proxy)
own_log() { [ -f "$1" ] && [ ! -L "$1" ] && chown root:proxy "$1" && chmod 0640 "$1" && chown proxy:proxy "$1"; }
new_log() { [ -e "$1" ] || : > "$1"; own_log "$1"; }
chown root:proxy "$LOGS" && chmod 0750 "$LOGS"
for f in "$LOGS"/*.log; do own_log "$f" || true; done   # older versions left 0644 files
new_log "$LOGS/access.log"; new_log "$LOGS/cache.log"
mkdir -p /run/squid && chown root:proxy /run/squid && chmod 775 /run/squid
rm -f "$MARKER" /run/squid/squid.pid

if [ ! -f "$RULES" ]; then
  echo "egress: no generated/rules.conf — every website is DENIED until you run: ./ohermes reconf" >&2
  grep -v '^include /etc/squid/hermes/generated/' "$CONF" > /run/hermes-first-boot.conf
  CONF=/run/hermes-first-boot.conf
  touch "$MARKER"
fi

# daily log rename: access.log → access-<yesterday>.log (ops/logs.sh archives old ones)
(
  while :; do
    now=$(date +%s); next=$(date -d 'tomorrow 00:00' +%s)
    sleep $((next - now))
    day=$(date -d yesterday +%F)
    [ -f "$LOGS/access.log" ] && mv "$LOGS/access.log" "$LOGS/access-$day.log"
    [ -f "$LOGS/cache.log" ] && mv "$LOGS/cache.log" "$LOGS/cache-$day.log"
    new_log "$LOGS/access.log"; new_log "$LOGS/cache.log"
    squid -f "$CONF" -k rotate || true
  done
) &

exec squid -f "$CONF" -NYC
