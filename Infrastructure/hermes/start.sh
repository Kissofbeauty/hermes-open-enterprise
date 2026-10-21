#!/bin/sh
# Entrypoint wrapper for each employee's Hermes container:
#  1) apply the organization's settings (setup.py, as root) — fails closed on a first boot
#  2) drop the central AI settings from the environment (Hermes gets the key only through the
#     read-only /opt/data/.env written by setup.py)
#  3) first start only: install the local browser driver (agent-browser, Hermes' own package
#     manager) into /opt/data/tools as the hermes user, through the egress proxy, in the background
#     — needs registry.npmjs.org to be allowed in Config/ohermes.conf when `default deny`
#  4) hand over to the image's own entrypoint (stays PID 1)
# Before 4: the dashboard login (HERMES_DASHBOARD_BASIC_AUTH_*) from /opt/enterprise/secrets.env
# (Users/<name>/secrets.env, root only on the host) is exported — read as data, never executed.
set -e
/opt/hermes/.venv/bin/python /opt/enterprise/bin/setup.py
unset HOE_AI_PROVIDER HOE_AI_MODEL HOE_AI_BASE_URL HOE_AI_API_KEY

if [ -f /opt/enterprise/secrets.env ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    key="${line%%=*}"; val="${line#*=}"
    case "$key" in HERMES_DASHBOARD_BASIC_AUTH_*) ;; *) continue ;; esac
    case "$key" in *[!A-Z0-9_]*) continue ;; esac
    case "$val" in
      \'*\') val="${val#\'}"; val="${val%\'}" ;;
      \"*\") val="${val#\"}"; val="${val%\"}" ;;
    esac
    export "$key=$val"
  done < /opt/enterprise/secrets.env
  unset line key val
fi

if ! ls -d /opt/data/tools/agent-browser-* >/dev/null 2>&1; then
  (
    sleep 15
    if /command/s6-setuidgid hermes /opt/hermes/.venv/bin/hermes pm install agent-browser >/dev/null 2>&1; then
      echo "[enterprise-setup] browser driver (agent-browser) installed — the browser tools appear in new chats"
    else
      echo "[enterprise-setup] WARNING: could not install the browser driver (agent-browser); allow registry.npmjs.org in Config/ohermes.conf, then restart"
    fi
  ) &
fi

exec /opt/hermes/docker/entrypoint-dispatch.sh "$@"
