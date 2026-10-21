#!/bin/sh
# Entrypoint wrapper for each employee's Hermes container:
#  1) apply the organization's settings (setup.py, as root) — fails closed on a first boot
#  2) drop the central AI settings from the environment (Hermes gets the key only through the
#     read-only /opt/data/.env written by setup.py)
#  3) first start only: install the local browser driver (agent-browser, Hermes' own package
#     manager) into /opt/data/tools as the hermes user, through the egress proxy, in the background
#     — needs registry.npmjs.org to be allowed in Config/ohermes.conf when `default deny`
#  4) hand over to the image's own entrypoint (stays PID 1)
set -e
/opt/hermes/.venv/bin/python /opt/enterprise/bin/setup.py
unset HOE_AI_PROVIDER HOE_AI_MODEL HOE_AI_BASE_URL HOE_AI_API_KEY

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
