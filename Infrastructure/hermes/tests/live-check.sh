#!/usr/bin/env bash
# Regression check of the read-only parts of one running employee container (security review
# H-01/H-02/M-07, R5-02/R5-04/R5-05, QA D5–D7). Changes nothing; every probe runs as the agent user (hermes).
#   Infrastructure/hermes/tests/live-check.sh <server name>      (on the server: with sudo)
set -uo pipefail
export MSYS_NO_PATHCONV=1
name="${1:?usage: live-check.sh <server name>}"
c="$(docker ps -q --filter "label=hermes.username=$name" | head -n1)"
[[ -n "$c" ]] || { echo "no running container for $name"; exit 2; }
fail=0
as_agent() { docker exec "$c" /command/s6-setuidgid hermes sh -c "$1" >/dev/null 2>&1; }
expect_fail() { # <what> <shell as the agent>
  if as_agent "$2"; then echo "FAIL  $1 (the agent could do it)"; fail=1; else echo "ok    $1 refused"; fi
}
expect_ok() {
  if as_agent "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi
}

# M-07: nothing can be added next to (or replace) the org-guard plugin
expect_fail "new plugin folder in /opt/data/plugins" "mkdir /opt/data/plugins/qa-shadow"
expect_fail "change org-guard"                       "echo x >> /opt/data/plugins/org-guard/plugin.yaml"
# H-01: no Hermes profile (own config.yaml) and no sticky active profile
expect_fail "create a profile"                       "mkdir /opt/data/profiles/qa"
expect_fail "set an active profile"                  "echo qa > /opt/data/active_profile"
# H-02: persona and settings are read-only
expect_fail "write SOUL.md"                          "echo x >> /opt/data/SOUL.md"
expect_fail "write config.yaml"                      "echo x >> /opt/data/config.yaml"
expect_fail "write .env"                             "echo x >> /opt/data/.env"
expect_fail "read the dashboard login file"          "cat /opt/enterprise/secrets.env"
expect_fail "add a gateway hook"                     "mkdir /opt/data/hooks/x"
# R5-02: shell start files in HOME are empty read-only mounts, and Hermes does not source them
for f in .profile .bash_profile .bash_login .bashrc .bash_logout .inputrc; do
  expect_fail "write ~/$f"                           "echo 'echo planted' >> /opt/data/$f"
  expect_fail "replace ~/$f"                         "rm -f /opt/data/$f"
done
expect_ok   "shell start files are empty"            "! test -s /opt/data/.bashrc && ! test -s /opt/data/.profile"
expect_ok   "Python user site is off"                "test \"\$PYTHONNOUSERSITE\" = 1"
expect_ok   "auto_source_bashrc off in the settings" "grep -q '\"auto_source_bashrc\": false' /opt/data/config.yaml"
# R5-04: provider lock built from the image's provider tables (saved copy present)
expect_ok   "provider tables saved (root-owned)"     "test -s /opt/enterprise/runtime/provider-facts.json -a ! -O /opt/enterprise/runtime/provider-facts.json"
# models.dev catalog (provider definitions) is fixed at start: read-only, cannot be replaced
expect_fail "write the models.dev catalog"           "echo '{}' > /opt/data/models_dev_cache.json"
expect_fail "rename the models.dev catalog"          "mv /opt/data/models_dev_cache.json /opt/data/x.json"
expect_fail "remove the models.dev catalog"          "rm -f /opt/data/models_dev_cache.json"
expect_fail "write the catalog ETag"                 "echo x > /opt/data/models_dev_cache.etag"
expect_ok   "catalog refresh pinned to a dead URL"   "grep -q 'catalog-is-fixed-at-start' /opt/data/config.yaml"
# R5-05: process limit
pids="$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$c")"
if [[ "$pids" =~ ^[0-9]+$ ]] && (( pids > 0 )); then echo "ok    pids limit $pids"; else echo "FAIL  no pids limit"; fail=1; fi
# Website rules (Config/ohermes.conf) are never mounted into an agent: only 3 Config files are
expect_fail "read the website rules"                 "ls /opt/enterprise/config/ohermes.conf"
expect_ok   "only defaults/enforced/SOUL in config"  "test \"\$(ls -A /opt/enterprise/config | tr '\n' ' ')\" = 'SOUL.md defaults.yaml enforced.yaml '"
# D5: Hermes owns its data (logs written, nothing left root-owned outside the mounts)
expect_ok   "Hermes log written by hermes"           "test -s /opt/data/logs/agent.log -a -O /opt/data/logs/agent.log"
expect_ok   "memories/ writable by hermes"           "test -w /opt/data/memories"
roots="$(docker exec "$c" sh -c 'find /opt/data -xdev -maxdepth 3 -user 0 2>/dev/null' \
  | grep -vE '^/opt/data/(config\.yaml|\.env|auth\.json|SOUL\.md|active_profile|hooks|plugins|profiles|\.profile|\.bash_profile|\.bash_login|\.bashrc|\.bash_logout|\.inputrc|models_dev_cache\.json|models_dev_cache\.etag)(/|$)')"
if [[ -n "$roots" ]]; then echo "FAIL  root-owned entries in /opt/data:"; printf '      %s\n' $roots; fail=1
else echo "ok    nothing root-owned in /opt/data (besides the read-only mounts)"; fi
if docker logs "$c" 2>&1 | grep -q "01-hermes-setup exited 1"; then echo "FAIL  image setup (01-hermes-setup) failed"; fail=1
else echo "ok    image setup (01-hermes-setup) did not fail"; fi
exit $fail
