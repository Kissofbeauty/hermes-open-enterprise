#!/usr/bin/env bash
# firewall.sh — OPTIONAL host firewall for a Linux server running Hermes Open Enterprise
# (security review M-05). Not run by anything automatically: read it, then run it yourself.
#
#   sudo Infrastructure/host/firewall.sh apply      add the rules (idempotent)
#   sudo Infrastructure/host/firewall.sh remove     take them out again
#   sudo Infrastructure/host/firewall.sh status     show them
#
# Why: every employee network is `internal: true`, but the host still has an address on it (the
# gateway, .1/.17/… of each /28). Anything on the host that listens on 0.0.0.0 — sshd, monitoring
# agents, databases, the Docker API over TCP — can be reached by an agent through that address.
# Agents need nothing from the host: they only talk to Caddy (inbound) and the egress proxy (out),
# both containers on the same network.
#
# What it does (iptables, the backend Docker itself uses):
#   INPUT        new connections from the employee range (NETWORK_PREFIX.0.0/16) to the host → DROP
#                (replies to connections the host opened, e.g. published ports → Caddy, still pass)
#   DOCKER-USER  new connections from the employee range to anything NOT in that range → DROP
#                (container-to-container traffic on the same network is bridged and stays allowed;
#                internal networks have no route out anyway — this is a second lock)
# Published ports (Caddy on 127.0.0.1:8080 or CADDY_BIND) are not affected: that traffic comes from
# the host / cloudflared, not from the employee range.
# Persist the rules with your distribution's tool (iptables-persistent, firewalld direct rules, …);
# Docker re-creates DOCKER-USER at start but keeps rules already in it.
# IPv6: employee networks are IPv4-only in this template.
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
prefix="$(grep -E '^NETWORK_PREFIX=' "$ROOT/.env" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d "'\" \r")"
prefix="${prefix:-10.213}"
[[ "$prefix" =~ ^[0-9]{1,3}\.[0-9]{1,3}$ ]] || { echo "NETWORK_PREFIX in .env must look like 10.213" >&2; exit 1; }
RANGE="$prefix.0.0/16"
TAG="hermes-open-enterprise M-05"

[[ "$(uname -s)" == Linux ]] || { echo "Linux hosts only" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
command -v iptables >/dev/null || { echo "iptables not found" >&2; exit 1; }

rule() { # <-A|-D|-C> <chain> <args…>
  local op="$1" chain="$2"; shift 2
  iptables -w "$op" "$chain" "$@" -m comment --comment "$TAG"
}
ensure() { local chain="$1"; shift; rule -C "$chain" "$@" 2>/dev/null || rule -I "$chain" "$@"; }
drop()   { local chain="$1"; shift; while rule -C "$chain" "$@" 2>/dev/null; do rule -D "$chain" "$@"; done; }

RULES_INPUT=(-s "$RANGE" -m conntrack --ctstate NEW -j DROP)
RULES_FORWARD=(-s "$RANGE" ! -d "$RANGE" -m conntrack --ctstate NEW -j DROP)

case "${1:-}" in
  apply)
    iptables -w -n -L DOCKER-USER >/dev/null 2>&1 || { echo "chain DOCKER-USER missing — is Docker running?" >&2; exit 1; }
    ensure INPUT "${RULES_INPUT[@]}"
    ensure DOCKER-USER "${RULES_FORWARD[@]}"
    echo "applied: $RANGE → host (INPUT) and → outside the range (DOCKER-USER) dropped"
    echo "test from an employee container: no connection to the gateway (e.g. port 22) — guides/admin.md section 11"
    ;;
  remove)
    drop INPUT "${RULES_INPUT[@]}"
    drop DOCKER-USER "${RULES_FORWARD[@]}"
    echo "removed"
    ;;
  status)
    iptables -w -S INPUT | grep -F "$TAG" || echo "INPUT: no rule"
    iptables -w -S DOCKER-USER 2>/dev/null | grep -F "$TAG" || echo "DOCKER-USER: no rule"
    ;;
  *)
    sed -n '2,8p' "$0"; exit 2 ;;
esac
