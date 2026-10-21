#!/usr/bin/env python3
"""Check the org-guard lines of one employee's container log (security review R5-06).

    docker compose logs --no-log-prefix --timestamps <name> | python3 Infrastructure/hermes/verify_guard_log.py

The agent runs as the same user as Hermes and can write lines into the container log too. Each
Hermes process signs its ORG-GUARD lines with a random key that exists only in its memory and is
announced once in the container log (`ORG-GUARD KEY src=… key=…`, which the agent cannot read).
This script reports:
  ok        signed with the key of its src, numbers going up
  FORGED    no signature, a wrong signature, or a src without a KEY line
  REPLAYED  a number that was already used (a valid line copied again)
  DUP-KEY   a second KEY line for the same src (an agent cannot replace a key this way)
KEY lines appear when a Hermes process starts (container start, a new dashboard chat). A KEY line
for an unknown process at an odd time may be an agent's own key: treat its lines as unproven.
Exit code 1 when anything is flagged. Standard library only.
"""
import hashlib
import hmac
import re
import sys

KEY = re.compile(r"ORG-GUARD KEY src=(\S+) key=([0-9a-f]{64})\s*$")
LINE = re.compile(r"(ORG-GUARD (?!KEY ).*? src=(\S+) seq=(\d+)) sig=(\S+)\s*$")


def main() -> int:
    keys, last, counts, flagged = {}, {}, {"ok": 0}, 0
    for raw in sys.stdin:
        if "ORG-GUARD" not in raw:
            continue
        text = raw.rstrip("\n")
        m = KEY.search(text)
        if m:
            src, key = m.group(1), bytes.fromhex(m.group(2))
            if src in keys and keys[src] != key:
                print(f"DUP-KEY   {text}")
                flagged += 1
            keys.setdefault(src, key)
            continue
        m = LINE.search(text)
        if not m:
            print(f"FORGED    {text}")
            flagged += 1
            continue
        body, src, seq, sig = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        key = keys.get(src)
        good = key is not None and hmac.compare_digest(
            hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()[:32], sig)
        if not good:
            print(f"FORGED    {text}")
            flagged += 1
        elif seq <= last.get(src, 0):
            print(f"REPLAYED  {text}")
            flagged += 1
        else:
            last[src] = seq
            counts["ok"] += 1
    print(f"{counts['ok']} signed line(s) ok, {flagged} flagged, {len(keys)} key(s)")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
