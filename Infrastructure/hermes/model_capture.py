"""`ohermes model` helper — runs in the throwaway container after Hermes' own `hermes model`.

Reads the temporary HERMES_HOME that `hermes model` just wrote and saves only the AI model:
  <out>/model.yaml   {model: {provider, default, base_url?, api_mode?, key_env}}
  <out>/model.env    <KEY_VAR>=<key>
Nothing else from the temporary home is kept. Only API-key providers are supported (OAuth
logins live in auth.json, which is not carried over).

Usage: model_capture.py <temporary HERMES_HOME> <out dir>
"""
import os
import re
import sys

sys.path.insert(0, "/opt/hermes")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from setup import parse_env, provider_key_var, dump_yaml, load_map  # noqa: E402

KEEP = ("provider", "default", "base_url", "api_mode", "context_length")


def main(home: str, out: str) -> int:
    model = load_map(os.path.join(home, "config.yaml")).get("model")
    if not isinstance(model, dict) or not model.get("provider"):
        print("ohermes model: no model was chosen — nothing saved", file=sys.stderr)
        return 2
    env = parse_env(open(os.path.join(home, ".env"), encoding="utf-8").read()) if os.path.isfile(
        os.path.join(home, ".env")) else {}

    # where did `hermes model` put the key?
    src = ""
    ref = str(model.get("api_key", ""))
    m = re.fullmatch(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}", ref)
    if m:
        src = m.group(1)
    elif model.get("key_env"):
        src = str(model["key_env"])
    else:
        src = provider_key_var(str(model["provider"]))
    key = env.get(src, "") if src else ""
    if not key and ref and not m:
        key = ref                      # key written inline into config.yaml
    if not key:
        print("ohermes model: no API key found — only providers that use an API key are supported "
              "(OAuth logins are not)", file=sys.stderr)
        return 3
    if any(c in key for c in "\n\r'\"") or len(key) > 4096:
        print("ohermes model: the API key contains characters that cannot be stored", file=sys.stderr)
        return 3

    var = provider_key_var(str(model["provider"])) or src
    saved = {k: model[k] for k in KEEP if model.get(k) not in (None, "")}
    saved["key_env"] = var
    old = os.umask(0o077)
    try:
        with open(os.path.join(out, "model.yaml"), "w", encoding="utf-8") as fh:
            fh.write("# Personal AI model — written by `ohermes model`, read by setup.py. No key here.\n")
            fh.write(dump_yaml({"model": saved}))
        with open(os.path.join(out, "model.env"), "w", encoding="utf-8") as fh:
            fh.write(f"{var}={key}\n")
    finally:
        os.umask(old)
    print(f"ohermes model: captured provider={saved['provider']} model={saved.get('default', '?')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
