"""org-guard — Hermes Open Enterprise guard plugin (mounted read-only at /opt/data/plugins/org-guard,
enabled by Config/enforced.yaml → plugins.enabled).

Hooks
  pre_tool_call            block / ask approval (see guard.py). Hermes FAILS CLOSED when this raises.
  transform_tool_result    strip invisible Unicode, redact secret values, wrap outside content as
  transform_terminal_output  untrusted. Hermes FAILS OPEN here, so every error is caught and the
                           result is then replaced by a safe notice instead of passing unfiltered.

Every block/approval request writes one line to the container log:
  ORG-GUARD BLOCK user=<owner> tool=<tool> reason=<code> src=<process> seq=<n> sig=<hmac>
(never a secret value), through the process's stderr = the container's stderr (see _channel).
The agent cannot open that pipe, but a program Hermes starts without redirecting stderr (e.g. the
agent-writable browser driver) inherits it — so lines are signed (security review R5-06): each
Hermes process makes a random key at start that lives only in its memory, announces it once with
`ORG-GUARD KEY src=… key=…` in the container log (which the agent cannot read) and signs every
line with it, numbered. Check a log with
Infrastructure/hermes/verify_guard_log.py — unsigned, badly signed or re-numbered lines are forged.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import sys
import threading

from . import guard as _g

ENV_FILES = ("/opt/data/.env", "/opt/enterprise/runtime/hermes.env")
ENV_DIRS = ("/run/s6/container_environment",)
PROTECTED_SKILLS = "/opt/enterprise/runtime/org-skill-names.json"
CONFIG = "/opt/data/config.yaml"   # org_guard: section (Config/enforced.yaml), read-only
OWNER = os.environ.get("OWNER_USERNAME", "") or "unknown"

_lock = threading.Lock()
_guard = None


def _get() -> "_g.Guard":
    global _guard
    with _lock:
        if _guard is None:
            org = _g.OrgIndex(warn=lambda m: _container_log(f"ORG-GUARD WARNING user={OWNER} {m}"))                 if os.path.isdir(_g.ORG_ROOT) else None
            settings = _g.load_settings(CONFIG)
            _guard = _g.Guard(_g.Secrets(env_files=ENV_FILES, env_dirs=ENV_DIRS), org,
                              owner_email=os.environ.get("OWNER_EMAIL", ""),
                              protected_skills=_g.load_protected_skills(PROTECTED_SKILLS),
                              min_org_chars=int(settings.get("min_org_chars") or _g.MIN_ORG_CHARS))
        return _guard


# per-process signing key (memory only) — see the module docstring
_LOG_KEY = secrets.token_bytes(32)
_LOG_SRC = f"{os.getpid()}-{secrets.token_hex(4)}"
_log_lock = threading.Lock()
_log_state = {"seq": 0, "announced": False}


def _sign(body: str) -> str:
    return hmac.new(_LOG_KEY, body.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def _channel():
    """Writer for the container log (docker compose logs <name>), or None. In the image, every Hermes
    process started by s6 (gateway, dashboard) has the container's stderr as fd 2 — a pipe owned by
    root: the agent cannot open it through /proc (EACCES, tested) and its commands do not inherit it.
    The gateway's stdout goes to a log file under /opt/data/logs that the agent can read, so neither
    the key nor the lines go there. Not a pipe (e.g. a terminal, a file) → None."""
    try:
        if stat.S_ISFIFO(os.fstat(2).st_mode):
            return lambda text: os.write(2, text.encode("utf-8"))
    except OSError:
        pass
    return None


def _container_log(line: str) -> None:
    """One signed, numbered line to the container log; the key is announced first (once). Without
    that channel the line goes to stdout marked `sig=none` (no key is ever written there)."""
    with _log_lock:
        _log_state["seq"] += 1
        body = f"{line} src={_LOG_SRC} seq={_log_state['seq']}"
        write = _channel()
        if write is not None:
            try:
                if not _log_state["announced"]:
                    write(f"ORG-GUARD KEY src={_LOG_SRC} key={_LOG_KEY.hex()}\n")
                    _log_state["announced"] = True
                write(f"{body} sig={_sign(body)}\n")
                return
            except OSError:
                pass
        try:
            os.write(1, f"{body} sig=none\n".encode())
        except OSError:
            pass


def _log(verdict, tool: str) -> None:
    kind = "BLOCK" if verdict.get("action") == "block" else "APPROVAL"
    _container_log(f"ORG-GUARD {kind} user={OWNER} tool={tool} reason={verdict.reason}")


def _session_places(task_id, session_id):
    """(cwds, resolve) for this call, taken from Hermes itself (QA D13/D14):
      cwds    the base dir Hermes' file tools resolve relative paths against
              (tools.file_tools_paths._resolve_base_dir), the cwd the terminal tool recorded for
              this call under every key it may use (task id, session id, the current session key —
              tools.terminal_tool.get_session_cwd, written after each command and read as the next
              command's cwd), $TERMINAL_CWD and the process cwd. A line is checked against all of
              them (false positives on purpose). Other sessions' records are not used: one
              session's cwd must not block another session's work.
      resolve tools.file_tools_paths._resolve_path_for_task bound to this task.
    Any import problem leaves fewer places (the process cwd at least), never an exception."""
    tid = str(task_id or "") or "default"
    cwds, resolve = [], None
    try:
        from tools import terminal_tool as tt
        keys = {tid, str(session_id or "")}
        try:
            from tools.approval import get_current_session_key
            keys.add(get_current_session_key(default=""))
        except Exception:
            pass
        for k in keys:
            if k:
                cwds.append(tt.get_session_cwd(k))
    except Exception:
        pass
    try:
        from tools.file_tools_paths import _resolve_base_dir, _resolve_path_for_task
        cwds.append(str(_resolve_base_dir(tid)))

        def resolve(path):
            return str(_resolve_path_for_task(path, tid))
    except Exception:
        resolve = None
    cwds.append(os.environ.get("TERMINAL_CWD", ""))
    cwds.append(os.getcwd())
    return [c for c in dict.fromkeys(cwds) if isinstance(c, str) and c and os.path.isabs(c)], resolve


def pre_tool_call(tool_name=None, args=None, session_id=None, task_id=None, **_kw):
    # Exceptions propagate on purpose: Hermes turns them into a block (fail closed).
    cwds, resolve = _session_places(task_id, session_id)
    verdict = _get().check_call(str(tool_name or ""), args or {}, str(session_id or task_id or ""),
                                cwds=cwds, resolve=resolve)
    if verdict is None:
        return None
    _log(verdict, str(tool_name))
    return dict(verdict)


_FAILED = ("<<org-guard could not check this tool output, so it was withheld. "
           "Tell the user the tool output is unavailable.>>")


def transform_tool_result(tool_name=None, args=None, result=None, **_kw):
    try:
        return _get().clean_result(str(tool_name or ""), args or {}, result)
    except Exception:
        return _FAILED


def transform_terminal_output(command=None, output=None, **_kw):
    try:
        return _get().clean_terminal(str(command or ""), output)
    except Exception:
        return _FAILED


def _announce_key() -> None:
    """KEY line at plugin load, before the agent runs any tool in this process."""
    with _log_lock:
        write = _channel()
        if write is None or _log_state["announced"]:
            return
        try:
            write(f"ORG-GUARD KEY src={_LOG_SRC} key={_LOG_KEY.hex()}\n")
            _log_state["announced"] = True
        except OSError:
            pass


def register(ctx):
    try:
        _announce_key()
    except Exception:   # noqa: BLE001 — logging must never stop the guard from loading
        pass
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
    ctx.register_hook("transform_terminal_output", transform_terminal_output)
