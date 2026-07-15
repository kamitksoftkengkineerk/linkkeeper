"""
commandbus.py — file-based command channel between the (unelevated) dashboard
and the (elevated) daemon.

The dashboard can't do privileged things (apply Windows fixes, install the task,
scan/join open Wi-Fi). It drops a command file in logs/commands/<id>.json; the
daemon processes it each cycle and writes logs/results/<id>.json. File-per-command
means no concurrent-write races on a shared file, and either side can read the
other's directory without locking.
"""

from __future__ import annotations

import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CMD_DIR = os.path.join(HERE, "logs", "commands")
RES_DIR = os.path.join(HERE, "logs", "results")

# Only these actions are honoured by the daemon — an allowlist so a stray file
# can't make the elevated daemon run anything arbitrary.
ALLOWED = {
    "apply_windows_fixes",
    "install_task",
    "uninstall_task",
    "scan_open",
    "join_open",
    "forget_open",
    "enable_location_help",
}


def _write_json(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def _new_id() -> str:
    # monotonic-ish unique id without Date.now (fine here — real clock allowed)
    return f"{int(time.time()*1000)}-{os.getpid()}-{len(os.listdir(CMD_DIR)) if os.path.isdir(CMD_DIR) else 0}"


# ---- dashboard side ---------------------------------------------------------

def submit(action: str, args: dict | None = None) -> str:
    """Enqueue a command; returns its id. Rejects non-allowlisted actions."""
    if action not in ALLOWED:
        raise ValueError(f"action not allowed: {action}")
    cid = _new_id()
    _write_json(os.path.join(CMD_DIR, cid + ".json"),
                {"id": cid, "action": action, "args": args or {},
                 "submitted": time.time()})
    return cid


def result(cid: str) -> dict | None:
    """Read a command's result, or None if not done yet."""
    try:
        with open(os.path.join(RES_DIR, cid + ".json"), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# ---- daemon side ------------------------------------------------------------

def pending() -> list[dict]:
    """Return unprocessed commands (those without a result file), oldest first."""
    if not os.path.isdir(CMD_DIR):
        return []
    out = []
    for fn in sorted(os.listdir(CMD_DIR)):
        if not fn.endswith(".json"):
            continue
        cid = fn[:-5]
        if os.path.exists(os.path.join(RES_DIR, cid + ".json")):
            continue
        try:
            with open(os.path.join(CMD_DIR, fn), "r", encoding="utf-8") as fh:
                cmd = json.load(fh)
            if cmd.get("action") in ALLOWED:
                out.append(cmd)
        except (OSError, ValueError):
            continue
    return out


def complete(cid: str, ok: bool, output=None) -> None:
    """Record a command's result and remove the request file."""
    _write_json(os.path.join(RES_DIR, cid + ".json"),
                {"id": cid, "ok": ok, "output": output, "done": time.time()})
    try:
        os.remove(os.path.join(CMD_DIR, cid + ".json"))
    except OSError:
        pass


def prune(max_age_seconds: int = 3600) -> None:
    """Delete result files older than max_age so the dir doesn't grow forever."""
    if not os.path.isdir(RES_DIR):
        return
    now = time.time()
    for fn in os.listdir(RES_DIR):
        p = os.path.join(RES_DIR, fn)
        try:
            if now - os.path.getmtime(p) > max_age_seconds:
                os.remove(p)
        except OSError:
            pass
