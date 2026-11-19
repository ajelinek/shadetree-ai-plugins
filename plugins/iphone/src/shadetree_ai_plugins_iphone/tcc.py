"""Full Disk Access (macOS TCC) diagnostics shared by the doctors and iphone_setup.

macOS checks Full Disk Access against the *responsible* process, not the process
that opens the file. Claude Desktop starts MCP servers through a helper that
makes the server's first binary responsible, so FDA on Claude.app does not
apply. `.mcp.json` therefore launches the bundled "Shadetree iPhone Bridge.app"
(see bridge/iphone_bridge.c), which always makes itself responsible, so users
grant FDA to that one app. Under a dev launch (`uv run` from a terminal) the
responsible process is the terminal instead; `responsible_binary()` reports
whichever it really is.
"""

from __future__ import annotations

import ctypes
import errno
import os
import sys
from pathlib import Path

BRIDGE_APP_NAME = "Shadetree iPhone Bridge.app"
FDA_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"

_DENIED_ERRNOS = {errno.EPERM, errno.EACCES}


def bridge_app_path() -> Path:
    # src/shadetree_ai_plugins_iphone/tcc.py -> plugin root is three levels up.
    return Path(__file__).resolve().parents[2] / "bin" / BRIDGE_APP_NAME


def responsible_binary() -> str | None:
    """Real path of the binary macOS checks Full Disk Access against, or None."""
    if sys.platform != "darwin":
        return None
    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        get_responsible = lib.responsibility_get_pid_responsible_for_pid
        get_responsible.argtypes = [ctypes.c_int]
        get_responsible.restype = ctypes.c_int
        pid = get_responsible(os.getpid())
        if pid <= 0:
            return None
        buf = ctypes.create_string_buffer(4096)
        if lib.proc_pidpath(pid, buf, len(buf)) <= 0:
            return None
        return os.path.realpath(buf.value.decode())
    except (OSError, AttributeError, UnicodeDecodeError):
        return None


def grant_target(binary: str | None) -> str | None:
    """What to add under Full Disk Access: the enclosing .app bundle, else the binary."""
    if not binary:
        return None
    parts = Path(binary).parts
    for i, part in enumerate(parts):
        if part.endswith(".app"):
            return str(Path(*parts[: i + 1]))
    return binary


def classify_access(path: str) -> str:
    """'readable', 'denied' (TCC/permissions), 'missing', or 'error'.

    Opens the file itself rather than going through SQLite, whose
    'unable to open database file' message hides whether the cause was a
    permission denial or something else.
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return "denied" if exc.errno in _DENIED_ERRNOS else "error"
    os.close(fd)
    return "readable"


def fda_report() -> dict:
    binary = responsible_binary()
    target = grant_target(binary)
    return {
        "checked_against": binary,
        "grant_to": target,
        "via_bridge": bool(target) and Path(target).name == BRIDGE_APP_NAME,
    }


def denied_message(db_path: str) -> str:
    report = fda_report()
    target = report["grant_to"]
    if report["via_bridge"]:
        who = f'"{BRIDGE_APP_NAME[:-4]}" ({target})'
    elif target:
        who = f"{target}, which is the app macOS checks for this server"
    else:
        who = "the app running this MCP server"
    return (
        f"macOS denied access to {db_path} (Full Disk Access not granted). Grant Full Disk "
        f"Access to {who}: call the iphone_setup tool, which opens the right System Settings "
        f"page and shows the app in Finder, then drag it into the list, turn it on, and quit "
        f"and reopen Claude. Granting Full Disk Access to Claude.app does NOT work for Claude "
        f"Desktop."
    )
