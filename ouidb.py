"""
ouidb.py — offline MAC -> vendor lookup for the Network tab.

Turns a device MAC into the maker's name ("OnePlus", "Apple", "Realtek") using a
bundled, trimmed copy of the IEEE MA-L (24-bit OUI) registry — no network call,
no third-party module. The data ships as `oui.csv.gz` (~310 KB) next to this
file; it is loaded lazily on the first lookup and cached in memory.

Only the manufacturer's *own* MACs resolve. Two cases return "" by design:
  * randomized/locally-administered MACs (modern phones on Wi-Fi) — no maker owns
    them, so there is nothing truthful to show; the Network tab labels these
    "randomized MAC" separately.
  * 28/36-bit (MA-M / MA-S) sub-allocations — a shared 24-bit prefix maps to many
    small vendors, so we don't guess; those simply read as unknown.
"""

from __future__ import annotations

import gzip
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_DATA = os.path.join(HERE, "oui.csv.gz")

_table: dict[str, str] | None = None   # "AABBCC" -> "Vendor"; None until loaded


def _load() -> dict[str, str]:
    """Parse oui.csv.gz once into {6-hex-prefix: vendor}. A missing/corrupt data
    file degrades to an empty table (every lookup returns "") — never raises, so
    a packaging slip can't take the daemon or dashboard down."""
    global _table
    if _table is not None:
        return _table
    table: dict[str, str] = {}
    try:
        with gzip.open(_DATA, "rt", encoding="utf-8") as fh:
            for line in fh:
                prefix, _, name = line.rstrip("\n").partition("\t")
                if len(prefix) == 6 and name:
                    table[prefix] = name
    except (OSError, EOFError, ValueError):
        table = {}
    _table = table
    return table


def _prefix(mac: str) -> str:
    """First three octets of a MAC as 6 uppercase hex chars, or '' if unparseable.
    Accepts AA-BB-CC-..., AA:BB:CC:..., or aabbcc... forms."""
    hexonly = "".join(c for c in str(mac) if c in "0123456789abcdefABCDEF")
    return hexonly[:6].upper() if len(hexonly) >= 6 else ""


def _is_locally_administered(prefix: str) -> bool:
    """True if bit 1 of the first octet is set — a randomized/local MAC no
    registered vendor owns. Skip the lookup for these (see module docstring)."""
    try:
        return bool(int(prefix[0:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def vendor(mac: str) -> str:
    """Best-effort maker name for a MAC, or "" when unknown/randomized."""
    prefix = _prefix(mac)
    if not prefix or _is_locally_administered(prefix):
        return ""
    return _load().get(prefix, "")


def count() -> int:
    """Number of vendor prefixes loaded (0 if the data file is missing)."""
    return len(_load())


if __name__ == "__main__":
    import sys
    print(f"{count()} OUI prefixes loaded")
    for m in sys.argv[1:]:
        print(f"  {m:20} -> {vendor(m) or '(unknown/randomized)'}")
