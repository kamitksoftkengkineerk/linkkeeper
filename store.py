"""
store.py — durable SQLite records for LinkKeeper (stdlib sqlite3, no deps).

Keeps the long-term history the live status.json snapshot cannot: every device
ever seen, presence changes, new-device alerts, WAN switches/outages, and
per-link quality samples. WAL mode so the single-threaded daemon can write while
the threaded dashboard reads its own connection. Every writer is best-effort —
a DB error must NEVER break the failover loop.

SQLite comfortably handles this: the low-volume tables are KBs-MBs over years;
the only heavy stream is link_samples (~1 GB/year at one sample per cycle),
which is trivial for SQLite on an NVMe with the indexes below.
"""
from __future__ import annotations

import os
import sqlite3
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "logs", "linkkeeper.db")
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS devices (
  mac TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, last_ip TEXT,
  name TEXT, vendor TEXT, randomized INTEGER DEFAULT 0,
  trusted INTEGER DEFAULT 0, times_seen INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS device_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, mac TEXT, event TEXT, ip TEXT
);
CREATE INDEX IF NOT EXISTS ix_devev_ts ON device_events(ts);
CREATE INDEX IF NOT EXISTS ix_devev_mac ON device_events(mac, ts);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, mac TEXT, ip TEXT, kind TEXT, note TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS switch_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, from_link TEXT, to_link TEXT,
  latency_ms REAL, reason TEXT
);
CREATE INDEX IF NOT EXISTS ix_switch_ts ON switch_history(ts);
CREATE TABLE IF NOT EXISTS outages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, started REAL, ended REAL, duration_s REAL
);
CREATE TABLE IF NOT EXISTS link_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, link TEXT, latency_ms REAL,
  jitter_ms REAL, loss_pct REAL, healthy INTEGER, is_primary INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ls_link_ts ON link_samples(link, ts);
CREATE INDEX IF NOT EXISTS ix_ls_ts ON link_samples(ts);
"""

_conn = None            # writer connection (daemon; single-threaded)
_online_state: dict = {}   # mac -> last online bool, for transition events
_alerted: dict = {}        # mac -> last alert ts (dedup)
_last_sample = 0.0         # rate-limit link_samples inserts
_open_outage = None        # rowid of an in-progress outage, or None


def _writer():
    global _conn
    if _conn is None:
        d = os.path.dirname(DB_PATH)
        if d:                       # '' for ':memory:' or a bare filename
            os.makedirs(d, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, timeout=5)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
    return _conn


def init_db(db_path=None):
    """Create the schema (idempotent). Safe to call at every startup. Pass
    db_path=':memory:' or a temp path for tests."""
    global DB_PATH, _conn, _online_state, _alerted, _last_sample, _open_outage
    if db_path:
        DB_PATH, _conn = db_path, None
        _online_state, _alerted, _last_sample, _open_outage = {}, {}, 0.0, None
    con = _writer()
    con.executescript(_SCHEMA)
    con.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),))
    con.commit()


def close():
    """Release the writer connection (tests / clean shutdown)."""
    global _conn
    if _conn is not None:
        try:
            _conn.close()
        except Exception:
            pass
        _conn = None


def _reader():
    """A fresh short-lived connection — thread-safe for the dashboard."""
    con = sqlite3.connect(DB_PATH, timeout=5)
    con.row_factory = sqlite3.Row
    return con


# ---- writers (best-effort; never raise into the daemon loop) ---------------

def record_scan(devices):
    """Upsert the device registry and log new/appeared/online/offline events."""
    try:
        con = _writer(); now = time.time(); c = con.cursor()
        for d in devices:
            mac = d.get("mac")
            if not mac:
                continue
            online = bool(d.get("online"))
            exists = c.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone()
            if not exists:
                c.execute(
                    "INSERT INTO devices(mac,first_seen,last_seen,last_ip,name,vendor,"
                    "randomized,trusted,times_seen) VALUES(?,?,?,?,?,?,?,?,1)",
                    (mac, d.get("first_seen", now), now, d.get("ip"), d.get("name", ""),
                     d.get("vendor", ""), int(bool(d.get("randomized"))), int(bool(d.get("known")))))
                c.execute("INSERT INTO device_events(ts,mac,event,ip) VALUES(?,?,?,?)",
                          (now, mac, "new" if d.get("is_new") else "appeared", d.get("ip")))
            else:
                c.execute(
                    "UPDATE devices SET last_seen=?, last_ip=?, name=?, "
                    "vendor=COALESCE(NULLIF(?,''),vendor), randomized=?, trusted=?, "
                    "times_seen=times_seen+? WHERE mac=?",
                    (now, d.get("ip"), d.get("name", ""), d.get("vendor", ""),
                     int(bool(d.get("randomized"))), int(bool(d.get("known"))),
                     1 if online else 0, mac))
                prev = _online_state.get(mac)
                if online and prev is not True:
                    c.execute("INSERT INTO device_events(ts,mac,event,ip) VALUES(?,?,?,?)",
                              (now, mac, "online", d.get("ip")))
                elif (not online) and prev is True:
                    c.execute("INSERT INTO device_events(ts,mac,event,ip) VALUES(?,?,?,?)",
                              (now, mac, "offline", d.get("ip")))
            _online_state[mac] = online
        con.commit()
    except Exception:
        pass


def record_alert(mac, ip=None, kind="intruder", note=""):
    """Log a new-device alert (deduped to once / 30 min per MAC)."""
    try:
        now = time.time()
        if now - _alerted.get(mac, 0) < 1800:
            return
        _alerted[mac] = now
        con = _writer()
        con.execute("INSERT INTO alerts(ts,mac,ip,kind,note) VALUES(?,?,?,?,?)",
                    (now, mac, ip, kind, note))
        con.commit()
    except Exception:
        pass


def record_switch(from_link, to_link, latency_ms=None, reason=""):
    """Log a WAN primary switch."""
    try:
        con = _writer()
        con.execute("INSERT INTO switch_history(ts,from_link,to_link,latency_ms,reason) "
                    "VALUES(?,?,?,?,?)", (time.time(), from_link, to_link, latency_ms, reason))
        con.commit()
    except Exception:
        pass


def _num(v):
    return None if v is None or v == float("inf") else round(float(v), 1)


def record_link_samples(links, primary_name=None, sample=True, interval=0):
    """Insert one quality sample per link (gated by `interval`) AND always track
    outage open/close from the healthy-link count."""
    global _last_sample, _open_outage
    try:
        con = _writer(); now = time.time()
        if sample and (not interval or now - _last_sample >= interval):
            _last_sample = now
            rows = [(now, getattr(lk, "name", None), _num(getattr(lk, "latency_ms", None)),
                     _num(getattr(lk, "jitter_ms", None)), _num(getattr(lk, "loss_pct", None)),
                     1 if getattr(lk, "healthy", False) else 0,
                     1 if (primary_name and getattr(lk, "name", None) == primary_name) else 0)
                    for lk in links]
            con.executemany("INSERT INTO link_samples(ts,link,latency_ms,jitter_ms,loss_pct,"
                            "healthy,is_primary) VALUES(?,?,?,?,?,?,?)", rows)
        # outage tracking (independent of the sample gate)
        if links:
            any_healthy = any(getattr(lk, "healthy", False) for lk in links)
            if not any_healthy and _open_outage is None:
                cur = con.execute("INSERT INTO outages(started,ended,duration_s) VALUES(?,?,?)",
                                  (now, None, None))
                _open_outage = cur.lastrowid
            elif any_healthy and _open_outage is not None:
                row = con.execute("SELECT started FROM outages WHERE id=?", (_open_outage,)).fetchone()
                started = row[0] if row else now
                con.execute("UPDATE outages SET ended=?, duration_s=? WHERE id=?",
                            (now, now - started, _open_outage))
                _open_outage = None
        con.commit()
    except Exception:
        pass


def prune(retention_days):
    """Drop link_samples older than retention_days (0/None = keep forever)."""
    if not retention_days or retention_days <= 0:
        return
    try:
        con = _writer()
        con.execute("DELETE FROM link_samples WHERE ts < ?",
                    (time.time() - retention_days * 86400,))
        con.commit()
    except Exception:
        pass


# ---- readers (dashboard; own connection per call) --------------------------

def all_devices(limit=300):
    try:
        con = _reader()
        rows = con.execute("SELECT mac,name,last_ip,last_seen,first_seen,times_seen,"
                           "trusted,randomized FROM devices ORDER BY last_seen DESC LIMIT ?",
                           (limit,)).fetchall()
        con.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def recent_events(limit=150):
    try:
        con = _reader()
        rows = con.execute("SELECT ts,mac,event,ip FROM device_events ORDER BY id DESC LIMIT ?",
                           (limit,)).fetchall()
        con.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def device_timeline(mac, limit=200):
    try:
        con = _reader()
        d = con.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        ev = con.execute("SELECT ts,event,ip FROM device_events WHERE mac=? ORDER BY id DESC LIMIT ?",
                         (mac, limit)).fetchall()
        al = con.execute("SELECT ts,kind,note FROM alerts WHERE mac=? ORDER BY id DESC LIMIT ?",
                         (mac, limit)).fetchall()
        con.close()
        return {"device": dict(d) if d else None,
                "events": [dict(r) for r in ev], "alerts": [dict(r) for r in al]}
    except Exception:
        return {"device": None, "events": [], "alerts": []}


def link_series(link, since=None, limit=3000):
    try:
        con = _reader()
        if since:
            rows = con.execute("SELECT ts,latency_ms,loss_pct,healthy FROM link_samples "
                               "WHERE link=? AND ts>=? ORDER BY ts DESC LIMIT ?",
                               (link, since, limit)).fetchall()
        else:
            rows = con.execute("SELECT ts,latency_ms,loss_pct,healthy FROM link_samples "
                               "WHERE link=? ORDER BY ts DESC LIMIT ?", (link, limit)).fetchall()
        con.close()
        return [dict(r) for r in rows][::-1]   # oldest-first for charting
    except Exception:
        return []


def switches(limit=100):
    try:
        con = _reader()
        rows = con.execute("SELECT ts,from_link,to_link,latency_ms,reason FROM switch_history "
                           "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        con.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def outage_log(limit=100):
    try:
        con = _reader()
        rows = con.execute("SELECT started,ended,duration_s FROM outages ORDER BY id DESC LIMIT ?",
                           (limit,)).fetchall()
        con.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def stats():
    try:
        con = _reader()
        one = lambda q: con.execute(q).fetchone()[0]
        s = {"devices": one("SELECT COUNT(*) FROM devices"),
             "events": one("SELECT COUNT(*) FROM device_events"),
             "alerts": one("SELECT COUNT(*) FROM alerts"),
             "switches": one("SELECT COUNT(*) FROM switch_history"),
             "samples": one("SELECT COUNT(*) FROM link_samples"),
             "db_bytes": os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0}
        con.close()
        return s
    except Exception:
        return {}
