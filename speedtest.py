"""
speedtest.py — Cloudflare-grade per-link quality test (Windows-correct).

Binding a socket to a backup link's source IP does NOT reliably send traffic
out that interface on Windows (weak host model) — only the primary/default
route carries bulk traffic. So to test each link honestly this tool:

  1. stops the LinkKeeper daemon (so it won't re-write metrics mid-test),
  2. for each link in turn, forces it to be the sole default route by setting
     its interface metric low and the others very high,
  3. measures latency / jitter / download / upload over the real route
     (multiple parallel streams) against speed.cloudflare.com,
  4. restores automatic metrics and restarts the daemon.

Requires an ELEVATED process (it changes interface metrics + the task).
Uses mobile data on both links — fine on unlimited 5G, for an on-demand check.

    python speedtest.py                       # test all links
    python speedtest.py --streams 8 --dl 10 --ul 6 --out logs/speedtest_result.txt
"""

from __future__ import annotations

import argparse
import http.client
import ssl
import statistics
import sys
import threading
import time

import netroute
from linkkeeper import load_config, managed_links

HOST = "speed.cloudflare.com"
_SSL = ssl.create_default_context()


def _conn(timeout: float = 20.0) -> http.client.HTTPSConnection:
    # No source binding: the forced default route already sends us out the
    # link under test, and lets Cloudflare resolve to whatever IP is nearest.
    return http.client.HTTPSConnection(HOST, timeout=timeout, context=_SSL)


# ---- measurements -----------------------------------------------------------

def measure_latency(samples: int = 14) -> dict | None:
    rtts: list[float] = []
    c = None
    for _ in range(samples):
        try:
            if c is None:
                c = _conn(timeout=8)
            t = time.perf_counter()
            c.request("GET", "/__down?bytes=0")
            c.getresponse().read()
            rtts.append((time.perf_counter() - t) * 1000.0)
        except OSError:
            if c:
                c.close()
            c = None
    if c:
        c.close()
    if not rtts:
        return None
    return {"min": min(rtts), "avg": sum(rtts) / len(rtts),
            "jitter": statistics.pstdev(rtts) if len(rtts) > 1 else 0.0}


_DL_BYTES = 10_000_000    # 10 MB per request (Cloudflare __down caps above this)
_UL_BYTES = 25_000_000    # 25 MB per upload request
_CHUNK = 65536


def _dl_worker(deadline, counter, idx):
    # Reuse one keep-alive connection for many 10 MB pulls until the deadline,
    # so TLS/connection setup isn't re-paid each request.
    c = None
    try:
        c = _conn()
        while time.perf_counter() < deadline:
            c.request("GET", f"/__down?bytes={_DL_BYTES}")
            r = c.getresponse()
            if r.status != 200:
                r.read()
                return
            done = True
            while True:
                b = r.read(_CHUNK)
                if not b:
                    break
                counter[idx] += len(b)
                if time.perf_counter() >= deadline:
                    done = False  # broke mid-body; connection no longer reusable
                    break
            if not done:
                return
    except OSError:
        return
    finally:
        if c:
            try:
                c.close()
            except OSError:
                pass


def _ul_worker(deadline, counter, idx):
    payload = b"\0" * _CHUNK
    # Fixed Content-Length requests (Cloudflare __up rejects chunked), looped.
    while time.perf_counter() < deadline:
        try:
            c = _conn()
            c.putrequest("POST", "/__up", skip_accept_encoding=True)
            c.putheader("Content-Type", "application/octet-stream")
            c.putheader("Content-Length", str(_UL_BYTES))
            c.endheaders()
            sent = 0
            while sent < _UL_BYTES and time.perf_counter() < deadline:
                n = min(_CHUNK, _UL_BYTES - sent)
                c.send(payload[:n])
                sent += n
                counter[idx] += n
            if sent >= _UL_BYTES:
                c.getresponse().read()
            c.close()
        except OSError:
            return


def _parallel(worker, streams, secs) -> float:
    counter = [0] * streams
    start = time.perf_counter()
    deadline = start + secs
    ts = [threading.Thread(target=worker, args=(deadline, counter, i)) for i in range(streams)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    elapsed = time.perf_counter() - start
    return (sum(counter) * 8) / elapsed / 1e6 if elapsed > 0 else 0.0


# ---- routing control (needs elevation) --------------------------------------

def task(action: str):
    netroute._ps(f"{action}-ScheduledTask -TaskName 'LinkKeeper' -ErrorAction SilentlyContinue")


def force_primary(links, primary):
    for lk in links:
        netroute.set_interface_metric(lk.if_index, 5 if lk.name == primary.name else 9000)
    netroute.flush_dns()


def restore_auto(links):
    for lk in links:
        try:
            netroute._ps(
                f"Set-NetIPInterface -InterfaceIndex {lk.if_index} -AddressFamily IPv4 "
                "-AutomaticMetric Enabled"
            )
        except RuntimeError:
            pass


# ---- driver -----------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--streams", type=int, default=6)
    ap.add_argument("--dl", type=int, default=8)
    ap.add_argument("--ul", type=int, default=6)
    ap.add_argument("--settle", type=float, default=3.0, help="seconds to let a forced route settle")
    ap.add_argument("--out", help="also write the report to this file")
    args = ap.parse_args()

    lines: list[str] = []

    def emit(s=""):
        print(s)
        lines.append(s)

    cfg = load_config()
    links = managed_links(cfg)
    if not links:
        emit("No links found (are the phones connected?)")
        return

    emit(f"\nCloudflare quality test — {args.streams} streams, "
         f"{args.dl}s down / {args.ul}s up per link")
    emit("(each link forced as sole default route during its own test)\n")
    emit(f"{'LINK':<15}{'LATENCY':<10}{'JITTER':<9}{'DOWNLOAD':<13}{'UPLOAD':<12}")
    emit("-" * 59)

    results = []
    task("Stop")
    time.sleep(1.0)
    try:
        for lk in links:
            force_primary(links, lk)
            time.sleep(args.settle)  # let routes flip + link revalidate
            lat = measure_latency()
            if lat is None:
                emit(f"{lk.name:<15}unreachable — link has no working internet right now")
                results.append((lk.name, None, 0.0, 0.0))
                continue
            dl = _parallel(_dl_worker, args.streams, args.dl)
            ul = _parallel(_ul_worker, args.streams, args.ul)
            results.append((lk.name, lat, dl, ul))
            emit(f"{lk.name:<15}{lat['avg']:>5.0f} ms  {lat['jitter']:>4.0f} ms  "
                 f"{dl:>7.1f} Mbps  {ul:>6.1f} Mbps")
    finally:
        restore_auto(links)
        task("Start")

    ok = [r for r in results if r[1] is not None]
    if len(ok) > 1:
        emit(f"\nFastest download: {max(ok, key=lambda r: r[2])[0]}")
    emit("\nDaemon restarted; automatic failover is active again.")

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
        except OSError as exc:
            print(f"(could not write {args.out}: {exc})", file=sys.stderr)


if __name__ == "__main__":
    main()
