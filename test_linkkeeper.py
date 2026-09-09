"""
LinkKeeper unit tests — stdlib `unittest` only (no pytest, matches the project's
stdlib-only ethos). Covers the pure decision logic that the hardening pass
(v1.1) fixed: link ranking, anti-flap selection, debounced health, the quality
score, LinkState math, and PowerShell-injection escaping.

Run:  python -m unittest test_linkkeeper -v
      python -m unittest test_linkkeeper.TestChooseLink -v

These are OS-independent: they construct WanLink dataclasses directly and
monkeypatch tcp_probe, so no PowerShell / sockets / elevation are touched.
"""
from __future__ import annotations

import os
import tempfile
import time
import unittest

import advisor
import linkkeeper as lk
import netroute
import store
from netroute import WanLink, ps_quote


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def make_link(name, *, wired=True, trusted=True, loss_pct=0.0, score=50.0,
              preference=100, healthy=True, source_ip="10.0.0.2",
              probe_target="1.1.1.1"):
    """Build a WanLink with the fields the decision engine reads."""
    l = WanLink(
        if_index=1, alias=name, source_ip=source_ip, gateway="10.0.0.1",
        metric=25, wired=wired, trusted=trusted,
    )
    l.name = name
    l.loss_pct = loss_pct
    l.score = score
    l.preference = preference
    l.healthy = healthy
    l.probe_target = probe_target
    return l


DEC = {
    "prefer_wired": True,
    "wired_degraded_loss_pct": 25,
    "switchback_dwell_seconds": 30,
    "switch_margin_ms": 60,
    "fail_after_bad_probes": 3,
    "jitter_weight": 0.5,
    "loss_weight_ms_per_pct": 20,
}


def cfg_for_choose(**over):
    dec = dict(DEC)
    dec.update(over)
    return {"decision": dec, "manual_pin": None}


def cfg_for_probe(**over):
    dec = dict(DEC)
    dec.update(over)
    return {
        "decision": dec,
        "probe": {"timeout_seconds": 1.0, "ports": [443], "targets": [["1.1.1.1", 443]]},
    }


# --------------------------------------------------------------------------- #
# ps_quote — injection escaping
# --------------------------------------------------------------------------- #
class TestPsQuote(unittest.TestCase):
    def test_doubles_single_quotes(self):
        self.assertEqual(ps_quote("it's"), "it''s")

    def test_hostile_ssid_is_neutralised(self):
        # a single-quoted PS string has no other metacharacters, so doubling the
        # quote is the whole defence; the injected "'; rm ..." can't break out.
        evil = "KKKKK'; Remove-Item C:\\ -Recurse; '"
        escaped = ps_quote(evil)
        self.assertEqual(escaped, evil.replace("'", "''"))
        # the whole defence: every quote is now part of a doubled '' pair, so
        # none can terminate the single-quoted PS string. Removing the pairs
        # must leave no lone quote behind.
        self.assertNotIn("'", escaped.replace("''", ""))

    def test_leaves_benign_text_untouched(self):
        self.assertEqual(ps_quote("Ethernet 3"), "Ethernet 3")

    def test_coerces_non_string(self):
        self.assertEqual(ps_quote(1234), "1234")


# --------------------------------------------------------------------------- #
# LinkState — loss / jitter math
# --------------------------------------------------------------------------- #
class TestLinkState(unittest.TestCase):
    def test_loss_pct_empty_is_zero(self):
        self.assertEqual(lk.LinkState(10).loss_pct, 0.0)

    def test_loss_pct_counts_failures(self):
        s = lk.LinkState(10)
        for ok in (True, True, False, True):   # 1 of 4 failed
            s.results.append(ok)
        self.assertAlmostEqual(s.loss_pct, 25.0)

    def test_loss_window_bounded(self):
        s = lk.LinkState(4)
        for ok in (False, False, True, True, True, True):  # only last 4 kept
            s.results.append(ok)
        self.assertEqual(s.loss_pct, 0.0)

    def test_jitter_needs_two_samples(self):
        s = lk.LinkState(10)
        s.latencies.append(20.0)
        self.assertEqual(s.jitter_ms, 0.0)

    def test_jitter_is_population_stdev(self):
        import statistics
        s = lk.LinkState(10)
        for v in (10.0, 20.0, 30.0):
            s.latencies.append(v)
        self.assertAlmostEqual(s.jitter_ms, statistics.pstdev([10, 20, 30]))


# --------------------------------------------------------------------------- #
# _rank_key — the ordering contract
# --------------------------------------------------------------------------- #
class TestRankKey(unittest.TestCase):
    def test_trusted_beats_untrusted_regardless_of_score(self):
        trusted_slow = make_link("phone", trusted=True, score=500)
        open_fast = make_link("openwifi", trusted=False, score=5, wired=False)
        self.assertLess(lk._rank_key(trusted_slow, DEC), lk._rank_key(open_fast, DEC))

    def test_wired_clean_beats_wireless(self):
        wired = make_link("usb", wired=True, loss_pct=0, score=80)
        wifi = make_link("wifi", wired=False, loss_pct=0, score=40)
        self.assertLess(lk._rank_key(wired, DEC), lk._rank_key(wifi, DEC))

    def test_degraded_wired_loses_class_privilege(self):
        # loss over the threshold => the flapping tether drops to wireless class
        bad_wired = make_link("usb", wired=True, loss_pct=40, score=80)
        wifi = make_link("wifi", wired=False, loss_pct=0, score=40)
        self.assertGreater(lk._rank_key(bad_wired, DEC), lk._rank_key(wifi, DEC))

    def test_same_class_lower_score_wins(self):
        a = make_link("a", wired=False, score=30)
        b = make_link("b", wired=False, score=90)
        self.assertLess(lk._rank_key(a, DEC), lk._rank_key(b, DEC))

    def test_preference_breaks_score_ties(self):
        a = make_link("a", wired=False, score=50, preference=10)
        b = make_link("b", wired=False, score=50, preference=99)
        self.assertLess(lk._rank_key(a, DEC), lk._rank_key(b, DEC))

    def test_prefer_wired_false_removes_class_edge(self):
        dec = dict(DEC, prefer_wired=False)
        wired = make_link("usb", wired=True, score=80)
        wifi = make_link("wifi", wired=False, score=40)
        # with prefer_wired off, pure score decides -> the faster wifi wins
        self.assertLess(lk._rank_key(wifi, dec), lk._rank_key(wired, dec))


# --------------------------------------------------------------------------- #
# choose_link — anti-flap selection
# --------------------------------------------------------------------------- #
class TestChooseLink(unittest.TestCase):
    def setUp(self):
        self._saved = lk._last_switch_at

    def tearDown(self):
        lk._last_switch_at = self._saved

    def _dwell_elapsed(self):
        lk._last_switch_at = 0.0            # long ago -> dwell satisfied

    def _dwell_fresh(self):
        lk._last_switch_at = time.time()    # just switched -> dwell NOT satisfied

    def test_no_healthy_returns_none(self):
        links = [make_link("a", healthy=False)]
        self.assertIsNone(lk.choose_link(links, cfg_for_choose(), "a"))

    def test_no_current_takes_best(self):
        self._dwell_elapsed()
        a = make_link("a", wired=False, score=90)
        b = make_link("b", wired=False, score=30)
        self.assertEqual(lk.choose_link([a, b], cfg_for_choose(), None).name, "b")

    def test_dead_current_switches_immediately(self):
        self._dwell_fresh()   # even with no dwell, a dead current must be dropped
        cur = make_link("cur", wired=False, score=30, healthy=False)
        alt = make_link("alt", wired=False, score=90, healthy=True)
        self.assertEqual(lk.choose_link([cur, alt], cfg_for_choose(), "cur").name, "alt")

    def test_holds_current_within_dwell(self):
        self._dwell_fresh()
        cur = make_link("cur", wired=False, score=200)
        rival = make_link("rival", wired=False, score=10)   # much better
        # same class, better score, but dwell not elapsed -> hold
        self.assertEqual(lk.choose_link([cur, rival], cfg_for_choose(), "cur").name, "cur")

    def test_switches_on_score_after_dwell(self):
        self._dwell_elapsed()
        cur = make_link("cur", wired=False, score=200)
        rival = make_link("rival", wired=False, score=10)   # beats margin (60)
        self.assertEqual(lk.choose_link([cur, rival], cfg_for_choose(), "cur").name, "rival")

    def test_small_score_win_does_not_switch(self):
        self._dwell_elapsed()
        cur = make_link("cur", wired=False, score=100)
        rival = make_link("rival", wired=False, score=70)   # only 30 < margin 60
        self.assertEqual(lk.choose_link([cur, rival], cfg_for_choose(), "cur").name, "cur")

    def test_better_class_switches(self):
        self._dwell_elapsed()
        cur = make_link("cur", wired=False, score=10)       # wifi, great score
        rival = make_link("usb", wired=True, loss_pct=0, score=300)  # wired, worse score
        # wired-clean is a better CLASS, so it wins despite the worse score
        self.assertEqual(lk.choose_link([cur, rival], cfg_for_choose(), "cur").name, "usb")

    def test_manual_pin_healthy_wins_after_dwell(self):
        self._dwell_elapsed()
        cur = make_link("cur", wired=False, score=10)
        pinned = make_link("pinme", wired=False, score=999)
        cfg = cfg_for_choose()
        cfg["manual_pin"] = "pinme"
        self.assertEqual(lk.choose_link([cur, pinned], cfg, "cur").name, "pinme")

    def test_manual_pin_holds_current_within_dwell(self):
        self._dwell_fresh()
        cur = make_link("cur", wired=False, score=10)
        pinned = make_link("pinme", wired=False, score=999)
        cfg = cfg_for_choose()
        cfg["manual_pin"] = "pinme"
        # pin not yet current and dwell not elapsed -> hold current, don't flap
        self.assertEqual(lk.choose_link([cur, pinned], cfg, "cur").name, "cur")

    def test_manual_pin_unhealthy_falls_through(self):
        self._dwell_elapsed()
        cur = make_link("cur", wired=False, score=100)
        best = make_link("best", wired=False, score=10)
        cfg = cfg_for_choose()
        cfg["manual_pin"] = "gone"   # pinned link not present/healthy
        self.assertEqual(lk.choose_link([cur, best], cfg, "cur").name, "best")


# --------------------------------------------------------------------------- #
# probe_link — debounced health + score
# --------------------------------------------------------------------------- #
class TestProbeHealthDebounce(unittest.TestCase):
    def setUp(self):
        self._real_probe = lk.tcp_probe

    def tearDown(self):
        lk.tcp_probe = self._real_probe

    def _set_probe(self, ms):
        """Force tcp_probe to return a fixed latency (ms) or None (miss)."""
        lk.tcp_probe = lambda *a, **k: ms

    def test_success_is_healthy_with_finite_score(self):
        self._set_probe(30.0)
        link = make_link("a", healthy=False)
        st = lk.LinkState(10)
        lk.probe_link(link, cfg_for_probe(), st)
        self.assertTrue(link.healthy)
        self.assertEqual(st.consecutive_fail, 0)
        self.assertTrue(link.score < float("inf"))
        self.assertAlmostEqual(link.latency_ms, 30.0)

    def test_single_miss_after_success_stays_healthy(self):
        link = make_link("a")
        st = lk.LinkState(10)
        self._set_probe(30.0)
        lk.probe_link(link, cfg_for_probe(), st)   # good
        self._set_probe(None)
        lk.probe_link(link, cfg_for_probe(), st)   # one miss -> debounced up
        self.assertTrue(link.healthy)
        self.assertEqual(st.consecutive_fail, 1)
        # scored off last-good latency, not infinity, but loss now penalises it
        self.assertTrue(link.score < float("inf"))

    def test_threshold_consecutive_misses_marks_down(self):
        link = make_link("a")
        st = lk.LinkState(10)
        self._set_probe(30.0)
        lk.probe_link(link, cfg_for_probe(), st)   # establish a good sample
        self._set_probe(None)
        for _ in range(DEC["fail_after_bad_probes"]):
            lk.probe_link(link, cfg_for_probe(), st)
        self.assertFalse(link.healthy)
        self.assertEqual(link.score, float("inf"))

    def test_never_succeeded_is_down_on_first_miss(self):
        self._set_probe(None)
        link = make_link("a", healthy=True)
        st = lk.LinkState(10)
        lk.probe_link(link, cfg_for_probe(), st)   # no prior latency
        self.assertFalse(link.healthy)

    def test_recovery_is_instant(self):
        link = make_link("a")
        st = lk.LinkState(10)
        self._set_probe(30.0)
        lk.probe_link(link, cfg_for_probe(), st)
        self._set_probe(None)
        for _ in range(DEC["fail_after_bad_probes"]):
            lk.probe_link(link, cfg_for_probe(), st)
        self.assertFalse(link.healthy)
        self._set_probe(25.0)
        lk.probe_link(link, cfg_for_probe(), st)   # one good probe
        self.assertTrue(link.healthy)
        self.assertEqual(st.consecutive_fail, 0)


# --------------------------------------------------------------------------- #
# netroute.lan_scan — parsing / filtering (mocked PowerShell)
# --------------------------------------------------------------------------- #
class TestLanScan(unittest.TestCase):
    def setUp(self):
        self._real = netroute._ps

    def tearDown(self):
        netroute._ps = self._real

    def _mock(self, payload):
        import json
        netroute._ps = lambda *a, **k: json.dumps(payload)

    def test_parses_and_flags_randomized(self):
        # F4-BD-B9 = globally administered (real); D2-.. has the local bit set
        self._mock([{"ip": "192.168.1.1", "mac": "F4-BD-B9-20-C4-1A", "state": "Reachable"},
                    {"ip": "192.168.1.34", "mac": "D2-AC-87-9E-06-25", "state": "Stale"}])
        d = {x["ip"]: x for x in netroute.lan_scan()}
        self.assertEqual(len(d), 2)
        self.assertFalse(d["192.168.1.1"]["randomized"])
        self.assertTrue(d["192.168.1.34"]["randomized"])

    def test_filters_multicast_broadcast(self):
        self._mock([
            {"ip": "192.168.1.5", "mac": "AA-11-22-33-44-55", "state": "Reachable"},
            {"ip": "192.168.1.255", "mac": "FF-FF-FF-FF-FF-FF", "state": "Reachable"},
            {"ip": "224.0.0.251", "mac": "01-00-5E-00-00-FB", "state": "Reachable"},
            {"ip": "239.255.255.250", "mac": "01-00-5E-7F-FF-FA", "state": "Reachable"},
        ])
        d = netroute.lan_scan()
        self.assertEqual([x["ip"] for x in d], ["192.168.1.5"])

    def test_dedup_and_sorted(self):
        self._mock([
            {"ip": "192.168.1.20", "mac": "AA-11-22-33-44-55", "state": "Stale"},
            {"ip": "192.168.1.3", "mac": "BB-11-22-33-44-55", "state": "Reachable"},
            {"ip": "192.168.1.99", "mac": "AA-11-22-33-44-55", "state": "Reachable"},  # dup MAC
        ])
        d = netroute.lan_scan()
        self.assertEqual(len(d), 2)                       # deduped by MAC
        self.assertEqual([x["ip"] for x in d], ["192.168.1.3", "192.168.1.20"])  # sorted

    def test_bad_output_is_empty(self):
        netroute._ps = lambda *a, **k: "not json"
        self.assertEqual(netroute.lan_scan(), [])


# --------------------------------------------------------------------------- #
# advisor intruder rule
# --------------------------------------------------------------------------- #
class TestIntruderRule(unittest.TestCase):
    def _cfg(self, **ns):
        base = {"enabled": True, "alert_new_devices": True}
        base.update(ns)
        return {"advisor": {"enabled": True}, "netscan": base, "links": []}

    def test_new_device_makes_intruder_advice(self):
        devs = [{"mac": "AA-BB", "ip": "192.168.1.9", "is_new": True, "known": False}]
        adv = advisor.evaluate([], self._cfg(), {}, {}, {}, devices=devs)
        self.assertTrue(any(a["id"] == "intruder:AA-BB" for a in adv))

    def test_known_device_no_advice(self):
        devs = [{"mac": "AA-BB", "is_new": False, "known": True}]
        adv = advisor.evaluate([], self._cfg(), {}, {}, {}, devices=devs)
        self.assertFalse(any(a["id"].startswith("intruder:") for a in adv))

    def test_alerts_disabled(self):
        devs = [{"mac": "AA-BB", "is_new": True, "known": False}]
        adv = advisor.evaluate([], self._cfg(alert_new_devices=False), {}, {}, {}, devices=devs)
        self.assertFalse(any(a["id"].startswith("intruder:") for a in adv))


# --------------------------------------------------------------------------- #
# store — SQLite records round-trip (temp file DB)
# --------------------------------------------------------------------------- #
class TestStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        store.init_db(os.path.join(self.dir, "t.db"))

    def tearDown(self):
        store.close()

    def test_scan_registry_and_events(self):
        store.record_scan([{"mac": "AA", "ip": "192.168.1.1", "online": True,
                            "is_new": True, "first_seen": time.time()}])
        self.assertEqual(store.stats()["devices"], 1)
        self.assertGreaterEqual(len(store.recent_events()), 1)
        self.assertIsNotNone(store.device_timeline("AA")["device"])

    def test_switch_and_samples(self):
        store.record_switch("a", "b", 5.0, "wired")
        lk_obj = make_link("b")
        lk_obj.latency_ms = 5.0
        store.record_link_samples([lk_obj], "b")
        self.assertEqual(len(store.switches()), 1)
        self.assertGreaterEqual(len(store.link_series("b")), 1)

    def test_alert_dedup(self):
        store.record_alert("AA", note="x")
        store.record_alert("AA", note="x")          # within 30 min -> deduped
        self.assertEqual(store.stats()["alerts"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
