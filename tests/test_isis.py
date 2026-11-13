"""Tests for 1.6: the i1iSis chart readers (0971:2006).

    python3 -m unittest discover -s tests -v

Every recording here is SYNTHETIC and its i1iSis traffic is INVENTED
(tests/synth.py, "the i1iSis chart reader"): no recording of an i1iSis
exists yet. The session tests use the same fake USBPcapCMD as the handheld
tests; nothing is captured, nothing runs as administrator, and no device is
ever opened.
"""

import builtins
import io
import json
import os
import re
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth  # noqa: E402
import synth_io  # noqa: E402
import test_instrument  # noqa: E402
import test_what_to_do  # noqa: E402

ISIS = (0x0971, 0x2006)
DISPLAY_PRO = (0x0765, 0x5020)
ISIS_KEYS = ["idle", "ready", "page-single", "page-dual", "page-skewed", "blank-page"]


def flat(text):
    return " ".join(text.split())


class Detection(unittest.TestCase):

    def test_the_id_has_a_name(self):
        self.assertIn("i1iSis", probe.pid_label(0x2006))
        self.assertEqual(probe.PROFILE_IDS[ISIS], "isis")
        self.assertEqual(probe.choose_profile([ISIS]), "isis")
        self.assertEqual(probe.family_for(0x0971, 0x2006), "isis")
        self.assertIn("i1iSis", probe.device_name(ISIS))

    def test_windows_and_linux_text(self):
        probe._DETECTION.clear()
        ids = probe.detected_ids("x :: USB\\VID_0971&PID_2006\\5&1\n"
                                 "  Bus 001 Device 004: ID 0971:2006 X-Rite")
        self.assertEqual(ids, [ISIS])

    def test_an_isis_plugged_in_suggests_the_session(self):
        sug = probe.suggest([ISIS])
        self.assertEqual(sug["choice"], 2)
        lines = flat("\n".join(probe.what_to_do_question(sug, True, [ISIS], {})))
        self.assertIn("Plugged in now: i1iSis", lines)
        self.assertIn("2. record a handheld instrument or an i1iSis <- suggested", lines)

    def test_usbpcap_hub_name_matches(self):
        self.assertTrue(probe._XRITE_NAME_RE.search("i1iSis"))
        self.assertTrue(probe._XRITE_NAME_RE.search("X-Rite i1 iSis"))

    def test_profile_question_lists_it_before_another_instrument(self):
        printed = io.StringIO()
        with mock.patch.object(probe, "ask", lambda *_a, **_k: ""), redirect_stdout(printed):
            self.assertEqual(probe._ask_profile("isis"), "isis")
        text = printed.getvalue()
        self.assertIn("5. i1iSis, i1iSis XL, i1iSis 2 or i1iSis 2 XL (chart reader)   <- seen",
                      text)
        self.assertIn("6. another X-Rite instrument", text)
        with mock.patch.object(probe, "ask", lambda *_a, **_k: "5"), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(probe._ask_profile("i1pro2"), "isis")


class WhichDevicesAreKept(unittest.TestCase):

    def test_rule(self):
        self.assertTrue(probe.keeps_device(0x0971, 0x2006, "isis"))
        self.assertFalse(probe.keeps_device(0x0765, 0x5020, "isis"))     # i1Display Pro
        self.assertFalse(probe.keeps_device(0x0971, 0x2000, "isis"))     # i1Pro family
        self.assertTrue(probe.keeps_device(0x0971, 0x2099, "isis"))      # not known: kept
        self.assertFalse(probe.keeps_device(0x046D, 0xC31C, "isis"))     # a keyboard
        # The other sessions keep every X-Rite device, as before 1.6.
        for profile in (None, "i1pro2", "i1pro3", "munki", "generic"):
            self.assertTrue(probe.keeps_device(0x0765, 0x5020, profile))
        self.assertNotIn(ISIS, probe.OTHER_INSTRUMENT_IDS)


class Filter(test_instrument.TempDirCase):

    def setUp(self):
        super().setUp()
        self.files = synth.isis_session_files(self.dir, os)

    def keys_in(self, path):
        lt, recs = probe._read_pcap(path)
        return set(probe.record_device_keys(lt, recs))

    def test_isis_session_keeps_only_the_isis(self):
        dst = os.path.join(self.dir, "out.pcap")
        self.assertTrue(probe.filter_xrite_capture(self.files["page-single"], dst, "isis"))
        self.assertEqual(self.keys_in(dst), {(1, synth.ISIS)})
        with open(dst, "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"DISPLAYSERIAL99", blob)

    def test_other_sessions_keep_every_xrite_device_as_before(self):
        dst = os.path.join(self.dir, "out.pcap")
        self.assertTrue(probe.filter_xrite_capture(self.files["page-single"], dst, "i1pro2"))
        self.assertEqual(self.keys_in(dst), {(1, synth.ISIS), (1, synth.DISPLAY)})

    def test_check_counts_only_the_isis(self):
        both = probe.check_capture(self.files["page-single"], "i1pro2")
        mine = probe.check_capture(self.files["page-single"], "isis")
        self.assertEqual(mine["code"], "ok")
        self.assertEqual(mine["kept"], "isis")
        self.assertLess(mine["xrite_packets"], both["xrite_packets"])
        # Without a session type the check is exactly 1.5.5's (second review).
        self.assertEqual(probe.check_capture(self.files["page-single"])["xrite_packets"],
                         both["xrite_packets"])

    def test_mac_records_by_their_own_ids(self):
        w = synth_io.DarwinWriter()
        w.bulk_out(5, 0x2006, 0x02, b"INVENTED-HELLO\r")
        w.bulk_in(5, 0x2006, 0x81, synth.ftdi_in(b"OK\r"))
        w._rec(1, 999, 6, 0x81, 3, 0x0765, 0x5020, b"DISPLAYSERIAL99", 15)
        w._rec(1, 998, 7, 0x81, 3, 0x046D, 0xC31C, b"\x00\x00\x04", 3)
        src = w.save(os.path.join(self.dir, "mac.pcap"))
        dst = os.path.join(self.dir, "mac-out.pcap")
        self.assertEqual(probe.filter_xrite_capture(src, dst, "isis"), 4)
        with open(dst, "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"DISPLAYSERIAL99", blob)
        self.assertIn(b"INVENTED-HELLO", blob)
        # A handheld session: the i1Display stays, the keyboard never.
        self.assertEqual(probe.filter_xrite_capture(src, dst, "i1pro2"), 5)

    def test_a_step_with_only_the_usb_description_is_empty(self):
        w = synth.UsbPcapWriter()
        w.describe(synth.ISIS, 0x0971, 0x2006, synth.ISIS_ENDPOINTS)
        synth.keyboard_noise(w)
        path = w.save(os.path.join(self.dir, "empty.pcap"))
        self.assertEqual(probe.check_capture(path, "isis")["code"], "empty-step")


# ---- the review's privacy simulation (review/sim/privacy_sim.py), as tests ----

PRIV_DEVS = {  # address: (vid, pid, marker, endpoints); markers are invented
    3: (0x0971, 0x2006, b"ISIS-MARK", [(0x81, 2), (0x02, 2)]),
    4: (0x0765, 0x5020, b"DISPLAY-SERIAL", [(0x81, 3), (0x01, 3)]),
    5: (0x046D, 0xC31C, b"KEYB-TYPED-PASSWORD", [(0x81, 3)]),
    6: (0x046D, 0xC077, b"MOUSE-MARK", [(0x81, 3)]),
    7: (0x0781, 0x5567, b"STICK-FILE-CONTENT", [(0x81, 2), (0x02, 2)]),
    8: (0x0971, 0x2099, b"UNKNOWN-XRITE-SERIAL", [(0x81, 2), (0x02, 2)]),
    9: (0x0971, 0x2000, b"I1PRO2-SERIAL", [(0x82, 2), (0x84, 3), (0x03, 2)]),
    10: (0x0765, 0x600A, b"DISPLAY3L-SERIAL", [(0x81, 3)]),
}
ALL_MARKERS = [v[2] for v in PRIV_DEVS.values()]


def priv_usbpcap(described, devices=PRIV_DEVS, i1pro_cmds=True):
    w = synth.UsbPcapWriter()
    for a, (vid, pid, _m, eps) in devices.items():
        if a in described:
            w.describe(a, vid, pid, eps)
    for a, (_vid, _pid, m, eps) in devices.items():
        w.bulk_in(a, [e for e, _k in eps if e & 0x80][0], m)
        outs = [e for e, _k in eps if not e & 0x80]
        if outs:
            w.bulk_out(a, outs[0], m + b"-OUT\r")
    if i1pro_cmds and 9 in devices:
        for req in sorted(probe.FAMILIES["i1pro2"]["requests"])[:4]:
            w.vendor_in(9, req, b"I1PRO2-SERIAL-EEPROM")
    return w


class PrivacyCases(test_instrument.TempDirCase):
    """What an i1iSis copy keeps, whatever the recording looks like."""

    def kept(self, w, profile="isis", name="x"):
        src = w.save(os.path.join(self.dir, name + ".pcap"))
        dst = os.path.join(self.dir, name + "-out.pcap")
        n = probe.filter_xrite_capture(src, dst, profile)
        blob = b""
        if n and os.path.exists(dst):
            with open(dst, "rb") as fh:
                blob = fh.read()
        return [m for m in ALL_MARKERS if m in blob], probe.check_capture(src, profile), src

    def test_everything_described_keeps_only_the_isis(self):
        kept, check, _src = self.kept(priv_usbpcap(set(PRIV_DEVS)))
        self.assertEqual(kept, [b"ISIS-MARK"])
        self.assertEqual((check["code"], check["kept"]), ("ok", "isis"))

    def test_no_description_keeps_nothing_and_does_not_say_ok(self):
        kept, check, _src = self.kept(priv_usbpcap(set()))
        self.assertEqual(kept, [])
        self.assertEqual(check["code"], "unidentified")
        self.assertIn("NOTHING KEPT", check["verdict"])

    def test_an_undescribed_i1pro_next_to_the_isis_is_dropped(self):
        kept, _check, _src = self.kept(priv_usbpcap(set(PRIV_DEVS) - {9}))
        self.assertEqual(kept, [b"ISIS-MARK"])

    def test_without_an_isis_only_unknown_xrite_devices_and_it_says_so(self):
        devs = {k: v for k, v in PRIV_DEVS.items() if k != 3}
        kept, check, _src = self.kept(priv_usbpcap(set(devs), devs))
        self.assertEqual(kept, [b"UNKNOWN-XRITE-SERIAL"])
        self.assertEqual(check["kept"], "unknown")
        self.assertEqual(check["kept_ids"], [(0x0971, 0x2099)])
        entry = {"files_xrite": ["x"], "kept_unknown": ["0971:2099"]}
        text = probe.handheld_step_verdict(entry, 3, False)
        self.assertIn("not of an i1iSis", text)
        self.assertIn("0971:2099", text)

    def test_mac_records(self):
        d = synth_io.DarwinWriter()
        for seq, (a, (vid, pid, m, _e)) in enumerate(PRIV_DEVS.items(), 1):
            d._rec(1, seq, a, 0x81, 2, vid, pid, m, len(m))
        kept, check, _src = self.kept(d, name="mac")
        self.assertEqual(kept, [b"ISIS-MARK"])
        self.assertEqual(check["kept_ids"], [(0x0971, 0x2006)])

    def test_linux_without_descriptions_keeps_nothing(self):
        u = synth_io.UsbmonWriter()
        for a, (_vid, _pid, m, _e) in PRIV_DEVS.items():
            u.bulk_in(a, 0x81, m)
        kept, check, _src = self.kept(u, name="linux")
        self.assertEqual(kept, [])
        self.assertEqual(check["code"], "unidentified")

    def test_the_3l_is_a_known_other_instrument(self):
        self.assertIn((0x0765, 0x600A), probe.OTHER_INSTRUMENT_IDS)

    def test_analyze_on_a_raw_full_file_shows_only_the_isis(self):
        # A plain file whose only known X-Rite device is the i1iSis (the
        # unknown X-Rite device, keyboard, mouse and stick are not known
        # instruments). With a known other instrument in it, a plain file is
        # read as in 1.5.5 (tests/test_regression_v155.py).
        devs = {k: v for k, v in PRIV_DEVS.items() if k not in (4, 9, 10)}
        src = priv_usbpcap(set(devs), devs).save(os.path.join(self.dir, "raw.pcap"))
        report = probe.analyze_paths([src])
        detail = report.split("Instrument recording analysis")[1]
        for marker in ALL_MARKERS:
            if marker != b"ISIS-MARK":
                self.assertNotIn(marker.decode(), report)
        self.assertNotIn("0971:2099", detail)
        self.assertEqual(detail.count("instrument at bus"), 1)
        lines = detail.split("the first different lines the program sent")[1]
        self.assertIn("ISIS-MARK-OUT", lines)
        self.assertNotIn("STICK", lines)
        # The i1iSis's own answers are not shown either, only their size.
        self.assertIn("data on 0x81 bulk IN: 9 bytes (from the device, not shown)", detail)

    def test_isis_undescribed_next_to_a_described_xrite_device(self):
        # Second review, minor 1: the i1iSis's description missing, an
        # i1Pro 2's present: NOTHING KEPT with the replug hint, not "no X-Rite".
        kept, check, _src = self.kept(priv_usbpcap(set(PRIV_DEVS) - {3}))
        self.assertEqual(kept, [])
        self.assertEqual(check["code"], "unidentified")

    def test_a_bus_without_the_isis_is_just_not_its_bus(self):
        devs = {5: PRIV_DEVS[5], 6: PRIV_DEVS[6]}
        kept, check, _src = self.kept(priv_usbpcap(set(devs), devs))
        self.assertEqual(kept, [])
        self.assertEqual(check["code"], "no-xrite")

    def test_a_session_step_without_descriptions(self):
        entry = {"files_xrite": [], "unidentified": True}
        text = probe.handheld_step_verdict(entry, 0, False)
        self.assertIn("NOTHING KEPT", text)
        self.assertIn("unplug the i1iSis's USB cable and plug it back in", text)


class Analysis(test_instrument.TempDirCase):

    def setUp(self):
        super().setUp()
        files = synth.isis_session_files(self.dir, os)
        self.folder = os.path.join(self.dir, "instrument-session-isis")
        os.makedirs(self.folder)
        steps = []
        for n, key in enumerate(ISIS_KEYS, 1):
            name = f"step{n}-{key}-take1-USBPcap1-instrument.pcap"
            probe.filter_xrite_capture(files[key], os.path.join(self.folder, name), "isis")
            steps.append({"number": n, "key": key, "title": key, "take": 1, "kept": True,
                          "files_xrite": [name], "notes": "did it",
                          "lights": "blue, then green" if key == "page-single" else "",
                          "page": "in once, out at the front" if key == "page-single" else "",
                          "setting": "dual, M0 M2" if key == "page-dual" else ""})
        session = {"kind": probe.SESSION_KIND, "family": "isis", "recorder": "USBPcapCMD",
                   "program": "i1Profiler", "program_version": "3.8.8",
                   "ended": "all steps done", "steps": steps}
        with open(os.path.join(self.folder, "session.json"), "w", encoding="utf-8") as fh:
            json.dump(session, fh)
        self.report = probe.analyze_paths([self.folder])

    def test_family_and_no_i1pro_parts(self):
        self.assertIn("instrument family: i1iSis chart reader", self.report)
        for i1pro_only in ("RULER", "FAST AGAINST SLOW", "THE LIGHTS' LANGUAGE",
                           "NOT USED BY THE OPEN DRIVER", "never uses"):
            self.assertNotIn(i1pro_only, self.report)

    def test_how_it_talks(self):
        self.assertIn("HOW DOES THE PROGRAM TALK TO THE iSis?", self.report)
        self.assertIn("reset x3", self.report)
        self.assertIn("So it LIKELY talks through a USB-to-serial chip", self.report)
        self.assertIn("      INVENTED-SCAN-PAGE", self.report)

    def test_the_devices_answers_never_shown_as_text(self):
        self.assertNotIn(synth.ISIS_FAKE_SERIAL.decode(), self.report)
        self.assertNotIn("DISPLAYSERIAL99", self.report)
        self.assertIn("not shown: they can hold its serial number", self.report)

    def test_side_by_side_notes_and_checklist(self):
        self.assertIn("STEPS SIDE BY SIDE", self.report)
        self.assertIn("operator, how the page moved: in once, out at the front", self.report)
        self.assertIn("page: in once, out at the front", self.report)
        self.assertIn("one page measured, single scan ....... yes", self.report)
        self.assertIn("the same page, dual scan ............. yes", self.report)
        self.assertIn("a page that fails on purpose ......... yes", self.report)
        self.assertIn("the same page, fed a little crooked .. yes", self.report)
        self.assertIn("notes on how the page moved .......... yes", self.report)
        self.assertIn("the recording shows the program and the iSis at work", flat(self.report))

    def test_a_plain_recording_is_recognised(self):
        files = synth.isis_session_files(self.dir, os, with_display=False)
        report = probe.analyze_paths([files["page-single"]])
        self.assertIn("instrument family: i1iSis chart reader", report)
        self.assertIn("DOES THIS RECORDING HOLD WHAT WE NEED?", report)


class PlainFilesTogether(test_instrument.TempDirCase):
    """1.6.1: several plain files given to --analyze together. A device is
    told apart by file, bus and address, and recordings of different
    instruments are never read as one (the known limit of 1.6.0)."""

    I1PRO2_EPS = [(0x82, 2), (0x84, 3), (0x03, 2), (0x85, 2), (0x81, 2)]

    def usbpcap(self, name, vid, pid, mark, eps, i1pro_cmds=False, addr=3):
        w = synth.UsbPcapWriter()
        w.describe(addr, vid, pid, eps)
        w.bulk_in(addr, [e for e, _k in eps if e & 0x80][0], mark)
        w.bulk_out(addr, [e for e, _k in eps if not e & 0x80][0], mark + b"-OUT\r")
        if i1pro_cmds:
            for req in sorted(probe.FAMILIES["i1pro2"]["requests"])[:3]:
                w.vendor_in(addr, req, mark + b"-EEPROM")
        return w.save(os.path.join(self.dir, name))

    def mac(self, name, pid, mark, addr=3):
        d = synth_io.DarwinWriter()
        d._rec(1, 1, addr, 0x81, 2, 0x0971, pid, mark, len(mark))
        d._rec(1, 2, addr, 0x02, 2, 0x0971, pid, mark + b"-OUT\r", len(mark) + 5)
        return d.save(os.path.join(self.dir, name))

    def pair(self, fmt):
        """An i1Pro 2 in one file and an i1iSis in the other, both at bus 1
        (macOS: bus 0), address 3."""
        if fmt == "usbpcap":
            return (self.usbpcap("a-i1pro2.pcap", 0x0971, 0x2000, b"I1PRO2-SERIAL",
                                 self.I1PRO2_EPS, i1pro_cmds=True),
                    self.usbpcap("b-isis.pcap", 0x0971, 0x2006, b"ISIS-MARK",
                                 [(0x81, 2), (0x02, 2)]))
        return (self.mac("a-i1pro2.pcap", 0x2000, b"I1PRO2-SERIAL"),
                self.mac("b-isis.pcap", 0x2006, b"ISIS-MARK"))

    def test_different_instruments_at_one_address_are_not_mixed(self):
        for fmt in ("usbpcap", "mac"):
            i1pro2, isis = self.pair(fmt)
            for files in ([i1pro2, isis], [isis, i1pro2]):
                with self.subTest(fmt=fmt, first=os.path.basename(files[0])):
                    report = probe.analyze_paths(files)
                    self.assertIn("These recordings come from different instruments:", report)
                    self.assertIn("a-i1pro2.pcap: i1Pro 2", report)
                    self.assertIn("b-isis.pcap: i1iSis chart reader", report)
                    self.assertIn("--analyze a-i1pro2.pcap", report)
                    self.assertIn("--analyze b-isis.pcap", report)
                    # nothing is analysed as one instrument, nothing sent is shown
                    self.assertNotIn("instrument family:", report)
                    self.assertNotIn("I1PRO2-SERIAL", report)
                    self.assertNotIn("ISIS-MARK", report)
                    self.assertNotIn("\u2014", report)
                    # the 1.4 check still lists both files
                    self.assertIn("USB recording check", report)

    def test_each_file_alone_is_read_as_before(self):
        for fmt in ("usbpcap", "mac"):
            i1pro2, isis = self.pair(fmt)
            with self.subTest(fmt=fmt):
                rep = probe.analyze_paths([i1pro2])
                self.assertIn("instrument family: i1Pro 2", rep)
                self.assertNotIn("i1iSis", rep.split("Instrument recording analysis")[1])
                rep = probe.analyze_paths([isis])
                self.assertIn("instrument family: i1iSis chart reader", rep)
                self.assertIn("ISIS-MARK-OUT", rep)

    def test_the_family_comes_from_the_selection_not_from_the_kept_devices(self):
        _a, isis = self.pair("usbpcap")
        unknown = self.usbpcap("c-unknown.pcap", 0x0971, 0x2099, b"UNKNOWN-XR",
                               [(0x81, 2), (0x02, 2)])
        for files in ([isis, unknown], [unknown, isis]):
            with self.subTest(first=os.path.basename(files[0])):
                steps, devinfo, _checks, plain = probe.session_steps(files)
                self.assertEqual(plain["plain"], "isis")
                self.assertEqual(probe.session_family(devinfo, steps, plain), "isis")
                report = probe.analyze_paths(files)
                self.assertIn("instrument family: i1iSis chart reader", report)
                # both devices at bus 1, address 3 are listed: neither hides the other
                self.assertIn("instrument at bus 1, address 3: 0971:2006", report)
                self.assertIn("instrument at bus 1, address 3: 0971:2099", report)

    def test_one_instrument_in_several_files_is_listed_once(self):
        a = self.usbpcap("scan-fast.pcap", 0x0971, 0x2000, b"I1PRO2-SERIAL",
                         self.I1PRO2_EPS, i1pro_cmds=True)
        b = self.usbpcap("noruler.pcap", 0x0971, 0x2000, b"I1PRO2-SERIAL",
                         self.I1PRO2_EPS, i1pro_cmds=True)
        report = probe.analyze_paths([a, b])
        self.assertIn("instrument family: i1Pro 2", report)
        self.assertEqual(report.count("instrument at bus 1, address 3: 0971:2000"), 1)
        self.assertNotIn("different instruments", report)

    def test_a_file_without_an_instrument_is_not_a_different_instrument(self):
        _a, isis = self.pair("usbpcap")
        w = synth.UsbPcapWriter()
        synth.keyboard_noise(w)
        other = w.save(os.path.join(self.dir, "keyboard-only.pcap"))
        report = probe.analyze_paths([isis, other])
        self.assertNotIn("different instruments", report)
        self.assertIn("instrument family: i1iSis chart reader", report)

    def test_the_i1pro_and_the_i1pro2_count_as_one(self):
        self.assertEqual(probe.mixed_families(
            {"plain": None, "families": [("a", "i1pro"), ("b", "i1pro2"), ("c", "generic")]}),
            [])
        self.assertTrue(probe.mixed_families(
            {"plain": None, "families": [("a", "munki"), ("b", "i1pro2")]}))
        self.assertEqual(probe.mixed_families(None), [])
        self.assertEqual(probe.mixed_families({"family": "isis"}), [])


class _IsisSessionBase(test_instrument.TempDirCase):
    """The handheld tests' fake USBPcapCMD, fed with invented i1iSis steps.
    Only the helpers are borrowed, so the handheld tests do not run twice."""

    saved = test_instrument.SessionTests.saved
    fake_log = test_instrument.SessionTests.fake_log

    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.dir, "bin")
        self.pcaps = os.path.join(self.dir, "pcaps")
        self.out = os.path.join(self.dir, "out")
        for d in (self.bin, self.pcaps, self.out):
            os.mkdir(d)
        self.log = os.path.join(self.dir, "fake.log")
        self.exe = os.path.join(self.bin, "fake_usbpcapcmd.py")
        with open(self.exe, "w") as fh:
            fh.write(test_instrument.FAKE_USBPCAPCMD)
        patcher = mock.patch.dict(os.environ, {"FAKE_LOG": self.log, "FAKE_PCAPS": self.pcaps})
        patcher.start()
        self.addCleanup(patcher.stop)
        for p in (mock.patch.object(probe, "RECORDER_STARTUP_WAIT", 0.3),
                  mock.patch.object(probe, "SHORT_STEP_SECONDS", 0.0)):
            p.start()
            self.addCleanup(p.stop)
        synth.isis_session_files(self.pcaps, os)
        self.folder = os.path.join(self.out, "instrument-session-test")
        self.prompts = []

    def run_session(self, answers, profile="isis"):
        """As the handheld tests' run_session, but the questions asked are
        kept too (they go to ask(), not to the screen)."""
        replies = iter(answers)

        def fake_ask(prompt, interruptible=False):
            self.prompts.append(prompt)
            return next(replies)
        recorder = probe.UsbPcapRecorder(self.exe, ["\\\\.\\USBPcap1"], "")
        buf = io.StringIO()
        with mock.patch.object(probe, "ask", fake_ask), redirect_stdout(buf):
            session = probe.run_instrument_session(recorder, self.folder, profile,
                                                   "i1Profiler", "3.8.8")
        return session, buf.getvalue()


class Session(_IsisSessionBase):
    """The guided session with the i1iSis profile."""

    def test_six_steps_in_order(self):
        self.assertEqual([s["key"] for s in probe.steps_for("isis")], ISIS_KEYS)
        self.assertTrue(probe.step_keys_unique())
        for profile in ("i1pro2", "i1pro", "i1pro3", "munki", "generic"):
            self.assertFalse(any(s["key"].startswith("page") or s["key"] in ("ready",)
                                 for s in probe.steps_for(profile)), profile)

    def test_whole_session(self):
        answers = []
        for key in ISIS_KEYS:
            answers += ["", "e", f"did {key}"] + (["dual, M0 M2"] if key == "page-dual" else [])
            answers += [f"moved {key}", "green", ""]
        session, screen = self.run_session(answers, profile="isis")
        self.assertEqual(session["ended"], "all steps done")
        self.assertIn("STEP 3 of 6: feed one page, single scan", screen)
        asked = "\n".join(self.prompts)
        self.assertIn('(for example: "page 1, measured", or "refused: barcode not found")',
                      asked)
        self.assertIn("How did the page move?", asked)
        saved = self.saved()["steps"]
        self.assertEqual([s["key"] for s in saved], ISIS_KEYS)
        self.assertEqual(saved[2]["page"], "moved page-single")
        self.assertEqual(saved[3]["setting"], "dual, M0 M2")
        self.assertEqual(saved[0]["lights"], "green")
        for step in saved:
            for name in step["files_xrite"]:
                lt, recs = probe._read_pcap(os.path.join(self.folder, name))
                self.assertEqual(set(probe.record_device_keys(lt, recs)), {(1, synth.ISIS)})
        with mock.patch.object(probe, "ask", lambda *_a, **_k: "yes"), \
                redirect_stdout(io.StringIO()):
            _lines, analysis = probe.finish_session(session, self.folder)
        self.assertIn("one page measured, single scan ....... yes", analysis)

    def test_empty_step_is_empty_and_offers_a_retake(self):
        w = synth.UsbPcapWriter()
        w.describe(synth.ISIS, 0x0971, 0x2006, synth.ISIS_ENDPOINTS)
        synth.keyboard_noise(w)
        w.save(os.path.join(self.pcaps, "idle.pcap"))
        session, screen = self.run_session(["", "e", "", "q"], profile="isis")
        self.assertIn("EMPTY: nothing was recorded in this step, please repeat it.",
                      flat(screen))
        self.assertIn("Type  r  and press Enter to record this step again",
                      "\n".join(self.prompts))
        step = self.saved()["steps"][0]
        self.assertTrue(step["empty"])
        self.assertIn("EMPTY", " ".join(step["check"]))
        self.assertEqual(session["ended"], "stopped by the operator")

    def test_only_some_steps(self):
        recorder = probe.UsbPcapRecorder(self.exe, ["\\\\.\\USBPcap1"], "")
        answers = iter(["", "e", "ok", "dual, M0 M2", "twice", "blue", ""])
        with mock.patch.object(probe, "ask", lambda *_a, **_k: next(answers)), \
                redirect_stdout(io.StringIO()) as out:
            session = probe.run_instrument_session(recorder, self.folder, "isis",
                                                   only=[4])
        self.assertIn("STEP 4 of 6: the same page again, dual scan", out.getvalue())
        self.assertEqual(session["only_steps"], [4])
        self.assertEqual([s["number"] for s in session["steps"]], [4])


class TheIsisOption(unittest.TestCase):

    setUp = test_what_to_do.TheWholeRun.setUp
    run_main = test_what_to_do.TheWholeRun.run_main

    def test_isis_option_skips_the_question_and_preselects(self):
        _code, _screen, asked, session = self.run_main([], [], argv=["--isis"])
        session.assert_called_once()
        self.assertEqual(session.call_args.kwargs.get("prefer"), "isis")
        prompts = " ".join(str(c) for c in asked.call_args_list)
        self.assertNotIn("Type 1, 2 or 3", prompts)

    def test_without_option_nothing_is_preferred(self):
        _code, _screen, _asked, session = self.run_main(["2"], [ISIS])
        self.assertIsNone(session.call_args.kwargs.get("prefer"))


class Windows(unittest.TestCase):

    def test_25h2_and_i1profiler_388(self):
        old = probe.i1profiler_check("3.8.6", "isis", 26200)
        self.assertEqual(old["level"], "warning")
        self.assertIn("3.8.8", old["text"])
        self.assertEqual(probe.i1profiler_check("3.8.8", "isis", 26200)["level"], "ok")
        self.assertEqual(probe.i1profiler_check("3.8.6", "isis", 22631)["level"], "ok")
        rel = probe.windows_release_check(26200, "25H2", False, "isis")
        self.assertEqual(rel["level"], "ok")
        self.assertIn("not the i1iSis", rel["text"])
        self.assertIn("3.8.8", rel["text"])
        self.assertNotIn("isis", probe.PROFILES_BLOCKED_ON_25H2)

    def test_driver_check_covers_the_isis(self):
        devs = [{"vid": 0x0971, "pid": 0x2006, "name": "i1iSis", "service": "",
                 "class": "", "provider": "", "status": ""}]
        checks = probe.instrument_driver_checks(devs)
        self.assertEqual(len(checks), 1)
        self.assertIn("no driver", checks[0]["text"])


class Texts(unittest.TestCase):

    def test_every_isis_step_asks_about_the_page(self):
        for step in probe.steps_for("isis"):
            self.assertTrue(step.get("page", "").strip(), step["key"])
            self.assertTrue(step["before"].startswith("  Before you press Enter"), step["key"])
            self.assertTrue(step["during"].startswith("  When the recording runs"), step["key"])
        self.assertIn("i1iSis", probe.steps_for("isis")[0]["lights"])

    def test_no_em_dash_anywhere_new(self):
        texts = [probe.ISIS_CHART_TEXT, probe.PROFILE_PURPOSE["isis"], probe.privacy_text("isis")]
        for step in probe.steps_for("isis"):
            texts += [step[k] for k in ("title", "before", "during", "lights", "page")]
            texts.append(step.get("setting", ""))
        for text in texts:
            self.assertNotIn(chr(0x2014), text)
        with open(os.path.join(HERE, "test_isis.py"), encoding="utf-8") as fh:
            self.assertEqual(fh.read().count(chr(0x2014)), 0)

    def test_power_before_usb_and_the_chart_how_to(self):
        idle = probe.steps_for("isis")[0]["before"]
        self.assertIn("switch it on BEFORE you plug in its USB cable", flat(idle))
        chart = flat(probe.ISIS_CHART_TEXT)
        self.assertIn("Its colours do not matter for this recording", chart)
        self.assertIn('names end in "i1iSis"', chart)
        self.assertIn("asks you to save the chart before printing it", chart)

    def test_privacy_names_the_chart_values_and_barcode(self):
        text = flat(probe.privacy_text("isis"))
        self.assertIn("The colour values the i1iSis measured from your chart page", text)
        self.assertIn("barcode", text)
        self.assertIn("very likely includes the i1iSis's serial number", text)
        self.assertIn("not yet proven for the i1iSis", text)
        self.assertIn("a copy that holds ONLY the i1iSis's traffic", text)
        self.assertIn("If the recording does not show which device is which, the tool "
                      "keeps nothing", text)
        self.assertIn("very likely contains your i1iSis's serial",
                      flat(probe.session_send_text("/x/f", "isis")))
        self.assertNotIn("barcode", probe.privacy_text("i1pro2"))

    def test_lines_fit_the_window(self):
        texts = [probe.ISIS_CHART_TEXT, probe.PROFILE_PURPOSE["isis"], probe.privacy_text("isis")]
        for step in probe.steps_for("isis"):
            texts += [step["before"]]
        for text in texts:
            for line in text.splitlines():
                self.assertLessEqual(len(line), 76, line)


class ReviewTexts(unittest.TestCase):
    """The review's minor findings 4 to 8 and the step-box nit."""

    def setUp(self):
        saved = dict(probe._RUN)
        self.addCleanup(lambda: (probe._RUN.clear(), probe._RUN.update(saved)))
        probe._RUN.clear()

    def test_old_chart_page_and_paper(self):
        chart = flat(probe.ISIS_CHART_TEXT)
        self.assertIn("as long as i1Profiler still has that chart (open the same chart file "
                      "in i1Profiler before step 2)", chart)
        self.assertIn("normal 80 g/m2 printer paper", chart)
        self.assertIn("please do not use thinner paper", chart)
        blank = flat(probe.steps_for("isis")[5]["before"])
        self.assertIn("normal 80 g/m2 printer paper, the same size as your chart", blank)

    def test_as_far_as_we_know(self):
        self.assertIn("as far as we know, nobody outside X-Rite",
                      flat(probe.PROFILE_PURPOSE["isis"]))

    def test_relaunch_keeps_isis_and_steps(self):
        probe._RUN.update(profile="isis", steps="4,6")
        _prog, params, _cwd = probe.relaunch_command()
        self.assertIn(" --isis", params)
        self.assertNotIn("--i1pro", params)
        self.assertIn("--steps 4,6", params)
        probe._RUN.clear()
        probe._RUN.update(isis=True)                 # flag given, nothing chosen yet
        self.assertIn(" --isis", probe.relaunch_command()[1])
        probe._RUN.clear()
        params = probe.relaunch_command()[1]
        self.assertIn(" --i1pro", params)
        self.assertNotIn("--steps", params)

    def test_relaunch_passes_the_chosen_profile_not_the_flag(self):
        # Second review, minor 3: started with --isis, then chose the i1Pro 3.
        probe._RUN.update(isis=True, profile="i1pro3")
        params = probe.relaunch_command()[1]
        self.assertIn("--i1pro --profile i1pro3", params)
        self.assertNotIn("--isis", params)

    def test_relaunch_steps_are_parsed_numbers(self):
        # Second review nit: a quote in the raw text broke the command line.
        probe._RUN.update(profile="i1pro2", steps='4" --no-redact "')
        params = probe.relaunch_command()[1]
        self.assertNotIn("--no-redact", params)
        self.assertEqual(params.count('"'), 2)          # only the script path
        probe._RUN.update(steps=" 6; 4, 4 ")
        self.assertIn("--steps 4,6", probe.relaunch_command()[1])

    def test_the_profile_option_is_hidden_and_checked(self):
        args = probe.argparse.Namespace
        with mock.patch.object(probe, "instrument_session_step") as step, \
                mock.patch.object(probe, "quick_summary", lambda: "NO X-RITE DEVICES SEEN."), \
                mock.patch.object(probe, "collect_macos", lambda: None), \
                mock.patch.object(probe, "collect_windows", lambda: None), \
                mock.patch.object(probe, "collect_linux", lambda: None), \
                mock.patch.object(probe, "collect_i1profiler_charts", lambda: None), \
                mock.patch.object(probe, "finish_report", lambda *a, **k: 0), \
                redirect_stdout(io.StringIO()):
            step.return_value = {}
            probe.main(["--profile", "munki", "--no-pause"])
        self.assertEqual(step.call_args.kwargs["prefer"], "munki")
        self.assertTrue(args)

    def test_linux_replug_hint_before_the_steps(self):
        text = flat(probe.LINUX_ISIS_REPLUG_TEXT)
        self.assertIn("in EVERY step: press Enter here to start the step, then unplug", text)

    def test_mac_box_speaks_to_the_isis_owner(self):
        r = {"reasons": ["SIP is switched on."], "cpu": {"apple_silicon": True}}
        isis = flat(probe.recording_not_possible_text(r, "instrument", "isis"))
        self.assertIn("i1Profiler 3.8.8 fixed the i1iSis drivers", isis)
        self.assertIn("Connect the i1iSis to that PC", isis)
        self.assertNotIn("i1Pro 2", isis)
        other = flat(probe.recording_not_possible_text(r, "instrument"))
        self.assertIn("the X-Rite driver for the i1Pro 2 and the i1iO 2", other)
        self.assertIn("IMPORTANT FOR OWNERS OF AN i1Pro 2", other)

    def test_windows_on_arm(self):
        text = probe.windows_release_check(26100, "24H2", True, "isis")["text"]
        self.assertIn("i1iSis works here is not known", text)
        self.assertNotIn("i1Pro 2", text)

    def test_what_to_do_now(self):
        probe._RUN["profile"] = "isis"
        text = flat("\n".join(probe.what_to_do_lines(["no_instrument"], None)))
        self.assertIn("Switch the i1iSis on FIRST, then plug its USB cable", text)
        self.assertNotIn("switch the table on", text)
        probe._RUN.clear()
        self.assertIn("switch the table on",
                      flat("\n".join(probe.what_to_do_lines(["no_instrument"], None))))

    def test_step_box_for_the_isis(self):
        first = probe.steps_for("isis")[0]
        box = flat(probe.step_box(first["during"], first["box"]))
        self.assertIn("2. Then: start i1Profiler and wait", box)
        self.assertNotIn("in the measuring program", box)
        handheld = flat(probe.step_box(probe.steps_for("i1pro2")[0]["during"]))
        self.assertIn("Then do this in the measuring program:", handheld)


# ---- the read-only promise -------------------------------------------------
#
# WHAT THIS TEST WATCHES (second review: said exactly, not "everything"):
#   files:     builtins.open, io.open, os.open (and so pathlib);
#   programs:  subprocess (every form goes through Popen), os.system,
#              os.popen, os.posix_spawn / posix_spawnp, os.spawn*, os.exec*;
#   libraries: ctypes.CDLL / PyDLL and the cdll / pydll loaders.
# Each program the tool may start is pinned to the arguments it really
# uses (taken from the source; test_the_allowlist_matches_the_source keeps
# the list of program names in step with it). A source check bans the
# process functions above outright and allows ctypes only for the Windows
# calls the tool names.
# One list per command line the tool really builds: a pattern per argument
# (an argument may hold spaces, such as a folder name). PowerShell is pinned
# to the exact scripts in the tool's POWERSHELL_SCRIPTS.
XRITE_FOLDER = "/Library/Application Support/X-Rite"
ARG_PATTERNS = [
    ["usbpcapcmd", r"--extcap-(interfaces|version)"],
    ["usbpcapcmd", "--extcap-config", "--extcap-interface", r".+"],
    ["usbpcapcmd", "-d", r".+", "-o", r".+", "-A"],
    ["usbpcapcmd", "-d", r".+", "-o", r".+", "-A", "--inject-descriptors"],
    ["sudo", "-v"],
    ["sudo", "-n", "true"],
    ["sudo", "-n", "ifconfig", r"\w+", "(up|down)"],
    ["sudo", "-n", "tcpdump", "-U", "-i", r"\w+", "-w", r".+"],
    ["sudo", "-n", "pkill", "-TERM", "-f", r"\S*tcpdump -U -i \w+ -w .+"],
    ["ifconfig", "-l"],
    ["ifconfig", r"\w+"],
    ["sysctl", "-n", r"hw\.optional\.arm64|machdep\.cpu\.brand_string"],
    ["csrutil", "status"],
    ["system_profiler", "-json", r"SPUSB(Host)?DataType"],
    ["ioreg", "-p", "IOUSB", "-l", "-w", "0"],
    ["ioreg", "-l", "-w", "0", "-r", "-c", "IOUSBHostDevice"],
    ["find", re.escape(XRITE_FOLDER), "-maxdepth", "12", "-name", r"Info\.plist"],
    ["plutil", "-p", re.escape(XRITE_FOLDER) + r"/[^\n]+/Info\.plist"],
    ["lsusb"],
    ["lsusb", "-t"],
    ["lsusb", "-v", "-d", r"[0-9a-f]{4}:"],
    ["bash", "-c", re.escape("dmesg 2>/dev/null | grep -iE 'usb|ftdi' | tail -60")],
    ["sc", "query", "USBPcap"],
]
POWERSHELL_HEAD = ["-NoProfile", "-NonInteractive", "-NoLogo", "-Command"]


def command_allowed(argv):
    """Is this exact command line one the tool really builds?"""
    words = [str(a) for a in argv]
    if not words:
        return False
    words[0] = _program(words[0])
    if words[0] == "sudo" and len(words) > 2:
        words[2] = _program(words[2])            # /usr/sbin/tcpdump -> tcpdump
    if words[0] in ("powershell", "pwsh"):
        scripts = set(probe.POWERSHELL_SCRIPTS)
        scripts |= {probe.PS_PREFIX + x for x in probe.POWERSHELL_SCRIPTS}
        return words[1:5] == POWERSHELL_HEAD and len(words) == 6 and words[5] in scripts
    return any(len(pat) == len(words) and all(re.fullmatch(p, w) for p, w in zip(pat, words))
               for pat in ARG_PATTERNS)


ALLOWED_PROGRAMS = {"usbpcapcmd", "tcpdump", "sudo", "ifconfig", "sysctl", "csrutil",
                    "system_profiler", "ioreg", "find", "plutil", "lsusb", "bash",
                    "powershell", "pwsh", "sc"}
# The Windows functions the tool calls through ctypes (kernel32, shell32).
CTYPES_CALLS = {"IsUserAnAdmin", "CreateJobObjectW", "SetInformationJobObject",
                "AssignProcessToJobObject", "CloseHandle", "GetStdHandle", "GetConsoleMode",
                "SetConsoleMode", "SetConsoleTitleW", "GetConsoleTitleW", "ShellExecuteExW",
                "WaitForSingleObject", "GetExitCodeProcess", "GetConsoleProcessList",
                "OpenProcess", "QueryFullProcessImageNameW"}


def _program(arg0):
    name = re.split(r"[\\/]", str(arg0))[-1].lower()     # Windows or POSIX folders
    return name[:-4] if name.endswith(".exe") else name


def _called_from(filename):
    frame = sys._getframe(1)
    while frame is not None:
        if os.path.basename(frame.f_code.co_filename) == filename:
            return True
        frame = frame.f_back
    return False


class _Refusing:
    """Stands in for ctypes.pythonapi: any function taken from it is refused."""

    def __init__(self, watch, name):
        self._watch, self._name = watch, name

    def __getattr__(self, attr):
        self._watch._refuse(f"{self._name}.{attr}")


class DeviceWatch:
    """Watches, and blocks, the ways listed above. A violation is recorded and
    refused with an error, so a broken tool cannot touch anything here."""

    def __init__(self, base, fake_recorder):
        self.base = os.path.realpath(base)
        self.fake = os.path.realpath(fake_recorder)
        self.violations = []
        self.opened = 0
        self.started = []

    def _refuse(self, text):
        self.violations.append(text)
        raise PermissionError("blocked by the test: " + text)

    def _check_path(self, path, writing, from_subprocess=False):
        if isinstance(path, int):
            return
        text = os.fspath(path)
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        self.opened += 1
        if from_subprocess and text == os.devnull:
            return    # subprocess opens /dev/null (Windows: nul) for unused input
        real = os.path.realpath(text)
        device = (real.startswith("/dev/") or text.startswith("/dev/")
                  or text.startswith("\\\\.\\") or text.startswith("//./"))
        if device:
            self._refuse(f"opened a device: {text}")
        if writing and not real.startswith(self.base):
            self._refuse(f"wrote outside its folders: {text}")

    def _check_program(self, args):
        argv = [args] if isinstance(args, (str, bytes)) else list(args)
        self.started.append(argv)
        if _program(argv[0]).startswith("python") and len(argv) > 1 and \
                os.path.realpath(str(argv[1])) == self.fake:
            argv = ["usbpcapcmd"] + argv[2:]          # the tests' fake USBPcapCMD
        elif _program(argv[0]) in ("uname", "file") and _called_from("platform.py"):
            return                 # Python's own platform module asks (3.9 does)
        if not command_allowed(argv):
            self._refuse(f"started a program not on the list: {argv}")

    def __enter__(self):
        import ctypes
        import io as io_mod
        import subprocess
        watch = self
        real_open, real_io_open, real_os_open = builtins.open, io_mod.open, os.open
        real_popen = subprocess.Popen
        real_posix_spawn = getattr(os, "posix_spawn", None)
        real_posix_spawnp = getattr(os, "posix_spawnp", None)

        def w_open(file, mode="r", *a, **k):
            watch._check_path(file, any(c in mode for c in "wax+"))
            return real_open(file, mode, *a, **k)

        def w_io_open(file, mode="r", *a, **k):
            watch._check_path(file, any(c in mode for c in "wax+"))
            return real_io_open(file, mode, *a, **k)

        def w_os_open(path, flags, *a, **k):
            caller = sys._getframe(1).f_code.co_filename
            watch._check_path(path, bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)),
                              from_subprocess=caller.endswith("subprocess.py"))
            return real_os_open(path, flags, *a, **k)

        class WatchedPopen(real_popen):
            def __init__(self, args, *a, **k):
                watch._check_program(args)
                super().__init__(args, *a, **k)

        def spawn_from_subprocess(real, name):
            def inner(*a, **k):
                # subprocess itself uses posix_spawn after Popen was checked
                if sys._getframe(1).f_code.co_filename.endswith("subprocess.py"):
                    return real(*a, **k)
                watch._refuse(f"{name}{a[:2]!r}")
            return inner

        def refuse(name):
            def inner(*a, **_k):
                watch._refuse(f"{name}{a[:2]!r}")
            return inner

        self._patches = [mock.patch.object(builtins, "open", w_open),
                         mock.patch.object(io_mod, "open", w_io_open),
                         mock.patch.object(os, "open", w_os_open),
                         mock.patch.object(subprocess, "Popen", WatchedPopen),
                         mock.patch.object(os, "system", refuse("os.system")),
                         mock.patch.object(os, "popen", refuse("os.popen")),
                         mock.patch.object(ctypes, "CDLL", refuse("ctypes.CDLL")),
                         mock.patch.object(ctypes, "PyDLL", refuse("ctypes.PyDLL")),
                         mock.patch.object(ctypes, "cdll", types.SimpleNamespace(
                             LoadLibrary=refuse("ctypes.cdll.LoadLibrary"))),
                         mock.patch.object(ctypes, "pydll", types.SimpleNamespace(
                             LoadLibrary=refuse("ctypes.pydll.LoadLibrary"))),
                         mock.patch.object(ctypes, "pythonapi", _Refusing(watch, "ctypes.pythonapi")),
                         mock.patch.object(ctypes, "_dlopen", refuse("ctypes._dlopen"))]
        import _ctypes
        import multiprocessing.process
        for name in ("dlopen", "dlsym", "dlclose"):
            if hasattr(_ctypes, name):
                self._patches.append(mock.patch.object(_ctypes, name, refuse("_ctypes." + name)))
        self._patches.append(mock.patch.object(multiprocessing.process.BaseProcess, "start",
                                               refuse("multiprocessing.Process.start")))
        try:
            import pty                       # POSIX only (it needs termios)
        except ImportError:
            pty = None
        for mod, name in ((os, "forkpty"), (os, "openpty"), (os, "fork"), (pty, "fork"),
                          (pty, "openpty"), (pty, "spawn")):
            if mod is not None and hasattr(mod, name):
                self._patches.append(mock.patch.object(
                    mod, name, refuse(f"{mod.__name__}.{name}")))
        if real_posix_spawn:
            self._patches.append(mock.patch.object(
                os, "posix_spawn", spawn_from_subprocess(real_posix_spawn, "os.posix_spawn")))
        if real_posix_spawnp:
            self._patches.append(mock.patch.object(
                os, "posix_spawnp", spawn_from_subprocess(real_posix_spawnp, "os.posix_spawnp")))
        for name in dir(os):
            if re.fullmatch(r"(spawn|exec)[lv]p?e?", name):
                self._patches.append(mock.patch.object(os, name, refuse("os." + name)))
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


# The reviews' mutations (review/mut/mutate.py and the second review), each a
# way a broken tool could reach a device or start something. Every one must
# be caught.
MUTATIONS = {
    "builtin_open": 'open("/dev/zero", "wb").close()',
    "pathlib": '__import__("pathlib").Path("/dev/zero").write_bytes(b"x")',
    "io_open": '__import__("io").open("/dev/zero", "wb").close()',
    "io_open_joined": '__import__("io").open(os.path.join("/dev", "zero"), "wb").close()',
    "windows_device": 'open(r"\\\\.\\COM3" if False else os.path.join("/dev", "zero"), "wb").close()',
    "subprocess": '__import__("subprocess").run(["sh", "-c", ": > /dev/zero"])',
    "devnull_write": 'open(os.devnull, "wb").write(b"x")',
    "os_open": 'os.close(os.open("/dev/zero", os.O_WRONLY))',
    "pathlib_text_outside": '__import__("pathlib").Path(os.path.expanduser("~")).joinpath('
                            '"chromiq-probe-test-must-not-exist.txt").write_text("x")',
    # second review
    "os_system": 'os.system(": > /dev/zero")',
    "posix_spawn": 'os.waitpid(os.posix_spawn("/bin/sh", ["sh", "-c", ":"], dict(os.environ)), 0)',
    "find_exec": '__import__("subprocess").run(["find", "/tmp", "-maxdepth", "0", '
                 '"-exec", "sh", "-c", ":", ";"])',
    "sysctl_write": '__import__("subprocess").run(["sysctl", "-w", "kern.maxfiles=12288"])',
    "ctypes_open": '__import__("ctypes").CDLL(None).open(b"/dev/zero", 1)',
    # third review
    "pythonapi_open": '__import__("ctypes").pythonapi.open(b"/dev/zero", 1)',
    "forkpty": '(lambda r: os._exit(0) if r[0] == 0 else os.waitpid(r[0], 0))(os.forkpty())',
    # fourth review
    "ctypes_dlsym": '(lambda c, _c: c.CFUNCTYPE(c.c_int, c.c_char_p, c.c_int)('
                    '_c.dlsym(_c.dlopen(None), "open"))(b"/dev/zero", 1))'
                    '(__import__("ctypes"), __import__("_ctypes"))',
    "multiprocessing_spawn": '__import__("multiprocessing").get_context("spawn").Process('
                             'target=os.getpid).start()',
}
# Mutations that need a POSIX function; on Windows the function does not
# exist, so the broken copy could not do it there either.
POSIX_ONLY = {"posix_spawn": ("os", "posix_spawn"), "forkpty": ("os", "forkpty"),
              "ctypes_dlsym": ("_ctypes", "dlsym")}
MUTATION_ANCHOR = '    os.makedirs(folder, exist_ok=True)\n    _END["session_folder"] = folder\n'


class ReadOnlyPromise(_IsisSessionBase):
    """The tool never opens a device, starts only the programs it names, and
    writes only into its own folders."""

    def watched_session(self, mod, only=None):
        answers = []
        for key in ISIS_KEYS:
            answers += ["", "e", "ok"] + (["dual"] if key == "page-dual" else []) + ["", "", ""]
        replies = iter(answers)
        recorder = mod.UsbPcapRecorder(self.exe, ["\\\\.\\USBPcap1"], "")
        with DeviceWatch(self.dir, self.exe) as watch, \
                mock.patch.object(mod, "ask", lambda *_a, **_k: next(replies)), \
                mock.patch.object(mod, "RECORDER_STARTUP_WAIT", 0.3), \
                mock.patch.object(mod, "SHORT_STEP_SECONDS", 0.0), \
                redirect_stdout(io.StringIO()):
            try:
                session = mod.run_instrument_session(recorder, self.folder, "isis",
                                                     "i1Profiler", "3.8.8", only=only)
            except Exception as exc:                      # noqa: BLE001
                session = {"ended": f"raised {exc!r}"}
        return session, watch

    def test_a_whole_isis_session_opens_no_device(self):
        session, watch = self.watched_session(probe)
        self.assertEqual(watch.violations, [])
        self.assertEqual(session["ended"], "all steps done")
        self.assertGreater(watch.opened, 0)
        # The (fake) recorder was really started, through the watched path.
        self.assertTrue(any(str(self.exe) in [str(x) for x in argv] for argv in watch.started))

    def test_every_mutation_is_caught(self):
        import importlib.util
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertEqual(src.count(MUTATION_ANCHOR), 1)
        for name, line in MUTATIONS.items():
            if name in POSIX_ONLY:
                mod_name, attr = POSIX_ONLY[name]
                if not hasattr(__import__(mod_name), attr):
                    continue
            with self.subTest(mutation=name):
                path = os.path.join(self.dir, f"mutant_{name}.py")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(src.replace(MUTATION_ANCHOR, MUTATION_ANCHOR + "    " + line + "\n"))
                spec = importlib.util.spec_from_file_location(f"mutant_{name}", path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                _session, watch = self.watched_session(mod, only=[1])
                self.assertTrue(watch.violations, f"mutation {name} was not caught")
        self.assertFalse(os.path.exists(os.path.join(os.path.expanduser("~"),
                                                     "chromiq-probe-test-must-not-exist.txt")))

    def test_every_powershell_call_uses_a_named_script(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertEqual(src.count('"-Command",'), 3)
        tails = re.findall(r'"-Command",\s*([^\]]+)\]', src)
        self.assertEqual(sorted(t.strip() for t in tails),
                         ["PS_PREFIX + script", "PS_PREFIX + script", "PS_SUMMARY"])
        names = re.findall(r"(?:psrun|_powershell)\((\w+)\)", src)
        self.assertTrue(names)
        for name in names:
            self.assertIn(getattr(probe, name), probe.POWERSHELL_SCRIPTS, name)

    def test_the_allowlist_matches_the_source(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        literal = set(re.findall(r"(?:run|run_cached|_run|call|Popen)\(\[\s*\"([\w.-]+)\"", src))
        self.assertTrue(literal)
        self.assertEqual(literal - ALLOWED_PROGRAMS, set())

    def test_the_source_has_no_way_to_talk_to_a_device(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        for pattern in (r"^\s*(import|from)\s+(usb|hid|serial|pyusb|libusb|ftd2xx|pyftdi)\b",
                        r"CreateFile", r"IOServiceOpen", r"IOCreatePlugInInterface",
                        r"WinUsb_", r"DeviceIoControl", r"open\(\s*['\"]/dev/",
                        r"os\.open\(", r"os\.system\b", r"os\.popen\b", r"os\.spawn",
                        r"os\.exec", r"posix_spawn", r"\bpty\.spawn", r"\bCDLL\b",
                        r"\bPyDLL\b", r"\bcdll\b", r"\bpydll\b", r"\boledll\b",
                        r"LoadLibrary", r"find_library", r"-exec\b", r"\bpythonapi\b",
                        r"\b_dlopen\b", r"\bforkpty\b", r"\bopenpty\b", r"\bos\.fork\b",
                        r"^\s*import pty\b", r"\bpty\.\w", r"\b_ctypes\b", r"\bdlsym\b",
                        r"\bCFUNCTYPE\b", r"\bmultiprocessing\b", r"\b_posixsubprocess\b"):
            self.assertIsNone(re.search(pattern, src, re.M), pattern)

    def test_the_patterns_match_the_recorders_commands(self):
        rec = probe.UsbPcapRecorder("C:\\Program Files\\USBPcap\\USBPcapCMD.exe",
                                    ["\\\\.\\USBPcap1"], "")
        tcp = probe.TcpdumpRecorder(["XHC0"], "", mac=True)
        tcp.sudo, tcp.tcpdump = "/usr/bin/sudo", "/usr/sbin/tcpdump"
        for argv in (rec.command("\\\\.\\USBPcap1", "C:\\x\\s1-full.pcap"),
                     rec.retry_command("\\\\.\\USBPcap1", "C:\\x\\s1-full.pcap", ""),
                     tcp.command("XHC0", "/x/s1-full.pcap")):
            self.assertTrue(command_allowed(argv), argv)
        for bad in (["sysctl", "-w", "kern.maxfiles=1"], ["find", "/", "-exec", "sh", ";"],
                    ["find", "/", "-exec", "sh", "-c", "x", ";", "-maxdepth", "12", "-name",
                     "Info.plist"],
                    ["find", "/", "-maxdepth", "12", "-name", "Info.plist"],
                    ["powershell", "-NoProfile", "-NonInteractive", "-NoLogo", "-Command",
                     "Remove-Item C:\\x"],
                    ["sudo", "-n", "sh", "-c", "x"], ["sh", "-c", ":"]):
            self.assertFalse(command_allowed(bad), bad)
        # the real ones, including a folder with a space and every PowerShell script
        self.assertTrue(command_allowed(["C:\\Program Files\\USBPcap\\USBPcapCMD.exe",
                                         "-d", "\\\\.\\USBPcap1", "-o",
                                         "C:\\Users\\A B\\s1-full.pcap", "-A"]))
        self.assertTrue(command_allowed(["find", XRITE_FOLDER, "-maxdepth", "12", "-name",
                                         "Info.plist"]))
        for script in probe.POWERSHELL_SCRIPTS:
            self.assertTrue(command_allowed(["powershell.exe"] + POWERSHELL_HEAD
                                            + [probe.PS_PREFIX + script]))

    def test_ctypes_only_for_the_named_windows_calls(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        libs = set(re.findall(r"windll\.(\w+)", src))
        self.assertEqual(libs, {"kernel32", "shell32"})
        called = set(re.findall(r"(?:k32|shell32|windll\.kernel32|windll\.shell32)\.(\w+)", src))
        self.assertTrue(called)
        self.assertEqual(called - CTYPES_CALLS, set())
        self.assertNotIn("windll.", re.sub(r"windll\.(kernel32|shell32)", "", src))


if __name__ == "__main__":
    unittest.main()
