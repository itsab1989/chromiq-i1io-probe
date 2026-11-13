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
        # A recording without a session that shows an i1iSis is read as one.
        self.assertEqual(probe.check_capture(self.files["page-single"])["xrite_packets"],
                         mine["xrite_packets"])

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
        src = priv_usbpcap(set(PRIV_DEVS)).save(os.path.join(self.dir, "raw.pcap"))
        report = probe.analyze_paths([src])
        detail = report.split("Instrument recording analysis")[1]
        for marker in ALL_MARKERS:
            if marker != b"ISIS-MARK":
                self.assertNotIn(marker.decode(), report)
        self.assertNotIn("0765:5020", detail)
        self.assertNotIn("0971:2000", detail)
        self.assertEqual(detail.count("instrument at bus"), 1)
        lines = detail.split("the first different lines the program sent")[1]
        self.assertIn("ISIS-MARK-OUT", lines)
        self.assertNotIn("STICK", lines)
        # The i1iSis's own answers are not shown either, only their size.
        self.assertIn("data on 0x81 bulk IN: 9 bytes (from the device, not shown)", detail)

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
        self.assertIn("notes on how the page moved .......... yes", self.report)
        self.assertIn("the recording shows the program and the iSis at work", flat(self.report))

    def test_a_plain_recording_is_recognised(self):
        files = synth.isis_session_files(self.dir, os, with_display=False)
        report = probe.analyze_paths([files["page-single"]])
        self.assertIn("instrument family: i1iSis chart reader", report)
        self.assertIn("DOES THIS RECORDING HOLD WHAT WE NEED?", report)


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


class ReadOnlyPromise(_IsisSessionBase):
    """The tool never opens a device, and writes only into its own folders."""

    def test_a_whole_isis_session_opens_no_device(self):
        opened = []
        real_open, real_os_open = builtins.open, os.open

        def watch_open(file, mode="r", *a, **k):
            opened.append((str(file), mode))
            return real_open(file, mode, *a, **k)

        def watch_os_open(path, flags, *a, **k):
            opened.append((str(path), "w" if flags & (os.O_WRONLY | os.O_RDWR) else "r"))
            return real_os_open(path, flags, *a, **k)

        answers = []
        for key in ISIS_KEYS:
            answers += ["", "e", "ok"] + (["dual"] if key == "page-dual" else []) + ["", "", ""]
        with mock.patch.object(builtins, "open", watch_open), \
                mock.patch.object(os, "open", watch_os_open):
            session, _screen = self.run_session(answers, profile="isis")
        self.assertEqual(session["ended"], "all steps done")
        self.assertTrue(opened)
        base = os.path.realpath(self.dir)
        for path, mode in opened:
            # /dev/null is where a helper program's unused input comes from.
            if path == os.devnull:
                continue
            self.assertFalse(path.startswith("/dev/") or path.startswith("\\\\.\\"),
                             f"opened a device: {path}")
            if any(c in mode for c in "wax+"):
                real = os.path.realpath(path)
                self.assertTrue(real.startswith(base), f"wrote outside its folders: {path}")

    def test_the_source_has_no_way_to_talk_to_a_device(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        for pattern in (r"^\s*(import|from)\s+(usb|hid|serial|pyusb|libusb|ftd2xx|pyftdi)\b",
                        r"CreateFile", r"IOServiceOpen", r"IOCreatePlugInInterface",
                        r"WinUsb_", r"DeviceIoControl", r"open\(\s*['\"]/dev/",
                        r"os\.open\("):
            self.assertIsNone(re.search(pattern, src, re.M), pattern)


if __name__ == "__main__":
    unittest.main()
