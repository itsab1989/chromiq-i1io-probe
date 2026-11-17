"""1.6.6 (b, c, d, f): the full recordings are kept when a step kept nothing,
an earlier session can be rescued from them with --reprocess, the session
follows the instrument and stops when nothing of it is seen, and
unplugging and plugging in again is safe.

The rescue is tested on folders shaped exactly like the ones 1.6.5 leaves
behind (instrument-session-<stamp>/session.json beside
instrument-session-<stamp>-FULL-do-not-send/step<N>-<key>-take<T>-USBPcap1-
full.pcap, as run_instrument_session and UsbPcapRecorder name them), with
INVENTED recordings (tests/synth_follow.py).

    python3 -m unittest discover -s tests -v
"""

import hashlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
import zipfile
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth_follow as sf  # noqa: E402
import test_all_empty as tae  # noqa: E402

STAMP = "20261117-090000"
STEPS = ((1, "idle", "start the program, then leave it idle"), (2, "calibrate", "calibrate"),
         (4, "scan-dual", "the same strip, dual scan"),
         (6, "scan-slow", "the same strip again, slowly"))
MARKERS = (sf.KEY_MARKER, sf.DISK_MARKER[:19], sf.BT_MARKER[:17])


def make_165_session(root, build=None, session_json=True):
    """A session as 1.6.5 leaves it when every step kept nothing."""
    name = f"instrument-session-{STAMP}"
    sess = os.path.join(root, name)
    full = sess + probe.FULL_SUFFIX
    os.makedirs(sess)
    os.makedirs(full)
    steps = []
    for number, key, title in STEPS:
        fn = f"step{number}-{key}-take1-USBPcap1-full.pcap"
        w = build(number) if build else sf.swapped_step(readings=number, hub_back=number == 2)
        w.save(os.path.join(full, fn))
        steps.append({
            "number": number, "key": key, "title": title, "take": 1, "control": False,
            "start_epoch": 1800000000.0, "end_epoch": 1800000040.0, "files_full": [fn],
            "files_xrite": [], "check": [f"{fn}: 6 instrument packets; EMPTY: only the USB "
                                         "description was recorded, nothing the instrument "
                                         "did."],
            "empty": True, "seen": {"records": 1000, "classes": {}, "family_ids": {},
                                    "family_eps": {}, "files": 1, "unreadable": 0,
                                    "other_instruments": {}},
            "kept": True})
    if session_json:
        with open(os.path.join(sess, "session.json"), "w", encoding="utf-8") as fh:
            json.dump({"kind": probe.SESSION_KIND, "probe_version": "1.6.5",
                       "created": "2026-11-17T08:50:29", "family": "i1pro2",
                       "instrument": "i1Pro 2", "program": "i1Profiler",
                       "program_version": "3.8.6", "recorder": "USBPcap (USBPcapCMD)",
                       "platform": "Windows-11", "steps": steps,
                       "ended": "all steps done", "context": {}, "only_steps": [1, 2, 4, 6],
                       "first_step_descriptor_only": True, "descriptor_only_go_on": True},
                      fh, indent=2)
    return sess, full


def digest(folder):
    out = {}
    for name in sorted(os.listdir(folder)):
        with open(os.path.join(folder, name), "rb") as fh:
            out[name] = hashlib.sha256(fh.read()).hexdigest()
    return out


class Rescue(unittest.TestCase):
    """(c) --reprocess on 1.6.5-shaped folders."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        for clear in (probe._SECTIONS, probe._END, probe._CAUSES, probe._LAST_REPORT):
            clear.clear()
            self.addCleanup(clear.clear)

    def run_main(self, argv, answers=()):
        it = iter(answers)
        out = io.StringIO()
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.root]), \
                mock.patch.object(probe, "ask", lambda *_a, **_k: next(it, "")), \
                redirect_stdout(out):
            code = probe.main(argv)
        return code, out.getvalue()

    def zip_names(self):
        zips = [n for n in os.listdir(self.root) if n.startswith("SEND-THIS-")]
        self.assertEqual(len(zips), 1, zips)
        with zipfile.ZipFile(os.path.join(self.root, zips[0])) as zf:
            return zips[0], {n: zf.read(n) for n in zf.namelist()}

    def test_rescues_the_full_folder(self):
        sess, full = make_165_session(self.root)
        before = digest(full)
        code, screen = self.run_main(["--reprocess", full])
        self.assertEqual(code, 0, screen)
        flat = " ".join(screen.split())
        self.assertIn("RESCUED: 4 steps now hold the instrument's traffic (step 1, 2, 4, 6).",
                      flat)
        self.assertIn("FOUND UNDER ANOTHER USB ADDRESS (one the recording gives to a USB hub)",
                      flat)
        self.assertIn("SEND THIS ONE FILE (the report and the instrument-only recordings):",
                      screen)
        self.assertIn("was only read, not changed. Do NOT send it.", flat)
        # the full recordings: untouched
        self.assertEqual(digest(full), before)
        new = sess + probe.REPROCESSED_SUFFIX
        files = sorted(os.listdir(new))
        self.assertEqual(files, ["analysis.txt", "session.json"]
                         + [f"step{n}-{k}-take1-USBPcap1-instrument.pcap" for n, k, _ in STEPS])
        with open(os.path.join(new, "session.json"), encoding="utf-8") as fh:
            saved = json.load(fh)
        self.assertEqual(saved["probe_version"], "1.6.5")
        self.assertEqual(saved["reprocessed"]["version"], probe.PROBE_VERSION)
        self.assertEqual(saved["reprocessed"]["from"], os.path.basename(full))
        for step in saved["steps"]:
            self.assertTrue(step["files_xrite"])
            self.assertNotIn("empty", step)
            self.assertNotIn("seen", step)
            self.assertTrue(step["followed"]["followed"])
        name, members = self.zip_names()
        self.assertFalse(name.endswith("-report-only.zip"))
        self.assertTrue(any(n.endswith("/analysis.txt") for n in members))
        self.assertFalse(any(n.endswith("-full.pcap") for n in members), members)
        self.assertEqual(sum(n.endswith("-instrument.pcap") for n in members), 4)
        for data in members.values():
            for marker in MARKERS:
                self.assertNotIn(marker, data)
        report = [v for n, v in members.items() if n.startswith("chromiq-io-probe-")][0].decode()
        self.assertIn("Rescued recording session (--reprocess)", report)
        self.assertIn("WHAT WAS FOLLOWED TO ANOTHER USB ADDRESS", report)
        self.assertNotIn("THIS REPORT CONTAINS NO RECORDING", report)
        self.assertIn("instrument family: i1Pro 2 (Rev E)", report)
        for line in screen.splitlines():
            if self.root not in line:
                self.assertLessEqual(len(line), 80, line)

    def test_the_session_folder_works_too_and_a_second_run_does_not_overwrite(self):
        sess, _full = make_165_session(self.root)
        self.assertEqual(self.run_main(["--reprocess", sess])[0], 0)
        for clear in (probe._SECTIONS, probe._END):
            clear.clear()
        self.assertEqual(self.run_main(["--reprocess", sess + os.sep])[0], 0)
        self.assertTrue(os.path.isdir(sess + probe.REPROCESSED_SUFFIX))
        self.assertTrue(os.path.isdir(sess + probe.REPROCESSED_SUFFIX + "-2"))

    def test_dropped_onto_the_tool(self):
        _sess, full = make_165_session(self.root)
        code, screen = self.run_main([full])
        self.assertEqual(code, 0)
        self.assertIn("RESCUED", screen)

    def test_without_a_path_the_newest_folder_next_to_the_tool(self):
        make_165_session(self.root)
        code, screen = self.run_main(["--reprocess"])
        self.assertEqual(code, 0, screen)
        self.assertIn("RESCUED", screen)

    def test_without_session_json_the_steps_come_from_the_file_names(self):
        sess, full = make_165_session(self.root, session_json=False)
        code, screen = self.run_main(["--reprocess", full])
        self.assertEqual(code, 0, screen)
        self.assertIn("taken from the file names", " ".join(screen.split()))
        with open(os.path.join(sess + probe.REPROCESSED_SUFFIX, "session.json"),
                  encoding="utf-8") as fh:
            saved = json.load(fh)
        self.assertEqual(saved["family"], "i1pro2")
        self.assertEqual([s["number"] for s in saved["steps"]], [1, 2, 4, 6])
        self.assertEqual(saved["steps"][1]["title"], "calibrate")

    def test_still_nothing_is_said_and_sends_the_report_only(self):
        _sess, full = make_165_session(self.root, build=lambda n: sf.description_only_step())
        before = digest(full)
        code, screen = self.run_main(["--reprocess", full])
        self.assertEqual(code, 0)
        self.assertIn("NOTHING COULD BE RESCUED", screen)
        self.assertIn("still nothing that could be attributed", " ".join(screen.split()))
        name, members = self.zip_names()
        self.assertTrue(name.endswith("-report-only.zip"))
        self.assertFalse(any(n.endswith(".pcap") for n in members))
        self.assertEqual(digest(full), before)

    def test_a_wrong_folder_says_so(self):
        code, screen = self.run_main(["--reprocess", os.path.join(self.root, "nope")])
        self.assertEqual(code, 1)
        self.assertIn("no such folder", screen)
        os.makedirs(os.path.join(self.root, "empty" + probe.FULL_SUFFIX))
        code, screen = self.run_main(["--reprocess",
                                      os.path.join(self.root, "empty" + probe.FULL_SUFFIX)])
        self.assertEqual(code, 1)
        self.assertIn("holds no full recording", screen)

    def test_the_menu_offers_it_only_when_a_folder_is_there(self):
        sug = probe.suggest([])
        plain = "\n".join(probe.what_to_do_question(sug, True, [], {}))
        self.assertNotIn("4. rescue", plain)
        _sess, full = make_165_session(self.root)
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.root]):
            folders = probe.find_full_folders()
        self.assertEqual(folders, [full])
        text = "\n".join(probe.what_to_do_question(sug, True, [], {}, rescue=folders))
        self.assertIn("4. rescue an earlier session", text)
        self.assertIn(os.path.basename(full), text)
        for line in text.splitlines():
            self.assertLessEqual(len(line), 80, line)
        args = types.SimpleNamespace(instrument=False, isis=False, profile=None, steps=None,
                                     io=False, annotate=False, skip_annotate=False)
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.root]), \
                mock.patch.object(probe, "ask", lambda *_a, **_k: "4"), \
                mock.patch.object(probe, "plugged_in_now", lambda ids: (True, [])), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(probe.choose_what_to_do(args, "x")[0], 4)


class FullRecordingsKept(unittest.TestCase):
    """(b) never deleted, never offered for deletion, when a step kept
    nothing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def session(self, kept_steps):
        folder = os.path.join(self.tmp.name, "instrument-session-x")
        full = folder + probe.FULL_SUFFIX
        os.makedirs(folder)
        os.makedirs(full)
        steps = []
        for number in (1, 2):
            fn = f"step{number}-k-take1-USBPcap1-full.pcap"
            with open(os.path.join(full, fn), "wb") as fh:
                fh.write(b"x")
            xr = [fn.replace("-full", "-instrument")] if number in kept_steps else []
            steps.append({"number": number, "title": "t", "take": 1, "files_full": [fn],
                          "files_xrite": xr, "kept": True})
        return {"steps": steps, "ended": "all steps done", "family": "i1pro2"}, folder, full

    def finish(self, session, folder):
        asked = []
        with mock.patch.object(probe, "ask", lambda q, *_a, **_k: asked.append(q) or "yes"), \
                mock.patch.object(probe, "summarize_session", lambda _p: "analysis"), \
                redirect_stdout(io.StringIO()) as out:
            lines, _analysis = probe.finish_session(session, folder)
        return lines, asked, out.getvalue()

    def test_a_step_that_kept_nothing_keeps_the_folder_without_asking(self):
        session, folder, full = self.session(kept_steps={1})
        lines, asked, screen = self.finish(session, folder)
        self.assertEqual(asked, [])
        self.assertEqual(len(os.listdir(full)), 2)
        text = " ".join("\n".join(lines).split())
        self.assertIn("PLEASE KEEP THE FOLDER WITH THE FULL RECORDINGS", text)
        self.assertIn("Step 2 kept nothing", text)
        self.assertIn("Do NOT send it", text)
        self.assertIn("--reprocess", text)
        self.assertNotIn("Delete the full recordings", screen)
        self.assertEqual(session["full_kept_for_reprocess"], os.path.basename(full))
        for line in lines:
            self.assertLessEqual(len("  " + line), 80, line)

    def test_a_take_replaced_by_a_good_one_does_not_count(self):
        session, folder, _full = self.session(kept_steps={1, 2})
        session["steps"].insert(1, {"number": 2, "title": "t", "take": 1,
                                    "files_full": ["old-full.pcap"],
                                    "files_xrite": [], "kept": False})
        self.assertEqual(probe.steps_that_kept_nothing(session), [])
        _lines, asked, _screen = self.finish(session, folder)
        self.assertEqual(len(asked), 1)                  # the old offer, as before

    def test_every_step_kept_something_offers_as_before(self):
        session, folder, full = self.session(kept_steps={1, 2})
        lines, asked, _screen = self.finish(session, folder)
        self.assertEqual(len(asked), 1)
        self.assertIn("Delete the full recordings now? Recommended.", asked[0])
        self.assertIn("The full recordings were deleted.", lines)

    def test_the_table_recording_keeps_them_when_nothing_was_kept(self):
        w = sf.UsbPcapWriter()
        sf.keyboard(w)
        sf.keyboard_work(w, sf.KEYBOARD)
        full = w.save(os.path.join(self.tmp.name, "a-full.pcap"))
        with mock.patch.object(probe, "ask", lambda *_a, **_k: self.fail("asked")), \
                redirect_stdout(io.StringIO()):
            lines = probe.finish_recordings({"USBPcap1": full}, None)
        self.assertTrue(os.path.exists(full))
        self.assertIn("they are the only copy", " ".join(lines))


class TheSession(tae.TheWholeSession):
    """(d) in a whole Windows session (the harness of test_all_empty, an
    i1Pro 3 session with a fake USBPcapCMD)."""

    def test_every_step_stale(self):                 # the parent's own test, not here
        pass

    def test_a_followed_first_step_is_kept_and_said_once(self):
        answers = self.START
        for _ in probe.steps_for("i1pro3"):
            answers = answers + ["", "e", "notes", "", "lights", ""]
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]):
            outcome, code, screen = self.run_all(tae.stale_at_disk, answers)
        self.assertEqual(code, 0)
        self.assertTrue(outcome["recorded"], screen[-3000:])
        self.assertEqual(screen.count("FOUND: YOUR INSTRUMENT'S TRAFFIC WAS UNDER ANOTHER USB"), 1)
        self.assertIn("(Followed the instrument again:", screen)
        flat = " ".join(screen.split())
        self.assertIn("Nothing for you to do: just carry on.", flat)
        self.assertNotIn("only the instrument's USB description", flat)
        for line in screen.splitlines():
            if "fake_usbpcapcmd" not in line and self.dir not in line:
                self.assertLessEqual(len(line), 80, line)

    def test_nothing_of_the_instrument_stops_after_the_first_step(self):
        with mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]):
            outcome, _code, screen = self.run_all(tae.absent, self.START + ["", "e", ""])
        flat = " ".join(screen.split())
        self.assertIn("Nothing of your instrument was in this recording", flat)
        self.assertIn("The i1Pro 3's USB id (0765:6009) was not seen", flat)
        self.assertNotIn("STEP 2 of", screen)
        self.assertTrue(outcome["all_empty"])
        self.assertIn("recorded nothing of the instrument at all", outcome["reason"])
        saved = [p for p in self.written() if p.endswith("session.json")]
        with open(saved[0], encoding="utf-8") as fh:
            session = json.load(fh)
        self.assertEqual(session["ended"],
                         "stopped after the first step: nothing of the instrument was recorded")


class Replug(unittest.TestCase):
    """(f) unplugging and plugging in again is safe."""

    def test_a_replug_during_a_step_keeps_both_addresses_and_no_disk(self):
        w = sf.replugged_step()
        att = probe.attribute_records(probe.LINKTYPE_USBPCAP, w.records, "i1pro2")
        kept = [r for r, k in zip(w.records, att["keep"]) if k]
        keys = {}
        for _t, d in kept:
            f = probe._record_fields(probe.LINKTYPE_USBPCAP, d)          # noqa: SLF001
            keys[f[0]] = keys.get(f[0], 0) + 1
        # address 3 before the replug: its description and 5 commands of 3
        # records and 7 data transfers of 2; address 7 after it: the same
        # twice over (2 readings, then 1) plus its description
        self.assertEqual(keys[(1, 3)], 6 + 5 * 3 + 7 * 2)
        self.assertEqual(keys[(1, 7)], 6 + (5 * 3 + 7 * 2) + (5 * 3 + 5 * 2))
        self.assertEqual(set(keys), {(1, 3), (1, 7)})
        blob = b"".join(d for _t, d in kept)
        self.assertNotIn(sf.DISK_MARKER[:19], blob)
        self.assertNotIn(sf.KEY_MARKER, blob)
        self.assertNotIn(b"USBC", blob)
        self.assertEqual(att["left_out"], {"owner": 6})
        self.assertIsNone(att["followed"])

    def test_the_check_and_the_analysis_read_it_as_one_instrument(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = sf.replugged_step().save(os.path.join(tmp, "r.pcap"))
            check = probe.check_capture(path, "i1pro2")
            text = probe.analyze_paths([path])
        self.assertEqual(check["code"], "ok")
        self.assertIn("0xD4 trigger measurement", text)

    def test_the_session_says_it_is_safe(self):
        text = " ".join(probe.REPLUG_SAFE_TEXT.split())
        self.assertIn("You may unplug the instrument and plug it in again between steps",
                      text)
        for line in probe.REPLUG_SAFE_TEXT.splitlines():
            self.assertLessEqual(len(line), 80, line)


if __name__ == "__main__":
    unittest.main()
