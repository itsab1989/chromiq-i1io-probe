"""1.5.4: starting USBPcapCMD, after a real Windows report from 1.5.3 that said
only "the recording program stopped at once".

The cause, from USBPcapCMD's own source (1.5.4.0, USBPcapCMD/cmd.c,
start_capture; thread.c): run as administrator it opens the output file with
CREATE_NEW, which fails when the file already exists, and then ends at once
with "Thread started with invalid write handle!". 1.5.3 created the file
before starting it. The fake USBPcapCMD in test_instrument.py behaves the
same way. Standard library only; nothing here touches a device."""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402
from test_instrument import FAKE_USBPCAPCMD  # noqa: E402

# An i1Pro 3 behind an external hub on USBPcap2, as in the report (invented
# addresses; USBPcapCMD lists devices behind a hub with a parent field).
INTERFACES = ("interface {value=\\\\.\\USBPcap1}{display=USBPcap1}\n"
              "interface {value=\\\\.\\USBPcap2}{display=USBPcap2}\n")
HUB1 = "value {arg=99}{value=1}{display=[1] USB Composite Device}{enabled=true}\n"
HUB2 = ("value {arg=99}{value=2}{display=[2] Generic USB Hub}{enabled=true}\n"
        "value {arg=99}{value=3}{display=[3] i1Pro3}{enabled=true}{parent=2}\n")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.exe = os.path.join(self.dir, "fake_usbpcapcmd.py")
        with open(self.exe, "w") as fh:
            fh.write(FAKE_USBPCAPCMD)
        self.log = os.path.join(self.dir, "fake.log")
        pcaps = os.path.join(self.dir, "pcaps")
        os.mkdir(pcaps)
        for p in (mock.patch.dict(os.environ, {"FAKE_LOG": self.log, "FAKE_PCAPS": pcaps}),
                  mock.patch.object(probe, "RECORDER_STARTUP_WAIT", 0.3)):
            p.start()
            self.addCleanup(p.stop)
        probe._SECTIONS.clear()
        self.addCleanup(probe._SECTIONS.clear)


class RecorderStart(Base):

    def recorder(self):
        return probe.UsbPcapRecorder(self.exe, ["\\\\.\\USBPcap2"], self.dir)

    def test_the_file_is_left_for_usbpcapcmd_to_create(self):
        rec = self.recorder()
        live = rec.start("step1-idle-take1")
        self.addCleanup(rec.stop)
        self.assertEqual(live, ["\\\\.\\USBPcap2"])
        self.assertEqual(rec.diag[0]["result"], "running")

    def test_what_1_5_3_did_fails_the_way_the_real_program_does(self):
        rec = self.recorder()
        rec.precreate = True                    # 1.5.3's behaviour
        self.assertEqual(rec.start("step1-idle-take1"), [])
        rec.stop()
        text = rec.diag_text()
        self.assertIn("first try", text)
        self.assertIn("retry (simpler options)", text)
        self.assertIn("stopped at once, exit code 0", text)
        self.assertIn("Thread started with invalid write handle!", text)
        self.assertIn("-d \\\\.\\USBPcap2 -o ", text)
        self.assertIn("--inject-descriptors", text)
        self.assertIn("output file step1-idle-take1-USBPcap2-full.pcap: 0 bytes", text)
        self.assertIn("could not create its recording file",
                      probe.recorder_failure_words(text))

    def test_a_leftover_file_is_removed_first(self):
        path = os.path.join(self.dir, "step1-idle-take1-USBPcap2-full.pcap")
        with open(path, "wb") as fh:
            fh.write(b"old")
        rec = self.recorder()
        self.assertEqual(len(rec.start("step1-idle-take1")), 1)
        rec.stop()

    def test_the_log_files_are_cleaned_up(self):
        rec = self.recorder()
        rec.start("s")
        rec.stop()
        self.assertEqual([f for f in os.listdir(self.dir) if f.endswith(".log")
                          and f != "fake.log"], [])


class TheWindowsSessionReport(Base):

    def run_step(self, answers, fail=True):
        def fake_run(cmd, timeout=40):
            joined = " ".join(cmd)
            if cmd[0] == "sc":
                return "SERVICE_NAME: USBPcap\n        STATE              : 4  RUNNING\n"
            if "--extcap-version" in joined:
                return "extcap {version=1.5.4.0}{help=http://desowin.org/usbpcap/}\n"
            if "--extcap-interfaces" in joined:
                return INTERFACES
            return HUB2 if "USBPcap2" in joined else HUB1
        it = iter(answers)
        patches = [
            mock.patch.object(probe, "run", fake_run),
            mock.patch.object(probe, "find_usbpcapcmd", lambda: self.exe),
            mock.patch.object(probe, "windows_program_versions",
                              lambda: {"i1Profiler": "3.8.6.16077"}),
            mock.patch.object(probe, "windows_build_info",
                              lambda: {"build": 26200, "display": "25H2", "product": ""}),
            mock.patch.object(probe, "windows_is_arm", lambda: False),
            mock.patch.object(probe, "windows_is_admin", lambda: True),
            mock.patch.object(probe, "windows_driver_devices", lambda: [
                {"vid": 0x0765, "pid": 0x6009, "name": "i1Pro3", "class": "USBDevice",
                 "service": "WinUSB", "provider": "libwdi", "status": "OK"}]),
            mock.patch.object(probe.platform, "system", lambda: "Windows"),
            mock.patch.object(probe, "_writable_dir", lambda: self.dir),
            mock.patch.object(probe, "ask", lambda *_a, **_k: next(it, "")),
            mock.patch.object(probe.UsbPcapRecorder, "precreate", fail),
        ]
        for p in patches:
            p.start()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                outcome = probe.instrument_session_step([(0x0765, 0x6009)], direct=True)
        finally:
            for p in patches:
                p.stop()
        return outcome, out.getvalue(), dict(probe._SECTIONS)["Instrument recording session"]

    # profile Enter, start yes, program 1, version Enter, step 1 Enter
    START = ["", "yes", "1", "", ""]

    def test_a_failed_start_is_explained_in_the_report_and_offers_the_way_by_hand(self):
        _outcome, screen, report = self.run_step(self.START + ["no"])
        self.assertIn("THE RECORDING DID NOT START", screen)
        self.assertIn("RECORDING WITH WIRESHARK BY HAND", screen)
        self.assertIn("did not work (twice)", screen)
        for want in ("THE RECORDER, IN DETAIL", "administrator: yes",
                     "USBPcapCMD: " + probe.scrub(self.exe), "version 1.5.4.0",
                     "\\\\.\\USBPcap2 (USBPcap2)  <-- recorded", "device 3: [3] i1Pro3",
                     "\\\\.\\USBPcap1 (USBPcap1)", "device 1: [1] USB Composite Device",
                     "the instrument's name was found",
                     "THE RECORDING PROGRAM DID NOT START",
                     "Thread started with invalid write handle!",
                     "retry (simpler options)", "exit code 0"):
            self.assertIn(want, report, want)
        self.assertNotIn("\\\\.\\USBPcap1 (USBPcap1)  <-- recorded", report)
        # the report shows paths with the user's folder hidden, on every platform
        self.assertNotIn(os.path.expanduser("~"), report)
        self.assertNotIn("were kept in the -FULL-do-not-send folder", report)

    def test_the_way_by_hand_runs_the_steps_without_a_recorder(self):
        answers = self.START + ["yes", "yes", "q", ""]
        _outcome, screen, report = self.run_step(answers)
        self.assertIn("-by-hand", screen)
        self.assertIn("whole-session.pcapng", screen)
        folders = [f for f in os.listdir(self.dir) if f.endswith("-by-hand")]
        self.assertEqual(len(folders), 1)
        self.assertIn("THE RECORDING PROGRAM DID NOT START", report)

    def test_with_the_fix_the_session_records(self):
        _outcome, screen, report = self.run_step(self.START + ["", "", "", "q"], fail=False)
        self.assertNotIn("THE RECORDING DID NOT START", screen)
        self.assertIn("RECORDING STEP 1 NOW", screen)
        self.assertIn("administrator: yes", report)

    def test_libwdi_winusb_is_not_called_x_rites_driver(self):
        _outcome, screen, _report = self.run_step(self.START + ["no"])
        self.assertIn('provider says "libwdi"', " ".join(screen.split()))
        self.assertNotIn("i1Pro3: X-Rite's driver", screen)


class EveryReportSaysAdministrator(unittest.TestCase):

    def test_environment_section_names_it_on_windows(self):
        probe._SECTIONS.clear()
        self.addCleanup(probe._SECTIONS.clear)
        with mock.patch.object(probe.platform, "system", lambda: "Windows"), \
                mock.patch.object(probe, "windows_is_admin", lambda: False), \
                mock.patch.object(probe, "quick_summary", lambda: "NO X-RITE DEVICES SEEN."), \
                mock.patch.object(probe, "collect_windows", lambda: None), \
                mock.patch.object(probe, "collect_i1profiler_charts", lambda: None), \
                mock.patch.object(probe, "finish_report", lambda *a, **k: 0), \
                mock.patch.object(probe, "ask", lambda *_a, **_k: "3"), \
                redirect_stdout(io.StringIO()):
            probe.main([])
        env = dict(probe._SECTIONS)["Environment"]
        self.assertIn('"administrator": "no"', env)


if __name__ == "__main__":
    unittest.main()


class WhatTheTesterSees(Base):
    """1.5.4, after a second real report: the tester measured in i1Profiler
    without ever starting a step, then pressed q; he sent only the report."""

    def test_the_step_box_says_the_order(self):
        box = probe.step_box("  When the recording runs: scan the strip.")
        self.assertIn("1. Press Enter HERE to start recording.", box)
        self.assertIn("2. Then do this in the measuring program: scan the strip.", box)
        self.assertIn("3. Come back to THIS window and press Enter to stop.", box)
        self.assertEqual(len({len(l) for l in box.splitlines()}), 1)

    def test_the_live_line(self):
        rec = mock.Mock(files={"a": os.path.join(self.dir, "nothing-yet")})
        line = probe.LiveLine(rec, 100.0)
        self.assertIn("no data yet", line.text(now=107.0))
        self.assertLess(len(line.text(now=107.0)), 80)
        with open(os.path.join(self.dir, "grows"), "wb") as fh:
            fh.write(b"x" * 1234)
        rec.files = {"a": os.path.join(self.dir, "grows")}
        self.assertIn("1,234 bytes on this USB bus", line.text(now=103.0))
        self.assertIn("your own recording runs", probe.LiveLine(None, 0.0).text(now=3.0))
        # no terminal: no thread, nothing written
        out = io.StringIO()
        ticker = probe.LiveLine(rec, 0.0, stream=out, interval=0.01)
        ticker.start()
        ticker.stop()
        self.assertEqual(out.getvalue(), "")

    def run_session(self, answers):
        it = iter(answers)
        recorder = probe.UsbPcapRecorder(self.exe, ["\\\\.\\USBPcap1"], "")
        folder = os.path.join(self.dir, "instrument-session-x")
        with mock.patch.object(probe, "ask", lambda *_a, **_k: next(it, "")), \
                redirect_stdout(io.StringIO()) as out:
            session = probe.run_instrument_session(recorder, folder, "i1pro3", "i1Profiler", "")
        return session, out.getvalue()

    def test_q_with_nothing_recorded_asks_once(self):
        session, screen = self.run_session(["q", "no", "q", "yes"])
        self.assertIn("Nothing was recorded yet.", screen)
        self.assertEqual(screen.count("Nothing was recorded yet."), 2)
        self.assertEqual(session["ended"], "stopped by the operator")

    def test_q_after_a_recorded_step_does_not_ask(self):
        session, screen = self.run_session(["", "", "ok", "", "", "q"])
        self.assertNotIn("Nothing was recorded yet.", screen)
        self.assertEqual(session["ended"], "stopped by the operator")


class OneFileToSend(Base):

    def test_the_zip_holds_report_and_instrument_files_only(self):
        import zipfile
        folder = os.path.join(self.dir, "instrument-session-1")
        os.makedirs(folder)
        os.makedirs(folder + "-FULL-do-not-send")
        for name in ("session.json", "analysis.txt", "step1-idle-take1-USBPcap1-instrument.pcap"):
            with open(os.path.join(folder, name), "w") as fh:
                fh.write("x")
        with open(os.path.join(folder + "-FULL-do-not-send",
                               "step1-idle-take1-USBPcap1-full.pcap"), "w") as fh:
            fh.write("keyboard")
        report = os.path.join(self.dir, "chromiq-io-probe-1.txt")
        with open(report, "w") as fh:
            fh.write("report")
        dst = probe.make_send_zip(report, {"folder": folder})
        self.assertTrue(os.path.basename(dst).startswith("SEND-THIS-"))
        with zipfile.ZipFile(dst) as zf:
            names = sorted(zf.namelist())
        self.assertEqual(names, ["chromiq-io-probe-1.txt",
                                 "instrument-session-1/analysis.txt",
                                 "instrument-session-1/session.json",
                                 "instrument-session-1/step1-idle-take1-USBPcap1-instrument.pcap"])
        self.assertFalse(any("full" in n or os.path.expanduser("~") in n for n in names))

    def test_report_top_line_when_nothing_was_recorded(self):
        probe._END.clear()
        self.addCleanup(probe._END.clear)
        probe._END["no_recording"] = "You stopped the session before the first step was recorded."
        text = probe.report_text(instrument=True)
        self.assertIn("THIS REPORT CONTAINS NO RECORDING. You stopped the session", text)
        self.assertLess(text.index("NO RECORDING"), 400)
        probe._END["send"] = {"folder": self.dir}
        self.assertNotIn("CONTAINS NO RECORDING", probe.report_text(instrument=True))

    def test_finish_report_makes_the_zip_and_says_so(self):
        probe._END.clear()
        self.addCleanup(probe._END.clear)
        folder = os.path.join(self.dir, "instrument-session-2")
        os.makedirs(folder)
        with open(os.path.join(folder, "session.json"), "w") as fh:
            fh.write("{}")
        probe._END["send"] = {"folder": folder}
        ns = mock.Mock(output=os.path.join(self.dir, "chromiq-io-probe-2.txt"))
        with redirect_stdout(io.StringIO()) as out:
            probe.finish_report(ns, "Windows", instrument=True, outcome={"recorded": True})
        self.assertIn("SEND THIS ONE FILE", out.getvalue())
        self.assertTrue(any(f.startswith("SEND-THIS-") for f in os.listdir(self.dir)))


class AllowListAndPaths(Base):

    def test_a_full_wireshark_file_never_goes_into_the_zip(self):
        import zipfile
        folder = os.path.join(self.dir, "instrument-session-3-by-hand")
        os.makedirs(folder)
        for name in ("whole-session.pcapng", "Wireshark capture.pcapng", "session.json",
                     "whole-session-instrument.pcap", "notes.txt"):
            with open(os.path.join(folder, name), "w") as fh:
                fh.write("x")
        report = os.path.join(self.dir, "chromiq-io-probe-3.txt")
        with open(report, "w") as fh:
            fh.write("r")
        with zipfile.ZipFile(probe.make_send_zip(report, {"folder": folder})) as zf:
            names = sorted(zf.namelist())
        self.assertEqual(names, ["chromiq-io-probe-3.txt",
                                 "instrument-session-3-by-hand/session.json",
                                 "instrument-session-3-by-hand/whole-session-instrument.pcap"])

    def test_scrub_hides_any_user_folder(self):
        text = probe.scrub("C:\\Users\\someone\\Desktop\\x and /Users/other/y and "
                           "C:\\Users\\Public\\z")
        self.assertNotIn("someone", text)
        self.assertNotIn("other", text)
        self.assertIn("Public", text)
        self.assertEqual(probe.scrub("C:\\Users\\John Smith\\Desktop"), "C:\\Users\\USER\\Desktop")

    def test_interrupted_report_does_not_say_no_recording(self):
        probe._END.clear()
        self.addCleanup(probe._END.clear)
        probe._END["session_folder"] = self.dir
        self.assertIn("saved before the end of the run", probe.report_text(instrument=True))
        # a run that ended normally says plainly that nothing was recorded, and why
        probe._END["finished"] = True
        probe._END["no_recording"] = "You stopped the session before the first step was recorded."
        text = probe.report_text(instrument=True)
        self.assertIn("THIS REPORT CONTAINS NO RECORDING. You stopped the session", text)
        self.assertNotIn("saved before the end", text)
