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
                     "USBPcapCMD: " + self.exe, "version 1.5.4.0",
                     "\\\\.\\USBPcap2 (USBPcap2)  <-- recorded", "device 3: [3] i1Pro3",
                     "\\\\.\\USBPcap1 (USBPcap1)", "device 1: [1] USB Composite Device",
                     "the instrument's name was found",
                     "THE RECORDING PROGRAM DID NOT START",
                     "Thread started with invalid write handle!",
                     "retry (simpler options)", "exit code 0"):
            self.assertIn(want, report, want)
        self.assertNotIn("\\\\.\\USBPcap1 (USBPcap1)  <-- recorded", report)
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
        self.assertIn("RECORDING step 1", screen)
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
