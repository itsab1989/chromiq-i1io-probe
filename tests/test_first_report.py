"""Tests for 1.5.1: what the first handheld report from a user showed.

    python3 -m unittest discover -s tests -v

The situation, rebuilt from that report's STRUCTURE with invented IDs
(tests/fixtures/README.txt): Windows 11 25H2, i1Profiler 3.8.5, an i1Pro 3
plugged in and bound to the ArgyllCMS driver, older entries Windows
remembers, administrator yes, USBPcap not installed. 1.5.0 then stopped
after the checks with the install steps printed above "ALL DONE", showed
the i1Pro 2 driver warning to an i1Pro 3 owner, did not notice the driver,
and listed remembered devices as if they were connected.
"""

import io
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
sys.path.insert(0, ROOT)

import chromiq_io_probe as probe  # noqa: E402


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


I1PRO3 = (0x0765, 0x6009)
I1PRO2 = (0x0971, 0x2000)


class The25H2NoteOnlyWhereItApplies(unittest.TestCase):

    def test_i1pro2_and_first_i1pro_and_unknown_get_the_warning(self):
        for profile in ("i1pro2", "i1pro", None):
            check = probe.windows_release_check(26200, "25H2", False, profile)
            self.assertEqual(check["level"], "warning", profile)
            self.assertIn("i1Pro 2 and the iO2", check["text"])
            self.assertIn("25H2 or newer", check["text"])
            self.assertIn("X-Rite will not update it", check["text"])

    def test_i1pro3_is_told_it_is_not_concerned(self):
        check = probe.windows_release_check(26200, "25H2", False, "i1pro3")
        self.assertEqual(check["level"], "ok")
        self.assertIn("concerns the i1Pro 2 and the iO2 only", check["text"])
        self.assertIn("i1Pro 3 works with the latest Windows 11 releases", check["text"])
        self.assertNotIn("blocks it", check["text"])

    def test_other_instruments_get_the_plain_version(self):
        for profile in ("munki", "generic"):
            self.assertEqual(probe.windows_release_check(26200, "25H2", False, profile),
                             {"level": "ok", "text": "Windows 11 version 25H2 (build 26200)"})

    def test_older_windows_unchanged(self):
        self.assertEqual(probe.windows_release_check(26100, "24H2", False, "i1pro2"),
                         {"level": "ok", "text": "Windows 11 version 24H2 (build 26100)"})

    def test_source_is_x_rites_note(self):
        self.assertIn("xrite.com", probe.XRITE_25H2_NOTE_URL)


class UsbPcapHelp(unittest.TestCase):

    def test_says_what_it_is_and_why(self):
        text = probe.USBPCAP_INSTALL_TEXT
        self.assertIn("WHAT USBPcap IS", text)
        self.assertIn("free program", text)
        self.assertIn("Windows has no such recorder", text)

    def test_numbered_steps_restart_and_run_again(self):
        text = probe.USBPCAP_INSTALL_TEXT
        for n in range(1, 5):
            self.assertIn(f"    {n}. ", text)
        self.assertIn('"USB Capture"', text)
        self.assertIn('"Install USBPcap"', text)
        self.assertIn("not ticked unless you tick it", text)
        self.assertIn("restart Windows", text)
        self.assertIn("Run this tool again", text)
        self.assertIn("https://www.wireshark.org/download.html", text)
        self.assertIn("https://desowin.org/usbpcap/", text)

    def test_no_security_setting_to_switch_off(self):
        text = probe.USBPCAP_INSTALL_TEXT
        self.assertIn("You do not need to switch off any security setting", text)
        self.assertIn("Secure Boot", text)
        self.assertIn("driver signature enforcement", text)
        self.assertIn("please do not switch any protection off", text)

    def test_lines_fit_a_console(self):
        for block in (probe.USBPCAP_INSTALL_TEXT, probe.DRIVER_HELP_TEXT):
            for line in block.splitlines():
                self.assertLessEqual(len(line), 76, line)
                self.assertNotIn(chr(0x2014), line)


class DriverCheck(unittest.TestCase):

    def test_argyll_driver_is_found_and_explained(self):
        devices = probe.parse_driver_lines(fixture("windows-drivers-argyll.txt"))
        self.assertEqual(len(devices), 1)
        self.assertEqual((devices[0]["vid"], devices[0]["pid"]), I1PRO3)
        self.assertEqual(probe.driver_state(devices[0]), "argyll")
        checks = probe.instrument_driver_checks(devices)
        self.assertEqual(checks[0]["level"], "problem")
        self.assertTrue(checks[0]["help"])
        self.assertIn("ArgyllCMS driver (libusb0)", checks[0]["text"])
        self.assertIn("vendor program cannot see", checks[0]["text"])

    def test_every_kind_of_binding(self):
        devices = probe.parse_driver_lines(fixture("windows-drivers-variants.txt"))
        # the composite child (&MI_00) and the junk line are not devices
        self.assertEqual(len(devices), 7)
        states = [(d["name"], probe.driver_state(d)) for d in devices]
        self.assertEqual(states, [
            ("i1Pro3", "winusb"),
            ("i1 Pro", "vendor"),
            ("eye-one", "winusb"),
            ("X-Rite i1 Pro 3 / i1 Pro 3+", "argyll"),
            ("ColorMunki", "argyll"),
            ("i1Studio", "none"),
            ("i1Display", "unknown"),
        ])
        checks = {c["name"]: c for c in probe.instrument_driver_checks(devices)}
        # a colorimeter is not a session instrument: not judged at all
        self.assertNotIn("i1Display", checks)
        self.assertEqual(checks["i1Pro3"]["level"], "ok")
        self.assertIn("WinUSB", checks["i1Pro3"]["text"])
        self.assertEqual(checks["i1 Pro"]["level"], "ok")
        self.assertIn("X-Rite's driver", checks["i1 Pro"]["text"])
        # WinUSB on the old X-Rite ID is not X-Rite's driver
        self.assertEqual(checks["eye-one"]["level"], "problem")
        self.assertTrue(checks["eye-one"]["help"])
        # ChromIQ's own libwdi install of libusb0 counts as ArgyllCMS's driver
        self.assertTrue(checks["X-Rite i1 Pro 3 / i1 Pro 3+"]["help"])
        self.assertTrue(checks["ColorMunki"]["help"])
        self.assertEqual(checks["i1Studio"]["level"], "warning")
        self.assertFalse(checks["i1Studio"]["help"])

    def test_help_text_has_the_way_there_and_back(self):
        text = probe.DRIVER_HELP_TEXT
        self.assertIn("cannot see it", text)
        self.assertIn("Device Manager", text)
        self.assertIn('"Update driver"', text)
        self.assertIn('"Let me pick from a', text)
        self.assertIn('"X-Rite i1Pro3"', text)
        self.assertIn("THE WAY BACK", text)
        self.assertIn('"Instrument drivers..."', text)
        self.assertIn('"Install Driver"', text)
        self.assertIn("separate entry for every USB socket", text)


def _his_checks(drivers_fixture="windows-drivers-argyll.txt"):
    """windows_capture_checks() on a PC like the one in the first report."""
    def fake_run(cmd, timeout=40):
        if cmd[0] == "sc":
            return fixture("windows-sc-query-usbpcap-missing.txt")
        raise AssertionError(f"unexpected command {cmd}")
    patches = [
        mock.patch.object(probe, "run", fake_run),
        mock.patch.object(probe, "find_usbpcapcmd", lambda: None),
        mock.patch.object(probe, "windows_program_versions",
                          lambda: {"i1Profiler": "3.8.5.10000"}),
        mock.patch.object(probe, "windows_build_info",
                          lambda: {"build": 26200, "display": "25H2", "product": ""}),
        mock.patch.object(probe, "windows_is_arm", lambda: False),
        mock.patch.object(probe, "windows_is_admin", lambda: True),
        mock.patch.object(probe, "windows_driver_devices",
                          lambda: probe.parse_driver_lines(fixture(drivers_fixture))),
    ]
    return patches


class TheFirstReportReplayed(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        probe._SECTIONS.clear()
        self.addCleanup(probe._SECTIONS.clear)

    def _session(self, answers=("",)):
        patches = _his_checks() + [
            mock.patch.object(probe.platform, "system", lambda: "Windows"),
            mock.patch.object(probe, "ask", mock.Mock(side_effect=list(answers))),
        ]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])
        out = io.StringIO()
        with redirect_stdout(out):
            outcome = probe.instrument_session_step([I1PRO3, I1PRO2], direct=True)
        return outcome, out.getvalue()

    def test_checks_and_help_on_screen(self):
        outcome, screen = self._session()
        self.assertEqual(outcome["profile"], "i1pro3")
        self.assertFalse(outcome["recorded"])
        self.assertIn("concerns the i1Pro 2 and the iO2 only", screen)
        self.assertNotIn("Windows blocks it", screen)
        self.assertIn("[PROBLEM] not installed", screen)
        self.assertIn("Driver:", screen)
        self.assertIn("on the ArgyllCMS driver", screen)
        self.assertIn("WHAT USBPcap IS", screen)
        self.assertIn("YOUR INSTRUMENT IS ON THE WRONG DRIVER", screen)
        self.assertEqual(outcome["help"], [probe.USBPCAP_INSTALL_TEXT, probe.DRIVER_HELP_TEXT])
        self.assertIn("USBPcap", outcome["reason"])

    def test_the_report_carries_the_help_too(self):
        self._session()
        body = dict(probe._SECTIONS)["Instrument recording session"]
        self.assertIn("[USBPcap is not installed]", body)
        self.assertIn("WHAT USBPcap IS", body)
        self.assertIn("THE WAY BACK", body)

    def test_the_end_of_the_run_says_nothing_was_recorded_and_what_to_do(self):
        outcome, _screen = self._session()
        args = types.SimpleNamespace(output=os.path.join(self.tmp.name, "report.txt"))
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(probe.finish_report(args, "Windows", instrument=True,
                                                 outcome=outcome), 0)
        end = out.getvalue()
        self.assertNotIn("ALL DONE", end)
        self.assertIn("FINISHED, BUT NOTHING WAS RECORDED YET", end)
        self.assertIn("There is no session folder to send", end)
        self.assertNotIn("together with the session folder", end)
        # no i1Pro 2 / iO2 warning for an i1Pro 3
        self.assertNotIn("IMPORTANT FOR OWNERS OF AN i1Pro 2", end)
        # what to do is the LAST thing on the screen
        tail = end.rstrip().splitlines()[-1]
        self.assertIn("run this tool again", tail)
        self.assertLess(end.rindex("WHAT USBPcap IS"), end.rindex("THE WAY BACK"))
        self.assertGreater(end.rindex("WHAT USBPcap IS"), end.index("report was saved"))

    def test_i1pro2_owner_still_gets_the_i1profiler_warning(self):
        self.assertTrue(probe.show_i1profiler_warning(True, {"profile": "i1pro2"}))
        self.assertTrue(probe.show_i1profiler_warning(True, {"profile": "i1pro"}))
        self.assertFalse(probe.show_i1profiler_warning(True, {"profile": "i1pro3"}))
        self.assertFalse(probe.show_i1profiler_warning(True, {"profile": "munki"}))
        self.assertTrue(probe.show_i1profiler_warning(False, None))

    def test_a_recorded_session_ends_as_before(self):
        lines = probe.closing_words({"recorded": True})
        self.assertIn("  Send it together with the session folder, as described above.", lines)
        self.assertIn(probe.HANDHELD_SEND_WAYS, lines)


class RememberedDevices(unittest.TestCase):

    def tearDown(self):
        probe._DETECTION.clear()

    def test_summary_marks_what_is_plugged_in(self):
        lines, present = probe.windows_summary_lines(
            fixture("windows-pnp-summary-remembered.txt"))
        self.assertEqual(present, [I1PRO3])
        self.assertEqual(len(lines), 5)
        self.assertEqual(sum("(plugged in now)" in l for l in lines), 1)
        self.assertEqual(sum("(not plugged in now; Windows remembers it" in l for l in lines), 4)
        self.assertTrue(lines[-1].startswith("i1 Pro3 (Argyll) :: "))

    def test_old_output_without_present_column_still_reads(self):
        lines, present = probe.windows_summary_lines(
            "eye-one :: USB\\VID_0971&PID_2000\\7&1&0&1\n[PowerShell not found]")
        self.assertEqual(lines, ["eye-one :: USB\\VID_0971&PID_2000\\7&1&0&1"])
        self.assertEqual(present, [])

    def test_session_is_chosen_from_the_plugged_in_instrument(self):
        lines, present = probe.windows_summary_lines(
            fixture("windows-pnp-summary-remembered.txt"))
        probe._DETECTION.clear()
        probe._DETECTION["present_ids"] = present
        summary = "X-Rite devices detected:\n  " + "\n  ".join(lines)
        ids = probe.detected_ids(summary)
        # the remembered i1Pro 2 comes first in Windows' list, the plugged-in
        # i1Pro 3 first in ours
        self.assertEqual(ids, [I1PRO3, I1PRO2])
        self.assertEqual(probe.choose_profile(ids), "i1pro3")

    def test_without_presence_information_nothing_changes(self):
        probe._DETECTION.clear()
        ids = probe.detected_ids("X-Rite devices detected:\n  eye-one :: USB\\VID_0971&PID_2000\\x\n"
                                 "  i1Pro3 :: USB\\VID_0765&PID_6009\\y")
        self.assertEqual(ids, [I1PRO2, I1PRO3])


class ChartNames(unittest.TestCase):

    def test_io_charts(self):
        for name in ("TC9.18 RGB 1P i1iO.txf", "ECI 2002 CMYK visual 1P i1iO Scan PM5.txf",
                     "TC1617x (i1iO2).txf", "Chart CMYKOGV v1a (2019) i1iO3.txf",
                     "default-i1iO.txf", "Strip iO.txf", "chart-iO2.txf"):
            self.assertTrue(probe.is_io_chart_name(name), name)

    def test_words_that_merely_contain_io(self):
        for name in ("Chart 450 Patches (printed with Studio).txf", "Project-option2.txf",
                     "Chart 420 Patches-iteration1.txf", "Radio.txf", "default-i1Pro.txf",
                     "ColorCheck24-i1Pro3.txf"):
            self.assertFalse(probe.is_io_chart_name(name), name)


if __name__ == "__main__":
    unittest.main()
