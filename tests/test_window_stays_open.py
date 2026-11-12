"""Tests for 1.5.2: after the second report from a user, the window closed
before the instructions could be read.

    python3 -m unittest discover -s tests -v

A Windows user double-clicked the exe, without administrator rights and
without USBPcap, with an i1Pro 2 on X-Rite's driver. The tool printed its
help, and the console window closed the moment it finished. Every fixture
here is invented (tests/fixtures/README.txt); nothing comes from a report.
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


I1PRO2 = (0x0971, 0x2000)
# An i1Pro 2 on X-Rite's driver, plugged in, Windows status OK (invented id).
XRITE_I1PRO2_WORKING = ("DRV :: i1 Pro :: USB\\VID_0971&PID_2000\\5&1A2B3C&0&4 :: "
                        "XRiteDevices :: EyeOne :: X-Rite :: OK\n")


class Tty(io.StringIO):
    def isatty(self):
        return True


class Pipe(io.StringIO):
    def isatty(self):
        return False


def _clean_state(test):
    for store in (probe._CAUSES, probe._SECTIONS, probe._LAST_REPORT):
        store.clear()
    test.addCleanup(probe._CAUSES.clear)
    test.addCleanup(probe._SECTIONS.clear)
    test.addCleanup(probe._LAST_REPORT.clear)


class WhenToWait(unittest.TestCase):

    def decide(self, argv=(), env=None, stdin=None, stdout=None, system="Windows",
               frozen=True, owned=True):
        return probe.should_pause(list(argv), env={} if env is None else env,
                                  stdin=stdin or Tty(), stdout=stdout or Tty(),
                                  system=system, frozen=frozen, owns=lambda: owned)

    def test_double_click_on_windows_waits(self):
        self.assertTrue(self.decide())

    def test_started_from_a_command_window_does_not(self):
        self.assertFalse(self.decide(owned=False))

    def test_no_pause_always_wins(self):
        self.assertFalse(self.decide(["--no-pause"]))
        self.assertFalse(self.decide(["--no-pause", "--pause"]))
        self.assertFalse(self.decide(env={"CHROMIQ_PROBE_NO_PAUSE": "1"}))

    def test_pause_forces_it(self):
        self.assertTrue(self.decide(["--pause"], owned=False, system="Darwin"))
        self.assertTrue(self.decide(["--pause"], stdin=Pipe()))

    def test_never_under_ci(self):
        self.assertFalse(self.decide(env={"CI": "true"}))
        self.assertFalse(self.decide(env={"GITHUB_ACTIONS": "true"}))

    def test_never_when_piped_or_redirected(self):
        self.assertFalse(self.decide(stdin=Pipe()))
        self.assertFalse(self.decide(stdout=Pipe()))

    def test_not_on_macos_or_linux_by_itself(self):
        self.assertFalse(self.decide(system="Darwin"))
        self.assertFalse(self.decide(system="Linux"))

    def test_unknown_ownership_frozen_exe_waits_script_does_not(self):
        self.assertTrue(self.decide(owned=None, frozen=True))
        self.assertFalse(self.decide(owned=None, frozen=False))

    def test_this_test_run_itself_never_waits(self):
        # the real streams of a test run: CI has no terminal; locally this is
        # not Windows. Either way no wait.
        if os.name != "nt":
            self.assertFalse(probe.should_pause([]))


class WhoOwnsTheConsole(unittest.TestCase):
    """GetConsoleProcessList with fakes. A one-file exe is two processes."""

    EXE = "C:\\Users\\someone\\Downloads\\chromiq-io-probe-windows.exe"

    def owns(self, ids, parent, images):
        return probe.owns_console(process_ids=ids, self_pid=200, parent_pid=parent,
                                  image_of=lambda pid: images.get(pid),
                                  executable=self.EXE)

    def test_double_clicked_one_file_exe(self):
        # explorer started the bootloader (100), which started us (200)
        self.assertTrue(self.owns([200, 100], 100, {100: self.EXE}))

    def test_same_exe_name_compared_without_case(self):
        self.assertTrue(self.owns([100, 200], 100, {100: self.EXE.upper()}))

    def test_alone_on_the_console(self):
        self.assertTrue(self.owns([200], 1, {}))

    def test_exe_started_from_cmd(self):
        self.assertFalse(self.owns([300, 100, 200], 100,
                                   {100: self.EXE, 300: "C:\\Windows\\System32\\cmd.exe"}))

    def test_script_started_from_cmd(self):
        self.assertFalse(self.owns([300, 200], 300, {300: "C:\\Windows\\System32\\cmd.exe"}))

    def test_script_started_by_the_launcher_bat(self):
        # Start-Windows.bat: cmd.exe holds the console (and passes --no-pause)
        self.assertFalse(self.owns([300, 200], 300, {300: "C:\\Windows\\System32\\cmd.exe"}))

    def test_double_clicked_py_file_under_the_py_launcher(self):
        self.assertTrue(self.owns([400, 200], 400, {400: "C:\\Windows\\py.exe"}))

    def test_parent_image_unreadable_counts_as_another_process(self):
        self.assertFalse(self.owns([100, 200], 100, {}))

    def test_list_unavailable_is_unknown(self):
        self.assertIsNone(probe.owns_console(process_ids=[], self_pid=1, parent_pid=2,
                                             image_of=lambda _p: None, executable="x"))

    def test_off_windows_the_real_call_is_unknown(self):
        if os.name != "nt":
            self.assertIsNone(probe._console_process_ids())
            self.assertIsNone(probe.owns_console())


class EveryWayOut(unittest.TestCase):
    """console_main with a stand-in for main(): the wait comes last, always."""

    def setUp(self):
        _clean_state(self)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.object(probe, "candidate_dirs", lambda: [self.tmp.name])
        p.start()
        self.addCleanup(p.stop)

    def run_with(self, body, pause=True, answers=()):
        events = []

        def fake_input(prompt=""):
            events.append(("input", prompt))
            return answers[len([e for e in events if e[0] == "input"]) - 1] \
                if len(answers) >= len([e for e in events if e[0] == "input"]) else ""

        out = io.StringIO()
        with mock.patch.object(probe, "main", body), \
                mock.patch.object(probe, "should_pause", lambda _argv: pause), \
                mock.patch("builtins.input", fake_input), redirect_stdout(out):
            code = probe.console_main([])
        return code, out.getvalue(), events

    def assertWaitsLast(self, screen, events):
        self.assertTrue(events, "no wait")
        self.assertEqual(events[-1], ("input", "  Press Enter to close this window."))

    def test_normal_end_waits(self):
        code, screen, events = self.run_with(lambda _argv: 0)
        self.assertEqual(code, 0)
        self.assertWaitsLast(screen, events)

    def test_nothing_recorded_waits_after_the_box(self):
        def body(_argv):
            probe._note_cause("usbpcap_missing")
            probe._LAST_REPORT["path"] = os.path.join(self.tmp.name, "chromiq-io-probe-x.txt")
            return 0
        _code, screen, events = self.run_with(body)
        self.assertIn("WHAT TO DO NOW", screen)
        self.assertWaitsLast(screen, events)
        self.assertEqual(screen.rstrip().splitlines()[-1].strip(), "=" * 66)

    def test_user_typed_q_with_no_instrument(self):
        summary = "NO X-RITE DEVICES SEEN.\nPlease check..."
        out_ask = mock.Mock(return_value="q")
        with mock.patch.object(probe, "quick_summary", lambda: summary), \
                mock.patch.object(probe, "ask", out_ask):
            events = []
            out = io.StringIO()
            with mock.patch.object(probe, "should_pause", lambda _argv: True), \
                    mock.patch("builtins.input", lambda p="": events.append(p) or ""), \
                    redirect_stdout(out):
                code = probe.console_main([])
        self.assertEqual(code, 0)
        screen = out.getvalue()
        self.assertIn("WHAT TO DO NOW", screen)
        self.assertIn("Plug the instrument in", screen)
        self.assertIn("No report was saved this time.", screen)
        self.assertEqual(events, ["  Press Enter to close this window."])

    def test_unhandled_error_apologises_saves_and_waits(self):
        def body(_argv):
            probe.section("Environment", "something collected")
            raise ValueError("invented failure")
        code, screen, events = self.run_with(body)
        self.assertEqual(code, 1)
        self.assertIn("SORRY: THE TOOL STOPPED BECAUSE OF A MISTAKE IN IT", screen)
        self.assertIn("This is our mistake, not something you did.", screen)
        self.assertIn("ValueError: invented failure", screen)
        saved = [f for f in os.listdir(self.tmp.name) if f.startswith("chromiq-io-probe-")]
        self.assertEqual(len(saved), 1)
        self.assertIn(os.path.join(self.tmp.name, saved[0]), screen)
        with open(os.path.join(self.tmp.name, saved[0]), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("something collected", text)
        self.assertIn("invented failure", text)
        self.assertWaitsLast(screen, events)

    def test_unhandled_error_when_nothing_can_be_saved(self):
        def body(_argv):
            raise RuntimeError("invented")
        with mock.patch.object(probe, "write_report", lambda *_a: None):
            _code, screen, events = self.run_with(body)
        self.assertIn("It could not save a report", screen)
        self.assertWaitsLast(screen, events)

    def test_ctrl_c_waits(self):
        def body(_argv):
            raise KeyboardInterrupt
        code, screen, events = self.run_with(body)
        self.assertEqual(code, 130)
        self.assertIn("Stopped (Ctrl-C)", screen)
        self.assertWaitsLast(screen, events)

    def test_ctrl_c_during_the_wait_just_closes(self):
        def angry(_prompt=""):
            raise KeyboardInterrupt
        with mock.patch.object(probe, "main", lambda _a: 0), \
                mock.patch.object(probe, "should_pause", lambda _a: True), \
                mock.patch("builtins.input", angry), redirect_stdout(io.StringIO()):
            self.assertEqual(probe.console_main([]), 0)

    def test_closed_input_does_not_hang(self):
        def eof(_prompt=""):
            raise EOFError
        with mock.patch.object(probe, "main", lambda _a: 0), \
                mock.patch.object(probe, "should_pause", lambda _a: True), \
                mock.patch("builtins.input", eof), redirect_stdout(io.StringIO()):
            self.assertEqual(probe.console_main([]), 0)

    def test_help_and_bad_options_keep_their_exit_code(self):
        def help_(_argv):
            raise SystemExit(0)

        def bad(_argv):
            raise SystemExit(2)
        self.assertEqual(self.run_with(help_, pause=False)[0], 0)
        self.assertEqual(self.run_with(bad, pause=False)[0], 2)

    def test_no_wait_means_no_input_at_all(self):
        def body(_argv):
            probe._note_cause("not_admin")
            return 0
        _code, screen, events = self.run_with(body, pause=False)
        self.assertEqual(events, [])
        self.assertIn("WHAT TO DO NOW", screen)

    def test_real_main_with_no_pause_under_a_pipe(self):
        # --analyze with no recording: the real main() ends at once
        out = io.StringIO()
        with mock.patch.object(probe, "find_session_folders", lambda: []), \
                mock.patch.object(probe, "find_captures", lambda: []), \
                mock.patch("builtins.input", mock.Mock(side_effect=AssertionError("waited"))), \
                redirect_stdout(out):
            self.assertEqual(probe.console_main(["--analyze", "--no-pause"]), 1)


class WhatToDoNow(unittest.TestCase):

    REPORT = os.path.join("C:\\Users\\someone\\Downloads", "chromiq-io-probe-20260101-120000.txt")

    def box(self, causes, report=REPORT):
        return probe.what_to_do_lines(causes, report)

    def test_nothing_to_do_no_box(self):
        self.assertEqual(self.box([]), [])

    def test_his_case_usbpcap_missing_not_administrator(self):
        with mock.patch.object(probe, "tool_name", lambda: "chromiq-io-probe-windows.exe"):
            text = "\n".join(self.box(["usbpcap_missing", "not_admin"]))
        flat = " ".join(text.split())
        self.assertIn("1. Install USBPcap: open https://www.wireshark.org/download.html", flat)
        self.assertIn('tick "Install USBPcap"', flat)
        self.assertIn("2. Restart Windows.", flat)
        self.assertIn('3. Then right-click chromiq-io-probe-windows.exe and choose '
                      '"Run as administrator"', flat)
        self.assertNotIn("4.", flat)
        self.assertIn("chromiq-io-probe-20260101-120000.txt", text)
        self.assertIn("It stays there after this window is closed", flat)

    def test_not_administrator_only(self):
        flat = " ".join("\n".join(self.box(["not_admin"])).split())
        self.assertIn('1. Then right-click', flat)
        self.assertIn("Run as administrator", flat)
        self.assertNotIn("USBPcap", flat)

    def test_wrong_driver(self):
        flat = " ".join("\n".join(self.box(["wrong_driver"])).split())
        self.assertIn("1. Give the instrument X-Rite's driver back in Device Manager", flat)
        self.assertIn("2. Then run this tool again.", flat)

    def test_no_instrument(self):
        flat = " ".join("\n".join(self.box(["no_instrument"], None)).split())
        self.assertIn("1. Plug the instrument in", flat)
        self.assertIn("2. Then run this tool again.", flat)
        self.assertIn("No report was saved this time.", flat)

    def test_short_and_fits_a_console(self):
        for causes in (["usbpcap_missing", "not_admin"], ["wrong_driver", "not_admin"],
                       ["no_instrument"], ["usbpcap_missing", "wrong_driver", "not_admin"]):
            lines = "\n".join(self.box(causes)).splitlines()
            numbered = [l for l in lines if l.lstrip()[:2] in ("1.", "2.", "3.", "4.", "5.")]
            self.assertLessEqual(len(numbered), 4, causes)
            for line in lines:
                self.assertLessEqual(len(line), 76, line)
                self.assertNotIn(chr(0x2014), line)

    def test_admin_help_text(self):
        with mock.patch.object(probe, "tool_name", lambda: "chromiq-io-probe-windows.exe"):
            text = probe.admin_help_text()
        self.assertIn("WHY ADMINISTRATOR RIGHTS ARE NEEDED", text)
        self.assertIn('Right-click chromiq-io-probe-windows.exe and choose "Run as administrator"',
                      " ".join(text.split()))
        for line in text.splitlines():
            self.assertLessEqual(len(line), 76, line)
            self.assertNotIn(chr(0x2014), line)

    def test_tool_name(self):
        with mock.patch.object(probe.sys, "frozen", True, create=True), \
                mock.patch.object(probe.sys, "executable", "C:\\x\\chromiq-io-probe-windows.exe"):
            self.assertEqual(probe.tool_name().split("\\")[-1], "chromiq-io-probe-windows.exe")
        with mock.patch.object(probe.platform, "system", lambda: "Windows"):
            self.assertEqual(probe.tool_name(), "Start-Windows.bat")


class TheDownloadPageOffer(unittest.TestCase):

    def setUp(self):
        _clean_state(self)
        probe._note_cause("usbpcap_missing")

    def offer(self, answer, interactive=True, system="Windows"):
        opened = mock.Mock()
        asked = mock.Mock(return_value=answer)
        with mock.patch.object(probe, "ask", asked), \
                mock.patch("webbrowser.open", opened), redirect_stdout(io.StringIO()):
            probe.offer_download_page(interactive, system=system)
        return asked, opened

    def test_yes_opens_the_page(self):
        asked, opened = self.offer("yes")
        opened.assert_called_once_with("https://www.wireshark.org/download.html")
        self.assertIn("wireshark.org/download.html", asked.call_args[0][0])

    def test_default_is_no(self):
        for answer in ("", "no", "n", "maybe"):
            _asked, opened = self.offer(answer)
            opened.assert_not_called()

    def test_not_asked_without_a_person_or_off_windows(self):
        for kwargs in ({"interactive": False}, {"system": "Darwin"}):
            asked, opened = self.offer("yes", **kwargs)
            asked.assert_not_called()
            opened.assert_not_called()

    def test_not_asked_when_usbpcap_is_there(self):
        probe._CAUSES.clear()
        asked, opened = self.offer("yes")
        asked.assert_not_called()
        opened.assert_not_called()


def _windows_checks(admin, usbpcap, drivers_text, build=26300, display="26H2"):
    def fake_run(cmd, timeout=40):
        if cmd[0] == "sc":
            return fixture("windows-sc-query-usbpcap-running.txt" if usbpcap
                           else "windows-sc-query-usbpcap-missing.txt")
        joined = " ".join(cmd)
        if "--extcap-interfaces" in joined:
            return fixture("windows-usbpcapcmd-extcap-interfaces.txt")
        if "USBPcap2" in joined:
            return fixture("windows-usbpcapcmd-extcap-config-hub2.txt")
        return fixture("windows-usbpcapcmd-extcap-config-hub1.txt")
    return [
        mock.patch.object(probe, "run", fake_run),
        mock.patch.object(probe, "find_usbpcapcmd",
                          lambda: "C:\\Program Files\\USBPcap\\USBPcapCMD.exe" if usbpcap else None),
        mock.patch.object(probe, "windows_program_versions", lambda: {"i1Profiler": "3.8.6.16077"}),
        mock.patch.object(probe, "windows_build_info",
                          lambda: {"build": build, "display": display, "product": ""}),
        mock.patch.object(probe, "windows_is_arm", lambda: False),
        mock.patch.object(probe, "windows_is_admin", lambda: admin),
        mock.patch.object(probe, "windows_driver_devices",
                          lambda: probe.parse_driver_lines(drivers_text)),
        mock.patch.object(probe.platform, "system", lambda: "Windows"),
        mock.patch.object(probe, "tool_name", lambda: "chromiq-io-probe-windows.exe"),
    ]


class TheSecondReportReplayed(unittest.TestCase):
    """USBPcap missing, not administrator, an i1Pro 2 on X-Rite's driver that
    Windows reports as working, Windows 11 build 26300."""

    def setUp(self):
        _clean_state(self)
        probe._DETECTION.clear()
        self.addCleanup(probe._DETECTION.clear)

    def session(self, admin=False, usbpcap=False, drivers=XRITE_I1PRO2_WORKING,
                answers=("",)):
        asked = mock.Mock(side_effect=list(answers))
        patches = _windows_checks(admin, usbpcap, drivers) + [
            mock.patch.object(probe, "ask", asked)]
        for p in patches:
            p.start()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                outcome = probe.instrument_session_step([I1PRO2], direct=True)
        finally:
            for p in patches:
                p.stop()
        return outcome, out.getvalue(), asked

    def test_his_case_on_screen(self):
        outcome, screen, _asked = self.session()
        flat = " ".join(screen.split())
        self.assertEqual(outcome["profile"], "i1pro2")
        self.assertFalse(outcome["recorded"])
        self.assertIn("[OK] Windows 11 version 26H2 (build 26300)", flat)
        self.assertIn("but on this PC X-Rite's driver is installed and Windows reports the "
                      "instrument as working, so please carry on", flat)
        self.assertIn("Please tell us whether i1Profiler measures with it", flat)
        self.assertNotIn("[PLEASE READ] Windows 11", flat)
        self.assertIn("[OK] i1 Pro: X-Rite's driver (EyeOne), and Windows reports it as "
                      "working", flat)
        self.assertIn("[PROBLEM] no. A recording needs it", flat)
        self.assertIn("WHAT USBPcap IS", screen)
        self.assertIn("WHY ADMINISTRATOR RIGHTS ARE NEEDED", screen)
        self.assertEqual(probe._CAUSES, ["usbpcap_missing", "not_admin"])
        self.assertEqual(outcome["help"][0], probe.USBPCAP_INSTALL_TEXT)

    def test_his_case_end_of_run(self):
        outcome, _screen, _asked = self.session()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        args = types.SimpleNamespace(output=os.path.join(tmp.name, "chromiq-io-probe-x.txt"))
        out = io.StringIO()
        with redirect_stdout(out):
            probe.finish_report(args, "Windows", instrument=True, outcome=outcome)
            print("\n".join(probe.what_to_do_lines(probe._CAUSES, probe._LAST_REPORT["path"])))
        end = out.getvalue()
        self.assertIn("FINISHED, BUT NOTHING WAS RECORDED YET", end)
        self.assertGreater(end.rindex("WHAT TO DO NOW"), end.rindex("WHAT USBPcap IS"))
        self.assertIn("chromiq-io-probe-x.txt", end.split("WHAT TO DO NOW")[-1])
        with open(args.output, encoding="utf-8") as fh:
            report = fh.read()
        self.assertIn("WHY ADMINISTRATOR RIGHTS ARE NEEDED", report)
        self.assertIn("WHAT USBPcap IS", report)

    def test_not_administrator_stops_before_the_steps(self):
        outcome, screen, asked = self.session(usbpcap=True)
        self.assertFalse(outcome["recorded"])
        self.assertIn("administrator", outcome["reason"])
        self.assertIn("WHY ADMINISTRATOR RIGHTS ARE NEEDED", screen)
        prompts = " ".join(str(c) for c in asked.call_args_list)
        self.assertNotIn("Start the session now?", prompts)
        self.assertEqual(probe._CAUSES, ["not_admin"])
        body = dict(probe._SECTIONS)["Instrument recording session"]
        self.assertIn("[not running as administrator]", body)

    def test_administrator_goes_on_to_the_start_question(self):
        outcome, screen, asked = self.session(admin=True, usbpcap=True, answers=("", "no"))
        prompts = " ".join(str(c) for c in asked.call_args_list)
        self.assertIn("Start the session now?", prompts)
        self.assertNotIn("WHY ADMINISTRATOR RIGHTS", screen)
        self.assertEqual(probe._CAUSES, [])

    def test_vendor_driver_without_status_keeps_the_warning(self):
        # an older Windows output without the status column, or a device in error
        for drivers in (fixture("windows-drivers-xrite-i1pro2.txt"),
                        XRITE_I1PRO2_WORKING.replace(":: OK", ":: Error")):
            probe._CAUSES.clear()
            _outcome, screen, _asked = self.session(drivers=drivers)
            flat = " ".join(screen.split())
            self.assertIn("[PLEASE READ] Windows 11 version 26H2 (build 26300)", flat)
            self.assertNotIn("so please carry on", flat)

    def test_wrong_driver_is_a_cause(self):
        self.session(admin=True, drivers=fixture("windows-drivers-argyll-i1pro2.txt"))
        self.assertEqual(probe._CAUSES, ["usbpcap_missing", "wrong_driver"])

    def test_release_check_directly(self):
        soft = probe.windows_release_check(26300, "26H2", False, "i1pro2",
                                           vendor_driver_working=True)
        self.assertEqual(soft["level"], "ok")
        self.assertIn("X-Rite says", soft["text"])
        hard = probe.windows_release_check(26300, "26H2", False, "i1pro2")
        self.assertEqual(hard["level"], "warning")


class TheLaunchersDoNotWaitTwice(unittest.TestCase):

    def read(self, name):
        with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
            return fh.read()

    def test_every_tool_start_passes_no_pause(self):
        for name in ("Start-Windows.bat", "Start-macOS.command", "Start-Linux.sh"):
            text = self.read(name)
            starts = [l for l in text.splitlines()
                      if "chromiq_io_probe.py" in l and not l.lstrip().startswith(("REM", "#"))]
            self.assertTrue(starts, name)
            for line in starts:
                self.assertIn("--no-pause", line, f"{name}: {line}")

    def test_each_launcher_still_waits_once_at_the_end(self):
        bat = self.read("Start-Windows.bat").split(":done", 1)[1]
        self.assertEqual(bat.lower().count("pause"), 1)
        for name in ("Start-macOS.command", "Start-Linux.sh"):
            tail = self.read(name).split("chromiq_io_probe.py --no-pause", 1)[1]
            self.assertEqual(tail.count("read -n 1"), 1, name)


if __name__ == "__main__":
    unittest.main()
