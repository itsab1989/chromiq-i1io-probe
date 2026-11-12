"""Tests for 1.5.3: the tool offers to fetch and start USBPcap's installer,
and to start itself again as administrator, only after a yes.

    python3 -m unittest discover -s tests -v

Nothing here touches the network, starts a real installer or asks Windows
for administrator rights: the download, the start and the check whether
USBPcap is installed are all fakes.
"""

import hashlib
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402
import test_window_stays_open as t152  # noqa: E402

FAKE = b"MZ this is not a real installer " * 10
FAKE_INFO = {"name": "USBPcapSetup-test.exe", "url": "https://example.invalid/USBPcapSetup-test.exe",
             "size": len(FAKE), "sha256": hashlib.sha256(FAKE).hexdigest()}


def no_network(*_a, **_k):
    raise AssertionError("the network was touched")


class Pinned(unittest.TestCase):

    def test_the_official_asset_is_pinned(self):
        info = probe.USBPCAP_INSTALLER
        self.assertEqual(info["name"], "USBPcapSetup-1.5.4.0.exe")
        self.assertTrue(info["url"].startswith(
            "https://github.com/desowin/usbpcap/releases/download/1.5.4.0/"))
        self.assertEqual(info["size"], 195040)
        self.assertEqual(info["sha256"],
                         "87a7edf9bbbcf07b5f4373d9a192a6770d2ff3add7aa1e276e82e38582ccb622")

    def test_the_plain_facts_before_the_first_yes(self):
        text = probe.USBPCAP_BEFORE_YOU_DECIDE
        flat = " ".join(text.split())
        self.assertIn("free, open-source software by its own author", flat)
        self.assertIn("not by us", flat)
        self.assertIn("installs a system driver", flat)
        self.assertIn("blue screen", flat)
        self.assertIn("USBPcap issue #146", flat)
        self.assertIn('Settings, Apps, Installed apps, "USBPcap", Uninstall', flat)
        for line in text.splitlines():
            self.assertLessEqual(len(line), 76, line)
            self.assertNotIn(chr(0x2014), line)


class Fetch(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_match_is_saved(self):
        got = probe.fetch_usbpcap_installer(self.tmp.name, fetch=lambda u, n: FAKE, info=FAKE_INFO)
        self.assertTrue(got["ok"])
        with open(got["path"], "rb") as fh:
            self.assertEqual(fh.read(), FAKE)
        self.assertIn("fingerprint (SHA-256) matches", got["message"])
        self.assertIn(FAKE_INFO["url"], got["message"])

    def test_mismatch_is_thrown_away(self):
        for blob in (FAKE[:-1] + b"X", FAKE + b"more"):
            got = probe.fetch_usbpcap_installer(self.tmp.name, fetch=lambda u, n, b=blob: b,
                                                info=FAKE_INFO)
            self.assertFalse(got["ok"])
            self.assertEqual(got["kind"], "fingerprint mismatch")
            self.assertIn("NOT started", got["message"])
            self.assertEqual(os.listdir(self.tmp.name), [])

    def test_download_failure(self):
        def offline(_url, _n):
            raise OSError("Name or service not known")
        got = probe.fetch_usbpcap_installer(self.tmp.name, fetch=offline, info=FAKE_INFO)
        self.assertFalse(got["ok"])
        self.assertEqual(got["kind"], "download failed")
        self.assertIn("without internet", got["message"])
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_the_real_downloader_is_plain_urllib_and_capped(self):
        seen = {}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                seen["n"] = n
                return b"x"

        def fake_urlopen(req, timeout):
            seen["url"], seen["timeout"] = req.full_url, timeout
            return Resp()
        with mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(probe._download("https://example.invalid/f", 10), b"x")
        self.assertEqual(seen, {"url": "https://example.invalid/f", "timeout": 60, "n": 11})


class TheInstallerOffer(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.object(probe, "USBPCAP_INSTALLER", FAKE_INFO)
        p.start()
        self.addCleanup(p.stop)

    def offer(self, answers, fetch=lambda u, n: FAKE, code=0, installed_after=True):
        launched = []

        def launch(path):
            launched.append(path)
            return code
        asked = mock.Mock(side_effect=list(answers))
        out = io.StringIO()
        with mock.patch.object(probe, "ask", asked), mock.patch.object(probe, "_download", no_network), \
                redirect_stdout(out):
            result = probe.offer_usbpcap_install(self.tmp.name, fetch=fetch, launch=launch,
                                                 installed=lambda: installed_after)
        return result, out.getvalue(), launched, asked

    def test_no_at_the_first_question(self):
        result, screen, launched, asked = self.offer(["no"], fetch=no_network)
        self.assertEqual(result, "declined")
        self.assertEqual(launched, [])
        self.assertIn("ABOUT USBPcap, BEFORE YOU DECIDE", screen)
        self.assertLess(screen.index("issue #146"), screen.index("All right"))
        self.assertIn("Shall this tool fetch its official", asked.call_args_list[0][0][0])
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_enter_is_no(self):
        result, _s, launched, _a = self.offer([""], fetch=no_network)
        self.assertEqual(result, "declined")
        self.assertEqual(launched, [])

    def test_no_at_the_second_question_keeps_the_file_unstarted(self):
        result, screen, launched, asked = self.offer(["yes", "no"])
        self.assertEqual(result, "downloaded, not started")
        self.assertEqual(launched, [])
        self.assertIn("User Account Control", asked.call_args_list[1][0][0])
        self.assertIn("licence", asked.call_args_list[1][0][0])
        self.assertEqual(os.listdir(self.tmp.name), ["USBPcapSetup-test.exe"])
        self.assertIn("The installer is kept here", screen)

    def test_mismatch_never_starts(self):
        result, screen, launched, asked = self.offer(["yes"], fetch=lambda u, n: FAKE + b"!")
        self.assertEqual(result, "fingerprint mismatch")
        self.assertEqual(launched, [])
        self.assertEqual(asked.call_count, 1)
        self.assertIn("NOT started", screen)

    def test_download_failure_falls_back(self):
        def offline(_u, _n):
            raise TimeoutError("timed out")
        result, screen, launched, _a = self.offer(["yes"], fetch=offline)
        self.assertEqual(result, "download failed")
        self.assertEqual(launched, [])
        self.assertIn("The steps above work without this tool", screen)

    def test_installed_then_restart_and_delete(self):
        result, screen, launched, _a = self.offer(["yes", "yes", "yes"])
        self.assertEqual(result, "installed")
        self.assertEqual(launched, [os.path.join(self.tmp.name, "USBPcapSetup-test.exe")])
        self.assertIn("Please restart Windows now", screen)
        self.assertIn("does not restart your computer for you", screen)
        self.assertIn("Deleted.", screen)
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_installed_keep_the_file(self):
        result, screen, _l, _a = self.offer(["yes", "yes", "no"])
        self.assertEqual(result, "installed")
        self.assertIn("It stays here", screen)
        self.assertEqual(os.listdir(self.tmp.name), ["USBPcapSetup-test.exe"])

    def test_installer_exits_non_zero_and_nothing_installed(self):
        result, screen, _l, _a = self.offer(["yes", "yes", "no"], code=2, installed_after=False)
        self.assertEqual(result, "still not installed")
        flat = " ".join(screen.split())
        self.assertIn("its exit code was 2", flat)
        self.assertIn("does not list USBPcap as installed", flat)
        self.assertIn("cannot install on this computer", flat)

    def test_windows_question_answered_no(self):
        result, screen, _l, asked = self.offer(["yes", "yes"], code=None)
        self.assertEqual(result, "installer did not start")
        self.assertIn("nothing was installed", screen)
        self.assertEqual(asked.call_count, 2)

    def test_no_silent_switch(self):
        # the default launch starts the file with no parameters at all
        calls = []
        with mock.patch.object(probe, "_shell_execute",
                               lambda *a, **k: calls.append((a, k)) or 0), \
                mock.patch.object(probe, "ask", mock.Mock(side_effect=["yes", "yes", "no"])), \
                redirect_stdout(io.StringIO()):
            probe.offer_usbpcap_install(self.tmp.name, fetch=lambda u, n: FAKE,
                                        installed=lambda: True)
        (args, kwargs), = calls
        self.assertEqual(args, (os.path.join(self.tmp.name, "USBPcapSetup-test.exe"),))
        self.assertTrue(kwargs["wait"])
        self.assertNotIn("params", kwargs)


class TheAdminOffer(unittest.TestCase):

    def run_offer(self, answer, started=0):
        calls = []

        def launch(prog, params, folder):
            calls.append((prog, params, folder))
            return started
        out = io.StringIO()
        with mock.patch.object(probe, "ask", lambda *_a, **_k: answer), \
                mock.patch.object(probe.time, "sleep", lambda _s: None), redirect_stdout(out):
            try:
                result = probe.offer_relaunch_as_admin(launch=launch)
            except probe.Relaunched:
                result = "relaunched"
        return result, calls, out.getvalue()

    def test_no_prints_the_manual_way(self):
        result, calls, screen = self.run_offer("")
        self.assertFalse(result)
        self.assertEqual(calls, [])
        self.assertIn("say how to do it yourself", screen)

    def test_yes_starts_once_and_closes(self):
        result, calls, screen = self.run_offer("yes")
        self.assertEqual(result, "relaunched")
        self.assertEqual(len(calls), 1)
        self.assertIn("This window closes now.", screen)

    def test_windows_question_refused(self):
        result, calls, screen = self.run_offer("yes", started=None)
        self.assertFalse(result)
        self.assertEqual(len(calls), 1)
        self.assertIn("did not start", screen)

    def test_the_command_for_the_exe_and_the_script(self):
        with mock.patch.object(probe.sys, "frozen", True, create=True), \
                mock.patch.object(probe.sys, "executable", "C:\\x\\chromiq-io-probe-windows.exe"):
            prog, params, _folder = probe.relaunch_command()
        self.assertEqual((prog, params), ("C:\\x\\chromiq-io-probe-windows.exe", "--i1pro"))
        prog, params, _folder = probe.relaunch_command()
        self.assertEqual(prog, sys.executable)
        self.assertEqual(params, f'"{os.path.abspath(probe.__file__)}" --i1pro')

    def test_default_launch_uses_runas_without_waiting(self):
        calls = []
        with mock.patch.object(probe, "_shell_execute",
                               lambda *a, **k: calls.append((a, k)) or 0), \
                mock.patch.object(probe, "ask", lambda *_a, **_k: "yes"), \
                mock.patch.object(probe.time, "sleep", lambda _s: None), \
                redirect_stdout(io.StringIO()):
            with self.assertRaises(probe.Relaunched):
                probe.offer_relaunch_as_admin()
        (args, kwargs), = calls
        self.assertEqual(kwargs["verb"], "runas")
        self.assertFalse(kwargs["wait"])
        self.assertIn("--i1pro", args[1])

    def test_console_main_closes_without_waiting(self):
        def body(_argv):
            raise probe.Relaunched()
        waited = mock.Mock()
        with mock.patch.object(probe, "main", body), \
                mock.patch.object(probe, "should_pause", lambda _a: True), \
                mock.patch("builtins.input", waited), redirect_stdout(io.StringIO()):
            self.assertEqual(probe.console_main([]), 0)
        waited.assert_not_called()


class InTheSession(unittest.TestCase):
    """The offers inside the Windows checks of the handheld session."""

    def setUp(self):
        t152._clean_state(self)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def session(self, admin, usbpcap, answers, offer_result="declined", arm=False):
        offers = []
        patches = t152._windows_checks(admin, usbpcap, t152.XRITE_I1PRO2_WORKING) + [
            mock.patch.object(probe, "ask", mock.Mock(side_effect=list(answers))),
            mock.patch.object(probe, "offer_usbpcap_install",
                              lambda folder: offers.append(folder) or offer_result),
            mock.patch.object(probe, "_writable_dir", lambda: self.tmp.name),
            mock.patch.object(probe, "windows_is_arm", lambda: arm),
        ]
        for p in patches:
            p.start()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                outcome = probe.instrument_session_step([t152.I1PRO2], direct=True)
        finally:
            for p in patches:
                p.stop()
        return outcome, out.getvalue(), offers

    def test_usbpcap_missing_offers_the_installer(self):
        _o, _s, offers = self.session(False, False, [""])
        self.assertEqual(offers, [self.tmp.name])
        body = dict(probe._SECTIONS)["Instrument recording session"]
        self.assertIn("The offer to fetch and start USBPcap's installer: declined", body)

    def test_after_an_install_the_box_says_restart(self):
        outcome, _s, _o = self.session(False, False, [""], offer_result="installed")
        self.assertEqual(probe._CAUSES, ["usbpcap_restart", "not_admin"])
        self.assertIn("now installed", outcome["reason"])
        flat = " ".join("\n".join(probe.what_to_do_lines(probe._CAUSES, None)).split())
        self.assertIn("1. Restart Windows: USBPcap is installed now", flat)
        self.assertIn("Run as administrator", flat)
        self.assertNotIn("Install USBPcap:", flat)

    def test_not_offered_on_windows_on_arm(self):
        _o, _s, offers = self.session(False, False, [""], arm=True)
        self.assertEqual(offers, [])

    def test_not_admin_with_usbpcap_offers_the_relaunch(self):
        with mock.patch.object(probe.time, "sleep", lambda _s: None), \
                mock.patch.object(probe, "_shell_execute", lambda *a, **k: 0):
            with self.assertRaises(probe.Relaunched):
                self.session(False, True, ["", "yes"])

    def test_not_admin_saying_no_stops_before_the_steps(self):
        outcome, screen, _o = self.session(False, True, ["", "no"])
        self.assertFalse(outcome["recorded"])
        self.assertIn("administrator", outcome["reason"])
        self.assertIn("HOW TO START THIS TOOL AS ADMINISTRATOR", screen)


class SelfTestSwitches(unittest.TestCase):
    """The hidden --selftest switches the Windows VM test uses."""

    def setUp(self):
        t152._clean_state(self)
        self.addCleanup(probe.SELFTEST.clear)

    def test_crash_goes_through_the_error_ending(self):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(probe, "candidate_dirs", lambda: [tmp]), \
                mock.patch.object(probe, "should_pause", lambda _a: False), redirect_stdout(out):
            self.assertEqual(probe.console_main(["--selftest", "crash"]), 1)
            self.assertEqual(len(os.listdir(tmp)), 1)
        self.assertIn("SORRY: THE TOOL STOPPED", out.getvalue())
        self.assertIn("self-test: a deliberate error", out.getvalue())

    def test_bad_fingerprint(self):
        probe.SELFTEST.add("bad-fingerprint")
        with tempfile.TemporaryDirectory() as tmp:
            got = probe.fetch_usbpcap_installer(tmp, fetch=lambda u, n: FAKE, info=FAKE_INFO)
            self.assertEqual(got["kind"], "fingerprint mismatch")
            self.assertEqual(os.listdir(tmp), [])

    def test_relaunch_keeps_the_switches(self):
        probe.SELFTEST.update({"pretend-usbpcap"})
        _prog, params, _f = probe.relaunch_command()
        self.assertTrue(params.endswith("--i1pro --selftest pretend-usbpcap"))

    def test_hidden_from_help(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            probe.main(["--help"])
        self.assertNotIn("selftest", out.getvalue())


class Honesty(unittest.TestCase):

    def test_no_silent_or_hidden_switches_in_the_source(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        block = src.split("def offer_usbpcap_install", 1)[1].split("def relaunch_command", 1)[0]
        for bad in ('"/S"', "'/S'", "/quiet", "/silent", "SW_HIDE", "CREATE_NO_WINDOW"):
            self.assertNotIn(bad, block)
        self.assertIn("info.nShow = 1", src)


if __name__ == "__main__":
    unittest.main()
