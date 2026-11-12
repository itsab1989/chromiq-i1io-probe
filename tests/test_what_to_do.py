"""Tests for 1.5.3: one plain question at step 3, "What would you like to
do?", suggested from what is plugged in NOW.

    python3 -m unittest discover -s tests -v

All IDs and names below are invented or taken from the tool's own tables.
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
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402
import test_window_stays_open as t152  # noqa: E402

IO = (0x0971, 0x2004)
I1PRO2 = (0x0971, 0x2000)
I1PRO3 = (0x0765, 0x6009)
UNKNOWN = (0x0971, 0x5555)


def flat(text):
    return " ".join(text.split())


def args(**kw):
    base = dict(instrument=False, io=False, annotate=False, skip_annotate=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


class Suggestion(unittest.TestCase):

    def test_each_combination(self):
        cases = [
            ([], 3, True),
            ([IO], 1, False),
            ([I1PRO2], 2, False),
            ([IO, I1PRO2], 1, False),
            ([I1PRO3, I1PRO2], 2, False),
            ([UNKNOWN], 3, False),
        ]
        for here, choice, nothing in cases:
            sug = probe.suggest(here)
            self.assertEqual(sug["choice"], choice, here)
            self.assertEqual(sug["nothing"], nothing, here)

    def test_only_what_is_plugged_in_counts(self):
        probe._DETECTION.clear()
        self.addCleanup(probe._DETECTION.clear)
        # remembered i1iO, plugged-in i1Pro 2: the i1iO must not hide it
        probe._DETECTION["present_ids"] = [I1PRO2]
        known, here = probe.plugged_in_now([IO, I1PRO2])
        self.assertTrue(known)
        self.assertEqual(here, [I1PRO2])
        self.assertEqual(probe.suggest(here)["choice"], 2)
        # remembered handheld only
        probe._DETECTION["present_ids"] = []
        known, here = probe.plugged_in_now([I1PRO2])
        self.assertEqual((known, here), (True, []))
        self.assertEqual(probe.suggest(here)["choice"], 3)

    def test_unknown_presence(self):
        probe._DETECTION.clear()
        with mock.patch.object(probe.platform, "system", lambda: "Windows"):
            self.assertEqual(probe.plugged_in_now([I1PRO2]), (False, [I1PRO2]))
        with mock.patch.object(probe.platform, "system", lambda: "Darwin"):
            # macOS lists only what is connected
            self.assertEqual(probe.plugged_in_now([I1PRO2]), (True, [I1PRO2]))


class TheTexts(unittest.TestCase):

    def lines(self, here, known=True, drivers=None):
        return "\n".join(probe.what_to_do_question(probe.suggest(here), known, here, drivers or {}))

    def test_nothing_plugged_in(self):
        text = self.lines([])
        self.assertIn("Plugged in now: no X-Rite instrument.", text)
        self.assertIn("type  a  to let the tool look again", text)
        self.assertIn("3. nothing more: just make the report   <- suggested", text)

    def test_handheld_with_its_driver(self):
        text = flat(self.lines([I1PRO2], drivers={I1PRO2: "X-Rite's driver"}))
        self.assertIn("Plugged in now: i1Pro 2", text)
        self.assertIn("(X-Rite's driver)", text)
        self.assertIn("2. record a handheld instrument <- suggested "
                      "(the i1Pro family, the ColorMunki, the i1Studio)", text)

    def test_table_and_its_instrument(self):
        text = flat(self.lines([IO, I1PRO2]))
        self.assertIn("1. record an i1iO table <- suggested", text)
        self.assertIn("The instrument mounted on the table was seen too", text)
        self.assertIn("Choose 2 instead if you want to record that instrument on its own", text)

    def test_unknown_device(self):
        text = flat(self.lines([UNKNOWN]))
        self.assertIn("an X-Rite device this tool does not know (0971:5555)", text)
        self.assertIn("The report (choice 3) is the most useful thing for it", text)

    def test_unknown_presence_said(self):
        self.assertIn("Windows did not say which devices are plugged in right now",
                      self.lines([I1PRO2], known=False))

    def test_fits_a_console_and_no_em_dash(self):
        for here in ([], [IO], [I1PRO2], [IO, I1PRO2], [UNKNOWN]):
            for line in self.lines(here, known=False,
                                   drivers={I1PRO2: "on the ArgyllCMS driver"}).splitlines():
                self.assertLessEqual(len(line), 79, line)
                self.assertNotIn(chr(0x2014), line)


class TheQuestion(unittest.TestCase):

    def setUp(self):
        t152._clean_state(self)
        probe._DETECTION.clear()
        self.addCleanup(probe._DETECTION.clear)

    def choose(self, answers, present, ids_summary="X-Rite devices detected:\n  x",
               flags=None, looked=None):
        probe._DETECTION["present_ids"] = present
        detected = list(present) if present else []
        asked = mock.Mock(side_effect=list(answers))
        out = io.StringIO()

        def again():
            probe._DETECTION["present_ids"] = looked
            return "X-Rite devices detected:\n  again"
        with mock.patch.object(probe, "ask", asked), \
                mock.patch.object(probe, "detected_ids",
                                  lambda s: list(probe._DETECTION["present_ids"] or detected)), \
                mock.patch.object(probe, "quick_summary", again), \
                mock.patch.object(probe, "_windows_driver_words", lambda: {}), \
                redirect_stdout(out):
            choice, _summary = probe.choose_what_to_do(flags or args(), ids_summary)
        return choice, out.getvalue(), asked

    def test_enter_takes_the_suggestion(self):
        self.assertEqual(self.choose([""], [I1PRO2])[0], 2)
        self.assertEqual(self.choose([""], [IO])[0], 1)
        self.assertEqual(self.choose([""], [])[0], 3)

    def test_each_number(self):
        for n in ("1", "2", "3"):
            self.assertEqual(self.choose([n], [I1PRO2])[0], int(n))

    def test_q_means_just_the_report(self):
        self.assertEqual(self.choose(["q"], [I1PRO2])[0], 3)

    def test_invalid_input_asks_again(self):
        choice, screen, asked = self.choose(["7", "yes", "2"], [I1PRO2])
        self.assertEqual(choice, 2)
        self.assertEqual(asked.call_count, 3)
        self.assertIn('"7" is not one of the choices. Please type 1, 2 or 3,', screen)

    def test_look_again_finds_the_instrument(self):
        probe._note_cause("no_instrument")
        choice, screen, asked = self.choose(["a", ""], [], looked=[I1PRO3])
        self.assertEqual(choice, 2)
        self.assertIn("Looking again...", screen)
        self.assertIn("Plugged in now: i1Pro 3", flat(screen))
        self.assertNotIn("no_instrument", probe._CAUSES)
        self.assertIn("Detection summary (looked again)", dict(probe._SECTIONS))

    def test_look_again_still_nothing(self):
        choice, screen, _asked = self.choose(["a", ""], [], looked=[])
        self.assertEqual(choice, 3)
        self.assertEqual(screen.count("Plugged in now: no X-Rite instrument."), 2)

    def test_closed_input_ends_cleanly(self):
        # ask() returns "" on a closed input: that is Enter, never a loop
        self.assertEqual(self.choose([""], [])[0], 3)

    def test_never_endless(self):
        choice, _s, asked = self.choose(["x"] * 40, [I1PRO2])
        self.assertEqual(choice, 3)
        self.assertEqual(asked.call_count, 30)

    def test_the_prompt_says_what_to_type(self):
        _c, _s, asked = self.choose([""], [I1PRO2])
        prompt = asked.call_args[0][0]
        self.assertIn("Type 1, 2 or 3 (or  a  to look again), or just press Enter for 2", prompt)

    def test_flags_skip_the_question(self):
        for flags, choice in ((args(instrument=True), 2), (args(io=True), 1),
                              (args(annotate=True), 1), (args(skip_annotate=True), 1)):
            got, _s, asked = self.choose([], [I1PRO2], flags=flags)
            self.assertEqual(got, choice)
            asked.assert_not_called()


class TheWholeRun(unittest.TestCase):
    """main() from detection to the end, per choice."""

    def setUp(self):
        t152._clean_state(self)
        probe._DETECTION.clear()
        self.addCleanup(probe._DETECTION.clear)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_main(self, answers, present, argv=()):
        def summary():
            probe._DETECTION["present_ids"] = present
            return "NO X-RITE DEVICES SEEN.\nPlease check" if not present else \
                "X-Rite devices detected:\n  " + "\n  ".join(
                    f"x :: USB\\VID_{v:04X}&PID_{p:04X}\\9&9" for v, p in present)
        asked = mock.Mock(side_effect=list(answers) + [""] * 40)
        session = mock.Mock(return_value={"profile": "i1pro2", "recorded": False,
                                          "help": [], "reason": "invented"})
        out = io.StringIO()
        with mock.patch.object(probe, "quick_summary", summary), \
                mock.patch.object(probe, "ask", asked), \
                mock.patch.object(probe.platform, "system", lambda: "Windows"), \
                mock.patch.object(probe, "collect_windows", lambda: None), \
                mock.patch.object(probe, "collect_i1profiler_charts", lambda: None), \
                mock.patch.object(probe, "_windows_driver_words", lambda: {}), \
                mock.patch.object(probe, "recording_step", lambda direct: None), \
                mock.patch.object(probe, "instrument_session_step", session), \
                mock.patch.object(probe, "candidate_dirs", lambda: [self.tmp.name]), \
                redirect_stdout(out):
            code = probe.main(list(argv))
        return code, out.getvalue(), asked, session

    def test_choice_3_is_just_the_report(self):
        code, screen, _asked, session = self.run_main(["3"], [I1PRO2])
        self.assertEqual(code, 0)
        session.assert_not_called()
        self.assertIn("ALL DONE", screen)
        self.assertIn("If you would like to share it with us", screen)
        self.assertNotIn("single thing standing between the project and i1iO support", screen)
        self.assertNotIn("three quick questions", screen)
        self.assertEqual(len(os.listdir(self.tmp.name)), 1)

    def test_choice_2_with_nothing_plugged_in_explains(self):
        _code, screen, _asked, session = self.run_main(["2"], [])
        session.assert_called_once()
        self.assertIn("No handheld instrument is plugged in right now", screen)

    def test_choice_1_asks_the_three_table_questions(self):
        _code, screen, asked, session = self.run_main(["1"], [IO])
        session.assert_not_called()
        self.assertIn("three quick questions about your i1iO table", screen)
        prompts = " ".join(str(c) for c in asked.call_args_list)
        self.assertIn("Which generation is your table", prompts)
        self.assertNotIn("No i1iO table is plugged in right now", screen)

    def test_choice_1_without_a_table_says_so(self):
        _code, screen, _asked, _s = self.run_main(["1"], [])
        self.assertIn("No i1iO table is plugged in right now", screen)

    def test_handheld_suggested_and_taken_with_enter(self):
        _code, screen, _asked, session = self.run_main([""], [I1PRO2])
        session.assert_called_once()
        self.assertIn("STEP 3 of 3: the recording session", screen)

    def test_i1pro_flag(self):
        _code, _screen, asked, session = self.run_main([], [], argv=["--i1pro"])
        session.assert_called_once()
        self.assertNotIn("What would you like to do", " ".join(str(c) for c in asked.call_args_list))

    def test_io_flag(self):
        _code, screen, _asked, session = self.run_main([], [I1PRO2], argv=["--io"])
        session.assert_not_called()
        self.assertIn("three quick questions about your i1iO table", screen)

    def test_new_name_on_the_first_screen_and_in_the_report(self):
        _code, screen, _a, _s = self.run_main(["3"], [I1PRO2])
        self.assertIn("ChromIQ X-Rite instrument probe " + probe.PROBE_VERSION, screen)
        with open(os.path.join(self.tmp.name, os.listdir(self.tmp.name)[0]), encoding="utf-8") as fh:
            report = fh.read()
        self.assertTrue(report.startswith("ChromIQ X-Rite instrument probe report, version"))
        self.assertIn("3: nothing more, just the report", report)


class SeenMarkOnlyWhenSeen(unittest.TestCase):

    def test_nothing_seen_no_mark(self):
        for seen in (True, False):
            out = io.StringIO()
            with mock.patch.object(probe, "ask", lambda *a, **k: ""), redirect_stdout(out):
                probe._ask_profile("generic", seen=seen)
            self.assertEqual("<- seen on this computer" in out.getvalue(), seen)


class TheDetectionFitsEightyColumns(unittest.TestCase):
    """Found in the VM's 80-column window: two detection lines wrapped."""

    def test_remembered_and_nothing(self):
        probe._DETECTION.clear()
        self.addCleanup(probe._DETECTION.clear)
        out = ("X-Rite i1 Studio :: USB\\VID_0765&PID_6008\\7&1A2B3C4D&0&2 :: False\n"
               "i1 Pro :: USB\\VID_0971&PID_2000\\6&2B3C4D5E&0&1 :: True")
        for text in (out, out.replace("True", "False"), ""):
            with mock.patch.object(probe.platform, "system", lambda: "Windows"), \
                    mock.patch.object(probe.shutil, "which", lambda n: "powershell"), \
                    mock.patch.object(probe, "run", lambda *a, **k: text):
                summary = probe.quick_summary()
            for line in ("  " + summary.replace("\n", "\n  ")).splitlines():
                self.assertLessEqual(len(line), 79, line)
        self.assertIn("Step 3 can look again", summary)


class TheLaunchersSayTheNewName(unittest.TestCase):

    def test_banners(self):
        for name in ("Start-Windows.bat", "Start-macOS.command", "Start-Linux.sh"):
            with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("X-Rite instrument probe", text, name)
            self.assertNotIn("i1iO information collector", text, name)


if __name__ == "__main__":
    unittest.main()
