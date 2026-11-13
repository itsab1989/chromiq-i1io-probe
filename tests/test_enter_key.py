"""1.5.5: after the first real Windows session (an i1Pro 3, probe 1.5.4).

The tester wrote "keyboard no response" and "keyboard not accepting enter, so
hit hard on it"; steps 7 and 9 then started and stopped at once (0.0 s, files
holding only the USB description). The tool went silent for some seconds
after each stop (stopping USBPcapCMD and checking the recording), and Enter
presses made meanwhile waited in the console and answered the next
questions. These tests replay that with a fake console. Standard library
only; nothing here touches a device."""

import builtins
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
import synth  # noqa: E402


class FakeConsole:
    """Keys typed by the person, in order. 'busy' keys are pressed while the
    tool is busy (no question on the screen); they wait in the console like
    real key presses and are lost only if the tool throws them away."""

    def __init__(self, keys):
        self.planned = list(keys)       # what the person types at questions
        self.buffer = []                # keys already pressed, not yet read
        self.prompts = []
        self.dropped = 0

    def press_while_busy(self, *keys):
        self.buffer.extend(keys)

    def input(self, prompt=""):
        self.prompts.append(prompt)
        if self.buffer:
            return self.buffer.pop(0)
        if self.planned:
            return self.planned.pop(0)
        raise EOFError

    def flush(self):
        self.dropped += len(self.buffer)
        n = len(self.buffer)
        self.buffer.clear()
        return n


class FakeRecorder:
    """Records nothing; while it starts and stops, the person keeps pressing
    Enter (the tool shows no question then)."""

    label = "fake recorder"

    def __init__(self, console, folder, recording):
        self.console = console
        self.outdir = ""
        self.notes = []
        self.files = {}
        self.diag = []
        self.recording = recording

    def session_start(self):
        return True

    def session_end(self):
        pass

    def iface_label(self, iface):
        return "USBPcap1"

    def start(self, stem):
        self.stem = stem
        self.console.press_while_busy("", "")            # impatient Enters
        return ["\\\\.\\USBPcap1"]

    def stop(self):
        self.console.press_while_busy("", "", "")        # "hit hard on it"
        path = os.path.join(self.outdir, f"{self.stem}-USBPcap1-full.pcap")
        with open(path, "wb") as fh:
            fh.write(self.recording)
        return [path]


def instrument_recording():
    w = synth.UsbPcapWriter()
    w.describe(synth.I1PRO, 0x0765, 0x6009, [(0x81, 2), (0x83, 3), (0x84, 2), (0x02, 2)])
    w.vendor_out(synth.I1PRO, 0x22, b"\x00\x00\x00\x00\x13\x00\x00\x00")
    w.bulk_in(synth.I1PRO, 0x81, bytes(564 * 10))
    return w.pcap()


def descriptor_only():
    w = synth.UsbPcapWriter()
    w.describe(synth.I1PRO, 0x0765, 0x6009, [(0x81, 2), (0x83, 3), (0x84, 2), (0x02, 2)])
    return w.pcap()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = os.path.join(self.tmp.name, "instrument-session-t")
        probe._INPUT_ENDED.clear()
        self.addCleanup(probe._INPUT_ENDED.clear)

    def run_session(self, console, recording=None, only=None, short=0.0, flush=True):
        rec = FakeRecorder(console, self.folder, recording or instrument_recording())
        patches = [mock.patch.object(builtins, "input", console.input),
                   mock.patch.object(probe, "flush_pending_input",
                                     console.flush if flush else (lambda: 0)),
                   mock.patch.object(probe, "SHORT_STEP_SECONDS", short)]
        for p in patches:
            p.start()
        try:
            with redirect_stdout(io.StringIO()) as out:
                session = probe.run_instrument_session(rec, self.folder, "i1pro3",
                                                       "i1Profiler", "", only=only)
        finally:
            for p in patches:
                p.stop()
        return session, out.getvalue()


class BufferedEnters(Base):

    def test_enters_pressed_while_busy_cannot_start_or_stop_a_step(self):
        # step 1: start, stop with e, notes, lights, go on; then quit at step 2
        console = FakeConsole(["", "e", "scanned one strip", "green twice", "", "q"])
        session, screen = self.run_session(console)
        steps = session["steps"]
        self.assertEqual(len(steps), 1, steps)
        self.assertEqual(steps[0]["notes"], "scanned one strip")
        self.assertEqual(steps[0]["lights"], "green twice")
        self.assertEqual(session["ended"], "stopped by the operator")
        self.assertGreaterEqual(console.dropped, 5)
        self.assertIn("Key received. Stopping the recording", screen)
        self.assertIn("do not press any key", screen)

    def test_without_throwing_keys_away_a_plain_enter_still_cannot_stop(self):
        # even if the console cannot be flushed, buffered Enters do not stop
        # the step: only  e  does.
        console = FakeConsole(["", "e", "notes", "lights", "", "q"])
        session, screen = self.run_session(console, flush=False)
        self.assertIn("still recording: type  e  and press Enter to stop", screen)
        self.assertEqual(session["steps"][0]["files_xrite"],
                         ["step1-idle-take1-USBPcap1-instrument.pcap"])

    def test_a_very_short_step_asks_whether_it_was_on_purpose(self):
        console = FakeConsole(["", "e", "r", "", "e", "", "notes", "lights", "", "q"])
        session, screen = self.run_session(console, short=60.0)
        self.assertTrue(any("That was very short" in p for p in console.prompts))
        self.assertEqual([s.get("take") for s in session["steps"]], [1, 2])
        self.assertTrue(session["steps"][0]["too_short"])


class EmptyStepsAndChecks(Base):

    def test_an_empty_step_is_called_empty(self):
        console = FakeConsole(["", "e", "", "", "", "q"])
        session, screen = self.run_session(console, recording=descriptor_only())
        self.assertIn("EMPTY: nothing was recorded in this step, please repeat it",
                      " ".join(screen.split()))
        self.assertTrue(session["steps"][0]["empty"])
        path = os.path.join(self.tmp.name, "d.pcap")
        with open(path, "wb") as fh:
            fh.write(descriptor_only())
        check = probe.check_capture(path)
        self.assertEqual(check["code"], "empty-step")
        self.assertNotIn("OK", check["verdict"])

    def test_a_good_step_is_called_good(self):
        console = FakeConsole(["", "e", "", "", "", "q"])
        _session, screen = self.run_session(console)
        self.assertRegex(" ".join(screen.split()), r"CHECK: this step recorded \d+ requests "
                                                   r"and data transfers of the instrument: good")

    def test_an_empty_control_step_is_not_a_no_ruler_control(self):
        files = synth.i1pro2_session_files(self.tmp.name, os)
        empty = os.path.join(self.tmp.name, "noruler.pcap")
        w = synth.UsbPcapWriter()
        w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
        w.save(empty)
        text = probe.summarize_session([files["scan-single"], empty])
        self.assertIn("EMPTY: nothing was recorded in this step", text)
        self.assertIn("a no-ruler control ................... NO", text)
        self.assertIn("EMPTY STEPS", text)


class OnlySomeSteps(Base):

    def test_only_steps_7_and_9_keep_their_numbers(self):
        console = FakeConsole(["", "e", "", "", "", "", "e", "", "", ""])
        session, screen = self.run_session(console, only=[7, 9])
        self.assertIn("STEP 7 of 9: let one scan fail on purpose", screen)
        self.assertIn("STEP 9 of 9: the same strip without the ruler", screen)
        self.assertNotIn("STEP 1 of 9", screen)
        self.assertEqual([s["number"] for s in session["steps"]], [7, 9])
        self.assertEqual(session["only_steps"], [7, 9])
        self.assertEqual(session["ended"], "all steps done")
        self.assertTrue(os.path.exists(os.path.join(
            self.folder, "step7-scan-fail-take1-USBPcap1-instrument.pcap")))

    def test_parse_step_numbers(self):
        self.assertEqual(probe.parse_step_numbers("7,9", 9), [7, 9])
        self.assertEqual(probe.parse_step_numbers(" 9 7 7 ", 9), [7, 9])
        self.assertEqual(probe.parse_step_numbers("0, 12, x, 3", 9), [3])
        self.assertEqual(probe.parse_step_numbers("", 9), [])

    def test_the_command_line_option_goes_to_the_handheld_session(self):
        args = mock.Mock(instrument=False, io=False, annotate=False, skip_annotate=False,
                         steps="7,9")
        self.assertEqual(probe.choose_what_to_do(args, "x")[0], 2)

    def test_the_dual_scan_step_asks_for_the_setting(self):
        dual = [s for s in probe.steps_for("i1pro3") if s["key"] == "scan-dual"][0]
        self.assertIn("single or dual scan", dual["setting"])
        console = FakeConsole(["", "e", "notes", "dual, M1", "lights", "", "q"])
        session, _screen = self.run_session(console, only=[4])
        self.assertEqual(session["steps"][0]["setting"], "dual, M1")


class Texts(unittest.TestCase):

    def test_idle_and_slow_steps_say_it_plainly(self):
        steps = {s["key"]: s for s in probe.steps_for("i1pro3")}
        self.assertIn("Do NOT measure or scan", steps["idle"]["during"])
        self.assertIn("3 to 5 seconds", steps["scan-slow"]["during"])

    def test_i1pro3_light_names(self):
        text = probe.decode_i1pro3_led(bytes.fromhex("061402120500"))["text"]
        self.assertIn("red pulse (likely", text)
        self.assertIn("white pulse (likely", text)
        self.assertIn("for ever", text)
        self.assertNotIn("off pulse", text)
        self.assertIn("meaning unknown (guess", probe.decode_i1pro3_led(
            bytes.fromhex("01fa04"))["text"])
        self.assertTrue(probe.I1PRO3_REQUESTS[0x3A][3])
        self.assertFalse(probe.I1PRO3_REQUESTS[0x3B][3])

    def test_flush_on_windows_reads_all_waiting_keys(self):
        keys = ["\r", "\r", "\r"]
        fake = mock.Mock()
        fake.kbhit.side_effect = lambda: bool(keys)
        fake.getwch.side_effect = lambda: keys.pop()
        with mock.patch.dict(sys.modules, {"msvcrt": fake}), \
                mock.patch.object(probe.os, "name", "nt"):
            self.assertEqual(probe.flush_pending_input(), 3)
        self.assertEqual(keys, [])


if __name__ == "__main__":
    unittest.main()
