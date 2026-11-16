"""1.6.6: a replay of a tester's i1Pro 2 morning, from the facts of its four
report-only files (structural facts only, nothing private): tool 1.6.3,
Windows, i1Profiler, the kit's command line  --i1pro --steps 1,2,4,6 , the
right root hub recorded (USBPcap1, the instrument listed on it), and every
step holding only the instrument's USB description (6 records at its
address). The instrument's driver stack was {EyeOne, ACPI, USBHUB3}: no
USBPcap, as on the same PC two days before; its install and arrival time
were the same second (Windows set it up again, a driver change), and a
second driver package for it (libusb0, the one ArgyllCMS and ChromIQ use)
was present. Four sessions, fourteen steps, nothing kept.

What these tests hold: the released check (1.6.5) stops this exact case
before step 1 for the i1Pro 2 on the kit's command line, and after the
first step when someone types "go on"; and (1.6.6) the text names the
driver change as the usual cause, and says to do the replug or restart
after every change of the instrument's driver."""

import io
import os
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402
import synth  # noqa: E402
import test_all_empty as tae  # noqa: E402
from test_usbpcap_start import INTERFACES, _answers  # noqa: E402

# the stack exactly in the form the tester's report shows it (with spaces)
MISSING = "\\Driver\\EyeOne, \\Driver\\ACPI, \\Driver\\USBHUB3"
ATTACHED = "\\Driver\\EyeOne, \\Driver\\USBPcap, \\Driver\\ACPI, \\Driver\\USBHUB3"
KIT_STEPS = [1, 2, 4, 6]


def i1pro2(stack):
    return {"vid": 0x0971, "pid": 0x2000, "name": "i1 Pro", "class": "XRiteDevices",
            "service": "EyeOne", "provider": "X-Rite", "status": "OK", "stack": stack}


def description_only():
    """What every step of that morning held: the i1Pro 2's USB description
    (injected by USBPcapCMD at the start) and other devices' traffic."""
    w = synth.UsbPcapWriter()
    w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
    synth.keyboard_noise(w, n=6)
    return w


class KitMorning(tae.TheWholeSession):

    def test_every_step_stale(self):                 # the parent's own test, not here
        pass

    def run_kit(self, stack, answers):
        for step in probe.steps_for("i1pro2"):
            description_only().save(os.path.join(self.pcaps, step["key"] + ".pcap"))

        def fake_run(cmd, timeout=40):
            joined = " ".join(cmd)
            if cmd[0] == "sc":
                return "SERVICE_NAME: USBPcap\n        STATE              : 4  RUNNING\n"
            if "--extcap-version" in joined:
                return "extcap {version=1.5.4.0}{help=http://desowin.org/usbpcap/}\n"
            if "--extcap-interfaces" in joined:
                return INTERFACES.split("\n")[0] + "\n"
            return "value {arg=99}{value=11}{display=[11] i1 Pro}{enabled=true}\n"
        it = iter(answers)
        patches = [
            mock.patch.object(probe, "run", fake_run),
            mock.patch.object(probe, "find_usbpcapcmd", lambda: self.exe),
            mock.patch.object(probe, "windows_program_versions",
                              lambda: {"i1Profiler": "3.8.6.18652"}),
            mock.patch.object(probe, "windows_build_info",
                              lambda: {"build": 26300, "display": "26H2", "product": ""}),
            mock.patch.object(probe, "windows_is_arm", lambda: False),
            mock.patch.object(probe, "windows_is_admin", lambda: True),
            mock.patch.object(probe, "windows_driver_devices", lambda: [i1pro2(stack)]),
            mock.patch.object(probe.platform, "system", lambda: "Windows"),
            mock.patch.object(probe, "_writable_dir", lambda: self.dir),
            mock.patch.object(probe, "candidate_dirs", lambda: [self.dir]),
            mock.patch.object(probe, "ask", _answers(it)),
        ]
        for p in patches:
            p.start()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                outcome = probe.instrument_session_step([(0x0971, 0x2000)], direct=True,
                                                        only=KIT_STEPS)
                code = probe.finish_report(types.SimpleNamespace(output=None), "Windows",
                                           instrument=True, outcome=outcome)
        finally:
            for p in patches:
                p.stop()
        return outcome, code, out.getvalue()

    def test_stack_without_usbpcap_is_no(self):
        self.assertEqual(probe.recorder_attached(i1pro2(MISSING)), "no")
        self.assertEqual(probe.recorder_attached(i1pro2(ATTACHED)), "yes")
        self.assertEqual(probe.recorder_verdict([i1pro2(MISSING)], "i1pro2")["verdict"], "no")

    def test_kit_command_stops_before_step_1(self):
        outcome, code, screen = self.run_kit(MISSING, ["", ""])   # profile, Enter = stop
        self.assertEqual(code, 0)
        self.assertIn("USB recorder attached to your instrument: no", screen)
        self.assertIn("THE USB RECORDER IS NOT ATTACHED TO YOUR INSTRUMENT YET", screen)
        self.assertNotIn("STEP 1 of", screen)
        self.assertFalse(outcome["recorded"])

    def test_go_on_stops_after_the_first_step(self):
        outcome, _c, screen = self.run_kit(MISSING, ["", "go on", "yes", "1", "", "", "e",
                                                      ""])
        flat = " ".join(screen.split())
        self.assertIn("STEP 1 of", screen)
        self.assertIn("only the instrument's USB description was recorded", flat)
        self.assertIn("Two things look exactly like this", flat)
        self.assertNotIn("STEP 2 of", screen)
        self.assertTrue(outcome["all_empty"])

    def test_names_the_driver_change(self):
        """1.6.6: the usual cause, a change of the instrument's driver, is
        named, and the advice says to repeat it after every such change."""
        _o, _c, screen = self.run_kit(MISSING, ["", ""])
        flat = " ".join(screen.split())
        self.assertIn("after its driver was changed", flat)
        self.assertIn("every time you switch the instrument between ChromIQ (ArgyllCMS) "
                      "and X-Rite's program", flat)
        for line in probe.recorder_not_attached_lines(
                probe.recorder_verdict([i1pro2(MISSING)], "i1pro2")):
            self.assertLessEqual(len("  " + line), 79, line)
            self.assertNotIn("—", line)

    def test_attached_records_the_kit_steps(self):
        _o, _c, screen = self.run_kit(ATTACHED, ["", "yes", "1", "", "", "e", ""])
        self.assertIn("USB recorder attached to your instrument: yes", screen)
        self.assertNotIn("NOT ATTACHED", screen)
        self.assertIn("STEP 1 of", screen)


if __name__ == "__main__":
    unittest.main()
