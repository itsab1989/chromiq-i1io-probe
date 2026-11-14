"""1.6.3 (review): the short codes that replace serial numbers and other
private values are salted per run, so they cannot be reversed by trying
every serial number, nor compared between runs or people. The salt is never
written anywhere."""

import hashlib
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import chromiq_io_probe as probe  # noqa: E402

SERIAL = "0012345"          # a planted 7-digit serial


def code_of(text):
    return text.split("<redacted:")[1].split(">")[0]


class SaltedCodes(unittest.TestCase):

    def setUp(self):
        self.addCleanup(setattr, probe, "REDACT", probe.REDACT)
        probe.REDACT = True

    def test_same_value_same_code_within_a_run(self):
        a = probe.scrub(f"serial_num: {SERIAL}")
        b = probe.scrub(f"USB\\VID_0765&PID_6009\\{SERIAL}")
        self.assertEqual(code_of(a), code_of(b))
        self.assertNotIn(SERIAL, a + b)

    def test_another_run_gives_another_code(self):
        a = code_of(probe.scrub(f"serial_num: {SERIAL}"))
        probe.new_salt()
        b = code_of(probe.scrub(f"serial_num: {SERIAL}"))
        self.assertNotEqual(a, b)
        # two real runs of the tool, as separate processes
        cmd = [sys.executable, "-c", "import chromiq_io_probe as p; "
               f"print(p.scrub('serial_num: {SERIAL}'))"]
        outs = {subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                               timeout=60).stdout.strip() for _ in range(2)}
        self.assertEqual(len(outs), 2, outs)

    def test_trying_every_number_does_not_find_it(self):
        # the reviewer's attack: hash every candidate the way 1.6.2 did
        code = code_of(probe.scrub(f"serial_num: {SERIAL}"))
        found = [n for n in range(100000)
                 if hashlib.sha256(f"{n:07d}".encode()).hexdigest()[:8] == code]
        self.assertEqual(found, [])
        # (1.6.2's own code for it would have been found at once)
        old = hashlib.sha256(SERIAL.encode()).hexdigest()[:8]
        self.assertIn(12345, [n for n in range(12340, 12350)
                              if hashlib.sha256(f"{n:07d}".encode()).hexdigest()[:8] == old])

    def test_windows_ids_and_chip_ids_are_salted_too(self):
        a = probe._hash_token("7&2A1B9C&0&USB001")
        b = probe._d_chipid(b"", b"\x01\x02\x03\x04\x05\x06\x07\x08")
        probe.new_salt()
        self.assertNotEqual(a, probe._hash_token("7&2A1B9C&0&USB001"))
        self.assertNotEqual(b, probe._d_chipid(b"", b"\x01\x02\x03\x04\x05\x06\x07\x08"))

    def test_the_salt_is_never_written(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        uses = [l for l in src.splitlines() if "_SALT[0]" in l]
        self.assertEqual(len(uses), 2, uses)     # renewed, used in the hash

    def test_no_redact_says_so(self):
        out = subprocess.run([sys.executable, os.path.join(ROOT, "chromiq_io_probe.py"),
                              "--help"], capture_output=True, text=True, timeout=60).stdout
        self.assertIn("every other USB device's name", " ".join(out.split()))
        self.assertEqual(probe.NO_REDACT_LINE, "Nothing is hidden in this report "
                         "(--no-redact). Do not post it publicly.")
        probe.REDACT = False
        self.assertIn(probe.NO_REDACT_LINE, probe.report_text())


if __name__ == "__main__":
    unittest.main()
