"""Tests for 1.5: the handheld-instrument session and its analyser.

    python3 -m unittest discover -s tests -v

Every recording here is SYNTHETIC (tests/synth.py), built from the request
formats ArgyllCMS documents. Nothing was recorded from a real instrument.
The session tests use a FAKE USBPcapCMD (a small Python script) and, for
Linux, fake sudo / tcpdump on PATH; nothing is captured, nothing runs as
administrator.
"""

import io
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth  # noqa: E402


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name


# --------------------------------------------------------------------------
# the analyser on synthetic i1Pro 2 recordings
# --------------------------------------------------------------------------

STEP_ORDER = ["calibrate", "scan-single", "scan-dual", "scan-fast", "scan-slow",
              "noruler", "unknown"]


class I1Pro2AnalysisTests(TempDirCase):

    def setUp(self):
        super().setUp()
        self.files = synth.i1pro2_session_files(self.dir, os)
        self.report = probe.summarize_session([self.files[k] for k in STEP_ORDER])

    def test_family_and_endpoint_0x85(self):
        self.assertIn("instrument family: i1Pro 2 (Rev E)", self.report)
        self.assertIn("Endpoint 0x85 is listed: this is an i1Pro 2", self.report)
        self.assertIn("Endpoints the open driver never uses: 0x85", self.report)

    def test_known_requests_named_with_arguments(self):
        r = self.report
        self.assertIn("0xD4 trigger measurement (i1Pro 2): integration 300 clocks, lamp 0 "
                      "clocks, 200 readings, flags 0x0105 = scan + lamp + RULER START", r)
        self.assertIn("flags 0x0201 = scan + UV LED", r)
        self.assertIn("0xD5 get measurement characteristics (i1Pro 2): clock 36 us, "
                      "6 extra bands, 128 bands", r)
        self.assertIn("0xCA reset: mask 0x1f", r)

    def test_unknown_request_listed_in_full(self):
        self.assertIn("UNKNOWN vendor request 0xDB OUT bmRequestType=0x40 wValue=0x0007 "
                      "wIndex=0x0000 wLength=4 out=aabbccdd in=-", self.report)
        self.assertIn("0xDB (unknown)", self.report)

    def test_ruler_flags_d7_and_foreign_endpoint_flagged(self):
        r = self.report
        self.assertIn("0xD4 with ruler bits: scan + lamp + RULER START", r)
        self.assertIn("0xD7 sent: parameter 0x0000", r)
        self.assertIn("0x85 bulk IN: 4 transfers, 256 bytes (sizes: 64 B x4)   <-- NOT USED "
                      "BY THE OPEN DRIVER", r)
        self.assertIn("every byte is 0 to 3, the shape of two-sensor position data", r)

    def test_control_comparison(self):
        r = self.report
        block = r.split("ONLY WITH THE RULER")[1].split("FAST AGAINST SLOW")[0]
        self.assertIn("scan-single.pcap: data on 0x85 bulk IN; request 0xD7", block)
        self.assertNotIn("noruler.pcap", block)
        self.assertIn("noruler.pcap  [CONTROL: no ruler]", r)

    def test_measurement_sizes_counts_and_rates(self):
        r = self.report
        self.assertIn("200 readings in 4 transfers, 53,600 bytes over 2.01 s (about 100 "
                      "readings/s)", r)
        self.assertIn("one reading = 268 bytes", r)
        side = r.split("STEPS SIDE BY SIDE")[1].split("THE OPEN DRIVER")[0]
        self.assertRegex(side, r"scan-dual\.pcap\s+2\s+400")
        self.assertRegex(side, r"scan-fast\.pcap\s+1\s+60")
        self.assertRegex(side, r"scan-slow\.pcap\s+1\s+600")

    def test_fast_against_slow(self):
        self.assertIn("fast: 60 readings in 0.50 s, integration clocks [300]", self.report)
        self.assertIn("slow: 600 readings in 6.01 s", self.report)

    def test_open_driver_comparison(self):
        r = self.report
        self.assertIn("requests both know: 0xC4, 0xC9, 0xCA, 0xD2, 0xD4, 0xD5, 0xD9", r)
        self.assertIn("requests the open driver never sends: 0xD6 (indicator lights: "
                      "sequence), 0xD7 (RULER: stop tracking (?))", r)

    def test_lights_decoded(self):
        # 1.6.2: in words first, the step list after it when it is short
        self.assertIn("LIGHTS: green blinking (243 ms on, 243 ms off), 3 times "
                      "([green 243 ms, off 243 ms] x3)", self.report)
        self.assertIn("calibrate.pcap: green blinking (243 ms on, 243 ms off), 3 times "
                      "([green 243 ms, off 243 ms] x3) | off for 1 ms ([off 1 ms] x1)",
                      self.report)

    def test_privacy_chip_id_hashed_eeprom_not_printed(self):
        self.assertNotIn("0102030405060708", self.report)
        self.assertIn("chip ID <hashed:", self.report)
        self.assertIn("EEPROM data on 0x82: 2048 bytes (not shown", self.report)
        self.assertNotIn("000102030405060708090a0b", self.report)

    def test_verdict(self):
        r = self.report.split("DOES THIS RECORDING HOLD WHAT WE NEED?")[1]
        for needle in ("real instrument traffic, not zeros ... yes",
                       "a dual-scan step ..................... yes",
                       "a no-ruler control ................... yes",
                       "light commands ....................... yes",
                       "the recording shows ruler commands"):
            self.assertIn(needle, r)

    def test_no_ruler_anywhere_says_so_plainly(self):
        report = probe.summarize_session([self.files["noruler"]])
        self.assertIn("no sign of ruler traffic", report)
        self.assertIn("a no-ruler control ................... yes", report)

    def test_analyze_paths_adds_instrument_report_for_plain_files(self):
        text = probe.analyze_paths([self.files["scan-single"]])
        self.assertIn("USB recording check", text)
        self.assertIn("Instrument recording analysis", text)


class FilterTests(TempDirCase):

    def test_usbpcap_copy_keeps_only_the_instrument(self):
        w = synth.UsbPcapWriter()
        synth.i1pro2_calibration(w)
        w.describe(synth.KEYBOARD, 0x046D, 0xC31C, [(0x81, 3)])
        synth.keyboard_noise(w, 5)
        src = w.save(os.path.join(self.dir, "full.pcap"))
        check = probe.check_capture(src)
        self.assertEqual(check["code"], "ok")
        self.assertLess(check["xrite_packets"], check["packets"])
        dst = os.path.join(self.dir, "instrument.pcap")
        kept = probe.filter_xrite_capture(src, dst)
        self.assertEqual(kept, check["xrite_packets"])
        lt, recs = probe._read_pcap(dst)
        self.assertEqual(lt, 249)
        self.assertEqual({k for k in probe.record_device_keys(lt, recs)}, {(1, synth.I1PRO)})

    def test_without_description_the_commands_point_at_the_instrument(self):
        w = synth.UsbPcapWriter()
        synth.i1pro2_calibration(w, describe=False)
        src = w.save(os.path.join(self.dir, "nodesc.pcap"))
        devices = probe.device_map(probe.capture_events(*probe._read_pcap(src)))
        self.assertEqual(devices[(1, synth.I1PRO)]["guess_family"], "i1pro2")
        dst = os.path.join(self.dir, "x.pcap")
        self.assertGreater(probe.filter_xrite_capture(src, dst), 0)
        _lt, recs = probe._read_pcap(dst)
        self.assertNotIn((1, synth.KEYBOARD), probe.record_device_keys(249, recs))

    def test_a_hub_without_the_instrument_says_no_xrite(self):
        w = synth.UsbPcapWriter()
        w.describe(synth.KEYBOARD, 0x046D, 0xC31C, [(0x81, 3)])
        synth.keyboard_noise(w, 5)
        src = w.save(os.path.join(self.dir, "kb.pcap"))
        self.assertEqual(probe.check_capture(src)["code"], "no-xrite")
        self.assertEqual(probe.filter_xrite_capture(src, os.path.join(self.dir, "o")), 0)


class OtherFamilyTests(TempDirCase):

    def test_i1pro3_comparison_ruler_and_lights(self):
        w = synth.UsbPcapWriter()
        synth.i1pro3_scan(w)
        report = probe.summarize_session([w.save(os.path.join(self.dir, "scan-single.pcap"))])
        self.assertIn("instrument family: i1Pro 3 / 3 Plus", report)
        self.assertIn("compare the vendor program with what the open driver sends", report)
        self.assertIn("0x22 measure (reflective): 0 readings (scan: until released), "
                      "flags 0x13 = lamp (all LEDs) + RULER (zebra) read", report)
        self.assertIn("requests the open driver never sends: 0x3B (set scan-start "
                      "indicator timing)", report)
        self.assertIn("2-bit samples packed four to a byte", report)
        self.assertIn("green pulse (likely, from a real recording), timing 0x14, 2 times", report)
        self.assertIn("100 readings", report)                # 564 bytes each
        self.assertIn("event on 0x83: button pressed", report)
        self.assertIn("firmware 1.23 '1.23x'", report)

    def test_colormunki(self):
        w = synth.UsbPcapWriter()
        synth.munki_scan(w)
        report = probe.summarize_session([w.save(os.path.join(self.dir, "scan.pcap"))])
        self.assertIn("instrument family: ColorMunki Photo / Design or i1Studio", report)
        self.assertIn("dial: surface, button released", report)
        self.assertIn("lamp, scan, normal gain, hold temperature duty 0, integration 200 "
                      "clocks, 50 readings", report)
        self.assertIn("on 1000 ms, off 0 ms, transition 0 ms, pulses as many as possible",
                      report)
        self.assertIn("button pressed at 12345 ms", report)
        self.assertIn("50 readings in 1 transfers", report)

    def test_unknown_xrite_device_is_listed_raw(self):
        w = synth.UsbPcapWriter()
        w.describe(synth.I1PRO, 0x0971, 0x2099, [(0x81, 2)])
        w.vendor_out(synth.I1PRO, 0x42, b"\x01\x02")
        w.bulk_in(synth.I1PRO, 0x81, b"\x09" * 40)
        report = probe.summarize_session([w.save(os.path.join(self.dir, "x.pcap"))])
        self.assertIn("X-Rite device the tool has no decoder for", report)
        self.assertIn("UNKNOWN vendor request 0x42", report)
        self.assertIn("the tool has no decoder for this device", report)

    def test_original_i1pro_by_its_endpoints(self):
        self.assertEqual(probe.family_for(0x0971, 0x2000,
                                          ["  endpoint 0x82 (IN), bulk", "  endpoint 0x84"]),
                         "i1pro")
        self.assertEqual(probe.family_for(0x0971, 0x2000, ["  endpoint 0x85 (IN), bulk"]),
                         "i1pro2")
        self.assertEqual(probe.family_for(0x0765, 0x6009), "i1pro3")
        self.assertEqual(probe.family_for(0x0765, 0x6008), "munki")
        self.assertEqual(probe.family_for(0x0971, 0x2007), "munki")


class DecoderTests(TempDirCase):

    def test_led_masks(self):
        self.assertEqual(probe.led_mask_text(0x3F), "white")
        self.assertEqual(probe.led_mask_text(0x09), "red")
        self.assertEqual(probe.led_mask_text(0x01), "left off, right red")
        self.assertEqual(probe.led_mask_text(0x36), "cyan")

    def test_led_sequence_forever(self):
        seq = synth.be32(1) + synth.be32(7) + synth.be32(0xFFFFFFFF) + b"\x3f" + synth.be16(13700)
        dec = probe.decode_led_sequence(seq)
        self.assertTrue(dec["ok"])
        self.assertEqual(dec["text"], "white, steady ([white 1000 ms] forever)")
        self.assertEqual(dec["colours"], ["white"])

    def test_broken_led_sequence_is_shown_raw(self):
        dec = probe.decode_led_sequence(b"\x00\x00\x00\x05\x00")
        self.assertFalse(dec["ok"])
        self.assertIn("undecodable", dec["text"])

    def test_i1pro2_flags(self):
        self.assertEqual(probe.i1pro2_flag_text(0x0109),
                         "scan + lamp + RULER END")
        self.assertIn("UNKNOWN BITS 0x0010", probe.i1pro2_flag_text(0x0011))

    def test_usbmon_records(self):
        def rec(uid, typ, xfer, ep, dev, setup=b"", data=b""):
            flag_setup = b"\x00" if setup else b"-"
            hdr = struct.pack("<QcBBBHccqiiII8s", uid, typ, xfer, ep, dev, 2, flag_setup,
                              b"=", 0, 0, 0, len(data), len(data), setup.ljust(8, b"\0"))
            return hdr + bytes(16) + data             # 64-byte header
        setup = struct.pack("<BBHHH", 0x40, 0xD4, 0, 0, 14)
        out = synth.be32(10) + synth.be32(0) + synth.be32(5) + synth.be16(0x0101)
        recs = [(1.0, rec(1, b"S", 2, 0x00, 7, setup, out)), (1.001, rec(1, b"C", 2, 0x80, 7)),
                (1.1, rec(2, b"S", 3, 0x82, 7)), (1.2, rec(2, b"C", 3, 0x82, 7,
                                                          data=bytes(268 * 5)))]
        events = probe.capture_events(220, recs)
        self.assertEqual(events[0]["req"], 0xD4)
        self.assertEqual(events[0]["out"], out)
        self.assertEqual((events[1]["ep"], len(events[1]["data"])), (0x82, 1340))
        res = probe.analyze_step(events, "i1pro2")
        self.assertEqual(res["measurements"][0]["readings"], 5)

    def test_pcapng_time_resolution(self):
        def block(btype, body):
            pad = (-len(body)) % 4
            total = 12 + len(body) + pad
            return struct.pack("<II", btype, total) + body + bytes(pad) + struct.pack("<I", total)
        shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        opts = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)
        idb = block(1, struct.pack("<HHI", 249, 0, 65535) + opts)
        ns = 1_800_000_000_123_456_789
        pkt = bytes([27, 0]) + bytes(25)
        epb = block(6, struct.pack("<IIIII", 0, ns >> 32, ns & 0xFFFFFFFF, len(pkt), len(pkt))
                    + pkt)
        path = os.path.join(self.dir, "ns.pcapng")
        with open(path, "wb") as fh:
            fh.write(shb + idb + epb)
        _lt, recs = probe._read_pcap(path)
        self.assertAlmostEqual(recs[0][0], 1_800_000_000.123457, places=3)


# --------------------------------------------------------------------------
# Windows facts, parsed from fixtures
# --------------------------------------------------------------------------

class WindowsTests(unittest.TestCase):

    def test_extcap_interfaces(self):
        self.assertEqual(probe.parse_extcap_interfaces(
            fixture("windows-usbpcapcmd-extcap-interfaces.txt")),
            [("\\\\.\\USBPcap1", "USBPcap1"), ("\\\\.\\USBPcap2", "USBPcap2")])

    def test_extcap_devices_and_instrument_name(self):
        devs = probe.parse_extcap_devices(fixture("windows-usbpcapcmd-extcap-config-hub2.txt"))
        self.assertEqual([a for a, _n in devs], [1, 2, 3])
        self.assertEqual([d for d in devs if probe._XRITE_NAME_RE.search(d[1])],
                         [(3, "[3] X-Rite i1Pro 2")])

    def test_sc_query(self):
        self.assertEqual(probe.parse_sc_query(fixture("windows-sc-query-usbpcap-running.txt")),
                         {"installed": True, "running": True})
        self.assertEqual(probe.parse_sc_query(fixture("windows-sc-query-usbpcap-missing.txt")),
                         {"installed": False, "running": False})

    def test_program_versions(self):
        text = fixture("windows-uninstall-programs.txt")
        self.assertEqual(probe.parse_i1profiler_uninstall(text), "3.8.6.16077")
        self.assertEqual(probe.parse_program_versions(text),
                         {"i1Profiler": "3.8.6.16077", "ccStudio": "1.5.0"})

    def test_windows_release_check(self):
        self.assertEqual(probe.windows_release_check(26100, "24H2", False),
                         {"level": "ok", "text": "Windows 11 version 24H2 (build 26100)"})
        self.assertEqual(probe.windows_release_check(19045, "22H2", False)["text"],
                         "Windows 10 version 22H2 (build 19045)")
        late = probe.windows_release_check(26200, "25H2", False)
        self.assertEqual(late["level"], "warning")
        self.assertIn("does not work with Windows 11 version 25H2 or newer", late["text"])
        self.assertIn("If the vendor program still finds your instrument, carry on", late["text"])
        self.assertEqual(probe.windows_release_check(26100, "24H2", True)["level"], "problem")

    def test_i1profiler_check(self):
        self.assertEqual(probe.i1profiler_check("3.8.6.16077", "i1pro2")["level"], "ok")
        self.assertIn("3.8.6 or older is needed",
                      probe.i1profiler_check("3.8.7", "i1pro2")["text"])
        self.assertEqual(probe.i1profiler_check("3.8.7", "i1pro3")["level"], "ok")

    def test_capture_checks_from_fixtures(self):
        def fake_run(cmd, timeout=40):
            joined = " ".join(cmd)
            if cmd[0] == "sc":
                return fixture("windows-sc-query-usbpcap-running.txt")
            if "--extcap-interfaces" in joined:
                return fixture("windows-usbpcapcmd-extcap-interfaces.txt")
            if "USBPcap2" in joined:
                return fixture("windows-usbpcapcmd-extcap-config-hub2.txt")
            return fixture("windows-usbpcapcmd-extcap-config-hub1.txt")
        with mock.patch.object(probe, "run", fake_run), \
                mock.patch.object(probe, "find_usbpcapcmd",
                                  lambda: "C:\\Program Files\\USBPcap\\USBPcapCMD.exe"), \
                mock.patch.object(probe, "windows_program_versions",
                                  lambda: probe.parse_program_versions(
                                      fixture("windows-uninstall-programs.txt"))), \
                mock.patch.object(probe, "windows_build_info",
                                  lambda: {"build": 26100, "display": "24H2", "product": ""}), \
                mock.patch.object(probe, "windows_is_arm", lambda: False), \
                mock.patch.object(probe, "windows_is_admin", lambda: False):
            checks = probe.windows_capture_checks("i1pro2")
        self.assertTrue(probe.windows_can_record(checks))
        text = probe.windows_checks_text(checks)
        self.assertIn("[OK] Windows 11 version 24H2 (build 26100)", text)
        self.assertIn("[OK] 3.8.6.16077", text)
        self.assertIn("USBPcap:", text)
        self.assertIn("installed and running", text)
        # 1.5.2: not "may refuse" any more; the session stops before the steps
        self.assertIn("[PROBLEM] no. A recording needs it", text)
        self.assertIn("USBPcap2 ([3] X-Rite i1Pro 2)", text)
        self.assertIn("ccStudio 1.5.0", text)

    def test_detected_ids_from_windows_and_linux_text(self):
        probe._DETECTION.clear()
        ids = probe.detected_ids(
            "X-Rite devices detected:\n  eye-one :: USB\\VID_0971&PID_2000\\<redacted:1>\n"
            "  Bus 001 Device 004: ID 0765:6009 X-Rite i1Pro3\n  ID 046d:c31c Logitech")
        self.assertEqual(ids, [(0x0971, 0x2000), (0x0765, 0x6009)])
        self.assertEqual(probe.choose_profile(ids), "i1pro2")
        self.assertEqual(probe.choose_profile([(0x0765, 0x6008)]), "munki")
        self.assertEqual(probe.choose_profile([(0x0971, 0x2099)]), "generic")


# --------------------------------------------------------------------------
# the guided session, with a fake USBPcapCMD
# --------------------------------------------------------------------------

FAKE_USBPCAPCMD = r"""
import glob, os, signal, sys, time
log = os.environ["FAKE_LOG"]
args = sys.argv[1:]
with open(log, "a") as fh:
    fh.write("usbpcapcmd " + " ".join(args) + "\n")
# The real program's own lines and exit codes (thread.c 38; cmd.c getopt).
if os.environ.get("FAKE_FAIL"):
    sys.stderr.write("Couldn't open device - " + os.environ["FAKE_FAIL"] + "\n")
    sys.exit(0)
if os.environ.get("FAKE_REJECT_INJECT") and "--inject-descriptors" in args:
    sys.stderr.write("Try 'USBPcapCMD.exe --help' for more information.\n")
    sys.exit(255)
out = args[args.index("-o") + 1]
# As the real USBPcapCMD 1.5.4.0 run as administrator: the output file is
# opened with CREATE_NEW, so an existing file makes it stop at once
# (cmd.c start_capture; thread.c "Thread started with invalid write handle!").
if os.path.exists(out):
    sys.stderr.write("Thread started with invalid write handle!\n")
    sys.exit(0)
for f in glob.glob(os.path.join(os.environ["FAKE_PCAPS"], "*.pcap")):
    key = os.path.basename(f)[:-5]
    if "-" + key + "-take" in out:
        with open(f, "rb") as src, open(out, "wb") as dst:
            dst.write(src.read())


def stop(*_args):
    with open(log, "a") as fh:
        fh.write("usbpcapcmd stopped " + os.path.basename(out) + "\n")
    sys.exit(0)


for name in ("SIGTERM", "SIGBREAK"):
    if hasattr(signal, name):
        signal.signal(getattr(signal, name), stop)
while True:
    time.sleep(0.05)
"""


class SessionTests(TempDirCase):

    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.dir, "bin")
        self.pcaps = os.path.join(self.dir, "pcaps")
        self.out = os.path.join(self.dir, "out")
        for d in (self.bin, self.pcaps, self.out):
            os.mkdir(d)
        self.log = os.path.join(self.dir, "fake.log")
        # A Python stand-in, so the same test runs on Windows, where the
        # recorder is stopped with CTRL_BREAK, and elsewhere (SIGTERM).
        self.exe = os.path.join(self.bin, "fake_usbpcapcmd.py")
        with open(self.exe, "w") as fh:
            fh.write(FAKE_USBPCAPCMD)
        patcher = mock.patch.dict(os.environ, {"FAKE_LOG": self.log, "FAKE_PCAPS": self.pcaps})
        patcher.start()
        self.addCleanup(patcher.stop)
        for p in (mock.patch.object(probe, "RECORDER_STARTUP_WAIT", 0.3),
                  mock.patch.object(probe, "SHORT_STEP_SECONDS", 0.0)):
            p.start()
            self.addCleanup(p.stop)
        # One synthetic recording per step key, plus a keyboard on the hub.
        files = synth.i1pro2_session_files(self.pcaps, os)
        for key in ("unknown",):
            os.remove(files[key])
        w = synth.UsbPcapWriter()
        w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
        w.vendor_in(synth.I1PRO, 0xC9, b"\x02\x75\x00\x00\xff\xff\x01\x00")
        synth.keyboard_noise(w, 4)
        w.save(os.path.join(self.pcaps, "idle.pcap"))
        self.folder = os.path.join(self.out, "instrument-session-test")

    def fake_log(self):
        if not os.path.exists(self.log):
            return ""
        with open(self.log) as fh:
            return fh.read()

    def run_session(self, answers, profile="i1pro2"):
        replies = iter(answers)

        def fake_ask(_prompt, interruptible=False):
            value = next(replies)
            if isinstance(value, BaseException):
                raise value
            return value
        recorder = probe.UsbPcapRecorder(self.exe, ["\\\\.\\USBPcap1"], "")
        buf = io.StringIO()
        with mock.patch.object(probe, "ask", fake_ask), redirect_stdout(buf):
            session = probe.run_instrument_session(recorder, self.folder, profile,
                                                   "i1Profiler", "3.8.6")
        return session, buf.getvalue()

    def saved(self):
        with open(os.path.join(self.folder, "session.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_record_repeat_skip_and_stop(self):
        answers = ["", "e", "started fine", "white, then off", "",          # 1 idle
                   "", "e", "cal ok", "M0", "blinked", "r",                 # 2 calibrate
                   "", "e", "cal ok again", "M0", "steady green", "",       # 2 take 2
                   "s",                                                    # 3 skipped
                   "q"]                                                    # stop at 4
        session, screen = self.run_session(answers)
        self.assertEqual(session["ended"], "stopped by the operator")
        steps = self.saved()["steps"]
        self.assertEqual([(s["number"], s.get("take")) for s in steps],
                         [(1, 1), (2, 1), (2, 2), (3, 1)])
        self.assertTrue(steps[3]["skipped"])
        self.assertFalse(steps[1]["kept"])
        self.assertTrue(steps[2]["kept"])
        self.assertEqual(steps[0]["lights"], "white, then off")
        self.assertEqual(steps[2]["notes"], "cal ok again")
        left = sorted(os.listdir(self.folder))
        self.assertIn("step1-idle-take1-USBPcap1-instrument.pcap", left)
        self.assertIn("step2-calibrate-take1-USBPcap1-instrument.pcap", left)
        self.assertIn("step2-calibrate-take2-USBPcap1-instrument.pcap", left)
        log = self.fake_log()
        self.assertIn("-d \\\\.\\USBPcap1 -o ", log)
        self.assertIn("-A --inject-descriptors", log)
        # On Windows USBPcapCMD is ended hard (1.5.4), so the fake logs nothing.
        if os.name != "nt":
            self.assertEqual(log.count("usbpcapcmd stopped"), 3)
        self.assertIn("STEP 4 of 9: the same strip, dual scan", screen)
        # The instrument-only copy has no keyboard in it.
        lt, recs = probe._read_pcap(os.path.join(self.folder,
                                                 "step1-idle-take1-USBPcap1-instrument.pcap"))
        self.assertEqual(set(probe.record_device_keys(lt, recs)), {(1, synth.I1PRO)})

    def test_ctrl_c_during_a_step_keeps_that_step_and_the_ones_before(self):
        answers = ["", "e", "ok", "white", "",                             # 1 idle
                   "", KeyboardInterrupt()]                                # Ctrl-C in 2
        session, _screen = self.run_session(answers)
        self.assertIn("Ctrl-C", session["ended"])
        steps = self.saved()["steps"]
        self.assertEqual([s["number"] for s in steps], [1, 2])
        self.assertTrue(steps[1]["interrupted"])
        self.assertEqual(steps[1]["files_xrite"],
                         ["step2-calibrate-take1-USBPcap1-instrument.pcap"])
        if os.name != "nt":
            self.assertEqual(self.fake_log().count("usbpcapcmd stopped"), 2)

    def test_ctrl_c_between_steps(self):
        answers = ["", "e", "ok", "white", "", KeyboardInterrupt()]
        session, _screen = self.run_session(answers)
        self.assertIn("Ctrl-C", session["ended"])
        self.assertEqual(len(self.saved()["steps"]), 1)
        if os.name != "nt":
            self.assertEqual(self.fake_log().count("usbpcapcmd stopped"), 1)

    def test_recorder_that_cannot_start(self):
        os.environ["FAKE_FAIL"] = "5"
        try:
            session, screen = self.run_session([""])
        finally:
            del os.environ["FAKE_FAIL"]
        self.assertEqual(session["ended"], "the recording program stopped at once")
        self.assertIn("Most likely another", screen)
        self.assertIn("device - 5", screen)
        self.assertEqual(self.saved()["steps"], [])

    def test_retry_without_inject_option(self):
        os.environ["FAKE_REJECT_INJECT"] = "1"
        try:
            session, _screen = self.run_session(["", "e", "ok", "white", "", "q"])
        finally:
            del os.environ["FAKE_REJECT_INJECT"]
        log = self.fake_log()
        self.assertIn("-A --inject-descriptors", log)
        self.assertRegex(log, r"-full\.pcap -A\n")
        self.assertEqual(self.saved()["steps"][0]["files_xrite"],
                         ["step1-idle-take1-USBPcap1-instrument.pcap"])

    def test_a_step_without_instrument_traffic_says_so(self):
        w = synth.UsbPcapWriter()
        w.describe(synth.KEYBOARD, 0x046D, 0xC31C, [(0x81, 3)])
        synth.keyboard_noise(w, 3)
        w.save(os.path.join(self.pcaps, "idle.pcap"))
        _session, screen = self.run_session(["", "e", "", "q"])
        flat = " ".join(screen.split())
        self.assertIn("NOTHING KEPT: this step's recording holds 12 records", flat)
        self.assertIn("The i1Pro 2's USB id (0971:2000) was not seen", flat)
        self.assertEqual(self.saved()["steps"][0]["files_xrite"], [])

    def test_whole_session_then_finish_analysis_and_delete(self):
        answers = []
        for n in range(1, 10):
            # 1.6.2: the measurement condition is asked from step 2 on
            answers += ["", "e", "did it"] + (["dual, M1"] if n == 4 else ["M0"] if n >= 2
                                               else []) + ["lights", ""]
        session, _screen = self.run_session(answers)
        self.assertEqual(session["ended"], "all steps done")
        with mock.patch.object(probe, "ask", lambda *_a, **_k: "yes"), \
                redirect_stdout(io.StringIO()):
            lines, analysis = probe.finish_session(session, self.folder)
        self.assertIn("The full recordings were deleted.", lines)
        self.assertFalse(os.path.exists(self.folder + "-FULL-do-not-send"))
        self.assertTrue(os.path.exists(os.path.join(self.folder, "analysis.txt")))
        self.assertIn("step 3: scan one strip (single scan, normal speed)", analysis)
        self.assertIn("operator, the lights: lights", analysis)
        self.assertIn("ONLY WITH THE RULER", analysis)
        self.assertIn("a no-ruler control ................... yes", analysis)
        # --analyze on the folder gives the same analysis.
        self.assertIn("DOES THIS RECORDING HOLD", probe.analyze_paths([self.folder]))

    def test_original_i1pro_session_has_no_light_question_and_no_dual(self):
        steps = [s["key"] for s in probe.steps_for("i1pro")]
        self.assertNotIn("scan-dual", steps)
        self.assertNotIn("noruler", steps)
        self.assertNotIn("i1pro", probe.PROFILES_WITH_LIGHTS)
        answers = ["", "e", "ok", "", "q"]
        _session, _screen = self.run_session(answers, profile="i1pro")
        self.assertNotIn("lights", self.saved()["steps"][0])

    def test_munki_session_steps(self):
        keys = [s["key"] for s in probe.steps_for("munki")]
        self.assertEqual(keys, ["idle", "calibrate", "scan-single", "scan-fast", "scan-slow",
                                "scan-fail", "spot"])


FAKE_SUDO = """#!/bin/bash
echo "sudo $*" >> "$FAKE_LOG"
while [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do shift; done
[ $# -eq 0 ] && exit 0
exec "$@"
"""

FAKE_TCPDUMP = """#!/bin/bash
echo "tcpdump $*" >> "$FAKE_LOG"
while [ $# -gt 0 ]; do
  case "$1" in -i) IF="$2"; shift;; -w) OUT="$2"; shift;; esac; shift
done
[ -f "$FAKE_PCAPS/$IF.pcap" ] && cat "$FAKE_PCAPS/$IF.pcap" > "$OUT"
trap 'echo "tcpdump $IF stopped" >> "$FAKE_LOG"; exit 0' TERM
while true; do sleep 0.05; done
"""


@unittest.skipIf(os.name == "nt", "the fake tools are bash scripts")
class LinuxRecorderTests(TempDirCase):
    """Linux usbmon through sudo + tcpdump, both fake."""

    def test_two_steps_on_usbmon(self):
        bin_dir = os.path.join(self.dir, "bin")
        pcaps = os.path.join(self.dir, "pcaps")
        os.mkdir(bin_dir)
        os.mkdir(pcaps)
        for name, body in (("sudo", FAKE_SUDO), ("tcpdump", FAKE_TCPDUMP)):
            path = os.path.join(bin_dir, name)
            with open(path, "w") as fh:
                fh.write(body)
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        log = os.path.join(self.dir, "fake.log")
        w = synth.UsbPcapWriter()
        synth.i1pro2_calibration(w)
        with open(os.path.join(pcaps, "usbmon1.pcap"), "wb") as fh:
            fh.write(w.pcap())          # the analyser does not care which tool wrote it
        env = {"PATH": bin_dir + os.pathsep + os.environ.get("PATH", ""),
               "FAKE_LOG": log, "FAKE_PCAPS": pcaps}
        folder = os.path.join(self.dir, "instrument-session-linux")
        answers = iter(["", "e", "ok", "", "", "", "q", "ok2", "", ""])
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(probe, "RECORDER_STARTUP_WAIT", 0.3), \
                mock.patch.object(probe, "SHORT_STEP_SECONDS", 0.0), \
                mock.patch.object(probe, "ask", lambda *_a, **_k: next(answers)), \
                redirect_stdout(io.StringIO()):
            recorder = probe.TcpdumpRecorder(["usbmon1"], "", mac=False)
            session = probe.run_instrument_session(recorder, folder, "munki")
        with open(log) as fh:
            text = fh.read()
        self.assertIn("sudo -v", text)
        self.assertIn("-U -i usbmon1 -w", text)
        self.assertEqual(text.count("tcpdump usbmon1 stopped"), 2)
        self.assertEqual(session["ended"], "stopped by the operator")
        self.assertEqual([s["number"] for s in session["steps"]], [1, 2])
        self.assertEqual(session["steps"][0]["files_xrite"],
                         ["step1-idle-take1-usbmon1-instrument.pcap"])


class ManualRecordingTests(TempDirCase):
    """A whole-session Wireshark recording cut at the tool's time marks."""

    def test_cut_by_time_marks_and_instrument_only_copy(self):
        folder = os.path.join(self.dir, "instrument-session-x")
        os.makedirs(folder)
        w = synth.UsbPcapWriter(t0=1_800_000_000.0)
        synth.i1pro2_calibration(w)
        t_cal_end = w.t
        w.tick(5)
        t_scan = w.t
        synth.i1pro2_scan(w, ruler=True, flags=0x0105)
        w.save(os.path.join(folder, "whole-session.pcapng"))
        session = {"kind": probe.SESSION_KIND, "family": "i1pro2", "recorder": "time marks only",
                   "whole_recording": "whole-session.pcapng", "ended": "all steps done",
                   "steps": [
                       {"number": 1, "key": "calibrate", "title": "calibrate",
                        "start_epoch": 1_800_000_000.0 - 1, "end_epoch": t_cal_end + 0.1},
                       {"number": 2, "key": "scan-single", "title": "scan one strip",
                        "start_epoch": t_scan - 0.5, "end_epoch": w.t + 1}]}
        with open(os.path.join(folder, "session.json"), "w") as fh:
            json.dump(session, fh)
        with mock.patch.object(probe, "ask", lambda *_a, **_k: "no"), \
                redirect_stdout(io.StringIO()):
            lines, analysis = probe.finish_session(session, folder)
        self.assertTrue(os.path.exists(os.path.join(folder, "whole-session-instrument.pcap")))
        self.assertFalse(os.path.exists(os.path.join(folder, "whole-session.pcapng")))
        self.assertTrue(os.path.exists(os.path.join(folder + "-FULL-do-not-send",
                                                    "whole-session.pcapng")))
        cal = analysis.split("--- step 1: calibrate ---")[1].split("--- step 2")[0]
        scan = analysis.split("--- step 2: scan one strip ---")[1]
        self.assertIn("0xC4 read EEPROM", cal)
        self.assertNotIn("RULER START", cal)
        self.assertIn("RULER START", scan)
        self.assertNotIn("0xC4 read EEPROM", scan)
        self.assertTrue(any("were kept" in l for l in lines))


class TextRules15(unittest.TestCase):

    def test_new_files_have_no_em_dash(self):
        for name in ("synth.py", "test_instrument.py", os.path.join("fixtures", "README.txt")):
            with open(os.path.join(HERE, name), encoding="utf-8") as fh:
                self.assertEqual(fh.read().count(chr(0x2014)), 0, name)

    def test_every_step_has_texts(self):
        for step in probe.SESSION_STEPS:
            for field in ("before", "during", "lights", "title"):
                self.assertTrue(step[field].strip(), (step["key"], field))
        for key in probe.PROFILE_NAMES:
            self.assertIn(key, probe.PROFILE_PURPOSE)
            self.assertTrue(probe.steps_for(key))

    def test_handheld_send_text_never_points_to_the_io_issue(self):
        text = probe.session_send_text("/x/instrument-session-1")
        self.assertNotIn("issues/129", text)
        self.assertIn("https://github.com/itsab1989/ChromIQ/issues/new", text)
        self.assertIn("forum thread where you heard about this tool", text)
        self.assertIn("private message to itsab1989 on the forum", text)
        self.assertIn("serial\n  number and its factory calibration data", text)
        self.assertIn("SEND-THIS-", text)
        self.assertIn("-FULL-do-not-send", text)
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        session_part = src[src.index("# 1.5: guided recording session"):
                           src.index("# main\n")]
        self.assertNotRegex(session_part, r"(?<!NEW_)ISSUE_URL")

    def test_no_promise_and_privacy_said_up_front(self):
        self.assertIn("We cannot promise", probe.PROMISE_TEXT)
        text = probe.privacy_text("i1pro2")
        self.assertIn("serial number", text)
        self.assertIn("factory", text)
        self.assertIn("Nothing is uploaded", text)


if __name__ == "__main__":
    unittest.main()
