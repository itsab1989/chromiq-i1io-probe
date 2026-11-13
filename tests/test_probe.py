"""Tests for chromiq_io_probe.py. Standard library only:

    python3 -m unittest discover -s tests -v

Nothing here talks to real hardware, runs sudo, or changes a setting. The
recording test puts FAKE sudo, ifconfig and tcpdump programs first on PATH.
"""

import io
import os
import platform
import stat
import struct
import sys
import tempfile
import textwrap
import time
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


# --------------------------------------------------------------------------
# synthetic macOS (Darwin, link type 266) recordings
# --------------------------------------------------------------------------

def darwin_record(direction, seq, vid, pid, payload, dlen=None):
    hdr = bytearray(40)
    hdr[2] = 40
    hdr[3] = direction
    struct.pack_into("<I", hdr, 4, len(payload) if dlen is None else dlen)
    struct.pack_into("<I", hdr, 0x10, seq)
    struct.pack_into("<HH", hdr, 0x24, vid, pid)
    return bytes(hdr) + payload


def pcap_bytes(records, linktype=266):
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)]
    for i, data in enumerate(records):
        out.append(struct.pack("<IIII", 1000 + i, 0, len(data), len(data)))
        out.append(data)
    return b"".join(out)


CONFIG_DESCRIPTOR = bytes([
    9, 2, 32, 0, 1, 1, 0, 0x80, 50,           # configuration
    9, 4, 0, 0, 2, 255, 0, 0, 0,              # interface 0, vendor-specific
    7, 5, 0x81, 2, 64, 0, 0,                  # endpoint 0x81 IN bulk 64
    7, 5, 0x02, 2, 64, 0, 0,                  # endpoint 0x02 OUT bulk 64
])


def io_records(zero=False):
    """A tiny i1iO conversation, plus a keyboard on the same bus."""
    def z(b):
        return bytes(len(b)) if zero else b
    return [
        darwin_record(0, 1, 0x0971, 0x2004, z(bytes([0x80, 6, 0, 2, 0, 0, 32, 0]))),
        darwin_record(1, 1, 0x0971, 0x2004, z(CONFIG_DESCRIPTOR)),
        darwin_record(0, 2, 0x0971, 0x2004, z(bytes([0xC0, 0xDE, 0, 0, 0, 0, 8, 0]))),
        darwin_record(1, 2, 0x0971, 0x2004, z(b"\x01\x02\x03\x04\x05\x06\x07\x08")),
        darwin_record(1, 99, 0x0971, 0x2000, z(bytes(range(1, 129)))),
        darwin_record(1, 7, 0x0483, 0x1234, b"\x00\x00\x04\x00\x00\x00\x00\x00"),
    ]


def keyboard_only_records():
    return [darwin_record(1, 7, 0x0483, 0x1234, b"\x00\x00\x04\x00\x00\x00\x00\x00")]


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------

class DetectionTests(unittest.TestCase):

    def test_usbhost_json_finds_table_and_instrument(self):
        devs = probe.parse_system_profiler_json(fixture("macos-sp-usbhost-io2.json"))
        xrite = [d for d in devs if d["vid"] == 0x0971]
        self.assertEqual(sorted(d["pid"] for d in xrite), [0x2000, 0x2004])
        io = [d for d in xrite if d["pid"] == 0x2004][0]
        self.assertEqual(io["location"], 0x02210000)
        self.assertIn("General Purpose USB Hub", io["parents"][-1])

    def test_empty_legacy_list_is_read_as_empty_not_as_failure(self):
        self.assertEqual(
            probe.parse_system_profiler_json(fixture("macos-sp-usb-legacy-empty.json")), [])

    def test_legacy_format_still_understood(self):
        legacy = ('{"SPUSBDataType": [{"_name": "USB Bus", "_items": [{"_name": "Eye-One iO",'
                  ' "vendor_id": "0x0971  (X-Rite Inc.)", "product_id": "0x2004",'
                  ' "location_id": "0x02210000 / 2", "bcd_device": "4.00"}]}]}')
        devs = probe.parse_system_profiler_json(legacy)
        self.assertEqual((devs[0]["vid"], devs[0]["pid"], devs[0]["location"]),
                         (0x0971, 0x2004, 0x02210000))

    def test_ioreg_tree_finds_devices_and_hub(self):
        devs = probe.ioreg_usb_devices(fixture("macos-ioreg-iousb-io2.txt"))
        xrite = {d["pid"]: d for d in devs if d["vid"] == 0x0971}
        self.assertEqual(set(xrite), {0x2000, 0x2004})
        self.assertEqual(xrite[0x2004]["revision"], "4.00")
        self.assertIn("General Purpose USB Hub", xrite[0x2004]["parents"][-1])
        self.assertIn("AppleEmbeddedUSBXHCIFL1100", xrite[0x2004]["parents"][0])

    def test_volunteer_case_is_no_longer_reported_as_no_devices(self):
        """1.3: SPUSBDataType empty -> 'NO X-RITE DEVICES SEEN' although ioreg
        listed the table. 1.4 must believe ioreg."""
        result = probe.detect_xrite([
            ("host", "[not available on this system: system_profiler]",
             probe.parse_system_profiler_json),
            ("legacy", fixture("macos-sp-usb-legacy-empty.json"),
             probe.parse_system_profiler_json),
            ("ioreg", fixture("macos-ioreg-iousb-io2.txt"), probe.ioreg_usb_devices),
        ])
        text = probe.format_detection(result)
        self.assertFalse(text.startswith("NO X-RITE"), text)
        self.assertIn("0971:2004", text)
        self.assertIn("i1iO table", text)
        self.assertIn("share one hub", text)
        self.assertIn("legacy:\n      returned an empty list", text)

    def test_all_sources_merge_without_duplicates(self):
        result = probe.detect_xrite([
            ("host", fixture("macos-sp-usbhost-io2.json"), probe.parse_system_profiler_json),
            ("legacy", fixture("macos-sp-usb-legacy-empty.json"),
             probe.parse_system_profiler_json),
            ("ioreg", fixture("macos-ioreg-iousb-io2.txt"), probe.ioreg_usb_devices),
        ])
        self.assertEqual(len(result["devices"]), 2)
        for dev in result["devices"]:
            self.assertEqual(dev["seen_by"], ["host", "ioreg"])

    def test_nothing_anywhere_says_no_devices(self):
        result = probe.detect_xrite([
            ("legacy", fixture("macos-sp-usb-legacy-empty.json"),
             probe.parse_system_profiler_json)])
        self.assertTrue(probe.format_detection(result).startswith("NO X-RITE DEVICES SEEN"))

    def test_id_labels_come_from_evidence_only(self):
        self.assertIn("i1iO", probe.pid_label(0x2004))
        self.assertIn("i1Pro 2", probe.pid_label(0x2000))
        # 1.3 called 0x2001 "i1Pro 2 / i1Pro 3 family" without evidence.
        self.assertIn("unknown", probe.pid_label(0x2001))
        self.assertIn("unknown", probe.pid_label(0x2006))

    def test_bus_guess_from_location_id(self):
        self.assertEqual(probe.bus_guess(0x02210000), "XHC2")
        self.assertEqual(probe.bus_guess(0x14100000), "XHC20")    # Intel
        self.assertIsNone(probe.bus_guess(None))


class DescriptionTests(unittest.TestCase):

    def test_interfaces_and_owner_listed_and_endpoints_honestly_missing(self):
        text = probe.describe_xrite_usb(fixture("macos-ioreg-iousb-io2.txt"),
                                        fixture("macos-ioreg-service-io2.txt"))
        self.assertIn("--- Eye-One iO ---", text)
        self.assertIn("idProduct = 0x2004", text)
        self.assertIn("bInterfaceClass = 255 (vendor-specific)", text)
        self.assertIn("bNumEndpoints = 2", text)
        self.assertIn("X-Rite Device Ser", text)
        self.assertIn("will be in a USB recording", text)
        self.assertNotIn("Generic Keyboard", text)


class PrivacyTests(unittest.TestCase):

    def test_serials_and_usb_signature_are_hashed(self):
        for name in ("macos-ioreg-iousb-io2.txt", "macos-sp-usbhost-io2.json",
                     "macos-ioreg-service-io2.txt"):
            out = probe.scrub(fixture(name))
            self.assertNotIn("FAKESERIAL123", out, name)
            # "FAKESN" as hex inside UsbDeviceSignature
            self.assertNotIn("46414b45534e", out.lower(), name)


# --------------------------------------------------------------------------
# SIP and the "recording not possible" texts
# --------------------------------------------------------------------------

class SipTests(unittest.TestCase):

    def test_parse_csrutil(self):
        self.assertEqual(probe.parse_csrutil(
            "System Integrity Protection status: enabled."), "on")
        self.assertEqual(probe.parse_csrutil(
            "System Integrity Protection status: disabled."), "off")
        self.assertEqual(probe.parse_csrutil(textwrap.dedent("""\
            System Integrity Protection status: unknown (Custom Configuration).

            Configuration:
            \tApple Internal: disabled
            \tKext Signing: disabled
            """)), "partly")
        self.assertEqual(probe.parse_csrutil("[not available on this system: csrutil]"),
                         "unknown")

    def readiness(self, sip="on", interfaces=(), arm=True):
        return {"cpu": {"apple_silicon": arm, "brand": "test"}, "sip": sip,
                "csrutil": "x", "interfaces": list(interfaces), "tcpdump": "/usr/sbin/tcpdump",
                "possible": False, "bus_guesses": ["XHC2"],
                "reasons": ["System Integrity Protection (SIP) is switched on."]}

    def test_not_possible_text_has_all_routes_and_warnings(self):
        text = probe.recording_not_possible_text(self.readiness())
        for needle in ("Why:", "WINDOWS PC", "USBPcap", "Windows 11 version 25H2",
                       "Windows on ARM", "csrutil disable", "csrutil enable",
                       "csrutil status", "honest risk", "HARDWARE USB SNIFFER",
                       "Cynthion", "Taradov", "3.8.7", "Loading startup options",
                       "every data byte was zero"):
            self.assertIn(needle, text)
        self.assertTrue(text.rstrip().endswith("(steps above)."))

    def test_intel_steps_use_command_r(self):
        text = probe.recording_not_possible_text(self.readiness(arm=False))
        self.assertIn("Command key and the R key", text)
        self.assertNotIn("Loading startup options", text)

    def test_no_claim_that_macos_already_has_everything(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("already includes everything", src)
        self.assertNotIn("already ships everything", src)
        self.assertNotIn("already has everything", src)

    def test_i1profiler_version_note(self):
        self.assertIn("no longer supports", probe.i1profiler_version_note("3.8.7"))
        self.assertIn("no longer supports", probe.i1profiler_version_note("3.9"))
        self.assertIn("still supports", probe.i1profiler_version_note("3.8.6"))


# --------------------------------------------------------------------------
# capture checks
# --------------------------------------------------------------------------

class CaptureTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, records, linktype=266):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(pcap_bytes(records, linktype))
        return path

    def test_good_capture(self):
        check = probe.check_capture(self.write("good.pcap", io_records()))
        self.assertEqual(check["code"], "ok", check)
        self.assertEqual(check["xrite_packets"], 5)

    def test_all_zero_payload_is_called_out(self):
        check = probe.check_capture(self.write("zero.pcap", io_records(zero=True)))
        self.assertEqual(check["code"], "all-zero", check)
        self.assertIn("ALL-ZERO", check["verdict"])
        summary = probe.summarize_captures([self.write("zero2.pcap", io_records(zero=True))])
        self.assertIn("every data byte was zero", summary)

    def test_other_bus_has_no_xrite(self):
        check = probe.check_capture(self.write("kb.pcap", keyboard_only_records()))
        self.assertEqual(check["code"], "no-xrite")

    def test_filter_keeps_only_xrite(self):
        src = self.write("full.pcap", io_records())
        dst = os.path.join(self.tmp.name, "x.pcap")
        self.assertEqual(probe.filter_xrite_capture(src, dst), 5)
        _lt, recs = probe._read_pcap(dst)
        self.assertTrue(all(probe._darwin_vid(d) == 0x0971 for _t, d in recs))

    def test_endpoints_decoded_from_recording(self):
        summary = probe.summarize_captures([self.write("g.pcap", io_records())])
        self.assertIn("endpoint 0x81 (IN), bulk, max packet 64 bytes", summary)
        self.assertIn("endpoint 0x02 (OUT), bulk", summary)
        self.assertIn("VERDICT: OK", summary)

    def test_pcapng_is_readable(self):
        def block(btype, body):
            pad = (-len(body)) % 4
            total = 12 + len(body) + pad
            return struct.pack("<II", btype, total) + body + bytes(pad) + struct.pack("<I", total)
        shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        idb = block(1, struct.pack("<HHI", 249, 0, 65535))
        pkt = bytes([27, 0]) + bytes(25) + b"\x11\x22"
        epb = block(6, struct.pack("<IIIII", 0, 0, 0, len(pkt), len(pkt)) + pkt)
        path = os.path.join(self.tmp.name, "w.pcapng")
        with open(path, "wb") as fh:
            fh.write(shb + idb + epb)
        lt, recs = probe._read_pcap(path)
        self.assertEqual((lt, len(recs)), (249, 1))
        self.assertEqual(probe.check_capture(path)["code"], "ok")


# --------------------------------------------------------------------------
# the guided recording, with fake sudo / ifconfig / tcpdump / csrutil
# --------------------------------------------------------------------------

FAKE_SUDO = """#!/bin/bash
echo "sudo $*" >> "$FAKE_LOG"
while [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do shift; done
[ $# -eq 0 ] && exit 0
exec "$@"
"""

FAKE_IFCONFIG = """#!/bin/bash
echo "ifconfig $*" >> "$FAKE_LOG"
if [ "$1" = "-l" ]; then echo "lo0 en0 XHC0 XHC2"; exit 0; fi
state="$FAKE_STATE/$1"
if [ "$2" = "up" ]; then touch "$state"; exit 0; fi
if [ "$2" = "down" ]; then rm -f "$state"; exit 0; fi
if [ -f "$state" ]; then echo "$1: flags=1<UP> mtu 0"; else echo "$1: flags=0<> mtu 0"; fi
"""

FAKE_TCPDUMP = """#!/bin/bash
echo "tcpdump $*" >> "$FAKE_LOG"
while [ $# -gt 0 ]; do
  case "$1" in -i) IF="$2"; shift;; -w) OUT="$2"; shift;; esac; shift
done
[ -f "$FAKE_PCAPS/$IF.pcap" ] && cat "$FAKE_PCAPS/$IF.pcap" > "$OUT"
trap 'echo "tcpdump $IF stopped" >> "$FAKE_LOG"; exit 0' TERM
while true; do sleep 0.1; done
"""

FAKE_CSRUTIL = """#!/bin/bash
echo "System Integrity Protection status: $FAKE_SIP."
"""


@unittest.skipIf(os.name == "nt", "the fake tools are bash scripts")
class RecordingTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = self.tmp.name
        self.bin = os.path.join(t, "bin")
        self.state = os.path.join(t, "state")
        self.pcaps = os.path.join(t, "pcaps")
        self.out = os.path.join(t, "out")
        for d in (self.bin, self.state, self.pcaps, self.out):
            os.mkdir(d)
        self.log = os.path.join(t, "fake.log")
        for name, body in (("sudo", FAKE_SUDO), ("ifconfig", FAKE_IFCONFIG),
                           ("tcpdump", FAKE_TCPDUMP), ("csrutil", FAKE_CSRUTIL)):
            path = os.path.join(self.bin, name)
            with open(path, "w") as fh:
                fh.write(body)
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        env = {"PATH": self.bin + os.pathsep + os.environ.get("PATH", ""),
               "FAKE_LOG": self.log, "FAKE_STATE": self.state,
               "FAKE_PCAPS": self.pcaps, "FAKE_SIP": "disabled"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        for p in (mock.patch.object(probe, "RECORDER_STARTUP_WAIT", 0.5),
                  mock.patch.object(probe, "_writable_dir", lambda: self.out)):
            p.start()
            self.addCleanup(p.stop)
        probe._SECTIONS.clear()
        probe._READINESS.clear()

    def fake_log(self):
        with open(self.log) as fh:
            return fh.read()

    def run_recording(self, answers, xhc2_records, xhc0_records):
        with open(os.path.join(self.pcaps, "XHC2.pcap"), "wb") as fh:
            fh.write(pcap_bytes(xhc2_records))
        with open(os.path.join(self.pcaps, "XHC0.pcap"), "wb") as fh:
            fh.write(pcap_bytes(xhc0_records))
        readiness = probe.macos_recording_readiness(
            [{"location": 0x02210000}])
        self.assertTrue(readiness["possible"], readiness)
        self.assertEqual(readiness["sip"], "off")
        self.assertEqual(readiness["interfaces"], ["XHC0", "XHC2"])
        replies = iter(answers)
        buf = io.StringIO()
        with mock.patch.object(probe, "ask", lambda *_a, **_k: next(replies)), \
                redirect_stdout(buf):
            probe.macos_guided_recording(readiness)
        return buf.getvalue()

    def test_full_recording_with_real_data(self):
        # yes to start; per step: start, stop, arm, go on (x4); notes; delete
        # the full recordings; the five questions (1.5.4)
        answers = ["yes"] + ["", "e", "", ""] * 5 + [""] + ["yes"] + [""] * 8
        screen = self.run_recording(answers, io_records(), keyboard_only_records())
        log = self.fake_log()
        for iface in ("XHC0", "XHC2"):
            self.assertIn(f"ifconfig {iface} up", log)
            self.assertIn(f"ifconfig {iface} down", log)
            self.assertIn(f"tcpdump {iface} stopped", log)
            self.assertFalse(os.path.exists(os.path.join(self.state, iface)))
        self.assertIn("sudo -v", log)
        self.assertIn("Switched XHC2, XHC0 off again.", screen)
        self.assertIn("csrutil enable", screen)
        result = dict(probe._SECTIONS)["Stage 2: macOS recording result"]
        self.assertIn("XHC2: 6 packets, 5 of them from X-Rite devices", result)
        self.assertIn("OK: real data recorded", result)
        self.assertIn("No X-Rite traffic on this bus", result)
        self.assertIn("full recordings were deleted", result)
        left = sorted(os.listdir(self.out))
        self.assertEqual(len(left), 1, left)
        self.assertTrue(left[0].endswith("-XHC2-xrite.pcap"))

    def test_each_step_is_checked_while_the_recording_runs(self):
        """1.5.4: the table's commands of a step are looked for in the growing
        recording right after the step, and again in the finished copy."""
        sys.path.insert(0, HERE)
        import synth_io as sio
        appended = []

        def fake_ask(prompt, interruptible=False):
            if prompt.strip() == ">" and not appended:
                # while step 1 runs, "i1Profiler" talks to the table: append
                # the conversation to the file tcpdump is writing
                full = [f for f in os.listdir(self.out) if f.endswith("XHC2-full.pcap")][0]
                w = sio.DarwinWriter(t0=time.time())
                w.simple("c4", data="B8")
                w.move("m0", -1200, 1500, 300, seconds=0.05)
                w.simple("c3")
                with open(os.path.join(self.out, full), "ab") as fh:
                    fh.write(w.pcap()[24:])
                appended.append(w.t)
                time.sleep(max(0.0, w.t - time.time()) + 0.05)
                return "e"
            return answers.pop(0) if answers else ""
        answers = ["yes", ""] + ["", ""] + ["", "e", "", ""] * 4 + [""] + ["yes"] + [""] * 8
        with open(os.path.join(self.pcaps, "XHC2.pcap"), "wb") as fh:
            fh.write(pcap_bytes(io_records()))
        readiness = probe.macos_recording_readiness([{"location": 0x02210000}])
        buf = io.StringIO()
        with mock.patch.object(probe, "ask", fake_ask), redirect_stdout(buf):
            probe.macos_guided_recording(readiness)
        screen = buf.getvalue()
        self.assertIn("HAVE YOU GOT EVERYTHING READY?", screen)
        self.assertRegex(screen, r"CHECK: this step recorded \d+ commands to the table: good")
        self.assertIn("CHECK: no table command was recorded in this step: please repeat it",
                      screen)
        result = dict(probe._SECTIONS)["Stage 2: macOS recording result"]
        self.assertRegex(result, r"One row of a chart that scans in one pass: this step recorded \d+ "
                                 r"commands to the table: good")
        glance = dict(probe._SECTIONS)["Stage 2: the steps at a glance"]
        self.assertIn("Still missing: A small chart to the end, fastest setting.", glance)
        self.assertLess(screen.index("THE STEPS AT A GLANCE"), screen.rindex("csrutil enable"))
        timeline = dict(probe._SECTIONS)["Stage 2: annotated capture timeline"]
        self.assertIn("session start (UTC epoch seconds):", timeline)

    def test_all_zero_recording_is_reported_plainly(self):
        answers = ["yes"] + ["", "e", "", ""] * 5 + [""] + ["no"] + [""] * 8
        self.run_recording(answers, io_records(zero=True), keyboard_only_records())
        result = dict(probe._SECTIONS)["Stage 2: macOS recording result"]
        self.assertIn("ALL-ZERO", result)
        self.assertIn("were kept. Please do not send them", result)

    def test_declining_runs_nothing_privileged(self):
        screen = self.run_recording(["no"], io_records(), [])
        self.assertNotIn("sudo", self.fake_log())
        self.assertIn("No recording made", screen)

    def test_interfaces_come_down_after_ctrl_c(self):
        def answers():
            yield "yes"
            yield ""
            raise KeyboardInterrupt
        gen = answers()

        def fake_ask(_prompt, interruptible=False):
            try:
                return next(gen)
            except StopIteration:
                return ""
        with open(os.path.join(self.pcaps, "XHC2.pcap"), "wb") as fh:
            fh.write(pcap_bytes(io_records()))
        readiness = probe.macos_recording_readiness([{"location": 0x02210000}])
        with mock.patch.object(probe, "ask", fake_ask), redirect_stdout(io.StringIO()):
            probe.macos_guided_recording(readiness)
        log = self.fake_log()
        self.assertIn("ifconfig XHC2 down", log)
        self.assertIn("ifconfig XHC0 down", log)
        self.assertIn("recording ended early: Ctrl-C",
                      dict(probe._SECTIONS)["Stage 2: annotated capture timeline"])

    def test_sip_on_means_not_possible(self):
        os.environ["FAKE_SIP"] = "enabled"
        r = probe.macos_recording_readiness([])
        self.assertFalse(r["possible"])
        self.assertIn("switched on", r["reasons"][0])


# --------------------------------------------------------------------------
# house rules
# --------------------------------------------------------------------------

class TextRules(unittest.TestCase):

    def test_no_em_dash_anywhere(self):
        names = ["chromiq_io_probe.py", "README.md", "CHANGELOG.md", "READ ME FIRST.txt",
                 "Start-macOS.command", "Start-Linux.sh", "Start-Windows.bat",
                 os.path.join(".github", "workflows", "build.yml"),
                 os.path.join("tests", "test_probe.py"),
                 os.path.join("tests", "test_instrument.py"), os.path.join("tests", "synth.py"),
                 os.path.join("tests", "test_first_report.py")]
        for name in names:
            path = os.path.join(ROOT, name)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as fh:
                count = fh.read().count(chr(0x2014))
            self.assertEqual(count, 0, f"{name} has {count} em dash(es)")

    def test_version(self):
        self.assertEqual(probe.PROBE_VERSION, "1.5.5")


@unittest.skipUnless(platform.system() == "Darwin", "macOS only")
class RealMacTests(unittest.TestCase):
    """Read-only checks against the Mac the tests run on."""

    def test_detection_runs_against_this_mac(self):
        result = probe.macos_detection()
        labels = [label for label, _status in result["sources"]]
        self.assertEqual(len(labels), 3)
        host_status = dict(result["sources"])[probe.MACOS_SOURCES[0][0]]
        # On current macOS the new name is the one with data.
        self.assertNotEqual(host_status, "could not be read")

    def test_readiness_runs(self):
        probe._READINESS.clear()
        r = probe.macos_recording_readiness([])
        self.assertIn(r["sip"], ("on", "off", "partly", "unknown"))
        if r["sip"] == "on":
            self.assertFalse(r["possible"])


if __name__ == "__main__":
    unittest.main()
