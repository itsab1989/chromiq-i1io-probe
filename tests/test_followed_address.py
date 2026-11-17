"""1.6.6 (a): the instrument's own traffic under another USB address.

A tester's three i1Pro 2 sessions (tool 1.6.5, Windows 11, USBPcap attached)
kept nothing. The reports showed, per step: the i1Pro 2's id at 1 address
with 6 records (its injected description) and none of its own requests or
data, and thousands of records on the i1Pro 2's endpoint numbers at an
address the recording's device list gives to a USB hub. These tests rebuild
that shape from INVENTED bytes (tests/synth_follow.py) and prove:

  * the shape: recording_facts() reports it exactly as his reports did;
  * the fix: the check follows the instrument and keeps its traffic, and
    says so with the counts;
  * the privacy: a keyboard's, a disk's, a Bluetooth adapter's and a hub's
    own records never enter the instrument-only copy, also when the
    instrument's traffic lands on THEIR address and on endpoint numbers
    they use themselves;
  * the limits: no following without the other device's own endpoints,
    without the family's own commands, or when that device's traffic shows
    on endpoints it does not have.

    python3 -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import synth_follow as sf  # noqa: E402
from synth import UsbPcapWriter, XFER_INT  # noqa: E402

LT = probe.LINKTYPE_USBPCAP


def kept(w, profile="i1pro2"):
    att = probe.attribute_records(LT, w.records, profile)
    return [r for r, k in zip(w.records, att["keep"]) if k], att


def blob(records) -> bytes:
    return b"".join(d for _t, d in records)


def fields(records):
    return [probe._record_fields(LT, d) for _t, d in records]          # noqa: SLF001


class TheTestersShape(unittest.TestCase):
    """JOB 1: the synthetic capture reproduces what his reports said."""

    def test_facts_read_like_his_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = sf.swapped_step(hub_back=False).save(os.path.join(tmp, "s.pcap"))
            facts = probe.recording_facts(path, "i1pro2")
            back = sf.swapped_step().save(os.path.join(tmp, "b.pcap"))
            facts_back = probe.recording_facts(back, "i1pro2")
        # his: "the i1Pro 2 (0971:2000): 1 device, 6 records ... none of them
        # its own requests or data"
        self.assertEqual(facts["family_ids"], {"0971:2000": [1, 6, 0]})
        self.assertEqual(facts["classes"]["the i1Pro 2 (0971:2000)"], [1, 6])
        # his: "On the i1Pro 2's endpoint numbers ... at other addresses:
        # ... USB hub: <thousands of> records"
        self.assertGreater(facts["family_eps"].get("USB hub", 0), 0)
        # his step 2 of one session: the hub's own traffic at the instrument's
        # address (left out there as "hub" and "endpoint")
        self.assertEqual(facts_back["family_ids"]["0971:2000"][0], 1)
        self.assertGreater(facts_back["family_ids"]["0971:2000"][2], 0)
        text = "\n".join(probe.facts_lines(dict(facts, files=1), "i1pro2"))
        self.assertIn("none of them its own requests or data", text)
        self.assertIn("- USB hub:", text)

    def test_without_following_the_described_address_holds_nothing_of_its_own(self):
        """What 1.6.5 saw: at the described address only the description and
        the hub's own traffic (the left-out kinds of his step 2)."""
        _recs, att = kept(sf.swapped_step())
        self.assertEqual(set(att["left_out"]), {"hub", "endpoint"})
        at_instr = [f for f in fields(_recs) if f[0] == (1, sf.INSTR)]
        self.assertEqual(len(at_instr), 6)                 # the description only
        self.assertTrue(all(f[2] == "control" for f in at_instr))


class FollowsTheInstrument(unittest.TestCase):

    def test_check_follows_and_keeps(self):
        w = sf.swapped_step()
        with tempfile.TemporaryDirectory() as tmp:
            path = w.save(os.path.join(tmp, "step2-calibrate-take1-USBPcap1-full.pcap"))
            check = probe.check_capture(path, "i1pro2")
            dst = os.path.join(tmp, "c.pcap")
            n = probe.filter_xrite_capture(path, dst, "i1pro2")
            _lt, copy = probe._read_pcap(dst)                           # noqa: SLF001
        self.assertEqual(check["code"], "ok", check["verdict"])
        self.assertGreater(check["activity"], 0)
        verdict = " ".join(check["verdict"].split())
        self.assertIn("FOLLOWED", verdict)
        self.assertIn("a USB hub", verdict)
        self.assertIn("very likely, but not certain", verdict)
        item = check["followed"]["followed"][0]
        self.assertEqual(item["address"], [1, sf.HUB])
        self.assertEqual((item["requests"], item["data"]), (5, 9))
        self.assertEqual(n, len(copy))
        # every record of the instrument's own work at the hub's address is
        # in the copy: 5 commands of 3 records, 9 data transfers of 2
        at_hub = [f for f in fields(copy) if f[0] == (1, sf.HUB)]
        self.assertEqual(len(at_hub), 5 * 3 + 9 * 2)
        # and nothing of the hub's own: no class request, no 0x81
        self.assertFalse(any(f[1] == 0x81 for f in fields(copy)))
        self.assertNotIn(b"\x03\x01\x00\x00", blob(copy))

    def test_swap_text_does_not_ask_to_unplug_other_devices(self):
        check = probe.check_capture(self._save(sf.swapped_step()), "i1pro2")
        self.assertIn("other half of the same address mix-up", " ".join(check["verdict"].split()))
        self.assertNotIn("every other USB device unplugged", check["verdict"])

    def test_session_analysis_reads_the_copy(self):
        w = sf.swapped_step(readings=4)
        with tempfile.TemporaryDirectory() as tmp:
            src = w.save(os.path.join(tmp, "full.pcap"))
            dst = os.path.join(tmp, "step4-scan-dual-take1-USBPcap1-instrument.pcap")
            probe.filter_xrite_capture(src, dst, "i1pro2")
            text = probe.analyze_paths([dst])
        self.assertIn("instrument family: i1Pro 2 (Rev E)", text)
        self.assertIn("0xD4 trigger measurement", text)
        self.assertIn("4 readings", text)

    def test_the_hub_at_the_instruments_address_does_not_hide_the_analysis(self):
        """The other half of the swap (his step 2): the hub's traffic at the
        instrument's address. Nothing of the instrument's own work was kept
        there, so nothing can hide: decoded values, never raw contents."""
        with tempfile.TemporaryDirectory() as tmp:
            folder = os.path.join(tmp, "instrument-session-x")
            full = folder + probe.FULL_SUFFIX
            os.makedirs(folder)
            os.makedirs(full)
            fn = "step2-calibrate-take1-USBPcap1-full.pcap"
            sf.swapped_step().save(os.path.join(full, fn))
            entry = {"number": 2, "key": "calibrate", "title": "calibrate", "take": 1,
                     "files_full": [fn]}
            probe.check_step_files(entry, full, folder, "i1pro2")
            self.assertTrue(entry["explained"])
            self.assertEqual(set(entry["left_out"]), {"hub", "endpoint"})
            with open(os.path.join(folder, "session.json"), "w", encoding="utf-8") as fh:
                json.dump({"kind": probe.SESSION_KIND, "family": "i1pro2", "steps": [entry]},
                          fh)
            text = probe.summarize_session([folder])
        self.assertNotIn(probe.WITHHELD_TEXT[:40], text)
        self.assertIn("decoded values only", " ".join(text.split()))
        self.assertIn("0xD4 trigger measurement", text)

    def test_own_work_at_the_described_address_keeps_withholding(self):
        """When the instrument also worked at its described address, the
        other device's traffic there may hide among it: counts only."""
        w = sf.swapped_step()
        sf.i1pro2_work(w, sf.INSTR, readings=1)
        _copy, att = kept(w)
        self.assertFalse(att["explained"])
        self.assertTrue(probe.hide_contents(att["left_out"], att["explained"]))

    def _save(self, w):
        tmp = tempfile.TemporaryDirectory(prefix="probe-test-")
        self.addCleanup(tmp.cleanup)
        return w.save(os.path.join(tmp.name, "s.pcap"))


class OtherDevicesNeverEnterTheCopy(unittest.TestCase):
    """The privacy proof for (a): the instrument's stale address lands on a
    keyboard, a disk or a Bluetooth adapter, also on endpoint numbers the
    instrument has as well. Their marked bytes never reach the copy."""

    MARKERS = (sf.KEY_MARKER, sf.DISK_MARKER[:19], sf.BT_MARKER[:17], b"USBC", b"USBS")

    def assert_clean(self, records):
        data = blob(records)
        for marker in self.MARKERS:
            self.assertNotIn(marker, data)

    def test_the_testers_shape_with_every_kind_beside_it(self):
        copy, att = kept(sf.swapped_step())
        self.assert_clean(copy)
        keys = {f[0] for f in fields(copy)}
        self.assertEqual(keys, {(1, sf.INSTR), (1, sf.HUB)})

    def assert_not_kept_but_said(self, att, as_word, copy):
        """The strict rule (1.6.6 review): under another kind of device's
        address nothing is kept, but the check says what it saw."""
        self.assertEqual(att["followed"]["followed"], [])
        item = att["followed"]["refused"][0]
        self.assertEqual(item["as"], as_word)
        self.assertIn("only under a USB hub's address", item["why"])
        self.assertEqual({f[0] for f in fields(copy)}, {(1, sf.INSTR)})
        text = " ".join(probe.followed_text(att["followed"]).split())
        self.assertIn("NOT KEPT: traffic that looks like the instrument's", text)
        self.assertIn(f"was seen under an address this recording gives to a {as_word}; "
                      "it was not kept, to be safe", text)
        self.assertIn("Please tell us about it", text)
        screen = " ".join(" ".join(probe.followed_screen_lines(att["followed"])).split())
        self.assertIn("it was not kept, to be safe", screen)
        self.assertIn("Please tell us about it", screen)
        for line in probe.followed_screen_lines(att["followed"]):
            self.assertLessEqual(len("  " + line), 80, line)

    def test_on_a_keyboards_address_and_its_endpoint_0x84(self):
        """Strict rule: a keyboard's address is never followed (it was
        followed before the review, with the 0x84 overlap left out)."""
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.keyboard(w, eps=[(0x84, 3)])                 # the i1Pro 2's button number
        sf.i1pro2_work(w, sf.KEYBOARD)
        sf.keyboard_work(w, sf.KEYBOARD, ep=0x84)
        copy, att = kept(w)
        self.assert_clean(copy)
        self.assert_not_kept_but_said(att, "keyboard, mouse or other input device", copy)

    def test_on_a_disks_address_and_its_endpoints(self):
        """Strict rule: a disk's address is never followed."""
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.disk(w, eps=[(0x82, 2), (0x01, 2)])         # the i1Pro 2's 0x82 and 0x01 too
        sf.i1pro2_work(w, sf.DISK)
        sf.disk_work(w, sf.DISK, out_ep=0x01, in_ep=0x82)
        copy, att = kept(w)
        self.assert_clean(copy)
        self.assert_not_kept_but_said(att, "USB disk or memory stick", copy)

    def test_a_vendor_device_alone_is_never_the_instrument(self):
        """The reviewer's WiFi case: a non-X-Rite device at its own,
        correct address sends vendor requests whose numbers the i1Pro uses
        too, and no instrument works anywhere. Nothing kept, no 'OK'."""
        for describe_hub in (True, False):
            with self.subTest(hub=describe_hub):
                w = UsbPcapWriter()
                sf.instrument(w)
                if describe_hub:
                    sf.hub(w)
                else:
                    sf.describe(w, sf.HUB, 0x0E8D, 0x7961, 0, 0xFF, [(0x84, 2), (0x08, 2)])
                for _ in range(3):
                    w.vendor_in(sf.HUB, 0xC0, sf.BT_MARKER[:8])
                    w.vendor_out(sf.HUB, 0xCA, sf.BT_MARKER[:4])
                copy, att = kept(w)
                self.assertIsNone(att["followed"])
                self.assertNotIn(sf.BT_MARKER[:8], blob(copy))
                with tempfile.TemporaryDirectory() as tmp:
                    check = probe.check_capture(w.save(os.path.join(tmp, "v.pcap")), "i1pro2")
                self.assertEqual(check["code"], "empty-step")

    def test_an_undescribed_configuration_is_not_followed_but_said(self):
        """The reviewer's s16 / s24 shape: a vendor device whose
        configuration the recording does not hold; requests and bulk data on
        0x82. Not kept; said."""
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.describe(w, sf.HUB, 0x0E8D, 0x7961, 0, 0xFF, [], config=False)
        w.vendor_out(sf.HUB, 0xCA, sf.BT_MARKER[:4])
        w.vendor_in(sf.HUB, 0xD9, sf.BT_MARKER[:4])
        w.bulk_in(sf.HUB, 0x82, sf.BT_MARKER)
        copy, att = kept(w)
        self.assertNotIn(sf.BT_MARKER[:8], blob(copy))
        self.assertEqual(att["followed"]["followed"], [])
        self.assertIn("configuration is not in the recording",
                      att["followed"]["refused"][0]["why"])
        self.assertIn("it was not kept, to be safe", probe.followed_text(att["followed"]))

    def test_on_a_bluetooth_adapters_address(self):
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.bluetooth(w)
        sf.i1pro2_work(w, sf.BLUETOOTH)
        sf.bluetooth_work(w, sf.BLUETOOTH)
        copy, att = kept(w)
        self.assert_clean(copy)
        self.assertFalse(any(f[1] in (0x81, 0x82, 0x02) for f in fields(copy)
                             if f[0] == (1, sf.BLUETOOTH)))
        # its HCI command is a class request: never kept
        self.assertNotIn(b"\x03\x0c\x00", blob(copy))

    def test_other_devices_alone_are_never_followed(self):
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.hub(w)
        sf.keyboard(w)
        sf.disk(w)
        sf.bluetooth(w)
        for _ in range(3):
            sf.hub_work(w, sf.HUB)
            sf.keyboard_work(w, sf.KEYBOARD)
            sf.disk_work(w, sf.DISK)
            sf.bluetooth_work(w, sf.BLUETOOTH)
        copy, att = kept(w)
        self.assertIsNone(att["followed"])
        self.assertEqual({f[0] for f in fields(copy)}, {(1, sf.INSTR)})
        self.assert_clean(copy)

    def test_a_disk_on_endpoints_it_does_not_have_stops_following(self):
        """Mass-storage commands where that device has no endpoint: the
        address is not followed at all."""
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.hub(w)
        sf.i1pro2_work(w, sf.HUB)
        sf.disk_work(w, sf.HUB, out_ep=0x03, in_ep=0x82)   # on the instrument's numbers
        copy, att = kept(w)
        self.assert_clean(copy)
        self.assertEqual(att["followed"]["followed"], [])
        self.assertIn("USB disk", att["followed"]["refused"][0]["why"])
        self.assertEqual({f[0] for f in fields(copy)}, {(1, sf.INSTR)})

    def test_a_disk_under_the_same_stale_address_on_its_own_pair(self):
        """Seen in a real recording: a USB disk's commands under the same
        stale address, on two endpoints the instrument does not have. Its
        complete commands show the pair, nothing on it is ever kept, and
        the instrument is still followed."""
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.hub(w)
        sf.i1pro2_work(w, sf.HUB)
        sf.disk_work(w, sf.HUB, out_ep=0x02, in_ep=0x81)
        sf.i1pro2_work(w, sf.HUB, readings=1)
        copy, att = kept(w)
        self.assert_clean(copy)
        self.assertEqual(len(att["followed"]["followed"]), 1)
        self.assertFalse(any(f[1] in (0x81, 0x02) for f in fields(copy)))

    def test_keyboard_reports_on_the_button_endpoint_stop_following(self):
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.hub(w)
        sf.i1pro2_work(w, sf.HUB)
        for _ in range(3):
            w.bulk_in(sf.HUB, 0x84, sf.KEY_MARKER, xfer=XFER_INT)
        copy, att = kept(w)
        self.assert_clean(copy)
        self.assertEqual(att["followed"]["followed"], [])
        self.assertIn("input device", att["followed"]["refused"][0]["why"])


class TheTable(unittest.TestCase):
    """The i1iO table (an FTDI chip) is followed by its command lines with a
    correct checksum, in a table session."""

    def build(self, lines=True):
        import synth_io                                          # noqa: PLC0415
        w = UsbPcapWriter()
        sf.describe(w, sf.INSTR, 0x0971, 0x2004, 0, 0xFF, [(0x81, 2), (0x02, 2)])
        sf.hub(w)
        sf.keyboard(w)
        w.control(sf.HUB, 0x40, 0x03, value=0x4138)               # FTDI: set baud rate
        for body in ((";RS", ";PA") if lines else ()):
            w.bulk_out(sf.HUB, 0x02, (synth_io.host(body) + "\r").encode("latin-1"))
            w.bulk_in(sf.HUB, 0x81, synth_io.ftdi_packets(
                (synth_io.table(body) + "\r").encode("latin-1")))
        if not lines:
            w.bulk_out(sf.HUB, 0x02, b"no line here")
            w.bulk_in(sf.HUB, 0x81, b"\x11\x60")
        sf.keyboard_work(w, sf.KEYBOARD)
        return w

    def test_followed_by_its_lines(self):
        copy, att = kept(self.build(), profile=probe.SESSION_TABLE)
        item = att["followed"]["followed"][0]
        self.assertEqual(item["family"], "io")
        self.assertEqual(item["requests"], 1)
        self.assertEqual(item["data"], 4)
        self.assertNotIn(sf.KEY_MARKER, blob(copy))

    def test_not_without_a_line(self):
        _copy, att = kept(self.build(lines=False), profile=probe.SESSION_TABLE)
        self.assertIsNone(att["followed"])


class OnlyARealHub(unittest.TestCase):
    """The confirmation review: a composite device (class 0xEF) with a hub
    interface beside a vendor interface is not a hub; its payloads must not
    reach the copy."""

    def test_composite_with_a_hub_interface_is_not_followed(self):
        import struct                                             # noqa: PLC0415
        w = UsbPcapWriter()
        sf.instrument(w)
        dev = sf.HUB
        dd = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0xEF, 2, 1, 64, 0x1234, 0x5678,
                         0x0100, 1, 2, 3, 1)
        w.control(dev, 0x80, 6, value=0x0100, length=18, reply=dd)
        ep_hub = struct.pack("<BBBBHB", 7, 5, 0x81, 3, 1, 12)
        ep_v = struct.pack("<BBBBHB", 7, 5, 0x86, 2, 64, 0)
        if0 = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, 1, 9, 0, 0, 0) + ep_hub
        if1 = struct.pack("<BBBBBBBBB", 9, 4, 1, 0, 1, 0xFF, 0, 0, 0) + ep_v
        total = 9 + len(if0) + len(if1)
        cfg = struct.pack("<BBHBBBBB", 9, 2, total, 2, 1, 0, 0x80, 50) + if0 + if1
        w.control(dev, 0x80, 6, value=0x0200, length=total, reply=cfg)
        marker = b"COMPOSITE-SECRET-PAYLOAD"
        w.vendor_in(dev, 0xC0, marker)
        w.vendor_out(dev, 0xCA, marker)
        w.bulk_in(dev, 0x82, marker * 4)
        copy, att = kept(w)
        self.assertNotIn(marker, blob(copy))
        self.assertEqual(att["followed"]["followed"], [])
        self.assertIn("only under a USB hub's address", att["followed"]["refused"][0]["why"])

    def test_a_real_hub_is_still_followed(self):
        _copy, att = kept(sf.swapped_step())
        self.assertEqual(len(att["followed"]["followed"]), 1)


class NotFollowedWithoutEvidence(unittest.TestCase):

    def test_no_configuration_description_no_following(self):
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.hub(w, config=False)
        sf.i1pro2_work(w, sf.HUB)
        copy, att = kept(w)
        self.assertEqual(att["followed"]["followed"], [])
        self.assertIn("configuration is not in the recording",
                      att["followed"]["refused"][0]["why"])
        self.assertIn("NOT KEPT", probe.followed_text(att["followed"]))
        self.assertEqual({f[0] for f in fields(copy)}, {(1, sf.INSTR)})

    def test_data_without_the_familys_commands_is_not_followed(self):
        w = UsbPcapWriter()
        sf.instrument(w)
        sf.hub(w)
        for i in range(5):
            w.bulk_in(sf.HUB, 0x82, bytes([i]) * 268)
        w.control(sf.HUB, 0x40, 0x01, out=b"\x00")      # a vendor request, not the i1Pro's
        _copy, att = kept(w)
        self.assertIsNone(att["followed"])

    def test_another_session_type_does_not_follow(self):
        """An i1iSis session has no known commands to follow by."""
        _copy, att = kept(sf.swapped_step(), profile="isis")
        self.assertIsNone(att["followed"])


if __name__ == "__main__":
    unittest.main()
