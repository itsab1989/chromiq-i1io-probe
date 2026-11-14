"""1.6.3 (review): the reviewer's inventory attack (review/inv.py) as a test.
Every planted MARK must be gone from every device list, also through
--clean of an old report. All samples invented."""

import json
import os
import re
import shutil
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import chromiq_io_probe as probe  # noqa: E402

MK = re.compile(r"MARK\w*")

win = """
FriendlyName : SanDisk Ultra MARKDISK
InstanceId   : USB\\VID_0781&PID_5567\\4C530MARKSERIAL1234
Status       : OK

FriendlyName : Basti's iPhone MARKPHONE
InstanceId   : USB\\VID_05AC&PID_12A8&MI_00\\7&2A3B4C5D&0&0000
Status       : OK

FriendlyName : USB Printing Support
InstanceId   : USB\\VID_04B8&PID_1234\\X3MARKPRINTERSERIAL
Status       : OK

FriendlyName : EPSON ET-8550 Series MARKPRINTER
InstanceId   : USBPRINT\\EPSONET-8550_SERIES_MARKMODEL\\7&1A2B3C4D&0&USB001
Status       : OK

FriendlyName : Generic USB Hub
InstanceId   : USB\\VID_05E3&PID_0610\\6&MARKHUBPORT&0&2
Status       : OK

FriendlyName : HID-compliant MARKVENDOR keyboard
InstanceId   : HID\\VID_046D&PID_C31C&MI_00\\8&MARKHID&0&0000
Status       : OK

FriendlyName : USB Serial Device (COM3) MARKSERIALDEV
InstanceId   : USB\\VID_0403&PID_6001\\A9MARKFTDI
Status       : OK

FriendlyName : i1Pro 3
InstanceId   : USB\\VID_0765&PID_6009\\1234567
Status       : OK
"""
sp = json.dumps({"SPUSBDataType": [{"_name": "USB31Bus", "_items": [
  {"_name": "MARKDISKNAME", "manufacturer": "SanDisk MARKMFR", "serial_num": "MARKSN", "vendor_id": "0x0781  (SanDisk MARKCORP)", "product_id": "0x5567", "location_id": "0x14200000 / 3",
   "Media": [{"_name": "MARKMEDIA", "bsd_name": "disk4", "removable_media": "yes", "volumes": [{"_name": "MARKLABEL", "mount_point": "/Volumes/MARKLABEL2", "file_system": "MS-DOS FAT32", "volume_uuid": "1A2B3C4D-1111-2222-3333-444455556666"}]}]},
  {"_name": "Basti's iPhone MARKPHONE", "vendor_id": "apple_vendor_id", "product_id": "0x12a8", "serial_num": "00008101MARKUDID"},
  {"_name": "i1Pro 3", "vendor_id": "0x0765", "product_id": "0x6009", "serial_num": "1234567"}]}]})
iore = """+-o Root  <class IORegistryEntry, id 0x100000100, retain 22>
  +-o MARKDISKNAME@14200000  <class IOUSBHostDevice, id 0x1000, registered, matched, active, busy 0 (1 ms), retain 30>
    | {
    |   "USB Product Name" = "MARKPRODUCT"
    |   "kUSBVendorString" = "MARKVENDOR"
    |   "idVendor" = 1921
    |   "USB Serial Number" = "MARKSERIALIO"
    |   "kUSBSerialNumberString" = "MARKSERIALIO2"
    |   "Bus Power Available" = 900
    |   "IOCFPlugInTypes" = {"9dc7b780-9ec0-11d4-a54f-000a27052861"="IOUSBFamily.kext/Contents/PlugIns/MARKPLUGIN.bundle"}
    |   "UsbDeviceSignature" = <81075655000001>
    | }
    |
    +-o MARKIFACE@0  <class IOUSBHostInterface, id 0x1001>
    |   {
    |     "USB Interface Name" = "MARKIFNAME"
    |     "bInterfaceClass" = 8
    |   }
"""
lsu = "Bus 001 Device 004: ID 0781:5567 SanDisk Corp. Cruzer MARKLSUSB\nBus 001 Device 005: ID 0765:6009 X-Rite i1Pro 3\nBus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub"
dm = """[    2.076512] usb 1-2: Product: MARKDMESG1
[   10.123456] usb 1-2: Manufacturer: MARKDMESG2
[   10.2] scsi 6:0:0:0: Direct-Access     SanDisk  Cruzer MARKDMESG3      1.00 PQ: 0 ANSI: 6
[   10.3] sd 6:0:0:0: [sdb] 30031872 512-byte logical blocks
[   10.4] usb 1-5: Product: My FTDI cable MARKDMESG4
[   10.5] input: Logitech MARKDMESG5 as /devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0/0003:046D:C31C.0001/input/input5
[   10.6] cdc_acm 1-6:1.0: ttyACM0: USB ACM device
[   10.7] usb 1-7: New USB device found, idVendor=04e8, idProduct=6860, bcdDevice= 4.00
[   10.8] usb 1-7: Product: SAMSUNG_Android MARKDMESG6
[   10.9] usb 1-7: SerialNumber: R58MARKDMESG7
[   11.0] usb 1-8: Product: MARKDMESG8 (path /home/basti/x)
[   11.1] sd 6:0:0:0: Attached scsi removable disk sdb  MARKDMESG9
[   11.2] EXT4-fs (sdb1): mounted filesystem with ordered data mode. Quota mode: none. MARKDMESG10
[   11.3] FAT-fs (sdb1): Volume was not properly unmounted. MARKLABELDMESG
"""

SECTIONS = [("Windows: all USB controllers/hubs (topology context)", win),
            ("macOS: USB device tree (JSON, older name SPUSBDataType)", sp),
            ("macOS: ioreg USB properties", iore),
            ("Linux: lsusb (all devices)", lsu),
            ("Linux: kernel messages mentioning USB/FTDI", dm)]


class ReviewInventory(unittest.TestCase):

    def setUp(self):
        self.addCleanup(setattr, probe, "REDACT", probe.REDACT)
        probe.REDACT = True

    def test_no_planted_mark_survives(self):
        for title, body in SECTIONS:
            with self.subTest(section=title):
                out = probe.redact_inventory(title, probe.scrub(body))
                self.assertEqual(sorted(set(MK.findall(out))), [], out)

    def test_what_stays(self):
        out = probe.redact_inventory(SECTIONS[0][0], probe.scrub(win))
        self.assertIn("FriendlyName : i1Pro 3", out)
        self.assertIn("FriendlyName : Generic USB Hub", out)
        self.assertIn("FriendlyName : USB Printing Support", out)
        self.assertIn("(name not shown) (vendor id 0403)", out)     # not "USB Serial Device (COM3) x"
        data = json.loads(probe.redact_inventory(SECTIONS[1][0], sp))
        items = data["SPUSBDataType"][0]["_items"]
        self.assertEqual(items[0]["vendor_id"], "0x0781")
        self.assertNotIn("Media", items[0])
        self.assertTrue(items[0]["location_id"].startswith("<redacted:"))
        self.assertEqual(items[2]["_name"], "i1Pro 3")
        lines = probe.redact_inventory(SECTIONS[4][0], dm).splitlines()
        self.assertEqual(lines[-1], "(14 lines about other devices not shown)")

    def test_a_timestamp_with_an_xrite_id_in_it_keeps_nothing(self):
        dm2 = "[    0.076512] usb 1-2: Product: SECRETNAME\n[  765.097100] usb 1-2: Manufacturer: X"
        out = probe.redact_inventory(SECTIONS[4][0], dm2)
        self.assertNotIn("SECRETNAME", out)

    def test_generic_names_are_exact(self):
        for name in ("HID-compliant MARK keyboard", "USB Serial Device (COM3) MARK",
                     "Unknown USB Device MARK", "USB Root Hub MARK", "MARK Host Controller x"):
            self.assertFalse(probe.is_generic_name(name), name)
        for name in ("HID-compliant keyboard", "USB Serial Device (COM3)",
                     "Unknown USB Device (Device Descriptor Request Failed)",
                     "USB Root Hub (USB 3.0)",
                     "Intel(R) USB 3.10 eXtensible Host Controller - 1.20 (Microsoft)"):
            self.assertTrue(probe.is_generic_name(name), name)

    def test_clean_of_an_old_report(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        bar = "=" * 72
        report = "ChromIQ X-Rite instrument probe report, version 1.6.2\n\n" + "".join(
            f"{bar}\n{t}\n{bar}\n{b}\n\n" for t, b in SECTIONS)
        zpath = os.path.join(tmp, "SEND-THIS-20261113-120000.zip")
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("chromiq-io-probe-20261113-120000.txt", report)
        _text, code = probe.clean_paths([zpath])
        self.assertEqual(code, 0)
        cleaned = [os.path.join(tmp, n) for n in os.listdir(tmp) if n.endswith("-cleaned.zip")]
        with zipfile.ZipFile(cleaned[0]) as zf:
            new = zf.read("chromiq-io-probe-20261113-120000.txt").decode()
        self.assertEqual(sorted(set(MK.findall(new))), [])
        self.assertIn("i1Pro 3", new)


if __name__ == "__main__":
    unittest.main()
