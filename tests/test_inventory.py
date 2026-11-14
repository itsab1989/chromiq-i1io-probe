"""1.6.3: the report's device lists without the other USB devices' names.

A tester's report (structural facts only) showed other devices' friendly
names, a printer's model inside a Windows device ID and a few location IDs
in the topology section, and --clean left them. Decision: with redaction on
(the default) another device keeps its vendor and product id and its class
where the list has one, not its name; Windows' generic names stay (they are
the class); X-Rite devices stay in full; --no-redact shows everything. All
samples below are invented."""

import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

PRIVATE = ("Logitech", "Receiver", "Canon", "PRO-300", "SanDisk", "Extreme", "Dell",
           "U2720Q", "11583659", "2A1B9C", "Magic Keyboard", "Apple Inc")

WINDOWS = """\

FriendlyName : Intel(R) USB 3.10 eXtensible Host Controller - 1.20 (Microsoft)
InstanceId   : PCI\\VEN_8086&DEV_A0ED&SUBSYS_0A1F1028&REV_20\\3&11583659&0&A0
Status       : OK

FriendlyName : USB Root Hub (USB 3.0)
InstanceId   : USB\\ROOT_HUB30\\4&2A1B9C&0&0
Status       : OK

FriendlyName : Logitech USB Receiver with a very long name that Windows wraps onto
               a second line
InstanceId   : USB\\VID_046D&PID_C52B\\5&1F3A2B&0&2
Status       : OK

FriendlyName : Canon PRO-300 series
InstanceId   : USBPRINT\\CANONPRO-300_SERIES\\7&2A1B9C&0&USB001
Status       : OK

FriendlyName : USB Mass Storage Device
InstanceId   : USB\\VID_0781&PID_5581\\4C530001090101112233
Status       : OK

FriendlyName : X-Rite i1Pro3
InstanceId   : USB\\VID_0765&PID_6009\\<redacted:1a2b3c4d>
Status       : OK
"""

SP = {"SPUSBHostDataType": [{"_name": "USB31Bus", "_items": [
    {"_name": "SanDisk Extreme", "USBDeviceKeyVendorID": "0x0781 (SanDisk Corp.)",
     "USBDeviceKeyProductID": "0x5581", "USBDeviceKeyVendorName": "SanDisk",
     "USBDeviceKeySerialNumber": "AA0011", "USBDeviceKeyLocationID": "0x01100000"},
    {"_name": "USB2.0 Hub", "USBDeviceKeyVendorID": "0x05e3", "_items": [
        {"_name": "i1Pro 2", "USBDeviceKeyVendorID": "0x0971",
         "USBDeviceKeyProductID": "0x2000", "USBDeviceKeyVendorName": "X-Rite"}]},
    {"_name": "Magic Keyboard", "vendor_id": "apple_vendor_id (Apple Inc)",
     "manufacturer": "Apple Inc."}]}]}

IOREG = """\
+-o Root  <class IORegistryEntry, id 0x100000100, retain 25>
  +-o AppleT8112USBXHCI@01000000  <class AppleT8112USBXHCI, id 0x1000002f1>
  | +-o Dell U2720Q Hub@01100000  <class IOUSBHostDevice, id 0x100000a01>
  | | {
  | |   "USB Product Name" = "Dell U2720Q Hub"
  | |   "idVendor" = 1729
  | |   "idProduct" = 21
  | |   "kUSBSerialNumberString" = "<redacted:00aa11bb>"
  | |   "USB Vendor Name" = "Dell"
  | | }
  | | +-o i1Pro 2@01110000  <class IOUSBHostDevice, id 0x100000b01>
  | |   {
  | |     "USB Product Name" = "eye-one"
  | |     "idVendor" = 2417
  | |     "idProduct" = 8192
  | |   }
"""

LSUSB = """\
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 001 Device 003: ID 046d:c52b Logitech, Inc. Unifying Receiver
Bus 001 Device 004: ID 0971:2000 Gretag-Macbeth AG i1 Pro"""

DMESG = """\
[    1.100000] usb 1-2: New USB device found, idVendor=046d, idProduct=c52b
[    1.100100] usb 1-2: Product: USB Receiver
[    1.100200] usb 1-2: Manufacturer: Logitech
[    1.200000] input: Logitech USB Receiver as /devices/pci0000:00/usb1/1-2/input/input5
[    1.300000] usb 1-3: New USB device found, idVendor=0971, idProduct=2000
[    1.300100] usb 1-3: Product: eye-one
[    1.400000] usb 1-4: reset high-speed USB device number 4 using xhci_hcd"""


class Redacted(unittest.TestCase):

    def setUp(self):
        self.addCleanup(setattr, probe, "REDACT", probe.REDACT)
        probe.REDACT = True

    def assertPrivateGone(self, text):
        for word in PRIVATE:
            self.assertNotIn(word, text, word)

    def test_windows_topology(self):
        title = "Windows: all USB controllers/hubs (topology context)"
        text = probe.redact_inventory(title, WINDOWS)
        self.assertPrivateGone(text)
        for want in ("FriendlyName : Intel(R) USB 3.10 eXtensible Host Controller",
                     "PCI\\VEN_8086&DEV_A0ED\\<redacted:", "USB Root Hub (USB 3.0)",
                     "FriendlyName : (name not shown) (vendor id 046d)",
                     "InstanceId   : USB\\VID_046D&PID_C52B\\<redacted:",
                     "FriendlyName : USB Mass Storage Device",
                     "FriendlyName : X-Rite i1Pro3",
                     "InstanceId   : USB\\VID_0765&PID_6009\\<redacted:1a2b3c4d>"):
            self.assertIn(want, text, want)
        self.assertNotIn("a second line", text)
        self.assertEqual(probe.redact_inventory(title, text), text)      # idempotent

    def test_macos_system_profiler(self):
        title = "macOS: USB device tree (JSON, SPUSBHostDataType)"
        text = probe.redact_inventory(title, json.dumps(SP))
        self.assertPrivateGone(text)
        data = json.loads(text)
        bus = data["SPUSBHostDataType"][0]
        self.assertEqual(bus["_name"], "USB31Bus")
        disk, hub, kbd = bus["_items"]
        self.assertEqual(disk["_name"], "(name not shown)")
        self.assertEqual(disk["USBDeviceKeyVendorID"], "0x0781")
        self.assertEqual(disk["USBDeviceKeyProductID"], "0x5581")
        self.assertEqual(hub["_name"], "USB2.0 Hub")
        self.assertEqual(hub["_items"][0]["_name"], "i1Pro 2")
        self.assertEqual(hub["_items"][0]["USBDeviceKeyVendorName"], "X-Rite")
        self.assertEqual(kbd["_name"], "(name not shown)")
        self.assertEqual(probe.redact_inventory(title, "[empty on this macOS version]"),
                         "[empty on this macOS version]")
        self.assertIn("could not be read", probe.redact_inventory(title, "{broken"))

    def test_macos_ioreg(self):
        text = probe.redact_inventory("macOS: ioreg USB properties", IOREG)
        self.assertPrivateGone(text)
        self.assertIn("+-o (name not shown)@01100000  <class IOUSBHostDevice", text)
        self.assertIn('"idVendor" = 1729', text)
        self.assertIn("AppleT8112USBXHCI@01000000", text)
        self.assertIn("+-o i1Pro 2@01110000", text)
        self.assertIn('"USB Product Name" = "eye-one"', text)

    def test_linux(self):
        text = probe.redact_inventory("Linux: lsusb (all devices)", LSUSB)
        self.assertPrivateGone(text)
        self.assertIn("ID 046d:c52b (name not shown)", text)
        self.assertIn("1d6b:0002 Linux Foundation 2.0 root hub", text)
        self.assertIn("0971:2000 Gretag-Macbeth AG i1 Pro", text)
        text = probe.redact_inventory("Linux: kernel messages mentioning USB/FTDI", DMESG)
        self.assertPrivateGone(text)
        self.assertIn("idVendor=046d, idProduct=c52b", text)
        self.assertIn("usb 1-3: Product: eye-one", text)
        self.assertIn("reset high-speed USB device number 4", text)
        self.assertIn("(3 lines naming other USB devices not shown)", text)

    def test_the_usbpcap_device_list(self):
        checks = {"admin": True, "usbpcapcmd": None, "service": {"installed": True,
                                                                 "running": True},
                  "hubs": [{"path": "\\\\.\\USBPcap1", "display": "USBPcap1",
                            "devices": [(1, "[1] USB Composite Device"),
                                        (3, "[3] X-Rite i1Pro3"),
                                        (4, "[4] Canon PRO-300 series")],
                            "instrument": [(3, "[3] X-Rite i1Pro3")]}]}
        text = probe.usbpcap_diagnosis(checks)
        self.assertIn("device 1: [1] USB Composite Device", text)
        self.assertIn("device 3: [3] X-Rite i1Pro3", text)
        self.assertIn("device 4: [4] (name not shown)", text)
        self.assertPrivateGone(text)

    def test_section_applies_it(self):
        saved = list(probe._SECTIONS)
        self.addCleanup(lambda: probe._SECTIONS.__setitem__(slice(None), saved))
        probe.section("Linux: lsusb (all devices)", LSUSB)
        self.assertIn("(name not shown)", probe._SECTIONS[-1][1])

    def test_no_redact_shows_everything(self):
        probe.REDACT = False
        self.assertEqual(probe.redact_inventory("Linux: lsusb (all devices)", LSUSB), LSUSB)
        self.assertEqual(probe.inventory_name("[4] Canon PRO-300 series"),
                         "[4] Canon PRO-300 series")


class CleanAnOldReport(unittest.TestCase):

    def test_clean_hides_the_names_in_an_old_report(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        bar = "=" * 72
        report = ("ChromIQ X-Rite instrument probe report, version 1.6.2\n\n"
                  f"{bar}\nWindows: all USB controllers/hubs (topology context)\n{bar}\n"
                  f"{WINDOWS}\n\n{bar}\nLinux: lsusb (all devices)\n{bar}\n{LSUSB}\n\n"
                  f"{bar}\nEnvironment\n{bar}\nLogitech stays here: not a device list\n")
        zpath = os.path.join(tmp, "SEND-THIS-20261113-120000.zip")
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("chromiq-io-probe-20261113-120000.txt", report)
        text, code = probe.clean_paths([zpath])
        self.assertEqual(code, 0, text)
        self.assertIn("other USB devices' names in its device lists are hidden", text)
        cleaned = [os.path.join(tmp, n) for n in os.listdir(tmp) if n.endswith("-cleaned.zip")]
        self.assertEqual(len(cleaned), 1)
        with zipfile.ZipFile(cleaned[0]) as zf:
            new = zf.read("chromiq-io-probe-20261113-120000.txt").decode()
        topology = new.split("Environment")[0]
        for word in ("Canon", "PRO-300", "Receiver", "11583659", "Unifying"):
            self.assertNotIn(word, topology, word)
        self.assertIn("X-Rite i1Pro3", new)
        self.assertIn("Logitech stays here: not a device list", new)
        with zipfile.ZipFile(zpath) as zf:                  # the original is unchanged
            self.assertEqual(zf.read("chromiq-io-probe-20261113-120000.txt").decode(), report)


if __name__ == "__main__":
    unittest.main()
