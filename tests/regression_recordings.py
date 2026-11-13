"""1.6: the same simulated recordings for every version of the tool.

Used by tools/make_v155_kept_fixture.py (which runs them through the tagged
v1.5.5 and writes tests/fixtures/v155-kept.json) and by
tests/test_regression_v155.py (which runs them through this version and
compares). Every byte is INVENTED; the markers only show which device's
traffic ended up where. Taken from the second review of 1.6
(review/re/compare.py), with the same device set.
"""

import os

import synth
import synth_io

# address: (vid, pid, label, marker, endpoints)
DEVICES = {
    3: (0x0971, 0x2006, "iSis", b"ISIS-A-MARK", [(0x81, 2), (0x02, 2)]),
    10: (0x0971, 0x2006, "iSis#2", b"ISIS-B-MARK", [(0x81, 2), (0x02, 2)]),
    4: (0x0765, 0x5020, "i1Display", b"DISPLAY-SERIAL", [(0x81, 3), (0x01, 3)]),
    5: (0x046D, 0xC31C, "keyboard", b"KEYB-TYPED", [(0x81, 3)]),
    6: (0x046D, 0xC077, "mouse", b"MOUSE-MARK", [(0x81, 3)]),
    7: (0x0781, 0x5567, "stick", b"STICK-FILE", [(0x81, 2), (0x02, 2)]),
    8: (0x0971, 0x2099, "unknownXR", b"UNKNOWN-XR-SERIAL", [(0x81, 2), (0x02, 2)]),
    9: (0x0971, 0x2000, "i1Pro2", b"I1PRO2-SERIAL", [(0x82, 2), (0x84, 3), (0x03, 2)]),
    11: (0x0971, 0x2004, "i1iO", b"IO-TABLE-MARK", [(0x81, 2), (0x02, 2)]),
    12: (0x05E3, 0x0610, "hub", b"HUB-STATUS", [(0x81, 3)]),
    13: (0x0765, 0x600A, "Display3L", b"D3L-SERIAL", [(0x81, 3)]),
}
# The i1Pro 2's own vendor requests (ArgyllCMS i1pro_imp.c), so that a
# device without a description can be guessed from its commands.
I1PRO2_REQS = (0xC0, 0xC1, 0xC2, 0xC3)


def _usbpcap(present, described, pro_cmds=False):
    w = synth.UsbPcapWriter()
    for a in present:
        if a in described:
            vid, pid, _l, _m, eps = DEVICES[a]
            w.describe(a, vid, pid, eps)
    for a in present:
        _vid, _pid, _l, m, eps = DEVICES[a]
        w.bulk_in(a, [e for e, _k in eps if e & 0x80][0], m)
        outs = [e for e, _k in eps if not e & 0x80]
        if outs:
            w.bulk_out(a, outs[0], m + b"-OUT\r")
    if pro_cmds and 9 in present:
        for req in I1PRO2_REQS:
            w.vendor_in(9, req, b"I1PRO2-SERIAL-EEPROM")
    return w


def _darwin(present):
    d = synth_io.DarwinWriter()
    for seq, a in enumerate(present, 1):
        vid, pid, _l, m, _e = DEVICES[a]
        d._rec(1, seq, a, 0x81, 2, vid, pid, m, len(m))  # noqa: SLF001
    return d


def _usbmon(present):
    u = synth_io.UsbmonWriter()
    for a in present:
        u.bulk_in(a, 0x81, DEVICES[a][3])
    return u


ALL = list(DEVICES)
CASES = {
    "A-everything-described": lambda: _usbpcap(ALL, set(ALL), True),
    "B-two-isis-keyboard": lambda: _usbpcap([3, 10, 5], {3, 10, 5}),
    "C-isis-undescribed-i1pro2-described": lambda: _usbpcap([3, 9, 5], {9, 5}),
    "D-nothing-described-i1pro2-commands": lambda: _usbpcap([3, 9, 5], set(), True),
    "E-no-isis-unknown-display-3l": lambda: _usbpcap([8, 4, 5, 13], {8, 4, 5, 13}),
    "F-i1io-table-with-isis": lambda: _usbpcap([11, 3, 5], {11, 3, 5}),
    "G-i1pro2-with-isis": lambda: _usbpcap([9, 3, 5], {9, 3, 5}, True),
    "H-mac-everything": lambda: _darwin(ALL),
    "H2-mac-i1io-table-with-isis": lambda: _darwin([11, 3, 5]),
    "I-linux-no-descriptions": lambda: _usbmon([3, 9, 5]),
    "K-i1pro2-alone": lambda: _usbpcap([9, 5], {9, 5}, True),
    "L-i1io-alone": lambda: _usbpcap([11, 5], {11, 5}),
    # third review: an i1Display beside the i1iSis (the CI smoke test's case)
    "M-isis-with-display": lambda: _usbpcap([3, 4, 5], {3, 4, 5}),
    "N-mac-isis-with-display": lambda: _darwin([3, 4, 5]),
}


def save_all(folder):
    """Write every case as <name>.pcap into folder; returns {name: path}."""
    os.makedirs(folder, exist_ok=True)
    return {name: build().save(os.path.join(folder, name + ".pcap"))
            for name, build in CASES.items()}


def markers_in(path):
    """The labels of the devices whose marker is in a file."""
    if not path or not os.path.exists(path):
        return []
    with open(path, "rb") as fh:
        blob = fh.read()
    return [label for _v, _p, label, marker, _e in DEVICES.values() if marker in blob]


def outcome(probe, path, folder, profile=None):
    """What one version of the tool keeps and says for one recording.
    profile None calls the functions the way 1.5.5 knows them."""
    dst = os.path.join(folder, os.path.basename(path)[:-5] + f"-{profile}-copy.pcap")
    if os.path.exists(dst):
        os.remove(dst)
    if profile is None:
        n = probe.filter_xrite_capture(path, dst)
        check = probe.check_capture(path)
    else:
        n = probe.filter_xrite_capture(path, dst, profile)
        check = probe.check_capture(path, profile)
    return {"records": n, "kept": markers_in(dst) if n else [],
            "check": check["code"], "xrite_packets": check["xrite_packets"]}


def analysis_outcome(probe, path):
    """--analyze on the plain file: the family line, the devices listed as
    the instrument, and which markers appear anywhere in the text."""
    rep = probe.analyze_paths([path])
    family = [l.strip() for l in rep.splitlines() if "instrument family" in l][:1]
    ids = sorted({l.split(":", 1)[1].strip()[:9] for l in rep.splitlines()
                  if l.strip().startswith("instrument at bus")})
    marks = [label for _v, _p, label, marker, _e in DEVICES.values()
             if marker.decode() in rep]
    return {"family": family, "instrument_ids": ids, "markers": marks}
