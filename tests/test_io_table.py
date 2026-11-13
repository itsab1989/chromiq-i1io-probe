"""1.5.4: the macOS OUT-data fix, the i1iO table analysis, the new i1iO
steps, --rehearse and the end of a Mac session. Standard library only.
Every recording here is synthetic (tests/synth_io.py)."""

import io
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402
import synth  # noqa: E402
import synth_io as sio  # noqa: E402


def scripted(answers):
    """An ask() that gives these answers in order, then empty ones."""
    it = iter(answers)

    def fake(_prompt="", interruptible=False):
        try:
            value = next(it)
        except StopIteration:
            probe._INPUT_ENDED[:] = [True]          # like a closed stdin
            return ""
        if isinstance(value, BaseException):
            raise value
        return value
    return fake


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        probe._SECTIONS.clear()
        probe.REDACT = True
        probe._INPUT_ENDED.clear()
        self.addCleanup(probe._INPUT_ENDED.clear)

    def path(self, name):
        return os.path.join(self.tmp.name, name)


# --------------------------------------------------------------------------
# 1. macOS recordings: data to the device is in the completion record
# --------------------------------------------------------------------------

class DarwinOutData(TmpCase):

    def test_bulk_out_data_from_the_completion(self):
        w = sio.DarwinWriter()
        w.bulk_out(sio.TABLE, sio.TABLE_PID, 0x02, b";s022\r")
        ev = probe._events_darwin(w.records)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["data"], b";s022\r")
        self.assertFalse(ev[0]["dir_in"])
        self.assertEqual(ev[0]["ep"], 0x02)

    def test_control_out_data_stage_from_the_completion(self):
        w = sio.DarwinWriter()
        w.trigger(readings=5)
        ctl = [e for e in probe._events_darwin(w.records) if e["kind"] == "control"]
        self.assertEqual(len(ctl[0]["out"]), 14)
        self.assertIn("5 readings", probe._d_trigger2(ctl[0]["out"], b""))

    def test_data_in_the_submit_is_used_once(self):
        w = sio.DarwinWriter()
        w.bulk_out(sio.TABLE, sio.TABLE_PID, 0x02, b";a133\r", data_in_submit=True)
        ev = probe._events_darwin(w.records)
        self.assertEqual([e["data"] for e in ev], [b";a133\r"])

    def test_an_out_without_completion_keeps_its_bytes(self):
        w = sio.DarwinWriter()
        w.bulk_out(sio.TABLE, sio.TABLE_PID, 0x02, b";p025\r", data_in_submit=True,
                   complete=False)
        self.assertEqual([e["data"] for e in probe._events_darwin(w.records)], [b";p025\r"])

    def test_in_data_still_from_the_completion_only(self):
        w = sio.DarwinWriter()
        w.bulk_in(sio.TABLE, sio.TABLE_PID, 0x81, b"\x11\x60:!s002\r")
        ev = probe._events_darwin(w.records)
        self.assertEqual(len(ev), 1)
        self.assertTrue(ev[0]["dir_in"])

    def test_handheld_analysis_on_a_mac_sees_trigger_bits_and_the_ruler_stop(self):
        """The 1.5.3 reader left these empty on a Mac, so its summary could say
        "no sign of ruler traffic" for a recording that has it."""
        w = sio.DarwinWriter()
        w.trigger(readings=10, lamp=41, flags=0x0105)            # scan + ruler start + lamp
        w.control(sio.PRO, sio.PRO_PID, 0x40, 0xD7, out=synth.be16(0x0002))
        res = probe.analyze_step(probe._events_darwin(w.records), "i1pro2")
        ruler = " | ".join(text for _t, text in res["ruler"])
        self.assertIn("0xD4 with ruler bits", ruler)
        self.assertIn("0xD7 sent: parameter 0x0002", ruler)
        self.assertEqual(res["measurements"][0]["nummeas"], 10)
        self.assertEqual(res["measurements"][0]["intclocks"], 139)

    def test_usbpcap_keeps_host_to_device_data(self):
        """USBPcap (per its documentation, which synth.UsbPcapWriter follows):
        OUT data in the request record, the control OUT data stage as its own
        stage-1 record. Checked here on a synthetic file only; no real
        Windows recording of an i1Pro 2 exists yet."""
        w = synth.UsbPcapWriter()
        w.describe(synth.I1PRO, 0x0971, 0x2000, synth.I1PRO2_ENDPOINTS)
        synth.i1pro2_trigger(w, 0x0105, 10)
        w.vendor_out(synth.I1PRO, 0xD6, synth.be32(len(synth.LED_OFF)))
        w.bulk_out(synth.I1PRO, 0x03, synth.LED_OFF)
        w.vendor_out(synth.I1PRO, 0xD7, synth.be16(0x0002))
        path = w.save(self.path("win.pcap"))
        linktype, recs = probe._read_pcap(path)
        ev = probe.capture_events(linktype, recs)
        outs = [e for e in ev if e["kind"] == "data" and not e["dir_in"]]
        self.assertEqual([e["data"] for e in outs], [synth.LED_OFF])
        ctl = {e["req"]: e["out"] for e in ev if e["kind"] == "control"}
        self.assertEqual(len(ctl[0xD4]), 14)
        self.assertEqual(ctl[0xD7], synth.be16(0x0002))
        res = probe.analyze_step(ev, "i1pro2")
        self.assertTrue(res["leds"] and res["leds"][0][1]["ok"])
        self.assertIn("0xD7 sent: parameter 0x0002", " | ".join(t for _r, t in res["ruler"]))

    def test_handheld_analysis_now_sees_the_lights_on_a_mac(self):
        w = sio.DarwinWriter()
        w.control(sio.PRO, sio.PRO_PID, 0x40, 0xD6, out=synth.be32(len(synth.LED_OFF)))
        w.bulk_out(sio.PRO, sio.PRO_PID, 0x03, synth.LED_OFF)
        res = probe.analyze_step(probe._events_darwin(w.records), "i1pro2")
        self.assertEqual(len(res["leds"]), 1)
        self.assertTrue(res["leds"][0][1]["ok"])


# --------------------------------------------------------------------------
# 2. the table: FTDI, lines, checksum
# --------------------------------------------------------------------------

class TableLines(TmpCase):

    def test_checksum_examples_from_the_real_recordings(self):
        for line in (";a133", ":!a113", ";s022", ":$s00CF", ":!m008", ":$m00D5",
                     ";m0042204b200c86d", ";c42e", ":$c40B960"):
            self.assertTrue(probe.io_checksum_ok(line), line)
        self.assertEqual(probe.io_checksum(";a1"), "33")
        self.assertFalse(probe.io_checksum_ok(";a134"))
        self.assertFalse(probe.io_checksum_ok(";a1-1"))
        self.assertFalse(probe.io_checksum_ok("x"))

    def test_ftdi_status_bytes_dropped_per_packet(self):
        data = bytes(range(200))
        self.assertEqual(probe.io_ftdi_payload(sio.ftdi_packets(data)), data)
        self.assertEqual(probe.io_ftdi_payload(b"\x11\x60"), b"")

    def lines_of(self, path):
        cap = probe.io_capture(path)
        self.assertIsNotNone(cap)
        return cap

    def test_session_lines_all_check_out(self):
        w = sio.DarwinWriter()
        sio.table_session(w)
        cap = self.lines_of(w.save(self.path("r.pcap")))
        self.assertTrue(cap["lines"])
        self.assertTrue(all(l["ok"] for l in cap["lines"]))
        host = [l for l in cap["lines"] if l["who"] == "host"]
        self.assertEqual(len(cap["lines"]), 3 * len(host))
        # the long memory reply crossed several 64-byte packets
        u8 = [l["line"] for l in cap["lines"] if l["line"].startswith(":$u8")]
        self.assertEqual(len(u8[0]), 5 + 512 + 2)

    def test_the_same_lines_from_usbpcap_and_usbmon(self):
        for writer in (synth.UsbPcapWriter(), sio.UsbmonWriter()):
            expected = sio.same_lines_other_format(writer)
            path = writer.save(self.path(f"{type(writer).__name__}.pcap"))
            cap = self.lines_of(path)
            self.assertEqual([l["line"] for l in cap["lines"]], expected,
                             type(writer).__name__)
            self.assertTrue(all(l["ok"] for l in cap["lines"]))

    def test_no_table_no_table_analysis(self):
        w = sio.DarwinWriter()
        w.trigger()
        self.assertIsNone(probe.io_capture(w.save(self.path("pro.pcap"))))

    def test_cut_line_and_bad_checksum_are_flagged(self):
        w = sio.DarwinWriter()
        w.bulk_out(sio.TABLE, sio.TABLE_PID, 0x02, b";a134\r")      # wrong checksum
        w.bulk_out(sio.TABLE, sio.TABLE_PID, 0x02, b";s0")           # cut off
        cap = probe.io_capture(w.save(self.path("bad.pcap")))
        text = "\n".join(probe.io_timeline(cap))
        self.assertIn("CHECKSUM WRONG", text)
        self.assertIn("cut off by the end of the recording", text)


# --------------------------------------------------------------------------
# 3. what the analysis says
# --------------------------------------------------------------------------

class TableAnalysis(TmpCase):

    def recording(self, name="io-capture-x-XHC2-xrite.pcap"):
        w = sio.DarwinWriter()
        span = sio.table_session(w)
        return w, w.save(self.path(name)), span

    def test_timeline_merges_table_and_i1pro_with_confidence_words(self):
        _w, path, _span = self.recording()
        text = probe.analyze_paths([path])
        self.assertIn("THE i1iO TABLE", text)
        self.assertIn("checksum right on", text)
        self.assertIn("every line checks out", text)
        self.assertIn("FTDI set baud rate (divisor 52, about 57,692 baud)", text)
        self.assertIn("FTDI set data format: 8 data bits, no parity, 1 stop bit", text)
        self.assertIn("c3, sent as each scan starts (guess: head down)", text)
        self.assertIn("home / reference run", text)
        self.assertIn("(likely)", text)
        self.assertIn("i1Pro BUTTON pressed", text)
        self.assertIn("i1Pro trigger measurement (i1Pro 2): integration 139 clocks", text)
        self.assertIn("commands not seen in the first recordings: none", text)
        # the handheld verdict (rulers, dual scan) is not printed for a table
        self.assertNotIn("a no-ruler control", text)

    def test_serial_hidden_by_default_and_shown_on_request(self):
        _w, path, _span = self.recording()
        serial_hex = sio.FAKE_SERIAL.to_bytes(4, "little").hex().upper()
        text = probe.analyze_paths([path])
        self.assertIn("<serial>", text)
        self.assertNotIn(serial_hex, text)
        probe.REDACT = False
        try:
            self.assertIn(serial_hex, probe.analyze_paths([path]))
        finally:
            probe.REDACT = True

    def test_usb_serial_string_hidden_in_the_generic_timeline(self):
        w = sio.DarwinWriter()
        serial = "12345".encode("utf-16-le")
        w.control(sio.TABLE, sio.TABLE_PID, 0x80, 6, value=0x0303,
                  reply=bytes([2 + len(serial), 3]) + serial)
        product = "Eye-One iO".encode("utf-16-le")
        w.control(sio.TABLE, sio.TABLE_PID, 0x80, 6, value=0x0302,
                  reply=bytes([2 + len(product), 3]) + product)
        text = probe.summarize_captures([w.save(self.path("d.pcap"))])
        self.assertIn("<serial number hidden>", text)
        self.assertNotIn("3100320033", text)
        self.assertIn("E.y.e.-.O.n.e", text)

    def test_new_command_and_odd_status_are_flagged(self):
        w = sio.DarwinWriter()
        w.simple("z9", "00ff")
        w.send(";i1", ":!i1", ":$i13")
        text = probe.analyze_paths([w.save(self.path("n.pcap"))])
        self.assertIn("commands not seen in the first recordings: z9", text)
        self.assertIn("NEW: command 'z9'", text)
        self.assertIn("i1 status 3 x1 (meaning unknown)", text)
        self.assertIn("<-- NOT 0", text)

    def report(self, t0, steps, name="chromiq-io-probe-20991231-000000.txt", exact=True,
               mention=""):
        lines = ["=" * 72, "Stage 2: annotated capture timeline", "=" * 72]
        lines.append("session start (monotonic zero): 2099-12-31T00:00:00")
        if exact:
            lines.append(f"session start (UTC epoch seconds): {t0:.3f}")
        lines += steps
        lines += ["", "=" * 72, "Stage 2: macOS recording result", "=" * 72, mention]
        path = self.path(name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return path

    def test_steps_from_a_154_report_get_their_verdicts(self):
        w, path, (start, end) = self.recording()
        t0 = w.records[0][0]
        rep = self.report(t0, [
            f"One row of a chart that scans in one pass: t={start - t0:8.3f}s .. {end - t0:8.3f}s   (x)",
            f"  mark: head down at t={start - t0 + 1:8.3f}s",
            "A small chart to the end, fastest setting: SKIPPED",
            f"A few patches in spot mode, watching the head: t={end - t0 + 5:8.3f}s .. {end - t0 + 9:8.3f}s"
            "   (x)"])
        text = probe.analyze_paths([path, rep])
        self.assertIn("(exact times)", text)
        self.assertRegex(text, r"One row of a chart that scans in one pass: this step recorded \d+ "
                               r"commands to the table: good")
        self.assertIn("A small chart to the end, fastest setting: skipped", text)
        self.assertIn("A few patches in spot mode, watching the head: no table command was recorded in "
                      "this step: please repeat it", text)
        self.assertIn(">>> OPERATOR: head down", text)
        self.assertIn(">>> STEP: One row of a chart that scans in one pass", text)

    def test_report_next_to_the_recording_is_found_by_name(self):
        w, path, (start, end) = self.recording()
        t0 = w.records[0][0]
        self.report(t0, [f"One row of a chart that scans in one pass: t={start - t0:8.3f}s .. "
                         f"{end - t0:8.3f}s   (x)"], mention=os.path.basename(path))
        text = probe.analyze_paths([path])
        self.assertIn("steps, from chromiq-io-probe-", text)
        self.assertIn(": good", text)

    def test_older_report_times_are_approximate(self):
        w, path, (start, end) = self.recording()
        t0 = w.records[0][0]
        import datetime
        # local clock one hour off UTC, recording 30 s after the session start
        local = datetime.datetime.utcfromtimestamp(t0 - 30 + 3600).isoformat()
        rep = self.report(t0, [f"Scanning: t={start - t0 + 30:8.3f}s .. "
                               f"{end - t0 + 30:8.3f}s   (x)"], exact=False)
        with open(rep, encoding="utf-8") as fh:
            body = fh.read().replace("2099-12-31T00:00:00", local)
        with open(rep, "w", encoding="utf-8") as fh:
            fh.write(body)
        text = probe.analyze_paths([path, rep])
        self.assertIn("times approximate", text)
        # an old step name gets a neutral count, not good / repeat
        self.assertRegex(text, r"Scanning: \d+ commands to the table\n")

    def test_verdict_words(self):
        self.assertEqual(probe.io_step_verdict(14, 3),
                         "this step recorded 14 commands to the table: good")
        self.assertEqual(probe.io_step_verdict(1, 1),
                         "this step recorded 1 command to the table: good")
        self.assertEqual(probe.io_step_verdict(0, 0),
                         "no table command was recorded in this step: please repeat it")
        self.assertIn("none that moves the arm", probe.io_step_verdict(4, 0))

    def test_a_report_alone_is_not_a_recording(self):
        rep = self.report(0.0, [])
        self.assertIn("holds no recording", probe.analyze_paths([rep]))


# --------------------------------------------------------------------------
# 4. the steps
# --------------------------------------------------------------------------

class Steps(TmpCase):

    def test_three_steps_in_order_of_value(self):
        self.assertEqual([s["key"] for s in probe.IO_STEPS], ["row", "spot", "fast", "dual", "earlier"])
        for s in probe.IO_STEPS:
            for field in ("title", "prepare", "do", "arm"):
                self.assertTrue(s[field].strip(), (s["key"], field))

    def test_walk_marks_skip_repeat_and_check(self):
        log, record = [], []
        answers = ["", "d", "", "u", "looked odd", "e", "down on each patch", "r",  # step 1
                   "", "a", "l", "e", "", "",                                   # again
                   "x", "s",                                                     # step 2
                   "", "e", "", "",                                             # step 3
                   "", "e", "", "",                                             # step 4
                   "s"]                                                          # step 5
        checks = []
        with mock.patch.object(probe, "ask", scripted(answers)), redirect_stdout(io.StringIO()) as out:
            how = probe.run_io_steps(probe.IO_STEPS, time.time(), log, record=record,
                                     check=lambda a, b: checks.append((a, b)) or
                                     "this step recorded 3 commands to the table: good")
        self.assertEqual(how, "all steps done")
        self.assertEqual([r["title"] for r in record],
                         ["One row of a chart that scans in one pass", "One row of a chart that scans in one pass (take 2)", "A few patches in spot mode, watching the head", "A small chart to the end, fastest setting", "One row with dual scan (M1 or M2)",
                          "One row of your earlier chart"])
        self.assertTrue(record[2]["skipped"])
        self.assertEqual([m[0] for m in record[1]["marks"]],
                         ["arm starts moving", "lamp lights up"])
        self.assertEqual([m[0] for m in record[0]["marks"]],
                         ["head down", "head up", "note: looked odd"])
        self.assertEqual(len(checks), 4)
        text = "\n".join(log)
        self.assertIn("  arm: down on each patch", text)
        self.assertIn("A few patches in spot mode, watching the head: SKIPPED", text)
        self.assertIn("CHECK: this step recorded 3 commands", out.getvalue())
        # the log reads back as steps and marks
        parsed = probe.io_steps_from_report(
            "Stage 2: annotated capture timeline\n=====\n"
            + "\n".join(probe.io_log_header(1000.0)) + "\n" + text, 0)
        self.assertTrue(parsed["exact"])
        self.assertEqual(len([s for s in parsed["steps"] if not s.get("skipped")]), 4)
        self.assertEqual([m["what"] for m in parsed["marks"]],
                         ["head down", "head up", "note: looked odd", "arm starts moving",
                          "lamp lights up"])

    def test_ctrl_c_keeps_the_finished_steps(self):
        log = []
        answers = ["", "e", "", "", "", "d", KeyboardInterrupt()]
        with mock.patch.object(probe, "ask", scripted(answers)), redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                probe.run_io_steps(probe.IO_STEPS, time.time(), log)
        self.assertTrue(any(l.startswith("One row of a chart that scans in one pass: t=")
                            for l in log))
        cut = [l for l in log if l.endswith("(interrupted)")]
        self.assertEqual(len(cut), 1)
        self.assertTrue(cut[0].startswith("A few patches in spot mode"))
        self.assertIn("  mark: head down at t=", "\n".join(log))

    def test_quit(self):
        log = []
        with mock.patch.object(probe, "ask", scripted(["q"])), redirect_stdout(io.StringIO()):
            self.assertEqual(probe.run_io_steps(probe.IO_STEPS, 0.0, log),
                             "stopped by the operator")

    def test_timed_steps_write_the_log_and_the_answers(self):
        answers = ["", "e", "", ""] * 5 + ["nothing odd", "small.pxf", "A4", "190 mm, 20 patches",
                               "M2, scan", "yes, always", "yes, no light", "no"]
        with mock.patch.object(probe, "ask", scripted(answers)), redirect_stdout(io.StringIO()):
            record = probe.io_timed_steps()
        self.assertEqual(len(record), 5)
        sections = dict(probe._SECTIONS)
        timeline = sections["Stage 2: annotated capture timeline"]
        self.assertIn("session start (UTC epoch seconds): ", timeline)
        self.assertIn("operator notes: nothing odd", timeline)
        answers_text = sections["Stage 2: answers about the chart and the settings"]
        self.assertIn("ruler: 190 mm, 20 patches", answers_text)
        self.assertIn("paper size: A4", answers_text)

    def test_rehearse_records_nothing(self):
        before = set(os.listdir(os.getcwd()))
        with mock.patch.object(probe, "ask", scripted(["", "e", "", ""])), \
                redirect_stdout(io.StringIO()) as out:
            code = probe.main(["--rehearse"])
        self.assertEqual(code, 0)
        screen = out.getvalue()
        self.assertIn("REHEARSAL", screen)
        self.assertIn("HAVE YOU GOT EVERYTHING READY?", screen)
        for s in probe.IO_STEPS:
            self.assertIn(s["title"], screen)
        self.assertIn("nothing to check", screen)
        self.assertEqual(set(os.listdir(os.getcwd())), before)
        self.assertEqual(probe._SECTIONS, [])

    def test_summary_table_says_what_is_missing(self):
        rows = [("One row of a chart that scans in one pass", True, 14, 3),
                ("A few patches in spot mode, watching the head", True, 0, 0),
                ("A small chart to the end, fastest setting", None, 0, 0),
                ("One row with dual scan (M1 or M2)", None, 0, 0),
                ("One row of your earlier chart", None, 0, 0)]
        text = "\n".join(probe.io_summary_table(rows))
        self.assertIn("step", text)
        self.assertIn("recorded", text)
        self.assertIn("table commands", text)
        self.assertIn("<-- no table command: please repeat", text)
        self.assertIn("Still missing: A small chart to the end, fastest setting.", text)
        self.assertIn("(fine if i1Profiler does not offer it)", text)
        self.assertNotIn("dual scan (M1 or M2);", text)
        full = [(s["title"], True, 9, 2) for s in probe.IO_STEPS]
        self.assertIn("Nothing important is missing", "\n".join(probe.io_summary_table(full)))

    def test_the_i1io3_is_named_and_suggested_as_a_table(self):
        self.assertIn("i1iO 3 table", probe.pid_label(0x30B0, 0x0765))
        self.assertIn("protocol is not known", probe.pid_label(0x30B0, 0x0765))
        self.assertEqual(probe.suggest([(0x0765, 0x30B0)])["choice"], 1)
        self.assertIn("i1iO 3", probe.device_name((0x0765, 0x30B0)))

    def test_takes_stay_apart_in_the_table(self):
        title = probe.IO_STEPS[0]["title"]
        text = "\n".join(probe.io_summary_table([(title, True, 0, 0),
                                                 (title + " (take 2)", True, 9, 2)]))
        self.assertIn("1. One row", text)
        self.assertIn("1. (take 2) One row", text)

    def test_cut_off_line_is_not_described_and_control_chars_are_hidden(self):
        w = sio.DarwinWriter()
        w.bulk_out(sio.TABLE, sio.TABLE_PID, 0x02, b";m0\x1b[2J00")
        cap = probe.io_capture(w.save(self.path("cut.pcap")))
        text = "\n".join(probe.io_timeline(cap))
        self.assertIn("(cut off, not described)", text)
        self.assertNotIn("\x1b", text)

    def test_a_repeat_that_worked_counts(self):
        rows = [("One row of a chart that scans in one pass", True, 0, 0),
                ("One row of a chart that scans in one pass (take 2)", True, 9, 2)]
        rows += [(s["title"], True, 5, 1) for s in probe.IO_STEPS[1:]]
        self.assertIn("Nothing important is missing", "\n".join(probe.io_summary_table(rows)))

    def test_live_check_reads_the_growing_file(self):
        w = sio.DarwinWriter(t0=time.time() - 5)
        start = w.t
        sio.table_session(w)
        path = w.save(self.path("live-full.pcap"))
        self.assertIn(": good", probe.io_live_check([path], start, w.t))
        self.assertIn("please repeat it", probe.io_live_check([path], w.t + 10, w.t + 20))
        self.assertIn("could not be read just now", probe.io_live_check([self.path("none")], 0, 1))

    def test_live_reader_reads_only_what_was_added_and_names_a_dead_recorder(self):
        w = sio.DarwinWriter(t0=1000.0)
        w.simple("s0")
        path = self.path("grow-full.pcap")
        blob = w.pcap()
        # half a record at the end, as when tcpdump is in the middle of writing
        with open(path, "wb") as fh:
            fh.write(blob[:-5])
        proc = mock.Mock()
        proc.poll.return_value = None
        reader = probe.IoLiveReader({"XHC2": path}, {"XHC2": proc})
        self.assertIn("none that moves the arm", reader.check(0, 2000))
        first = len(reader.state["XHC2"]["recs"])
        with open(path, "ab") as fh:
            fh.write(blob[-5:])
            w2 = sio.DarwinWriter(t0=1001.0)
            w2.move("m0", 10, 10, 300)
            fh.write(w2.pcap()[24:])
        self.assertIn(": good", reader.check(0, 2000))
        self.assertEqual(len(reader.state["XHC2"]["recs"]),
                         first + 1 + len(w2.records))
        proc.poll.return_value = 0
        self.assertIn("the recording on XHC2 has stopped", reader.check(0, 2000))

    def test_stray_keys_neither_start_nor_end_a_step(self):
        log, record = [], []
        answers = ["x", "", "", "", "e", "", "", "z", "q"]
        with mock.patch.object(probe, "ask", scripted(answers)), redirect_stdout(io.StringIO()) as out:
            probe.run_io_steps(probe.IO_STEPS, time.time(), log, record=record)
        self.assertEqual(len(record), 1)
        self.assertIn("not one of the choices", out.getvalue())
        self.assertIn("still running", out.getvalue())

    def test_closed_input_ends_the_walk(self):
        with mock.patch.object(probe, "ask", scripted([])), redirect_stdout(io.StringIO()):
            self.assertEqual(probe.run_io_steps(probe.IO_STEPS, 0.0, []),
                             "stopped by the operator")


# --------------------------------------------------------------------------
# 5. texts
# --------------------------------------------------------------------------

class Texts(unittest.TestCase):

    def test_arm_text_for_the_i1pro3_does_not_overclaim(self):
        t = probe.windows_release_check(26100, "24H2", True, "i1pro3")
        self.assertEqual(t["level"], "problem")
        self.assertIn("is not known", t["text"])
        self.assertIn("Intel or AMD", t["text"])
        self.assertNotIn("cannot talk", t["text"])

    def test_arm_text_for_the_others(self):
        for profile in ("i1pro2", "i1pro", "munki", None):
            t = probe.windows_release_check(26100, "24H2", True, profile)
            self.assertEqual(t["level"], "problem")
            self.assertIn("We know of no X-Rite driver", t["text"])
            self.assertIn("most likely cannot talk", t["text"])
            self.assertIn("USBPcap", t["text"])
            self.assertIn("Intel or AMD", t["text"])
        self.assertIn("We know of no X-Rite driver", probe.WINDOWS_ARM_NOTE)
        self.assertIn("Intel or AMD", probe.WINDOWS_ARM_NOTE)

    def test_mac_help_on_windows_vms(self):
        r = {"reasons": ["x"], "cpu": {"apple_silicon": True}}
        text = probe.recording_not_possible_text(r)
        self.assertNotIn("there is no i1Pro or i1iO driver", text)
        self.assertIn("USBPcap) does not exist", text)

    def test_sip_box_has_the_exact_steps_and_the_check(self):
        for apple in (True, False):
            box = probe.sip_back_on_box(apple)
            self.assertIn("PLEASE SWITCH SIP BACK ON", box)
            self.assertIn("csrutil enable", box)
            self.assertIn("csrutil status", box)
            self.assertIn('"enabled"', box)
            self.assertIn("power button" if apple else "Command and R", box)
            widths = {len(l) for l in box.splitlines()}
            self.assertEqual(len(widths), 1, "box lines are not all the same width")
            self.assertLessEqual(widths.pop(), 80)

    def _finish(self, sip_box):
        ns = mock.Mock(output=os.path.join(tempfile.gettempdir(), "x-probe-test.txt"))
        probe._READINESS.clear()
        probe._READINESS.update({"sip": "off", "cpu": {"apple_silicon": True}})
        probe._END.clear()
        if sip_box:
            probe._END["sip_box"] = True
        probe._IO_SUMMARY[:] = ["THE STEPS AT A GLANCE", "Nothing important is missing."]
        self.addCleanup(probe._READINESS.clear)
        self.addCleanup(probe._IO_SUMMARY.clear)
        self.addCleanup(probe._END.clear)
        try:
            with redirect_stdout(io.StringIO()) as out:
                probe.finish_report(ns, "Darwin")
                print("\n".join(probe.end_of_run_lines()))
        finally:
            if os.path.exists(ns.output):
                os.remove(ns.output)
        return out.getvalue().rstrip()

    def test_sip_box_is_the_last_thing_after_a_mac_recording(self):
        screen = self._finish(sip_box=True)
        self.assertTrue(screen.endswith("+"), screen[-200:])
        self.assertLess(screen.index("That's everything"), screen.index("THE STEPS AT A GLANCE"))
        self.assertLess(screen.index("THE STEPS AT A GLANCE"),
                        screen.index("PLEASE SWITCH SIP BACK ON"))

    def test_no_big_box_when_nothing_was_recorded(self):
        screen = self._finish(sip_box=False)
        self.assertNotIn("PLEASE SWITCH SIP BACK ON", screen)
        self.assertIn("REMINDER: System Integrity Protection (SIP) is switched OFF", screen)

    def test_the_box_comes_after_what_to_do_now(self):
        probe._READINESS.clear()
        probe._READINESS.update({"sip": "off", "cpu": {"apple_silicon": False}})
        self.addCleanup(probe._READINESS.clear)

        def fake_main(_argv):
            probe._END["sip_box"] = True
            probe._CAUSES[:] = ["no_instrument"]
            return 0
        with mock.patch.object(probe, "main", fake_main), \
                mock.patch.object(probe, "should_pause", lambda _a: False), \
                redirect_stdout(io.StringIO()) as out:
            probe.console_main(["--no-pause"])
        probe._CAUSES.clear()
        probe._END.clear()
        screen = out.getvalue()
        self.assertLess(screen.index("WHAT TO DO NOW"), screen.index("PLEASE SWITCH SIP BACK ON"))
        self.assertIn("Command and R", screen)

    def test_no_em_dash_in_the_new_files(self):
        for name in ("test_io_table.py", "synth_io.py"):
            with open(os.path.join(HERE, name), encoding="utf-8") as fh:
                self.assertNotIn(chr(0x2014), fh.read(), name)


if __name__ == "__main__":
    unittest.main()
