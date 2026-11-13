"""1.6, second review: every session type except the i1iSis keeps EXACTLY
what 1.5.5 kept, and --analyze reads a plain file as 1.5.5 did unless the
only X-Rite device it knows in it is an i1iSis.

    python3 -m unittest discover -s tests -v

The expected results are tests/fixtures/v155-kept.json, written by
tools/make_v155_kept_fixture.py from the tagged v1.5.5 itself. The
recordings are invented (tests/regression_recordings.py).
"""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import chromiq_io_probe as probe  # noqa: E402

import regression_recordings as rr  # noqa: E402

with open(os.path.join(HERE, "fixtures", "v155-kept.json"), encoding="utf-8") as _fh:
    V155 = json.load(_fh)

# Every session type the tool has, except the i1iSis: None (a caller from
# before 1.6), the i1iO table, and every handheld profile.
OLD_TYPES = (None, probe.SESSION_TABLE, "i1pro2", "i1pro", "i1pro3", "munki", "generic")
# Plain files whose only known X-Rite device is an i1iSis: read as i1iSis.
ISIS_ONLY = {"B-two-isis-keyboard", "M-isis-with-display", "N-mac-isis-with-display"}


class SameAsV155(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.files = rr.save_all(os.path.join(cls.tmp.name, "rec"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_fixture_is_from_v155(self):
        self.assertEqual(V155["version"], "1.5.5")
        self.assertEqual(set(V155["copies"]), set(rr.CASES))

    def test_every_old_session_type_keeps_what_v155_kept(self):
        for name, path in self.files.items():
            for profile in OLD_TYPES:
                with self.subTest(recording=name, session=profile):
                    self.assertEqual(rr.outcome(probe, path, self.tmp.name, profile),
                                     V155["copies"][name])

    def test_analyze_reads_plain_files_as_v155(self):
        for name, path in self.files.items():
            if name in ISIS_ONLY:
                continue
            with self.subTest(recording=name):
                self.assertEqual(rr.analysis_outcome(probe, path), V155["analysis"][name])


class ReviewCases(unittest.TestCase):
    """The second review's cases F, H2 and G (review/re/compare.py)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.files = rr.save_all(os.path.join(cls.tmp.name, "rec"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_F_the_table_session_keeps_the_table(self):
        got = rr.outcome(probe, self.files["F-i1io-table-with-isis"], self.tmp.name,
                         probe.SESSION_TABLE)
        self.assertIn("i1iO", got["kept"])
        self.assertEqual(got["check"], "ok")

    def test_H2_the_table_on_a_mac_too(self):
        got = rr.outcome(probe, self.files["H2-mac-i1io-table-with-isis"], self.tmp.name,
                         probe.SESSION_TABLE)
        self.assertIn("i1iO", got["kept"])

    def test_G_a_handheld_file_with_an_isis_is_read_as_handheld(self):
        got = rr.analysis_outcome(probe, self.files["G-i1pro2-with-isis"])
        self.assertNotIn("i1iSis", " ".join(got["family"]))
        self.assertIn("0971:2000", got["instrument_ids"])

    def test_finish_recordings_keeps_the_table_beside_an_isis(self):
        # Third review nit: drive the table session's own finish, not its text.
        import io as io_mod
        import shutil
        from contextlib import redirect_stdout
        for name in ("F-i1io-table-with-isis", "H2-mac-i1io-table-with-isis"):
            with self.subTest(recording=name):
                full = os.path.join(self.tmp.name, f"io-capture-x-{name}-full.pcap")
                shutil.copy(self.files[name], full)
                with redirect_stdout(io_mod.StringIO()):
                    probe.finish_recordings({"XHC0": full}, None, ask_delete=False)
                copy = full.replace("-full.pcap", "-xrite.pcap")
                self.assertIn("i1iO", rr.markers_in(copy))
                self.assertNotIn("keyboard", rr.markers_in(copy))

    def test_the_finish_of_the_table_session_names_its_type(self):
        with open(os.path.join(ROOT, "chromiq_io_probe.py"), encoding="utf-8") as fh:
            src = fh.read()
        part = src[src.index("def finish_recordings"):src.index("def finish_recordings") + 1200]
        self.assertIn("check_capture(path, SESSION_TABLE)", part)
        self.assertIn("filter_xrite_capture(path, dst, SESSION_TABLE)", part)

    def test_isis_with_a_monitor_calibrator_is_read_as_isis_without_it(self):
        for name in ("M-isis-with-display", "N-mac-isis-with-display"):
            with self.subTest(recording=name):
                rep = probe.analyze_paths([self.files[name]])
                detail = rep.split("Instrument recording analysis")[1]
                self.assertIn("instrument family: i1iSis chart reader", detail)
                self.assertNotIn("0765:5020", detail)
                self.assertNotIn("DISPLAY-SERIAL", rep)
                self.assertEqual(detail.count("instrument at bus"), 1)

    def test_isis_with_an_i1pro2_stays_handheld_as_in_v155(self):
        got = rr.analysis_outcome(probe, self.files["G-i1pro2-with-isis"])
        self.assertEqual(got, V155["analysis"]["G-i1pro2-with-isis"])

    def test_a_plain_isis_only_file_is_read_as_isis(self):
        got = rr.analysis_outcome(probe, self.files["B-two-isis-keyboard"])
        self.assertIn("instrument family: i1iSis chart reader", " ".join(got["family"]))
        self.assertNotIn("keyboard", got["markers"])


if __name__ == "__main__":
    unittest.main()
