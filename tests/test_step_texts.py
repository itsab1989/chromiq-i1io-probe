"""1.6.2: every step says what to do as a short numbered list, one action
per line, as a tester asked ("it would be nice to start each step on a new
line ... keep it simple with simple steps on each new line").

    python3 -m unittest discover -s tests -v
"""

import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import chromiq_io_probe as probe  # noqa: E402

ITEM = re.compile(r"^\s*(\d+)\.\s+(.*)$")


def numbered_items(text):
    """The numbered items of a text, each with its wrapped lines joined
    (inside a step box, without its frame)."""
    items = []
    for line in text.splitlines():
        if line.startswith("  |"):
            line = line[3:].rstrip().rstrip("|")
            if line.strip().startswith("Then"):      # the box's heading line
                continue
        elif line.startswith("  +"):
            continue
        m = ITEM.match(line)
        if m:
            items.append((int(m.group(1)), m.group(2).strip()))
        elif items and line.strip():
            n, body = items[-1]
            items[-1] = (n, body + " " + line.strip())
    return items


def without_brackets(text):
    while True:
        new = re.sub(r"\([^()]*\)", "", text)
        if new == text:
            return text
        text = new


def all_texts():
    for profile in ("i1pro2", "i1pro", "i1pro3", "munki", "generic", "isis"):
        for step in probe.steps_for(profile):
            yield f"{profile}/{step['key']}/before", step["before"]
            yield f"{profile}/{step['key']}/during", step["during"]
            yield (f"{profile}/{step['key']}/box",
                   probe.step_box(step["during"], step.get("box", "Then do this in the "
                                                                   "measuring program: ")))
    for step in probe.IO_STEPS:
        yield f"io/{step['key']}/prepare", step["prepare"]
        yield f"io/{step['key']}/do", step["do"]


class OneActionPerLine(unittest.TestCase):

    def test_every_instruction_is_a_numbered_list(self):
        for name, text in all_texts():
            with self.subTest(text=name):
                items = numbered_items(text)
                self.assertTrue(items, "no numbered list")
                self.assertEqual([n for n, _b in items], list(range(1, len(items) + 1)))

    def test_no_item_holds_two_sentences(self):
        """The checkable rule: outside brackets, no item has a full stop,
        question mark, exclamation mark or semicolon followed by more text.
        (A colon may introduce the detail of the same action.)"""
        for name, text in all_texts():
            for n, body in numbered_items(text):
                with self.subTest(text=name, item=n):
                    plain = without_brackets(body.replace("|", " "))
                    plain = " ".join(plain.split())
                    self.assertIsNone(re.search(r"[.!?;]\s+\S", plain), body)

    def test_lines_fit_an_80_column_console(self):
        for name, text in all_texts():
            for line in text.splitlines():
                with self.subTest(text=name):
                    self.assertLessEqual(len(line), 78, line)

    def test_the_fast_and_slow_steps_say_it_concretely(self):
        steps = {s["key"]: " ".join((s["before"] + " " + s["during"]).split())
                 for s in probe.steps_for("i1pro2")}
        self.assertIn("signals that it is ready", steps["scan-fast"])
        self.assertIn("do not move yet", steps["scan-fast"])
        self.assertIn("twice as long as in the normal scan of step 3", steps["scan-slow"])
        self.assertIn("Count the seconds", steps["scan-slow"])

    def test_the_condition_is_asked_where_it_matters(self):
        asked = {s["key"] for s in probe.steps_for("i1pro2") if s.get("setting")}
        self.assertEqual(asked, {"calibrate", "scan-single", "scan-dual", "scan-fast",
                                 "scan-slow", "scan-fail", "spot", "noruler"})
        for key in ("scan-single", "spot"):
            step = [s for s in probe.steps_for("i1pro2") if s["key"] == key][0]
            self.assertIn("M0, M1", step["setting"])

    def test_no_question_or_box_line_is_wider_than_79_columns(self):
        for profile in ("i1pro2", "i1pro", "i1pro3", "munki", "generic", "isis"):
            for step in probe.steps_for(profile):
                shown = [probe.step_box(step["during"], step.get("box", "Then do this in the "
                                                                         "measuring program: "))]
                for key in ("lights", "setting", "page"):
                    if step.get(key):
                        shown.append("  " + probe._question(step[key]))
                for text in shown:
                    for line in text.splitlines():
                        with self.subTest(step=f"{profile}/{step['key']}"):
                            self.assertLessEqual(len(line), 79, line)

    def test_a_stop_key_is_not_taken_as_the_notes(self):
        for word in ("e", " E ", "end", "done", "q"):
            self.assertTrue(probe.is_stop_word(word), word)
        for word in ("strip A, accepted", "ok", "e-mail", ""):   # empty: notes are optional
            self.assertFalse(probe.is_stop_word(word), word)

    def test_the_session_prompts_fit_79_columns_with_their_trailing_space(self):
        with open(os.path.join(os.path.dirname(HERE), "chromiq_io_probe.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        start = src.index("def run_instrument_session")
        body = src[start:src.index("\nSHORT_STEP_SECONDS", start)]
        for m in re.finditer(r'_session_ask\(\s*((?:f?"(?:[^"\\]|\\.)*"\s*)+)', body):
            text = "".join(re.findall(r'f?"((?:[^"\\]|\\.)*)"', m.group(1)))
            text = text.replace("\\n", "\n")
            for line in text.split("\n"):
                if "{" in line:
                    continue                    # filled in at run time, checked elsewhere
                self.assertLessEqual(len(line), 79, repr(line))

    def test_no_em_dash(self):
        for name, text in all_texts():
            self.assertNotIn(chr(0x2014), text, name)


if __name__ == "__main__":
    unittest.main()
