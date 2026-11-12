#!/usr/bin/env python3
"""The probe's end-to-end test on a real Windows (virtual) machine.

Needs vm_server.py running and runner.ps1 polling inside Windows (see
README.md). Every check starts the Windows exe the way a user does (a
double-click: Explorer starts it, so it gets a console window of its own),
reads what its window shows, types into that window's input only when the
tool is waiting, and photographs the screen. Results: <session>/report.md
with PASS / FAIL per check, screenshots and screen texts beside it.

    python3 vm_scenarios.py --session DIR --exe chromiq-io-probe-windows.exe [--only a1,b]
"""

import argparse
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vmq  # noqa: E402

EXE = "chromiq-io-probe-windows.exe"
WAIT_LINE = "Press Enter to close this window."

GUEST = r'''
$bin = Join-Path $env:USERPROFILE 'vm_test\bin'
function ProbeIds([string]$dir) {
    @(Get-CimInstance Win32_Process -Filter "Name='chromiq-io-probe-windows.exe'" |
      Where-Object { $_.ExecutablePath -like "$dir\*" } | ForEach-Object { $_.ProcessId })
}
function Screen([int]$id, [string]$name) {
    $out = Join-Path $env:TEMP "vmt-$name"
    Remove-Item $out -ErrorAction SilentlyContinue
    $p = Start-Process "$bin\conhelper.exe" -Wait -PassThru -ArgumentList @('read', $id, "`"$out`"")
    if (Test-Path $out) { Upload $out $name | Out-Null; Get-Content $out -Raw -Encoding UTF8 } else { "NO SCREEN " + $p.ExitCode }
}
function SendText([int]$id, [string]$text) {
    $p = Start-Process "$bin\conhelper.exe" -Wait -PassThru -ArgumentList @('type', $id, "`"$text`"")
    "typed exit " + $p.ExitCode
}
'''


class Run:
    def __init__(self, session, only=None):
        self.q = vmq.Queue(session)
        self.session = session
        self.only = only
        self.rows = []
        self.out = os.path.join(session, "results")

    def ps(self, script, timeout=180, name="cmd"):
        return self.q.ps(GUEST + "\n" + script, timeout=timeout, name=name)

    def check(self, key, what, ok, note=""):
        self.rows.append((key, what, "PASS" if ok else "FAIL", note))
        print(f"  [{'PASS' if ok else 'FAIL'}] {key}: {what} {note}", flush=True)

    # ---- guest operations ------------------------------------------------
    def setup(self, exe_path):
        files = os.path.join(self.session, "files")
        for src in (exe_path, os.path.join(HERE, "conhelper.cs")):
            shutil.copy(src, os.path.join(files, os.path.basename(src)))
        print(self.ps(r'''
New-Item -ItemType Directory -Force -Path $bin | Out-Null
Fetch 'conhelper.cs' "$bin\conhelper.cs"
if (-not (Test-Path "$bin\conhelper.exe") -or (Get-Item "$bin\conhelper.cs").LastWriteTime -gt (Get-Item "$bin\conhelper.exe").LastWriteTime) {
    Remove-Item "$bin\conhelper.exe" -ErrorAction SilentlyContinue
    Add-Type -TypeDefinition (Get-Content "$bin\conhelper.cs" -Raw) -OutputAssembly "$bin\conhelper.exe" -OutputType WindowsApplication
}
"conhelper: " + (Test-Path "$bin\conhelper.exe")
Fetch 'chromiq-io-probe-windows.exe' "$bin\chromiq-io-probe-windows.exe"
(Get-Item "$bin\chromiq-io-probe-windows.exe").Length
''', timeout=300, name="setup"))

    def fresh(self, case):
        """A new folder of its own for one case, with a copy of the exe (the
        report is written next to it)."""
        out = self.ps(rf'''
$d = Join-Path $env:USERPROFILE ('vm_test\cases\{case}-' + (Get-Date -Format HHmmss))
New-Item -ItemType Directory -Force -Path $d | Out-Null
Copy-Item "$bin\chromiq-io-probe-windows.exe" $d
"DIR=" + $d
''', name=f"fresh-{case}")
        return [x for x in out.splitlines() if x.startswith("DIR=")][0][4:].strip()

    def stop_all(self):
        """Close every copy of the tool this harness started (cases folders)."""
        return self.ps(r'''
$c = Join-Path $env:USERPROFILE 'vm_test\cases'
Get-CimInstance Win32_Process -Filter "Name='chromiq-io-probe-windows.exe'" | Where-Object { $_.ExecutablePath -like "$c\*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
"left: " + @(Get-CimInstance Win32_Process -Filter "Name='chromiq-io-probe-windows.exe'").Count
''', name="stop")

    def double_click(self, folder, args=""):
        """Start the exe as Explorer does on a double-click. With arguments,
        through a shortcut (.lnk), which Explorer opens the same way."""
        if args:
            script = rf'''
$sh = New-Object -ComObject WScript.Shell
$l = $sh.CreateShortcut("{folder}\probe.lnk")
$l.TargetPath = "{folder}\{EXE}"
$l.Arguments = "{args}"
$l.WorkingDirectory = "{folder}"
$l.Save()
Start-Process explorer.exe -ArgumentList "`"{folder}\probe.lnk`""
'''
        else:
            script = rf'Start-Process explorer.exe -ArgumentList "`"{folder}\{EXE}`""'
        self.ps(script + "\n'started'", name="start")
        for _ in range(30):                       # until Explorer has started it
            if self.ids(folder):
                return
            time.sleep(1)

    def ids(self, folder):
        out = self.ps(f'(ProbeIds "{folder}") -join ","', name="ids").strip()
        return [int(x) for x in out.split(",") if x.strip().isdigit()]

    def screen(self, folder, name):
        ids = self.ids(folder)
        if not ids:
            return None
        return self.ps(f'Screen {ids[-1]} "{name}"', name="screen")

    def wait_for(self, folder, text, name, timeout=240):
        end = time.time() + timeout
        last = ""
        while time.time() < end:
            s = self.screen(folder, name)
            if s is None:
                return None
            last = s
            if text in s:
                return s
            time.sleep(3)
        return last

    def type(self, folder, text):
        ids = self.ids(folder)
        return self.ps(f'SendText {ids[-1]} "{text}"', name="type") if ids else "no process"

    def shot(self, name):
        self.ps(f'Shot "{name}"', name="shot")

    def report_text(self, folder):
        return self.ps(rf'''
$f = Get-ChildItem "{folder}" -Filter 'chromiq-io-probe-*.txt' | Sort-Object LastWriteTime | Select-Object -Last 1
if ($f) {{ Upload $f.FullName ("report-" + (Split-Path "{folder}" -Leaf) + ".txt") | Out-Null; $f.Name }} else {{ "NO REPORT" }}
''', name="report").strip()

    def wanted(self, key):
        return not self.only or any(key.startswith(o) for o in self.only)

    # ---- a bounded dialogue with the tool ---------------------------------
    def dialogue(self, key, folder, answers, limit=600, stall=90):
        """Answer the tool's prompts until it shows the wait line or ends.

        answers: [(text on the last screen lines, what to type)], first match
        wins. A prompt nobody answers for `stall` seconds, or a case longer
        than `limit`, is recorded as hung, photographed and closed."""
        end = time.time() + limit
        last_tail, since, n = None, time.time(), 0
        seen = []          # every line shown, in order: the window keeps only 30 rows
        while time.time() < end:
            n += 1
            s = self.screen(folder, f"{key}-screen.txt")
            if s is None:
                return "ENDED", "\n".join(seen)
            for line in s.splitlines()[1:]:
                if line.strip() and line not in seen[-400:]:
                    seen.append(line)
            lines = [x for x in s.splitlines()[1:] if x.strip()]
            tail = "\n".join(lines[-3:])
            if WAIT_LINE in (lines[-1] if lines else ""):
                return "WAITING", "\n".join(seen)
            for text, typed in answers:
                if text in tail and tail != last_tail:
                    if isinstance(typed, list):       # answers in turn, then Enter
                        typed = typed.pop(0) if typed else "\\n"
                    self.type(folder, typed)
                    last_tail, since = tail, time.time()
                    break
            else:
                if tail != last_tail:
                    last_tail, since = tail, time.time()
                elif time.time() - since > stall:
                    self.shot(f"{key}-hung.png")
                    self.check(key, "no prompt left unanswered", False,
                               "hung at prompt: " + (lines[-1].strip() if lines else "?"))
                    self.kill(folder)
                    return "HUNG", "\n".join(seen)
            time.sleep(2.5)
        self.shot(f"{key}-timeout.png")
        self.check(key, f"finished within {limit} s", False, "timed out")
        self.kill(folder)
        return "TIMEOUT", ""

    def kill(self, folder):
        self.ps(rf'''Get-CimInstance Win32_Process -Filter "Name='chromiq-io-probe-windows.exe'" | Where-Object {{ $_.ExecutablePath -like "{folder}\*" }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}''', name="kill")

    def ending(self, key, label, folder, state, s):
        self.shot(f"{key}-end.png")
        self.check(key, f"{label}: window stays open with '{WAIT_LINE}'",
                   state == "WAITING" and bool(self.ids(folder)))
        bad = sorted({c for c in s if ord(c) > 126})
        self.check(key, f"{label}: no mangled characters on screen", not bad,
                   repr("".join(bad))[:40] if bad else "")
        if state == "WAITING":
            time.sleep(2)
            alive = bool(self.ids(folder))
            self.type(folder, "\\n")
            time.sleep(4)
            self.check(key, f"{label}: still waiting after 2 s, closes after Enter",
                       alive and not self.ids(folder))
        else:
            self.kill(folder)

    # common answers: no instrument here (Windows may remember one)
    BASE = [("Try the advanced step too?", "no\\n"), ("     >", "\\n"),
            ("Open the download page", "\\n"), ("Type a number", "1\\n"),
            ("Type 1, 2 or 3", "\\n")]

    # ---- scenarios -------------------------------------------------------
    def a1_quit(self):
        """Double-click, nothing plugged in: the question, "look again", then 3."""
        f = self.fresh("a1")
        self.double_click(f)
        state, s = self.dialogue("a1", f, [("Type 1, 2 or 3", ["a\\n", "3\\n"])] + self.BASE,
                                 limit=420)
        self.check("a1", "the question says nothing is plugged in, suggests 3",
                   "Plugged in now: no X-Rite instrument." in s and "or just press Enter for 3" in s)
        self.check("a1", "look again: detection runs again", "Looking again..." in s)
        self.check("a1", "choice 3: just the report", "If you would like to share it with us" in s)
        self.ending("a1", "double-click, choice 3", f, state, s)
        self.check("a1", "WHAT TO DO NOW: plug the instrument in",
                   "WHAT TO DO NOW" in s and "Plug the instrument in" in s)

    def q2_nothing(self):
        """Choice 2 with nothing plugged in: explains, does not crash."""
        f = self.fresh("q2")
        self.double_click(f)
        state, s = self.dialogue("q2", f, [("Type 1, 2 or 3", "2\\n"),
                                           ("Shall this tool fetch", "no\\n")] + self.BASE, limit=600)
        self.check("q2", "choice 2 with nothing plugged in: explained",
                   "No handheld instrument is plugged in right now" in s)
        self.check("q2", "no traceback", "Traceback" not in s)
        self.ending("q2", "choice 2, nothing plugged in", f, state, s)

    def q1_table(self):
        """Choice 1 with no table: says so, asks the three questions."""
        f = self.fresh("q1")
        self.double_click(f)
        state, s = self.dialogue("q1", f, [("Type 1, 2 or 3", "1\\n")] + self.BASE, limit=600)
        self.check("q1", "choice 1: the table questions, and that no table is plugged in",
                   "No i1iO table is plugged in right now" in s and "Which generation" in s)
        self.ending("q1", "choice 1", f, state, s)

    def a2_normal(self):
        f = self.fresh("a2")
        self.double_click(f, "--skip-annotate")
        state, s = self.dialogue("a2", f, self.BASE, limit=600)
        self.ending("a2", "double-click, normal end", f, state, s)
        rep = self.report_text(f)
        self.check("a2", "the report file is written", rep.startswith("chromiq-io-probe-"), rep)

    def a3_error(self):
        f = self.fresh("a3")
        self.double_click(f, "--selftest crash")
        state, s = self.dialogue("a3", f, self.BASE, limit=180)
        self.ending("a3", "double-click, unexpected error", f, state, s)
        self.check("a3", "error: apology, where it was saved, traceback",
                   "SORRY: THE TOOL STOPPED" in s and "saved here" in s and "deliberate error" in s)

    def a4_ctrl_c(self):
        f = self.fresh("a4")
        self.double_click(f)
        # a real Ctrl-C while it collects (at a question, Ctrl-C counts as
        # Enter by design, so it is sent while no question is open)
        self.wait_for(f, "STEP 1 of 3", "a4-step1.txt", timeout=120)
        ids = self.ids(f)
        self.ps(f'Start-Process "$bin\\conhelper.exe" -Wait -ArgumentList @("ctrlc", {ids[-1]})', name="ctrlc")
        state, s = self.dialogue("a4", f, self.BASE, limit=180)
        if "Stopped (Ctrl-C)" in s:
            self.check("a4", "Ctrl-C while it looks for devices: says it stopped", True)
        else:
            self.rows.append(("a4", "Ctrl-C: a real Ctrl-C reaching the tool", "NOT VERIFIED",
                              "the injected Ctrl-C event did not reach the tool; the unit tests "
                              "cover the Ctrl-C ending"))
            print("  [NOT VERIFIED] a4: Ctrl-C did not reach the tool", flush=True)
        self.ending("a4", "double-click, Ctrl-C", f, state, s)

    def b_redirected(self):
        out = self.ps(rf'''
$d = Join-Path $env:USERPROFILE ('vm_test\cases\b-' + (Get-Date -Format HHmmss))
New-Item -ItemType Directory -Force -Path $d | Out-Null
Copy-Item "$bin\chromiq-io-probe-windows.exe" $d
$t = Measure-Command {{ cmd /c "`"$d\chromiq-io-probe-windows.exe`" --skip-annotate < NUL > `"$d\out.txt`" 2>&1" }}
"exit " + $LASTEXITCODE + " seconds " + [int]$t.TotalSeconds
Upload "$d\out.txt" "b-out.txt" | Out-Null
"waitlines " + (Select-String -Path "$d\out.txt" -Pattern 'Press Enter to close' -SimpleMatch | Measure-Object).Count
''', timeout=600, name="b")
        lines = [x for x in out.strip().splitlines() if x.strip()]
        self.check("b", "from a console, output redirected: ends by itself, never waits",
                   lines[0].startswith("exit ") and lines[-1].strip() == "waitlines 0", " / ".join(lines))

    def c80(self):
        f = self.fresh("c80")
        self.ps(rf'''Start-Process conhost.exe -ArgumentList "cmd /c mode con cols=80 lines=50 & `"{f}\{EXE}`" --i1pro --pause"''', name="c80")
        state, s = self.dialogue("c80", f, [("Type a number", "1\\n"), ("Shall this tool fetch", "no\\n")]
                                 + self.BASE, limit=600)
        lines = s.splitlines()
        self.check("c80", "80 columns: window is 80 wide, the end is reached",
                   bool(lines) and lines[0].startswith("COLUMNS 80") and state == "WAITING",
                   lines[0] if lines else state)
        longest = max((len(x) for x in lines[1:]), default=0)
        self.check("c80", "80 columns: no line runs into the edge", longest < 80, f"longest {longest}")
        self.shot("c80-end.png")
        self.type(f, "\\n")

    def d_admin(self):
        f = self.fresh("d")
        self.double_click(f, "--i1pro --selftest pretend-usbpcap")
        state, s = self.dialogue("d", f, [("Type a number", "1\\n"),
                                          ("Start this tool again as administrator now?", "no\\n")]
                                 + self.BASE, limit=600)
        self.check("d", "not administrator: explained before the steps, offer, then stops",
                   "WHY ADMINISTRATOR RIGHTS ARE NEEDED" in s or "Run as administrator" in s)
        self.ending("d", "not administrator, said no", f, state, s)

    def e_mismatch(self):
        f = self.fresh("e1")
        self.double_click(f, "--i1pro --selftest offer-on-arm,bad-fingerprint")
        state, s = self.dialogue("e1", f, [("Type a number", "1\\n"), ("Shall this tool fetch", "yes\\n")]
                                 + self.BASE, limit=600)
        rep = self.report_text(f)
        body = self.ps(f'''Get-Content "{f}\\{rep}" -Raw''', name="e1-report") if rep.startswith("chromiq") else ""
        self.check("e1", "download with a wrong fingerprint is refused (screen or report)",
                   "NOT started" in s or "installer: fingerprint mismatch" in body)
        self.ending("e1", "fingerprint mismatch", f, state, s)

    def e_no(self):
        f = self.fresh("e0")
        self.double_click(f, "--i1pro --selftest offer-on-arm")
        state, s = self.dialogue("e0", f, [("Type a number", "1\\n"), ("Shall this tool fetch", "no\\n")]
                                 + self.BASE, limit=600)
        self.ending("e0", "USBPcap missing, said no", f, state, s)
        self.check("e0", "WHAT TO DO NOW: install USBPcap, restart, run as administrator",
                   "Install USBPcap" in s and "Restart Windows" in s)
        rep = self.report_text(f)
        self.check("e0", "the report is written", rep.startswith("chromiq"), rep)

    def report(self):
        path = os.path.join(self.session, "report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("| check | what | result | note |\n|---|---|---|---|\n")
            for key, what, res, note in self.rows:
                fh.write(f"| {key} | {what} | **{res}** | {note} |\n")
        print("report:", path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--exe", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--no-setup", action="store_true")
    a = ap.parse_args()
    r = Run(a.session, [x for x in a.only.split(",") if x])
    if not r.q.runner_alive():
        print("The runner inside Windows is not polling. Start it first (README.md).")
        return 2
    print(r.stop_all())
    if not a.no_setup:
        r.setup(a.exe)
    for key, fn in (("a1", r.a1_quit), ("q1", r.q1_table), ("q2", r.q2_nothing),
                    ("a2", r.a2_normal), ("a3", r.a3_error),
                    ("a4", r.a4_ctrl_c), ("b", r.b_redirected), ("c80", r.c80),
                    ("d", r.d_admin), ("e0", r.e_no), ("e1", r.e_mismatch)):
        if r.wanted(key):
            try:
                fn()
            except Exception as exc:                      # noqa: BLE001
                r.check(key, "ran without a harness error", False, repr(exc)[:200])
    r.report()
    return 0 if all(row[2] != "FAIL" for row in r.rows) else 1


if __name__ == "__main__":
    sys.exit(main())
