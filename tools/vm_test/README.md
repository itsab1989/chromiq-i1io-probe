# The probe on a real Windows: an end-to-end test

The unit tests (`tests/`) run everywhere with stand-ins. This folder drives
the **built Windows exe** on a real Windows machine (a virtual machine is
fine) the way a user does, and writes a PASS / FAIL list with screen texts
and screenshots. It needs no password inside Windows and installs nothing
there.

## How it works

- `vm_server.py` runs on the test host: a small HTTP command queue (standard
  library only). Bind it **only** to the address the Windows machine reaches
  the host on (for a VMware Fusion NAT network the vmnet8 host address, for
  example `192.168.248.1`), never to every interface: whoever reaches the
  port can run commands in that Windows session.
- `runner.ps1` runs inside Windows, as the signed-in user, started once by
  pasting one line into a PowerShell window:

      iex(iwr http://192.168.248.1:8765/r -UseB).Content

  It asks the server for the next command every second, runs it and sends
  the output back. Close its window to stop it.
- `conhelper.cs` is compiled inside Windows on first use (by PowerShell's
  `Add-Type`) into `conhelper.exe`, a program WITHOUT a console of its own.
  It reads the text of the tool's window and types into the tool's input
  (WriteConsoleInput), so the harness answers prompts without focus and
  without any host keystroke, and never writes into the tool's window. (A
  PowerShell helper did that: after attaching to the tool's console its host
  printed "invalid handle" errors there. That was the harness, not the tool.)
- `winshot.cs` (compiled the same way) photographs ONE window by a part of
  its title (PrintWindow, DPI aware), for clean pictures of the tool's
  window; `conhelper.exe scroll <pid> <row|end>` moves a console's view, so
  text that scrolled away can be photographed.
- `vm_scenarios.py` holds the checks. Each case runs in its own folder
  (`%USERPROFILE%\vm_test\cases\<case>-<time>`) with its own copy of the exe.
  The exe is started **as a double-click is**: by Explorer, with a shortcut
  (.lnk) when it needs arguments, so it gets a console window of its own.
  Every case is a bounded dialogue: prompts the case knows are answered, a
  prompt nobody answers for 90 s is recorded as "hung at prompt: <text>",
  photographed, and the tool is closed; the run goes on.

## The checks

| case | what |
|---|---|
| a1 | double-click, no arguments, no instrument: ends with WHAT TO DO NOW, stays open on "Press Enter to close this window.", closes on Enter |
| a2 | double-click, `--skip-annotate`, the normal end; the report file is written |
| a3 | double-click, `--selftest crash`: the apology, where it was saved, the traceback, then the wait |
| a4 | double-click, a Ctrl-C keystroke: "Stopped (Ctrl-C)", then the wait |
| b | started from a console with input and output redirected: ends by itself, never waits |
| c80 | an 80-column console: readable, no line runs into the edge |
| d | not administrator (`--selftest pretend-usbpcap`): explained before the steps, the offer to start again as administrator, "no" |
| e0 | USBPcap missing (`--selftest offer-on-arm`): the facts, the question, "no", WHAT TO DO NOW, report |
| e1 | `--selftest offer-on-arm,bad-fingerprint`: the download is refused and never started |

The cases that need Windows' own permission window (UAC) to be answered,
which no program inside Windows can do by design, are not automated: the
real installer start and the elevated restart. See the release notes for
what was checked by hand.

`--selftest` is a hidden switch of the tool, for this test only: `crash`
raises an error on purpose, `bad-fingerprint` makes the pinned fingerprint
wrong, `offer-on-arm` allows the USBPcap offer on Windows on ARM (where it is
normally not offered), `pretend-usbpcap` acts as if USBPcap were installed.
It is written into the report when used.

## Running it

    python3 vm_server.py --bind 192.168.248.1 --dir SESSION &
    # once, inside Windows: paste the runner line into PowerShell
    python3 vm_scenarios.py --session SESSION --exe chromiq-io-probe-windows.exe [--only a1,b]

Results: `SESSION/report.md`, and in `SESSION/results/` the screen texts
(`<case>-screen.txt`), screenshots (`<case>-end.png`, `-hung.png`) and the
reports the tool wrote (`report-<case>.txt`).
