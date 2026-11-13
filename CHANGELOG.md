# Changelog

## v1.5.4

Aimed at the next recording of an i1iO table. The first real recording of an
i1iO 2 (with an i1Pro 2, made on a Mac with SIP switched off, issue #129)
now exists. It showed that i1Profiler talks to the table in short lines of
text through a common USB-to-serial chip, and every one of its 2,475 lines
passed the check number we worked out, so we very likely read the format
correctly. Much is still unknown, and nothing is promised: ChromIQ cannot
drive the table. There is still no recording from a handheld instrument.

- **Fixed: `--analyze` never showed what the program sent on a Mac.** In
  macOS recordings the data going to a device sits in the completion record,
  not in the request; 1.5.3 read it only from the request, so every command
  i1Profiler sent to the table (and the i1Pro's trigger parameters and light
  sequences) was missing. Found in the first real recording. The Windows
  (USBPcap) and Linux (usbmon) readers were checked for the same mistake and
  do not have it; tests now feed the same conversation through all three.
- **`--analyze` understands the i1iO table:** it recognises 0971:2004 as a
  USB-to-serial link, removes the chip's 2 status bytes from every USB packet,
  puts the lines back together, checks every line's check number, and prints
  one timeline of the table's lines (both directions), the chip's own
  settings and the i1Pro's requests. Every meaning carries a word for how
  sure we are (certain, likely or guess); a command not seen before is
  flagged as new. With the probe report (named after `--analyze`, or lying
  next to the recording) it marks the steps and says per step whether table
  commands were recorded. The table's serial number is hidden unless
  `--no-redact` is given, and so is the USB serial number in the general
  timeline. On the two real recordings it finds exactly the same 1,125 and
  1,350 lines as our separate decoder, all with a correct check number.
- **New i1iO steps**, exactly what the first recordings lack, the most useful
  first: (1) a few patches, watching the head, marking `d` (down) and `u`
  (up) as it happens, in spot mode if i1Profiler offers it; (2) a small
  chart measured to the end, letting the arm park by itself; (3) cancel in
  the middle of a row. Then a few questions with no recording running: the
  chart file, the paper size, a ruler measurement, the i1Profiler settings,
  and whether i1Profiler can lower or lift the head on its own. Each step:
  what to get ready, Enter to start and stop, one line on what the arm did,
  skip or do it again; finished steps are kept, also after Ctrl-C. Left out
  on purpose: provoking an error by holding the arm back or removing the
  instrument (we cannot know that it is harmless), and switching the table
  off with the arm out (the first recordings already show that start-up).
- **On a Mac, each step is checked while SIP is still off:** right after a
  step the tool reads the recording so far and says "this step recorded 14
  commands to the table: good" or "no table command was recorded in this
  step: please repeat it". At the end a table shows every step, whether it
  was recorded and how many table commands it holds, and says plainly what
  is still missing.
- **"Have you got everything ready?"** A short list (charts, ruler, settings,
  time) before the recording starts, so everything fits into one round with
  SIP switched off.
- **`--rehearse`** walks through the i1iO steps without recording or saving
  anything, so a tester can see them first, while SIP is still on.
- **Switch SIP back on:** a mac session now ends with a box holding the
  exact steps for this Mac (Apple Silicon or Intel) and how to check it
  (`csrutil status`). The earlier reminders stay.
- **Windows on ARM, worded as far as the evidence goes:** for the i1Pro 3 the
  tool no longer says the vendor program cannot talk to it (its firmware
  asks Windows for Microsoft's own USB driver, and nobody knows yet whether
  i1Profiler works with it on ARM). For the others it says we know of no
  X-Rite driver on ARM. The advice is the same: no recorder (USBPcap) exists
  for ARM, so please use a PC with an Intel or AMD processor.
- **Driver help:** no longer names X-Rite's Device Manager entry for the
  i1Pro 3 as "X-Rite i1Pro3", which was never verified; it says how to
  recognise X-Rite's entry and what to do if unsure.
- An independent review before the release; see the release notes.

## v1.5.3

Help with the step where both users so far got stuck, and one plain
question instead of guessing what the user wants. Still untested with a real
instrument and a real recording. For the first time the Windows exe was
driven on a real Windows (11 on ARM, x64 emulated, in a virtual machine):
see the release notes for exactly what was and was not tested there.

- **"What would you like to do?"** After the detection the tool shows what
  is plugged in right now (on Windows with its driver) and asks: 1 record an
  i1iO table, 2 record a handheld instrument, 3 nothing more, just the
  report, or `a` to look again. The suggestion comes only from what is
  plugged in now (a remembered i1iO no longer hides a plugged-in handheld
  instrument); with nothing plugged in it says so. `--io` is new; `--io`,
  `--i1pro`, `--annotate` and `--skip-annotate` choose without asking. The
  tool is now called "the ChromIQ X-Rite instrument probe" everywhere.

- **USBPcap missing: the tool can fetch and start its installer, only after
  a yes.** Before asking, it says what USBPcap is (free, open-source, by its
  own author, not by us), that it installs a system driver, that one user
  has reported a blue screen naming its driver on Windows 11 25H2 (USBPcap
  issue #146), and how to remove it. On a yes it downloads USBPcap's own
  installer (`USBPcapSetup-1.5.4.0.exe`, 195,040 bytes) from the official
  GitHub release into a new, empty folder of the user's own (in the user's
  temporary folder) and checks its SHA-256 fingerprint against the one
  written into the tool (the same one Wireshark's build pins), after the
  download and again just before starting it; on any difference it deletes
  the file and starts nothing. A cut-off download says so. A second question comes before the installer starts, normally
  and visibly, with Windows' own permission question and USBPcap's licence.
  Afterwards it checks whether USBPcap is installed and says so, asks you to
  restart Windows (it does not restart anything itself), and offers to
  delete the downloaded file. Not offered on Windows on ARM.
- **Not administrator: the tool offers to start itself again as
  administrator**, once, through Windows' own question; the new window
  carries on (with the same `-o` and `--no-redact`) and this one closes.
  The new copy never offers it again. On "no", the manual steps as before.
- **An independent review** before the release found, and this release
  fixes: a half-written installer could stay behind after a failed save;
  the install steps were repeated after a successful install; Ctrl-C at
  the new question took the suggestion instead of stopping.
- A failed download, a "no" anywhere or a refused Windows question leads to
  the manual steps of 1.5.2, including the offer to open Wireshark's
  download page.
- **Found by running the exe on a real Windows 11 (on ARM, the x64 exe
  emulated):** with an instrument that Windows only remembers and nothing
  plugged in, the tool said "None of them is plugged in right now" and then
  "This computer has a handheld instrument plugged in" and offered the
  session (also in 1.5.1 and 1.5.2). Only what is plugged in counts now.
- **Helper programs never touch the window:** every program the tool asks
  (PowerShell, `sc`, USBPcapCMD) now gets no input from the keyboard, has
  its output and errors captured into the report, and on Windows runs
  without a console of its own.
- **For testing only:** a hidden `--selftest` switch and `tools/vm_test/`,
  an automated end-to-end test that drives the built exe on a real Windows
  (see its README).

## v1.5.2

After the second report from a user: the window closed before the
instructions could be read. Still untested with a real recording.

- **The window stays open.** Double-clicked on Windows, the tool's console
  window closed the moment the tool finished, so the help it had just
  printed vanished and the run looked like a crash. Now every way the tool
  ends (the normal end, "nothing was recorded", typing q, Ctrl-C, an error)
  finishes with "Press Enter to close this window." It waits only when it
  has a console window of its own (a double-click); started from a command
  window, with input or output piped or redirected, or under CI it does
  not wait. `--pause` and `--no-pause` force it either way, and the three
  launchers pass `--no-pause` because they wait themselves.
- **WHAT TO DO NOW.** When something is missing (USBPcap, administrator
  rights, X-Rite's driver, the instrument itself), the last thing above the
  wait is a short box with the next steps, the single next action first,
  and the name and folder of the report that holds the full instructions.
  When USBPcap is missing, the tool offers to open Wireshark's download page
  in the browser (only on a yes; Enter means no).
- **Administrator rights are checked before the steps.** USBPcap lets only
  administrators listen to the USB ports; without them its recorder would
  ask Windows for permission at every step. The tool now says so before the
  steps start, explains how to start it as administrator (right-click,
  "Run as administrator"), and does not start the steps. 1.5.1 said "may
  refuse" and let the session begin.
- **An unexpected error** no longer makes the window vanish: the tool says
  sorry in plain words, saves what it had collected with the technical
  details, says where, and waits.
- **Windows 11 25H2 and newer with an i1Pro 2:** when X-Rite's driver is
  installed and Windows reports the instrument as working, the tool now
  says so plainly and asks the user to carry on and tell us whether
  i1Profiler measures with it, instead of a warning next to "[OK] X-Rite's
  driver".

## v1.5.1

After the first report from a user (Windows 11 25H2, an i1Pro 3, USBPcap
not yet installed). Still untested with a real recording.

- **USBPcap missing: clearer help.** The tool now says in plain words what
  USBPcap is and why it is needed, gives numbered steps (Wireshark's "USB
  Capture" page and its "Install USBPcap" box, which is not ticked by
  default; the restart; run the tool again), and says that no security
  setting has to be switched off: on Windows 10 and 11 USBPcap installs a
  driver signed through Microsoft's signing service. 1.5.0 printed its
  shorter steps above "ALL DONE", where they scrolled away.
- **The run ends honestly when nothing was recorded.** Instead of "ALL
  DONE" and "send it together with the session folder", it says that
  nothing was recorded and why, and repeats what to do as the last thing
  on the screen. The help is in the report too.
- **The 25H2 note only where it applies.** X-Rite's note says the i1Pro 2 /
  iO2 driver is blocked on Windows 11 25H2 and newer and that the i1Pro 3 /
  iO3 works with the latest Windows 11 releases. 1.5.0 showed the warning to
  everybody; 1.5.1 shows it for the i1Pro 2 (and the first i1Pro, which
  looks the same to the computer) and tells i1Pro 3 owners it does not
  concern them. The closing "stay on i1Profiler 3.8.6" note is likewise
  shown only to i1Pro 2 and i1Pro users.
- **New check: which driver the instrument is on.** If the plugged-in
  instrument is on the ArgyllCMS driver (libusb0 or libusbK, as ArgyllCMS,
  ChromIQ or Zadig install it, or WinUSB on the older X-Rite ID), the vendor
  program cannot see it. The tool says so and gives the Device Manager
  steps to give it X-Rite's driver back, and the way back for ChromIQ
  afterwards.
- **Remembered devices.** Windows remembers every instrument it has seen,
  once per USB socket. They are now marked "not plugged in now", and the
  session is chosen from the instrument that is plugged in.
- **The original i1Pro:** the version check now says that X-Rite removed
  revisions A to D from i1Profiler in 3.2.0 and that 3.1.1 is needed, and a
  user with both an i1Pro and an i1Pro 2 (one USB ID for both) is asked to
  plug in only the one being recorded.
- **Chart list:** names that merely contain the letters "io" ("Studio",
  "option", "iteration") are no longer tagged as iO charts.

## v1.5.0

- **New: a guided recording session for handheld instruments**: the
  original i1Pro, the i1Pro 2, the i1Pro 3 / 3 Plus, the ColorMunki Photo /
  Design and the i1Studio, plus a raw path for any other X-Rite device. The
  tool offers it when it sees such an instrument and no i1iO table, or start
  it with `--i1pro`. It asks which program you measure with (i1Profiler,
  ccStudio / ColorChecker Studio, the ColorMunki or i1Studio software, or
  another) and guides up to nine short steps: idle, calibration, one strip
  in single scan, the same strip in dual scan, faster, slower, a scan that
  fails on purpose, one single patch, and the strip without the ruler. Each
  step is recorded into its own file; every step can be skipped or repeated,
  and stopping (q, Ctrl-C, closing the window) keeps every finished step.
  After each step you type one line about what happened and one about what
  the instrument's lights did.
- **Says honestly what it is for, per instrument**: i1Pro 2, the ruler
  sensor, the dual scan and the lights; i1Pro 3, what the vendor program does
  differently from the open driver; original i1Pro, ColorMunki and i1Studio,
  how the vendor program reads strips so reliably. Nothing is promised.
- **Windows checks before recording (read only)**: Windows version, USBPcap
  installed and running, administrator rights, which USB root hub the
  instrument is on, which measuring programs and versions are installed, and
  plain install steps for USBPcap if it is missing. The version facts
  (i1Profiler 3.8.7 dropped the i1Pro 2; X-Rite says the i1Pro 2 driver is
  blocked on Windows 11 25H2 and newer; no driver on Windows on ARM) are shown
  as checks; you can carry on if your program still finds the instrument.
- **Recording**: USBPcap's own `USBPcapCMD` per step on Windows (or time marks
  for a Wireshark recording you make yourself), `tcpdump` on a Mac with SIP off
  or on Linux.
- **Privacy**: the tool says up front that a recording necessarily contains
  the instrument's serial number and calibration data. After each step it
  keeps only the instrument's traffic (its device address and nothing else)
  in the session folder; the full recordings go into a separate folder ending
  in `-FULL-do-not-send`, which it offers to delete. Chip IDs are hashed and
  EEPROM contents are not printed in the analysis. Nothing is uploaded.
  When it is time to send, the tool says again that the zip holds the
  instrument's serial number and calibration data, and offers three ways:
  the forum thread where you heard about the tool, a new GitHub issue, or a
  private message on the forum. (Issue #129 stays the i1iO's.)
- **`--analyze` understands Windows (USBPcap) and Linux (usbmon) recordings
  too**, not only macOS ones, and session folders. For the i1Pro, i1Pro 2,
  i1Pro 3 and ColorMunki / i1Studio it decodes the commands that ArgyllCMS
  documents (written from those facts; no Argyll code is copied), lists
  unknown commands in full, counts every endpoint that carries data, flags
  anything the open driver never uses (for example the i1Pro 2's endpoint
  0x85, ruler bits, request 0xD7), compares the steps (readings, sizes,
  readings per second, fast against slow, the no-ruler control), decodes the
  light commands, and ends with a plain "does this hold what we need" list.
- **X-Rite's newer vendor ID 0765** (i1Pro 3, i1Studio) is recognised.
- **Tests** with synthetic recordings built from the documented formats and a
  stand-in `USBPcapCMD`.
- **Not tested**: any recording of a real i1Pro, i1Pro 2, i1Pro 3, ColorMunki
  or i1Studio (none was available), and the tool on a real Windows PC with
  USBPcap. The Windows checks were tested against text written from the
  documented formats, not against a real PC.

## v1.4.0

- **Fixed: "NO X-RITE DEVICES SEEN" on current macOS although the table was
  plugged in.** 1.3 asked macOS for its USB list under the old name
  `SPUSBDataType`, which now returns an empty list. 1.4 asks under the current
  name `SPUSBHostDataType`, falls back to the old name and to the IOKit
  registry (`ioreg`), and believes any of them. The summary also says where it
  looked and what each source returned.
- **Fixed: a wrong device name.** 1.3 labelled USB ID 0971:2001 as "i1Pro 2 /
  i1Pro 3 family", but a real i1Pro 2 reports 0971:2000. The list now only
  names IDs that a real report has shown (0971:2004 is the i1iO table, which
  calls itself "Eye-One iO"; 0971:2000 is the i1Pro family, "eye-one") and
  calls everything else "unknown" instead of guessing.
- **More of the USB description, still without opening the device.** For the
  X-Rite devices the report now lists the device descriptor, the interfaces
  (class, number of endpoints), which software has them open, and the hub
  topology that shows the instrument behind the table's own hub. The endpoint
  details are not kept by macOS where they can be read safely, and the report
  says so: they come from a recording.
- **The recording step on a Mac now tells the truth.** 1.2 and 1.3 said macOS
  already had everything needed to record USB traffic. That was wrong: macOS
  only allows it with System Integrity Protection (SIP) fully switched off.
  1.4 checks SIP, the processor type and the recording interfaces (read only)
  and says plainly whether a recording is possible.
  - If it is not, it says why, and shows the three real ways: a Windows PC
    with an Intel or AMD processor (easiest; which Windows and i1Profiler
    versions work is spelled out), switching SIP off on the Mac (exact steps,
    the risk in one sentence, and the exact steps to switch it back on), or a
    hardware USB sniffer.
  - If it is, it guides a short recording with the system's own `tcpdump` on
    every `XHC` interface, switches the interfaces off again afterwards (also
    after Ctrl-C), checks whether the recording holds real data or only zeros,
    makes an X-Rite-only copy to send, offers to delete the full recordings
    (they can contain other USB traffic), and reminds you to switch SIP back
    on. The tool never changes SIP itself.
  - The separate `start-usb-capture.command` script is gone; the tool does
    the recording itself.
- **Warning about i1Profiler 3.8.7**, which removed support for the i1Pro 2
  and the i1iO 2. On a Mac the report also shows the installed i1Profiler
  version (1.3 looked in one folder only).
- **`--analyze` checks for all-zero recordings**, reads Wireshark's `.pcapng`
  files too, and decodes the USB description (endpoints) if the recording
  contains it.
- **Privacy:** the serial number macOS hides inside `UsbDeviceSignature` is now
  hashed too (1.3 let it through).
- **Tests:** `python3 -m unittest discover -s tests`, including a fixture
  modelled on a real (anonymised) report and a recording run with fake
  `sudo`, `ifconfig` and `tcpdump`. CI runs them on every build.
- **Not tested yet:** a recording against a real i1iO, and any recording on a
  Mac with SIP switched off. The recording path was only tested with stand-in
  programs.

## v1.3.0

- **New `--analyze` step: check a capture before you send it.** After recording
  the table's USB traffic you were left with a large binary file and no way to
  know whether it captured anything useful. `--analyze` reads a `.pcap` you
  already made (it sends **nothing** to the table and cannot move the arm) and
  prints a plain verdict (*"real device traffic captured, good to send"* or
  *"wrong bus, or no measurement was taken"*), which device was seen, and a
  command timeline. With no path it finds the newest capture next to the tool.
- The timeline is **device-agnostic**: it assumes no command codes and just
  shows the raw USB control commands and how much data the device streamed,
  which is what an implementer needs. (The underlying analysis was validated on
  real hardware and matched byte-for-byte to ArgyllCMS's own instrument driver.)
- ChromIQ is free and always will be. If it saves you time or ink, a
  coffee on [Ko-fi](https://ko-fi.com/itsab1989) is a kind way to say thanks.

## v1.2.1

- **The guided walkthrough now matches what i1Profiler can actually do.** It
  previously asked for two things the software offers no way to do: sending the
  arm to a home position, and switching the electrostatic foil on and off. The
  arm parks itself and the static mat holds the paper on its own; neither is
  under the operator's control. The steps now follow i1Profiler's real
  sequence: press Measure, then align the arm **by hand** on the top-left,
  bottom-left and bottom-right corner patches, then let it scan.
- **Saying "no" to the capture no longer silently swallows the walkthrough.**
  The prompt now says what it is about to do and roughly how long it takes, and
  declining explains what was skipped and how to come back to it later.
- ChromIQ is free and always will be. If it saves you time or ink, a
  coffee on [Ko-fi](https://ko-fi.com/itsab1989) is a kind way to say
  thanks.

## v1.2.0

- **macOS USB capture no longer needs Wireshark, or anything installed.**
  The optional advanced step used to say "install Wireshark plus its ChmodBPF
  helper". That is no longer necessary: macOS already ships `tcpdump`, and
  running it under `sudo` removes the need for ChmodBPF entirely. The tool now
  writes a ready-made `start-usb-capture.command` script you can read and
  double-click. It records the traffic, then puts every setting back as it
  found it. Nothing is installed and nothing is left behind.
- **Capture interfaces are detected, not guessed.** The old instructions named
  `XHC20`, which simply does not exist on many Macs (an Apple-Silicon machine
  has `XHC0`/`XHC1`/`XHC2`). The names are now read from the system, all of
  them are recorded at once, and the report says which ones exist, so it is
  clear up front whether a capture is possible on that Mac at all.
- **Clearer downloads.** README and release notes now spell out `chmod +x` and
  the Finder right-click → Open route, because a downloaded binary that is not
  marked executable appears to do nothing at all when double-clicked.
- New `--capture-setup` option writes just the capture script and exits.

## v1.1.0

- **Ready-to-run downloads, no Python needed.** GitHub Actions now builds
  standalone binaries for Windows, Linux, and a single **universal** macOS build
  that runs on both Intel and Apple-Silicon Macs. Grab the one for your system
  from the release; the readable source is still available as a scripts zip.
- **i1Profiler chart-metadata collector.** On a machine with i1Profiler
  installed, the tool now reports the iO test charts it finds: their names,
  patch counts, and any patch-size figures stated in the help text. It reports
  facts *about* those files, never their contents.
- **Report always lands somewhere you can find it.** When run as a packaged
  binary, the report is saved next to the downloaded file (and, failing that,
  on your Desktop), never in a temporary folder that disappears on exit.
- **Serial numbers hashed, personal paths stripped** by default, on every
  platform's output format.

## v1.0.0

- First version. Read-only collector of USB device details for the ChromIQ
  i1iO support investigation ([ChromIQ #129](https://github.com/itsab1989/ChromIQ/issues/129)).
  It never opens or sends anything to the table; it only reports what the
  operating system already knows about connected hardware. Cross-platform
  (macOS / Windows / Linux) with double-click launchers, plus an optional
  guided USB-capture step.
