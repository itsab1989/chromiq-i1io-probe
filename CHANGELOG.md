# Changelog

## v1.6.0

The i1iSis chart readers (i1iSis, i1iSis XL, i1iSis 2, i1iSis 2 XL).

- **Detection:** the USB ID 0971:2006 now has a name. It comes from X-Rite's
  own i1iSis driver file (installed with i1Profiler 3.8.8) and from
  ArgyllCMS's device list. The driver file lists one ID for the whole
  family, so the newer and the XL models most likely share it.
- **A guided i1iSis session** (offered when an i1iSis is plugged in, or with
  `--isis`), in six steps: start i1Profiler and leave it idle; get the i1iSis
  ready for a page without feeding it; feed one page in single scan; the same
  page in dual scan; the same page a little crooked; a plain sheet that fails
  on purpose. After each step one extra question: how did the page move? It
  uses the same session as the handheld instruments, so every lesson of
  1.5.5 holds (a step stops only with `e` and Enter, keys pressed while the
  tool is busy are thrown away, an empty step is called EMPTY, `--steps`
  repeats single steps).
- **How to get a chart page**, from i1Profiler's own help: any printed
  i1iSis chart page works, because the colours do not matter for the
  recording. The tool ships no chart.
- **Only the i1iSis is kept:** in an i1iSis session the copy to send also
  drops any other X-Rite instrument the tool knows (for example a monitor
  calibrator plugged in at the same time). The other sessions are unchanged.
- **Analysis for the i1iSis:** the steps side by side, whether it talks
  through a USB-to-serial chip like the i1iO table, the first readable lines
  the program sent (never the device's answers, which can hold its serial
  number), and a checklist.
- **Windows facts:** switch the i1iSis on before plugging in its USB cable
  (X-Rite's notes for i1Profiler 3.8.8); on Windows 11 25H2 i1Profiler
  3.8.8 or newer is needed for the i1iSis (X-Rite says that version fixed
  its drivers there). The i1Pro 2 warning is not shown to i1iSis owners.
- **Tested promise:** a new test runs a whole simulated i1iSis session and
  fails if the tool opens any device (through `open`, `io.open`, `os.open`
  or `pathlib`), starts a program that is not on the list taken from its own
  source, or writes anywhere outside its own folders. Nine deliberately
  broken copies of the tool are run through it, and every one is caught. A
  source check fails if the tool ever gains a way to talk to a USB device.
- **Not yet tried with a real i1iSis.** Everything above was tested with
  invented recordings only.

An independent review before the release found, and this release fixes:

- **Privacy:** when a recording held no USB description (USBPcap's retry
  without injected descriptions, or a device never plugged in again), a
  device guessed from i1Pro commands could end up in the i1iSis copy, even
  as its only content, while the check said OK. Now an i1iSis session keeps
  ONLY the i1iSis when the recording shows one; without one, only X-Rite
  devices the tool does not know (and it says so right after the step);
  never a known other instrument (now also the i1Display 3L, 0765:600a) and
  never a guessed device. Without any USB description nothing is kept, and
  the step says "NOTHING KEPT" and how to repeat it.
- `--analyze` and `analysis.txt` use the same choice: a raw recording with
  an i1iSis in it lists only the i1iSis, never a monitor calibrator, and
  never another device's text as lines sent to the i1iSis. The answers of
  devices the tool has no decoder for (the i1iSis among them) are never
  shown, only their sizes.
- The privacy texts say exactly what is kept, and that the serial number
  and calibration data are "very likely" in an i1iSis recording (not yet
  proven for this family).
- A restart as administrator on Windows forgot `--isis` and `--steps`.
- Texts that still spoke to i1Pro owners in an i1iSis session: the Mac
  "not possible" box, the Windows on ARM note, the closing "WHAT TO DO NOW"
  (switch the i1iSis on before plugging it in) and the "not plugged in"
  note (the session goes on, and now the text says so).
- An old chart page works only if i1Profiler still has that chart; the
  paper is normal 80 g/m2 printer paper, the same size as the chart.
- Step 5 is in the checklist; the step box reads "Then:" for the i1iSis.
- The build smoke-tests the frozen binary on an invented i1iSis recording.
- A test of the Enter-key fix could fail at random (it wrote into a
  terminal that had already closed); it no longer does (30 of 30 runs).

## v1.5.5

Fixes from the first real Windows recording session. Version 1.5.4 made a
recording on Windows possible for the first time: a tester recorded seven of
nine steps with an i1Pro 3. Thank you! His session showed what still went
wrong:

- **The Enter key.** After each step the tool went quiet for a few seconds
  while it stopped and checked the recording. Enter presses made during that
  time waited in the window and then answered the next questions, so two
  steps started and stopped at once and recorded nothing. Now keys pressed
  while the tool is busy are thrown away before every question, the tool
  says "Key received. Stopping the recording and checking it, please wait",
  a step stops only with  e  and Enter (a stray Enter cannot end it), and a
  step shorter than 2 seconds asks whether that was on purpose.
- **No more drawing over what you type.** 1.5.4 rewrote a status line every
  second on the line where you type, so typed keys seemed to vanish. The
  running count is now in the window's title only.
- **Windows "QuickEdit":** in the classic Windows console a click into the
  window starts a text selection, and the next Enter only ends it. The tool
  switches that off during the session and back on afterwards.
- An independent review before the release found, and this release fixes:
  an empty step's "please repeat" pointed at the wrong question; a repeated
  step was still listed as empty; an all-zero step could be called good;
  late keys could answer the last questions or close the window; a wrong
  step list silently recorded every step.
- **Empty steps are called empty.** A step that holds only the USB
  description is "EMPTY: nothing was recorded in this step, please repeat
  it", never "OK: real data recorded", in the check after each step, the
  final list and `--analyze`. Each handheld step now gets a check like the
  i1iO table steps: "this step recorded N requests and data transfers of the
  instrument: good". Empty steps no longer count as, for example, "a no-ruler
  control".
- **Repeat only some steps:** `--steps 7,9` (or the question at the start,
  shown when an earlier session folder lies next to the tool) records just
  those steps, with their usual numbers. The one file to send then holds
  only them and the report.
- **Clearer steps:** the idle step says plainly not to measure anything; the
  slow swipe says "take 3 to 5 seconds for the whole strip"; the dual-scan
  step asks which setting was on (single or dual, M0, M1 or M2). The
  analysis notes when a "slow" swipe was not slower than the fast one.
- **i1Pro 3 lights:** the code 0x06 is a red pulse (likely, from the real
  recording; 1.5.4 called it "off"); 0x01 is marked as unknown. 0x3A (set
  tint multiplier) is used by ArgyllCMS after all, and is no longer listed
  as a command the open driver never sends.

## v1.5.4

Aimed at the next recording of an i1iO table. The first real recording of an
i1iO 2 (with an i1Pro 2, made on a Mac with SIP switched off, issue #129)
now exists. It showed that i1Profiler talks to the table in short lines of
text through a common USB-to-serial chip, and every one of its 2,475 lines
passed the check number we worked out, so we very likely read the format
correctly. Much is still unknown, and nothing is promised: ChromIQ cannot
drive the table. There is still no recording from a handheld instrument.

- **Fixed: on Windows the recording stopped at once (found in a real report
  from 1.5.3).** Run as administrator, USBPcap's recording program opens its
  output file in a way that fails when the file already exists (USBPcapCMD
  1.5.4.0, `cmd.c`), and then ends at once. 1.5.3 created that file just
  before starting it, so every recording on a Windows PC with USBPcap
  ended this way, and the simpler second try too. The file is now left for
  USBPcap to create. A fake USBPcapCMD in the tests now behaves the same way.
  This fix follows from the recorder's source code and our tests; a real
  Windows recording has not confirmed it yet.
- **When the recorder does not start, the report says why:** the exact
  command, the exit code, everything the program printed, whether the
  retry ran, whether a file was created and how big, which USBPcap root
  hub was recorded and why, every root hub with the devices behind it,
  USBPcapCMD's path and version, and whether the tool ran as
  administrator (now stated in every Windows report). On the screen it
  says in plain words what happened, and offers the way by hand at once:
  record with Wireshark while the tool walks the same steps.
- **One file to send:** at the end the tool makes `SEND-THIS-<date>.zip` next
  to itself, with the report, the instrument-only recordings, session.json
  and analysis.txt (only the tool's own files and its instrument-only
  copies, never a full recording, whatever its name), and says "send this
  one file".
  A report without a recording says so in its first lines, and why (you
  chose only the report, the recording program stopped at once, you stopped
  before the first step, ...).
- **Each handheld step says plainly what to do, in order**, in a small
  frame: press Enter HERE to start recording, then do the step in the
  measuring program, then come back to THIS window and press Enter. While a
  step records, a line shows the seconds and the bytes recorded so far (or
  "no data yet"). Stopping with nothing recorded asks once more.
  (A real tester measured in the program without starting a step here.)
- **An i1Pro 3 on WinUSB from a libwdi-based tool** is no longer called
  X-Rite's driver because of its name: the tool says who provided it and
  that whether i1Profiler opens it like this is not known.
- **Fixed: `--analyze` never showed what the program sent on a Mac.** In
  macOS recordings the data going to a device sits in the completion record,
  not in the request; 1.5.3 read it only from the request, so every command
  i1Profiler sent to the table (and the i1Pro's trigger parameters and light
  sequences) was missing. Found in the first real recording. The Windows
  (USBPcap) and Linux (usbmon) readers were checked against those formats'
  documentation and do not have this mistake; tests feed the same
  conversation through all three, but neither has been tried on a real
  recording of the table yet.
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
  first: (1) one row of a chart that i1Profiler scans in one pass (the first
  recordings most likely show its fallback: its help says a row that cannot
  be scanned is read again more slowly and then patch by patch, which
  happened on every row), with the calibration, marking `a`
  (the arm starts along the row), `l` (the lamp lights up), `d` and `u` (the
  head goes down and up) as it happens, then a cancel during the second row;
  (2) a few patches in spot mode, if offered; (3) a small chart measured to
  the end with the fastest setting, letting the arm park by itself; (4) one
  row with dual scan (M1 or M2), if offered; (5) one row of the earlier
  chart, if it is still printed. Step 1 matters most: the first
  recordings suggest that the table waits for the instrument before it
  moves, without being told, and the marks are how we can tell the two
  apart. Then a few questions with no recording running: the
  chart file, the paper size, a ruler measurement, the i1Profiler settings,
  and whether i1Profiler can lower or lift the head on its own. Each step:
  what to get ready, Enter to start, `e` and Enter to end it (a stray key or
  a second Enter can neither end a step nor start the next one), one line on
  what the arm did, skip or do it again; finished steps are kept, also after
  Ctrl-C or a closed window. Left out
  on purpose: provoking an error by holding the arm back or removing the
  instrument (we cannot know that it is harmless), and switching the table
  off with the arm out (the first recordings already show that start-up),
  and trying whether the table moves without the instrument measuring
  (i1Profiler offers no way to try it safely).
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
- **The i1iO 3 (0765:30B0, from X-Rite's own driver file) is recognised**
  and named as a table in the detection and the report; its protocol is
  not known, so the i1iO 2 analysis is not applied to it.
- **Windows on ARM, worded as far as the evidence goes:** for the i1Pro 3 the
  tool no longer says the vendor program cannot talk to it (its firmware
  asks Windows for Microsoft's own USB driver, and nobody knows yet whether
  i1Profiler works with it on ARM). For the others it says we know of no
  X-Rite driver on ARM. The advice is the same: no recorder (USBPcap) exists
  for ARM, so please use a PC with an Intel or AMD processor.
- **Driver help:** no longer names X-Rite's Device Manager entry for the
  i1Pro 3 as "X-Rite i1Pro3", which was never verified; it says how to
  recognise X-Rite's entry and what to do if unsure.
- **An independent review before the release** found, and this release
  fixes: a stray key or a double Enter could end a step or start the next
  one while the arm moved; a second Ctrl-C or a closed window at the end
  could lose the step log; the check said "please repeat" when the recorder
  itself had stopped, and re-read the whole recording after every step; the
  big SIP box also appeared when nothing had been recorded; letters could
  land in i1Profiler (the steps now say to click into the tool's window
  first); a few meanings were worded more firmly than our notes allow. A
  second review of those fixes found, and this release fixes: an accidental
  Ctrl-D ended the walk; a window closed during the last questions lost the
  report; an i1iO 3 recording would have been called empty after every step
  (its protocol is not known, so its steps are now marked "cannot be checked
  here"); some step texts claimed more than we know.

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
