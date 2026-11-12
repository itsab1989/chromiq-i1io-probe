# ChromIQ X-Rite instrument probe

<p align="center">
  <a href="https://ko-fi.com/itsab1989"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support ChromIQ on Ko-fi" height="36"></a>
  <br>
  <sub>ChromIQ is free and always will be. If it's useful to you, a coffee is a kind way to say thanks. It is completely optional, and the app stays fully featured either way.</sub>
</p>

A small, **read-only** tool that collects information about **X-Rite
instruments** and the computer they are connected to, and can record what the
vendor's own program says to them: the **i1iO** scanning table, the **i1Pro
family** (original i1Pro, i1Pro 2, i1Pro 3 and 3 Plus) and the **ColorMunki
Photo / Design** and **i1Studio**. It exists to help
[ChromIQ](https://github.com/itsab1989/ChromIQ) understand these instruments
better. For the i1iO see [ChromIQ issue #129](https://github.com/itsab1989/ChromIQ/issues/129);
the handheld-instrument session is described [below](#the-handheld-instrument-session-new-in-15).

It takes about **two minutes**, and you do **not** need to be technical.

> **Important for owners of an i1Pro 2 or an i1iO 2:** i1Profiler **3.8.7**
> (July 2026) removed support for the i1Pro 2 and the i1iO 2. Please stay on
> **i1Profiler 3.8.6 or older**, and do not let it update itself.

---

## Is this safe?

**Yes. This is the important part, so here it is plainly:**

- It **never sends anything to the table or the instrument.** Not one byte.
- It **cannot move the arm.** It does not even open a connection to the device.
  (Opening it could take it away from X-Rite's own software, so the tool never
  does that.)
- It **changes no settings.** In particular it never switches System Integrity
  Protection (SIP) on or off on a Mac; it only reads whether it is on.

All it does is read information your operating system already keeps about
plugged-in hardware (the same kind of thing you'd see in Device Manager or
System Information), plus a few facts about the X-Rite software you have
installed. You can run it with the arm parked. Nothing will move.

The only exception is the optional recording step on a Mac, and only if you
say yes to it: it then briefly switches on the Mac's USB recording interfaces
and switches them off again when it finishes. Details below.

---

## How to run it: the easy way (no Python needed)

Download the one file for your system from the
[**latest release**](../../releases/latest), then run it. Plug in and switch on
your i1iO first.

| Your system | Download |
|-------------|----------|
| **Windows** | `chromiq-io-probe-windows.exe` |
| **macOS** (Intel **and** Apple Silicon) | `chromiq-io-probe-macos` |
| **Linux** | `chromiq-io-probe-linux` |

The macOS download is a single universal build. It runs on both Intel and
Apple Silicon Macs, so there's only one file to pick.

### Windows

Double-click the `.exe`. Windows will warn you once: click **More info**, then
**Run anyway**.

For a recording, start it as administrator instead: **right-click** the
`.exe` and choose **Run as administrator** (since 1.5.2 the tool says so
before the recording steps, and stops there if it is not). When the tool has
finished, its window stays open with **"Press Enter to close this window."**,
so you can read everything first.

### macOS

Downloaded files aren't marked as runnable, so **double-clicking may appear to
do nothing at all**. Two ways round it:

**In Terminal** (the reliable route):

```bash
cd ~/Downloads
chmod +x chromiq-io-probe-macos
xattr -d com.apple.quarantine chromiq-io-probe-macos
./chromiq-io-probe-macos
```

`chmod +x` marks the file as runnable (downloads never are). The `xattr` line
removes the "downloaded from the internet" mark, which is what makes macOS
refuse an unsigned program (if it says "No such xattr", the mark was not
there; carry on). The last line starts it.

**In Finder:** double-click the file. Because the tool is not signed by an
Apple-registered developer, current macOS (15 and newer) refuses it the first
time. Then open **System Settings > Privacy & Security**, scroll down, click
**Open Anyway**, and confirm with **Open** when the warning appears again
(Apple's own steps: support.apple.com/102445). On older macOS, right-click the
file, choose **Open**, then **Open** again. If the file is not runnable yet,
use the Terminal route above.

### Linux

Same idea, from a terminal:

```bash
cd ~/Downloads
chmod +x chromiq-io-probe-linux
./chromiq-io-probe-linux
```

> These downloads are **not code-signed** (signing needs a paid certificate),
> so your computer will warn you the first time. That's normal and doesn't mean
> anything is wrong. The full source is in this repo if you'd like to check it
> first.

Prefer to **read the source before running anything**? That's the best instinct.
Download `chromiq-i1io-probe-scripts.zip` from the release instead (or clone this
repo). It's a short, plain Python file plus double-click launchers. See
["Running from source"](#running-from-source) below.

---

## What happens when you run it

A window opens and walks you through three short steps:

1. **It looks for your X-Rite instruments** and tells you straight away what
   it found, and whether each one is plugged in right now or only remembered
   by the computer.
2. **It collects the details** (a few seconds, nothing needed from you).
3. **It asks what you would like to do** (since 1.5.3), with the answer that
   fits what is plugged in already suggested, so Enter is usually right:

   ```
     Plugged in now: i1Pro 2 (X-Rite's driver).

     What would you like to do?
       1. record an i1iO table
       2. record a handheld instrument   <- suggested
          (the i1Pro family, the ColorMunki, the i1Studio)
       3. nothing more: just make the report
       a. look again (after plugging something in)
   ```

   With nothing plugged in it says so, and `a` lets it look again after you
   plug the instrument in. For the i1iO (choice 1) it asks three easy
   questions (which iO generation, which instrument is mounted, which
   software and version) and then offers an **optional extra**: recording
   what i1Profiler says to the table. Choice 2 is the handheld session
   described below. `--io` and `--i1pro` choose without asking.

It then saves a plain-text file such as `chromiq-io-probe-20261111-143052.txt`.
**Open it, have a look, then attach it to
[issue #129](https://github.com/itsab1989/ChromIQ/issues/129)** (for the i1iO;
the handheld-instrument session says where its files go). That's it.

---

## The optional recording, honestly

A recording of the USB traffic between i1Profiler and the table is the most
useful thing anyone can send us. It is also the hardest part, and on a Mac it
is often not possible at all. Here is the real situation.

### On a Mac

macOS can record USB traffic with its own `tcpdump` program, but **only when
System Integrity Protection (SIP) is fully switched off**. That has been the
case since macOS Catalina. Switching off single parts of SIP does not work.
The recording interfaces are called `XHC0`, `XHC1` and `XHC2` on Apple Silicon
Macs (`XHC20` on Intel Macs), and they only appear once SIP is off.

So the tool first checks, without changing anything:

- whether SIP is on or off (`csrutil status`),
- whether the Mac has Apple Silicon or Intel,
- which `XHC` recording interfaces exist,
- and on which bus the table probably is (a guess from its Location ID).

**If SIP is on** (as on nearly every Mac, and rightly so), the tool says up
front that a recording is not possible here and why, and shows the three real
ways to make one (below).

**If SIP is off and the interfaces exist**, it offers a guided recording:

1. macOS asks for your password through its own `sudo` prompt. The tool never
   sees or stores it.
2. It switches on the `XHC` interfaces that were off (`sudo ifconfig XHC2 up`
   and so on) and starts the system's own `tcpdump` on every one of them,
   because which bus the table is on is only a guess.
3. You do a few short steps in i1Profiler: replug the table, start i1Profiler,
   press Measure once, cancel. About 3 minutes. A longer part (aligning the
   arm, scanning two rows) is offered afterwards, if you have the time.
4. It stops recording, **switches the interfaces off again** (also after
   Ctrl-C), and checks each recording. If every data byte in it is zero, it
   says so plainly: that has been seen on an Apple Silicon Mac before.
5. It makes a copy holding only the X-Rite devices' traffic. That copy is the
   one to send. The full recordings can hold everything else on those USB
   buses, possibly including what you typed on a USB keyboard, so the tool
   offers to delete them.
6. It reminds you to switch SIP back on.

How well this works on Apple Silicon is only partly known: one public report
from 2026 says it works (with `sudo ifconfig XHC2 up` and recording on `XHC2`),
while a 2021 report saw recordings in which every data byte was zero. That is
why the tool checks.

### The three ways to make a recording

**1. A Windows PC with an Intel or AMD processor (the easiest way).** Install
the free [Wireshark](https://www.wireshark.org) and tick **USBPcap** when its
installer offers it. Then run this tool on that PC and choose the recording
step; it tells you what to do and times each step.
Which Windows works: the X-Rite driver for the i1Pro 2 and the i1iO 2 needs
**Windows 10 with i1Profiler 3.8.5**, or **Windows 11 version 24H2 or older
with i1Profiler 3.8.6**. X-Rite says the driver is blocked on Windows 11
version 25H2 and newer ([X-Rite's note](https://www.xrite.com/service-support/i1pro-2-eol-notes-compatibility-issues-with-windows-11-macos));
the same note says the i1Pro 3 / iO3 works with the latest Windows 11 releases.
**A Windows virtual machine on an Apple Silicon Mac does not work**: there is
no i1Pro or i1iO driver for Windows on ARM.

**2. Switch SIP off on the Mac, only for the recording.** The honest risk:
while SIP is off, macOS no longer protects its own system files, so harmful
software could change them more easily. Keep it off only for the recording and
switch it back on straight after.

To switch SIP off on an **Apple Silicon** Mac:

1. Choose Apple menu > Shut Down, and wait until the Mac is off.
2. Press and hold the power button until "Loading startup options" appears.
3. Click **Options**, then **Continue**. If asked, choose your user and type
   your password.
4. In the menu bar choose **Utilities > Terminal**.
5. Type `csrutil disable` and press Return. If it asks, answer `y` and type
   your user name and password.
6. Choose Apple menu > Restart.

On an **Intel** Mac, steps 1 to 3 are instead: choose Apple menu > Restart and
straight away hold **Command and R** until the Apple logo appears; then choose
your user if asked. Steps 4 to 6 are the same.

To switch SIP **back on** afterwards (please do not forget): do steps 1 to 4
again, type `csrutil enable`, press Return, answer `y` if asked, and restart.
To check, open Terminal and type `csrutil status`; it should say "enabled".

**3. A hardware USB sniffer.** A small box that goes into the cable between
the computer and the table and records what passes through. It changes nothing
on the Mac. Examples: [Cynthion](https://greatscottgadgets.com/cynthion/) with
the free Packetry program (about 210 EUR), or Taradov's open-hardware USB
Sniffer (about 35 USD; its software is ready-made only for Windows and Linux).
Only worth it if you already own one or enjoy this kind of thing. The tool can
still time your i1Profiler steps for such a recording.

### On Linux

Load `usbmon` (`sudo modprobe usbmon`) and record with
`sudo tcpdump -i usbmon<BUS> -w io-capture.pcap` while the tool times the
steps. Note that i1Profiler itself does not run on Linux.

---

## The handheld-instrument session (new in 1.5)

If the tool sees a handheld instrument (i1Pro, i1Pro 2, i1Pro 3, ColorMunki
or i1Studio) and no i1iO table, it offers a guided recording session. You can
also start it directly with `--i1pro` (or `--instrument`). It is optional.

### What it is for

The session records, step by step, the USB conversation between the program
you normally measure with (i1Profiler, ccStudio / ColorChecker Studio, the
ColorMunki or the i1Studio software) and your instrument. What we hope to
learn depends on the instrument, and the tool says so before you start:

- **i1Pro 2:** the instrument has a sensor that can read the striped
  ("zebra") edge of its ruler. The free ArgyllCMS driver, which ChromIQ uses,
  never reads it and finds the patches only from how the colour changes over
  time. We would like to learn how i1Profiler switches the ruler sensor on and
  where the position data arrives, how its dual scan works, and how it drives
  the coloured lights on the instrument.
- **i1Pro 3 / 3 Plus:** the open driver already reads its ruler, so this is a
  comparison: what does the vendor program do differently (commands the open
  driver never sends, the dual scan, the lights, the reaction to a fast or
  uneven swipe, readings per patch, reading again by itself)?
- **Original i1Pro, ColorMunki and i1Studio:** no ruler sensor. We would like
  to learn how the vendor program reads strips so reliably: how many readings
  per second and per patch, how it reacts to speed, what it does with a failed
  strip, and (ColorMunki / i1Studio) what its light does and how it asks about
  the dial positions.

**Nothing is promised.** A recording helps us understand; whether an
open-source measurement engine can ever use what we learn is a separate
question, and the answer may be no.

### The steps

Each step is recorded into its own small file. You can skip or repeat any
step, and stop at any time (type `q`, press Ctrl-C or close the window): the
steps you finished are kept. About 15 minutes; you need the instrument, your
measuring program and one printed test chart.

1. Start the program, then leave it idle for about 10 seconds.
2. Calibrate, as the program asks (white tile; ColorMunki / i1Studio: the
   dial's calibration position).
3. Scan one strip in single-scan mode at your normal speed.
4. The same strip in dual-scan mode (i1Pro 2 and i1Pro 3 only).
5. The same strip again, about twice as fast.
6. The same strip again, slowly (about three times as long).
7. Let one scan fail on purpose, for example by lifting the instrument
   halfway (skip it if you would rather not).
8. Read one single patch, if the program offers it.
9. The same strip without the ruler, as a comparison, if the program allows
   it (i1Pro 2 and i1Pro 3 only).

After each step you type one line about what you did and what the program
showed, and (for instruments with lights) one line about what the lights did.

### What it needs

- **Windows (the main route):** the free USBPcap, which comes with
  [Wireshark](https://www.wireshark.org): on the installer's page "USB
  Capture", tick "Install USBPcap" (it is not ticked by default), then restart
  Windows. No security setting has to be switched off: on Windows 10 and 11
  USBPcap installs a driver signed through Microsoft's signing service. The
  tool checks, without changing anything: the Windows version, whether USBPcap
  is installed and running, whether the window runs as administrator (a recording
  needs that, because USBPcap lets only administrators listen to the USB
  ports: right-click the tool, "Run as administrator"; since 1.5.2 the tool
  stops before the steps and says how, instead of trying), which driver
  the instrument is on (since 1.5.1: on the ArgyllCMS driver the vendor
  program cannot see it, and the tool says how to switch it to X-Rite's driver
  and back), which USB root hub the instrument is on, and which measuring
  programs and versions are installed. It then starts and stops
  USBPcap's own recorder (`USBPcapCMD`) for every step. If it cannot, it times
  the steps while you record the whole session with Wireshark yourself, and
  the analysis cuts that recording into the steps later.
- **Help with installing USBPcap, and with administrator rights (since
  1.5.3), only after a yes.** When USBPcap is missing, the tool first says
  in plain words what it is (free, open-source, by its own author, not by
  us), that it installs a system driver, that one user has reported a blue
  screen naming its driver on Windows 11 25H2 (USBPcap issue #146), and how
  to remove it. Then it asks whether to fetch USBPcap's own installer. On a
  yes it downloads `USBPcapSetup-1.5.4.0.exe` from USBPcap's official GitHub
  release over HTTPS (Python's standard `urllib`, nothing else) into a new,
  empty folder of your own (in your user's temporary folder; the tool shows
  where), and compares its SHA-256 fingerprint with the one written into the
  tool's source (the same one Wireshark's build pins), once after the
  download and again just before starting it; on any difference it deletes
  the file and starts nothing. (Not next to the tool: a Downloads folder can
  hold old files that an installer running as administrator might pick up.) It then asks again
  before starting the installer, which it starts the normal, visible way: no
  silent switches, Windows asks its own User Account Control question, and
  USBPcap's installer shows its licence. Afterwards it checks whether USBPcap
  is installed, says so, asks you to restart Windows (it never restarts the
  computer itself), and offers to delete the downloaded file. Not running as
  administrator, with USBPcap installed, it offers once to start itself again
  as administrator through Windows' own question, and closes this window
  when the new one opens. Every "no", a failed download or a refused Windows
  question leads to the manual steps. This is written out here on purpose,
  for you and for any antivirus analyst: an unsigned program that downloads
  and starts an installer can look suspicious, so the code doing it is plain
  and short (`offer_usbpcap_install` and `offer_relaunch_as_admin` in
  `chromiq_io_probe.py`). It is not offered on Windows on ARM, where there
  is no instrument driver anyway.
- **Version facts, checked and shown up front:** i1Profiler 3.8.7 removed
  support for the i1Pro 2, so 3.8.6 or older is needed for it. X-Rite says the
  i1Pro 2 / iO2 driver is blocked on Windows 11 version 25H2 and newer; the
  tool shows that to i1Pro 2 (and first i1Pro) users only, and lets them carry
  on if their program still finds the instrument. It does not concern the
  i1Pro 3. There is no driver for Windows on ARM (including a Windows
  virtual machine on an Apple Silicon Mac).
- **Mac:** only with System Integrity Protection switched off, exactly as for
  the i1iO (see above). The measuring programs run on Windows and on the Mac,
  so the Windows route works with the same instrument.
- **Linux:** `usbmon` and `tcpdump`; the vendor programs themselves do not run
  on Linux.

### What is collected, and what happens to it

- The USB conversation between the program and the instrument. It
  necessarily includes the instrument's **serial number and factory
  calibration data**, because the program reads them from the instrument every
  time it connects. They identify your instrument, not you. The tool says so
  before you start.
- While a step records, USBPcap also sees the other devices on the same USB
  root hub, such as a keyboard. After each step the tool makes a copy that
  holds **only the instrument's traffic** (its device address and nothing
  else). Only that copy goes into the session folder (`instrument-session-<date>`);
  the full recordings sit in a separate folder ending in `-FULL-do-not-send`,
  and the tool offers to delete them at the end.
- Your one-line notes for each step, the program name and version, and the
  checks above, in `session.json`.
- `analysis.txt`: the tool's own reading of the recordings (see `--analyze`).
- **Nothing is uploaded, ever.** If you want to help, zip the session folder
  yourself and send it, with the report. Remember that the zip contains your
  instrument's serial number and its factory calibration data. Either attach
  it in the forum thread where you heard about this tool, or open a
  [new issue](https://github.com/itsab1989/ChromIQ/issues/new) and attach it
  there. If you would rather not post your instrument's serial number in
  public, send the zip in a private message to itsab1989 on the forum
  instead. (Issue #129 is for the i1iO table only.)

### What we will do with it

Study how the vendor program drives the instrument: the commands, where the
ruler or position data travels, how the dual scan and the lights are
commanded, the measurement timing and sizes. The analyser decodes the commands
that ArgyllCMS documents for each instrument family (its source is GPL; this
tool is MIT, so no Argyll code is copied, only facts, with references to
where Argyll documents them) and lists everything else raw.

---

## What's in the report

So you know exactly what you're sending:

- Your operating system name and version, and the processor type (for example
  "Apple Silicon (Apple M1)").
- The list of USB devices the system knows about, how they are wired together
  (hubs and Location IDs), and for the X-Rite devices their USB descriptors and
  interfaces as the system recorded them. This is the same kind of list 1.3
  collected; on current macOS 1.3 simply got an empty one.
- Which X-Rite driver software and i1Profiler version is installed.
- On a Mac: whether SIP is on or off, and which USB recording interfaces exist.
- **i1Profiler chart *metadata***: the names and patch *counts* of the iO test
  charts, and any patch-size figures stated in i1Profiler's own help text. This
  reports facts *about* those files (names, counts, short number snippets); it
  does **not** copy X-Rite's chart data.
- Your three answers.
- If you did the optional step: a list of timestamps of what you were doing,
  and on a Mac the result of the recording check.

> A note on any patch sizes it may quote: i1Profiler's help text tends to state
> the numbers for the **i1Pro 3 PLUS** (the large-aperture instrument), which
> are bigger than a regular i1Pro / Pro 2 / Pro 3 would use. So read those as
> "for the PLUS" unless it says otherwise.

A recording file (`.pcap`) is separate from the report. The X-Rite-only copy
holds nothing but the table's and the instrument's USB traffic.

---

## Running from source

If you'd rather run the readable Python (it needs Python 3.8+, which macOS and
Linux normally already have):

```bash
python3 chromiq_io_probe.py
```

Or use the double-click launchers in the scripts bundle: `Start-macOS.command`,
`Start-Windows.bat`, `Start-Linux.sh`.

For testing, `tools/vm_test/` drives the built Windows exe on a real Windows
machine (a double-click start, every ending, an 80-column window, the
questions) and writes a PASS / FAIL list; its README explains the hidden
`--selftest` switch it uses.

Useful options:

- `--no-redact`: keep serial numbers and paths as-is (there's no need to; they
  aren't useful for this work).
- `--skip-annotate`: never offer the recording step.
- `--annotate` (or `--record`): go straight to the recording step.
- `--capture-setup` (macOS): say whether this Mac can record USB traffic, and
  how, then exit. Changes nothing.
- `--i1pro` (or `--instrument`): go straight to the handheld-instrument session.
- `--pause` / `--no-pause`: always, or never, end with "Press Enter to close
  this window." Without either, the tool waits only when it has a console
  window of its own (a double-click on Windows); a run whose input or output
  is piped or redirected, or under CI, never waits. The launchers pass
  `--no-pause` because they wait themselves.
- `--analyze [FILE or FOLDER ...]`: read USB recordings (`.pcap` or `.pcapng`,
  from Windows, macOS or Linux) or an `instrument-session-*` folder and print a
  plain verdict (real traffic, or only zeros?) plus a command timeline. For an
  i1Pro, i1Pro 2, i1Pro 3, ColorMunki or i1Studio it names every known command
  with its arguments, lists unknown commands in full, counts every endpoint
  that carries data, compares the steps (sizes, counts, readings per second,
  fast against slow, the no-ruler control) and decodes the light commands.
  With no path it finds the newest session or recording next to the tool.
  Reads only; sends nothing to the device.

The tests need nothing but Python: `python3 -m unittest discover -s tests -v`.

---

## Privacy

By default the tool replaces serial numbers with a short scrambled code
(including the copy macOS hides inside `UsbDeviceSignature`, which 1.3 missed)
and removes your username and home-folder path. It does not collect documents,
images, profiles, measurements, or anything personal: only descriptions of
connected hardware, the processor type, the SIP state, and which X-Rite
software is installed. If you spot anything in the report you'd rather not
share, just delete it before sending.

---

## Building the binaries yourself

The release binaries are built by GitHub Actions (`.github/workflows/build.yml`)
on Windows, Linux, and macOS runners (one universal Intel + Apple Silicon
build), using PyInstaller. Push a `v*` tag to build them and publish a release.
There is nothing to cross-compile and no hidden steps: it's just
`pyinstaller --onefile` on each OS.

---

## License

MIT, see [LICENSE](LICENSE).
