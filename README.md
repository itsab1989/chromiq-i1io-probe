# ChromIQ X-Rite instrument probe

<p align="center">
  <a href="https://ko-fi.com/itsab1989"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support ChromIQ on Ko-fi" height="36"></a>
  <br>
  <sub>ChromIQ is free and always will be. If it's useful to you, a coffee is a kind way to say thanks. It is completely optional, and the app stays fully featured either way.</sub>
</p>

A small, **read-only** tool that collects information about **X-Rite
instruments** and the computer they are connected to, and can record what the
vendor's own program says to them: the **i1iO** scanning table, the **i1Pro
family** (original i1Pro, i1Pro 2, i1Pro 3 and 3 Plus), the **ColorMunki
Photo / Design** and **i1Studio**, and since 1.6 the **i1iSis** chart readers
(i1iSis, i1iSis XL, i1iSis 2, i1iSis 2 XL). It exists to help
[ChromIQ](https://github.com/itsab1989/ChromIQ) understand these instruments
better. For the i1iO see [ChromIQ issue #129](https://github.com/itsab1989/ChromIQ/issues/129);
the handheld-instrument session is described [below](#the-handheld-instrument-session-new-in-15),
the i1iSis session [after it](#the-i1isis-session-new-in-16).

It takes about **two minutes**, and you do **not** need to be technical.

> **Version 1.5.4 is aimed at the next i1iO recording.** The first real
> recording of an i1iO 2 (with an i1Pro 2, on a Mac) now exists. It showed
> that i1Profiler talks to the table in short lines of text through a common
> USB-to-serial chip, and every one of its 2,475 lines passed the check
> number we worked out, so we very likely read the format correctly. Much is
> still unknown (what lowers and lifts the head, how a job is stopped, how
> the table reports a problem), and nothing is promised: ChromIQ cannot drive
> the table. 1.5.4 asks for exactly what is missing, in
> [up to five short steps](#the-i1io-steps-in-154). Since then, testers have
> also recorded handheld instruments (an original i1Pro, an i1Pro 2 and an
> i1Pro 3) with the handheld session.

> **Important if you made a recording with version 1.6.1 or older:** those
> versions could keep traffic of **another USB device** that shared the
> instrument's USB hub (for example a USB disk or memory stick) in the files
> meant to hold only the instrument's traffic, and in `analysis.txt` and the
> report. For a disk that can include its model name, its serial number and
> the first sectors of the disk. Version 1.6.2 fixes this. What to do:
> 1. Update to 1.6.2.
> 2. Clean what you already made: run the tool with `--clean` and the
>    `SEND-THIS-....zip` (or the session folder). It writes a cleaned copy
>    next to it and says what it removed (how much, and what kind of device
>    it looked like, never the content); your original stays as it was.
>    Or simply delete the old files.
> 3. While you record, unplug every other USB device you can from that
>    computer, or at least from the same hub or dock (disks, memory sticks,
>    printers, phones, adapters). 1.6.2 cannot tell every such device apart
>    from the instrument ([what it can and cannot](#which-traffic-is-the-instruments-since-162)).
>
> If you already sent us an older file, tell us and we will delete it
> wherever we can, and treat it as private meanwhile.
> [Why it happened](#which-traffic-is-the-instruments-since-162).

> **If every step of a session says it kept nothing (1.6.3):** a tester's
> screenshot showed this once, on Windows with an i1Pro 3, although the same
> PC recorded fine before and after. Why it happens is **not known yet**.
> Since 1.6.3 the tool says, after such a step, what the recording did hold
> (counts, kinds of device and USB ids only, never contents) and what you can
> try, one action per line; at the end it writes one small
> `SEND-THIS-<date>-report-only.zip` with only the report and `session.json`
> (no recording). Sending that helps us find the cause.
> [Details](#when-a-step-keeps-nothing-since-163).

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
       2. record a handheld instrument or an i1iSis   <- suggested
          (the i1Pro family, the ColorMunki, the i1Studio, the i1iSis
          chart readers)
       3. nothing more: just make the report
       a. look again (after plugging something in)
   ```

   With nothing plugged in it says so, and `a` lets it look again after you
   plug the instrument in. For the i1iO (choice 1) it asks three easy
   questions (which iO generation, which instrument is mounted, which
   software and version) and then offers an **optional extra**: recording
   what i1Profiler says to the table. Choice 2 is the handheld session (or
   the i1iSis session) described below. `--io`, `--i1pro` and `--isis`
   choose without asking.

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
3. You do up to five short steps in i1Profiler, about 30 minutes (see
   [the i1iO steps](#the-i1io-steps-in-154) below). The recording runs the
   whole time; after each step the tool checks the recording so far and says
   whether the table's commands are in it ("this step recorded 14 commands to
   the table: good", or "please repeat it"), so nothing has to be done again
   later.
4. It stops recording, **switches the interfaces off again** (also after
   Ctrl-C), and checks each recording. If every data byte in it is zero, it
   says so plainly: that has been seen on an Apple Silicon Mac before.
5. It makes a copy holding only the X-Rite devices' traffic. That copy is the
   one to send. The full recordings can hold everything else on those USB
   buses, possibly including what you typed on a USB keyboard, so the tool
   offers to delete them.
6. It asks a few questions about the chart, shows a table of the steps
   (recorded, table commands seen, anything missing) while SIP is still off,
   and ends with a box with the exact steps to switch SIP back on and how to
   check it (`csrutil status`).

### The i1iO steps in 1.5.4

The first recordings already hold the connection, the calibration, the hand
alignment of the corners and the row scans. These steps ask for what is
missing, the most useful first, so stopping after one or two still helps:

1. **One row of a chart that scans in one pass**, for example one of
   i1Profiler's own i1iO test charts. With the calibration.
   You type a letter (and Enter) the moment you see something: `a` when the arm starts
   along the row, `l` when the instrument's lamp lights up, `d` and `u` when
   the head goes down and up. Then Cancel during the second row. The first
   recordings most likely show i1Profiler's fallback (its help says a row
   that cannot be scanned is read again more slowly and then patch by
   patch, and that happened on every row), so a normal one-pass scan has
   not been recorded yet. They also suggest that the table waits for the
   instrument before it moves, without being told; the marks are how we can
   tell the two apart, and learn which command lowers the head.
2. **A few patches in spot mode, watching the head**, if i1Profiler offers
   spot mode for the table.
3. **A small chart to the end, with the fastest setting** i1Profiler offers
   (two rows, 10 to 20 patches, placed somewhere else on the table),
   letting the arm park by itself.
4. **One row with dual scan (M1 or M2)**, if offered. The recording shows only
   how the instrument is asked to measure; i1Profiler most likely does the M1
   or M2 arithmetic itself.
5. **One row of the earlier chart**, if it is still printed: the fallback
   once more, now that we know what it is.

Then a few questions with no recording running: the chart files, the paper
size, a ruler measurement of the first row (this proves the unit of length),
the i1Profiler settings, whether the earlier chart always fell back, the
sheet hold and what the table shows when something goes wrong, and whether
i1Profiler can lower or lift the head on its own. A step starts with Enter and ends when you type `e` and Enter, so a stray key
cannot cut it short. Each step can be skipped or done again; steps 2, 4 and 5
are only for when i1Profiler offers them or the chart is at hand.

Left out on purpose: provoking an error by holding the arm back or removing
the instrument, or trying whether the table moves without the instrument
measuring (we cannot know that it is harmless for the table, and i1Profiler
offers no way to try it), and switching the table off with the arm out (the
first recordings already show that start-up).

**See every step first, without recording:** run the tool with `--rehearse`
(on a Mac: `./chromiq-io-probe-macos --rehearse` in the Terminal, in the
folder where the file is). It records nothing and saves nothing, so you can
do it while SIP is still on. Before the recording starts, the tool also shows
a short list of what to have ready.

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
**A Windows virtual machine on an Apple Silicon Mac does not work** for a
recording: it runs Windows on ARM, where the recorder (USBPcap) does not
exist, and we know of no X-Rite driver there for the i1Pro 2, the i1iO or the
ColorMunki.

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
5. The same strip again, clearly faster (press the button, wait for the
   ready signal, then move).
6. The same strip again, slowly: about twice as long as the normal scan in
   step 3 (for most people 4 to 6 seconds, counted).
7. Let one scan fail on purpose, for example by lifting the instrument
   halfway (skip it if you would rather not).
8. Read one single patch, if the program offers it. Afterwards the tool
   reminds you to switch the program back to scanning strips (since 1.6.3).
9. The same strip without the ruler, as a comparison, if the program allows
   it (i1Pro 2 and i1Pro 3 only).

Each step's instructions are a short numbered list, one action per line
(since 1.6.2). After each step you type one line about what you did and what
the program showed, which measurement condition the program showed (M0, M1,
M2 or dual scan) where it matters, and (for instruments with lights) one
line about what the lights did (since 1.6.3 a bare "no" is asked once more:
did the lights not change, or did you not look?).

### When a step keeps nothing (since 1.6.3)

The tool keeps only traffic it can attribute to the instrument, and that has
not changed. When a step's recording is not empty but nothing in it could be
attributed, the step's check now says what the recording did hold, in counts
and USB ids only:

- how many records, and of which kinds of device (hub, keyboard or mouse,
  disk, a device whose USB description the recording does not hold, ...);
- whether the instrument family's USB id was seen, and whether the
  instrument did anything there;
- how many records travelled on the family's endpoint numbers under another
  address;
- whether another X-Rite instrument the tool knows was at work.

If a step holds only another instrument's traffic (you chose, say, the
i1Pro 2, but an i1Pro 3 is plugged in), the tool says that first, names
the number to choose when you start it again, and offers to stop at once;
it gives no replug advice then.

Then it lists what you can try, one action per line: unplug the instrument,
wait five seconds, plug it back in, start the tool again; if the steps are
still empty, restart Windows with "Restart" (not "Shut down" and switching
on again) and plug the instrument in afterwards. The cause of a session in
which every step stays empty is not known; this is what may help, nothing
more. When no step of a session kept anything, the tool still writes ONE
small file, `SEND-THIS-<date>-report-only.zip`, with only the report and
`session.json`. They hold no recording, and they help us find out why.

**On Windows, if the check says "USB recorder attached to your instrument:
no" (since 1.6.5):** USBPcap joins a USB device only when Windows sets it up.
Close the tool, unplug the instrument, restart Windows with "Restart" (not
"Shut down"), plug the instrument in afterwards and start the tool again.
If the first step records only the instrument's USB description, the tool
says so at once and asks you to check that the measuring program shows the
instrument as connected.

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
  `chromiq_io_probe.py`). It is not offered on Windows on ARM, where USBPcap
  does not exist.
- **Version facts, checked and shown up front:** i1Profiler 3.8.7 removed
  support for the i1Pro 2, so 3.8.6 or older is needed for it. X-Rite says the
  i1Pro 2 / iO2 driver is blocked on Windows 11 version 25H2 and newer; the
  tool shows that to i1Pro 2 (and first i1Pro) users only, and lets them carry
  on if their program still finds the instrument. It does not concern the
  i1Pro 3. On Windows on ARM (including a Windows virtual machine on an
  Apple Silicon Mac) no recording is possible, because USBPcap does not
  exist there. We know of no X-Rite driver there for the i1Pro 2, the i1iO
  or the ColorMunki. The i1Pro 3 asks Windows for Microsoft's own USB driver,
  so it may be recognised there; whether i1Profiler can measure with it on
  ARM is not known.
- **Mac:** only with System Integrity Protection switched off, exactly as for
  the i1iO (see above). The measuring programs run on Windows and on the Mac,
  so the Windows route works with the same instrument.
- **Linux:** `usbmon` and `tcpdump`; the vendor programs themselves do not run
  on Linux, so a recording works only when they run in a virtual machine that
  the instrument is passed through to. A Linux recording does not carry the
  instrument's USB description unless it is plugged in while recording; the
  analysis then recognises an i1Pro or ColorMunki by its own commands.

### What is collected, and what happens to it

- The USB conversation between the program and the instrument. It
  necessarily includes the instrument's **serial number and factory
  calibration data**, because the program reads them from the instrument every
  time it connects. They identify your instrument, not you. The tool says so
  before you start.
- While a step records, USBPcap also sees the other devices on the same USB
  root hub, such as a keyboard. After each step the tool makes a copy that
  is meant to hold **only the instrument's traffic** (by the rules
  [below](#which-traffic-is-the-instruments-since-162), which say what they
  cannot tell apart; up to 1.6.1 by its device address alone, which was not
  enough). Since 1.6.3 that is only the instrument family you chose (the
  i1Pro and the i1Pro 2 count as one), never another instrument the tool
  knows; an X-Rite device the tool does not know is kept only when the step
  shows none of your family, and the tool then says so after the step. Only
  that copy goes into the session folder (`instrument-session-<date>`);
  the full recordings sit in a separate folder ending in `-FULL-do-not-send`,
  and the tool offers to delete them at the end.
- Your one-line notes for each step, the program name and version, and the
  checks above, in `session.json`.
- `analysis.txt`: the tool's own reading of the recordings (see `--analyze`).
- **Nothing is uploaded, ever.** At the end the tool puts the report and the
  session folder's own files into ONE `SEND-THIS-<date>.zip` next to it; if
  you want to help, send that. Remember that the zip contains your
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

## The i1iSis session (new in 1.6)

The i1iSis reads a whole printed chart page by itself: you push the page in,
it pulls it through and measures every patch. The free ArgyllCMS driver, which
ChromIQ uses, cannot talk to the i1iSis at all, and as far as we know, nobody
outside X-Rite has described how i1Profiler does it. If you own an i1iSis, i1iSis XL, i1iSis 2 or
i1iSis 2 XL, a recording of a few pages helps us learn the basics. As always,
**nothing is promised**: whether ChromIQ can ever use an i1iSis is a separate
question, and the answer may be no.

**Please note: this session has not been tried with a real i1iSis yet.** We
built and tested it with made-up recordings only. So if something in it looks
odd or does not fit what your i1iSis does, that is not your fault: please tell
us, it helps just as much as a recording.

The tool offers the session when it sees an i1iSis plugged in (choice 2 at the
question "What would you like to do?"). You can also start it directly with
`--isis`. It works exactly like the handheld session above: the same recorders
and checks, one small file per step, skip, repeat or stop at any time,
`--steps` to repeat only some steps, the same help when a step keeps nothing
(since 1.6.3), and ONE `SEND-THIS-<date>.zip` at the end. Windows with
USBPcap is the main route; a Mac works only with System Integrity Protection
switched off.

**Linux** works only by recording the USB traffic of a virtual machine that
runs i1Profiler and has the i1iSis passed through to it (i1Profiler does not
run on Linux itself). And a Linux recording shows which device is the i1iSis
only when the i1iSis is plugged in while a step records, so the tool asks,
before the steps: in every step, start the step, then unplug the i1iSis's USB
cable and plug it back in (leave it switched on), wait until the virtual
machine and i1Profiler have found it again, and then do the step. Without
that, the tool keeps nothing from the step and says so.

**Before you start:** switch the i1iSis on FIRST, and then plug in its USB
cable. X-Rite's own notes for i1Profiler 3.8.8 say that if the cable goes in
first and the power comes on afterwards, i1Profiler does not see the i1iSis.
On Windows 11 version 25H2, use i1Profiler 3.8.8 or newer: X-Rite says that
version fixed the i1iSis drivers there.

### The chart page you need

One printed chart page made for the i1iSis. **Its colours do not matter for
this recording at all.** An old chart page you still have is perfect, as long
as i1Profiler still has that chart (open the same chart file in i1Profiler
before step 2). A quick print is fine too. This tool ships no chart. If you have
none, make one in i1Profiler:

- in the printer profiling part, go to the test chart page. With the i1iSis
  plugged in, i1Profiler lays the chart out for it by itself (in Advanced mode
  you can also choose the i1iSis by hand, in the device setup);
- i1Profiler also comes with ready-made charts for the i1iSis; their names end
  in "i1iSis" (for an i1iSis XL: "i1iSis XL");
- if the chart has a barcode, i1Profiler asks you to save the chart before
  printing it. That is normal: save it, then print;
- a chart with only one page is easiest. Print page 1 on normal 80 g/m2
  printer paper; that is all you need. (X-Rite's guide asks for paper 0.08 to
  0.45 mm thick; normal printer paper is right, please do not use thinner
  paper.)

For step 6 you also need one plain sheet of normal 80 g/m2 printer paper, the
same size as your chart.

### The steps

About 15 minutes. In every step you first press Enter in the tool's window,
then do the step in i1Profiler, then come back and type `e` and Enter.

1. **Start i1Profiler, then leave it idle.** i1Profiler closed, the i1iSis on
   and connected with no page in it. Start i1Profiler, wait until it has found
   the i1iSis, then leave everything alone for about 10 seconds.
2. **Get the i1iSis ready for a page, without feeding it.** On i1Profiler's
   measuring page, with Single scan, click Measure (or Start Measurement) and
   wait until the i1iSis is ready for the page (its light blinks green when it
   waits for a chart), then about 10 seconds more.
3. **Feed one page, single scan.** Feed page 1 as usual (quickly, about 5 cm,
   along the left-hand guide; the i1iSis pulls it in by itself) and wait until
   it has come out again and i1Profiler shows it as measured.
4. **The same page again, dual scan** (M0 and M2, on the i1iSis 2 also M1), if
   i1Profiler offers it; otherwise skip it.
5. **The same page, fed a little crooked** (a few millimetres, never forced).
   The i1iSis is made to correct small skew; this shows how. Skip it if you
   would rather not.
6. **A sheet without a chart**, fed like a chart page, so that it fails on
   purpose; then do what i1Profiler asks. Skip it if you would rather not.

After each step you type one line about what you did and what i1Profiler
showed, one about the i1iSis's light, and one about **how the page moved**
(in, out, back and forth, how many times, any sounds). These notes matter as
much as the recording: nobody has seen this traffic before.

What is deliberately not a step: paper jams (risk to the device), switching
the i1iSis off and on during a recording, and the OBC workflow.

### What is collected

The same as for the handheld session (see above): the USB conversation, your
notes, and the tool's analysis. The conversation **very likely** includes the
i1iSis's **serial number and factory calibration data**, as it does for every
X-Rite instrument we know; for the i1iSis that is not proven yet. In addition,
for the i1iSis: the **colour values it measured from your chart page** (your
printer's and paper's colours; they say nothing about you) and, if the chart
has a barcode, what the barcode holds, which may include the chart's name.

**Only the i1iSis is kept.** When a step's recording shows the i1iSis
(0971:2006), the copy that goes into the zip holds the i1iSis's traffic and
nothing else: not the keyboard, not a monitor calibrator, no other device at
all. (If two i1iSis are plugged in, both are kept: they share one ID.) Only
when a step's recording shows **no** i1iSis does the copy keep an X-Rite device
the tool does not know, in case an i1iSis model reports an ID nobody has seen
yet, and the tool then says so right after the step. It never keeps an X-Rite
instrument it knows to be another one. When the recording does not show which
device is which (a device in it has no USB description), the tool keeps
nothing and asks you to repeat the step.

### What the analysis shows

There is no decoder for the i1iSis: its protocol is not known. A plain
recording given to `--analyze` is read as an i1iSis recording when it shows an
i1iSis and no instrument the tool has a decoder for (an i1Pro, ColorMunki,
i1Studio or i1iO table); otherwise it is read as before 1.6. When you give
`--analyze` several plain files that come from different instruments (for
example an i1Pro 2 recording and an i1iSis recording), it does not mix them:
it lists which instrument each file shows and asks you to analyse each
instrument's recordings on their own (since 1.6.1; since 1.6.2 it prints the
paths as you gave them, and ends with exit code 2). `--analyze`
(and `analysis.txt` in the zip) lists each step's traffic, puts the steps side
by side (how long, how many bytes each way), says whether the i1iSis seems to
talk through a USB-to-serial chip like the i1iO table does, and, if the
program sends readable text, shows the first lines the **program** sent. The
i1iSis's answers are never shown in the analysis, only their sizes, because
they can hold its serial number (the same goes for any X-Rite device the tool
has no decoder for). It ends with a checklist: real traffic, the USB
description, a page measured in single scan, a dual-scan page, a crooked
page, a page that failed on purpose, and your notes on how the page moved.

**How the read-only promise is tested (since 1.6):** a test runs a whole
simulated i1iSis session while it watches, and blocks, the usual ways a Python
program opens files and starts programs (`open`, `io.open`, `os.open` and so
`pathlib`, `subprocess`, `os.system`, `os.popen`, `os.posix_spawn`,
`os.spawn*`, `os.exec*`, `os.fork`, `os.forkpty`, `os.openpty`, the `pty`
module, and libraries or Python's own C functions reached through `ctypes`).
It fails if the tool opens a device (on Windows also by a reserved name such
as `COM3` or `nul`, or by a `\\.\` or `\\?\` device path; since 1.6.2),
writes outside its own folders, or starts
a program other than the ones it names, each command line with the arguments
the tool really builds (each PowerShell command is compared with the exact
scripts the tool holds). A check of the source bans those functions outright
(and `_ctypes`, `dlsym`, `CFUNCTYPE`, `ctypes.CDLL`, `pythonapi`,
`multiprocessing` and `_posixsubprocess`) and allows `ctypes` only through
Windows' kernel32 and shell32, for the Windows calls the tool names. A test cannot
prove that nothing could slip through some other way, which is why the code is
kept plain to read.

**Where the facts come from:** the USB ID 0971:2006 from X-Rite's own i1iSis
driver file (installed with i1Profiler 3.8.8) and ArgyllCMS's device list; the
status light and how a page is fed from X-Rite's i1iSis quick start guide; the
single and dual scan modes and the chart rules from i1Profiler's own help. The
driver file lists one ID for the whole family, so the i1iSis 2 and the XL
models most likely report the same ID; that is not yet confirmed by a real
device.

---

## What's in the report

So you know exactly what you're sending:

- Your operating system name and version, and the processor type (for example
  "Apple Silicon (Apple M1)").
- The list of USB devices the system knows about, how they are wired together
  (hubs and Location IDs), and for the X-Rite devices their USB descriptors and
  interfaces as the system recorded them. This is the same kind of list 1.3
  collected; on current macOS 1.3 simply got an empty one. Since 1.6.3 the
  other devices appear with their USB vendor and product ids (and their kind,
  where the list has one) but **without their names**, and the location parts
  of Windows device IDs as short codes; Windows' own generic names
  ("Generic USB Hub", "USB Mass Storage Device") stay, because they only say
  what kind of device it is. With `--no-redact` everything is shown as the
  system lists it.
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
- `--steps 7,9`: in the handheld session, record only these steps (to repeat
  steps of an earlier session; 1.5.5).
- `--rehearse`: walk through the i1iO recording steps without recording or
  saving anything (1.5.4).
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
  For the **i1iO table** (1.5.4) it removes the USB-to-serial chip's status
  bytes, puts the table's lines back together, checks every line's check
  number, and prints one timeline of the table's lines (both directions) and
  the i1Pro's requests, each with what it most likely means and how sure we
  are (certain, likely or guess). Give it the probe report too
  (`--analyze io-capture-....pcap chromiq-io-probe-....txt`, or leave the
  report next to the recording) and it marks your steps and says per step
  whether the table's commands were recorded. The table's serial number is
  hidden unless you add `--no-redact`.
  With no path it finds the newest session or recording next to the tool.
  Reads only; sends nothing to the device. Since 1.6.2 it reads only what
  the copies keep, and shows no contents of a step in which another device
  shared the instrument's address. Since 1.6.3 it also counts the i1Pro 3's
  ruler travel per scan, lists every swipe with the time its readings took,
  and leaves the dual scan out of the "only with the ruler" comparison.
- `--clean ZIP_OR_FOLDER ...` (1.6.2): for files made with version 1.6.1 or
  older. Writes a cleaned copy of a `SEND-THIS-....zip` (as
  `...-cleaned.zip`), a session folder (as `...-cleaned`) or a single
  recording (as `...-cleaned.pcap`), next to the original: only the
  instrument's traffic by the rules of this version, `analysis.txt` made
  again from the cleaned recordings, the analysis inside the report
  replaced, and (since 1.6.3) the other USB devices' names in the report's
  device lists hidden. It
  says per file what it removed, as counts and the kind of device it looked
  like, never the content. The original is not changed; delete it yourself
  once you have the cleaned copy. Reports made with a version before 1.6.3
  contain codes that can be traced back to short serial numbers; please do
  not post such a report publicly, and delete one you already posted if you
  can. `--clean` cannot change those old codes.

The tests need nothing but Python: `python3 -m unittest discover -s tests -v`.

---

## Which traffic is the instrument's (since 1.6.2)

A real Windows recording showed a USB disk's traffic carrying the
instrument's own USB address. The most likely reason is in USBPcap, the
recorder: the address it writes into each packet is one it remembered when
the device was started, and after Windows gives a device a new address (for
example after waking from hibernation) another device can by then own the
remembered one (USBPcap's own issue 105). The tool used to keep everything
at the instrument's address, so it kept the disk's traffic too. (The full
recording no longer exists, so this cannot be proven for that one file.) A
Mac recording names the device in every packet, and Linux never gives one
address to two devices at the same time, but an address can come back after
a replug.

**What 1.6.2 leaves out.** A packet at the instrument's address is left out
when:

1. the address belonged to another device at that moment (each USB
   description at an address starts a new owner; the address every device
   uses while it is being set up is never kept);
2. it travels on an endpoint the instrument does not have, or of the wrong
   kind (from the instrument's own USB description in the recording, or the
   endpoints its family is known to have). This is the case in the recording
   we saw;
3. it is another kind of device's traffic: disk commands with their data and
   status, requests of a disk, keyboard, mouse or hub, another device's USB
   description, or a keyboard's typed keys on the instrument's own button or
   event endpoint (on a ColorMunki or i1Studio an empty or modifier-only
   keyboard report, with no key pressed, cannot be told apart; it carries no
   typed key).

No session keeps a monitor calibrator (such as an i1Display) either, and
since 1.6.3 a handheld session keeps only its own instrument family (as the
i1iSis session always did): never another instrument the tool knows, and an
X-Rite device it does not know only when the step shows none of the family,
with a note. The
step's check says what was left out, how much and what kind of device it
looked like, never what it was. When all of that traffic is explained as one
USB disk on two endpoints the instrument does not have (as in the recording
we saw), the analysis shows the step's decoded values (readings, ruler, lights,
counts, sizes, times) but no raw bytes, and says that another device's
traffic was removed. When another device's traffic was also seen on
one of the instrument's own endpoints, or could not be placed, the analysis
shows no contents of that step, only counts and sizes, marks it as "not
shown" in every comparison, and asks you to record it again with the other
devices unplugged.

**What 1.6.2 cannot tell apart.** A device that was given the instrument's
address and uses the same endpoint numbers as the instrument looks to the
recording exactly like the instrument. Its traffic can still end up in the
recording files, for example a USB 3 "UAS" disk, a printer, a phone or a
USB-serial adapter, and so can another device's vendor requests. If the tool
sees nothing else of that device, the analysis can show some of it too.

**So, while you record:** unplug every other USB device you can from that
computer, or at least from the same hub or dock. Not only disks and memory
sticks: also printers, phones, adapters and card readers. A keyboard and a
mouse may stay.

---

## Privacy

By default the tool replaces serial numbers with a short code (including the
copy macOS hides inside `UsbDeviceSignature`, which 1.3 missed) and removes
your username and home-folder path. Since 1.6.3 that code is mixed with a
random value made new for every run and never written anywhere, so it cannot
be traced back to the serial number by trying numbers, and is not the same in
two people's reports. **Reports made with a version before 1.6.3 contain codes
that can be traced back to short serial numbers.** Please do not post such a
report publicly, and delete one you already posted if you can. `--clean`
cannot change those old codes. It does not collect documents,
images, profiles, measurements, or anything personal: only descriptions of
connected hardware, the processor type, the SIP state, and which X-Rite
software is installed. Since 1.6.3 the other USB devices in its device lists
appear without their names (with `--no-redact`, as the system lists them). If
you spot anything in the report you'd rather not share, just delete it before
sending.

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
