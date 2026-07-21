# ChromIQ — i1iO information collector

<a href="https://ko-fi.com/itsab1989"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support ChromIQ on Ko-fi" height="36"></a>

A tiny, **read-only** tool that collects information about an **X-Rite i1iO
scanning table** and the computer it's connected to. It exists to help work out
whether [ChromIQ](https://github.com/itsab1989/ChromIQ) could one day drive the
i1iO directly — see [ChromIQ issue #129](https://github.com/itsab1989/ChromIQ/issues/129).

It takes about **two minutes**, and you do **not** need to be technical.

---

## Is this safe?

**Yes — this is the important part, so here it is plainly:**

- It **never sends anything to the table.** Not one byte.
- It **cannot move the arm.** It does not even open a connection to the device.
- It changes nothing, and needs no special setup or calibration.

All it does is read information your operating system already keeps about
plugged-in hardware — the same kind of thing you'd see in Device Manager or
System Information — plus a few facts about the X-Rite software you have
installed. You can run it with the arm parked. Nothing will move.

Serial numbers are scrambled and personal paths removed by default. You can
open the report it produces and read every line before sending it.

---

## How to run it — the easy way (no Python needed)

Download the one file for your system from the
[**latest release**](../../releases/latest), then run it. Plug in and switch on
your i1iO first.

| Your system | Download |
|-------------|----------|
| **Windows** | `chromiq-io-probe-windows.exe` |
| **macOS** (Intel **and** Apple Silicon) | `chromiq-io-probe-macos` |
| **Linux** | `chromiq-io-probe-linux` |

The macOS download is a single universal build — it runs on both Intel and
Apple-Silicon Macs, so there's only one file to pick.

### Windows

Double-click the `.exe`. Windows will warn you once — click **More info** →
**Run anyway**.

### macOS

Downloaded files aren't marked as runnable, so **double-clicking may appear to
do nothing at all**. Two ways round it:

**In Finder:** **right-click** the file → **Open** → **Open** again in the
dialog that appears. (Right-click → Open is what gets past the warning;
double-click alone won't.) If macOS still refuses, go to **System Settings →
Privacy & Security**, scroll down, and click **Open Anyway** — then open it
again.

**Or in Terminal** (this is the reliable route):

```bash
cd ~/Downloads
chmod +x chromiq-io-probe-macos
./chromiq-io-probe-macos
```

`chmod +x` simply marks the file as runnable — downloads never are by default.
The second line starts it.

### Linux

Same idea, from a terminal:

```bash
cd ~/Downloads
chmod +x chromiq-io-probe-linux
./chromiq-io-probe-linux
```

> These downloads are **not code-signed** (signing needs a paid certificate),
> so your computer will warn you the first time. That's normal and doesn't mean
> anything is wrong — the full source is in this repo if you'd like to check it
> first.

Prefer to **read the source before running anything**? That's the best instinct.
Download `chromiq-i1io-probe-scripts.zip` from the release instead (or clone this
repo). It's a short, plain Python file plus double-click launchers — see
["Running from source"](#running-from-source) below.

---

## What happens when you run it

A window opens and walks you through three short steps:

1. **It looks for your i1iO** and tells you straight away whether it found it.
2. **It collects the details** (a few seconds, nothing needed from you).
3. **It asks three easy questions** — which iO generation you have, which
   instrument is mounted, and which software you use. Press Enter to skip any.

At the end it offers an **optional advanced step** (recording what i1Profiler
says to the table while you use it). It takes longer, and you are very welcome
to say no — the basic report is already useful on its own.

**On macOS that step now needs nothing installed.** No Wireshark, no ChmodBPF,
no drivers: macOS already includes `tcpdump`, so the tool simply writes a
short, readable `start-usb-capture.command` script that you can double-click.
It asks for your admin password (macOS requires that to listen to USB
traffic), records to a `.pcap` file, and puts every setting back the way it
found it when it finishes. It still only listens — it cannot move the arm.

It then saves a plain-text file such as `chromiq-io-probe-20260721-143052.txt`.
**Open it, have a look, then attach it to
[issue #129](https://github.com/itsab1989/ChromIQ/issues/129).** That's it.

---

## What's in the report

So you know exactly what you're sending:

- Your operating system name and version.
- Connected X-Rite USB devices — identifiers, hardware revision, how they're
  wired together, and their USB descriptors.
- Which X-Rite driver software and i1Profiler version is installed.
- **i1Profiler chart *metadata*** — the names and patch *counts* of the iO test
  charts, and any patch-size figures stated in i1Profiler's own help text. This
  reports facts *about* those files (names, counts, short number snippets); it
  does **not** copy X-Rite's chart data.
- Your three answers.
- If you did the optional step: a list of timestamps of what you were doing.

> A note on any patch sizes it may quote: i1Profiler's help text tends to state
> the numbers for the **i1Pro 3 PLUS** (the large-aperture instrument), which
> are bigger than a regular i1Pro / Pro 2 / Pro 3 would use. So read those as
> "for the PLUS" unless it says otherwise.

---

## Running from source

If you'd rather run the readable Python (it needs Python 3.8+, which macOS and
Linux normally already have):

```bash
python3 chromiq_io_probe.py
```

Or use the double-click launchers in the scripts bundle: `Start-macOS.command`,
`Start-Windows.bat`, `Start-Linux.sh`.

Useful options:

- `--no-redact` — keep serial numbers and paths as-is (there's no need to; they
  aren't useful for this work).
- `--skip-annotate` — never offer the advanced capture step.
- `--annotate` — go straight into the advanced capture step.

---

## Privacy

By default the tool replaces serial numbers with a short scrambled code and
removes your username and home-folder path. It does not collect documents,
images, profiles, measurements, or anything personal — only descriptions of
connected hardware and which X-Rite software is installed. If you spot anything
in the report you'd rather not share, just delete it before sending.

---

## Building the binaries yourself

The release binaries are built by GitHub Actions (`.github/workflows/build.yml`)
on Windows, Linux, and Intel + Apple-Silicon macOS runners, using PyInstaller.
Push a `v*` tag to build them and publish a release. There is nothing to
cross-compile and no hidden steps — it's just `pyinstaller --onefile` on each OS.

---

## License

MIT — see [LICENSE](LICENSE).
