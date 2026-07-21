# Changelog

## v1.2.1

- **The guided walkthrough now matches what i1Profiler can actually do.** It
  previously asked for two things the software offers no way to do: sending the
  arm to a home position, and switching the electrostatic foil on and off. The
  arm parks itself and the static mat holds the paper on its own — neither is
  under the operator's control. The steps now follow i1Profiler's real
  sequence: press Measure, then align the arm **by hand** on the top-left,
  bottom-left and bottom-right corner patches, then let it scan.
- **Saying "no" to the capture no longer silently swallows the walkthrough.**
  The prompt now says what it is about to do and roughly how long it takes, and
  declining explains what was skipped and how to come back to it later.
- ChromIQ is free and always will be — if it saves you time or ink, a
  coffee on [Ko-fi](https://ko-fi.com/itsab1989) is a kind way to say
  thanks.

## v1.2.0

- **macOS USB capture no longer needs Wireshark — or anything installed.**
  The optional advanced step used to say "install Wireshark plus its ChmodBPF
  helper". That is no longer necessary: macOS already ships `tcpdump`, and
  running it under `sudo` removes the need for ChmodBPF entirely. The tool now
  writes a ready-made `start-usb-capture.command` script you can read and
  double-click. It records the traffic, then puts every setting back as it
  found it. Nothing is installed and nothing is left behind.
- **Capture interfaces are detected, not guessed.** The old instructions named
  `XHC20`, which simply does not exist on many Macs (an Apple-Silicon machine
  has `XHC0`/`XHC1`/`XHC2`). The names are now read from the system, all of
  them are recorded at once, and the report says which ones exist — so it is
  clear up front whether a capture is possible on that Mac at all.
- **Clearer downloads.** README and release notes now spell out `chmod +x` and
  the Finder right-click → Open route, because a downloaded binary that is not
  marked executable appears to do nothing at all when double-clicked.
- New `--capture-setup` option writes just the capture script and exits.

## v1.1.0

- **Ready-to-run downloads — no Python needed.** GitHub Actions now builds
  standalone binaries for Windows, Linux, and a single **universal** macOS build
  that runs on both Intel and Apple-Silicon Macs. Grab the one for your system
  from the release; the readable source is still available as a scripts zip.
- **i1Profiler chart-metadata collector.** On a machine with i1Profiler
  installed, the tool now reports the iO test charts it finds — their names,
  patch counts, and any patch-size figures stated in the help text. It reports
  facts *about* those files, never their contents.
- **Report always lands somewhere you can find it.** When run as a packaged
  binary, the report is saved next to the downloaded file (and, failing that,
  on your Desktop) — never in a temporary folder that disappears on exit.
- **Serial numbers hashed, personal paths stripped** by default, on every
  platform's output format.

## v1.0.0

- First version. Read-only collector of USB device details for the ChromIQ
  i1iO support investigation ([ChromIQ #129](https://github.com/itsab1989/ChromIQ/issues/129)).
  It never opens or sends anything to the table — it only reports what the
  operating system already knows about connected hardware. Cross-platform
  (macOS / Windows / Linux) with double-click launchers, plus an optional
  guided USB-capture step.
