# Changelog

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
