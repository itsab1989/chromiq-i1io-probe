# Changelog

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
