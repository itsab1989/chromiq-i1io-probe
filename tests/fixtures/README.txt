Test fixtures, modelled on the structure of a real volunteer report from a
Mac with an i1iO 2 and an i1Pro 2 (ChromIQ issue #129).

Anonymised: serial numbers, container IDs, session IDs and every other
device on that Mac are replaced or removed. The serial "FAKESERIAL123" is
invented and exists so the redaction tests have something to hash.
The interface values in macos-ioreg-service-io2.txt are invented too (the
real report did not include the service plane); they only test the parser.

The windows-*.txt files are NOT copies of real output. They were written
from the formats the USBPcap and Windows documentation describe
(USBPcapCMD's --extcap-interfaces / --extcap-config output, "sc query",
and "DisplayName :: DisplayVersion" lines from the tool's own PowerShell
query), with invented device names. They test the parsers, not Windows.

1.5.1: windows-pnp-summary-remembered.txt and windows-drivers-*.txt follow
the STRUCTURE of the first handheld report (Windows 11, an i1Pro 3 plugged
in on the ArgyllCMS driver, older entries Windows remembers from other USB
sockets and from an earlier instrument). Device and driver names are the
generic product and driver names Windows shows; every instance ID is
invented, and nothing personal from that report is in them. The
"DRV :: ..." lines are the tool's own PowerShell output format.
