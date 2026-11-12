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
