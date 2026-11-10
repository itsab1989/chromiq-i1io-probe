Test fixtures, modelled on the structure of a real volunteer report from a
Mac with an i1iO 2 and an i1Pro 2 (ChromIQ issue #129).

Anonymised: serial numbers, container IDs, session IDs and every other
device on that Mac are replaced or removed. The serial "FAKESERIAL123" is
invented and exists so the redaction tests have something to hash.
The interface values in macos-ioreg-service-io2.txt are invented too (the
real report did not include the service plane); they only test the parser.
