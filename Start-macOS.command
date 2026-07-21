#!/bin/bash
# ChromIQ i1iO probe — macOS launcher. Double-click this file.

# A double-clicked .command starts in the user's home folder, not here.
cd "$(dirname "$0")" || exit 1

clear
echo
echo "  ChromIQ — i1iO information collector (macOS)"
echo

# /usr/bin/python3 exists on every Mac, but on a machine without the Xcode
# Command Line Tools it is only a stub that pops up an installer. So test that
# it can actually run something rather than just that it exists.
if ! python3 -c "print()" >/dev/null 2>&1; then
    echo "  Python 3 is not ready on this Mac yet."
    echo
    echo "  macOS can install it for you. Open the Terminal app and run:"
    echo
    echo "      xcode-select --install"
    echo
    echo "  Accept the dialog that appears, wait for it to finish (a few"
    echo "  minutes), then double-click this file again."
    echo
    read -n 1 -s -r -p "  Press any key to close this window..."
    echo
    exit 1
fi

python3 chromiq_io_probe.py
status=$?

echo
if [ $status -ne 0 ]; then
    echo "  The collector exited with an error (code $status)."
    echo "  Please copy this window's contents into the GitHub issue."
    echo
fi
read -n 1 -s -r -p "  Press any key to close this window..."
echo
