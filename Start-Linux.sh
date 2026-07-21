#!/bin/bash
# ChromIQ i1iO probe — Linux launcher.
#
# Double-click this if your file manager allows it, otherwise open a terminal
# in this folder and run:   bash Start-Linux.sh

cd "$(dirname "$0")" || exit 1

clear
echo
echo "  ChromIQ — i1iO information collector (Linux)"
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "  Python 3 is not installed."
    echo
    echo "  Install it with your package manager, for example:"
    echo "      Debian / Ubuntu :  sudo apt install python3"
    echo "      Fedora          :  sudo dnf install python3"
    echo "      Arch            :  sudo pacman -S python"
    echo
    read -n 1 -s -r -p "  Press any key to close..."
    echo
    exit 1
fi

# usbmon gives far richer USB detail, and loading it is harmless. Only try if
# it is not already there, and never make the run depend on it succeeding.
if ! lsmod 2>/dev/null | grep -q usbmon; then
    echo "  (optional) Loading the usbmon module improves the report."
    echo "  You may be asked for your password. Skipping is fine — press"
    echo "  Ctrl-C at the password prompt if you would rather not."
    sudo modprobe usbmon 2>/dev/null || true
    echo
fi

python3 chromiq_io_probe.py
status=$?

echo
if [ $status -ne 0 ]; then
    echo "  The collector exited with an error (code $status)."
    echo "  Please copy this window's contents into the GitHub issue."
    echo
fi
read -n 1 -s -r -p "  Press any key to close..."
echo
