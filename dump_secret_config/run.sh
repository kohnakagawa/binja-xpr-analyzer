#!/bin/bash
#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#

# check SIP is disabled
if [[ $(csrutil status) == "System Integrity Protection status: enabled." ]]; then
    echo "This script will not work with SIP enabled. Please disable it."
    echo "NOTE: Disabling SIP reduces the security of your system. After you finish using this script, please re-enable SIP."
    exit 1
fi

XProtectPath="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediator*"

echo "command script import \"$PWD/extract_config.py\"" > autorun
echo "run" >> autorun
echo "quit" >> autorun

for i in $XProtectPath
do
    lldb -s autorun -- "$i"
    mv /tmp/config.txt "$(basename "$i")_config.txt"
    mv /tmp/bss_section_dump.bin "$(basename "$i")_bss_section_dump.bin"
done

rm autorun
