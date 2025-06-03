#!/bin/bash
# This script scans all files in /sbin and runs objdump -t on each executable file.
# This is meant to check if the files are stripped or not, and to filter out files that do not contain symbols.

# Directory to scan
BIN_DIR="."

# Loop through all files in /usr/bin
for file in "$BIN_DIR"/*; do

    echo -ne "\r$file                   "
    
    # Skip if not a regular file or not executable
    [ -f "$file" ] || continue
    [ -x "$file" ] || continue

    # Run objdump -t and capture both stdout and stderr
    output=$(objdump -t "$file" 2>&1)

    # Check if output contains error or 'no symbols'
    if echo "$output" | grep -q -i -e 'no symbols' -e 'file format not recognized' -e 'objdump:'; then
        continue
    fi

    # If passed the checks, print the filename
    echo "Success: $file"
done
echo ""
