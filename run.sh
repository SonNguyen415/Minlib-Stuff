#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <file.o> <output.o>"
    exit 1
fi

file="$1"
output="$2"

# Make sure splitter is built
make splitter || { echo "Failed to build splitter"; exit 1; }

base="${file%.o}"   # Remove .o extension
stage1="${base}_1.o"
stage2="${base}_2.o"
stage3="${base}_3.o"

# Step 1: splitter → stage1
./splitter "$file" "$stage1"
exit_code=$?
if [[ $exit_code -eq 2 ]]; then
    echo "Splitter returned 2, skipping file: $file"
    exit 0
elif [[ $exit_code -ne 0 ]]; then
    echo "FAILED at splitter: $file"
    exit 1
fi

# Step 2: python3 reorder.py → stage2
if ! python3 reorder.py "$stage1" "$stage2"; then
    echo "FAILED at python3 reorder.py: $file"
    exit 1
fi

# Step 3: python3 update.py → stage3
if ! python3 update.py "$stage2" "$stage3"; then
    echo "FAILED at python3 update.py: $file"
    exit 1
fi

# Step 4: objcopy → output
if ! objcopy -R .text -R .rela.text -R .eh_frame -R .rela.eh_frame "$stage3" "$output"; then
    echo "FAILED at objcopy: $output"
    exit 1
fi

# Cleanup intermediate files
rm -f "$stage1" "$stage2" "$stage3"

echo "Splitting successful: $output"