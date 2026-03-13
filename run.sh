#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <file.o> <output.o>"
    exit 1
fi


SECTIONS=(".text" ".data")

file="$1"
output="$2"

# Make sure splitter is built
make splitter || { echo "Failed to build splitter"; exit 1; }

base="${file%.o}"   # Remove .o extension
stage1="${base}_1.o"
stage2="${base}_2.o"
stage3="${base}_3.o"

text_split=0
data_split=0
input="$file"
# Step 1: splitter → stage1
for section in "${SECTIONS[@]}"; do
    ./splitter "$input" "$stage1" "$section"
    exit_code=$?

    if [[ $exit_code -eq 2 ]]; then
        continue
    elif [[ $exit_code -ne 0 ]]; then
        echo "FAILED at splitter: $file"
        exit 1
    fi

    input="$stage1"

    if [[ "$section" == ".text" ]]; then
        text_split=1
    else
        data_split=1
    fi
done

# Skip remaining steps if no split was needed
if [[ $text_split -eq 0 && $data_split -eq 0 ]]; then
    echo "No splitting needed: $file"
    cp "$file" "$stage4"
    exit 0
fi


# Step 2: python3 reorder.py → stage2
if ! python3 reorder.py "$stage1" "$stage2"; then
    echo "FAILED at python3 reorder.py: $file"
    exit 1
fi

# Step 3: python3 update.py → stage3
input="$stage2"
tmp="${base}_tmp.o"
final="$stage3"

for section in "${SECTIONS[@]}"; do
    if [[ "$section" == ".text" && $text_split -eq 1 ]] || \
       [[ "$section" == ".data" && $data_split -eq 1 ]]; then

        # Determine output file for this pass
        if [[ "$input" == "$stage2" ]]; then
            output="$tmp"   # first section
        else
            output="$final" # second section (or single)
        fi

        if ! python3 update.py "$input" "$output" "$section"; then
            echo "FAILED at python3 update.py ($section): $file"
            exit 1
        fi

        # next input is previous output
        input="$output"
    fi
done

# Ensure final result is in stage3
if [[ "$input" != "$stage3" ]]; then
    mv "$input" "$stage3"
fi

# Step 4: objcopy → stage4
objcopy_args=()
[[ $text_split -eq 1 ]] && objcopy_args+=(-R .text -R .rela.text)
[[ $data_split -eq 1 ]] && objcopy_args+=(-R .data -R .rela.data)
objcopy_args+=(-R .eh_frame -R .rela.eh_frame)

if ! objcopy "${objcopy_args[@]}" "$stage3" "$output"; then
    echo "FAILED at objcopy: $file"
    exit 1
fi

# Cleanup intermediate files
rm -f "$stage1" "$stage2" "$stage3" "$tmp"

echo "Splitting successful: $output"