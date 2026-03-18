#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <file.o> <output.o>"
    exit 1
fi


SECTIONS=(".text" ".data" ".rodata" ".data.rel.ro.local")

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
rodata_split=0
rodata_rel_ro_local_split=0
input="$file"
section_idx="new_sections.txt"
rm -f $section_idx 

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
    elif [[ "$section" == ".data" ]]; then
        data_split=1
    elif [[ "$section" == ".rodata" ]]; then
        rodata_split=1
    elif [[ "$section" == ".data.rel.ro.local" ]]; then
        data_rel_ro_local_split=1
    fi
done


echo "Text split: $text_split, Data split: $data_split, Rodata split: $rodata_split, Data.rel.ro.local split: $data_rel_ro_local_split"

# Skip remaining steps if no split was needed
if [[ $text_split -eq 0 && $data_split -eq 0 && $rodata_split -eq 0 && $data_rel_ro_local_split -eq 0 ]]; then
    cp "$file" "$stage4"
    exit 0
fi


# Step 2: python3 reorder.py → stage2
if ! python3 reorder.py "$stage1" "$stage2"; then
    echo "FAILED at python3 reorder.py: $file"
    exit 1
fi

# Step 3: python3 update.py → stage3
input3="$stage2"

for section in "${SECTIONS[@]}"; do
    if [[ "$section" == ".text" && $text_split -eq 1 ]] then
        output3="${base}_3_text.o"   
    elif [[ "$section" == ".data" && $data_split -eq 1 ]]; then
        output3="${base}_3_data.o"   
    elif [[ "$section" == ".rodata" && $rodata_split -eq 1 ]]; then
        output3="${base}_3_rodata.o"   
    elif [[ "$section" == ".data.rel.ro.local" && $data_rel_ro_local_split -eq 1 ]]; then
        output3="${base}_3_data.rel.ro.local.o"
    else
        continue
    fi

    if ! python3 update.py "$input3" "$output3" "$section"; then
        echo "FAILED at python3 update.py ($section): $file"
        exit 1
    fi
    input3="$output3"
done

# Ensure final result is in stage3
if [[ "$input3" != "$stage3" ]]; then
    mv "$input3" "$stage3"
fi

echo "Objcopy file: $stage3"
# Step 4: objcopy → stage4
objcopy_args=()
[[ $text_split -eq 1 ]] && objcopy_args+=(-R .text -R .rela.text)
[[ $data_split -eq 1 ]] && objcopy_args+=(-R .data -R .rela.data)
[[ $rodata_split -eq 1 ]] && objcopy_args+=(-R .rodata -R .rela.rodata)
[[ $data_rel_ro_local_split -eq 1 ]] && objcopy_args+=(-R .data.rel.ro.local -R .rela.data.rel.ro.local)
objcopy_args+=(-R .eh_frame -R .rela.eh_frame)

if ! objcopy "${objcopy_args[@]}" "$stage3" "$output"; then
    echo "FAILED at objcopy: $file"
    exit 1
fi

# Cleanup intermediate files 
rm -f "$stage1" "$stage2" "$stage3" "$section_idx"
 
echo "Splitting successful: $output"