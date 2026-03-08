#!/bin/bash

# ar x libssl.a

DIR="libssl"

make splitter

total=0
success=0
failure=0


for file in $(ls "$DIR"/*.o 2>/dev/null | sort); do
    ((total++))

    base="${file%.o}"   # Remove .o extension
    stage1="${base}1.o"
    stage2="${base}2.o"
    stage3="${base}3.o"
    stage4="${base}4.o"

    # Step 1: splitter → stage1
    if ! ./splitter "$file" "$stage1"; then
        echo "FAILED at splitter: $file"
        ((failure++))
        echo "------------------------------------------------------------------"
        continue
    fi

    # Step 2: python3 reorder.py → stage2
    if ! python3 reorder.py "$stage1" "$stage2"; then
        echo "FAILED at python3 reorder.py: $file"
        ((failure++))
        echo "------------------------------------------------------------------"
        continue
    fi

    # Step 3: python3 update.py → stage3
    if ! python3 update.py "$stage2" "$stage3"; then
        echo "FAILED at python3 update.py: $file"
        ((failure++))
        echo "------------------------------------------------------------------"
        continue
    fi

    # Step 4: objcopy → stage4
    if ! objcopy -R .text -R .rela.text -R .eh_frame -R .rela.eh_frame "$stage3" "$stage4"; then
        echo "FAILED at objcopy: $file"
        ((failure++))
        echo "------------------------------------------------------------------"
        continue
    fi

    rm -f "$stage1" "$stage2" "$stage3"
    ((success++))
done

echo "==================== RESULT ===================="
echo "Total files    : $total"
echo "Total success  : $success"
echo "Total failures : $failure"