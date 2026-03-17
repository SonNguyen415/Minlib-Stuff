#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <test directory>"
    exit 1
fi

DIR="$1"
RESULT_DIR="results"
SECTIONS=(".text" ".data")

rm -rf "$DIR/$RESULT_DIR"
mkdir -p "$DIR/$RESULT_DIR"

make splitter

total=0
success=0
failure=0

for file in $(ls "$DIR"/*.o 2>/dev/null | sort); do
    ((total++))

    filename=$(basename "$file")
    base="$DIR/$RESULT_DIR/${filename%.o}"

    stage1="${base}_1.o"
    stage2="${base}_2.o"
    stage3="${base}_3.o"
    stage4="${base}_4.o"

    input="$file"
    text_split=0
    data_split=0

    # Step 1: splitter for .text and .data
    for section in "${SECTIONS[@]}"; do
        ./splitter "$input" "$stage1" "$section"
        exit_code=$?

        if [[ $exit_code -eq 2 ]]; then
            continue
        elif [[ $exit_code -ne 0 ]]; then
            echo "FAILED at splitter: $file"
            ((failure++))
            echo "------------------------------------------------------------------"
            continue 2
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
        ((success++))
        cp "$file" "$stage4"
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
    input="$stage2"
    tmp="${base}_tmp.o"
    final="$stage3"

    for section in "${SECTIONS[@]}"; do
        if [[ "$section" == ".text" && $text_split -eq 1 ]] || \
        [[ "$section" == ".data" && $data_split -eq 1 ]]; then

            # Determine output file for this pass
            if [[ "$input" == "$stage2" ]]; then
                output="$tmp"   
            else
                output="$final" 
            fi

            if ! python3 update.py "$input" "$output" "$section"; then
                echo "FAILED at python3 update.py ($section): $file"
                ((failure++))
                echo "------------------------------------------------------------------"
                continue 2
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

    if ! objcopy "${objcopy_args[@]}" "$stage3" "$stage4"; then
        echo "FAILED at objcopy: $file"
        ((failure++))
        echo "------------------------------------------------------------------"
        continue
    fi

    # Clean intermediate stages
    rm -f "$stage1" "$stage2" "$stage3" "$tmp"
    ((success++))
done

echo "==================== RESULT ===================="
echo "Total files    : $total"
echo "Total success  : $success"
echo "Total failures : $failure"

# ar x libcrypto.a
# ld -r -o original/libcrypto.o libcrypto/*.o
# ld -r -o libcrypto.o libcrypto/results/*.o
# gcc -shared -fPIC -fno-plt -Wl,-z,now libcrypto.o -o libcrypto.so

# ar x libssl.a
# ld -r -o libssl.o libssl/results/*.o
# ld -r -o original/libssl.o libssl/*.o
# gcc -shared -fPIC -fno-plt -Wl,-z,now libssl.o -o libssl.so