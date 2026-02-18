OBJ=$1
GCC=gcc
BIN=output
GCCFLAGS="-Wl,--gc-sections -o"

# Compile the test program
$GCC $OBJ $GCCFLAGS $BIN

# Test run
./$BIN 

# Check if unused_fn exists in binary
if nm -C $BIN | grep -q "unused_fn"; then
    echo "[❌] Test 1: unused_fn still exists in the result binary"
else
    echo "[✅] Test 1: unused_fn successfully removed"
fi
