# ./run_tests.sh libcrypto
# ./run_tests.sh libssl
ld -r -o libcrypto.o libcrypto/*.o
ld -r -o libssl.o libssl/*.o
gcc -shared -fPIC -fno-plt -Wl,-z,now libcrypto.o -o results/libcrypto.so
gcc -shared -fPIC -fno-plt -Wl,-z,now libssl.o -o results/libssl.so
