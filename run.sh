
gcc -o test test.c
chmod +x test
g++ -std=c++17 -I../ELFIO split.cpp -o split
./split test output 
python3 split.py output output 
objdump -SRThrtpsz test > test.txt
objdump -SRThrtpsz output > output.txt
readelf -lS test > test2.txt
readelf -lS output > output2.txt