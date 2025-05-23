
gcc -o test test.c
chmod +x test
g++ -std=c++17 -I../ELFIO split.cpp -o split
./split test output 
# objdump -SRThrtpsz test > test.txt
# objdump -SRThrtpsz output > output.txt