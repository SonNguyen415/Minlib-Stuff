./run.sh

python3 test.py output test0
echo "Test 0: Compare with original"
./test0
echo "----------------------------------"
python3 test.py output test1 test1
echo "Test 1: Reemove unused section"
./test1
echo "----------------------------------"
python3 test.py output test2 test2
echo "Test 2: Remove main (should crash)"
./test2
