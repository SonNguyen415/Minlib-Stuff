# Compiler settings
CC = gcc
CXX = g++
CXXFLAGS = -std=c++17 -I../ELFIO

# Files
TEST_SRC = test.c
TEST_BIN = test
SPLIT_SRC = split.cpp
SPLIT_BIN = split
OUTPUT = output
TXT_FILES := $(filter-out r5emu.txt,$(wildcard *.txt))

.PHONY: all run clean test_dump output_dump tests 


run: $(SPLIT_BIN)
	@if [ -z "$(INPUT)" ]; then \
		echo "Error: Please provide INPUT via 'make run INPUT=your_binary'"; \
		exit 1; \
	fi
	@echo "Using input binary: $(INPUT)"
	@./$(SPLIT_BIN) $(INPUT) $(OUTPUT)
	chmod +x $(OUTPUT)

all: $(TEST_BIN) $(SPLIT_BIN) $(OUTPUT)

$(TEST_BIN): $(TEST_SRC)
	$(CC) -o $@ $<
	chmod +x $@

$(SPLIT_BIN): $(SPLIT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(OUTPUT): $(SPLIT_BIN) $(TEST_BIN)
	./$(SPLIT_BIN) $(TEST_BIN) $(OUTPUT)

# Optional objdump dump outputs
test_dump: $(TEST_BIN)
	objdump -SRThrtpsz $(TEST_BIN) > test.txt

output_dump: $(OUTPUT)
	objdump -SRThrtpsz $(OUTPUT) > output.txt

tests: all
	@echo "----------------------------------"
	
	@echo "Running Original: "
	@./test
	@echo "----------------------------------"

	@echo "Running Test 0: Compare with original"
	@python3 test.py $(OUTPUT) test0
	@./test0
	@echo "----------------------------------"

	@echo "Running Test 1: Remove unused section"
	@python3 test.py $(OUTPUT) test1 test1
	@./test1
	@echo "----------------------------------"

	@echo "Running Test 2: Remove main (should crash)"
	@python3 test.py $(OUTPUT) test2 test2
	@./test2

clean:
	rm -f $(TEST_BIN) $(SPLIT_BIN) $(OUTPUT) $(TXT_FILES) test0 test1 test2
