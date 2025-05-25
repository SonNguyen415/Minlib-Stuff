# Compiler settings
CC = gcc -g
CXX = g++
CXXFLAGS = -std=c++17 -Iexternal/ELFIO

# Files
TEST_SRC = test.c
TEST_BIN = test
SPLIT_SRC = split.cpp
SPLIT_BIN = split
OUTPUT = output

OFILES = $(wildcard *.o)
OUTPUT_FILES = $(wildcard output*)
TXT_FILES := $(filter-out r5emu.txt,$(wildcard *.txt))

.PHONY: all run clean test_dump output_dump tests remove

all: $(TEST_BIN) $(SPLIT_BIN) $(OUTPUT)

$(TEST_BIN): $(TEST_SRC)
	$(CC) -o $@ $<
	chmod +x $@

$(SPLIT_BIN): $(SPLIT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(OUTPUT): $(SPLIT_BIN) $(TEST_BIN)
	./$(SPLIT_BIN) $(TEST_BIN) $(OUTPUT)
	chmod +x $(OUTPUT)

dump:
	@if [ -z "$(BIN)" ]; then \
		echo "Usage: make dump BIN=binary"; \
		exit 1; \
	fi
	objdump -SRThrtpsz $(BIN) > $(BIN).txt


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
	rm -f $(TEST_BIN) $(SPLIT_BIN) $(TXT_FILES) $(OUTPUT_FILES) $(OFILES) test0 test1 test2
