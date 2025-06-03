# Compiler settings
CC = gcc 
CXX = g++
CXXFLAGS = -std=c++17 -Iexternal/ELFIO

# Files
SPLIT_SRC = splitter.cpp
SPLIT_BIN = splitter

# Test Files
TEST_SRC = test.c
TEST_BIN = test
OFILES = $(wildcard *.o)
TXT_FILES := $(filter-out r5emu.txt,$(wildcard *.txt))
OUTPUT_LIST = .outputs
OUTPUT_FILES := $(shell cat $(OUTPUT_LIST) 2>/dev/null)

.PHONY: all run clean dump tests

all: $(TEST_BIN) $(SPLIT_BIN)

# Compile the test file
$(TEST_BIN): $(TEST_SRC)
	$(CC) -o $@ $<

# Compile the splitter
$(SPLIT_BIN): $(SPLIT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Compile the splitter and run it on a given binary
run: $(SPLIT_BIN)
	@if [ -z "$(BIN)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make split BIN=binary OUTPUT=output"; \
		exit 1; \
	fi
	./$(SPLIT_BIN) $(BIN) $(OUTPUT)
	chmod +x $(OUTPUT)
	@echo $(OUTPUT) >> $(OUTPUT_LIST)
	@sort -u $(OUTPUT_LIST) -o $(OUTPUT_LIST)

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
	rm -f $(TEST_BIN) $(SPLIT_BIN) $(TXT_FILES) $(OFILES) $(OUTPUT_FILES) $(OUTPUT_LIST) test0 test1 test2
