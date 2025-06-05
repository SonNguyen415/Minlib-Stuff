# Compiler settings
CC = gcc 
CXX = g++
CXXFLAGS = -std=c++17 -Iexternal/ELFIO

# Files
SPLIT_SRC = splitter.cpp
SPLIT_BIN = splitter
PARSER_SRC = parser.cpp
PARSER_BIN = parser

# Test Files
TESTER = test.py
TEST_SRC = test.c
TEST_BIN = test
# Test results
NUMS = $(shell seq 0 9)  
TESTS = $(foreach n, $(NUMS), test$(n))
OFILES = $(wildcard *.o)
TXT_FILES := $(wildcard *.txt) 
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


# Compile the splitter
$(PARSER_BIN): $(PARSER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

dump:
	@if [ -z "$(BIN)" ]; then \
		echo "Usage: make dump BIN=binary"; \
		exit 1; \
	fi
	objdump -SRThrtpsz $(BIN) > $(BIN).txt

# Compile the splitter and run it on a given binary, we'll also keep track of the output files if we need to remove them later
run: $(SPLIT_BIN)
	@if [ -z "$(BIN)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make run BIN=binary OUTPUT=output"; \
		exit 1; \
	fi
	@./$(SPLIT_BIN) $(BIN) $(OUTPUT)
	@echo $(OUTPUT) >> $(OUTPUT_LIST)
	@sort -u $(OUTPUT_LIST) -o $(OUTPUT_LIST)

tests: 
	@if [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make tests OUTPUT=output. Might need to do make run first."; \
		exit 1; \
	fi

	@echo "----------------------------------"

	@echo "Running Original: "
	@./test
	@echo "----------------------------------"

	@echo "Running Test 0: Compare with original"
	@objcopy $(OUTPUT) test0
	@./test0
	@echo "----------------------------------"

	@echo "Running Test 1: Remove unused function"
	@objcopy -R .text.unused_fn $(OUTPUT) test1
	@./test1
	@echo "----------------------------------"

	@echo "Running Test 2: Remove main (should crash)"
	@objcopy -R .text.main $(OUTPUT) test2
	-@./test2
	@echo "----------------------------------"

	@echo "Running Test 3: Remove unused unintialized variable"
	@objcopy -R .bss.bss_unused $(OUTPUT) test3
	@./test3
	@echo "----------------------------------"

	@echo "Running Test 4: Remove used bss"
	@objcopy -R .bss.bss_var $(OUTPUT) test4
	@./test4
	@echo "----------------------------------"

	@echo "Running Test 5: Remove unused variable section"
	@objcopy -R .data.unused_var $(OUTPUT) test5
	@./test5
	@echo "----------------------------------"

	@echo "Running Test 6: Remove used variable (shouldn't crash but var becomes junk)"
	@objcopy -R .data.used_var $(OUTPUT) test6
	-@./test6
	@echo "----------------------------------"
	

clean:
	rm -f $(TEST_BIN) $(SPLIT_BIN) $(PARSER_BIN) $(TXT_FILES) $(OFILES) $(OUTPUT_FILES) $(OUTPUT_LIST) $(TESTS)
