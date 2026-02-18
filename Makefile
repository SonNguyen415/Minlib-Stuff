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
TEST_SRC = test.c
TEST_OBJ = test.o

# Test results
NUMS = $(shell seq 0 9)  
TESTS = $(foreach n, $(NUMS), test$(n))
OFILES = $(wildcard *.o)
TXT_FILES := $(wildcard *.txt) 
OUTPUT_LIST = .outputs
OUTPUT_FILES := $(shell cat $(OUTPUT_LIST) 2>/dev/null)

.PHONY: all run clean dump tests object

all: $(TEST_OBJ) $(SPLIT_BIN)

# Compile the test file
$(TEST_OBJ): $(TEST_SRC)
	$(CC) -O0 -c $< $@ 

# Compile the splitter
$(SPLIT_BIN): $(SPLIT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Compile the splitter
$(PARSER_BIN): $(PARSER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

object:
	$(CC) -c $(TEST_SRC) -o $(TEST_OBJ)

dump:
	@if [ -z "$(BIN)" ]; then \
		echo "Usage: make dump BIN=binary"; \
		exit 1; \
	fi
	objdump -SThrtpsz $(BIN) > $(BIN).txt

# Compile the splitter and run it on a given binary, we'll also keep track of the output files if we need to remove them later
run: $(SPLIT_BIN)
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make run INPUT=<object> OUTPUT=<object>"; \
		exit 1; \
	fi
	@./$(SPLIT_BIN) $(INPUT) $(OUTPUT)
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
	
help: 
	@echo "Makefile Usage:"
	@echo "  make                                    - Compile the test and splitter binaries."
	@echo "  make run INPUT=<object> OUTPUT=<object> - Run the splitter on the specified object and output to the specified file (both obj)."
	@echo "  make dump BIN=<binary>                  - Dump the contents of the specified binary to a text file."
	@echo "  make clean                              - Clean up generated binaries and files."

clean:
	rm -f $(TEST_OBJ) $(SPLIT_BIN) $(PARSER_BIN) $(TXT_FILES) $(OFILES) $(OUTPUT_FILES) $(OUTPUT_LIST) $(TESTS)
