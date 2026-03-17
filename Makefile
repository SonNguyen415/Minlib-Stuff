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

.PHONY: all clean object dump

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
	objdump -Shrtpsz $(FILE) > $(FILE:.o=_dump.txt)
	readelf -aW $(FILE) > $(FILE:.o=.txt)

clean:
	rm -f $(TEST_OBJ) $(SPLIT_BIN) $(PARSER_BIN) $(TXT_FILES) $(OFILES) $(OUTPUT_FILES) $(OUTPUT_LIST) $(TESTS)
