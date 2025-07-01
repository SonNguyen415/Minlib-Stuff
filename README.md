# Minlib Stuff Research

This is some work to try to create more sections in a binary such that each function has its own section.

## Current Status
The splitter currently is functional, but there are 2 issues remaining:
1. For some reason, the `.text` section has to be the last section to be split.
2. `.rodata` new sections get moved to a new segment after objcopy removes original section

In addition, the unit tests now rely on using printouts to determine veracity. This is not very nice.

## Requirements
You'll need the modification to ELFIO found here: 

## Usage
To compile the splitter, run:
```sh
make splitter
```

To compile and run the splitter, run the following command, replacing input_binary and output_binary with the file names:
```sh
make run BIN=<input_binary> OUTPUT=<output_binary>
```

The tests use a binary in `test.c`. To run the tests, run `make test OUTPUT=<output_binary>` after you've splitted the binary via `make run` as above.