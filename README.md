# Minlib Stuff Research

This is some work to try to create more sections in a binary such that each function has its own section.


## Requirements
You'll need the modification to ELFIO found here: 

## Usage
To compile the splitter, run:
`make splitter`

To compile and run the splitter, run the following command, replacing input_binary and output_binary with the file names:
`make run BIN=<input_binary> OUTPUT=<output_binary>`

The tests use a binary in `test.c`. To run the tests, run `make test OUTPUT=<output_binary>` after you've splitted the binary via `make run` as above.