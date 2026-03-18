# Minlib Stuff Research

This is some work to try to create more sections in an object file such that each function has its own section.

## Current Status
The splitter currently works with `.data` , `.text`, `.rodata`,  `.data.rel.ro.local`

## Requirements
You'll need to have ELFIO: 

```
git clone https://github.com/SonNguyen415/ELFIO.git external/ELFIO 
```

## Usage

Run `make splitter` to compile the splitter tool.

To build a single object file:
```sh
./run.sh <input.o> <output.o>
```
