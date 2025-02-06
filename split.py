import lief
import os
import subprocess

INPUT = "test"  
OUTPUT = "result"
binary = lief.parse("test")

def run_command(command):
    """Runs a shell command and returns the output."""
    return subprocess.run(command, shell=True, text=True, capture_output=True).stdout

def output_result():
    run_command(f"readelf -S {INPUT} > {INPUT}.txt")
    run_command(f"readelf -S {OUTPUT} > {OUTPUT}.txt")
    run_command(f"chmod +x {OUTPUT}")


def get_section(name):
    # Find the section
    section = binary.get_section(name)
    if not section:
        print(f"No {name} section found!")
        exit(1)
    return section

def extract_symbols(og_section):
    # Extract function symbols from the symbol table 
    function_addresses = []
    for symbol in binary.symbols:
        if og_section.virtual_address <= symbol.value < og_section.virtual_address + og_section.size:
            function_addresses.append((symbol.value, symbol.name))
        
    # Sort functions by address
    function_addresses.sort()
    return function_addresses


def create_sections(og_section, function_addresses):
    base_addr = og_section.virtual_address

    # Create sections for each function
    for i, (func_addr, func_name) in enumerate(function_addresses):
        # Determine function size
        if i < len(function_addresses) - 1:
            next_func_addr = function_addresses[i + 1][0]
            func_size = next_func_addr - func_addr
        else:
            func_size = (base_addr + og_section.size) - func_addr  # Last function until .text ends

        # Extract function bytes
        offset = func_addr - base_addr
        function_bytes = og_section.content[offset:offset + func_size]

        # Create a new section for the function
        new_section = lief.ELF.Section(f"{og_section.name}.{func_name}")
        new_section.content = function_bytes
        new_section.virtual_address = func_addr
        new_section.size = len(function_bytes)
        new_section.alignment = og_section.alignment
        new_section.type = og_section.type
        new_section.flags = og_section.flags

        # Add the new section
        binary.add(new_section)

    # Remove the original section
    binary.remove(og_section)

text_section = get_section(".text")
function_addresses = extract_symbols(text_section)
create_sections(text_section, function_addresses)

data_section = get_section(".data")
variable_addresses = extract_symbols(data_section)
create_sections(data_section, variable_addresses)

binary.write(OUTPUT)
output_result()
