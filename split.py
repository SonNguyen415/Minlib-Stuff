import lief
import os
import subprocess

INPUT = "test"  
OUTPUT = "result"
binary = lief.parse(INPUT)

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
    # Extract all symbols within the section
    subsection_addresses = []
    for symbol in binary.symbols:
        if og_section.virtual_address <= symbol.value < og_section.virtual_address + og_section.size:
            print(symbol.name)
            subsection_addresses.append((symbol.value, symbol.name))
        
    # Sort functions by address
    subsection_addresses.sort()
    return subsection_addresses


def create_sections(og_section, subsection_addresses):
    base_addr = og_section.virtual_address

    # Create sections for each function
    for i, (sub_addr, sub_name) in enumerate(subsection_addresses):
        # Determine function size
        if i < len(subsection_addresses) - 1:
            next_sub_addr = subsection_addresses[i + 1][0]
            func_size = next_sub_addr - sub_addr
        else:
            func_size = (base_addr + og_section.size) - sub_addr  # Last function until .text ends

        # Extract function bytes
        offset = sub_addr - base_addr
        function_bytes = og_section.content[offset:offset + func_size]

        # Create a new section for the function
        new_section = lief.ELF.Section(f"{og_section.name}.{sub_name}")
        new_section.content = function_bytes
        new_section.virtual_address = sub_addr
        new_section.size = len(function_bytes)
        new_section.alignment = og_section.alignment
        new_section.type = og_section.type
        new_section.flags = og_section.flags

        # Add the new section
        binary.add(new_section)

    # Remove the original section
    binary.remove(og_section)

text_section = get_section(".text")
subsection_addresses = extract_symbols(text_section)
create_sections(text_section, subsection_addresses)

# data_section = get_section(".data")
# variable_addresses = extract_symbols(data_section)
# create_sections(data_section, variable_addresses)

binary.write(OUTPUT)
output_result()
