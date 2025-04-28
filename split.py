import lief
import subprocess
import sys

if len(sys.argv) < 3:
    print("Usage: python split.py <binary> <output>")
    print("Please provide the binary to split and an output.")
    exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]
binary = lief.parse(input_file)

def run_command(command):
    """Runs a shell command and returns the output."""
    return subprocess.run(command, shell=True, text=True, capture_output=True).stdout

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
            subsection_addresses.append((symbol.value, symbol.name))
        
    # Sort by address
    subsection_addresses.sort()
    return subsection_addresses


def create_sections(og_section, subsection_addresses):
    base_addr = og_section.virtual_address

    # Create new section for each symbol in the section
    for i, (sub_addr, sub_name) in enumerate(subsection_addresses):
        # Determine new section size for the current symbol
        if i < len(subsection_addresses) - 1:
            next_sub_addr = subsection_addresses[i + 1][0]
            func_size = next_sub_addr - sub_addr
        else:
            func_size = (base_addr + og_section.size) - sub_addr

        # Extract new section bytes
        offset = sub_addr - base_addr
        content = og_section.content[offset:offset + func_size]

        # Create a new section 
        new_section = lief.ELF.Section(f"{og_section.name}.{sub_name}")
        new_section.content = content
        new_section.virtual_address = sub_addr
        new_section.size = len(content)
        new_section.alignment = og_section.alignment
        new_section.flags = og_section.flags
            
        # Add the new section
        binary.add(new_section, loaded=False)  

    # Remove the original section
    binary.remove(og_section)



data_section = get_section(".data")
variable_addresses = extract_symbols(data_section)
create_sections(data_section, variable_addresses)

text_section = get_section(".text")
subsection_addresses = extract_symbols(text_section)
create_sections(text_section, subsection_addresses)

binary.write(output_file)
run_command(f"chmod +x {output_file}")
