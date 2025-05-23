import lief
import subprocess
import sys


def run_command(command):
    """Runs a shell command and returns the output."""
    return subprocess.run(command, shell=True, text=True, capture_output=True).stdout

def remove_section(binary, name, clear):
    # Find the section
    section = binary.get_section(name)
    if not section:
        print(f"No {name} section found!")
        exit(1)
    binary.remove(section, clear)


if len(sys.argv) < 3:
    print("Usage: python split.py <binary> <output>")
    print("Please provide the binary to split and an output.")
    exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]
binary = lief.parse(input_file)


remove_section(binary, ".text", True)

binary.write(output_file)
run_command(f"chmod +x {output_file}")