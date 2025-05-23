import lief
import subprocess
import sys


if len(sys.argv) < 3:
    print("Usage: python split.py <binary> <output>")
    exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]
test_mode = sys.argv[3] if len(sys.argv) > 3 else None
binary = lief.parse(input_file)


def run_command(command):
    """Runs a shell command and returns the output."""
    return subprocess.run(command, shell=True, text=True, capture_output=True).stdout

def get_section(name):
    """Gets a section by name from the binary."""
    section = binary.get_section(name)
    if not section:
        print(f"No {name} section found!")
        exit(1)
    print(f"Found {section.name} section!")
    return section

def remove_section(name, clear):
    """Removes a section by name from the binary."""
    section = get_section(name)
    binary.remove(section, clear)


if test_mode == "test1":
    # Test 1: Remove unused section, should still be fine
    remove_section(".text.unused", True)
elif test_mode == "test2":
    # Test 2: Remove main, we should now segfault
    remove_section(".text.main", True)


binary.write(output_file)
run_command(f"chmod +x {output_file}")