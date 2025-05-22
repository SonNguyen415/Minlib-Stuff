#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <elfio/elfio.hpp>
#include <cstdio>

using namespace ELFIO;

// Struct to hold symbol data
struct Symbol {
    std::string name;
    Elf64_Addr value;
    Elf_Xword size;
    unsigned char bind, type;
    Elf_Half section_index;
    unsigned char other;
};

std::vector<Symbol> symbols_list;

// Function to load ELF file
bool load_elf_file(const std::string& input_path, elfio& reader) {
    if (!reader.load(input_path)) {
        std::cerr << "Failed to load ELF file: " << input_path << "\n";
        return false;
    }
    return true;
}

// Function to find the .text section
section* find_text_section(elfio& reader) {
    section* text_sec = reader.sections[".text"];
    if (text_sec == nullptr) {
        std::cerr << "No .text section found.\n";
    }
    return text_sec;
}

// Function to find the symbol table
symbol_section_accessor find_symbol_table(elfio& reader, section* symtab_sec) {
    if (symtab_sec == nullptr) {
        std::cerr << "No .symtab section found.\n";
    }
    return symbol_section_accessor(reader, symtab_sec);
}

// Function to find the segment containing the .text section
segment* find_text_segment(elfio& reader, section* text_sec) {
    segment* text_segment = nullptr;
    for (int i = 0; i < reader.segments.size(); ++i) {
        segment* seg = reader.segments[i];
        for (int j = 0; j < seg->get_sections_num(); ++j) {
            section* sec = reader.sections[seg->get_section_index_at(j)];
            if (sec == text_sec) {
                text_segment = seg;
                break;
            }
        }
        if (text_segment != nullptr) break;
    }
    if (text_segment == nullptr) {
        std::cerr << "No segment containing .text section found.\n";
    }
    return text_segment;
}

// Function to gather symbols from the symbol table
void gather_symbols(symbol_section_accessor& symbols, section* text_sec) {
    Elf64_Addr text_addr = text_sec->get_address();
    Elf_Xword text_size = text_sec->get_size();

    for (Elf_Xword i = 0; i < symbols.get_symbols_num(); ++i) {
        Symbol sym;
        symbols.get_symbol(i, sym.name, sym.value, sym.size, sym.bind, sym.type, sym.section_index, sym.other);

        // Skip non-function symbols or empty symbols
        if (sym.type != STT_FUNC || sym.name.empty()) {
            continue;
        }

        // Skip symbols that are not in the .text section
        if (sym.value < text_addr || sym.value + sym.size > text_addr + text_size) {
            continue;
        }

        symbols_list.push_back(sym);
    }
}

// Function to sort symbols by value
void sort_symbols_by_value() {
    std::sort(symbols_list.begin(), symbols_list.end(), [](const Symbol &a, const Symbol &b) {
        return a.value < b.value;
    });
}

// Function to create new section from symbols
void create_sections_from_symbols(elfio& writer, segment* text_segment, section* text_sec) {
    const char* text_data = text_sec->get_data();
    Elf_Word text_type = text_sec->get_type();
    Elf_Word text_flags = text_sec->get_flags();
    Elf_Word text_align = text_sec->get_addr_align();
    Elf_Xword text_size = text_sec->get_size();
    Elf_Xword text_addr = text_sec->get_address();

    for (Elf_Xword i = 0; i < symbols_list.size(); ++i) {
        const Symbol& sym = symbols_list[i];

        Elf_Xword size = 0;
        if (i < symbols_list.size() - 1) {
            // Calculate size by the difference in value between consecutive symbols
            size = symbols_list[i + 1].value - sym.value;
        } else {
            // For the last symbol, use the size of the remaining .text section
            size = (text_addr + text_size) - sym.value;
        }

        // Ensure size is greater than 0
        if (size == 0) {
            continue; // Skip if the size is still 0 after calculation
        }

        Elf_Xword offset = sym.value - text_addr;
        std::string fn_code(text_data + offset, size);

        // Create a new section
        std::string new_name = ".text." + sym.name;
        section* new_sec = writer.sections.add(new_name);
        new_sec->set_type(text_type);
        new_sec->set_flags(text_flags);
        new_sec->set_addr_align(text_align);
        new_sec->set_data(fn_code);
        new_sec->set_address(sym.value);

        // Add the new section to the same segment as the original .text section
        text_segment->add_section(new_sec, text_align);
        std::cout << "Created section: " << new_name << " @ 0x" << std::hex << sym.value << " (" << size << " bytes)\n";
    }
}

// Function to save the modified ELF
bool save_elf_file(elfio& writer, const std::string& output_path) {
    if (!writer.save(output_path)) {
        std::cerr << "Failed to save output ELF to " << output_path << "\n";
        return false;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: ./split2 <input_elf> <output_elf>\n";
        return 1;
    }

    std::string input_path = argv[1];
    std::string output_path = argv[2];

    elfio reader;
    if (!load_elf_file(input_path, reader)) {
        return 1;
    }

    // Find .text section and symbol table
    section* text_sec = find_text_section(reader);
    if (text_sec == nullptr) {
        return 1;
    }

    section* symtab_sec = reader.sections[".symtab"];
    symbol_section_accessor symbols = find_symbol_table(reader, symtab_sec);

    // Find the segment containing the .text section
    segment* text_segment = find_text_segment(reader, text_sec);
    if (text_segment == nullptr) {
        return 1;
    }

    // Gather and sort symbols
    gather_symbols(symbols, text_sec);
    sort_symbols_by_value();

    // Create new sections from symbols
    create_sections_from_symbols(reader, text_segment, text_sec);

    // Save the modified ELF
    if (!save_elf_file(reader, output_path)) {
        return 1;
    }

    std::cout << "Modified ELF written to " << output_path << "\n";
    return 0;
}
