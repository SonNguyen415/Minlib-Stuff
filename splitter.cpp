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
void create_sections_from_symbols(elfio& writer, segment* text_segment, section* text_sec, symbol_section_accessor& symbols) {
    const char* text_data = text_sec->get_data();
    Elf_Word text_type = text_sec->get_type();
    Elf_Word text_flags = text_sec->get_flags();
    Elf_Word text_align = text_sec->get_addr_align();
    Elf_Xword text_size = text_sec->get_size();
    Elf_Xword text_addr = text_sec->get_address();

    // Find the symbol table section
    section* symtab = writer.sections[".symtab"];
    ELFIO::string_section_accessor str_accessor(writer.sections[symtab->get_link()]);

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

        // Add symbol mapping to the section
        Elf_Word name_offset = str_accessor.add_string(sym.name);
        symbols.add_symbol(name_offset, sym.value, sym.size, sym.bind, sym.type, sym.other, new_sec->get_index());

        // Add the new section to the same segment as the original .text section
        text_segment->add_section(new_sec, text_align);
    }
}


int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: ./split2 <input_elf> <output_elf>\n";
        return 1;
    }

    std::string input_path = argv[1];
    std::string output_path = argv[2];

    elfio reader;
    if (!reader.load(input_path)) {
        std::cerr << "Failed to load ELF file: " << input_path << "\n";
        return 1;
    }
    printf("Finished loading\n");

    // Find .text section and symbol table
    section* text_sec = reader.sections[".text"];
    if (text_sec == nullptr) {
        return 1;
    }

    printf("Found text section\n");
    // Find the segment containing the .text section
    segment* text_segment = find_text_segment(reader, text_sec);
    if (text_segment == nullptr) {
        return 1;
    }

    printf("Found text segment\n");
    section* symtab_sec = reader.sections[".symtab"];
    if (symtab_sec == nullptr) {
        std::cerr << "No symbol table section found.\n";
        return 1;
    }
    symbol_section_accessor symbols = symbol_section_accessor(reader, symtab_sec);

    printf("Found symbol section\n");

    // Gather and sort symbols
    gather_symbols(symbols, text_sec);
    sort_symbols_by_value();

    // Create new sections from symbols
    create_sections_from_symbols(reader, text_segment, text_sec, symbols);

    printf("Saving modified ELF to %s\n", output_path.c_str());
    // Save the modified ELF
    if (!reader.save(output_path)) {
        std::cerr << "Failed to save output ELF to " << output_path << "\n";
        return 1;
    }

    std::cout << "Modified ELF written to " << output_path << "\n";
    return 0;
}
