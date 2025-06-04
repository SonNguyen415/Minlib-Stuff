#include <iostream>
#include <fstream>
#include <string>
#include <vector>
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

// Function to find the segment containing the target section
segment* 
find_segment(elfio& reader, section* target_section) 
{
    segment* target_segment = nullptr;
    for (int i = 0; i < reader.segments.size(); ++i) {
        segment* seg = reader.segments[i];
        for (int j = 0; j < seg->get_sections_num(); ++j) {
            section* sec = reader.sections[seg->get_section_index_at(j)];
            if (sec == target_section) {
                target_segment = seg;
                break;
            }
        }
        if (target_segment != nullptr) break;
    }
    if (target_segment == nullptr) {
        std::cerr << "No segment containing .text section found.\n";
    }
    return target_segment;
}

// Function to gather symbols from the symbol table
void 
gather_symbols(symbol_section_accessor& symbols, section* sec) 
{
    Elf64_Addr addr = sec->get_address();
    Elf_Xword size = sec->get_size();

    for (Elf_Xword i = 0; i < symbols.get_symbols_num(); ++i) {
        Symbol sym;
        symbols.get_symbol(i, sym.name, sym.value, sym.size, sym.bind, sym.type, sym.section_index, sym.other);

        // Skip empty symbols
        if (sym.name.empty()) {
            continue;
        }

        // Skip symbols that are not in the section
        if (sym.value < addr || sym.value + sym.size > addr + size) {
            continue;
        }
        symbols_list.push_back(sym);
    }
}

// Function to sort symbols by value
void 
sort_symbols_by_value() 
{
    std::sort(symbols_list.begin(), symbols_list.end(), [](const Symbol &a, const Symbol &b) {
        return a.value < b.value;
    });
}

// Function to create new section from symbols
void 
create_sections_from_symbols(elfio& writer, segment* target_segment, section* target_sec, symbol_section_accessor& symbols) 
{
    const char* target_data = target_sec->get_data();
    Elf_Word target_type = target_sec->get_type();
    Elf_Word target_flags = target_sec->get_flags();
    Elf_Word target_align = target_sec->get_addr_align();
    Elf_Xword target_size = target_sec->get_size();
    Elf_Xword target_addr = target_sec->get_address();

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
            // For the last symbol, use the size of the remainder
            size = (target_addr + target_size) - sym.value;
        }

        Elf_Xword offset = sym.value - target_addr;
        std::string fn_code(target_data + offset, size);

        // Create a new section
        std::string new_name = target_sec->get_name() + "." + sym.name;
        section* new_sec = writer.sections.add(new_name);
        new_sec->set_type(target_type);
        new_sec->set_flags(target_flags);
        new_sec->set_addr_align(target_align);
        new_sec->set_data(fn_code);
        new_sec->set_address(sym.value);

        // Add symbol mapping to the section
        Elf_Word name_offset = str_accessor.add_string(sym.name);
        symbols.add_symbol(name_offset, sym.value, sym.size, sym.bind, sym.type, sym.other, new_sec->get_index());

        // Add the new section to the same segment as the original .text section
        target_segment->add_section(new_sec, target_align);
    }
}

int 
split_section(const std::string& input_path, const std::string& output_path, std::string section_name) 
{
    elfio reader;
    if (!reader.load(input_path)) {
        std::cerr << "Failed to load ELF file: " << input_path << "\n";
        return 1;
    }

    // Get all the symbols
    section* symtab_sec = reader.sections[".symtab"];
    if (symtab_sec == nullptr) {
        std::cerr << "No symbol table section found.\n";
        return 1;
    }
    symbol_section_accessor symbols = symbol_section_accessor(reader, symtab_sec);

    // Find the section by name
    section* target_sec = reader.sections[section_name];
    if (target_sec == nullptr) {
        std::cerr << "Section " << section_name << " not found.\n";
        return 1;
    }

    // Find the segment containing the target section
    segment* target_segment = find_segment(reader, target_sec);
    if (target_segment == nullptr) {
        return 1;
    }

    // Gather and sort symbols
    gather_symbols(symbols, target_sec);
    sort_symbols_by_value();

    // Create new sections from symbols
    create_sections_from_symbols(reader, target_segment, target_sec, symbols);

     // Save the modified ELF
    if (!reader.save(output_path)) {
        std::cerr << "Failed to save output ELF to " << output_path << "\n";
        return 1;
    }

    // Remove the original section from the output ELF
    std::string command = "objcopy -R " + section_name + " " + output_path;
    if (std::system(command.c_str()) != 0) {
        std::cerr << "Failed to remove original section " << section_name << " from output ELF.\n";
        return 1;
    }

    // Give final binary executable permissions
    command = "chmod +x " + output_path;
    if (std::system(command.c_str()) != 0) {
        std::cerr << "Failed to set executable permissions on output ELF.\n";
        return 1;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: ./split2 <input_elf> <output_elf>\n";
        return 1;
    }

    std::string input_path = argv[1];
    std::string output_path = argv[2];

    std::vector<std::string> sections_to_split = {".text", ".data"};
    for (const auto& section : sections_to_split) {
        if (split_section(input_path, output_path, section) != 0) {
            std::cerr << "Failed to split " << section << " section.\n";
            return 1;
        }
        symbols_list.clear();  
    }

    std::cout << "Modified ELF written to " << output_path << "\n";
    return 0;
}
