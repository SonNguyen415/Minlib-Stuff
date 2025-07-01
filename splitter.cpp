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


section * 
find_next_section(elfio& reader, section* target_section) 
{
    /* 
     * We can't rely on section indices being in order, so we need to find the next section
     * via the addresses. We'll find the section that has the lowest address greater than
     * the target section's address.
     */
    Elf64_Addr target_addr = target_section->get_address();
    Elf64_Addr min_addr = UINT64_MAX;
    section* next_section = nullptr;
    for (int i = 0; i < reader.sections.size(); ++i) {
        section* sec = reader.sections[i];
        if (sec == target_section) continue; // Skip the target section
        Elf64_Addr sec_addr = sec->get_address();
        if (sec_addr > target_addr && sec_addr < min_addr) {
            min_addr = sec_addr;
            next_section = sec;
        }
    }

    return next_section; 
}

// Function to gather symbols from the symbol table
void 
gather_symbols(symbol_section_accessor& symbols, section* sec) 
{

    Elf_Half section_index = sec->get_index();
    for (Elf_Xword i = 0; i < symbols.get_symbols_num(); ++i) {
        Symbol sym;
        symbols.get_symbol(i, sym.name, sym.value, sym.size, sym.bind, sym.type, sym.section_index, sym.other);

        // Skip empty symbols or symbols not in the target section
        if (sym.name.empty() || sym.section_index != section_index) {
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

void
print_sections_by_segment(elfio& writer)
{
    std::cout << "Displaying sections by segment:\n";
    for (int i = 0; i < writer.segments.size(); ++i) {
        segment* seg = writer.segments[i];
        std::cout << "\tSegment:";
        for (int j = 0; j < seg->get_sections_num(); ++j) {
            section* sec = writer.sections[seg->get_section_index_at(j)];
            std::cout << " " << sec->get_name();
        }
        std::cout << "\n";
    }
    std::cout << "--------------------------------\n";
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

    // Find where the target section is in the segment
    Elf_Half target_pos = 0;
    for (Elf_Half i = 0; i < target_segment->get_sections_num(); ++i) {
        section* sec = writer.sections[target_segment->get_section_index_at(i)];
        if (sec == target_sec) {
            target_pos = i;
            break;
        }
    }

    // Find the symbol table section
    section* symtab = writer.sections[".symtab"];
    ELFIO::string_section_accessor str_accessor(writer.sections[symtab->get_link()]);

    // Find the next section after the target section
    section* next_sec = find_next_section(writer, target_sec);

    // Create a new section for each symbol
    for (Elf_Xword i = 0; i < symbols_list.size(); ++i) {
        const Symbol& sym = symbols_list[i];
        Elf_Sxword size = sym.size;
        Elf64_Addr addr = sym.value;

        // Calculate size by the difference in value between consecutive symbols
        // We use the next symbol's value only if it's within original section's address space
        if (i < symbols_list.size() - 1 && symbols_list[i + 1].value <= target_addr + target_size) {
            size = symbols_list[i + 1].value - addr;
        } else if (next_sec) {
            size = next_sec->get_address() - addr;
        } else {
            size = target_addr + target_size - addr;
        }
        
        // For .bss section, set size to 0
        if (target_sec->get_name() == ".bss") {
            size = 0;
        }

        // Edge case: Some symbols (TMC_END) can exist outside the original section's address space
        // We will give them a section at the end of the original section 
        if (size < 0) {
            size = 0;
            addr = target_addr + target_size;
        }

        // Get symbol data 
        Elf_Xword offset = addr - target_addr;
        std::string symbol_data(target_data + offset, size);

        // Create a new section
        std::string new_name = target_sec->get_name() + "." + sym.name;
        section* new_sec = writer.sections.add(new_name);
        new_sec->set_type(target_type);
        new_sec->set_flags(target_flags);
        new_sec->set_addr_align(target_align);
        new_sec->set_address(addr);
        new_sec->set_data(symbol_data); 

        // Add symbol mapping to the section
        Elf_Word name_offset = str_accessor.add_string(sym.name);
        symbols.add_symbol(name_offset, sym.value, sym.size, sym.bind, sym.type, sym.other, new_sec->get_index());

        // Add the new section to the same segment as the original .text section
        // adjust_section_indices(writer, new_sec->get_index()); // Adjust indices to avoid conflicts
        target_segment->insert_section(new_sec, target_align, target_pos + i + 1);

        // Mark section as split
        target_sec->is_split = true;
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
        std::cerr << "Usage: ./splitter <input_elf> <output_elf>\n";
        return 1;
    }

    std::string input_path = argv[1];
    std::string output_path = argv[2];
    
    // FIXME: .text have to split last rn for some weird reason
    // FIXME: .rodata new sections get moved to a new segment after objcopy removes original section
    std::vector<std::string> sections_to_split = {".rodata", ".data", ".bss", ".text"};
    for (const auto& section : sections_to_split) {
        if (split_section(input_path, output_path, section) != 0) {
            std::cerr << "Failed to split " << section << " section\n";
            return 1;
        }
        input_path = output_path;  // Update input path for the next section
        symbols_list.clear();  
    }

    std::cout << "Modified ELF written to " << output_path << "\n";
    return 0;
}
