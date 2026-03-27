#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <elfio/elfio.hpp>
#include <cstdio>
#include <unordered_map>
#include <algorithm>

using namespace ELFIO;

// Struct to hold symbol data
struct Symbol {
    std::string name;
    Elf64_Addr value;
    Elf_Xword size;
    unsigned char bind, type;
    Elf_Half section_index;
    unsigned char other;
    Elf_Word idx;
};


struct RelocEntry {
    Elf_Xword index;
    Elf64_Addr offset;
    Elf_Word symbol;
    unsigned type;
    Elf_Sxword addend;
};

std::vector<Symbol> symbols_list;
std::unordered_map<Elf_Word, std::tuple<Elf_Word, Elf_Word>> symbol_mapping; // old sym idx -> new sym idx

// Function to gather symbols from the symbol table
void 
gather_symbols(symbol_section_accessor& symbols, section* sec) 
{

    Elf_Half section_index = sec->get_index();
    for (Elf_Xword i = 0; i < symbols.get_symbols_num(); ++i) {
        Symbol sym;
        symbols.get_symbol(i, sym.name, sym.value, sym.size, sym.bind, sym.type, sym.section_index, sym.other);
        sym.idx = i;

        // Skip empty symbols or symbols not in the target section
        if (sym.name.empty() || sym.section_index != section_index || sym.type == STT_SECTION) {
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

// Create new relocation sections for each new section
void 
create_relo(elfio& writer, section* original_sec, section* new_sec, Elf64_Addr sym_offset)
{
    // Create new relocation section
    for (int i = 0; i < writer.sections.size(); ++i) {
        section* sec = writer.sections[i];
        // Look for the relocation section that corresponds to the original section
        if ((sec->get_type() == SHT_RELA || sec->get_type() == SHT_REL) && sec->get_info() == original_sec->get_index()) {
            // Create a new relocation section for new_sec
            section * rel_sec = writer.sections.add(".rela" + new_sec->get_name());
            rel_sec->set_type(sec->get_type());
            rel_sec->set_info(new_sec->get_index());
            rel_sec->set_addr_align(new_sec->get_addr_align());
            rel_sec->set_entry_size(sec->get_entry_size());
            rel_sec->set_link(writer.sections[".symtab"]->get_index());

            // Create reloc table writer and write entries
            relocation_section_accessor rel_writer(writer, rel_sec);

            // Get the reloc entry of the original section that corresponds to the new section
            relocation_section_accessor rel_accessor(writer, sec);
            RelocEntry original_reloc_entry;

            // For each entry in the original relocation section, check if it applies to the new section and if so, add a corresponding entry to the new relocation section
            for (Elf_Xword j = 0; j < rel_accessor.get_entries_num(); ++j) {
                rel_accessor.get_entry(j, original_reloc_entry.offset, original_reloc_entry.symbol, original_reloc_entry.type, original_reloc_entry.addend);
                
                // Check if the relocation entry applies to the new section (i.e., if its offset falls within the symbol's range in the original section)
                if (original_reloc_entry.offset >= sym_offset && original_reloc_entry.offset < sym_offset + new_sec->get_size()) {
                    Elf64_Addr new_offset = original_reloc_entry.offset - sym_offset; // Adjust offset for the new section
                    Elf_Word reloc_symbol_idx = original_reloc_entry.symbol;
                    if (symbol_mapping.find(reloc_symbol_idx) != symbol_mapping.end()) {
                        auto& sym_idx = symbol_mapping[reloc_symbol_idx];
                        reloc_symbol_idx = std::get<0>(sym_idx);
                        if (original_reloc_entry.type == R_X86_64_PC32) {
                            reloc_symbol_idx = std::get<1>(sym_idx);
                        } 
                    }
                    rel_writer.add_entry(new_offset, reloc_symbol_idx, original_reloc_entry.type, original_reloc_entry.addend);
                }
            }
        }
    }
}

// Return the STT_SECTION symbol for a given section name
Symbol 
get_section_symbol_by_name(symbol_section_accessor& symbols, const elfio& reader, const std::string& sec_name) 
{
    Symbol sec_sym;
    sec_sym.idx = (Elf_Word)-1;  // default to "not found"

    for (Elf_Xword i = 0; i < symbols.get_symbols_num(); ++i) {
        std::string name;
        Elf64_Addr value;
        Elf_Xword size;
        unsigned char bind, type;
        Elf_Half section_index;
        unsigned char other;

        symbols.get_symbol(i, name, value, size, bind, type, section_index, other);

        if (type == STT_SECTION && section_index < reader.sections.size()) {
            if (reader.sections[section_index]->get_name() == sec_name) {
                // fill the Symbol struct
                sec_sym.name = name;
                sec_sym.value = value;
                sec_sym.size = size;
                sec_sym.bind = bind;
                sec_sym.type = type;
                sec_sym.section_index = section_index;
                sec_sym.other = other;
                sec_sym.idx = i;
                return sec_sym;
            }
        }
    }

    return sec_sym; // idx == -1 means not found
}


// Function to create new section from symbols
void 
create_sections_from_symbols(elfio& writer, section* original_sec, symbol_section_accessor& symbols, bool is_bss) 
{
    std::ofstream out("new_sections.txt", std::ios::app);
    const char* target_data = original_sec->get_data();
    Elf_Word target_type = original_sec->get_type();
    Elf_Word target_flags = original_sec->get_flags();
    Elf_Word target_align = original_sec->get_addr_align();
    Elf_Xword target_size = original_sec->get_size();
    Elf_Xword target_addr = original_sec->get_address();
    Elf64_Off target_offset = original_sec->get_offset();

    // Find the symbol table section
    section* symtab = writer.sections[".symtab"];
    string_section_accessor str_accessor(writer.sections[symtab->get_link()]);

    // Original STT_SECTION symbol for the section being split
    Symbol og_sec_sym = get_section_symbol_by_name(symbols, writer, original_sec->get_name());
    if (og_sec_sym.idx == (Elf_Word)-1) {
        // No original section, create an empty section to hold the symbol
        Elf_Word og_name_offset = str_accessor.add_string(original_sec->get_name());
        symbols.add_symbol(og_name_offset, 0, 0, STB_LOCAL, STT_SECTION, 0, original_sec->get_index());
    }
    og_sec_sym = get_section_symbol_by_name(symbols, writer, original_sec->get_name());

    // Create a new section for each symbol
    for (Elf_Xword i = 0; i < symbols_list.size(); ++i) {  
        const Symbol& sym = symbols_list[i];
        Elf64_Addr sym_offset = sym.value; // Offset of the symbol relative to the section's address
        Elf_Sxword size = sym.size;
        if (i < symbols_list.size()-1) {;
            size = symbols_list[i+1].value - sym_offset;
        } else {
            size = original_sec->get_size() - sym_offset;
        }
    
        // Create a new section
        std::string new_name = original_sec->get_name() + "." + sym.name;
        section* new_sec = writer.sections.add(new_name);
        if (new_sec == nullptr) {
            std::cerr << "Failed to create new section for symbol: " << sym.name << "\n";
            continue;
        }
      
        if (!is_bss) {
            std::string symbol_data(target_data + sym_offset, size);  
            new_sec->set_data(symbol_data); 
        }

        new_sec->set_type(target_type);
        new_sec->set_flags(target_flags);
        new_sec->set_addr_align(target_align);
        new_sec->set_address(0);

        // Add symbol mapping to the symbol table
        Elf_Word name_offset = str_accessor.add_string(sym.name);
        Elf_Word sec_sym_idx = symbols.add_symbol(name_offset, 0, 0, og_sec_sym.bind, STT_SECTION, sym.other, new_sec->get_index());
        Elf_Word new_sym_idx = symbols.add_symbol(name_offset, 0, sym.size, sym.bind, sym.type, sym.other, new_sec->get_index());


        symbol_mapping[sym.idx] = std::make_tuple(new_sym_idx, sec_sym_idx);
        create_relo(writer, original_sec, new_sec, sym_offset);
        out << original_sec->get_name() << " " << new_sec->get_index() << "\n";

    }
    out.close();
}

int 
split_section(elfio& reader, const std::string& input_path, const std::string& output_path, std::string section_name) 
{
    // Find the section by name
    section* original_sec = reader.sections[section_name];
    if (original_sec == nullptr) {
        return 2;
    }
    // If the section size is 0, just return
    if (original_sec->get_size() == 0) {
        return 2;
    }

    // Get all the symbols
    section* symtab_sec = reader.sections[".symtab"];
    if (symtab_sec == nullptr) {
        std::cerr << "No symbol table section found.\n";
        return 1;
    }
    symbol_section_accessor symbols = symbol_section_accessor(reader, symtab_sec);

    // Gather and sort symbols
    gather_symbols(symbols, original_sec);
    sort_symbols_by_value();

    if (symbols_list.empty() || (symbols_list.size() == 1 && symbols_list[0].type == STT_SECTION)) {
        return 2;
    }
    
    bool is_bss = section_name == ".bss";

    // Create new sections from symbols
    create_sections_from_symbols(reader, original_sec, symbols, is_bss);

    // Save the modified ELF
    if (!reader.save(output_path)) {
        std::cerr << "Failed to save output ELF to " << output_path << "\n";
        return 1;
    }
    return 0;
}

int 
main(int argc, char** argv) 
{
    if (argc < 3) {
        std::cerr << "Usage: ./splitter <input_elf> <output_elf> <section>\n";
        return 1;
    }

    std::string input_path = argv[1];
    std::string output_path = argv[2];
    std::string section_name = argv[3];

    elfio reader;
    if (!reader.load(input_path)) {
        std::cerr << "Failed to load ELF file: " << input_path << "\n";
        return 1;
    }

    // Create a list of all sections that start with <section_name>
    std::vector<std::string> sections_to_split = {section_name};
    for (Elf_Half i = 0; i < reader.sections.size(); ++i) {
        if (reader.sections[i]->get_name().find(section_name + ".") == 0) {
            sections_to_split.push_back(reader.sections[i]->get_name());
        }
    }

    int ret;
    ret = split_section(reader, input_path, output_path, section_name);
    if (ret == 1) {
        std::cerr << "Failed to split " << section_name << " section\n";
    } 
    return ret;
}
