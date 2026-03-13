#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <elfio/elfio.hpp>
#include <cstdio>
#include <unordered_map>

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
std::unordered_map<Elf_Word, Elf_Word> symbol_mapping; // old sym idx -> new sym idx

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
            RelocEntry reloc_entry;

            // For each entry in the original relocation section, check if it applies to the new section and if so, add a corresponding entry to the new relocation section
            for (Elf_Xword j = 0; j < rel_accessor.get_entries_num(); ++j) {
                rel_accessor.get_entry(j, reloc_entry.offset, reloc_entry.symbol, reloc_entry.type, reloc_entry.addend);
                
                // Check if the relocation entry applies to the new section (i.e., if its offset falls within the symbol's range in the original section)
                if (reloc_entry.offset >= sym_offset && reloc_entry.offset < sym_offset + new_sec->get_size()) {
                    Elf64_Addr new_offset = reloc_entry.offset - sym_offset; // Adjust offset for the new section
                    Elf_Word reloc_symbol_idx = reloc_entry.symbol;
                    if (symbol_mapping.find(reloc_symbol_idx) != symbol_mapping.end()) { 
                        reloc_symbol_idx = symbol_mapping[reloc_symbol_idx]; // Update symbol index to the new symbol
                    }
                    rel_writer.add_entry(new_offset, reloc_symbol_idx, reloc_entry.type, reloc_entry.addend);
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
create_sections_from_symbols(elfio& writer, section* original_sec, symbol_section_accessor& symbols) 
{
    const char* target_data = original_sec->get_data();
    // if (!target_data) {
    //     std::cerr << "Section " << original_sec->get_name() << " data is null!" << std::endl;
    //     return;
    // }
    Elf_Word target_type = original_sec->get_type();
    Elf_Word target_flags = original_sec->get_flags();
    Elf_Word target_align = original_sec->get_addr_align();
    Elf_Xword target_size = original_sec->get_size();
    Elf_Xword target_addr = original_sec->get_address();
    Elf64_Off target_offset = original_sec->get_offset();
    

    // Find the symbol table section
    section* symtab = writer.sections[".symtab"];
    string_section_accessor str_accessor(writer.sections[symtab->get_link()]);

    // Create a new section for each symbol
    for (Elf_Xword i = 0; i < symbols_list.size(); ++i) {       
        const Symbol& sym = symbols_list[i];
        Elf_Sxword size = sym.size;
        Elf64_Addr sym_offset = sym.value; // Offset of the symbol relative to the section's address
      
        // if (sym_offset + size > original_sec->get_size()) {
        //     std::cerr << "Symbol extends past section bounds!" << std::endl;
        //     return;
        // }
        std::string symbol_data(target_data + sym_offset, size);
    
        // Create a new section
        std::string new_name = original_sec->get_name() + "." + sym.name;
        section* new_sec = writer.sections.add(new_name);
        if (new_sec == nullptr) {
            std::cerr << "Failed to create new section for symbol: " << sym.name << "\n";
            continue;
        }
        new_sec->set_type(target_type);
        new_sec->set_flags(target_flags);
        new_sec->set_addr_align(target_align);
        new_sec->set_address(0); // Object files won't need this, linker can decide
        new_sec->set_data(symbol_data); 

        // Add symbol mapping to the symbol table
        Elf_Word name_offset = str_accessor.add_string(sym.name);
        Elf_Word new_sym_idx = symbols.add_symbol(name_offset, 0, sym.size, sym.bind, sym.type, sym.other, new_sec->get_index());
       
        // Add symbol of the section to the symbol table
        Symbol sec_sym = get_section_symbol_by_name(symbols, writer, original_sec->get_name());
        symbols.add_symbol(name_offset, sec_sym.value, sec_sym.size, sec_sym.bind, sec_sym.type, sec_sym.other, new_sec->get_index());

        symbol_mapping[sym.idx] = new_sym_idx;
        create_relo(writer, original_sec, new_sec, sym_offset);
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

    // Create new sections from symbols
    create_sections_from_symbols(reader, original_sec, symbols);

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
    std::string section = argv[3];
    
    std::vector<std::string> sections_to_split = {".text"};
    int count = 0;
    int n = 0;
    int ret = split_section(input_path, output_path, section);
    if (ret == 1) {
        std::cerr << "Failed to split " << section << " section\n";
    } 
    return ret;
}
