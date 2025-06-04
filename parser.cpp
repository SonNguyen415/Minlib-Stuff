#include <iostream>
#include <elfio/elfio.hpp>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <ELF binary>\n";
        return 1;
    }

    const char* filepath = argv[1];
    ELFIO::elfio reader;

    // Load ELF file
    if (!reader.load(filepath)) {
        std::cerr << "Failed to load ELF file: " << filepath << "\n";
        return 1;
    }

    std::cout << "Parsing ELF: " << filepath << "\n";
    std::cout << "Number of segments: " << reader.segments.size() << "\n";

    // Iterate over segments
    for (int i = 0; i < reader.segments.size(); ++i) {
        const ELFIO::segment* seg = reader.segments[i];
        std::cout << "\nSegment " << i << " [type: " << seg->get_type()
                  << ", offset: 0x" << std::hex << seg->get_offset()
                  << ", vaddr: 0x" << seg->get_virtual_address() << std::dec << "]\n";
        std::cout << "Contains sections:\n";

        // Iterate over sections
         for (int j = 0; j < seg->get_sections_num(); ++j ) {
            const ELFIO::section* sec = reader.sections[seg->get_section_index_at( j )];

            ELFIO::Elf64_Addr sec_start = sec->get_address();
            ELFIO::Elf_Xword sec_size = sec->get_size();
            ELFIO::Elf64_Addr sec_end = sec_start + sec_size;

            ELFIO::Elf64_Addr seg_start = seg->get_virtual_address();
            ELFIO::Elf64_Addr seg_end = seg_start + seg->get_memory_size();

            std::cout << "  - " << sec->get_name()
                        << " [addr: 0x" << std::hex << sec_start
                        << ", size: 0x" << sec_size << std::dec << "]\n";
            
        }
        std::cout << "------------------------------------\n";
    }

    return 0;
}
