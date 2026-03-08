#!/usr/bin/env python3

import sys
import shutil
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


def get_symtab_and_index(elf):
    for i, sec in enumerate(elf.iter_sections()):
        if sec.name == ".symtab":
            return sec, i
    raise Exception("Cannot find .symtab")


def read_symbol_entries(fp, symtab):
    sym_offset = symtab["sh_offset"]
    sym_size = symtab["sh_size"]
    entsize = symtab["sh_entsize"]

    if entsize == 0:
        raise Exception("Invalid .symtab entry size")

    count = sym_size // entsize

    fp.seek(sym_offset)
    data = fp.read(sym_size)

    entries = []
    for i in range(count):
        start = i * entsize
        end = start + entsize
        entries.append(data[start:end])

    return entries, entsize


def build_new_order(symtab):
    local_indices = []
    global_indices = []

    for i, sym in enumerate(symtab.iter_symbols()):
        if i == 0:
            continue
        bind = sym["st_info"]["bind"]
        if bind == "STB_LOCAL":
            local_indices.append(i)
        else:
            global_indices.append(i)

    new_order = [0] + local_indices + global_indices
    old_to_new = {}

    for new_idx, old_idx in enumerate(new_order):
        old_to_new[old_idx] = new_idx

    new_sh_info = 1 + len(local_indices)
    return new_order, old_to_new, new_sh_info


def rewrite_symtab(fp, symtab, entries, new_order):
    sym_offset = symtab["sh_offset"]
    new_data = b"".join(entries[old_idx] for old_idx in new_order)

    fp.seek(sym_offset)
    fp.write(new_data)


def patch_symtab_sh_info(fp, elf, symtab_index, new_sh_info):
    e_shoff = elf.header["e_shoff"]
    e_shentsize = elf.header["e_shentsize"]

    sh_offset = e_shoff + symtab_index * e_shentsize

    # ELF64 section header:
    # sh_name      4
    # sh_type      4
    # sh_flags     8
    # sh_addr      8
    # sh_offset    8
    # sh_size      8
    # sh_link      4
    # sh_info      4   <-- offset 44
    # sh_addralign 8
    # sh_entsize   8
    sh_info_off = sh_offset + 44

    fp.seek(sh_info_off)
    fp.write(struct.pack("<I", new_sh_info))


def patch_relocations(fp, elf, old_to_new):
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue

        sh_type = sec["sh_type"]
        relsec_offset = sec["sh_offset"]
        entsize = sec["sh_entsize"]

        # print(f"Updating relocation section: {sec.name}")

        for rel_index, rel in enumerate(sec.iter_relocations()):
            old_sym = rel["r_info_sym"]
            rel_type = rel["r_info_type"]

            if old_sym not in old_to_new:
                continue

            new_sym = old_to_new[old_sym]
            if new_sym == old_sym:
                continue

            if sh_type == "SHT_RELA":
                entry_off = relsec_offset + rel_index * entsize
                r_info_off = entry_off + 8
                new_r_info = (new_sym << 32) | rel_type

                fp.seek(r_info_off)
                fp.write(struct.pack("<Q", new_r_info))

            elif sh_type == "SHT_REL":
                entry_off = relsec_offset + rel_index * entsize
                r_info_off = entry_off + 8
                new_r_info = (new_sym << 32) | rel_type

                fp.seek(r_info_off)
                fp.write(struct.pack("<Q", new_r_info))


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} input.o output.o")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2]

    shutil.copyfile(infile, outfile)

    with open(outfile, "r+b") as fp:
        elf = ELFFile(fp)
        symtab, symtab_index = get_symtab_and_index(elf)

        if not isinstance(symtab, SymbolTableSection):
            raise Exception(".symtab is not a symbol table")

        entries, entsize = read_symbol_entries(fp, symtab)
        new_order, old_to_new, new_sh_info = build_new_order(symtab)

        # print("Old -> New symbol index mapping:")
        # for old_idx in sorted(old_to_new.keys()):
        #     new_idx = old_to_new[old_idx]
        #     if old_idx != new_idx:
        #         print(f"  {old_idx} -> {new_idx}")

        rewrite_symtab(fp, symtab, entries, new_order)
        patch_symtab_sh_info(fp, elf, symtab_index, new_sh_info)

        # Re-open ELF view after rewriting .symtab so later offsets/section info stay fresh
        fp.flush()
        fp.seek(0)
        elf = ELFFile(fp)

        patch_relocations(fp, elf, old_to_new)


if __name__ == "__main__":
    main()