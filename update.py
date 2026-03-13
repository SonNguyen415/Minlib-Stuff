#!/usr/bin/env python3

import sys
import shutil
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

R_X86_64_PC32 = 2
R_X86_64_PLT32 = 4


def get_sym_name(elf, sym_idx):
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None or not isinstance(symtab, SymbolTableSection):
        raise Exception("Cannot find .symtab")

    sym = symtab.get_symbol(sym_idx)
    if sym is None:
        raise Exception(f"Cannot find symbol with index {sym_idx}")

    return sym.name

def find_section_index(elf, section_name):
    for i, sec in enumerate(elf.iter_sections()):
        if sec.name == section_name:
            return i
    raise Exception(f"Cannot find {section_name}")


def find_symtab(elf):
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None or not isinstance(symtab, SymbolTableSection):
        raise Exception("Cannot find .symtab")
    return symtab


def load_symbols(symtab):
    out = []
    for i, sym in enumerate(symtab.iter_symbols()):
        out.append({
            "index": i,
            "name": sym.name,
            "type": sym["st_info"]["type"],
            "bind": sym["st_info"]["bind"],
            "shndx": sym["st_shndx"],
            "value": sym["st_value"],
            "size": sym["st_size"],
        })
    return out


def find_symbol_idx(symbols, section_idx):
    # Find the symbol index that is the STT_SECTION symbol for the given section index
    for s in symbols:
        if s["type"] == "STT_SECTION" and s["shndx"] == section_idx:
            return s["index"]
    raise Exception("Cannot find SECTION symbol")


def collect_old_data(symbols, old_data_idx):
    data_syms = []
    for s in symbols:
        if s["type"] == "STT_SECTION" and s["shndx"] == old_data_idx:
            data_syms.append(s)
    return data_syms


def collect_old_functions(symbols, old_sym_idx, section_name):
    funcs = []
    if section_name == ".text":
        sec_type = "STT_FUNC"
    else:
        sec_type = "STT_OBJECT"
    for s in symbols:
        if s["type"] == sec_type and s["shndx"] == old_sym_idx:
            funcs.append({
                "index": s["index"],
                "name": s["name"],
                "start": s["value"],
                "size": s["size"],
                "shndx": s["shndx"],
            })
    funcs.sort(key=lambda x: x["start"])
    return funcs


def collect_new_functions(symbols, old_sym_idx, section_name):
    new_funcs = {}
    if section_name == ".text":
        sec_type = "STT_FUNC"
    else:
        sec_type = "STT_OBJECT"
    for s in symbols:
        if s["type"] == sec_type and s["shndx"] != old_sym_idx:
            new_funcs.setdefault(s["name"], []).append({
                "index": s["index"],
                "name": s["name"],
                "start": s["value"],
                "size": s["size"],
                "shndx": s["shndx"],
                "bind": s["bind"],
            })
    return new_funcs

def collect_section_symbols(symbols):
    # map section index -> SECTION symbol index
    sec_to_sym = {}
    for s in symbols:
        if s["type"] == "STT_SECTION" and isinstance(s["shndx"], int):
            sec_to_sym[s["shndx"]] = s["index"]
    return sec_to_sym


def find_target_function(addr, old_funcs):
    # Case 1: inside a function
    for f in old_funcs:
        start = f["start"]
        end = f["start"] + f["size"]
        if start <= addr < end:
            return f, addr - start

    # Case 2: in a gap before a later function
    for f in old_funcs:
        if addr < f["start"]:
            return f, addr - f["start"]

    # Case 3: after the last function, use the last function
    if old_funcs:
        last = old_funcs[-1]
        return last, addr - last["start"]

    return None, None


def find_new_function_symbol(old_func, new_funcs):
    cands = new_funcs.get(old_func["name"], [])
    if not cands:
        return None

    # Prefer same size first
    for c in cands:
        if c["size"] == old_func["size"]:
            return c

    return cands[0]


def choose_new_symbol_index(rel_type, new_func, section_symbols):
    # Keep relocation type unchanged.
    # Only choose symbol differently.
    if rel_type == R_X86_64_PC32:
        sec_idx = new_func["shndx"]
        sec_sym = section_symbols.get(sec_idx)
        if sec_sym is None:
            return None, "missing-section-symbol"
        return sec_sym, "section"

    # PLT32 and others keep function symbol
    return new_func["index"], "func"


def patch_rela_entry(fp, relsec_offset, rel_index, entsize, new_sym_index, rel_type, new_addend):
    entry_off = relsec_offset + rel_index * entsize
    r_info_off = entry_off + 8
    r_addend_off = entry_off + 16

    new_r_info = (new_sym_index << 32) | rel_type

    fp.seek(r_info_off)
    fp.write(struct.pack("<Q", new_r_info))

    fp.seek(r_addend_off)
    fp.write(struct.pack("<q", new_addend))

    

def main():
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} input.o output.o section_name")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2]
    section_name = sys.argv[3]

    shutil.copyfile(infile, outfile)

    with open(outfile, "r+b") as fp:
        elf = ELFFile(fp)
        symtab = find_symtab(elf)
        symbols = load_symbols(symtab)
        old_section_idx = find_section_index(elf, section_name)
        
        old_sym_idx = find_symbol_idx(symbols, old_section_idx)
        old_funcs = collect_old_functions(symbols, old_section_idx, section_name)
        new_funcs = collect_new_functions(symbols, old_section_idx, section_name)
        section_symbols = collect_section_symbols(symbols)

        old_func_by_index = {}
        for f in old_funcs:
            old_func_by_index[f["index"]] = f

        new_func_by_index = {}
        for _, cands in new_funcs.items():
            for f in cands:
                new_func_by_index[f["index"]] = f

        for sec in elf.iter_sections():
            # Find the relocation sections
            if not isinstance(sec, RelocationSection):
                continue
            if sec["sh_type"] != "SHT_RELA":
                continue

            relsec_offset = sec["sh_offset"]
            entsize = sec["sh_entsize"]


            # print(f"Processing relocation section: {sec.name}")

            # For every relocation entry in this section, check if it points to the old symbol, and if so, patch it to point to the new symbol
            for rel_index, rel in enumerate(sec.iter_relocations()):
                sym_idx = rel["r_info_sym"]
                rel_type = rel["r_info_type"]
                addend = rel["r_addend"]

                # pointed_symbol = get_sym_name(elf, sym_idx)
                # print(f"Pre-Processing - Symbol: {sym_idx} points to {pointed_symbol} + {addend}")

                # Case 1: Points to old symbol (which we're gonna delete)
                if sym_idx == old_sym_idx:
                    old_addr = addend 

                    owner, new_addend = find_target_function(old_addr, old_funcs)
                    if owner is None:
                        print(f"  skip rel#{rel_index}: {section_name} +0x{old_addr:x} cannot map to any function")
                        continue

                    new_func = find_new_function_symbol(owner, new_funcs)
                    if new_func is None:
                        print(f"  skip rel#{rel_index}: no new symbol for {owner['name']}")
                        continue

                    new_sym_index, mode = choose_new_symbol_index(rel_type, new_func, section_symbols)
                    if new_sym_index is None:
                        sec_name = elf.get_section(new_func["shndx"]).name
                        print(f"  skip rel#{rel_index}: no SECTION symbol for section {sec_name} {new_func['shndx']}")
                        continue

                    # print("Patching: {} +0x{:x} -> {} +0x{:x} (mode={})".format(
                    #     owner["name"], old_addr - owner["start"],
                    #     new_func["name"], new_addend, mode
                    # ))

                    patch_rela_entry(
                        fp,
                        relsec_offset,
                        rel_index,
                        entsize,
                        new_sym_index,
                        rel_type,
                        new_addend
                    )
    
                # Case 2: old function symbol in old section may still exist if there are other relocations pointing to it
                elif sym_idx in old_func_by_index:
                    old_func = old_func_by_index[sym_idx]

                    new_func = find_new_function_symbol(old_func, new_funcs)
                    if new_func is None:
                        # print(f"  skip rel#{rel_index}: no new symbol for {old_func['name']}")
                        continue

                    new_sym_index, mode = choose_new_symbol_index(rel_type, new_func, section_symbols)
                    if new_sym_index is None:
                        print(f"  skip rel#{rel_index}: no SECTION symbol for section {new_func['shndx']}")
                        continue

                    patch_rela_entry(
                        fp,
                        relsec_offset,
                        rel_index,
                        entsize,
                        new_sym_index,
                        rel_type,
                        addend
                    )

                # Case 3: already points to a new split function symbol, but PC32 should target the SECTION symbol, not FUNC symbol
                elif rel_type == R_X86_64_PC32 and sym_idx in new_func_by_index:
                    new_func = new_func_by_index[sym_idx]

                    new_sym_index, mode = choose_new_symbol_index(rel_type, new_func, section_symbols)
                    if new_sym_index is None:
                        print(f"  skip rel#{rel_index}: no SECTION symbol for section {new_func['shndx']}")
                        continue

                    if new_sym_index == sym_idx:
                        continue

                    patch_rela_entry(
                        fp,
                        relsec_offset,
                        rel_index,
                        entsize,
                        new_sym_index,
                        rel_type,
                        addend
                    )
                    


if __name__ == "__main__":
    main()