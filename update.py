#!/usr/bin/env python3

import sys
import shutil
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

R_X86_64_PC32 = 2
R_X86_64_PLT32 = 4


def find_text_section_index(elf):
    for i, sec in enumerate(elf.iter_sections()):
        if sec.name == ".text":
            return i
    raise Exception("Cannot find .text")


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


def find_old_text_section_symbol(symbols, old_text_idx):
    for s in symbols:
        if s["type"] == "STT_SECTION" and s["shndx"] == old_text_idx:
            return s["index"]
    raise Exception("Cannot find old .text SECTION symbol")


def collect_old_functions(symbols, old_text_idx):
    funcs = []
    for s in symbols:
        if s["type"] == "STT_FUNC" and s["shndx"] == old_text_idx:
            funcs.append({
                "index": s["index"],
                "name": s["name"],
                "start": s["value"],
                "size": s["size"],
                "shndx": s["shndx"],
            })
    funcs.sort(key=lambda x: x["start"])
    return funcs


def collect_new_functions(symbols, old_text_idx):
    new_funcs = {}
    for s in symbols:
        if s["type"] == "STT_FUNC" and s["shndx"] != old_text_idx:
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
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} input.o output.o")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2]

    shutil.copyfile(infile, outfile)

    with open(outfile, "r+b") as fp:
        elf = ELFFile(fp)
        symtab = find_symtab(elf)
        old_text_idx = find_text_section_index(elf)

        symbols = load_symbols(symtab)
        old_text_sym_idx = find_old_text_section_symbol(symbols, old_text_idx)
        old_funcs = collect_old_functions(symbols, old_text_idx)
        new_funcs = collect_new_functions(symbols, old_text_idx)
        section_symbols = collect_section_symbols(symbols)

        old_func_by_index = {}
        for f in old_funcs:
            old_func_by_index[f["index"]] = f

        new_func_by_index = {}
        for _, cands in new_funcs.items():
            for f in cands:
                new_func_by_index[f["index"]] = f

        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            if sec["sh_type"] != "SHT_RELA":
                continue

            relsec_offset = sec["sh_offset"]
            entsize = sec["sh_entsize"]

            # print(f"Processing relocation section: {sec.name}")

            for rel_index, rel in enumerate(sec.iter_relocations()):
                sym_idx = rel["r_info_sym"]
                rel_type = rel["r_info_type"]
                addend = rel["r_addend"]

                # Case 1: old .text SECTION symbol
                if sym_idx == old_text_sym_idx:
                    # print("CASE 1")
                    old_addr = addend

                    owner, new_addend = find_target_function(old_addr, old_funcs)
                    if owner is None:
                        print(f"  skip rel#{rel_index}: .text+0x{old_addr:x} cannot map to any function")
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

                    patch_rela_entry(
                        fp,
                        relsec_offset,
                        rel_index,
                        entsize,
                        new_sym_index,
                        rel_type,
                        new_addend
                    )
                    continue

                # Case 2: old function symbol in old .text
                if sym_idx in old_func_by_index:
                    old_func = old_func_by_index[sym_idx]

                    new_func = find_new_function_symbol(old_func, new_funcs)
                    if new_func is None:
                        print(f"  skip rel#{rel_index}: no new symbol for {old_func['name']}")
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
                    continue

                # Case 3: already points to a new split function symbol,
                # but PC32 should target the SECTION symbol, not FUNC symbol
                if rel_type == R_X86_64_PC32 and sym_idx in new_func_by_index:
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
                    continue


if __name__ == "__main__":
    main()