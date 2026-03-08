
import sys
import shutil
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


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
    syms = []
    for i, sym in enumerate(symtab.iter_symbols()):
        syms.append({
            "index": i,
            "name": sym.name,
            "type": sym["st_info"]["type"],
            "bind": sym["st_info"]["bind"],
            "shndx": sym["st_shndx"],
            "value": sym["st_value"],
            "size": sym["st_size"],
        })
    return syms


def find_old_text_section_symbol(symbols, old_text_idx):
    for s in symbols:
        if s["type"] == "STT_SECTION" and s["shndx"] == old_text_idx:
            return s["index"]
    raise Exception("Cannot find old .text section symbol")


def collect_old_functions(symbols, old_text_idx):
    funcs = []
    for s in symbols:
        if s["type"] == "STT_FUNC" and s["shndx"] == old_text_idx:
            funcs.append({
                "index": s["index"],
                "name": s["name"],
                "start": s["value"],
                "size": s["size"],
            })
    funcs.sort(key=lambda x: x["start"])
    return funcs


def collect_new_functions(symbols, old_text_idx):
    new_funcs = {}
    for s in symbols:
        if s["type"] == "STT_FUNC" and s["shndx"] != old_text_idx:
            if s["name"] not in new_funcs:
                new_funcs[s["name"]] = []
            new_funcs[s["name"]].append({
                "index": s["index"],
                "name": s["name"],
                "start": s["value"],
                "size": s["size"],
                "shndx": s["shndx"],
            })
    return new_funcs


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

    for c in cands:
        if c["size"] == old_func["size"]:
            return c

    return cands[0]


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

        old_func_by_index = {}
        for f in old_funcs:
            old_func_by_index[f["index"]] = f

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

                # Case 1: old .text section symbol
                if sym_idx == old_text_sym_idx:
                    old_addr = addend

                    owner, new_addend = find_target_function(old_addr, old_funcs)
                    if owner is None:
                        print(f"  skip rel#{rel_index}: .text+0x{old_addr:x} cannot map to any function")
                        continue

                    new_func = find_new_function_symbol(owner, new_funcs)
                    if new_func is None:
                        print(f"  skip rel#{rel_index}: no new symbol for {owner['name']}")
                        continue

                    # print(
                    #     f"  patch rel#{rel_index}: "
                    #     f".text+0x{old_addr:x} -> {new_func['name']} {new_addend:+#x}"
                    # )

                    patch_rela_entry(
                        fp,
                        relsec_offset,
                        rel_index,
                        entsize,
                        new_func["index"],
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

                    # print(
                    #     f"  patch rel#{rel_index}: "
                    #     f"{old_func['name']} {addend:+#x} -> {new_func['name']} {addend:+#x}"
                    # )

                    patch_rela_entry(
                        fp,
                        relsec_offset,
                        rel_index,
                        entsize,
                        new_func["index"],
                        rel_type,
                        addend
                    )


if __name__ == "__main__":
    main()