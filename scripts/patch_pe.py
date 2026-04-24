#!/usr/bin/env python3
"""
patch_pe.py - Post-build PE patching for static evasion.
  1. Zero Rich Header + PE timestamp
  2. Inject low-entropy .pad section to reduce average file entropy
"""

import sys
import os
import struct
import math

# Low-entropy filler: readable ASCII that looks like embedded version/resource data
_FILLER = (
    "Microsoft Visual C++ Runtime Library  "
    "Copyright (c) Microsoft Corporation. All rights reserved.  "
    "FileDescription  ProductName  CompanyName  LegalCopyright  "
    "FileVersion  ProductVersion  InternalName  OriginalFilename  "
    "This program requires Microsoft Windows.  "
    "The procedure entry point could not be located.  "
    "The ordinal could not be located in the dynamic link library.  "
).encode("ascii")

PAD_VSIZE = 0x8000  # 32 KB of low-entropy data


def align_up(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    e = 0.0
    for f in freq:
        if f:
            p = f / n
            e -= p * math.log2(p)
    return e


def zero_rich_header(pe: bytearray) -> None:
    rich_pos = pe.find(b"Rich")
    if rich_pos == -1:
        return
    xk = struct.unpack_from("<I", pe, rich_pos + 4)[0]
    dans_enc = struct.pack("<I", 0x536E6144 ^ xk)
    start = pe.find(dans_enc, 0x40)
    if start == -1 or start >= rich_pos:
        return
    end = rich_pos + 8  # include "Rich" + key
    pe[start:end] = b"\x00" * (end - start)
    print(f"[+] Rich Header zeroed  (0x{start:X} -> 0x{end:X})")


def zero_timestamp(pe: bytearray) -> None:
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    ts_off = e_lfanew + 8  # PE sig(4) + Machine(2) + NumberOfSections(2)
    struct.pack_into("<I", pe, ts_off, 0)
    print(f"[+] PE timestamp zeroed (offset 0x{ts_off:X})")


def add_pad_section(pe: bytearray) -> bytearray:
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
        print("[!] Not a valid PE, skipping .pad section")
        return pe

    fh_off  = e_lfanew + 4
    num_sec = struct.unpack_from("<H", pe, fh_off + 2)[0]
    opt_sz  = struct.unpack_from("<H", pe, fh_off + 16)[0]
    oh_off  = fh_off + 20

    sect_align = struct.unpack_from("<I", pe, oh_off + 32)[0]
    file_align = struct.unpack_from("<I", pe, oh_off + 36)[0]
    soi_off    = oh_off + 56  # SizeOfImage (same offset for PE32 and PE32+)

    sec_tbl       = fh_off + 20 + opt_sz
    new_hdr_off   = sec_tbl + num_sec * 40
    first_raw_ptr = struct.unpack_from("<I", pe, sec_tbl + 20)[0]

    if new_hdr_off + 40 > first_raw_ptr:
        print("[!] No room in section table for .pad — skipping entropy padding")
        return pe

    last_sec = sec_tbl + (num_sec - 1) * 40
    last_va   = struct.unpack_from("<I", pe, last_sec + 12)[0]
    last_vsz  = struct.unpack_from("<I", pe, last_sec + 8)[0]
    last_rptr = struct.unpack_from("<I", pe, last_sec + 20)[0]
    last_rsz  = struct.unpack_from("<I", pe, last_sec + 16)[0]

    new_va   = align_up(last_va + max(last_vsz, last_rsz), sect_align)
    new_rptr = align_up(last_rptr + last_rsz, file_align)
    new_rsz  = align_up(PAD_VSIZE, file_align)

    filler = (_FILLER * (new_rsz // len(_FILLER) + 1))[:new_rsz]

    # Build 40-byte section header
    hdr = bytearray(40)
    hdr[0:5] = b".pad\x00"
    struct.pack_into("<I", hdr, 8,  PAD_VSIZE)   # VirtualSize
    struct.pack_into("<I", hdr, 12, new_va)       # VirtualAddress
    struct.pack_into("<I", hdr, 16, new_rsz)      # SizeOfRawData
    struct.pack_into("<I", hdr, 20, new_rptr)     # PointerToRawData
    # IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    struct.pack_into("<I", hdr, 36, 0x40000040)

    struct.pack_into("<H", pe, fh_off + 2, num_sec + 1)
    struct.pack_into("<I", pe, soi_off, align_up(new_va + PAD_VSIZE, sect_align))
    pe[new_hdr_off: new_hdr_off + 40] = hdr

    if len(pe) < new_rptr:
        pe.extend(b"\x00" * (new_rptr - len(pe)))
    pe.extend(filler)

    print(f"[+] .pad section added  (VA=0x{new_va:X}, raw=0x{new_rptr:X}, {new_rsz // 1024} KB)")
    return pe


def main():
    if len(sys.argv) < 2:
        print("Usage: patch_pe.py <binary>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"[-] File not found: {path}")
        sys.exit(1)

    with open(path, "rb") as f:
        pe = bytearray(f.read())

    before = entropy(bytes(pe))

    zero_rich_header(pe)
    zero_timestamp(pe)
    pe = add_pad_section(pe)

    after = entropy(bytes(pe))

    with open(path, "wb") as f:
        f.write(pe)

    print(f"[+] Entropy : {before:.3f} -> {after:.3f}")


if __name__ == "__main__":
    main()
