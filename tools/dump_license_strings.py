import struct
import sys
import io

PE = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\original\Proxifier PE\Proxifier.exe"
OUT = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\tools\out_strings.txt"
data = open(PE, "rb").read()
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

def va2off(va):
    if 0x400000 <= va < 0x660000:
        return va - 0x401000 + 0x400
    if 0x660000 <= va < 0x6F4000:
        return va - 0x660000 + 0x261000
    if 0x6F4000 <= va < 0x70B000:
        return va - 0x6F4000 + 0x2F2F40
    if va >= 0x70B000:
        return va - 0x70B000 + 0x2FB400
    return None

def u16(va, nchars):
    off = va2off(va)
    raw = data[off:off + nchars * 2]
    return raw.decode("utf-16-le", "replace")

# error strings referenced from the license verify flow
targets = [
    (0x69FD88, 0x15, "sub_402430 len!=29 error"),
    (0x69FDB4, 0xD, "sub_402430 checksum-fail error"),
    (0x69FC69, None, "sub_402430 (len-11?) error, read till null"),
    (0x6A7650, 0xB9, "caller: key[2]=='Y' path"),
    (0x6A77C8, 0x85, "caller: decode-fail path"),
    (0x6A79B0, None, "caller: product-mismatch fmt"),
    (0x6A797C, None, "caller: owner-mismatch fmt"),
    (0x6A7910, None, "caller: version fmt"),
    (0x6A79F0, 0x95, "caller: version<min error"),
    (0x6A7B20, 0xB9, "caller: expired-error"),
    (0x6A7CF8, 0x4E, "caller: expiry date fmt"),
    (0x6A7C98, 0x1FF, "caller: expiry date fmt2"),
]
for va, n, note in targets:
    if n is None:
        off = va2off(va)
        i = off
        while i < len(data) - 1 and data[i] != 0:
            i += 2
        s = data[off:i].decode("utf-16-le", "replace")
        print("0x%06X (%s) => %r" % (va, note, s))
    else:
        print("0x%06X (%s) => %r" % (va, note, u16(va, n)))

# pointer table at 0x6A0C30 (3 entries)
off = va2off(0x6A0C30)
ptrs = struct.unpack_from("<3I", data, off)
print("table 0x6A0C30:", [hex(p) for p in ptrs])
for p in ptrs:
    print("   0x%06X => %r" % (p, u16(p, 0x60)))
