import struct, sys

path = sys.argv[1]
data = open(path, 'rb').read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
nsects = struct.unpack_from('<H', data, e_lfanew + 2)[0]
sections = []
for i in range(nsects):
    s = e_lfanew + 0x40 + i * 8
    va, vsize, roff, rsize = struct.unpack_from('<IIII', data, s)
    sections.append((va, vsize, roff, rsize))

def va2off(va):
    for (s_va, vsize, roff, rsize) in sections:
        if s_va <= va < s_va + max(vsize, rsize):
            return roff + (va - s_va)
    return None

def off2va(off):
    for (s_va, vsize, roff, rsize) in sections:
        if roff <= off < roff + max(vsize, rsize):
            return s_va + (off - roff)
    return None

if len(sys.argv) > 2:
    x = int(sys.argv[2], 0)
    if sys.argv[3] == 'va2off':
        r = va2off(x)
    else:
        r = off2va(x)
    print(hex(r) if r is not None else None)
