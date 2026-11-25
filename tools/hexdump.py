import sys

# VA -> file offset for Proxifier.exe sections
# .text VA 0x401000 offset 0x400 ; .rdata VA 0x660000 offset 0x261000
# .data VA 0x6F4000 offset 0x2F2F40 ; .rsrc VA 0x70B000 offset 0x2FB400
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

path = sys.argv[1]
data = open(path, 'rb').read()
va = int(sys.argv[2], 0)
n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 128
off = va2off(va)
chunk = data[off:off+n]
for i in range(0, len(chunk), 16):
    row = chunk[i:i+16]
    hexs = ' '.join('%02x' % b for b in row)
    asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
    print('%06x  %s |%s|' % (va + i, hexs.ljust(16*2-1), asc))
