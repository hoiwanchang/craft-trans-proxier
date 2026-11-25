import re
import sys
import io

PE = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\original\Proxifier PE\Proxifier.exe"
OUT = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\tools\out_license_words.txt"
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

def off2va(off):
    if 0x400 <= off < 0x261000:
        return off - 0x400 + 0x401000
    if 0x261000 <= off < 0x2F2F40:
        return off - 0x261000 + 0x660000
    if 0x2F2F40 <= off < 0x2FB400:
        return off - 0x2F2F40 + 0x6F4000
    if off >= 0x2FB400:
        return off - 0x2FB400 + 0x70B000
    return None

rdata_off, rdata_va, rdata_size = 0x261000, 0x660000, 0x6F4000 - 0x660000

KW = re.compile(rb"key|licens|trial|expir|edition|premium|regist|period|limit|version", re.I)

rows = []
# UTF-16LE strings, min 8 chars
for m in re.finditer(rb"(?:[ -~]\x00){8,}", data[rdata_off:rdata_off + rdata_size]):
    s = m.group(0).decode("utf-16-le")
    off = rdata_off + m.start()
    if KW.search(m.group(0)):
        rows.append((off, "u16", s))

# ASCII strings, min 8 chars
for m in re.finditer(rb"[ -~]{8,}", data[rdata_off:rdata_off + rdata_size]):
    s = m.group(0).decode()
    off = rdata_off + m.start()
    if KW.search(m.group(0)):
        rows.append((off, "asc", s))

rows.sort()
f = open(OUT, "w", encoding="utf-8")
for off, kind, s in rows:
    va = off2va(off)
    f.write("0x%06X %-3s %s\n" % (va, kind, s[:180].replace("\n", " ")))
f.close()
print("wrote", len(rows), "hits to", OUT)
