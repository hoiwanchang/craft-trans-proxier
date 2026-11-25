import sys
import io
import re

import struct

PE = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\original\Proxifier PE\Proxifier.exe"
OUT = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\tools\out_regions.txt"
data = open(PE, "rb").read()
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
nsects = struct.unpack_from("<H", data, e_lfanew + 2)[0]
f = open(OUT, "w", encoding="utf-8")
f.write("=== sections ===\n")
for i in range(nsects):
    s = e_lfanew + 0x40 + i * 8
    va, vsize, roff, rsize = struct.unpack_from("<IIII", data, s)
    f.write("VA 0x%08X vsize 0x%08X off 0x%08X rsize 0x%08X\n" % (va, vsize, roff, rsize))

# (offset, start, end) file-offset ranges to decode as u16 with markers
regions = [
    (0x0029EF00, 0x0029EF00, 0x0029F700, "error strings + PE title"),
    (0x002A5700, 0x002A5700, 0x002A7700, "editions/license msgs"),
    (0x002A8000, 0x002A8000, 0x002AB000, "trial/welcome area"),
    (0x002AD000, 0x002AD000, 0x002AD700, "trial.html area"),
    (0x002B0100, 0x002B0100, 0x002B1000, "license save msgs"),
    (0x002B5000, 0x002B5000, 0x002B5200, "registration key dlg"),
    (0x00306900, 0x00306900, 0x00306A00, "Registration..."),
    (0x003CC100, 0x003CC100, 0x003CD700, "registration info dlg"),
    (0x003CEC00, 0x003CEC00, 0x003CEF00, "PE v4.14 area"),
]
f = open(OUT, "w", encoding="utf-8")
for (a, b, e, note) in regions:
    f.write("\n===== %s =====\n" % note)
    for m in re.finditer(rb"(?:[ -~]\x00){4,}", data[a:e]):
        s = m.group(0).decode("utf-16-le")
        f.write("0x%08X %s\n" % (m.start(), s[:300].replace("\r", "")))
    for m in re.finditer(rb"[ -~]{6,}", data[a:e]):
        s = m.group(0).decode()
        f.write("0x%08X asc %s\n" % (m.start(), s[:200].replace("\r", "")))
f.close()
print("done")
