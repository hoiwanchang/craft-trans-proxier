import re
import sys
import io

PE = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\original\Proxifier PE\Proxifier.exe"
OUT = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\tools\out_u16_phrases.txt"
data = open(PE, "rb").read()
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

KW = re.compile(r"(?i)(trial|expir|premium|edition|period|unlimited|registration|key|days|months|years|standard|license)")

hits = []
for m in re.finditer(rb"(?:[ -~]\x00){8,}", data):
    s = m.group(0).decode("utf-16-le")
    if KW.search(s):
        hits.append((m.start(), s))

hits.sort()
f = open(OUT, "w", encoding="utf-8")
for off, s in hits:
    f.write("0x%08X %s\n" % (off, s[:220].replace("\n", " ")))
f.close()
print("wrote", len(hits), "hits")
