import json
import sys
import io

SRC = r"C:\Users\Kane Chang\.qoder-cn\tmp\C--Users-Kane-Chang-Downloads-cracker-app\tool-outputs\session-354d9e8e-1392-43d7-a807-da81a095ad2d\mcp_call_xfdccnl05sbb4xprdyr1jqs2mdok01wb.txt"
OUT = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\tools\out_caller.txt"
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

d = json.load(open(SRC, encoding="utf-8"))
ins = d["result"]["instructions"]
f = open(OUT, "w", encoding="utf-8")
for i in ins:
    va = int(i["address"], 16)
    refs = ",".join(r["address"] for r in i.get("references", []))
    f.write("0x%06x %s %s %s\n" % (va, i["bytes"], i["text"], refs))
f.close()
print("wrote", len(ins))
