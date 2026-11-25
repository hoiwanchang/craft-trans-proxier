import json
import sys

SRC = r"C:\Users\Kane Chang\.qoder-cn\tmp\C--Users-Kane-Chang-Downloads-cracker-app\tool-outputs\session-354d9e8e-1392-43d7-a807-da81a095ad2d\mcp_call_wxi51mkg6tvywyiwksfvmja77tsympkx.txt"
d = json.load(open(SRC, encoding="utf-8"))
ins = d["result"]["instructions"]
out = open(r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\tools\sub_402430.txt", "w", encoding="utf-8")
for i in ins:
    refs = ",".join(r["address"] for r in i.get("references", []))
    out.write("0x%06x %s %s %s\n" % (int(i["address"], 16), i["bytes"], i["text"], refs))
out.close()
print("wrote", len(ins), "instructions")
