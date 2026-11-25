import re, sys

path = sys.argv[1]
data = open(path, 'rb').read()

# ASCII strings >= 6 chars
ascii_re = re.compile(rb'[ -~]{6,}')
hits = {}
for m in ascii_re.finditer(data):
    s = m.group().decode()
    hits.setdefault(s, m.start())

# UTF-16LE strings >= 6 chars
u16_re = re.compile(rb'(?:[ -~]\x00){6,}')
for m in u16_re.finditer(data):
    raw = m.group()
    s = raw.decode('utf-16-le')
    hits.setdefault(s, m.start())

kw = sys.argv[2] if len(sys.argv) > 2 else ''
kw_re = re.compile(kw, re.IGNORECASE)
for s, off in sorted(hits.items(), key=lambda kv: kv[1]):
    if not kw or kw_re.search(s):
        print(f"{off:8d}  {s}")
