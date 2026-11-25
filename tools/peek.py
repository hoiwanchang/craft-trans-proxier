import sys

path = sys.argv[1]
data = open(path, 'rb').read()
start = int(sys.argv[2], 0) if len(sys.argv) > 2 else None
if start is None:
    sys.exit(0)
end = int(sys.argv[3], 0) if len(sys.argv) > 3 else start + 0x1000
chunk = data[start:end]
out = []
i = 0
for j, b in enumerate(chunk):
    off = start + j
    if 32 <= b < 127:
        out.append(chr(b))
    else:
        out.append('\\x%02x' % b)
print(''.join(out))
