# Empirical harness for Proxifier.exe sub_402430 (license key decoder).
# Path hardcoded - no command-line parameters (avoid terminal arg issues).
import ctypes
import sys
import io
import struct

PE = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\original\Proxifier PE\Proxifier.exe"
OUT = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\tools\out_decode_harness.txt"
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

h = ctypes.WinDLL(PE)
base = ctypes.windll.kernel32.GetModuleHandleW(PE)
print("loaded at 0x%X" % base)
addr = base + 0x402430

KEYS = [
    "00000-00000-00000-00000-00000",
    "11111-11111-11111-11111-11111",
    "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
    "99999-99999-99999-99999-99999",
    "12345-67890-12345-67890-12345",
]

def run_layout(name, argtypes, this, key_w, len, limit, err):
    for key in KEYS:
        kb = ctypes.create_string_buffer(key.encode("utf-16-le"))
        thisbuf = (ctypes.c_uint32 * 16)()
        errbuf = (ctypes.c_uint32 * 64)()
        func = ctypes.windll.kernel32  # placeholder
        f = ctypes.WinDLL(None)
        restype = ctypes.c_uint32
        fptr = ctypes.c_void_p(addr)
        try:
            # build callable
            callable_ = ctypes.cast(addr, argtypes)
            r = callable_(thisbuf, kb, 0, 0, 0, len, limit, errbuf)
        except Exception as e:
            print("  layout %s key=%s EXC %s" % (name, key, e))
            continue
        fields = [hex(v) for v in thisbuf]
        print("layout %-12s key=%s ret=%d this=%s" % (name, key, r, " ".join(fields)))
        print("           errbuf=%s" % " ".join(hex(v) for v in errbuf[:4]))

# Layout A: thiscall - first arg (ECX) = this, stack args follow.
run_layout("A_thiscall", None, None, None, 29, 8, None)

# Layout B: stdcall-ish - this also on stack as first arg, key second.
def run_b():
    for key in KEYS:
        kb = ctypes.create_string_buffer(key.encode("utf-16-le"))
        thisbuf = (ctypes.c_uint32 * 16)()
        errbuf = (ctypes.c_uint32 * 64)()
        proto = ctypes.WinFUNCTYPE(
            ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
        callable_ = proto(addr)
        r = callable_(thisbuf, kb, 0, 0, 0, 29, 8, errbuf)
        fields = [hex(v) for v in thisbuf]
        print("layout B_stdcall   key=%s ret=%d this=%s" % (key, r, " ".join(fields)))
        print("           errbuf=%s" % " ".join(hex(v) for v in errbuf[:4]))

print("---- layout B ----")
run_b()

# Layout A callable properly
def run_a():
    proto = ctypes.WinFUNCTYPE(
        ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
    callable_ = proto(addr)
    for key in KEYS:
        kb = ctypes.create_string_buffer(key.encode("utf-16-le"))
        thisbuf = (ctypes.c_uint32 * 16)()
        errbuf = (ctypes.c_uint32 * 64)()
        r = callable_(thisbuf, kb, 0, 0, 0, 29, 8, errbuf)
        fields = [hex(v) for v in thisbuf]
        print("layout A_thiscall key=%s ret=%d this=%s" % (key, r, " ".join(fields)))
        print("           errbuf=%s" % " ".join(hex(v) for v in errbuf[:4]))

print("---- layout A ----")
run_a()
