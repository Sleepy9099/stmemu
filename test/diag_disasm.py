import sys, re; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from elf_symbols import parse_elf_symbols, resolve
from stmemu.core.disasm import ThumbDisassembler
blob = (ROOT/"test/arducopter_with_bl.bin").read_bytes()
# version string
for m in re.finditer(rb"(ArduCopter|APM:Copter)[ -~]{0,40}", blob):
    print("VER:", m.group().decode(errors="replace"))
syms = parse_elf_symbols(ROOT/"test"/"arducopter.elf")
def find(sub):
    return sorted([(v,s,n) for v,s,n in syms if sub in n], key=lambda x:x[0])
ig = find("10_init_gyroEv")
print("init_gyro matches:", [(hex(v),s,n) for v,s,n in ig][:3])
v,size,name = ig[0]; base=v & ~1; size = size or 0x600
off = base - 0x08000000
code = blob[off:off+size]
md = ThumbDisassembler()
print(f"\n== disasm {name} @0x{base:08X} size={size} ==")
for ins in md.disasm(code, base):
    tgt=""
    if ins.mnemonic.startswith(("bl","b","cbz","cbnz")) and ins.op_str.startswith("#0x"):
        try:
            a=int(ins.op_str.split("#")[1],16)
            if 0x08000000<=a<0x081e0000: tgt="  -> "+resolve(syms,a|1)
            else: tgt=f"  -> 0x{a:08X}"
        except: pass
    print(f"  0x{ins.address:08X}  {ins.mnemonic:<9}{ins.op_str}{tgt}")
