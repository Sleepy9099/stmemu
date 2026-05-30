import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from elf_symbols import parse_elf_symbols, resolve
run_instr = int(sys.argv[1]) if len(sys.argv)>1 else 60_000_000
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
emu.add_pc_cpu_action("setreg", pc=0x0806232C, reg="r3", value=200, once=True)
emu.add_pc_cpu_action("ret", pc=0x08062044, once=False)
emu.enable_stall_diagnostics()
syms = parse_elf_symbols(ROOT/"test"/"arducopter.elf")
res = lambda a: resolve(syms, a)
print(f"running {run_instr} (force-cal-exit) ...", flush=True)
emu.run(run_instr)
print(f"stopped pc=0x{emu.pc:08X}  fp={emu._fp_emulated_count}\n")
print("== top hot PCs (cumulative) ==")
for pc,c in sorted(emu._pc_hist.items(), key=lambda kv:-kv[1])[:14]:
    print(f"  x{c:>9}  0x{pc&~1:08X}  {res((pc&~1)|1)}")
print("\n== main-thread stack (0x24000600..0x24002200) ==")
data = emu.mem_read(0x24000600, 0x1C00); last=None
for off in range(0, len(data)-3, 4):
    w=int.from_bytes(data[off:off+4],'little')
    if (w&1) and 0x08000000<=(w&~1)<0x081DB1C8:
        lbl=res(w)
        if lbl!=last: print(f"  [+0x{off:04X}] 0x{w&~1:08X}  {lbl}"); last=lbl
