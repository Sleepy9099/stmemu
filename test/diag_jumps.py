import sys; from pathlib import Path
from collections import Counter
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
jumps = []
orig = emu._idle_fast_forward
def wrapped():
    before = emu.time.cycles
    try: irq = emu.bus.cycles_until_irq()
    except Exception: irq = "ERR"
    try: tev = emu._cycles_until_timed_event()
    except Exception: tev = "ERR"
    orig()
    jumps.append((emu.time.cycles - before, irq, tev, emu.pc & ~1))
emu._idle_fast_forward = wrapped
emu.run(2_000_000)
sizes = [j[0] for j in jumps]
print("idle jumps:", len(jumps), " total jumped:", sum(sizes)/1e6, "s")
b = Counter()
for s in sizes:
    b['>=50M cap' if s>=50_000_000 else '1M-50M' if s>=1_000_000 else '1k-1M' if s>=1000 else '<1k'] += 1
print("jump-size buckets:", dict(b))
print("irq=None:", sum(1 for j in jumps if j[1] is None), "of", len(jumps), " | tev=None:", sum(1 for j in jumps if j[2] is None))
print("\nsample BIG jumps (>=1M cyc):")
for j in [x for x in jumps if x[0] >= 1_000_000][:12]:
    print(f"  jump={j[0]:>10} irq={j[1]} tev={j[2]} pc=0x{j[3]:08X}")
# which timers report an IRQ right now, at the end
print("\nper-timer cycles_until_irq at end:")
for m in bus._mounted:
    f = getattr(m.model, "cycles_until_irq", None)
    if f:
        try: c = f()
        except Exception as e: c = f"ERR {e}"
        if c is not None: print(f"  {m.name}: {c}")
