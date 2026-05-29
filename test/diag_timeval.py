"""Validate the time-system-v2 acceleration: quantify emulated-time coverage
per instruction in each mode, and confirm a cycle-scheduled timed event fires
across an idle fast-forward jump (the headline new capability)."""
from __future__ import annotations
import sys, time as _wall
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config


def fresh(mode: str, instrs: int):
    fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
    dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
    bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
    emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
                   sram_base=0x24000000, sram_size=0x80000, firmware_format=fw.format,
                   firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
                   stuck_loop_threshold=0, interrupt_stuck_threshold=0)
    emu.boot_from_vector_table()
    cfg = load_board_config(ROOT / "test/arducopter_with_bl.yaml")
    apply_board_config(cfg, bus, emu, base_dir=ROOT / "test")
    emu.import_snapshot(str(ROOT / "test/snap_i2c.snap"), name="s")
    emu.load_snapshot("s")
    emu.time.mode = mode
    emu.time.instructions = 0
    emu.time.cycles = 0
    t0 = _wall.perf_counter()
    emu.run(instrs)
    wall = _wall.perf_counter() - t0
    return emu, wall


print("=== Acceleration: emulated cycles covered per fixed instruction budget ===")
INSTR = 1_500_000
for mode in ("fixed", "idle"):
    emu, wall = fresh(mode, INSTR)
    cyc = emu.time.cycles
    print(f"  mode={mode:6s}  instrs={emu.time.instructions:>9d}  "
          f"cycles={cyc:>12d}  cyc/instr={cyc/max(1,emu.time.instructions):6.1f}  "
          f"wall={wall:5.1f}s  emulated_us={cyc/1_000_000:8.1f}")

print("\n=== Cycle-scheduled event fires across an idle jump ===")
emu, _ = fresh("idle", 1)
fired = {"n": 0, "at": None}
emu.time.instructions = 0
emu.time.cycles = 0
# Schedule an event 5,000,000 cycles out -- far enough that an idle jump
# would leap past it if the engine didn't stop at the deadline.
emu.add_timed_event_cycle(emu.time.cycles + 5_000_000, "event_emit", kind="timeval_probe", source="test")
def on_evt(ev):
    if getattr(ev, "kind", "") == "timeval_probe":
        fired["n"] += 1
        fired["at"] = emu.time.cycles
bus = emu.bus
bus.subscribe("timeval_probe", on_evt)
emu.run(2_000_000)
print(f"  scheduled at cycle 5,000,000; fired={fired['n']} at cycle={fired['at']}  "
      f"(final cycles={emu.time.cycles}, instrs={emu.time.instructions})")
ok = fired["n"] >= 1 and fired["at"] is not None and abs(fired["at"] - 5_000_000) < 200_000
print("  RESULT:", "PASS - cycle event fired near its deadline" if ok else "FAIL")
