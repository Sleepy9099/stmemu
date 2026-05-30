"""Is the EKF's IMU sample clock advancing? (root-cause for 'EKF never inits')

NavEKF3_core::InitialiseFilterBootstrap gates init on
    imuSampleTime_ms - firstInitTime_ms >= 1000
If imuSampleTime_ms is STUCK, that subtraction stays 0 forever and the EKF
never initialises -> InitialiseFilter is called every loop -> GPS task starved.

From the disasm of InitialiseFilterBootstrap (entry 0x0808D7D8, `mov r4,r0`):
    firstInitTime_ms = *(u32*)(core + 0x1b70)
    imuSampleTime_ms = *(u32*)(core + 0x15b0)
The core `this` ptr is r0 at entry. We breakpoint the entry, capture the core
pointer, then sample both fields over run chunks to see whether the IMU sample
clock advances (root cause) or is stuck (the real blocker behind GPS).

  python test/diag_ekf_imutime.py [budget]
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "test"))

from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config

budget = int(sys.argv[1]) if len(sys.argv) > 1 else 90_000_000
BOOT = 0x0808D7D8          # NavEKF3_core::InitialiseFilterBootstrap entry
OFF_FIRST = 0x1b70         # firstInitTime_ms
OFF_IMUT = 0x15b0          # imuSampleTime_ms

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000,
               sram_size=0x80000, firmware_format=fw.format, firmware_entry_point=fw.entry_point,
               core_peripheral=core, tick_scale=10, stuck_loop_threshold=10_000_000,
               interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT / "test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / "test/snap_insinit.snap"), name="ins_init")
emu.load_snapshot("ins_init")
emu.add_pc_cpu_action("setreg", pc=0x0806232C, reg="r3", value=200, once=True)
emu.add_pc_cpu_action("ret", pc=0x08062044, once=False)

emu.add_breakpoint(BOOT)
core_ptr = None
t0 = emu.time.cycles
done = 0
print("looking for EKF core ptr (InitialiseFilterBootstrap entry)...", flush=True)
while done < budget:
    emu.run(2_000_000)
    done += 2_000_000
    if core_ptr is None and emu.last_pc_break == BOOT:
        core_ptr = emu.reg_read("r0") & 0xFFFFFFFF
        emu.remove_breakpoint(BOOT)
        print(f">>> EKF core @ 0x{core_ptr:08X}  (first={core_ptr+OFF_FIRST:#x} imut={core_ptr+OFF_IMUT:#x})", flush=True)
    et = (emu.time.cycles - t0) / 1e6
    if core_ptr is not None:
        try:
            first = int.from_bytes(emu.mem_read(core_ptr + OFF_FIRST, 4), "little")
            imut = int.from_bytes(emu.mem_read(core_ptr + OFF_IMUT, 4), "little")
            print(f"[{done:>9}] et=+{et:7.2f}s firstInit={first} imuSampleTime={imut} diff={imut-first}", flush=True)
        except Exception as e:
            print(f"[{done:>9}] et=+{et:7.2f}s read-fail {e}", flush=True)
    else:
        print(f"[{done:>9}] et=+{et:7.2f}s pc=0x{emu.pc:08X} (no core yet)", flush=True)

print(f"\ndone {done} instr, core=0x{(core_ptr or 0):08X}")
