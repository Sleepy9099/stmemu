"""Isolate the idle-fast-forward acceleration: park the CPU in a `b .` idle
loop with TIM2 set to raise its update IRQ after a large cycle span, then
measure how many *instructions* (= wall-clock work) each mode needs to reach
that timer interrupt. This is the boot-delay / sensor-wait case where the
time system accelerates testing."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from stmemu.core.loader import load_firmware, FirmwareSegment
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from unicorn.arm_const import UC_ARM_REG_PC

SPAN = 10_000_000  # cycles of "idle wait" before the timer fires


def build(mode: str):
    dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
    bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
    # Tiny program at 0x08000000: a `b .` self-loop (0xE7FE) -- the idle wait.
    seg = FirmwareSegment(address=0x08000000, data=bytes([0xFE, 0xE7]) * 8)
    emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=(seg,),
                   sram_base=0x24000000, sram_size=0x1000, firmware_format="bin",
                   core_peripheral=core, tick_scale=10,
                   stuck_loop_threshold=0, interrupt_stuck_threshold=0)
    emu.time.mode = mode
    emu.time.instructions = 0
    emu.time.cycles = 0
    # Program TIM2: ARR=SPAN-1, PSC=0, enable update interrupt, enable counter.
    tim = bus.model_for_name("TIM2")
    tim.write_register_value(tim._PSC, 0)
    tim.write_register_value(tim._ARR, SPAN - 1)
    tim.write_register_value(tim._DIER, tim._DIER_UIE)
    tim.write_register_value(tim._CNT, 0)
    tim.write_register_value(tim._CR1, tim._CR1_CEN)
    # Park PC at the idle loop (thumb bit set).
    emu.uc.reg_write(UC_ARM_REG_PC, 0x08000001)
    return emu, core, tim


def run(mode: str, budget: int):
    emu, core, tim = build(mode)
    emu.run(budget)  # fixed instruction budget; measure emulated time covered
    return emu.time.instructions, emu.time.cycles


BUDGET = 2000  # instructions of pure idle wait
print(f"CPU parked in a `b .` idle loop, TIM2 firing every {SPAN:,} cycles,")
print(f"tick_scale=10, fixed instruction budget = {BUDGET}:\n")
base = None
for mode in ("fixed", "idle"):
    instrs, cyc = run(mode, BUDGET)
    cpi = cyc / max(1, instrs)
    if mode == "fixed":
        base = cpi
    print(f"  mode={mode:6s}: {cyc:>16,} emulated cycles  "
          f"({cpi:>12,.0f} cycles/instruction)")
print(f"\n  speedup (emulated-time per instruction): "
      f"{(run('idle', BUDGET)[1] / run('fixed', BUDGET)[1]):,.0f}x")
print("In 'fixed' mode the CPU single-steps every idle cycle; in 'idle' mode")
print("it jumps straight to the next scheduled interrupt. That ratio is the")
print("boot-delay / sensor-wait speedup the time system gives testing -- while")
print("cycle-scheduled events still fire at their correct emulated time.")
