"""Trace I2C4 register access + bus transactions to see how the firmware
drives the baro/compass probe (DMA vs interrupt mode, which addresses)."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config

run_instr = int(sys.argv[1]) if len(sys.argv) > 1 else 4_000_000

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
               sram_base=0x24000000, sram_size=0x80000, firmware_format=fw.format,
               firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=1,
               stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000,
               stuck_loop_auto=False)
emu.boot_from_vector_table()
cfg = load_board_config(ROOT / "test/arducopter_with_bl.yaml")
apply_board_config(cfg, bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / "test/snap_i2c.snap"), name="s")
emu.load_snapshot("s")

i2c = bus.model_for_name("I2C4")
print("I2C4 model:", type(i2c).__name__, "i2c_bus attached:", i2c._i2c_bus is not None)
print(f"  CR1=0x{i2c.read_register_value(i2c._CR1):08x} (TXDMAEN=bit14 RXDMAEN=bit15)")
print(f"  CR2=0x{i2c.read_register_value(i2c._CR2):08x}  state={i2c._state}")

log: list[str] = []
ow = i2c.write
def tw(off, size, val):
    nm = {i2c._CR1:"CR1", i2c._CR2:"CR2", i2c._TXDR:"TXDR", i2c._ICR:"ICR"}.get(off, f"+0x{off:02x}")
    if len(log) < 150:
        log.append(f"  W {nm}=0x{val:08x}" + (f" [START addr=0x{(val>>1)&0x7f:02x} rd={(val>>10)&1} n={(val>>16)&0xff}]" if (nm=='CR2' and val&(1<<13)) else ""))
    return ow(off, size, val)
i2c.write = tw
orr = i2c.read
def tr(off, size):
    v = orr(off, size)
    if off == i2c._RXDR and len(log) < 150:
        log.append(f"  R RXDR -> 0x{v:02x}")
    return v
i2c.read = tr

# Hook the i2c bus transactions (start/write/read) to see device addressing.
b = i2c._i2c_bus
if b is not None:
    for meth in ("start", "write_byte", "read_byte", "stop"):
        if hasattr(b, meth):
            _o = getattr(b, meth)
            def mk(name, fn):
                def w(*a, **k):
                    r = fn(*a, **k)
                    # Only log ACKed starts (a real device answered) and the
                    # MS5611 addresses (0x76/0x77), plus the bytes they exchange.
                    acked = (name == "start" and r) or name in ("write_byte", "read_byte")
                    interesting = name == "start" and a and a[0] in (0x76, 0x77)
                    if (acked or interesting) and len(log) < 150:
                        log.append(f"    BUS {name}{a} -> {r}")
                    return r
                return w
            setattr(b, meth, mk(meth, _o))

# IRQ raised log
_irqs = []
_osip = core.set_irq_pending
def sip(irq, pending=True):
    if pending and len(_irqs) < 40: _irqs.append(irq)
    return _osip(irq, pending)
core.set_irq_pending = sip

# Track every probed address + ACK result across the whole run.
probed: dict[int, int] = {}   # addr -> count
acked: set = set()
if b is not None and hasattr(b, "start"):
    _os = b.start
    def start_track(addr, read, *a, **k):
        r = _os(addr, read, *a, **k)
        probed[addr] = probed.get(addr, 0) + 1
        if r:
            acked.add(addr)
        return r
    b.start = start_track

emu.run(run_instr)
print(f"\nafter {run_instr}: pc=0x{emu.pc:08X}")
print("IRQs raised:", _irqs[:20])
print("I2C addresses probed (addr: count):")
for a in sorted(probed):
    print(f"  0x{a:02X} ({a:3d}): {probed[a]}x  {'ACK' if a in acked else 'nack'}")
print("ACKed:", sorted(hex(a) for a in acked))
