"""Trace FRAM SPI bytes + CS edges to see exactly what the storage init does."""
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

run_instr = int(sys.argv[1]) if len(sys.argv) > 1 else 6_000_000

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
emu.import_snapshot(str(ROOT / "test/snap_setup.snap"), name="s")
emu.load_snapshot("s")

fram = bus._spi_attached_devices.get("storage_fram")
log: list[str] = []
orig_exchange = fram.exchange
def traced_exchange(mosi):
    miso = orig_exchange(mosi)
    if len(log) < 120:
        log.append(f"  ex mosi={mosi:02x} miso={miso:02x} state={fram._state} cs={int(fram.cs_active)}")
    return miso
fram.exchange = traced_exchange

orig_sel, orig_rel = fram.cs_select, fram.cs_release
def tsel():
    if len(log) < 120: log.append("  CS select (assert)")
    orig_sel()
def trel():
    if len(log) < 120: log.append("  CS release (deassert)")
    orig_rel()
fram.cs_select = tsel
fram.cs_release = trel

def on_edge(ev):
    p = ev.payload or {}
    if str(ev.source) == "GPIOD" and p.get("pin") == 4 and len(log) < 120:
        log.append(f"  GPIOD.4 edge falling={p.get('falling')} rising={p.get('rising')}")
bus.subscribe("gpio_edge", on_edge)

# Log what the firmware reads back from SPI2 RXDR (what it actually receives).
spi2 = bus.model_for_name("SPI2")
orig_read = spi2.read
def traced_read(offset, size):
    val = orig_read(offset, size)
    if spi2._is_data_read(offset) and len(log) < 120:
        log.append(f"  RXDR read -> 0x{val:02x}")
    return val
spi2.read = traced_read

# Monitor DMA TC + IRQ raising to see if the SPI completion interrupt fires.
dma2 = bus.model_for_name("DMA2")
print("DMA2._irqs (stream->irq):", getattr(dma2, "_irqs", None))
print("DMA2 stream_request map:", getattr(dma2, "_stream_request", None) or getattr(dma2, "_stream_requests", None))
if dma2 is not None and hasattr(dma2, "_set_tcif"):
    _orig_tcif = dma2._set_tcif
    def traced_tcif(stream, cr):
        if len(log) < 120: log.append(f"  DMA2 TCIF stream={stream} cr={cr:#x} irq={getattr(dma2,'_irqs',{}).get(stream)}")
        return _orig_tcif(stream, cr)
    dma2._set_tcif = traced_tcif
_irqlog = []
if core is not None and hasattr(core, "set_irq_pending"):
    _orig_sip = core.set_irq_pending
    def traced_sip(irq, pending=True):
        if pending and len(_irqlog) < 60: _irqlog.append(irq)
        return _orig_sip(irq, pending)
    core.set_irq_pending = traced_sip

emu.run(run_instr)
print(f"pc=0x{emu.pc:08X} cmds={fram._commands_total} bytes={fram._bytes_exchanged} cs_active={fram.cs_active}")
print("IRQs raised (first 60):", _irqlog)
print("first events:")
print("\n".join(log[:120]))
