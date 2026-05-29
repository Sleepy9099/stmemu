"""Run firmware briefly from a snapshot, then introspect SPI2 + FRAM state."""
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

run_instr = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
tick = int(sys.argv[2]) if len(sys.argv) > 2 else 1

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
               sram_base=0x24000000, sram_size=0x80000, firmware_format=fw.format,
               firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=tick,
               stuck_loop_threshold=0, interrupt_stuck_threshold=0)
emu.boot_from_vector_table()
cfg = load_board_config(ROOT / "test/arducopter_with_bl.yaml")
apply_board_config(cfg, bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / "test/snap_setup.snap"), name="s")
emu.load_snapshot("s")

spi2 = bus.model_for_name("SPI2")
fram = bus._spi_attached_devices.get("storage_fram")
print("pre-run: SPI2._devices=", [type(d).__name__ for d in spi2._devices],
      "fram is devices[0]:", spi2._devices and spi2._devices[0] is fram)

emu.run(run_instr)

print(f"\nafter {run_instr} @tick={tick}: pc=0x{emu.pc:08X}")
print("SPI2 tx_fifo=", len(spi2._tx_fifo), "rx_fifo=", len(spi2._rx_fifo))
print("SPI2._devices=", [type(d).__name__ for d in spi2._devices])
cfg1 = spi2.read_register_value(spi2._H7_CFG1) if spi2._H7_CFG1 is not None else None
cr1 = spi2.read_register_value(spi2._CR1)
print(f"SPI2 CFG1={cfg1:#x} CR1={cr1:#x} dma_flags={spi2._dma_flags()} dma_active={spi2._spi_dma_active()}")
print("FRAM(_spi_attached): cmds=", fram._commands_total, "bytes=", fram._bytes_exchanged,
      "cs_active=", fram.cs_active, "state=", fram._state)
print("FRAM recent_mosi=", bytes(fram._recent_mosi).hex(), "miso=", bytes(fram._recent_miso).hex())
if spi2._devices:
    d0 = spi2._devices[0]
    print("FRAM(_devices[0]): cmds=", getattr(d0, "_commands_total", "?"),
          "bytes=", getattr(d0, "_bytes_exchanged", "?"), "same_obj=", d0 is fram)
# DMA streams: which are enabled and their PAR / request mapping
for dn in ("DMA1", "DMA2", "BDMA"):
    dm = bus.model_for_name(dn)
    if dm is None: continue
    reqmap = getattr(dm, "_stream_request", {}) or getattr(dm, "_stream_requests", {})
    if reqmap:
        print(f"{dn} stream_request map:", reqmap)
