from __future__ import annotations

from pathlib import Path

from stmemu.utils.logger import get_logger, setup_logging
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.bus import PeripheralBus
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.core.loader import load_raw_bin
from stmemu.core.emulator import Emulator
from stmemu.shell.shell import StmEmuShell
from stmemu.peripherals.core_cm import CortexMCorePeripheral

log = get_logger(__name__)


def run_app(
    image_path: Path,
    base_addr: int,
    svd_path: Path,
    sram_base: int,
    sram_size: int,
    shell: bool,
    cmd: str,
    log_level: str,
    quiet: bool,
    args=None,
) -> None:
    setup_logging(level=log_level, quiet=quiet)

    log.info("stmemu starting")
    log.info("Firmware: %s base=0x%08X", image_path, base_addr)
    log.info("SVD: %s", svd_path)

    fw = load_raw_bin(image_path)
    device = load_svd(svd_path)
    amap = build_address_map(device)

    bus = PeripheralBus(amap)
    # Register generic models for all peripherals from SVD by default
    for p in amap.peripherals:
        model = GenericRegisterFilePeripheral(p)

        # Break the early boot wait loop:
        # at PC 0x08003D24 firmware polls PWR register @ offset 0x04 waiting for bit13 to go high.
        if p.name == "PWR":
            model.force_bit_after_reads(0x04, 13, reads_before_set=10)

        bus.register_peripheral(p.name, model)


    # Register minimal Cortex-M core peripheral model (SCB/NVIC/SysTick region)
    core = CortexMCorePeripheral(vtor=base_addr)
    # We don't have an SVD peripheral for this; so we handle it via a special-case in Emulator hooks:
    emu = Emulator(
        bus=bus,
        flash_base=base_addr,
        flash_image=fw,
        sram_base=sram_base,
        sram_size=sram_size,
        core_peripheral=core,   # <-- add
    )

    emu.boot_from_vector_table(flash_base=base_addr)

    sh = StmEmuShell(emu=emu, bus=bus)
    # Run optional startup script from --cfg (supports ';' and newlines; '#' line comments)
    if getattr(args, 'cfg', None):
        import os
        cfg_path = args.cfg
        if not os.path.exists(cfg_path):
            raise FileNotFoundError(cfg_path)
        with open(cfg_path, 'r', encoding='utf-8', errors='replace') as f:
            raw = f.read()
        # Strip full-line comments and normalize newlines to ';' so it feeds run_script()
        cleaned_lines = []
        for ln in raw.splitlines():
            s = ln.strip()
            if not s or s.startswith('#'):
                continue
            cleaned_lines.append(ln)
        script = ';'.join(cleaned_lines)
        if script.strip():
            sh.run_script(script)

    # Run scripted commands first (if provided)
    if cmd.strip():
        sh.run_script(cmd)

    if shell or not cmd.strip():
        sh.cmdloop()
