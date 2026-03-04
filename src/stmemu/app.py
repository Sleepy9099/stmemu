from __future__ import annotations

from pathlib import Path

from stmemu.utils.logger import get_logger, setup_logging
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.core.loader import load_firmware
from stmemu.core.emulator import Emulator
from stmemu.shell.shell import StmEmuShell
from stmemu.peripherals.factory import build_default_bus

log = get_logger(__name__)


def run_app(
    image_path: Path,
    base_addr: int,
    svd_path: Path,
    sram_base: int,
    sram_size: int,
    tick_scale: int,
    stuck_threshold: int,
    interrupt_stuck_threshold: int,
    stuck_auto: bool,
    shell: bool,
    cmd: str,
    log_level: str,
    quiet: bool,
    args=None,
) -> None:
    setup_logging(level=log_level, quiet=quiet)

    log.info("stmemu starting")
    log.info("Firmware: %s", image_path)
    log.info("SVD: %s", svd_path)

    firmware = load_firmware(image_path, base_addr=base_addr)
    log.info(
        "Firmware format=%s vector_base=0x%08X segments=%d",
        firmware.format,
        firmware.vector_base,
        len(firmware.segments),
    )
    device = load_svd(svd_path)
    amap = build_address_map(device)

    bus, core = build_default_bus(amap, flash_base=firmware.vector_base)
    emu = Emulator(
        bus=bus,
        flash_base=firmware.vector_base,
        firmware_segments=firmware.segments,
        sram_base=sram_base,
        sram_size=sram_size,
        firmware_format=firmware.format,
        firmware_entry_point=firmware.entry_point,
        core_peripheral=core,
        tick_scale=tick_scale,
        stuck_loop_threshold=stuck_threshold,
        interrupt_stuck_threshold=interrupt_stuck_threshold,
        stuck_loop_auto=stuck_auto,
    )

    emu.boot_from_vector_table(flash_base=firmware.vector_base)

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
