from __future__ import annotations

from pathlib import Path

from stmemu.utils.logger import get_logger, setup_logging
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.core.loader import load_firmware
from stmemu.core.emulator import Emulator
from stmemu.core.symbols import SymbolTable, load_symbols
from stmemu.shell.shell import StmEmuShell
from stmemu.peripherals.factory import build_default_bus

log = get_logger(__name__)


_STRUCTURED_CFG_SUFFIXES = {".yaml", ".yml", ".json"}
_PRELAUNCH_CFG_KEYS = {
    "svd",
    "base",
    "sram_base",
    "sram_size",
    "sysmem_base",
    "tick_scale",
    "stuck_threshold",
    "interrupt_stuck_threshold",
    "stuck_manual",
    "log_level",
    "quiet",
    "board",
}


def _is_prelaunch_cfg_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    sep = "=" if "=" in stripped else ":" if ":" in stripped else ""
    if not sep:
        return False
    key = stripped.split(sep, 1)[0].strip().lower().replace("-", "_")
    return key in _PRELAUNCH_CFG_KEYS


def _is_structured_cfg(path: Path) -> bool:
    return path.suffix.lower() in _STRUCTURED_CFG_SUFFIXES


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
    sysmem_base: int | None = None,
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

    bus, core = build_default_bus(amap, flash_base=firmware.vector_base, sysmem_base=sysmem_base)
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

    # Load ELF symbols if available
    if firmware.format == "elf":
        symbols = load_symbols(image_path)
        if symbols.count > 0:
            emu.symbols = symbols
            log.info("Loaded %d symbols from ELF", symbols.count)

    emu.boot_from_vector_table(flash_base=firmware.vector_base)

    sh = StmEmuShell(emu=emu, bus=bus)

    # Apply board/scenario config if provided
    board_cfg_path = getattr(args, 'board', None)
    if board_cfg_path is not None:
        from stmemu.board_config import load_board_config, apply_board_config
        board_cfg = load_board_config(Path(board_cfg_path))
        messages = apply_board_config(
            board_cfg, bus, emu,
            shell=sh, base_dir=Path(board_cfg_path).parent,
        )
        for msg in messages:
            log.info("board: %s", msg)

    # Run optional startup/scenario config from --cfg.
    ran_cfg_script = False
    if getattr(args, 'cfg', None):
        cfg_path = Path(args.cfg)
        if not cfg_path.exists():
            raise FileNotFoundError(cfg_path)
        if _is_structured_cfg(cfg_path):
            from stmemu.board_config import load_board_config, apply_board_config

            cfg = load_board_config(cfg_path)
            messages = apply_board_config(cfg, bus, emu, shell=sh, base_dir=cfg_path.parent)
            for msg in messages:
                log.info("cfg: %s", msg)
            ran_cfg_script = True
        else:
            raw = cfg_path.read_text(encoding='utf-8', errors='replace')
            # Strip full-line comments and normalize newlines to ';' so it feeds run_script().
            cleaned_lines = []
            for ln in raw.splitlines():
                s = ln.strip()
                if not s or s.startswith('#'):
                    continue
                if _is_prelaunch_cfg_line(s):
                    continue
                cleaned_lines.append(ln)
            script = ';'.join(cleaned_lines)
            if script.strip():
                sh.run_script(script)
                ran_cfg_script = True

    # Run scripted commands first (if provided)
    if cmd.strip():
        sh.run_script(cmd)

    if shell or (not cmd.strip() and not ran_cfg_script):
        sh.cmdloop()
