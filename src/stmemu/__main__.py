from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from stmemu.app import run_app


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


def _normal_key(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _read_prelaunch_cfg(path: Path) -> dict[str, Any]:
    """Read cfg directives that must be known before the emulator starts."""
    if not path.exists():
        raise FileNotFoundError(path)

    if path.suffix.lower() in _STRUCTURED_CFG_SUFFIXES:
        from stmemu.board_config import load_board_config

        config = load_board_config(path)
        out: dict[str, Any] = {}
        target = config.get("target", {})
        if isinstance(target, dict):
            for key in ("svd", "base", "sram_base", "sram_size", "sysmem_base", "board"):
                if key in target:
                    out[key] = target[key]
        emulator = config.get("emulator", {})
        if isinstance(emulator, dict):
            for key in (
                "tick_scale",
                "stuck_threshold",
                "interrupt_stuck_threshold",
                "stuck_manual",
                "log_level",
                "quiet",
            ):
                if key in emulator:
                    out[key] = emulator[key]
        for key in _PRELAUNCH_CFG_KEYS:
            value = config.get(key)
            if key not in out and value is not None and not isinstance(value, (dict, list)):
                out[key] = value
        return out

    out: dict[str, Any] = {}
    raw = path.read_text(encoding="utf-8", errors="replace")
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sep = "=" if "=" in stripped else ":" if ":" in stripped else ""
        if not sep:
            continue
        key, value = stripped.split(sep, 1)
        key = _normal_key(key)
        if key in _PRELAUNCH_CFG_KEYS:
            out[key] = value.strip()
    return out


def _cfg_path(raw: str, cfg_path: Path | None) -> Path:
    path = Path(str(raw))
    if path.is_absolute() or cfg_path is None:
        return path

    cfg_relative = cfg_path.parent / path
    if path.exists() or not cfg_relative.exists():
        return path
    return cfg_relative


def _cfg_int(cfg: dict[str, Any], key: str, default: str) -> int:
    return int(str(cfg.get(key, default)), 0)


def main() -> None:
    p = argparse.ArgumentParser(prog="stmemu", description="STM emulator scaffold (Unicorn + SVD + interactive shell)")
    p.add_argument("image", type=Path, help="Firmware image (.bin or ELF)")
    p.add_argument(
        "--base",
        type=lambda s: int(s, 0),
        default=None,
        help="Raw binary load base (default: 0x08000000, ignored for ELF)",
    )
    p.add_argument("--svd", type=Path, default=None, help="CMSIS-SVD XML file path (or set target.svd in --cfg)")

    # Memory layout defaults (reasonable for many STM32, adjust per target)
    p.add_argument("--sram-base", type=lambda s: int(s, 0), default=None)
    p.add_argument("--sram-size", type=lambda s: int(s, 0), default=None)  # default 128 KiB

    p.add_argument(
        "--sysmem-base",
        type=lambda s: int(s, 0),
        default=None,
        help="System memory base address (auto-detected from SVD device name if omitted)",
    )

    # Execution controls
    p.add_argument("--shell", action="store_true", help="Start interactive shell after loading")
    p.add_argument("--cmd", type=str, default="", help='Semicolon-separated shell commands to run, e.g. "regs; step 10; run 1000"')
    p.add_argument("--cfg", help="Path to a startup script or YAML/JSON scenario config")
    p.add_argument("--board", type=Path, default=None, help="Board topology config (YAML/JSON) for device attachments")
    p.add_argument(
        "--tick-scale",
        type=lambda s: int(s, 0),
        default=None,
        help="Peripheral/core timer ticks to advance per emulated instruction (default: 1)",
    )
    p.add_argument(
        "--stuck-threshold",
        type=lambda s: int(s, 0),
        default=None,
        help="Stop after this many hits at one PC when no interrupt source is available (0 disables)",
    )
    p.add_argument(
        "--interrupt-stuck-threshold",
        type=lambda s: int(s, 0),
        default=None,
        help="Stop after this many hits at one PC when interrupts are enabled/pending (0 disables)",
    )
    p.add_argument(
        "--stuck-manual",
        action="store_true",
        default=None,
        help="Use --stuck-threshold as a fixed limit instead of auto-relaxing for interrupt-driven loops",
    )

    # Logging
    p.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--quiet", action="store_true", default=None, help="Reduce console output")

    args = p.parse_args()
    cfg_path = Path(args.cfg) if args.cfg else None
    cfg = _read_prelaunch_cfg(cfg_path) if cfg_path else {}

    svd_path = args.svd
    if svd_path is None and "svd" in cfg:
        svd_path = _cfg_path(cfg["svd"], cfg_path)
    if svd_path is None:
        p.error("--svd is required unless --cfg contains target.svd")

    board_path = args.board
    if board_path is None and "board" in cfg:
        board_path = _cfg_path(cfg["board"], cfg_path)
    args.board = board_path

    base_addr = args.base if args.base is not None else _cfg_int(cfg, "base", "0x08000000")
    sram_base = args.sram_base if args.sram_base is not None else _cfg_int(cfg, "sram_base", "0x20000000")
    sram_size = args.sram_size if args.sram_size is not None else _cfg_int(cfg, "sram_size", "0x20000")
    sysmem_base = args.sysmem_base
    if sysmem_base is None and "sysmem_base" in cfg:
        sysmem_base = int(str(cfg["sysmem_base"]), 0)
    tick_scale = args.tick_scale if args.tick_scale is not None else _cfg_int(cfg, "tick_scale", "1")
    stuck_threshold = (
        args.stuck_threshold
        if args.stuck_threshold is not None
        else _cfg_int(cfg, "stuck_threshold", "5000")
    )
    interrupt_stuck_threshold = (
        args.interrupt_stuck_threshold
        if args.interrupt_stuck_threshold is not None
        else _cfg_int(cfg, "interrupt_stuck_threshold", "50000000")
    )
    stuck_manual = args.stuck_manual
    if stuck_manual is None:
        stuck_manual = _parse_bool(cfg.get("stuck_manual", "false"))
    log_level = args.log_level or str(cfg.get("log_level", "INFO")).upper()
    quiet = args.quiet
    if quiet is None:
        quiet = _parse_bool(cfg.get("quiet", "false"))

    run_app(
        image_path=args.image,
        base_addr=base_addr,
        svd_path=svd_path,
        sram_base=sram_base,
        sram_size=sram_size,
        sysmem_base=sysmem_base,
        tick_scale=tick_scale,
        stuck_threshold=stuck_threshold,
        interrupt_stuck_threshold=interrupt_stuck_threshold,
        stuck_auto=not stuck_manual,
        shell=args.shell,
        cmd=args.cmd,
        log_level=log_level,
        quiet=quiet,
        args=args,
    )
    
if __name__ == "__main__":
    main()
