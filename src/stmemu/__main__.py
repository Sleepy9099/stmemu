from __future__ import annotations

import argparse
from pathlib import Path

from stmemu.app import run_app


def main() -> None:
    p = argparse.ArgumentParser(prog="stmemu", description="STM emulator scaffold (Unicorn + SVD + interactive shell)")
    p.add_argument("image", type=Path, help="Firmware image (.bin or ELF)")
    p.add_argument(
        "--base",
        type=lambda s: int(s, 0),
        default=0x08000000,
        help="Raw binary load base (default: 0x08000000, ignored for ELF)",
    )
    p.add_argument("--svd", type=Path, required=True, help="CMSIS-SVD XML file path")

    # Memory layout defaults (reasonable for many STM32, adjust per target)
    p.add_argument("--sram-base", type=lambda s: int(s, 0), default=0x20000000)
    p.add_argument("--sram-size", type=lambda s: int(s, 0), default=0x00020000)  # 128 KiB

    # Execution controls
    p.add_argument("--shell", action="store_true", help="Start interactive shell after loading")
    p.add_argument("--cmd", type=str, default="", help='Semicolon-separated shell commands to run, e.g. "regs; step 10; run 1000"')
    p.add_argument("--cfg", help="Path to a semicolon/newline-separated startup script to run before --cmd")
    p.add_argument(
        "--tick-scale",
        type=lambda s: int(s, 0),
        default=1,
        help="Peripheral/core timer ticks to advance per emulated instruction (default: 1)",
    )
    p.add_argument(
        "--stuck-threshold",
        type=lambda s: int(s, 0),
        default=5000,
        help="Stop after this many hits at one PC when no interrupt source is available (0 disables)",
    )
    p.add_argument(
        "--interrupt-stuck-threshold",
        type=lambda s: int(s, 0),
        default=50000000,
        help="Stop after this many hits at one PC when interrupts are enabled/pending (0 disables)",
    )
    p.add_argument(
        "--stuck-manual",
        action="store_true",
        help="Use --stuck-threshold as a fixed limit instead of auto-relaxing for interrupt-driven loops",
    )

    # Logging
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--quiet", action="store_true", help="Reduce console output")

    args = p.parse_args()

    run_app(
        image_path=args.image,
        base_addr=args.base,
        svd_path=args.svd,
        sram_base=args.sram_base,
        sram_size=args.sram_size,
        tick_scale=args.tick_scale,
        stuck_threshold=args.stuck_threshold,
        interrupt_stuck_threshold=args.interrupt_stuck_threshold,
        stuck_auto=not args.stuck_manual,
        shell=args.shell,
        cmd=args.cmd,
        log_level=args.log_level,
        quiet=args.quiet,
        args=args,
    )
    
if __name__ == "__main__":
    main()
