from __future__ import annotations

import cmd
import shlex

from stmemu.core.emulator import Emulator
from stmemu.peripherals.bus import PeripheralBus
from stmemu.shell.commands import Commands
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


class StmEmuShell(cmd.Cmd):
    intro = "stmemu interactive shell. Type 'help' for commands."
    prompt = "stmemu> "

    def __init__(self, emu: Emulator, bus: PeripheralBus):
        super().__init__()
        self.emu = emu
        self.bus = bus
        self.cmds = Commands(emu=emu, bus=bus)

    def run_script(self, script: str) -> None:
        parts = [p.strip() for p in script.split(";") if p.strip()]
        for p in parts:
            self.onecmd(p)

    def default(self, line: str) -> None:
        try:
            argv = shlex.split(line)
        except ValueError as e:
            print(f"parse error: {e}")
            return
        if not argv:
            return

        name = argv[0].replace("-", "_")
        handler = getattr(self.cmds, f"cmd_{name}", None)
        if handler is None:
            print(f"unknown command: {argv[0]}")
            return
        try:
            out = handler(argv[1:])
            if out:
                print(out)
        except Exception as e:
            log.exception("command failed")
            print(f"error: {e}")

    def do_exit(self, arg: str) -> bool:
        return True

    def do_quit(self, arg: str) -> bool:
        return True

    def do_EOF(self, arg: str) -> bool:
        print()
        return True
    
    def do_regs(self, arg: str) -> None:
        self.default("regs " + arg if arg else "regs")

    def do_step(self, arg: str) -> None:
        self.default("step " + arg if arg else "step")

    def do_run(self, arg: str) -> None:
        self.default("run " + arg if arg else "run")

    def do_mem(self, arg: str) -> None:
        self.default("mem " + arg if arg else "mem")

    def do_reg(self, arg: str) -> None:
        self.default("reg " + arg if arg else "reg")

    def do_mmio(self, arg: str) -> None:
        self.default("mmio " + arg if arg else "mmio")

    def do_mmioprof(self, arg: str) -> None:
        self.default("mmioprof " + arg if arg else "mmioprof")

    def do_pcprof(self, arg: str) -> None:
        self.default("pcprof " + arg if arg else "pcprof")

    def do_periph(self, arg: str) -> None:
        self.default("periph " + arg if arg else "periph")

    def do_image(self, arg: str) -> None:
        self.default("image " + arg if arg else "image")

    def do_stuck(self, arg: str) -> None:
        self.default("stuck " + arg if arg else "stuck")

    def do_tickscale(self, arg: str) -> None:
        self.default("tickscale " + arg if arg else "tickscale")

    def do_uart(self, arg: str) -> None:
        self.default("uart " + arg if arg else "uart")

    def do_vtbl(self, arg: str) -> None:
        self.default("vtbl " + arg if arg else "vtbl")

    def do_wp(self, arg: str) -> None:
        self.default("wp " + arg if arg else "wp")

    def do_snap(self, arg: str) -> None:
        self.default("snap " + arg if arg else "snap")

    def do_ret(self, arg: str) -> None:
        self.default("ret " + arg if arg else "ret")

    def do_stub(self, arg: str) -> None:
        self.default("stub " + arg if arg else "stub")

    def do_skip(self, arg: str) -> None:
        self.default("skip " + arg if arg else "skip")

    def do_fault(self, arg: str) -> None:
        self.default("fault " + arg if arg else "fault")

    def do_export(self, arg: str) -> None:
        self.default("export " + arg if arg else "export")

    def do_scenario(self, arg: str) -> None:
        self.default("scenario " + arg if arg else "scenario")
