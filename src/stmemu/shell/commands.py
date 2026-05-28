from __future__ import annotations

import csv
import json
import shlex
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from stmemu.core.emulator import Emulator, PcRegWrite
from stmemu.peripherals.bus import PeripheralBus
from stmemu.peripherals.gpio import GpioPeripheral
from stmemu.peripherals.i2c import I2cPeripheral
from stmemu.peripherals.spi import SpiPeripheral
from stmemu.peripherals.usart import Stm32UsartPeripheral
from stmemu.utils.hexdump import hexdump
from stmemu.core.disasm import ThumbDisassembler
from unicorn.unicorn_const import UC_HOOK_CODE

def _int(s: str) -> int:
    try:
        return int(s, 0)
    except ValueError:
        raise ValueError(f"invalid integer: {s!r}")


def _fmt_cov_filter(f: tuple[int, int] | None) -> str:
    if f is None:
        return "disabled"
    return f"0x{f[0]:08X}-0x{f[1]:08X}"


@dataclass
class Commands:
    emu: Emulator
    bus: PeripheralBus

    def __post_init__(self) -> None:
        self._dasm = ThumbDisassembler()
        self._checkpoint_default_name = "baseline"
        self._command_log_path: Path | None = None

    def cmd_regs(self, argv: list[str]) -> str:
        regs = self.emu.read_regs()
        keys = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","sp","lr","pc"]
        return "\n".join(f"{k:>3} = 0x{regs[k]:08X}" for k in keys)

    def cmd_step(self, argv: list[str]) -> str:
        n = _int(argv[0]) if argv else 1
        try:
            self.emu.step(n)
        except Exception as e:
            report = None
            if hasattr(self.emu, "record_fault"):
                try:
                    report = self.emu.record_fault("step_error", detail=str(e))
                except Exception:
                    report = None
            if report is not None and getattr(self.emu, "auto_fault_report", True):
                return f"error: {e}\n{self._format_fault_report(report)}"
            return f"error: {e}"
        if getattr(self.emu, "last_pc_break", None) is not None:
            return f"PC BP HIT: 0x{int(self.emu.last_pc_break):08X}"
        if getattr(self.emu, "last_watch_break", None):
            return self._format_watchpoint_hit(self.emu.last_watch_break)
        if getattr(self.emu, "last_mmio_break", None):
            b = self.emu.last_mmio_break
            val = b.get("value", None)
            val_s = "-" if val is None else f"0x{int(val):X}"
            return (
                f"MMIO BP HIT: {b['name']} "
                f"@0x{b['address']:08X} size={b['size']} "
                f"value={val_s}"
            )
        if getattr(self.emu, "last_event_break", None):
            return self._format_event_break(self.emu.last_event_break)
        return f"pc=0x{self.emu.pc:08X}"

    def cmd_run(self, argv: list[str]) -> str:
        n = _int(argv[0]) if argv else 100000
        try:
            self.emu.run(n)
        except Exception as e:
            report = None
            if hasattr(self.emu, "record_fault"):
                try:
                    report = self.emu.record_fault("run_error", detail=str(e))
                except Exception:
                    report = None
            if report is not None and getattr(self.emu, "auto_fault_report", True):
                return f"error: {e}\n{self._format_fault_report(report)}"
            return f"error: {e}"
        if getattr(self.emu, "last_pc_break", None) is not None:
            return f"PC BP HIT: 0x{int(self.emu.last_pc_break):08X}"
        if getattr(self.emu, "last_watch_break", None):
            return self._format_watchpoint_hit(self.emu.last_watch_break)
        if getattr(self.emu, "last_mmio_break", None):
            b = self.emu.last_mmio_break
            val = b.get("value", None)
            val_s = "-" if val is None else f"0x{int(val):X}"
            return (
                f"MMIO BP HIT: {b['name']} "
                f"@0x{b['address']:08X} size={b['size']} "
                f"value={val_s}"
            )
        if getattr(self.emu, "last_event_break", None):
            return self._format_event_break(self.emu.last_event_break)
        return f"pc=0x{self.emu.pc:08X}"

    def cmd_mem(self, argv: list[str]) -> str:
        if len(argv) < 1:
            return (
                "usage: mem r <addr> <len> | mem w <addr> <hexbytes|@file|hex@file> | "
                "mem load <addr> <file> | mem save <addr> <len> <file>"
            )
        op = argv[0]
        if op == "r":
            if len(argv) != 3:
                return "usage: mem r <addr> <len>"
            addr = _int(argv[1]); ln = _int(argv[2])
            data = self.emu.mem_read(addr, ln)
            return hexdump(data, base=addr)
        if op == "w":
            if len(argv) != 3:
                return "usage: mem w <addr> <hexbytes|@file|hex@file>"
            addr = _int(argv[1])
            try:
                data = self._read_bytes_spec(argv[2])
            except Exception as e:
                return f"error: {e}"
            self.emu.mem_write(addr, data)
            return f"wrote {len(data)} bytes to 0x{addr:08X}"
        if op == "load":
            if len(argv) != 3:
                return "usage: mem load <addr> <file>"
            addr = _int(argv[1])
            try:
                data = Path(argv[2]).expanduser().read_bytes()
            except OSError as e:
                return f"error: {e}"
            self.emu.mem_write(addr, data)
            return f"loaded {len(data)} bytes from {argv[2]} into 0x{addr:08X}"
        if op == "save":
            if len(argv) != 4:
                return "usage: mem save <addr> <len> <file>"
            addr = _int(argv[1])
            ln = _int(argv[2])
            if ln < 0:
                return "len must be >= 0"
            try:
                data = bytes(self.emu.mem_read(addr, ln))
                path = self._prepare_export_path(argv[3])
                path.write_bytes(data)
            except Exception as e:
                return f"error: {e}"
            return f"saved {len(data)} bytes from 0x{addr:08X} to {path}"
        return (
            "usage: mem r <addr> <len> | mem w <addr> <hexbytes|@file|hex@file> | "
            "mem load <addr> <file> | mem save <addr> <len> <file>"
        )

    def cmd_mmio(self, argv: list[str]) -> str:
        if len(argv) != 2 or argv[0] != "log":
            return "usage: mmio log on|off"
        self.bus.mmio_log_enabled = (argv[1].lower() == "on")
        return f"mmio log = {'on' if self.bus.mmio_log_enabled else 'off'}"

    def _collect_mmioprof_data(self, steps: int, top: int) -> dict[str, object]:
        reads: Counter[tuple[int, int]] = Counter()
        writes: Counter[tuple[int, int]] = Counter()
        orig_read = self.bus.read
        orig_write = self.bus.write

        def wrapped_read(addr: int, size: int) -> int:
            reads[(int(addr), int(size))] += 1
            return orig_read(addr, size)

        def wrapped_write(addr: int, size: int, value: int) -> None:
            writes[(int(addr), int(size))] += 1
            return orig_write(addr, size, value)

        self.bus.read = wrapped_read
        self.bus.write = wrapped_write
        try:
            self.emu.run(steps)
        finally:
            self.bus.read = orig_read
            self.bus.write = orig_write

        read_rows = [
            {
                "count": int(n),
                "addr": int(addr),
                "size": int(size),
                "label": self._describe_mmio_addr(addr),
            }
            for (addr, size), n in reads.most_common(top)
        ]
        write_rows = [
            {
                "count": int(n),
                "addr": int(addr),
                "size": int(size),
                "label": self._describe_mmio_addr(addr),
            }
            for (addr, size), n in writes.most_common(top)
        ]
        return {
            "pc": int(self.emu.pc),
            "instructions": int(steps),
            "read_events": int(sum(reads.values())),
            "write_events": int(sum(writes.values())),
            "reads": read_rows,
            "writes": write_rows,
        }

    def cmd_mmioprof(self, argv: list[str]) -> str:
        if not argv:
            return "usage: mmioprof <instructions> [top]"
        steps = _int(argv[0])
        if steps <= 0:
            return "instructions must be > 0"
        top = _int(argv[1]) if len(argv) > 1 else 20
        top = max(1, min(int(top), 100))
        data = self._collect_mmioprof_data(int(steps), int(top))
        return self._format_mmioprof_data(data)

    def _format_mmioprof_data(self, data: dict[str, object]) -> str:
        lines = [
            f"pc = 0x{int(data['pc']):08X}",
            f"instructions = {int(data['instructions'])}",
            f"read_events = {int(data['read_events'])}",
            f"write_events = {int(data['write_events'])}",
            "",
            "top reads:",
        ]
        reads = list(data.get("reads", []))
        if reads:
            for row in reads:
                lines.append(
                    f"{int(row['count']):8d}  {str(row['label']):30} "
                    f"addr=0x{int(row['addr']):08X} size={int(row['size'])}"
                )
        else:
            lines.append("(none)")

        lines.append("")
        lines.append("top writes:")
        writes = list(data.get("writes", []))
        if writes:
            for row in writes:
                lines.append(
                    f"{int(row['count']):8d}  {str(row['label']):30} "
                    f"addr=0x{int(row['addr']):08X} size={int(row['size'])}"
                )
        else:
            lines.append("(none)")
        return "\n".join(lines)

    def _collect_pcprof_data(self, steps: int, top: int) -> dict[str, object]:
        pcs: Counter[int] = Counter()

        def wrapped_code(uc, address, size, user_data):
            pcs[int(address) & ~1] += 1

        hook = None
        try:
            hook = self.emu.uc.hook_add(UC_HOOK_CODE, wrapped_code)
            self.emu.run(steps)
        finally:
            if hook is not None:
                try:
                    self.emu.uc.hook_del(hook)
                except Exception:
                    pass

        executed = int(sum(pcs.values()))
        entries = []
        for addr, n in pcs.most_common(top):
            pct = (float(n) * 100.0 / float(executed)) if executed else 0.0
            entries.append(
                {
                    "count": int(n),
                    "pct": float(pct),
                    "pc": int(addr),
                    "disasm": self._disasm_one(addr),
                }
            )
        return {
            "pc": int(self.emu.pc),
            "instructions_requested": int(steps),
            "instructions_executed": executed,
            "entries": entries,
        }

    def cmd_pcprof(self, argv: list[str]) -> str:
        if not argv:
            return "usage: pcprof <instructions> [top]"

        steps = _int(argv[0])
        if steps <= 0:
            return "instructions must be > 0"

        top = _int(argv[1]) if len(argv) > 1 else 20
        top = max(1, min(int(top), 100))
        data = self._collect_pcprof_data(int(steps), int(top))
        return self._format_pcprof_data(data)

    def _format_pcprof_data(self, data: dict[str, object]) -> str:
        lines = [
            f"pc = 0x{int(data['pc']):08X}",
            f"instructions_requested = {int(data['instructions_requested'])}",
            f"instructions_executed = {int(data['instructions_executed'])}",
            "",
            "top pcs:",
        ]

        entries = list(data.get("entries", []))
        if entries:
            for row in entries:
                lines.append(
                    f"{int(row['count']):8d}  {float(row['pct']):6.2f}%  "
                    f"0x{int(row['pc']):08X}  {str(row['disasm'])}"
                )
        else:
            lines.append("(none)")

        return "\n".join(lines)

    def cmd_periph(self, argv: list[str]) -> str:
        if not argv:
            return "usage: periph list | periph read <P.REG|addr> | periph write <P.REG|addr> <value>"
        sub = argv[0]

        if sub == "list":
            lines = []
            for p in self.bus.amap.peripherals:
                lines.append(f"{p.name:20} base=0x{p.base_address:08X} size=0x{p.size:X} regs={len(p.registers)}")
            return "\n".join(lines) if lines else "(no peripherals)"

        if sub == "read":
            if len(argv) != 2:
                return "usage: periph read <P.REG|addr>"
            addr = self._resolve_periph_addr(argv[1])
            val = self.bus.read(addr, 4)
            lines = [f"[0x{addr:08X}] = 0x{val:08X}"]
            # Field decode: find the peripheral and register for this address
            p = self.bus.amap.find_peripheral(addr)
            if p is not None:
                reg = self.bus.amap.find_register(p, addr)
                if reg is not None and reg.fields:
                    for f in sorted(reg.fields, key=lambda f: f.bit_offset, reverse=True):
                        mask = (1 << f.bit_width) - 1
                        fval = (val >> f.bit_offset) & mask
                        bits = f"[{f.bit_offset + f.bit_width - 1}:{f.bit_offset}]" if f.bit_width > 1 else f"[{f.bit_offset}]"
                        lines.append(f"  {f.name:20} {bits:>8} = 0x{fval:X} ({fval})")
            return "\n".join(lines)

        if sub == "write":
            if len(argv) != 3:
                return "usage: periph write <P.REG|addr> <value>"
            addr = self._resolve_periph_addr(argv[1])
            val = _int(argv[2])
            self.bus.write(addr, 4, val)
            return f"[0x{addr:08X}] <- 0x{val:08X}"

        return "usage: periph list | periph read <P.REG|addr> | periph write <P.REG|addr> <value>"

    def cmd_uart(self, argv: list[str]) -> str:
        usage = (
            "usage: uart list | uart status <name> | uart rx <name> <hexbytes|@file|hex@file> | "
            "uart tx <name> [clear] | uart txsave <name> <file> [clear] | "
            "uart waittx <name> <min_len> [max_steps] | "
            "uart xfer <name> <hexbytes|@file|hex@file> [steps] "
            "[expect <hexbytes|@file|hex@file>] [expect-prefix <hexbytes|@file|hex@file>] [clear] | "
            "uart sweep <name> <snapshot> <steps> <cmd1> [cmd2 ...] | "
            "uart sweepfile <name> <snapshot> <steps> <file>"
        )
        if not argv:
            return usage

        sub = argv[0].lower()
        if sub == "list":
            lines: list[str] = []
            for peripheral in self.bus.amap.peripherals:
                model = self.bus.model_for_name(peripheral.name)
                if isinstance(model, Stm32UsartPeripheral):
                    lines.append(f"{peripheral.name:8} {model.status_summary()}")
            return "\n".join(lines) if lines else "(no uart peripherals)"

        if sub == "status":
            if len(argv) != 2:
                return "usage: uart status <name>"
            model = self._resolve_uart_model(argv[1])
            return f"{argv[1].upper()} {model.status_summary()}"

        if sub == "rx":
            if len(argv) != 3:
                return "usage: uart rx <name> <hexbytes|@file|hex@file>"
            model = self._resolve_uart_model(argv[1])
            try:
                payload = self._read_bytes_spec(argv[2])
            except Exception as e:
                return f"error: {e}"
            model.inject_rx_bytes(payload)
            return f"injected {len(payload)} byte(s) into {argv[1].upper()}"

        if sub == "tx":
            if len(argv) not in {2, 3}:
                return "usage: uart tx <name> [clear]"
            model = self._resolve_uart_model(argv[1])
            clear = len(argv) == 3 and argv[2].lower() == "clear"
            payload = model.drain_tx_bytes() if clear else model.peek_tx_bytes()
            return self._format_uart_tx(argv[1], payload)

        if sub == "txsave":
            if len(argv) not in {3, 4}:
                return "usage: uart txsave <name> <file> [clear]"
            model = self._resolve_uart_model(argv[1])
            clear = len(argv) == 4 and argv[3].lower() == "clear"
            payload = model.drain_tx_bytes() if clear else model.peek_tx_bytes()
            try:
                path = self._prepare_export_path(argv[2])
                path.write_bytes(payload)
            except OSError as e:
                return f"error: {e}"
            return f"saved {len(payload)} byte(s) from {argv[1].upper()} tx to {path}"

        if sub == "waittx":
            if len(argv) not in {3, 4}:
                return "usage: uart waittx <name> <min_len> [max_steps]"
            model = self._resolve_uart_model(argv[1])
            min_len = _int(argv[2])
            if min_len < 0:
                return "min_len must be >= 0"
            max_steps = _int(argv[3]) if len(argv) == 4 else 100000
            if max_steps < 0:
                return "max_steps must be >= 0"

            steps = 0
            while len(model.peek_tx_bytes()) < int(min_len) and steps < int(max_steps):
                self.emu.step(1)
                steps += 1

            payload = model.peek_tx_bytes()
            if len(payload) < int(min_len):
                return (
                    f"error: waittx timeout name={argv[1].upper()} got={len(payload)} "
                    f"need={int(min_len)} steps={steps}"
                )
            return f"waittx ready: {argv[1].upper()} steps={steps}\n" + self._format_uart_tx(argv[1], payload)

        if sub == "xfer":
            if len(argv) < 3:
                return (
                    "usage: uart xfer <name> <hexbytes> [steps] "
                    "[expect <hexbytes>] [expect-prefix <hexbytes>] [clear]"
                )
            model = self._resolve_uart_model(argv[1])
            try:
                rx_payload = self._read_bytes_spec(argv[2])
            except Exception as e:
                return f"error: {e}"

            steps = 100000
            expect_exact: bytes | None = None
            expect_prefix: bytes | None = None
            clear = False
            i = 3
            if i < len(argv):
                try:
                    steps = _int(argv[i])
                    i += 1
                except Exception:
                    pass
            while i < len(argv):
                tok = argv[i].lower()
                if tok == "clear":
                    clear = True
                    i += 1
                    continue
                if tok in {"expect", "expect-prefix"}:
                    if i + 1 >= len(argv):
                        return (
                            "usage: uart xfer <name> <hexbytes> [steps] "
                            "[expect <hexbytes>] [expect-prefix <hexbytes>] [clear]"
                        )
                    try:
                        val = self._read_bytes_spec(argv[i + 1])
                    except Exception as e:
                        return f"error: {e}"
                    if tok == "expect":
                        expect_exact = val
                    else:
                        expect_prefix = val
                    i += 2
                    continue
                return (
                    "usage: uart xfer <name> <hexbytes> [steps] "
                    "[expect <hexbytes>] [expect-prefix <hexbytes>] [clear]"
                )

            if steps < 0:
                return "steps must be >= 0"
            model.inject_rx_bytes(rx_payload)
            if steps > 0:
                try:
                    self.emu.run(steps)
                except Exception as e:
                    return f"error: {e}"
            tx_payload = model.drain_tx_bytes() if clear else model.peek_tx_bytes()
            if expect_exact is not None and tx_payload != expect_exact:
                return (
                    f"error: uart xfer expected={expect_exact.hex() or '-'} "
                    f"got={tx_payload.hex() or '-'}"
                )
            if expect_prefix is not None and not tx_payload.startswith(expect_prefix):
                return (
                    f"error: uart xfer expected-prefix={expect_prefix.hex() or '-'} "
                    f"got={tx_payload.hex() or '-'}"
                )

            lines = [
                f"{argv[1].upper()} xfer steps={steps} clear={'1' if clear else '0'}",
                f"rx_len={len(rx_payload)} rx_hex={rx_payload.hex() or '-'}",
                self._format_uart_tx(argv[1], tx_payload),
            ]
            if expect_exact is not None:
                lines.append("match = ok (exact)")
            if expect_prefix is not None:
                lines.append("match = ok (prefix)")
            return "\n".join(lines)

        if sub == "sweep":
            if len(argv) < 5:
                return "usage: uart sweep <name> <snapshot> <steps> <hexcmd1> [hexcmd2 ...]"
            name = argv[1]
            snapshot_name = argv[2]
            steps = _int(argv[3])
            if steps < 0:
                return "steps must be >= 0"

            commands = argv[4:]
            failed = 0
            lines = [
                (
                    f"uart sweep name={name.upper()} snapshot={snapshot_name} "
                    f"steps={steps} count={len(commands)}"
                )
            ]
            for idx, hex_cmd in enumerate(commands, start=1):
                load_out = self.cmd_snap(["load", snapshot_name])
                if load_out.startswith("unknown snapshot:"):
                    return load_out
                out = self.cmd_uart(["xfer", name, hex_cmd, str(steps), "clear"])
                is_error = out.lower().startswith("error:")
                if is_error:
                    failed += 1
                tx_hex = "-"
                for row in out.splitlines():
                    if row.startswith("hex  = "):
                        tx_hex = row.split("=", 1)[1].strip()
                        break
                lines.append(
                    f"[{idx}] cmd={hex_cmd} status={'error' if is_error else 'ok'} tx={tx_hex}"
                )
                if is_error:
                    lines.append("    " + out)
            lines.insert(1, f"summary passed={len(commands) - failed} failed={failed}")
            return "\n".join(lines)

        if sub == "sweepfile":
            if len(argv) != 5:
                return "usage: uart sweepfile <name> <snapshot> <steps> <file>"
            name = argv[1]
            snapshot_name = argv[2]
            steps = _int(argv[3])
            if steps < 0:
                return "steps must be >= 0"
            path = Path(argv[4]).expanduser()
            try:
                raw_lines = path.read_text(encoding="utf-8").splitlines()
            except OSError as e:
                return f"error: {e}"

            entries: list[tuple[str, str, str | None, int]] = []
            for lineno, raw in enumerate(raw_lines, start=1):
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                try:
                    toks = shlex.split(stripped)
                except ValueError as e:
                    return f"error: sweepfile parse {path}:{lineno}: {e}"
                if len(toks) == 1:
                    entries.append((toks[0], "", None, lineno))
                    continue
                if len(toks) == 3 and toks[1] in {"=>", "~>"}:
                    entries.append((toks[0], toks[1], toks[2], lineno))
                    continue
                return (
                    f"error: sweepfile parse {path}:{lineno}: "
                    "expected '<cmd>', '<cmd> => <expect>', or '<cmd> ~> <prefix>'"
                )

            failed = 0
            lines = [
                (
                    f"uart sweepfile name={name.upper()} snapshot={snapshot_name} "
                    f"steps={steps} file={path} count={len(entries)}"
                )
            ]
            for idx, (cmd_spec, op, expect_spec, lineno) in enumerate(entries, start=1):
                load_out = self.cmd_snap(["load", snapshot_name])
                if load_out.startswith("unknown snapshot:"):
                    return load_out
                xfer_argv = ["xfer", name, cmd_spec, str(steps), "clear"]
                if op == "=>":
                    xfer_argv.extend(["expect", str(expect_spec)])
                elif op == "~>":
                    xfer_argv.extend(["expect-prefix", str(expect_spec)])
                out = self.cmd_uart(xfer_argv)
                is_error = out.lower().startswith("error:")
                if is_error:
                    failed += 1
                tx_hex = "-"
                for row in out.splitlines():
                    if row.startswith("hex  = "):
                        tx_hex = row.split("=", 1)[1].strip()
                        break
                lines.append(
                    f"[{idx}] line={lineno} cmd={cmd_spec} status={'error' if is_error else 'ok'} tx={tx_hex}"
                )
                if is_error:
                    lines.append("    " + out)
            lines.insert(1, f"summary passed={len(entries) - failed} failed={failed}")
            return "\n".join(lines)

        return usage

    @staticmethod
    def _format_uart_tx(name: str, payload: bytes) -> str:
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in payload)
        return (
            f"{name.upper()} tx_len={len(payload)}\n"
            f"hex  = {payload.hex() or '-'}\n"
            f"ascii= {text or '-'}"
        )

    def cmd_vtbl(self, argv: list[str]) -> str:
        if not argv:
            return "usage: vtbl <addr> [count] | vtbl obj <addr> [count]"

        obj_mode = argv[0].lower() == "obj"
        if obj_mode:
            if len(argv) not in {2, 3}:
                return "usage: vtbl obj <addr> [count]"
            obj_addr = _int(argv[1])
            count = _int(argv[2]) if len(argv) == 3 else 8
            vtbl_addr = int.from_bytes(self.emu.mem_read(obj_addr, 4), "little")
            lines = [f"object = 0x{obj_addr:08X}", f"vtable = 0x{vtbl_addr:08X}"]
        else:
            if len(argv) not in {1, 2}:
                return "usage: vtbl <addr> [count] | vtbl obj <addr> [count]"
            vtbl_addr = _int(argv[0])
            count = _int(argv[1]) if len(argv) == 2 else 8
            lines = [f"vtable = 0x{vtbl_addr:08X}"]

        count = max(1, min(int(count), 64))
        for index in range(count):
            slot_addr = vtbl_addr + (index * 4)
            value = int.from_bytes(self.emu.mem_read(slot_addr, 4), "little")
            lines.append(self._format_pointer_slot(index, slot_addr, value))
        return "\n".join(lines)

    def cmd_peekpc(self, argv: list[str]) -> str:
        n = _int(argv[0]) if argv else 64
        pc = self.emu.pc
        addr = pc & ~1  # thumb bit is sometimes reflected, be safe
        data = self.emu.mem_read(addr, n)
        return hexdump(data, base=addr)

    def _resolve_periph_addr(self, s: str) -> int:
        # Accept "0x40021018" or "RCC.APB2ENR"
        if s.startswith("0x") or s.isdigit():
            return _int(s)

        if "." not in s:
            raise ValueError("expected P.REG or address")
        p_name, r_name = s.split(".", 1)

        p = self.bus.amap.find_peripheral_by_name(p_name)
        if not p:
            raise KeyError(f"unknown peripheral: {p_name}")

        r_upper = r_name.upper()
        r = next((x for x in p.registers if x.name.upper() == r_upper), None)
        if not r:
            raise KeyError(f"unknown register: {p_name}.{r_name}")

        return p.base_address + r.offset

    def _resolve_uart_model(self, name: str) -> Stm32UsartPeripheral:
        model = self.bus.model_for_name(name)
        if not isinstance(model, Stm32UsartPeripheral):
            raise KeyError(f"unknown uart peripheral: {name}")
        return model

    def _describe_mmio_addr(self, addr: int) -> str:
        peripheral = self.bus.amap.find_peripheral(addr)
        if peripheral is None:
            return f"0x{addr:08X}"
        reg = self.bus.amap.find_register(peripheral, addr)
        if reg is None:
            return f"{peripheral.name}+0x{addr - peripheral.base_address:X}"
        return f"{peripheral.name}.{reg.name}"

    def _format_pointer_slot(self, index: int, slot_addr: int, value: int) -> str:
        target = value & ~1
        suffix = self._describe_pointer_target(value)
        return f"[{index:02d}] 0x{slot_addr:08X}: 0x{value:08X}{suffix}"

    def _describe_pointer_target(self, value: int) -> str:
        target = value & ~1
        if value & 1 and self.emu.flash_base <= target < self.emu.flash_end:
            summary = self._disasm_one(target)
            return f" -> code 0x{target:08X} {summary}"
        if self.emu.flash_base <= value < self.emu.flash_end:
            return f" -> flash 0x{value:08X}"
        if self.emu.sram_base <= value < (self.emu.sram_base + self.emu.sram_size):
            return f" -> sram 0x{value:08X}"
        peripheral = self.bus.amap.find_peripheral(value)
        if peripheral is not None:
            return f" -> mmio {peripheral.name}+0x{value - peripheral.base_address:X}"
        return ""

    def _disasm_one(self, addr: int) -> str:
        try:
            code = self.emu.mem_read(addr & ~1, 4)
            insns = self._dasm.disasm(code, addr & ~1, count=1)
        except Exception:
            return "(unreadable)"
        if not insns:
            return "(undecoded)"
        ins = insns[0]
        return f"{ins.mnemonic} {ins.op_str}".rstrip()

    def cmd_disasm(self, argv: list[str]) -> str:
        """
        disasm [addr] [nbytes]
        If addr omitted, uses current PC.
        """
        if argv:
            addr = _int(argv[0])
        else:
            addr = self.emu.pc

        # Thumb: clear bit0 for memory fetch
        addr &= ~1

        nbytes = _int(argv[1]) if len(argv) > 1 else 64
        code = self.emu.mem_read(addr, nbytes)

        insns = self._dasm.disasm(code, addr)
        if not insns:
            return f"(no instructions decoded at 0x{addr:08X})"

        lines = []
        for ins in insns[:50]:
            lines.append(f"{ins.address:08X}  {ins.bytes_hex:<10}  {ins.mnemonic} {ins.op_str}".rstrip())
        return "\n".join(lines)

    def cmd_poll(self, argv: list[str]) -> str:
        """
        poll [addr]
        Disassembles a few instructions at addr (or PC) and tries to guess
        if we're polling a memory-mapped register.
        """
        addr = (_int(argv[0]) if argv else self.emu.pc) & ~1
        code = self.emu.mem_read(addr, 64)
        insns = self._dasm.disasm(code, addr)

        lines = []
        for ins in insns[:12]:
            lines.append(f"{ins.address:08X}  {ins.bytes_hex:<10}  {ins.mnemonic} {ins.op_str}".rstrip())

        # Heuristic: look for ldr rt, [pc, #imm] which loads an absolute address from a literal pool
        guess = []
        for ins in insns[:12]:
            if ins.mnemonic == "ldr" and ins.op_str.startswith("r") and "[pc" in ins.op_str:
                # Example: "r3, [pc, #0x1c]"
                guess.append(f"Possible literal load: {ins.mnemonic} {ins.op_str} @0x{ins.address:08X}")

        out = "\n".join(lines)
        if guess:
            out += "\n\n" + "\n".join(guess)

        return out

    def cmd_reg(self, argv: list[str]) -> str:
        if len(argv) == 1:
            name = argv[0].lower()
            regs = self.emu.read_regs()
            if name not in regs:
                return f"unknown reg: {name}"
            return f"{name} = 0x{regs[name]:08X}"

        if len(argv) == 3 and argv[0].lower() == "set":
            name = argv[1].lower()
            value = _int(argv[2])
            try:
                self.emu.write_reg(name, value)
            except KeyError:
                return f"unknown reg: {name}"
            regs = self.emu.read_regs()
            if name in regs:
                return f"{name} <- 0x{regs[name]:08X}"
            return f"{name} <- 0x{(int(value) & 0xFFFFFFFF):08X}"

        return "usage: reg <r0..r12|sp|lr|pc> | reg set <r0..r12|sp|lr|pc> <value>"

    @staticmethod
    def _parse_range_spec(spec: str) -> tuple[int, int]:
        s = spec.strip()
        if "-" in s:
            left, right = s.split("-", 1)
            start = _int(left)
            end = _int(right)
        else:
            start = _int(s)
            end = start
        if end < start:
            start, end = end, start
        return int(start), int(end)

    @staticmethod
    def _format_watchpoint_hit(hit: dict[str, object]) -> str:
        value = hit.get("value")
        value_s = "-" if value is None else f"0x{int(value):X}"
        return (
            f"WP HIT: #{int(hit.get('id', -1))} "
            f"[{int(hit.get('start', 0)):08X}-{int(hit.get('end', 0)):08X}] "
            f"({str(hit.get('access', '?'))}) "
            f"@0x{int(hit.get('address', 0)):08X} size={int(hit.get('size', 0))} "
            f"value={value_s}"
        )

    @staticmethod
    def _format_event_break(eb: dict[str, object]) -> str:
        kind = str(eb.get("kind", "?"))
        source = str(eb.get("source", ""))
        pc = int(eb.get("pc", 0))
        bp_id = int(eb.get("bp_id", 0))
        payload = eb.get("payload")
        parts = [f"EVENT BP HIT: #{bp_id} {kind}"]
        if source:
            parts[0] += f" source={source}"
        parts.append(f"pc=0x{pc:08X}")
        if isinstance(payload, dict):
            for k, v in list(payload.items())[:6]:
                parts.append(f"{k}={v}")
        return " ".join(parts)

    @staticmethod
    def _format_fault_report(report: dict[str, object]) -> str:
        reason = str(report.get("reason", "fault"))
        detail = str(report.get("detail", "") or "")
        pc = int(report.get("pc", 0))
        active_num = int(report.get("active_exception", 0))
        active_name = str(report.get("active_exception_name", "Thread"))
        depth = int(report.get("exception_depth", 0))
        cfsr = int(report.get("cfsr", 0))
        hfsr = int(report.get("hfsr", 0))
        mmfar = int(report.get("mmfar", 0))
        bfar = int(report.get("bfar", 0))
        icsr = int(report.get("icsr", 0))
        cfsr_flags = report.get("cfsr_flags", []) or []
        hfsr_flags = report.get("hfsr_flags", []) or []

        regs = report.get("regs", {}) or {}
        def _rv(name: str) -> int:
            return int(regs.get(name, 0)) & 0xFFFFFFFF

        lines = [
            f"fault reason = {reason}",
            f"pc          = 0x{pc:08X}",
            f"exception   = {active_name} ({active_num}) depth={depth}",
            f"icsr        = 0x{icsr:08X}",
            f"cfsr        = 0x{cfsr:08X}" + ("" if not cfsr_flags else f" [{', '.join(str(x) for x in cfsr_flags)}]"),
            f"hfsr        = 0x{hfsr:08X}" + ("" if not hfsr_flags else f" [{', '.join(str(x) for x in hfsr_flags)}]"),
            f"mmfar       = 0x{mmfar:08X}",
            f"bfar        = 0x{bfar:08X}",
            (
                "regs        = "
                f"r0=0x{_rv('r0'):08X} r1=0x{_rv('r1'):08X} r2=0x{_rv('r2'):08X} r3=0x{_rv('r3'):08X} "
                f"r12=0x{_rv('r12'):08X} sp=0x{_rv('sp'):08X} lr=0x{_rv('lr'):08X} pc=0x{_rv('pc'):08X}"
            ),
        ]
        if detail:
            lines.insert(1, f"detail      = {detail}")

        stacked = report.get("stacked_frame")
        if isinstance(stacked, dict):
            lines.append(
                "stacked     = "
                f"{stacked.get('stack', '?')} sp=0x{int(stacked.get('sp', 0)):08X} "
                f"exc_return=0x{int(stacked.get('exc_return', 0)):08X}"
            )
            lines.append(
                "stacked-reg = "
                f"r0=0x{int(stacked.get('r0', 0)):08X} r1=0x{int(stacked.get('r1', 0)):08X} "
                f"r2=0x{int(stacked.get('r2', 0)):08X} r3=0x{int(stacked.get('r3', 0)):08X} "
                f"r12=0x{int(stacked.get('r12', 0)):08X} lr=0x{int(stacked.get('lr', 0)):08X} "
                f"pc=0x{int(stacked.get('pc', 0)):08X} xpsr=0x{int(stacked.get('xpsr', 0)):08X}"
            )

        pending_irqs = report.get("pending_irqs", []) or []
        pending_system = report.get("pending_system", []) or []
        if pending_irqs or pending_system:
            irq_s = ",".join(str(int(x)) for x in pending_irqs) if pending_irqs else "-"
            sys_s = ",".join(str(x) for x in pending_system) if pending_system else "-"
            lines.append(f"pending     = irq:{irq_s} sys:{sys_s}")
        return "\n".join(lines)

    def cmd_fault(self, argv: list[str]) -> str:
        """
        fault
        fault show|last
        fault clear
        fault auto on|off
        """
        if not argv or argv[0].lower() in ("show", "last"):
            report = getattr(self.emu, "last_fault_report", None)
            if report is None and hasattr(self.emu, "capture_fault_report"):
                report = self.emu.capture_fault_report("status")
            if report is None:
                return "fault report unavailable"
            return self._format_fault_report(report)

        sub = argv[0].lower()
        if sub == "clear":
            if hasattr(self.emu, "clear_fault_report"):
                self.emu.clear_fault_report()
                return "fault report cleared"
            setattr(self.emu, "last_fault_report", None)
            return "fault report cleared"

        if sub == "auto":
            if len(argv) == 1:
                return "fault auto = " + ("on" if getattr(self.emu, "auto_fault_report", True) else "off")
            if len(argv) != 2 or argv[1].lower() not in ("on", "off"):
                return "usage: fault auto on|off"
            enabled = argv[1].lower() == "on"
            setattr(self.emu, "auto_fault_report", enabled)
            return "fault auto = " + ("on" if enabled else "off")

        return "usage: fault [show|last|clear|auto on|off]"

    def cmd_wp(self, argv: list[str]) -> str:
        """wp [list] | wp add <addr|start-end> [r|w|x|rw|rx|wx|rwx] | wp clear [all|id]"""
        if not argv or argv[0].lower() == "list":
            items = self.emu.list_watchpoints() if hasattr(self.emu, "list_watchpoints") else []
            if not items:
                return "watchpoints: (none)"
            lines = ["watchpoints:"]
            for wp in items:
                lines.append(
                    f"  #{int(wp['id'])} {wp['name']} "
                    f"[{int(wp['start']):08X}-{int(wp['end']):08X}] ({wp['access']})"
                )
            return "\n".join(lines)

        sub = argv[0].lower()
        if sub == "add":
            if len(argv) not in (2, 3):
                return "usage: wp add <addr|start-end> [r|w|x|rw|rx|wx|rwx]"
            try:
                start, end = self._parse_range_spec(argv[1])
            except Exception:
                return "usage: wp add <addr|start-end> [r|w|x|rw|rx|wx|rwx]"
            access = argv[2].lower() if len(argv) == 3 else "rw"
            try:
                wid = self.emu.add_watchpoint(start, end, access=access, name=argv[1])
            except ValueError as e:
                return str(e)
            return f"added watchpoint #{wid}: [{start:08X}-{end:08X}] ({access})"

        if sub == "clear":
            if len(argv) == 1 or (len(argv) == 2 and argv[1].lower() == "all"):
                if not hasattr(self.emu, "clear_watchpoints"):
                    return "watchpoint clear is not supported by this emulator build"
                n = self.emu.clear_watchpoints()
                return f"cleared watchpoints: {n}"
            if len(argv) != 2:
                return "usage: wp clear [all|id]"
            try:
                wid = _int(argv[1])
            except Exception:
                return "usage: wp clear [all|id]"
            ok = self.emu.remove_watchpoint(wid) if hasattr(self.emu, "remove_watchpoint") else False
            if not ok:
                return f"watchpoint not found: {wid}"
            return f"cleared watchpoint: {wid}"

        return "usage: wp [list] | wp add <addr|start-end> [r|w|x|rw|rx|wx|rwx] | wp clear [all|id]"

    @staticmethod
    def _snapshot_mem_bytes(snapshot) -> int:
        total = 0
        for chunk in getattr(snapshot, "memory", ()):
            data = getattr(chunk, "data", b"")
            if isinstance(data, (bytes, bytearray)):
                total += len(data)
        return total

    def _snapshot_diff_data(self, left, right) -> dict[str, object]:
        raw = self.emu.diff_snapshots(left, right)
        reg_changes: list[dict[str, object]] = []
        for name, old, new in raw.get("reg_changes", []):
            reg_changes.append(
                {
                    "name": str(name),
                    "old": None if old is None else int(old) & 0xFFFFFFFF,
                    "new": None if new is None else int(new) & 0xFFFFFFFF,
                }
            )
        ranges: list[dict[str, int]] = []
        for start, end in raw.get("memory_changed_ranges", []):
            s = int(start) & 0xFFFFFFFF
            e = int(end) & 0xFFFFFFFF
            ranges.append({"start": s, "end": e, "size": max(0, e - s)})
        return {
            "left": str(raw.get("left", left.name)),
            "right": str(raw.get("right", right.name)),
            "reg_changes": reg_changes,
            "memory_changed_bytes": int(raw.get("memory_changed_bytes", 0)),
            "memory_changed_ranges": ranges,
        }

    def _format_snapshot_diff_data(self, data: dict[str, object]) -> str:
        reg_changes = list(data.get("reg_changes", []))
        mem_ranges = list(data.get("memory_changed_ranges", []))
        mem_bytes = int(data.get("memory_changed_bytes", 0))
        left_name = str(data.get("left", "left"))
        right_name = str(data.get("right", "right"))

        lines = [
            f"snapshot diff: {left_name} -> {right_name}",
            f"reg changes = {len(reg_changes)}",
        ]
        for row in reg_changes[:32]:
            name = str(row.get("name", "?"))
            old = row.get("old")
            new = row.get("new")
            old_s = "-" if old is None else f"0x{int(old):08X}"
            new_s = "-" if new is None else f"0x{int(new):08X}"
            lines.append(f"  {name:10} {old_s} -> {new_s}")
        if len(reg_changes) > 32:
            lines.append(f"  ... ({len(reg_changes) - 32} more)")

        lines.append(f"memory changed bytes = {mem_bytes}")
        lines.append(f"memory changed ranges = {len(mem_ranges)}")
        for row in mem_ranges[:32]:
            start = int(row.get("start", 0))
            end = int(row.get("end", 0))
            size = int(row.get("size", max(0, end - start)))
            lines.append(f"  [0x{start:08X}-0x{end:08X}) size=0x{size:X}")
        if len(mem_ranges) > 32:
            lines.append(f"  ... ({len(mem_ranges) - 32} more)")
        return "\n".join(lines)

    def cmd_break(self, argv: list[str]) -> str:
        usage = (
            "usage: break event <kind> [source=NAME] | "
            "break event list | break event remove <id> | break event clear"
        )
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub != "event":
            return usage

        if len(argv) == 1:
            return usage

        action = argv[1].lower()

        if action == "list":
            bps = self.emu.list_event_breakpoints()
            if not bps:
                return "(no event breakpoints)"
            lines = [f"{len(bps)} event breakpoint(s):"]
            for bp in bps:
                src = f" source={bp['source']}" if bp.get("source") else ""
                lines.append(
                    f"  #{bp['id']} {bp['kind']}{src} "
                    f"hits={bp['hits']} {'ON' if bp['enabled'] else 'off'}"
                )
            return "\n".join(lines)

        if action == "remove":
            if len(argv) != 3:
                return "usage: break event remove <id>"
            bp_id = _int(argv[2])
            if self.emu.remove_event_breakpoint(bp_id):
                return f"removed event breakpoint #{bp_id}"
            return f"event breakpoint not found: {bp_id}"

        if action == "clear":
            count = self.emu.clear_event_breakpoints()
            return f"cleared {count} event breakpoint(s)"

        kind = action
        source = None
        for tok in argv[2:]:
            if tok.lower().startswith("source="):
                source = tok.split("=", 1)[1]

        bp_id = self.emu.add_event_breakpoint(kind, source=source)
        desc = f"added event breakpoint #{bp_id}: {kind}"
        if source:
            desc += f" source={source}"
        return desc

    def cmd_snap(self, argv: list[str]) -> str:
        """
        snap list
        snap save <name>
        snap load <name>
        snap diff <name> [other|current]
        snap clear <name|all>
        """
        if not argv or argv[0].lower() == "list":
            names = self.emu.list_snapshots() if hasattr(self.emu, "list_snapshots") else []
            if not names:
                return "snapshots: (none)"
            lines = ["snapshots:"]
            for name in names:
                snap = self.emu.get_snapshot(name)
                if snap is None:
                    continue
                pc = int(snap.regs.get("pc", 0))
                mem_bytes = self._snapshot_mem_bytes(snap)
                lines.append(f"  {name:16} pc=0x{pc:08X} mem=0x{mem_bytes:X}")
            return "\n".join(lines)

        sub = argv[0].lower()
        if sub == "save":
            if len(argv) != 2:
                return "usage: snap save <name>"
            snap = self.emu.save_snapshot(argv[1])
            mem_bytes = self._snapshot_mem_bytes(snap)
            return f"snapshot saved: {snap.name} (regions={len(snap.memory)} bytes=0x{mem_bytes:X})"

        if sub == "load":
            if len(argv) != 2:
                return "usage: snap load <name>"
            try:
                snap = self.emu.load_snapshot(argv[1])
            except KeyError:
                return f"unknown snapshot: {argv[1]}"
            return f"snapshot loaded: {snap.name} pc=0x{int(snap.regs.get('pc', 0)):08X}"

        if sub == "clear":
            if len(argv) != 2:
                return "usage: snap clear <name|all>"
            if argv[1].lower() == "all":
                count = self.emu.clear_snapshots()
                return f"snapshots cleared: {count}"
            ok = self.emu.remove_snapshot(argv[1])
            if not ok:
                return f"unknown snapshot: {argv[1]}"
            return f"snapshot cleared: {argv[1]}"

        if sub == "diff":
            if len(argv) not in (2, 3):
                return "usage: snap diff <name> [other|current]"
            left = self.emu.get_snapshot(argv[1])
            if left is None:
                return f"unknown snapshot: {argv[1]}"

            if len(argv) == 2 or argv[2].lower() in ("current", "now"):
                right = self.emu.capture_snapshot("(current)")
            else:
                right = self.emu.get_snapshot(argv[2])
                if right is None:
                    return f"unknown snapshot: {argv[2]}"

            data = self._snapshot_diff_data(left, right)
            return self._format_snapshot_diff_data(data)

        return (
            "usage: snap [list] | snap save <name> | snap load <name> | "
            "snap diff <name> [other|current] | snap clear <name|all>"
        )

    @staticmethod
    def _prepare_export_path(raw_path: str) -> Path:
        path = Path(raw_path).expanduser()
        parent = path.parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _read_bytes_spec(spec: str) -> bytes:
        s = str(spec).strip()
        if not s:
            return b""
        if s.lower().startswith("hex@"):
            path = Path(s[4:]).expanduser()
            text = path.read_text(encoding="utf-8")
            # bytes.fromhex tolerates whitespace; also support separators.
            cleaned = text.replace(",", " ").replace(":", " ")
            return bytes.fromhex(cleaned)
        if s.startswith("@"):
            path = Path(s[1:]).expanduser()
            return path.read_bytes()
        return bytes.fromhex(s.replace(",", " ").replace(":", " "))

    @staticmethod
    def _detect_export_format(path: Path, default: str) -> str:
        ext = path.suffix.lower().lstrip(".")
        if ext in {"json", "csv", "txt"}:
            return ext
        if ext == "log":
            return "txt"
        return default

    @staticmethod
    def _write_text_file(path: Path, text: str) -> None:
        with path.open("w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            if text and not text.endswith("\n"):
                f.write("\n")

    @staticmethod
    def _write_json_file(path: Path, data: object) -> None:
        with path.open("w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")

    @staticmethod
    def _write_csv_file(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: row.get(key, "") for key in fieldnames})

    def _dispatch_command_tokens(self, tokens: list[str]) -> str:
        if not tokens:
            return ""
        cmd_name = tokens[0].replace("-", "_")
        handler = getattr(self, f"cmd_{cmd_name}", None)
        if handler is None:
            err = f"unknown command: {tokens[0]}"
            self._append_command_log(command_line=shlex.join(tokens), output="", error=err)
            raise ValueError(err)
        cmd_line = shlex.join(tokens)
        try:
            out = handler(tokens[1:])
        except Exception as e:
            self._append_command_log(command_line=cmd_line, output="", error=str(e))
            raise
        out_s = "" if out is None else str(out)
        self._append_command_log(command_line=cmd_line, output=out_s, error=None)
        return out_s

    def _append_command_log(self, *, command_line: str, output: str, error: str | None) -> None:
        path = self._command_log_path
        if path is None:
            return
        ts = datetime.now(timezone.utc).isoformat()
        lines = [f"[{ts}] $ {command_line}"]
        if error is not None and str(error):
            lines.append(f"error: {error}")
        elif output:
            lines.extend(str(output).splitlines())
        try:
            with path.open("a", encoding="utf-8", newline="\n") as f:
                for line in lines:
                    f.write(line)
                    f.write("\n")
        except Exception:
            pass

    @staticmethod
    def _scenario_compare(actual: int, op: str, expected: int) -> bool:
        if op in ("==", "="):
            return actual == expected
        if op == "!=":
            return actual != expected
        raise ValueError("operator must be == or !=")

    def _scenario_wait(self, argv: list[str]) -> None:
        if not argv:
            raise ValueError("usage: wait pc <addr> [max_steps] | wait fault [max_steps]")

        subject = argv[0].lower()
        if subject == "pc":
            if len(argv) not in (2, 3):
                raise ValueError("usage: wait pc <addr> [max_steps]")
            target = _int(argv[1]) & ~1
            max_steps = _int(argv[2]) if len(argv) == 3 else 100000
            if max_steps < 0:
                raise ValueError("max_steps must be >= 0")
            for _ in range(max_steps):
                current = int(getattr(self.emu, "pc", 0)) & ~1
                if current == target:
                    return
                self.emu.step(1)
            current = int(getattr(self.emu, "pc", 0)) & ~1
            if current == target:
                return
            raise AssertionError(
                f"wait pc timeout: target=0x{target:08X} current=0x{current:08X} steps={max_steps}"
            )

        if subject == "fault":
            if len(argv) not in (1, 2):
                raise ValueError("usage: wait fault [max_steps]")
            max_steps = _int(argv[1]) if len(argv) == 2 else 100000
            if max_steps < 0:
                raise ValueError("max_steps must be >= 0")
            for _ in range(max_steps):
                if getattr(self.emu, "last_fault_report", None) is not None:
                    return
                self.emu.step(1)
            if getattr(self.emu, "last_fault_report", None) is not None:
                return
            raise AssertionError(f"wait fault timeout: steps={max_steps}")

        raise ValueError("usage: wait pc <addr> [max_steps] | wait fault [max_steps]")

    def _scenario_assert(self, argv: list[str], last_output: str) -> None:
        if not argv:
            raise ValueError(
                "usage: assert reg <name> (==|!=) <value> | "
                "assert pc (==|!=) <value> | assert out contains <text> | assert fault | assert nofault"
            )

        subject = argv[0].lower()
        if subject == "reg":
            if len(argv) != 4:
                raise ValueError("usage: assert reg <name> (==|!=) <value>")
            reg_name = argv[1].lower()
            op = argv[2]
            expected = _int(argv[3]) & 0xFFFFFFFF
            regs = self.emu.read_regs()
            if reg_name not in regs:
                raise AssertionError(f"unknown reg: {reg_name}")
            actual = int(regs[reg_name]) & 0xFFFFFFFF
            if not self._scenario_compare(actual, op, expected):
                raise AssertionError(
                    f"assert reg failed: {reg_name}=0x{actual:08X} {op} 0x{expected:08X}"
                )
            return

        if subject == "pc":
            if len(argv) != 3:
                raise ValueError("usage: assert pc (==|!=) <value>")
            op = argv[1]
            expected = _int(argv[2]) & ~1
            actual = int(getattr(self.emu, "pc", 0)) & ~1
            if not self._scenario_compare(actual, op, expected):
                raise AssertionError(f"assert pc failed: 0x{actual:08X} {op} 0x{expected:08X}")
            return

        if subject == "out":
            if len(argv) < 3 or argv[1].lower() != "contains":
                raise ValueError("usage: assert out contains <text>")
            needle = " ".join(argv[2:])
            if needle not in (last_output or ""):
                raise AssertionError(f"assert out contains failed: {needle!r}")
            return

        if subject == "fault":
            if len(argv) != 1:
                raise ValueError("usage: assert fault")
            if getattr(self.emu, "last_fault_report", None) is None:
                raise AssertionError("expected fault report, got none")
            return

        if subject == "nofault":
            if len(argv) != 1:
                raise ValueError("usage: assert nofault")
            if getattr(self.emu, "last_fault_report", None) is not None:
                raise AssertionError("expected no fault report")
            return

        raise ValueError(
            "usage: assert reg <name> (==|!=) <value> | "
            "assert pc (==|!=) <value> | assert out contains <text> | assert fault | assert nofault"
        )

    def _run_scenario_file(self, script_path: Path, *, _depth: int = 0) -> tuple[int, int, str]:
        if _depth > 8:
            raise RuntimeError("scenario include depth exceeded (max=8)")
        try:
            lines = script_path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            raise RuntimeError(f"unable to read scenario file: {script_path} ({e})") from e

        parsed_lines = 0
        actions = 0
        last_output = ""
        for lineno, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parsed_lines += 1
            try:
                tokens = shlex.split(line)
            except ValueError as e:
                raise RuntimeError(f"{script_path}:{lineno}: parse error: {e}") from e
            if not tokens:
                continue

            try:
                head = tokens[0].lower()
                if head == "include":
                    if len(tokens) != 2:
                        raise ValueError("usage: include <path>")
                    include_path = Path(tokens[1]).expanduser()
                    if not include_path.is_absolute():
                        include_path = script_path.parent / include_path
                    inc_lines, inc_actions, inc_last_output = self._run_scenario_file(
                        include_path,
                        _depth=_depth + 1,
                    )
                    parsed_lines += inc_lines
                    actions += inc_actions
                    last_output = inc_last_output
                    continue

                if head == "wait":
                    self._scenario_wait(tokens[1:])
                    actions += 1
                    continue

                if head == "assert":
                    self._scenario_assert(tokens[1:], last_output)
                    actions += 1
                    continue

                last_output = self._dispatch_command_tokens(tokens)
                actions += 1
            except Exception as e:
                raise RuntimeError(f"{script_path}:{lineno}: {e}") from e

        return parsed_lines, actions, last_output

    def cmd_scenario(self, argv: list[str]) -> str:
        """
        scenario run <path>
        scenario <path>

        Script DSL:
          - normal shell command lines
          - include <path>
          - wait pc <addr> [max_steps]
          - wait fault [max_steps]
          - assert reg <name> (==|!=) <value>
          - assert pc (==|!=) <value>
          - assert out contains <text>
          - assert fault | assert nofault
        """
        if not argv:
            return "usage: scenario run <path> | scenario <path>"

        if argv[0].lower() == "run":
            if len(argv) != 2:
                return "usage: scenario run <path> | scenario <path>"
            path = Path(argv[1]).expanduser()
        else:
            if len(argv) != 1:
                return "usage: scenario run <path> | scenario <path>"
            path = Path(argv[0]).expanduser()

        if not path.is_absolute():
            path = Path.cwd() / path
        path = path.resolve()

        try:
            parsed_lines, actions, _ = self._run_scenario_file(path)
        except Exception as e:
            return f"scenario failed: {e}"
        return f"scenario ok: {path} (lines={parsed_lines} actions={actions})"

    def cmd_export(self, argv: list[str]) -> str:
        """
        export pcprof <path.{json|csv|txt}> <instructions> [top]
        export mmioprof <path.{json|csv|txt}> <instructions> [top]
        export trace <path.{txt|json|csv}> [clear]
        export snapdiff <path.{json|csv|txt}> <left> [right|current]
        """
        if not argv:
            return (
                "usage: export pcprof <path.{json|csv|txt}> <instructions> [top] | "
                "export mmioprof <path.{json|csv|txt}> <instructions> [top] | "
                "export trace <path.{txt|json|csv}> [clear] | "
                "export snapdiff <path.{json|csv|txt}> <left> [right|current]"
            )

        kind = argv[0].lower()
        if kind == "pcprof":
            if len(argv) not in (3, 4):
                return "usage: export pcprof <path.{json|csv|txt}> <instructions> [top]"
            path = self._prepare_export_path(argv[1])
            steps = _int(argv[2])
            if steps <= 0:
                return "instructions must be > 0"
            top = _int(argv[3]) if len(argv) == 4 else 20
            top = max(1, min(int(top), 100))
            data = self._collect_pcprof_data(int(steps), int(top))
            fmt = self._detect_export_format(path, default="json")

            if fmt == "json":
                self._write_json_file(path, data)
            elif fmt == "txt":
                self._write_text_file(path, self._format_pcprof_data(data))
            elif fmt == "csv":
                rows: list[dict[str, object]] = []
                for entry in data.get("entries", []):
                    rows.append(
                        {
                            "pc_current": f"0x{int(data.get('pc', 0)):08X}",
                            "instructions_requested": int(data.get("instructions_requested", 0)),
                            "instructions_executed": int(data.get("instructions_executed", 0)),
                            "pc": f"0x{int(entry.get('pc', 0)):08X}",
                            "count": int(entry.get("count", 0)),
                            "pct": f"{float(entry.get('pct', 0.0)):.6f}",
                            "disasm": str(entry.get("disasm", "")),
                        }
                    )
                self._write_csv_file(
                    path,
                    [
                        "pc_current",
                        "instructions_requested",
                        "instructions_executed",
                        "pc",
                        "count",
                        "pct",
                        "disasm",
                    ],
                    rows,
                )
            else:
                return f"unsupported export format: {path.suffix or '(none)'}"
            return f"exported pcprof: {path} ({fmt})"

        if kind == "mmioprof":
            if len(argv) not in (3, 4):
                return "usage: export mmioprof <path.{json|csv|txt}> <instructions> [top]"
            path = self._prepare_export_path(argv[1])
            steps = _int(argv[2])
            if steps <= 0:
                return "instructions must be > 0"
            top = _int(argv[3]) if len(argv) == 4 else 20
            top = max(1, min(int(top), 100))
            data = self._collect_mmioprof_data(int(steps), int(top))
            fmt = self._detect_export_format(path, default="json")

            if fmt == "json":
                self._write_json_file(path, data)
            elif fmt == "txt":
                self._write_text_file(path, self._format_mmioprof_data(data))
            elif fmt == "csv":
                rows: list[dict[str, object]] = []
                for direction in ("reads", "writes"):
                    for entry in data.get(direction, []):
                        rows.append(
                            {
                                "pc_current": f"0x{int(data.get('pc', 0)):08X}",
                                "instructions": int(data.get("instructions", 0)),
                                "read_events": int(data.get("read_events", 0)),
                                "write_events": int(data.get("write_events", 0)),
                                "direction": direction[:-1],
                                "addr": f"0x{int(entry.get('addr', 0)):08X}",
                                "size": int(entry.get("size", 0)),
                                "count": int(entry.get("count", 0)),
                                "label": str(entry.get("label", "")),
                            }
                        )
                self._write_csv_file(
                    path,
                    [
                        "pc_current",
                        "instructions",
                        "read_events",
                        "write_events",
                        "direction",
                        "addr",
                        "size",
                        "count",
                        "label",
                    ],
                    rows,
                )
            else:
                return f"unsupported export format: {path.suffix or '(none)'}"
            return f"exported mmioprof: {path} ({fmt})"

        if kind == "trace":
            if len(argv) not in (2, 3):
                return "usage: export trace <path.{txt|json|csv}> [clear]"
            path = self._prepare_export_path(argv[1])
            do_clear = False
            if len(argv) == 3:
                if argv[2].lower() != "clear":
                    return "usage: export trace <path.{txt|json|csv}> [clear]"
                do_clear = True

            trace_lines = [str(x) for x in getattr(self.emu, "trace_history", [])]
            fmt = self._detect_export_format(path, default="txt")
            if fmt == "txt":
                self._write_text_file(path, "\n".join(trace_lines))
            elif fmt == "json":
                self._write_json_file(path, {"line_count": len(trace_lines), "lines": trace_lines})
            elif fmt == "csv":
                rows = [{"index": idx, "line": line} for idx, line in enumerate(trace_lines)]
                self._write_csv_file(path, ["index", "line"], rows)
            else:
                return f"unsupported export format: {path.suffix or '(none)'}"

            if do_clear and hasattr(self.emu, "trace_history"):
                self.emu.trace_history.clear()
            suffix = " + cleared" if do_clear else ""
            return f"exported trace: {path} ({fmt}) lines={len(trace_lines)}{suffix}"

        if kind == "snapdiff":
            if len(argv) not in (3, 4):
                return "usage: export snapdiff <path.{json|csv|txt}> <left> [right|current]"
            path = self._prepare_export_path(argv[1])
            left = self.emu.get_snapshot(argv[2])
            if left is None:
                return f"unknown snapshot: {argv[2]}"

            if len(argv) == 3 or argv[3].lower() in ("current", "now"):
                right = self.emu.capture_snapshot("(current)")
            else:
                right = self.emu.get_snapshot(argv[3])
                if right is None:
                    return f"unknown snapshot: {argv[3]}"

            data = self._snapshot_diff_data(left, right)
            fmt = self._detect_export_format(path, default="json")
            if fmt == "json":
                self._write_json_file(path, data)
            elif fmt == "txt":
                self._write_text_file(path, self._format_snapshot_diff_data(data))
            elif fmt == "csv":
                rows: list[dict[str, object]] = [
                    {
                        "kind": "summary",
                        "left": str(data.get("left", "")),
                        "right": str(data.get("right", "")),
                        "name": "",
                        "before": "",
                        "after": "",
                        "start": "",
                        "end": "",
                        "size": "",
                        "memory_changed_bytes": int(data.get("memory_changed_bytes", 0)),
                    }
                ]
                for reg_row in data.get("reg_changes", []):
                    old = reg_row.get("old")
                    new = reg_row.get("new")
                    rows.append(
                        {
                            "kind": "reg",
                            "left": "",
                            "right": "",
                            "name": str(reg_row.get("name", "")),
                            "before": "" if old is None else f"0x{int(old):08X}",
                            "after": "" if new is None else f"0x{int(new):08X}",
                            "start": "",
                            "end": "",
                            "size": "",
                            "memory_changed_bytes": "",
                        }
                    )
                for mem_row in data.get("memory_changed_ranges", []):
                    start = int(mem_row.get("start", 0))
                    end = int(mem_row.get("end", 0))
                    size = int(mem_row.get("size", max(0, end - start)))
                    rows.append(
                        {
                            "kind": "memory_range",
                            "left": "",
                            "right": "",
                            "name": "",
                            "before": "",
                            "after": "",
                            "start": f"0x{start:08X}",
                            "end": f"0x{end:08X}",
                            "size": size,
                            "memory_changed_bytes": "",
                        }
                    )
                self._write_csv_file(
                    path,
                    [
                        "kind",
                        "left",
                        "right",
                        "name",
                        "before",
                        "after",
                        "start",
                        "end",
                        "size",
                        "memory_changed_bytes",
                    ],
                    rows,
                )
            else:
                return f"unsupported export format: {path.suffix or '(none)'}"
            return f"exported snapdiff: {path} ({fmt})"

        return (
            "usage: export pcprof <path.{json|csv|txt}> <instructions> [top] | "
            "export mmioprof <path.{json|csv|txt}> <instructions> [top] | "
            "export trace <path.{txt|json|csv}> [clear] | "
            "export snapdiff <path.{json|csv|txt}> <left> [right|current]"
        )

    def cmd_checkpoint(self, argv: list[str]) -> str:
        """
        checkpoint [name]
        Save a snapshot and make it the default for `reload`.
        """
        if len(argv) > 1:
            return "usage: checkpoint [name]"
        name = argv[0] if argv else self._checkpoint_default_name
        out = self.cmd_snap(["save", name])
        self._checkpoint_default_name = name
        return out

    def cmd_reload(self, argv: list[str]) -> str:
        """
        reload [name]
        Load a snapshot (defaults to most recent checkpoint name).
        """
        if len(argv) > 1:
            return "usage: reload [name]"
        name = argv[0] if argv else self._checkpoint_default_name
        return self.cmd_snap(["load", name])

    def cmd_repeat(self, argv: list[str]) -> str:
        """
        repeat <count> <command ...>
        """
        if len(argv) < 2:
            return "usage: repeat <count> <command ...>"
        count = _int(argv[0])
        if count <= 0:
            return "count must be > 0"
        command_tokens = argv[1:]
        lines: list[str] = []
        for i in range(1, int(count) + 1):
            out = self._dispatch_command_tokens(command_tokens)
            if out:
                lines.append(f"[{i}] {out}")
            else:
                lines.append(f"[{i}] (ok)")
        return "\n".join(lines)

    def cmd_test(self, argv: list[str]) -> str:
        """
        test [from <snapshot>] <count> <command ...>
        Runs a command repeatedly and reports failures (outputs starting with "error:").
        """
        if not argv:
            return "usage: test [from <snapshot>] <count> <command ...>"

        snap_name: str | None = None
        idx = 0
        if len(argv) >= 3 and argv[0].lower() == "from":
            snap_name = argv[1]
            idx = 2

        if len(argv) <= idx + 0:
            return "usage: test [from <snapshot>] <count> <command ...>"
        if len(argv) <= idx + 1:
            return "usage: test [from <snapshot>] <count> <command ...>"

        count = _int(argv[idx])
        if count <= 0:
            return "count must be > 0"
        command_tokens = argv[idx + 1 :]
        if not command_tokens:
            return "usage: test [from <snapshot>] <count> <command ...>"

        failures: list[str] = []
        for i in range(1, int(count) + 1):
            if snap_name is not None:
                loaded = self.cmd_snap(["load", snap_name])
                if loaded.startswith("unknown snapshot:"):
                    return loaded
            out = self._dispatch_command_tokens(command_tokens)
            if out.lower().startswith("error:"):
                failures.append(f"[{i}] {out}")

        passed = int(count) - len(failures)
        lines = [f"test done: passed={passed} failed={len(failures)} total={int(count)}"]
        for row in failures[:10]:
            lines.append(row)
        if len(failures) > 10:
            lines.append(f"... ({len(failures) - 10} more failures)")
        return "\n".join(lines)

    def cmd_log(self, argv: list[str]) -> str:
        """
        log status
        log start <path>
        log stop
        log note <text ...>
        log run <command ...>
        """
        if not argv or argv[0].lower() == "status":
            if self._command_log_path is None:
                return "log = off"
            return f"log = on ({self._command_log_path})"

        sub = argv[0].lower()
        if sub == "start":
            if len(argv) != 2:
                return "usage: log start <path>"
            path = self._prepare_export_path(argv[1])
            self._command_log_path = path
            with path.open("w", encoding="utf-8", newline="\n") as f:
                f.write(f"# stmemu command log started {datetime.now(timezone.utc).isoformat()}\n")
            return f"log = on ({path})"

        if sub == "stop":
            if len(argv) != 1:
                return "usage: log stop"
            self._command_log_path = None
            return "log = off"

        if sub == "note":
            if len(argv) < 2:
                return "usage: log note <text ...>"
            if self._command_log_path is None:
                return "log is off; use: log start <path>"
            self._append_command_log(
                command_line="note",
                output=" ".join(argv[1:]),
                error=None,
            )
            return "log note written"

        if sub == "run":
            if len(argv) < 2:
                return "usage: log run <command ...>"
            out = self._dispatch_command_tokens(argv[1:])
            return out or "(ok)"

        return "usage: log [status|start <path>|stop|note <text ...>|run <command ...>]"

    def cmd_image(self, argv: list[str]) -> str:
        if argv:
            return "usage: image"

        ranges: list[tuple[int, int]] = []
        for segment in self.emu.firmware_segments:
            start = int(segment.address)
            end = start + len(segment.data)
            if not ranges or start > ranges[-1][1]:
                ranges.append((start, end))
                continue
            prev_start, prev_end = ranges[-1]
            ranges[-1] = (prev_start, max(prev_end, end))

        lines = [
            f"format      = {self.emu.firmware_format}",
            f"vector_base = 0x{self.emu.flash_base:08X}",
        ]
        entry = getattr(self.emu, "firmware_entry_point", None)
        lines.append(
            "entry_point = " + ("-" if entry is None else f"0x{int(entry):08X}")
        )
        lines.append(f"segments    = {len(self.emu.firmware_segments)}")
        lines.append(f"ranges      = {len(ranges)}")
        for index, (start, end) in enumerate(ranges):
            lines.append(f"(range {index}) 0x{start:08X}-0x{end:08X} size=0x{end - start:X}")
        for index, segment in enumerate(self.emu.firmware_segments):
            start = int(segment.address)
            size = len(segment.data)
            end = start + size
            lines.append(f"[{index}] 0x{start:08X}-0x{end:08X} size=0x{size:X}")
        return "\n".join(lines)

    def cmd_stuck(self, argv: list[str]) -> str:
        if not argv:
            mode = "auto" if self.emu.stuck_loop_auto else "manual"
            return (
                f"mode        = {mode}\n"
                f"base        = {self.emu.stuck_loop_threshold}\n"
                f"interrupt   = {self.emu.interrupt_stuck_threshold}\n"
                f"effective   = {self.emu._stuck_loop_threshold()}"
            )

        sub = argv[0].lower()
        if sub == "off":
            self.emu.stuck_loop_auto = False
            self.emu.stuck_loop_threshold = 0
            return "stuck loop guard = off"

        if sub == "auto":
            if len(argv) > 3:
                return "usage: stuck | stuck off | stuck auto [base] [interrupt] | stuck <base> [interrupt]"
            if len(argv) >= 2:
                self.emu.stuck_loop_threshold = _int(argv[1])
            if len(argv) == 3:
                self.emu.interrupt_stuck_threshold = _int(argv[2])
            self.emu.stuck_loop_auto = True
            return self.cmd_stuck([])

        if len(argv) > 2:
            return "usage: stuck | stuck off | stuck auto [base] [interrupt] | stuck <base> [interrupt]"

        self.emu.stuck_loop_threshold = _int(argv[0])
        if len(argv) == 2:
            self.emu.interrupt_stuck_threshold = _int(argv[1])
        self.emu.stuck_loop_auto = False
        return self.cmd_stuck([])

    def cmd_tickscale(self, argv: list[str]) -> str:
        if not argv:
            return f"tick_scale = {self.emu.tick_scale}"
        if len(argv) != 1:
            return "usage: tickscale [value]"
        value = _int(argv[0])
        if value <= 0:
            return "tickscale must be >= 1"
        self.emu.tick_scale = value
        return f"tick_scale = {self.emu.tick_scale}"

    def cmd_addr2reg(self, argv: list[str]) -> str:
        if len(argv) != 1:
            return "usage: addr2reg <addr>"
        addr = _int(argv[0])
        p = self.bus.amap.find_peripheral(addr)
        if not p:
            return f"0x{addr:08X}: (no peripheral)"
        reg = self.bus.amap.find_register(p, addr)
        if reg:
            return f"0x{addr:08X}: {p.name}.{reg.name} (offset=0x{reg.offset:X})"
        return f"0x{addr:08X}: {p.name}+0x{addr - p.base_address:X}"

    def cmd_irq(self, argv: list[str]) -> str:
        core = self.emu.core_peripheral
        if core is None:
            return "irq controller unavailable"

        if not argv or argv[0] == "list":
            pending = ", ".join(str(n) for n in core.pending_irqs()) or "-"
            system = ", ".join(core.pending_system_exceptions()) or "-"
            return f"pending external: {pending}\npending system: {system}"

        sub = argv[0].lower()
        if sub in ("set", "clear", "enable", "disable"):
            if len(argv) != 2:
                return f"usage: irq {sub} <num|SysTick|PendSV|NMI>"
            target = argv[1]
            if target.lower() in ("systick", "pendsv", "nmi"):
                if sub not in ("set", "clear"):
                    return "system exceptions support only set|clear"
                core.set_system_pending(target, pending=sub == "set")
                state = "pending" if sub == "set" else "cleared"
                return f"{target} {state}"

            irq = _int(target)
            if sub == "set":
                core.set_irq_pending(irq, True)
                return f"irq {irq} pending"
            if sub == "clear":
                core.set_irq_pending(irq, False)
                return f"irq {irq} cleared"
            if sub == "enable":
                core.set_irq_enabled(irq, True)
                return f"irq {irq} enabled"
            core.set_irq_enabled(irq, False)
            return f"irq {irq} disabled"

        if sub == "show":
            if len(argv) != 2:
                return "usage: irq show <num>"
            irq = _int(argv[1])
            state = core.irq_state(irq)
            return (
                f"irq {irq}: "
                f"enabled={'1' if state['enabled'] else '0'} "
                f"pending={'1' if state['pending'] else '0'} "
                f"active={'1' if state['active'] else '0'}"
            )

        return "usage: irq [list|show <num>|set <num|SysTick>|clear <num|SysTick>|enable <num>|disable <num>]"

    # --- Breakpoints (PC + MMIO watchpoints) ---
    def _resolve_mmio_spec(self, spec: str) -> tuple[str, int, int]:
        """
        Resolve:
        PERIPH        → full peripheral MMIO range
        PERIPH.REG    → register MMIO range
        Returns: (stable_name, start_addr, end_addr)
        """
        s = spec.strip()
        if not s:
            raise ValueError("empty spec")

        # --- PERIPH.REG ---
        if "." in s:
            periph_name, reg_name = s.split(".", 1)

            p = self.bus.amap.find_peripheral_by_name(periph_name)
            if not p:
                raise ValueError(f"unknown peripheral: {periph_name}")

            reg_upper = reg_name.upper()
            r = next((x for x in p.registers if x.name.upper() == reg_upper), None)
            if not r:
                raise ValueError(f"unknown register: {periph_name}.{reg_name}")

            size_bits = getattr(r, "size_bits", 32)
            size_bytes = max(1, (size_bits + 7) // 8)

            start = p.base_address + r.offset
            end = start + size_bytes - 1

            return (f"{p.name}.{r.name}", start, end)

        # --- PERIPH ---
        p = self.bus.amap.find_peripheral_by_name(s)
        if not p:
            raise ValueError(f"unknown peripheral: {s}")

        start = p.base_address

        if getattr(p, "size", None):
            end = start + p.size - 1
        else:
            # fallback: compute from registers
            max_end = start
            for r in p.registers:
                size_bits = getattr(r, "size_bits", 32)
                size_bytes = max(1, (size_bits + 7) // 8)
                max_end = max(max_end, start + r.offset + size_bytes - 1)
            end = max_end

        return (p.name, start, end)


    def cmd_bp(self, argv: list[str]) -> str:
        """bp <addr|PERIPH|PERIPH.REG> [r|w|rw]

        Adds either a PC breakpoint (addr) or an MMIO watchpoint (PERIPH / PERIPH.REG).

        Examples:
          bp 0x080002A1
          bp USART3
          bp USART3.TDR w
        """
        if not argv:
            return "usage: bp <addr|PERIPH|PERIPH.REG> [r|w|rw]"

        target = argv[0]
        access = (argv[1].lower() if len(argv) > 1 else "rw").strip()
        if access not in ("r", "w", "rw"):
            return "usage: bp <addr|PERIPH|PERIPH.REG> [r|w|rw]"

        # Numeric => PC breakpoint
        try:
            if target.lower().startswith("0x") or target.isdigit():
                addr = _int(target) & ~1
                self.emu.add_breakpoint(addr)
                return f"added PC breakpoint: 0x{addr:08X}"
        except Exception:
            pass

        # Otherwise treat as MMIO watchpoint
        try:
            name, start, end = self._resolve_mmio_spec(target)
        except ValueError as e:
            return str(e)

        self.emu.add_mmio_breakpoint(name=name, start=start, end=end, access=access)
        return f"added MMIO breakpoint: {name} [{start:08X}-{end:08X}] ({access})"

    def cmd_bl(self, argv: list[str]) -> str:
        """bl - List breakpoints (PC + MMIO)."""
        if argv:
            return "usage: bl"

        lines: list[str] = []

        pcs = self.emu.list_breakpoints() if hasattr(self.emu, "list_breakpoints") else []
        if pcs:
            lines.append("PC breakpoints:")
            for a in pcs:
                lines.append(f"  0x{a:08X}")
        else:
            lines.append("PC breakpoints: (none)")

        mm = self.emu.list_mmio_breakpoints() if hasattr(self.emu, "list_mmio_breakpoints") else []
        if mm:
            lines.append("MMIO breakpoints:")
            for bp in mm:
                lines.append(
                    f"  {bp['name']} [{int(bp['start']):08X}-{int(bp['end']):08X}] ({bp['access']})"
                )
        else:
            lines.append("MMIO breakpoints: (none)")

        return "\n".join(lines)

    def cmd_bc(self, argv: list[str]) -> str:
        """bc [all|addr|PERIPH|PERIPH.REG]

        Clears breakpoints.
        """
        if not argv or argv[0].lower() == "all":
            # Clear everything we can.
            removed_pc = len(self.emu.list_breakpoints()) if hasattr(self.emu, "list_breakpoints") else 0
            for a in (self.emu.list_breakpoints() if hasattr(self.emu, "list_breakpoints") else []):
                self.emu.remove_breakpoint(a)
            removed_mmio = len(self.emu.list_mmio_breakpoints()) if hasattr(self.emu, "list_mmio_breakpoints") else 0
            if hasattr(self.emu, "clear_mmio_breakpoints"):
                self.emu.clear_mmio_breakpoints()
            return f"cleared breakpoints: pc={removed_pc} mmio={removed_mmio}"

        target = argv[0]

        # Try numeric PC breakpoint
        try:
            if target.lower().startswith("0x") or target.isdigit():
                addr = _int(target) & ~1
                self.emu.remove_breakpoint(addr)
                return f"cleared PC breakpoint: 0x{addr:08X}"
        except Exception:
            pass

        # Otherwise MMIO by resolved stable name.
        try:
            name, _, _ = self._resolve_mmio_spec(target)
        except ValueError as e:
            return str(e)

        if hasattr(self.emu, "remove_mmio_breakpoint"):
            n = self.emu.remove_mmio_breakpoint(name)
            return f"cleared MMIO breakpoint: {name} ({n} removed)"
        return "MMIO breakpoint removal is not supported by this emulator build"
    
    def cmd_trace(self, argv: list[str]) -> str:
        """
        trace
        trace on|off
        trace mmio
        trace all
        trace call|nocall
        trace branch|nobranch
        trace regs|noregs
        trace until <pc>
        """
        if not argv:
            flags = []
            if self.emu.trace_enabled:
                flags.append("on")
            if self.emu.trace_mmio_only:
                flags.append("mmio")
            if getattr(self.emu, "trace_callret_only", False):
                flags.append("call")
            if getattr(self.emu, "trace_branch_only", False):
                flags.append("branch")
            if getattr(self.emu, "trace_reg_deltas", False):
                flags.append("regs")
            if self.emu.trace_until_pc is not None:
                flags.append(f"until=0x{self.emu.trace_until_pc:08X}")
            return "trace = " + (" ".join(flags) if flags else "off")

        sub = argv[0].lower()

        if sub in ("on", "1", "enable"):
            self.emu.trace_enabled = True
            return "trace = on"

        if sub in ("off", "0", "disable"):
            self.emu.trace_enabled = False
            self.emu.trace_mmio_only = False
            self.emu.trace_until_pc = None
            self.emu.trace_callret_only = False
            self.emu.trace_branch_only = False
            self.emu.trace_reg_deltas = False
            if hasattr(self.emu, "_trace_call_depth"):
                self.emu._trace_call_depth = 0
            if hasattr(self.emu, "_trace_reset_pending"):
                self.emu._trace_reset_pending()
            return "trace = off"

        if sub == "mmio":
            self.emu.trace_enabled = True
            self.emu.trace_mmio_only = True
            return "trace = on (mmio-only)"

        if sub == "all":
            self.emu.trace_enabled = True
            self.emu.trace_mmio_only = False
            self.emu.trace_callret_only = False
            self.emu.trace_branch_only = False
            return "trace = on (all)"

        if sub in ("call", "callret"):
            self.emu.trace_enabled = True
            self.emu.trace_callret_only = True
            return "trace call = on"

        if sub in ("nocall", "nocallret"):
            self.emu.trace_callret_only = False
            return "trace call = off"

        if sub == "branch":
            self.emu.trace_enabled = True
            self.emu.trace_branch_only = True
            return "trace branch = on"

        if sub == "nobranch":
            self.emu.trace_branch_only = False
            return "trace branch = off"

        if sub in ("regs", "delta", "deltas"):
            self.emu.trace_enabled = True
            self.emu.trace_reg_deltas = True
            return "trace regs = on"

        if sub in ("noregs", "nodelta", "nodeltas"):
            self.emu.trace_reg_deltas = False
            return "trace regs = off"

        if sub == "until":
            if len(argv) != 2:
                return "usage: trace until <pc>"
            pc = int(argv[1], 0) & ~1
            self.emu.trace_enabled = True
            self.emu.trace_until_pc = pc
            return f"trace = on until 0x{pc:08X}"

        return "usage: trace [on|off|mmio|all|call|nocall|branch|nobranch|regs|noregs|until <pc>]"

    def cmd_atpc(self, argv):
        # MMIO action syntax:
        #   atpc <pc> PERIPH.REG = <value> [if PERIPH.REG == <value>]
        #
        # CPU action syntax:
        #   atpc reg <pc> <reg> = <value> [once]
        #   atpc ret <pc> [r0=<value>|<value>] [once]
        #   atpc skip <pc> [bytes] [once]
        #   atpc stub <pc> [r0=<value>|<value>] [once]
        if not argv:
            return (
                "usage: atpc <pc> PERIPH.REG = <value> [if PERIPH.REG == <value>] | "
                "atpc reg <pc> <reg> = <value> [once] | "
                "atpc ret <pc> [r0=<value>|<value>] [once] | "
                "atpc skip <pc> [bytes] [once] | "
                "atpc stub <pc> [r0=<value>|<value>] [once]"
            )

        sub = argv[0].lower()
        if sub == "reg":
            if len(argv) not in (5, 6):
                return "usage: atpc reg <pc> <reg> = <value> [once]"
            pc = self._parse_int(argv[1])
            try:
                reg = self._parse_cpu_reg(argv[2])
            except ValueError as e:
                return str(e)
            if argv[3] != "=":
                return "usage: atpc reg <pc> <reg> = <value> [once]"
            value = self._parse_int(argv[4])
            once = len(argv) == 6 and argv[5].lower() == "once"
            if len(argv) == 6 and not once:
                return "usage: atpc reg <pc> <reg> = <value> [once]"
            aid = self.emu.add_pc_cpu_action("setreg", pc=pc, reg=reg, value=value, once=once)
            suffix = " once" if once else ""
            return f"pc-cpu action #{aid} added: @0x{pc & ~1:X} {reg} = 0x{value & 0xFFFFFFFF:X}{suffix}"

        if sub in ("ret", "stub"):
            if len(argv) < 2 or len(argv) > 4:
                return "usage: atpc ret <pc> [r0=<value>|<value>] [once]"
            pc = self._parse_int(argv[1])
            value = None
            once = False
            for tok in argv[2:]:
                t = tok.strip().lower()
                if t == "once":
                    once = True
                    continue
                if value is not None:
                    return "usage: atpc ret <pc> [r0=<value>|<value>] [once]"
                if t.startswith("r0="):
                    value = self._parse_int(tok.split("=", 1)[1])
                else:
                    value = self._parse_int(tok)
            aid = self.emu.add_pc_cpu_action("ret", pc=pc, value=value, once=once)
            suffix = " once" if once else ""
            value_s = "" if value is None else f" r0=0x{int(value) & 0xFFFFFFFF:X}"
            label = "stub" if sub == "stub" else "ret"
            return f"pc-cpu action #{aid} added: {label} @0x{pc & ~1:X}{value_s}{suffix}"

        if sub == "skip":
            if len(argv) < 2 or len(argv) > 4:
                return "usage: atpc skip <pc> [bytes] [once]"
            pc = self._parse_int(argv[1])
            skip_bytes = None
            once = False
            for tok in argv[2:]:
                if tok.lower() == "once":
                    once = True
                    continue
                if skip_bytes is not None:
                    return "usage: atpc skip <pc> [bytes] [once]"
                skip_bytes = self._parse_int(tok)
            aid = self.emu.add_pc_cpu_action("skip", pc=pc, skip_bytes=skip_bytes, once=once)
            delta_s = "(insn-size)" if skip_bytes is None else f"0x{int(skip_bytes):X}"
            suffix = " once" if once else ""
            return f"pc-cpu action #{aid} added: skip @0x{pc & ~1:X} +{delta_s}{suffix}"

        if len(argv) < 4:
            return "usage: atpc <pc> PERIPH.REG = <value> [if PERIPH.REG == <value>]"

        pc = self._parse_int(argv[0])
        periph, reg = self._parse_reg_spec(argv[1])

        if argv[2] != "=":
            return "usage: atpc <pc> PERIPH.REG = <value> [if PERIPH.REG == <value>]"

        value = self._parse_int(argv[3])

        cond = None
        if len(argv) > 4:
            if argv[4].lower() != "if":
                return "expected 'if' or end of command"
            if len(argv) < 8:
                return "usage: ... if PERIPH.REG == <value>"

            c_per, c_reg = self._parse_reg_spec(argv[5])
            op = argv[6]
            if op not in ("==", "="):
                return "condition must use '==' (or '=')"

            c_val = self._parse_int(argv[7])
            cond = (c_per, c_reg, c_val)

        self.emu.add_pc_reg_write(PcRegWrite(
            pc=pc,
            peripheral=periph,
            register=reg,
            value=value,
            cond=cond,
        ))

        if cond:
            c_per, c_reg, c_val = cond
            return f"pc-action added: @0x{pc:X} {periph}.{reg} = 0x{value:X} if {c_per}.{c_reg} == 0x{c_val:X}"
        return f"pc-action added: @0x{pc:X} {periph}.{reg} = 0x{value:X}"

    def cmd_atpc_list(self, argv):
        if argv:
            return "usage: atpc_list"
        out = []
        for w in getattr(self.emu, "pc_reg_writes", []):
            cond_s = ""
            if getattr(w, "cond", None):
                c_per, c_reg, c_val = w.cond
                cond_s = f" if {c_per}.{c_reg} == 0x{int(c_val):X}"
            out.append(
                f"MMIO @0x{int(w.pc):X} {w.peripheral}.{w.register} = 0x{int(w.value):X}{cond_s}"
            )
        if hasattr(self.emu, "list_pc_cpu_actions"):
            for a in self.emu.list_pc_cpu_actions():
                kind = str(a.get("kind", "?"))
                if kind == "setreg":
                    desc = (
                        f"CPU  #{int(a['id'])} @0x{int(a['pc']):X} "
                        f"{a.get('reg')} = 0x{int(a.get('value', 0)):X}"
                    )
                elif kind == "ret":
                    value = a.get("value")
                    value_s = "" if value is None else f" r0=0x{int(value):X}"
                    desc = f"CPU  #{int(a['id'])} @0x{int(a['pc']):X} ret{value_s}"
                elif kind == "skip":
                    delta = a.get("skip_bytes")
                    delta_s = "(insn-size)" if delta is None else f"0x{int(delta):X}"
                    desc = f"CPU  #{int(a['id'])} @0x{int(a['pc']):X} skip +{delta_s}"
                else:
                    desc = f"CPU  #{int(a['id'])} @0x{int(a['pc']):X} {kind}"
                if bool(a.get("once")):
                    desc += " once"
                desc += f" hits={int(a.get('hits', 0))}"
                out.append(desc)
        return "\n".join(out) or "(no pc actions)"

    def cmd_atpc_clear(self, argv):
        if not argv or argv[0].lower() == "all":
            mmio_n = len(getattr(self.emu, "pc_reg_writes", []))
            self.emu.pc_reg_writes.clear()
            cpu_n = self.emu.clear_pc_cpu_actions() if hasattr(self.emu, "clear_pc_cpu_actions") else 0
            return f"pc actions cleared: mmio={mmio_n} cpu={cpu_n}"

        sub = argv[0].lower()
        if sub == "mmio":
            mmio_n = len(getattr(self.emu, "pc_reg_writes", []))
            self.emu.pc_reg_writes.clear()
            return f"pc mmio actions cleared: {mmio_n}"
        if sub == "cpu":
            if not hasattr(self.emu, "clear_pc_cpu_actions"):
                return "pc cpu actions are not supported by this emulator build"
            cpu_n = self.emu.clear_pc_cpu_actions()
            return f"pc cpu actions cleared: {cpu_n}"

        try:
            aid = self._parse_int(argv[0])
        except Exception:
            return "usage: atpc_clear [all|mmio|cpu|id]"
        if not hasattr(self.emu, "remove_pc_cpu_action"):
            return "pc cpu action removal is not supported by this emulator build"
        if not self.emu.remove_pc_cpu_action(aid):
            return f"pc cpu action not found: {aid}"
        return f"pc cpu action cleared: {aid}"

    def cmd_ret(self, argv):
        return self.cmd_atpc(["ret", *argv])

    def cmd_stub(self, argv):
        return self.cmd_atpc(["stub", *argv])

    def cmd_skip(self, argv):
        return self.cmd_atpc(["skip", *argv])

    def _parse_reg_spec(self, s: str) -> tuple[str, str]:
        # "USART3.ISR" -> ("USART3", "ISR")
        if "." not in s:
            raise ValueError("expected PERIPH.REG")
        p, r = s.split(".", 1)
        return p.strip().upper(), r.strip().upper()

    def _parse_cpu_reg(self, s: str) -> str:
        reg = s.strip().lower()
        valid = {
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
            "msp", "psp", "control", "primask", "basepri", "faultmask", "cpsr",
        }
        if reg not in valid:
            raise ValueError(f"unknown cpu reg: {s}")
        return reg

    def _parse_int(self, s: str) -> int:
        s = s.strip()
        return int(s, 0)  # supports 0x..., decimal

    # --- SPI commands ---
    def _resolve_spi_model(self, name: str) -> SpiPeripheral:
        model = self.bus.model_for_name(name)
        if not isinstance(model, SpiPeripheral):
            raise KeyError(f"unknown spi peripheral: {name}")
        return model

    def cmd_spi(self, argv: list[str]) -> str:
        usage = (
            "usage: spi list | spi status <name> | spi rx <name> <hexbytes|@file|hex@file> | "
            "spi tx <name> [clear] | spi xfer <name> <hexbytes> [steps]"
        )
        if not argv:
            return usage

        sub = argv[0].lower()
        if sub == "list":
            lines: list[str] = []
            for peripheral in self.bus.amap.peripherals:
                model = self.bus.model_for_name(peripheral.name)
                if isinstance(model, SpiPeripheral):
                    tx_len = len(model.drain_tx() if False else model._tx_fifo)
                    rx_len = len(model._rx_fifo)
                    lines.append(f"{peripheral.name:8} tx={tx_len} rx={rx_len}")
            return "\n".join(lines) if lines else "(no spi peripherals)"

        if sub == "status":
            if len(argv) != 2:
                return "usage: spi status <name>"
            model = self._resolve_spi_model(argv[1])
            return f"{argv[1].upper()} tx={len(model._tx_fifo)} rx={len(model._rx_fifo)}"

        if sub == "rx":
            if len(argv) != 3:
                return "usage: spi rx <name> <hexbytes|@file|hex@file>"
            model = self._resolve_spi_model(argv[1])
            try:
                payload = self._read_bytes_spec(argv[2])
            except Exception as e:
                return f"error: {e}"
            model.inject_rx(payload)
            return f"injected {len(payload)} byte(s) into {argv[1].upper()} rx"

        if sub == "tx":
            if len(argv) not in {2, 3}:
                return "usage: spi tx <name> [clear]"
            model = self._resolve_spi_model(argv[1])
            clear = len(argv) == 3 and argv[2].lower() == "clear"
            payload = model.drain_tx() if clear else bytes(model._tx_fifo)
            if not payload:
                return f"{argv[1].upper()} tx: (empty)"
            return f"{argv[1].upper()} tx ({len(payload)} bytes): {payload.hex()}"

        if sub == "xfer":
            if len(argv) < 3:
                return "usage: spi xfer <name> <hexbytes> [steps]"
            model = self._resolve_spi_model(argv[1])
            try:
                rx_payload = self._read_bytes_spec(argv[2])
            except Exception as e:
                return f"error: {e}"
            steps = _int(argv[3]) if len(argv) > 3 else 10000
            model.inject_rx(rx_payload)
            model._tx_fifo.clear()
            self.emu.step(steps)
            tx_data = model.drain_tx()
            return f"spi xfer: injected {len(rx_payload)} rx bytes, ran {steps} steps, got {len(tx_data)} tx bytes: {tx_data.hex()}"

        return usage

    # --- I2C commands ---
    def _resolve_i2c_model(self, name: str) -> I2cPeripheral:
        model = self.bus.model_for_name(name)
        if not isinstance(model, I2cPeripheral):
            raise KeyError(f"unknown i2c peripheral: {name}")
        return model

    def cmd_i2c(self, argv: list[str]) -> str:
        usage = (
            "usage: i2c list | i2c status <name> | i2c rx <name> <hexbytes|@file|hex@file> | "
            "i2c tx <name> [clear]"
        )
        if not argv:
            return usage

        sub = argv[0].lower()
        if sub == "list":
            lines: list[str] = []
            for peripheral in self.bus.amap.peripherals:
                model = self.bus.model_for_name(peripheral.name)
                if isinstance(model, I2cPeripheral):
                    tx_len = len(model._tx_fifo)
                    rx_len = len(model._rx_fifo)
                    lines.append(f"{peripheral.name:8} tx={tx_len} rx={rx_len}")
            return "\n".join(lines) if lines else "(no i2c peripherals)"

        if sub == "status":
            if len(argv) != 2:
                return "usage: i2c status <name>"
            model = self._resolve_i2c_model(argv[1])
            return f"{argv[1].upper()} tx={len(model._tx_fifo)} rx={len(model._rx_fifo)}"

        if sub == "rx":
            if len(argv) != 3:
                return "usage: i2c rx <name> <hexbytes|@file|hex@file>"
            model = self._resolve_i2c_model(argv[1])
            try:
                payload = self._read_bytes_spec(argv[2])
            except Exception as e:
                return f"error: {e}"
            model.inject_rx(payload)
            return f"injected {len(payload)} byte(s) into {argv[1].upper()} rx"

        if sub == "tx":
            if len(argv) not in {2, 3}:
                return "usage: i2c tx <name> [clear]"
            model = self._resolve_i2c_model(argv[1])
            clear = len(argv) == 3 and argv[2].lower() == "clear"
            payload = model.drain_tx() if clear else bytes(model._tx_fifo)
            if not payload:
                return f"{argv[1].upper()} tx: (empty)"
            return f"{argv[1].upper()} tx ({len(payload)} bytes): {payload.hex()}"

        return usage

    # --- GPIO commands ---
    def _resolve_gpio_model(self, name: str) -> GpioPeripheral:
        model = self.bus.model_for_name(name)
        if not isinstance(model, GpioPeripheral):
            raise KeyError(f"unknown gpio peripheral: {name}")
        return model

    def cmd_gpio(self, argv: list[str]) -> str:
        usage = (
            "usage: gpio list | gpio read <name> | gpio show <name> | "
            "gpio set <name> <pin> | gpio clear <name> <pin> | "
            "gpio toggle <name> <pin> | "
            "gpio inject <name> <pin> high|low"
        )
        if not argv:
            return usage

        sub = argv[0].lower()
        if sub == "list":
            lines: list[str] = []
            for peripheral in self.bus.amap.peripherals:
                model = self.bus.model_for_name(peripheral.name)
                if isinstance(model, GpioPeripheral):
                    odr = model.read_register_value(model._ODR)
                    lines.append(f"{peripheral.name:8} ODR=0x{odr:04X}")
            return "\n".join(lines) if lines else "(no gpio peripherals)"

        if sub == "read":
            if len(argv) != 2:
                return "usage: gpio read <name>"
            model = self._resolve_gpio_model(argv[1])
            odr = model.read_register_value(model._ODR)
            idr = model.read(model._IDR, 4)
            moder = model.read_register_value(model._MODER)
            lines = [f"{argv[1].upper()} ODR=0x{odr:04X}  IDR=0x{idr:04X}  MODER=0x{moder:08X}"]
            # Show per-pin status
            pin_info = []
            for pin in range(16):
                mode = (moder >> (pin * 2)) & 0x3
                mode_str = ["IN", "OUT", "AF", "AN"][mode]
                state = "H" if (odr >> pin) & 1 else "L"
                pin_info.append(f"P{pin}:{mode_str}/{state}")
            lines.append("  ".join(pin_info[:8]))
            lines.append("  ".join(pin_info[8:]))
            return "\n".join(lines)

        if sub == "set":
            if len(argv) != 3:
                return "usage: gpio set <name> <pin>"
            model = self._resolve_gpio_model(argv[1])
            pin = _int(argv[2])
            if not (0 <= pin <= 15):
                return "pin must be 0-15"
            model.write(model._BSRR, 4, 1 << pin)
            return f"{argv[1].upper()} pin {pin} set (ODR=0x{model.read_register_value(model._ODR):04X})"

        if sub == "clear":
            if len(argv) != 3:
                return "usage: gpio clear <name> <pin>"
            model = self._resolve_gpio_model(argv[1])
            pin = _int(argv[2])
            if not (0 <= pin <= 15):
                return "pin must be 0-15"
            model.write(model._BSRR, 4, 1 << (pin + 16))
            return f"{argv[1].upper()} pin {pin} cleared (ODR=0x{model.read_register_value(model._ODR):04X})"

        if sub == "toggle":
            if len(argv) != 3:
                return "usage: gpio toggle <name> <pin>"
            model = self._resolve_gpio_model(argv[1])
            pin = _int(argv[2])
            if not (0 <= pin <= 15):
                return "pin must be 0-15"
            odr = model.read_register_value(model._ODR)
            if odr & (1 << pin):
                model.write(model._BSRR, 4, 1 << (pin + 16))
            else:
                model.write(model._BSRR, 4, 1 << pin)
            return f"{argv[1].upper()} pin {pin} toggled (ODR=0x{model.read_register_value(model._ODR):04X})"

        if sub == "inject":
            if len(argv) != 4:
                return "usage: gpio inject <name> <pin> high|low"
            model = self._resolve_gpio_model(argv[1])
            pin = _int(argv[2])
            if not (0 <= pin <= 15):
                return "pin must be 0-15"
            level = argv[3].lower()
            if level not in ("high", "low", "1", "0"):
                return "level must be high or low"
            high = level in ("high", "1")
            model.set_input_level(pin, high)
            idr = model.read(model._IDR, 4)
            return f"{argv[1].upper()} pin {pin} input={'H' if high else 'L'} (IDR=0x{idr:04X})"

        if sub == "show":
            if len(argv) != 2:
                return "usage: gpio show <name>"
            model = self._resolve_gpio_model(argv[1])
            return f"{argv[1].upper()} pinmux:\n{model.port_summary()}"

        return usage

    # ── ADC commands ──────────────────────────────────────────────

    def cmd_adc(self, argv: list[str]) -> str:
        usage = (
            "usage: adc list | adc status <name> | "
            "adc sample <name> <value> | adc convert <name>"
        )
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "list":
            from stmemu.peripherals.adc import Stm32AdcPeripheral
            lines: list[str] = []
            for p in self.bus.amap.peripherals:
                model = self.bus.model_for_name(p.name)
                if isinstance(model, Stm32AdcPeripheral):
                    isr = model.read_register_value(model._ISR)
                    dr = model.read_register_value(model._DR)
                    lines.append(f"{p.name:8} ISR=0x{isr:08X} DR=0x{dr:04X}")
            return "\n".join(lines) if lines else "(no ADC peripherals)"

        if sub == "status":
            if len(argv) != 2:
                return "usage: adc status <name>"
            model = self._resolve_adc_model(argv[1])
            isr = model.read_register_value(model._ISR)
            cr = model.read_register_value(model._CR)
            dr = model.read_register_value(model._DR)
            cfgr = model.read_register_value(model._CFGR)
            return (
                f"{argv[1].upper()} CR=0x{cr:08X} ISR=0x{isr:08X} "
                f"DR=0x{dr:04X} CFGR=0x{cfgr:08X} "
                f"queue={len(model._sample_queue)} conv={model._conversion_count}"
            )

        if sub == "sample":
            if len(argv) != 3:
                return "usage: adc sample <name> <value>"
            model = self._resolve_adc_model(argv[1])
            value = _int(argv[2])
            model.inject_sample(value)
            return f"{argv[1].upper()} queued sample 0x{value & 0xFFFF:04X} (queue={len(model._sample_queue)})"

        if sub == "convert":
            if len(argv) != 2:
                return "usage: adc convert <name>"
            model = self._resolve_adc_model(argv[1])
            model.write(model._CR, 4, model.read_register_value(model._CR) | model._CR_ADSTART)
            dr = model.read_register_value(model._DR)
            return f"{argv[1].upper()} conversion complete DR=0x{dr:04X}"

        return usage

    def _resolve_adc_model(self, name: str):
        from stmemu.peripherals.adc import Stm32AdcPeripheral
        model = self.bus.model_for_name(name)
        if not isinstance(model, Stm32AdcPeripheral):
            raise KeyError(f"unknown ADC peripheral: {name}")
        return model

    # ── Timer commands ─────────────────────────────────────────────

    def cmd_timer(self, argv: list[str]) -> str:
        usage = (
            "usage: timer list | timer status <name> | "
            "timer tick <name> <cycles> | timer force_update <name>"
        )
        if not argv:
            return usage
        sub = argv[0].lower().replace("-", "_")

        if sub == "list":
            from stmemu.peripherals.timer import BasicTimerPeripheral
            lines: list[str] = []
            for p in self.bus.amap.peripherals:
                model = self.bus.model_for_name(p.name)
                if isinstance(model, BasicTimerPeripheral):
                    cr1 = model.read_register_value(model._CR1)
                    cnt = model.read_register_value(model._CNT)
                    arr = model.read_register_value(model._ARR)
                    en = "ON" if cr1 & model._CR1_CEN else "off"
                    lines.append(f"{p.name:8} {en:3} CNT={cnt} ARR={arr}")
            return "\n".join(lines) if lines else "(no timer peripherals)"

        if sub == "status":
            if len(argv) != 2:
                return "usage: timer status <name>"
            model = self._resolve_timer_model(argv[1])
            cr1 = model.read_register_value(model._CR1)
            sr = model.read_register_value(model._SR)
            cnt = model.read_register_value(model._CNT)
            arr = model.read_register_value(model._ARR)
            psc = model.read_register_value(model._PSC)
            dier = model.read_register_value(model._DIER)
            return (
                f"{argv[1].upper()} CR1=0x{cr1:08X} SR=0x{sr:08X} "
                f"DIER=0x{dier:08X}\n"
                f"  CNT={cnt} ARR={arr} PSC={psc} "
                f"updates={model._update_count}"
            )

        if sub == "tick":
            if len(argv) != 3:
                return "usage: timer tick <name> <cycles>"
            model = self._resolve_timer_model(argv[1])
            cycles = _int(argv[2])
            model.tick(cycles)
            cnt = model.read_register_value(model._CNT)
            sr = model.read_register_value(model._SR)
            return f"{argv[1].upper()} ticked {cycles} cycles CNT={cnt} SR=0x{sr:08X}"

        if sub == "force_update":
            if len(argv) != 2:
                return "usage: timer force_update <name>"
            model = self._resolve_timer_model(argv[1])
            model.write(model._EGR, 4, model._EGR_UG)
            return f"{argv[1].upper()} update forced CNT={model.read_register_value(model._CNT)}"

        return usage

    def _resolve_timer_model(self, name: str):
        from stmemu.peripherals.timer import BasicTimerPeripheral
        model = self.bus.model_for_name(name)
        if not isinstance(model, BasicTimerPeripheral):
            raise KeyError(f"unknown timer peripheral: {name}")
        return model

    # ── Symbol table commands ──────────────────────────────────────

    def cmd_sym(self, argv: list[str]) -> str:
        usage = "usage: sym search <pattern> | sym addr <address> | sym name <name> | sym stats"
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "stats":
            t = self.emu.symbols
            return f"symbols loaded: {t.count}"

        if sub == "search":
            if len(argv) != 2:
                return "usage: sym search <pattern>"
            results = self.emu.symbols.search(argv[1])
            if not results:
                return "(no matches)"
            lines = []
            for s in results[:50]:
                lines.append(f"0x{s.address:08X}  {s.sym_type:6}  size={s.size:<6}  {s.name}")
            if len(results) > 50:
                lines.append(f"... and {len(results) - 50} more")
            return "\n".join(lines)

        if sub == "addr":
            if len(argv) != 2:
                return "usage: sym addr <address>"
            addr = _int(argv[1])
            return self.emu.symbols.format_addr(addr)

        if sub == "name":
            if len(argv) != 2:
                return "usage: sym name <name>"
            s = self.emu.symbols.lookup_name(argv[1])
            if s is None:
                return f"symbol not found: {argv[1]}"
            return f"0x{s.address:08X}  {s.sym_type:6}  size={s.size}  {s.name}"

        return usage

    # ── Semihosting commands ───────────────────────────────────────

    def cmd_semihost(self, argv: list[str]) -> str:
        usage = "usage: semihost on|off|status|drain|echo on|off"
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "on":
            self.emu.semihosting.enabled = True
            return "semihosting enabled"

        if sub == "off":
            self.emu.semihosting.enabled = False
            return "semihosting disabled"

        if sub == "status":
            sh = self.emu.semihosting
            buf_len = len(sh.output)
            return (
                f"enabled={sh.enabled}  echo={sh._console_echo}  "
                f"buffer={buf_len} bytes"
            )

        if sub == "drain":
            data = self.emu.semihosting.drain_output()
            if not data:
                return "(empty)"
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = repr(data)
            return f"--- semihosting output ({len(data)} bytes) ---\n{text}"

        if sub == "echo":
            if len(argv) != 2:
                return "usage: semihost echo on|off"
            self.emu.semihosting._console_echo = argv[1].lower() == "on"
            return f"semihost echo = {'on' if self.emu.semihosting._console_echo else 'off'}"

        return usage

    # ── Coverage commands ──────────────────────────────────────────

    def cmd_coverage(self, argv: list[str]) -> str:
        usage = (
            "usage: coverage on|off|status|clear|report [top]|hotspots [top]|"
            "functions [top]|ranges|diff <snapshot>|"
            "snapshot <name>|snapshots|"
            "export <file>|lcov <file>|pct"
        )
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "on":
            self.emu.coverage_enabled = True
            return "coverage tracking enabled"

        if sub == "off":
            self.emu.coverage_enabled = False
            return "coverage tracking disabled"

        if sub == "status":
            total_hits = sum(self.emu._coverage_hits.values())
            return (
                f"enabled={self.emu.coverage_enabled}  "
                f"unique_pcs={len(self.emu._coverage)}  "
                f"total_hits={total_hits}  "
                f"snapshots={len(self.emu._coverage_snapshots)}"
            )

        if sub == "clear":
            self.emu._coverage.clear()
            self.emu._coverage_hits.clear()
            return "coverage data cleared"

        if sub == "report":
            top = _int(argv[1]) if len(argv) > 1 else 30
            top = max(1, min(top, 200))
            pcs = sorted(self.emu._coverage)
            if not pcs:
                return "no coverage data"
            lines = [f"unique PCs covered: {len(pcs)}"]
            if len(pcs) <= top:
                for pc in pcs:
                    label = self.emu.symbols.format_addr(pc)
                    lines.append(f"  {label}")
            else:
                lines.append(f"(showing first {top} of {len(pcs)})")
                for pc in pcs[:top]:
                    label = self.emu.symbols.format_addr(pc)
                    lines.append(f"  {label}")
            return "\n".join(lines)

        if sub == "hotspots":
            top = _int(argv[1]) if len(argv) > 1 else 20
            top = max(1, min(top, 200))
            if not self.emu._coverage_hits:
                return "no coverage data"
            ranked = sorted(
                self.emu._coverage_hits.items(), key=lambda kv: kv[1], reverse=True
            )[:top]
            total = sum(self.emu._coverage_hits.values())
            lines = [f"top {min(top, len(ranked))} hotspots ({total} total instructions):"]
            for pc, hits in ranked:
                pct = (hits * 100.0 / total) if total else 0.0
                label = self.emu.symbols.format_addr(pc)
                lines.append(f"  {hits:8d}  {pct:5.1f}%  {label}")
            return "\n".join(lines)

        if sub == "functions":
            top = _int(argv[1]) if len(argv) > 1 else 20
            top = max(1, min(top, 200))
            if not self.emu._coverage_hits:
                return "no coverage data"
            return self._coverage_functions(top)

        if sub == "ranges":
            pcs = sorted(self.emu._coverage)
            if not pcs:
                return "no coverage data"
            return self._coverage_ranges(pcs)

        if sub == "pct":
            return self._coverage_pct()

        if sub == "diff":
            if len(argv) != 2:
                return "usage: coverage diff <snapshot>"
            return self._coverage_diff(argv[1])

        if sub == "snapshot":
            if len(argv) != 2:
                return "usage: coverage snapshot <name>"
            name = argv[1]
            self.emu._coverage_snapshots[name] = set(self.emu._coverage)
            return f"saved coverage snapshot '{name}' ({len(self.emu._coverage)} PCs)"

        if sub == "snapshots":
            if not self.emu._coverage_snapshots:
                return "(no coverage snapshots)"
            lines = []
            for name, pcs in sorted(self.emu._coverage_snapshots.items()):
                lines.append(f"  {name:20} {len(pcs)} PCs")
            return "\n".join(lines)

        if sub == "export":
            if len(argv) != 2:
                return "usage: coverage export <file>"
            pcs = sorted(self.emu._coverage)
            if not pcs:
                return "no coverage data to export"
            try:
                path = self._prepare_export_path(argv[1])
                lines = []
                for pc in pcs:
                    hits = self.emu._coverage_hits.get(pc, 0)
                    label = self.emu.symbols.format_addr(pc)
                    lines.append(f"0x{pc:08X}\t{hits}\t{label}")
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            except OSError as e:
                return f"error: {e}"
            return f"exported {len(pcs)} addresses to {path}"

        if sub == "lcov":
            if len(argv) != 2:
                return "usage: coverage lcov <file>"
            return self._coverage_lcov_export(argv[1])

        return usage

    def _coverage_functions(self, top: int) -> str:
        """Aggregate coverage by function using symbol table."""
        func_hits: dict[str, int] = {}
        func_pcs: dict[str, int] = {}
        unknown_hits = 0
        unknown_pcs = 0

        for pc, hits in self.emu._coverage_hits.items():
            sym = self.emu.symbols.find_containing(pc)
            if sym is not None:
                func_hits[sym.name] = func_hits.get(sym.name, 0) + hits
                func_pcs[sym.name] = func_pcs.get(sym.name, 0) + 1
            else:
                unknown_hits += hits
                unknown_pcs += 1

        if not func_hits and unknown_pcs == 0:
            return "no coverage data (or no symbols loaded)"

        ranked = sorted(func_hits.items(), key=lambda kv: kv[1], reverse=True)[:top]
        total_hits = sum(self.emu._coverage_hits.values())
        lines = [f"function coverage ({len(func_hits)} functions hit, {total_hits} total instructions):"]
        for name, hits in ranked:
            pct = (hits * 100.0 / total_hits) if total_hits else 0.0
            pcs = func_pcs.get(name, 0)
            sym = self.emu.symbols.lookup_name(name)
            size_str = ""
            if sym and sym.size > 0:
                # Estimate instruction coverage within this function
                # Thumb instructions are 2 or 4 bytes; use 2 as estimate
                est_insns = sym.size // 2
                func_cov = min(100.0, pcs * 100.0 / est_insns) if est_insns > 0 else 0.0
                size_str = f"  cov~{func_cov:.0f}%"
            lines.append(f"  {hits:8d}  {pct:5.1f}%  {pcs:4d} PCs  {name}{size_str}")
        if unknown_pcs > 0:
            pct = (unknown_hits * 100.0 / total_hits) if total_hits else 0.0
            lines.append(f"  {unknown_hits:8d}  {pct:5.1f}%  {unknown_pcs:4d} PCs  (unknown/no symbol)")
        return "\n".join(lines)

    def _coverage_ranges(self, pcs: list[int]) -> str:
        """Show contiguous covered address ranges."""
        if not pcs:
            return "no coverage data"
        ranges: list[tuple[int, int, int]] = []
        start = pcs[0]
        prev = pcs[0]
        count = 1
        for pc in pcs[1:]:
            # Consider PCs within 4 bytes as contiguous (Thumb instructions are 2 or 4 bytes)
            if pc <= prev + 4:
                prev = pc
                count += 1
            else:
                ranges.append((start, prev, count))
                start = pc
                prev = pc
                count = 1
        ranges.append((start, prev, count))

        lines = [f"{len(ranges)} contiguous range(s) from {len(pcs)} PCs:"]
        for rstart, rend, rcount in ranges:
            span = rend - rstart + 2  # +2 for last instruction
            label_start = self.emu.symbols.format_addr(rstart)
            label_end = self.emu.symbols.format_addr(rend)
            lines.append(
                f"  0x{rstart:08X}-0x{rend + 1:08X}  "
                f"{span:5d} bytes  {rcount:4d} PCs  "
                f"{label_start} .. {label_end}"
            )
        return "\n".join(lines)

    def _coverage_pct(self) -> str:
        """Calculate coverage percentage of firmware flash area."""
        if not self.emu._coverage:
            return "no coverage data"
        flash_base = self.emu.flash_base
        flash_end = self.emu.flash_end
        flash_size = flash_end - flash_base
        if flash_size <= 0:
            return "flash size unknown"

        in_flash = sum(1 for pc in self.emu._coverage if flash_base <= pc < flash_end)
        # Estimate total instructions: Thumb = 2 bytes average
        est_total_insns = flash_size // 2
        pct = (in_flash * 100.0 / est_total_insns) if est_total_insns > 0 else 0.0
        return (
            f"flash: 0x{flash_base:08X}-0x{flash_end:08X} ({flash_size} bytes)\n"
            f"covered: {in_flash} unique PCs of ~{est_total_insns} estimated instructions\n"
            f"coverage: {pct:.2f}%"
        )

    def _coverage_diff(self, snapshot_name: str) -> str:
        """Show coverage difference vs a saved snapshot."""
        snap = self.emu._coverage_snapshots.get(snapshot_name)
        if snap is None:
            return f"unknown coverage snapshot: {snapshot_name}"
        current = self.emu._coverage
        added = sorted(current - snap)
        removed = sorted(snap - current)
        lines = [
            f"diff vs '{snapshot_name}': "
            f"+{len(added)} new PCs, -{len(removed)} lost PCs"
        ]
        if added:
            show = added[:20]
            lines.append("  new:")
            for pc in show:
                lines.append(f"    + {self.emu.symbols.format_addr(pc)}")
            if len(added) > 20:
                lines.append(f"    ... and {len(added) - 20} more")
        if removed:
            show = removed[:20]
            lines.append("  lost:")
            for pc in show:
                lines.append(f"    - {self.emu.symbols.format_addr(pc)}")
            if len(removed) > 20:
                lines.append(f"    ... and {len(removed) - 20} more")
        return "\n".join(lines)

    def _coverage_lcov_export(self, raw_path: str) -> str:
        """Export coverage in LCOV tracefile format for use with genhtml/etc."""
        if not self.emu._coverage_hits:
            return "no coverage data to export"

        # Group by function
        func_data: dict[str, list[tuple[int, int]]] = {}
        unknown_data: list[tuple[int, int]] = []
        for pc, hits in sorted(self.emu._coverage_hits.items()):
            sym = self.emu.symbols.find_containing(pc)
            if sym is not None:
                func_data.setdefault(sym.name, []).append((pc, hits))
            else:
                unknown_data.append((pc, hits))

        try:
            path = self._prepare_export_path(raw_path)
            lines: list[str] = []
            source = "firmware.elf"

            lines.append("TN:")
            lines.append(f"SF:{source}")

            # Function entries
            for fname, pcs in sorted(func_data.items()):
                sym = self.emu.symbols.lookup_name(fname)
                addr = sym.address if sym else pcs[0][0]
                total_hits = sum(h for _, h in pcs)
                lines.append(f"FN:{addr},{fname}")
                lines.append(f"FNDA:{total_hits},{fname}")

            lines.append(f"FNF:{len(func_data)}")
            lines.append(f"FNH:{len(func_data)}")

            # Line/address entries (we use PC addresses as "line numbers")
            for pc, hits in sorted(self.emu._coverage_hits.items()):
                lines.append(f"DA:{pc},{hits}")
            lines.append(f"LF:{len(self.emu._coverage_hits)}")
            lines.append(f"LH:{len(self.emu._coverage_hits)}")

            lines.append("end_of_record")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as e:
            return f"error: {e}"

        return (
            f"exported LCOV data to {path} "
            f"({len(func_data)} functions, {len(self.emu._coverage_hits)} addresses)"
        )

    # ── Fuzzer commands ────────────────────────────────────────────

    def cmd_fuzz(self, argv: list[str]) -> str:
        usage = (
            "usage: fuzz setup [snapshot_name] | fuzz run <iterations> [steps] | "
            "fuzz profile <file.yaml|file.json> | "
            "fuzz targets | fuzz stats | fuzz findings [max] | "
            "fuzz corpus | fuzz seed <hexbytes|@file> | "
            "fuzz dict <token_hex> | fuzz config <key> <value> | "
            "fuzz target memory <name> <addr> [size_reg] | "
            "fuzz target function <name> <entry_addr> <buffer_addr> | "
            "fuzz replay <index> [steps] [trace] | "
            "fuzz export findings <file> | fuzz export corpus <dir> | "
            "fuzz import <dir> | fuzz reset"
        )
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "setup":
            snap_name = argv[1] if len(argv) > 1 else "__fuzz_baseline"
            return self._fuzz_setup(snap_name)

        if sub == "profile":
            if len(argv) != 2:
                return "usage: fuzz profile <file.yaml|file.json>"
            return self._fuzz_load_profile(argv[1])

        if sub == "run":
            if len(argv) < 2:
                return "usage: fuzz run <iterations> [steps_per_iter]"
            iters = _int(argv[1])
            if iters <= 0:
                return "iterations must be > 0"
            steps = _int(argv[2]) if len(argv) > 2 else 5000
            if steps <= 0:
                return "steps must be > 0"
            return self._fuzz_run(iters, steps)

        if sub == "targets":
            return self._fuzz_targets()

        if sub == "target":
            return self._fuzz_add_target(argv[1:])

        if sub == "stats":
            return self._fuzz_stats()

        if sub == "findings":
            max_show = _int(argv[1]) if len(argv) > 1 else 20
            return self._fuzz_findings(max_show)

        if sub == "corpus":
            return self._fuzz_corpus()

        if sub == "seed":
            if len(argv) != 2:
                return "usage: fuzz seed <hexbytes|@file>"
            try:
                data = self._read_bytes_spec(argv[1])
            except Exception as e:
                return f"error: {e}"
            self._ensure_fuzz_engine()
            self._fuzz_engine.add_seed_input(data)
            return f"added seed input ({len(data)} bytes)"

        if sub == "dict":
            if len(argv) != 2:
                return "usage: fuzz dict <token_hex>"
            try:
                token = bytes.fromhex(argv[1])
            except ValueError:
                return "invalid hex for dictionary token"
            self._ensure_fuzz_engine()
            self._fuzz_engine.mutator.add_dict_entry(token)
            return f"added dictionary token ({len(token)} bytes)"

        if sub == "config":
            if len(argv) != 3:
                return "usage: fuzz config <key> <value>"
            return self._fuzz_config(argv[1], argv[2])

        if sub == "replay":
            if len(argv) < 2:
                return "usage: fuzz replay <index> [steps] [trace]"
            return self._fuzz_replay(argv[1:])

        if sub == "export":
            if len(argv) < 3:
                return "usage: fuzz export findings <file> | fuzz export corpus <dir>"
            return self._fuzz_export(argv[1], argv[2])

        if sub == "import":
            if len(argv) != 2:
                return "usage: fuzz import <dir>"
            return self._fuzz_import(argv[1])

        if sub == "reset":
            return self._fuzz_reset()

        return usage

    def _ensure_fuzz_engine(self):
        if not hasattr(self, "_fuzz_engine") or self._fuzz_engine is None:
            from stmemu.fuzz.engine import FuzzEngine
            self._fuzz_engine = FuzzEngine(emu=self.emu, bus=self.bus)

    def _fuzz_setup(self, snap_name: str) -> str:
        self._ensure_fuzz_engine()
        result = self._fuzz_engine.setup(snapshot_name=snap_name)
        return f"fuzz setup: {result}"

    def _fuzz_load_profile(self, path_str: str) -> str:
        from stmemu.fuzz.profile import load_profile, apply_profile
        path = Path(path_str).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        try:
            profile = load_profile(path)
        except Exception as e:
            return f"error loading profile: {e}"
        self._ensure_fuzz_engine()
        try:
            result = apply_profile(
                profile, self._fuzz_engine, base_dir=path.parent,
            )
        except Exception as e:
            return f"error applying profile: {e}"
        snap = profile.snapshot
        setup_result = self._fuzz_engine.setup(snapshot_name=snap)
        return f"{result}\n\nfuzz setup: {setup_result}"

    def _fuzz_add_target(self, argv: list[str]) -> str:
        target_usage = (
            "usage: fuzz target memory <name> <addr> [size_reg] | "
            "fuzz target function <name> <entry_addr> <buffer_addr> [key=value ...]"
            "\n  function options: abi=ptr_len|ptr|regs  stop=steps|return|pc"
            "\n    return_addr=<addr>  stop_pc=<addr>  buf_reg=<reg>  len_reg=<reg>"
        )
        if len(argv) < 3:
            return target_usage
        self._ensure_fuzz_engine()
        eng = self._fuzz_engine
        if eng.injector is None:
            from stmemu.fuzz.injector import Injector
            eng.injector = Injector(bus=self.bus, emu=self.emu)

        kind = argv[0].lower()
        if kind == "memory":
            name = argv[1]
            addr = _int(argv[2])
            size_reg = argv[3] if len(argv) > 3 else None
            eng.injector.add_memory_target(name, addr, size_reg=size_reg)
            desc = f"memory target '{name}' @0x{addr:08X}"
            if size_reg:
                desc += f" size_reg={size_reg}"
            return f"added {desc}"

        if kind == "function":
            if len(argv) < 4:
                return target_usage
            name = argv[1]
            entry_addr = _int(argv[2])
            buffer_addr = _int(argv[3])

            kv: dict[str, str] = {}
            for tok in argv[4:]:
                if "=" not in tok:
                    return f"expected key=value, got: {tok!r}\n{target_usage}"
                k, v = tok.split("=", 1)
                kv[k.lower()] = v

            from stmemu.fuzz.injector import FunctionTargetConfig
            try:
                cfg = FunctionTargetConfig(
                    abi=kv.get("abi", "ptr_len"),
                    stop=kv.get("stop", "steps"),
                    return_addr=_int(kv["return_addr"]) if "return_addr" in kv else 0,
                    stop_pc=_int(kv["stop_pc"]) if "stop_pc" in kv else 0,
                    buf_reg=kv.get("buf_reg", "r0"),
                    len_reg=kv.get("len_reg", "r1"),
                )
            except ValueError as e:
                return f"error: {e}"

            eng.injector.add_function_target(
                name, entry_addr, buffer_addr, fn_config=cfg,
            )

            parts = [
                f"added function target '{name}'",
                f"entry=0x{entry_addr:08X} buf=0x{buffer_addr:08X}",
                f"abi={cfg.abi} stop={cfg.stop}",
            ]
            if cfg.stop == "return" and cfg.return_addr:
                parts.append(f"return_addr=0x{cfg.return_addr:08X}")
            if cfg.stop == "pc" and cfg.stop_pc:
                parts.append(f"stop_pc=0x{cfg.stop_pc:08X}")
            return " ".join(parts)

        return target_usage

    def _fuzz_run(self, iterations: int, steps: int) -> str:
        self._ensure_fuzz_engine()
        if not self._fuzz_engine._snapshot_name:
            return "error: run 'fuzz setup' first"
        findings = self._fuzz_engine.run(iterations=iterations, steps_per_iter=steps)
        lines = [self._fuzz_engine.format_stats()]
        if findings:
            lines.append("")
            crash_count = sum(1 for f in findings if "crash" in f.kind)
            hang_count = sum(1 for f in findings if f.kind == "hang")
            cov_count = sum(1 for f in findings if f.kind == "new_coverage")
            lines.append(
                f"session: {len(findings)} findings "
                f"({crash_count} crashes, {hang_count} hangs, {cov_count} new coverage)"
            )
        return "\n".join(lines)

    def _fuzz_targets(self) -> str:
        self._ensure_fuzz_engine()
        if not self._fuzz_engine.injector:
            return "(not set up — run 'fuzz setup' first)"
        targets = self._fuzz_engine.injector.list_targets()
        if not targets:
            return "(no injectable targets found)"
        lines = [f"{len(targets)} target(s):"]
        for t in targets:
            lines.append(f"  {t['kind']:6}  {t['name']}")
        return "\n".join(lines)

    def _fuzz_stats(self) -> str:
        self._ensure_fuzz_engine()
        return self._fuzz_engine.format_stats()

    def _fuzz_findings(self, max_show: int) -> str:
        self._ensure_fuzz_engine()
        return self._fuzz_engine.format_findings(max_show)

    def _fuzz_corpus(self) -> str:
        self._ensure_fuzz_engine()
        corpus = self._fuzz_engine.corpus
        if not corpus:
            return "(empty corpus)"
        lines = [f"{len(corpus)} corpus entry/entries:"]
        for i, entry in enumerate(corpus[:30]):
            preview = entry.data[:16].hex()
            if len(entry.data) > 16:
                preview += "..."
            lines.append(
                f"  [{i:4d}] iter={entry.iteration_found:5d} "
                f"+{entry.new_pcs}PCs "
                f"{entry.target_kind}:{entry.target_name:8s} "
                f"{len(entry.data):3d}B  {preview}"
            )
        if len(corpus) > 30:
            lines.append(f"  ... and {len(corpus) - 30} more")
        return "\n".join(lines)

    def _fuzz_config(self, key: str, value: str) -> str:
        self._ensure_fuzz_engine()
        eng = self._fuzz_engine
        key_lower = key.lower()
        if key_lower == "min_len":
            eng.min_input_len = max(1, _int(value))
            return f"min_input_len = {eng.min_input_len}"
        if key_lower == "max_len":
            eng.max_input_len = max(1, _int(value))
            return f"max_input_len = {eng.max_input_len}"
        if key_lower == "max_mutations":
            eng.max_mutations = max(1, _int(value))
            return f"max_mutations = {eng.max_mutations}"
        if key_lower == "mode":
            if value.lower() not in ("random", "round_robin", "all"):
                return "mode must be: random, round_robin, or all"
            eng.mode = value.lower()
            return f"mode = {eng.mode}"
        if key_lower == "seed":
            eng.seed(_int(value))
            return f"rng seed = {value}"
        if key_lower == "target":
            if eng.target_filter is None:
                eng.target_filter = []
            eng.target_filter.append(value)
            return f"target filter: {eng.target_filter}"
        if key_lower == "capture_mmio":
            eng.capture_mmio = value.lower() in ("on", "true", "1", "yes")
            return f"capture_mmio = {'on' if eng.capture_mmio else 'off'}"
        if key_lower == "coverage_mode":
            if value.lower() not in ("edge", "block"):
                return "coverage_mode must be: edge or block"
            eng.coverage_mode = value.lower()
            return f"coverage_mode = {eng.coverage_mode}"
        if key_lower == "coverage_start":
            start = _int(value)
            end = eng.coverage_filter[1] if eng.coverage_filter else 0
            eng.coverage_filter = (start, end) if end > start else (start, end)
            return f"coverage_filter = {_fmt_cov_filter(eng.coverage_filter)}"
        if key_lower == "coverage_end":
            start = eng.coverage_filter[0] if eng.coverage_filter else 0
            end = _int(value)
            eng.coverage_filter = (start, end) if end > start else (start, end)
            return f"coverage_filter = {_fmt_cov_filter(eng.coverage_filter)}"
        if key_lower == "faults":
            if not value or value.lower() in ("all", "none", ""):
                eng.fault_policy = {}
                return "fault_policy = all (no filter)"
            eng.fault_policy = {f.strip(): True for f in value.split(",") if f.strip()}
            return f"fault_policy = {', '.join(sorted(eng.fault_policy))}"
        return (
            f"unknown config key: {key} "
            "(valid: min_len, max_len, max_mutations, mode, seed, target, "
            "capture_mmio, coverage_mode, coverage_start, coverage_end, faults)"
        )

    def _fuzz_replay(self, argv: list[str]) -> str:
        self._ensure_fuzz_engine()
        eng = self._fuzz_engine
        if not eng._snapshot_name:
            return "error: run 'fuzz setup' first"

        idx = _int(argv[0])
        steps = 5000
        enable_trace = False
        for tok in argv[1:]:
            if tok.lower() == "trace":
                enable_trace = True
            else:
                steps = _int(tok)

        try:
            result = eng.replay(idx, steps=steps, enable_trace=enable_trace)
        except (IndexError, RuntimeError) as e:
            return f"error: {e}"
        return eng.format_replay(result)

    def _fuzz_export(self, what: str, path_str: str) -> str:
        self._ensure_fuzz_engine()
        eng = self._fuzz_engine
        if what == "findings":
            try:
                path = self._prepare_export_path(path_str)
                count = eng.export_findings(path)
            except OSError as e:
                return f"error: {e}"
            return f"exported {count} findings to {path}"
        if what == "corpus":
            try:
                path = Path(path_str).expanduser()
                count = eng.export_corpus(path)
            except OSError as e:
                return f"error: {e}"
            return f"exported {count} corpus entries to {path}"
        return "usage: fuzz export findings <file> | fuzz export corpus <dir>"

    def _fuzz_import(self, dir_str: str) -> str:
        self._ensure_fuzz_engine()
        directory = Path(dir_str).expanduser()
        if not directory.is_dir():
            return f"not a directory: {dir_str}"
        count = self._fuzz_engine.import_corpus(directory)
        return f"imported {count} seed inputs from {directory}"

    def _fuzz_reset(self) -> str:
        self._ensure_fuzz_engine()
        self._fuzz_engine.reset()
        return "fuzzer state reset"

    # ── RTOS awareness commands ────────────────────────────────────

    def cmd_rtos(self, argv: list[str]) -> str:
        usage = "usage: rtos status | rtos trace on|off"
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "status":
            s = self.emu.rtos_status()
            lines = [
                f"trace: {'on' if s['trace_enabled'] else 'off'}",
                f"context switches: {s['switch_count']}",
                f"PSP: 0x{s['psp']:08X}  MSP: 0x{s['msp']:08X}  CONTROL: 0x{s['control']:08X}",
                f"in handler: {'yes' if s['in_handler'] else 'no'} (depth={s['exception_depth']})",
                f"instructions: {s['instruction_count']}",
            ]
            if s['active_exceptions']:
                names = []
                for exc in s['active_exceptions']:
                    if hasattr(self.emu, 'core_peripheral') and self.emu.core_peripheral:
                        names.append(self.emu.core_peripheral.exception_name(exc))
                    else:
                        names.append(str(exc))
                lines.append(f"active: {', '.join(names)}")
            return "\n".join(lines)

        if sub == "trace":
            if len(argv) != 2:
                return "usage: rtos trace on|off"
            on = argv[1].lower() in ("on", "true", "1")
            self.emu.rtos_trace_enabled = on
            return f"rtos trace {'on' if on else 'off'}"

        return usage

    # ── Board config commands ─────────────────────────────────────

    def cmd_board(self, argv: list[str]) -> str:
        usage = "usage: board load <file> | board show | board validate <file>"
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "load":
            if len(argv) != 2:
                return "usage: board load <file.yaml|file.json>"
            from stmemu.board_config import load_board_config, apply_board_config
            path = Path(argv[1]).expanduser()
            try:
                config = load_board_config(path)
            except Exception as e:
                return f"error loading board config: {e}"
            try:
                messages = apply_board_config(
                    config, self.bus, self.emu,
                    base_dir=path.parent,
                    source=f"board load {path.name}",
                )
            except Exception as e:
                return f"error applying board config: {e}"
            return "\n".join(messages) if messages else "board config applied (empty)"

        if sub == "show":
            return self._board_show()

        if sub == "validate":
            if len(argv) != 2:
                return "usage: board validate <file>"
            from stmemu.board_config import load_board_config, validate_config
            path = Path(argv[1]).expanduser()
            try:
                config = load_board_config(path)
            except Exception as e:
                return f"error loading: {e}"
            warnings = validate_config(config)
            if not warnings:
                return "config OK (no warnings)"
            return "\n".join(f"warning: {w}" for w in warnings)

        return usage

    def _board_show(self) -> str:
        from stmemu.board_config import config_applied_summary
        applied = config_applied_summary()
        lines_dict = self.bus.serial_lines()
        timed = self.emu.list_timed_events() if hasattr(self.emu, "list_timed_events") else []
        evt_bps = self.emu.list_event_breakpoints() if hasattr(self.emu, "list_event_breakpoints") else []

        lines = [f"configs applied: {len(applied)}"]
        for i, a in enumerate(applied):
            lines.append(f"  [{i}] {a.get('_source', '?')} sections={a.get('_sections', [])}")

        lines.append(f"serial lines: {len(lines_dict)}")
        for name, line in lines_dict.items():
            dev = getattr(line, "device", None)
            lines.append(f"  {name}: {type(dev).__name__ if dev else 'none'}")

        lines.append(f"timed events: {len(timed)} pending")
        lines.append(f"event breakpoints: {len(evt_bps)}")
        lines.append(f"bus policy: {self.bus.access_policy}")
        if hasattr(self.emu, "rtos_trace_enabled"):
            lines.append(f"rtos trace: {'on' if self.emu.rtos_trace_enabled else 'off'}")
        if hasattr(self.emu, "coverage_enabled"):
            lines.append(f"coverage: {'on' if self.emu.coverage_enabled else 'off'}")
        return "\n".join(lines)

    # ── Timed event commands ─────────────────────────────────────

    def cmd_timed(self, argv: list[str]) -> str:
        usage = (
            "usage: timed list | timed clear | "
            "timed add <at> <action> [key=value ...] | timed count"
        )
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "list":
            events = self.emu.list_timed_events()
            if not events:
                return "(no timed events)"
            lines = [f"{len(events)} timed event(s):"]
            for e in events:
                parts = [f"  @{e['at']:>8d} {e['action']}"]
                for k, v in e.items():
                    if k not in ("at", "action", "fired"):
                        parts.append(f"{k}={v}")
                lines.append(" ".join(parts))
            return "\n".join(lines)

        if sub == "count":
            return f"instruction count: {self.emu.instruction_count}"

        if sub == "clear":
            count = self.emu.clear_timed_events()
            return f"cleared {count} timed event(s)"

        if sub == "add":
            if len(argv) < 3:
                return "usage: timed add <at> <action> [key=value ...]"
            at = _int(argv[1])
            action = argv[2]
            params: dict[str, str] = {}
            for tok in argv[3:]:
                if "=" not in tok:
                    return f"expected key=value, got: {tok!r}"
                k, v = tok.split("=", 1)
                params[k] = v
            self.emu.add_timed_event(at, action, **params)
            return f"timed event @{at}: {action}"

        return usage

    # ── External device commands ──────────────────────────────────

    def _get_device_types(self) -> dict[str, type]:
        if not hasattr(Commands, "_device_types_cache"):
            from stmemu.external.ublox import UbloxGpsDevice
            Commands._device_types_cache = {
                "ublox": UbloxGpsDevice,
                "ublox-gps": UbloxGpsDevice,
            }
        return Commands._device_types_cache

    def cmd_device(self, argv: list[str]) -> str:
        usage = (
            "usage: device list | device attach uart <PERIPH> <type> [key=value ...] | "
            "device status [name] | device inject <name> <hex|@file> | "
            "device detach <name>"
        )
        if not argv:
            return usage
        sub = argv[0].lower()

        if sub == "list":
            return self._device_list()
        if sub == "attach":
            return self._device_attach(argv[1:])
        if sub == "status":
            name = argv[1] if len(argv) > 1 else None
            return self._device_status(name)
        if sub == "inject":
            if len(argv) < 3:
                return "usage: device inject <name> <hex|@file>"
            return self._device_inject(argv[1], argv[2])
        if sub == "detach":
            if len(argv) != 2:
                return "usage: device detach <name>"
            return self._device_detach(argv[1])
        if sub == "types":
            _dtypes = self._get_device_types()
            return "device types: " + ", ".join(sorted(_dtypes))
        return usage

    def _device_list(self) -> str:
        lines_dict = self.bus.serial_lines()
        if not lines_dict:
            return "(no external devices attached)"
        lines = [f"{len(lines_dict)} device(s):"]
        for name, line in lines_dict.items():
            dev = getattr(line, "device", None)
            uart = getattr(line, "uart", None)
            dev_type = type(dev).__name__ if dev else "none"
            uart_name = "?"
            for m in self.bus.mounted_ranges():
                if m.model is uart:
                    uart_name = m.name
                    break
            lines.append(f"  {name:16s} {dev_type:20s} uart={uart_name}")
        return "\n".join(lines)

    def _device_attach(self, argv: list[str]) -> str:
        attach_usage = (
            "usage: device attach uart <PERIPH> <type> [key=value ...]\n"
            "  types: ublox, ublox-gps"
        )
        if len(argv) < 3:
            return attach_usage
        transport = argv[0].lower()
        if transport != "uart":
            return f"unknown transport: {transport}\n{attach_usage}"

        periph_name = argv[1].upper()
        dev_type = argv[2].lower()

        _dtypes = self._get_device_types()
        dev_cls = _dtypes.get(dev_type)
        if dev_cls is None:
            return f"unknown device type: {dev_type} (available: {', '.join(sorted(_dtypes))})"

        uart_model = self.bus.model_for_name(periph_name)
        if uart_model is None:
            return f"unknown peripheral: {periph_name}"
        if not hasattr(uart_model, "inject_rx_bytes"):
            return f"{periph_name} is not a UART peripheral"

        kv: dict[str, str] = {}
        for tok in argv[3:]:
            if "=" not in tok:
                return f"expected key=value, got: {tok!r}"
            k, v = tok.split("=", 1)
            kv[k.lower()] = v

        dev = dev_cls()
        dev.name = kv.pop("name", f"{periph_name.lower()}_{dev_type}")
        if "mode" in kv:
            dev.mode = kv.pop("mode")
        if "lat" in kv:
            dev.lat = float(kv.pop("lat"))
        if "lon" in kv:
            dev.lon = float(kv.pop("lon"))
        if "alt" in kv:
            dev.alt = float(kv.pop("alt"))
        if "rate_cycles" in kv:
            dev.rate_cycles = _int(kv.pop("rate_cycles"))

        from stmemu.external.serial_line import SerialLine
        line_name = dev.name
        line = SerialLine(line_name, uart=uart_model, device=dev)
        self.bus.attach_serial_line(line)

        parts = [
            f"attached '{line_name}'",
            f"type={type(dev).__name__}",
            f"uart={periph_name}",
        ]
        if hasattr(dev, "mode"):
            parts.append(f"mode={dev.mode}")
        return " ".join(parts)

    def _device_status(self, name: str | None) -> str:
        lines_dict = self.bus.serial_lines()
        if name is not None:
            line = lines_dict.get(name)
            if line is None:
                return f"unknown device: {name}"
            targets = [(name, line)]
        elif not lines_dict:
            return "(no external devices)"
        else:
            targets = list(lines_dict.items())

        result = []
        for lname, line in targets:
            dev = getattr(line, "device", None)
            if dev is None:
                result.append(f"{lname}: no device")
                continue
            parts = [f"{lname}: {type(dev).__name__}"]
            for attr in ("mode", "lat", "lon", "alt", "fix_type", "sats", "rate_cycles"):
                if hasattr(dev, attr):
                    parts.append(f"  {attr}={getattr(dev, attr)}")
            parts.append(f"  tx_pending={dev.pending_tx_len()}")
            result.append("\n".join(parts))
        return "\n".join(result)

    def _device_inject(self, name: str, data_spec: str) -> str:
        lines_dict = self.bus.serial_lines()
        line = lines_dict.get(name)
        if line is None:
            return f"unknown device: {name}"
        dev = getattr(line, "device", None)
        if dev is None:
            return f"{name}: no device attached"
        try:
            data = self._read_bytes_spec(data_spec)
        except Exception as e:
            return f"error: {e}"
        dev.on_rx_from_mcu(data)
        return f"injected {len(data)} bytes into {name}"

    def _device_detach(self, name: str) -> str:
        if self.bus.detach_serial_line(name):
            return f"detached '{name}'"
        return f"unknown device: {name}"
