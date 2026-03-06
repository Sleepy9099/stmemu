from __future__ import annotations

import csv
import json
import shlex
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from stmemu.core.emulator import Emulator, PcRegWrite
from stmemu.peripherals.bus import PeripheralBus
from stmemu.peripherals.usart import Stm32UsartPeripheral
from stmemu.utils.hexdump import hexdump
from stmemu.core.disasm import ThumbDisassembler
from unicorn.unicorn_const import UC_HOOK_CODE

def _int(s: str) -> int:
    return int(s, 0)


@dataclass
class Commands:
    emu: Emulator
    bus: PeripheralBus

    def __post_init__(self) -> None:
        self._dasm = ThumbDisassembler()

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
        return f"pc=0x{self.emu.pc:08X}"

    def cmd_mem(self, argv: list[str]) -> str:
        if len(argv) < 1:
            return "usage: mem r <addr> <len> | mem w <addr> <hexbytes>"
        op = argv[0]
        if op == "r":
            if len(argv) != 3:
                return "usage: mem r <addr> <len>"
            addr = _int(argv[1]); ln = _int(argv[2])
            data = self.emu.mem_read(addr, ln)
            return hexdump(data, base=addr)
        if op == "w":
            if len(argv) != 3:
                return "usage: mem w <addr> <hexbytes>"
            addr = _int(argv[1])
            hx = argv[2].replace(" ", "")
            data = bytes.fromhex(hx)
            self.emu.mem_write(addr, data)
            return f"wrote {len(data)} bytes to 0x{addr:08X}"
        return "usage: mem r <addr> <len> | mem w <addr> <hexbytes>"

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
            return f"[0x{addr:08X}] = 0x{val:08X}"

        if sub == "write":
            if len(argv) != 3:
                return "usage: periph write <P.REG|addr> <value>"
            addr = self._resolve_periph_addr(argv[1])
            val = _int(argv[2])
            self.bus.write(addr, 4, val)
            return f"[0x{addr:08X}] <- 0x{val:08X}"

        return "usage: periph list | periph read <P.REG|addr> | periph write <P.REG|addr> <value>"

    def cmd_uart(self, argv: list[str]) -> str:
        if not argv:
            return "usage: uart list | uart status <name> | uart rx <name> <hexbytes> | uart tx <name> [clear]"

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
                return "usage: uart rx <name> <hexbytes>"
            model = self._resolve_uart_model(argv[1])
            payload = bytes.fromhex(argv[2].replace(" ", ""))
            model.inject_rx_bytes(payload)
            return f"injected {len(payload)} byte(s) into {argv[1].upper()}"

        if sub == "tx":
            if len(argv) not in {2, 3}:
                return "usage: uart tx <name> [clear]"
            model = self._resolve_uart_model(argv[1])
            clear = len(argv) == 3 and argv[2].lower() == "clear"
            payload = model.drain_tx_bytes() if clear else model.peek_tx_bytes()
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in payload)
            return (
                f"{argv[1].upper()} tx_len={len(payload)}\n"
                f"hex  = {payload.hex() or '-'}\n"
                f"ascii= {text or '-'}"
            )

        return "usage: uart list | uart status <name> | uart rx <name> <hexbytes> | uart tx <name> [clear]"

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

        p = next((x for x in self.bus.amap.peripherals if x.name == p_name), None)
        if not p:
            raise KeyError(f"unknown peripheral: {p_name}")

        r = next((x for x in p.registers if x.name == r_name), None)
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
            raise ValueError(f"unknown command: {tokens[0]}")
        out = handler(tokens[1:])
        return "" if out is None else str(out)

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
            for i in range(max_steps + 1):
                current = int(getattr(self.emu, "pc", 0)) & ~1
                if current == target:
                    return
                if i == max_steps:
                    break
                self.emu.step(1)
            current = int(getattr(self.emu, "pc", 0)) & ~1
            raise AssertionError(
                f"wait pc timeout: target=0x{target:08X} current=0x{current:08X} steps={max_steps}"
            )

        if subject == "fault":
            if len(argv) not in (1, 2):
                raise ValueError("usage: wait fault [max_steps]")
            max_steps = _int(argv[1]) if len(argv) == 2 else 100000
            if max_steps < 0:
                raise ValueError("max_steps must be >= 0")
            for i in range(max_steps + 1):
                if getattr(self.emu, "last_fault_report", None) is not None:
                    return
                if i == max_steps:
                    break
                self.emu.step(1)
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

            p = next((x for x in self.bus.amap.peripherals if x.name == periph_name), None)
            if not p:
                raise ValueError(f"unknown peripheral: {periph_name}")

            r = next((x for x in p.registers if x.name == reg_name), None)
            if not r:
                raise ValueError(f"unknown register: {periph_name}.{reg_name}")

            size_bits = getattr(r, "size_bits", 32)
            size_bytes = max(1, (size_bits + 7) // 8)

            start = p.base_address + r.offset
            end = start + size_bytes - 1

            return (f"{p.name}.{r.name}", start, end)

        # --- PERIPH ---
        p = next((x for x in self.bus.amap.peripherals if x.name == s), None)
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
