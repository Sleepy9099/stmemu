from __future__ import annotations

from dataclasses import dataclass

from stmemu.core.emulator import Emulator
from stmemu.peripherals.bus import PeripheralBus
from stmemu.utils.hexdump import hexdump
from stmemu.core.disasm import ThumbDisassembler

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
        self.emu.step(n)
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
        self.emu.run(n)
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
        if len(argv) != 1:
            return "usage: reg <r0..r12|sp|lr|pc>"
        name = argv[0].lower()
        regs = self.emu.read_regs()
        if name not in regs:
            return f"unknown reg: {name}"
        return f"{name} = 0x{regs[name]:08X}"

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
        trace until <pc>
        """
        if not argv:
            flags = []
            if self.emu.trace_enabled:
                flags.append("on")
            if self.emu.trace_mmio_only:
                flags.append("mmio")
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
            return "trace = off"

        if sub == "mmio":
            self.emu.trace_enabled = True
            self.emu.trace_mmio_only = True
            return "trace = on (mmio-only)"

        if sub == "until":
            if len(argv) != 2:
                return "usage: trace until <pc>"
            pc = int(argv[1], 0) & ~1
            self.emu.trace_enabled = True
            self.emu.trace_until_pc = pc
            return f"trace = on until 0x{pc:08X}"

        return "usage: trace [on|off|mmio|until <pc>]"

