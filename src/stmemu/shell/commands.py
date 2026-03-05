from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from sys import argv

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
        self.emu.step(n)
        if getattr(self.emu, "last_pc_break", None) is not None:
            return f"PC BP HIT: 0x{int(self.emu.last_pc_break):08X}"
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
        if getattr(self.emu, "last_pc_break", None) is not None:
            return f"PC BP HIT: 0x{int(self.emu.last_pc_break):08X}"
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

    def cmd_mmioprof(self, argv: list[str]) -> str:
        if not argv:
            return "usage: mmioprof <instructions> [top]"
        steps = _int(argv[0])
        if steps <= 0:
            return "instructions must be > 0"
        top = _int(argv[1]) if len(argv) > 1 else 20
        top = max(1, min(int(top), 100))

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

        lines = [
            f"pc = 0x{self.emu.pc:08X}",
            f"instructions = {steps}",
            f"read_events = {sum(reads.values())}",
            f"write_events = {sum(writes.values())}",
            "",
            "top reads:",
        ]
        if reads:
            for (addr, size), n in reads.most_common(top):
                lines.append(
                    f"{n:8d}  {self._describe_mmio_addr(addr):30} addr=0x{addr:08X} size={size}"
                )
        else:
            lines.append("(none)")

        lines.append("")
        lines.append("top writes:")
        if writes:
            for (addr, size), n in writes.most_common(top):
                lines.append(
                    f"{n:8d}  {self._describe_mmio_addr(addr):30} addr=0x{addr:08X} size={size}"
                )
        else:
            lines.append("(none)")
        return "\n".join(lines)

    def cmd_pcprof(self, argv: list[str]) -> str:
        if not argv:
            return "usage: pcprof <instructions> [top]"

        steps = _int(argv[0])
        if steps <= 0:
            return "instructions must be > 0"

        top = _int(argv[1]) if len(argv) > 1 else 20
        top = max(1, min(int(top), 100))

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

        executed = sum(pcs.values())
        lines = [
            f"pc = 0x{self.emu.pc:08X}",
            f"instructions_requested = {steps}",
            f"instructions_executed = {executed}",
            "",
            "top pcs:",
        ]

        if pcs:
            for addr, n in pcs.most_common(top):
                pct = (float(n) * 100.0 / float(executed)) if executed else 0.0
                lines.append(
                    f"{n:8d}  {pct:6.2f}%  0x{addr:08X}  {self._disasm_one(addr)}"
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
        if len(argv) != 1:
            return "usage: reg <r0..r12|sp|lr|pc>"
        name = argv[0].lower()
        regs = self.emu.read_regs()
        if name not in regs:
            return f"unknown reg: {name}"
        return f"{name} = 0x{regs[name]:08X}"

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

    def cmd_atpc(self, argv):
        # Syntax:
        #   atpc <pc> PERIPH.REG = <value> [if PERIPH.REG == <value>]
        #
        # Examples:
        #   atpc 0x08003D44 USART3.ISR = 0x40
        #   atpc 0x08003D44 USART3.ISR = 0x40 if USART3.ISR == 0x0

        if len(argv) < 4:
            raise ValueError("usage: atpc <pc> PERIPH.REG = <value> [if PERIPH.REG == <value>]")

        pc = self._parse_int(argv[0])
        periph, reg = self._parse_reg_spec(argv[1])

        if argv[2] != "=":
            raise ValueError("usage: atpc <pc> PERIPH.REG = <value> [if PERIPH.REG == <value>]")

        value = self._parse_int(argv[3])

        cond = None
        if len(argv) > 4:
            # expect: if X == Y
            if argv[4].lower() != "if":
                raise ValueError("expected 'if' or end of command")
            if len(argv) < 8:
                raise ValueError("usage: ... if PERIPH.REG == <value>")

            c_per, c_reg = self._parse_reg_spec(argv[5])

            op = argv[6]
            if op not in ("==", "="):
                raise ValueError("condition must use '==' (or '=')")

            c_val = self._parse_int(argv[7])
            cond = (c_per, c_reg, c_val)

        # PcRegWrite is in core/emulator.py (import where you already keep it)
        from stmemu.core.emulator import PcRegWrite

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
        out = []
        for w in self.emu.pc_reg_writes:
            out.append(
                f"@0x{w.pc:X} {w.peripheral}.{w.register} {w.mode} 0x{w.value:X} "
                f"{'(fired)' if w.fired else ''}"
            )
        return "\n".join(out) or "(no pc actions)"

    def cmd_atpc_clear(self, argv):
        self.emu.pc_reg_writes.clear()
        return "pc actions cleared"

    def _parse_reg_spec(self, s: str) -> tuple[str, str]:
        # "USART3.ISR" -> ("USART3", "ISR")
        if "." not in s:
            raise ValueError("expected PERIPH.REG")
        p, r = s.split(".", 1)
        return p.strip().upper(), r.strip().upper()

    def _parse_int(self, s: str) -> int:
        s = s.strip()
        return int(s, 0)  # supports 0x..., decimal
