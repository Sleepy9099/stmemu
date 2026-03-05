from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple, List
from stmemu.peripherals.core_cm import CortexMCorePeripheral
from stmemu.core.disasm import ThumbDisassembler
from stmemu.core.loader import FirmwareSegment

from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
from unicorn.arm_const import (
    UC_ARM_REG_PC,
    UC_ARM_REG_SP,
    UC_ARM_REG_LR,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_CPSR
)
from unicorn.unicorn_const import (
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_INSN_INVALID,
    UC_PROT_ALL,
)

from unicorn.unicorn_const import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE

try:
    from unicorn.arm_const import (
        UC_ARM_REG_MSP,
        UC_ARM_REG_PSP,
        UC_ARM_REG_CONTROL,
        UC_ARM_REG_PRIMASK,
        UC_ARM_REG_BASEPRI,
        UC_ARM_REG_FAULTMASK,
    )
except Exception:
    UC_ARM_REG_MSP = None
    UC_ARM_REG_PSP = None
    UC_ARM_REG_CONTROL = None
    UC_ARM_REG_PRIMASK = None
    UC_ARM_REG_BASEPRI = None
    UC_ARM_REG_FAULTMASK = None

from stmemu.peripherals.bus import PeripheralBus
from stmemu.utils.logger import get_logger
log = get_logger(__name__)

CondSpec = Tuple[str, str, int]  # (PERIPH, REG, VALUE)
EXC_RETURN_HANDLER_MSP = 0xFFFFFFF1
EXC_RETURN_THREAD_MSP = 0xFFFFFFF9
EXC_RETURN_THREAD_PSP = 0xFFFFFFFD
EXC_RETURN_VALUES = {
    EXC_RETURN_HANDLER_MSP,
    EXC_RETURN_THREAD_MSP,
    EXC_RETURN_THREAD_PSP,
}

@dataclass
class PcRegWrite:
    pc: int
    peripheral: str
    register: str
    value: int
    cond: Optional[CondSpec] = None

def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 4], "little", signed=False)


@dataclass
class Emulator:
    bus: PeripheralBus
    flash_base: int
    firmware_segments: tuple[FirmwareSegment, ...]
    sram_base: int
    sram_size: int
    firmware_format: str = "bin"
    firmware_entry_point: Optional[int] = None
    core_peripheral: Optional[CortexMCorePeripheral] = None
    tick_scale: int = 1
    stuck_loop_threshold: int = 5000
    interrupt_stuck_threshold: int = 50000000
    stuck_loop_auto: bool = True
    pc_reg_writes: list[PcRegWrite] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self._breakpoints: set[int] = set()
        self._running = False
        # MMIO breakpoints (watchpoints): break when an MMIO read/write hits a range.
        # Each entry: {"name": str, "start": int, "end": int, "access": "r"|"w"|"rw"}
        self._mmio_breakpoints: list[dict] = []
        self.last_mmio_break: dict | None = None
        self.last_pc_break: int | None = None

        self._map_memory()
        self._install_hooks()
        self._pc_hist = {}
        self._last_stuck_report = 0
        self.trace_enabled = False
        self._disasm = ThumbDisassembler()
        # Trace (disasm) options
        self.trace_mmio_only: bool = False
        self.trace_until_pc: int | None = None
        # When trace_mmio_only is enabled we buffer the *current* instruction and only
        # emit it if any MMIO access happens during that instruction.
        self._trace_prev_pc: int | None = None
        self._trace_prev_disasm: str | None = None
        self._trace_prev_mmio_touched: bool = False
        self._trace_stop_after_prev: bool = False
        self.pc_reg_writes: List[PcRegWrite] = []
        self._exception_stack: list[int] = []
        self._exception_return_stack: list[int] = []
        self._special_step_consumed = False
        self._ignore_breakpoint_once: int | None = None

    def _map_memory(self) -> None:
        image_end = self.flash_base
        mapped_segments = 0
        firmware_ranges: list[tuple[int, int]] = []
        for segment in self.firmware_segments:
            start = int(segment.address)
            end = start + len(segment.data)
            page_base = start & ~0xFFF
            page_end = max(page_base + 0x1000, (end + 0xFFF) & ~0xFFF)
            firmware_ranges.append((page_base, page_end))
            image_end = max(image_end, end)
            mapped_segments += 1

        for base, end in self._merge_ranges(firmware_ranges):
            self.uc.mem_map(base, end - base, UC_PROT_ALL)

        for segment in self.firmware_segments:
            start = int(segment.address)
            end = start + len(segment.data)
            if segment.data:
                self.uc.mem_write(start, segment.data)
            log.info(
                "Mapped firmware segment: 0x%08X-0x%08X (%d bytes)",
                start,
                end,
                len(segment.data),
            )

        if mapped_segments == 0:
            self.uc.mem_map(self.flash_base, 0x1000, UC_PROT_ALL)
            image_end = self.flash_base + 0x1000

        self.flash_size = max(0x1000, ((image_end - self.flash_base) + 0xFFF) & ~0xFFF)
        self.flash_end = max(self.flash_base + 0x1000, (image_end + 0xFFF) & ~0xFFF)

        # SRAM
        sram_size = (self.sram_size + 0xFFF) & ~0xFFF
        try:
            self.uc.mem_map(self.sram_base, sram_size, UC_PROT_ALL)
        except Exception:
            # ELF images may preload .data/.bss into SRAM pages we still want to use.
            pass
        log.info("Mapped sram : 0x%08X-0x%08X (%d bytes)", self.sram_base, self.sram_base + sram_size, sram_size)

        for mounted in self.bus.mounted_ranges():
            base = mounted.base & ~0xFFF
            end = (mounted.end + 0xFFF) & ~0xFFF
            size = end - base
            if size <= 0:
                continue
            try:
                self.uc.mem_map(base, size, UC_PROT_ALL)
            except Exception:
                # already mapped or overlap; ok
                pass

    def add_pc_reg_write(self, w: PcRegWrite) -> None:
         self.pc_reg_writes.append(w)
         
    def _install_hooks(self) -> None:
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_unmapped_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_unmapped_write)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_unmapped_fetch)
        self.uc.hook_add(UC_HOOK_INSN_INVALID, self._hook_insn_invalid)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        for r in self.bus.mounted_ranges():
            # Unicorn end is inclusive
            self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mmio_read, begin=r.base, end=r.end - 1)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mmio_write, begin=r.base, end=r.end - 1)

    # ---- boot helpers

    def boot_from_vector_table(self, flash_base: Optional[int] = None) -> None:
        base = self.flash_base if flash_base is None else flash_base
        vt = self.uc.mem_read(base, 8)
        msp = _u32(vt, 0)
        reset = _u32(vt, 4)

        # Cortex-M reset handler is Thumb; force bit0=1
        reset |= 1

        self.uc.reg_write(UC_ARM_REG_SP, msp)
        self.uc.reg_write(UC_ARM_REG_PC, reset)

        log.info("Boot: MSP=0x%08X RESET=0x%08X", msp, reset)

    # ---- execution controls

    def add_breakpoint(self, addr: int) -> None:
        self._breakpoints.add(addr & ~1)

    def remove_breakpoint(self, addr: int) -> None:
        self._breakpoints.discard(addr & ~1)

    def list_breakpoints(self) -> list[int]:
        return sorted(self._breakpoints)

    # --- MMIO breakpoints (watchpoints) ---
    def add_mmio_breakpoint(
        self,
        name: str,
        start: int,
        end: int,
        access: str = "rw",
    ) -> None:
        """Break when an MMIO read/write hits [start, end] inclusive.

        access: "r", "w", or "rw"
        """
        a = access.lower().strip()
        if a not in ("r", "w", "rw"):
            raise ValueError("access must be one of: r, w, rw")
        s = int(start)
        e = int(end)
        if e < s:
            s, e = e, s
        self._mmio_breakpoints.append({"name": str(name), "start": s, "end": e, "access": a})

    def list_mmio_breakpoints(self) -> list[dict[str, object]]:
        return list(self._mmio_breakpoints)

    def remove_mmio_breakpoint(self, name: str) -> int:
        """Remove MMIO breakpoints matching the provided name. Returns number removed."""
        before = len(self._mmio_breakpoints)
        self._mmio_breakpoints = [bp for bp in self._mmio_breakpoints if bp["name"] != name]
        return before - len(self._mmio_breakpoints)

    def clear_mmio_breakpoints(self) -> None:
        self._mmio_breakpoints.clear()

    def _mmio_break_if_needed(
        self,
        access: str,
        address: int,
        size: int,
        value: int | None = None,
    ) -> None:
        """If an MMIO breakpoint matches, stop emulation (watchpoint).

        Called from MMIO read/write hooks.
        """
        if not self._running or not self._mmio_breakpoints:
            return

        # Normalize access -> 'r' or 'w'
        a = (access or "").lower().strip()
        if a in ("read", "mem_read", "load"):
            a = "r"
        elif a in ("write", "mem_write", "store"):
            a = "w"
        elif a not in ("r", "w"):
            # Unknown access type; don't accidentally match everything.
            return

        # size can be 0 depending on hook/engine edge cases; treat as 1 byte.
        access_size = int(size) if int(size) > 0 else 1
        access_start = int(address)
        access_end = access_start + access_size - 1

        for bp in self._mmio_breakpoints:
            # Normalize bp access into a set {'r','w'}
            bp_a = str(bp.get("access", "rw")).lower().strip()
            bp_set: set[str]
            if bp_a in ("rw", "wr"):
                bp_set = {"r", "w"}
            elif bp_a == "r":
                bp_set = {"r"}
            elif bp_a == "w":
                bp_set = {"w"}
            else:
                # malformed bp; skip it instead of matching incorrectly
                continue

            if a not in bp_set:
                continue

            start = int(bp.get("start", 0))
            end = int(bp.get("end", -1))
            if end < start:
                start, end = end, start

            # Inclusive overlap: [access_start, access_end] vs [start, end]
            if access_end < start or access_start > end:
                continue

            self.last_mmio_break = {
                "name": str(bp.get("name", "")),
                "access": a,
                "address": int(address),
                "size": int(size),
                "value": None if value is None else int(value),
                "pc": int(self.pc),
            }

            try:
                self.uc.emu_stop()
            except Exception:
                pass
            return

    def step(self, count: int = 1) -> None:
        self.last_mmio_break = None
        self.last_pc_break = None
        self._running = True
        try:
            self._execute(count)
        finally:
            self._running = False
        # Flush pending trace output (esp. for trace mmio mode).
        self.flush_trace()

    def run(self, max_instructions: int = 100000) -> None:
        self.last_mmio_break = None
        self.last_pc_break = None
        self._running = True
        try:
            self._execute(max_instructions)
        finally:
            self._running = False
        # Flush pending trace output (esp. for trace mmio mode).
        self.flush_trace()

    # ---- register helpers

    @property
    def pc(self) -> int:
        return int(self.uc.reg_read(UC_ARM_REG_PC))

    @property
    def sp(self) -> int:
        return int(self.uc.reg_read(UC_ARM_REG_SP))

    def read_regs(self) -> dict[str, int]:
        regs = {
            "r0": self.uc.reg_read(UC_ARM_REG_R0),
            "r1": self.uc.reg_read(UC_ARM_REG_R1),
            "r2": self.uc.reg_read(UC_ARM_REG_R2),
            "r3": self.uc.reg_read(UC_ARM_REG_R3),
            "r4": self.uc.reg_read(UC_ARM_REG_R4),
            "r5": self.uc.reg_read(UC_ARM_REG_R5),
            "r6": self.uc.reg_read(UC_ARM_REG_R6),
            "r7": self.uc.reg_read(UC_ARM_REG_R7),
            "r8": self.uc.reg_read(UC_ARM_REG_R8),
            "r9": self.uc.reg_read(UC_ARM_REG_R9),
            "r10": self.uc.reg_read(UC_ARM_REG_R10),
            "r11": self.uc.reg_read(UC_ARM_REG_R11),
            "r12": self.uc.reg_read(UC_ARM_REG_R12),
            "sp": self.uc.reg_read(UC_ARM_REG_SP),
            "lr": self.uc.reg_read(UC_ARM_REG_LR),
            "pc": self.uc.reg_read(UC_ARM_REG_PC),
        }
        return {k: int(v) for k, v in regs.items()}

    # ---- memory helpers

    def mem_read(self, addr: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(addr, size))

    def mem_write(self, addr: int, data: bytes) -> None:
        self.uc.mem_write(addr, data)

    # ---- hooks

    def _hook_unmapped_read(self, uc, access, address, size, value, user_data):
        if self._maybe_map_internal_ram(address, size):
            return True
        log.error("UNMAPPED READ: addr=0x%08X size=%d PC=0x%08X", address, size, self.pc)
        return False

    def _hook_unmapped_write(self, uc, access, address, size, value, user_data):
        if self._maybe_map_internal_ram(address, size):
            return True
        log.error("UNMAPPED WRITE: addr=0x%08X size=%d value=0x%X PC=0x%08X", address, size, value, self.pc)
        return False


    def _hook_unmapped_fetch(self, uc, access, address, size, value, user_data):
        log.error("UNMAPPED FETCH: addr=0x%08X size=%d PC=0x%08X", address, size, self.pc)
        return False

    def _maybe_map_internal_ram(self, address: int, size: int) -> bool:
        addr = int(address) & 0xFFFFFFFF
        span = max(1, int(size))
        start = addr & ~0xFFF
        end = (addr + span + 0xFFF) & ~0xFFF

        # Conservative STM32-oriented RAM windows. These are data-only fallbacks
        # for cases where firmware uses internal SRAM/TCM regions not explicitly
        # described by the loaded image.
        windows = (
            (0x00000000, 0x00020000),  # ITCM/low-memory SRAM aliases on M7 parts
            (0x10000000, 0x10020000),  # DTCM aliases used by some STM32 families
            (0x20000000, 0x20200000),  # SRAM / DTCM (common STM32 range)
            (0x24000000, 0x24200000),  # AXI SRAM (H7)
            (0x30000000, 0x30200000),  # SRAM D2 (H7)
            (0x38000000, 0x38100000),  # SRAM D3 (H7)
        )

        def in_window(page: int) -> bool:
            for lo, hi in windows:
                if lo <= page < hi:
                    return True
            return False

        if not all(in_window(page) for page in range(start, end, 0x1000)):
            return False

        mapped = False
        for page in range(start, end, 0x1000):
            try:
                self.uc.mem_map(page, 0x1000, UC_PROT_ALL)
                mapped = True
            except Exception:
                # Already mapped or overlaps an existing region.
                continue
        return mapped

    def _hook_insn_invalid(self, uc, user_data):
        """
        Unicorn sometimes rejects Cortex-M system instructions (CPSID/MSR/DSB/ISB).
        We emulate a tiny subset and advance PC so firmware can continue.
        """
        pc = self.pc
        addr = pc & ~1  # ensure even address for fetch

        try:
            b2 = bytes(self.uc.mem_read(addr, 2))
            hw1 = int.from_bytes(b2, "little")
        except Exception:
            log.error("INVALID INSN at PC=0x%08X (could not read halfword)", pc)
            return False

        # ---- 16-bit Thumb: CPSID i  (0xB672)
        # bytes: 72 B6
        if hw1 == 0xB672:
            if UC_ARM_REG_PRIMASK is not None:
                try:
                    uc.reg_write(UC_ARM_REG_PRIMASK, 1)
                except Exception:
                    pass
            # advance PC by 2
            uc.reg_write(UC_ARM_REG_PC, (addr + 2) | 1)
            return True

        # Try 32-bit decode
        try:
            b4 = bytes(self.uc.mem_read(addr, 4))
            hw1 = int.from_bytes(b4[0:2], "little")  # first halfword
            hw2 = int.from_bytes(b4[2:4], "little")  # second halfword
        except Exception:
            # can't read 32-bit, fall back to logging
            self._log_invalid_window(pc)
            return False

        # ---- 32-bit Thumb: DSB/ISB commonly:
        # DSB: BF F3 4F 8F => hw1=0xF3BF hw2=0x8F4F
        # ISB: BF F3 6F 8F => hw1=0xF3BF hw2=0x8F6F
        if hw1 == 0xF3BF and hw2 in (0x8F4F, 0x8F6F):
            # treat as NOP barrier
            uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
            return True

        # ---- 32-bit Thumb VFP/FP coprocessor instructions (EDxx/EExx prefix).
        # Unicorn MCLASS builds often reject these even when firmware relies on
        # them heavily. We currently treat unsupported FP ops as NOPs so control
        # flow can progress to peripheral/runtime integration work.
        if (hw1 & 0xFF00) in (0xED00, 0xEE00):
            uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
            return True

        # ---- 32-bit Thumb: MSR special register, rN
        # Examples seen:
        #   80 F3 08 88 -> MSR MSP, r0
        #   80 F3 09 88 -> MSR PSP, r0
        #   83 F3 11 88 -> MSR BASEPRI, r3
        if (hw1 & 0xFFF0) == 0xF380 and (hw2 & 0xFF00) == 0x8800:
            sysm = hw2 & 0x00FF
            rn = hw1 & 0x000F

            reg_map = {
                0: UC_ARM_REG_R0, 1: UC_ARM_REG_R1, 2: UC_ARM_REG_R2, 3: UC_ARM_REG_R3,
                4: UC_ARM_REG_R4, 5: UC_ARM_REG_R5, 6: UC_ARM_REG_R6, 7: UC_ARM_REG_R7,
                8: UC_ARM_REG_R8, 9: UC_ARM_REG_R9, 10: UC_ARM_REG_R10, 11: UC_ARM_REG_R11,
                12: UC_ARM_REG_R12,
            }
            src_reg = reg_map.get(rn)
            if src_reg is None:
                self._log_invalid_window(pc)
                return False

            val = int(uc.reg_read(src_reg)) & 0xFFFFFFFF

            current_sp = int(uc.reg_read(UC_ARM_REG_SP))

            if sysm == 8 and UC_ARM_REG_MSP is not None:
                try:
                    uc.reg_write(UC_ARM_REG_MSP, val)
                except Exception:
                    pass
                uc.reg_write(
                    UC_ARM_REG_SP,
                    val if not self._active_stack_is_psp() else current_sp,
                )

                uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
                return True

            if sysm == 9 and UC_ARM_REG_PSP is not None:
                try:
                    uc.reg_write(UC_ARM_REG_PSP, val)
                except Exception:
                    pass
                uc.reg_write(
                    UC_ARM_REG_SP,
                    val if self._active_stack_is_psp() else current_sp,
                )
                uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
                return True

            if sysm == 16 and UC_ARM_REG_PRIMASK is not None:
                try:
                    uc.reg_write(UC_ARM_REG_PRIMASK, val & 0x1)
                except Exception:
                    pass
                uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
                return True

            if sysm == 17 and UC_ARM_REG_BASEPRI is not None:
                try:
                    uc.reg_write(UC_ARM_REG_BASEPRI, val & 0xFF)
                except Exception:
                    pass
                uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
                return True

            if sysm == 19 and UC_ARM_REG_FAULTMASK is not None:
                try:
                    uc.reg_write(UC_ARM_REG_FAULTMASK, val & 0x1)
                except Exception:
                    pass
                uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
                return True

            if sysm == 20 and UC_ARM_REG_CONTROL is not None:
                try:
                    uc.reg_write(UC_ARM_REG_CONTROL, val & 0x3)
                except Exception:
                    pass
                uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
                return True

            # Unknown sysm: fall through to log
            self._log_invalid_window(pc)
            return False

        # Unknown invalid instruction: dump context
        self._log_invalid_window(pc)
        return False

    def _log_invalid_window(self, pc: int) -> None:
        try:
            start = pc & ~0xF
            data = bytes(self.uc.mem_read(start, 0x40))
            log.error("INVALID INSN at PC=0x%08X (window @0x%08X)", pc, start)
            log.error("BYTES: %s", data.hex())
        except Exception as e:
            log.error("INVALID INSN at PC=0x%08X (could not read bytes: %s)", pc, e)

        try:
            regs = self.read_regs()
            log.error(
                "REGS: r0=%08X r1=%08X r2=%08X r3=%08X sp=%08X lr=%08X pc=%08X",
                regs["r0"], regs["r1"], regs["r2"], regs["r3"], regs["sp"], regs["lr"], regs["pc"],
            )
        except Exception:
            pass

    def _execute(self, max_instructions: int) -> None:
        executed = 0
        self._ignore_breakpoint_once = (self.pc & ~1) if ((self.pc & ~1) in self._breakpoints) else None
        while executed < max_instructions:
            if self._handle_exception_return():
                continue

            if self._deliver_pending_exception():
                continue

            start = self.pc | 1
            self._special_step_consumed = False
            try:
                self.uc.emu_start(start, self.flash_end, count=1)
            except UcError:
                if not self._special_step_consumed:
                    raise
            executed += 1
            self.bus.tick(self._effective_tick_scale())

            if self.last_mmio_break is not None:
                break

    def _deliver_pending_exception(self) -> bool:
        if self.core_peripheral is None:
            return False
        if self._exception_stack:
            return False

        primask = False
        if UC_ARM_REG_PRIMASK is not None:
            try:
                primask = bool(int(self.uc.reg_read(UC_ARM_REG_PRIMASK)) & 0x1)
            except Exception:
                primask = False

        basepri_active = False
        if UC_ARM_REG_BASEPRI is not None:
            try:
                basepri_active = bool(int(self.uc.reg_read(UC_ARM_REG_BASEPRI)) & 0xFF)
            except Exception:
                basepri_active = False

        exc_num = self.core_peripheral.next_pending_exception(
            primask=primask,
            basepri=basepri_active,
        )
        if exc_num is None:
            return False

        return self._enter_exception(exc_num, clear_pending_on_drop=True)

    def _handle_exception_return(self) -> bool:
        pc = self.pc & 0xFFFFFFFF
        if pc not in EXC_RETURN_VALUES:
            return False
        self._perform_exception_return(pc)
        return True

    def _perform_exception_return(self, exc_return: int) -> None:
        if not self._exception_stack:
            log.warning("EXC return requested with empty exception stack")
            self.uc.reg_write(UC_ARM_REG_PC, self.flash_base | 1)
            return

        exc_num = self._exception_stack.pop()
        if self._exception_return_stack:
            self._exception_return_stack.pop()
        self._pop_exception_frame(exc_return)
        if self.core_peripheral is not None:
            self.core_peripheral.exit_exception(exc_num)
            log.info("EXC return %s", self.core_peripheral.exception_name(exc_num))

    def _exception_vector_address(self, exc_num: int) -> int:
        base = self.flash_base
        if self.core_peripheral is not None:
            base = self.core_peripheral.vtor or self.flash_base
        data = self.uc.mem_read(base + (int(exc_num) * 4), 4)
        return _u32(data, 0)

    @staticmethod
    def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
        if not ranges:
            return []
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
                continue
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
        return merged

    def _enter_exception(self, exc_num: int, clear_pending_on_drop: bool = False) -> bool:
        handler_addr = self._exception_vector_address(exc_num)
        if handler_addr in (0, 0xFFFFFFFF):
            name = f"exception {exc_num}"
            if self.core_peripheral is not None:
                name = self.core_peripheral.exception_name(exc_num)
            log.warning(
                "Dropping pending exception %s: handler vector is 0x%08X",
                name,
                handler_addr,
            )
            if clear_pending_on_drop and self.core_peripheral is not None:
                self.core_peripheral.clear_pending_exception(exc_num)
            return False

        in_handler = bool(self._exception_stack)
        return_to_psp = self._active_stack_is_psp() if not in_handler else False
        if in_handler:
            exc_return = EXC_RETURN_HANDLER_MSP
        else:
            exc_return = EXC_RETURN_THREAD_PSP if return_to_psp else EXC_RETURN_THREAD_MSP
        self._push_exception_frame(return_to_psp=return_to_psp)
        self._exception_stack.append(exc_num)
        self._exception_return_stack.append(exc_return)
        if self.core_peripheral is not None:
            self.core_peripheral.enter_exception(exc_num)
        self._set_control_spsel(False)
        if UC_ARM_REG_MSP is not None:
            try:
                self.uc.reg_write(UC_ARM_REG_SP, int(self.uc.reg_read(UC_ARM_REG_MSP)))
            except Exception:
                pass
        self.uc.reg_write(UC_ARM_REG_LR, exc_return)
        self.uc.reg_write(UC_ARM_REG_PC, handler_addr | 1)
        if self.core_peripheral is not None:
            log.info(
                "EXC enter %s -> handler=0x%08X",
                self.core_peripheral.exception_name(exc_num),
                handler_addr | 1,
            )
        else:
            log.info("EXC enter %d -> handler=0x%08X", exc_num, handler_addr | 1)
        return True

    def _push_exception_frame(self, return_to_psp: bool) -> None:
        regs = self.read_regs()
        xpsr = 0x01000000
        try:
            xpsr = int(self.uc.reg_read(UC_ARM_REG_CPSR)) & 0xFFFFFFFF
        except Exception:
            pass

        frame = [
            regs["r0"],
            regs["r1"],
            regs["r2"],
            regs["r3"],
            regs["r12"],
            regs["lr"],
            regs["pc"],
            xpsr,
        ]
        sp = self._read_stack_pointer(use_psp=return_to_psp) - (len(frame) * 4)
        payload = b"".join(int(word & 0xFFFFFFFF).to_bytes(4, "little") for word in frame)
        self.uc.mem_write(sp, payload)
        self._write_stack_pointer(use_psp=return_to_psp, value=sp)
        if not return_to_psp:
            self.uc.reg_write(UC_ARM_REG_SP, sp)

    def _pop_exception_frame(self, exc_return: int) -> None:
        use_psp = exc_return == EXC_RETURN_THREAD_PSP
        sp = self._read_stack_pointer(use_psp=use_psp)
        data = bytes(self.uc.mem_read(sp, 32))
        words = [_u32(data, off) for off in range(0, 32, 4)]
        self.uc.reg_write(UC_ARM_REG_R0, words[0])
        self.uc.reg_write(UC_ARM_REG_R1, words[1])
        self.uc.reg_write(UC_ARM_REG_R2, words[2])
        self.uc.reg_write(UC_ARM_REG_R3, words[3])
        self.uc.reg_write(UC_ARM_REG_R12, words[4])
        self.uc.reg_write(UC_ARM_REG_LR, words[5])
        self.uc.reg_write(UC_ARM_REG_PC, words[6] | 1)
        try:
            self.uc.reg_write(UC_ARM_REG_CPSR, words[7])
        except Exception:
            pass
        new_sp = sp + 32
        self._write_stack_pointer(use_psp=use_psp, value=new_sp)
        self._set_control_spsel(use_psp)
        self.uc.reg_write(UC_ARM_REG_SP, new_sp)

    def _hook_code(self, uc, address, size, user_data):
        pc = int(address)
        if self._intercept_pop_exc_return(uc, pc, size):
            return
        if self._intercept_special_register_write(uc, pc, size):
            return
        if self._intercept_svc(uc, pc, size):
            return
        if self._intercept_exc_return(uc, pc, size):
            return
        if self._pc_break_if_needed(uc, pc):
            return

        self._apply_pc_reg_writes( int(address))

        if self.trace_enabled:
            try:
                addr = pc & ~1  # Thumb alignment
                code = bytes(uc.mem_read(addr, size))

                insns = self._disasm.disasm(code, addr, count=1)
                if insns:
                    i = insns[0]
                    log.info(
                        "TRACE 0x%08X: %-7s %-20s ; %s",
                        i.address,
                        i.mnemonic,
                        i.op_str,
                        i.bytes_hex,
                    )
                else:
                    log.info("TRACE 0x%08X: <undecoded>", addr)
            except Exception as e:
                log.info(
                    "TRACE 0x%08X size=%d (disasm failed: %s)",
                    pc,
                    size,
                    e,
                )

        # Treat tight loops as suspicious, but let interrupt-driven idle loops run longer.
        c = self._pc_hist.get(address, 0) + 1
        self._pc_hist[address] = c
        threshold = self._stuck_loop_threshold()
        if threshold > 0 and c == threshold:
            log.error("Likely stuck polling at PC=0x%08X (hit %d times)", address, c)
            uc.emu_stop()

    def _stuck_loop_threshold(self) -> int:
        base = max(0, int(self.stuck_loop_threshold))
        irq = max(0, int(self.interrupt_stuck_threshold))
        if not self.stuck_loop_auto or self.core_peripheral is None:
            return base
        if self.core_peripheral.pending_irqs():
            return max(base, irq)
        if self.core_peripheral.pending_system_exceptions():
            return max(base, irq)
        if self.core_peripheral.enabled_irqs():
            return max(base, irq)
        return base

    def _effective_tick_scale(self) -> int:
        return max(1, int(self.tick_scale))

    def _active_stack_is_psp(self) -> bool:
        if self._exception_stack:
            return False
        if UC_ARM_REG_CONTROL is None:
            return False
        try:
            return bool(int(self.uc.reg_read(UC_ARM_REG_CONTROL)) & 0x2)
        except Exception:
            return False

    def _read_stack_pointer(self, use_psp: bool) -> int:
        reg = UC_ARM_REG_PSP if use_psp and UC_ARM_REG_PSP is not None else UC_ARM_REG_MSP
        if reg is None:
            return self.sp
        try:
            return int(self.uc.reg_read(reg))
        except Exception:
            return self.sp

    def _write_stack_pointer(self, use_psp: bool, value: int) -> None:
        reg = UC_ARM_REG_PSP if use_psp and UC_ARM_REG_PSP is not None else UC_ARM_REG_MSP
        if reg is None:
            self.uc.reg_write(UC_ARM_REG_SP, value)
            return
        try:
            self.uc.reg_write(reg, value)
        except Exception:
            self.uc.reg_write(UC_ARM_REG_SP, value)

    def _set_control_spsel(self, use_psp: bool) -> None:
        if UC_ARM_REG_CONTROL is None:
            return
        try:
            control = int(self.uc.reg_read(UC_ARM_REG_CONTROL)) & 0xFFFFFFFF
        except Exception:
            return
        next_control = (control | 0x2) if use_psp else (control & ~0x2)
        try:
            self.uc.reg_write(UC_ARM_REG_CONTROL, next_control)
        except Exception:
            pass

    def _pc_break_if_needed(self, uc, pc: int) -> bool:
        addr = int(pc) & ~1
        if self._ignore_breakpoint_once == addr:
            self._ignore_breakpoint_once = None
            return False
        if not self._running or addr not in self._breakpoints:
            return False
        self.last_pc_break = addr
        try:
            uc.emu_stop()
        except Exception:
            pass
        return True

    def _intercept_special_register_write(self, uc, pc: int, size: int) -> bool:
        addr = pc & ~1
        if size != 4:
            return False
        try:
            data = bytes(uc.mem_read(addr, 4))
        except Exception:
            return False

        hw1 = int.from_bytes(data[0:2], "little")
        hw2 = int.from_bytes(data[2:4], "little")
        if (hw1 & 0xFFF0) != 0xF380 or (hw2 & 0xFF00) != 0x8800:
            return False

        sysm = hw2 & 0x00FF
        rn = hw1 & 0x000F
        reg_map = {
            0: UC_ARM_REG_R0, 1: UC_ARM_REG_R1, 2: UC_ARM_REG_R2, 3: UC_ARM_REG_R3,
            4: UC_ARM_REG_R4, 5: UC_ARM_REG_R5, 6: UC_ARM_REG_R6, 7: UC_ARM_REG_R7,
            8: UC_ARM_REG_R8, 9: UC_ARM_REG_R9, 10: UC_ARM_REG_R10, 11: UC_ARM_REG_R11,
            12: UC_ARM_REG_R12,
        }
        src_reg = reg_map.get(rn)
        if src_reg is None:
            return False

        val = int(uc.reg_read(src_reg)) & 0xFFFFFFFF
        current_sp = int(uc.reg_read(UC_ARM_REG_SP))

        handled = False
        if sysm == 8 and UC_ARM_REG_MSP is not None:
            try:
                uc.reg_write(UC_ARM_REG_MSP, val)
            except Exception:
                pass
            uc.reg_write(
                UC_ARM_REG_SP,
                val if not self._active_stack_is_psp() else current_sp,
            )
            handled = True
        elif sysm == 9 and UC_ARM_REG_PSP is not None:
            try:
                uc.reg_write(UC_ARM_REG_PSP, val)
            except Exception:
                pass
            uc.reg_write(
                UC_ARM_REG_SP,
                val if self._active_stack_is_psp() else current_sp,
            )
            handled = True
        elif sysm == 16 and UC_ARM_REG_PRIMASK is not None:
            try:
                uc.reg_write(UC_ARM_REG_PRIMASK, val & 0x1)
            except Exception:
                pass
            handled = True
        elif sysm == 17 and UC_ARM_REG_BASEPRI is not None:
            try:
                uc.reg_write(UC_ARM_REG_BASEPRI, val & 0xFF)
            except Exception:
                pass
            handled = True
        elif sysm == 19 and UC_ARM_REG_FAULTMASK is not None:
            try:
                uc.reg_write(UC_ARM_REG_FAULTMASK, val & 0x1)
            except Exception:
                pass
            handled = True
        elif sysm == 20 and UC_ARM_REG_CONTROL is not None:
            try:
                uc.reg_write(UC_ARM_REG_CONTROL, val & 0x3)
            except Exception:
                pass
            uc.reg_write(
                UC_ARM_REG_SP,
                int(uc.reg_read(UC_ARM_REG_PSP if self._active_stack_is_psp() else UC_ARM_REG_MSP))
                if (UC_ARM_REG_PSP is not None and UC_ARM_REG_MSP is not None)
                else current_sp,
            )
            handled = True

        if not handled:
            return False

        self._special_step_consumed = True
        uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
        try:
            uc.emu_stop()
        except Exception:
            pass
        return True

    def _intercept_svc(self, uc, pc: int, size: int) -> bool:
        if size != 2:
            return False
        try:
            opcode = int.from_bytes(bytes(uc.mem_read(pc & ~1, 2)), "little")
        except Exception:
            return False
        if (opcode & 0xFF00) != 0xDF00:
            return False

        if not self._enter_exception(11):
            return False

        self._special_step_consumed = True
        try:
            uc.emu_stop()
        except Exception:
            pass
        return True

    def _intercept_pop_exc_return(self, uc, pc: int, size: int) -> bool:
        if size != 2:
            return False
        try:
            opcode = int.from_bytes(bytes(uc.mem_read(pc & ~1, 2)), "little")
        except Exception:
            return False
        if (opcode & 0xFE00) != 0xBC00 or not (opcode & 0x0100):
            return False

        reglist = opcode & 0x00FF
        reg_count = reglist.bit_count()
        sp = self.sp
        frame_size = (reg_count + 1) * 4
        try:
            data = bytes(self.uc.mem_read(sp, frame_size))
        except Exception:
            return False

        reg_map = {
            0: UC_ARM_REG_R0,
            1: UC_ARM_REG_R1,
            2: UC_ARM_REG_R2,
            3: UC_ARM_REG_R3,
            4: UC_ARM_REG_R4,
            5: UC_ARM_REG_R5,
            6: UC_ARM_REG_R6,
            7: UC_ARM_REG_R7,
        }
        offset = 0
        for bit in range(8):
            if not (reglist & (1 << bit)):
                continue
            reg_value = _u32(data, offset)
            uc.reg_write(reg_map[bit], reg_value)
            offset += 4

        exc_return = _u32(data, offset) | 1
        if exc_return not in EXC_RETURN_VALUES:
            return False

        uc.reg_write(UC_ARM_REG_SP, sp + frame_size)
        self._special_step_consumed = True
        self._perform_exception_return(exc_return)
        try:
            uc.emu_stop()
        except Exception:
            pass
        return True

    def _intercept_exc_return(self, uc, pc: int, size: int) -> bool:
        if size != 2:
            return False
        try:
            opcode = bytes(uc.mem_read(pc & ~1, 2))
        except Exception:
            return False
        if opcode != b"\x70\x47":
            return False

        lr = int(uc.reg_read(UC_ARM_REG_LR)) & 0xFFFFFFFF
        if lr not in EXC_RETURN_VALUES:
            return False

        self._special_step_consumed = True
        self._perform_exception_return(lr)
        try:
            uc.emu_stop()
        except Exception:
            pass
        return True


    def _hook_mmio_read(self, uc, access, address, size, value, user_data):
        try:
            val = self.bus.read(address, size)
        except Exception:
            return False

        try:
            uc.mem_write(address, int(val).to_bytes(size, "little"))
        except Exception:
            pass

        # If we are in "trace mmio" mode, mark the current instruction as MMIO-touching.
        if self.trace_enabled and self.trace_mmio_only:
            try:
                cur_pc = int(uc.reg_read(UC_ARM_REG_PC)) & ~1
                if self._trace_prev_pc == cur_pc:
                    self._trace_prev_mmio_touched = True
            except Exception:
                pass

        # Break on MMIO reads if a watchpoint matches.
        self._mmio_break_if_needed("r", address, size, int(val))
        return True  # 🔑 THIS IS REQUIRED


    def _hook_mmio_write(self, uc, access, address, size, value, user_data):
        try:
            self.bus.write(address, size, int(value))
        except Exception:
            return False

        try:
            uc.mem_write(address, int(value).to_bytes(size, "little"))
        except Exception:
            pass

        # If we are in "trace mmio" mode, mark the current instruction as MMIO-touching.
        if self.trace_enabled and self.trace_mmio_only:
            try:
                cur_pc = int(uc.reg_read(UC_ARM_REG_PC)) & ~1
                if self._trace_prev_pc == cur_pc:
                    self._trace_prev_mmio_touched = True
            except Exception:
                pass

        # Break on MMIO writes if a watchpoint matches.
        self._mmio_break_if_needed("w", address, size, int(value))
        return True  # 🔑 ALSO REQUIRED

    def flush_trace(self) -> None:
        """
        Flush deferred trace output (used for trace mmio mode).
        """
        if not self.trace_enabled:
            return

        if self.trace_mmio_only and self._trace_prev_disasm:
            if self._trace_prev_mmio_touched:
                log.info("TRACE %s", self._trace_prev_disasm)

            if self._trace_stop_after_prev:
                self.trace_enabled = False
                self.trace_until_pc = None
                log.info(
                    "TRACE auto-disabled at PC=0x%08X",
                    self._trace_prev_pc,
                )

        # reset buffer
        self._trace_prev_pc = None
        self._trace_prev_disasm = None
        self._trace_prev_mmio_touched = False
        self._trace_stop_after_prev = False

    def _apply_pc_reg_writes(self, pc: int):
        if not self.pc_reg_writes:
            return

        for w in list(self.pc_reg_writes):
            if pc != w.pc:
                continue

            per = w.peripheral.upper()
            reg = w.register.upper()

            # Resolve (periph, reg) -> absolute address
            p = self.bus.amap.find_peripheral_by_name(per)
            if p is None:
                log.warning("ATPC fired @0x%08X but peripheral not found: %s", pc, per)
                continue

            # Common patterns in your codebase:
            # - peripheral.registers is iterable of SVD registers with .name and .address_offset
            # - or you maintain p.registers_by_name
            r = None
            if hasattr(p, "registers_by_name"):
                r = p.registers_by_name.get(reg)
            else:
                for rr in getattr(p, "registers", ()):
                    if getattr(rr, "name", "").upper() == reg:
                        r = rr
                        break

            if r is None:
                log.warning("ATPC fired @0x%08X but register not found: %s.%s", pc, per, reg)
                continue

            off = getattr(r, "address_offset", None)
            if off is None:
                # Some SVD models call it "offset"
                off = getattr(r, "offset", None)
            if off is None:
                log.warning("ATPC fired @0x%08X but reg has no offset: %s.%s", pc, per, reg)
                continue

            addr = int(p.base_address) + int(off)

            # --- conditional logic ---
            if w.cond is not None:
                c_per, c_reg, c_val = w.cond
                c_per = c_per.upper()
                c_reg = c_reg.upper()

                cp = self.bus.amap.find_peripheral_by_name(c_per)
                if cp is None:
                    log.info(
                        "ATPC cond @0x%08X: %s.%s == 0x%X ? peripheral missing -> SKIP",
                        pc, c_per, c_reg, c_val
                    )
                    continue

                cr = None
                if hasattr(cp, "registers_by_name"):
                    cr = cp.registers_by_name.get(c_reg)
                else:
                    for rr in getattr(cp, "registers", ()):
                        if getattr(rr, "name", "").upper() == c_reg:
                            cr = rr
                            break

                if cr is None:
                    log.info(
                        "ATPC cond @0x%08X: %s.%s == 0x%X ? reg missing -> SKIP",
                        pc, c_per, c_reg, c_val
                    )
                    continue

                c_off = getattr(cr, "address_offset", None)
                if c_off is None:
                    c_off = getattr(cr, "offset", None)
                if c_off is None:
                    log.info(
                        "ATPC cond @0x%08X: %s.%s == 0x%X ? no offset -> SKIP",
                        pc, c_per, c_reg, c_val
                    )
                    continue

                c_addr = int(cp.base_address) + int(c_off)

                # Read current value via the bus (so it matches your MMIO model)
                cur = self.bus.read(c_addr, 4)

                if int(cur) != int(c_val):
                    log.info(
                        "ATPC cond @0x%08X: %s.%s == 0x%X ? current=0x%X -> SKIP",
                        pc, c_per, c_reg, c_val, cur
                    )
                    continue
                else:
                    log.info(
                        "ATPC cond @0x%08X: %s.%s == 0x%X ? current=0x%X -> APPLY",
                        pc, c_per, c_reg, c_val, cur
                    )

            # Perform the write through the bus so it updates your peripheral model
            self.bus.write(addr, 4, int(w.value))

            # --- trace integration: always print when firing ---
            # This is the part you asked for: "atpc + trace integration (print when firing)"
            log.info(
                "ATPC fired @0x%08X: %s.%s <= 0x%X",
                pc, per, reg, int(w.value)
            )
