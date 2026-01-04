from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple, List
from stmemu.peripherals.core_cm import CortexMCorePeripheral  # add
from stmemu.core.disasm import ThumbDisassembler

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
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
from stmemu.utils.bits import mask_for_size

log = get_logger(__name__)

CondSpec = Tuple[str, str, int]  # (PERIPH, REG, VALUE)

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
    flash_image: bytes
    sram_base: int
    sram_size: int
    core_peripheral: Optional[CortexMCorePeripheral] = None
    pc_reg_writes: list[PcRegWrite] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self._breakpoints: set[int] = set()
        self._running = False
        # MMIO breakpoints (watchpoints): break when an MMIO read/write hits a range.
        # Each entry: {"name": str, "start": int, "end": int, "access": "r"|"w"|"rw"}
        self._mmio_breakpoints: list[dict] = []
        self.last_mmio_break: dict | None = None

        self._map_memory()
        self._install_hooks()
        self._core = {
            "vtor": self.flash_base,
            "demcr": 0,
            "dwt_ctrl": 0,
            "cyccnt": 0,
            "systick_ctrl": 0,
            "systick_load": 0,
            "systick_val": 0,
        }
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

    def _map_memory(self) -> None:
        # Flash: map enough pages for image (round up)
        flash_size = (len(self.flash_image) + 0xFFF) & ~0xFFF
        if flash_size == 0:
            flash_size = 0x1000
        self.uc.mem_map(self.flash_base, flash_size, UC_PROT_ALL)
        self.uc.mem_write(self.flash_base, self.flash_image)
        log.info("Mapped flash: 0x%08X-0x%08X (%d bytes)", self.flash_base, self.flash_base + flash_size, flash_size)
        self.flash_size = flash_size
        self.flash_end = self.flash_base + flash_size

        # SRAM
        sram_size = (self.sram_size + 0xFFF) & ~0xFFF
        self.uc.mem_map(self.sram_base, sram_size, UC_PROT_ALL)
        log.info("Mapped sram : 0x%08X-0x%08X (%d bytes)", self.sram_base, self.sram_base + sram_size, sram_size)

        # Cortex-M System Control Space (SCS): 0xE000E000 - 0xE0100000 (1 MB)
        # Contains SCB, NVIC, SysTick, etc. Firmware often writes VTOR early.
        self.uc.mem_map(0xE000E000, 0x00100000, UC_PROT_ALL)
        log.info("Mapped SCS  : 0x%08X-0x%08X (%d bytes)", 0xE000E000, 0xE000E000 + 0x00100000, 0x00100000)

        for r in self.bus.amap.ranges:
            base = r.base & ~0xFFF
            end = (r.end + 0xFFF) & ~0xFFF
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
        # self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read, begin=0xE0000000, end=0xE010FFFF)
        # self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write, begin=0xE0000000, end=0xE010FFFF)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        for r in self.bus.amap.ranges:
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
        start = self.pc | 1
        self.last_mmio_break = None
        self._running = True
        try:
            self.uc.emu_start(start, self.flash_end, count=count)
        finally:
            self._running = False
        # Flush pending trace output (esp. for trace mmio mode).
        self.flush_trace()
        self._tick_core(count)

    def run(self, max_instructions: int = 100000) -> None:
        start = self.pc | 1
        self.last_mmio_break = None
        self._running = True
        try:
            self.uc.emu_start(start, self.flash_end, count=max_instructions)
        finally:
            self._running = False
        # Flush pending trace output (esp. for trace mmio mode).
        self.flush_trace()
        self._tick_core(max_instructions)

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
        log.error("UNMAPPED READ: addr=0x%08X size=%d PC=0x%08X", address, size, self.pc)
        return False

    def _hook_unmapped_write(self, uc, access, address, size, value, user_data):
        log.error("UNMAPPED WRITE: addr=0x%08X size=%d value=0x%X PC=0x%08X", address, size, value, self.pc)
        return False


    def _hook_unmapped_fetch(self, uc, access, address, size, value, user_data):
        log.error("UNMAPPED FETCH: addr=0x%08X size=%d PC=0x%08X", address, size, self.pc)
        return False

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

        # ---- 32-bit Thumb: MSR special register, rN (common early boot)
        # Pattern seen: 80 F3 08 88  -> hw1=0xF380 hw2=0x8808  (MSR MSP, r0)
        #              80 F3 09 88  -> hw1=0xF380 hw2=0x8809  (MSR PSP, r0)
        #
        # We'll match hw1==0xF380 and hw2 high bits 0x8800, low nibble selects special reg.
        if hw1 == 0xF380 and (hw2 & 0xFFF0) == 0x8800:
            sysm = hw2 & 0x000F  # 8=MSP, 9=PSP in what we observed
            rn = hw1 & 0x000F    # low nibble is Rn (works for r0 in your case)

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

            # sysm values we care about for now
            if sysm == 8 and UC_ARM_REG_MSP is not None:
                try:
                    uc.reg_write(UC_ARM_REG_MSP, val)
                except Exception:
                    pass
                # Also update SP to match (good enough for MVP)
                uc.reg_write(UC_ARM_REG_SP, val)

                uc.reg_write(UC_ARM_REG_PC, (addr + 4) | 1)
                return True

            if sysm == 9 and UC_ARM_REG_PSP is not None:
                try:
                    uc.reg_write(UC_ARM_REG_PSP, val)
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

    # Core register addresses (Cortex-M)
    _SCB_VTOR   = 0xE000ED08
    _SCB_DEMCR  = 0xE000EDFC

    _DWT_CTRL   = 0xE0001000
    _DWT_CYCCNT = 0xE0001004

    _SYST_CSR   = 0xE000E010
    _SYST_RVR   = 0xE000E014
    _SYST_CVR   = 0xE000E018

    def _tick_core(self, instructions: int = 1) -> None:
        # crude but effective: advance cycle counter proportional to executed instructions
        self._core["cyccnt"] = (self._core["cyccnt"] + instructions) & 0xFFFFFFFF

        # SysTick downcounter if enabled
        if self._core["systick_ctrl"] & 0x1:
            load = self._core["systick_load"] & 0x00FFFFFF
            if load == 0:
                load = 0x00FFFFFF
            val = self._core["systick_val"] & 0x00FFFFFF
            val = (val - instructions) % (load + 1)
            self._core["systick_val"] = val

    def _hook_mem_read(self, uc, access, address, size, value, user_data):
        # Provide dynamic values for core regs; otherwise do nothing (allow normal memory read)
        if address == self._SCB_VTOR and size == 4:
            v = self._core["vtor"] & 0xFFFFFFFF
            uc.mem_write(address, v.to_bytes(4, "little"))
            return

        if address == self._SCB_DEMCR and size == 4:
            v = self._core["demcr"] & 0xFFFFFFFF
            uc.mem_write(address, v.to_bytes(4, "little"))
            return

        if address == self._DWT_CTRL and size == 4:
            v = self._core["dwt_ctrl"] & 0xFFFFFFFF
            uc.mem_write(address, v.to_bytes(4, "little"))
            return

        if address == self._DWT_CYCCNT and size == 4:
            # tick a little on every read to break spin loops
            self._tick_core(10)
            v = self._core["cyccnt"] & 0xFFFFFFFF
            uc.mem_write(address, v.to_bytes(4, "little"))
            return

        if address == self._SYST_CSR and size == 4:
            v = self._core["systick_ctrl"] & 0xFFFFFFFF
            uc.mem_write(address, v.to_bytes(4, "little"))
            return

        if address == self._SYST_RVR and size == 4:
            v = self._core["systick_load"] & 0xFFFFFFFF
            uc.mem_write(address, v.to_bytes(4, "little"))
            return

        if address == self._SYST_CVR and size == 4:
            self._tick_core(1)
            v = self._core["systick_val"] & 0xFFFFFFFF
            uc.mem_write(address, v.to_bytes(4, "little"))
            return

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        if size != 4:
            return

        if address == self._SCB_VTOR:
            self._core["vtor"] = int(value) & 0xFFFFFFFF
            return

        if address == self._SCB_DEMCR:
            self._core["demcr"] = int(value) & 0xFFFFFFFF
            return

        if address == self._DWT_CTRL:
            self._core["dwt_ctrl"] = int(value) & 0xFFFFFFFF
            return

        if address == self._DWT_CYCCNT:
            self._core["cyccnt"] = int(value) & 0xFFFFFFFF
            return

        if address == self._SYST_CSR:
            self._core["systick_ctrl"] = int(value) & 0xFFFFFFFF
            return

        if address == self._SYST_RVR:
            self._core["systick_load"] = int(value) & 0xFFFFFFFF
            self._core["systick_val"] = int(value) & 0xFFFFFFFF
            return

        if address == self._SYST_CVR:
            self._core["systick_val"] = int(value) & 0xFFFFFFFF
            return
        
    def _hook_code(self, uc, address, size, user_data):
        pc = int(address)

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

        # ---- stuck-loop detection (keep exactly as you had it)
        c = self._pc_hist.get(address, 0) + 1
        self._pc_hist[address] = c
        if c == 5000:
            log.error("Likely stuck polling at PC=0x%08X (hit %d times)", address, c)
            uc.emu_stop()


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
