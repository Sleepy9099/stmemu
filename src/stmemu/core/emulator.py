from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple, List
from stmemu.peripherals.core_cm import CortexMCorePeripheral
from stmemu.core.disasm import ThumbDisassembler
from stmemu.core.loader import FirmwareSegment
from stmemu.core.semihosting import SemihostingHandler, BKPT_SEMIHOST
from stmemu.core.symbols import SymbolTable
from stmemu.core.time_engine import EmulatedTime, VALID_MODES

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


@dataclass
class PcCpuAction:
    aid: int
    kind: str  # setreg | ret | skip
    pc: int
    reg: str | None = None
    value: int | None = None
    skip_bytes: int | None = None
    once: bool = False
    hits: int = 0


@dataclass(frozen=True)
class SnapshotMemoryChunk:
    start: int
    data: bytes


@dataclass(frozen=True)
class EmulatorSnapshot:
    name: str
    regs: dict[str, int]
    memory: tuple[SnapshotMemoryChunk, ...]
    model_state: dict[str, object]
    exception_stack: tuple[int, ...]
    exception_return_stack: tuple[int, ...]
    pc_hist: dict[int, int]
    coverage: frozenset[int] | None = None
    fault_report: dict[str, object] | None = None
    mutable_ranges: tuple[tuple[int, int], ...] | None = None

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
    symbols: SymbolTable = field(default_factory=SymbolTable)
    semihosting: SemihostingHandler = field(default_factory=SemihostingHandler)

    def __post_init__(self) -> None:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self._breakpoints: set[int] = set()
        self._running = False
        # MMIO breakpoints (watchpoints): break when an MMIO read/write hits a range.
        # Each entry: {"name": str, "start": int, "end": int, "access": "r"|"w"|"rw"}
        self._mmio_breakpoints: list[dict] = []
        self._watchpoints: list[dict] = []
        self._watchpoint_next_id: int = 1
        self._pc_cpu_actions: list[PcCpuAction] = []
        self._pc_cpu_action_next_id: int = 1
        self._dynamic_ram_pages: set[int] = set()
        self._snapshot_base_ranges: list[tuple[int, int]] = []
        self._snapshots: dict[str, EmulatorSnapshot] = {}
        self.last_mmio_break: dict | None = None
        self.last_watch_break: dict | None = None
        self.last_pc_break: int | None = None
        self.last_event_break: dict | None = None
        self._event_breakpoints: list[dict] = []
        self._event_bp_next_id: int = 1
        self.time = EmulatedTime()
        self._timed_events: list[dict] = []
        self.rtos_trace_enabled: bool = False
        self._rtos_switch_count: int = 0
        self._rtos_last_psp: int = 0
        self.event_trace_enabled: bool = False
        self._event_trace: list[dict] = []
        self._event_trace_max: int = 10000
        self.auto_fault_report: bool = True
        self.last_fault_report: dict[str, object] | None = None

        # Unsupported FP/VFP instructions are emulated as NOPs so firmware can
        # boot, but that can mask real FP side effects. Track how often it
        # happens and let callers switch to "strict" (fault instead of NOP).
        self.unsupported_fp_mode: str = "permissive"  # or "strict"
        self.unsupported_fp_count: int = 0
        self.last_unsupported_fp_pc: int | None = None

        self._map_memory()
        self._install_hooks()
        self._pc_hist = {}
        self._last_stuck_report = 0
        self.trace_enabled = False
        self._disasm = ThumbDisassembler()
        # Trace (disasm) options
        self.trace_mmio_only: bool = False
        self.trace_until_pc: int | None = None
        self.trace_callret_only: bool = False
        self.trace_branch_only: bool = False
        self.trace_reg_deltas: bool = False
        self._trace_call_depth: int = 0
        self.trace_history: list[str] = []
        self.trace_history_limit: int = 50000
        # When trace_mmio_only is enabled we buffer the *current* instruction and only
        # emit it if any MMIO access happens during that instruction.
        self._trace_prev_pc: int | None = None
        self._trace_prev_disasm: str | None = None
        self._trace_prev_mnemonic: str | None = None
        self._trace_prev_op_str: str | None = None
        self._trace_prev_size: int = 0
        self._trace_prev_regs_before: dict[str, int] | None = None
        self._trace_prev_mmio_touched: bool = False
        self._trace_stop_after_prev: bool = False
        self.pc_reg_writes: List[PcRegWrite] = []
        self._exception_stack: list[int] = []
        # Code coverage tracking
        self.coverage_enabled: bool = False
        self._coverage: set[int] = set()
        self._coverage_hits: dict[int, int] = {}
        self._coverage_snapshots: dict[str, set[int]] = {}
        # Edge coverage: (prev_pc >> 4) ^ cur_pc
        self._prev_coverage_pc: int = 0
        self._edge_coverage: set[int] = set()
        self._edge_coverage_hits: dict[int, int] = {}
        # Optional address-range filter (0 = disabled)
        self._coverage_filter_start: int = 0
        self._coverage_filter_end: int = 0
        self._exception_return_stack: list[int] = []
        self._special_step_consumed = False
        self._ignore_breakpoint_once: int | None = None

        if hasattr(self.bus, "set_emulator"):
            self.bus.set_emulator(self)

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

        # Snapshot memory defaults to writable/runtime memory regions.
        snapshot_ranges: list[tuple[int, int]] = []
        if sram_size > 0:
            snapshot_ranges.append((self.sram_base, self.sram_base + sram_size))
        for segment in self.firmware_segments:
            start = int(segment.address)
            end = start + len(segment.data)
            if end <= start:
                continue
            # Flash image is usually immutable during emulation; checkpoint RAM instead.
            if self.flash_base <= start and end <= self.flash_end:
                continue
            snapshot_ranges.append((start, end))
        self._snapshot_base_ranges = self._merge_ranges(snapshot_ranges)

    def add_pc_reg_write(self, w: PcRegWrite) -> None:
        self.pc_reg_writes.append(w)

    def add_pc_cpu_action(
        self,
        kind: str,
        pc: int,
        *,
        reg: str | None = None,
        value: int | None = None,
        skip_bytes: int | None = None,
        once: bool = False,
    ) -> int:
        k = str(kind).lower().strip()
        if k not in {"setreg", "ret", "skip"}:
            raise ValueError("pc action kind must be one of: setreg, ret, skip")
        aid = self._pc_cpu_action_next_id
        self._pc_cpu_action_next_id += 1
        self._pc_cpu_actions.append(
            PcCpuAction(
                aid=aid,
                kind=k,
                pc=int(pc) & ~1,
                reg=None if reg is None else str(reg).lower().strip(),
                value=None if value is None else int(value) & 0xFFFFFFFF,
                skip_bytes=None if skip_bytes is None else int(skip_bytes),
                once=bool(once),
            )
        )
        return aid

    def list_pc_cpu_actions(self) -> list[dict[str, object]]:
        return [
            {
                "id": int(a.aid),
                "kind": str(a.kind),
                "pc": int(a.pc),
                "reg": a.reg,
                "value": a.value,
                "skip_bytes": a.skip_bytes,
                "once": bool(a.once),
                "hits": int(a.hits),
            }
            for a in self._pc_cpu_actions
        ]

    def clear_pc_cpu_actions(self) -> int:
        count = len(self._pc_cpu_actions)
        self._pc_cpu_actions.clear()
        return count

    def remove_pc_cpu_action(self, aid: int) -> bool:
        target = int(aid)
        before = len(self._pc_cpu_actions)
        self._pc_cpu_actions = [a for a in self._pc_cpu_actions if int(a.aid) != target]
        return len(self._pc_cpu_actions) != before
         
    def _install_hooks(self) -> None:
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_unmapped_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_unmapped_write)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_unmapped_fetch)
        self.uc.hook_add(UC_HOOK_INSN_INVALID, self._hook_insn_invalid)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read_any)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write_any)
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

    @staticmethod
    def _normalize_watch_access(access: str) -> str:
        chars = {c for c in str(access).lower().strip() if c in "rwx"}
        if not chars:
            raise ValueError("access must include at least one of: r, w, x")
        if len(chars) != len(str(access).replace(" ", "")):
            for c in str(access).lower().strip():
                if c not in "rwx":
                    raise ValueError("access must use only: r, w, x")
        return "".join(c for c in "rwx" if c in chars)

    def add_watchpoint(
        self,
        start: int,
        end: int,
        access: str = "rw",
        name: str | None = None,
    ) -> int:
        a = self._normalize_watch_access(access)
        s = int(start) & 0xFFFFFFFF
        e = int(end) & 0xFFFFFFFF
        if e < s:
            s, e = e, s
        wid = self._watchpoint_next_id
        self._watchpoint_next_id += 1
        self._watchpoints.append(
            {
                "id": wid,
                "name": str(name) if name else f"0x{s:08X}-0x{e:08X}",
                "start": s,
                "end": e,
                "access": a,
            }
        )
        return wid

    def list_watchpoints(self) -> list[dict[str, object]]:
        return list(self._watchpoints)

    def remove_watchpoint(self, wid: int) -> bool:
        target = int(wid)
        before = len(self._watchpoints)
        self._watchpoints = [wp for wp in self._watchpoints if int(wp.get("id", -1)) != target]
        return len(self._watchpoints) != before

    def clear_watchpoints(self) -> int:
        count = len(self._watchpoints)
        self._watchpoints.clear()
        return count

    # --- Event breakpoints ---
    def add_event_breakpoint(
        self, kind: str, *, source: str | None = None, name: str = "",
    ) -> int:
        bp_id = self._event_bp_next_id
        self._event_bp_next_id += 1
        bp = {
            "id": bp_id,
            "kind": kind,
            "source": source,
            "name": name or f"evt:{kind}" + (f"/{source}" if source else ""),
            "enabled": True,
            "hits": 0,
        }
        self._event_breakpoints.append(bp)
        already_subscribed = any(
            b["kind"] == kind for b in self._event_breakpoints if b["id"] != bp_id
        )
        if not already_subscribed:
            self.bus.subscribe(kind, self._on_event_for_breakpoint)
        return bp_id

    def remove_event_breakpoint(self, bp_id: int) -> bool:
        before = len(self._event_breakpoints)
        self._event_breakpoints = [
            bp for bp in self._event_breakpoints if bp["id"] != bp_id
        ]
        return len(self._event_breakpoints) < before

    def list_event_breakpoints(self) -> list[dict]:
        return [dict(bp) for bp in self._event_breakpoints]

    def clear_event_breakpoints(self) -> int:
        count = len(self._event_breakpoints)
        self._event_breakpoints.clear()
        return count

    def _on_event_for_breakpoint(self, event) -> None:
        if not self._running:
            return
        for bp in self._event_breakpoints:
            if not bp["enabled"]:
                continue
            if bp["kind"] != event.kind:
                continue
            if bp["source"] is not None and bp["source"].upper() != str(getattr(event, "source", "")).upper():
                continue
            bp["hits"] += 1
            self.last_event_break = {
                "bp_id": bp["id"],
                "kind": event.kind,
                "source": getattr(event, "source", ""),
                "address": getattr(event, "address", 0),
                "payload": getattr(event, "payload", None),
                "pc": self.pc,
            }
            try:
                self.uc.emu_stop()
            except Exception:
                pass
            return

    # --- Timed events ---

    @property
    def instruction_count(self) -> int:
        return self.time.instructions

    def add_timed_event(self, at: int, action: str, **params) -> dict:
        """Schedule an action at a specific instruction count."""
        evt = {"at": int(at), "action": str(action), "fired": False}
        evt.update(params)
        self._timed_events.append(evt)
        self._timed_events.sort(key=lambda e: e.get("at", float("inf")))
        return evt

    def add_timed_event_cycle(self, at_cycle: int, action: str, **params) -> dict:
        """Schedule an action at a specific emulated cycle deadline.

        Cycle deadlines share the unified timebase, so they fire even when idle
        fast-forward jumps over millions of instructions (unlike instruction
        deadlines, which only advance one per executed instruction).
        """
        evt = {"at_cycle": int(at_cycle), "action": str(action), "fired": False}
        evt.update(params)
        self._timed_events.append(evt)
        return evt

    def add_timed_event_ms(self, after_ms: float, action: str, **params) -> dict:
        """Schedule an action ``after_ms`` from now, on the nominal cycle clock."""
        deadline = self.time.cycles + self.time.ms_to_cycles(after_ms)
        return self.add_timed_event_cycle(deadline, action, **params)

    def list_timed_events(self) -> list[dict]:
        return [dict(e) for e in self._timed_events]

    def clear_timed_events(self) -> int:
        count = len(self._timed_events)
        self._timed_events.clear()
        return count

    def _check_timed_events(self) -> None:
        if not self._timed_events:
            return
        ic = self.time.instructions
        cyc = self.time.cycles
        fired_any = False
        for evt in self._timed_events:
            if evt.get("fired"):
                continue
            at = evt.get("at")
            at_cycle = evt.get("at_cycle")
            due = (at is not None and at <= ic) or (at_cycle is not None and at_cycle <= cyc)
            if due:
                evt["fired"] = True
                fired_any = True
                self._execute_timed_action(evt)
        if fired_any:
            self._timed_events = [e for e in self._timed_events if not e.get("fired")]

    def _execute_timed_action(self, evt: dict) -> None:
        action = evt.get("action", "")
        # Events may be scheduled by instruction ("at") or cycle ("at_cycle");
        # use whichever is present for log/snapshot naming.
        when = evt.get("at", evt.get("at_cycle", -1))

        if action == "gpio_inject":
            port = str(evt.get("port", "")).upper()
            pin = int(evt.get("pin", 0))
            level = str(evt.get("level", "high")).lower()
            model = self.bus.model_for_name(port)
            if model is not None and hasattr(model, "set_input_level"):
                model.set_input_level(pin, level in ("high", "1", "true"))
                log.debug("timed@%s: gpio_inject %s pin %d %s", when, port, pin, level)

        elif action == "uart_inject":
            periph = str(evt.get("peripheral", "")).upper()
            model = self.bus.model_for_name(periph)
            if model is not None and hasattr(model, "inject_rx_bytes"):
                hex_data = evt.get("hex", "")
                data = bytes.fromhex(str(hex_data)) if hex_data else b""
                if data:
                    model.inject_rx_bytes(data)
                    log.debug("timed@%s: uart_inject %s %dB", when, periph, len(data))

        elif action == "adc_sample":
            periph = str(evt.get("peripheral", "")).upper()
            model = self.bus.model_for_name(periph)
            if model is not None and hasattr(model, "inject_sample"):
                value = int(evt.get("value", 0))
                model.inject_sample(value)
                log.debug("timed@%s: adc_sample %s %d", when, periph, value)

        elif action == "event_emit":
            from stmemu.peripherals.bus import PeripheralEvent
            kind = str(evt.get("kind", "custom"))
            source = str(evt.get("source", "timed"))
            self.bus.emit(PeripheralEvent(
                kind=kind, source=source, payload=evt.get("payload"),
            ))
            log.debug("timed@%s: event_emit %s source=%s", when, kind, source)

        elif action == "snapshot":
            name = str(evt.get("name", f"timed_{when}"))
            self.save_snapshot(name)
            log.debug("timed@%s: snapshot '%s'", when, name)

        else:
            log.warning("timed@%s: unknown action '%s'", when, action)

    # --- RTOS awareness ---

    def _read_psp(self) -> int:
        if UC_ARM_REG_PSP is None:
            return 0
        try:
            return int(self.uc.reg_read(UC_ARM_REG_PSP)) & 0xFFFFFFFF
        except Exception:
            return 0

    def _read_msp(self) -> int:
        if UC_ARM_REG_MSP is None:
            return 0
        try:
            return int(self.uc.reg_read(UC_ARM_REG_MSP)) & 0xFFFFFFFF
        except Exception:
            return 0

    def _read_control(self) -> int:
        if UC_ARM_REG_CONTROL is None:
            return 0
        try:
            return int(self.uc.reg_read(UC_ARM_REG_CONTROL)) & 0xFFFFFFFF
        except Exception:
            return 0

    def _emit_rtos_exception_event(self, exc_num: int, phase: str) -> None:
        if not self.rtos_trace_enabled:
            return
        exc_name = "unknown"
        if self.core_peripheral is not None:
            exc_name = self.core_peripheral.exception_name(exc_num)
        from stmemu.peripherals.bus import PeripheralEvent
        self.bus.emit(PeripheralEvent(
            kind="rtos_exception",
            source=exc_name,
            payload={
                "exception": exc_name,
                "exc_num": exc_num,
                "phase": phase,
                "pc": self.pc & 0xFFFFFFFF,
                "msp": self._read_msp(),
                "psp": self._read_psp(),
                "control": self._read_control(),
                "active_depth": len(self._exception_stack),
                "instruction": self.time.instructions,
            },
        ))

    def _emit_rtos_context_switch(
        self, exc_num: int, old_psp: int, new_psp: int,
    ) -> None:
        if not self.rtos_trace_enabled:
            return
        self._rtos_switch_count += 1
        from stmemu.peripherals.bus import PeripheralEvent
        self.bus.emit(PeripheralEvent(
            kind="rtos_context_switch",
            source="PendSV",
            payload={
                "switch_count": self._rtos_switch_count,
                "old_psp": old_psp,
                "new_psp": new_psp,
                "msp": self._read_msp(),
                "control": self._read_control(),
                "pc": self.pc & 0xFFFFFFFF,
                "instruction": self.time.instructions,
            },
        ))

    def rtos_status(self) -> dict[str, object]:
        """Return current RTOS-relevant state."""
        return {
            "trace_enabled": self.rtos_trace_enabled,
            "switch_count": self._rtos_switch_count,
            "psp": self._read_psp(),
            "msp": self._read_msp(),
            "control": self._read_control(),
            "active_exceptions": list(self._exception_stack),
            "exception_depth": len(self._exception_stack),
            "instruction_count": self.time.instructions,
            "in_handler": bool(self._exception_stack),
        }

    # --- Event trace ---

    def enable_event_trace(self, max_events: int = 10000) -> None:
        self._event_trace_max = max_events
        if not self.event_trace_enabled:
            self.bus.subscribe("*", self._on_trace_event)
        self.event_trace_enabled = True

    def disable_event_trace(self) -> None:
        self.event_trace_enabled = False
        self.bus.unsubscribe("*", self._on_trace_event)

    def _on_trace_event(self, event) -> None:
        if not self.event_trace_enabled:
            return
        entry = {
            "instruction": self.time.instructions,
            "pc": self.pc & 0xFFFFFFFF,
            "kind": event.kind,
            "source": getattr(event, "source", ""),
            "address": getattr(event, "address", 0),
        }
        direction = getattr(event, "direction", "")
        if direction:
            entry["direction"] = direction
        size = getattr(event, "size", 0)
        if size:
            entry["size"] = size
        payload = getattr(event, "payload", None)
        if payload is not None:
            entry["payload"] = payload
        self._event_trace.append(entry)
        if len(self._event_trace) > self._event_trace_max:
            self._event_trace = self._event_trace[-self._event_trace_max:]

    def event_trace_list(self, count: int = 20) -> list[dict]:
        return list(self._event_trace[-count:])

    def event_trace_clear(self) -> int:
        n = len(self._event_trace)
        self._event_trace.clear()
        return n

    def event_trace_export(self, path) -> int:
        """Export event trace as JSONL (one JSON object per line)."""
        import json
        from pathlib import Path
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            for entry in self._event_trace:
                safe = {}
                for k, v in entry.items():
                    try:
                        json.dumps(v)
                        safe[k] = v
                    except (TypeError, ValueError):
                        safe[k] = str(v)
                f.write(json.dumps(safe) + "\n")
        return len(self._event_trace)

    @staticmethod
    def _reg_alias_to_unicorn(name: str):
        reg_name = str(name).lower().strip()
        reg_map = {
            "r0": UC_ARM_REG_R0,
            "r1": UC_ARM_REG_R1,
            "r2": UC_ARM_REG_R2,
            "r3": UC_ARM_REG_R3,
            "r4": UC_ARM_REG_R4,
            "r5": UC_ARM_REG_R5,
            "r6": UC_ARM_REG_R6,
            "r7": UC_ARM_REG_R7,
            "r8": UC_ARM_REG_R8,
            "r9": UC_ARM_REG_R9,
            "r10": UC_ARM_REG_R10,
            "r11": UC_ARM_REG_R11,
            "r12": UC_ARM_REG_R12,
            "sp": UC_ARM_REG_SP,
            "lr": UC_ARM_REG_LR,
            "pc": UC_ARM_REG_PC,
            "cpsr": UC_ARM_REG_CPSR,
        }
        if UC_ARM_REG_MSP is not None:
            reg_map["msp"] = UC_ARM_REG_MSP
        if UC_ARM_REG_PSP is not None:
            reg_map["psp"] = UC_ARM_REG_PSP
        if UC_ARM_REG_CONTROL is not None:
            reg_map["control"] = UC_ARM_REG_CONTROL
        if UC_ARM_REG_PRIMASK is not None:
            reg_map["primask"] = UC_ARM_REG_PRIMASK
        if UC_ARM_REG_BASEPRI is not None:
            reg_map["basepri"] = UC_ARM_REG_BASEPRI
        if UC_ARM_REG_FAULTMASK is not None:
            reg_map["faultmask"] = UC_ARM_REG_FAULTMASK
        return reg_map.get(reg_name)

    def write_reg(self, name: str, value: int) -> None:
        reg = self._reg_alias_to_unicorn(name)
        if reg is None:
            raise KeyError(f"unknown reg: {name}")
        self.uc.reg_write(reg, int(value) & 0xFFFFFFFF)

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
        self.last_watch_break = None
        self.last_pc_break = None
        self.last_event_break = None
        self._running = True
        err: Exception | None = None
        try:
            self._execute(count)
        except Exception as e:
            err = e
            if isinstance(e, UcError):
                self.record_fault("uc_error", detail=str(e))
        finally:
            self._running = False
            # Flush pending trace output (esp. for trace mmio mode).
            self.flush_trace()
        if err is not None:
            raise err

    def run(self, max_instructions: int = 100000) -> None:
        self.last_mmio_break = None
        self.last_watch_break = None
        self.last_pc_break = None
        self.last_event_break = None
        self._running = True
        err: Exception | None = None
        try:
            self._execute(max_instructions)
        except Exception as e:
            err = e
            if isinstance(e, UcError):
                self.record_fault("uc_error", detail=str(e))
        finally:
            self._running = False
            # Flush pending trace output (esp. for trace mmio mode).
            self.flush_trace()
        if err is not None:
            raise err

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

    def _read_snapshot_regs(self) -> dict[str, int]:
        regs = self.read_regs()
        for name in ("cpsr", "msp", "psp", "control", "primask", "basepri", "faultmask"):
            reg_id = self._reg_alias_to_unicorn(name)
            if reg_id is None:
                continue
            try:
                regs[name] = int(self.uc.reg_read(reg_id)) & 0xFFFFFFFF
            except Exception:
                continue
        return regs

    def _write_snapshot_regs(self, regs: dict[str, int]) -> None:
        order = [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12",
            "msp", "psp", "control", "primask", "basepri", "faultmask",
            "sp", "lr", "pc", "cpsr",
        ]
        for name in order:
            if name not in regs:
                continue
            try:
                self.write_reg(name, int(regs[name]))
            except KeyError:
                continue

    def _snapshot_ranges(self) -> list[tuple[int, int]]:
        ranges = list(self._snapshot_base_ranges)
        for page in sorted(self._dynamic_ram_pages):
            ranges.append((int(page), int(page) + 0x1000))
        return self._merge_ranges(ranges)

    def _capture_snapshot_memory(self) -> tuple[SnapshotMemoryChunk, ...]:
        chunks: list[SnapshotMemoryChunk] = []
        for start, end in self._snapshot_ranges():
            if end <= start:
                continue
            size = int(end - start)
            try:
                data = bytes(self.uc.mem_read(int(start), size))
            except Exception:
                continue
            chunks.append(SnapshotMemoryChunk(start=int(start), data=data))
        return tuple(chunks)

    def capture_snapshot(
        self,
        name: str = "(current)",
        *,
        include_coverage: bool = False,
    ) -> EmulatorSnapshot:
        return EmulatorSnapshot(
            name=str(name),
            regs=self._read_snapshot_regs(),
            memory=self._capture_snapshot_memory(),
            model_state=self.bus.snapshot_models_state(),
            exception_stack=tuple(int(x) for x in self._exception_stack),
            exception_return_stack=tuple(int(x) for x in self._exception_return_stack),
            pc_hist={int(k): int(v) for k, v in self._pc_hist.items()},
            coverage=frozenset(self._coverage) if include_coverage else None,
            fault_report=dict(self.last_fault_report) if self.last_fault_report else None,
            mutable_ranges=tuple(
                (int(s), int(e)) for s, e in self._snapshot_ranges()
            ),
        )

    def save_snapshot(self, name: str) -> EmulatorSnapshot:
        key = str(name).strip()
        if not key:
            raise ValueError("snapshot name cannot be empty")
        snap = self.capture_snapshot(name=key)
        self._snapshots[key] = snap
        return snap

    def get_snapshot(self, name: str) -> EmulatorSnapshot | None:
        return self._snapshots.get(str(name))

    def list_snapshots(self) -> list[str]:
        return sorted(self._snapshots.keys())

    def clear_snapshots(self) -> int:
        count = len(self._snapshots)
        self._snapshots.clear()
        return count

    def remove_snapshot(self, name: str) -> bool:
        key = str(name)
        if key not in self._snapshots:
            return False
        del self._snapshots[key]
        return True

    def export_snapshot(self, name: str, path) -> int:
        """Persist a snapshot to disk via pickle. Returns bytes written."""
        from pathlib import Path
        import pickle
        snap = self._snapshots.get(str(name))
        if snap is None:
            raise KeyError(f"unknown snapshot: {name}")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = pickle.dumps(snap, protocol=pickle.HIGHEST_PROTOCOL)
        p.write_bytes(data)
        return len(data)

    def import_snapshot(self, path, name: str | None = None) -> EmulatorSnapshot:
        """Load a snapshot from disk into the in-memory dict.

        The snapshot's saved name is used unless overridden. The snapshot is
        not loaded into the emulator -- call ``load_snapshot`` next if you
        want to apply it.
        """
        from pathlib import Path
        import pickle
        p = Path(path)
        data = p.read_bytes()
        snap = pickle.loads(data)
        if not isinstance(snap, EmulatorSnapshot):
            raise ValueError(f"file is not an EmulatorSnapshot: {path}")
        key = str(name) if name else snap.name
        if name and name != snap.name:
            snap = EmulatorSnapshot(
                name=key,
                regs=snap.regs,
                memory=snap.memory,
                model_state=snap.model_state,
                exception_stack=snap.exception_stack,
                exception_return_stack=snap.exception_return_stack,
                pc_hist=snap.pc_hist,
                coverage=snap.coverage,
                fault_report=snap.fault_report,
                mutable_ranges=snap.mutable_ranges,
            )
        self._snapshots[key] = snap
        return snap

    def load_snapshot(self, name: str) -> EmulatorSnapshot:
        key = str(name)
        snap = self._snapshots.get(key)
        if snap is None:
            raise KeyError(f"unknown snapshot: {key}")

        for chunk in snap.memory:
            start = int(chunk.start)
            length = len(chunk.data)
            if length == 0:
                continue
            # Imported snapshots may include RAM pages that were lazily
            # mapped during the original run (e.g. AXI/D2/D3 SRAM on H7).
            # Map any missing pages before restoring data so the
            # mem_write doesn't trip UC_ERR_WRITE_UNMAPPED.
            page_start = start & ~0xFFF
            page_end = (start + length + 0xFFF) & ~0xFFF
            for page in range(page_start, page_end, 0x1000):
                try:
                    self.uc.mem_map(page, 0x1000, UC_PROT_ALL)
                    self._dynamic_ram_pages.add(int(page))
                except Exception:
                    # Already mapped (overlap with flash/SRAM/peripheral)
                    pass
            self.uc.mem_write(start, bytes(chunk.data))

        self.bus.restore_models_state(snap.model_state)
        self._write_snapshot_regs(snap.regs)
        self._exception_stack = [int(x) for x in snap.exception_stack]
        self._exception_return_stack = [int(x) for x in snap.exception_return_stack]
        self._pc_hist = {int(k): int(v) for k, v in snap.pc_hist.items()}
        self._ignore_breakpoint_once = None
        self.last_pc_break = None
        self.last_mmio_break = None
        self.last_watch_break = None
        self.last_event_break = None

        self._prev_coverage_pc = 0
        if snap.coverage is not None:
            self._coverage = set(snap.coverage)
            self._coverage_hits.clear()
            self._edge_coverage.clear()
            self._edge_coverage_hits.clear()
        if snap.fault_report is not None:
            self.last_fault_report = dict(snap.fault_report)
        else:
            self.last_fault_report = None
        return snap

    @staticmethod
    def _append_merged_range(
        ranges: list[tuple[int, int]],
        start: int,
        end: int,
    ) -> None:
        if end <= start:
            return
        if not ranges:
            ranges.append((start, end))
            return
        prev_start, prev_end = ranges[-1]
        if start <= prev_end:
            ranges[-1] = (prev_start, max(prev_end, end))
            return
        ranges.append((start, end))

    @staticmethod
    def _diff_bytes_ranges(
        start: int,
        left: bytes,
        right: bytes,
    ) -> tuple[list[tuple[int, int]], int]:
        ranges: list[tuple[int, int]] = []
        changed = 0
        left_len = len(left)
        right_len = len(right)
        max_len = max(left_len, right_len)
        i = 0
        while i < max_len:
            lval = left[i] if i < left_len else None
            rval = right[i] if i < right_len else None
            if lval == rval:
                i += 1
                continue
            j = i + 1
            while j < max_len:
                lnext = left[j] if j < left_len else None
                rnext = right[j] if j < right_len else None
                if lnext == rnext:
                    break
                j += 1
            ranges.append((start + i, start + j))
            changed += j - i
            i = j
        return ranges, changed

    def diff_snapshots(
        self,
        left: EmulatorSnapshot,
        right: EmulatorSnapshot,
    ) -> dict[str, object]:
        reg_changes: list[tuple[str, int | None, int | None]] = []
        for name in sorted(set(left.regs) | set(right.regs)):
            lv = left.regs.get(name)
            rv = right.regs.get(name)
            if lv != rv:
                reg_changes.append((name, lv, rv))

        left_mem = {int(chunk.start): bytes(chunk.data) for chunk in left.memory}
        right_mem = {int(chunk.start): bytes(chunk.data) for chunk in right.memory}
        changed_ranges: list[tuple[int, int]] = []
        changed_bytes = 0

        for start in sorted(set(left_mem) | set(right_mem)):
            ldata = left_mem.get(start)
            rdata = right_mem.get(start)
            if ldata is None and rdata is not None:
                end = start + len(rdata)
                changed_bytes += len(rdata)
                self._append_merged_range(changed_ranges, start, end)
                continue
            if rdata is None and ldata is not None:
                end = start + len(ldata)
                changed_bytes += len(ldata)
                self._append_merged_range(changed_ranges, start, end)
                continue
            if ldata is None or rdata is None:
                continue
            ranges, count = self._diff_bytes_ranges(start, ldata, rdata)
            changed_bytes += count
            for r_start, r_end in ranges:
                self._append_merged_range(changed_ranges, r_start, r_end)

        return {
            "left": left.name,
            "right": right.name,
            "reg_changes": reg_changes,
            "memory_changed_ranges": changed_ranges,
            "memory_changed_bytes": changed_bytes,
        }

    @staticmethod
    def _decode_cfsr(cfsr: int) -> list[str]:
        flags: list[tuple[int, str]] = [
            (0, "IACCVIOL"),
            (1, "DACCVIOL"),
            (3, "MUNSTKERR"),
            (4, "MSTKERR"),
            (5, "MLSPERR"),
            (7, "MMARVALID"),
            (8, "IBUSERR"),
            (9, "PRECISERR"),
            (10, "IMPRECISERR"),
            (11, "UNSTKERR"),
            (12, "STKERR"),
            (13, "LSPERR"),
            (15, "BFARVALID"),
            (16, "UNDEFINSTR"),
            (17, "INVSTATE"),
            (18, "INVPC"),
            (19, "NOCP"),
            (20, "STKOF"),
            (24, "UNALIGNED"),
            (25, "DIVBYZERO"),
        ]
        out: list[str] = []
        value = int(cfsr) & 0xFFFFFFFF
        for bit, name in flags:
            if value & (1 << bit):
                out.append(name)
        return out

    @staticmethod
    def _decode_hfsr(hfsr: int) -> list[str]:
        flags = [
            (1, "VECTTBL"),
            (30, "FORCED"),
            (31, "DEBUGEVT"),
        ]
        out: list[str] = []
        value = int(hfsr) & 0xFFFFFFFF
        for bit, name in flags:
            if value & (1 << bit):
                out.append(name)
        return out

    def _read_system_word(self, addr: int) -> int:
        try:
            return int(self.bus.read(int(addr), 4)) & 0xFFFFFFFF
        except Exception:
            try:
                return int.from_bytes(self.mem_read(int(addr), 4), "little") & 0xFFFFFFFF
            except Exception:
                return 0

    def _capture_stacked_frame(self) -> dict[str, object] | None:
        if not self._exception_stack:
            return None
        exc_return = (
            int(self._exception_return_stack[-1])
            if self._exception_return_stack
            else EXC_RETURN_THREAD_MSP
        )
        use_psp = exc_return == EXC_RETURN_THREAD_PSP
        sp = self._read_stack_pointer(use_psp=use_psp)
        try:
            data = bytes(self.uc.mem_read(int(sp), 32))
        except Exception:
            return None
        words = [_u32(data, off) for off in range(0, 32, 4)]
        return {
            "stack": "PSP" if use_psp else "MSP",
            "sp": int(sp) & 0xFFFFFFFF,
            "exc_return": exc_return & 0xFFFFFFFF,
            "r0": int(words[0]) & 0xFFFFFFFF,
            "r1": int(words[1]) & 0xFFFFFFFF,
            "r2": int(words[2]) & 0xFFFFFFFF,
            "r3": int(words[3]) & 0xFFFFFFFF,
            "r12": int(words[4]) & 0xFFFFFFFF,
            "lr": int(words[5]) & 0xFFFFFFFF,
            "pc": int(words[6]) & 0xFFFFFFFF,
            "xpsr": int(words[7]) & 0xFFFFFFFF,
        }

    def capture_fault_report(
        self,
        reason: str = "fault",
        *,
        detail: str | None = None,
        pc_override: int | None = None,
    ) -> dict[str, object]:
        regs = self._read_snapshot_regs()
        active_exc = 0
        active_exc_name = "Thread"
        pending_irqs: list[int] = []
        pending_system: list[str] = []
        if self.core_peripheral is not None:
            try:
                active_exc = int(self.core_peripheral.current_active_exception())
                active_exc_name = self.core_peripheral.exception_name(active_exc)
                pending_irqs = [int(x) for x in self.core_peripheral.pending_irqs()]
                pending_system = [str(x) for x in self.core_peripheral.pending_system_exceptions()]
            except Exception:
                pass

        cfsr = self._read_system_word(0xE000ED28)
        hfsr = self._read_system_word(0xE000ED2C)
        mmfar = self._read_system_word(0xE000ED34)
        bfar = self._read_system_word(0xE000ED38)
        icsr = self._read_system_word(0xE000ED04)

        report = {
            "reason": str(reason),
            "detail": "" if detail is None else str(detail),
            "pc": int(regs.get("pc", self.pc if pc_override is None else int(pc_override))) & 0xFFFFFFFF,
            "regs": regs,
            "active_exception": active_exc,
            "active_exception_name": active_exc_name,
            "exception_depth": len(self._exception_stack),
            "pending_irqs": pending_irqs,
            "pending_system": pending_system,
            "cfsr": cfsr,
            "hfsr": hfsr,
            "mmfar": mmfar,
            "bfar": bfar,
            "icsr": icsr,
            "cfsr_flags": self._decode_cfsr(cfsr),
            "hfsr_flags": self._decode_hfsr(hfsr),
            "stacked_frame": self._capture_stacked_frame(),
        }
        return report

    def record_fault(
        self,
        reason: str,
        *,
        detail: str | None = None,
        pc_override: int | None = None,
    ) -> dict[str, object]:
        report = self.capture_fault_report(
            reason=reason,
            detail=detail,
            pc_override=pc_override,
        )
        self.last_fault_report = report
        return report

    def clear_fault_report(self) -> None:
        self.last_fault_report = None

    # ---- hooks

    def _hook_unmapped_read(self, uc, access, address, size, value, user_data):
        if self._maybe_map_internal_ram(address, size):
            return True
        log.error("UNMAPPED READ: addr=0x%08X size=%d PC=0x%08X", address, size, self.pc)
        self.record_fault(
            "unmapped_read",
            detail=f"addr=0x{int(address):08X} size={int(size)}",
            pc_override=self.pc,
        )
        return False

    def _hook_unmapped_write(self, uc, access, address, size, value, user_data):
        if self._maybe_map_internal_ram(address, size):
            return True
        log.error("UNMAPPED WRITE: addr=0x%08X size=%d value=0x%X PC=0x%08X", address, size, value, self.pc)
        self.record_fault(
            "unmapped_write",
            detail=f"addr=0x{int(address):08X} size={int(size)} value=0x{int(value):X}",
            pc_override=self.pc,
        )
        return False


    def _hook_unmapped_fetch(self, uc, access, address, size, value, user_data):
        log.error("UNMAPPED FETCH: addr=0x%08X size=%d PC=0x%08X", address, size, self.pc)
        self.record_fault(
            "unmapped_fetch",
            detail=f"addr=0x{int(address):08X} size={int(size)}",
            pc_override=self.pc,
        )
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
                self._dynamic_ram_pages.add(int(page))
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
            self.record_fault("invalid_insn", detail="could not read halfword", pc_override=pc)
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
        # them heavily. In "permissive" mode (default) we treat unsupported FP
        # ops as NOPs so control flow can progress; the occurrence is counted
        # and emitted as an `unsupported_fp_instruction` event so it is visible
        # rather than silent. In "strict" mode we let it fault instead.
        if (hw1 & 0xFF00) in (0xED00, 0xEE00):
            self.unsupported_fp_count += 1
            self.last_unsupported_fp_pc = pc
            self._emit_unsupported_fp(pc, hw1, hw2)
            if self.unsupported_fp_mode == "strict":
                self.record_fault(
                    "unsupported_fp_instruction",
                    detail=f"hw1=0x{hw1:04X} hw2=0x{hw2:04X}",
                    pc_override=pc,
                )
                return False
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

    def _emit_unsupported_fp(self, pc: int, hw1: int, hw2: int) -> None:
        """Surface an unsupported-FP NOP as a traceable event."""
        try:
            from stmemu.peripherals.bus import PeripheralEvent
            self.bus.emit(PeripheralEvent(
                kind="unsupported_fp_instruction",
                source="cpu",
                address=pc,
                payload={
                    "pc": pc,
                    "hw1": hw1,
                    "hw2": hw2,
                    "mode": self.unsupported_fp_mode,
                    "count": self.unsupported_fp_count,
                },
            ))
        except Exception:
            log.debug("failed to emit unsupported_fp_instruction event")

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
        self.record_fault("invalid_insn", detail="unknown/unsupported opcode", pc_override=pc)

    def _execute(self, max_instructions: int) -> None:
        executed = 0
        self._ignore_breakpoint_once = (self.pc & ~1) if ((self.pc & ~1) in self._breakpoints) else None
        while executed < max_instructions:
            if self._handle_exception_return():
                continue

            if self._deliver_pending_exception():
                continue

            start = self.pc | 1
            pre_pc = self.pc & 0xFFFFFFFF
            self._special_step_consumed = False
            try:
                self.uc.emu_start(start, self.flash_end, count=1)
            except UcError:
                if not self._special_step_consumed:
                    raise
            executed += 1
            self.time.instructions += 1
            self.advance_time(self._effective_tick_scale(), reason="instruction")

            if (
                self.last_mmio_break is not None
                or self.last_watch_break is not None
                or self.last_pc_break is not None
                or self.last_event_break is not None
            ):
                break

            # Idle fast-forward: a self-branch (`b .`) leaves PC unchanged.
            # That is exactly the ChibiOS idle thread (and any wait-for-IRQ
            # spin). Rather than single-step millions of idle branches while
            # time creeps tick_scale at a time, jump straight to the next
            # scheduled interrupt so the waiting thread wakes promptly.
            if self.time.idle_fast_forward and (self.pc & 0xFFFFFFFF) == pre_pc:
                self._idle_fast_forward()

    def advance_time(self, cycles: int, *, reason: str = "step") -> None:
        """The one canonical path that advances emulated time.

        Every cycle increment — per-instruction stepping, idle fast-forward,
        an explicit ``time advance`` — flows through here so the cycle counter,
        all peripheral clocks (core DWT/SysTick, timers, external-device pacing,
        DMA), and cycle-deadline scheduled events stay on a single timebase.
        """
        cycles = int(cycles)
        if cycles <= 0:
            return
        self.time.cycles += cycles
        self.bus.tick(cycles)
        self._check_timed_events()

    def _cycles_until_timed_event(self) -> int | None:
        """Cycles until the nearest pending cycle-deadline timed event.

        Idle fast-forward must not leap past a cycle-scheduled event (which may
        inject input / pend an IRQ and change execution); it stops at the
        deadline so the event fires at its proper time.
        """
        best: int | None = None
        now = self.time.cycles
        for evt in self._timed_events:
            if evt.get("fired"):
                continue
            at_cycle = evt.get("at_cycle")
            if at_cycle is None:
                continue
            delta = int(at_cycle) - int(now)
            if delta <= 0:
                return 1
            if best is None or delta < best:
                best = delta
        return best

    def _idle_fast_forward(self) -> None:
        # Don't skip while interrupts are masked -- the spin won't be broken by
        # an IRQ, so jumping time forward would be wrong (and could loop).
        if UC_ARM_REG_PRIMASK is not None:
            try:
                if int(self.uc.reg_read(UC_ARM_REG_PRIMASK)) & 0x1:
                    return
            except Exception:
                pass
        irq_cyc = self.bus.cycles_until_irq() if hasattr(self.bus, "cycles_until_irq") else None
        evt_cyc = self._cycles_until_timed_event()
        floor = self._effective_tick_scale()
        # Jump to whichever comes first -- the next peripheral IRQ or the next
        # cycle-scheduled event -- so neither deadline is overshot.
        candidates = [c for c in (irq_cyc, evt_cyc) if c is not None and c > floor]
        if not candidates:
            return
        # Cap a single jump so a runaway never advances unbounded.
        cyc = min(min(candidates), self.time.max_fast_forward_cycles)
        # NOTE: advancing here moves cycle-domain time (and any at_cycle events)
        # forward, but NOT the instruction counter -- instruction-count-scheduled
        # events are intentionally not advanced by skipped idle cycles. Schedule
        # by cycle (at_cycle / after_ms) when you want idle-jumped time.
        self.advance_time(cyc, reason="idle_fast_forward")

    def _deliver_pending_exception(self) -> bool:
        if self.core_peripheral is None:
            return False

        primask = False
        if UC_ARM_REG_PRIMASK is not None:
            try:
                primask = bool(int(self.uc.reg_read(UC_ARM_REG_PRIMASK)) & 0x1)
            except Exception:
                primask = False

        basepri_val = 0
        if UC_ARM_REG_BASEPRI is not None:
            try:
                basepri_val = int(self.uc.reg_read(UC_ARM_REG_BASEPRI)) & 0xFF
            except Exception:
                basepri_val = 0

        exc_num = self.core_peripheral.next_pending_exception(
            primask=primask,
            basepri=basepri_val,
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
        self._emit_rtos_exception_event(exc_num, "exit")
        if exc_num == 14:
            new_psp = self._read_psp()
            if new_psp != self._rtos_last_psp and self._rtos_last_psp != 0:
                self._emit_rtos_context_switch(exc_num, self._rtos_last_psp, new_psp)

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
        self._emit_rtos_exception_event(exc_num, "enter")
        if exc_num == 14:
            self._rtos_last_psp = self._read_psp()
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
        sp = (self._read_stack_pointer(use_psp=return_to_psp) - (len(frame) * 4)) & 0xFFFFFFFF
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
        new_sp = (sp + 32) & 0xFFFFFFFF
        self._write_stack_pointer(use_psp=use_psp, value=new_sp)
        self._set_control_spsel(use_psp)
        self.uc.reg_write(UC_ARM_REG_SP, new_sp)

    def _hook_code(self, uc, address, size, user_data):
        pc = int(address)
        if self.coverage_enabled:
            clean_pc = pc & ~1
            if (
                self._coverage_filter_end == 0
                or self._coverage_filter_start <= clean_pc < self._coverage_filter_end
            ):
                self._coverage.add(clean_pc)
                self._coverage_hits[clean_pc] = self._coverage_hits.get(clean_pc, 0) + 1
                edge = (self._prev_coverage_pc >> 4) ^ clean_pc
                self._edge_coverage.add(edge)
                self._edge_coverage_hits[edge] = self._edge_coverage_hits.get(edge, 0) + 1
            self._prev_coverage_pc = clean_pc
        if self.trace_enabled:
            self._trace_finalize_pending(next_pc=pc & ~1)
        else:
            self._trace_reset_pending()

        # Semihosting: intercept BKPT 0xAB (opcode 0xBEAB)
        if size == 2 and self.semihosting.enabled:
            try:
                opcode = int.from_bytes(bytes(uc.mem_read(pc & ~1, 2)), "little")
                if opcode == BKPT_SEMIHOST:
                    r0 = uc.reg_read(UC_ARM_REG_R0)
                    r1 = uc.reg_read(UC_ARM_REG_R1)
                    result = self.semihosting.handle(r0, r1, uc.mem_read, uc.mem_write, uc)
                    uc.reg_write(UC_ARM_REG_R0, result & 0xFFFFFFFF)
                    # The BKPT instruction itself would raise UC_ERR_EXCEPTION and
                    # leave PC unchanged, so we must step over it ourselves: advance
                    # past the 2-byte BKPT and stop this single-step cycle cleanly.
                    self._special_step_consumed = True
                    uc.reg_write(UC_ARM_REG_PC, ((pc & ~1) + 2) | 1)
                    try:
                        uc.emu_stop()
                    except Exception:
                        pass
                    return
            except Exception:
                pass

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
        if self._watch_break_if_needed("x", pc & ~1, size, pc=pc):
            return

        self._apply_pc_reg_writes(int(address))
        if self._apply_pc_cpu_actions(uc, int(address), int(size)):
            return

        if self.trace_enabled:
            self._trace_prepare_pending(uc, pc, size)

        # Treat tight loops as suspicious, but let interrupt-driven idle loops run longer.
        c = self._pc_hist.get(address, 0) + 1
        self._pc_hist[address] = c
        # The effective threshold is always >= stuck_loop_threshold (when set),
        # so until the repeat count reaches that floor nothing can fire. Skip the
        # per-instruction NVIC-state probe (pending/enabled IRQs) below it -- this
        # runs on essentially every instruction.
        base = self.stuck_loop_threshold
        floor = base if base > 0 else (
            self.interrupt_stuck_threshold if self.stuck_loop_auto else 0
        )
        if floor > 0 and c >= floor:
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

        uc.reg_write(UC_ARM_REG_SP, (sp + frame_size) & 0xFFFFFFFF)
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

    def _watch_break_if_needed(
        self,
        access: str,
        address: int,
        size: int,
        value: int | None = None,
        pc: int | None = None,
    ) -> bool:
        if not self._running or not self._watchpoints:
            return False
        a = (access or "").lower().strip()
        if a not in ("r", "w", "x"):
            return False

        access_size = int(size) if int(size) > 0 else 1
        access_start = int(address) & 0xFFFFFFFF
        access_end = (access_start + access_size - 1) & 0xFFFFFFFF

        for wp in self._watchpoints:
            wp_access = str(wp.get("access", "rw")).lower()
            if a not in wp_access:
                continue

            start = int(wp.get("start", 0))
            end = int(wp.get("end", -1))
            if end < start:
                start, end = end, start

            if access_end < start or access_start > end:
                continue

            self.last_watch_break = {
                "id": int(wp.get("id", -1)),
                "name": str(wp.get("name", "")),
                "access": a,
                "address": int(address),
                "size": int(size),
                "value": None if value is None else int(value),
                "pc": int(self.pc if pc is None else pc),
                "start": start,
                "end": end,
            }
            try:
                self.uc.emu_stop()
            except Exception:
                pass
            return True
        return False

    def _hook_mem_read_any(self, uc, access, address, size, value, user_data):
        self._watch_break_if_needed("r", address, size)

    def _hook_mem_write_any(self, uc, access, address, size, value, user_data):
        self._watch_break_if_needed("w", address, size, value=int(value))

    def _trace_reset_pending(self) -> None:
        self._trace_prev_pc = None
        self._trace_prev_disasm = None
        self._trace_prev_mnemonic = None
        self._trace_prev_op_str = None
        self._trace_prev_size = 0
        self._trace_prev_regs_before = None
        self._trace_prev_mmio_touched = False
        self._trace_stop_after_prev = False

    def _trace_append_history(self, line: str) -> None:
        self.trace_history.append(str(line))
        limit = max(1, int(self.trace_history_limit))
        overflow = len(self.trace_history) - limit
        if overflow > 0:
            del self.trace_history[:overflow]

    def _trace_prepare_pending(self, uc, pc: int, size: int) -> None:
        addr = int(pc) & ~1
        mnemonic = "<undecoded>"
        op_str = ""
        bytes_hex = ""
        insn_size = int(size) if int(size) > 0 else 2

        try:
            code = bytes(uc.mem_read(addr, max(insn_size, 4)))
            insns = self._disasm.disasm(code, addr, count=1)
            if insns:
                ins = insns[0]
                mnemonic = ins.mnemonic
                op_str = ins.op_str
                bytes_hex = ins.bytes_hex
                insn_size = int(ins.size) if int(ins.size) > 0 else insn_size
        except Exception:
            pass

        self._trace_prev_pc = addr
        self._trace_prev_disasm = (
            f"0x{addr:08X}: {mnemonic:<7} {op_str:<20} ; {bytes_hex}"
        ).rstrip()
        self._trace_prev_mnemonic = mnemonic.lower()
        self._trace_prev_op_str = op_str.lower()
        self._trace_prev_size = insn_size
        self._trace_prev_regs_before = self.read_regs()
        self._trace_prev_mmio_touched = False
        self._trace_stop_after_prev = (
            self.trace_until_pc is not None and addr == int(self.trace_until_pc)
        )

    @staticmethod
    def _trace_reg_delta(before: dict[str, int], after: dict[str, int]) -> list[str]:
        order = [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
        ]
        out: list[str] = []
        for name in order:
            if name not in before or name not in after:
                continue
            b = int(before[name]) & 0xFFFFFFFF
            a = int(after[name]) & 0xFFFFFFFF
            if a != b:
                out.append(f"{name}=0x{b:08X}->0x{a:08X}")
        return out

    def _trace_classify_prev(self, next_pc: int) -> dict[str, object]:
        pc = int(self._trace_prev_pc if self._trace_prev_pc is not None else 0) & 0xFFFFFFFF
        size = int(self._trace_prev_size) if int(self._trace_prev_size) > 0 else 2
        nxt = int(next_pc) & ~1
        fallthrough = (pc + size) & 0xFFFFFFFF
        mnemonic = (self._trace_prev_mnemonic or "").strip().lower()
        op = (self._trace_prev_op_str or "").strip().lower()

        is_call = mnemonic in {"bl", "blx"}
        is_ret = (
            (mnemonic == "bx" and "lr" in op)
            or (mnemonic == "pop" and "pc" in op)
            or (mnemonic == "mov" and "pc" in op and "lr" in op)
        )
        branch_mnemonics = {
            "b", "b.w", "beq", "bne", "bcs", "bcc", "bhs", "blo",
            "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge", "blt",
            "bgt", "ble", "cbz", "cbnz", "tbb", "tbh",
        }
        is_branch_candidate = mnemonic in branch_mnemonics or mnemonic.startswith("b.")
        taken = nxt != fallthrough
        return {
            "is_call": is_call and taken,
            "is_ret": is_ret and taken,
            "is_branch": is_branch_candidate and taken,
            "next_pc": nxt,
            "fallthrough": fallthrough,
        }

    def _trace_should_emit(
        self,
        *,
        is_call: bool,
        is_ret: bool,
        is_branch: bool,
    ) -> bool:
        if self.trace_mmio_only and not self._trace_prev_mmio_touched:
            return False
        if self.trace_callret_only or self.trace_branch_only:
            want_callret = self.trace_callret_only and (is_call or is_ret)
            want_branch = self.trace_branch_only and is_branch
            return want_callret or want_branch
        return True

    def _trace_finalize_pending(self, next_pc: int) -> None:
        if self._trace_prev_pc is None or self._trace_prev_disasm is None:
            return

        regs_after = self.read_regs()
        regs_before = self._trace_prev_regs_before or {}
        delta = self._trace_reg_delta(regs_before, regs_after)
        cls = self._trace_classify_prev(next_pc)
        is_call = bool(cls["is_call"])
        is_ret = bool(cls["is_ret"])
        is_branch = bool(cls["is_branch"])

        depth_before = int(self._trace_call_depth)
        depth_after = depth_before
        if is_call:
            depth_after = depth_before + 1
        elif is_ret:
            depth_after = max(0, depth_before - 1)

        if self._trace_should_emit(is_call=is_call, is_ret=is_ret, is_branch=is_branch):
            extras: list[str] = []
            if self.trace_callret_only:
                if is_call:
                    extras.append(f"call d={depth_before}->{depth_after} to=0x{int(cls['next_pc']):08X}")
                if is_ret:
                    extras.append(f"ret d={depth_before}->{depth_after} to=0x{int(cls['next_pc']):08X}")
            if self.trace_branch_only and is_branch:
                extras.append(
                    f"branch to=0x{int(cls['next_pc']):08X} from=0x{int(cls['fallthrough']):08X}"
                )
            if self.trace_reg_deltas and delta:
                extras.append("delta " + ", ".join(delta))
            line = self._trace_prev_disasm if not extras else (self._trace_prev_disasm + " | " + " ; ".join(extras))
            log.info("TRACE %s", line)
            self._trace_append_history(line)

        self._trace_call_depth = depth_after

        if self._trace_stop_after_prev:
            self.trace_enabled = False
            self.trace_until_pc = None
            log.info("TRACE auto-disabled at PC=0x%08X", int(self._trace_prev_pc))

        self._trace_reset_pending()

    def flush_trace(self) -> None:
        if not self.trace_enabled:
            return
        self._trace_finalize_pending(next_pc=self.pc & ~1)

    def _apply_pc_cpu_actions(self, uc, pc: int, size: int) -> bool:
        if not self._pc_cpu_actions:
            return False

        current_pc = int(pc) & ~1
        remove_ids: set[int] = set()
        stop = False

        for action in list(self._pc_cpu_actions):
            if current_pc != int(action.pc):
                continue

            fired = False
            if action.kind == "setreg":
                if not action.reg or action.value is None:
                    continue
                reg_id = self._reg_alias_to_unicorn(action.reg)
                if reg_id is None:
                    log.warning("ATPC CPU setreg has invalid reg: %s", action.reg)
                    continue
                uc.reg_write(reg_id, int(action.value) & 0xFFFFFFFF)
                fired = True
                log.info(
                    "ATPC CPU fired @0x%08X: %s <= 0x%X",
                    current_pc,
                    action.reg,
                    int(action.value),
                )

            elif action.kind == "ret":
                if action.value is not None:
                    uc.reg_write(UC_ARM_REG_R0, int(action.value) & 0xFFFFFFFF)
                lr = int(uc.reg_read(UC_ARM_REG_LR)) & 0xFFFFFFFF
                uc.reg_write(UC_ARM_REG_PC, lr | 1)
                fired = True
                stop = True
                log.info(
                    "ATPC CPU fired @0x%08X: return to LR=0x%08X%s",
                    current_pc,
                    lr,
                    "" if action.value is None else f" with r0=0x{int(action.value):X}",
                )

            elif action.kind == "skip":
                delta = int(action.skip_bytes) if action.skip_bytes is not None else int(size)
                if delta <= 0:
                    delta = int(size) if int(size) > 0 else 2
                next_pc = (current_pc + delta) | 1
                uc.reg_write(UC_ARM_REG_PC, next_pc & 0xFFFFFFFF)
                fired = True
                stop = True
                log.info(
                    "ATPC CPU fired @0x%08X: skip +0x%X -> 0x%08X",
                    current_pc,
                    delta,
                    next_pc & 0xFFFFFFFF,
                )

            if not fired:
                continue

            action.hits += 1
            if action.once:
                remove_ids.add(int(action.aid))
            if stop:
                break

        if remove_ids:
            self._pc_cpu_actions = [a for a in self._pc_cpu_actions if int(a.aid) not in remove_ids]

        if stop:
            try:
                uc.emu_stop()
            except Exception:
                pass
            return True
        return False

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
