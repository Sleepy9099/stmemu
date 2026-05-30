"""Explain *why* execution is stuck — in one call, without needing symbols.

When firmware stops making progress it is almost always one of a few shapes:

  * a polling loop spinning on an MMIO bit that never changes
    (``while (!(I2C->ISR & TXIS)) {}``),
  * a self-branch idle loop (``b .``) waiting for an interrupt that never
    fires,
  * a higher-level algorithmic loop that never converges (e.g. a sensor
    calibration that keeps reading the same data).

Diagnosing those by hand meant re-running with ad-hoc instrumentation each
time. This turns it into a single structured report:

  * the hot loop PC(s) and how many times they repeated,
  * the MMIO register the loop keeps touching — named via the SVD map
    (``I2C4.ISR``) — the value last seen there, and how many recent accesses
    hit it,
  * an address backtrace of the *active* thread stack (PSP/MSP aware),
  * an English verdict.

Everything is keyed on **addresses**, so it works on a stripped raw ``.bin``.
A symbol resolver (``addr -> str``) may be passed to :meth:`StallReport.format`
to enrich the output, but it is never required.

Usage
-----
    from stmemu.core.stall_analyzer import analyze_stall
    emu.enable_stall_diagnostics()      # start recording recent MMIO accesses
    emu.run(...)                        # ... until it stalls
    print(analyze_stall(emu).format())
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


# ── recent-MMIO ring buffer entry ──────────────────────────────────────
# (pc, access, address, size, value) — populated by the emulator's MMIO
# hooks when stall diagnostics are enabled.
MmioAccess = tuple


@dataclass
class MmioHotspot:
    access: str           # "r" or "w"
    address: int
    name: Optional[str]   # "I2C4.ISR" or None if unmapped
    count: int            # accesses to this (access, address) in the window
    last_value: int
    distinct_values: int  # how many distinct values were seen (1 == stuck)


@dataclass
class StallReport:
    stuck_pc: int
    hot_pcs: list                       # [(pc, count), ...] hottest first
    mmio_hotspots: list[MmioHotspot]    # hottest first
    backtrace: list                     # [(stack_addr, code_addr), ...] inner -> outer
    sp: int
    use_psp: bool
    window: int                         # MMIO accesses examined
    code_range: tuple                   # (lo, hi)

    # ── verdict ────────────────────────────────────────────────────────
    @property
    def spin_pc(self) -> int:
        """The dominant hot PC (where time is actually going), not just the
        instant the run stopped — more meaningful in a multi-threaded RTOS."""
        return self.hot_pcs[0][0] if self.hot_pcs else self.stuck_pc

    @property
    def verdict(self) -> str:
        pc = self.spin_pc
        top = self.mmio_hotspots[0] if self.mmio_hotspots else None
        if top is not None and top.count >= 3 and top.distinct_values <= 1:
            who = top.name or f"0x{top.address:08X}"
            verb = "polling" if top.access == "r" else "hammering"
            return (
                f"Spinning at PC=0x{pc:08X} {verb} {who} "
                f"(stuck at 0x{top.last_value:X}, {top.count} recent accesses) "
                f"- waiting on a bit that never changes."
            )
        if top is not None and top.count >= 3:
            who = top.name or f"0x{top.address:08X}"
            return (
                f"Looping at PC=0x{pc:08X} with active MMIO on {who} "
                f"({top.count} accesses, values changing) - not a stuck-bit "
                f"poll; likely an algorithmic loop or multi-step transfer that "
                f"isn't progressing. Inspect the backtrace."
            )
        return (
            f"Looping at PC=0x{pc:08X} with no MMIO in the window "
            f"- an idle/self-loop waiting for an interrupt, or a pure compute "
            f"loop. Inspect the backtrace for the owning routine."
        )

    # ── rendering ──────────────────────────────────────────────────────
    def format(self, resolver: Optional[Callable[[int], str]] = None) -> str:
        def sym(addr: int) -> str:
            if resolver is None:
                return ""
            try:
                s = resolver(addr | 1)
            except Exception:
                s = None
            return f"  {s}" if s else ""

        lines: list[str] = []
        lines.append("== stall analysis ==")
        lines.append(self.verdict)
        lines.append("")
        lines.append(f"stuck pc : 0x{self.stuck_pc:08X}{sym(self.stuck_pc)}")
        lines.append(
            f"stack    : {'PSP' if self.use_psp else 'MSP'}=0x{self.sp:08X}  "
            f"code=0x{self.code_range[0]:08X}..0x{self.code_range[1]:08X}"
        )

        if self.hot_pcs:
            lines.append("")
            lines.append("hot PCs (repeat count):")
            for pc, cnt in self.hot_pcs:
                lines.append(f"  0x{pc:08X}  x{cnt}{sym(pc)}")

        lines.append("")
        if self.mmio_hotspots:
            lines.append(f"MMIO accessed in last {self.window} accesses:")
            for h in self.mmio_hotspots:
                who = h.name or "(unmapped)"
                stuck = " STUCK" if h.distinct_values <= 1 else f" {h.distinct_values} vals"
                lines.append(
                    f"  [{h.access}] {who:<16} 0x{h.address:08X}  x{h.count}  "
                    f"last=0x{h.last_value:X}{stuck}"
                )
        else:
            lines.append("MMIO accessed in window: (none - not an MMIO spin loop)")

        lines.append("")
        lines.append("backtrace (inner -> outer):")
        if self.backtrace:
            for sp_addr, code in self.backtrace:
                lines.append(f"  [sp+0x{sp_addr - self.sp:04X}] 0x{code:08X}{sym(code)}")
        else:
            lines.append("  (no code return addresses found on the active stack)")
        return "\n".join(lines)


# ── helpers ────────────────────────────────────────────────────────────

def _code_range(emu) -> tuple:
    """Loaded-image address span; falls back to the flash window."""
    lo = hi = None
    for seg in getattr(emu, "firmware_segments", None) or ():
        addr = getattr(seg, "address", None)
        if addr is None:
            continue
        end = addr + len(getattr(seg, "data", b""))
        lo = addr if lo is None else min(lo, addr)
        hi = end if hi is None else max(hi, end)
    if lo is None:
        base = int(getattr(emu, "flash_base", 0x08000000))
        return base, base + 0x00800000
    return lo, hi


def _name_addr(emu, addr: int) -> Optional[str]:
    """Resolve an MMIO address to ``PERIPH.REG`` via the SVD-backed bus map."""
    bus = getattr(emu, "bus", None)
    if bus is None:
        return None
    try:
        mounted = bus._mount_for_addr(addr)
        if mounted is None:
            return None
        reg = mounted.model.describe(addr - mounted.base)
        return f"{mounted.name}.{reg}" if reg else f"{mounted.name}+0x{addr - mounted.base:X}"
    except Exception:
        return None


def _mmio_hotspots(emu, top: int) -> tuple[list[MmioHotspot], int]:
    ring = list(getattr(emu, "_mmio_ring", ()) or ())
    counts: dict = {}
    last_val: dict = {}
    seen_vals: dict = {}
    for entry in ring:
        # entry = (pc, access, address, size, value)
        _pc, access, address, _size, value = entry
        key = (access, address)
        counts[key] = counts.get(key, 0) + 1
        last_val[key] = value
        seen_vals.setdefault(key, set()).add(value)
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:top]
    out: list[MmioHotspot] = []
    for (access, address), cnt in ranked:
        out.append(MmioHotspot(
            access=access,
            address=address,
            name=_name_addr(emu, address),
            count=cnt,
            last_value=last_val[(access, address)],
            distinct_values=len(seen_vals[(access, address)]),
        ))
    return out, len(ring)


def _backtrace(emu, code_lo: int, code_hi: int, *, max_depth: int = 40, span: int = 0x1200) -> tuple:
    use_psp = False
    try:
        use_psp = bool(emu._active_stack_is_psp())
    except Exception:
        pass
    try:
        sp = int(emu._read_stack_pointer(use_psp))
    except Exception:
        sp = int(getattr(emu, "sp", 0))
    out: list = []
    try:
        data = emu.mem_read(sp, span)
    except Exception:
        return out, sp, use_psp
    last = None
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "little")
        if (w & 1) and code_lo <= (w & ~1) < code_hi:
            code = w & ~1
            if code != last:
                out.append((sp + off, code))
                last = code
                if len(out) >= max_depth:
                    break
    return out, sp, use_psp


def analyze_stall(emu, *, top_mmio: int = 6, top_pcs: int = 6) -> StallReport:
    """Produce a :class:`StallReport` from the emulator's current state.

    Reads the recent-MMIO ring buffer (enabled via
    :meth:`Emulator.enable_stall_diagnostics`), the per-PC repeat histogram,
    and the active thread stack. Pure analysis — does not advance execution.
    """
    pc_hist = dict(getattr(emu, "_pc_hist", {}) or {})
    hot = sorted(pc_hist.items(), key=lambda kv: -kv[1])[:top_pcs]
    # Strip thumb bits from the histogram keys for display.
    hot = [((pc & ~1), cnt) for pc, cnt in hot]
    try:
        stuck_pc = int(emu.pc) & ~1
    except Exception:
        stuck_pc = hot[0][0] if hot else 0
    lo, hi = _code_range(emu)
    hotspots, window = _mmio_hotspots(emu, top_mmio)
    bt, sp, use_psp = _backtrace(emu, lo, hi)
    return StallReport(
        stuck_pc=stuck_pc,
        hot_pcs=hot,
        mmio_hotspots=hotspots,
        backtrace=bt,
        sp=sp,
        use_psp=use_psp,
        window=window,
        code_range=(lo, hi),
    )
