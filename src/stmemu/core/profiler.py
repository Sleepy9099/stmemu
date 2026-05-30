"""Built-in execution profile — instr/s, acceleration, hot PCs, MMIO hotspots.

Replaces the ad-hoc ``diag_profile.py`` we kept re-writing. One call after a
run reports how fast the emulator went (instructions/sec of wall time), how
much faster than real-time it ran (emulated-seconds / wall-seconds), where the
CPU time went (hottest PCs), and which MMIO registers were hottest.

Everything is keyed on **addresses**, so it works on a stripped raw ``.bin``.
An optional symbol resolver (``addr -> str``) enriches the hot-PC list but is
never required.

Usage
-----
    emu.reset_profile()      # zero the wall-clock + instruction/cycle baseline
    emu.run(...)
    print(emu.profile_report().format())
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from stmemu.core.stall_analyzer import _mmio_hotspots  # reuse the MMIO ranker


@dataclass
class ProfileReport:
    instructions: int           # executed since the last reset_profile()
    emulated_seconds: float     # firmware-clock time advanced since reset
    wall_seconds: float         # host time spent executing since reset
    instr_per_sec: float        # instructions / wall_seconds
    accel_factor: float         # emulated_seconds / wall_seconds (x real-time)
    fp_emulated: int            # ARMv8-M FP ops software-emulated (cumulative)
    hot_pcs: list               # [(pc, count), ...] cumulative, hottest first
    mmio_hotspots: list         # recent-window MMIO hotspots (stall-diag ring)
    mmio_window: int            # MMIO accesses examined

    def format(self, resolver: Optional[Callable[[int], str]] = None) -> str:
        def sym(addr: int) -> str:
            if resolver is None:
                return ""
            try:
                s = resolver(addr | 1)
            except Exception:
                s = None
            return f"  {s}" if s else ""

        L: list[str] = ["== profile =="]
        L.append(f"instructions   : {self.instructions:,}")
        L.append(f"emulated time  : {self.emulated_seconds:.4f}s")
        L.append(f"wall time      : {self.wall_seconds:.4f}s")
        L.append(f"instr/sec      : {self.instr_per_sec:,.0f}" if self.wall_seconds > 0 else "instr/sec      : n/a")
        L.append(
            f"acceleration   : {self.accel_factor:.2f}x real-time"
            if self.wall_seconds > 0 else "acceleration   : n/a"
        )
        if self.fp_emulated:
            L.append(f"fp emulated    : {self.fp_emulated}")
        if self.hot_pcs:
            L.append("")
            L.append("hot PCs (cumulative hit count):")
            for pc, cnt in self.hot_pcs:
                L.append(f"  0x{pc:08X}  x{cnt:,}{sym(pc)}")
        if self.mmio_hotspots:
            L.append("")
            L.append(f"MMIO hotspots (last {self.mmio_window} accesses):")
            for h in self.mmio_hotspots:
                who = h.name or "(unmapped)"
                L.append(
                    f"  [{h.access}] {who:<16} 0x{h.address:08X}  x{h.count}  "
                    f"last=0x{h.last_value:X}"
                )
        return "\n".join(L)


def profile_report(emu, *, top_pcs: int = 8, top_mmio: int = 6) -> ProfileReport:
    """Build a :class:`ProfileReport` from the emulator's counters.

    Pure read of ``emu`` state — does not advance execution. Counts are
    measured since the last :meth:`Emulator.reset_profile` (or boot).
    """
    cycle_hz = float(getattr(getattr(emu, "time", None), "cycle_hz", 1_000_000)) or 1_000_000.0
    instr0 = int(getattr(emu, "_profile_instr0", 0))
    cyc0 = int(getattr(emu, "_profile_cycles0", 0))
    instr = max(0, int(emu.time.instructions) - instr0)
    cyc = max(0, int(emu.time.cycles) - cyc0)
    emulated_s = cyc / cycle_hz
    wall_s = float(getattr(emu, "_wall_elapsed", 0.0))
    ips = (instr / wall_s) if wall_s > 0 else 0.0
    accel = (emulated_s / wall_s) if wall_s > 0 else 0.0

    pc_hist = dict(getattr(emu, "_pc_hist", {}) or {})
    hot = sorted(pc_hist.items(), key=lambda kv: -kv[1])[:top_pcs]
    hot = [((pc & ~1), cnt) for pc, cnt in hot]

    hotspots, window = _mmio_hotspots(emu, top_mmio)
    return ProfileReport(
        instructions=instr,
        emulated_seconds=emulated_s,
        wall_seconds=wall_s,
        instr_per_sec=ips,
        accel_factor=accel,
        fp_emulated=int(getattr(emu, "_fp_emulated_count", 0)),
        hot_pcs=hot,
        mmio_hotspots=hotspots,
        mmio_window=window,
    )


__all__ = ["ProfileReport", "profile_report"]
