"""Central emulated-time service.

A single object that owns the emulator's notion of time so timer, DWT/SysTick,
external-device pacing, DMA, idle fast-forward, and scheduled events all advance
through one canonical path (``Emulator.advance_time``) instead of each calling
``bus.tick`` on its own.

For now ``core_cycles == peripheral_cycles`` (one cycle domain). APB/HCLK
prescaler trees are a deliberate future layer; ``cycle_hz`` is a nominal clock
used only to convert wall-clock scheduling (``after_ms``) into cycles.
"""
from __future__ import annotations

from dataclasses import dataclass

# normal   — every instruction advances tick_scale cycles; no idle skipping.
# idle     — normal stepping while code runs; fast-forward only when the CPU is
#            parked (self-branch / WFI) to the next scheduled interrupt.
# adaptive — like idle today (reserved for "widen the jump when nothing is
#            happening"; behaves as idle until that heuristic lands).
# fixed    — force tick_scale cycles per instruction for brute-force progress;
#            no idle skipping.
VALID_MODES = ("normal", "idle", "adaptive", "fixed")


@dataclass
class EmulatedTime:
    instructions: int = 0
    cycles: int = 0
    mode: str = "idle"
    max_fast_forward_cycles: int = 50_000_000
    coalesce_timer_events: bool = True
    cycle_hz: int = 1_000_000  # nominal clock for after_ms -> cycle conversion

    @property
    def idle_fast_forward(self) -> bool:
        """Whether the current mode permits jumping time over CPU idle waits."""
        return self.mode in ("idle", "adaptive")

    def ms_to_cycles(self, ms: float) -> int:
        return int(round(float(ms) * self.cycle_hz / 1000.0))

    def status(self) -> dict[str, object]:
        return {
            "instructions": self.instructions,
            "cycles": self.cycles,
            "mode": self.mode,
            "idle_fast_forward": self.idle_fast_forward,
            "max_fast_forward_cycles": self.max_fast_forward_cycles,
            "coalesce_timer_events": self.coalesce_timer_events,
            "cycle_hz": self.cycle_hz,
        }
