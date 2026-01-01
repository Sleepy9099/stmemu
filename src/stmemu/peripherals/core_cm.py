from __future__ import annotations

from dataclasses import dataclass

from stmemu.utils.bits import mask_for_size


@dataclass
class CortexMCorePeripheral:
    """
    Minimal model for Cortex-M System Control Space (SCS) registers we care about.
    Right now: SCB->VTOR (0xE000ED08).
    """
    vtor: int = 0

    def read(self, addr: int, size: int) -> int:
        if addr == 0xE000ED08:  # SCB->VTOR
            return self.vtor & mask_for_size(size)
        return 0

    def write(self, addr: int, size: int, value: int) -> None:
        if addr == 0xE000ED08:  # SCB->VTOR
            # VTOR must be aligned; we won't enforce hard rules yet
            self.vtor = value & 0xFFFFFFFF
            return
        # ignore everything else for MVP
