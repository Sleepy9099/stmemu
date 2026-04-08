"""Injection router — maps fuzz inputs to emulator peripheral interfaces."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralBus
from stmemu.peripherals.usart import Stm32UsartPeripheral
from stmemu.peripherals.spi import SpiPeripheral
from stmemu.peripherals.i2c import I2cPeripheral
from stmemu.peripherals.gpio import GpioPeripheral


@dataclass(frozen=True)
class InjectionTarget:
    """Describes one injectable peripheral."""
    name: str
    kind: str  # "uart", "spi", "i2c", "gpio", "mmio"
    model: object  # the peripheral model instance


@dataclass
class Injector:
    """Routes fuzz data to discovered peripheral injection points."""

    bus: PeripheralBus
    targets: list[InjectionTarget] = field(default_factory=list)
    _rng: random.Random = field(default_factory=random.Random)

    def set_seed(self, seed: int) -> None:
        self._rng.seed(seed)

    def discover_targets(self) -> list[InjectionTarget]:
        """Scan the bus for all injectable peripherals."""
        self.targets.clear()
        for mounted in self.bus.mounted_ranges():
            model = mounted.model
            name = mounted.name
            if isinstance(model, Stm32UsartPeripheral):
                self.targets.append(InjectionTarget(name=name, kind="uart", model=model))
            elif isinstance(model, SpiPeripheral):
                self.targets.append(InjectionTarget(name=name, kind="spi", model=model))
            elif isinstance(model, I2cPeripheral):
                self.targets.append(InjectionTarget(name=name, kind="i2c", model=model))
            elif isinstance(model, GpioPeripheral):
                self.targets.append(InjectionTarget(name=name, kind="gpio", model=model))
        return list(self.targets)

    def inject(self, target: InjectionTarget, data: bytes) -> str:
        """Inject fuzz data into a specific target. Returns description of what was done."""
        if target.kind == "uart":
            model: Stm32UsartPeripheral = target.model
            model.inject_rx_bytes(data)
            return f"uart:{target.name} rx {len(data)}B"

        if target.kind == "spi":
            model: SpiPeripheral = target.model
            model.inject_rx(data)
            return f"spi:{target.name} rx {len(data)}B"

        if target.kind == "i2c":
            model: I2cPeripheral = target.model
            model.inject_rx(data)
            return f"i2c:{target.name} rx {len(data)}B"

        if target.kind == "gpio":
            model: GpioPeripheral = target.model
            # Interpret fuzz data as pin state: set low 16 bits of first 2 bytes as IDR
            if len(data) >= 2:
                pin_state = int.from_bytes(data[:2], "little") & 0xFFFF
            else:
                pin_state = data[0] if data else 0
            # Use BSRR to set pins: bits[15:0] = set, bits[31:16] = reset
            set_bits = pin_state
            reset_bits = (~pin_state) & 0xFFFF
            bsrr_val = set_bits | (reset_bits << 16)
            model.write(model._BSRR, 4, bsrr_val)
            return f"gpio:{target.name} IDR=0x{pin_state:04X}"

        return f"unknown:{target.name}"

    def inject_random_target(self, data: bytes) -> str:
        """Inject into a randomly chosen target."""
        if not self.targets:
            return "(no targets)"
        target = self._rng.choice(self.targets)
        return self.inject(target, data)

    def inject_all(self, data: bytes) -> list[str]:
        """Inject into all targets, splitting data across them."""
        if not self.targets:
            return ["(no targets)"]
        results = []
        chunk_size = max(1, len(data) // len(self.targets))
        for i, target in enumerate(self.targets):
            start = i * chunk_size
            end = start + chunk_size if i < len(self.targets) - 1 else len(data)
            chunk = data[start:end]
            if chunk:
                results.append(self.inject(target, chunk))
        return results

    def list_targets(self) -> list[dict[str, str]]:
        """Return summary of discovered targets."""
        return [{"name": t.name, "kind": t.kind} for t in self.targets]
