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
    """Describes one injectable peripheral or memory/function target."""
    name: str
    kind: str  # "uart", "spi", "i2c", "gpio", "memory", "function"
    model: object  # peripheral model instance, or None for memory/function
    address: int | None = None
    buffer_addr: int | None = None
    size_reg: str | None = None


@dataclass
class Injector:
    """Routes fuzz data to discovered peripheral injection points."""

    bus: PeripheralBus
    emu: object | None = None
    targets: list[InjectionTarget] = field(default_factory=list)
    _rng: random.Random = field(default_factory=random.Random)

    def set_seed(self, seed: int) -> None:
        self._rng.seed(seed)

    def discover_targets(self) -> list[InjectionTarget]:
        """Scan the bus for all injectable peripherals."""
        self.targets = [t for t in self.targets if t.kind in ("memory", "function")]
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

    def add_memory_target(
        self, name: str, address: int, *, size_reg: str | None = None
    ) -> InjectionTarget:
        """Register a direct memory-buffer injection target."""
        target = InjectionTarget(
            name=name, kind="memory", model=None,
            address=address, size_reg=size_reg,
        )
        self.targets.append(target)
        return target

    def add_function_target(
        self, name: str, entry_addr: int, buffer_addr: int,
    ) -> InjectionTarget:
        """Register a function-call injection target (r0=buf, r1=len, pc=entry)."""
        target = InjectionTarget(
            name=name, kind="function", model=None,
            address=entry_addr, buffer_addr=buffer_addr,
        )
        self.targets.append(target)
        return target

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

        if target.kind == "memory":
            if self.emu is None:
                return f"memory:{target.name} (no emulator)"
            addr = target.address
            self.emu.mem_write(addr, data)
            if target.size_reg:
                self.emu.write_reg(target.size_reg, len(data))
            return f"memory:{target.name} @0x{addr:08X} {len(data)}B"

        if target.kind == "function":
            if self.emu is None:
                return f"function:{target.name} (no emulator)"
            self.emu.mem_write(target.buffer_addr, data)
            self.emu.write_reg("r0", target.buffer_addr)
            self.emu.write_reg("r1", len(data))
            self.emu.write_reg("pc", target.address | 1)
            return (
                f"function:{target.name} @0x{target.address:08X} "
                f"buf=0x{target.buffer_addr:08X} {len(data)}B"
            )

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
