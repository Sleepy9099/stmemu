from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class SpiPeripheral(GenericRegisterFilePeripheral):
    """SPI peripheral with TXE/RXNE/BSY flag simulation.

    Firmware expects TXE=1 (transmit buffer empty) after writing DR,
    and BSY=0 when no transfer is in progress. Without these flags,
    firmware polling loops will hang.
    """

    irq: int | None = None
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _tx_fifo: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _rx_fifo: deque[int] = field(default_factory=deque, init=False, repr=False)
    _devices: list[object] = field(default_factory=list, init=False, repr=False)

    # Standard SPI register offsets (legacy F1/F4/F7 layout).
    _CR1 = 0x00
    _CR2 = 0x04
    _SR = 0x08
    _DR = 0x0C        # legacy combined data register
    _TXDR: int | None = None  # H7 split TX data register
    _RXDR: int | None = None  # H7 split RX data register

    # SR flags (legacy layout). H7 uses different bit positions but firmware
    # for ChibiOS HAL drivers usually consults TXE/RXNE/EOT semantically.
    _SR_RXNE = 1 << 0   # Receive buffer not empty
    _SR_TXE = 1 << 1    # Transmit buffer empty
    _SR_BSY = 1 << 7    # Busy flag

    # H7 SR flags (datasheet bit positions):
    _H7_SR_RXP = 1 << 0   # RX packet available
    _H7_SR_TXP = 1 << 1   # TX packet space available
    _H7_SR_EOT = 1 << 3   # End of transfer
    _H7_SR_TXC = 1 << 12  # TX complete

    # CR1 flags (legacy)
    _CR1_SPE = 1 << 6   # SPI enable

    # CR2 flags (legacy)
    _CR2_RXDMAEN = 1 << 0  # RX buffer DMA enable
    _CR2_TXDMAEN = 1 << 1  # TX buffer DMA enable

    # H7 CR1 flags
    _H7_CR1_SPE = 1 << 0      # SPI enable
    _H7_CR1_CSTART = 1 << 9   # Master transfer start (self-clearing on EOT)
    _H7_CR1_CSUSP = 1 << 10   # Master transfer suspend (self-clearing on EOT)

    # H7 CFG1 fields. On the H7 layout the DMA enable bits live in CFG1
    # rather than CR2; the bits are TXDMAEN=15, RXDMAEN=14 per RM0433.
    _H7_CFG1: int | None = None
    _H7_CFG1_TXDMAEN = 1 << 15
    _H7_CFG1_RXDMAEN = 1 << 14

    def __post_init__(self) -> None:
        super().__post_init__()
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "CR1":
                self._CR1 = reg.offset
            elif rname == "CR2":
                self._CR2 = reg.offset
            elif rname == "SR":
                self._SR = reg.offset
            elif rname == "DR":
                self._DR = reg.offset
            elif rname == "TXDR":
                self._TXDR = reg.offset
            elif rname == "RXDR":
                self._RXDR = reg.offset
            elif rname == "CFG1":
                self._H7_CFG1 = reg.offset
        # When the SVD provides split TX/RX (H7), suppress the legacy
        # combined DR so writes to that offset don't accidentally clock
        # the bus — on H7 0x0C is the CFG2 register.
        if self._TXDR is not None or self._RXDR is not None:
            self._DR = -1
        self._refresh_status()

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def _is_data_read(self, offset: int) -> bool:
        if self._RXDR is not None:
            return offset == self._RXDR
        return offset == self._DR

    def _is_data_write(self, offset: int) -> bool:
        if self._TXDR is not None:
            return offset == self._TXDR
        return offset == self._DR

    def read(self, offset: int, size: int) -> int:
        if self._is_data_read(offset):
            value = self._rx_fifo.popleft() if self._rx_fifo else 0
            self._refresh_status()
            # If RX DMA is enabled and the FIFO still has data, signal
            # another drain request so DMA keeps consuming bytes.
            if self._rx_fifo:
                self._emit_dma_request_rx()
            return value
        if offset == self._SR:
            self._refresh_status()
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if size in (1, 2, 4) and self._is_data_write(offset):
            byte = int(value) & 0xFF
            self._tx_fifo.append(byte)
            miso = self._exchange_with_selected(byte)
            self._rx_fifo.append(miso)
            self._refresh_status()
            # A byte just landed in the RX FIFO — drain via RX DMA, then
            # ask DMA for the next TX byte if TX DMA is enabled.
            self._emit_dma_request_rx()
            self._emit_dma_request_tx()
            return
        super().write(offset, size, value)
        if offset == self._CR1:
            # H7 CSTART / CSUSP auto-clear when the hardware completes the
            # transfer. Without real timing we treat them as immediately
            # self-clearing so firmware polling loops can progress.
            if self._TXDR is not None or self._RXDR is not None:
                cr1 = self.read_register_value(self._CR1)
                cleared = cr1 & ~(self._H7_CR1_CSTART | self._H7_CR1_CSUSP)
                if cleared != cr1:
                    self.write_register_value(self._CR1, cleared)
            self._refresh_status()
            self._kick_dma_on_enable()
        elif offset == self._CR2 or (
            self._H7_CFG1 is not None and offset == self._H7_CFG1
        ):
            self._refresh_status()
            self._kick_dma_on_enable()

    def _exchange_with_selected(self, byte: int) -> int:
        """Route MOSI to whichever attached slave currently has CS asserted.

        Multiple devices can share one SPI peripheral (e.g. SPI1 with an
        IMU and two BMI088 chips). Each device tracks its own ``cs_active``;
        the first one whose CS is low gets the byte. If no slave's CS is
        asserted but the bus has exactly one attached device, route to it
        anyway -- a single-slave bus with no CS detection (FRAM auto-CS
        before the first GPIO falling edge is seen) shouldn't go silent.
        """
        for dev in self._devices:
            if getattr(dev, "cs_active", False) and hasattr(dev, "exchange"):
                return int(dev.exchange(byte)) & 0xFF
        if len(self._devices) == 1:
            dev = self._devices[0]
            if hasattr(dev, "exchange"):
                return int(dev.exchange(byte)) & 0xFF
        return 0xFF

    def attach_device(self, device: object) -> None:
        """Wire an SPI slave so MOSI bytes go through device.exchange().

        Multiple devices may be attached to one SPI bus; each is dispatched
        based on its ``cs_active`` flag at exchange time.
        """
        if device not in self._devices:
            self._devices.append(device)

    def detach_device(self, device: object | None = None) -> None:
        if device is None:
            self._devices.clear()
        else:
            try:
                self._devices.remove(device)
            except ValueError:
                pass

    @property
    def attached_device(self) -> object | None:
        return self._devices[0] if self._devices else None

    @property
    def attached_devices(self) -> tuple[object, ...]:
        return tuple(self._devices)

    def _refresh_status(self) -> None:
        sr = self.read_register_value(self._SR)
        if self._TXDR is not None or self._RXDR is not None:
            # H7-style SR: TXP/RXP/EOT/TXC sit at the bottom; force
            # TXP+TXC=1 (host can keep writing) and toggle RXP based on
            # whether MISO bytes are queued.
            sr &= ~(self._H7_SR_RXP | self._H7_SR_TXP | self._H7_SR_EOT | self._H7_SR_TXC)
            sr |= self._H7_SR_TXP | self._H7_SR_TXC | self._H7_SR_EOT
            if self._rx_fifo:
                sr |= self._H7_SR_RXP
        else:
            sr &= ~(self._SR_TXE | self._SR_RXNE | self._SR_BSY)
            sr |= self._SR_TXE  # always ready to transmit
            if self._rx_fifo:
                sr |= self._SR_RXNE
            # BSY stays 0 (transfers complete instantly)
        self.write_register_value(self._SR, sr)

    def _data_register_address(self) -> int | None:
        """Return the absolute bus address peripherals would point PAR at."""
        if self._context is None:
            return None
        if self._RXDR is not None:
            return self._context.base + self._RXDR
        if self._DR >= 0:
            return self._context.base + self._DR
        return None

    def _tx_register_address(self) -> int | None:
        if self._context is None:
            return None
        if self._TXDR is not None:
            return self._context.base + self._TXDR
        if self._DR >= 0:
            return self._context.base + self._DR
        return None

    def _dma_flags(self) -> tuple[bool, bool]:
        """Return (rxdma_enabled, txdma_enabled) honoring legacy/H7 layouts."""
        if self._H7_CFG1 is not None:
            cfg1 = self.read_register_value(self._H7_CFG1)
            return (
                bool(cfg1 & self._H7_CFG1_RXDMAEN),
                bool(cfg1 & self._H7_CFG1_TXDMAEN),
            )
        cr2 = self.read_register_value(self._CR2)
        return (bool(cr2 & self._CR2_RXDMAEN), bool(cr2 & self._CR2_TXDMAEN))

    def _emit_dma_request_rx(self) -> None:
        if self._context is None or self._context.bus is None:
            return
        rx_en, _ = self._dma_flags()
        if not rx_en or not self._rx_fifo:
            return
        addr = self._data_register_address()
        if addr is not None:
            self._context.bus.request_dma(
                addr, "p2m", size=1, source=self._context.name,
            )

    def _emit_dma_request_tx(self) -> None:
        if self._context is None or self._context.bus is None:
            return
        _, tx_en = self._dma_flags()
        if not tx_en:
            return
        addr = self._tx_register_address()
        if addr is not None:
            self._context.bus.request_dma(
                addr, "m2p", size=1, source=self._context.name,
            )

    def _kick_dma_on_enable(self) -> None:
        """Fire an initial TX DMA request after a CR1/CR2/CFG1 write.

        Real silicon starts asserting the TX DMA request line as soon as
        SPE and TXDMAEN are both set, because the TX shift register is
        empty. We emulate that by emitting one M2P request here; the DMA
        stream will keep pulling bytes via the per-exchange chain.
        """
        if not self._spi_dma_active():
            return
        self._emit_dma_request_tx()

    def _spi_dma_active(self) -> bool:
        if self._context is None:
            return False
        cr1 = self.read_register_value(self._CR1)
        if self._TXDR is not None or self._RXDR is not None:
            return bool(cr1 & self._H7_CR1_SPE)
        return bool(cr1 & self._CR1_SPE)

    def on_dma_armed(self, offset: int, direction: str) -> None:
        """Called by DMA when a stream targeting this peripheral arms.

        Handles the firmware order ``configure SPI + DMAEN -> arm streams``:
        the initial TX request emitted at CR1/CR2/CFG1 write time would
        otherwise have been dropped because no stream was enabled yet.
        """
        if not self._spi_dma_active():
            return
        if direction == "m2p" and self._is_data_write(offset):
            self._emit_dma_request_tx()
        elif direction == "p2m" and self._is_data_read(offset):
            self._emit_dma_request_rx()

    def drain_tx(self) -> bytes:
        data = bytes(self._tx_fifo)
        self._tx_fifo.clear()
        return data

    def inject_rx(self, data: bytes) -> None:
        for b in data:
            self._rx_fifo.append(int(b) & 0xFF)
            self._refresh_status()
            self._emit_dma_request_rx()
        # Final refresh covers the empty-input case.
        if not data:
            self._refresh_status()

    def reset(self) -> None:
        super().reset()
        self._tx_fifo.clear()
        self._rx_fifo.clear()
        # Devices stay attached across reset (board topology persists).
        self._refresh_status()

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base["tx_fifo"] = bytes(self._tx_fifo)
        base["rx_fifo"] = list(self._rx_fifo)
        attached = []
        for i, dev in enumerate(self._devices):
            entry = {
                "name": getattr(dev, "name", f"dev{i}"),
                "type": type(dev).__name__,
            }
            if hasattr(dev, "snapshot_state"):
                try:
                    entry["state"] = dev.snapshot_state()
                except Exception:
                    entry["state"] = None
            attached.append(entry)
        base["attached_devices"] = attached
        return base

    def restore_state(self, state: object) -> None:
        super().restore_state(state)
        if not isinstance(state, dict):
            return
        tx = state.get("tx_fifo")
        if isinstance(tx, (bytes, bytearray)):
            self._tx_fifo = bytearray(tx)
        rx = state.get("rx_fifo")
        if isinstance(rx, list):
            self._rx_fifo = deque(int(b) & 0xFF for b in rx)
        attached = state.get("attached_devices")
        if isinstance(attached, list):
            # Build lookup by name first, then fall back to type, then index.
            by_name: dict[str, object] = {}
            by_type: dict[str, list[object]] = {}
            for dev in self._devices:
                name = getattr(dev, "name", None)
                if name:
                    by_name.setdefault(name, dev)
                by_type.setdefault(type(dev).__name__, []).append(dev)
            type_cursor: dict[str, int] = {}
            for i, entry in enumerate(attached):
                if not isinstance(entry, dict):
                    continue
                dev_state = entry.get("state")
                if dev_state is None:
                    continue
                name = entry.get("name", "")
                type_name = entry.get("type", "")
                target = by_name.get(name)
                if target is None:
                    candidates = by_type.get(type_name, [])
                    cursor = type_cursor.get(type_name, 0)
                    if cursor < len(candidates):
                        target = candidates[cursor]
                        type_cursor[type_name] = cursor + 1
                if target is None and i < len(self._devices):
                    target = self._devices[i]
                if target is not None and hasattr(target, "restore_state"):
                    try:
                        target.restore_state(dev_state)
                    except Exception:
                        pass
        self._refresh_status()


def _first_irq(peripheral: SvdPeripheral) -> Optional[int]:
    if peripheral.interrupts:
        return peripheral.interrupts[0].value
    return None


def build_spi(peripheral: SvdPeripheral) -> SpiPeripheral:
    return SpiPeripheral(peripheral=peripheral, irq=_first_irq(peripheral))
