"""Decoded, filterable bus-transaction tracer.

Replaces the per-diagnostic habit of monkeypatching ``exchange()`` /
``drain_tx_bytes`` / ``inject_rx_bytes``. Peripheral models push raw
transaction records to the bus at their choke points (SPI byte exchange,
I2C START, UART tx/rx); a :class:`BusTracer` collects, filters, coalesces
and decodes them into human-readable lines:

    SPI1  icm42688   rd reg=0x75  -> 47
    SPI1  bmi088_g   rd reg=0x3f  -> 00 00 00 00 00 00  (+42 more)
    I2C4  0x76 wr nbytes=1 ACK
    UART5 tx 28B  b5 62 06 00 14 00 ...
    UART5 rx 8B   b5 62 05 01 02 00 ...

Filtering is by **bus name or device name** (``sources=["SPI1","UART5"]`` or
``["icm42688"]``). Everything is address/name based — no symbols required.

Usage
-----
    tr = emu.enable_tracing(sources=["SPI1"])   # installs + records
    emu.run(...)
    print(tr.dump())
    emu.disable_tracing()
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


def _hexs(data, limit: int = 16) -> str:
    b = bytes(data)
    head = " ".join(f"{x:02x}" for x in b[:limit])
    return head + (f"  (+{len(b) - limit} more)" if len(b) > limit else "")


@dataclass
class BusTracer:
    """Collects and decodes bus transactions pushed from peripheral models.

    Pass ``sources`` to restrict to specific buses/devices (case-insensitive,
    matched against both the bus name and the device name). ``decode=False``
    keeps the raw records only. ``limit`` caps stored lines; overflow is
    counted and surfaced (never silently dropped).
    """

    sources: Optional[set] = None
    decode: bool = True
    limit: int = 20000
    lines: list = field(default_factory=list)
    records: list = field(default_factory=list)
    dropped: int = 0
    _spi_run: Optional[dict] = field(default=None, repr=False)

    def __post_init__(self):
        if self.sources is not None:
            self.sources = {str(s).lower() for s in self.sources}

    # ── install / teardown ─────────────────────────────────────────────
    def install(self, bus) -> "BusTracer":
        bus.install_tracer(self)
        return self

    def stop(self, bus) -> "BusTracer":
        self._flush_spi()
        bus.remove_tracer()
        return self

    # ── filtering ──────────────────────────────────────────────────────
    def _match(self, *names) -> bool:
        if self.sources is None:
            return True
        for n in names:
            if n and str(n).lower() in self.sources:
                return True
        return False

    # ── ingest (called from bus._trace) ────────────────────────────────
    def record(self, rec: dict) -> None:
        proto = rec.get("proto")
        if proto == "spi":
            self._on_spi(rec)
            return
        # Non-SPI record ends any open SPI run so ordering stays sane.
        self._flush_spi()
        if proto == "i2c":
            self._on_i2c(rec)
        elif proto == "uart":
            self._on_uart(rec)

    # ── SPI: coalesce a run of bytes to one (bus, device) into a frame ──
    def _on_spi(self, rec: dict) -> None:
        bus_name = rec.get("bus")
        dev = rec.get("device")
        if not self._match(bus_name, dev):
            self._flush_spi()
            return
        run = self._spi_run
        if run is None or run["bus"] != bus_name or run["device"] != dev:
            self._flush_spi()
            run = self._spi_run = {"bus": bus_name, "device": dev, "mosi": bytearray(), "miso": bytearray()}
        run["mosi"].append(rec.get("mosi", 0) & 0xFF)
        run["miso"].append(rec.get("miso", 0xFF) & 0xFF)
        if not self.decode:
            self.records.append(rec)

    def _flush_spi(self) -> None:
        run = self._spi_run
        self._spi_run = None
        if run is None or not run["mosi"]:
            return
        if not self.decode:
            return
        mosi = bytes(run["mosi"])
        miso = bytes(run["miso"])
        cmd = mosi[0]
        is_read = bool(cmd & 0x80)
        reg = cmd & 0x7F
        rw = "rd" if is_read else "wr"
        # For a read the response rides MISO (skip the address byte's dummy);
        # for a write the payload is what the host sent on MOSI.
        payload = miso[1:] if is_read else mosi[1:]
        arrow = "->" if is_read else "<-"
        self._emit(
            f"{run['bus']:<5} {str(run['device'] or '?'):<10} {rw} reg=0x{reg:02x}  "
            f"{arrow} {_hexs(payload)}"
        )

    # ── I2C: one line per START ─────────────────────────────────────────
    def _on_i2c(self, rec: dict) -> None:
        if not self._match(rec.get("bus")):
            return
        ack = "ACK" if rec.get("ack") else "NACK"
        self._emit(
            f"{rec.get('bus'):<5} 0x{rec.get('addr', 0):02x} {rec.get('rw')} "
            f"nbytes={rec.get('nbytes', 0)} {ack}"
        )
        if not self.decode:
            self.records.append(rec)

    # ── UART: one line per tx/rx chunk ──────────────────────────────────
    def _on_uart(self, rec: dict) -> None:
        if not self._match(rec.get("bus"), rec.get("device")):
            return
        data = bytes(rec.get("bytes", b""))
        dev = rec.get("device") or ""
        self._emit(
            f"{rec.get('bus'):<5} {str(dev):<10} {rec.get('dir')} {len(data)}B   {_hexs(data, 24)}"
        )
        if not self.decode:
            self.records.append(rec)

    # ── output ──────────────────────────────────────────────────────────
    def _emit(self, line: str) -> None:
        if len(self.lines) >= self.limit:
            self.dropped += 1
            return
        self.lines.append(line)

    def dump(self) -> str:
        self._flush_spi()
        out = list(self.lines)
        if self.dropped:
            out.append(f"... [{self.dropped} more lines dropped; raise limit= to see them]")
        return "\n".join(out)

    def counts(self) -> dict:
        """Per-line-prefix tally — quick 'who is talking and how much'."""
        self._flush_spi()
        tally: dict = {}
        for ln in self.lines:
            key = " ".join(ln.split()[:2])
            tally[key] = tally.get(key, 0) + 1
        return tally
