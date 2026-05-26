"""u-blox GPS device emulator (NMEA + UBX binary protocol)."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from stmemu.external.device import ExternalDevice
from stmemu.external import nmea as nmea_gen
from stmemu.utils.logger import get_logger

log = get_logger(__name__)

UBX_SYNC = b"\xB5\x62"


def _ubx_checksum(cls: int, msg_id: int, payload: bytes) -> tuple[int, int]:
    ck_a = ck_b = 0
    for b in (cls, msg_id, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF):
        ck_a = (ck_a + b) & 0xFF
        ck_b = (ck_b + ck_a) & 0xFF
    for b in payload:
        ck_a = (ck_a + b) & 0xFF
        ck_b = (ck_b + ck_a) & 0xFF
    return ck_a, ck_b


def ubx_frame(cls: int, msg_id: int, payload: bytes = b"") -> bytes:
    ck_a, ck_b = _ubx_checksum(cls, msg_id, payload)
    hdr = struct.pack("<BBH", cls, msg_id, len(payload))
    return UBX_SYNC + hdr + payload + bytes([ck_a, ck_b])


def _ubx_validate(data: bytes) -> tuple[int, int, bytes] | None:
    """Parse and validate a complete UBX frame. Returns (cls, id, payload) or None."""
    if len(data) < 8 or data[:2] != UBX_SYNC:
        return None
    cls, msg_id, length = struct.unpack_from("<BBH", data, 2)
    if len(data) < 6 + length + 2:
        return None
    payload = data[6 : 6 + length]
    ck_a, ck_b = _ubx_checksum(cls, msg_id, payload)
    if data[6 + length] != ck_a or data[6 + length + 1] != ck_b:
        return None
    return cls, msg_id, payload


# UBX message classes
UBX_NAV = 0x01
UBX_CFG = 0x06
UBX_ACK = 0x05
UBX_MON = 0x0A

# NAV message IDs
NAV_PVT = 0x07
NAV_STATUS = 0x03

# CFG message IDs
CFG_PRT = 0x00
CFG_MSG = 0x01
CFG_RATE = 0x08
CFG_NAV5 = 0x24
CFG_RST = 0x04

# ACK message IDs
ACK_ACK = 0x01
ACK_NAK = 0x00

# MON message IDs
MON_VER = 0x04


@dataclass
class UbloxGpsDevice(ExternalDevice):
    """u-blox GPS receiver emulator.

    Modes:
      nmea: emits periodic NMEA GGA/RMC sentences
      ubx:  responds to UBX binary protocol commands
      both: NMEA output + UBX command handling
    """

    name: str = "ublox"
    mode: str = "nmea"
    lat: float = 34.7304
    lon: float = -86.5861
    alt: float = 190.0
    speed_knots: float = 0.0
    fix_type: int = 3
    sats: int = 8
    rate_cycles: int = 100000
    _tx_buf: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _rx_buf: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _cycle_counter: int = field(default=0, init=False, repr=False)
    _time_seconds: int = field(default=43200, init=False, repr=False)

    def reset(self) -> None:
        self._tx_buf.clear()
        self._rx_buf.clear()
        self._cycle_counter = 0
        self._time_seconds = 43200

    def tick(self, cycles: int) -> None:
        self._cycle_counter += cycles
        if self.rate_cycles > 0 and self._cycle_counter >= self.rate_cycles:
            self._cycle_counter = 0
            self._time_seconds = (self._time_seconds + 1) % 86400
            if self.mode in ("nmea", "both"):
                self._emit_nmea()

    def on_rx_from_mcu(self, data: bytes) -> None:
        if self.mode not in ("ubx", "both"):
            return
        self._rx_buf.extend(data)
        self._process_ubx_rx()

    def read_tx_to_mcu(self, max_bytes: int = 4096) -> bytes:
        if not self._tx_buf:
            return b""
        out = bytes(self._tx_buf[:max_bytes])
        del self._tx_buf[:max_bytes]
        return out

    def _emit_nmea(self) -> None:
        t = self._time_seconds
        time_str = f"{t // 3600:02d}{(t % 3600) // 60:02d}{t % 60:02d}.00"
        self._tx_buf.extend(nmea_gen.gga(
            time_utc=time_str,
            lat=self.lat, lon=self.lon,
            fix=1 if self.fix_type > 0 else 0,
            sats=self.sats, alt=self.alt,
        ))
        self._tx_buf.extend(nmea_gen.rmc(
            time_utc=time_str,
            lat=self.lat, lon=self.lon,
            speed_knots=self.speed_knots,
            status="A" if self.fix_type > 0 else "V",
        ))

    def _process_ubx_rx(self) -> None:
        while len(self._rx_buf) >= 8:
            idx = self._rx_buf.find(UBX_SYNC[0])
            if idx < 0:
                self._rx_buf.clear()
                return
            if idx > 0:
                del self._rx_buf[:idx]

            if len(self._rx_buf) < 6:
                return
            if self._rx_buf[0:2] != UBX_SYNC:
                del self._rx_buf[:1]
                continue

            cls, msg_id, length = struct.unpack_from("<BBH", self._rx_buf, 2)
            frame_len = 6 + length + 2
            if len(self._rx_buf) < frame_len:
                return

            frame = bytes(self._rx_buf[:frame_len])
            del self._rx_buf[:frame_len]

            parsed = _ubx_validate(frame)
            if parsed is None:
                continue
            self._handle_ubx(*parsed)

    def _handle_ubx(self, cls: int, msg_id: int, payload: bytes) -> None:
        if cls == UBX_CFG:
            self._handle_cfg(msg_id, payload)
        elif cls == UBX_NAV:
            self._handle_nav_poll(msg_id, payload)
        elif cls == UBX_MON:
            self._handle_mon(msg_id, payload)
        else:
            self._send_nak(cls, msg_id)

    def _handle_cfg(self, msg_id: int, payload: bytes) -> None:
        if msg_id == CFG_RATE and len(payload) >= 6:
            self._send_ack(UBX_CFG, msg_id)
        elif msg_id == CFG_PRT:
            if not payload:
                resp = struct.pack("<BBHIHH", 1, 0, 0, 0, 0, 0)
                self._tx_buf.extend(ubx_frame(UBX_CFG, CFG_PRT, resp))
            self._send_ack(UBX_CFG, msg_id)
        elif msg_id == CFG_MSG:
            self._send_ack(UBX_CFG, msg_id)
        elif msg_id == CFG_NAV5:
            self._send_ack(UBX_CFG, msg_id)
        elif msg_id == CFG_RST:
            self.reset()
            self._send_ack(UBX_CFG, msg_id)
        else:
            self._send_ack(UBX_CFG, msg_id)

    def _handle_nav_poll(self, msg_id: int, payload: bytes) -> None:
        if msg_id == NAV_PVT:
            self._tx_buf.extend(ubx_frame(UBX_NAV, NAV_PVT, self._build_nav_pvt()))
        elif msg_id == NAV_STATUS:
            status_payload = struct.pack("<IBBBB", 0, self.fix_type, 0x01, 0, 0)
            self._tx_buf.extend(ubx_frame(UBX_NAV, NAV_STATUS, status_payload))
        else:
            self._send_nak(UBX_NAV, msg_id)

    def _handle_mon(self, msg_id: int, payload: bytes) -> None:
        if msg_id == MON_VER:
            sw = b"stmemu-ublox\x00" + b"\x00" * 18
            hw = b"00080000\x00" + b"\x00" * 21
            self._tx_buf.extend(ubx_frame(UBX_MON, MON_VER, sw[:30] + hw[:30]))
        else:
            self._send_nak(UBX_MON, msg_id)

    def _build_nav_pvt(self) -> bytes:
        t = self._time_seconds
        hour = t // 3600
        minute = (t % 3600) // 60
        sec = t % 60
        lat_scaled = int(self.lat * 1e7)
        lon_scaled = int(self.lon * 1e7)
        alt_mm = int(self.alt * 1000)
        buf = bytearray(92)
        struct.pack_into("<I", buf, 0, 0)
        struct.pack_into("<HBBBBBx", buf, 4, 2024, 1, 1, hour, minute, sec)
        struct.pack_into("<B", buf, 20, self.fix_type)
        struct.pack_into("<B", buf, 21, 0x01)
        struct.pack_into("<B", buf, 23, self.sats)
        struct.pack_into("<ii", buf, 24, lon_scaled, lat_scaled)
        struct.pack_into("<ii", buf, 32, alt_mm, alt_mm)
        return bytes(buf)

    def _send_ack(self, cls: int, msg_id: int) -> None:
        self._tx_buf.extend(ubx_frame(UBX_ACK, ACK_ACK, bytes([cls, msg_id])))

    def _send_nak(self, cls: int, msg_id: int) -> None:
        self._tx_buf.extend(ubx_frame(UBX_ACK, ACK_NAK, bytes([cls, msg_id])))

    def snapshot_state(self) -> object | None:
        return {
            "mode": self.mode,
            "tx_buf": bytes(self._tx_buf),
            "rx_buf": bytes(self._rx_buf),
            "cycle_counter": self._cycle_counter,
            "time_seconds": self._time_seconds,
            "lat": self.lat,
            "lon": self.lon,
            "alt": self.alt,
            "fix_type": self.fix_type,
            "sats": self.sats,
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        self.mode = str(state.get("mode", self.mode))
        self._tx_buf = bytearray(state.get("tx_buf", b""))
        self._rx_buf = bytearray(state.get("rx_buf", b""))
        self._cycle_counter = int(state.get("cycle_counter", 0))
        self._time_seconds = int(state.get("time_seconds", 43200))
        self.lat = float(state.get("lat", self.lat))
        self.lon = float(state.get("lon", self.lon))
        self.alt = float(state.get("alt", self.alt))
        self.fix_type = int(state.get("fix_type", self.fix_type))
        self.sats = int(state.get("sats", self.sats))
