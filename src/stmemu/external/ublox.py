"""u-blox M8/M10 GPS receiver emulator (NMEA + UBX binary protocol)."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from stmemu.external.device import ExternalDevice
from stmemu.external import nmea as nmea_gen
from stmemu.utils.logger import get_logger

log = get_logger(__name__)

UBX_SYNC = b"\xB5\x62"

# UBX message classes
UBX_NAV = 0x01
UBX_RXM = 0x02
UBX_INF = 0x04
UBX_ACK = 0x05
UBX_CFG = 0x06
UBX_MON = 0x0A

# NAV message IDs
NAV_POSLLH = 0x02
NAV_STATUS = 0x03
NAV_DOP = 0x04
NAV_SOL = 0x06
NAV_PVT = 0x07
NAV_VELNED = 0x12
NAV_TIMEUTC = 0x21
NAV_SAT = 0x35
NAV_SVINFO = 0x30

# CFG message IDs
CFG_PRT = 0x00
CFG_MSG = 0x01
CFG_RST = 0x04
CFG_RATE = 0x08
CFG_CFG = 0x09
CFG_NAV5 = 0x24
CFG_GNSS = 0x3E
CFG_SBAS = 0x16

# ACK message IDs
ACK_ACK = 0x01
ACK_NAK = 0x00

# MON message IDs
MON_VER = 0x04
MON_HW = 0x09

# Dynamic platform models for CFG-NAV5
DYN_PORTABLE = 0
DYN_STATIONARY = 2
DYN_PEDESTRIAN = 3
DYN_AUTOMOTIVE = 4
DYN_SEA = 5
DYN_AIRBORNE_1G = 6
DYN_AIRBORNE_2G = 7
DYN_AIRBORNE_4G = 8

# NMEA message keys for CFG-MSG rate control
_NMEA_MSG_KEYS = {
    (0xF0, 0x00): "GGA",
    (0xF0, 0x01): "GLL",
    (0xF0, 0x02): "GSA",
    (0xF0, 0x03): "GSV",
    (0xF0, 0x04): "RMC",
    (0xF0, 0x05): "VTG",
}

# Default NMEA output rates (1 = every fix, 0 = off)
_DEFAULT_NMEA_RATES: dict[str, int] = {
    "GGA": 1, "RMC": 1, "GSA": 1, "GSV": 1, "VTG": 1, "GLL": 0,
}


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


@dataclass(frozen=True)
class SatInfo:
    prn: int
    elev: int
    azim: int
    snr: int
    gnss_id: int = 0
    sv_id: int = 0
    flags: int = 0x1F


_DEFAULT_CONSTELLATION: tuple[SatInfo, ...] = (
    SatInfo(prn=2,  elev=45, azim=30,  snr=35, gnss_id=0, sv_id=2),
    SatInfo(prn=5,  elev=60, azim=120, snr=40, gnss_id=0, sv_id=5),
    SatInfo(prn=10, elev=30, azim=200, snr=30, gnss_id=0, sv_id=10),
    SatInfo(prn=12, elev=70, azim=310, snr=42, gnss_id=0, sv_id=12),
    SatInfo(prn=15, elev=20, azim=80,  snr=28, gnss_id=0, sv_id=15),
    SatInfo(prn=21, elev=55, azim=250, snr=38, gnss_id=0, sv_id=21),
    SatInfo(prn=24, elev=35, azim=150, snr=33, gnss_id=0, sv_id=24),
    SatInfo(prn=29, elev=50, azim=340, snr=36, gnss_id=0, sv_id=29),
)


@dataclass
class UbloxGpsDevice(ExternalDevice):
    """u-blox M8/M10 GPS receiver emulator.

    Modes:
      nmea: emits periodic NMEA sentences
      ubx:  responds to UBX binary protocol commands
      both: NMEA output + UBX command handling
    """

    name: str = "ublox"
    mode: str = "nmea"
    lat: float = 34.7304
    lon: float = -86.5861
    alt: float = 190.0
    speed_knots: float = 0.0
    course: float = 0.0
    fix_type: int = 3
    sats: int = 8
    hdop: float = 1.2
    vdop: float = 1.6
    pdop: float = 2.0
    rate_cycles: int = 100000
    ttff_ticks: int = 0

    _tx_buf: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _rx_buf: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _cycle_counter: int = field(default=0, init=False, repr=False)
    _time_seconds: int = field(default=43200, init=False, repr=False)
    _fix_epoch: int = field(default=0, init=False, repr=False)
    _total_ticks: int = field(default=0, init=False, repr=False)

    _dyn_model: int = field(default=DYN_AUTOMOTIVE, init=False, repr=False)
    _meas_rate_ms: int = field(default=1000, init=False, repr=False)
    _nav_rate: int = field(default=1, init=False, repr=False)
    _nmea_rates: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _ubx_periodic: dict[tuple[int, int], int] = field(
        default_factory=dict, init=False, repr=False,
    )
    _constellation: list[SatInfo] = field(default_factory=list, init=False, repr=False)
    _port_protocols: dict[int, tuple[int, int]] = field(
        default_factory=dict, init=False, repr=False,
    )

    def __post_init__(self) -> None:
        self._nmea_rates = dict(_DEFAULT_NMEA_RATES)
        self._constellation = list(_DEFAULT_CONSTELLATION)
        self._port_protocols = {1: (0x07, 0x03)}

    def reset(self) -> None:
        self._tx_buf.clear()
        self._rx_buf.clear()
        self._cycle_counter = 0
        self._time_seconds = 43200
        self._fix_epoch = 0
        self._total_ticks = 0
        self._dyn_model = DYN_AUTOMOTIVE
        self._meas_rate_ms = 1000
        self._nav_rate = 1
        self._nmea_rates = dict(_DEFAULT_NMEA_RATES)
        self._ubx_periodic.clear()
        self._constellation = list(_DEFAULT_CONSTELLATION)
        self._port_protocols = {1: (0x07, 0x03)}

    @property
    def _effective_fix(self) -> int:
        if self.ttff_ticks > 0 and self._total_ticks < self.ttff_ticks:
            return 0
        return self.fix_type

    @property
    def _effective_sats(self) -> int:
        if self._effective_fix == 0:
            return 0
        return min(self.sats, len(self._constellation))

    def tick(self, cycles: int) -> None:
        self._cycle_counter += int(cycles)
        self._total_ticks += int(cycles)
        while self.rate_cycles > 0 and self._cycle_counter >= self.rate_cycles:
            self._cycle_counter -= self.rate_cycles
            self._time_seconds = (self._time_seconds + 1) % 86400
            self._fix_epoch += 1
            if self.mode in ("nmea", "both"):
                self._emit_nmea()
            if self.mode in ("ubx", "both"):
                self._emit_ubx_periodic()

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

    def pending_tx_len(self) -> int:
        return len(self._tx_buf)

    # ── NMEA output ──────────────────────────────────────────────

    def _time_str(self) -> str:
        t = self._time_seconds
        return f"{t // 3600:02d}{(t % 3600) // 60:02d}{t % 60:02d}.00"

    def _emit_nmea(self) -> None:
        ts = self._time_str()
        fix = self._effective_fix
        ns = self._effective_sats
        status = "A" if fix > 0 else "V"
        pos = dict(lat=self.lat, lon=self.lon)
        epoch = self._fix_epoch

        if self._nmea_rates.get("GGA", 0) and epoch % max(1, self._nmea_rates["GGA"]) == 0:
            self._tx_buf.extend(nmea_gen.gga(
                time_utc=ts, fix=1 if fix > 0 else 0,
                sats=ns, hdop=self.hdop, alt=self.alt, **pos,
            ))
        if self._nmea_rates.get("RMC", 0) and epoch % max(1, self._nmea_rates["RMC"]) == 0:
            self._tx_buf.extend(nmea_gen.rmc(
                time_utc=ts, speed_knots=self.speed_knots,
                course=self.course, status=status, **pos,
            ))
        if self._nmea_rates.get("GSA", 0) and epoch % max(1, self._nmea_rates["GSA"]) == 0:
            prns = [s.prn for s in self._constellation[:ns]]
            self._tx_buf.extend(nmea_gen.gsa(
                fix_3d=fix if fix > 0 else 1, prns=prns,
                pdop=self.pdop, hdop=self.hdop, vdop=self.vdop,
            ))
        if self._nmea_rates.get("GSV", 0) and epoch % max(1, self._nmea_rates["GSV"]) == 0:
            self._emit_gsv()
        if self._nmea_rates.get("VTG", 0) and epoch % max(1, self._nmea_rates["VTG"]) == 0:
            self._tx_buf.extend(nmea_gen.vtg(
                course_true=self.course,
                speed_knots=self.speed_knots,
                speed_kmh=self.speed_knots * 1.852,
                mode="A" if fix > 0 else "N",
            ))
        if self._nmea_rates.get("GLL", 0) and epoch % max(1, self._nmea_rates["GLL"]) == 0:
            self._tx_buf.extend(nmea_gen.gll(
                time_utc=ts, status=status, **pos,
            ))

    def _emit_gsv(self) -> None:
        sats = self._constellation[:self._effective_sats] if self._effective_fix > 0 else []
        total = len(sats) if sats else len(self._constellation)
        view = sats if sats else list(self._constellation)
        per_msg = 4
        n_msgs = max(1, (len(view) + per_msg - 1) // per_msg)
        for i in range(n_msgs):
            chunk = view[i * per_msg : (i + 1) * per_msg]
            sat_tuples = [(s.prn, s.elev, s.azim, s.snr) for s in chunk]
            self._tx_buf.extend(nmea_gen.gsv(
                total_msgs=n_msgs, msg_num=i + 1,
                sats_in_view=total, satellites=sat_tuples,
            ))

    # ── UBX periodic output ──────────────────────────────────────

    def _emit_ubx_periodic(self) -> None:
        for (cls, msg_id), rate in self._ubx_periodic.items():
            if rate > 0 and self._fix_epoch % rate == 0:
                resp = self._build_nav_response(cls, msg_id)
                if resp is not None:
                    self._tx_buf.extend(ubx_frame(cls, msg_id, resp))

    # ── UBX RX parsing ───────────────────────────────────────────

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

    # ── CFG handlers ─────────────────────────────────────────────

    def _handle_cfg(self, msg_id: int, payload: bytes) -> None:
        if msg_id == CFG_PRT:
            self._handle_cfg_prt(payload)
        elif msg_id == CFG_MSG:
            self._handle_cfg_msg(payload)
        elif msg_id == CFG_RATE:
            self._handle_cfg_rate(payload)
        elif msg_id == CFG_NAV5:
            self._handle_cfg_nav5(payload)
        elif msg_id == CFG_RST:
            self.reset()
            self._send_ack(UBX_CFG, msg_id)
        elif msg_id == CFG_CFG:
            self._send_ack(UBX_CFG, msg_id)
        elif msg_id == CFG_GNSS:
            self._handle_cfg_gnss(payload)
        elif msg_id == CFG_SBAS:
            self._send_ack(UBX_CFG, msg_id)
        else:
            self._send_ack(UBX_CFG, msg_id)

    def _handle_cfg_prt(self, payload: bytes) -> None:
        if not payload:
            port_id = 1
            in_proto, out_proto = self._port_protocols.get(port_id, (0x07, 0x03))
            resp = bytearray(20)
            struct.pack_into("<B", resp, 0, port_id)
            struct.pack_into("<I", resp, 8, 0x000008D0)
            struct.pack_into("<H", resp, 12, in_proto)
            struct.pack_into("<H", resp, 14, out_proto)
            self._tx_buf.extend(ubx_frame(UBX_CFG, CFG_PRT, bytes(resp)))
        elif len(payload) >= 20:
            port_id = payload[0]
            in_proto = struct.unpack_from("<H", payload, 12)[0]
            out_proto = struct.unpack_from("<H", payload, 14)[0]
            self._port_protocols[port_id] = (in_proto, out_proto)
        self._send_ack(UBX_CFG, CFG_PRT)

    def _handle_cfg_msg(self, payload: bytes) -> None:
        if len(payload) >= 3:
            cls, msg_id, rate = payload[0], payload[1], payload[2]
            key = (cls, msg_id)
            nmea_name = _NMEA_MSG_KEYS.get(key)
            if nmea_name is not None:
                self._nmea_rates[nmea_name] = rate
            elif cls == UBX_NAV:
                self._ubx_periodic[key] = rate
        elif len(payload) == 2:
            cls, msg_id = payload[0], payload[1]
            key = (cls, msg_id)
            nmea_name = _NMEA_MSG_KEYS.get(key)
            if nmea_name is not None:
                rate = self._nmea_rates.get(nmea_name, 0)
                resp = bytes([cls, msg_id, rate, rate, rate, rate, rate, rate])
                self._tx_buf.extend(ubx_frame(UBX_CFG, CFG_MSG, resp))
            elif cls == UBX_NAV:
                rate = self._ubx_periodic.get(key, 0)
                resp = bytes([cls, msg_id, rate, rate, rate, rate, rate, rate])
                self._tx_buf.extend(ubx_frame(UBX_CFG, CFG_MSG, resp))
        self._send_ack(UBX_CFG, CFG_MSG)

    def _handle_cfg_rate(self, payload: bytes) -> None:
        if len(payload) >= 6:
            self._meas_rate_ms = struct.unpack_from("<H", payload, 0)[0]
            self._nav_rate = struct.unpack_from("<H", payload, 2)[0]
        elif not payload:
            resp = struct.pack("<HHH", self._meas_rate_ms, self._nav_rate, 1)
            self._tx_buf.extend(ubx_frame(UBX_CFG, CFG_RATE, resp))
        self._send_ack(UBX_CFG, CFG_RATE)

    def _handle_cfg_nav5(self, payload: bytes) -> None:
        if len(payload) >= 36:
            mask = struct.unpack_from("<H", payload, 0)[0]
            if mask & 0x01:
                self._dyn_model = payload[2]
        elif not payload:
            resp = bytearray(36)
            struct.pack_into("<H", resp, 0, 0x01)
            resp[2] = self._dyn_model
            resp[3] = 3  # fixMode = auto 2D/3D
            self._tx_buf.extend(ubx_frame(UBX_CFG, CFG_NAV5, bytes(resp)))
        self._send_ack(UBX_CFG, CFG_NAV5)

    def _handle_cfg_gnss(self, payload: bytes) -> None:
        if not payload:
            resp = bytearray(12)
            resp[0] = 0  # msgVer
            resp[1] = 0  # numTrkChHw
            resp[2] = 32  # numTrkChUse
            resp[3] = 1  # numConfigBlocks
            block = struct.pack("<BBBBI", 0, 8, 16, 0, 0x01010001)
            resp.extend(block)
            self._tx_buf.extend(ubx_frame(UBX_CFG, CFG_GNSS, bytes(resp)))
        self._send_ack(UBX_CFG, CFG_GNSS)

    # ── NAV poll handlers ────────────────────────────────────────

    def _handle_nav_poll(self, msg_id: int, payload: bytes) -> None:
        resp = self._build_nav_response(UBX_NAV, msg_id)
        if resp is not None:
            self._tx_buf.extend(ubx_frame(UBX_NAV, msg_id, resp))
        else:
            self._send_nak(UBX_NAV, msg_id)

    def _build_nav_response(self, cls: int, msg_id: int) -> bytes | None:
        if cls != UBX_NAV:
            return None
        if msg_id == NAV_PVT:
            return self._build_nav_pvt()
        if msg_id == NAV_STATUS:
            return self._build_nav_status()
        if msg_id == NAV_POSLLH:
            return self._build_nav_posllh()
        if msg_id == NAV_VELNED:
            return self._build_nav_velned()
        if msg_id == NAV_DOP:
            return self._build_nav_dop()
        if msg_id == NAV_TIMEUTC:
            return self._build_nav_timeutc()
        if msg_id == NAV_SAT:
            return self._build_nav_sat()
        if msg_id == NAV_SOL:
            return self._build_nav_sol()
        return None

    def _build_nav_pvt(self) -> bytes:
        t = self._time_seconds
        fix = self._effective_fix
        ns = self._effective_sats
        lat_s = int(self.lat * 1e7)
        lon_s = int(self.lon * 1e7)
        alt_mm = int(self.alt * 1000)
        buf = bytearray(92)
        struct.pack_into("<I", buf, 0, self._fix_epoch)
        struct.pack_into("<HBBBBB", buf, 4,
            2024, 1, 1, t // 3600, (t % 3600) // 60, t % 60)
        struct.pack_into("<B", buf, 11, 0x07)  # valid: date+time+fullyResolved
        struct.pack_into("<I", buf, 12, 100)   # tAcc ns
        struct.pack_into("<i", buf, 16, 0)     # nano
        struct.pack_into("<B", buf, 20, fix)
        flags = 0x01 if fix > 0 else 0x00
        struct.pack_into("<B", buf, 21, flags)
        struct.pack_into("<B", buf, 23, ns)
        struct.pack_into("<ii", buf, 24, lon_s, lat_s)
        struct.pack_into("<ii", buf, 32, alt_mm, alt_mm)
        struct.pack_into("<II", buf, 40, 1000, 1000)  # hAcc, vAcc mm
        speed_mms = int(self.speed_knots * 514.444)
        struct.pack_into("<i", buf, 60, speed_mms)  # gSpeed mm/s
        heading = int(self.course * 1e5)
        struct.pack_into("<i", buf, 64, heading)
        struct.pack_into("<I", buf, 68, 50000)  # sAcc mm/s
        struct.pack_into("<I", buf, 72, 500000) # headAcc 1e-5 deg
        struct.pack_into("<H", buf, 76, int(self.pdop * 100))
        return bytes(buf)

    def _build_nav_status(self) -> bytes:
        fix = self._effective_fix
        buf = bytearray(16)
        struct.pack_into("<I", buf, 0, self._fix_epoch)
        buf[4] = fix
        flags = 0x01 if fix > 0 else 0x00
        buf[5] = flags
        buf[6] = 0x00  # fixStat
        buf[7] = 0x04 if fix > 0 else 0x01  # flags2
        struct.pack_into("<I", buf, 8, self._total_ticks // 1000)  # ttff ms
        struct.pack_into("<I", buf, 12, self._total_ticks // 1000)  # msss
        return bytes(buf)

    def _build_nav_posllh(self) -> bytes:
        buf = bytearray(28)
        struct.pack_into("<I", buf, 0, self._fix_epoch)
        struct.pack_into("<ii", buf, 4, int(self.lon * 1e7), int(self.lat * 1e7))
        alt_mm = int(self.alt * 1000)
        struct.pack_into("<ii", buf, 12, alt_mm, alt_mm)
        struct.pack_into("<II", buf, 20, 1000, 1000)
        return bytes(buf)

    def _build_nav_velned(self) -> bytes:
        buf = bytearray(36)
        struct.pack_into("<I", buf, 0, self._fix_epoch)
        speed_cms = int(self.speed_knots * 51.4444)
        struct.pack_into("<iii", buf, 4, 0, 0, 0)  # velN, velE, velD
        struct.pack_into("<I", buf, 16, abs(speed_cms) * 10)  # speed mm/s
        struct.pack_into("<I", buf, 20, abs(speed_cms) * 10)  # gSpeed mm/s
        heading = int(self.course * 1e5)
        struct.pack_into("<i", buf, 24, heading)
        struct.pack_into("<II", buf, 28, 50000, 500000)
        return bytes(buf)

    def _build_nav_dop(self) -> bytes:
        buf = bytearray(18)
        struct.pack_into("<I", buf, 0, self._fix_epoch)
        struct.pack_into("<H", buf, 4, 99)  # gDOP
        struct.pack_into("<H", buf, 6, int(self.pdop * 100))
        struct.pack_into("<H", buf, 8, 99)  # tDOP
        struct.pack_into("<H", buf, 10, int(self.vdop * 100))
        struct.pack_into("<H", buf, 12, int(self.hdop * 100))
        struct.pack_into("<H", buf, 14, 99)  # nDOP
        struct.pack_into("<H", buf, 16, 99)  # eDOP
        return bytes(buf)

    def _build_nav_timeutc(self) -> bytes:
        t = self._time_seconds
        buf = bytearray(20)
        struct.pack_into("<I", buf, 0, self._fix_epoch)
        struct.pack_into("<I", buf, 4, 100)  # tAcc ns
        struct.pack_into("<i", buf, 8, 0)     # nano
        struct.pack_into("<HBBBBB", buf, 12,
            2024, 1, 1, t // 3600, (t % 3600) // 60, t % 60)
        buf[19] = 0x07 if self._effective_fix > 0 else 0x00  # valid
        return bytes(buf)

    def _build_nav_sat(self) -> bytes:
        sats = self._constellation[:self._effective_sats] if self._effective_fix > 0 else self._constellation
        hdr = bytearray(8)
        struct.pack_into("<I", hdr, 0, self._fix_epoch)
        hdr[4] = 1  # version
        hdr[5] = len(sats)
        buf = bytearray(hdr)
        for s in sats:
            entry = bytearray(12)
            entry[0] = s.gnss_id
            entry[1] = s.sv_id
            entry[2] = s.snr
            struct.pack_into("<bH", entry, 3, s.elev, s.azim)
            used = 0x08 if self._effective_fix > 0 else 0x00
            struct.pack_into("<I", entry, 8, s.flags | used)
            buf.extend(entry)
        return bytes(buf)

    def _build_nav_sol(self) -> bytes:
        fix = self._effective_fix
        buf = bytearray(52)
        struct.pack_into("<I", buf, 0, self._fix_epoch)
        struct.pack_into("<i", buf, 4, 0)  # fTOW
        struct.pack_into("<h", buf, 8, 0)  # week
        buf[10] = fix
        buf[11] = 0x0D if fix > 0 else 0x00  # flags
        struct.pack_into("<iii", buf, 12, int(self.lat * 100), int(self.lon * 100), int(self.alt * 100))
        struct.pack_into("<I", buf, 24, 1000)
        struct.pack_into("<iii", buf, 28, 0, 0, 0)
        struct.pack_into("<I", buf, 40, 100)
        struct.pack_into("<H", buf, 44, int(self.pdop * 100))
        buf[47] = self._effective_sats
        return bytes(buf)

    # ── MON handlers ─────────────────────────────────────────────

    def _handle_mon(self, msg_id: int, payload: bytes) -> None:
        if msg_id == MON_VER:
            sw = b"ROM CORE 3.01 (107888)\x00"
            sw = sw.ljust(30, b"\x00")[:30]
            hw = b"00080000\x00"
            hw = hw.ljust(10, b"\x00")[:10]
            ext1 = b"FWVER=SPG 3.01\x00".ljust(30, b"\x00")[:30]
            ext2 = b"PROTVER=18.00\x00".ljust(30, b"\x00")[:30]
            self._tx_buf.extend(ubx_frame(UBX_MON, MON_VER, sw + hw + ext1 + ext2))
        elif msg_id == MON_HW:
            buf = bytearray(60)
            struct.pack_into("<I", buf, 0, 0x00080000)  # pinSel
            struct.pack_into("<I", buf, 16, 3)  # aStatus: OK
            struct.pack_into("<I", buf, 20, 2)  # aPower: ON
            self._tx_buf.extend(ubx_frame(UBX_MON, MON_HW, bytes(buf)))
        else:
            self._send_nak(UBX_MON, msg_id)

    # ── helpers ───────────────────────────────────────────────────

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
            "fix_epoch": self._fix_epoch,
            "total_ticks": self._total_ticks,
            "lat": self.lat, "lon": self.lon, "alt": self.alt,
            "speed_knots": self.speed_knots, "course": self.course,
            "fix_type": self.fix_type, "sats": self.sats,
            "hdop": self.hdop, "vdop": self.vdop, "pdop": self.pdop,
            "dyn_model": self._dyn_model,
            "meas_rate_ms": self._meas_rate_ms,
            "nav_rate": self._nav_rate,
            "nmea_rates": dict(self._nmea_rates),
            "ubx_periodic": {f"{k[0]:02x}:{k[1]:02x}": v for k, v in self._ubx_periodic.items()},
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        self.mode = str(state.get("mode", self.mode))
        self._tx_buf = bytearray(state.get("tx_buf", b""))
        self._rx_buf = bytearray(state.get("rx_buf", b""))
        self._cycle_counter = int(state.get("cycle_counter", 0))
        self._time_seconds = int(state.get("time_seconds", 43200))
        self._fix_epoch = int(state.get("fix_epoch", 0))
        self._total_ticks = int(state.get("total_ticks", 0))
        self.lat = float(state.get("lat", self.lat))
        self.lon = float(state.get("lon", self.lon))
        self.alt = float(state.get("alt", self.alt))
        self.speed_knots = float(state.get("speed_knots", self.speed_knots))
        self.course = float(state.get("course", self.course))
        self.fix_type = int(state.get("fix_type", self.fix_type))
        self.sats = int(state.get("sats", self.sats))
        self.hdop = float(state.get("hdop", self.hdop))
        self.vdop = float(state.get("vdop", self.vdop))
        self.pdop = float(state.get("pdop", self.pdop))
        self._dyn_model = int(state.get("dyn_model", self._dyn_model))
        self._meas_rate_ms = int(state.get("meas_rate_ms", self._meas_rate_ms))
        self._nav_rate = int(state.get("nav_rate", self._nav_rate))
        nr = state.get("nmea_rates")
        if isinstance(nr, dict):
            self._nmea_rates = {str(k): int(v) for k, v in nr.items()}
        ubx_p = state.get("ubx_periodic")
        if isinstance(ubx_p, dict):
            self._ubx_periodic = {}
            for k, v in ubx_p.items():
                parts = str(k).split(":")
                if len(parts) == 2:
                    self._ubx_periodic[(int(parts[0], 16), int(parts[1], 16))] = int(v)
