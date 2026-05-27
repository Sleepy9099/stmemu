"""NMEA-0183 sentence generation."""
from __future__ import annotations


def nmea_checksum(body: str) -> str:
    cs = 0
    for ch in body:
        cs ^= ord(ch)
    return f"{cs:02X}"


def nmea_sentence(body: str) -> bytes:
    return f"${body}*{nmea_checksum(body)}\r\n".encode("ascii")


def _fmt_lat(lat: float) -> tuple[str, str]:
    d = int(abs(lat))
    m = (abs(lat) - d) * 60
    return f"{d:02d}{m:07.4f}", "N" if lat >= 0 else "S"


def _fmt_lon(lon: float) -> tuple[str, str]:
    d = int(abs(lon))
    m = (abs(lon) - d) * 60
    return f"{d:03d}{m:07.4f}", "E" if lon >= 0 else "W"


def gga(
    *,
    time_utc: str = "120000.00",
    lat: float = 34.7304,
    lon: float = -86.5861,
    fix: int = 1,
    sats: int = 8,
    hdop: float = 1.2,
    alt: float = 190.0,
) -> bytes:
    la, la_d = _fmt_lat(lat)
    lo, lo_d = _fmt_lon(lon)
    body = (
        f"GPGGA,{time_utc},"
        f"{la},{la_d},{lo},{lo_d},"
        f"{fix},{sats:02d},{hdop:.1f},{alt:.1f},M,0.0,M,,"
    )
    return nmea_sentence(body)


def rmc(
    *,
    time_utc: str = "120000.00",
    date: str = "010124",
    lat: float = 34.7304,
    lon: float = -86.5861,
    speed_knots: float = 0.0,
    course: float = 0.0,
    status: str = "A",
) -> bytes:
    la, la_d = _fmt_lat(lat)
    lo, lo_d = _fmt_lon(lon)
    body = (
        f"GPRMC,{time_utc},{status},"
        f"{la},{la_d},{lo},{lo_d},"
        f"{speed_knots:.1f},{course:.1f},{date},,,A"
    )
    return nmea_sentence(body)


def gsa(
    *,
    mode_auto: str = "A",
    fix_3d: int = 3,
    prns: list[int] | None = None,
    pdop: float = 2.0,
    hdop: float = 1.2,
    vdop: float = 1.6,
) -> bytes:
    prn_fields = []
    for i in range(12):
        if prns and i < len(prns):
            prn_fields.append(f"{prns[i]:02d}")
        else:
            prn_fields.append("")
    body = (
        f"GPGSA,{mode_auto},{fix_3d},"
        + ",".join(prn_fields)
        + f",{pdop:.1f},{hdop:.1f},{vdop:.1f}"
    )
    return nmea_sentence(body)


def gsv(
    *,
    total_msgs: int = 1,
    msg_num: int = 1,
    sats_in_view: int = 0,
    satellites: list[tuple[int, int, int, int]] | None = None,
) -> bytes:
    body = f"GPGSV,{total_msgs},{msg_num},{sats_in_view:02d}"
    if satellites:
        for prn, elev, azim, snr in satellites:
            body += f",{prn:02d},{elev:02d},{azim:03d},{snr:02d}"
    return nmea_sentence(body)


def vtg(
    *,
    course_true: float = 0.0,
    course_mag: float = 0.0,
    speed_knots: float = 0.0,
    speed_kmh: float = 0.0,
    mode: str = "A",
) -> bytes:
    body = (
        f"GPVTG,{course_true:.1f},T,{course_mag:.1f},M,"
        f"{speed_knots:.1f},N,{speed_kmh:.1f},K,{mode}"
    )
    return nmea_sentence(body)


def gll(
    *,
    time_utc: str = "120000.00",
    lat: float = 34.7304,
    lon: float = -86.5861,
    status: str = "A",
    mode: str = "A",
) -> bytes:
    la, la_d = _fmt_lat(lat)
    lo, lo_d = _fmt_lon(lon)
    body = f"GPGLL,{la},{la_d},{lo},{lo_d},{time_utc},{status},{mode}"
    return nmea_sentence(body)
