"""NMEA-0183 sentence generation."""
from __future__ import annotations


def nmea_checksum(body: str) -> str:
    cs = 0
    for ch in body:
        cs ^= ord(ch)
    return f"{cs:02X}"


def nmea_sentence(body: str) -> bytes:
    return f"${body}*{nmea_checksum(body)}\r\n".encode("ascii")


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
    lat_deg = int(abs(lat))
    lat_min = (abs(lat) - lat_deg) * 60
    lat_dir = "N" if lat >= 0 else "S"
    lon_deg = int(abs(lon))
    lon_min = (abs(lon) - lon_deg) * 60
    lon_dir = "E" if lon >= 0 else "W"
    body = (
        f"GPGGA,{time_utc},"
        f"{lat_deg:02d}{lat_min:07.4f},{lat_dir},"
        f"{lon_deg:03d}{lon_min:07.4f},{lon_dir},"
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
    lat_deg = int(abs(lat))
    lat_min = (abs(lat) - lat_deg) * 60
    lat_dir = "N" if lat >= 0 else "S"
    lon_deg = int(abs(lon))
    lon_min = (abs(lon) - lon_deg) * 60
    lon_dir = "E" if lon >= 0 else "W"
    body = (
        f"GPRMC,{time_utc},{status},"
        f"{lat_deg:02d}{lat_min:07.4f},{lat_dir},"
        f"{lon_deg:03d}{lon_min:07.4f},{lon_dir},"
        f"{speed_knots:.1f},{course:.1f},{date},,,A"
    )
    return nmea_sentence(body)
