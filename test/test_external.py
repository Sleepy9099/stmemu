"""Tests for external device layer: SerialLine, NMEA, u-blox GPS."""
from __future__ import annotations

import struct
import sys
import types
import unittest

# ── Stub external dependencies for shell command tests ───────────

if "capstone" not in sys.modules:
    _cs = types.ModuleType("capstone")
    class _Cs:
        def __init__(self, *a, **k): self.detail = False
        def disasm(self, code, addr, count=0): return []
    _cs.Cs = _Cs
    _cs.CS_ARCH_ARM = 0
    _cs.CS_MODE_THUMB = 0
    sys.modules["capstone"] = _cs

if "unicorn" not in sys.modules:
    _uc = types.ModuleType("unicorn")
    _uc_const = types.ModuleType("unicorn.unicorn_const")
    _uc_const.UC_HOOK_CODE = 0
    _uc.unicorn_const = _uc_const
    sys.modules["unicorn"] = _uc
    sys.modules["unicorn.unicorn_const"] = _uc_const

if "stmemu.core.emulator" not in sys.modules:
    _emu = types.ModuleType("stmemu.core.emulator")
    class _PcRegWrite:
        pass
    class _Emulator:
        pass
    _emu.PcRegWrite = _PcRegWrite
    _emu.Emulator = _Emulator
    sys.modules["stmemu.core.emulator"] = _emu

from stmemu.external.device import ExternalDevice
from stmemu.external.serial_line import SerialLine
from stmemu.external import nmea
from stmemu.external.ublox import (
    UbloxGpsDevice,
    ubx_frame,
    _ubx_validate,
    UBX_CFG, UBX_NAV, UBX_ACK, UBX_MON,
    CFG_RATE, CFG_PRT, CFG_RST, CFG_MSG, CFG_NAV5, CFG_GNSS, CFG_CFG,
    NAV_PVT, NAV_STATUS, NAV_POSLLH, NAV_DOP, NAV_VELNED, NAV_TIMEUTC,
    NAV_SAT, NAV_SOL,
    MON_VER, MON_HW,
    ACK_ACK, ACK_NAK,
    DYN_PEDESTRIAN,
)


class _FakeUart:
    def __init__(self):
        self._tx = bytearray()
        self._rx = bytearray()

    def drain_tx_bytes(self):
        data = bytes(self._tx)
        self._tx.clear()
        return data

    def inject_rx_bytes(self, data):
        self._rx.extend(data)

    def peek_tx_bytes(self):
        return bytes(self._tx)

    def mcu_write(self, data: bytes):
        self._tx.extend(data)


class _EchoDevice(ExternalDevice):
    name = "echo"

    def __init__(self):
        self._buf = bytearray()

    def on_rx_from_mcu(self, data: bytes):
        self._buf.extend(data)

    def read_tx_to_mcu(self, max_bytes=4096):
        out = bytes(self._buf[:max_bytes])
        del self._buf[:max_bytes]
        return out

    def reset(self):
        self._buf.clear()

    def snapshot_state(self):
        return {"buf": bytes(self._buf)}

    def restore_state(self, state):
        if isinstance(state, dict):
            self._buf = bytearray(state.get("buf", b""))


# ── NMEA Tests ────────────────────────────────────────────────────


class NmeaTests(unittest.TestCase):
    def test_checksum(self):
        cs = nmea.nmea_checksum("GPGGA,120000.00,3443.8240,N,08635.1660,W,1,08,1.2,190.0,M,0.0,M,,")
        self.assertEqual(len(cs), 2)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in cs))

    def test_sentence_format(self):
        s = nmea.nmea_sentence("TEST,hello")
        self.assertTrue(s.startswith(b"$"))
        self.assertTrue(s.endswith(b"\r\n"))
        self.assertIn(b"*", s)

    def test_gga_produces_valid_sentence(self):
        s = nmea.gga(lat=34.7304, lon=-86.5861)
        self.assertTrue(s.startswith(b"$GPGGA,"))
        self.assertTrue(s.endswith(b"\r\n"))

    def test_rmc_produces_valid_sentence(self):
        s = nmea.rmc(lat=34.7304, lon=-86.5861)
        self.assertTrue(s.startswith(b"$GPRMC,"))

    def test_gga_negative_coords(self):
        s = nmea.gga(lat=-33.8688, lon=151.2093)
        text = s.decode("ascii")
        self.assertIn(",S,", text)
        self.assertIn(",E,", text)

    def test_gsa_produces_valid_sentence(self):
        s = nmea.gsa(prns=[2, 5, 10, 12], pdop=2.0, hdop=1.2, vdop=1.6)
        self.assertTrue(s.startswith(b"$GPGSA,"))
        text = s.decode("ascii")
        self.assertIn(",02,", text)
        self.assertIn(",2.0,1.2,1.6*", text)

    def test_gsv_produces_valid_sentence(self):
        s = nmea.gsv(
            total_msgs=1, msg_num=1, sats_in_view=2,
            satellites=[(2, 45, 30, 35), (5, 60, 120, 40)],
        )
        self.assertTrue(s.startswith(b"$GPGSV,"))

    def test_vtg_produces_valid_sentence(self):
        s = nmea.vtg(course_true=90.0, speed_knots=5.0, speed_kmh=9.3)
        self.assertTrue(s.startswith(b"$GPVTG,"))
        self.assertIn(b",N,", s)

    def test_gll_produces_valid_sentence(self):
        s = nmea.gll(lat=34.7304, lon=-86.5861)
        self.assertTrue(s.startswith(b"$GPGLL,"))


# ── SerialLine Tests ──────────────────────────────────────────────


class SerialLineTests(unittest.TestCase):
    def test_mcu_tx_reaches_device(self):
        uart = _FakeUart()
        dev = _EchoDevice()
        line = SerialLine("s0", uart=uart, device=dev)
        uart.mcu_write(b"hello")
        line.tick(1)
        self.assertEqual(dev._buf, bytearray())
        data = uart._rx
        self.assertEqual(data, bytearray(b"hello"))

    def test_device_tx_reaches_mcu(self):
        uart = _FakeUart()
        dev = _EchoDevice()
        line = SerialLine("s0", uart=uart, device=dev)
        dev._buf.extend(b"world")
        line.tick(1)
        self.assertEqual(bytes(uart._rx), b"world")

    def test_bidirectional_echo(self):
        uart = _FakeUart()
        dev = _EchoDevice()
        line = SerialLine("s0", uart=uart, device=dev)
        uart.mcu_write(b"\x01\x02\x03")
        line.tick(1)
        self.assertEqual(bytes(uart._rx), b"\x01\x02\x03")

    def test_no_device_no_crash(self):
        uart = _FakeUart()
        line = SerialLine("s0", uart=uart)
        uart.mcu_write(b"data")
        line.tick(1)

    def test_no_uart_no_crash(self):
        dev = _EchoDevice()
        line = SerialLine("s0", device=dev)
        line.tick(1)

    def test_attach_after_creation(self):
        line = SerialLine("s0")
        uart = _FakeUart()
        dev = _EchoDevice()
        line.attach_uart(uart)
        line.attach_device(dev)
        uart.mcu_write(b"hi")
        line.tick(1)
        self.assertEqual(bytes(uart._rx), b"hi")

    def test_reset_resets_device(self):
        dev = _EchoDevice()
        dev._buf.extend(b"stale")
        line = SerialLine("s0", device=dev)
        line.reset()
        self.assertEqual(dev._buf, bytearray())

    def test_snapshot_restore(self):
        dev = _EchoDevice()
        dev._buf.extend(b"\xAA\xBB")
        line = SerialLine("s0", device=dev)
        state = line.snapshot_state()
        dev.reset()
        self.assertEqual(dev._buf, bytearray())
        line.restore_state(state)
        self.assertEqual(dev._buf, bytearray(b"\xAA\xBB"))


# ── UBX protocol Tests ───────────────────────────────────────────


class UbxProtocolTests(unittest.TestCase):
    def test_ubx_frame_roundtrip(self):
        frame = ubx_frame(UBX_CFG, CFG_RATE, b"\xE8\x03\x01\x00\x01\x00")
        parsed = _ubx_validate(frame)
        self.assertIsNotNone(parsed)
        cls, msg_id, payload = parsed
        self.assertEqual(cls, UBX_CFG)
        self.assertEqual(msg_id, CFG_RATE)
        self.assertEqual(payload, b"\xE8\x03\x01\x00\x01\x00")

    def test_ubx_frame_empty_payload(self):
        frame = ubx_frame(UBX_NAV, NAV_PVT)
        parsed = _ubx_validate(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[2], b"")

    def test_ubx_validate_bad_checksum(self):
        frame = bytearray(ubx_frame(UBX_CFG, CFG_RATE, b"\x00\x00"))
        frame[-1] ^= 0xFF
        self.assertIsNone(_ubx_validate(bytes(frame)))

    def test_ubx_validate_too_short(self):
        self.assertIsNone(_ubx_validate(b"\xB5\x62\x06"))


# ── u-blox GPS device Tests ──────────────────────────────────────


class UbloxDeviceTests(unittest.TestCase):
    def test_nmea_emission_on_tick(self):
        dev = UbloxGpsDevice(mode="nmea", rate_cycles=100)
        dev.tick(100)
        data = dev.read_tx_to_mcu()
        self.assertIn(b"$GPGGA,", data)
        self.assertIn(b"$GPRMC,", data)

    def test_no_emission_before_rate(self):
        dev = UbloxGpsDevice(mode="nmea", rate_cycles=1000)
        dev.tick(500)
        data = dev.read_tx_to_mcu()
        self.assertEqual(data, b"")

    def test_ubx_ack_on_cfg_rate(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(UBX_CFG, CFG_RATE, b"\xE8\x03\x01\x00\x01\x00")
        dev.on_rx_from_mcu(cmd)
        resp = dev.read_tx_to_mcu()
        parsed = _ubx_validate(resp)
        self.assertIsNotNone(parsed)
        cls, msg_id, payload = parsed
        self.assertEqual(cls, UBX_ACK)
        self.assertEqual(msg_id, ACK_ACK)
        self.assertEqual(payload, bytes([UBX_CFG, CFG_RATE]))

    def test_ubx_nav_pvt_poll(self):
        dev = UbloxGpsDevice(mode="ubx", lat=51.5074, lon=-0.1278)
        cmd = ubx_frame(UBX_NAV, NAV_PVT)
        dev.on_rx_from_mcu(cmd)
        resp = dev.read_tx_to_mcu()
        parsed = _ubx_validate(resp)
        self.assertIsNotNone(parsed)
        cls, msg_id, payload = parsed
        self.assertEqual(cls, UBX_NAV)
        self.assertEqual(msg_id, NAV_PVT)
        self.assertEqual(len(payload), 92)

    def test_ubx_nav_status_poll(self):
        dev = UbloxGpsDevice(mode="ubx", fix_type=3)
        cmd = ubx_frame(UBX_NAV, NAV_STATUS)
        dev.on_rx_from_mcu(cmd)
        resp = dev.read_tx_to_mcu()
        parsed = _ubx_validate(resp)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], UBX_NAV)
        self.assertEqual(parsed[1], NAV_STATUS)
        self.assertEqual(parsed[2][4], 3)

    def test_ubx_mon_ver(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(UBX_MON, MON_VER)
        dev.on_rx_from_mcu(cmd)
        resp = dev.read_tx_to_mcu()
        parsed = _ubx_validate(resp)
        self.assertIsNotNone(parsed)
        self.assertIn(b"ROM CORE", parsed[2])

    def test_ubx_nak_on_unknown(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(0xFF, 0xFF)
        dev.on_rx_from_mcu(cmd)
        resp = dev.read_tx_to_mcu()
        parsed = _ubx_validate(resp)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], UBX_ACK)
        self.assertEqual(parsed[1], ACK_NAK)

    def test_ubx_cfg_rst_resets_device(self):
        dev = UbloxGpsDevice(mode="ubx")
        dev._time_seconds = 99999
        cmd = ubx_frame(UBX_CFG, CFG_RST, b"\x00\x00\x00\x00")
        dev.on_rx_from_mcu(cmd)
        self.assertEqual(dev._time_seconds, 43200)

    def test_both_mode_nmea_and_ubx(self):
        dev = UbloxGpsDevice(mode="both", rate_cycles=100)
        dev.tick(100)
        data = dev.read_tx_to_mcu()
        self.assertIn(b"$GPGGA,", data)

        cmd = ubx_frame(UBX_CFG, CFG_MSG, b"\x01\x07\x01")
        dev.on_rx_from_mcu(cmd)
        resp = dev.read_tx_to_mcu()
        parsed = _ubx_validate(resp)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], UBX_ACK)

    def test_snapshot_restore(self):
        dev = UbloxGpsDevice(mode="ubx", lat=40.0, lon=-74.0)
        dev._time_seconds = 50000
        dev._tx_buf.extend(b"pending")
        state = dev.snapshot_state()
        dev.reset()
        self.assertEqual(dev._time_seconds, 43200)
        dev.restore_state(state)
        self.assertEqual(dev._time_seconds, 50000)
        self.assertEqual(dev.lat, 40.0)
        data = dev.read_tx_to_mcu()
        self.assertEqual(data, b"pending")

    def test_partial_ubx_frame_buffered(self):
        dev = UbloxGpsDevice(mode="ubx")
        full = ubx_frame(UBX_CFG, CFG_MSG, b"\x01\x07\x01")
        dev.on_rx_from_mcu(full[:4])
        self.assertEqual(dev.read_tx_to_mcu(), b"")
        dev.on_rx_from_mcu(full[4:])
        resp = dev.read_tx_to_mcu()
        parsed = _ubx_validate(resp)
        self.assertIsNotNone(parsed)

    def test_nmea_mode_ignores_ubx(self):
        dev = UbloxGpsDevice(mode="nmea")
        cmd = ubx_frame(UBX_CFG, CFG_RATE, b"\xE8\x03\x01\x00\x01\x00")
        dev.on_rx_from_mcu(cmd)
        self.assertEqual(dev.read_tx_to_mcu(), b"")

    def test_nmea_emits_gsa_gsv_vtg(self):
        dev = UbloxGpsDevice(mode="nmea", rate_cycles=100)
        dev.tick(100)
        data = dev.read_tx_to_mcu()
        self.assertIn(b"$GPGSA,", data)
        self.assertIn(b"$GPGSV,", data)
        self.assertIn(b"$GPVTG,", data)

    def test_cfg_msg_disables_nmea_sentence(self):
        dev = UbloxGpsDevice(mode="both", rate_cycles=100)
        cmd = ubx_frame(UBX_CFG, CFG_MSG, bytes([0xF0, 0x05, 0x00]))
        dev.on_rx_from_mcu(cmd)
        dev.read_tx_to_mcu()
        dev.tick(100)
        data = dev.read_tx_to_mcu()
        self.assertNotIn(b"$GPVTG,", data)
        self.assertIn(b"$GPGGA,", data)

    def test_cfg_msg_poll_returns_rate(self):
        dev = UbloxGpsDevice(mode="ubx")
        poll = ubx_frame(UBX_CFG, CFG_MSG, bytes([0xF0, 0x00]))
        dev.on_rx_from_mcu(poll)
        data = dev.read_tx_to_mcu()
        frames = _parse_all_ubx(data)
        cfg_resp = [f for f in frames if f[0] == UBX_CFG and f[1] == CFG_MSG]
        self.assertEqual(len(cfg_resp), 1)
        self.assertEqual(cfg_resp[0][2][0], 0xF0)
        self.assertEqual(cfg_resp[0][2][1], 0x00)

    def test_cfg_rate_sets_measurement_rate(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(UBX_CFG, CFG_RATE, struct.pack("<HHH", 500, 2, 1))
        dev.on_rx_from_mcu(cmd)
        data = dev.read_tx_to_mcu()
        _expect_ack(self, data, UBX_CFG, CFG_RATE)
        self.assertEqual(dev._meas_rate_ms, 500)
        self.assertEqual(dev._nav_rate, 2)

    def test_cfg_rate_poll(self):
        dev = UbloxGpsDevice(mode="ubx")
        dev._meas_rate_ms = 200
        poll = ubx_frame(UBX_CFG, CFG_RATE)
        dev.on_rx_from_mcu(poll)
        data = dev.read_tx_to_mcu()
        frames = _parse_all_ubx(data)
        rate_resp = [f for f in frames if f[0] == UBX_CFG and f[1] == CFG_RATE]
        self.assertEqual(len(rate_resp), 1)
        meas = struct.unpack_from("<H", rate_resp[0][2], 0)[0]
        self.assertEqual(meas, 200)

    def test_cfg_nav5_sets_dyn_model(self):
        dev = UbloxGpsDevice(mode="ubx")
        payload = bytearray(36)
        struct.pack_into("<H", payload, 0, 0x01)
        payload[2] = DYN_PEDESTRIAN
        cmd = ubx_frame(UBX_CFG, CFG_NAV5, bytes(payload))
        dev.on_rx_from_mcu(cmd)
        _expect_ack(self, dev.read_tx_to_mcu(), UBX_CFG, CFG_NAV5)
        self.assertEqual(dev._dyn_model, DYN_PEDESTRIAN)

    def test_cfg_nav5_poll(self):
        dev = UbloxGpsDevice(mode="ubx")
        poll = ubx_frame(UBX_CFG, CFG_NAV5)
        dev.on_rx_from_mcu(poll)
        data = dev.read_tx_to_mcu()
        frames = _parse_all_ubx(data)
        nav5 = [f for f in frames if f[0] == UBX_CFG and f[1] == CFG_NAV5]
        self.assertEqual(len(nav5), 1)
        self.assertEqual(len(nav5[0][2]), 36)

    def test_cfg_gnss_poll(self):
        dev = UbloxGpsDevice(mode="ubx")
        poll = ubx_frame(UBX_CFG, CFG_GNSS)
        dev.on_rx_from_mcu(poll)
        data = dev.read_tx_to_mcu()
        frames = _parse_all_ubx(data)
        gnss = [f for f in frames if f[0] == UBX_CFG and f[1] == CFG_GNSS]
        self.assertEqual(len(gnss), 1)

    def test_cfg_cfg_acks(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(UBX_CFG, CFG_CFG, b"\x00" * 12)
        dev.on_rx_from_mcu(cmd)
        _expect_ack(self, dev.read_tx_to_mcu(), UBX_CFG, CFG_CFG)

    def test_cfg_prt_poll_and_set(self):
        dev = UbloxGpsDevice(mode="ubx")
        poll = ubx_frame(UBX_CFG, CFG_PRT)
        dev.on_rx_from_mcu(poll)
        data = dev.read_tx_to_mcu()
        frames = _parse_all_ubx(data)
        prt = [f for f in frames if f[0] == UBX_CFG and f[1] == CFG_PRT]
        self.assertEqual(len(prt), 1)
        self.assertEqual(len(prt[0][2]), 20)

    def test_nav_posllh(self):
        dev = UbloxGpsDevice(mode="ubx", lat=51.5074, lon=-0.1278)
        cmd = ubx_frame(UBX_NAV, NAV_POSLLH)
        dev.on_rx_from_mcu(cmd)
        data = dev.read_tx_to_mcu()
        parsed = _ubx_validate(data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], UBX_NAV)
        self.assertEqual(len(parsed[2]), 28)

    def test_nav_dop(self):
        dev = UbloxGpsDevice(mode="ubx", hdop=1.5, vdop=2.0, pdop=2.5)
        cmd = ubx_frame(UBX_NAV, NAV_DOP)
        dev.on_rx_from_mcu(cmd)
        parsed = _ubx_validate(dev.read_tx_to_mcu())
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed[2]), 18)
        hdop = struct.unpack_from("<H", parsed[2], 12)[0]
        self.assertEqual(hdop, 150)

    def test_nav_velned(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(UBX_NAV, NAV_VELNED)
        dev.on_rx_from_mcu(cmd)
        parsed = _ubx_validate(dev.read_tx_to_mcu())
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed[2]), 36)

    def test_nav_timeutc(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(UBX_NAV, NAV_TIMEUTC)
        dev.on_rx_from_mcu(cmd)
        parsed = _ubx_validate(dev.read_tx_to_mcu())
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed[2]), 20)

    def test_nav_sat(self):
        dev = UbloxGpsDevice(mode="ubx", fix_type=3)
        cmd = ubx_frame(UBX_NAV, NAV_SAT)
        dev.on_rx_from_mcu(cmd)
        parsed = _ubx_validate(dev.read_tx_to_mcu())
        self.assertIsNotNone(parsed)
        self.assertGreater(len(parsed[2]), 8)
        num_svs = parsed[2][5]
        self.assertGreater(num_svs, 0)

    def test_nav_sol(self):
        dev = UbloxGpsDevice(mode="ubx", fix_type=3)
        cmd = ubx_frame(UBX_NAV, NAV_SOL)
        dev.on_rx_from_mcu(cmd)
        parsed = _ubx_validate(dev.read_tx_to_mcu())
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed[2]), 52)
        self.assertEqual(parsed[2][10], 3)

    def test_mon_hw(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(UBX_MON, MON_HW)
        dev.on_rx_from_mcu(cmd)
        parsed = _ubx_validate(dev.read_tx_to_mcu())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], UBX_MON)
        self.assertEqual(parsed[1], MON_HW)

    def test_mon_ver_realistic(self):
        dev = UbloxGpsDevice(mode="ubx")
        cmd = ubx_frame(UBX_MON, MON_VER)
        dev.on_rx_from_mcu(cmd)
        parsed = _ubx_validate(dev.read_tx_to_mcu())
        self.assertIsNotNone(parsed)
        self.assertIn(b"ROM CORE", parsed[2])
        self.assertIn(b"PROTVER", parsed[2])

    def test_ttff_simulation(self):
        dev = UbloxGpsDevice(mode="nmea", rate_cycles=100, ttff_ticks=500, fix_type=3)
        dev.tick(100)
        data = dev.read_tx_to_mcu()
        text = data.decode("ascii", errors="replace")
        self.assertIn(",0,00,", text)
        for _ in range(5):
            dev.tick(100)
        data = dev.read_tx_to_mcu()
        text = data.decode("ascii", errors="replace")
        self.assertIn(",1,08,", text)

    def test_ubx_periodic_output(self):
        dev = UbloxGpsDevice(mode="ubx", rate_cycles=100)
        cmd = ubx_frame(UBX_CFG, CFG_MSG, bytes([UBX_NAV, NAV_PVT, 1]))
        dev.on_rx_from_mcu(cmd)
        dev.read_tx_to_mcu()
        dev.tick(100)
        data = dev.read_tx_to_mcu()
        parsed = _ubx_validate(data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], UBX_NAV)
        self.assertEqual(parsed[1], NAV_PVT)

    def test_snapshot_restore_config(self):
        dev = UbloxGpsDevice(mode="ubx")
        dev._dyn_model = DYN_PEDESTRIAN
        dev._meas_rate_ms = 200
        dev._nmea_rates["GLL"] = 1
        dev._ubx_periodic[(UBX_NAV, NAV_PVT)] = 2
        state = dev.snapshot_state()
        dev.reset()
        self.assertEqual(dev._dyn_model, 4)
        dev.restore_state(state)
        self.assertEqual(dev._dyn_model, DYN_PEDESTRIAN)
        self.assertEqual(dev._meas_rate_ms, 200)
        self.assertEqual(dev._nmea_rates["GLL"], 1)
        self.assertEqual(dev._ubx_periodic.get((UBX_NAV, NAV_PVT)), 2)


def _parse_all_ubx(data: bytes) -> list[tuple[int, int, bytes]]:
    results = []
    while len(data) >= 8:
        idx = data.find(b"\xB5\x62")
        if idx < 0:
            break
        data = data[idx:]
        parsed = _ubx_validate(data)
        if parsed is None:
            data = data[1:]
            continue
        results.append(parsed)
        frame_len = 6 + len(parsed[2]) + 2
        data = data[frame_len:]
    return results


def _expect_ack(tc, data: bytes, cls: int, msg_id: int) -> None:
    frames = _parse_all_ubx(data)
    acks = [f for f in frames if f[0] == UBX_ACK and f[1] == ACK_ACK]
    tc.assertTrue(
        any(a[2] == bytes([cls, msg_id]) for a in acks),
        f"expected ACK for {cls:02X}:{msg_id:02X}, got {acks}",
    )


# ── Integration: SerialLine + u-blox ─────────────────────────────


class UbloxSerialIntegrationTests(unittest.TestCase):
    def test_nmea_through_serial_line(self):
        uart = _FakeUart()
        gps = UbloxGpsDevice(mode="nmea", rate_cycles=50)
        line = SerialLine("gps0", uart=uart, device=gps)
        line.tick(50)
        self.assertIn(b"$GPGGA,", bytes(uart._rx))

    def test_ubx_command_through_serial_line(self):
        uart = _FakeUart()
        gps = UbloxGpsDevice(mode="ubx")
        line = SerialLine("gps0", uart=uart, device=gps)
        uart.mcu_write(ubx_frame(UBX_NAV, NAV_PVT))
        line.tick(1)
        parsed = _ubx_validate(bytes(uart._rx))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], UBX_NAV)
        self.assertEqual(parsed[1], NAV_PVT)


# ── Bus serial line integration ──────────────────────────────────


class _FakeBusWithLines:
    """Minimal bus fake that supports serial lines and model lookup."""
    def __init__(self):
        self._serial_lines: dict[str, object] = {}
        self._models: dict[str, object] = {}
        self._mounted: list[object] = []

    def attach_serial_line(self, line):
        self._serial_lines[line.name] = line

    def detach_serial_line(self, name):
        return self._serial_lines.pop(name, None) is not None

    def serial_lines(self):
        return dict(self._serial_lines)

    def model_for_name(self, name):
        return self._models.get(name.upper())

    def mounted_ranges(self):
        return tuple(self._mounted)

    def tick(self, cycles):
        for line in self._serial_lines.values():
            line.tick(cycles)

    def snapshot_models_state(self):
        states = {}
        for name, line in self._serial_lines.items():
            state = line.snapshot_state()
            if state is not None:
                states[f"__line__{name}"] = state
        return states

    def restore_models_state(self, states):
        for name, line in self._serial_lines.items():
            key = f"__line__{name}"
            if key in states:
                line.restore_state(states[key])


class BusSerialLineTests(unittest.TestCase):
    def test_bus_tick_ticks_serial_lines(self):
        bus = _FakeBusWithLines()
        uart = _FakeUart()
        gps = UbloxGpsDevice(mode="nmea", rate_cycles=50)
        line = SerialLine("gps0", uart=uart, device=gps)
        bus.attach_serial_line(line)
        bus.tick(50)
        self.assertIn(b"$GPGGA,", bytes(uart._rx))

    def test_bus_snapshot_restore_serial_lines(self):
        bus = _FakeBusWithLines()
        uart = _FakeUart()
        gps = UbloxGpsDevice(mode="nmea", rate_cycles=1000)
        gps._time_seconds = 50000
        line = SerialLine("gps0", uart=uart, device=gps)
        bus.attach_serial_line(line)

        states = bus.snapshot_models_state()
        gps._time_seconds = 99999
        bus.restore_models_state(states)
        self.assertEqual(gps._time_seconds, 50000)

    def test_bus_detach_serial_line(self):
        bus = _FakeBusWithLines()
        uart = _FakeUart()
        gps = UbloxGpsDevice(mode="nmea", rate_cycles=50)
        line = SerialLine("gps0", uart=uart, device=gps)
        bus.attach_serial_line(line)
        self.assertEqual(len(bus.serial_lines()), 1)
        self.assertTrue(bus.detach_serial_line("gps0"))
        self.assertEqual(len(bus.serial_lines()), 0)
        self.assertFalse(bus.detach_serial_line("gps0"))


# ── Shell device command tests ───────────────────────────────────


class _FakeMountedUart:
    def __init__(self, name, model):
        self.name = name
        self.model = model
        self.base = 0x40004400
        self.end = 0x40004800


class _ShellBus:
    """Minimal bus for shell command tests."""
    def __init__(self, models=None):
        self._models = {k.upper(): v for k, v in (models or {}).items()}
        self._serial_lines: dict[str, object] = {}
        self._mounted = [
            _FakeMountedUart(n, m) for n, m in self._models.items()
        ]

    def model_for_name(self, name):
        return self._models.get(name.upper())

    def mounted_ranges(self):
        return tuple(self._mounted)

    def serial_lines(self):
        return dict(self._serial_lines)

    def attach_serial_line(self, line):
        self._serial_lines[line.name] = line

    def detach_serial_line(self, name):
        return self._serial_lines.pop(name, None) is not None

    def snapshot_models_state(self):
        return {}

    def restore_models_state(self, states):
        pass

    def read(self, addr, size):
        return 0

    def write(self, addr, size, value):
        pass


class DeviceShellCommandTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        from stmemu.core.symbols import SymbolTable
        from stmemu.core.semihosting import SemihostingHandler

        self.uart = _FakeUart()
        self.bus = _ShellBus({"USART1": self.uart})

        class _FakeEmu:
            symbols = SymbolTable()
            semihosting = SemihostingHandler()
            coverage_enabled = False
            _coverage = set()
            _coverage_hits = {}
            flash_base = 0x08000000
            flash_end = 0x08010000
            pc = 0x08000100
        self.emu = _FakeEmu()
        self.cmds = Commands(emu=self.emu, bus=self.bus)

    def test_device_list_empty(self):
        out = self.cmds.cmd_device([])
        self.assertIn("usage:", out)

    def test_device_list_no_devices(self):
        out = self.cmds.cmd_device(["list"])
        self.assertIn("no external devices", out)

    def test_device_attach_ublox(self):
        out = self.cmds.cmd_device(["attach", "uart", "USART1", "ublox"])
        self.assertIn("attached", out)
        self.assertIn("USART1", out)
        self.assertEqual(len(self.bus.serial_lines()), 1)

    def test_device_attach_with_options(self):
        out = self.cmds.cmd_device([
            "attach", "uart", "USART1", "ublox",
            "mode=ubx", "lat=51.5", "name=gps0",
        ])
        self.assertIn("attached", out)
        self.assertIn("gps0", out)
        lines = self.bus.serial_lines()
        self.assertIn("gps0", lines)

    def test_device_attach_unknown_type(self):
        out = self.cmds.cmd_device(["attach", "uart", "USART1", "bogus"])
        self.assertIn("unknown device type", out)

    def test_device_attach_unknown_peripheral(self):
        out = self.cmds.cmd_device(["attach", "uart", "USART99", "ublox"])
        self.assertIn("unknown peripheral", out)

    def test_device_list_after_attach(self):
        self.cmds.cmd_device(["attach", "uart", "USART1", "ublox", "name=gps0"])
        out = self.cmds.cmd_device(["list"])
        self.assertIn("gps0", out)
        self.assertIn("UbloxGpsDevice", out)

    def test_device_status(self):
        self.cmds.cmd_device(["attach", "uart", "USART1", "ublox", "name=gps0"])
        out = self.cmds.cmd_device(["status", "gps0"])
        self.assertIn("UbloxGpsDevice", out)
        self.assertIn("mode=", out)

    def test_device_status_unknown(self):
        out = self.cmds.cmd_device(["status", "bogus"])
        self.assertIn("unknown device", out)

    def test_device_inject(self):
        self.cmds.cmd_device(["attach", "uart", "USART1", "ublox", "name=gps0", "mode=ubx"])
        cmd = ubx_frame(UBX_CFG, CFG_MSG, b"\x01\x07\x01")
        out = self.cmds.cmd_device(["inject", "gps0", cmd.hex()])
        self.assertIn("injected", out)

    def test_device_inject_unknown(self):
        out = self.cmds.cmd_device(["inject", "bogus", "AABB"])
        self.assertIn("unknown device", out)

    def test_device_detach(self):
        self.cmds.cmd_device(["attach", "uart", "USART1", "ublox", "name=gps0"])
        out = self.cmds.cmd_device(["detach", "gps0"])
        self.assertIn("detached", out)
        self.assertEqual(len(self.bus.serial_lines()), 0)

    def test_device_detach_unknown(self):
        out = self.cmds.cmd_device(["detach", "bogus"])
        self.assertIn("unknown device", out)

    def test_device_types(self):
        out = self.cmds.cmd_device(["types"])
        self.assertIn("ublox", out)


if __name__ == "__main__":
    unittest.main()
