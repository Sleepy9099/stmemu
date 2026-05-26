"""Tests for external device layer: SerialLine, NMEA, u-blox GPS."""
from __future__ import annotations

import struct
import unittest

from stmemu.external.device import ExternalDevice
from stmemu.external.serial_line import SerialLine
from stmemu.external import nmea
from stmemu.external.ublox import (
    UbloxGpsDevice,
    ubx_frame,
    _ubx_validate,
    UBX_CFG, UBX_NAV, UBX_ACK, UBX_MON,
    CFG_RATE, CFG_PRT, CFG_RST, CFG_MSG,
    NAV_PVT, NAV_STATUS,
    MON_VER,
    ACK_ACK, ACK_NAK,
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
        self.assertIn(b"stmemu", parsed[2])

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


if __name__ == "__main__":
    unittest.main()
