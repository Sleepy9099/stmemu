"""STM32H7 SDMMC peripheral — minimal command-completion model.

The full SDIO/SDMMC protocol is far beyond this emulator's scope (no SD
card transfers, no FIFO, no IDMA). What we *do* model is enough to keep
the ChibiOS HAL's polling loops from spinning forever:

* Writing CMDR with CPSMEN (CMD Path State Machine enable) immediately
  flags STAR.CMDSENT (for no-response commands) and STAR.CTIMEOUT
  (no card responded). Without that the firmware's
  `sdc_lld_send_cmd_none` polls STAR bit 7 forever.
* Writing ICR clears the corresponding STAR bits (datasheet behaviour).

The intent is "no SD card present" — every command times out, the
driver gives up and ArduPilot moves on to the rest of init. Logging
backends, parameter persistence, etc. continue to use FRAM via SPI2.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


# STAR (status) bit positions per RM0433.
_STAR_CCRCFAIL = 1 << 0
_STAR_DCRCFAIL = 1 << 1
_STAR_CTIMEOUT = 1 << 2
_STAR_DTIMEOUT = 1 << 3
_STAR_TXUNDERR = 1 << 4
_STAR_RXOVERR = 1 << 5
_STAR_CMDREND = 1 << 6
_STAR_CMDSENT = 1 << 7
_STAR_DATAEND = 1 << 8
_STAR_DBCKEND = 1 << 10
_STAR_BUSYD0END = 1 << 21

_CMDR_CPSMEN = 1 << 12
_CMDR_WAITRESP_SHIFT = 8
_CMDR_WAITRESP_MASK = 0x3 << _CMDR_WAITRESP_SHIFT
_CMDR_CMDINDEX_MASK = 0x3F


@dataclass
class SdmmcPeripheral(GenericRegisterFilePeripheral):
    """SDMMC1 / SDMMC2 stub: report 'no card' on every command."""

    _context: PeripheralContext | None = field(default=None, init=False, repr=False)

    _POWER = 0x00
    _CLKCR = 0x04
    _ARGR = 0x08
    _CMDR = 0x0C
    _RESP1R = 0x14
    _DTIMER = 0x24
    _DLENR = 0x28
    _DCTRL = 0x2C
    _DCNTR = 0x30
    _STAR = 0x34
    _ICR = 0x38
    _MASKR = 0x3C

    def __post_init__(self) -> None:
        super().__post_init__()
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "POWER":
                self._POWER = reg.offset
            elif rname == "CLKCR":
                self._CLKCR = reg.offset
            elif rname == "ARGR":
                self._ARGR = reg.offset
            elif rname == "CMDR":
                self._CMDR = reg.offset
            elif rname == "RESP1R":
                self._RESP1R = reg.offset
            elif rname == "DTIMER":
                self._DTIMER = reg.offset
            elif rname == "DLENR":
                self._DLENR = reg.offset
            elif rname == "DCTRL":
                self._DCTRL = reg.offset
            elif rname == "DCNTR":
                self._DCNTR = reg.offset
            elif rname == "STAR":
                self._STAR = reg.offset
            elif rname == "ICR":
                self._ICR = reg.offset
            elif rname == "MASKR":
                self._MASKR = reg.offset

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def write(self, offset: int, size: int, value: int) -> None:
        if offset == self._ICR:
            # Clear corresponding STAR bits.
            current = self.read_register_value(self._STAR)
            self.write_register_value(self._STAR, current & ~(int(value) & 0xFFFFFFFF))
            return

        super().write(offset, size, value)

        if offset == self._CMDR:
            self._on_command(int(value) & 0xFFFFFFFF)

    def _on_command(self, cmd_value: int) -> None:
        if not (cmd_value & _CMDR_CPSMEN):
            return
        wait_resp = (cmd_value & _CMDR_WAITRESP_MASK) >> _CMDR_WAITRESP_SHIFT
        star = self.read_register_value(self._STAR)
        if wait_resp == 0:
            # No-response command: just flag CMDSENT.
            star |= _STAR_CMDSENT
        else:
            # Response expected -- "no card" timeout. CTIMEOUT signals the
            # driver to give up on that command.
            star |= _STAR_CTIMEOUT
        # Mirror command index into the response register; some drivers
        # sanity-check this after CMDREND, even when reporting timeout.
        self.write_register_value(self._RESP1R, 0)
        self.write_register_value(self._STAR, star)


def build_sdmmc(peripheral: SvdPeripheral) -> SdmmcPeripheral:
    return SdmmcPeripheral(peripheral=peripheral)
