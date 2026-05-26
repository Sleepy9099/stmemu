"""RCC peripheral model with clock gating, reset, and status tracking."""
from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


def _strip_suffix(name: str, suffix: str) -> str:
    """Strip *suffix* only from the end of *name*, e.g. GPIOAEN -> GPIOA."""
    if name.endswith(suffix) and len(name) > len(suffix):
        return name[: -len(suffix)].rstrip("_")
    return ""


@dataclass
class RccPeripheral(GenericRegisterFilePeripheral):
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _cr_offset: int = field(default=0x00, init=False, repr=False)
    _cfgr_offset: int = field(default=0x08, init=False, repr=False)
    _enr_offsets: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _rstr_offsets: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _enabled_peripherals: set[str] = field(default_factory=set, init=False, repr=False)
    _enr_written: bool = field(default=False, init=False, repr=False)
    _cr_rdy_bits: list[tuple[str, int, int]] = field(
        default_factory=list, init=False, repr=False,
    )
    _cfgr_sws_fields: list[tuple[int, int, int, int]] = field(
        default_factory=list, init=False, repr=False,
    )
    _enr_field_map: dict[tuple[int, int], str] = field(
        default_factory=dict, init=False, repr=False,
    )
    _rstr_field_map: dict[tuple[int, int], str] = field(
        default_factory=dict, init=False, repr=False,
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        self._scan_registers()

    def _scan_registers(self) -> None:
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "CR":
                self._cr_offset = reg.offset
                for f in reg.fields:
                    fn = f.name.upper()
                    if fn.endswith("RDY"):
                        enable_name = fn.replace("RDY", "ON")
                        enable_bit = self._find_field_bit(reg, enable_name)
                        self._cr_rdy_bits.append((fn, f.bit_offset, enable_bit))
            elif rname in ("CFGR", "CFGR1"):
                self._cfgr_offset = reg.offset
                self._scan_sw_sws_fields(reg)
            elif "ENR" in rname and "RSTR" not in rname:
                self._enr_offsets[rname] = reg.offset
                for f in reg.fields:
                    pname = _strip_suffix(f.name.upper(), "EN")
                    if pname:
                        self._enr_field_map[(reg.offset, f.bit_offset)] = pname
            elif "RSTR" in rname:
                self._rstr_offsets[rname] = reg.offset
                for f in reg.fields:
                    pname = _strip_suffix(f.name.upper(), "RST")
                    if pname:
                        self._rstr_field_map[(reg.offset, f.bit_offset)] = pname

    def _scan_sw_sws_fields(self, reg) -> None:
        fields_by_name = {f.name.upper(): f for f in reg.fields}
        matched: set[str] = set()
        for fn, f in fields_by_name.items():
            if not fn.startswith("SWS"):
                continue
            sw_name = "SW" + fn[3:]
            sw_field = fields_by_name.get(sw_name)
            if sw_field is None and fn == "SWS":
                sw_field = fields_by_name.get("SW")
            if sw_field is not None and fn not in matched:
                matched.add(fn)
                self._cfgr_sws_fields.append((
                    f.bit_offset, f.bit_width,
                    sw_field.bit_offset, sw_field.bit_width,
                ))

    @staticmethod
    def _find_field_bit(reg, name: str) -> int:
        for f in reg.fields:
            if f.name.upper() == name:
                return f.bit_offset
        return -1

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def reset(self) -> None:
        super().reset()
        self._enabled_peripherals.clear()
        self._enr_written = False

    def read(self, offset: int, size: int) -> int:
        if offset == self._cr_offset:
            self._sync_cr_ready_bits()
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        super().write(offset, size, value)

        if offset == self._cr_offset:
            self._sync_cr_ready_bits()
        elif offset == self._cfgr_offset:
            self._sync_sws_bits()

        if offset in self._enr_offsets.values():
            self._update_enabled_peripherals(offset, value)

        if offset in self._rstr_offsets.values():
            self._apply_peripheral_resets(offset, value)

    def _sync_cr_ready_bits(self) -> None:
        cr = self.read_register_value(self._cr_offset)
        changed = False
        for rdy_name, rdy_bit, enable_bit in self._cr_rdy_bits:
            if enable_bit >= 0 and (cr & (1 << enable_bit)):
                if not (cr & (1 << rdy_bit)):
                    cr |= (1 << rdy_bit)
                    changed = True
            elif enable_bit >= 0 and not (cr & (1 << enable_bit)):
                if cr & (1 << rdy_bit):
                    cr &= ~(1 << rdy_bit)
                    changed = True
        if changed:
            self.write_register_value(self._cr_offset, cr)

    def _sync_sws_bits(self) -> None:
        cfgr = self.read_register_value(self._cfgr_offset)
        changed = False
        for sws_off, sws_width, sw_off, sw_width in self._cfgr_sws_fields:
            width = min(sws_width, sw_width)
            mask = (1 << width) - 1
            sw_val = (cfgr >> sw_off) & mask
            sws_val = (cfgr >> sws_off) & mask
            if sws_val != sw_val:
                cfgr &= ~(mask << sws_off)
                cfgr |= (sw_val << sws_off)
                changed = True
        if changed:
            self.write_register_value(self._cfgr_offset, cfgr)

    def _update_enabled_peripherals(self, offset: int, value: int) -> None:
        self._enr_written = True
        for (reg_off, bit), pname in self._enr_field_map.items():
            if reg_off != offset:
                continue
            if value & (1 << bit):
                self._enabled_peripherals.add(pname)
            else:
                self._enabled_peripherals.discard(pname)

    def _apply_peripheral_resets(self, offset: int, value: int) -> None:
        if not self._context:
            return
        for (reg_off, bit), pname in self._rstr_field_map.items():
            if reg_off != offset:
                continue
            if value & (1 << bit):
                model = self._context.bus.model_for_name(pname)
                if model is not None:
                    model.reset()
                    log.debug("RCC reset: %s", pname)

    def is_peripheral_enabled(self, name: str) -> bool:
        if not self._enr_written:
            return True
        return name.upper() in self._enabled_peripherals

    def enabled_peripherals(self) -> frozenset[str]:
        return frozenset(self._enabled_peripherals)

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base["enabled_peripherals"] = sorted(self._enabled_peripherals)
        return base

    def restore_state(self, state: object) -> None:
        super().restore_state(state)
        if isinstance(state, dict):
            ep = state.get("enabled_peripherals")
            if isinstance(ep, list):
                self._enabled_peripherals = set(str(x) for x in ep)


def build_rcc(peripheral: SvdPeripheral) -> RccPeripheral:
    return RccPeripheral(peripheral)
