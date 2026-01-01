from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from stmemu.svd.model import SvdDevice, SvdPeripheral, SvdRegister, SvdField
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


def _t(node: Optional[ET.Element], tag: str) -> Optional[str]:
    if node is None:
        return None
    e = node.find(tag)
    return e.text.strip() if (e is not None and e.text) else None


def _int(s: Optional[str], default: Optional[int] = None) -> Optional[int]:
    if s is None:
        return default
    s = s.strip()
    try:
        return int(s, 0)
    except ValueError:
        # some SVDs use hex without 0x
        try:
            return int(s, 16)
        except ValueError:
            return default


def load_svd(path: Path) -> SvdDevice:
    tree = ET.parse(path)
    root = tree.getroot()

    dev_name = _t(root, "name") or path.stem
    perips_node = root.find("peripherals")

    if perips_node is None:
        log.warning("No <peripherals> found in SVD: %s", path)
        return SvdDevice(name=dev_name, peripherals=())

    # ---- first pass: capture XML + basic fields
    raw: dict[str, dict] = {}

    for p in perips_node.findall("peripheral"):
        pname = _t(p, "name")
        if not pname:
            continue

        derived = p.get("derivedFrom")  # attribute on peripheral element
        base = _int(_t(p, "baseAddress"), 0) or 0

        ab = p.find("addressBlock")
        size = _int(_t(ab, "size"), None)

        regs_node = p.find("registers")

        raw[pname] = {
            "name": pname,
            "derivedFrom": derived,
            "base": base,
            "size": size,
            "regs_node": regs_node,  # keep xml node
        }

    # ---- helper to parse registers from a <registers> node
    def parse_registers(regs_node: Optional[ET.Element]) -> tuple[SvdRegister, ...]:
        if regs_node is None:
            return ()
        regs: list[SvdRegister] = []
        for r in regs_node.findall("register"):
            rname = _t(r, "name")
            if not rname:
                continue
            offset = _int(_t(r, "addressOffset"), 0) or 0
            size_bits = _int(_t(r, "size"), 32) or 32
            reset_value = _int(_t(r, "resetValue"), None)

            fields: list[SvdField] = []
            fnode = r.find("fields")
            if fnode is not None:
                for f in fnode.findall("field"):
                    fname = _t(f, "name") or ""
                    bo = _int(_t(f, "bitOffset"), 0) or 0
                    bw = _int(_t(f, "bitWidth"), 1) or 1
                    if fname:
                        fields.append(SvdField(name=fname, bit_offset=bo, bit_width=bw))

            regs.append(
                SvdRegister(
                    name=rname,
                    offset=offset,
                    size_bits=size_bits,
                    reset_value=reset_value,
                    fields=tuple(fields),
                )
            )
        return tuple(regs)

    # ---- resolve derivedFrom by copying missing pieces
    resolved: dict[str, SvdPeripheral] = {}

    def resolve(name: str, depth: int = 0) -> SvdPeripheral:
        if name in resolved:
            return resolved[name]
        if depth > 8:
            raise ValueError(f"derivedFrom chain too deep at {name}")

        entry = raw.get(name)
        if entry is None:
            raise KeyError(f"peripheral not found: {name}")

        parent_name = entry["derivedFrom"]
        parent: Optional[SvdPeripheral] = None
        if parent_name:
            parent = resolve(parent_name, depth + 1)

        # inherit size/regs if missing
        size = entry["size"]
        regs = parse_registers(entry["regs_node"])

        if parent is not None:
            if size is None:
                size = parent.size
            if not regs:
                regs = parent.registers

        if size is None:
            size = 0x400  # fallback heuristic

        periph = SvdPeripheral(
            name=entry["name"],
            base_address=entry["base"],
            size=int(size),
            registers=tuple(regs),
        )
        resolved[name] = periph
        return periph

    peripherals = [resolve(n) for n in raw.keys()]
    log.info("Loaded SVD device=%s peripherals=%d", dev_name, len(peripherals))
    return SvdDevice(name=dev_name, peripherals=tuple(peripherals))

