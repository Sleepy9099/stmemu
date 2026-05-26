from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from stmemu.svd.model import SvdDevice, SvdField, SvdInterrupt, SvdPeripheral, SvdRegister
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


def _expand_dim_name(template: str, index: str) -> str:
    """Expand a dim-templated name like 'CH%s' with index '0' -> 'CH0'."""
    if "%s" in template:
        return template.replace("%s", index)
    if "[%s]" in template:
        return template.replace("[%s]", index)
    return template + index


def _dim_indices(node: ET.Element) -> list[str]:
    """Return the list of dim indices from <dimIndex> or range."""
    dim_index = _t(node, "dimIndex")
    dim = _int(_t(node, "dim"))
    if dim is None or dim <= 0:
        return []
    if dim_index:
        # Comma-separated list like "A,B,C" or range like "0-7"
        if "," in dim_index:
            return [s.strip() for s in dim_index.split(",")]
        m = re.match(r"(\d+)\s*-\s*(\d+)", dim_index)
        if m:
            return [str(i) for i in range(int(m.group(1)), int(m.group(2)) + 1)]
    # Default: 0..dim-1
    return [str(i) for i in range(dim)]


def _parse_access(raw: Optional[str]) -> str:
    if raw is None:
        return "rw"
    access = raw.strip().lower()
    if access in ("read-only", "readonly"):
        return "ro"
    if access in ("write-only", "writeonce", "write-only once"):
        return "wo"
    return "rw"


def _parse_fields(reg_node: ET.Element) -> tuple[SvdField, ...]:
    fnode = reg_node.find("fields")
    if fnode is None:
        return ()
    fields: list[SvdField] = []
    for f in fnode.findall("field"):
        fname = _t(f, "name") or ""
        bo = _int(_t(f, "bitOffset"), 0) or 0
        bw = _int(_t(f, "bitWidth"), 1) or 1
        if fname:
            fields.append(SvdField(name=fname, bit_offset=bo, bit_width=bw))
    return tuple(fields)


def _parse_single_register(r: ET.Element) -> Optional[SvdRegister]:
    rname = _t(r, "name")
    if not rname:
        return None
    offset = _int(_t(r, "addressOffset"), 0) or 0
    size_bits = _int(_t(r, "size"), 32) or 32
    reset_value = _int(_t(r, "resetValue"), None)
    access = _parse_access(_t(r, "access"))
    desc = _t(r, "description") or ""
    fields = _parse_fields(r)
    return SvdRegister(
        name=rname,
        offset=offset,
        size_bits=size_bits,
        reset_value=reset_value,
        access=access,
        fields=fields,
        description=desc,
    )


def _expand_register_dims(r: ET.Element, base_reg: SvdRegister) -> list[SvdRegister]:
    """Expand dim-templated registers into multiple concrete registers."""
    dim = _int(_t(r, "dim"))
    if dim is None or dim <= 0:
        return [base_reg]

    dim_increment = _int(_t(r, "dimIncrement"), 4) or 4
    indices = _dim_indices(r)
    if not indices:
        return [base_reg]

    expanded: list[SvdRegister] = []
    for i, idx in enumerate(indices):
        expanded.append(SvdRegister(
            name=_expand_dim_name(base_reg.name, idx),
            offset=base_reg.offset + i * dim_increment,
            size_bits=base_reg.size_bits,
            reset_value=base_reg.reset_value,
            access=base_reg.access,
            fields=base_reg.fields,
            description=base_reg.description,
        ))
    return expanded


def _parse_cluster(cluster: ET.Element, base_offset: int = 0) -> list[SvdRegister]:
    """Parse a <cluster> element and flatten its registers with offset applied."""
    cluster_offset = (_int(_t(cluster, "addressOffset"), 0) or 0) + base_offset
    cluster_name = _t(cluster, "name") or ""
    regs: list[SvdRegister] = []

    # Parse registers inside the cluster
    for r in cluster.findall("register"):
        base_reg = _parse_single_register(r)
        if base_reg is None:
            continue
        # Prefix the register name with cluster name
        prefixed = SvdRegister(
            name=f"{cluster_name}_{base_reg.name}" if cluster_name else base_reg.name,
            offset=cluster_offset + base_reg.offset,
            size_bits=base_reg.size_bits,
            reset_value=base_reg.reset_value,
            access=base_reg.access,
            fields=base_reg.fields,
            description=base_reg.description,
        )
        regs.extend(_expand_register_dims(r, prefixed))

    # Nested clusters
    for sub in cluster.findall("cluster"):
        regs.extend(_parse_cluster(sub, base_offset=cluster_offset))

    # Expand cluster-level dims
    dim = _int(_t(cluster, "dim"))
    if dim is not None and dim > 1:
        dim_increment = _int(_t(cluster, "dimIncrement"), 4) or 4
        indices = _dim_indices(cluster)
        if indices:
            base_regs = list(regs)
            regs = []
            for i, idx in enumerate(indices):
                for reg in base_regs:
                    regs.append(SvdRegister(
                        name=_expand_dim_name(reg.name, idx),
                        offset=reg.offset + i * dim_increment,
                        size_bits=reg.size_bits,
                        reset_value=reg.reset_value,
                        access=reg.access,
                        fields=reg.fields,
                        description=reg.description,
                    ))

    return regs


def _parse_interrupts(p_node: ET.Element) -> tuple[SvdInterrupt, ...]:
    """Extract <interrupt> elements from a peripheral node."""
    interrupts: list[SvdInterrupt] = []
    for intr in p_node.findall("interrupt"):
        name = _t(intr, "name")
        value = _int(_t(intr, "value"))
        if name and value is not None:
            interrupts.append(SvdInterrupt(name=name, value=value))
    return tuple(interrupts)


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
        desc = _t(p, "description") or ""
        interrupts = _parse_interrupts(p)

        raw[pname] = {
            "name": pname,
            "derivedFrom": derived,
            "base": base,
            "size": size,
            "regs_node": regs_node,
            "description": desc,
            "interrupts": interrupts,
        }

    # ---- helper to parse registers from a <registers> node
    def parse_registers(regs_node: Optional[ET.Element]) -> tuple[SvdRegister, ...]:
        if regs_node is None:
            return ()
        regs: list[SvdRegister] = []

        # Direct registers
        for r in regs_node.findall("register"):
            base_reg = _parse_single_register(r)
            if base_reg is None:
                continue
            regs.extend(_expand_register_dims(r, base_reg))

        # Clusters
        for cluster in regs_node.findall("cluster"):
            regs.extend(_parse_cluster(cluster))

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
        interrupts = entry["interrupts"]
        desc = entry["description"]

        if parent is not None:
            if size is None:
                size = parent.size
            if not regs:
                regs = parent.registers
            if not interrupts:
                interrupts = parent.interrupts
            if not desc:
                desc = parent.description

        if size is None:
            size = 0x400  # fallback heuristic

        periph = SvdPeripheral(
            name=entry["name"],
            base_address=entry["base"],
            size=int(size),
            registers=tuple(regs),
            description=desc,
            interrupts=interrupts,
        )
        resolved[name] = periph
        return periph

    peripherals = [resolve(n) for n in raw.keys()]
    log.info("Loaded SVD device=%s peripherals=%d", dev_name, len(peripherals))
    return SvdDevice(name=dev_name, peripherals=tuple(peripherals))
