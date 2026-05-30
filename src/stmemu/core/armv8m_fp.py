"""Software emulation of ARMv8-M floating-point instructions Unicorn lacks.

Unicorn's Cortex-M model executes the classic VFPv4 set but not the ARMv8-M FP
extension additions — VRINT* (directed round-to-integer), VMAXNM/VMINNM
(NaN-aware min/max), VCVT{A,N,P,M} (convert with explicit rounding), and VSEL
(flag-conditional select). ArduPilot's EKF3 (e.g. NavEKF3_core::setup_core and
readIMUData) uses these, so an otherwise-fine run dies with UC_ERR_INSN_INVALID.

On an invalid-instruction fault the emulator hands the faulting bytes here; if
they decode to a supported op we evaluate it against Unicorn's S/D register
file (and CPSR for VSEL) and report the instruction size so the caller can step
over it. Anything we don't recognise returns ``None`` and the fault stands.

Exact IEEE corner cases (signalling NaNs, tie rounding under non-default FPSCR)
are approximated where Python's float model differs — immaterial to running
firmware.
"""
from __future__ import annotations

import math
import struct
import sys as _sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

_md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
_md.detail = False

# Built lazily on first use: importing unicorn at module top trips "unicorn is
# not a package" during `unittest discover` (some tests stub sys.modules
# ['unicorn'] with a non-package mock before this module's tests run). By
# first-use time in a real run unicorn is the genuine package, so this resolves.
_REGS: dict[str, int] | None = None


def _regs() -> dict:
    global _REGS
    if _REGS is None:
        regs: dict[str, int] = {}
        try:
            import importlib
            ac = importlib.import_module("unicorn.arm_const")
            for i in range(32):
                s = getattr(ac, f"UC_ARM_REG_S{i}", None)
                if s is not None:
                    regs[f"s{i}"] = s
                d = getattr(ac, f"UC_ARM_REG_D{i}", None)
                if d is not None:
                    regs[f"d{i}"] = d
            cpsr = getattr(ac, "UC_ARM_REG_CPSR", None)
            if cpsr is not None:
                regs["cpsr"] = cpsr
        except Exception:
            pass
        if regs:            # cache only a real resolution
            _REGS = regs
        return regs
    return _REGS


def _read(uc, name: str) -> float:
    raw = int(uc.reg_read(_regs()[name]))
    if name[0] == "d":
        return struct.unpack("<d", struct.pack("<Q", raw & 0xFFFFFFFFFFFFFFFF))[0]
    return struct.unpack("<f", struct.pack("<I", raw & 0xFFFFFFFF))[0]


def _write(uc, name: str, val: float) -> None:
    if name[0] == "d":
        uc.reg_write(_regs()[name], struct.unpack("<Q", struct.pack("<d", float(val)))[0])
    else:
        uc.reg_write(_regs()[name], struct.unpack("<I", struct.pack("<f", float(val)))[0])


def _round_away(x: float) -> float:
    if math.isnan(x) or math.isinf(x):
        return x
    return float(math.floor(x + 0.5)) if x >= 0 else float(math.ceil(x - 0.5))


_VRINT = {
    "vrintp": lambda x: x if (math.isnan(x) or math.isinf(x)) else float(math.ceil(x)),
    "vrintm": lambda x: x if (math.isnan(x) or math.isinf(x)) else float(math.floor(x)),
    "vrintz": lambda x: x if (math.isnan(x) or math.isinf(x)) else float(math.trunc(x)),
    "vrintn": lambda x: x if (math.isnan(x) or math.isinf(x)) else float(round(x)),
    "vrinta": _round_away,
    "vrintx": lambda x: x if (math.isnan(x) or math.isinf(x)) else float(round(x)),
    "vrintr": lambda x: x if (math.isnan(x) or math.isinf(x)) else float(round(x)),
}

_VCVT_ROUND = {
    "vcvtp": math.ceil,
    "vcvtm": math.floor,
    "vcvtn": lambda x: int(round(x)),
    "vcvta": lambda x: int(math.floor(x + 0.5)) if x >= 0 else int(math.ceil(x - 0.5)),
}


def _cond(uc, suffix: str) -> bool:
    cpsr = int(uc.reg_read(_regs()["cpsr"]))
    N = (cpsr >> 31) & 1
    Z = (cpsr >> 30) & 1
    C = (cpsr >> 29) & 1
    V = (cpsr >> 28) & 1
    # ARMv8-M VSEL supports only EQ, VS, GE, GT.
    return {
        "eq": Z == 1,
        "vs": V == 1,
        "ge": N == V,
        "gt": (Z == 0) and (N == V),
    }.get(suffix, False)


def try_emulate(uc, code: bytes, pc: int):
    """Emulate one ARMv8-M FP instruction at ``pc``; return its size if handled."""
    try:
        ins = next(_md.disasm(code, pc, count=1))
    except (StopIteration, Exception):
        return None

    mnem = ins.mnemonic                       # e.g. "vrintp.f64", "vselgt.f64"
    base = mnem.split(".", 1)[0]
    ops = [o.strip() for o in ins.op_str.split(",")]
    R = _regs()
    if not R:
        return None

    try:
        if base in _VRINT and len(ops) == 2 and ops[0] in R and ops[1] in R:
            _write(uc, ops[0], _VRINT[base](_read(uc, ops[1])))
            return ins.size

        if base in ("vmaxnm", "vminnm") and len(ops) == 3 and all(o in R for o in ops):
            a, b = _read(uc, ops[1]), _read(uc, ops[2])
            if math.isnan(a):
                r = b
            elif math.isnan(b):
                r = a
            else:
                r = max(a, b) if base == "vmaxnm" else min(a, b)
            _write(uc, ops[0], r)
            return ins.size

        if base.startswith("vsel") and len(base) == 6 and len(ops) == 3 and all(o in R for o in ops):
            pick = ops[1] if _cond(uc, base[4:6]) else ops[2]
            _write(uc, ops[0], _read(uc, pick))
            return ins.size

        if base in _VCVT_ROUND and len(ops) == 2 and ops[0] in R and ops[1] in R:
            x = _read(uc, ops[1])
            signed = ".s32" in mnem or mnem.endswith("s32")
            if math.isnan(x):
                ival = 0
            else:
                ival = int(_VCVT_ROUND[base](x))
                ival = max(-(2 ** 31), min(2 ** 31 - 1, ival)) if signed \
                    else max(0, min(2 ** 32 - 1, ival))
            uc.reg_write(R[ops[0]], ival & 0xFFFFFFFF)
            return ins.size
    except Exception:
        return None

    return None


__all__ = ["try_emulate"]
