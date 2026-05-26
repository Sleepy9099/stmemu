"""Declarative fuzz-target profiles (YAML / JSON)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from stmemu.fuzz.injector import FunctionTargetConfig


def _parse_int(v: Any) -> int:
    if isinstance(v, int):
        return v
    return int(str(v), 0)


@dataclass
class TargetProfile:
    """One injectable target described in a profile."""
    name: str
    kind: str  # "function", "memory", "peripheral"
    entry: int = 0
    buffer: int = 0
    abi: str = "ptr_len"
    stop: str = "steps"
    return_addr: int = 0
    stop_pc: int = 0
    buf_reg: str = "r0"
    len_reg: str = "r1"
    size_reg: str | None = None

    def to_fn_config(self) -> FunctionTargetConfig:
        return FunctionTargetConfig(
            abi=self.abi,
            stop=self.stop,
            return_addr=self.return_addr,
            stop_pc=self.stop_pc,
            buf_reg=self.buf_reg,
            len_reg=self.len_reg,
        )


@dataclass
class CoverageFilter:
    """Restrict coverage tracking to an address range."""
    start: int = 0
    end: int = 0


@dataclass
class FuzzProfile:
    """Complete fuzz session configuration loaded from a profile file."""
    name: str = ""
    targets: list[TargetProfile] = field(default_factory=list)
    snapshot: str = "__fuzz_baseline"

    # Engine config
    iterations: int = 1000
    steps_per_iter: int = 5000
    min_input_len: int = 1
    max_input_len: int = 256
    max_mutations: int = 4
    mode: str = "random"
    coverage_mode: str = "edge"
    capture_mmio: bool = False
    seed: int | None = None

    # Seed corpus
    seed_dir: str | None = None
    seed_inputs: list[str] = field(default_factory=list)

    # Dictionary
    dictionary: list[str] = field(default_factory=list)

    # Coverage filter
    coverage: CoverageFilter | None = None

    # Fault policy
    faults: dict[str, bool] = field(default_factory=dict)


def _parse_target(raw: dict[str, Any]) -> TargetProfile:
    kind = str(raw.get("type", raw.get("kind", "function")))
    tp = TargetProfile(
        name=str(raw["name"]),
        kind=kind,
    )
    if "entry" in raw:
        tp.entry = _parse_int(raw["entry"])
    if "buffer" in raw:
        tp.buffer = _parse_int(raw["buffer"])
    if "size_reg" in raw:
        tp.size_reg = str(raw["size_reg"])

    args = raw.get("args", {})
    if isinstance(args, dict):
        if "r0" in args:
            tp.buf_reg = "r0"
        for reg, role in args.items():
            role_s = str(role).lower()
            if role_s in ("buffer", "buf", "ptr"):
                tp.buf_reg = str(reg)
            elif role_s in ("length", "len", "size"):
                tp.len_reg = str(reg)

    abi = raw.get("abi")
    if abi:
        tp.abi = str(abi)
    elif args:
        has_buf = any(str(v).lower() in ("buffer", "buf", "ptr") for v in args.values())
        has_len = any(str(v).lower() in ("length", "len", "size") for v in args.values())
        if has_buf and has_len:
            tp.abi = "ptr_len"
        elif has_buf:
            tp.abi = "ptr"

    stop = raw.get("stop")
    if isinstance(stop, str):
        tp.stop = stop
    elif isinstance(stop, list) and stop:
        tp.stop = str(stop[0])
    if "return_addr" in raw:
        tp.return_addr = _parse_int(raw["return_addr"])
    elif tp.stop == "return" and "return_addr" not in raw:
        pass
    if "stop_pc" in raw:
        tp.stop_pc = _parse_int(raw["stop_pc"])

    return tp


def _parse_coverage(raw: dict[str, Any] | None) -> CoverageFilter | None:
    if not raw:
        return None
    return CoverageFilter(
        start=_parse_int(raw.get("start", 0)),
        end=_parse_int(raw.get("end", 0)),
    )


def load_profile(path: Path) -> FuzzProfile:
    """Load a fuzz profile from a JSON or YAML file."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("pyyaml is required for YAML profiles: pip install pyyaml")
        raw = yaml.safe_load(text)
    else:
        raw = json.loads(text)

    if not isinstance(raw, dict):
        raise ValueError(f"profile must be a mapping, got {type(raw).__name__}")

    prof = FuzzProfile()
    prof.name = str(raw.get("name", path.stem))

    for t_raw in raw.get("targets", []):
        prof.targets.append(_parse_target(t_raw))
    if "target" in raw and isinstance(raw["target"], dict):
        prof.targets.append(_parse_target(raw["target"]))

    prof.snapshot = str(raw.get("snapshot", prof.snapshot))
    prof.iterations = int(raw.get("iterations", prof.iterations))
    prof.steps_per_iter = int(raw.get("steps_per_iter", raw.get("steps", prof.steps_per_iter)))
    prof.min_input_len = int(raw.get("min_input_len", prof.min_input_len))
    prof.max_input_len = int(raw.get("max_input_len", prof.max_input_len))
    prof.max_mutations = int(raw.get("max_mutations", prof.max_mutations))
    prof.mode = str(raw.get("mode", prof.mode))
    prof.coverage_mode = str(raw.get("coverage_mode", prof.coverage_mode))
    prof.capture_mmio = bool(raw.get("capture_mmio", prof.capture_mmio))

    seed_val = raw.get("seed")
    if seed_val is not None:
        prof.seed = int(seed_val)

    prof.seed_dir = raw.get("seed_dir")
    for s in raw.get("seed_inputs", []):
        prof.seed_inputs.append(str(s))

    for d in raw.get("dictionary", []):
        prof.dictionary.append(str(d))

    prof.coverage = _parse_coverage(raw.get("coverage"))
    prof.faults = {str(k): bool(v) for k, v in raw.get("faults", {}).items()}

    return prof


def apply_profile(
    profile: FuzzProfile,
    engine: object,
    *,
    base_dir: Path | None = None,
) -> str:
    """Apply a loaded profile to a FuzzEngine, returning a status summary."""
    from stmemu.fuzz.engine import FuzzEngine
    eng: FuzzEngine = engine

    eng.min_input_len = profile.min_input_len
    eng.max_input_len = profile.max_input_len
    eng.max_mutations = profile.max_mutations
    eng.mode = profile.mode
    eng.coverage_mode = profile.coverage_mode
    eng.capture_mmio = profile.capture_mmio

    if profile.seed is not None:
        eng.seed(profile.seed)

    if eng.injector is None:
        from stmemu.fuzz.injector import Injector
        eng.injector = Injector(bus=eng.bus, emu=eng.emu)

    targets_added = 0
    for tp in profile.targets:
        if tp.kind == "function":
            eng.injector.add_function_target(
                tp.name, tp.entry, tp.buffer,
                fn_config=tp.to_fn_config(),
            )
            targets_added += 1
        elif tp.kind == "memory":
            eng.injector.add_memory_target(
                tp.name, tp.buffer or tp.entry,
                size_reg=tp.size_reg,
            )
            targets_added += 1

    for hex_str in profile.seed_inputs:
        try:
            data = bytes.fromhex(hex_str)
            if data:
                eng.add_seed_input(data)
        except ValueError:
            pass

    if profile.seed_dir:
        seed_path = Path(profile.seed_dir)
        if base_dir and not seed_path.is_absolute():
            seed_path = base_dir / seed_path
        if seed_path.is_dir():
            eng.import_corpus(seed_path)

    for hex_str in profile.dictionary:
        try:
            token = bytes.fromhex(hex_str)
            if token:
                eng.mutator.add_dict_entry(token)
        except ValueError:
            pass

    lines = [f"profile '{profile.name}' applied"]
    lines.append(f"  targets: {targets_added}")
    lines.append(f"  mode: {profile.mode}  coverage: {profile.coverage_mode}")
    lines.append(
        f"  input: {profile.min_input_len}-{profile.max_input_len}B  "
        f"mutations: {profile.max_mutations}"
    )
    if profile.seed_inputs:
        lines.append(f"  seed inputs: {len(profile.seed_inputs)}")
    if profile.seed_dir:
        lines.append(f"  seed dir: {profile.seed_dir}")
    if profile.dictionary:
        lines.append(f"  dictionary: {len(profile.dictionary)} tokens")
    if profile.coverage:
        lines.append(
            f"  coverage filter: 0x{profile.coverage.start:08X}"
            f"-0x{profile.coverage.end:08X}"
        )
    if profile.faults:
        enabled = [k for k, v in profile.faults.items() if v]
        if enabled:
            lines.append(f"  faults: {', '.join(enabled)}")
    return "\n".join(lines)
