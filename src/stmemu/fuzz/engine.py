"""Coverage-guided fuzzer engine for STM32 emulator."""
from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from stmemu.fuzz.mutator import Mutator
from stmemu.fuzz.injector import Injector, InjectionTarget


@dataclass(frozen=True)
class IterationTrace:
    """Execution context captured when a finding is recorded."""
    regs: dict[str, int]
    pc_freq: tuple[tuple[int, int], ...]
    new_pcs: tuple[int, ...]
    mmio_log: tuple[tuple[str, int, int, int], ...] | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "regs": {k: f"0x{int(v):08X}" for k, v in self.regs.items()},
            "pc_freq": [
                {"pc": f"0x{pc:08X}", "count": c} for pc, c in self.pc_freq
            ],
            "new_pcs": [f"0x{pc:08X}" for pc in self.new_pcs],
        }
        if self.mmio_log is not None:
            d["mmio_log"] = [
                {
                    "kind": k,
                    "addr": f"0x{a:08X}",
                    "size": s,
                    "value": f"0x{v:08X}",
                }
                for k, a, s, v in self.mmio_log
            ]
        return d


@dataclass(frozen=True)
class FuzzFinding:
    """A noteworthy finding from a fuzz iteration."""
    iteration: int
    kind: str  # "crash", "hang", "new_coverage", "unique_crash"
    input_data: bytes
    target_name: str
    target_kind: str
    new_pcs: int
    detail: str
    fault_report: dict | None = None
    trace: IterationTrace | None = None


@dataclass
class CorpusEntry:
    """An input in the corpus that discovered new coverage."""
    data: bytes
    target_name: str
    target_kind: str
    new_pcs: int
    iteration_found: int
    total_coverage_at_find: int


@dataclass
class FuzzStats:
    """Running statistics for a fuzzing session."""
    iterations: int = 0
    total_instructions: int = 0
    crashes: int = 0
    hangs: int = 0
    unique_crashes: int = 0
    new_coverage_inputs: int = 0
    corpus_size: int = 0
    coverage_at_start: int = 0
    coverage_current: int = 0
    start_time: float = 0.0
    elapsed: float = 0.0

    def execs_per_sec(self) -> float:
        if self.elapsed <= 0:
            return 0.0
        return self.iterations / self.elapsed


@dataclass
class FuzzEngine:
    """Coverage-guided fuzzer that runs against the emulator.

    Usage:
        engine = FuzzEngine(emu=emu, bus=bus)
        engine.setup(snapshot_name="fuzz_baseline")
        findings = engine.run(iterations=1000, steps_per_iter=5000)
    """

    emu: object  # Emulator instance
    bus: object  # PeripheralBus instance
    mutator: Mutator = field(default_factory=Mutator)
    injector: Injector | None = None
    stats: FuzzStats = field(default_factory=FuzzStats)
    corpus: list[CorpusEntry] = field(default_factory=list)
    findings: list[FuzzFinding] = field(default_factory=list)
    seed_corpus: list[bytes] = field(default_factory=list)

    # Configuration
    min_input_len: int = 1
    max_input_len: int = 256
    max_mutations: int = 4
    target_filter: list[str] | None = None
    mode: str = "random"  # "random", "round_robin", "all"
    capture_mmio: bool = False
    _mmio_ring_size: int = 256
    _snapshot_name: str = ""
    _crash_hashes: set[str] = field(default_factory=set)
    _global_coverage: set[int] = field(default_factory=set)
    _rng_seed: int | None = None

    def setup(self, snapshot_name: str = "__fuzz_baseline") -> str:
        """Prepare for fuzzing: save snapshot, discover targets, enable coverage."""
        self._snapshot_name = snapshot_name
        self.emu.save_snapshot(snapshot_name)

        if self.injector is None:
            self.injector = Injector(bus=self.bus, emu=self.emu)
        else:
            self.injector.emu = self.emu
        self.injector.discover_targets()

        if self.target_filter:
            allowed = {n.upper() for n in self.target_filter}
            self.injector.targets = [
                t for t in self.injector.targets
                if t.name.upper() in allowed or t.kind.upper() in allowed
            ]

        if not self.injector.targets:
            return "no injectable targets found"

        self.emu.coverage_enabled = True
        self._global_coverage = set(self.emu._coverage)
        self.stats.coverage_at_start = len(self._global_coverage)

        if self._rng_seed is not None:
            self.mutator.set_seed(self._rng_seed)
            self.injector.set_seed(self._rng_seed)

        targets_desc = ", ".join(
            f"{t.name}({t.kind})" for t in self.injector.targets
        )
        return f"ready: snapshot={snapshot_name}, targets=[{targets_desc}]"

    def seed(self, seed_value: int) -> None:
        """Set RNG seed for reproducibility."""
        self._rng_seed = seed_value
        self.mutator.set_seed(seed_value)
        if self.injector:
            self.injector.set_seed(seed_value)

    def add_seed_input(self, data: bytes) -> None:
        """Add a seed input to bootstrap the corpus."""
        if data:
            self.seed_corpus.append(bytes(data))

    def run(self, iterations: int = 1000, steps_per_iter: int = 5000) -> list[FuzzFinding]:
        """Run the fuzzer for the specified number of iterations."""
        if not self.injector or not self.injector.targets:
            return []

        self.stats.start_time = time.monotonic()
        session_findings: list[FuzzFinding] = []
        target_idx = 0

        mmio_log: deque | None = None
        orig_read = orig_write = None
        if self.capture_mmio:
            mmio_log = deque(maxlen=self._mmio_ring_size)
            orig_read = self.bus.read
            orig_write = self.bus.write

            def _tr(addr, size):
                val = orig_read(addr, size)
                mmio_log.append(("r", int(addr), int(size), int(val)))
                return val

            def _tw(addr, size, value):
                mmio_log.append(("w", int(addr), int(size), int(value)))
                return orig_write(addr, size, value)

            self.bus.read = _tr
            self.bus.write = _tw

        try:
            for i in range(iterations):
                self.stats.iterations += 1

                self.emu.load_snapshot(self._snapshot_name)
                self.emu._coverage.clear()
                self.emu._coverage_hits.clear()
                if mmio_log is not None:
                    mmio_log.clear()

                input_data = self._next_input(i)

                if self.mode == "all":
                    self.injector.inject_all(input_data)
                    target_name = "all"
                    target_kind = "all"
                    active_target = None
                else:
                    active_target = self._pick_target(target_idx)
                    target_idx += 1
                    self.injector.inject(active_target, input_data)
                    target_name = active_target.name
                    target_kind = active_target.kind

                stop_bp = self._install_stop_bp(active_target)

                crashed = False
                hung = False
                detail = ""
                try:
                    self.emu.run(steps_per_iter)
                    self.stats.total_instructions += steps_per_iter
                except Exception as e:
                    crashed = True
                    detail = str(e)

                returned = self._cleanup_stop_bp(stop_bp)

                if not crashed and not returned and hasattr(self.emu, '_pc_hist'):
                    threshold = max(
                        0, int(getattr(self.emu, 'stuck_loop_threshold', 5000))
                    )
                    if threshold > 0:
                        for count in self.emu._pc_hist.values():
                            if int(count) >= threshold:
                                hung = True
                                detail = "stuck loop detected"
                                break

                iter_coverage = set(self.emu._coverage)
                new_pcs = iter_coverage - self._global_coverage
                new_pcs_count = len(new_pcs)
                self._global_coverage |= iter_coverage

                has_finding = crashed or hung or new_pcs_count > 0
                trace = (
                    self._capture_trace(new_pcs, mmio_log) if has_finding else None
                )

                if crashed:
                    self.stats.crashes += 1
                    crash_hash = self._crash_hash(detail)
                    kind = "crash"
                    if crash_hash not in self._crash_hashes:
                        self._crash_hashes.add(crash_hash)
                        self.stats.unique_crashes += 1
                        kind = "unique_crash"

                    fault_report = None
                    if hasattr(self.emu, 'capture_fault_report'):
                        try:
                            fault_report = self.emu.capture_fault_report(
                                "fuzz_crash", detail=detail
                            )
                        except Exception:
                            pass

                    finding = FuzzFinding(
                        iteration=self.stats.iterations,
                        kind=kind,
                        input_data=bytes(input_data),
                        target_name=target_name,
                        target_kind=target_kind,
                        new_pcs=new_pcs_count,
                        detail=detail,
                        fault_report=fault_report,
                        trace=trace,
                    )
                    self.findings.append(finding)
                    session_findings.append(finding)

                elif hung:
                    self.stats.hangs += 1
                    finding = FuzzFinding(
                        iteration=self.stats.iterations,
                        kind="hang",
                        input_data=bytes(input_data),
                        target_name=target_name,
                        target_kind=target_kind,
                        new_pcs=new_pcs_count,
                        detail=detail,
                        trace=trace,
                    )
                    self.findings.append(finding)
                    session_findings.append(finding)

                if new_pcs_count > 0:
                    self.stats.new_coverage_inputs += 1
                    self.corpus.append(CorpusEntry(
                        data=bytes(input_data),
                        target_name=target_name,
                        target_kind=target_kind,
                        new_pcs=new_pcs_count,
                        iteration_found=self.stats.iterations,
                        total_coverage_at_find=len(self._global_coverage),
                    ))
                    self.stats.corpus_size = len(self.corpus)
                    if not crashed and not hung:
                        finding = FuzzFinding(
                            iteration=self.stats.iterations,
                            kind="new_coverage",
                            input_data=bytes(input_data),
                            target_name=target_name,
                            target_kind=target_kind,
                            new_pcs=new_pcs_count,
                            detail=f"+{new_pcs_count} PCs",
                            trace=trace,
                        )
                        self.findings.append(finding)
                        session_findings.append(finding)

                self.stats.coverage_current = len(self._global_coverage)
        finally:
            if orig_read is not None:
                self.bus.read = orig_read
                self.bus.write = orig_write

        self.stats.elapsed = time.monotonic() - self.stats.start_time
        return session_findings

    def replay(
        self,
        finding_index: int,
        *,
        steps: int = 5000,
        enable_trace: bool = False,
    ) -> dict:
        """Replay a finding deterministically, returning detailed execution info."""
        if finding_index < 0 or finding_index >= len(self.findings):
            raise IndexError(
                f"finding index {finding_index} out of range "
                f"(0..{len(self.findings) - 1})"
            )
        if not self._snapshot_name:
            raise RuntimeError("no snapshot — run 'fuzz setup' first")

        finding = self.findings[finding_index]

        self.emu.load_snapshot(self._snapshot_name)
        self.emu._coverage.clear()
        self.emu._coverage_hits.clear()

        target = self._find_target(finding.target_name, finding.target_kind)

        if enable_trace and hasattr(self.emu, "trace_enabled"):
            self.emu.trace_enabled = True

        mmio_log: deque[tuple[str, int, int, int]] = deque(maxlen=4096)
        orig_read = self.bus.read
        orig_write = self.bus.write

        def _tr(addr, size):
            val = orig_read(addr, size)
            mmio_log.append(("r", int(addr), int(size), int(val)))
            return val

        def _tw(addr, size, value):
            mmio_log.append(("w", int(addr), int(size), int(value)))
            return orig_write(addr, size, value)

        self.bus.read = _tr
        self.bus.write = _tw

        if finding.target_kind == "all" and self.injector:
            self.injector.inject_all(finding.input_data)
        elif target is not None and self.injector:
            self.injector.inject(target, finding.input_data)

        stop_bp = self._install_stop_bp(target)

        crashed = False
        detail = ""
        try:
            self.emu.run(steps)
        except Exception as e:
            crashed = True
            detail = str(e)
        finally:
            self.bus.read = orig_read
            self.bus.write = orig_write
            if enable_trace and hasattr(self.emu, "trace_enabled"):
                self.emu.trace_enabled = False

        returned = self._cleanup_stop_bp(stop_bp)

        new_pcs = set(self.emu._coverage) - self._global_coverage
        trace = self._capture_trace(new_pcs, mmio_log)

        fault_report = None
        if crashed and hasattr(self.emu, "capture_fault_report"):
            try:
                fault_report = self.emu.capture_fault_report(
                    "replay_crash", detail=detail
                )
            except Exception:
                pass

        return {
            "finding_index": finding_index,
            "finding_kind": finding.kind,
            "input_hex": finding.input_data.hex(),
            "input_len": len(finding.input_data),
            "target_name": finding.target_name,
            "target_kind": finding.target_kind,
            "crashed": crashed,
            "returned": returned,
            "detail": detail,
            "trace": trace,
            "fault_report": fault_report,
        }

    def format_replay(self, result: dict) -> str:
        """Format a replay result as a human-readable string."""
        status = (
            "CRASH" if result["crashed"]
            else "returned" if result["returned"]
            else "completed"
        )
        lines = [
            f"replay finding #{result['finding_index']} ({result['finding_kind']})",
            f"target: {result['target_kind']}:{result['target_name']}",
            f"input:  {result['input_len']}B "
            f"{result['input_hex'][:64]}{'...' if result['input_len'] > 32 else ''}",
            f"result: {status}",
        ]
        if result["detail"]:
            lines.append(f"detail: {result['detail']}")

        trace: IterationTrace | None = result.get("trace")
        if trace is not None:
            regs = trace.regs
            keys = [k for k in ("r0", "r1", "r2", "r3", "sp", "lr", "pc") if k in regs]
            if keys:
                lines.append(
                    "regs:   "
                    + " ".join(f"{k}=0x{regs[k]:08X}" for k in keys)
                )
            extra = [k for k in sorted(regs) if k not in keys]
            if extra:
                lines.append(
                    "        "
                    + " ".join(f"{k}=0x{regs[k]:08X}" for k in extra[:8])
                )

            if trace.pc_freq:
                lines.append(f"top PCs ({len(trace.pc_freq)}):")
                for pc, count in trace.pc_freq[:10]:
                    lines.append(f"  0x{pc:08X}  {count:6d}")
                if len(trace.pc_freq) > 10:
                    lines.append(f"  ... and {len(trace.pc_freq) - 10} more")

            if trace.new_pcs:
                lines.append(f"new coverage: +{len(trace.new_pcs)} PCs")

            if trace.mmio_log:
                reads = sum(1 for k, *_ in trace.mmio_log if k == "r")
                writes = len(trace.mmio_log) - reads
                lines.append(
                    f"mmio: {reads} reads, {writes} writes "
                    f"(last {len(trace.mmio_log)}):"
                )
                for k, addr, size, val in list(trace.mmio_log)[-10:]:
                    lines.append(
                        f"  {k.upper()} 0x{addr:08X} sz={size} val=0x{val:08X}"
                    )

        fault = result.get("fault_report")
        if fault:
            lines.append(f"fault:  {fault.get('reason', 'unknown')}")

        return "\n".join(lines)

    # ── internal helpers ──────────────────────────────────────────

    def _capture_trace(
        self, new_pcs: set[int], mmio_log: deque | None = None,
    ) -> IterationTrace:
        regs: dict[str, int] = {}
        if hasattr(self.emu, "read_regs"):
            regs = {
                k: int(v) & 0xFFFFFFFF
                for k, v in self.emu.read_regs().items()
            }

        pc_freq = sorted(
            ((int(k), int(v)) for k, v in self.emu._pc_hist.items()),
            key=lambda x: x[1],
            reverse=True,
        )[:32]

        mmio: tuple[tuple[str, int, int, int], ...] | None = None
        if mmio_log is not None:
            mmio = tuple(mmio_log)

        return IterationTrace(
            regs=regs,
            pc_freq=tuple(pc_freq),
            new_pcs=tuple(sorted(new_pcs)),
            mmio_log=mmio,
        )

    def _find_target(
        self, name: str, kind: str,
    ) -> InjectionTarget | None:
        if not self.injector:
            return None
        for t in self.injector.targets:
            if t.name == name and t.kind == kind:
                return t
        for t in self.injector.targets:
            if t.name == name:
                return t
        return None

    def _install_stop_bp(self, target: InjectionTarget | None) -> int | None:
        if target is None or target.kind != "function":
            return None
        cfg = target.fn_config
        if cfg is None:
            return None
        addr: int | None = None
        if cfg.stop == "return" and cfg.return_addr:
            addr = cfg.return_addr & ~1
        elif cfg.stop == "pc" and cfg.stop_pc:
            addr = cfg.stop_pc & ~1
        if addr is not None and hasattr(self.emu, "add_breakpoint"):
            self.emu.add_breakpoint(addr)
        return addr

    def _cleanup_stop_bp(self, addr: int | None) -> bool:
        if addr is None:
            return False
        if hasattr(self.emu, "remove_breakpoint"):
            self.emu.remove_breakpoint(addr)
        bp = getattr(self.emu, "last_pc_break", None)
        if bp is not None and (int(bp) & ~1) == addr:
            return True
        return False

    def _next_input(self, iteration: int) -> bytearray:
        if iteration < len(self.seed_corpus):
            data = bytearray(self.seed_corpus[iteration])
            if self.max_input_len > 0 and len(data) > self.max_input_len:
                data = data[:self.max_input_len]
            return data
        if self.corpus:
            base = self.mutator._rng.choice(self.corpus).data
            if len(self.corpus) > 1 and self.mutator._rng.random() < 0.1:
                other = self.mutator._rng.choice(self.corpus).data
                return self.mutator.splice(base, other, max_len=self.max_input_len)
            return self.mutator.mutate(
                base, self.max_mutations, max_len=self.max_input_len,
            )
        return self.mutator.generate(self.min_input_len, self.max_input_len)

    def _pick_target(self, idx: int) -> InjectionTarget:
        targets = self.injector.targets
        if self.mode == "round_robin":
            return targets[idx % len(targets)]
        return self.mutator._rng.choice(targets)

    def _crash_hash(self, detail: str) -> str:
        pc = getattr(self.emu, 'pc', 0)
        return f"{pc:08x}:{detail[:64]}"

    def format_stats(self) -> str:
        s = self.stats
        lines = [
            f"iterations:      {s.iterations}",
            f"exec/sec:        {s.execs_per_sec():.1f}",
            f"corpus size:     {s.corpus_size}",
            f"crashes:         {s.crashes} ({s.unique_crashes} unique)",
            f"hangs:           {s.hangs}",
            f"new cov inputs:  {s.new_coverage_inputs}",
            f"coverage start:  {s.coverage_at_start} PCs",
            f"coverage now:    {s.coverage_current} PCs",
            f"coverage gained: +{s.coverage_current - s.coverage_at_start} PCs",
        ]
        return "\n".join(lines)

    def format_findings(self, max_show: int = 20) -> str:
        if not self.findings:
            return "no findings"
        lines = [f"{len(self.findings)} finding(s):"]
        for f in self.findings[:max_show]:
            data_preview = f.input_data[:16].hex()
            if len(f.input_data) > 16:
                data_preview += "..."
            tag = " [trace]" if f.trace is not None else ""
            lines.append(
                f"  [{f.iteration:5d}] {f.kind:14s} "
                f"{f.target_kind}:{f.target_name:8s} "
                f"+{f.new_pcs}PCs  "
                f"data={data_preview}  {f.detail}{tag}"
            )
        if len(self.findings) > max_show:
            lines.append(f"  ... and {len(self.findings) - max_show} more")
        return "\n".join(lines)

    def export_findings(self, path: Path) -> int:
        entries = []
        for f in self.findings:
            entry: dict = {
                "iteration": f.iteration,
                "kind": f.kind,
                "input_hex": f.input_data.hex(),
                "input_len": len(f.input_data),
                "target_name": f.target_name,
                "target_kind": f.target_kind,
                "new_pcs": f.new_pcs,
                "detail": f.detail,
            }
            if f.fault_report:
                safe_report = {}
                for k, v in f.fault_report.items():
                    try:
                        json.dumps(v)
                        safe_report[k] = v
                    except (TypeError, ValueError):
                        safe_report[k] = str(v)
                entry["fault_report"] = safe_report
            if f.trace is not None:
                entry["trace"] = f.trace.to_dict()
            entries.append(entry)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
        return len(entries)

    def export_corpus(self, directory: Path) -> int:
        directory.mkdir(parents=True, exist_ok=True)
        for i, entry in enumerate(self.corpus):
            filename = f"id_{i:06d}_{entry.target_kind}_{entry.target_name}.bin"
            (directory / filename).write_bytes(entry.data)
        return len(self.corpus)

    def import_corpus(self, directory: Path, target_name: str | None = None) -> int:
        if not directory.is_dir():
            return 0
        count = 0
        for p in sorted(directory.iterdir()):
            if p.is_file():
                data = p.read_bytes()
                if data:
                    self.add_seed_input(data)
                    count += 1
        return count

    def reset(self) -> None:
        self.stats = FuzzStats()
        self.corpus.clear()
        self.findings.clear()
        self._crash_hashes.clear()
        self._global_coverage.clear()
