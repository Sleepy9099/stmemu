"""Coverage-guided fuzzer engine for STM32 emulator."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from stmemu.fuzz.mutator import Mutator
from stmemu.fuzz.injector import Injector, InjectionTarget


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
    target_filter: list[str] | None = None  # limit to specific target names
    mode: str = "random"  # "random", "round_robin", "all"
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
        """Run the fuzzer for the specified number of iterations.

        Returns list of findings (crashes, hangs, new coverage).
        """
        if not self.injector or not self.injector.targets:
            return []

        self.stats.start_time = time.monotonic()
        session_findings: list[FuzzFinding] = []
        target_idx = 0

        for i in range(iterations):
            self.stats.iterations += 1

            # 1. Restore snapshot
            self.emu.load_snapshot(self._snapshot_name)

            # 2. Clear per-iteration coverage so we only see this iteration's PCs
            self.emu._coverage.clear()
            self.emu._coverage_hits.clear()

            # 3. Generate or mutate input
            input_data = self._next_input(i)

            # 4. Inject into target(s)
            if self.mode == "all":
                self.injector.inject_all(input_data)
                target_name = "all"
                target_kind = "all"
            else:
                target = self._pick_target(target_idx)
                target_idx += 1
                self.injector.inject(target, input_data)
                target_name = target.name
                target_kind = target.kind

            # 5. Run emulator
            crashed = False
            hung = False
            detail = ""
            try:
                self.emu.run(steps_per_iter)
                self.stats.total_instructions += steps_per_iter
            except Exception as e:
                crashed = True
                detail = str(e)

            # 6. Check for hang (stuck loop detection)
            if not crashed and hasattr(self.emu, '_pc_hist'):
                threshold = max(0, int(getattr(self.emu, 'stuck_loop_threshold', 5000)))
                if threshold > 0:
                    for count in self.emu._pc_hist.values():
                        if int(count) >= threshold:
                            hung = True
                            detail = "stuck loop detected"
                            break

            # 7. Analyze coverage against the engine's global set
            iter_coverage = set(self.emu._coverage)
            new_pcs = iter_coverage - self._global_coverage
            new_pcs_count = len(new_pcs)
            self._global_coverage |= iter_coverage

            # 8. Record findings
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
                    )
                    self.findings.append(finding)
                    session_findings.append(finding)

            self.stats.coverage_current = len(self._global_coverage)

        self.stats.elapsed = time.monotonic() - self.stats.start_time
        return session_findings

    def _next_input(self, iteration: int) -> bytearray:
        """Pick or generate the next fuzz input."""
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
        """Pick injection target based on mode."""
        targets = self.injector.targets
        if self.mode == "round_robin":
            return targets[idx % len(targets)]
        # default: random
        return self.mutator._rng.choice(targets)

    def _crash_hash(self, detail: str) -> str:
        """Simple hash for crash deduplication."""
        pc = getattr(self.emu, 'pc', 0)
        return f"{pc:08x}:{detail[:64]}"

    def format_stats(self) -> str:
        """Format current statistics as a human-readable string."""
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
        """Format findings list."""
        if not self.findings:
            return "no findings"
        lines = [f"{len(self.findings)} finding(s):"]
        for f in self.findings[:max_show]:
            data_preview = f.input_data[:16].hex()
            if len(f.input_data) > 16:
                data_preview += "..."
            lines.append(
                f"  [{f.iteration:5d}] {f.kind:14s} "
                f"{f.target_kind}:{f.target_name:8s} "
                f"+{f.new_pcs}PCs  "
                f"data={data_preview}  {f.detail}"
            )
        if len(self.findings) > max_show:
            lines.append(f"  ... and {len(self.findings) - max_show} more")
        return "\n".join(lines)

    def export_findings(self, path: Path) -> int:
        """Export findings to a JSON file. Returns count exported."""
        entries = []
        for f in self.findings:
            entry = {
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
            entries.append(entry)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
        return len(entries)

    def export_corpus(self, directory: Path) -> int:
        """Export corpus inputs to a directory (one file per entry)."""
        directory.mkdir(parents=True, exist_ok=True)
        for i, entry in enumerate(self.corpus):
            filename = f"id_{i:06d}_{entry.target_kind}_{entry.target_name}.bin"
            (directory / filename).write_bytes(entry.data)
        return len(self.corpus)

    def import_corpus(self, directory: Path, target_name: str | None = None) -> int:
        """Import seed inputs from a directory of binary files."""
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
        """Reset fuzzer state for a new session."""
        self.stats = FuzzStats()
        self.corpus.clear()
        self.findings.clear()
        self._crash_hashes.clear()
        self._global_coverage.clear()
