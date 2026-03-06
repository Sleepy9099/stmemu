from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass
from pathlib import Path

_MODULE_BACKUP: dict[str, object] = {}


def _set_module(name: str, module: object) -> None:
    if name not in _MODULE_BACKUP:
        _MODULE_BACKUP[name] = sys.modules.get(name)
    sys.modules[name] = module


if "capstone" not in sys.modules:
    capstone_stub = types.ModuleType("capstone")

    class _Cs:
        def __init__(self, *args, **kwargs) -> None:
            self.detail = False

        def disasm(self, code, addr, count=0):
            del code, addr, count
            return []

    capstone_stub.Cs = _Cs
    capstone_stub.CS_ARCH_ARM = 0
    capstone_stub.CS_MODE_THUMB = 0
    _set_module("capstone", capstone_stub)

if "unicorn" not in sys.modules:
    unicorn_stub = types.ModuleType("unicorn")
    unicorn_const_stub = types.ModuleType("unicorn.unicorn_const")
    unicorn_const_stub.UC_HOOK_CODE = 0
    unicorn_stub.unicorn_const = unicorn_const_stub
    _set_module("unicorn", unicorn_stub)
    _set_module("unicorn.unicorn_const", unicorn_const_stub)

if "stmemu.core.emulator" not in sys.modules:
    emu_stub = types.ModuleType("stmemu.core.emulator")

    @dataclass
    class _PcRegWrite:
        pc: int
        peripheral: str
        register: str
        value: int
        cond: object = None

    class _Emulator:
        pass

    emu_stub.PcRegWrite = _PcRegWrite
    emu_stub.Emulator = _Emulator
    _set_module("stmemu.core.emulator", emu_stub)

from stmemu.shell.commands import Commands


class _FakeEmu:
    def __init__(self) -> None:
        self._regs = {
            "r0": 0,
            "r1": 0,
            "r2": 0,
            "r3": 0,
            "r4": 0,
            "r5": 0,
            "r6": 0,
            "r7": 0,
            "r8": 0,
            "r9": 0,
            "r10": 0,
            "r11": 0,
            "r12": 0,
            "sp": 0,
            "lr": 0,
            "pc": 0,
        }
        self._watchpoints: list[dict[str, object]] = []
        self._next_watch_id = 1
        self._snapshots: dict[str, object] = {}
        self.pc_reg_writes: list[object] = []
        self._pc_cpu_actions: list[dict[str, object]] = []
        self._pc_cpu_next_id = 1

        self.last_pc_break = None
        self.last_mmio_break = None
        self.last_watch_break = None
        self.pc = 0
        self.last_step = None
        self.last_run = None
        self.trace_enabled = False
        self.trace_mmio_only = False
        self.trace_until_pc = None
        self.trace_callret_only = False
        self.trace_branch_only = False
        self.trace_reg_deltas = False
        self.trace_history: list[str] = []
        self.trace_history_limit = 50000
        self._trace_call_depth = 0
        self._trace_reset_count = 0
        self.auto_fault_report = True
        self.last_fault_report = None
        self._fail_step = False
        self._fail_run = False

    def read_regs(self) -> dict[str, int]:
        return dict(self._regs)

    def write_reg(self, name: str, value: int) -> None:
        key = name.lower()
        if key not in self._regs:
            raise KeyError(key)
        val = int(value) & 0xFFFFFFFF
        self._regs[key] = val
        if key == "pc":
            self.pc = val

    def add_watchpoint(self, start: int, end: int, access: str = "rw", name: str | None = None) -> int:
        chars = {c for c in str(access).lower().strip() if c in "rwx"}
        if not chars:
            raise ValueError("access must include at least one of: r, w, x")
        canonical = "".join(c for c in "rwx" if c in chars)
        wid = self._next_watch_id
        self._next_watch_id += 1
        self._watchpoints.append(
            {
                "id": wid,
                "name": str(name) if name else f"0x{start:08X}-0x{end:08X}",
                "start": int(start),
                "end": int(end),
                "access": canonical,
            }
        )
        return wid

    def list_watchpoints(self) -> list[dict[str, object]]:
        return list(self._watchpoints)

    def remove_watchpoint(self, wid: int) -> bool:
        before = len(self._watchpoints)
        self._watchpoints = [wp for wp in self._watchpoints if int(wp["id"]) != int(wid)]
        return len(self._watchpoints) != before

    def clear_watchpoints(self) -> int:
        count = len(self._watchpoints)
        self._watchpoints.clear()
        return count

    def step(self, count: int = 1) -> None:
        self.last_step = count
        if self._fail_step:
            raise RuntimeError("step failed")

    def run(self, count: int = 1) -> None:
        self.last_run = count
        if self._fail_run:
            raise RuntimeError("run failed")

    def capture_snapshot(self, name: str = "(current)"):
        return types.SimpleNamespace(
            name=name,
            regs=self.read_regs(),
            memory=[types.SimpleNamespace(start=0x20000000, data=b"\x00" * 16)],
            model_state={},
            exception_stack=(),
            exception_return_stack=(),
            pc_hist={},
        )

    def save_snapshot(self, name: str):
        snap = self.capture_snapshot(name)
        self._snapshots[name] = snap
        return snap

    def get_snapshot(self, name: str):
        return self._snapshots.get(name)

    def list_snapshots(self) -> list[str]:
        return sorted(self._snapshots.keys())

    def clear_snapshots(self) -> int:
        count = len(self._snapshots)
        self._snapshots.clear()
        return count

    def remove_snapshot(self, name: str) -> bool:
        if name not in self._snapshots:
            return False
        del self._snapshots[name]
        return True

    def load_snapshot(self, name: str):
        if name not in self._snapshots:
            raise KeyError(name)
        snap = self._snapshots[name]
        self._regs.update(snap.regs)
        return snap

    def diff_snapshots(self, left, right) -> dict[str, object]:
        reg_changes = []
        for key in sorted(set(left.regs) | set(right.regs)):
            lval = left.regs.get(key)
            rval = right.regs.get(key)
            if lval != rval:
                reg_changes.append((key, lval, rval))
        return {
            "left": left.name,
            "right": right.name,
            "reg_changes": reg_changes,
            "memory_changed_ranges": [],
            "memory_changed_bytes": 0,
        }

    def add_pc_reg_write(self, action) -> None:
        self.pc_reg_writes.append(action)

    def add_pc_cpu_action(
        self,
        kind: str,
        pc: int,
        *,
        reg: str | None = None,
        value: int | None = None,
        skip_bytes: int | None = None,
        once: bool = False,
    ) -> int:
        aid = self._pc_cpu_next_id
        self._pc_cpu_next_id += 1
        self._pc_cpu_actions.append(
            {
                "id": aid,
                "kind": kind,
                "pc": int(pc) & ~1,
                "reg": reg,
                "value": value,
                "skip_bytes": skip_bytes,
                "once": bool(once),
                "hits": 0,
            }
        )
        return aid

    def list_pc_cpu_actions(self) -> list[dict[str, object]]:
        return list(self._pc_cpu_actions)

    def clear_pc_cpu_actions(self) -> int:
        count = len(self._pc_cpu_actions)
        self._pc_cpu_actions.clear()
        return count

    def remove_pc_cpu_action(self, aid: int) -> bool:
        before = len(self._pc_cpu_actions)
        self._pc_cpu_actions = [a for a in self._pc_cpu_actions if int(a["id"]) != int(aid)]
        return len(self._pc_cpu_actions) != before

    def _trace_reset_pending(self) -> None:
        self._trace_reset_count += 1

    def capture_fault_report(self, reason: str = "fault", *, detail: str | None = None, pc_override: int | None = None):
        return {
            "reason": reason,
            "detail": "" if detail is None else detail,
            "pc": int(pc_override if pc_override is not None else self._regs.get("pc", 0)),
            "regs": self.read_regs(),
            "active_exception": 0,
            "active_exception_name": "Thread",
            "exception_depth": 0,
            "pending_irqs": [],
            "pending_system": [],
            "cfsr": 0,
            "hfsr": 0,
            "mmfar": 0,
            "bfar": 0,
            "icsr": 0,
            "cfsr_flags": [],
            "hfsr_flags": [],
            "stacked_frame": None,
        }

    def record_fault(self, reason: str, *, detail: str | None = None, pc_override: int | None = None):
        report = self.capture_fault_report(reason, detail=detail, pc_override=pc_override)
        self.last_fault_report = report
        return report

    def clear_fault_report(self) -> None:
        self.last_fault_report = None


class _FakeBus:
    pass


class ShellCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.emu = _FakeEmu()
        self.cmds = Commands(emu=self.emu, bus=_FakeBus())

    def test_reg_set_updates_register(self) -> None:
        out = self.cmds.cmd_reg(["set", "r0", "0x1234"])
        self.assertEqual(out, "r0 <- 0x00001234")
        self.assertEqual(self.emu.read_regs()["r0"], 0x1234)

    def test_reg_set_rejects_unknown_register(self) -> None:
        out = self.cmds.cmd_reg(["set", "foo", "1"])
        self.assertEqual(out, "unknown reg: foo")

    def test_watchpoint_add_list_and_clear(self) -> None:
        out_add = self.cmds.cmd_wp(["add", "0x20000000-0x20000010", "rw"])
        self.assertIn("added watchpoint #", out_add)

        out_list = self.cmds.cmd_wp([])
        self.assertIn("watchpoints:", out_list)
        self.assertIn("(rw)", out_list)

        out_clear = self.cmds.cmd_wp(["clear", "1"])
        self.assertEqual(out_clear, "cleared watchpoint: 1")

        out_empty = self.cmds.cmd_wp(["list"])
        self.assertEqual(out_empty, "watchpoints: (none)")

    def test_step_reports_watchpoint_hit(self) -> None:
        self.emu.last_watch_break = {
            "id": 3,
            "start": 0x20000000,
            "end": 0x20000010,
            "access": "w",
            "address": 0x20000008,
            "size": 4,
            "value": 0xDEADBEEF,
        }
        out = self.cmds.cmd_step([])
        self.assertIn("WP HIT: #3", out)
        self.assertIn("@0x20000008", out)

    def test_snapshot_save_list_and_clear(self) -> None:
        out_save = self.cmds.cmd_snap(["save", "init"])
        self.assertIn("snapshot saved: init", out_save)

        out_list = self.cmds.cmd_snap(["list"])
        self.assertIn("snapshots:", out_list)
        self.assertIn("init", out_list)

        out_clear = self.cmds.cmd_snap(["clear", "init"])
        self.assertEqual(out_clear, "snapshot cleared: init")

    def test_snapshot_diff_against_current(self) -> None:
        self.emu.write_reg("r0", 1)
        self.cmds.cmd_snap(["save", "a"])
        self.emu.write_reg("r0", 2)
        out = self.cmds.cmd_snap(["diff", "a"])
        self.assertIn("snapshot diff: a -> (current)", out)
        self.assertIn("reg changes = 1", out)

    def test_atpc_cpu_reg_action(self) -> None:
        out = self.cmds.cmd_atpc(["reg", "0x08000100", "r0", "=", "0", "once"])
        self.assertIn("pc-cpu action #1 added", out)
        listed = self.cmds.cmd_atpc_list([])
        self.assertIn("CPU  #1 @0x8000100 r0 = 0x0 once", listed)

    def test_ret_and_skip_aliases(self) -> None:
        out_ret = self.cmds.cmd_ret(["0x08000200", "r0=0x1234", "once"])
        out_skip = self.cmds.cmd_skip(["0x08000300", "4"])
        self.assertIn("pc-cpu action #1 added", out_ret)
        self.assertIn("pc-cpu action #2 added", out_skip)

        listed = self.cmds.cmd_atpc_list([])
        self.assertIn("ret r0=0x1234 once", listed)
        self.assertIn("skip +0x4", listed)

        out_clear = self.cmds.cmd_atpc_clear(["1"])
        self.assertEqual(out_clear, "pc cpu action cleared: 1")

    def test_trace_mode_toggles(self) -> None:
        self.assertEqual(self.cmds.cmd_trace(["call"]), "trace call = on")
        self.assertTrue(self.emu.trace_callret_only)
        self.assertTrue(self.emu.trace_enabled)

        self.assertEqual(self.cmds.cmd_trace(["branch"]), "trace branch = on")
        self.assertTrue(self.emu.trace_branch_only)

        self.assertEqual(self.cmds.cmd_trace(["regs"]), "trace regs = on")
        self.assertTrue(self.emu.trace_reg_deltas)

        status = self.cmds.cmd_trace([])
        self.assertIn("call", status)
        self.assertIn("branch", status)
        self.assertIn("regs", status)

        self.assertEqual(self.cmds.cmd_trace(["off"]), "trace = off")
        self.assertFalse(self.emu.trace_enabled)
        self.assertEqual(self.emu._trace_reset_count, 1)

    def test_fault_command_and_auto_toggle(self) -> None:
        self.emu.record_fault("invalid_insn", detail="bad opcode")
        shown = self.cmds.cmd_fault([])
        self.assertIn("fault reason = invalid_insn", shown)
        self.assertIn("detail      = bad opcode", shown)

        self.assertEqual(self.cmds.cmd_fault(["auto", "off"]), "fault auto = off")
        self.assertFalse(self.emu.auto_fault_report)
        self.assertEqual(self.cmds.cmd_fault(["auto"]), "fault auto = off")

        self.assertEqual(self.cmds.cmd_fault(["clear"]), "fault report cleared")
        self.assertIsNone(self.emu.last_fault_report)

    def test_step_auto_fault_report_on_error(self) -> None:
        self.emu._fail_step = True
        out = self.cmds.cmd_step([])
        self.assertIn("error: step failed", out)
        self.assertIn("fault reason = step_error", out)

    def test_export_trace_json_and_clear(self) -> None:
        self.emu.trace_history = ["line one", "line two"]
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "trace.json"
            out = self.cmds.cmd_export(["trace", str(out_path), "clear"])
            self.assertIn("exported trace:", out)
            self.assertIn("lines=2", out)
            self.assertEqual(self.emu.trace_history, [])

            payload = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["line_count"], 2)
            self.assertEqual(payload["lines"], ["line one", "line two"])

    def test_export_snapdiff_csv(self) -> None:
        self.emu.write_reg("r0", 1)
        self.cmds.cmd_snap(["save", "base"])
        self.emu.write_reg("r0", 2)

        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "diff.csv"
            out = self.cmds.cmd_export(["snapdiff", str(out_path), "base", "current"])
            self.assertIn("exported snapdiff:", out)
            text = out_path.read_text(encoding="utf-8")
            self.assertIn("kind,left,right", text)
            self.assertIn("summary,base,(current)", text)
            self.assertIn("reg,,,r0", text)

    def test_scenario_run_with_include_wait_and_assert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            include_path = tmpdir / "common.scn"
            include_path.write_text(
                "reg set r1 0x2\n"
                "assert reg r1 == 0x2\n",
                encoding="utf-8",
            )
            scenario_path = tmpdir / "main.scn"
            scenario_path.write_text(
                "reg set pc 0x100\n"
                "wait pc 0x100 0\n"
                "reg set r0 0x1\n"
                "reg r0\n"
                "assert out contains 0x00000001\n"
                "include common.scn\n"
                "assert reg r1 == 0x2\n"
                "assert nofault\n",
                encoding="utf-8",
            )

            out = self.cmds.cmd_scenario(["run", str(scenario_path)])
            self.assertIn("scenario ok:", out)
            self.assertEqual(self.emu.read_regs()["r1"], 2)

    def test_scenario_failure_reports_location(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scenario_path = Path(tmp) / "bad.scn"
            scenario_path.write_text(
                "reg set r0 0x1\n"
                "assert reg r0 == 0x2\n",
                encoding="utf-8",
            )
            out = self.cmds.cmd_scenario([str(scenario_path)])
            self.assertIn("scenario failed:", out)
            self.assertIn("bad.scn:2:", out)


if __name__ == "__main__":
    unittest.main()


def tearDownModule() -> None:
    for name, original in _MODULE_BACKUP.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
