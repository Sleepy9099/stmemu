from __future__ import annotations

from stmemu.peripherals.registers import RegisterPeripheral, RegisterSpec


class CortexMCorePeripheral(RegisterPeripheral):
    """
    Minimal model for the Cortex-M Private Peripheral Bus block.
    """

    PPB_BASE = 0xE0000000
    PPB_SIZE = 0x00100000

    _SCB_VTOR = 0xED08
    _SCB_ICSR = 0xED04
    _SCB_SHPR1 = 0xED18
    _SCB_SHPR2 = 0xED1C
    _SCB_SHPR3 = 0xED20
    _SCB_DEMCR = 0xEDFC
    _DWT_CTRL = 0x1000
    _DWT_CYCCNT = 0x1004
    _DEMCR_TRCENA = 1 << 24
    _DWT_CTRL_CYCCNTENA = 1 << 0
    _SYST_CSR = 0xE010
    _SYST_RVR = 0xE014
    _SYST_CVR = 0xE018
    _NVIC_ISER_BASE = 0xE100
    _NVIC_ICER_BASE = 0xE180
    _NVIC_ISPR_BASE = 0xE200
    _NVIC_ICPR_BASE = 0xE280
    _NVIC_IABR_BASE = 0xE300
    _NVIC_IPR_BASE = 0xE400
    _NVIC_WORDS = 8
    _NVIC_IPR_WORDS = 60
    _EXC_NMI = 2
    _EXC_SVC = 11
    _EXC_PENDSV = 14
    _EXC_SYSTICK = 15
    _SYST_CSR_ENABLE = 1 << 0
    _SYST_CSR_TICKINT = 1 << 1
    _SYST_CSR_COUNTFLAG = 1 << 16

    def __init__(self, vtor: int = 0):
        super().__init__("CORE")
        self._irq_enabled: list[int] = [0] * self._NVIC_WORDS
        self._irq_pending: list[int] = [0] * self._NVIC_WORDS
        self._irq_active: list[int] = [0] * self._NVIC_WORDS
        self._irq_priority: list[int] = [0] * 240
        self._sys_priority: list[int] = [0] * 16
        self._system_pending: dict[str, bool] = {
            "SysTick": False,
            "PendSV": False,
            "NMI": False,
        }
        self._active_exceptions: list[int] = []
        self.add_register(RegisterSpec(name="SCB.ICSR", offset=self._SCB_ICSR, on_read=self._on_read_icsr, on_write=self._on_write_icsr))
        self.add_register(RegisterSpec(name="SCB.VTOR", offset=self._SCB_VTOR, reset_value=vtor))
        self.add_register(RegisterSpec(name="SCB.DEMCR", offset=self._SCB_DEMCR))
        self.add_register(RegisterSpec(
            name="SCB.SHPR1", offset=self._SCB_SHPR1,
            on_read=self._on_read_shpr1, on_write=self._on_write_shpr1,
        ))
        self.add_register(RegisterSpec(
            name="SCB.SHPR2", offset=self._SCB_SHPR2,
            on_read=self._on_read_shpr2, on_write=self._on_write_shpr2,
        ))
        self.add_register(RegisterSpec(
            name="SCB.SHPR3", offset=self._SCB_SHPR3,
            on_read=self._on_read_shpr3, on_write=self._on_write_shpr3,
        ))
        self.add_register(RegisterSpec(name="DWT.CTRL", offset=self._DWT_CTRL))
        self.add_register(
            RegisterSpec(
                name="DWT.CYCCNT",
                offset=self._DWT_CYCCNT,
            )
        )
        self.add_register(RegisterSpec(name="SysTick.CTRL", offset=self._SYST_CSR))
        self.add_register(
            RegisterSpec(
                name="SysTick.LOAD",
                offset=self._SYST_RVR,
                on_write=self._on_write_systick_load,
            )
        )
        self.add_register(
            RegisterSpec(
                name="SysTick.VAL",
                offset=self._SYST_CVR,
                on_write=self._on_write_systick_val,
            )
        )
        self._add_nvic_bank("NVIC.ISER", self._NVIC_ISER_BASE, self._read_enable_word, self._write_iser_word)
        self._add_nvic_bank("NVIC.ICER", self._NVIC_ICER_BASE, self._read_enable_word, self._write_icer_word)
        self._add_nvic_bank("NVIC.ISPR", self._NVIC_ISPR_BASE, self._read_pending_word, self._write_ispr_word)
        self._add_nvic_bank("NVIC.ICPR", self._NVIC_ICPR_BASE, self._read_pending_word, self._write_icpr_word)
        self._add_nvic_bank("NVIC.IABR", self._NVIC_IABR_BASE, self._read_active_word, self._ignore_write_word)
        for i in range(self._NVIC_IPR_WORDS):
            offset = self._NVIC_IPR_BASE + i * 4
            self.add_register(RegisterSpec(
                name=f"NVIC.IPR{i}",
                offset=offset,
                on_read=self._make_ipr_read(i),
                on_write=self._make_ipr_write(i),
            ))

    @property
    def vtor(self) -> int:
        return self.read_register_value(self._SCB_VTOR)

    def set_irq_pending(self, irq: int, pending: bool = True) -> None:
        word, bit = self._irq_index(irq)
        mask = 1 << bit
        if pending:
            self._irq_pending[word] |= mask
        else:
            self._irq_pending[word] &= ~mask
        self._sync_irq_words(word)

    def set_irq_enabled(self, irq: int, enabled: bool = True) -> None:
        word, bit = self._irq_index(irq)
        mask = 1 << bit
        if enabled:
            self._irq_enabled[word] |= mask
        else:
            self._irq_enabled[word] &= ~mask
        self._sync_irq_words(word)

    def set_system_pending(self, name: str, pending: bool = True) -> None:
        key = self._normalize_system_name(name)
        self._system_pending[key] = bool(pending)
        self._values[self._SCB_ICSR] = self._build_icsr_value()

    def irq_state(self, irq: int) -> dict[str, bool]:
        word, bit = self._irq_index(irq)
        mask = 1 << bit
        return {
            "enabled": bool(self._irq_enabled[word] & mask),
            "pending": bool(self._irq_pending[word] & mask),
            "active": bool(self._irq_active[word] & mask),
        }

    def pending_irqs(self) -> list[int]:
        pending: list[int] = []
        for word, value in enumerate(self._irq_pending):
            bits = value
            while bits:
                lsb = bits & -bits
                bit = lsb.bit_length() - 1
                pending.append(word * 32 + bit)
                bits &= bits - 1
        return pending

    def enabled_irqs(self) -> list[int]:
        enabled: list[int] = []
        for word, value in enumerate(self._irq_enabled):
            bits = value
            while bits:
                lsb = bits & -bits
                bit = lsb.bit_length() - 1
                enabled.append(word * 32 + bit)
                bits &= bits - 1
        return enabled

    def pending_system_exceptions(self) -> list[str]:
        return [name for name, pending in self._system_pending.items() if pending]

    def current_active_exception(self) -> int:
        return self._active_exceptions[-1] if self._active_exceptions else 0

    def next_pending_exception(
        self, primask: bool = False, basepri: int | bool = False,
    ) -> int | None:
        """Return the highest-priority pending exception that can preempt.

        Considers:
        - PRIMASK: blocks all configurable exceptions (not NMI)
        - BASEPRI: blocks exceptions with priority >= basepri value
        - Active exception priority: only higher-priority (lower number)
          exceptions can preempt
        """
        basepri_val = 0
        if isinstance(basepri, bool):
            basepri_val = 0xFF if basepri else 0
        else:
            basepri_val = int(basepri) & 0xFF

        current_priority = self._running_priority()

        best_exc: int | None = None
        best_priority = current_priority

        if self._system_pending["NMI"]:
            nmi_pri = self.exception_priority(self._EXC_NMI)
            if nmi_pri < best_priority:
                best_exc = self._EXC_NMI
                best_priority = nmi_pri

        if not primask:
            for exc_num, pending in (
                (self._EXC_PENDSV, self._system_pending["PendSV"]),
                (self._EXC_SYSTICK, self._system_pending["SysTick"]),
            ):
                if not pending:
                    continue
                pri = self.exception_priority(exc_num)
                if basepri_val and pri >= basepri_val:
                    continue
                if pri < best_priority:
                    best_exc = exc_num
                    best_priority = pri

            for irq in self.pending_irqs():
                if not (self._irq_enabled[irq // 32] & (1 << (irq % 32))):
                    continue
                if self._irq_active[irq // 32] & (1 << (irq % 32)):
                    continue
                exc_num = 16 + irq
                pri = self.exception_priority(exc_num)
                if basepri_val and pri >= basepri_val:
                    continue
                if pri < best_priority:
                    best_exc = exc_num
                    best_priority = pri

        return best_exc

    def _running_priority(self) -> int:
        """Return the priority of the currently executing exception, or 0x100 for Thread mode."""
        if not self._active_exceptions:
            return 0x100
        best = 0x100
        for exc in self._active_exceptions:
            p = self.exception_priority(exc)
            if p < best:
                best = p
        return best

    def enter_exception(self, exc_num: int) -> None:
        number = int(exc_num)
        self.clear_pending_exception(number)
        self._set_active_exception(number, True)

    def exit_exception(self, exc_num: int) -> None:
        number = int(exc_num)
        self._set_active_exception(number, False)

    def clear_pending_exception(self, exc_num: int) -> None:
        number = int(exc_num)
        if number >= 16:
            self.set_irq_pending(number - 16, False)
            return
        if number == self._EXC_NMI:
            self.set_system_pending("NMI", False)
        elif number == self._EXC_PENDSV:
            self.set_system_pending("PendSV", False)
        elif number == self._EXC_SYSTICK:
            self.set_system_pending("SysTick", False)

    def exception_name(self, exc_num: int) -> str:
        number = int(exc_num)
        if number >= 16:
            return f"IRQ{number - 16}"
        names = {
            0: "Thread",
            self._EXC_NMI: "NMI",
            self._EXC_SVC: "SVC",
            self._EXC_PENDSV: "PendSV",
            self._EXC_SYSTICK: "SysTick",
        }
        return names.get(number, f"Exception{number}")

    def tick(self, cycles: int) -> None:
        # The DWT cycle counter only runs when tracing is enabled
        # (DEMCR.TRCENA) and the counter itself is enabled (DWT_CTRL.CYCCNTENA),
        # matching real Cortex-M hardware. Firmware that uses CYCCNT (ChibiOS,
        # ArduPilot, ...) sets both before relying on it.
        demcr = self.read_register_value(self._SCB_DEMCR)
        dwt_ctrl = self.read_register_value(self._DWT_CTRL)
        if (demcr & self._DEMCR_TRCENA) and (dwt_ctrl & self._DWT_CTRL_CYCCNTENA):
            cyccnt = self.read_register_value(self._DWT_CYCCNT)
            self.write_register_value(self._DWT_CYCCNT, (cyccnt + cycles) & 0xFFFFFFFF)

        ctrl = self.read_register_value(self._SYST_CSR)
        if not (ctrl & self._SYST_CSR_ENABLE):
            return

        load = self.read_register_value(self._SYST_RVR) & 0x00FFFFFF
        if load == 0:
            load = 0x00FFFFFF

        value = self.read_register_value(self._SYST_CVR) & 0x00FFFFFF
        period = load + 1
        # The counter decrements each cycle and fires when it reaches 0. From a
        # non-zero value that takes `value` cycles (so landing exactly on 0
        # counts); when already resting at 0 it must count a full period before
        # the next reach-zero. The old `value < cycles` test was off by one in
        # both directions (missed the exact-zero case, and spuriously fired
        # while sitting at 0).
        cycles_to_zero = value if value > 0 else period
        wrapped = cycles > 0 and cycles >= cycles_to_zero
        value = (value - cycles) % period
        if wrapped:
            self.write_register_value(self._SYST_CSR, ctrl | self._SYST_CSR_COUNTFLAG)
            if ctrl & self._SYST_CSR_TICKINT:
                self.set_system_pending("SysTick", True)
        self.write_register_value(self._SYST_CVR, value)

    def _on_read_icsr(self, current: int) -> int:
        return self._build_icsr_value()

    def _on_write_icsr(self, current: int, next_value: int) -> int:
        del current
        if next_value & (1 << 25):
            self.set_system_pending("SysTick", True)
        if next_value & (1 << 26):
            self.set_system_pending("SysTick", False)
        if next_value & (1 << 28):
            self.set_system_pending("PendSV", True)
        if next_value & (1 << 27):
            self.set_system_pending("PendSV", False)
        if next_value & (1 << 31):
            self.set_system_pending("NMI", True)
        return self._build_icsr_value()

    def _on_write_systick_load(self, current: int, next_value: int) -> int:
        return next_value & 0x00FFFFFF

    def _on_write_systick_val(self, current: int, next_value: int) -> int:
        # ARM: writing any value to SYST_CVR clears it to 0 and clears COUNTFLAG
        ctrl = self.read_register_value(self._SYST_CSR)
        if ctrl & self._SYST_CSR_COUNTFLAG:
            self.write_register_value(self._SYST_CSR, ctrl & ~self._SYST_CSR_COUNTFLAG)
        return 0

    def _add_nvic_bank(
        self,
        prefix: str,
        base_offset: int,
        read_fn,
        write_fn,
    ) -> None:
        for word in range(self._NVIC_WORDS):
            offset = base_offset + (word * 4)
            self.add_register(
                RegisterSpec(
                    name=f"{prefix}{word}",
                    offset=offset,
                    on_read=self._make_word_read(read_fn, word),
                    on_write=self._make_word_write(write_fn, word),
                )
            )

    def _make_word_read(self, fn, word: int):
        def _read(current: int) -> int:
            del current
            return int(fn(word)) & 0xFFFFFFFF

        return _read

    def _make_word_write(self, fn, word: int):
        def _write(current: int, next_value: int) -> int:
            del current
            return int(fn(word, next_value)) & 0xFFFFFFFF

        return _write

    def _read_enable_word(self, word: int) -> int:
        return self._irq_enabled[word]

    def _write_iser_word(self, word: int, value: int) -> int:
        self._irq_enabled[word] |= value & 0xFFFFFFFF
        return self._sync_irq_words(word)

    def _write_icer_word(self, word: int, value: int) -> int:
        self._irq_enabled[word] &= ~(value & 0xFFFFFFFF)
        return self._sync_irq_words(word)

    def _read_pending_word(self, word: int) -> int:
        return self._irq_pending[word]

    def _write_ispr_word(self, word: int, value: int) -> int:
        self._irq_pending[word] |= value & 0xFFFFFFFF
        return self._sync_irq_words(word)

    def _write_icpr_word(self, word: int, value: int) -> int:
        self._irq_pending[word] &= ~(value & 0xFFFFFFFF)
        return self._sync_irq_words(word)

    def _read_active_word(self, word: int) -> int:
        return self._irq_active[word]

    def _ignore_write_word(self, word: int, value: int) -> int:
        del value
        return self._irq_active[word]

    def _make_ipr_read(self, word: int):
        def _read(current: int) -> int:
            base_irq = word * 4
            val = 0
            for i in range(4):
                irq = base_irq + i
                if irq < len(self._irq_priority):
                    val |= (self._irq_priority[irq] & 0xFF) << (i * 8)
            return val
        return _read

    def _make_ipr_write(self, word: int):
        def _write(current: int, next_value: int) -> int:
            base_irq = word * 4
            for i in range(4):
                irq = base_irq + i
                if irq < len(self._irq_priority):
                    self._irq_priority[irq] = (next_value >> (i * 8)) & 0xFF
            return next_value
        return _write

    def irq_priority(self, irq: int) -> int:
        if 0 <= irq < len(self._irq_priority):
            return self._irq_priority[irq]
        return 0

    def set_irq_priority(self, irq: int, priority: int) -> None:
        if 0 <= irq < len(self._irq_priority):
            self._irq_priority[irq] = priority & 0xFF

    def exception_priority(self, exc_num: int) -> int:
        """Return the effective priority for an exception number.

        Fixed priorities: Reset=-3, NMI=-2, HardFault=-1.
        Configurable: exceptions 4-15 via SHPR, IRQs 0+ via NVIC_IPR.
        """
        if exc_num < 0:
            return -1
        if exc_num == 1:
            return -3
        if exc_num == self._EXC_NMI:
            return -2
        if exc_num == 3:
            return -1
        if 4 <= exc_num <= 15:
            return self._sys_priority[exc_num]
        if exc_num >= 16:
            return self.irq_priority(exc_num - 16)
        return 0

    def set_system_priority(self, exc_num: int, priority: int) -> None:
        if 4 <= exc_num <= 15:
            self._sys_priority[exc_num] = priority & 0xFF

    def _on_read_shpr1(self, current: int) -> int:
        return (
            (self._sys_priority[4])
            | (self._sys_priority[5] << 8)
            | (self._sys_priority[6] << 16)
            | (self._sys_priority[7] << 24)
        )

    def _on_write_shpr1(self, current: int, next_value: int) -> int:
        self._sys_priority[4] = next_value & 0xFF
        self._sys_priority[5] = (next_value >> 8) & 0xFF
        self._sys_priority[6] = (next_value >> 16) & 0xFF
        self._sys_priority[7] = (next_value >> 24) & 0xFF
        return next_value

    def _on_read_shpr2(self, current: int) -> int:
        return (
            (self._sys_priority[8])
            | (self._sys_priority[9] << 8)
            | (self._sys_priority[10] << 16)
            | (self._sys_priority[11] << 24)
        )

    def _on_write_shpr2(self, current: int, next_value: int) -> int:
        self._sys_priority[8] = next_value & 0xFF
        self._sys_priority[9] = (next_value >> 8) & 0xFF
        self._sys_priority[10] = (next_value >> 16) & 0xFF
        self._sys_priority[11] = (next_value >> 24) & 0xFF
        return next_value

    def _on_read_shpr3(self, current: int) -> int:
        return (
            (self._sys_priority[12])
            | (self._sys_priority[13] << 8)
            | (self._sys_priority[14] << 16)
            | (self._sys_priority[15] << 24)
        )

    def _on_write_shpr3(self, current: int, next_value: int) -> int:
        self._sys_priority[12] = next_value & 0xFF
        self._sys_priority[13] = (next_value >> 8) & 0xFF
        self._sys_priority[14] = (next_value >> 16) & 0xFF
        self._sys_priority[15] = (next_value >> 24) & 0xFF
        return next_value

    def _sync_irq_words(self, word: int) -> int:
        self.write_register_value(self._NVIC_ISER_BASE + (word * 4), self._irq_enabled[word])
        self.write_register_value(self._NVIC_ICER_BASE + (word * 4), self._irq_enabled[word])
        self.write_register_value(self._NVIC_ISPR_BASE + (word * 4), self._irq_pending[word])
        self.write_register_value(self._NVIC_ICPR_BASE + (word * 4), self._irq_pending[word])
        self.write_register_value(self._NVIC_IABR_BASE + (word * 4), self._irq_active[word])
        self._values[self._SCB_ICSR] = self._build_icsr_value()
        return self._irq_pending[word]

    def _build_icsr_value(self) -> int:
        value = 0
        active = self.current_active_exception() & 0x1FF
        if active:
            value |= active
        if len(self._active_exceptions) <= 1:
            value |= 1 << 11
        if any(self._irq_pending):
            value |= 1 << 22
        pending_exc = self.next_pending_exception(primask=False)
        if pending_exc is not None:
            value |= (pending_exc & 0x1FF) << 12
        if self._system_pending["SysTick"]:
            value |= 1 << 26
        if self._system_pending["PendSV"]:
            value |= 1 << 28
        if self._system_pending["NMI"]:
            value |= 1 << 31
        return value & 0xFFFFFFFF

    def _irq_index(self, irq: int) -> tuple[int, int]:
        irq_num = int(irq)
        if irq_num < 0 or irq_num >= self._NVIC_WORDS * 32:
            raise ValueError(f"irq out of range: {irq_num}")
        return divmod(irq_num, 32)

    def _normalize_system_name(self, name: str) -> str:
        lookup = {
            "systick": "SysTick",
            "sys_tick": "SysTick",
            "pendsv": "PendSV",
            "pend_sv": "PendSV",
            "nmi": "NMI",
        }
        key = lookup.get(str(name).strip().lower())
        if key is None:
            raise ValueError(f"unknown system exception: {name}")
        return key

    def _set_active_exception(self, exc_num: int, active: bool) -> None:
        number = int(exc_num)
        if active:
            if number not in self._active_exceptions:
                self._active_exceptions.append(number)
        else:
            self._active_exceptions = [n for n in self._active_exceptions if n != number]

        if number >= 16:
            irq = number - 16
            word, bit = self._irq_index(irq)
            mask = 1 << bit
            if active:
                self._irq_active[word] |= mask
            else:
                self._irq_active[word] &= ~mask
            self._sync_irq_words(word)
            return

        self._values[self._SCB_ICSR] = self._build_icsr_value()

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base.update(
            {
                "irq_enabled": [int(x) & 0xFFFFFFFF for x in self._irq_enabled],
                "irq_pending": [int(x) & 0xFFFFFFFF for x in self._irq_pending],
                "irq_active": [int(x) & 0xFFFFFFFF for x in self._irq_active],
                "irq_priority": [int(x) & 0xFF for x in self._irq_priority],
                "sys_priority": [int(x) & 0xFF for x in self._sys_priority],
                "system_pending": {k: bool(v) for k, v in self._system_pending.items()},
                "active_exceptions": [int(x) for x in self._active_exceptions],
            }
        )
        return base

    def restore_state(self, state: object) -> None:
        super().restore_state(state)
        if not isinstance(state, dict):
            return

        irq_enabled = state.get("irq_enabled")
        if isinstance(irq_enabled, list):
            self._irq_enabled = [int(x) & 0xFFFFFFFF for x in irq_enabled[: self._NVIC_WORDS]]
            self._irq_enabled += [0] * max(0, self._NVIC_WORDS - len(self._irq_enabled))

        irq_pending = state.get("irq_pending")
        if isinstance(irq_pending, list):
            self._irq_pending = [int(x) & 0xFFFFFFFF for x in irq_pending[: self._NVIC_WORDS]]
            self._irq_pending += [0] * max(0, self._NVIC_WORDS - len(self._irq_pending))

        irq_active = state.get("irq_active")
        if isinstance(irq_active, list):
            self._irq_active = [int(x) & 0xFFFFFFFF for x in irq_active[: self._NVIC_WORDS]]
            self._irq_active += [0] * max(0, self._NVIC_WORDS - len(self._irq_active))

        irq_priority = state.get("irq_priority")
        if isinstance(irq_priority, list):
            for i, v in enumerate(irq_priority[:240]):
                self._irq_priority[i] = int(v) & 0xFF

        sys_priority = state.get("sys_priority")
        if isinstance(sys_priority, list):
            for i, v in enumerate(sys_priority[:16]):
                self._sys_priority[i] = int(v) & 0xFF

        system_pending = state.get("system_pending")
        if isinstance(system_pending, dict):
            merged = dict(self._system_pending)
            for key, value in system_pending.items():
                if key in merged:
                    merged[key] = bool(value)
            self._system_pending = merged

        active_exceptions = state.get("active_exceptions")
        if isinstance(active_exceptions, list):
            self._active_exceptions = [int(x) for x in active_exceptions]

        for word in range(self._NVIC_WORDS):
            self._sync_irq_words(word)
