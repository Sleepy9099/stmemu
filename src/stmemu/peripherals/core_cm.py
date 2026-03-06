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
    _SCB_DEMCR = 0xEDFC
    _DWT_CTRL = 0x1000
    _DWT_CYCCNT = 0x1004
    _SYST_CSR = 0xE010
    _SYST_RVR = 0xE014
    _SYST_CVR = 0xE018
    _NVIC_ISER_BASE = 0xE100
    _NVIC_ICER_BASE = 0xE180
    _NVIC_ISPR_BASE = 0xE200
    _NVIC_ICPR_BASE = 0xE280
    _NVIC_IABR_BASE = 0xE300
    _NVIC_WORDS = 8
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
        self._system_pending: dict[str, bool] = {
            "SysTick": False,
            "PendSV": False,
            "NMI": False,
        }
        self._active_exceptions: list[int] = []
        self.add_register(RegisterSpec(name="SCB.ICSR", offset=self._SCB_ICSR, on_read=self._on_read_icsr, on_write=self._on_write_icsr))
        self.add_register(RegisterSpec(name="SCB.VTOR", offset=self._SCB_VTOR, reset_value=vtor))
        self.add_register(RegisterSpec(name="SCB.DEMCR", offset=self._SCB_DEMCR))
        self.add_register(RegisterSpec(name="DWT.CTRL", offset=self._DWT_CTRL))
        self.add_register(
            RegisterSpec(
                name="DWT.CYCCNT",
                offset=self._DWT_CYCCNT,
                on_read=self._on_read_cyccnt,
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
                on_read=self._on_read_systick_val,
                on_write=self._on_write_systick_val,
            )
        )
        self._add_nvic_bank("NVIC.ISER", self._NVIC_ISER_BASE, self._read_enable_word, self._write_iser_word)
        self._add_nvic_bank("NVIC.ICER", self._NVIC_ICER_BASE, self._read_enable_word, self._write_icer_word)
        self._add_nvic_bank("NVIC.ISPR", self._NVIC_ISPR_BASE, self._read_pending_word, self._write_ispr_word)
        self._add_nvic_bank("NVIC.ICPR", self._NVIC_ICPR_BASE, self._read_pending_word, self._write_icpr_word)
        self._add_nvic_bank("NVIC.IABR", self._NVIC_IABR_BASE, self._read_active_word, self._ignore_write_word)

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

    def next_pending_exception(self, primask: bool = False, basepri: bool = False) -> int | None:
        candidates: list[int] = []

        if self._system_pending["NMI"]:
            candidates.append(self._EXC_NMI)

        # Without modeled priorities, treat BASEPRI as masking all configurable
        # exceptions (PendSV, SysTick, external IRQs). NMI remains unmasked.
        if not primask and not basepri:
            if self._system_pending["PendSV"]:
                candidates.append(self._EXC_PENDSV)
            if self._system_pending["SysTick"]:
                candidates.append(self._EXC_SYSTICK)
            for irq in self.pending_irqs():
                state = self.irq_state(irq)
                if state["enabled"]:
                    candidates.append(16 + irq)

        if not candidates:
            return None
        return min(candidates)

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
        self.write_register_value(self._DWT_CYCCNT, self.read_register_value(self._DWT_CYCCNT) + cycles)

        ctrl = self.read_register_value(self._SYST_CSR)
        if not (ctrl & self._SYST_CSR_ENABLE):
            return

        load = self.read_register_value(self._SYST_RVR) & 0x00FFFFFF
        if load == 0:
            load = 0x00FFFFFF

        value = self.read_register_value(self._SYST_CVR) & 0x00FFFFFF
        wrapped = cycles > 0 and value < cycles
        value = (value - cycles) % (load + 1)
        if wrapped:
            self.write_register_value(self._SYST_CSR, ctrl | self._SYST_CSR_COUNTFLAG)
            if ctrl & self._SYST_CSR_TICKINT:
                self.set_system_pending("SysTick", True)
        self.write_register_value(self._SYST_CVR, value)

    def _on_read_cyccnt(self, current: int) -> int:
        self.tick(10)
        return self.read_register_value(self._DWT_CYCCNT)

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

    def _on_read_systick_val(self, current: int) -> int:
        self.tick(1)
        return self.read_register_value(self._SYST_CVR)

    def _on_write_systick_load(self, current: int, next_value: int) -> int:
        return next_value & 0x00FFFFFF

    def _on_write_systick_val(self, current: int, next_value: int) -> int:
        return next_value & 0x00FFFFFF

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
