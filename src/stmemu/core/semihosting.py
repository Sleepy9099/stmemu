from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Optional

from stmemu.utils.logger import get_logger

log = get_logger(__name__)

# ARM semihosting operation numbers
SYS_OPEN = 0x01
SYS_CLOSE = 0x02
SYS_WRITEC = 0x03
SYS_WRITE0 = 0x04
SYS_WRITE = 0x05
SYS_READ = 0x06
SYS_READC = 0x07
SYS_SEEK = 0x0A
SYS_FLEN = 0x0C
SYS_TMPNAM = 0x0D
SYS_REMOVE = 0x0E
SYS_RENAME = 0x0F
SYS_CLOCK = 0x10
SYS_TIME = 0x11
SYS_ERRNO = 0x13
SYS_GET_CMDLINE = 0x15
SYS_HEAPINFO = 0x16
SYS_EXIT = 0x18
SYS_EXIT_EXTENDED = 0x20

# BKPT 0xAB opcode (Thumb)
BKPT_SEMIHOST = 0xBEAB


@dataclass
class SemihostingHandler:
    """Handles ARM semihosting calls from firmware.

    When firmware executes BKPT 0xAB, R0 contains the operation
    number and R1 points to the parameter block in memory.
    """

    enabled: bool = True
    _output_buffer: bytearray = field(default_factory=bytearray)
    _console_echo: bool = field(default=True)

    @property
    def output(self) -> bytes:
        return bytes(self._output_buffer)

    def drain_output(self) -> bytes:
        data = bytes(self._output_buffer)
        self._output_buffer.clear()
        return data

    def handle(self, op: int, r1: int, mem_read, mem_write, uc) -> int:
        """Handle a semihosting call. Returns the result value for R0."""
        if not self.enabled:
            return -1

        if op == SYS_WRITEC:
            # R1 points to a single character
            try:
                data = bytes(mem_read(r1, 1))
                self._emit(data)
            except Exception:
                pass
            return 0

        if op == SYS_WRITE0:
            # R1 points to a null-terminated string
            try:
                buf = bytearray()
                addr = r1
                while len(buf) < 4096:
                    b = bytes(mem_read(addr, 1))
                    if b[0] == 0:
                        break
                    buf.append(b[0])
                    addr += 1
                self._emit(bytes(buf))
            except Exception:
                pass
            return 0

        if op == SYS_WRITE:
            # R1 points to: [fd, data_ptr, length]
            try:
                params = bytes(mem_read(r1, 12))
                _fd = int.from_bytes(params[0:4], "little")
                data_ptr = int.from_bytes(params[4:8], "little")
                length = int.from_bytes(params[8:12], "little")
                if length > 0 and length < 0x10000:
                    data = bytes(mem_read(data_ptr, length))
                    self._emit(data)
                return 0  # 0 = all bytes written
            except Exception:
                return -1

        if op == SYS_READC:
            return -1  # No stdin support

        if op == SYS_EXIT or op == SYS_EXIT_EXTENDED:
            log.info("Semihosting: firmware requested exit")
            return 0

        if op == SYS_ERRNO:
            return 0

        if op == SYS_CLOCK:
            return 0  # Return 0 centiseconds

        if op == SYS_TIME:
            import time
            return int(time.time())

        if op == SYS_HEAPINFO:
            # R1 points to a 4-word block to fill: [heap_base, heap_limit, stack_base, stack_limit]
            try:
                info = (0x20010000).to_bytes(4, "little")  # heap_base
                info += (0x20020000).to_bytes(4, "little")  # heap_limit
                info += (0x20020000).to_bytes(4, "little")  # stack_base
                info += (0x20010000).to_bytes(4, "little")  # stack_limit
                mem_write(r1, info)
            except Exception:
                pass
            return 0

        if op == SYS_FLEN:
            return 0

        if op == SYS_OPEN:
            # Return handle 1 for stdout/stderr, -1 for anything else
            try:
                params = bytes(mem_read(r1, 12))
                name_ptr = int.from_bytes(params[0:4], "little")
                name_len = int.from_bytes(params[8:12], "little")
                name_data = bytes(mem_read(name_ptr, min(name_len, 256)))
                name = name_data.split(b"\x00")[0].decode("utf-8", errors="replace")
                if name in (":tt", ":STDOUT", ":STDERR", ""):
                    return 1  # stdout handle
                return -1  # unsupported file
            except Exception:
                return -1

        if op == SYS_CLOSE:
            return 0

        log.debug("Semihosting: unhandled op 0x%02X", op)
        return -1

    def _emit(self, data: bytes) -> None:
        self._output_buffer.extend(data)
        if self._console_echo:
            try:
                text = data.decode("utf-8", errors="replace")
                sys.stderr.write(text)
                sys.stderr.flush()
            except Exception:
                pass
