"""Scenario config loader — full emulation setup from a single YAML/JSON file.

Covers target definition, emulator settings, board topology, breakpoints,
register/memory pre-sets, timed events, and startup commands.

Example scenario.yaml:

  target:
    svd: stm32f411.svd
    firmware: firmware.bin
    base: 0x08000000
    sram_base: 0x20000000
    sram_size: 0x20000

  emulator:
    tick_scale: 1
    stuck_threshold: 5000
    interrupt_stuck_threshold: 50000000
    bus_policy: permissive

  board:
    uart_devices:
      - peripheral: USART1
        device: ublox
        mode: nmea
        lat: 34.7304
        lon: -86.5861

    i2c_devices:
      - peripheral: I2C1
        devices:
          - type: imu
            address: 0x68
            whoami_reg: 0x75
            whoami_value: 0x71

    gpio_levels:
      GPIOA:
        0: high

    adc:
      ADC1:
        default_sample: 2048
        trigger: TIM2

  breakpoints:
    pc:
      - 0x08001000
      - 0x08002000
    events:
      - kind: timer_update
        source: TIM2
      - kind: adc_eoc
    watchpoints:
      - start: 0x20000100
        end: 0x20000200
        access: rw

  registers:
    - peripheral: RCC
      register: AHB1ENR
      value: 0x01
    - reg: r0
      value: 0x00000000

  memory:
    - address: 0x20001000
      hex: "DEADBEEF"
    - address: 0x20002000
      file: test_data.bin

  timed_events:
    - at: 10000
      action: gpio_inject
      port: GPIOA
      pin: 0
      level: high
    - at: 50000
      action: uart_inject
      peripheral: USART1
      hex: "48656C6C6F"

  startup_commands:
    - "coverage on"
    - "mmio log on"
    - "run 1000"
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stmemu.utils.logger import get_logger

log = get_logger(__name__)


def _parse_int(v: Any) -> int:
    if isinstance(v, int):
        return v
    return int(str(v), 0)


def load_board_config(path: Path) -> dict[str, Any]:
    """Load a scenario/board config from YAML or JSON."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("pyyaml required for YAML configs")
        return yaml.safe_load(text) or {}
    return json.loads(text)


_KNOWN_TOP_KEYS = {
    "target", "emulator", "board", "bus_policy",
    "uart_devices", "i2c_devices", "spi_devices", "gpio_levels", "adc",
    "dma", "dmamux",
    "registers", "memory", "breakpoints", "timed_events",
    "startup_commands",
}

_KNOWN_EMULATOR_KEYS = {
    "tick_scale", "stuck_threshold", "interrupt_stuck_threshold",
    "bus_policy", "trace", "coverage",
}

_KNOWN_UART_KEYS = {
    "peripheral", "device", "name", "mode", "lat", "lon", "alt",
    "speed_knots", "rate_cycles", "ttff_ticks",
}

_KNOWN_I2C_DEV_KEYS = {
    "type", "address", "name", "whoami_reg", "whoami_value", "registers",
}


def validate_config(config: dict[str, Any]) -> list[str]:
    """Validate a scenario config, returning a list of warnings."""
    warnings: list[str] = []
    if not isinstance(config, dict):
        warnings.append("config must be a mapping")
        return warnings

    unknown_top = set(config.keys()) - _KNOWN_TOP_KEYS
    for k in sorted(unknown_top):
        if not isinstance(config[k], (dict, list)):
            warnings.append(f"unknown top-level key: '{k}'")

    emu_cfg = config.get("emulator", {})
    if isinstance(emu_cfg, dict):
        for k in emu_cfg:
            if k not in _KNOWN_EMULATOR_KEYS:
                warnings.append(f"unknown emulator key: '{k}'")

    for uart_cfg in config.get("uart_devices", []) + config.get("board", {}).get("uart_devices", []):
        if isinstance(uart_cfg, dict):
            for k in uart_cfg:
                if k not in _KNOWN_UART_KEYS:
                    warnings.append(f"unknown uart_device key: '{k}'")

    bp_cfg = config.get("breakpoints", {})
    if isinstance(bp_cfg, dict):
        for k in bp_cfg:
            if k not in ("pc", "events", "watchpoints"):
                warnings.append(f"unknown breakpoints key: '{k}'")

    for te in config.get("timed_events", []):
        if isinstance(te, dict):
            if "at" not in te:
                warnings.append("timed_event missing 'at' field")
            if "action" not in te:
                warnings.append("timed_event missing 'action' field")

    return warnings


def _bus_applied_configs(bus: object) -> list[dict[str, Any]]:
    """Per-session applied-config history, stored on the bus instance.

    Tracking applied configs on the bus (rather than a module global) scopes
    the double-apply guard to a single emulator session: a fresh bus starts
    with empty history, so configs applied by a previous session in the same
    process no longer suppress board topology in a new one.
    """
    configs = getattr(bus, "_applied_configs", None)
    if configs is None:
        configs = []
        try:
            setattr(bus, "_applied_configs", configs)
        except Exception:
            # Bus doesn't allow attribute assignment; fall back to a transient
            # list (guard degrades to "never previously applied" for this bus).
            pass
    return configs


def config_applied_count(bus: object) -> int:
    return len(_bus_applied_configs(bus))


def config_applied_summary(bus: object) -> list[dict[str, Any]]:
    return list(_bus_applied_configs(bus))


def apply_board_config(
    config: dict[str, Any],
    bus: object,
    emu: object | None = None,
    *,
    shell: object | None = None,
    base_dir: Path | None = None,
    source: str = "config",
) -> list[str]:
    """Apply a full scenario config. Returns status messages.

    Processes sections in order:
    1. emulator settings (tick_scale, thresholds, bus_policy)
    2. board topology (devices, GPIO, ADC) — also handles top-level keys
    3. registers (peripheral and CPU register pre-sets)
    4. memory (pre-load data)
    5. breakpoints (PC, event, watchpoint)
    6. timed_events (stored for later execution)
    7. startup_commands (shell commands)
    """
    messages: list[str] = []

    # Validate config
    warnings = validate_config(config)
    for w in warnings:
        messages.append(f"warning: {w}")

    # Track applied configs and prevent double-apply of board *device*
    # topology. DMA/DMAMUX request routing is deliberately excluded here: it is
    # an idempotent overlay (mapping stream request lines, not creating
    # devices), so a later routing-only config must still take effect.
    has_board_topology = any(
        k in config or k in config.get("board", {})
        for k in ("uart_devices", "i2c_devices", "spi_devices", "gpio_levels", "adc")
    )
    applied = _bus_applied_configs(bus)
    skip_topology = False
    if has_board_topology and applied:
        prev_sources = [c.get("_source", "?") for c in applied if c.get("_has_board")]
        if prev_sources:
            messages.append(
                f"board topology skipped: already applied from {prev_sources[0]}"
            )
            skip_topology = True
    applied.append({
        "_source": source,
        "_has_board": has_board_topology and not skip_topology,
        "_sections": [k for k in config if k != "target"],
    })

    # 1. Emulator settings
    emu_cfg = config.get("emulator", {})
    if isinstance(emu_cfg, dict) and emu is not None:
        msgs = _apply_emulator_settings(emu_cfg, emu, bus)
        messages.extend(msgs)

    # Top-level bus_policy (backward compat)
    policy = config.get("bus_policy")
    if policy:
        bus.access_policy = str(policy)
        messages.append(f"bus policy: {policy}")

    # 2. Board topology — check both "board" sub-key and top-level keys
    if not skip_topology:
        board = config.get("board", {})
        if isinstance(board, dict) and board:
            messages.extend(_apply_board_topology(board, bus, base_dir=base_dir))
        for key in ("uart_devices", "i2c_devices", "spi_devices", "gpio_levels", "adc"):
            if key in config and key not in (board if isinstance(board, dict) else {}):
                messages.extend(_apply_board_topology({key: config[key]}, bus, base_dir=base_dir))

    # 2b. DMA/DMAMUX request routing — applied on every config (even when the
    # device topology above is skipped as a double-apply), because mapping a
    # stream request is idempotent overlay state, not device creation.
    messages.extend(_apply_dma_routing(config, bus))

    # 3. Register pre-sets
    for reg_cfg in config.get("registers", []):
        msg = _apply_register(reg_cfg, bus, emu)
        messages.append(msg)

    # 4. Memory pre-loads
    for mem_cfg in config.get("memory", []):
        msg = _apply_memory(mem_cfg, emu, base_dir)
        messages.append(msg)

    # 5. Breakpoints
    bp_cfg = config.get("breakpoints", {})
    if isinstance(bp_cfg, dict) and emu is not None:
        msgs = _apply_breakpoints(bp_cfg, emu)
        messages.extend(msgs)

    # 6. Timed events — store on emulator for later
    timed = config.get("timed_events", [])
    if timed and emu is not None and hasattr(emu, "add_timed_event"):
        for te in timed:
            at = _parse_int(te.get("at", 0))
            action = str(te.get("action", ""))
            params = {k: v for k, v in te.items() if k not in ("at", "action")}
            emu.add_timed_event(at, action, **params)
        messages.append(f"timed events: {len(timed)} scheduled")

    # 7. Startup commands
    commands = config.get("startup_commands", [])
    if commands and shell is not None:
        for cmd_str in commands:
            shell.onecmd(str(cmd_str))
        messages.append(f"startup commands: {len(commands)} executed")

    return messages


def _apply_emulator_settings(
    cfg: dict[str, Any], emu: object, bus: object,
) -> list[str]:
    msgs: list[str] = []
    if "tick_scale" in cfg:
        emu.tick_scale = int(cfg["tick_scale"])
        msgs.append(f"emulator: tick_scale={emu.tick_scale}")
    if "stuck_threshold" in cfg:
        emu.stuck_loop_threshold = int(cfg["stuck_threshold"])
        msgs.append(f"emulator: stuck_threshold={emu.stuck_loop_threshold}")
    if "interrupt_stuck_threshold" in cfg:
        emu.interrupt_stuck_threshold = int(cfg["interrupt_stuck_threshold"])
        msgs.append(f"emulator: interrupt_stuck_threshold={emu.interrupt_stuck_threshold}")
    if "bus_policy" in cfg:
        bus.access_policy = str(cfg["bus_policy"])
        msgs.append(f"emulator: bus_policy={cfg['bus_policy']}")
    if "trace" in cfg and cfg["trace"]:
        emu.trace_enabled = True
        msgs.append("emulator: trace enabled")
    if "coverage" in cfg and cfg["coverage"]:
        emu.coverage_enabled = True
        msgs.append("emulator: coverage enabled")
    return msgs


def _apply_board_topology(
    board: dict[str, Any],
    bus: object,
    *,
    base_dir: Path | None = None,
) -> list[str]:
    msgs: list[str] = []
    for uart_cfg in board.get("uart_devices", []):
        msgs.append(_attach_uart_device(bus, uart_cfg))
    for i2c_cfg in board.get("i2c_devices", []):
        msgs.append(_attach_i2c_devices(bus, i2c_cfg))
    for spi_cfg in board.get("spi_devices", []):
        msgs.append(_attach_spi_device(bus, spi_cfg, base_dir=base_dir))
    for port_name, pins in board.get("gpio_levels", {}).items():
        msgs.append(_set_gpio_levels(bus, port_name, pins))
    for adc_name, adc_cfg in board.get("adc", {}).items():
        msgs.append(_configure_adc(bus, adc_name, adc_cfg))
    return msgs


def _apply_dma_routing(config: dict[str, Any], bus: object) -> list[str]:
    """Apply DMA/DMAMUX request-line routing from a config (idempotent overlay).

    Reads ``dma`` / ``dmamux`` from both the top level and the ``board`` block.
    """
    msgs: list[str] = []
    board = config.get("board", {})
    sources = [board, config] if isinstance(board, dict) else [config]
    for src in sources:
        dma_cfg = src.get("dma")
        if isinstance(dma_cfg, dict):
            for dma_name, cfg in dma_cfg.items():
                msgs.append(_configure_dma_streams(bus, dma_name, cfg))
        mux_cfg = src.get("dmamux")
        if isinstance(mux_cfg, dict):
            for mux_name, cfg in mux_cfg.items():
                msgs.append(_configure_dmamux(bus, mux_name, cfg))
    return msgs


def _apply_register(cfg: dict[str, Any], bus: object, emu: object | None) -> str:
    # CPU register
    reg_name = cfg.get("reg")
    if reg_name and emu is not None and hasattr(emu, "write_reg"):
        val = _parse_int(cfg.get("value", 0))
        try:
            emu.write_reg(str(reg_name), val)
            return f"register: {reg_name} = 0x{val:08X}"
        except Exception as e:
            return f"register: error setting {reg_name}: {e}"

    # Peripheral register
    periph = cfg.get("peripheral")
    register = cfg.get("register")
    if periph and register:
        model = bus.model_for_name(str(periph).upper())
        if model is None:
            return f"register: {periph} not found"
        val = _parse_int(cfg.get("value", 0))
        # Find register offset (and width) by name. Honor the register's
        # declared size so an 8/16-bit register isn't written as 32 bits,
        # which would spill into adjacent registers or be rejected.
        offset = None
        width = 4
        if hasattr(model, "peripheral"):
            for reg in model.peripheral.registers:
                if reg.name.upper() == str(register).upper():
                    offset = reg.offset
                    byte_width = max(1, int(getattr(reg, "size_bits", 32) or 32) // 8)
                    width = byte_width if byte_width in (1, 2, 4) else 4
                    break
        if offset is None:
            try:
                offset = _parse_int(register)
            except ValueError:
                return f"register: {periph}.{register} not found"
        model.write(offset, width, val)
        return f"register: {periph}.{register} = 0x{val:08X}"

    return "register: missing 'reg' or 'peripheral'+'register'"


def _apply_memory(cfg: dict[str, Any], emu: object | None, base_dir: Path | None) -> str:
    if emu is None or not hasattr(emu, "mem_write"):
        return "memory: no emulator"
    addr = _parse_int(cfg.get("address", 0))
    hex_data = cfg.get("hex")
    file_path = cfg.get("file")

    if hex_data:
        data = bytes.fromhex(str(hex_data))
        emu.mem_write(addr, data)
        return f"memory: wrote {len(data)}B to 0x{addr:08X}"
    elif file_path:
        path = Path(file_path)
        if base_dir and not path.is_absolute():
            path = base_dir / path
        try:
            data = path.read_bytes()
            emu.mem_write(addr, data)
            return f"memory: loaded {len(data)}B from {path} to 0x{addr:08X}"
        except OSError as e:
            return f"memory: error loading {path}: {e}"
    return "memory: missing 'hex' or 'file'"


def _apply_breakpoints(cfg: dict[str, Any], emu: object) -> list[str]:
    msgs: list[str] = []

    for addr in cfg.get("pc", []):
        a = _parse_int(addr)
        if hasattr(emu, "add_breakpoint"):
            emu.add_breakpoint(a)
            msgs.append(f"breakpoint: PC 0x{a:08X}")

    for ev_cfg in cfg.get("events", []):
        kind = str(ev_cfg.get("kind", ""))
        source = ev_cfg.get("source")
        if kind and hasattr(emu, "add_event_breakpoint"):
            bp_id = emu.add_event_breakpoint(kind, source=source)
            desc = f"breakpoint: event #{bp_id} {kind}"
            if source:
                desc += f" source={source}"
            msgs.append(desc)

    for wp_cfg in cfg.get("watchpoints", []):
        start = _parse_int(wp_cfg.get("start", 0))
        end = _parse_int(wp_cfg.get("end", start))
        access = str(wp_cfg.get("access", "rw"))
        if hasattr(emu, "add_watchpoint"):
            wid = emu.add_watchpoint(start, end, access=access, name="cfg")
            msgs.append(f"breakpoint: watchpoint #{wid} [{start:#010x}-{end:#010x}] ({access})")

    return msgs


# ── Board topology helpers (preserved from V0) ──────────────────

def _attach_uart_device(bus: object, cfg: dict[str, Any]) -> str:
    periph_name = str(cfg.get("peripheral", "")).upper()
    dev_type = str(cfg.get("device", "ublox")).lower()

    uart_model = bus.model_for_name(periph_name)
    if uart_model is None:
        return f"uart: {periph_name} not found"
    if not hasattr(uart_model, "inject_rx_bytes"):
        return f"uart: {periph_name} is not a UART"

    if dev_type in ("ublox", "ublox-gps"):
        from stmemu.external.ublox import UbloxGpsDevice
        dev = UbloxGpsDevice()
        dev.name = cfg.get("name", f"{periph_name.lower()}_gps")
        _INT_ATTRS = {"rate_cycles", "ttff_ticks"}
        for attr in ("mode", "lat", "lon", "alt", "speed_knots", "rate_cycles", "ttff_ticks"):
            if attr in cfg:
                val = cfg[attr]
                if attr == "mode":
                    pass
                elif attr in _INT_ATTRS:
                    val = _parse_int(val)
                elif isinstance(val, str):
                    val = float(val)
                setattr(dev, attr, val)
    else:
        return f"uart: unknown device type '{dev_type}'"

    from stmemu.external.serial_line import SerialLine
    line = SerialLine(dev.name, uart=uart_model, device=dev, bus=bus)
    bus.attach_serial_line(line)
    return f"uart: attached {dev_type} '{dev.name}' to {periph_name}"


def _attach_i2c_devices(bus: object, cfg: dict[str, Any]) -> str:
    periph_name = str(cfg.get("peripheral", "")).upper()
    i2c_model = bus.model_for_name(periph_name)
    if i2c_model is None:
        return f"i2c: {periph_name} not found"

    from stmemu.external.i2c_bus import I2cBus
    from stmemu.external.i2c_device import (
        RegisterI2cDevice, EepromI2cDevice, ImuI2cDevice,
    )

    i2c_bus = I2cBus(periph_name.lower())
    attached = []

    for dev_cfg in cfg.get("devices", []):
        dev_type = str(dev_cfg.get("type", "register")).lower()
        addr = int(str(dev_cfg.get("address", "0x50")), 0)

        if dev_type == "eeprom":
            dev = EepromI2cDevice(address=addr)
            dev.name = dev_cfg.get("name", f"eeprom_{addr:#x}")
        elif dev_type == "imu":
            whoami_reg = int(str(dev_cfg.get("whoami_reg", "0x75")), 0)
            whoami_value = int(str(dev_cfg.get("whoami_value", "0x71")), 0)
            dev = ImuI2cDevice(
                address=addr, whoami_reg=whoami_reg, whoami_value=whoami_value,
            )
            dev.name = dev_cfg.get("name", f"imu_{addr:#x}")
        elif dev_type in ("ms5611", "baro_ms5611"):
            from stmemu.external.ms5611 import Ms5611I2cDevice
            dev = Ms5611I2cDevice(address=addr)
            dev.name = dev_cfg.get("name", f"ms5611_{addr:#x}")
        elif dev_type in ("register", "sensor"):
            dev = RegisterI2cDevice(address=addr)
            dev.name = dev_cfg.get("name", f"reg_{addr:#x}")
            for reg_str, val in dev_cfg.get("registers", {}).items():
                dev.set_register(int(str(reg_str), 0), int(str(val), 0))
        else:
            attached.append(f"unknown:{dev_type}")
            continue

        i2c_bus.attach_device(dev)
        attached.append(f"{dev_type}@{addr:#x}")

    if hasattr(i2c_model, "attach_i2c_bus"):
        i2c_model.attach_i2c_bus(i2c_bus)

    return f"i2c: {periph_name} attached [{', '.join(attached)}]"


def _set_gpio_levels(bus: object, port_name: str, pins: dict) -> str:
    model = bus.model_for_name(port_name.upper())
    if model is None:
        return f"gpio: {port_name} not found"
    if not hasattr(model, "set_input_level"):
        return f"gpio: {port_name} is not a GPIO"

    count = 0
    for pin_s, level in pins.items():
        pin = int(pin_s)
        if isinstance(level, str):
            high = level.lower() in ("high", "1", "true")
        else:
            high = bool(level)
        model.set_input_level(pin, high)
        count += 1
    return f"gpio: {port_name} set {count} pin(s)"


def _attach_spi_device(
    bus: object,
    cfg: dict[str, Any],
    *,
    base_dir: Path | None = None,
) -> str:
    periph_name = str(cfg.get("peripheral", "")).upper()
    dev_type = str(cfg.get("type", "")).lower()

    spi_model = bus.model_for_name(periph_name)
    if spi_model is None:
        return f"spi: {periph_name} not found"
    if not hasattr(spi_model, "attach_device"):
        return f"spi: {periph_name} does not support device attach"

    dev, extra = _build_spi_device(dev_type, cfg, base_dir=base_dir)
    if dev is None:
        return f"spi: unknown device type '{dev_type}'"

    cs_port = cfg.get("cs_port")
    cs_pin = cfg.get("cs_pin")
    if cs_port is not None and cs_pin is not None:
        _wire_spi_cs(bus, dev, str(cs_port).upper(), int(_parse_int(cs_pin)))
        cs_desc = f" cs={cs_port}.{cs_pin}"
    else:
        # Auto-CS: latch onto the first GPIO pin to see a falling edge.
        _wire_spi_cs_auto(bus, dev)
        cs_desc = " cs=auto"

    spi_model.attach_device(dev)
    _spi_devices_register(bus, dev)
    return f"spi: attached {dev_type} '{dev.name}' to {periph_name}{cs_desc}{extra}"


def _build_spi_device(
    dev_type: str,
    cfg: dict[str, Any],
    *,
    base_dir: Path | None,
) -> tuple[object | None, str]:
    """Construct an SPI slave model. Returns (device, extra description)."""
    if dev_type in ("fm25v02a", "fram", "fm25v02"):
        from stmemu.external.fram import FramFm25v02a

        image_file = cfg.get("image_file") or cfg.get("image")
        image_path: Path | None = None
        if image_file:
            image_path = Path(str(image_file)).expanduser()
            if base_dir and not image_path.is_absolute():
                image_path = base_dir / image_path

        dev = FramFm25v02a(
            name=str(cfg.get("name", "fram")),
            image_path=image_path,
        )
        extra = f" image={image_path.name}" if image_path is not None else ""
        return dev, extra

    if dev_type in ("icm42688", "icm-42688", "icm42688p", "icm-42688-p"):
        from stmemu.external.spi_imu import Icm42688Device
        dev = Icm42688Device(name=str(cfg.get("name", "icm42688")))
        return dev, " whoami=0x47"

    if dev_type in ("bmi088_a", "bmi088-accel", "bmi088a", "bmi055_a"):
        from stmemu.external.spi_imu import Bmi088AccelDevice
        dev = Bmi088AccelDevice(name=str(cfg.get("name", "bmi088_a")))
        return dev, " whoami=0x1E"

    if dev_type in ("bmi088_g", "bmi088-gyro", "bmi088g", "bmi055_g"):
        from stmemu.external.spi_imu import Bmi088GyroDevice
        dev = Bmi088GyroDevice(name=str(cfg.get("name", "bmi088_g")))
        return dev, " whoami=0x0F"

    return None, ""


def _wire_spi_cs(bus: object, device: object, port_name: str, pin: int) -> None:
    """Drive the device's cs_select/cs_release from GPIO edge events."""

    def _on_edge(event):
        if str(getattr(event, "source", "")).upper() != port_name:
            return
        payload = getattr(event, "payload", None) or {}
        if int(payload.get("pin", -1)) != pin:
            return
        if payload.get("falling"):
            device.cs_select()
        elif payload.get("rising"):
            device.cs_release()

    bus.subscribe("gpio_edge", _on_edge)


def _wire_spi_cs_auto(bus: object, device: object) -> None:
    """CS auto-detection: latch onto whichever GPIO pin first falls.

    Many ArduPilot boards drive the FRAM CS through a GPIO line whose
    identity we don't know up front. To stay useful without per-board
    config, listen to every ``gpio_edge`` event and adopt the first pin
    that goes low as the chip-select. Once latched, only edges on that
    pin reach the device.
    """
    state = {"port": None, "pin": None}

    def _on_edge(event):
        payload = getattr(event, "payload", None) or {}
        src = str(getattr(event, "source", "")).upper()
        pin = int(payload.get("pin", -1))
        if state["port"] is None:
            if not payload.get("falling"):
                return
            state["port"] = src
            state["pin"] = pin
            device.cs_select()
            return
        if src != state["port"] or pin != state["pin"]:
            return
        if payload.get("falling"):
            device.cs_select()
        elif payload.get("rising"):
            device.cs_release()

    bus.subscribe("gpio_edge", _on_edge)


def _spi_devices_register(bus: object, device: object) -> None:
    table = getattr(bus, "_spi_attached_devices", None)
    if table is None:
        table = {}
        setattr(bus, "_spi_attached_devices", table)
    table[device.name] = device


def _configure_adc(bus: object, adc_name: str, cfg: dict[str, Any]) -> str:
    model = bus.model_for_name(adc_name.upper())
    if model is None:
        return f"adc: {adc_name} not found"

    parts = [f"adc: {adc_name}"]

    default_sample = cfg.get("default_sample")
    if default_sample is not None:
        model.default_sample = int(default_sample)
        parts.append(f"default={model.default_sample}")

    trigger = cfg.get("trigger")
    if trigger and hasattr(model, "set_external_trigger"):
        model.set_external_trigger(str(trigger))
        parts.append(f"trigger={trigger}")

    samples = cfg.get("samples")
    if samples and hasattr(model, "inject_samples"):
        model.inject_samples([int(s) for s in samples])
        parts.append(f"samples={len(samples)}")

    return " ".join(parts)


def _apply_stream_requests(bus: object, dma_name: str, streams: dict) -> tuple[int, str | None]:
    """Map ``{stream: {request: NAME}}`` onto a DMA controller's streams.

    Returns (count_mapped, error_message_or_None).
    """
    model = bus.model_for_name(str(dma_name).upper())
    if model is None or not hasattr(model, "set_stream_request"):
        return 0, f"unknown/unsupported DMA controller: {dma_name}"
    n = 0
    for skey, scfg in (streams or {}).items():
        try:
            stream = int(skey)
        except (TypeError, ValueError):
            continue
        request = scfg.get("request") if isinstance(scfg, dict) else scfg
        if request:
            model.set_stream_request(stream, str(request).upper())
            n += 1
    return n, None


def _configure_dma_streams(bus: object, dma_name: str, cfg: dict[str, Any]) -> str:
    streams = cfg.get("streams", cfg) if isinstance(cfg, dict) else {}
    n, err = _apply_stream_requests(bus, dma_name, streams)
    if err:
        return f"dma {dma_name}: {err}"
    return f"dma {dma_name}: {n} stream request(s) mapped"


# DMAMUX channel -> (DMA controller, stream) convention. On STM32 H7 DMAMUX1
# channels 0..7 drive DMA1 streams 0..7 and channels 8..15 drive DMA2 streams
# 0..7. V0 uses this symbolic mapping; exact numeric request IDs are out of
# scope.
def _dmamux_channel_target(mux_name: str, channel: int) -> tuple[str, int]:
    mux = str(mux_name).upper()
    if mux in ("DMAMUX1", "DMAMUX"):
        if channel < 8:
            return "DMA1", channel
        return "DMA2", channel - 8
    if mux == "DMAMUX2":
        return "BDMA", channel
    # Unknown mux: assume a single DMA1 with 1:1 channel->stream.
    return "DMA1", channel


def _configure_dmamux(bus: object, mux_name: str, cfg: dict[str, Any]) -> str:
    channels = cfg.get("channels", {}) if isinstance(cfg, dict) else {}
    mapped = 0
    misses: list[str] = []
    for ckey, ccfg in channels.items():
        try:
            channel = int(ckey)
        except (TypeError, ValueError):
            continue
        request = ccfg.get("request") if isinstance(ccfg, dict) else ccfg
        if not request:
            continue
        dma_name, stream = _dmamux_channel_target(mux_name, channel)
        model = bus.model_for_name(dma_name)
        if model is None or not hasattr(model, "set_stream_request"):
            misses.append(f"ch{channel}->{dma_name}")
            continue
        model.set_stream_request(stream, str(request).upper())
        mapped += 1
    msg = f"dmamux {mux_name}: {mapped} channel request(s) mapped"
    if misses:
        msg += f" (unmapped: {', '.join(misses)})"
    return msg
