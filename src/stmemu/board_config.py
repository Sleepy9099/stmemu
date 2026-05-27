"""Board topology loader — configures the emulator from a YAML/JSON board description.

Example board.yaml:

  uart_devices:
    - peripheral: USART1
      device: ublox
      mode: nmea
      rate_cycles: 100000
      lat: 34.7304
      lon: -86.5861

  i2c_devices:
    - peripheral: I2C1
      devices:
        - type: imu
          address: 0x68
          whoami_reg: 0x75
          whoami_value: 0x71
        - type: eeprom
          address: 0x50

  gpio_levels:
    GPIOA:
      0: high
      3: low
    GPIOB:
      5: high

  adc:
    ADC1:
      default_sample: 2048
      trigger: TIM2
      samples: [1000, 2000, 3000]

  bus_policy: permissive
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stmemu.utils.logger import get_logger

log = get_logger(__name__)


def load_board_config(path: Path) -> dict[str, Any]:
    """Load a board config from YAML or JSON."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("pyyaml required for YAML board configs")
        return yaml.safe_load(text) or {}
    return json.loads(text)


def apply_board_config(
    config: dict[str, Any],
    bus: object,
    emu: object | None = None,
) -> list[str]:
    """Apply a board config to the bus and emulator. Returns status messages."""
    messages: list[str] = []

    policy = config.get("bus_policy")
    if policy:
        bus.access_policy = str(policy)
        messages.append(f"bus policy: {policy}")

    for uart_cfg in config.get("uart_devices", []):
        msg = _attach_uart_device(bus, uart_cfg)
        messages.append(msg)

    for i2c_cfg in config.get("i2c_devices", []):
        msg = _attach_i2c_devices(bus, i2c_cfg)
        messages.append(msg)

    for port_name, pins in config.get("gpio_levels", {}).items():
        msg = _set_gpio_levels(bus, port_name, pins)
        messages.append(msg)

    for adc_name, adc_cfg in config.get("adc", {}).items():
        msg = _configure_adc(bus, adc_name, adc_cfg)
        messages.append(msg)

    return messages


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
        for attr in ("mode", "lat", "lon", "alt", "speed_knots", "rate_cycles", "ttff_ticks"):
            if attr in cfg:
                val = cfg[attr]
                if isinstance(val, str) and attr != "mode":
                    val = float(val)
                setattr(dev, attr, val)
    else:
        return f"uart: unknown device type '{dev_type}'"

    from stmemu.external.serial_line import SerialLine
    line = SerialLine(dev.name, uart=uart_model, device=dev)
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
