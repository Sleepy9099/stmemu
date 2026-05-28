"""STM32H7 DMAMUX1/DMAMUX2 peripheral with runtime stream-request routing.

The DMAMUX (DMA request router) on H7 lets firmware programmatically map
peripheral DMA request lines (SPI1_TX, USART3_RX, ...) onto specific DMA
streams. ArduPilot's ChibiOS HAL programs DMAMUX1.CxCR at boot to wire
each peripheral's TX/RX channel to a stream of its choosing.

This model watches CxCR writes, extracts the DMAREQ_ID (bits 0..7),
translates it through the STM32H7 request-ID map to a symbolic name, and
calls DmaPeripheral.set_stream_request(stream, name) on the target DMA.
That way the existing DMAMUX routing in DmaPeripheral picks up the
mapping at runtime instead of having to be statically declared in YAML.

Channel-to-stream convention (from RM0433):
  DMAMUX1 channel 0..7  -> DMA1 stream 0..7
  DMAMUX1 channel 8..15 -> DMA2 stream 0..7
  DMAMUX2 channel 0..7  -> BDMA channel 0..7
"""
from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


# STM32H7 DMAMUX1 request ID -> symbolic name. Covers what ArduPilot uses
# for sensor probe/streaming paths -- SPI, I2C, UART, ADC, TIM. Extend as
# needed; entries we don't know fall through to "REQ<id>".
_DMAMUX1_REQUESTS: dict[int, str] = {
    1: "DMAMUX1_REQ_GEN0",
    2: "DMAMUX1_REQ_GEN1",
    3: "DMAMUX1_REQ_GEN2",
    4: "DMAMUX1_REQ_GEN3",
    5: "DMAMUX1_REQ_GEN4",
    6: "DMAMUX1_REQ_GEN5",
    7: "DMAMUX1_REQ_GEN6",
    8: "DMAMUX1_REQ_GEN7",
    9: "ADC1",
    10: "ADC2",
    11: "TIM1_CH1",
    12: "TIM1_CH2",
    13: "TIM1_CH3",
    14: "TIM1_CH4",
    15: "TIM1_UP",
    16: "TIM1_TRIG",
    17: "TIM1_COM",
    18: "TIM2_CH1",
    19: "TIM2_CH2",
    20: "TIM2_CH3",
    21: "TIM2_CH4",
    22: "TIM2_UP",
    23: "TIM3_CH1",
    24: "TIM3_CH2",
    25: "TIM3_CH3",
    26: "TIM3_CH4",
    27: "TIM3_UP",
    28: "TIM3_TRIG",
    29: "TIM4_CH1",
    30: "TIM4_CH2",
    31: "TIM4_CH3",
    32: "TIM4_UP",
    33: "I2C1_RX",
    34: "I2C1_TX",
    35: "I2C2_RX",
    36: "I2C2_TX",
    37: "SPI1_RX",
    38: "SPI1_TX",
    39: "SPI2_RX",
    40: "SPI2_TX",
    41: "SPI3_RX",
    42: "SPI3_TX",
    43: "USART1_RX",
    44: "USART1_TX",
    45: "USART2_RX",
    46: "USART2_TX",
    47: "USART3_RX",
    48: "USART3_TX",
    49: "TIM8_CH1",
    50: "TIM8_CH2",
    51: "TIM8_CH3",
    52: "TIM8_CH4",
    53: "TIM8_UP",
    54: "TIM8_TRIG",
    55: "TIM8_COM",
    57: "TIM5_CH1",
    58: "TIM5_CH2",
    59: "TIM5_CH3",
    60: "TIM5_CH4",
    61: "TIM5_UP",
    62: "TIM5_TRIG",
    63: "SPI4_RX",
    64: "SPI4_TX",
    65: "SPI5_RX",
    66: "SPI5_TX",
    67: "SAI1_A",
    68: "SAI1_B",
    69: "SAI2_A",
    70: "SAI2_B",
    71: "DFSDM1_FLT0",
    72: "DFSDM1_FLT1",
    73: "DFSDM1_FLT2",
    74: "DFSDM1_FLT3",
    75: "TIM15_CH1",
    76: "TIM15_UP",
    77: "TIM15_TRIG",
    78: "TIM15_COM",
    79: "TIM16_CH1",
    80: "TIM16_UP",
    81: "TIM17_CH1",
    82: "TIM17_UP",
    83: "SAI3_A",
    84: "SAI3_B",
    85: "ADC3",
    86: "UART4_RX",
    87: "UART4_TX",
    88: "UART5_RX",
    89: "UART5_TX",
    90: "DAC1_CH1",
    91: "DAC1_CH2",
    92: "UART7_RX",
    93: "UART7_TX",
    94: "UART8_RX",
    95: "UART8_TX",
    96: "USART6_RX",
    97: "USART6_TX",
    98: "I2C3_RX",
    99: "I2C3_TX",
    100: "USB1_OTG_HS",
    101: "USB2_OTG_FS",
}

# STM32H7 DMAMUX2 (BDMA) request ID -> name. BDMA serves D3-domain
# peripherals: LPUART1, I2C4, SPI6, ADC3, LPTIMx, ...
_DMAMUX2_REQUESTS: dict[int, str] = {
    1: "LPUART1_RX",
    2: "LPUART1_TX",
    3: "SPI6_RX",
    4: "SPI6_TX",
    5: "I2C4_RX",
    6: "I2C4_TX",
    7: "SAI4_A",
    8: "SAI4_B",
    9: "ADC3",
    10: "DAC2",
    11: "DFSDM2_FLT0",
}


@dataclass
class DmaMuxPeripheral(GenericRegisterFilePeripheral):
    """DMAMUX1 / DMAMUX2 with runtime request-line routing."""

    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _channel_count: int = field(default=16, init=False, repr=False)
    _is_dmamux2: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        # DMAMUX1 has 16 channels (DMA1 + DMA2), DMAMUX2 has 8 (BDMA).
        self._is_dmamux2 = self.peripheral.name.upper() == "DMAMUX2"
        self._channel_count = 8 if self._is_dmamux2 else 16

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def write(self, offset: int, size: int, value: int) -> None:
        super().write(offset, size, value)
        # CxCR registers occupy the first 16*4 = 64 bytes (or 8*4 = 32 for
        # DMAMUX2). Each write reprograms the routing for one channel.
        if offset < self._channel_count * 4 and (offset & 0x3) == 0:
            channel = offset // 4
            request_id = int(value) & 0xFF
            self._route_channel(channel, request_id)

    def _route_channel(self, channel: int, request_id: int) -> None:
        if self._context is None or self._context.bus is None:
            return
        dma_name, stream = self._target_for_channel(channel)
        dma = self._context.bus.model_for_name(dma_name)
        if dma is None or not hasattr(dma, "set_stream_request"):
            return
        if request_id == 0:
            # Writing 0 to DMAREQ_ID is "no request" -> clear the mapping.
            dma.set_stream_request(stream, None)
            return
        table = _DMAMUX2_REQUESTS if self._is_dmamux2 else _DMAMUX1_REQUESTS
        name = table.get(request_id, f"REQ{request_id}")
        dma.set_stream_request(stream, name)
        log.debug(
            "dmamux %s ch%d -> %s stream %d (req=%d %s)",
            self.peripheral.name, channel, dma_name, stream, request_id, name,
        )

    def _target_for_channel(self, channel: int) -> tuple[str, int]:
        if self._is_dmamux2:
            return "BDMA", channel
        if channel < 8:
            return "DMA1", channel
        return "DMA2", channel - 8


def build_dmamux(peripheral: SvdPeripheral) -> DmaMuxPeripheral:
    return DmaMuxPeripheral(peripheral=peripheral)
