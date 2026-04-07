from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map


def _write_svd(xml: str) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".svd", delete=False, mode="w")
    tmp.write(xml)
    tmp.close()
    return Path(tmp.name)


class SvdDimExpansionTests(unittest.TestCase):
    """Tests for dim/dimIncrement register array expansion."""

    def test_dim_expansion_creates_indexed_registers(self) -> None:
        path = _write_svd("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <peripherals>
    <peripheral>
      <name>DMA1</name>
      <baseAddress>0x40020000</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x400</size></addressBlock>
      <registers>
        <register>
          <name>CH%sCR</name>
          <addressOffset>0x08</addressOffset>
          <size>32</size>
          <dim>3</dim>
          <dimIncrement>0x14</dimIncrement>
          <dimIndex>1-3</dimIndex>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
""")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        device = load_svd(path)
        dma = device.peripherals[0]
        self.assertEqual(dma.name, "DMA1")
        self.assertEqual(len(dma.registers), 3)
        self.assertEqual(dma.registers[0].name, "CH1CR")
        self.assertEqual(dma.registers[0].offset, 0x08)
        self.assertEqual(dma.registers[1].name, "CH2CR")
        self.assertEqual(dma.registers[1].offset, 0x08 + 0x14)
        self.assertEqual(dma.registers[2].name, "CH3CR")
        self.assertEqual(dma.registers[2].offset, 0x08 + 0x28)

    def test_dim_comma_index(self) -> None:
        path = _write_svd("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <peripherals>
    <peripheral>
      <name>GPIO</name>
      <baseAddress>0x40020000</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x400</size></addressBlock>
      <registers>
        <register>
          <name>PIN%s</name>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
          <dim>2</dim>
          <dimIncrement>4</dimIncrement>
          <dimIndex>A,B</dimIndex>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
""")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        device = load_svd(path)
        regs = device.peripherals[0].registers
        self.assertEqual(len(regs), 2)
        self.assertEqual(regs[0].name, "PINA")
        self.assertEqual(regs[1].name, "PINB")
        self.assertEqual(regs[1].offset, 4)


class SvdClusterTests(unittest.TestCase):
    """Tests for register cluster flattening."""

    def test_cluster_registers_are_flattened_with_offset(self) -> None:
        path = _write_svd("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <peripherals>
    <peripheral>
      <name>USB</name>
      <baseAddress>0x40040000</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x1000</size></addressBlock>
      <registers>
        <register>
          <name>GOTGCTL</name>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
        </register>
        <cluster>
          <name>HOST</name>
          <addressOffset>0x400</addressOffset>
          <register>
            <name>HCFG</name>
            <addressOffset>0x00</addressOffset>
            <size>32</size>
          </register>
          <register>
            <name>HFIR</name>
            <addressOffset>0x04</addressOffset>
            <size>32</size>
          </register>
        </cluster>
      </registers>
    </peripheral>
  </peripherals>
</device>
""")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        device = load_svd(path)
        usb = device.peripherals[0]
        reg_names = {r.name: r.offset for r in usb.registers}
        self.assertIn("GOTGCTL", reg_names)
        self.assertEqual(reg_names["GOTGCTL"], 0x00)
        self.assertIn("HOST_HCFG", reg_names)
        self.assertEqual(reg_names["HOST_HCFG"], 0x400)
        self.assertIn("HOST_HFIR", reg_names)
        self.assertEqual(reg_names["HOST_HFIR"], 0x404)


class SvdDerivedFromTests(unittest.TestCase):
    """Tests for peripheral derivedFrom inheritance."""

    def test_derived_peripheral_inherits_registers(self) -> None:
        path = _write_svd("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <peripherals>
    <peripheral>
      <name>USART1</name>
      <baseAddress>0x40011000</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x400</size></addressBlock>
      <registers>
        <register>
          <name>CR1</name>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
        </register>
        <register>
          <name>ISR</name>
          <addressOffset>0x1C</addressOffset>
          <size>32</size>
        </register>
      </registers>
      <interrupt><name>USART1</name><value>37</value></interrupt>
    </peripheral>
    <peripheral derivedFrom="USART1">
      <name>USART2</name>
      <baseAddress>0x40004400</baseAddress>
      <interrupt><name>USART2</name><value>38</value></interrupt>
    </peripheral>
  </peripherals>
</device>
""")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        device = load_svd(path)
        self.assertEqual(len(device.peripherals), 2)

        usart1 = device.peripherals[0]
        usart2 = device.peripherals[1]

        self.assertEqual(usart1.name, "USART1")
        self.assertEqual(usart2.name, "USART2")
        self.assertEqual(usart2.base_address, 0x40004400)
        # Inherited registers from USART1
        self.assertEqual(len(usart2.registers), 2)
        self.assertEqual(usart2.registers[0].name, "CR1")
        # Inherited size
        self.assertEqual(usart2.size, 0x400)

    def test_derived_peripheral_gets_own_interrupts(self) -> None:
        path = _write_svd("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <peripherals>
    <peripheral>
      <name>TIM2</name>
      <baseAddress>0x40000000</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x400</size></addressBlock>
      <registers>
        <register>
          <name>CR1</name>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
        </register>
      </registers>
      <interrupt><name>TIM2</name><value>28</value></interrupt>
    </peripheral>
    <peripheral derivedFrom="TIM2">
      <name>TIM3</name>
      <baseAddress>0x40000400</baseAddress>
      <interrupt><name>TIM3</name><value>29</value></interrupt>
    </peripheral>
  </peripherals>
</device>
""")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        device = load_svd(path)
        tim2 = device.peripherals[0]
        tim3 = device.peripherals[1]
        self.assertEqual(tim2.interrupts[0].value, 28)
        self.assertEqual(tim3.interrupts[0].value, 29)


class SvdInterruptExtractionTests(unittest.TestCase):
    """Tests for interrupt element extraction."""

    def test_interrupts_parsed_from_peripheral(self) -> None:
        path = _write_svd("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <peripherals>
    <peripheral>
      <name>USART1</name>
      <baseAddress>0x40011000</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x400</size></addressBlock>
      <registers>
        <register><name>CR1</name><addressOffset>0x00</addressOffset><size>32</size></register>
      </registers>
      <interrupt><name>USART1</name><value>37</value></interrupt>
    </peripheral>
  </peripherals>
</device>
""")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        device = load_svd(path)
        periph = device.peripherals[0]
        self.assertEqual(len(periph.interrupts), 1)
        self.assertEqual(periph.interrupts[0].name, "USART1")
        self.assertEqual(periph.interrupts[0].value, 37)

    def test_multiple_interrupts_per_peripheral(self) -> None:
        path = _write_svd("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <peripherals>
    <peripheral>
      <name>DMA1</name>
      <baseAddress>0x40020000</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x400</size></addressBlock>
      <registers>
        <register><name>ISR</name><addressOffset>0x00</addressOffset><size>32</size></register>
      </registers>
      <interrupt><name>DMA1_Stream0</name><value>11</value></interrupt>
      <interrupt><name>DMA1_Stream1</name><value>12</value></interrupt>
    </peripheral>
  </peripherals>
</device>
""")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        device = load_svd(path)
        periph = device.peripherals[0]
        self.assertEqual(len(periph.interrupts), 2)
        self.assertEqual(periph.interrupts[0].value, 11)
        self.assertEqual(periph.interrupts[1].value, 12)


class SvdAddressMapBisectTests(unittest.TestCase):
    """Tests for the bisect-based address map lookup."""

    def test_find_peripheral_by_address(self) -> None:
        path = _write_svd("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <baseAddress>0x40020000</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x400</size></addressBlock>
      <registers>
        <register><name>MODER</name><addressOffset>0x00</addressOffset><size>32</size></register>
      </registers>
    </peripheral>
    <peripheral>
      <name>GPIOB</name>
      <baseAddress>0x40020400</baseAddress>
      <addressBlock><offset>0x0</offset><size>0x400</size></addressBlock>
      <registers>
        <register><name>MODER</name><addressOffset>0x00</addressOffset><size>32</size></register>
      </registers>
    </peripheral>
  </peripherals>
</device>
""")
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        device = load_svd(path)
        amap = build_address_map(device)

        # Found at base
        p = amap.find_peripheral(0x40020000)
        self.assertIsNotNone(p)
        self.assertEqual(p.name, "GPIOA")

        # Found at offset within range
        p = amap.find_peripheral(0x40020100)
        self.assertIsNotNone(p)
        self.assertEqual(p.name, "GPIOA")

        # Found at second peripheral
        p = amap.find_peripheral(0x40020400)
        self.assertIsNotNone(p)
        self.assertEqual(p.name, "GPIOB")

        # Not found (before any peripheral)
        p = amap.find_peripheral(0x10000000)
        self.assertIsNone(p)

        # Not found (between peripherals)
        # GPIOA ends at 0x40020400, GPIOB starts at 0x40020400
        # So 0x400203FF is within GPIOA
        p = amap.find_peripheral(0x400203FF)
        self.assertIsNotNone(p)
        self.assertEqual(p.name, "GPIOA")


if __name__ == "__main__":
    unittest.main()
