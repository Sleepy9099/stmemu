import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
# Hook each SPI1 device's exchange to flag non-zero MISO during a data burst.
devs = getattr(bus, "_spi_attached_devices", {}) or {}
hits = {}
import functools
def wrap(name, d):
    orig = d.exchange
    state = {"first": True, "reg": None, "n": 0}
    def ex(b):
        m = orig(b)
        # track transaction reg (first byte after cs)
        if getattr(d, "_state", None) == "IDLE" or state["first"]:
            pass
        if m not in (0x00, 0xFF) and state["reg"] in (0x3F, 0x30, 0xBF, 0xB0):
            hits.setdefault(name, []).append((state["reg"], m))
        return m
    return ex
# simpler: snapshot per-device nonzero data-byte counts by sampling reg pointer
for nm, d in devs.items():
    o = d.exchange
    cnt = {"nz": 0, "samp": []}
    def mk(dd, c, oo):
        def w(b):
            m = oo(b)
            rp = getattr(dd, "_reg_ptr", -1); st = getattr(dd, "_state", "")
            if st == "DATA" and rp in (0x3F, 0x30) and (m & 0xFF) not in (0,):
                c["nz"] += 1
                if len(c["samp"])<8: c["samp"].append((hex(rp), hex(m&0xFF)))
            return m
        return w
    d.exchange = mk(d, cnt, o); hits[nm]=cnt
emu.run(8_000_000)
print("non-zero FIFO-data MISO bytes per SPI1 device (reg 0x30/0x3f):")
for nm, c in hits.items():
    print(f"  {nm}: nz_count={c['nz']}  samples={c['samp']}")
