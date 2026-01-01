# stmemu

Minimal STM-ish emulator scaffold:
- Loads a raw `.bin` firmware at a base address
- Boots Cortex-M style via vector table (MSP/Reset_Handler)
- Parses CMSIS-SVD and builds an MMIO address map
- Routes Unicorn unmapped reads/writes into an MMIO bus
- Interactive shell: regs/run/step/mem/periph read-write/mmio logging

## Install
```bash
python -m venv .venv
source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install -e .
