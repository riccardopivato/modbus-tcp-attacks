"""
Modbus TCP Slave (Field Device Simulator)
Simulates an industrial sensor/actuator node with 5 holding registers:
  HR[0] = Temperature   (x0.1 °C,  initial 23.5°C  → value 235)
  HR[1] = Pressure      (x0.1 kPa, initial 85.6 kPa → value 856)
  HR[2] = Flow rate     (x0.1 L/min, initial 102.0  → value 1020)
  HR[3] = Valve status  (0=closed, 1=open)
  HR[4] = Supply voltage (x0.1 V, initial 48.0V     → value 480)
"""

import asyncio
import logging
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusSlaveContext,
    ModbusServerContext,
)

logging.basicConfig(
    format="%(asctime)s  [SLAVE]  %(levelname)s  %(message)s",
    level=logging.INFO,
)


# pyModbus maps client address N → internal index N+1, so index 0 is never
# returned. A dummy 0 at position 0 keeps the real values at the right addresses.
INITIAL_HOLDING_REGISTERS = [0, 235, 856, 1020, 0, 480] + [0] * 94


async def main() -> None:
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, [0] * 100),
        hr=ModbusSequentialDataBlock(0, INITIAL_HOLDING_REGISTERS),
        ir=ModbusSequentialDataBlock(0, [0] * 100),
    )
    context = ModbusServerContext(slaves=store, single=True)

    logging.info("Modbus TCP slave listening on 0.0.0.0:502")
    logging.info(
        "Initial registers: "
        "Temp=235 (23.5°C) | Pressure=856 (85.6 kPa) | "
        "Flow=1020 (102.0 L/min) | Valve=0 (closed) | Voltage=480 (48.0 V)"
    )
    await StartAsyncTcpServer(context, address=("0.0.0.0", 502))


if __name__ == "__main__":
    asyncio.run(main())
