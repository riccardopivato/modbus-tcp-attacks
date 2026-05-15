"""
Modbus TCP Master (SCADA Simulator)
Polls the slave every 2 seconds and prints register values.
Environment variables:
  SLAVE_IP   — IP of the Modbus slave (default: 172.20.0.2)
  SLAVE_PORT — TCP port              (default: 502)
"""

import asyncio
import os
import logging

from pymodbus.client import AsyncModbusTcpClient

logging.basicConfig(
    format="%(asctime)s  [MASTER] %(levelname)s  %(message)s",
    level=logging.WARNING,
)

SLAVE_IP = os.getenv("SLAVE_IP", "172.20.0.2")
SLAVE_PORT = int(os.getenv("SLAVE_PORT", "502"))

REG_LABELS = [
    "Temp (x0.1°C)",
    "Pressure (x0.1 kPa)",
    "Flow (x0.1 L/min)",
    "Valve (0=closed)",
    "Voltage (x0.1 V)",
]


async def poll() -> None:
    client = AsyncModbusTcpClient(SLAVE_IP, port=SLAVE_PORT)
    await client.connect()
    print(f"[MASTER] Connected to {SLAVE_IP}:{SLAVE_PORT}")

    try:
        while True:
            result = await client.read_holding_registers(0, count=5, slave=1)  # unit ID 1 (only slave on this network)
            if result.isError():
                print(f"[MASTER] ERROR reading registers: {result}")
            else:
                vals = result.registers
                row = " | ".join(f"{REG_LABELS[i]}={vals[i]}" for i in range(5))
                print(f"[MASTER] {row}")
            await asyncio.sleep(2)
    except Exception as exc:
        print(f"[MASTER] Connection lost: {exc}")
    finally:
        client.close()


async def main() -> None:
    print(f"[MASTER] Starting — target slave {SLAVE_IP}:{SLAVE_PORT}")
    while True:
        try:
            await poll()
        except Exception:
            pass
        print("[MASTER] Reconnecting in 3 s…")
        await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(main())
