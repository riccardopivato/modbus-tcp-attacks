"""
B6 - Modbus Network Scanning
Actively probes the slave by sending benign read requests to all unit IDs
and reading all accessible holding registers. No write commands are issued,
so the scan appears as normal traffic to the slave.

Reference: Huitsing et al. (2008), attack B6
Threat type: Interception
Target assets: Field device data (B6-1), network topology (B6-2)
"""

import asyncio
from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ModbusException

SLAVE_IP = "172.20.0.2"
SLAVE_PORT = 502
UNIT_IDS = range(1, 11)      # probe unit IDs 1-10
REGISTER_START = 0
REGISTER_COUNT = 10          # read HR[0] through HR[9]

REG_LABELS = {
    0: "Temperature (x0.1 °C)",
    1: "Pressure (x0.1 kPa)",
    2: "Flow (x0.1 L/min)",
    3: "Valve status",
    4: "Supply voltage (x0.1 V)",
}


async def scan() -> None:
    print(f"[B6] Modbus Network Scan → {SLAVE_IP}:{SLAVE_PORT}")
    print(f"[B6] Probing unit IDs {min(UNIT_IDS)}–{max(UNIT_IDS)}, "
          f"reading HR[{REGISTER_START}–{REGISTER_START + REGISTER_COUNT - 1}]\n")

    client = AsyncModbusTcpClient(SLAVE_IP, port=SLAVE_PORT)
    await client.connect()

    discovered = {}

    for uid in UNIT_IDS:
        try:
            result = await client.read_holding_registers(
                REGISTER_START, count=REGISTER_COUNT, slave=uid
            )
            if result.isError():
                print(f"[B6] Unit {uid:3d} — no response")
                continue

            regs = result.registers
            discovered[uid] = regs
            print(f"[B6] Unit {uid:3d} FOUND — raw HR values: {regs}")
            for i, val in enumerate(regs[:5]):
                label = REG_LABELS.get(i, f"HR[{i}]")
                print(f"         {label} = {val}")
            print()
        except ModbusException as exc:
            print(f"[B6] Unit {uid:3d} — exception: {exc}")

    client.close()

    print("=" * 60)
    print(f"[B6] Scan complete — {len(discovered)} unit(s) found: {list(discovered)}")
    print("[B6] Attacker now has a full register map of the ICS field devices.")


asyncio.run(scan())
