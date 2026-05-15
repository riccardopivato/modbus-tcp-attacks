# Modbus TCP Attack Testbed

Docker-based testbed reproducing the attacks from the Modbus TCP attack
taxonomy by Huitsing et al. (2008), implemented for the CPS and IoT
Security course.

The full write-up is in [`report_modbus.pdf`](report_modbus.pdf).

## Repository layout

```
.
├── testbed/                  # master + slave Dockerfile and Python sources
├── attacks/                  # one script per attack
├── captures/                 # .pcap files and screenshots referenced in the report
├── docker-compose.yml        # spins up master, slave, attacker on an isolated bridge
├── README_attacks.md         # short notes on how to invoke each attack
└── report_modbus.pdf         # final report
```

## Requirements

- Docker Desktop (Windows / macOS / Linux)

No host-side Python is required: every attack runs inside the `modbus-attacker`
container, which already ships with `pyModbus 3.7.0` and `Scapy 2.6.1`.

## Quick start

Bring the testbed up:

```bash
docker compose up --build -d
```

Three containers start on the `172.20.0.0/24` bridge network:

| Container         | IP             | Role                                |
|-------------------|----------------|-------------------------------------|
| `modbus-slave`    | `172.20.0.2`   | Modbus TCP server on port 502       |
| `modbus-master`   | `172.20.0.3`   | Polls the slave every second        |
| `modbus-attacker` | `172.20.0.4`   | Toolbox for running the attacks     |

Verify normal traffic:

```bash
docker logs -f modbus-master
```

## Running an attack

Each attack is a standalone Python script under `attacks/`. They are copied
into the attacker container at `/app/`, so you run them with `docker exec`:

```bash
docker exec modbus-attacker python /app/interception_passive.py
docker exec modbus-attacker python /app/interception_scan.py
docker exec modbus-attacker python /app/interruption_rst_flood.py
docker exec modbus-attacker python /app/interruption_pool_exhaustion.py
docker exec modbus-attacker python /app/modification_mitm.py
docker exec modbus-attacker python /app/fabrication_replay.py
docker exec modbus-attacker python /app/fabrication_rogue_master.py
```

See `README_attacks.md` for the mapping between script names and the
taxonomy codes (B2, B4, B6, B9, B14, T10, T11) used in the report.

## Captures

`captures/` contains the exact `.pcap` files and Wireshark screenshots
shown in the report, so the results can be inspected without re-running
the testbed.

## Tearing down

```bash
docker compose down
```

## References

- [1] P. Huitsing, R. Chandia, M. Papa, S. Shenoi. *"Attack Taxonomies for
  the Modbus Protocols."* Critical Infrastructure Protection II, IFIP
  vol. 273, Springer, 2008.
- [2] A. Crain et al. *pyModbus — A full Modbus protocol implementation in
  Python.* github.com/pymodbus-dev/pymodbus (v3.7.0, 2024).
- [3] P. Biondi et al. *Scapy — Packet manipulation library.* scapy.net
  (v2.6.1, 2024).
- [4] The Modbus Organization. *Modbus Messaging on TCP/IP Implementation
  Guide Rev. 1.0b.* modbus.org, 2006.
- [5] IEC 62351-3:2014. *Power systems management — Data and communications
  security — Profiles including TCP/IP.*

See `report_modbus.pdf` for the full discussion.
