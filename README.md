# Packet-Sniffer
Learning to program a packet sniffer so I dont have to rely on pre-made programs

I am a new programmer/cyber security analyst and I am currently in the process of programming my own packet sniffer (like wire shark) so I can understand how packets work etc.

#Today is 29/10/2026 and I learned how bits are calculated and wrote a basic program that uses octets to decipher strings of Hex numbers into Decimal numbers and vise versa.

---

## 🚀 Project Architecture & Roadmap

### 📦 Phase 1: Foundational Hex & Binary Decoding (29/10/2026)
* **Understanding Octets:** Built out localized bit-manipulation functions to parse and decode strings of raw Hex codes into standard dotted-decimal profiles.
* **Network Endianness Analysis:** Mapped and converted 16-bit packed structures manually to understand Network Byte Order (Big-Endian vs. Little-Endian storage constraints).

### ⚡ Phase 2: Dynamic OS Detection & Live File Logging (Current)
* **Cross-Platform Initialization:** Programmed dynamic runtime tracking to automatically select the optimal sniffing interface framework based on the host operating system (`nt` vs. `posix`).
* **Layer 2 Pipeline Ingestion:** Configured raw socket bindings using `socket.AF_PACKET` and standard network flags (`socket.htons(0x0003)`) to intercept live hardware frame streams on Linux architectures.
* **Low-Level Index Parsing:** Bypassed traditional interpreter structure-padding bugs by writing direct integer array slicing lookups (`ip_header_bytes[9]`) to decode IP header boundaries manually.
* **Automated Forensic Logging:** Designed an automated file I/O framework that appends live, timestamped protocol actions straight into a localized text repository using a custom signature layout.

---

## 🛠️ Core Functional Script Layout

```python
# Save this profile locally as understanding_socket.py
import socket
import struct
import os
from datetime import datetime

def log_traffic(log_entry):
    with open("network_traffic.log", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Custom NeoPackets_ callsign configuration
        log_file.write(f"NeoPackets_[{timestamp}] {log_entry}\n")

# [The complete multi-OS start_sniffer engine runs below...]
```

---

## 🔬 Real-World Captured Evidence (`network_traffic.log`)

The following live log output confirms the tool successfully maps layer traffic endpoints dynamically on a Linux interface using the **NeoPackets_** callsign signature:

```text
NeoPackets_[2026-11-04 16:21:05] IP Routing: 192.168.8.6 -> 8.8.8.8 | Protocol ID: 1
NeoPackets_[2026-11-04 16:21:05]    ICMP Type: 8 | ICMP Code: 0
NeoPackets_[2026-11-04 16:21:05] IP Routing: 8.8.8.8 -> 192.168.8.6 | Protocol ID: 1
NeoPackets_[2026-11-04 16:21:05]    ICMP Type: 0 | ICMP Code: 0
NeoPackets_[2026-11-04 16:21:10] IP Routing: 20.207.70.99 -> 192.168.8.6 | Protocol ID: 6
NeoPackets_[2026-11-04 16:21:10]    TCP Ports: 443 -> 54574
NeoPackets_[2026-11-04 16:21:15] IP Routing: 192.168.8.26 -> 239.255.255.250 | Protocol ID: 17
NeoPackets_[2026-11-04 16:21:15]    UDP Ports: 62838 -> 1900
```
---

## 💻 Usage & Log Analysis

Because this program taps directly into raw hardware layer sockets, it requires administrative privileges to execute.

### 1. Launching the Sniffer
Open your terminal emulator and execute the script using `sudo` (Linux) or run your command environment as an Administrator (Windows):
```bash
sudo python3 understanding_socket.py
```

### 2. Inspecting the Generated Evidence Log
Once active, the engine dynamically appends all packet information to `network_traffic.log`. Use the following native core commands to review and track your network events:

* **View the full history log:**
  ```bash
  cat network_traffic.log
  ```
* **Monitor incoming packets live (Real-time forensic stream):**
  ```bash
  tail -f network_traffic.log
  ```
* **Filter logs exclusively for ICMP (Ping) traffic payloads:**
  ```bash
  cat network_traffic.log | grep "Protocol ID: 1"
  ```
* **Filter logs exclusively for Secure Web Traffic (HTTPS/Port 443):**
  ```bash
  cat network_traffic.log | grep "Ports: 443"
  ```

---

## 🔮 Upcoming Phases
* **Phase 3: Standard Hex Dump Generator** - Splitting the trailing data buffers into a clean, 16-byte aligned Hex dump grid with printable ASCII dot overlays.
* **Phase 4: TCP Stream Reassembly** - Tracking sequence numbers and packet fragment configurations to re-stitch streams back into legible file buffers.
