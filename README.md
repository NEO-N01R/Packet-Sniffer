# Packet-Sniffer (NeoPackets)

A lightweight, cross-platform raw socket packet sniffer built from scratch in Python using only the Python Standard Library (`socket`, `struct`, `os`, `datetime`). 

This project was built to gain a deep, low-level understanding of how network frames, IP headers, and transport protocols operate on the wire—without relying on high-level abstractions like `scapy` or `libpcap`.

---

## 🚀 Key Features & Architecture

* **Zero External Dependencies:** Built 100% with Python's built-in standard library modules.
* **Cross-Platform Raw Socket Engine:** Automatically detects the host operating system at runtime:
  * **Linux (`posix`):** Binds directly to Layer 2 using `socket.AF_PACKET` and `socket.htons(0x0003)` to capture raw Ethernet frames.
  * **Windows (`nt`):** Binds to `socket.AF_INET` and enables promiscuous mode via `SIO_RCVALL`.
* **Manual Byte & Header Slicing:** Unpacks Network Byte Order (Big-Endian) binary headers using `struct` to extract source/destination IPv4 addresses, protocol IDs, TCP/UDP ports, and ICMP types/codes.
* **Automated Forensic Logging:** Appends live, timestamped packet metadata to `network_traffic.log` using a custom `NeoPackets_` callsign for real-time monitoring and post-capture filtering.

---

## 📂 Repository Structure

* `understanding_octet.py` — Foundational bit-manipulation script for converting raw hexadecimal strings into dotted-decimal IPv4 octets and analyzing Big-Endian vs. Little-Endian storage.
* `understanding_socket.py` — Main cross-platform raw socket packet capture and protocol decoding engine.

---

## 💻 Usage & Log Analysis

Because raw hardware sockets require elevated system privileges, you must run the script as **root** (Linux) or **Administrator** (Windows).

### 1. Run the Packet Sniffer

**On Linux:**
```bash
sudo python3 understanding_socket.py
```

**On Windows (Command Prompt / PowerShell as Administrator):**
```powershell
python understanding_socket.py
```

Press `Ctrl + C` at any time to safely close the socket (and disable promiscuous mode on Windows).

### 2. Inspect & Filter Captured Logs

While the sniffer runs, all decoded traffic is written to `network_traffic.log`. Use standard Linux CLI utilities to inspect the stream:

* **Monitor live traffic in real time:**
  ```bash
  tail -f network_traffic.log
  ```
* **Filter exclusively for ICMP (Ping) packets:**
  ```bash
  grep "Protocol ID: 1" network_traffic.log
  ```
* **Filter for HTTPS web traffic (Port 443):**
  ```bash
  grep "Ports: 443" network_traffic.log
  ```

---

## 🔬 Sample Captured Output (`network_traffic.log`)

```text
NeoPackets_[2026-11-04 16:21:05] IP Routing: 192.168.8.6 -> 8.8.8.8 | Protocol ID: 1
NeoPackets_[2026-11-04 16:21:05] ICMP Type: 8 | ICMP Code: 0
NeoPackets_[2026-11-04 16:21:05] IP Routing: 8.8.8.8 -> 192.168.8.6 | Protocol ID: 1
NeoPackets_[2026-11-04 16:21:05] ICMP Type: 0 | ICMP Code: 0
NeoPackets_[2026-11-04 16:21:10] IP Routing: 20.207.70.99 -> 192.168.8.6 | Protocol ID: 6
NeoPackets_[2026-11-04 16:21:10] TCP Ports: 443 -> 54574
NeoPackets_[2026-11-04 16:21:15] IP Routing: 192.168.8.26 -> 239.255.255.250 | Protocol ID: 17
NeoPackets_[2026-11-04 16:21:15] UDP Ports: 62838 -> 1900
```

---

## 🗺️ Development Roadmap

* [x] **Phase 1:** Hexadecimal-to-decimal octet conversion & Endianness analysis (`understanding_octet.py`).
* [x] **Phase 2:** Multi-OS raw socket initialization, IPv4/TCP/UDP/ICMP header slicing, and file logging (`understanding_socket.py`).
* [ ] **Phase 3:** Dynamic IP Header Length (`IHL`) calculation & EtherType (`0x0800`) filtering on Linux.
* [ ] **Phase 4:** Basic anomaly detection (flagging rapid port scans and cleartext Telnet/FTP traffic).
* [ ] **Phase 5:** 16-byte aligned Hex + ASCII payload dump viewer.
