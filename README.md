# PCAP Analyzer 🕵️‍♂️

A Python script for analyzing `.pcap` network captures to extract and decode Base64 or XOR-obfuscated data — ideal for penetration testers, CTF players, and malware analysts.

---

## 🚀 Features

- Parses `.pcap` files using **Scapy**
- Detects Base64-encoded payloads and auth/data parameters
- Automatically decodes and XOR-decrypts reversed data with a custom key
- Displays printable decoded results for inspection

---

## 🧰 Requirements

- Python 3.8+
- Scapy

Install dependencies:
```bash
pip install scapy
