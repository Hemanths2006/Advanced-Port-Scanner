# Advanced Port Scanner

## Overview
This is a powerful and feature-rich network security tool designed for scanning open ports, performing host discovery, detecting operating systems, identifying vulnerabilities, and crafting custom network packets. It supports multiple scanning techniques such as TCP Connect, SYN (Half-Open), and UDP scans.

## Features
- **Port Scanning:** Supports TCP, SYN, and UDP scans.
- **Host Discovery:** Identifies live hosts in a given IP range.
- **OS Detection:** Uses TTL-based fingerprinting.
- **Banner Grabbing:** Extracts service banners for deeper analysis.
- **Service Version Detection:** Identifies versions of detected services.
- **Vulnerability Scanning:** Fetches CVE data from an online API.
- **DNS Resolution:** Resolves domain names to IP addresses.
- **Packet Crafting:** Sends custom packets for penetration testing.
- **Multi-threading:** Enables faster scanning with adjustable thread count.

## Requirements
Ensure you have the following dependencies installed:
- Python 3.x
- Required Python packages:
  ```bash
  pip install socket threading queue ipaddress json csv time logging dns.resolver readline requests scapy
  ```
- Scapy is required for SYN scan, UDP scan, and OS detection:
  ```bash
  pip install scapy
  ```

## Usage
Run the script using:
```bash
python scanner.py
```
Follow the interactive menu to choose the desired functionality.

### Menu Options
1. **Scan Ports**: Perform TCP, SYN, or UDP scans on a target.
2. **Host Discovery**: Identify active hosts within an IP range.
3. **OS Detection**: Detect operating systems using TTL values.
4. **Run Custom Script**: Execute a script on a target.
5. **Vulnerability Scan**: Fetch CVE details for a target.
6. **Craft Custom Packet**: Send a crafted packet to a target.
7. **Exit**: Quit the application.

### Example Usage
**Port Scanning:**
```bash
Enter target IP or domain: 192.168.1.1
Enter port range (default: 1-1024): 22-80
Enter scan type (tcp, syn, udp, default: tcp): tcp
Enter number of threads (default: 100): 50
```

**Host Discovery:**
```bash
Enter IP range (e.g., 192.168.1.0/24): 192.168.1.0/24
```

**OS Detection:**
```bash
Enter target IP or domain: 192.168.1.1
Detected OS: Linux/Unix
```

**Vulnerability Scan:**
```bash
Enter target IP or domain: example.com
Fetching CVE data...
Vulnerabilities for example.com:
- CVE-2024-XXXXX: Description...
```

## Notes
- Running SYN and UDP scans requires administrative privileges.
- Network scanning should only be conducted on authorized systems.

## Disclaimer
This tool is intended for ethical cybersecurity research and network security auditing. Unauthorized scanning of networks is illegal and may result in severe consequences.

## License
This project is released under the MIT License.

