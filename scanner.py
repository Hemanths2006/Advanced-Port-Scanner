import socket
import threading
from queue import Queue
import ipaddress
import json
import csv
import time
import logging
import dns.resolver
import readline  # For interactive shell
import sys
import subprocess
import requests  # For API requests

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
DEFAULT_PORTS = "1-1024"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 1

# Queue for ports
queue = Queue()

# Scan types
SCAN_TYPES = {
    "tcp": "TCP Connect Scan",
    "syn": "SYN (Half-Open) Scan",
    "udp": "UDP Scan",
}

# Service detection (add more as needed)
SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

# Banner grabbing
def grab_banner(ip, port):
    try:
        socket.setdefaulttimeout(DEFAULT_TIMEOUT)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return None

# Service version detection
def detect_service_version(ip, port):
    try:
        socket.setdefaulttimeout(DEFAULT_TIMEOUT)
        s = socket.socket()
        s.connect((ip, port))
        if port == 80 or port == 443:  # HTTP/HTTPS
            s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        elif port == 22:  # SSH
            s.send(b"SSH-2.0-Client\r\n")
        response = s.recv(1024).decode().strip()
        s.close()
        return response.split("\r\n")[0]  # Return the first line of the response
    except:
        return None

# OS Detection using TTL
def os_detection(ip):
    try:
        from scapy.all import IP, ICMP, sr1, conf
    except ImportError:
        print("Scapy module is required for OS Detection. Install it using: pip install scapy")
        return

    try:
        conf.verb = 0  # Suppress Scapy warnings
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=DEFAULT_TIMEOUT, verbose=0)
        if response:
            ttl = response.ttl
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown"
    except Exception as e:
        logging.error(f"Error during OS Detection: {e}")
    return None

# TCP Connect Scan
def tcp_connect_scan(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = SERVICE_PORTS.get(port, "Unknown")
            banner = grab_banner(ip, port)
            version = detect_service_version(ip, port)
            if version and "400 Bad Request" not in version and "404 Not Found" not in version:
                logging.info(f"Port {port} ({service}) is open. Banner: {banner} | Version: {version}")
            else:
                logging.info(f"Port {port} ({service}) is open. Banner: {banner}")
        sock.close()
    except Exception as e:
        logging.error(f"Error scanning port {port}: {e}")

# SYN (Half-Open) Scan using Scapy
def syn_scan(ip, port):
    try:
        from scapy.all import IP, TCP, sr1, RandShort, conf
    except ImportError:
        print("Scapy module is required for SYN Scan. Install it using: pip install scapy")
        return

    try:
        conf.verb = 0  # Suppress Scapy warnings
        packet = IP(dst=ip)/TCP(dport=port, flags="S", sport=RandShort())
        response = sr1(packet, timeout=DEFAULT_TIMEOUT, verbose=0)
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                logging.info(f"Port {port} is open (SYN Scan)")
    except Exception as e:
        logging.error(f"Error during SYN scan on port {port}: {e}")

# UDP Scan
def udp_scan(ip, port):
    try:
        from scapy.all import IP, UDP, sr1, RandShort, conf
    except ImportError:
        print("Scapy module is required for UDP Scan. Install it using: pip install scapy")
        return

    try:
        conf.verb = 0  # Suppress Scapy warnings
        packet = IP(dst=ip)/UDP(dport=port, sport=RandShort())
        response = sr1(packet, timeout=DEFAULT_TIMEOUT, verbose=0)
        if response and response.haslayer(UDP):
            logging.info(f"Port {port} is open (UDP Scan)")
    except Exception as e:
        logging.error(f"Error during UDP scan on port {port}: {e}")

# Worker function for threading
def worker(ip, scan_type):
    while not queue.empty():
        port = queue.get()
        if scan_type == "tcp":
            tcp_connect_scan(ip, port)
        elif scan_type == "syn":
            syn_scan(ip, port)
        elif scan_type == "udp":
            udp_scan(ip, port)
        queue.task_done()

# IP Range Scanning
def scan_ip_range(ip_range, ports, scan_type, threads):
    for ip in ipaddress.IPv4Network(ip_range, strict=False):
        logging.info(f"Scanning IP: {ip}")
        scan_ports(str(ip), ports, scan_type, threads)

# Port scanning
def scan_ports(ip, ports, scan_type, threads):
    for port in ports:
        queue.put(port)

    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(ip, scan_type))
        thread.start()

    queue.join()

# Parse port range
def parse_ports(port_range):
    if "-" in port_range:
        start, end = map(int, port_range.split("-"))
        return range(start, end + 1)
    else:
        return [int(port_range)]

# DNS Resolution
def resolve_dns(domain):
    try:
        result = dns.resolver.resolve(domain, "A")
        return [ip.address for ip in result]
    except Exception as e:
        logging.error(f"Error resolving DNS: {e}")
        return []

# Host Discovery with Progress Indicator
def host_discovery(ip_range):
    try:
        from scapy.all import IP, ICMP, sr1, conf
    except ImportError:
        print("Scapy module is required for Host Discovery. Install it using: pip install scapy")
        return

    # Suppress Scapy warnings
    conf.verb = 0

    live_hosts = []
    total_hosts = len(list(ipaddress.IPv4Network(ip_range, strict=False)))
    completed = 0

    try:
        for ip in ipaddress.IPv4Network(ip_range, strict=False):
            packet = IP(dst=str(ip))/ICMP()
            response = sr1(packet, timeout=DEFAULT_TIMEOUT, verbose=0)
            if response:
                live_hosts.append(str(ip))
                print(f"Host {ip} is up.")
            completed += 1
            progress = (completed / total_hosts) * 100
            print(f"Progress: {progress:.2f}%", end="\r")  # Update progress in place
    except KeyboardInterrupt:
        print("\nHost Discovery interrupted by user.")
    except Exception as e:
        logging.error(f"Error during Host Discovery: {e}")
    finally:
        print("\nHost Discovery completed.")

# Custom Script Execution
def run_custom_script(script_name, target):
    try:
        # Example: Run a shell script
        print(f"Running custom script: {script_name} on {target}")
        subprocess.run([script_name, target], check=True)
    except Exception as e:
        logging.error(f"Error running custom script: {e}")

# Vulnerability Scan using CVE Search API
def vulnerability_scan(target):
    try:
        # Resolve domain to IP if necessary
        try:
            ipaddress.ip_address(target)
        except ValueError:
            resolved_ips = resolve_dns(target)
            if resolved_ips:
                target = resolved_ips[0]
            else:
                logging.error(f"Could not resolve domain: {target}")
                return

        # Fetch CVE data for the target IP
        url = f"https://cve.circl.lu/api/host/{target}"
        response = requests.get(url)
        if response.status_code == 200:
            cve_data = response.json()
            if cve_data:
                print(f"Vulnerabilities for {target}:")
                for cve in cve_data:
                    print(f"- CVE ID: {cve['id']}")
                    print(f"  Description: {cve['summary']}")
                    print(f"  CVSS Score: {cve.get('cvss', 'N/A')}")
                    print(f"  References: {', '.join(cve.get('references', []))}")
            else:
                print(f"No vulnerabilities found for {target}.")
        elif response.status_code == 404:
            print(f"No vulnerability data found for {target}.")
        else:
            logging.error(f"Failed to fetch CVE data: {response.status_code}")
    except Exception as e:
        logging.error(f"Error during vulnerability scan: {e}")

# Packet Crafting
def craft_packet(ip, port):
    try:
        from scapy.all import IP, TCP, send, RandShort
    except ImportError:
        print("Scapy module is required for packet crafting. Install it using: pip install scapy")
        return

    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S", sport=RandShort())
        send(packet, verbose=0)
        print(f"Custom packet sent to {ip}:{port}")
    except Exception as e:
        logging.error(f"Error crafting packet: {e}")

# Display menu
def display_menu():
    print("\n=== Advanced Port Scanner ===")
    print("1. Scan Ports")
    print("2. Host Discovery")
    print("3. OS Detection")
    print("4. Run Custom Script")
    print("5. Vulnerability Scan")
    print("6. Craft Custom Packet")
    print("7. Exit")

# Main function
def main():
    while True:
        display_menu()
        choice = input("Enter your choice (1-7): ").strip()

        if choice == "1":
            target = input("Enter target IP or domain: ").strip()
            port_range = input(f"Enter port range (default: {DEFAULT_PORTS}): ").strip() or DEFAULT_PORTS
            scan_type = input(f"Enter scan type ({', '.join(SCAN_TYPES.keys())}, default: tcp): ").strip() or "tcp"
            threads = int(input(f"Enter number of threads (default: {DEFAULT_THREADS}): ").strip() or DEFAULT_THREADS)

            # DNS Resolution
            try:
                ipaddress.ip_address(target)
            except ValueError:
                resolved_ips = resolve_dns(target)
                if resolved_ips:
                    target = resolved_ips[0]
                else:
                    logging.error(f"Could not resolve domain: {target}")
                    continue

            # Parse ports
            ports = parse_ports(port_range)

            # Start scanning
            start_time = time.time()
            if scan_type == "all":
                for scan in SCAN_TYPES.keys():
                    logging.info(f"Starting {SCAN_TYPES[scan]}...")
                    scan_ports(target, ports, scan, threads)
            else:
                scan_ports(target, ports, scan_type, threads)
            logging.info(f"Scan completed in {time.time() - start_time:.2f} seconds.")

        elif choice == "2":
            ip_range = input("Enter IP range (e.g., 192.168.1.0/24): ").strip()
            host_discovery(ip_range)

        elif choice == "3":
            target = input("Enter target IP or domain: ").strip()
            os = os_detection(target)
            if os:
                print(f"Detected OS: {os}")
            else:
                print("OS Detection failed.")

        elif choice == "4":
            target = input("Enter target IP or domain: ").strip()
            script_name = input("Enter script name: ").strip()
            run_custom_script(script_name, target)

        elif choice == "5":
            target = input("Enter target IP or domain: ").strip()
            vulnerability_scan(target)

        elif choice == "6":
            target = input("Enter target IP: ").strip()
            port = int(input("Enter target port: ").strip())
            craft_packet(target, port)

        elif choice == "7":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
