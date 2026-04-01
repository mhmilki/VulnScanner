#!/usr/bin/env python3
"""
VulnScanner - Network Vulnerability Scanner
A portfolio project for cybersecurity professionals
Author: [Your Name]
"""

import nmap
import argparse
import socket
import sys
import json
from datetime import datetime
from fpdf import FPDF


RISKY_SERVICES = {
    21: {"service": "FTP", "risk": "High", "note": "FTP often allows anonymous login or transmits credentials in plaintext"},
    22: {"service": "SSH", "risk": "Medium", "note": "Check for outdated SSH versions vulnerable to exploits"},
    23: {"service": "Telnet", "risk": "Critical", "note": "Telnet transmits everything in plaintext including passwords"},
    25: {"service": "SMTP", "risk": "Medium", "note": "Open SMTP relay can be used for spam and phishing"},
    53: {"service": "DNS", "risk": "Medium", "note": "DNS can be exploited for zone transfers or amplification attacks"},
    80: {"service": "HTTP", "risk": "Medium", "note": "Unencrypted web traffic, check for outdated web servers"},
    110: {"service": "POP3", "risk": "High", "note": "POP3 transmits credentials in plaintext"},
    135: {"service": "MSRPC", "risk": "High", "note": "Microsoft RPC often targeted by worms and exploits"},
    139: {"service": "NetBIOS", "risk": "High", "note": "NetBIOS can leak system info and allow unauthorized access"},
    143: {"service": "IMAP", "risk": "High", "note": "IMAP without TLS transmits credentials in plaintext"},
    443: {"service": "HTTPS", "risk": "Low", "note": "Check for SSL/TLS misconfigurations and expired certificates"},
    445: {"service": "SMB", "risk": "Critical", "note": "SMB is frequently targeted (EternalBlue, WannaCry)"},
    1433: {"service": "MSSQL", "risk": "High", "note": "Exposed database server, check for default credentials"},
    1434: {"service": "MSSQL Browser", "risk": "High", "note": "Can reveal SQL Server instance information"},
    3306: {"service": "MySQL", "risk": "High", "note": "Exposed database, check for default or weak credentials"},
    3389: {"service": "RDP", "risk": "Critical", "note": "RDP is a top target for brute force and BlueKeep exploits"},
    5432: {"service": "PostgreSQL", "risk": "High", "note": "Exposed database server, check for weak authentication"},
    5900: {"service": "VNC", "risk": "Critical", "note": "VNC often has weak or no authentication"},
    6379: {"service": "Redis", "risk": "Critical", "note": "Redis often runs without authentication by default"},
    8080: {"service": "HTTP-Proxy", "risk": "Medium", "note": "Alternative HTTP port, often used for admin panels"},
    8443: {"service": "HTTPS-Alt", "risk": "Low", "note": "Alternative HTTPS port, check for misconfigurations"},
    27017: {"service": "MongoDB", "risk": "Critical", "note": "MongoDB often exposed without authentication"},
}


class VulnScanner:
    def __init__(self, target, ports="1-1024", scan_type="basic"):
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.nm = nmap.PortScanner()
        self.results = {
            "target": target,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": [],
            "vulnerabilities": [],
            "os_detection": None,
            "summary": {}
        }

    def resolve_target(self):
        print(f"\n[*] Resolving target: {self.target}")
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[+] Target IP: {ip}")
            self.results["target_ip"] = ip
            return ip
        except socket.gaierror:
            print(f"[-] Could not resolve hostname: {self.target}")
            sys.exit(1)

    def banner_grab(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner[:200] if banner else "No banner"
        except Exception:
            return "No banner"

    def port_scan(self):
        ip = self.resolve_target()
        print(f"\n[*] Starting port scan on {ip}")
        print(f"[*] Port range: {self.ports}")
        print(f"[*] Scan type: {self.scan_type}")
        print("-" * 50)

        if self.scan_type == "basic":
            args = "-sT -T4"
        elif self.scan_type == "stealth":
            args = "-sS -T4"
        elif self.scan_type == "aggressive":
            args = "-sS -sV -O -T4"
        else:
            args = "-sT -T4"

        try:
            self.nm.scan(ip, self.ports, arguments=args)
        except nmap.PortScannerError as e:
            print(f"[-] Nmap error: {e}")
            print("[!] Try running with sudo for stealth/aggressive scans")
            sys.exit(1)

        for host in self.nm.all_hosts():
            print(f"\n[+] Host: {host} ({self.nm[host].hostname()})")
            print(f"[+] State: {self.nm[host].state()}")

            for proto in self.nm[host].all_protocols():
                ports = sorted(self.nm[host][proto].keys())
                for port in ports:
                    state = self.nm[host][proto][port]["state"]
                    service = self.nm[host][proto][port]["name"]
                    version = self.nm[host][proto][port].get("version", "")

                    if state == "open":
                        banner = self.banner_grab(ip, port)
                        port_info = {
                            "port": port,
                            "state": state,
                            "service": service,
                            "version": version,
                            "banner": banner
                        }
                        self.results["open_ports"].append(port_info)

                        risk = "Info"
                        note = ""
                        if port in RISKY_SERVICES:
                            risk = RISKY_SERVICES[port]["risk"]
                            note = RISKY_SERVICES[port]["note"]

                        color = {
                            "Critical": "\033[91m",
                            "High": "\033[93m",
                            "Medium": "\033[94m",
                            "Low": "\033[92m",
                            "Info": "\033[97m"
                        }.get(risk, "\033[97m")

                        reset = "\033[0m"
                        print(f"  {color}[{risk:^8}]{reset} Port {port:>5}/{proto} - {service} {version}")
                        if note:
                            print(f"           -> {note}")

        return self.results

    def check_vulnerabilities(self):
        print(f"\n[*] Analyzing vulnerabilities...")
        print("-" * 50)

        critical = 0
        high = 0
        medium = 0
        low = 0

        for port_info in self.results["open_ports"]:
            port = port_info["port"]
            if port in RISKY_SERVICES:
                vuln = {
                    "port": port,
                    "service": RISKY_SERVICES[port]["service"],
                    "risk": RISKY_SERVICES[port]["risk"],
                    "description": RISKY_SERVICES[port]["note"]
                }
                self.results["vulnerabilities"].append(vuln)

                if vuln["risk"] == "Critical":
                    critical += 1
                elif vuln["risk"] == "High":
                    high += 1
                elif vuln["risk"] == "Medium":
                    medium += 1
                else:
                    low += 1

        self.results["summary"] = {
            "total_open_ports": len(self.results["open_ports"]),
            "total_vulnerabilities": len(self.results["vulnerabilities"]),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        }

        print(f"\n  {'='*40}")
        print(f"  SCAN SUMMARY")
        print(f"  {'='*40}")
        print(f"  Open Ports Found    : {self.results['summary']['total_open_ports']}")
        print(f"  Vulnerabilities     : {self.results['summary']['total_vulnerabilities']}")
        print(f"  \033[91mCritical\033[0m            : {critical}")
        print(f"  \033[93mHigh\033[0m                : {high}")
        print(f"  \033[94mMedium\033[0m              : {medium}")
        print(f"  \033[92mLow\033[0m                 : {low}")
        print(f"  {'='*40}")

    def save_json(self, filename="scan_report.json"):
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"\n[+] JSON report saved: {filename}")

    def save_pdf(self, filename="scan_report.pdf"):
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", "B", 20)
        pdf.cell(0, 15, "Vulnerability Scan Report", ln=True, align="C")
        pdf.ln(5)

        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 8, f"Target: {self.results['target']}", ln=True)
        pdf.cell(0, 8, f"IP: {self.results.get('target_ip', 'N/A')}", ln=True)
        pdf.cell(0, 8, f"Date: {self.results['scan_date']}", ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Summary", ln=True)
        pdf.set_font("Arial", "", 11)
        s = self.results["summary"]
        pdf.cell(0, 8, f"Open Ports: {s['total_open_ports']}", ln=True)
        pdf.cell(0, 8, f"Vulnerabilities: {s['total_vulnerabilities']}", ln=True)
        pdf.cell(0, 8, f"Critical: {s['critical']}  |  High: {s['high']}  |  Medium: {s['medium']}  |  Low: {s['low']}", ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Open Ports", ln=True)
        pdf.set_font("Arial", "B", 10)
        pdf.cell(25, 8, "Port", 1)
        pdf.cell(40, 8, "Service", 1)
        pdf.cell(35, 8, "Version", 1)
        pdf.cell(25, 8, "Risk", 1)
        pdf.ln()
        pdf.set_font("Arial", "", 10)
        for p in self.results["open_ports"]:
            risk = RISKY_SERVICES.get(p["port"], {}).get("risk", "Info")
            pdf.cell(25, 8, str(p["port"]), 1)
            pdf.cell(40, 8, p["service"][:20], 1)
            pdf.cell(35, 8, p["version"][:18] if p["version"] else "-", 1)
            pdf.cell(25, 8, risk, 1)
            pdf.ln()
        pdf.ln(5)

        if self.results["vulnerabilities"]:
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Vulnerabilities Found", ln=True)
            pdf.set_font("Arial", "", 10)
            for v in self.results["vulnerabilities"]:
                pdf.set_font("Arial", "B", 10)
                pdf.cell(0, 8, f"[{v['risk']}] Port {v['port']} - {v['service']}", ln=True)
                pdf.set_font("Arial", "", 10)
                pdf.multi_cell(0, 7, f"  {v['description']}")
                pdf.ln(2)

        pdf.output(filename)
        print(f"[+] PDF report saved: {filename}")


def main():
    banner = """
    \033[96m
    =============================================
         VulnScanner v1.0
         Network Vulnerability Scanner
         [Your Name]
    =============================================
    \033[0m"""
    print(banner)

    parser = argparse.ArgumentParser(
        description="VulnScanner - Network Vulnerability Scanner"
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range to scan (default: 1-1024)"
    )
    parser.add_argument(
        "-s", "--scan-type",
        choices=["basic", "stealth", "aggressive"],
        default="basic",
        help="Scan type (default: basic)"
    )
    parser.add_argument(
        "--pdf", action="store_true",
        help="Generate PDF report"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Generate JSON report"
    )

    args = parser.parse_args()
    scanner = VulnScanner(args.target, args.ports, args.scan_type)
    scanner.port_scan()
    scanner.check_vulnerabilities()

    if args.json:
        scanner.save_json()
    if args.pdf:
        scanner.save_pdf()
    if not args.json and not args.pdf:
        scanner.save_json()
        scanner.save_pdf()

    print("\n[*] Scan complete!\n")


if __name__ == "__main__":
    main()
