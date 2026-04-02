# VulnScanner - Network Vulnerability Scanner

A Python-based network vulnerability scanner that identifies open ports, grabs service banners, and flags potential security risks. Built for cybersecurity professionals and penetration testers.

## Features
- **Port Scanning** - TCP port scanning with configurable ranges
- **Service Detection** - Identifies running services and versions
- **Banner Grabbing** - Extracts service banners for fingerprinting
- **Vulnerability Assessment** - Flags risky services with severity ratings (Critical/High/Medium/Low)
- **Report Generation** - Exports results as PDF and JSON reports
- **Multiple Scan Modes** - Basic, Stealth (SYN), and Aggressive scanning

## Installation

```bash
git clone https://github.com/mhmilki/VulnScanner.git
cd VulnScanner
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### Requirements
- Python 3.8+
- Nmap installed on system (sudo apt install nmap)
- python-nmap
- fpdf

## Usage

```bash
# Basic scan
sudo $(which python3) vulnscanner.py <target>

# Scan specific ports
sudo $(which python3) vulnscanner.py 192.168.1.1 -p 1-65535

# Stealth scan with PDF report
sudo $(which python3) vulnscanner.py 10.0.0.1 -s stealth --pdf

# Aggressive scan (includes OS detection)
sudo $(which python3) vulnscanner.py target.com -s aggressive --pdf --json
```

### Options
| Flag | Description |
|------|-------------|
| -p, --ports | Port range (default: 1-1024) |
| -s, --scan-type | basic / stealth / aggressive |
| --pdf | Generate PDF report |
| --json | Generate JSON report |

## Sample Output

```
[Critical] Port   445/tcp - microsoft-ds
           -> SMB is frequently targeted (EternalBlue, WannaCry)
[High    ] Port  3306/tcp - mysql 8.0.32
           -> Exposed database, check for default or weak credentials
[Medium  ] Port    80/tcp - http Apache 2.4.54
           -> Unencrypted web traffic, check for outdated web servers
```

## Disclaimer
This tool is for **authorized security testing only**. Always obtain proper written permission before scanning any network or system. Unauthorized scanning is illegal.

## License
MIT License
