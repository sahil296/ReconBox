
**Author:** Sahil  


An all-in-one,reconnaissance framework in Bash.  
Modular, strictly-harded, with interactive menu and non-interactive CLI modes.  

---

## 🚀 Features

- **WHOIS Lookup** — local port 43 lookup, RDAP fallback, IP Info for IPv4  
- **DNS Records** — A, MX, NS, TXT queries via `dig`  
- **Subdomain Enumeration** — parallel scans from built-in wordlist  
- **IP Geolocation** — resolves domain → IP, then uses `ipinfo.io`  
- **Port Scanning** — Nmap top 1000 ports, default scripts & version detection  
- **HTTP Fingerprinting** — headers, full HTML dump, page `<title>` extraction  
- **Vulnerability Scan** — Nikto if installed, otherwise Docker Kali fallback  
- **Logging** — per-module logs in `logs/`, plus live terminal output  
- **Strict Mode** — `set -euo pipefail`, safe IFS, signal traps  
- **Configurable** — timeouts, log directory, wordlists, TLD lists via variables  
- **Interactive & Non-Interactive** — run in menu or via `-m MODULE` flags  

---

## 📦 Prerequisites

On **Fedora/Asahi**:

```bash
sudo dnf install -y whois bind-utils curl jq nmap coreutils  # coreutils for timeout
sudo dnf install -y docker docker-cli containerd            # for Nikto fallback
sudo systemctl enable --now docker
sudo usermod -aG docker $USER



💻 Installation

    Clone or copy reconbox.sh into your working directory.

    Make it executable:

chmod +x reconbox.sh

(Optional) Install ShellCheck and lint:

    shellcheck reconbox.sh

⚙️ Usage
Interactive Menu

./reconbox.sh

    Enter your target domain or IPv4 address.

    Choose an option [1–8] from the menu.

    View results on screen and in logs/<module>.txt.

Non-Interactive Mode

./reconbox.sh -t example.com -m MODULE [-o ./mylogs]

    -t TARGET — domain or IPv4

    -m MODULE — one of:

        whois | dns | subs | geo | port | http | vuln

    -o DIR — override default ./logs directory

    -h — show help/usage

Example:

./reconbox.sh -t 8.8.8.8 -m geo

🔧 Configuration

    VERSION — script version

    LOG_DIR — directory for logs (default: ./logs)

    SUBDOMAIN_WORDLIST — bash array of subdomains to test

    RDAP_TLDS — comma-separated list of TLDs for Verisign RDAP

    WHOIS_TIMEOUT / RDAP_TIMEOUT — seconds for timeout and curl --max-time

You can override via environment variables:

export LOG_DIR=~/recon_logs
export WHOIS_TIMEOUT=5