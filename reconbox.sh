#!/usr/bin/env bash
# === ReconBox v2.1 ===
# Author: Sahil
# Hardened, strict mode, timeouts configurable, input validation, signal traps

set -euo pipefail
IFS=$'\n\t'
trap 'echo -e "\n[!] Interrupted. Exiting."; exit 130' INT TERM

# --- Configuration ---
VERSION="v2.1"
LOG_DIR="${LOG_DIR:-./logs}"
SUBDOMAIN_WORDLIST=(www mail ftp test dev staging admin blog)
RDAP_TLDS="com net edu gov mil biz info"
WHOIS_TIMEOUT="${WHOIS_TIMEOUT:-8}"
RDAP_TIMEOUT="${RDAP_TIMEOUT:-10}"

# --- Usage ---
usage() {
  cat <<EOF
ReconBox ${VERSION}
All-in-one recon tool.

Usage:
  ${0##*/} [options]

Options:
  -t TARGET    Target domain or IPv4 address
  -m MODULE    Module to run (whois|dns|subs|geo|port|http|vuln)
  -o DIR       Output/log directory (default: ${LOG_DIR})
  -h           Show help
EOF
  exit 1
}

# --- Logging Helper ---
log() {
  # $1=module, $2=message
  local module=$1 msg=$2 ts
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  mkdir -p "$LOG_DIR"
  echo "[$ts] [$module] $msg" | tee -a "${LOG_DIR}/${module}.log"
}

# --- Dependency Checks ---
check_deps() {
  for cmd in whois dig curl jq nmap timeout; do
    if ! command -v "$cmd" &>/dev/null; then
      log "setup" "Installing missing dependency: $cmd"
      sudo dnf install -y "$cmd" \
        || { log "setup" "Failed to install $cmd"; exit 2; }
    fi
  done
}

ensure_docker() {
  if ! command -v docker &>/dev/null; then
    log "setup" "Docker not found—installing Docker"
    sudo dnf install -y docker docker-cli containerd \
      && sudo systemctl enable --now docker \
      && sudo usermod -aG docker "$USER" \
      || { log "setup" "Docker installation failed"; exit 3; }
    log "setup" "Docker installed. Please log out/in to activate group."
    exit 0
  fi
}

# --- Input Validation ---
validate_target() {
  local t=$1
  if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
     [[ "$t" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$ ]]; then
    return 0
  fi
  echo "❌ Invalid target: $t"
  exit 1
}

# --- Normalize for HTTP ---
normalize_target() {
  local t=$1
  if [[ "$t" =~ ^https?:// ]]; then
    echo "$t"
  else
    echo "http://$t"
  fi
}

# --- Module Functions ---
do_whois() {
  local t=$1 out resp rdap_url
  log "whois" "Starting WHOIS for $t"
  if out=$(timeout "${WHOIS_TIMEOUT}" whois "$t" 2>/dev/null) && [[ -n "$out" ]]; then
    echo "$out" | tee "${LOG_DIR}/whois.txt"
    return
  fi
  log "whois" "Local WHOIS timed out"
  if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    curl -s --max-time "${RDAP_TIMEOUT}" "https://ipinfo.io/$t/json" \
      | jq | tee "${LOG_DIR}/whois.txt"
  else
    local tld=${t##*.}
    if grep -qE "(^|,)${tld}(,|$)" <<< "$RDAP_TLDS"; then
      rdap_url="https://rdap.verisign.com/${tld}/v1/domain/$t"
    else
      rdap_url="https://rdap.iana.org/domain/$t"
    fi
    resp=$(curl -s --max-time "${RDAP_TIMEOUT}" "$rdap_url")
    echo "$resp" | jq | tee "${LOG_DIR}/whois.txt"
  fi
}

do_dns() {
  local t=$1
  log "dns" "Fetching DNS for $t"
  {
    echo "A:   $(dig +short A "$t")"
    echo "MX:  $(dig +short MX "$t")"
    echo "NS:  $(dig +short NS "$t")"
    echo "TXT: $(dig +short TXT "$t")"
  } | tee "${LOG_DIR}/dns.txt"
}

do_subs() {
  local t=$1 fqdn ips
  log "subs" "Scanning subdomains of $t"
  printf "%s\n" "${SUBDOMAIN_WORDLIST[@]}" \
    | xargs -I{} -P10 bash -c '
        fqdn="{}.'"$t"'"
        ips=$(dig +short A "$fqdn")
        if [[ -n "$ips" ]]; then
          echo "[+] $fqdn → $ips"
        else
          echo "[-] $fqdn"
        fi' \
    | tee "${LOG_DIR}/subs.txt"
}

do_geo() {
  local t=$1 ip
  log "geo" "IP Geolocation for $t"
  if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip=$t
  else
    ip=$(dig +short A "$t" | head -n1)
    echo "Resolved $t → $ip"
  fi
  curl -s --max-time "${RDAP_TIMEOUT}" "https://ipinfo.io/$ip/json" \
    | jq | tee "${LOG_DIR}/geo.txt"
}

do_port() {
  local t=$1
  log "port" "Port Scan for $t"
  nmap -Pn -sC -sV --top-ports 1000 -T4 "$t" \
    | tee "${LOG_DIR}/port.txt"
}

do_http() {
  local t=$1 norm html title
  log "http" "HTTP info for $t"
  norm=$(normalize_target "$t")
  echo "🛡️ Server Banner:"
  curl -sI -L "$norm" | grep -i '^Server:' \
    | tee "${LOG_DIR}/http.txt"
  echo -e "\n📥 Full HTML:"
  html=$(curl -sL --max-time "${RDAP_TIMEOUT}" "$norm")
  echo "$html" | tee -a "${LOG_DIR}/http.txt"
  echo -e "\n🔖 Page Title:"
  title=$(grep -iPo '(?<=<title>)[^<]+' <<< "$html" | head -1)
  echo "${title:-No <title> found.}" | tee -a "${LOG_DIR}/http.txt"
}

do_vuln() {
  local t=$1
  log "vuln" "Running Nikto against $t"
  if command -v nikto &>/dev/null; then
    nikto -host "$t" | tee "${LOG_DIR}/vuln.txt"
  else
    docker run --rm -v "$(pwd)":/data:Z kalilinux/kali-rolling \
      /bin/bash -c "apt update -y && apt install -y nikto && nikto -host $t" \
      | tee "${LOG_DIR}/vuln.txt"
  fi
}

# --- Interactive Menu ---
interactive_menu() {
  while true; do
    cat <<EOF
Choose a recon option:
  1) WHOIS Lookup
  2) DNS Records
  3) Subdomain Scan
  4) IP Geolocation
  5) Port Scan
  6) HTTP Info
  7) Vulnerability Scan (Nikto)
  8) Exit
EOF
    read -rp "Enter choice [1-8]: " choice
    case $choice in
      1) do_whois "$TARGET" ;;
      2) do_dns   "$TARGET" ;;
      3) do_subs  "$TARGET" ;;
      4) do_geo   "$TARGET" ;;
      5) do_port  "$TARGET" ;;
      6) do_http  "$TARGET" ;;
      7) do_vuln  "$TARGET" ;;
      8) exit 0 ;;
      *) echo "❌ Invalid option";;
    esac
  done
}

# --- Main Logic ---

# Parse flags
while getopts "t:m:o:h" opt; do
  case $opt in
    t) TARGET=$OPTARG ;;
    m) MODULE=$OPTARG ;;
    o) LOG_DIR=$OPTARG ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND -1))

# Validate and prepare
[[ -z "${TARGET:-}" ]] && read -rp "Enter target domain or IP: " TARGET
validate_target "$TARGET"
mkdir -p "$LOG_DIR"

# Setup
check_deps
ensure_docker

# Execute
if [[ -z "${MODULE:-}" ]]; then
  interactive_menu
else
  case $MODULE in
    whois) do_whois "$TARGET" ;;
    dns)   do_dns   "$TARGET" ;;
    subs)  do_subs  "$TARGET" ;;
    geo)   do_geo   "$TARGET" ;;
    port)  do_port  "$TARGET" ;;
    http)  do_http  "$TARGET" ;;
    vuln)  do_vuln  "$TARGET" ;;
    *) echo "❌ Unknown module: $MODULE"; usage ;;
  esac
fi
