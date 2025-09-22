#!/usr/bin/env bash
# recon.sh - basic automated recon: subdomain enum, nmap, traceroute
# Usage: ./recon.sh target.com [output_dir]
# Requirements (recommended): amass, subfinder, assetfinder, curl, jq (optional), nmap, traceroute, dig, awk, sort, uniq
# The script will skip tools that are not installed and will continue with available ones.

set -euo pipefail
IFS=$'\n\t'

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 target.com [output_dir]"
  exit 1
fi

TARGET="$1"
OUT_BASE="${2:-recon_${TARGET}_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUT_BASE"
SUMMARY="$OUT_BASE/summary.txt"

echo "Recon run for: $TARGET" > "$SUMMARY"
echo "Output directory: $OUT_BASE" >> "$SUMMARY"
echo "Started: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" >> "$SUMMARY"
echo "" >> "$SUMMARY"

log() {
  echo "[$(date +"%H:%M:%S")] $*"
}

check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# 1) Subdomain enumeration
log "Starting subdomain enumeration..."
SUBS_RAW="$OUT_BASE/subdomains_raw.txt"
> "$SUBS_RAW"

# amass
if check_cmd amass; then
  log "Running amass (passive)..."
  amass enum -passive -d "$TARGET" -o "$OUT_BASE/amass.txt" || true
  [ -s "$OUT_BASE/amass.txt" ] && cat "$OUT_BASE/amass.txt" >> "$SUBS_RAW"
else
  log "amass not installed, skipping."
fi

# subfinder
if check_cmd subfinder; then
  log "Running subfinder..."
  subfinder -d "$TARGET" -silent -o "$OUT_BASE/subfinder.txt" || true
  [ -s "$OUT_BASE/subfinder.txt" ] && cat "$OUT_BASE/subfinder.txt" >> "$SUBS_RAW"
else
  log "subfinder not installed, skipping."
fi

# assetfinder
if check_cmd assetfinder; then
  log "Running assetfinder..."
  assetfinder --subs-only "$TARGET" > "$OUT_BASE/assetfinder.txt" 2>/dev/null || true
  [ -s "$OUT_BASE/assetfinder.txt" ] && cat "$OUT_BASE/assetfinder.txt" >> "$SUBS_RAW"
else
  log "assetfinder not installed, skipping."
fi

# crt.sh (public certificate transparency) fallback using curl
if check_cmd curl; then
  log "Querying crt.sh for certificates..."
  # note: this may return JSON or HTML; try JSON endpoint first (some crt.sh installs)
  CRT_JSON="$OUT_BASE/crt_sh.json"
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" -o "$CRT_JSON" || true
  if [ -s "$CRT_JSON" ]; then
    # extract common_name and name_value if jq present, otherwise use grep
    if check_cmd jq; then
      jq -r '.[].name_value' "$CRT_JSON" | sed 's/\*\.//g' >> "$SUBS_RAW" || true
    else
      # crude extraction fallback
      grep -oE "[A-Za-z0-9._-]+\\.$TARGET" "$CRT_JSON" | sed 's/\*\.//g' >> "$SUBS_RAW" || true
    fi
  fi
else
  log "curl missing — cannot query crt.sh"
fi

# Optionally, add more tools (massdns, dnsdumpster, etc.) here.

# Normalise, dedupe, resolve
log "Cleaning and deduplicating subdomains..."
SUBS_CLEAN="$OUT_BASE/subdomains_clean.txt"
cat "$SUBS_RAW" | sed 's/^[[:space:]]*//' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]' | sort -u > "$SUBS_CLEAN"

log "Found $(wc -l < "$SUBS_CLEAN" | tr -d ' ') unique subdomains."
echo "Subdomains found: $(wc -l < "$SUBS_CLEAN" | tr -d ' ')" >> "$SUMMARY"

# 2) Resolve subdomains to IPs
log "Resolving subdomains to IP addresses..."
RESOLVED="$OUT_BASE/resolved.txt"
> "$RESOLVED"

while read -r host; do
  # skip empty lines
  [ -z "$host" ] && continue
  ips=$(dig +short A "$host" | tr '\n' ' ')
  if [ -n "$ips" ]; then
    echo "$host,$ips" >> "$RESOLVED"
  else
    # try CNAME/AAAA
    ips=$(dig +short AAAA "$host" | tr '\n' ' ')
    [ -n "$ips" ] && echo "$host,$ips" >> "$RESOLVED"
  fi
done < "$SUBS_CLEAN"

log "Resolved $(wc -l < "$RESOLVED" | tr -d ' ') hosts with at least one IP."
echo "Resolved hosts count: $(wc -l < "$RESOLVED" | tr -d ' ')" >> "$SUMMARY"

# 3) Port/service discovery with nmap
# Build list of unique IPs
IPS_LIST="$OUT_BASE/ips_unique.txt"
awk -F, '{ for(i=2;i<=NF;i++) print $i }' "$RESOLVED" | tr ' ' '\n' | sed '/^$/d' | sort -u > "$IPS_LIST"

NMAP_DIR="$OUT_BASE/nmap"
mkdir -p "$NMAP_DIR"

if check_cmd nmap; then
  if [ -s "$IPS_LIST" ]; then
    log "Running nmap scans on resolved IPs (this may take some time)..."
    # quick service scan + default scripts, top 1000 ports, service/version detection
    # -T4 speeds up on reliable networks; adjust if needed
    nmap -sV -sC -T4 -Pn -iL "$IPS_LIST" -oA "$NMAP_DIR/scan" || true
    echo "Nmap output directory: $NMAP_DIR" >> "$SUMMARY"
  else
    log "No IPs to scan with nmap."
  fi
else
  log "nmap not installed, skipping port scans."
fi

# 4) traceroute for live hosts (use one traceroute per unique IP)
TR_DIR="$OUT_BASE/traceroutes"
mkdir -p "$TR_DIR"
if check_cmd traceroute; then
  if [ -s "$IPS_LIST" ]; then
    log "Running traceroute for each IP..."
    while read -r ip; do
      outf="$TR_DIR/traceroute_${ip//:/_}.txt"
      (echo "Traceroute to $ip - $(date)"; traceroute -n "$ip") > "$outf" 2>&1 || true
    done < "$IPS_LIST"
    echo "Traceroutes saved to $TR_DIR" >> "$SUMMARY"
  fi
else
  log "traceroute not installed, skipping traceroutes."
fi

# 5) Per-host HTTP probe (optional if httpx is available)
if check_cmd httpx; then
  log "Running httpx to probe for web services..."
  httpx -l "$SUBS_CLEAN" -o "$OUT_BASE/httpx.txt" -silent || true
  echo "HTTP probe saved: $OUT_BASE/httpx.txt" >> "$SUMMARY"
else
  log "httpx not installed, skipping HTTP probing."
fi

# 6) Simple summary output: combine top-level results into a human-readable file
echo "" >> "$SUMMARY"
echo "---- Top-level files generated ----" >> "$SUMMARY"
ls -1 "$OUT_BASE" | sed 's/^/ - /' >> "$SUMMARY"

log "Recon complete. Summary saved to $SUMMARY"
echo ""
echo "Quick summary:"
cat "$SUMMARY"

exit 0
