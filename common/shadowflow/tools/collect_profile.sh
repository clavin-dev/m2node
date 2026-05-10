#!/bin/bash
# ====================================================================
# ShadowFlow Traffic Profile Collector
#
# Captures real browser TLS traffic and extracts TLS record sizes
# for building accurate traffic profiles.
#
# Usage:
#   1. Upload this script to a clean VPS outside GFW
#   2. Run: bash collect_profile.sh <target_url> [profile_name]
#   3. Download the generated JSON profile
#   4. Import into ShadowFlow via panel or config file
#
# Requirements:
#   - tshark (Wireshark CLI)
#   - chromium or google-chrome (headless)
#   - jq
# ====================================================================

set -euo pipefail

# Default values
TARGET_URL="${1:-https://www.google.com}"
PROFILE_NAME="${2:-captured_profile}"
CAPTURE_DURATION="${3:-30}"  # seconds
INTERFACE="${4:-any}"
OUTPUT_DIR="./profiles"
PCAP_FILE="${OUTPUT_DIR}/${PROFILE_NAME}.pcap"
JSON_FILE="${OUTPUT_DIR}/${PROFILE_NAME}.json"

echo "================================================"
echo "  ShadowFlow Traffic Profile Collector"
echo "================================================"
echo "  Target URL:     ${TARGET_URL}"
echo "  Profile Name:   ${PROFILE_NAME}"
echo "  Capture Time:   ${CAPTURE_DURATION}s"
echo "  Interface:      ${INTERFACE}"
echo "================================================"

# Check dependencies
for cmd in tshark jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "ERROR: $cmd is required but not installed."
        echo "  Install with: apt-get install -y tshark jq"
        exit 1
    fi
done

# Find Chrome/Chromium
CHROME=""
for browser in google-chrome chromium-browser chromium; do
    if command -v "$browser" &> /dev/null; then
        CHROME="$browser"
        break
    fi
done

if [ -z "$CHROME" ]; then
    echo "WARNING: No Chrome/Chromium found. Using curl as fallback."
    echo "  For best results, install: apt-get install -y chromium-browser"
fi

mkdir -p "$OUTPUT_DIR"

# Step 1: Start packet capture
echo ""
echo "[1/4] Starting packet capture on ${INTERFACE}..."
tshark -i "$INTERFACE" -f "tcp port 443" -w "$PCAP_FILE" -a duration:"$CAPTURE_DURATION" &
TSHARK_PID=$!
sleep 2

# Step 2: Generate traffic
echo "[2/4] Generating traffic to ${TARGET_URL}..."
if [ -n "$CHROME" ]; then
    # Use headless Chrome for realistic browser traffic
    timeout "$CAPTURE_DURATION" "$CHROME" \
        --headless \
        --disable-gpu \
        --no-sandbox \
        --disable-dev-shm-usage \
        --user-data-dir="/tmp/chrome_profile_$$" \
        --window-size=1920,1080 \
        "$TARGET_URL" \
        "https://www.youtube.com" \
        "https://mail.google.com" \
        "https://docs.google.com" \
        2>/dev/null || true
else
    # Fallback: use curl with HTTP/2
    for i in $(seq 1 10); do
        curl -s -o /dev/null --http2 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "$TARGET_URL" &
    done
    wait
fi

# Wait for capture to finish
echo "[3/4] Waiting for capture to complete..."
wait "$TSHARK_PID" 2>/dev/null || true
echo "  Captured: $(ls -lh "$PCAP_FILE" | awk '{print $5}')"

# Step 3: Extract TLS record sizes
echo "[4/4] Extracting TLS record sizes..."

# Extract TLS records with direction info
# Fields: frame.number, ip.src, ip.dst, tcp.srcport, tcp.dstport, tls.record.length, frame.time_epoch
tshark -r "$PCAP_FILE" \
    -Y "tls.record.content_type == 23" \
    -T fields \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tls.record.length \
    -e frame.time_epoch \
    -E separator=, \
    2>/dev/null | head -2000 > "${OUTPUT_DIR}/raw_records.csv"

RECORD_COUNT=$(wc -l < "${OUTPUT_DIR}/raw_records.csv")
echo "  Extracted ${RECORD_COUNT} TLS Application Data records"

if [ "$RECORD_COUNT" -lt 10 ]; then
    echo "ERROR: Too few records captured. Try increasing duration or checking interface."
    exit 1
fi

# Step 4: Build JSON profile
echo ""
echo "Building profile..."

# Determine client IP (source port > 1024 = client)
# C→S: srcport > 1024, dstport == 443
# S→C: srcport == 443, dstport > 1024

python3 << 'PYEOF'
import csv
import json
import sys
import os

output_dir = os.environ.get('OUTPUT_DIR', './profiles')
profile_name = os.environ.get('PROFILE_NAME', 'captured_profile')
json_file = os.environ.get('JSON_FILE', f'{output_dir}/{profile_name}.json')

c2s_sizes = []
s2c_sizes = []
c2s_initial = []
s2c_initial = []
c2s_count = 0
s2c_count = 0

with open(f'{output_dir}/raw_records.csv', 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        if len(row) < 6:
            continue
        try:
            srcport = int(row[3])
            dstport = int(row[4])
            # tls.record.length may have multiple values separated by comma
            sizes = [int(s.strip()) for s in row[5].split(',') if s.strip().isdigit()]
        except (ValueError, IndexError):
            continue
        
        for size in sizes:
            if size <= 0 or size > 16384:
                continue
            
            if dstport == 443 and srcport > 1024:
                # C→S
                c2s_sizes.append(size)
                if c2s_count < 4:
                    c2s_initial.append(size)
                c2s_count += 1
            elif srcport == 443 and dstport > 1024:
                # S→C
                s2c_sizes.append(size)
                if s2c_count < 4:
                    s2c_initial.append(size)
                s2c_count += 1

def build_distribution(sizes, bucket_count=5):
    if not sizes:
        return [{"Min": 26, "Max": 16384, "Weight": 100}]
    sizes.sort()
    ranges = []
    for i in range(bucket_count):
        start = len(sizes) * i // bucket_count
        end = len(sizes) * (i + 1) // bucket_count
        if start >= end:
            continue
        bucket = sizes[start:end]
        ranges.append({
            "Min": bucket[0],
            "Max": bucket[-1],
            "Weight": 20
        })
    return ranges

def build_initial(sizes):
    result = []
    for s in sizes:
        margin = max(s // 5, 5)
        result.append({
            "MinSize": max(20, s - margin),
            "MaxSize": min(16384, s + margin)
        })
    return result

min_size = min(c2s_sizes + s2c_sizes) if (c2s_sizes or s2c_sizes) else 26

profile = {
    "Name": profile_name,
    "C2SSizes": build_distribution(c2s_sizes),
    "S2CSizes": build_distribution(s2c_sizes),
    "C2SInitial": build_initial(c2s_initial),
    "S2CInitial": build_initial(s2c_initial),
    "MinRecordPayload": max(min_size, 20),
    "MaxRecordPayload": 16384
}

with open(json_file, 'w') as f:
    json.dump(profile, f, indent=2)

print(f"  C→S records: {len(c2s_sizes)}")
print(f"  S→C records: {len(s2c_sizes)}")
print(f"  Min size:    {min_size}")
print(f"  C→S distribution: {len(profile['C2SSizes'])} buckets")
print(f"  S→C distribution: {len(profile['S2CSizes'])} buckets")
print(f"  Initial C→S: {[s for s in c2s_initial[:4]]}")
print(f"  Initial S→C: {[s for s in s2c_initial[:4]]}")
PYEOF

echo ""
echo "================================================"
echo "  Profile saved: ${JSON_FILE}"
echo "================================================"
echo ""
echo "To use this profile in ShadowFlow:"
echo "  1. Copy ${JSON_FILE} to your v2node server"
echo "  2. Place it at /etc/v2node/profiles/${PROFILE_NAME}.json"
echo "  3. In panel shaping_settings, set:"
echo '     {"custom_profiles": ["/etc/v2node/profiles/'"${PROFILE_NAME}"'.json"]}'
echo ""

# Cleanup
rm -f "${OUTPUT_DIR}/raw_records.csv"
rm -rf "/tmp/chrome_profile_$$"

echo "Done!"
