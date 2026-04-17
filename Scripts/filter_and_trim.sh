#!/bin/bash

INPUT=$1
OUTPUT=$2
FILTER=$3

echo "[*] Filtering..."
tcpdump -r $INPUT "$FILTER" -w temp_clean.pcap

echo "[*] Trimming to 64 packets..."
tcpdump -r temp_clean.pcap -c 64 -w $OUTPUT

rm temp_clean.pcap

echo "[✓] Output: $OUTPUT"

echo "[*] Packet count:"
tcpdump -r "$OUTPUT" -q | wc -l