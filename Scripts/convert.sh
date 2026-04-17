#!/bin/bash

INPUT=$1
OUTPUT=$2

python3 pcap_to_ids_header.py $INPUT $OUTPUT

echo "[✓] Generated: $OUTPUT"