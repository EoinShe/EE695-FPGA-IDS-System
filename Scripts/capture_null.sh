#!/bin/bash
# ----------------------------------------
# command used to generate traffic
# Sends TCP packets with FIN + PSH + URG flags
# sudo nmap -sX -Pn <target-ip>
# for the Lab Pc it was:
# sudo nmap -sX -Pn 149.157.142.144
# ----------------------------------------

INPUT=$1
OUTPUT=$2

python3 pcap_to_ids_header.py $INPUT $OUTPUT

echo "[✓] Generated: $OUTPUT"