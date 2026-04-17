#!/bin/bash

FILE=$1
echo "Packet count:"
tcpdump -r "$FILE" | wc -l
echo
echo "First 10 packets:"
tcpdump -r "$FILE" -c 10