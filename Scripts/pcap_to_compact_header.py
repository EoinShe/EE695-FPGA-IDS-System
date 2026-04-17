eoin@Lab-pc:/media/sf_FPGA_Share/PCAP-03-11$ cat pcap_to_compact_header.py
from pathlib import Path
from scapy.all import rdpcap, IP, TCP

PCAP_FILE = "syn_64.pcapng"
OUT_H = "syn_64_syn_only.h"

TOTAL_SLOTS = 16
LEN_WORDS = 12


def ip_to_u32(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def build_parser_compatible_packet(dst_ip_u32: int, proto: int, tcp_flags: int) -> list[int]:
    dst_hi = (dst_ip_u32 >> 16) & 0xFFFF
    dst_lo = dst_ip_u32 & 0xFFFF

    words = [0x00000000] * LEN_WORDS
    words[3] = 0x0800 << 16
    words[5] = proto & 0xFF
    words[7] = dst_hi
    words[8] = dst_lo << 16
    words[11] = tcp_flags & 0xFF
    return words


def format_words(words: list[int], total_slots: int = TOTAL_SLOTS) -> str:
    padded = words + [0x00000000] * (total_slots - len(words))
    return ",\n            ".join(f"0x{w:08X}" for w in padded)


def extract_compact_fields(pkt):
    if IP not in pkt or TCP not in pkt:
        return None

    ip = pkt[IP]
    tcp = pkt[TCP]

    proto = int(ip.proto)
    if proto != 0x06:
        return None

    tcp_flags = int(tcp.flags) & 0xFF

    # Only keep SYN-only packets
    if tcp_flags != 0x02:
        return None

    dst_ip_u32 = ip_to_u32(ip.dst)
    return dst_ip_u32, proto, tcp_flags


def generate_header_from_pcap(pcap_file: str) -> str:
    packets = rdpcap(pcap_file)
    entries = []

    for pkt in packets:
        fields = extract_compact_fields(pkt)
        if fields is None:
            continue

        dst_ip_u32, proto, tcp_flags = fields
        words = build_parser_compatible_packet(dst_ip_u32, proto, tcp_flags)

        entry = (
            "    {\n"
            f"        .len_words = {LEN_WORDS},\n"
            "        .words = {\n"
            f"            {format_words(words)}\n"
            "        }\n"
            "    }"
        )
        entries.append(entry)

    joined_entries = ",\n".join(entries)

    return f"""#ifndef IDS_TEST_PACKETS_H
#define IDS_TEST_PACKETS_H

#include <stdint.h>

typedef struct {{
    uint16_t len_words;
    uint32_t words[{TOTAL_SLOTS}];
}} packet_record_t;

static const packet_record_t ids_test_packets[] = {{
{joined_entries}
}};

static const uint32_t ids_test_packets_count =
    sizeof(ids_test_packets) / sizeof(ids_test_packets[0]);

#endif
"""


def main():
    text = generate_header_from_pcap(PCAP_FILE)
    Path(OUT_H).write_text(text, encoding="utf-8")
    print(f"Generated: {OUT_H}")


if __name__ == "__main__":
    main()
eoin@Lab-pc:/media/sf_FPGA_Share/PCAP-03-11$ 
