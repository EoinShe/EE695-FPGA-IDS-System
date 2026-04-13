from dataclasses import dataclass


@dataclass
class ScenarioItem:
    source_name: str
    source_ip: str
    dest_name: str
    dest_ip: str
    attack_type: str
    packet_count: int


def ip_to_u32(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def attack_to_proto_flags(attack_type: str) -> tuple[int, int]:
    if attack_type == "Normal":
        return 0x06, 0x12
    if attack_type == "SYN Flood":
        return 0x06, 0x02
    if attack_type == "UDP Flood":
        return 0x11, 0x00
    if attack_type == "ICMP Flood":
        return 0x01, 0x00
    if attack_type == "Xmas Scan":
        return 0x06, 0x29
    if attack_type == "Null Scan":
        return 0x06, 0x00
    return 0x06, 0x12


def build_parser_compatible_packet(dst_ip: str, attack_type: str) -> list[int]:
    """
    Build a minimal 12-word packet matching the Verilog parser expectations.

    Verilog expects:
      word 3  -> tdata[31:16] = ethertype (0x0800 for IPv4)
      word 5  -> tdata[7:0]   = IP protocol
      word 7  -> tdata[15:0]  = dst_ip[31:16]
      word 8  -> tdata[31:16] = dst_ip[15:0]
      word 11 -> tdata[7:0]   = TCP flags
    """
    proto, flags = attack_to_proto_flags(attack_type)
    dst = ip_to_u32(dst_ip)

    dst_hi = (dst >> 16) & 0xFFFF
    dst_lo = dst & 0xFFFF

    words = [0x00000000] * 12

    words[3] = 0x0800 << 16
    words[5] = proto & 0xFF
    words[7] = dst_hi
    words[8] = dst_lo << 16
    words[11] = flags & 0xFF

    return words


def format_words(words: list[int], total_slots: int = 16) -> str:
    padded = words + [0x00000000] * (total_slots - len(words))
    return ",\n            ".join(f"0x{w:08X}" for w in padded)


def generate_header_text(items: list[ScenarioItem]) -> str:
    entries = []

    for item in items:
        for _ in range(item.packet_count):
            words = build_parser_compatible_packet(item.dest_ip, item.attack_type)

            entry = (
                "    {\n"
                "        .len_words = 12,\n"
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
    uint32_t words[16];
}} packet_record_t;

static const packet_record_t ids_test_packets[] = {{
{joined_entries}
}};

static const uint32_t ids_test_packets_count =
    sizeof(ids_test_packets) / sizeof(ids_test_packets[0]);

#endif
""" 