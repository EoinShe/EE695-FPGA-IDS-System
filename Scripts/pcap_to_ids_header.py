eoin@Lab-pc:/media/sf_FPGA_Share$ cat pcap_to_ids_header.py
from pathlib import Path
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import sys


TOTAL_SLOTS = 16
LEN_WORDS = 12


def ip_to_u32(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def build_parser_compatible_packet(dst_ip_u32: int, proto: int, tcp_flags: int) -> list[int]:
    """
    Build the 12-word compact packet format expected by the Verilog parser.

    word 3  -> tdata[31:16] = ethertype (0x0800 for IPv4)
    word 5  -> tdata[7:0]   = IP protocol
    word 7  -> tdata[15:0]  = dst_ip[31:16]
    word 8  -> tdata[31:16] = dst_ip[15:0]
    word 11 -> tdata[7:0]   = TCP flags
    """
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


def sanitize_identifier(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum():
            out.append(ch.upper())
        else:
            out.append("_")
    ident = "".join(out)
    while "__" in ident:
        ident = ident.replace("__", "_")
    return ident.strip("_")


def extract_compact_fields(pkt):
    """
    Returns (dst_ip_u32, proto, tcp_flags) or None if packet is not usable.
    """
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = int(ip.proto)
    dst_ip_u32 = ip_to_u32(ip.dst)

    if proto == 0x06 and TCP in pkt:
        tcp_flags = int(pkt[TCP].flags) & 0xFF
    elif proto == 0x11 and UDP in pkt:
        tcp_flags = 0x00
    elif proto == 0x01 and ICMP in pkt:
        tcp_flags = 0x00
    else:
        tcp_flags = 0x00

    return dst_ip_u32, proto, tcp_flags


def generate_header_from_pcap(pcap_file: str, array_name: str, guard_name: str) -> str:
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

    return f"""#ifndef {guard_name}
#define {guard_name}

#include <stdint.h>

typedef struct {{
    uint16_t len_words;
    uint32_t words[{TOTAL_SLOTS}];
}} packet_record_t;

static const packet_record_t {array_name}[] = {{
{joined_entries}
}};

static const uint32_t {array_name}_count =
    sizeof({array_name}) / sizeof({array_name}[0]);

#endif
"""


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 pcap_to_ids_header.py <input.pcap> <output.h> <array_name>")
        print("Example: python3 pcap_to_ids_header.py null_64.pcap null_packet_real_world.h null_packet_real_world")
        sys.exit(1)

    pcap_file = sys.argv[1]
    out_file = sys.argv[2]
    array_name = sys.argv[3]

    stem = Path(out_file).stem
    guard_name = sanitize_identifier(stem) + "_H"

    text = generate_header_from_pcap(pcap_file, array_name=array_name, guard_name=guard_name)
    Path(out_file).write_text(text, encoding="utf-8")
    print(f"Generated: {out_file}")


if __name__ == "__main__":
    main()
eoin@Lab-pc:/media/sf_FPGA_Share$ 
