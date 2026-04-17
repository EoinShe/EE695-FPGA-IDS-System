from pathlib import Path

HEX_FILE = "syn_64.hex"
LEN_FILE = "syn_64_lengths.hex"
OUT_FILE = "ids_test_packets.h"

WORDS_PER_PACKET = 16  # padded size


def read_hex_words(filename):
    words = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                words.append(int(line, 16))
    return words


def read_lengths(filename):
    lengths = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                lengths.append(int(line, 16))
    return lengths


def format_words(words):
    return ",\n            ".join(f"0x{w:08X}" for w in words)


def main():
    words = read_hex_words(HEX_FILE)
    lengths = read_lengths(LEN_FILE)

    packets = []
    idx = 0

    for length in lengths:
        pkt_words = words[idx:idx + length]
        idx += length

        # pad to 16 words
        pkt_words += [0] * (WORDS_PER_PACKET - len(pkt_words))

        packets.append((length, pkt_words))

    entries = []
    for length, pkt_words in packets:
        entry = (
            "    {\n"
            f"        .len_words = {length},\n"
            "        .words = {\n"
            f"            {format_words(pkt_words)}\n"
            "        }\n"
            "    }"
        )
        entries.append(entry)

    joined = ",\n".join(entries)

    header = f"""#ifndef IDS_TEST_PACKETS_H
#define IDS_TEST_PACKETS_H

#include <stdint.h>

typedef struct {{
    uint16_t len_words;
    uint32_t words[{WORDS_PER_PACKET}];
}} packet_record_t;

static const packet_record_t ids_test_packets[] = {{
{joined}
}};

static const uint32_t ids_test_packets_count =
    sizeof(ids_test_packets) / sizeof(ids_test_packets[0]);

#endif
"""

    Path(OUT_FILE).write_text(header)
    print(f"Generated {OUT_FILE} with {len(packets)} packets")


if __name__ == "__main__":
    main()
eoin@Lab-pc:/media/sf_FPGA_Share/PCAP-03-11$ 