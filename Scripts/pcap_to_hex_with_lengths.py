from scapy.all import rdpcap
import struct

PCAP_FILE = "syn_64.pcapng"
OUT_HEX   = "syn_64.hex"
OUT_LEN   = "syn_64_lengths.hex"

def bytes_to_words(data):
    # pad to multiple of 4 bytes
    if len(data) % 4 != 0:
        data += b'\x00' * (4 - (len(data) % 4))

    words = []
    for i in range(0, len(data), 4):
        word = struct.unpack(">I", data[i:i+4])[0]  # big-endian
        words.append(word)

    return words

def main():
    packets = rdpcap(PCAP_FILE)

    with open(OUT_HEX, "w") as f_hex, open(OUT_LEN, "w") as f_len:

        for pkt in packets:
            raw = bytes(pkt)
            words = bytes_to_words(raw)

            # write words
            for w in words:
                f_hex.write(f"{w:08X}\n")

            # write length (in words)
            f_len.write(f"{len(words):04X}\n")

    print(f"Generated:")
    print(f"  {OUT_HEX}")
    print(f"  {OUT_LEN}")
    print(f"Packets: {len(packets)}")

if __name__ == "__main__":
    main()
