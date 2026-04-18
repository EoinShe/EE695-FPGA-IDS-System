from scapy.all import PcapReader, PcapWriter, IP, TCP
import glob

OUTFILE = "syn_only.pcap"
LIMIT = 64

files = sorted(glob.glob("SAT-03-11-2018_*"))
count = 0

writer = PcapWriter(OUTFILE, sync=True)

for fname in files:
    try:
        for pkt in PcapReader(fname):
            if IP in pkt and TCP in pkt:
                flags = int(pkt[TCP].flags)
                # pure SYN only: SYN set, ACK not set
                if (flags & 0x02) and not (flags & 0x10):
                    writer.write(pkt)
                    count += 1
                    if count >= LIMIT:
                        writer.close()
                        print(f"Wrote {count} packets to {OUTFILE}")
                        raise SystemExit
    except Exception as e:
        print(f"Skipping {fname}: {e}")

writer.close()
print(f"Wrote {count} packets to {OUTFILE}")
eoin@Lab-pc:/media/sf_FPGA_Share/PCAP-03-11$ 
