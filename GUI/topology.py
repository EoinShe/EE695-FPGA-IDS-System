from dataclasses import dataclass


@dataclass
class Node:
    name: str
    ip: str
    x: float
    y: float
    kind: str = "endpoint"


NODES = [
    Node("Network Switch", "192.168.10.1", 0, 0, "core"),
    Node("VMware-VM1", "192.168.10.3", -220, -140),
    Node("VMware-VM2", "192.168.10.4", 220, -140),
    Node("Server1", "192.168.10.5", -280, 110),
    Node("Server2", "192.168.10.6", 280, 110),
    Node("VMware-VM3", "192.168.10.7", -60, 220),
    Node("FPGA IDS", "192.168.10.100", 170, 320, "fpga"),
]