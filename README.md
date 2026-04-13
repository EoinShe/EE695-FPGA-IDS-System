# EE695

This repository contains the complete code and data for my EE695 FYP:  
Design and Implementation of a Hardware-Based Intrusion Detection System (IDS) using an FPGA.

The project implements a hardware-accelerated IDS capable of detecting network attacks such as SYN floods, UDP floods, ICMP floods, and scan-based attacks. A custom GUI is used to generate test scenarios, which are then processed on FPGA hardware in real time.

---

# Layout

- GUI: Python based interface for building attack scenarios and generating packet data.
  - main.py: main python code for the GUI, using PySide6
  - packet_builder.py: generates packet datasets and header files.
  - topology.py: defines network topology and node locations.
  - Images/: images used for visualising nodes.

- Vitis: code for programming the microblaze.
  - src/main.c: packet monitoring, and UART output.
  - ids_*.h: generated packet datasets.
  - lscript.ld: linker script.

- Vivado: hardware design implementing the IDS logic.
  - src/: Verilog modules including IDS system and hardware wrapper.
  - constraints/: FPGA constraint files.
  - hex/: memory initialisation files used during testing.
  - design_1.bd: block design of the system.

---

# System Overview

The system works as follows:

1. Attack scenarios are created using the GUI by selecting source and destination nodes and specifying attack types and packet counts.  
2. The GUI generates packet datasets, which are exported as header files and memory initialisation files.  
3. Vitis transmits these packets to the FPGA.  
4. The FPGA processes packets in real time and applies detection logic based on thresholds defined the main.c.  
5. Detected attacks are reported via UART, including both window summaries and per target attack classifications.

---

# Features

- Support for multiple attack types:
  - SYN Flood  
  - UDP Flood  
  - ICMP Flood  
  - Xmas Scan  
  - Null Scan  
- Window-based detection logic  
- Per-target attack classification  
- Real-time reporting  

---

# Author

Eoin Sheerin - 20465956
eoin.sheerin.2021@mumail.ie
