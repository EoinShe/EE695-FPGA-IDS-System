//Copyright 1986-2022 Xilinx, Inc. All Rights Reserved.
//Copyright 2022-2025 Advanced Micro Devices, Inc. All Rights Reserved.
//--------------------------------------------------------------------------------
//Tool Version: Vivado v.2025.1 (win64) Build 6140274 Thu May 22 00:12:29 MDT 2025
//Date        : Fri Apr 10 19:09:44 2026
//Host        : EECR-DQ3V674 running 64-bit major release  (build 9200)
//Command     : generate_target design_1_wrapper.bd
//Design      : design_1_wrapper
//Purpose     : IP block netlist
//--------------------------------------------------------------------------------
`timescale 1 ps / 1 ps

module design_1_wrapper
   (clk_in1_n_0,
    clk_in1_p_0,
    reset,
    rs232_uart_rxd,
    rs232_uart_txd);
  input clk_in1_n_0;
  input clk_in1_p_0;
  input reset;
  input rs232_uart_rxd;
  output rs232_uart_txd;

  wire clk_in1_n_0;
  wire clk_in1_p_0;
  wire reset;
  wire rs232_uart_rxd;
  wire rs232_uart_txd;

  design_1 design_1_i
       (.clk_in1_n_0(clk_in1_n_0),
        .clk_in1_p_0(clk_in1_p_0),
        .reset(reset),
        .rs232_uart_rxd(rs232_uart_rxd),
        .rs232_uart_txd(rs232_uart_txd));
endmodule
