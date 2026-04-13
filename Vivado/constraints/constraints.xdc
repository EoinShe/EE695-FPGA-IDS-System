## VC707 system clock (200 MHz differential)
set_property PACKAGE_PIN E19 [get_ports clk_in1_p_0]
set_property PACKAGE_PIN E18 [get_ports clk_in1_n_0]
set_property IOSTANDARD LVDS [get_ports {clk_in1_p_0 clk_in1_n_0}]
create_clock -name sys_clk -period 5.000 [get_ports clk_in1_p_0]

## Device config
set_property CFGBVS GND [current_design]
set_property CONFIG_VOLTAGE 1.8 [current_design]