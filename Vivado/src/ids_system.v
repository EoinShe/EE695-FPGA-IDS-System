module ids_system (
    input  wire        clk,
    input  wire        resetn,

    input  wire [31:0] tdata,
    input  wire        tvalid,
    input  wire        tlast,

    input  wire [31:0] thresholds,

    output reg  [31:0] status_out,
    output reg  [31:0] dst_ip_out,
    output reg  [31:0] packet_info_out,
    output reg  [31:0] window_stats_out,
    output reg  [31:0] window_id_out
);

    parameter integer CLK_FREQ_HZ = 100_000_000;
    parameter integer WINDOW_MS   = 250;
    localparam integer WINDOW_SIZE = (CLK_FREQ_HZ / 1000) * WINDOW_MS;

    wire [15:0] vol_threshold   = thresholds[15:0];
    wire [15:0] flood_threshold = thresholds[31:16];

    reg        in_packet;
    reg        packet_done;
    reg [7:0]  word_index;

    reg [15:0] ethertype;
    reg [7:0]  ip_proto;
    reg [7:0]  tcp_flags;
    reg [31:0] dst_ip;

    reg [31:0] timer_cnt;

    reg [15:0] cnt_total;
    reg [15:0] cnt_syn;
    reg [15:0] cnt_icmp;
    reg [15:0] cnt_udp;

    reg seen_xmas;
    reg seen_null;

    reg alert_vol;
    reg alert_syn;
    reg alert_icmp;
    reg alert_udp;
    reg alert_xmas;
    reg alert_null;

    reg tvalid_d;
    wire word_strobe = tvalid & ~tvalid_d;

    wire is_ipv4 = (ethertype == 16'h0800);
    wire is_tcp  = is_ipv4 && (ip_proto == 8'h06);
    wire is_icmp = is_ipv4 && (ip_proto == 8'h01);
    wire is_udp  = is_ipv4 && (ip_proto == 8'h11);

    wire is_syn  = is_tcp && (tcp_flags == 8'h02);
    wire is_xmas = is_tcp && (tcp_flags == 8'h29);
    wire is_null = is_tcp && (tcp_flags == 8'h00);

    always @(posedge clk) begin
        if (!resetn)
            tvalid_d <= 1'b0;
        else
            tvalid_d <= tvalid;
    end

    // -----------------------------
    // Packet parser
    // -----------------------------
    always @(posedge clk) begin
        if (!resetn) begin
            in_packet        <= 1'b0;
            packet_done      <= 1'b0;
            word_index       <= 8'd0;
            ethertype        <= 16'h0000;
            ip_proto         <= 8'h00;
            tcp_flags        <= 8'h00;
            dst_ip           <= 32'h0000_0000;
            dst_ip_out       <= 32'h0000_0000;
            packet_info_out  <= 32'h0000_0000;
        end else begin
            packet_done <= 1'b0;

            if (word_strobe && !in_packet) begin
                in_packet  <= 1'b1;
                word_index <= 8'd0;
                ethertype  <= 16'h0000;
                ip_proto   <= 8'h00;
                tcp_flags  <= 8'h00;
                dst_ip     <= 32'h0000_0000;
            end

            if (word_strobe) begin
                case (word_index)
                    8'd3:  ethertype <= tdata[31:16];
                    8'd5:  ip_proto  <= tdata[7:0];
                    8'd7:  dst_ip[31:16] <= tdata[15:0];
                    8'd8:  dst_ip[15:0]  <= tdata[31:16];
                    8'd11: tcp_flags <= tdata[7:0];
                endcase

                if (tlast) begin
                    in_packet   <= 1'b0;
                    packet_done <= 1'b1;
                    dst_ip_out  <= dst_ip;

                    packet_info_out <= {
                        1'b1,
                        (ethertype == 16'h0800),
                        ((ethertype == 16'h0800) && (ip_proto == 8'h06)),
                        ((ethertype == 16'h0800) && (ip_proto == 8'h11)),
                        ((ethertype == 16'h0800) && (ip_proto == 8'h01)),
                        ((ethertype == 16'h0800) && (ip_proto == 8'h06) &&
                         ((word_index == 8'd11) ? (tdata[7:0] == 8'h02) : (tcp_flags == 8'h02))),
                        ((ethertype == 16'h0800) && (ip_proto == 8'h06) &&
                         ((word_index == 8'd11) ? (tdata[7:0] == 8'h29) : (tcp_flags == 8'h29))),
                        ((ethertype == 16'h0800) && (ip_proto == 8'h06) &&
                         ((word_index == 8'd11) ? (tdata[7:0] == 8'h00) : (tcp_flags == 8'h00))),
                        ip_proto,
                        8'h00,
                        ((word_index == 8'd11) ? tdata[7:0] : tcp_flags)
                    };

                    word_index <= 8'd0;
                end else begin
                    word_index <= word_index + 1'b1;
                end
            end
        end
    end

    // -----------------------------
    // Sliding-window counters
    // -----------------------------
    always @(posedge clk) begin
        if (!resetn) begin
            timer_cnt         <= 32'd0;
            cnt_total         <= 16'd0;
            cnt_syn           <= 16'd0;
            cnt_icmp          <= 16'd0;
            cnt_udp           <= 16'd0;
            seen_xmas         <= 1'b0;
            seen_null         <= 1'b0;
            alert_vol         <= 1'b0;
            alert_syn         <= 1'b0;
            alert_icmp        <= 1'b0;
            alert_udp         <= 1'b0;
            alert_xmas        <= 1'b0;
            alert_null        <= 1'b0;
            window_stats_out  <= 32'h0000_0000;
            window_id_out     <= 32'd0;
            status_out        <= 32'h0000_0000;
        end else begin
            if (packet_done && is_ipv4) begin
                cnt_total <= cnt_total + 1'b1;

                if (is_icmp) cnt_icmp <= cnt_icmp + 1'b1;
                if (is_udp)  cnt_udp  <= cnt_udp  + 1'b1;
                if (is_syn)  cnt_syn  <= cnt_syn  + 1'b1;
                if (is_xmas) seen_xmas <= 1'b1;
                if (is_null) seen_null <= 1'b1;
            end

            if (timer_cnt >= WINDOW_SIZE - 1) begin
                if ((cnt_total != 16'd0) ||
                    (cnt_syn   != 16'd0) ||
                    (cnt_icmp  != 16'd0) ||
                    (cnt_udp   != 16'd0) ||
                    seen_xmas || seen_null) begin

                    alert_vol  <= (cnt_total > vol_threshold);
                    alert_syn  <= (cnt_syn   > flood_threshold);
                    alert_icmp <= (cnt_icmp  > flood_threshold);
                    alert_udp  <= (cnt_udp   > flood_threshold);
                    alert_xmas <= seen_xmas;
                    alert_null <= seen_null;

                    window_stats_out <= {cnt_total, cnt_syn};

                    status_out <= {
                        (cnt_total > vol_threshold),   // [31]
                        (cnt_syn   > flood_threshold), // [30]
                        (cnt_icmp  > flood_threshold), // [29]
                        (cnt_udp   > flood_threshold), // [28]
                        seen_xmas,                    // [27]
                        seen_null,                    // [26]
                        cnt_syn[9:0],                 // [25:16]
                        cnt_total                     // [15:0]
                    };

                    window_id_out <= window_id_out + 1'b1;
                end

                timer_cnt <= 32'd0;
                cnt_total <= 16'd0;
                cnt_syn   <= 16'd0;
                cnt_icmp  <= 16'd0;
                cnt_udp   <= 16'd0;
                seen_xmas <= 1'b0;
                seen_null <= 1'b0;
            end else begin
                timer_cnt <= timer_cnt + 1'b1;
            end
        end
    end

endmodule