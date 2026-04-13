#include "sleep.h"
#include "xil_io.h"
#include "xparameters.h"
#include "xuartlite_l.h"
#include <stdint.h>

#include "ids_test_packets.h"

#define GPIO_PKT_BASE XPAR_AXI_GPIO_PKT_BASEADDR
#define GPIO_CTRL_BASE XPAR_AXI_GPIO_TRIG_BASEADDR
#define GPIO_THR_BASE XPAR_AXI_GPIO_THR_BASEADDR
#define GPIO_STAT_BASE XPAR_AXI_GPIO_STAT_BASEADDR
#define GPIO_DST_BASE XPAR_AXI_GPIO_DST_BASEADDR
#define GPIO_PKTINFO_BASE XPAR_AXI_GPIO_PKTINFO_BASEADDR
#define GPIO_WINSTATS_BASE XPAR_AXI_GPIO_WINSTATS_BASEADDR
#define GPIO_WINID_BASE XPAR_AXI_GPIO_0_BASEADDR

#define UART_BASE XPAR_AXI_UARTLITE_0_BASEADDR

#define CTRL_TVALID (1u << 0)
#define CTRL_TLAST (1u << 1)

#define MASK_VOL_ALERT (1u << 31)
#define MASK_SYN_ALERT (1u << 30)
#define MASK_ICMP_ALERT (1u << 29)
#define MASK_UDP_ALERT (1u << 28)
#define MASK_XMAS_ALERT (1u << 27)
#define MASK_NULL_ALERT (1u << 26)

#define PKTINFO_SYN (1u << 26)
#define PKTINFO_UDP (1u << 28)
#define PKTINFO_ICMP (1u << 27)
#define PKTINFO_XMAS (1u << 25)
#define PKTINFO_NULL (1u << 24)

#define MAX_WINDOWS 64

typedef struct {
  uint32_t status;
  uint32_t packets;
} window_summary_t;

typedef struct {
  uint32_t ip;
  const char *name;
  uint32_t total;
  uint32_t syn;
  uint32_t udp;
  uint32_t icmp;
  uint32_t xmas;
  uint32_t nulls;
} target_stats_t;


static target_stats_t targets[] = {
    {0xC0A80A03, "VMware-VM1"}, {0xC0A80A04, "VMware-VM2"},
    {0xC0A80A05, "Server1"},    {0xC0A80A06, "Server2"},
    {0xC0A80A07, "VMware-VM3"},
};

#define TARGET_COUNT (sizeof(targets) / sizeof(targets[0]))

static void uart_putc(char c) {
  XUartLite_SendByte(UART_BASE, c);
  usleep(80);
}

static void uart_puts(const char *s) {
  while (*s)
    uart_putc(*s++);
}

static void uart_put_dec(uint32_t v) {
  char buf[10];
  int i = 0;
  if (v == 0) {
    uart_putc('0');
    return;
  }
  while (v) {
    buf[i++] = '0' + (v % 10);
    v /= 10;
  }
  while (i--)
    uart_putc(buf[i]);
}

static void uart_put_ip(uint32_t ip) {
  uart_put_dec((ip >> 24) & 0xFF);
  uart_putc('.');
  uart_put_dec((ip >> 16) & 0xFF);
  uart_putc('.');
  uart_put_dec((ip >> 8) & 0xFF);
  uart_putc('.');
  uart_put_dec(ip & 0xFF);
}

static void send_packet(const packet_record_t *pkt) {
  for (int i = 0; i < pkt->len_words; i++) {
    uint32_t ctrl = CTRL_TVALID;
    if (i == pkt->len_words - 1)
      ctrl |= CTRL_TLAST;

    Xil_Out32(GPIO_PKT_BASE, pkt->words[i]);
    Xil_Out32(GPIO_CTRL_BASE, ctrl);
    usleep(10);
    Xil_Out32(GPIO_CTRL_BASE, 0);
  }
}

static void update_targets(uint32_t dst, uint32_t pktinfo) {
  for (int i = 0; i < TARGET_COUNT; i++) {
    if (targets[i].ip == dst) {
      targets[i].total++;

      if (pktinfo & PKTINFO_SYN)
        targets[i].syn++;
      if (pktinfo & PKTINFO_UDP)
        targets[i].udp++;
      if (pktinfo & PKTINFO_ICMP)
        targets[i].icmp++;
      if (pktinfo & PKTINFO_XMAS)
        targets[i].xmas++;
      if (pktinfo & PKTINFO_NULL)
        targets[i].nulls++;
    }
  }
}

static void print_window(uint32_t idx, window_summary_t *w) {
  uart_puts("Window ");
  uart_put_dec(idx + 1);
  uart_puts(":\r\n");

  uart_puts("Packets in window ");
  uart_put_dec(idx + 1);
  uart_puts(": ");
  uart_put_dec(w->packets);
  uart_puts("\r\n");

  uart_puts("Attacks in window ");
  uart_put_dec(idx + 1);
  uart_puts(":\r\n");

  if (w->status & MASK_SYN_ALERT)
    uart_puts("  [!] SYN Flood\r\n");
  if (w->status & MASK_UDP_ALERT)
    uart_puts("  [!] UDP Flood\r\n");
  if (w->status & MASK_ICMP_ALERT)
    uart_puts("  [!] ICMP Flood\r\n");
  if (w->status & MASK_XMAS_ALERT)
    uart_puts("  [!] XMAS Scan\r\n");
  if (w->status & MASK_NULL_ALERT)
    uart_puts("  [!] NULL Scan\r\n");
  if (w->status & MASK_VOL_ALERT)
    uart_puts("  [!] Volumetric Attack\r\n");

  uart_puts("\r\n");
}

static void print_attacks_detected(void) {
  uart_puts("\r\n=====================================\r\n");
  uart_puts("Attacks Detected\r\n");
  uart_puts("=====================================\r\n");

  for (int i = 0; i < TARGET_COUNT; i++) {
    if (targets[i].total == 0)
      continue;

    uart_puts("Target: ");
    uart_puts(targets[i].name);
    uart_puts(" (");
    uart_put_ip(targets[i].ip);
    uart_puts(")\r\n");

    if (targets[i].syn) {
      uart_puts("  [!] SYN Attack (");
      uart_put_dec(targets[i].syn);
      uart_puts(" SYN packets)\r\n");
    }

    if (targets[i].udp) {
      uart_puts("  [!] UDP Flood (");
      uart_put_dec(targets[i].udp);
      uart_puts(" UDP packets)\r\n");
    }

    if (targets[i].icmp) {
      uart_puts("  [!] ICMP Flood (");
      uart_put_dec(targets[i].icmp);
      uart_puts(" ICMP packets)\r\n");
    }

    if (targets[i].xmas)
      uart_puts("  [!] XMAS Scan\r\n");

    if (targets[i].nulls)
      uart_puts("  [!] NULL Scan\r\n");

    if (targets[i].total > 2) {
      uart_puts("  [!] Volumetric Attack (");
      uart_put_dec(targets[i].total);
      uart_puts(" total packets)\r\n");
    }

    uart_puts("\r\n");
  }
}

int main(void) {
  window_summary_t windows[MAX_WINDOWS];
  uint32_t win_count = 0;
  uint32_t last_win = 0;

  Xil_Out32(GPIO_CTRL_BASE, 0);
  uint16_t vol_threshold = 2;
  uint16_t flood_threshold = 1;

  uint32_t threshold_val = ((uint32_t)flood_threshold << 16) | vol_threshold;

  Xil_Out32(GPIO_THR_BASE, threshold_val);

  for (int i = 0; i < ids_test_packets_count; i++) {
    send_packet(&ids_test_packets[i]);
    usleep(20000);

    uint32_t cur = Xil_In32(GPIO_WINID_BASE);

    while (last_win < cur && win_count < MAX_WINDOWS) {
      uint32_t stat = Xil_In32(GPIO_STAT_BASE);
      uint32_t ws = Xil_In32(GPIO_WINSTATS_BASE);

      uint32_t packets = (ws >> 16) & 0xFFFF;

      if (packets) {
        windows[win_count].status = stat;
        windows[win_count].packets = packets;
        win_count++;
      }

      last_win++;
    }

    uint32_t dst = Xil_In32(GPIO_DST_BASE);
    uint32_t info = Xil_In32(GPIO_PKTINFO_BASE);
    update_targets(dst, info);
  }

  usleep(700000);

  uint32_t cur = Xil_In32(GPIO_WINID_BASE);

  while (last_win < cur && win_count < MAX_WINDOWS) {
    uint32_t stat = Xil_In32(GPIO_STAT_BASE);
    uint32_t ws = Xil_In32(GPIO_WINSTATS_BASE);
    uint32_t packets = (ws >> 16) & 0xFFFF;

    if (packets) {
      windows[win_count].status = stat;
      windows[win_count].packets = packets;
      win_count++;
    }

    last_win++;
  }

  uart_puts("\r\n=====================================\r\n");
  uart_puts("RUN CONFIGURATION\r\n");
  uart_puts("=====================================\r\n");

  uart_puts("Window Size: ");
  uart_put_dec(500);
  uart_puts(" ms\r\n");

  uart_puts("Volumetric Threshold: ");
  uart_put_dec(vol_threshold);
  uart_puts("\r\n");

  uart_puts("Flood Threshold: ");
  uart_put_dec(flood_threshold);
  uart_puts("\r\n\r\n");

  uart_puts("\r\n=====================================\r\n");
  uart_puts("WINDOW SUMMARY\r\n");
  uart_puts("=====================================\r\n\r\n");

  for (uint32_t i = 0; i < win_count; i++)
    print_window(i, &windows[i]);

  print_attacks_detected();

  uart_puts("=====================================\r\n");
  uart_puts("             DEMO DONE\r\n");
  uart_puts("=====================================\r\n");

  while (1) {
  }
}