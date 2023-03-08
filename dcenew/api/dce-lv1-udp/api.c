#define _TCP_DECODE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/util.h>
#include <exanic/config.h>

#include "dce-nano.h"
int udp_running = 1;
exanic_rx_t *rx0;
exanic_rx_t *rx1;

int main(int argc, char *argv[])
{
    if (argc != 2) 
    {
        fprintf(stderr, "Usage: %s exanic_dev\n", argv[0]);
        return -1;
    }

    exanic_t *nic = exanic_acquire_handle(argv[1]);
    if (!nic)
    {
        printf("failed to acquire NIC handle:%s\n", exanic_get_last_error());
        return -1;
    }

    rx0 = exanic_acquire_rx_buffer(nic, 0, 0);
    rx1 = exanic_acquire_rx_buffer(nic, 1, 0);

    char rxbuf[1024];
    memset(rxbuf, 0, sizeof(rxbuf));

    while(udp_running)
    {
        ssize_t size = exanic_receive_frame(rx1, rxbuf, sizeof(rxbuf), 0);
	if (size > 0)
	{
	    if (*(uint32_t *)rxbuf == 33554432)
	    {
		dce_lv1_t *dce_lv1 = (dce_lv1_t *)rxbuf;
		printf("%u,%u,%u,%s,%ld,%u,%ld,%u,%ld,%u,%u,%ld,%u,%u,%ld,%ld\n",
                    dce_lv1->counter,
                    dce_lv1->contract_idx,
                    dce_lv1->seq_no,
                    dce_lv1->contract_name,
                    dce_lv1->last_px,
                    dce_lv1->last_qty,
                    dce_lv1->turnover,
                    dce_lv1->open_interest,
                    dce_lv1->bid_px,
                    dce_lv1->bid_qty,
                    dce_lv1->bid_imply_qty,
                    dce_lv1->ask_px,
                    dce_lv1->ask_qty,
                    dce_lv1->ask_imply_qty);
	    }
	}
    }
}
