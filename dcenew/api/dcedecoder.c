#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include "udp.h"
//#include "utils.h"

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/util.h>
#include <signal.h>

void packetHandler(uint8_t * packet, ssize_t size)
{
    dce_dmdp_t *dmdp = (dce_dmdp_t *)packet;
    if (size >= 0x19 && dmdp->pkg_size <= size)
    {
        do {
            switch(dmdp->pkg_type)
            {
            case 1792:
            {
                //printf("on best quote\n");
                int8_t * pd = (int8_t *)dmdp + sizeof(dce_dmdp_t);
                dce_dmdp_field_t *field = (dce_dmdp_field_t *)pd;
                if (field->field_id == 1792)
                {
                    fld_quot_t *quote = (fld_quot_t *)pd;
                    printf("best,contract_id=%s\n", quote->contract_id);
                }
                pd += field->field_size;
                field = (dce_dmdp_field_t *)pd;
                /*
                if (field->field_id == 1794)
                {
                    fld_snap_best_quot_t *best = (fld_snap_best_quot_t *)field;
                    printf("last_price=%.2f,",best->last_price);
                    printf("last_match_qty=%d,",best->last_match_qty);
                    printf("match_tot_qty=%d,",best->match_tot_qty);
                    printf("bid_price=%.2f,",best->bid_price);
                    printf("bid_qty=%d,",best->bid_qty);
                    printf("ask_price=%d,",best->ask_qty);
                    printf("ask_qty=%d\n",best->ask_qty);
                }
                */
                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            case 1793:
            {
                //printf("on arbi best quote\n");
                int8_t * pd = (int8_t *)dmdp + sizeof(dce_dmdp_t);
                dce_dmdp_field_t *field = (dce_dmdp_field_t *)pd;
                if (field->field_id == 1792)
                {
                    fld_quot_t *quote = (fld_quot_t *)pd;
                    printf("arbi,contract_id=%s\n", quote->contract_id);
                }
                pd += field->field_size;
                field = (dce_dmdp_field_t *)pd;
                /*
                if (field->field_id == 1795)
                {
                    fld_snap_arbi_best_quot_t *arbi = (fld_snap_arbi_best_quot_t *)field;
                    printf("last_price=%.2f,", arbi->last_price);
                    printf("last_match_qty=%d,", arbi->last_match_qty);
                    printf("bid_price=%.2f,", arbi->bid_price);
                    printf("bid_qty=%d,", arbi->bid_qty);
                    printf("ask_price=%d,", arbi->ask_qty);
                    printf("ask_qty=%d\n", arbi->ask_qty);
                }
                */
                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            case 1795:
            {
                //printf("on segment quote\n");
                int8_t * pd = (int8_t *)dmdp + sizeof(dce_dmdp_t);
                dce_dmdp_field_t *field = (dce_dmdp_field_t *)pd;
                if (field->field_id == 1792)
                {
                    fld_quot_t *seg = (fld_quot_t *)pd;
                    printf("segment,contract_id=%s\n", seg->contract_id);
                }
                pd += field->field_size;
                field = (dce_dmdp_field_t *)pd;
                /*
                if (field->field_id == 1796)
                {
                    fld_snap_segment_price_qty_t *seg_px_qty = (fld_snap_segment_price_qty_t *)field; 
                    // TODO refer to udp.h to find member in fld_snap_segment_price_qty_t
                }
                */
                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            case 1796:
            {
                //printf("on order statics quote\n");
                int8_t * pd = (int8_t *)dmdp + sizeof(dce_dmdp_t);
                dce_dmdp_field_t *field = (dce_dmdp_field_t *)pd;
                if (field->field_id == 1792)
                {
                    fld_quot_t *statics = (fld_quot_t *)pd;
                    printf("statics,contract_id=%s\n", statics->contract_id);
                }
                pd += field->field_size;
                field = (dce_dmdp_field_t *)pd;
                /*
                if (field->field_id == 1799)
                {
                    fld_snap_order_statics_t *s = (fld_snap_order_statics_t *)field;
                    // TODO refer to udp.h to find member in fld_snap_order_statics_t
                }
                */
                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            case 1797:
            {
                //printf("on best orders quot\n");
                int8_t * pd = (int8_t *)dmdp + sizeof(dce_dmdp_t);
                dce_dmdp_field_t *field = (dce_dmdp_field_t *)pd;
                if (field->field_id == 1792)
                {
                    fld_quot_t *statics = (fld_quot_t *)pd;
                    printf("best orders,contract_id=%s\n", statics->contract_id);
                }
                pd += field->field_size;
                field = (dce_dmdp_field_t *)pd;
                /*
                if (field->field_id == 1797)
                {
                    fld_snap_best_orders_t *b = (fld_snap_best_orders_t *)field;
                    // TODO refer to udp.h to find member in fld_snap_best_orders_t
                }
                */
                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            case 1798:
            {
                //printf("on mbl quot\n");
                int8_t * pd = (int8_t *)dmdp + sizeof(dce_dmdp_t);
                dce_dmdp_field_t *field = (dce_dmdp_field_t *)pd;
                if (field->field_id == 1792)
                {
                    fld_quot_t *quote = (fld_quot_t *)pd;
                    printf("mbl,%s\n", quote->contract_id);
                }
                pd += field->field_size;
                field = (dce_dmdp_field_t *)pd;
                /*
                if (field->field_id == 1798)
                {
                    fld_snap_mbl_t *deep = (fld_snap_mbl_t *)field;
                    printf("%.2f,%d,%d,%.2f,%d,%d,%.2f,%d,%d,%.2f,%d,%d,%.2f,%d,%d\n", 
                            deep->bid_1, deep->bid_1_qty, deep->bid_1_imp_qty, 
                            deep->bid_2, deep->bid_2_qty, deep->bid_2_imp_qty,
                            deep->bid_3, deep->bid_3_qty, deep->bid_3_imp_qty,
                            deep->bid_4, deep->bid_4_qty, deep->bid_4_imp_qty,
                            deep->bid_5, deep->bid_5_qty, deep->bid_5_imp_qty);

                    printf("%.2f,%d,%d,%.2f,%d,%d,%.2f,%d,%d,%.2f,%d,%d,%.2f,%d,%d\n", 
                            deep->ask_1, deep->ask_2_qty, deep->ask_2_imp_qty,
                            deep->ask_2, deep->ask_2_qty, deep->ask_2_imp_qty,
                            deep->ask_3, deep->ask_3_qty, deep->ask_3_imp_qty,
                            deep->ask_4, deep->ask_4_qty, deep->ask_4_imp_qty,
                            deep->ask_5, deep->ask_5_qty, deep->ask_5_imp_qty);
                }
                */
                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            default:
            {
                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            }
        }while ((uint8_t *)dmdp + 4 < packet + size);
    }
}

int keep_running = 1;
void sig_handler(int signal)
{
    keep_running = 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s exanic[0-N]\n", argv[0]);
        return -1;
    }

    /* acquire exanic device handle */
    exanic_t *nic = exanic_acquire_handle(argv[1]);
    if (!nic)
    {
        fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
        return -1;
    }

    /* fpga upload data to port1, acquire rx buffer to receive data */
    exanic_rx_t *rx = exanic_acquire_rx_buffer(nic, 1, 0);
    if (!rx)
    {
        fprintf(stderr, "exanic_acquire_rx_buffer: %s\n", exanic_get_last_error());
        return -1;
    }

    ssize_t size = 0;
    /* uploaded data will be copied to buf */
    char buf[2048];
    memset(buf, 0, sizeof(buf));

    while (keep_running)
    {
        size = exanic_receive_frame(rx, buf, sizeof(buf), 0);
        if (size > 0)
        {
            packetHandler(buf, size);
        }
    }
    
    return 0;
}
