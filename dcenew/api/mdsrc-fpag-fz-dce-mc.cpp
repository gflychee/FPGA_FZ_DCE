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
#include <pthread.h>
#include <limits.h>
#include <cfloat>
#include <sys/time.h>
#include <map>
#include <fstream>

#pragma pack(push)
#pragma pack(1)

struct DepthMarketDataField
{
    unsigned int type;
    ///本地时间戳
    struct timeval LocalTime;
    ///交易所时间戳
    int64_t ExchTime;
    ///最新价
    double  LastPrice;
    ///数量
    int Volume;
    ///成交金额
    double  Turnover;
    ///持仓量
    double  OpenInterest;
    ///涨停板价
    double UpperLimitPrice;
    ///跌停板价
    double LowerLimitPrice;
    ///申买价一
    double  BidPrice1;
    ///申卖价一
    double  AskPrice1;
    ///申买量一
    int BidVolume1;
    ///申卖量一
    int AskVolume1;
    ///申买价二
    double  BidPrice2;
    ///申卖价二
    double  AskPrice2;
    ///申买量二
    int BidVolume2;
    ///申卖量二
    int AskVolume2;
    ///申买价三
    double  BidPrice3;
    ///申卖价三
    double  AskPrice3;
    ///申买量三
    int BidVolume3;
    ///申卖量三
    int AskVolume3;
    ///申买价四
    double  BidPrice4;
    ///申卖价四
    double  AskPrice4;
    ///申买量四
    int BidVolume4;
    ///申卖量四
    int AskVolume4;
    ///申买价五
    double  BidPrice5;
    ///申卖价五
    double  AskPrice5;
    ///申买量五
    int BidVolume5;
    ///申卖量五
    int AskVolume5;
    ///合约代码
    char    InstrumentID[31];
    ///交易所代码
    char    ExchangeID[9];
    char    GenTime[13];
};

#pragma pack(pop)
constexpr double precision = 0.000001;
std::map<std::string, DepthMarketDataField> mdmap;

FILE *ofile = NULL;

pthread_spinlock_t write_lock;
struct exanic_dce_mc_client {
	struct mdclient mdclient;
	char   lv1_exanic[64];
	char   lv2_exanic[64];
	int    debug;
	int    merge;

	exanic_dce_mc_client();

	static void *recv_udp_lv1(void *arg);

	void run_lv1_thread();
};

void exanic_dce_mc_client::run_lv1_thread() {
	pthread_t lv1_thread;
	pthread_create(&lv1_thread, NULL, recv_udp_lv1, this);
}

fabs(premd[data->InstrumentID].LastPrice - data->LastPrice) < precision && premd[data->InstrumentID].Volume == data->Volume &&
            fabs(premd[data->InstrumentID].Turnover - data->Turnover) < precision && fabs(premd[data->InstrumentID].OpenInterest - data->OpenInterest) < precision &&
            fabs(premd[data->InstrumentID].BidPrice1 - data->BidPrice1) < precision && premd[data->InstrumentID].BidVolume1 == data->BidVolume1 &&
            fabs(premd[data->InstrumentID].AskPrice1 - data->AskPrice1) < precision && premd[data->InstrumentID].AskVolume1 == data->AskVolume1

void *exanic_dce_mc_client::recv_udp_lv1(void *arg) {
	printf("start receiving udp lv1...\n");

	struct exanic_dce_mc_client *self = (struct exanic_dce_mc_client *)arg;

	printf("ifname = %s\n", self->lv1_exanic);

	exanic_t *nic = exanic_acquire_handle(self->lv1_exanic);

	if (!nic) {
        printf("failed to acquire NIC handle:%s\n", exanic_get_last_error());
        return NULL;
    }

    exanic_rx_t *rx1 = exanic_acquire_rx_buffer(nic, 1, 0);

    char rxbuf[1024];

    memset(rxbuf, 0, sizeof(rxbuf));

    while(1) {
        ssize_t size = exanic_receive_frame(rx1, rxbuf, sizeof(rxbuf), 0);
		if (size > 0) {
	    	if (*(uint32_t *)rxbuf == 33554432) {
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
	return NULL;
}

void WriteMd1(DepthMarketDataField *md) {
    if (strlen(md->InstrumentID) == 0) {
        return;
    }
    struct timespec ts {};
    clock_gettime(CLOCK_REALTIME, &ts);

    fprintf(ofile,"%ld.%09ld,%s,%s,%lf,%d,%lf,%lf,%lf,%d,%lf,%d,%lf,%lf\n", \
            ts.tv_sec, ts.tv_nsec, md->GenTime, md->InstrumentID, md->LastPrice, md->Volume, md->Turnover, md->OpenInterest, \
            md->BidPrice1, md->BidVolume1, md->AskPrice1, md->AskVolume1, md->UpperLimitPrice, md->LowerLimitPrice);
    fflush(ofile);
}

void WriteMd5(DepthMarketDataField *md) {
    if (strlen(md->InstrumentID) == 0) {
        return;
    }
    struct timespec ts {};
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(ofile,"%ld.%09ld,%s,%s,%lf,%d,%lf,%lf,%lf,%d,%lf,%d,%lf,%d,%lf,%d,%lf,%d,%lf,%d,%lf,%d,%lf,%d,%lf,%d,%lf,%d,%lf,%lf\n", \
        ts.tv_sec, ts.tv_nsec, md->GenTime, md->InstrumentID, md->LastPrice, md->Volume, md->Turnover, md->OpenInterest, \
        md->BidPrice1, md->BidVolume1, md->AskPrice1, md->AskVolume1, \
        md->BidPrice2, md->BidVolume2, md->AskPrice2, md->AskVolume2, \
        md->BidPrice3, md->BidVolume3, md->AskPrice3, md->AskVolume3, \
        md->BidPrice4, md->BidVolume4, md->AskPrice4, md->AskVolume4, \
        md->BidPrice5, md->BidVolume5, md->AskPrice5, md->AskVolume5, md->UpperLimitPrice, md->LowerLimitPrice);
    fflush(ofile);
}


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
                DepthMarketDataField *md;
                if (field->field_id == 1792)
                {
                    fld_quot_t *quote = (fld_quot_t *)pd;
                    if (strlen(quote->contract_id) > 8) { //过滤期权，组合合约
                    	dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
            			break;
        			} else {
        				md = &mdmap[quote->contract_id];
        				strncpy(md->InstrumentID, quote->contract_id, sizeof(md->InstrumentID));
        				strncpy(md->GenTime, quote->gen_time, sizeof(md->GenTime));
        			}
                }
                pd += field->field_size;
                field = (dce_dmdp_field_t *)pd;
                
                if (field->field_id == 1794)
                {
                    fld_snap_best_quot_t *best = (fld_snap_best_quot_t *)field;
                    md->LastPrice = best->last_price != DBL_MAX ? best->last_price : 0.0;
        			md->Volume = best->match_tot_qty;
        			md->Turnover = best->turnover;
        			md->OpenInterest = best->open_interest;
        			md->UpperLimitPrice = best->rise_limit;
        			md->LowerLimitPrice = best->fall_limit;
        			md->BidPrice1  = best->bid_price != DBL_MAX ? best->bid_price : 0.0;
        			md->BidVolume1 = best->bid_qty;
        			md->AskPrice1  = best->ask_price != DBL_MAX ? best->ask_price : 0.0;
        			md->AskVolume1 = best->ask_qty;
        			WriteMd1(md);
                }
                
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
                    if (strlen(quote->contract_id) > 8) { //过滤期权，组合合约
                    	dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
            			break;
        			} else {
        				md = &mdmap[quote->contract_id];
        				strncpy(md->InstrumentID, quote->contract_id, sizeof(md->InstrumentID));
        				strncpy(md->GenTime, quote->gen_time, sizeof(md->GenTime));
        			}
                }
                pd += field->field_size;
                field = (dce_dmdp_field_t *)pd;

                if (field->field_id == 1798)
                {
                    fld_snap_mbl_t *deep = (fld_snap_mbl_t *)field;
                    md->BidPrice1  = deep->bid_1 != DBL_MAX ? deep->bid_1 : 0.0;
                    md->BidVolume1 = deep->bid_1_qty;
                    md->AskPrice1  = deep->ask_1 != DBL_MAX ? deep->ask_1 : 0.0;
                    md->AskVolume1 = deep->ask_1_qty;
            
                    md->BidPrice2  = deep->bid_2 != DBL_MAX ? deep->bid_2 : 0.0;
                    md->BidVolume2 = deep->bid_2_qty;
                    md->AskPrice2  = deep->ask_2 != DBL_MAX ? deep->ask_2 : 0.0;
                    md->AskVolume2 = deep->ask_2_qty;
            
                    md->BidPrice3  = deep->bid_3 != DBL_MAX ? deep->bid_3 : 0.0;
                    md->BidVolume3 = deep->bid_3_qty;
                    md->AskPrice3  = deep->ask_3 != DBL_MAX ? deep->ask_3 : 0.0;
                    md->AskVolume3 = deep->ask_3_qty;
            
                    md->BidPrice4  = deep->bid_4 != DBL_MAX ? deep->bid_4 : 0.0;
                    md->BidVolume4 = deep->bid_4_qty;
                    md->AskPrice4  = deep->ask_4 != DBL_MAX ? deep->ask_4 : 0.0;
                    md->AskVolume4 = deep->ask_4_qty;
            
                    md->BidPrice5  = deep->bid_5 != DBL_MAX ? deep->bid_5 : 0.0;
                    md->BidVolume5 = deep->bid_5_qty;
                    md->AskPrice5  = deep->ask_5 != DBL_MAX ? deep->ask_5 : 0.0;
                    md->AskVolume5 = deep->ask_5_qty;
                    WriteMd5(md);
                }

                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            default:
            {
                dmdp = (dce_dmdp_t *)((int8_t *)dmdp + dmdp->pkg_size);
                break;
            }
            }
        } while ((uint8_t *)dmdp + 4 < packet + size);
    }
}

static void run(struct mdclient *client) {
	pthread_spin_init(&write_lock, 0);
	struct exanic_dce_mc_client *exanic_mc = (struct exanic_dce_mc_client *)client->container;
	//pclient = &(exanic_mc->mdclient);
	pclient = client;

	exanic_mc->run_lv1_thread();

	/* acquire exanic device handle */
    exanic_t *nic = exanic_acquire_handle(exanic_mc->lv2_exanic);
    if (!nic)
    {
        printf("exanic_acquire_handle: %s\n", exanic_get_last_error());
        fflush(stdout);
        return;
    }

    /* fpga upload data to port1, acquire rx buffer to receive data */
    exanic_rx_t *rx = exanic_acquire_rx_buffer(nic, 1, 0);
    if (!rx)
    {
        printf("exanic_acquire_rx_buffer: %s\n", exanic_get_last_error());
        fflush(stdout);
        return;
    }

    ssize_t size = 0;
    /* uploaded data will be copied to buf */
    char buf[2048];
    memset(buf, 0, sizeof(buf));

    while (1)
    {
        size = exanic_receive_frame(rx, buf, sizeof(buf), 0);
        if (size > 0)
        {
            packetHandler(buf, size);
        }
    }
}

static struct mdclient *exanic_dce_mc_create(cfg_t *cfg, struct memdb *memdb) {
	struct exanic_dce_mc_client *exanic_mc = new struct exanic_dce_mc_client();
	struct mdclient *client = &exanic_mc->mdclient;

	mdclient_init(client, cfg, memdb);

	const char *lv1_exanic;
	cfg_get_string(cfg, "lv1_exanic", &lv1_exanic);
	snprintf(exanic_mc->lv1_exanic, sizeof(exanic_mc->lv1_exanic), "%s", lv1_exanic);
	const char *lv2_exanic;
	cfg_get_string(cfg, "lv2_exanic", &lv2_exanic);
	snprintf(exanic_mc->lv2_exanic, sizeof(exanic_mc->lv2_exanic), "%s", lv2_exanic);
	cfg_get_int(cfg, "debug", &exanic_mc->debug);
	cfg_get_int(cfg, "merge", &exanic_mc->merge);

	client->run = run;
	client->decoder = NULL;
	client->flags = 0;
	client->container = exanic_mc;

	return client;
}

static struct mdsrc_module mdsrc_exanic_dce_mc = {
	.create = exanic_dce_mc_create,
	.api = "exanic-dce-mc"
};

mdsrc_module_register(&mdsrc_exanic_dce_mc);
