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

std::map<std::string, DepthMarketDataField> mdmap;

FILE *ofile = NULL;

// pthread_spinlock_t write_lock;
// struct exanic_shfe_mc_client {
// 	struct mdclient mdclient;
// 	char   udp_only_ifr[64];
// 	char   udp_tcp_ifr[64];

// 	// shfe market data tcp&udp address, to filter in exanic
// 	struct in_addr *tcp_srv;
// 	int            *tcp_port;
// 	struct in_addr *udp_srv;
// 	int            *udp_port;

// 	MIRP mirps[4][2];
// 	map<uint16_t, TCPQuery> tcpq_map;

// 	static const int TCP_SRV_NUM = 2;
// 	static const int UDP_SRV_NUM = 8;

// 	exanic_shfe_mc_client();

// 	static void *recv_udp_and_tcp(void *arg);
// 	static void *recv_udp_only(void *arg);

// 	void run_tcp_thread();
// 	void raw_parse_ether(struct timespec *ts, void *pkt, int len);
// 	void polling_udp(const char *buf, int len, int islast);
// 	void polling_udp_and_tcp(const char *buf, int len, int islast);
// };

// void exanic_shfe_mc_client::run_tcp_thread() {
// 	pthread_t udp_and_tcp_thread;
// 	pthread_create(&udp_and_tcp_thread, NULL, recv_udp_and_tcp, this);
// }

// void *exanic_shfe_mc_client::recv_udp_and_tcp(void *arg) {
// 	printf("start receiving shfe including tcp and A&B udp...\n");

// 	struct exanic_shfe_mc_client *self = (struct exanic_shfe_mc_client *)arg;
// 	char *ifname = self->udp_tcp_ifr;
// 	fprintf(stderr, "ifname = %s\n", ifname);

// 	char device[16];
// 	int port_number;
// 	if (exanic_find_port_by_interface_name(ifname, device, sizeof(device), &port_number) != 0 
// 		&& parse_device_port(ifname, device, &port_number) != 0) {
// 		printf("error: no such interface or not an exanic:%s\n", ifname);
// 		return NULL;
// 	}

// 	exanic_t *exanic = exanic_acquire_handle(device);
// 	if (!exanic) {
// 		printf("error: exanic acquire handle %s: %s\n", device,
// 			exanic_get_last_error());
// 		return NULL;
// 	}

// 	exanic_rx_t *rx = exanic_acquire_unused_filter_buffer(exanic, port_number);

// 	if (!rx) {
// 		printf("error: exanic acquire buffer %s: %s\n", device, exanic_get_last_error());
// 		return NULL;
// 	}

// 	exanic_ip_filter_t filter;

// 	filter.protocol = IPPROTO_TCP;
// 	for (int i = 0; i < TCP_SRV_NUM; i++) {
// 		filter.src_addr = self->tcp_srv[i].s_addr;
// 		filter.src_port = htons(self->tcp_port[i]);
// 		filter.dst_addr = 0;
// 		filter.dst_port = 0;
// 		exanic_filter_add_ip(exanic, rx, &filter);
// 	}

// 	filter.protocol = IPPROTO_UDP;
// 	for (int i = 0; i < UDP_SRV_NUM; i++) {
// 		filter.src_addr = 0;
// 		filter.src_port = 0;
// 		filter.dst_addr = self->udp_srv[i].s_addr;
// 		filter.dst_port = htons(self->udp_port[i]);
// 		exanic_filter_add_ip(exanic, rx, &filter);
// 	}

// 	exanic_cycles32_t timestamp;
// 	union {
// 		struct rx_chunk_info info;
// 		uint64_t data;
// 	} u;
// 	while (1) {
// 		u.data = rx->buffer[rx->next_chunk].u.data;

// 		if (u.info.generation == rx->generation) {
// 			while (1) {
// 				const char *payload = (char *)rx->buffer[rx->next_chunk].payload;
// 				rx->next_chunk++;
// 				if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS) {
// 					rx->next_chunk = 0;
// 					rx->generation++;
// 				}

// 				if (u.info.length != 0) {
// 					self->polling_udp_and_tcp(payload, u.info.length, 1);
// 					break;
// 				} else {
// 					self->polling_udp_and_tcp(payload, EXANIC_RX_CHUNK_PAYLOAD_SIZE, 0);
// 					do 
// 						u.data = rx->buffer[rx->next_chunk].u.data;
// 					while (u.info.generation == (uint8_t)(rx->generation - 1));
// 					if (u.info.generation != rx->generation) {
// 						printf("error: data got lapped\n");
// 						__exanic_rx_catchup(rx);
// 						break;
// 					}
// 				}
// 			} // while
// 		} else if (u.info.generation == (uint8_t)(rx->generation - 1)) {
// 			// TODO: no new packet
// 		} else {
// 			printf("error: data got lapped\n");
// 			__exanic_rx_catchup(rx);
// 		}
// 	} // poll

// 	return NULL;
// }

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

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s exanic[0-N] filename\n", argv[0]);
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

    ofile = fopen(argv[2], "w");
    if (ofile == NULL) {
        return -1;
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
    
    return 0;
}

// static struct mdclient *exanic_shfe_mc_create(cfg_t *cfg, struct memdb *memdb) {
// 	struct exanic_shfe_mc_client *exanic_mc = new struct exanic_shfe_mc_client();
// 	struct mdclient *client = &exanic_mc->mdclient;

// 	mdclient_init(client, cfg, memdb);

// 	for (int i = 0; i < MAX_INSTRUMENT_NR; ++i) {
// 		exchtime_prev[i] = LONG_MIN;
// 	}

// 	const char *udp_only_ifr;
// 	cfg_get_string(cfg, "udp_only_ifr", &udp_only_ifr);
// 	snprintf(exanic_mc->udp_only_ifr, sizeof(exanic_mc->udp_only_ifr), "%s", udp_only_ifr);
// 	const char *udp_tcp_ifr;
// 	cfg_get_string(cfg, "udp_tcp_ifr", &udp_tcp_ifr);
// 	snprintf(exanic_mc->udp_tcp_ifr, sizeof(exanic_mc->udp_tcp_ifr), "%s", udp_tcp_ifr);

// 	client->run = run;
// 	client->decoder = NULL;
// 	client->flags = 0;
// 	client->container = exanic_mc;

// 	return client;
// }

// static struct mdsrc_module mdsrc_exanic_shfe_mc = {
// 	.create = exanic_shfe_mc_create,
// 	.api = "exanic-shfe-mc"
// };

// mdsrc_module_register(&mdsrc_exanic_shfe_mc);
