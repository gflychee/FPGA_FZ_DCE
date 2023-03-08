#include <winterfell/instab.h>
#include <winterfell/mdclient.h>
#include "efvi-udp.h"

#include "MarketData.h"

#include <onload/extensions.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <stdint.h>
#include <cstring>
#include <ctime>
#include <limits.h>
#include <cfloat>
using namespace std;

#pragma pack(push)
#pragma pack(1)

struct deep {
	double OrderPrice;
	int OrderQty;
	int ImplyQty;
	char BsFlag;
	char GenTime[13];
	char padding[2];
};

struct best {
	char TradeDate[9]; // 0
	char ContractID[23];
	unsigned int TID;
	char ContractName[41];
	char padding1[3];
	double LastPrice;
	double HighPrice; // 88
	double LowPrice;
	unsigned int LastMatchQty;
	unsigned int MatchTotQty;
	double Turnover;
	unsigned int InitOpenInterest; // 120
	unsigned int OpenInterest;
	int InterestChg;
	double ClearPrice;
	double LifeLow;
	double LifeHigh; // 148
	double RiseLimit;
	double FallLimit;
	double LastClearPrice;
	double LastClose;
	double BidPrice; // 188
	unsigned int BidQty; // 196
	unsigned int BidImplyQty; // 200
	double AskPrice; // 204
	unsigned int AskQty; // 212
	unsigned int AskImplyQty; // 216
	double AvgPrice; // 220
	char GenTime[13];
	char padding2[3];
	double OpenPrice;
	double ClosePrice;
	int count_for_deepquote; // 260
	struct deep quote[10]; // 264
	char unknown4[36]; // 384
	double Delta; // 420
	double Gamma; // 428
	double Rho; // 436
	double Theta; // 444
	double Vega; // 452
	char unknown5[8]; // 460
};

struct entrust {
	char Type;
	char ContractID[83];
	double BestBuyOrderPrice;
	int BestBuyOrderQtyOne;
	int BestBuyOrderQtyTwo;
	int BestBuyOrderQtyThree;
	int BestBuyOrderQtyFour;
	int BestBuyOrderQtyFive;
	int BestBuyOrderQtySix;
	int BestBuyOrderQtySeven;
	int BestBuyOrderQtyEight;
	int BestBuyOrderQtyNine;
	int BestBuyOrderQtyTen;
	double BestSellOrderPrice;
	int BestSellOrderQtyOne;
	int BestSellOrderQtyTwo;
	int BestSellOrderQtyThree;
	int BestSellOrderQtyFour;
	int BestSellOrderQtyFive;
	int BestSellOrderQtySix;
	int BestSellOrderQtySeven;
	int BestSellOrderQtyEight;
	int BestSellOrderQtyNine;
	int BestSellOrderQtyTen;
	char GenTime[13];
	char padding[3];
	char unknown[8];
};

struct efvi_dce_mc_client {
    struct mdclient mdclient;
    char   ifname[64];
    char   filename[64];
    char   udp_srvip[32];
    int    udp_port;
    char   key;
};
#pragma pack(pop)

struct mdclient *pclient;
static map<string, DepthMarketDataField> mdmap;
static inline long
get_exchtime(const char *time, int msec)
{
	long t;

	t  = (time[0] - '0') * 10 + (time[1] - '0');
	t *= 60;
	t += (time[3] - '0') * 10 + (time[4] - '0');
	t *= 60;
	t += (time[6] - '0') * 10 + (time[7] - '0');
	if (t > 3600 * 18)
		t -= 3600 * 24;

	t *= 1000;
	t += msec;

	return t;
}

static inline void
swap_int32(int32_t *a, int32_t *b)
{
	int32_t tmp = *a;
	*a = *b;
	*b = tmp;
}

static inline void
swap_uint32(uint32_t *a, uint32_t *b)
{
	uint32_t tmp = *a;
	*a = *b;
	*b = tmp;
}

static inline void
swap_double(double *a, double *b)
{
	double tmp = *a;
	*a = *b;
	*b = tmp;
}

static void
decode_best_1(struct best *best)
{
	swap_uint32(&best->BidQty, &best->AskImplyQty);
	swap_uint32(&best->AskQty, &best->BidImplyQty);
	swap_double(&best->BidPrice, &best->HighPrice);
}

static void
decode_deep_1(struct deep *deep)
{
	swap_int32(&deep->OrderQty, &deep->ImplyQty);
}

static void
decode_entrust_1(struct entrust *entrust)
{
	entrust->BestSellOrderQtyOne -= 2888;
	entrust->BestBuyOrderQtyTwo -= 3555;
	entrust->BestSellOrderQtyTwo -= 2333;
}

static void
decode_best_2(struct best *best)
{
	swap_uint32(&best->BidQty, &best->BidImplyQty);
	swap_uint32(&best->AskQty, &best->AskImplyQty);
	swap_double(&best->BidPrice, &best->LowPrice);
}

static void
decode_deep_2(struct deep *deep)
{
	swap_int32(&deep->OrderQty, &deep->ImplyQty);
}

static void
decode_entrust_2(struct entrust *entrust)
{
	entrust->BestSellOrderQtyOne -= 288;
	entrust->BestBuyOrderQtyTwo -= 355;
	entrust->BestSellOrderQtyTwo -= 233;
}

static void
decode_best_3(struct best *best)
{
	best->BidQty -= 2834;
	best->AskQty -= 231;

	swap_double(&best->BidPrice, &best->LastPrice);
}

static void
decode_deep_3(struct deep *deep)
{
	deep->OrderQty -= 377;
}

static void
decode_entrust_3(struct entrust *entrust)
{
	entrust->BestSellOrderQtyOne /= 2;
	entrust->BestBuyOrderQtyTwo -= 344;
	entrust->BestSellOrderQtyTwo -= 233;
}

static void
decode_best_4(struct best *best)
{
	best->BidQty >>= 1;
	best->BidQty -= 100;

	best->AskQty /= 5u;
	best->AskQty -= 20;

	swap_double(&best->BidPrice, &best->AskPrice);
}

static void
decode_deep_4(struct deep *deep)
{
	deep->OrderQty /= 3;
}

static void
decode_entrust_4(struct entrust *entrust)
{
	swap_int32(&entrust->BestSellOrderQtyOne, &entrust->BestSellOrderQtyTen);
	swap_int32(&entrust->BestBuyOrderQtyTwo,  &entrust->BestBuyOrderQtyNine);
	swap_int32(&entrust->BestSellOrderQtyTwo, &entrust->BestSellOrderQtyNine);
}

static void
decode_best_5(struct best *best)
{
	swap_uint32(&best->BidQty, &best->LastMatchQty);
	swap_uint32(&best->AskQty, &best->TID);
	swap_double(&best->BidPrice, &best->LastClose);
}

static void
decode_deep_5(struct deep *deep)
{
	swap_int32(&deep->OrderQty, &deep->ImplyQty);
}

static void
decode_entrust_5(struct entrust *entrust)
{
	swap_int32(&entrust->BestSellOrderQtyOne, &entrust->BestBuyOrderQtySix);
	entrust->BestSellOrderQtyOne -= 3848;
	entrust->BestBuyOrderQtyTwo -= 53;
	entrust->BestSellOrderQtyTwo -= 1033;
}

static void
decode_best_6(struct best *best)
{
	swap_uint32(&best->BidQty, &best->AskImplyQty);
	swap_uint32(&best->AskQty, &best->LastMatchQty);
	swap_double(&best->BidPrice, &best->AvgPrice);
}

static void
decode_deep_6(struct deep *deep)
{
	swap_int32(&deep->OrderQty, &deep->ImplyQty);
}

static void
decode_entrust_6(struct entrust *entrust)
{
	entrust->BestSellOrderQtyOne -= 188;
	entrust->BestBuyOrderQtyTwo -= 315;
	entrust->BestSellOrderQtyTwo -= 33;
}

static void
decode_best_7(struct best *best)
{
	best->BidQty -= 2334;
	best->AskQty -= 321;
	swap_double(&best->BidPrice, &best->LastPrice);
	swap_double(&best->AskPrice, &best->ClosePrice);
}

static void
decode_deep_7(struct deep *deep)
{
	deep->OrderQty -= 197;
}

static void
decode_entrust_7(struct entrust *entrust)
{
	entrust->BestSellOrderQtyOne /= 3;
	entrust->BestBuyOrderQtyTwo -= 74;
	entrust->BestSellOrderQtyTwo -= 234;
}

static void
decode_best_8(struct best *best)
{
	best->BidQty /= 3u;
	best->BidQty -= 6;
	best->AskQty >>= 2;
	best->AskQty -= 21;

	swap_double(&best->BidPrice, &best->AskPrice);
}

static void
decode_deep_8(struct deep *deep)
{
	deep->OrderQty /= 2;
}

static void
decode_entrust_8(struct entrust *entrust)
{
	swap_int32(&entrust->BestSellOrderQtyOne,  &entrust->BestSellOrderQtyThree);
	swap_int32(&entrust->BestBuyOrderQtyThree, &entrust->BestBuyOrderQtyNine);
	swap_int32(&entrust->BestSellOrderQtyTwo,  &entrust->BestSellOrderQtyNine);
}

struct decode_algo_t {
	void (*decode_best)(struct best *);
	void (*decode_deep)(struct deep *);
	void (*decode_entrust)(struct entrust *);
};

static struct decode_algo_t decode_algo_1 = {decode_best_1, decode_deep_1, decode_entrust_1};
static struct decode_algo_t decode_algo_2 = {decode_best_2, decode_deep_2, decode_entrust_2};
static struct decode_algo_t decode_algo_3 = {decode_best_3, decode_deep_3, decode_entrust_3};
static struct decode_algo_t decode_algo_4 = {decode_best_4, decode_deep_4, decode_entrust_4};
static struct decode_algo_t decode_algo_5 = {decode_best_5, decode_deep_5, decode_entrust_5};
static struct decode_algo_t decode_algo_6 = {decode_best_6, decode_deep_6, decode_entrust_6};
static struct decode_algo_t decode_algo_7 = {decode_best_7, decode_deep_7, decode_entrust_7};
static struct decode_algo_t decode_algo_8 = {decode_best_8, decode_deep_8, decode_entrust_8};

static struct decode_algo_t decode_algo[8];

static void
set_decode_algo(char ch)
{
	switch (ch) {
	case 'a':
		decode_algo[0] = decode_algo_1;
		decode_algo[1] = decode_algo_2;
		decode_algo[2] = decode_algo_3;
		decode_algo[3] = decode_algo_4;
		decode_algo[4] = decode_algo_5;
		decode_algo[5] = decode_algo_6;
		decode_algo[6] = decode_algo_7;
		decode_algo[7] = decode_algo_8;
		break;
	case 'b':
		decode_algo[0] = decode_algo_2;
		decode_algo[1] = decode_algo_3;
		decode_algo[2] = decode_algo_4;
		decode_algo[3] = decode_algo_1;
		decode_algo[4] = decode_algo_6;
		decode_algo[5] = decode_algo_7;
		decode_algo[6] = decode_algo_8;
		decode_algo[7] = decode_algo_5;
		break;
	case 'c':
		decode_algo[0] = decode_algo_4;
		decode_algo[1] = decode_algo_3;
		decode_algo[2] = decode_algo_2;
		decode_algo[3] = decode_algo_1;
		decode_algo[4] = decode_algo_8;
		decode_algo[5] = decode_algo_7;
		decode_algo[6] = decode_algo_6;
		decode_algo[7] = decode_algo_5;
		break;
	case 'd':
		decode_algo[0] = decode_algo_3;
		decode_algo[1] = decode_algo_4;
		decode_algo[2] = decode_algo_1;
		decode_algo[3] = decode_algo_2;
		decode_algo[4] = decode_algo_7;
		decode_algo[5] = decode_algo_8;
		decode_algo[6] = decode_algo_5;
		decode_algo[7] = decode_algo_6;
		break;
	case 'e':
		decode_algo[0] = decode_algo_3;
		decode_algo[1] = decode_algo_4;
		decode_algo[2] = decode_algo_1;
		decode_algo[3] = decode_algo_2;
		decode_algo[4] = decode_algo_5;
		decode_algo[5] = decode_algo_6;
		decode_algo[6] = decode_algo_7;
		decode_algo[7] = decode_algo_8;
		break;
	case 'f':
		decode_algo[0] = decode_algo_4;
		decode_algo[1] = decode_algo_3;
		decode_algo[2] = decode_algo_2;
		decode_algo[3] = decode_algo_1;
		decode_algo[4] = decode_algo_6;
		decode_algo[5] = decode_algo_7;
		decode_algo[6] = decode_algo_8;
		decode_algo[7] = decode_algo_5;
		break;
	case 'g':
		decode_algo[0] = decode_algo_2;
		decode_algo[1] = decode_algo_3;
		decode_algo[2] = decode_algo_4;
		decode_algo[3] = decode_algo_1;
		decode_algo[4] = decode_algo_8;
		decode_algo[5] = decode_algo_7;
		decode_algo[6] = decode_algo_6;
		decode_algo[7] = decode_algo_5;
		break;
	case 'h':
		decode_algo[0] = decode_algo_1;
		decode_algo[1] = decode_algo_2;
		decode_algo[2] = decode_algo_3;
		decode_algo[3] = decode_algo_4;
		decode_algo[4] = decode_algo_7;
		decode_algo[5] = decode_algo_8;
		decode_algo[6] = decode_algo_5;
		decode_algo[7] = decode_algo_6;
		break;
	default:
		//OnSysFail("md", "All", -1, "invalid decode algo");
		printf("[%s] err_code:%d msg:%s\n", "md", -1, "invalid decode algo");
		break;
	}
}

static bool equal(double lh, double rh) {
  if (lh >= rh) {
	return lh - rh <= 1e-5;
  } else {
	return rh - lh <= 1e-5;
  }
}

static void price_check(DepthMarketDataField *rawmd)
{
	if (equal(rawmd->BidPrice1, rawmd->UpperLimitPrice)) {
		rawmd->AskPrice1 = 0.0;
		rawmd->AskVolume1 = 0;
		rawmd->AskPrice2 = 0.0;
		rawmd->AskVolume2 = 0;
		rawmd->AskPrice3 = 0.0;
		rawmd->AskVolume3 = 0;
		rawmd->AskPrice4 = 0.0;
		rawmd->AskVolume4 = 0;
		rawmd->AskPrice5 = 0.0;
		rawmd->AskVolume5 = 0;
	} else if (equal(rawmd->AskPrice1, rawmd->LowerLimitPrice)) {
		rawmd->BidPrice1 = 0.0;
		rawmd->BidVolume1 = 0;
		rawmd->BidPrice2 = 0.0;
		rawmd->BidVolume2 = 0;
		rawmd->BidPrice3 = 0.0;
		rawmd->BidVolume3 = 0;
		rawmd->BidPrice4 = 0.0;
		rawmd->BidVolume4 = 0;
		rawmd->BidPrice5 = 0.0;
		rawmd->BidVolume5 = 0;
	} else {
		if (equal(rawmd->AskPrice1, 0.0) || rawmd->AskVolume1 == 0) {
			rawmd->AskPrice5 = 0.0;
			rawmd->AskVolume5 = 0;
			rawmd->AskPrice4 = 0.0;
			rawmd->AskVolume4 = 0;
			rawmd->AskPrice3 = 0.0;
			rawmd->AskVolume3 = 0;
			rawmd->AskPrice2 = 0.0;
			rawmd->AskVolume2 = 0;
			rawmd->AskPrice1 = 0.0;
			rawmd->AskVolume1 = 0;
		} else if (rawmd->AskPrice2 <= rawmd->AskPrice1) {
			rawmd->AskPrice5 = 0.0;
			rawmd->AskVolume5 = 0;
			rawmd->AskPrice4 = 0.0;
			rawmd->AskVolume4 = 0;
			rawmd->AskPrice3 = 0.0;
			rawmd->AskVolume3 = 0;
			rawmd->AskPrice2 = 0.0;
			rawmd->AskVolume2 = 0;
		} else if (rawmd->AskPrice3 <= rawmd->AskPrice2) {
			rawmd->AskPrice5 = 0.0;
			rawmd->AskVolume5 = 0;
			rawmd->AskPrice4 = 0.0;
			rawmd->AskVolume4 = 0;
			rawmd->AskPrice3 = 0.0;
			rawmd->AskVolume3 = 0;
		} else if (rawmd->AskPrice4 <= rawmd->AskPrice3) {
			rawmd->AskPrice5 = 0.0;
			rawmd->AskVolume5 = 0;
			rawmd->AskPrice4 = 0.0;
			rawmd->AskVolume4 = 0;
		} else if (rawmd->AskPrice5 <= rawmd->AskPrice4) {
			rawmd->AskPrice5 = 0.0;
			rawmd->AskVolume5 = 0;
		}

		if (equal(rawmd->BidPrice1, 0.0) || rawmd->BidVolume1 == 0) {
			rawmd->BidPrice5 = 0.0;
			rawmd->BidVolume5 = 0;
			rawmd->BidPrice4 = 0.0;
			rawmd->BidVolume4 = 0;
			rawmd->BidPrice3 = 0.0;
			rawmd->BidVolume3 = 0;
			rawmd->BidPrice2 = 0.0;
			rawmd->BidVolume2 = 0;
			rawmd->BidPrice1 = 0.0;
			rawmd->BidVolume1 = 0;
		} else if (rawmd->BidPrice2 >= rawmd->BidPrice1) {
			rawmd->BidPrice5 = 0.0;
			rawmd->BidVolume5 = 0;
			rawmd->BidPrice4 = 0.0;
			rawmd->BidVolume4 = 0;
			rawmd->BidPrice3 = 0.0;
			rawmd->BidVolume3 = 0;
			rawmd->BidPrice2 = 0.0;
			rawmd->BidVolume2 = 0;
		} else if (rawmd->BidPrice3 >= rawmd->BidPrice2) {
			rawmd->BidPrice5 = 0.0;
			rawmd->BidVolume5 = 0;
			rawmd->BidPrice4 = 0.0;
			rawmd->BidVolume4 = 0;
			rawmd->BidPrice3 = 0.0;
			rawmd->BidVolume3 = 0;
		} else if (rawmd->BidPrice4 >= rawmd->BidPrice3) {
			rawmd->BidPrice5 = 0.0;
			rawmd->BidVolume5 = 0;
			rawmd->BidPrice4 = 0.0;
			rawmd->BidVolume4 = 0;
		} else if (rawmd->BidPrice5 >= rawmd->BidPrice4) {
			rawmd->BidPrice5 = 0.0;
			rawmd->BidVolume5 = 0;
		}
	}
}

static void
parse_best(char *buf, int pkt_len)
{
	long rece_time = currtime();
	if (buf[0] != '1')
		return;

	struct best *best = (struct best *)(buf + 8);
	const int key = best->MatchTotQty % 8;
	decode_algo[key].decode_best(best);

	const int insidx = ins2idx(pclient->instab, best->ContractID);

	if (insidx == -1)
        return;
	if (strlen(best->ContractID) > 8)
		return;

	long exchtime = get_exchtime(best->GenTime, strtol(best->GenTime + 9, NULL, 10));
	DepthMarketDataField *md = &mdmap[best->ContractID];

	if (md->ExchTime != 0 && md->ExchTime >= exchtime) 
		return;

	md->ExchTime = exchtime;
	strncpy(md->InstrumentID, best->ContractID, sizeof(md->InstrumentID));
	md->LastPrice = best->LastPrice != DBL_MAX ? best->LastPrice : 0.0;
	md->Volume = best->MatchTotQty;
	md->Turnover = best->Turnover;
	md->OpenInterest = best->OpenInterest;
	md->UpperLimitPrice = best->RiseLimit;
	md->LowerLimitPrice = best->FallLimit;


	int i;
	int bid_cnt = 0;

	for (i = 0; i < 10; ++i) {
		if (best->quote[i].BsFlag == 51)
			break;

		++bid_cnt;
	}

	int ask_cnt = best->count_for_deepquote - bid_cnt;

	struct deep *bid = best->quote;
	struct deep *ask = best->quote + bid_cnt;

	for (i = 0; i < best->count_for_deepquote; ++i) {
		decode_algo[key].decode_deep(&best->quote[i]);
	}

	switch (bid_cnt) {
	case 5:
		md->BidPrice5  = bid[4].OrderPrice != DBL_MAX ? bid[4].OrderPrice : 0.0;
		md->BidVolume5 = bid[4].OrderQty;
	case 4:
		md->BidPrice4  = bid[3].OrderPrice != DBL_MAX ? bid[3].OrderPrice : 0.0;
		md->BidVolume4 = bid[3].OrderQty;
	case 3:
		md->BidPrice3  = bid[2].OrderPrice != DBL_MAX ? bid[2].OrderPrice : 0.0;
		md->BidVolume3 = bid[2].OrderQty;
	case 2:
		md->BidPrice2  = bid[1].OrderPrice != DBL_MAX ? bid[1].OrderPrice : 0.0;
		md->BidVolume2 = bid[1].OrderQty;
	case 1:
		md->BidPrice1  = bid[0].OrderPrice != DBL_MAX ? bid[0].OrderPrice : 0.0;
		md->BidVolume1 = bid[0].OrderQty;
		break;
	default:
		break;
	}

	switch (ask_cnt) {
	case 5:
		md->AskPrice5  = ask[4].OrderPrice != DBL_MAX ? ask[4].OrderPrice : 0.0;
		md->AskVolume5 = ask[4].OrderQty;
	case 4:
		md->AskPrice4  = ask[3].OrderPrice != DBL_MAX ? ask[3].OrderPrice : 0.0;
		md->AskVolume4 = ask[3].OrderQty;
	case 3:
		md->AskPrice3  = ask[2].OrderPrice != DBL_MAX ? ask[2].OrderPrice : 0.0;
		md->AskVolume3 = ask[2].OrderQty;
	case 2:
		md->AskPrice2  = ask[1].OrderPrice != DBL_MAX ? ask[1].OrderPrice : 0.0;
		md->AskVolume2 = ask[1].OrderQty;
	case 1:
		md->AskPrice1  = ask[0].OrderPrice != DBL_MAX ? ask[0].OrderPrice : 0.0;
		md->AskVolume1 = ask[0].OrderQty;
		break;
	default:
		break;
	}

	price_check(md);
	if (md->BidPrice1 >= md->AskPrice1 && !equal(md->AskPrice1, 0.0)) {
		printf("cross! BidPrice1:%f,AskPrice1:%f\n", md->BidPrice1, md->AskPrice1);
		fflush(stdout);
		return;
	}

	uint32_t mdslot;
    struct md_static *mdst = (struct md_static *)get_md_static(pclient->instab, insidx);
    struct md_snapshot *mdsn = snapshottab_get_next_slot(pclient->sstab, insidx, &mdslot);

    if (unlikely(mdst->upper_limit == 0.0)) {
        mdst->upper_limit = md->UpperLimitPrice;
        mdst->lower_limit = md->LowerLimitPrice;
    }

    mdsn->type = MDT_Level5;
    mdsn->exchange_time = md->ExchTime * 1000000l;
    mdsn->recv_time = rece_time;
    mdsn->last_price = md->LastPrice;
    mdsn->volume = md->Volume;
    mdsn->turnover = md->Turnover;
    mdsn->open_interest = md->OpenInterest;


	mdsn->bid_price[4] = md->BidPrice5;
	mdsn->bid_size[4]  = md->BidVolume5;
	mdsn->bid_price[3] = md->BidPrice4;
	mdsn->bid_size[3]  = md->BidVolume4;
	mdsn->bid_price[2] = md->BidPrice3;
	mdsn->bid_size[2]  = md->BidVolume3;
	mdsn->bid_price[1] = md->BidPrice2;
	mdsn->bid_size[1]  = md->BidVolume2;
	mdsn->bid_price[0] = md->BidPrice1;
	mdsn->bid_size[0]  = md->BidVolume1;
	mdsn->ask_price[4] = md->AskPrice5;
	mdsn->ask_size[4]  = md->AskVolume5;
	mdsn->ask_price[3] = md->AskPrice4;
	mdsn->ask_size[3]  = md->AskVolume4;
	mdsn->ask_price[2] = md->AskPrice3;
	mdsn->ask_size[2]  = md->AskVolume3;
	mdsn->ask_price[1] = md->AskPrice2;
	mdsn->ask_size[1]  = md->AskVolume2;
	mdsn->ask_price[0] = md->AskPrice1;
	mdsn->ask_size[0]  = md->AskVolume1;

	mdsn->decode_time = currtime();
	pclient->output(pclient, mdst, mdslot);
}



static void
parse_ether(struct timespec *ts, void *rawpkt, int pkt_len)
{
	char *pkt = (char *)rawpkt + 14 + 20 + 8;
	int len = pkt_len - 14 - 20 - 8;

	switch (len) {
	case 676:
		parse_best(pkt, len);
		break;
	case 204:
		//parse_entrust(pkt, len);
		break;
	default:
		break;
	}
}


static void
mcast_add_group(int sock, const char *mcast_ip, const char *local_ip)
{
	struct ip_mreq group;

	group.imr_multiaddr.s_addr = inet_addr(mcast_ip);

	if (!strcmp(local_ip, "any"))
		group.imr_interface.s_addr = INADDR_ANY;
	else
		group.imr_interface.s_addr = inet_addr(local_ip);

	setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group));
}

static void
xorEncrypt(const string& key, char *buf, int len)
{
	int keylen = (int)key.size();

	for (int i = 0; i < len; ++i)
		buf[i] ^= key[i % keylen];
}

int check_stat(const char *filename) {
	struct stat fs;
	if (stat(filename, &fs) != 0) {
		perror("stat error ");
		return 0;
	}

	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (tv.tv_sec - fs.st_mtim.tv_sec > 7 * 3600 ||
		tv.tv_sec - fs.st_mtim.tv_sec < 0)
		return 0;

	return 1;
}

static void run(struct mdclient *client) {
    struct efvi_dce_mc_client *efvi_mc = (struct efvi_dce_mc_client *)client->container;
    pclient = client;

    struct efd *efd = efd_alloc(efvi_mc->ifname, EF_VI_FLAGS_DEFAULT);

    if (!check_stat(efvi_mc->filename)) {
		printf("dce-mcast-key.txt not updated. exiting...\n");
		return;
	}
    FILE *fp = fopen(efvi_mc->filename, "r");
	if (fp == NULL)
		printf("[%s] err_code:%d msg:%s\n", "md", -1, "mcast key file not found");
	char *rbuf = NULL;
	size_t len;
	ssize_t rlen = getline(&rbuf, &len, fp);
	int field_nr;
	char *field[9] = {NULL};
	char *p = strtok(rbuf, "|");
	for (field_nr = 0; field_nr < 9 && p; ++field_nr) {
		field[field_nr] = p;
		p = strtok(NULL, "|");
	}
	if (field_nr != 9
		|| strtol(field[0], NULL, 10) != 4055
		|| strtol(field[1], NULL, 10) != 1
		|| strtol(field[2], NULL, 10) != 0
		|| strcmp(field[3], "success"))
		printf("[%s] err_code:%d msg:%s\n", "md", -1, "mcast get key is wrong");
	efvi_mc->key = field[4][0];
	snprintf(efvi_mc->udp_srvip, sizeof(efvi_mc->udp_srvip), "%s", field[6]);
	efvi_mc->udp_port = strtol(field[7], NULL, 10);
	set_decode_algo(efvi_mc->key);
    efd_set_callback(efd, parse_ether, NULL);
    efd_add_udp_filter(efd, efvi_mc->udp_srvip, efvi_mc->udp_port);
    int sock = onload_socket_nonaccel(AF_INET, SOCK_DGRAM, 0);
	mcast_add_group(sock, efvi_mc->udp_srvip, "any");
    efd_poll(&efd, 1);
}


static struct mdclient *efvi_dce_mc_create(cfg_t *cfg, struct memdb *memdb) {
    struct efvi_dce_mc_client *efvi_mc = new struct efvi_dce_mc_client;
    struct mdclient *client = &efvi_mc->mdclient;

    mdclient_init(client, cfg, memdb);

    const char *ifname;
    const char *filename;
    cfg_get_string(cfg, "ifname", &ifname);
    cfg_get_string(cfg, "filename", &filename);
    snprintf(efvi_mc->ifname, sizeof(efvi_mc->ifname), "%s", ifname);
    snprintf(efvi_mc->filename, sizeof(efvi_mc->filename), "%s", filename);
    printf("label ifname:%s\n", ifname);
    printf("label filename:%s\n", filename);
    client->run = run;
    client->decoder = NULL;
    client->flags = 0;
    client->container = efvi_mc;

    return client;
}


static struct mdsrc_module mdsrc_efvi_dce_mc = {
    .create = efvi_dce_mc_create,
    .api = "efvi-dce-mc"
};

mdsrc_module_register(&mdsrc_efvi_dce_mc);