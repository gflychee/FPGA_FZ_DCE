#include <winterfell/instab.h>
#include <winterfell/mdclient.h>

#include "smdp_struct.h"
#include "depth-octopus.h"
#include <limits.h>

#include <exanic/exanic.h>
#include <exanic/config.h>
#include <exanic/fifo_rx.h>
#include <exanic/time.h>
#include <exanic/port.h>
#include <exanic/filter.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <time.h>
#include <pthread.h>

#include <string>
#include <queue>
#include <map>
#include <set>
#include <cfloat>
struct mdclient *pclient;

#define ZERO 1e-5
bool equal(double lh, double rh) {
  if (lh >= rh) {
    return lh - rh <= ZERO;
  } else {
    return rh - lh <= ZERO;
  }
}

bool gt(double lh, double rh) {
  if (lh >= rh) {
    return lh - rh > ZERO;
  } else return false;
}

void change_endian(char *src, int len) {
  char tmp;
  for (int i = 0; i < len / 2; i++) {
    tmp = src[i];
    src[i] = src[len - i - 1];
    src[len - i - 1] = tmp;
  } 
}

/* Parses a string of the format "<device>:<port>" */
int parse_device_port(const char *str, char *device, int *port_number)
{
    const char *p;
    char *q;

    p = strchr(str, ':');
    if (p == NULL)
        return -1;

    if ((p-str) >= 16)
        return -1;
    strncpy(device, str, p - str);
    device[p - str] = '\0';
    *port_number = strtol(p + 1, &q, 10);
    if (*(p + 1) == '\0' || *q != '\0')
        /* strtol failed */
        return -1;
    return 0;
}

void objdump(const uint8_t *src, int len) {
//void objdump(const char *src, int len) {

  int space = 4, line = 4;
  for (int i = 0; i < len; i++) {
    printf("%02x", src[i]);
    if ((i + 1) % space == 0) printf(" ");
    if ((i + 1) % (space * line) == 0) printf("\n");
  }
  printf("\n");
}

void scan_and_copy(char *dst, const char *src, int len) {
	for (int i = 0; i < len; i++)
		dst[i] = src[i];
}

// return true to continue to decode next byte
inline bool decode_varint(uint8_t *src, int64_t *dst) {
	*dst = *src & 0x7f; // & 01111111
	return *src & 0x80;
}

inline int64_t decode_zigzag(uint64_t n) {
	return (-(n & 0x01)) ^ ((n>>1) & ~(0x80000000));
}

int64_t vint(uint8_t* &p) {
	int i = 1;
	int64_t r;
	uint64_t zz = 0;
	while (decode_varint(p++, &r)) {
		zz += r<<7*(i++-1);
	}
	zz += r<<7*(i++-1);
	return decode_zigzag(zz);
}

int ptoidx(int port) {
	int idx = 0;
	switch (port) {
		case 21000:
			idx = 0;
			break;
		case 21001:
			idx = 1;
			break;
		case 25000:
			idx = 2;
			break;
		case 25001:
			idx = 3;
			break;
		default:
			printf("invalid port:%d\n", port);
			idx = 0;
			break;
	}
	return idx;
}

#define CHECK_FHDR(fhdr) ((fhdr->FieldID == 0x0003 || \
                           fhdr->FieldID == 0x1001 || \
			   fhdr->FieldID == 0x1002 || \
			   (fhdr->FieldID >= 0x1011 && fhdr->FieldID <= 0x1018)) && \
			   (fhdr->FieldSize > 0 && fhdr->FieldSize < 16))

using namespace std;

const int BUFSIZE = 65536;

set<int> init_topicids;

struct TCPData {
    uint32_t seq;
    uint16_t len;
    uint8_t  buf[BUFSIZE];
};

bool operator>(const TCPData &a, const TCPData &b) {
    return a.seq > b.seq;
}

class TCPStack {
public:
    TCPStack();
    bool Push(struct tcphdr *tcphd, uint8_t *tcpdata, uint16_t len);
    void Pop();
    uint8_t *GetData(uint16_t len);
    bool Consume(uint16_t len);
    void Clear();

private:
    uint32_t expected_seq_;
    bool init_;
    priority_queue<TCPData, vector<TCPData>, greater<TCPData> > data_queue_;
    uint8_t buffer_[BUFSIZE];
    uint16_t buf_len_;
};

TCPStack::TCPStack() {
    init_ = false;
    buf_len_ = 0;
}

bool TCPStack::Push(struct tcphdr *tcphd, uint8_t *tcpdata, uint16_t len){
    uint32_t seq = ntohl(tcphd->seq);

    if (!init_) {
        init_ = true;
        expected_seq_ = seq + len + tcphd->syn + tcphd->fin;
        memcpy(buffer_, tcpdata, len);
        buf_len_ = len;
        return true;
    }

    if (tcphd->syn) {
        expected_seq_ = seq + 1 + len;
        memcpy(buffer_, tcpdata, len);
        buf_len_ = len;
        return true;
    }

    if (tcphd->rst) {
        expected_seq_ = 0;
        memcpy(buffer_, tcpdata, len);
        buf_len_ = len;
        return true;
    }

    if (seq == expected_seq_) {
        expected_seq_ = seq + len + tcphd->fin;
        //printf("push expected:%u:%u\n", seq, expected_seq_);
        memcpy(buffer_ + buf_len_, tcpdata, len);
        buf_len_ += len;
        Pop();
        return true;
    }

    //printf("push expected:%u:%u\n", seq, expected_seq_);
    if (seq < expected_seq_)
        return false;

    TCPData d;
    d.seq = seq;
    d.len = len;
    memcpy(d.buf, tcpdata, len);
    data_queue_.push(d);
    return false;
} 

void TCPStack::Pop() {
    while (!data_queue_.empty() &&
            data_queue_.top().seq < expected_seq_)
        data_queue_.pop();
    
    if (!data_queue_.empty()) {
        const TCPData &d = data_queue_.top();
        if (d.seq == expected_seq_) {
            memcpy(buffer_ + buf_len_, d.buf, d.len);
            buf_len_ += d.len;
            data_queue_.pop();
        }
    }
}

uint8_t *TCPStack::GetData(uint16_t len) {
    if (len > buf_len_)
        return NULL;
    return buffer_;
}

bool TCPStack::Consume(uint16_t len) {
    if (len > buf_len_)
        return false;
    memmove(buffer_, buffer_ + len, buf_len_ - len);
    buf_len_ -= len;
    return true;
}

void TCPStack::Clear() {
    buf_len_ = 0;
}

#define MAX_INSNO 4096
#define MAX_DEPTH 10

struct Level {
	double Price;
	int32_t Volume;
};

struct OrderBook {
	int32_t InstrumentNo;
	char    InstrumentID;
	struct Level Ask[MAX_DEPTH], Bid[MAX_DEPTH];
};

class MDTopic {
public:
	MDTopic();
	void Init();
	void OnRtnMDEvent(int32_t insno, struct MDEventField *event);
	void OnRtnTradeInfo(int32_t insno, struct TradeInfoField *trade);
	void SubscribeInstrument(char **ins, int insnum);
	int  Subscribed(int32_t insno);
	void RefreshBook(int32_t insno, long exchtime);
	void ClearBook(int32_t insno);
	void InsertLevel(struct PriceLevelField *lv);
	void ValidateLevel(struct PriceLevelField *lv, int idx);
	void SetDepth(int32_t dep);
	void Update(int32_t pktno);
	bool Updateable(int32_t pktno);
	void PrintBook(int32_t insno, long exchtime);

	int32_t init;
	int16_t topicid;
	int32_t depth;
	int32_t packetno;
	struct InstrumentInfoField insinfos[MAX_INSNO];
	struct TradeSummaryField trades[MAX_INSNO];
	struct OrderBook orderbook[MAX_INSNO];
	int subscribed[MAX_INSNO];
};

class MDCenter {
public:
	MDCenter();
	// TCP data
	void OnRtnInstrumentInfo(int16_t tpid, struct InstrumentInfoField *insinfo);
	void OnRtnTradeSummary(int16_t tpid, struct TradeSummaryField *trade);
	// UDP data
	void OnRtnMDEvent(int16_t tpid, int32_t insno, struct MDEventField *event);
	void OnRtnTradeInfo(int16_t tpid, int32_t insno, struct TradeInfoField *trade);

	void Init(int16_t tpid);
	void SubscribeInstrument(int16_t tpid, char **ins, int insnum);
	int  Subscribed(int16_t tpid, int32_t insno);
	void RefreshBook(int16_t tpid, int32_t insno, long exchtime);
	void ClearBook(int16_t tpid, int32_t insno);
	void InsertPriceLevel(int16_t tpid, struct PriceLevelField *lv);
	void SetDepth(int16_t tpid, int32_t dep);
	void Update(int16_t tpid, int32_t pktno);
	bool Updateable(int16_t tpid, int32_t pktno);
	void ValidateLevel(int16_t tpid, struct PriceLevelField *lv, int idx);

private:
	int GetTopicMD(int16_t tpid);
	MDTopic mdtopics[5];
	int topicno;
};

MDCenter mdcenter[2];


class TCPQuery {
public:
    TCPQuery();
    void TCPPush(struct tcphdr *tcphd, uint8_t *tcpdata, uint16_t len);

private:
    TCPStack tcpstack;
	int16_t topicid; // 
	int32_t depth;
	int32_t packetno;
	bool init;

	int64_t curr_insno; // Current InstrumentNo
};

class MIRP {
public:
	MIRP() {}

	int Updateable(int mdcid, struct MIRPHeader *mirphdr);
	void ProcessField(int mdcid, struct FieldHeader *fhdr, char *pkt);
	void LastCheck(int mdcid);

private:
	time_t  exchtime_;
	
	struct MIRPHeader mirphdr_;
	struct IncMDHeader inchdr_;
	struct MDEventField mdevent_;
	struct TradeInfoField trade_;
};

struct exanic_shfe_mc_client {
	struct mdclient mdclient;
	char   udp_only_ifr[64];
	char   udp_tcp_ifr[64];

	// shfe market data tcp&udp address, to filter in exanic
	struct in_addr *tcp_srv;
	int            *tcp_port;
	struct in_addr *udp_srv;
	int            *udp_port;

	MIRP mirps[4][2];
	map<uint16_t, TCPQuery> tcpq_map;

	static const int TCP_SRV_NUM = 2;
	static const int UDP_SRV_NUM = 8;

	exanic_shfe_mc_client();

	static void *recv_udp_and_tcp(void *arg);
	static void *recv_udp_only(void *arg);

	void run_tcp_thread();
	void raw_parse_ether(struct timespec *ts, void *pkt, int len);
	void polling_udp(const char *buf, int len, int islast);
	void polling_udp_and_tcp(const char *buf, int len, int islast);
};






/************ implementation of MDTopic **************/

MDTopic::MDTopic() : init(0), topicid(0), depth(5), packetno(-1) {
	memset(insinfos, 0, sizeof(insinfos));
	memset(trades, 0, sizeof(trades));
	memset(subscribed, 0, sizeof(subscribed));
}

void MDTopic::OnRtnMDEvent(int32_t insno, struct MDEventField *event) {
	if (insno < 0 || insno >= MAX_INSNO)
		return;
	struct Level *lvptr;
	if (event->MDEntryType == '0') {
		// bid
		lvptr = orderbook[insno].Bid;
	} else {
		// ask
		lvptr = orderbook[insno].Ask;
	}
	switch (event->EventType) {
		case '1':
			// ADD
			for (int i = MAX_DEPTH - 1; i >= event->PriceLevel; i--)
				lvptr[i] = lvptr[i - 1];
			lvptr[event->PriceLevel - 1].Price = insinfos[insno].CodecPrice + insinfos[insno].PriceTick * event->PriceOffset;
			lvptr[event->PriceLevel - 1].Volume = event->Volume;
			break;
		case '2':
			// MODIFY
			lvptr[event->PriceLevel - 1].Price = insinfos[insno].CodecPrice + insinfos[insno].PriceTick * event->PriceOffset;
			lvptr[event->PriceLevel - 1].Volume = event->Volume;
			break;
		case '3':
			// DELETE
			for (int i = event->PriceLevel - 1; i < MAX_DEPTH - 1; i++)
				lvptr[i] = lvptr[i + 1];
			break;
		default:
			break;
	} // switch

}

void MDTopic::OnRtnTradeInfo(int32_t insno, struct TradeInfoField *trade) {
	if (insno < 0 || insno >= MAX_INSNO)
		return;
	trades[insno].LastPrice = insinfos[insno].CodecPrice + insinfos[insno].PriceTick * trade->LastPriceOffset;
	trades[insno].Volume += trade->VolumeChange;
	trades[insno].Turnover += ((double)trade->VolumeChange*insinfos[insno].CodecPrice 
								+ trade->TurnoverOffset*insinfos[insno].PriceTick) * (double)insinfos[insno].VolumeMultiple;
	trades[insno].OpenInterest += trade->OpenInterestChange;
}

void MDTopic::Init() {
	init = 1;
}

void MDTopic::SubscribeInstrument(char **ins, int insnum) {
	for (int i = 0; i < MAX_INSNO; i++) {
		if (!insinfos[i].InstrumentID[0]) // skip null instrument
			continue; 
		if (strlen(insinfos[i].InstrumentID) > 8) // skip option instrument
			continue;
		for (int j = 0; j < insnum; j++) {
			if (strcmp(insinfos[i].InstrumentID, ins[j]) == 0) {
				subscribed[i] = 1;
				break;
			}
		} // for j
		if (insnum == 0) {
			// insnum = 0 to subscribe all instruments
			subscribed[i] = 1;
		}
	} // for i
}

int MDTopic::Subscribed(int32_t insno) {
	if (insno >= 0 && insno < MAX_INSNO)
		return subscribed[insno];
	return 0;
}

long recv_time[2];
int  curr_mdcid;
long exchtime_prev[MAX_INSTRUMENT_NR];
pthread_spinlock_t write_lock;

static void price_check(struct md_snapshot *rawmd, struct md_static *ms)
{
	if (equal(rawmd->bid_price[0], ms->upper_limit)) {
		for (int i = 0; i < 5; ++i) {
			rawmd->ask_price[i] = 0.0;
			rawmd->ask_size[i] = 0;
		}
	} else if (equal(rawmd->ask_price[0], ms->lower_limit)) {
		for (int i = 0; i < 5; ++i) {
			rawmd->bid_price[i] = 0.0;
			rawmd->bid_size[i] = 0;
		}
	} else {
		if (equal(rawmd->ask_price[0], 0.0) || rawmd->ask_size[0] == 0) {
			for (int i = 0; i < 5; ++i) {
				rawmd->ask_price[i] = 0.0;
				rawmd->ask_size[i] = 0;
			}
		} else if (rawmd->ask_price[1] <= rawmd->ask_price[0]) {
			for (int i = 1; i < 5; ++i) {
				rawmd->ask_price[i] = 0.0;
				rawmd->ask_size[i] = 0;
			}
		} else if (rawmd->ask_price[2] <= rawmd->ask_price[1]) {
			for (int i = 2; i < 5; ++i) {
				rawmd->ask_price[i] = 0.0;
				rawmd->ask_size[i] = 0;
			}
		} else if (rawmd->ask_price[3] <= rawmd->ask_price[2]) {
			for (int i = 3; i < 5; ++i) {
				rawmd->ask_price[i] = 0.0;
				rawmd->ask_size[i] = 0;
			}
		} else if (rawmd->ask_price[4] <= rawmd->ask_price[3]) {
			rawmd->ask_price[4] = 0.0;
			rawmd->ask_size[4] = 0;
		}

		if (equal(rawmd->bid_price[0], 0.0) || rawmd->bid_size[0] == 0) {
			for (int i = 0; i < 5; ++i) {
				rawmd->bid_price[i] = 0.0;
				rawmd->bid_size[i] = 0;
			}
		} else if (rawmd->bid_price[1] >= rawmd->bid_price[0]) {
			for (int i = 1; i < 5; ++i) {
				rawmd->bid_price[i] = 0.0;
				rawmd->bid_size[i] = 0;
			}
		} else if (rawmd->bid_price[2] >= rawmd->bid_price[1]) {
			for (int i = 2; i < 5; ++i) {
				rawmd->bid_price[i] = 0.0;
				rawmd->bid_size[i] = 0;
			}
		} else if (rawmd->bid_price[3] >= rawmd->bid_price[2]) {
			for (int i = 3; i < 5; ++i) {
				rawmd->bid_price[i] = 0.0;
				rawmd->bid_size[i] = 0;
			}
		} else if (rawmd->bid_price[4] >= rawmd->bid_price[3]) {
			rawmd->bid_price[4] = 0.0;
			rawmd->bid_size[4] = 0;
		}
	}
}


void MDTopic::RefreshBook(int32_t insno, long exchtime) {
	if (insno < 0 || insno >= MAX_INSNO) {
		return;
	}

	if (depth == 1) {
		return;
	}

	const int insidx = ins2idx(pclient->instab, insinfos[insno].InstrumentID);

	if (insidx == -1) {
		return;
	}

	pthread_spin_lock(&write_lock);

	if (exchtime_prev[insidx] >= exchtime) {
		pthread_spin_unlock(&write_lock);
		return;
	}

	exchtime_prev[insidx] = exchtime;

	uint32_t mdslot;
	struct md_static *ms = (struct md_static *)get_md_static(pclient->instab, insidx);
	struct md_snapshot *md = snapshottab_get_next_slot(pclient->sstab, insidx, &mdslot);
    
	md->type = MDT_Level5;
    
	if (unlikely(ms->upper_limit == 0.0)) {
		ms->upper_limit = trades[insno].UpperLimitPrice;
		ms->lower_limit = trades[insno].LowerLimitPrice;
	}
    
	md->exchange_time = exchtime * 1000000l;
	md->recv_time = recv_time[curr_mdcid];
    
	md->last_price = trades[insno].LastPrice != DBL_MAX ? trades[insno].LastPrice : 0.0;
	md->volume = trades[insno].Volume;
	md->turnover = trades[insno].Turnover;
	md->open_interest = (int)trades[insno].OpenInterest;
    
	for (int i = 0; i < depth; ++i) {
		md->bid_price[i] = orderbook[insno].Bid[i].Price != DBL_MAX ? orderbook[insno].Bid[i].Price : 0.0;
		md->bid_size[i]  = orderbook[insno].Bid[i].Volume;
		md->ask_price[i] = orderbook[insno].Ask[i].Price != DBL_MAX ? orderbook[insno].Ask[i].Price : 0.0;
		md->ask_size[i]  = orderbook[insno].Ask[i].Volume;
	}
    
	md->decode_time = currtime();
	price_check(md, ms);
	if (md->bid_price[0] >= md->ask_price[0] && !equal(md->ask_price[0], 0.0)) {
		printf("cross! bid_price[0]:%f,ask_price[0]:%f\n", md->bid_price[0], md->ask_price[0]);
		fflush(stdout);
		pthread_spin_unlock(&write_lock);
		return;
	}
	pthread_spin_unlock(&write_lock);
	pclient->output(pclient, ms, mdslot);
}

void MDTopic::ClearBook(int32_t insno) {
	if (insno >= 0 && insno < MAX_INSNO) {
		memset(&orderbook[insno], 0, sizeof(struct OrderBook));
		orderbook[insno].Ask[0].Price = orderbook[insno].Ask[1].Price = orderbook[insno].Ask[2].Price \
			 = orderbook[insno].Ask[3].Price = orderbook[insno].Ask[4].Price = DBL_MAX;
	}
}

void MDTopic::SetDepth(int32_t dep) {
	depth = dep;
}

void MDTopic::Update(int32_t pktno) {
	if (!init)
		return;
	if (pktno - packetno > 1)
		printf("Lap from %d to %d\n", packetno, pktno);
	if (pktno > packetno)
		packetno = pktno;
}

bool MDTopic::Updateable(int32_t pktno) {
	if (!init)
		return false;
	return (pktno == packetno + 1 || packetno == -1);
}

void MDTopic::InsertLevel(struct PriceLevelField *lv) {
	if (insinfos[lv->InstrumentNo].ProductClass != '1')
		return;
	if (lv->InstrumentNo >= 0 && lv->InstrumentNo < MAX_INSNO) {
		switch (lv->Direction) {
			case '0': {
				for (int i = 0; i < depth; i++) {
					if (orderbook[lv->InstrumentNo].Bid[i].Price < lv->Price) {
						for (int j = depth - 1; j > i; j--) {
							orderbook[lv->InstrumentNo].Bid[j] = orderbook[lv->InstrumentNo].Bid[j - 1];
						} // for j
						orderbook[lv->InstrumentNo].Bid[i].Price = lv->Price;
						orderbook[lv->InstrumentNo].Bid[i].Volume = lv->Volume;
						break;
					} // 
				}// for
			}
			break;
			case '1': {
				int i;
				for (i = 0; i < depth; i++) {
					if (orderbook[lv->InstrumentNo].Ask[i].Price > lv->Price) {
						break;
					} // 
				}// for
				for (int j = depth - 1; j > i; j--) {
					orderbook[lv->InstrumentNo].Ask[j] = orderbook[lv->InstrumentNo].Ask[j - 1];
				} // for j
				if (i < depth) {
					orderbook[lv->InstrumentNo].Ask[i].Price = lv->Price;
					orderbook[lv->InstrumentNo].Ask[i].Volume = lv->Volume;
				}
			}
			break;
			default:
			break;
		} // switch
	}
}

void MDTopic::ValidateLevel(struct PriceLevelField *lv, int idx) {
	struct Level *lvptr = (lv->Direction == '0')? orderbook[lv->InstrumentNo].Bid : orderbook[lv->InstrumentNo].Ask;
	if (!equal(lv->Price, lvptr[idx].Price) || lv->Volume != lvptr[idx].Volume) {
		printf("Not Match: topicid:%d pktno:%d %s %c %d %lf:%d -- %lf:%d\n",
			topicid, packetno, insinfos[lv->InstrumentNo].InstrumentID,
			lv->Direction, idx, lv->Price, lv->Volume, lvptr[idx].Price, lvptr[idx].Volume);
	}
}

void MDTopic::PrintBook(int32_t insno, long exchtime) {
            if (exchtime < 0)
                exchtime += 24 * 3600 * 1000;

            const int ms = exchtime % 1000;
            exchtime /= 1000;
            const int s = exchtime % 60;
            exchtime /= 60;
            const int m = exchtime % 60;
            exchtime /= 60;
            const int h = exchtime;

	printf("%02d:%02d:%02d.%03d %d %s %lf,%d,%lf,%lf,%lf,%lf, ", h, m, s, ms, topicid, insinfos[insno].InstrumentID,
		trades[insno].LastPrice, trades[insno].Volume, trades[insno].Turnover,
		trades[insno].OpenInterest, trades[insno].UpperLimitPrice, trades[insno].LowerLimitPrice);
	for (int i = 0; i < depth; i++) 
		printf("Ask%d:%lf,%d Bid%d:%lf,%d ",
			 i+1, orderbook[insno].Ask[i].Price, orderbook[insno].Ask[i].Volume,
			 i+1, orderbook[insno].Bid[i].Price, orderbook[insno].Bid[i].Volume);
	printf("\n");
}

/************ implementation of MDCenter **************/
MDCenter::MDCenter() : topicno(0) {

}

void MDCenter::OnRtnInstrumentInfo(int16_t tpid, struct InstrumentInfoField *insinfo) {
	int i = GetTopicMD(tpid);
	if (insinfo->ProductClass == '1' &&
		!mdtopics[i].insinfos[insinfo->InstrumentNo].InstrumentID[0]) {
		mdtopics[i].insinfos[insinfo->InstrumentNo] = *insinfo;
		printf("OnRtnInstrumentInfo Topic:%d InsNo:%d ID:%s\n", tpid, insinfo->InstrumentNo, insinfo->InstrumentID);
		fflush(stdout);
	}
}

void MDCenter::OnRtnTradeSummary(int16_t tpid, struct TradeSummaryField *trade) {
	int i = GetTopicMD(tpid);
	mdtopics[i].trades[trade->InstrumentNo] = *trade;
}

void MDCenter::OnRtnMDEvent(int16_t tpid, int32_t insno, struct MDEventField *event) {
	int i = GetTopicMD(tpid);
	mdtopics[i].OnRtnMDEvent(insno, event);
}

void MDCenter::OnRtnTradeInfo(int16_t tpid, int32_t insno, struct TradeInfoField *trade) {
	int i = GetTopicMD(tpid);
	mdtopics[i].OnRtnTradeInfo(insno, trade);
}

void MDCenter::Init(int16_t tpid) {
	int i = GetTopicMD(tpid);
	mdtopics[i].Init();
}

void MDCenter::SubscribeInstrument(int16_t tpid, char **ins, int insnum) {
	int i = GetTopicMD(tpid);
	mdtopics[i].SubscribeInstrument(ins, insnum);
}

int MDCenter::Subscribed(int16_t tpid, int32_t insno) {
	if (insno < 0 || insno >= MAX_INSNO)
		return 0;
	int i = GetTopicMD(tpid);
	return mdtopics[i].Subscribed(insno);
}

void MDCenter::RefreshBook(int16_t tpid, int32_t insno, long exchtime) {
	int i = GetTopicMD(tpid);
	mdtopics[i].RefreshBook(insno, exchtime);
}

void MDCenter::ClearBook(int16_t tpid, int32_t insno) {
	int i = GetTopicMD(tpid);
	mdtopics[i].ClearBook(insno);
}

void MDCenter::InsertPriceLevel(int16_t tpid, struct PriceLevelField *lv) {
	int i = GetTopicMD(tpid);
	mdtopics[i].InsertLevel(lv);
}

void MDCenter::SetDepth(int16_t tpid, int32_t dep) {
	int i = GetTopicMD(tpid);
	mdtopics[i].SetDepth(dep);
}

void MDCenter::Update(int16_t tpid, int32_t pktno) {
	int i = GetTopicMD(tpid);
	mdtopics[i].Update(pktno);
}

bool MDCenter::Updateable(int16_t tpid, int32_t pktno) {
	int i = GetTopicMD(tpid);
	return mdtopics[i].Updateable(pktno);
}

void MDCenter::ValidateLevel(int16_t tpid, struct PriceLevelField *lv, int idx) {
	int i = GetTopicMD(tpid);
	mdtopics[i].ValidateLevel(lv, idx);
}

int MDCenter::GetTopicMD(int16_t tpid) {
	int i;
	for (i = 0; i < topicno; i++) {
		if (mdtopics[i].topicid == tpid)
			break;
	}
	if (i == topicno) {
		topicno++;
		mdtopics[i].topicid = tpid;
	}
	return i;
}


/*********** implementation of TCPQuery ****************/
TCPQuery::TCPQuery() : topicid(0), depth(0), packetno(-1), init(false), curr_insno(-1) {
    // TODO
}


void TCPQuery::TCPPush(struct tcphdr *tcphd, uint8_t *tcpdata, uint16_t len) {
    tcpstack.Push(tcphd, tcpdata, len);
    struct MDQPHeader *mdqphdr;
    while (true) {
        if ((mdqphdr = (struct MDQPHeader *)tcpstack.GetData(sizeof(struct MDQPHeader))) != NULL) {
            if (mdqphdr->Length >= 0 && mdqphdr->Length <= 1280) {
                uint8_t *pkt;
                uint16_t pkt_off = sizeof(struct MDQPHeader);
                if ((pkt = tcpstack.GetData(mdqphdr->Length + sizeof(*mdqphdr))) != NULL) {
					uint8_t not_end = mdqphdr->Flag >> 4;
                    //printf("Flag:0x%x not end:%u TypeID:0x%x TotLen:%d RequestID:%d\n", mdqphdr->Flag, not_end, mdqphdr->TypeID, mdqphdr->Length, mdqphdr->RequestID);
                    switch(mdqphdr->TypeID) {
                        case 0x12: {
                            // OnRspUserLogin
                            break;
                        }
                        case 0x14: {
                            // OnRspUserLogout
                            break;
                        }
                        case 0x32: {
                            // OnRspQryMarketData
                    		struct FieldHeader *fhdr;
					    	while (pkt_off < mdqphdr->Length + sizeof(struct MDQPHeader)) {
                        		fhdr = (struct FieldHeader *)(pkt + pkt_off);
                        		pkt_off += sizeof(*fhdr);
								if (fhdr->FieldID == 0x32) {
									//struct CenterChangeField *ccf = (struct CenterChangeField*)(pkt + pkt_off);
								} else if (fhdr->FieldID == 0x31) {
									//struct SettlementSessionField *ssf = (struct SettlementSessionField*)(pkt + pkt_off);
								} else if (fhdr->FieldID == 0x1001) {
									if (!init) {
										struct ReqQryMarketDataField *f = (struct ReqQryMarketDataField*)(pkt + pkt_off);
										topicid = f->TopicID;
									}
								} else if (fhdr->FieldID == 0x1003) {
									if (!init) {
										struct TopicIDField *tid = (struct TopicIDField*)(pkt + pkt_off);
										depth = tid->MarketDataDepth;
									} // record depth
								} else if (fhdr->FieldID == 0x1002) {
									//struct SnapTimestampField *stime = (struct SnapTimestampField*)(pkt + pkt_off);
								} else if (fhdr->FieldID == 0x1004) {
									if (!init) {
										struct IncMDPacketNoField *pktno = (struct IncMDPacketNoField *)(pkt + pkt_off);
										packetno = pktno->PacketNo;
										mdcenter[0].Update(topicid, packetno);
										mdcenter[0].SetDepth(topicid, depth);
										mdcenter[1].Update(topicid, packetno);
										mdcenter[1].SetDepth(topicid, depth);
									}
								} else if (fhdr->FieldID == 0x101) {
									if (!init && depth) {
										struct InstrumentInfoField *ins_info = (struct InstrumentInfoField*)(pkt + pkt_off);
										mdcenter[0].OnRtnInstrumentInfo(topicid, ins_info);
										mdcenter[0].ClearBook(topicid, ins_info->InstrumentNo);
										mdcenter[1].OnRtnInstrumentInfo(topicid, ins_info);
										mdcenter[1].ClearBook(topicid, ins_info->InstrumentNo);
										curr_insno = ins_info->InstrumentNo;
									} // not init
								} else if (fhdr->FieldID == 0x102) {
									if (!init && depth) {
										struct TradeSummaryField *trade = (struct TradeSummaryField*)(pkt + pkt_off);
										mdcenter[0].OnRtnTradeSummary(topicid, trade);
										mdcenter[1].OnRtnTradeSummary(topicid, trade);
									} // not init
								} else if (fhdr->FieldID == 0x103) {
									if (!init && depth) {
										struct PriceLevelField *lv = (struct PriceLevelField*)(pkt + pkt_off);
										mdcenter[0].InsertPriceLevel(topicid, lv);
										mdcenter[1].InsertPriceLevel(topicid, lv);
										//printf("PriceLevel: InsNo:%d Direction:%c Price:%lf Volume:%d\n",
										//	lv->InstrumentNo, lv->Direction, lv->Price, lv->Volume);
									}
								}
								pkt_off += fhdr->FieldSize;
							} // while pkt_off < Length
                        break;
                        }
                    } // switch TypeID
					
					if (!not_end && depth && !init) {
						init = true;
						// TODO: subscribe instruments in memdb

						// const vector<string> &instrument = memdb.get_instrument();
						// char **p = new char*[instrument.size()];
						// int n = 10;
						// char **p;
						// for (int i = 0; i < n; i++) {
						// 	p[i] = NULL;
						// }
						// mdcenter[0].SubscribeInstrument(topicid, p, instrument.size());
						// mdcenter[1].SubscribeInstrument(topicid, p, instrument.size());
						/*char **p = new char*[3];
						p[0] = const_cast<char*>("rb2110");
						p[1] = const_cast<char*>("ni2110");
						p[2] = const_cast<char*>("sc2110");*/
						char **p = NULL;
						mdcenter[0].SubscribeInstrument(topicid, p, 0);
						mdcenter[1].SubscribeInstrument(topicid, p, 0);
						mdcenter[0].Init(topicid);
						mdcenter[1].Init(topicid);
						printf("TCP Initialization: %d subscribe instruments and init...\n", topicid);
						fflush(stdout);
						if (topicid == 1000 || topicid == 5000)
							init_topicids.insert(topicid);
					}
                    tcpstack.Consume(mdqphdr->Length + sizeof(*mdqphdr));
                } else {
                    break;
                }
            } else {
                printf("invalid header:\n");
                //objdump((uint8_t*)mdqphdr, sizeof(struct MDQPHeader));
                tcpstack.Clear();
                break;
            }
        } else {
            break;
        }
    } // while
}

// return bytes consumed
int MIRP::Updateable(int mdcid, struct MIRPHeader *mirphdr) {
	if (!mdcenter[mdcid].Updateable(mirphdr->TopicID, mirphdr->PacketNo)) {
		return 0;
	} else {
		mirphdr_ = *mirphdr;
		time_t sec = mirphdr_.SnapTime;
		exchtime_ = sec % (3600*24) + 3600*8;
		if (exchtime_ > 3600 * 18)
			exchtime_ -= 3600 * 24;
		exchtime_ = exchtime_ * 1000 + mirphdr_.SnapMillisec;
		mdcenter[mdcid].Update(mirphdr_.TopicID, mirphdr_.PacketNo);
		return 1;
	}
}

void MIRP::ProcessField(int mdcid, struct FieldHeader *fhdr, char *pkt) {
	if (fhdr->FieldID == 0x0003) {
		uint8_t *ptr = (uint8_t *)pkt;
		int64_t curr_insno = inchdr_.InstrumentNo;
		inchdr_.InstrumentNo = vint(ptr);
		inchdr_.ChangeNo = vint(ptr);
		if (mdcenter[mdcid].Subscribed(mirphdr_.TopicID, curr_insno)) {
			curr_mdcid = mdcid;
			mdcenter[mdcid].RefreshBook(mirphdr_.TopicID, curr_insno, exchtime_);
		}
	} else if (fhdr->FieldID == 0x1001) {
		if (mdcenter[mdcid].Subscribed(mirphdr_.TopicID, inchdr_.InstrumentNo)) {
			mdevent_.EventType = *(char*)(pkt);
			mdevent_.MDEntryType = *(char*)(pkt + 1);
			uint8_t *ptr = (uint8_t*)(pkt + 2);
			mdevent_.PriceLevel = vint(ptr);
			mdevent_.PriceOffset = vint(ptr);
			mdevent_.Volume = vint(ptr);
			mdcenter[mdcid].OnRtnMDEvent(mirphdr_.TopicID, inchdr_.InstrumentNo, &mdevent_);
		}
	} else if (fhdr->FieldID == 0x1002) {
		if (mdcenter[mdcid].Subscribed(mirphdr_.TopicID, inchdr_.InstrumentNo)) {
			uint8_t *ptr = (uint8_t*)(pkt);
			trade_.LastPriceOffset = vint(ptr);
			trade_.VolumeChange = vint(ptr);
			trade_.TurnoverOffset = vint(ptr);
			trade_.OpenInterestChange = vint(ptr);
			mdcenter[mdcid].OnRtnTradeInfo(mirphdr_.TopicID, inchdr_.InstrumentNo, &trade_);
		}
	} else if (fhdr->FieldID == 0x1011 || fhdr->FieldID == 0x1012 || fhdr->FieldID == 0x1013 || 
		fhdr->FieldID == 0x1014 || fhdr->FieldID == 0x1015 || fhdr->FieldID == 0x1016 || 
		fhdr->FieldID == 0x1017 || fhdr->FieldID == 0x1018) {
	}
}

void MIRP::LastCheck(int mdcid) {
	uint8_t not_end = mirphdr_.Flag >> 4;
	if (not_end)
		return;
	int64_t curr_insno = inchdr_.InstrumentNo;
	if (mdcenter[mdcid].Subscribed(mirphdr_.TopicID, curr_insno)) {
		mdcenter[mdcid].RefreshBook(mirphdr_.TopicID, curr_insno, exchtime_);
	}
	inchdr_.InstrumentNo = -1;
}



exanic_shfe_mc_client::exanic_shfe_mc_client() {

	tcp_srv = new struct in_addr[TCP_SRV_NUM];
	tcp_port = new int[TCP_SRV_NUM];
	tcp_srv[0].s_addr = inet_addr("192.168.12.73");
	tcp_port[0] = 33022;
	tcp_srv[1].s_addr = inet_addr("192.168.12.74");
	tcp_port[1] = 33022;

	udp_srv = new struct in_addr[UDP_SRV_NUM];
	udp_port = new int[UDP_SRV_NUM];
	udp_srv[0].s_addr = inet_addr("239.4.51.72");
	udp_port[0] = 25001;
	udp_srv[1].s_addr = inet_addr("239.4.52.72");
	udp_port[1] = 25000;
	udp_srv[2].s_addr = inet_addr("239.4.42.72");
	udp_port[2] = 21000;
	udp_srv[3].s_addr = inet_addr("239.4.41.72");
	udp_port[3] = 21001;
	udp_srv[4].s_addr = inet_addr("239.3.42.71");
	udp_port[4] = 21000;
	udp_srv[5].s_addr = inet_addr("239.3.41.71");
	udp_port[5] = 21001;
	udp_srv[6].s_addr = inet_addr("239.3.52.71");
	udp_port[6] = 25000;
	udp_srv[7].s_addr = inet_addr("239.3.51.71");
	udp_port[7] = 25001;
}

void exanic_shfe_mc_client::run_tcp_thread() {
	pthread_t udp_and_tcp_thread;
	pthread_create(&udp_and_tcp_thread, NULL, recv_udp_and_tcp, this);
}


void exanic_shfe_mc_client::raw_parse_ether(struct timespec *ts, void *pkt, int len) {
//void raw_parse_ether(struct timespec *ts, void *pkt, int len) {
	struct ether_header *ethhdr = (struct ether_header *)pkt;

	struct iphdr *ip_hd = (struct iphdr *)(ethhdr + 1);
	
	struct in_addr src_addr, dst_addr;
	src_addr.s_addr = ip_hd->saddr;
	dst_addr.s_addr = ip_hd->daddr;
	char src_ip[32], dst_ip[32];
	snprintf(src_ip, sizeof(src_ip), "%s", inet_ntoa(src_addr));	
	snprintf(dst_ip, sizeof(dst_ip), "%s", inet_ntoa(dst_addr));	

	if (ip_hd->protocol == IPPROTO_TCP) {
		bool ipfilter = false;
		for (int i = 0; i < TCP_SRV_NUM; i++)
			if (tcp_srv[i].s_addr == ip_hd->saddr) {
				ipfilter = true;
				break;
			}
		if (!ipfilter)
			return;
		struct tcphdr *tcp_hd = (struct tcphdr *)((uint8_t *)ip_hd + 4 * ip_hd->ihl);
		printf(":::::%s:%d -------> %s:%d %d\n", src_ip, ntohs(tcp_hd->source), dst_ip, ntohs(tcp_hd->dest), len);
		fflush(stdout);
		if (ntohs(tcp_hd->source) != 33022)
			return;
		TCPQuery &tcpq = tcpq_map[ntohs(tcp_hd->dest)];
		uint16_t tcp_len = ntohs(ip_hd->tot_len) - 4 * (ip_hd->ihl + tcp_hd->doff);
		uint8_t *tcp_data = (uint8_t *)tcp_hd + 4 * tcp_hd->doff;
		tcpq.TCPPush(tcp_hd, tcp_data, tcp_len);
	}
}

void exanic_shfe_mc_client::polling_udp_and_tcp(const char *buf, int len, int islast) {
	static char packet[4096];
	static int pkt_size = 0;
	static int dst_port = 0;
	static int udp_tlen = 0;
	static int tcp_tlen = 0;
	static int is_tcp = 0;
	static int tcp_done = 0;
	static int toff = 0;
	static int updateable = 0;
	static int mdcid = 1;

	memcpy(packet + pkt_size, buf, len);
	pkt_size += len;

	int offset = 0;
	if (toff == 0) {
		offset += sizeof(struct ether_header);
		struct iphdr *ip = (struct iphdr *)(packet + offset);
		offset += 4 * ip->ihl;

		struct in_addr src_addr, dst_addr;
		src_addr.s_addr = ip->saddr;
		dst_addr.s_addr = ip->daddr;
		char src_ip[32], dst_ip[32];
		snprintf(src_ip, sizeof(src_ip), "%s", inet_ntoa(src_addr));	
		snprintf(dst_ip, sizeof(dst_ip), "%s", inet_ntoa(dst_addr));	

		if (ip->protocol == IPPROTO_TCP) {
			struct tcphdr *tcp_hd = (struct tcphdr *)(packet + offset);
			dst_port = ntohs(tcp_hd->dest);
			tcp_tlen = ntohs(ip->tot_len) - 4 * (ip->ihl + tcp_hd->doff);
			is_tcp = 1;
			offset += 4 * tcp_hd->doff;
			toff   += 4 * tcp_hd->doff;
			//printf("TCP: %s:%d -----> %s:%d\n", src_ip, ntohs(tcp_hd->source), dst_ip, dst_port);
			//fflush(stdout);
		} else if (ip->protocol == IPPROTO_UDP) {
			struct udphdr *udp_hd = (struct udphdr *)(packet + offset);
			dst_port = ntohs(udp_hd->dest);
			udp_tlen = ntohs(udp_hd->len);
			is_tcp = 0;
			offset += sizeof(struct udphdr);
			toff   += sizeof(struct udphdr);
			//printf("UDP AB: toff udp port %s:%d -----> %s:%d tlen:%d toff:%d\n", src_ip, ntohs(udp_hd->source), dst_ip, dst_port, udp_tlen, toff);
			//fflush(stdout);
		}
	}

	if (is_tcp) {
		if (islast) {
			if (!tcp_done) {
				raw_parse_ether(NULL, packet, pkt_size);
			}
			toff = 0;
			pkt_size = 0;
			if (!tcp_done && init_topicids.size() == 2) {
				tcp_done = 1;
				printf("TCP initialization done!\n");
				fflush(stdout);
			}
		}
	} else {
		recv_time[mdcid] = currtime();
		if (toff == sizeof(struct udphdr)) {
			if (pkt_size - offset < sizeof(struct MIRPHeader)) {
				if (offset)
					memmove(packet, packet + offset, pkt_size - offset);
				return;
			} else {
				struct MIRPHeader *mirphdr = (struct MIRPHeader *)(packet + offset);
				offset += sizeof(struct MIRPHeader);
				toff   += sizeof(struct MIRPHeader);
				updateable = mirps[ptoidx(dst_port)][mdcid].Updateable(mdcid, mirphdr);
			}
		}
                
		if (updateable) {
			while (pkt_size - offset >= sizeof(struct FieldHeader) && udp_tlen > toff) {
				struct FieldHeader *fhdr = (struct FieldHeader*)(packet + offset);
				if (!CHECK_FHDR(fhdr)) {
					break;
				}
				if (pkt_size - offset >= sizeof(struct FieldHeader) + fhdr->FieldSize) {
					mirps[ptoidx(dst_port)][mdcid].ProcessField(mdcid, fhdr, packet + offset + sizeof(struct FieldHeader));
					offset += sizeof(struct FieldHeader) + fhdr->FieldSize;
					toff   += sizeof(struct FieldHeader) + fhdr->FieldSize;
				} else {
					break;
				}
			}
		} else {
			int rlen = (pkt_size - offset < udp_tlen - toff)? pkt_size - offset : udp_tlen - toff;
			toff += rlen;
			offset += rlen;
		}
        
		pkt_size = pkt_size - offset;
        
		if (islast) {
			pkt_size = 0;
			toff = 0;
			if (updateable)
				mirps[ptoidx(dst_port)][mdcid].LastCheck(mdcid);
		}
        
		if (pkt_size) {
			//printf("memmove %d\n", pkt_size);
			memmove(packet, packet + offset, pkt_size);
		}
	} // udp_tlen
}

void *exanic_shfe_mc_client::recv_udp_and_tcp(void *arg) {
	printf("start receiving shfe including tcp and A&B udp...\n");

	struct exanic_shfe_mc_client *self = (struct exanic_shfe_mc_client *)arg;
	char *ifname = self->udp_tcp_ifr;
	fprintf(stderr, "ifname = %s\n", ifname);

	char device[16];
	int port_number;
	if (exanic_find_port_by_interface_name(ifname, device, sizeof(device), &port_number) != 0 
		&& parse_device_port(ifname, device, &port_number) != 0) {
		printf("error: no such interface or not an exanic:%s\n", ifname);
		return NULL;
	}

	exanic_t *exanic = exanic_acquire_handle(device);
	if (!exanic) {
		printf("error: exanic acquire handle %s: %s\n", device,
			exanic_get_last_error());
		return NULL;
	}

	exanic_rx_t *rx = exanic_acquire_unused_filter_buffer(exanic, port_number);

	if (!rx) {
		printf("error: exanic acquire buffer %s: %s\n", device, exanic_get_last_error());
		return NULL;
	}

	exanic_ip_filter_t filter;

	filter.protocol = IPPROTO_TCP;
	for (int i = 0; i < TCP_SRV_NUM; i++) {
		filter.src_addr = self->tcp_srv[i].s_addr;
		filter.src_port = htons(self->tcp_port[i]);
		filter.dst_addr = 0;
		filter.dst_port = 0;
		exanic_filter_add_ip(exanic, rx, &filter);
	}

	filter.protocol = IPPROTO_UDP;
	for (int i = 0; i < UDP_SRV_NUM; i++) {
		filter.src_addr = 0;
		filter.src_port = 0;
		filter.dst_addr = self->udp_srv[i].s_addr;
		filter.dst_port = htons(self->udp_port[i]);
		exanic_filter_add_ip(exanic, rx, &filter);
	}

	exanic_cycles32_t timestamp;
	union {
		struct rx_chunk_info info;
		uint64_t data;
	} u;
	while (1) {
		u.data = rx->buffer[rx->next_chunk].u.data;

		if (u.info.generation == rx->generation) {
			while (1) {
				const char *payload = (char *)rx->buffer[rx->next_chunk].payload;
				rx->next_chunk++;
				if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS) {
					rx->next_chunk = 0;
					rx->generation++;
				}

				if (u.info.length != 0) {
					self->polling_udp_and_tcp(payload, u.info.length, 1);
					break;
				} else {
					self->polling_udp_and_tcp(payload, EXANIC_RX_CHUNK_PAYLOAD_SIZE, 0);
					do 
						u.data = rx->buffer[rx->next_chunk].u.data;
					while (u.info.generation == (uint8_t)(rx->generation - 1));
					if (u.info.generation != rx->generation) {
						printf("error: data got lapped\n");
						__exanic_rx_catchup(rx);
						break;
					}
				}
			} // while
		} else if (u.info.generation == (uint8_t)(rx->generation - 1)) {
			// TODO: no new packet
		} else {
			printf("error: data got lapped\n");
			__exanic_rx_catchup(rx);
		}
	} // poll

	return NULL;
}


void exanic_shfe_mc_client::polling_udp(const char *buf, int len, int islast) {
	static char packet[4096];
	static int pkt_size = 0;
	static int dst_port = 0;
	static int udp_tlen = 0;
	static int toff = 0;
	static int updateable = 0;
	static int mdcid = 0;

	memcpy(packet + pkt_size, buf, len);
	//scan_and_copy(packet + pkt_size, buf, len);
	pkt_size += len;
	//printf("polling %d islast:%d\n", len, islast);
	//objdump((const uint8_t *)buf, len);


	int offset = 0;
	//if (toff < sizeof(struct udphdr)) {
	if (toff == 0) {
		offset += sizeof(struct ether_header);
		struct iphdr *ip = (struct iphdr *)(packet + offset);
		offset += 4 * ip->ihl;
		struct udphdr *udp_hd = (struct udphdr *)(packet + offset);
		dst_port = ntohs(udp_hd->dest);
		udp_tlen = ntohs(udp_hd->len);
		offset += sizeof(struct udphdr);
		toff   += sizeof(struct udphdr);
		//printf("%s B: toff udp port %d -----> %d tlen:%d toff:%d\n", __FUNCTION__, ntohs(udp_hd->source), dst_port, udp_tlen, toff);
		//fflush(stdout);
	}

	recv_time[mdcid] = currtime();
	if (toff == sizeof(struct udphdr)) {
		if (pkt_size - offset < sizeof(struct MIRPHeader)) {
			if (offset)
				memmove(packet, packet + offset, pkt_size - offset);
			return;
		} else {
			struct MIRPHeader *mirphdr = (struct MIRPHeader *)(packet + offset);
			offset += sizeof(struct MIRPHeader);
			toff   += sizeof(struct MIRPHeader);
			updateable = mirps[ptoidx(dst_port)][mdcid].Updateable(mdcid, mirphdr);
			//printf("MIRPHeader: TypeID:%04x Len:%d PktNo:%d TpID:%d \n",
				//mirphdr->TypeID, mirphdr->Length, mirphdr->PacketNo, mirphdr->TopicID);
			//fflush(stdout);
		}
	}

	if (updateable) {
		while (pkt_size - offset >= sizeof(struct FieldHeader) && udp_tlen > toff) {
			struct FieldHeader *fhdr = (struct FieldHeader*)(packet + offset);
			if (!CHECK_FHDR(fhdr)) {
				break;
			}
			if (pkt_size - offset >= sizeof(struct FieldHeader) + fhdr->FieldSize) {
				mirps[ptoidx(dst_port)][mdcid].ProcessField(mdcid, fhdr, packet + offset + sizeof(struct FieldHeader));
				offset += sizeof(struct FieldHeader) + fhdr->FieldSize;
				toff   += sizeof(struct FieldHeader) + fhdr->FieldSize;
			} else {
				//printf("break FieldID:%04x FieldSize:%d off:%d toff:%d pkt_size:%d tlen:%d\n", fhdr->FieldID, fhdr->FieldSize, offset, toff, pkt_size, udp_tlen);
				break;
			}
		}
	} else {
		int rlen = (pkt_size - offset < udp_tlen - toff)? pkt_size - offset : udp_tlen - toff;
		toff += rlen;
		offset += rlen;
	}

	pkt_size = pkt_size - offset;

	if (islast) {
		pkt_size = 0;
		toff = 0;
		if (updateable)
			mirps[ptoidx(dst_port)][mdcid].LastCheck(mdcid);
	}

	if (pkt_size) {
		//printf("memmove %d\n", pkt_size);
		memmove(packet, packet + offset, pkt_size);
	}
}



static void run(struct mdclient *client) {
	pthread_spin_init(&write_lock, 0);
	struct exanic_shfe_mc_client *exanic_mc = (struct exanic_shfe_mc_client *)client->container;
	//pclient = &(exanic_mc->mdclient);
	pclient = client;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	strcpy(ifr.ifr_name, exanic_mc->udp_tcp_ifr);
	ioctl(sock, SIOCGIFFLAGS, &ifr);
	printf("set promisc %s\n", ifr.ifr_name);
	fflush(stdout);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sock, SIOCSIFFLAGS, &ifr);

	exanic_mc->run_tcp_thread();

	const char *ifname = exanic_mc->udp_only_ifr;
	printf("ifname:%s\n", ifname);
	fflush(stdout);
	char device[16];
	int port = 0;
	if (exanic_find_port_by_interface_name(ifname, device, sizeof(device), &port) != 0
		&& parse_device_port(ifname, device, &port) != 0) {
		printf("no such interface or not an exanic: %s\n", ifname);
		fflush(stdout);
		return;
	}

	exanic_t *exanic = exanic_acquire_handle(device);
	if (!exanic) {
		printf("exanic acquire handle:%s %s\n", device, exanic_get_last_error());
		fflush(stdout);
		return;
	}
	
	exanic_rx_t *rx = exanic_acquire_unused_filter_buffer(exanic, port);

	exanic_ip_filter_t filter;
	filter.protocol = IPPROTO_UDP;
	for (int i = 0; i < exanic_shfe_mc_client::UDP_SRV_NUM; i++) {
		filter.src_addr = 0;
		filter.src_port = 0;
		filter.dst_addr = exanic_mc->udp_srv[i].s_addr;
		filter.dst_port = htons(exanic_mc->udp_port[i]);
		exanic_filter_add_ip(exanic, rx, &filter);
	}

	union {
		struct rx_chunk_info info;
		uint64_t data;
	} u;
	while (1) {
		u.data = rx->buffer[rx->next_chunk].u.data;

		if (u.info.generation == rx->generation) {
			while (1) {
				const char *payload = (char *)rx->buffer[rx->next_chunk].payload;
				rx->next_chunk++;
				if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS) {
					rx->next_chunk = 0;
					rx->generation++;
				}

				if (u.info.length != 0) {
					exanic_mc->polling_udp(payload, u.info.length, 1);
					break;
				} else {
					exanic_mc->polling_udp(payload, EXANIC_RX_CHUNK_PAYLOAD_SIZE, 0);
					do 
						u.data = rx->buffer[rx->next_chunk].u.data;
					while (u.info.generation == (uint8_t)(rx->generation - 1));
					if (u.info.generation != rx->generation) {
						printf("error: data got lapped\n");
						fflush(stdout);
						__exanic_rx_catchup(rx);
						break;
					}
				}
			} // while
		} else if (u.info.generation == (uint8_t)(rx->generation - 1)) {
			// TODO: no new packet
		} else {
			printf("error: data got lapped\n");
			fflush(stdout);
			__exanic_rx_catchup(rx);
		}
	} // poll
}

static struct mdclient *exanic_shfe_mc_create(cfg_t *cfg, struct memdb *memdb) {
	struct exanic_shfe_mc_client *exanic_mc = new struct exanic_shfe_mc_client();
	struct mdclient *client = &exanic_mc->mdclient;

	mdclient_init(client, cfg, memdb);

	for (int i = 0; i < MAX_INSTRUMENT_NR; ++i) {
		exchtime_prev[i] = LONG_MIN;
	}

	const char *udp_only_ifr;
	cfg_get_string(cfg, "udp_only_ifr", &udp_only_ifr);
	snprintf(exanic_mc->udp_only_ifr, sizeof(exanic_mc->udp_only_ifr), "%s", udp_only_ifr);
	const char *udp_tcp_ifr;
	cfg_get_string(cfg, "udp_tcp_ifr", &udp_tcp_ifr);
	snprintf(exanic_mc->udp_tcp_ifr, sizeof(exanic_mc->udp_tcp_ifr), "%s", udp_tcp_ifr);

	client->run = run;
	client->decoder = NULL;
	client->flags = 0;
	client->container = exanic_mc;

	return client;
}

static struct mdsrc_module mdsrc_exanic_shfe_mc = {
	.create = exanic_shfe_mc_create,
	.api = "exanic-shfe-mc"
};

mdsrc_module_register(&mdsrc_exanic_shfe_mc);


