#include <stdint.h>

typedef struct __attribute__((packed))
{
    uint32_t dma_type;
    uint32_t dma_len;
    uint8_t  eth_ip_udp[42];            // 网络信息头
    uint16_t counter;                   // 计数器，连续递增，标记共发送了多少个数据包
    uint64_t send_time;                 // 行情更新时间
    uint32_t contract_idx;              // 合约编号
    uint32_t seq_no;                    // 合约在原始行情中编号 
    uint8_t  contract_name[20];         // 合约名称
    uint64_t last_px;                   // 最新成交价，真实值x10000
    uint32_t last_qty;                  // 最新成交量
    uint32_t total_qty;                 // 总成交量
    uint64_t turnover;                  // 总成价格，真实值x10000
    uint32_t open_interest;             // 持仓量
    uint32_t open_interest_chg;         // 持仓量变化
    uint64_t avg_px;                    // 平均价
    uint64_t bid_px;                    // 最优买价, 真实值x10000
    uint32_t bid_qty;                   // 最优买量
    uint32_t bid_imply_qty;             // 推导量（买）
    uint64_t ask_px;                    // 最优卖价, 真实值x10000
    uint32_t ask_qty;                   // 最优卖量
    uint32_t ask_imply_qty;             // 推导量（卖）
} dce_lv1_t;
