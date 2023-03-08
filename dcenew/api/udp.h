#include <stdint.h>
#include <stdio.h>

#pragma pack(1)
typedef struct 
{
    /* 报文长度。报文头和报文体总长度 */
    uint16_t    pkg_size;
    /* 报文类型。唯一标记一种报文。 */
    uint16_t    pkg_type;
    /* 版本号。目前版本号为1。 */
    uint8_t     version;
    /* 消息结束标示符：
     *  0：单个/组合报文
     *  1：开始报文
     *  2：中间报文；
     *  3：结束报文
     * */
    uint8_t     flag;
    /* 产品组号 */
    uint8_t     mdg_no;
    /* 开始消息编号 */
    uint64_t    start_seq_no;
    /* 当flag不为0时，则此字段代表当前报文是当前行情消息的第几个报文；
     * 当flag为0时，此字段代表当前报文包含几个消息
     * 心跳报文此字段为0
     * */
    uint8_t     seq_num;
    /* L1、L2定时行情报文发送时间；UTC时间；精确到纳秒 */
    uint64_t    send_time;
    int8_t      reserved;
} dce_dmdp_t;

typedef struct
{
    /* 域长度=域头+域体总长度 */
    uint16_t    field_size;
    /* 域ID */
    uint16_t    field_id;
} dce_dmdp_field_t;

typedef struct
{
    union{
        uint8_t     array_key[4];
        uint32_t    int_key;
    };
}mask_key_t; 

typedef struct {
	uint16_t field_size;
	uint16_t field_id;
	uint8_t market;
	uint64_t batch_no;
	uint8_t	contract_id[129];
	uint8_t	variety[5];
	uint8_t trade_type;
	uint32_t contract_no;
	uint32_t trade_date;
	uint8_t	gen_time[13];
}fld_quot_t;

typedef struct 
{
	uint16_t field_size;
	uint16_t field_id;
	double	last_price;
	double	high_price;
	double	low_price;
	uint32_t  last_match_qty;
	uint32_t match_tot_qty;
	double	turnover;
	uint32_t init_open_interest;
	uint32_t open_interest;
	int32_t interest_chg;
	double	clear_price;
	double	life_low;
	double	life_high;
	double	rise_limit;
	double	fall_limit;
	double	last_clear;
	double	last_close;
	double	bid_price;
	uint32_t bid_qty;
	uint32_t bid_imply_qty;
	double	ask_price;
	uint32_t ask_qty;
	uint32_t ask_imply_qty;
	double	avg_price;
	double	open_price;
	double	close_price;
} fld_snap_best_quot_t;

typedef struct  {
	uint16_t field_size;
	uint16_t field_id;
	double	last_price;
	uint32_t last_match_qty;
	double	low_price;
	double	high_price;
	double	life_low;
	double	life_high;
	double	rise_limit;
	double	fall_limit;
	double	bid_price;
	uint32_t bid_qty;
	double	ask_price;
	uint32_t ask_qty;
}fld_snap_arbi_best_quot_t;

typedef struct  {
	uint16_t field_size;
	uint16_t field_id;
	double	bid_1;
	uint32_t bid_1_qty;
	uint32_t bid_1_imp_qty;
	double	bid_2;
	uint32_t bid_2_qty;
	uint32_t bid_2_imp_qty;
	double	bid_3;
	uint32_t bid_3_qty;
	uint32_t bid_3_imp_qty;
	double	bid_4;
	uint32_t bid_4_qty;
	uint32_t bid_4_imp_qty;
	double	bid_5;
	uint32_t bid_5_qty;
	uint32_t bid_5_imp_qty;
	double	ask_1;
	uint32_t ask_1_qty;
	uint32_t ask_1_imp_qty;
	double	ask_2;
	uint32_t ask_2_qty;
	uint32_t ask_2_imp_qty;
	double	ask_3;
	uint32_t ask_3_qty;
	uint32_t ask_3_imp_qty;
	double	ask_4;
	uint32_t ask_4_qty;
	uint32_t ask_4_imp_qty;
	double	ask_5;
	uint32_t ask_5_qty;
	uint32_t ask_5_imp_qty;
} fld_snap_mbl_t;

typedef struct {
    uint16_t field_size;
    uint16_t field_id;
    double  price_1;
    uint32_t price_1bo_qty;
    uint32_t price_1be_qty;
    uint32_t price_1so_qty;
    uint32_t price_1se_qty;
    double  price_2;
    uint32_t price_2bo_qty;
    uint32_t price_2be_qty;
    uint32_t price_2so_qty;
    uint32_t price_2se_qty;
    double  price_3;
    uint32_t price_3bo_qty;
    uint32_t price_3be_qty;
    uint32_t price_3so_qty;
    uint32_t price_3se_qty;
    double  price_4;
    uint32_t price_4bo_qty;
    uint32_t price_4be_qty;
    uint32_t price_4so_qty;
    uint32_t price_4se_qty;
    double  price_5;
    uint32_t price_5bo_qty;
    uint32_t price_5be_qty;
    uint32_t price_5so_qty;
    uint32_t price_5se_qty;
} fld_snap_segment_price_qty_t;

typedef struct {
    uint16_t field_size;
    uint16_t field_id;
    uint32_t total_buy_order_qty;
    uint32_t total_sell_order_qty;
    double  weighted_average_buy_order_price;
    double  weighted_average_sell_order_price;
} fld_snap_order_statics_t;

typedef struct  {
    uint16_t field_size;
    uint16_t field_id;
    double  bid;
    double  ask;
    int bid_qty_1;
    int bid_qty_2;
    int bid_qty_3;
    int bid_qty_4;
    int bid_qty_5;
    int bid_qty_6;
    int bid_qty_7;
    int bid_qty_8;
    int bid_qty_9;
    int bid_qty_10;
    int ask_qty_1;
    int ask_qty_2;
    int ask_qty_3;
    int ask_qty_4;
    int ask_qty_5;
    int ask_qty_6;
    int ask_qty_7;
    int ask_qty_8;
    int ask_qty_9;
    int ask_qty_10;
}fld_snap_best_orders_t;
#pragma pack()
