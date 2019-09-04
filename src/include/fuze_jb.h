#ifndef __FUZE_JB_H__
#define __FUZE_JB_H__

#ifdef _USE_NEW_JB_

#include <dlist.h>

#define MAX_JB_DATA_LEN 2048

typedef struct {
	uint32_t ts;
	uint16_t seq;
	uint32_t pt;
	uint8_t plc;
	uint8_t data[MAX_JB_DATA_LEN];
	size_t dlen;
} jb_frame_t;
 
struct jb_node;
typedef struct jb_node jb_node_t;

struct  jb_node {
	dlist_link_t link;	
	
	jb_frame_t frame;
};

typedef enum {
	PLAY_EMPTY,
	PLAY_LAST
} dummy_pkt_t;

typedef struct {
	dlist_t active_buffers;
	dlist_t free_buffers;
	jb_frame_t last_frame;
	jb_frame_t null_frame;

	switch_memory_pool_t *pool;
	uint16_t min_len;
	uint16_t max_len;
	uint16_t cur_len;
	uint32_t samples_per_packet;
	uint32_t samples_per_second;

	uint16_t last_rd_seq;
	uint16_t next_out_seq;
	uint32_t next_out_ts;
	uint32_t reference_ts;
	uint32_t reference_local_timer;

	uint8_t  been_in_slow_save_zone;
	uint8_t  received_first_packet;
	uint8_t  sent_first_packet;
	uint8_t  dummy_type; //dummy_pkt_t type
	uint16_t save_ahead_factor;
	uint16_t save_ahead_count;

	uint16_t max_drift;
	uint32_t total_count; 
	uint32_t missed_count;
	uint32_t overflow_drop_count;
	uint16_t most_qlen;
	uint32_t dropped_too_late_count;
	uint32_t out_of_order_count;
	uint32_t jb_exhaustion_count;
	uint32_t cumulative_drift;
} jb_t;

#else

#include "switch_stfu.h"

typedef stfu_instance_t jb_t;
typedef stfu_frame_t jb_frame_t;

#endif

#endif
