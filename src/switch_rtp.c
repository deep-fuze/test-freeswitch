/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Anthony Minessale II <anthm@freeswitch.org>
 * Marcel Barbulescu <marcelbarbulescu@gmail.com>
 * Seven Du <dujinfang@gmail.com>
 *
 * switch_rtp.c -- RTP
 *
 */
//#define DEBUG_2833
//#define RTP_DEBUG_WRITE_DELTA
//#define DEBUG_MISSED_SEQ

#include <switch.h>
#ifndef _MSC_VER
#include <switch_private.h>
#endif
#include <switch_stun.h>
#include <apr_network_io.h>
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#undef VERSION
#undef PACKAGE
#undef inline
#include <datatypes.h>
#include <srtp.h>
#include <srtp_priv.h>
#include <switch_ssl.h>
#include "include/Transport_c.h"
#include "interface/webrtc_neteq_if.h"
#include "g711.h"

/*
 * frequency for printing out packet stats
 * 3000 = 1 minutes at 20ms
 */
#define LOG_OUT_FREQUENCY 3000

#define FIR_COUNTDOWN 50
#define JITTER_LEAD_FRAMES 10
#define READ_INC(rtp_session) switch_mutex_lock(rtp_session->read_mutex); rtp_session->reading++
#define READ_DEC(rtp_session)  switch_mutex_unlock(rtp_session->read_mutex); rtp_session->reading--
#define WRITE_INC(rtp_session)  switch_mutex_lock(rtp_session->write_mutex); rtp_session->writing++
#define WRITE_DEC(rtp_session) switch_mutex_unlock(rtp_session->write_mutex); rtp_session->writing--

#define RTP_STUN_FREQ 1000000
#define rtp_header_len 12
#define RTP_START_PORT 16384
#define RTP_END_PORT 32768
#define MASTER_KEY_LEN   30
#define RTP_MAGIC_NUMBER 42
#define MAX_SRTP_ERRS 10
#define RTP_TS_RESET 1
#define SIZE_OF_30MS_PKT 240

#define MAX_RTP_READ_LOOPS 20

#define DTMF_SANITY (rtp_session->one_second * 30)

#define rtp_session_name(_rtp_session) _rtp_session->session ? switch_core_session_get_name(_rtp_session->session) : "-"

#define JB_BUF_HEADROOM 2
#define JB_BUF_INCREMENTS 3
#define JB_BUF_DECREMENTS 1
#define MIN(a,b) ((a < b) ? a : b)

static switch_port_t START_PORT = RTP_START_PORT;
static switch_port_t END_PORT = RTP_END_PORT;
static switch_mutex_t *port_lock = NULL;
static void do_flush(switch_rtp_t *rtp_session, int force);

typedef srtp_hdr_t rtp_hdr_t;

#ifdef ENABLE_ZRTP
#include "zrtp.h"
static zrtp_global_t *zrtp_global;
#ifndef WIN32
static zrtp_zid_t zid = { "FreeSWITCH01" };
#else
static zrtp_zid_t zid = { "FreeSWITCH0" };
#endif
static int zrtp_on = 0;
#define ZRTP_MITM_TRIES 100
#endif

#ifdef _MSC_VER
#pragma pack(4)
#endif

#ifdef _MSC_VER
#pragma pack()
#define ENABLE_SRTP
#endif

static switch_hash_t *alloc_hash = NULL;

typedef struct {
    srtp_hdr_t header;
    char body[SWITCH_RTP_MAX_BUF_LEN];
    switch_rtp_hdr_ext_t *ext;
    switch_rtp_audio_lvl_t *audio_lvl;
    char *ebody;
} rtp_msg_t;

#define RTP_BODY(_s) (char *) (_s->recv_msg.ebody ? _s->recv_msg.ebody : _s->recv_msg.body)

typedef struct {
    uint32_t ssrc;
    uint8_t seq;
    uint8_t r1;
    uint8_t r2;
    uint8_t r3;
} rtcp_fir_t;

#ifdef _MSC_VER
#pragma pack(push, r1, 1)
#endif

#if SWITCH_BYTE_ORDER == __BIG_ENDIAN
typedef struct {
    unsigned version:2;
    unsigned p:1;
    unsigned fmt:5;
    unsigned pt:8;
    unsigned length:16;
    uint32_t send_ssrc;
    uint32_t recv_ssrc;
} switch_rtcp_ext_hdr_t;

#else /*  BIG_ENDIAN */

typedef struct {
    unsigned fmt:5;
    unsigned p:1;
    unsigned version:2;
    unsigned pt:8;
    unsigned length:16;
    uint32_t send_ssrc;
    uint32_t recv_ssrc;
} switch_rtcp_ext_hdr_t;

#endif

#ifdef _MSC_VER
#pragma pack(pop, r1)
#endif


typedef struct {
    switch_rtcp_ext_hdr_t header;
    char body[SWITCH_RTCP_MAX_BUF_LEN];
} rtcp_ext_msg_t;

typedef struct {
    switch_rtcp_hdr_t header;
    char body[SWITCH_RTCP_MAX_BUF_LEN];
} rtcp_msg_t;


typedef enum {
    VAD_FIRE_TALK = (1 << 0),
    VAD_FIRE_NOT_TALK = (1 << 1)
} vad_talk_mask_t;

struct switch_rtp_vad_data {
    switch_core_session_t *session;
    switch_codec_t vad_codec;
    switch_codec_t *read_codec;
    uint32_t bg_level;
    uint32_t bg_count;
    uint32_t bg_len;
    uint32_t diff_level;
    uint8_t hangunder;
    uint8_t hangunder_hits;
    uint8_t hangover;
    uint8_t hangover_hits;
    uint8_t cng_freq;
    uint8_t cng_count;
    switch_vad_flag_t flags;
    uint32_t ts;
    uint8_t start;
    uint8_t start_count;
    uint8_t scan_freq;
    time_t next_scan;
    int fire_events;
};

struct switch_rtp_rfc2833_data {
    switch_queue_t *dtmf_queue;
    char out_digit;
    unsigned char out_digit_packet[4];
    unsigned int out_digit_sofar;
    unsigned int out_digit_sub_sofar;
    unsigned int out_digit_dur;
    uint16_t in_digit_seq;
    uint32_t in_digit_ts;
    uint32_t last_in_digit_ts;
    uint32_t in_digit_sanity;
    uint32_t in_interleaved;
    uint32_t timestamp_dtmf;
    uint16_t last_duration;
    uint32_t flip;
    char first_digit;
    char last_digit;
    switch_queue_t *dtmf_inqueue;
    switch_mutex_t *dtmf_mutex;
    uint8_t in_digit_queued;
};

typedef struct {
    char *ice_user;
    char *user_ice;
    char *pass;
    char *rpass;
    switch_sockaddr_t *addr;
    uint32_t funny_stun;
    switch_time_t next_run;
    switch_core_media_ice_type_t type;
    ice_t *ice_params;
    ice_proto_t proto;
    uint8_t sending;
    uint8_t ready;
    uint8_t rready;
    int missed_count;
    char last_sent_id[12];
} switch_rtp_ice_t;

struct switch_rtp;

typedef struct switch_dtls_s {
    /* DTLS */
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;
    dtls_fingerprint_t *local_fp;
    dtls_fingerprint_t *remote_fp;
    dtls_state_t state;
    dtls_state_t last_state;
    uint8_t new_state;
    dtls_type_t type;
    switch_size_t bytes;
    void *data;
    switch_socket_t *sock_output;
    switch_sockaddr_t *remote_addr;
    char *rsa;
    char *pvt;
    char *ca;
    char *pem;
    struct switch_rtp *rtp_session;
} switch_dtls_t;

typedef int (*dtls_state_handler_t)(switch_rtp_t *, switch_dtls_t *);


static int dtls_state_handshake(switch_rtp_t *rtp_session, switch_dtls_t *dtls);
static int dtls_state_ready(switch_rtp_t *rtp_session, switch_dtls_t *dtls);
static int dtls_state_setup(switch_rtp_t *rtp_session, switch_dtls_t *dtls);
static int dtls_state_fail(switch_rtp_t *rtp_session, switch_dtls_t *dtls);

dtls_state_handler_t dtls_states[DS_INVALID] = {dtls_state_handshake, dtls_state_setup, dtls_state_ready, dtls_state_fail};

typedef struct ts_normalize_s {
    uint32_t last_ssrc;
    uint32_t last_frame;
    uint32_t ts;
    uint32_t delta;
    uint32_t delta_ct;
    uint32_t delta_ttl;
    uint32_t delta_avg;
    uint32_t delta_delta;
    double delta_percent;
    uint8_t m;
} ts_normalize_t;

#define MAX_CONN_NAME_LEN 20

#define MAX_EMAIL_LEN 1024
#define MAX_PHONE_LEN 100
//#define TRACE_READ 1
#define N_LAST_READ_BUCKETS 20
#define LAST_READ_BUCKET_SIZE 50

struct switch_rtp {
    /*
     * Two sockets are needed because we might be transcoding protocol families
     * (e.g. receive over IPv4 and send over IPv6). In case the protocol
     * families are equal, sock_input == sock_output and only one socket is
     * used.
     */
    switch_socket_t *sock_input, *sock_output, *rtcp_sock_input, *rtcp_sock_output;
    switch_pollfd_t *read_pollfd, *rtcp_read_pollfd;
    switch_pollfd_t *jb_pollfd;

    switch_sockaddr_t *local_addr, *rtcp_local_addr;
    rtp_msg_t send_msg;
    rtcp_msg_t rtcp_send_msg;
    rtcp_ext_msg_t rtcp_ext_send_msg;
    uint8_t fir_seq;
    uint16_t fir_countdown;
    ts_normalize_t ts_norm;
    switch_sockaddr_t *remote_addr, *rtcp_remote_addr;
    rtp_msg_t recv_msg;
    rtcp_msg_t rtcp_recv_msg;
    rtcp_msg_t *rtcp_recv_msg_p;

    switch_bool_t remote_rtp_address_set;
    switch_bool_t remote_rtcp_address_set;

    uint32_t autoadj_window;
    uint32_t autoadj_threshold;
    uint32_t autoadj_tally;

    srtp_ctx_t *send_ctx[2];
    srtp_ctx_t *recv_ctx[2];

    srtp_policy_t send_policy[2];
    srtp_policy_t recv_policy[2];

    uint32_t srtp_errs[2];
    uint32_t srctp_errs[2];


    int srtp_idx_rtp;
    int srtp_idx_rtcp;

    switch_dtls_t *dtls;
    switch_dtls_t *rtcp_dtls;

    uint16_t seq;
    uint32_t ssrc;
    uint32_t remote_ssrc;
    int8_t sending_dtmf;
    uint8_t need_mark;
    switch_payload_t payload;
    switch_rtp_invalid_handler_t invalid_handler;
    void *private_data;
    uint32_t ts;
    uint32_t last_write_ts;
    uint32_t last_read_ts;
    uint32_t last_cng_ts;
    uint32_t last_write_samplecount;
    uint32_t delay_samples;
    uint32_t next_write_samplecount;
    uint32_t max_next_write_samplecount;
    uint32_t queue_delay;
    switch_time_t last_write_timestamp;
    uint32_t flags[SWITCH_RTP_FLAG_INVALID];
    switch_memory_pool_t *pool;
    switch_sockaddr_t *from_addr, *rtcp_from_addr;
    char *rx_host;
    switch_port_t rx_port;
    switch_rtp_ice_t ice;
    switch_rtp_ice_t rtcp_ice;
    char *timer_name;
    char *local_host_str;
    char *remote_host_str;
    char *eff_remote_host_str;
    switch_time_t last_stun;
    uint32_t samples_per_interval;
    uint32_t samples_per_second;
    uint32_t conf_samples_per_interval;
    uint32_t rsamples_per_interval;
    uint32_t ms_per_packet;
    uint32_t one_second;
    uint32_t consecutive_flaws;
    uint32_t jitter_lead;
    double old_mean;
    switch_time_t next_stat_check_time;
    switch_port_t local_port;
    switch_port_t remote_port;
    switch_port_t eff_remote_port;
    switch_port_t remote_rtcp_port;
    uint8_t timestamp_multiplier;

    struct switch_rtp_vad_data vad_data;
    struct switch_rtp_rfc2833_data dtmf_data;
    switch_payload_t te;
    switch_payload_t recv_te;
    switch_payload_t cng_pt;
    switch_mutex_t *flag_mutex;
    switch_mutex_t *read_mutex;
    switch_mutex_t *write_mutex;
    switch_timer_t timer;
    uint8_t ready;
    uint8_t cn;
    jb_t *jb;
    uint32_t max_missed_packets;
    uint32_t missed_count;
    rtp_msg_t write_msg;
    switch_rtp_crypto_key_t *crypto_keys[SWITCH_RTP_CRYPTO_MAX];
    int reading;
    int writing;
    char *stun_ip;
    switch_port_t stun_port;
    int from_auto;
    uint32_t cng_count;
    switch_rtp_bug_flag_t rtp_bugs;
    switch_rtp_stats_t stats;
    int rtcp_interval;
    uint32_t send_rtcp;
    switch_bool_t rtcp_fresh_frame;
    uint8_t been_active_talker;

    switch_time_t send_time;
    switch_byte_t auto_adj_used;
    uint8_t pause_jb;
    uint16_t last_seq;
    switch_time_t last_read_time;
    switch_size_t last_flush_packet_count;
    uint32_t interdigit_delay;
    switch_core_session_t *session;
    payload_map_t **pmaps;
    payload_map_t *pmap_tail;

    uint16_t base_seq;
    uint16_t seq_rollover;
    uint32_t total_received;
    uint32_t last_ts;

    /* fuze stuff*/
    switch_bool_t use_webrtc_neteq;
    switch_bool_t base_seq_set;
    switch_bool_t last_seq_set;
    switch_bool_t srtp_protect_error;
    uint16_t last_bridge_seq[2];
    switch_bool_t is_bridge;
    switch_bool_t is_fuze_app;
    switch_bool_t is_ivr;
    switch_bool_t is_conf;
    switch_bool_t last_write_ts_set;

    switch_time_t time_of_first_ts;
    switch_time_t time_of_last_ts_check;
    switch_time_t time_of_last_xchannel_ts_check;
    uint32_t first_ts;
    int ts_delta;

    switch_time_t time_of_first_rx_ts;
    uint32_t first_rx_ts;

    uint32_t high_drift_packets;
    uint32_t high_drift_log_suppress;
    uint32_t total_sent;
    uint32_t total_bytes_sent;
    uint32_t total_bad_sent;
    uint32_t total_bad_bytes_sent;
    uint32_t out_of_order_sent;
    switch_bool_t dontwait;

    switch_bool_t use_next_ts;
    uint32_t next_ts;

#ifdef ENABLE_ZRTP
    zrtp_session_t *zrtp_session;
    zrtp_profile_t *zrtp_profile;
    zrtp_stream_t *zrtp_stream;
    int zrtp_mitm_tries;
    int zinit;
#endif

    /*Fuze transport Interfaces*/
    void *rtp_conn;
    void *rtcp_conn;

    unsigned short id;
    char rtp_conn_name[MAX_CONN_NAME_LEN];
    char rtcp_conn_name[MAX_CONN_NAME_LEN];

    char email[MAX_EMAIL_LEN];
    char phone[MAX_PHONE_LEN];

    uint32_t write_count;

    switch_bool_t sync_seq_no;

    uint32_t ts_ooo_count;
    uint32_t rtp_send_fail_count;
    uint32_t adjust_cn_count;
    uint32_t bad_packet_size_recv;
    switch_time_t last_adjust_cn_count;
    switch_time_t last_ivr_send_time;
    uint32_t in_cn_period;
#ifdef TRACE_READ
    int trace_cnt;
    char trace_buffer[1024];
#endif

    switch_time_t last_read;
    switch_time_t last_read_w_data;

    int last_ts_delta;

    switch_time_t last_read_log_time;
    switch_time_t last_pkt_sent;
    int last_read_log_time_cnt;
    uint32_t last_read_bucket[N_LAST_READ_BUCKETS];
    switch_size_t ignore_rtp_size;
    int ignore_rtp_cnt;

    uint32_t anchor_next_ts;
    uint16_t anchor_next_seq;
    switch_bool_t anchor_next_set;

    uint32_t anchor_base_ts;
    uint16_t anchor_base_seq;

    switch_bool_t active;
    switch_bool_t muted;

    uint32_t low_level_duration;
    switch_time_t low_level_start;

    int32_t level_out;
    int32_t level_in;

    switch_time_t last_rtcp_send;
};

struct switch_rtcp_report_block {
    uint32_t ssrc; /* The SSRC identifier of the source to which the information in this reception report block pertains. */
    unsigned int fraction :8; /* The fraction of RTP data packets from source SSRC_n lost since the previous SR or RR packet was sent */
    int lost :24; /* The total number of RTP data packets from source SSRC_n that have been lost since the beginning of reception */
    uint32_t highest_sequence_number_received;
    uint32_t jitter; /* An estimate of the statistical variance of the RTP data packet interarrival time, measured in timestamp units and expressed as an unsigned integer. */
    uint32_t lsr; /* The middle 32 bits out of 64 in the NTP timestamp */
    uint32_t dlsr; /* The delay, expressed in units of 1/65536 seconds, between receiving the last SR packet from source SSRC_n and sending this reception report block */
};

/* This was previously used, but a similar struct switch_rtcp_report_block existed and I merged them both.  It also fixed the problem of lost being an integer and not a unsigned.*/
struct switch_rtcp_source {
       unsigned ssrc1:32;
       unsigned fraction_lost:8;
       unsigned cumulative_lost:24;
       unsigned hi_seq_recieved:32;
       unsigned interarrival_jitter:32;
       unsigned lsr:32;
       unsigned lsr_delay:32;
};


struct switch_rtcp_sr_head {
        unsigned ssrc:32;
        unsigned ntp_msw:32;
        unsigned ntp_lsw:32;
        unsigned ts:32;
        unsigned pc:32;
        unsigned oc:32;
};

struct switch_rtcp_s_desc_trunk {
       unsigned ssrc:32;
       unsigned cname:8;
       unsigned length:8;
       char text[1];
};

struct switch_rtcp_s_desc_priv_extn {
    unsigned ssrc:32;
    unsigned priv:8;
    unsigned length:8;
    unsigned prefix_length:8;
    char prefix_and_value[1];
};

struct switch_rtcp_report {
    struct switch_rtcp_source sr_source; //report block; Only one needed
    switch_rtcp_hdr_t sr_desc_head;
    char items[1];
};

struct switch_rtcp_receiverinfo {
    unsigned ssrc:32;
    struct switch_rtcp_report reports;
};

struct switch_rtcp_senderinfo {
    unsigned ssrc:32;
    unsigned ntp_msw:32;
    unsigned ntp_lsw:32;
    unsigned ts:32;
    unsigned pc:32;
    unsigned oc:32;
    struct switch_rtcp_report reports;
};

struct switch_rtcp_app_specific {
    unsigned ssrc:32;
    unsigned name:32;
    char data[1];
};

#define APP_RX_NUM_STATS 10

typedef struct switch_rtcp_app_rx_congestion {
    unsigned ssrc:32;
    unsigned name:32;
#if SWITCH_BYTE_ORDER == __BIG_ENDIAN
    unsigned version:2;
    unsigned degraded:2;
    unsigned active:2;
    unsigned muted:1
    unsigned cn:1
#else
    unsigned cn:1;
    unsigned muted:1;
    unsigned active:2;
    unsigned degraded:2;
    unsigned version:2;
#endif
    unsigned pad2:8;
    uint16_t jitter;
    uint16_t lost_percent;
    uint16_t pad;
    uint16_t rx[APP_RX_NUM_STATS];
} switch_rtcp_app_rx_congestion_t;

typedef enum {
    RESULT_CONTINUE,
    RESULT_GOTO_END,
    RESULT_GOTO_RECVFROM,
    RESULT_GOTO_TIMERCHECK
} handle_rfc2833_result_t;

#ifdef _USE_NEW_JB_

static int jb_buffer_grow(jb_t *jb, uint32_t len)
{
    int i;
    jb_node_t *node;

    int cur_len = DLIST_LEN(&jb->active_buffers) + DLIST_LEN(&jb->free_buffers);

    if (cur_len + len > jb->max_len)
        if (!(len = jb->max_len - cur_len))
            return -1;

    for (i = 0; i < len; ++i) {
        node = switch_core_alloc(jb->pool, sizeof(*node));

        DLIST_INSERT(&jb->free_buffers, node);
    }

    jb->cur_len += len;
    switch_assert(jb->cur_len == cur_len + len);

    return 0;
}

static jb_t *
jb_init (switch_memory_pool_t *pool, uint32_t min_len,
                    uint32_t max_len, uint32_t samples_per_packet,
                    uint32_t samples_per_second)
{
    jb_t *jb;

    jb = switch_core_alloc(pool, sizeof(*jb));

    DLIST_INIT(&jb->active_buffers, ELEM_OFFSET(jb_node_t, link));
    DLIST_INIT(&jb->free_buffers, ELEM_OFFSET(jb_node_t, link));
    jb->pool = pool;
    jb->min_len = min_len;
    jb->max_len = max_len;
    jb->cur_len = 0;
    jb->samples_per_packet = samples_per_packet;
    jb->samples_per_second = samples_per_second;

    jb->last_rd_seq = 0;
    jb->next_out_seq = 0;
    jb->next_out_ts = 0;

    jb->been_in_slow_save_zone = 0;
    jb->received_first_packet = 0;
    jb->sent_first_packet = 0;
    jb->dummy_type = PLAY_EMPTY;
    jb->save_ahead_factor = 0;
    jb->save_ahead_count = 0;

    jb->max_drift = 0;
    jb->total_count = 0;
    jb->missed_count = 0;
    jb->most_qlen = 0;
    jb->overflow_drop_count = 0;
    jb->dropped_too_late_count = 0;
    jb->out_of_order_count = 0;
    jb->cumulative_drift = 0;
    jb->jb_exhaustion_count = 0;

    jb_buffer_grow(jb, jb->min_len);

    memset(&jb->last_frame, 0, sizeof(jb->last_frame));
    memset(&jb->null_frame, 0, sizeof(jb->null_frame));

    memset(jb->null_frame.data, 255, sizeof(jb->null_frame.data));
    jb->null_frame.dlen = samples_per_packet;
    jb->null_frame.plc = 1;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Jitter Buffer min=%d max=%d\n",
                                            jb->min_len, jb->max_len);
    return jb;
}

#define MAX_SEQNO 0xffff

static switch_status_t jb_add_frame (jb_t *jb, uint32_t ts, uint16_t seq, uint32_t pt,
                    void *data, size_t datalen, uint32_t timer)
{
    jb_node_t *node = NULL, *n;

    jb->total_count++;

    if (!jb->received_first_packet) {
        jb->reference_ts = ts;
        jb->reference_local_timer = timer;
        jb->received_first_packet = 1;
    } else {
        uint32_t ts_diff;
        uint32_t timer_diff = timer - jb->reference_local_timer;
        ts_diff = MIN(ts - jb->reference_ts, 0xffffffff - jb->reference_ts + ts + 1); //Found rollover cases

        if(ts_diff > timer_diff) { //new reference
            jb->reference_ts = ts;
            jb->reference_local_timer = timer;
        } else {
            if (timer_diff - ts_diff > jb->max_drift)
                jb->max_drift = timer_diff - ts_diff;

            jb->cumulative_drift += timer_diff - ts_diff;
        }
    }

    if ((seq <= jb->last_rd_seq && jb->last_rd_seq - seq < MAX_SEQNO - jb->last_rd_seq + seq) ||
            (jb->last_rd_seq < seq && jb->total_count > jb->max_len &&
                seq - jb->last_rd_seq > MAX_SEQNO - seq + jb->last_rd_seq)) {
        jb->dropped_too_late_count++;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Delayed Frame. No use. seq=%u last_rd_seq=%u\n", seq, jb->last_rd_seq);
        return SWITCH_STATUS_TIMEOUT;
    }

    if (!DLIST_LEN(&jb->free_buffers)) {
        if (jb_buffer_grow(jb, JB_BUF_INCREMENTS) < 0) {
             /* Buffer is full. Can't grow any further. */
            jb->overflow_drop_count++;
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Jitter Buffer overflow. Packet dropped.\n");
            return SWITCH_STATUS_SUCCESS;
        }
    }

    node = (jb_node_t *) DLIST_HEAD(&jb->free_buffers);
    DLIST_REMOVE(&jb->free_buffers, node);

    node->frame.ts = ts;
    node->frame.seq = seq;
    node->frame.pt = pt;
    node->frame.plc = 0;
    node->frame.dlen = MIN(datalen, MAX_JB_DATA_LEN);
    memcpy(node->frame.data, data, node->frame.dlen);

    if(!DLIST_LEN(&jb->active_buffers)) {
        DLIST_INSERT(&jb->active_buffers, node);
    } else {
        uint8_t found = 0;
        /*
         * List is sorted based on seq. Sorting based on ts will
         * cause problems with DTMF events where two can share same ts.
         */
        n = (jb_node_t *) DLIST_TAIL(&jb->active_buffers);
        do {
            if (n->frame.seq == node->frame.seq) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Duplicate frame with seq=%u.\n", n->frame.seq);
                DLIST_INSERT(&jb->free_buffers, node);
                return SWITCH_STATUS_SUCCESS;
            }

            if (n->frame.seq < node->frame.seq) {
                /*
                 * If n->frame.seq is not rolled over, then node should succeed n.
                 */
                if (node->frame.seq - n->frame.seq < MAX_SEQNO - node->frame.seq + n->frame.seq) {
                    found = 1;
                    break;
                }
            } else {
                /*
                 * If node->frame.seq is rolled over, then node should succeed n.
                 */
                if (n->frame.seq - node->frame.seq > MAX_SEQNO - n->frame.seq + node->frame.seq) {
                    found = 1;
                    break;
                }
            }

            n = (jb_node_t *) DLIST_PREV(&jb->active_buffers, n);
        } while (n != (jb_node_t*) DLIST_TAIL(&jb->active_buffers));

        if (n != (jb_node_t *) DLIST_TAIL(&jb->active_buffers))
            jb->out_of_order_count++;

        DLIST_INSERT_AFTER(&jb->active_buffers, node, n);
        if (!found) {
            DLIST_UPDATE_HEAD(&jb->active_buffers, node);
            jb->out_of_order_count++;
        }
    }

    if (DLIST_LEN(&jb->active_buffers) > jb->most_qlen)
        jb->most_qlen = DLIST_LEN(&jb->active_buffers);

    if (jb->save_ahead_factor && DLIST_LEN(&jb->free_buffers) <= 2) {
        jb->save_ahead_factor = 0;
        jb->save_ahead_count = 0;
        jb->dummy_type = PLAY_LAST;
    }

    return SWITCH_STATUS_SUCCESS;
}

static jb_frame_t * jb_read_frame (jb_t *jb)
{
    jb_node_t *node = NULL;
    jb_frame_t *rframe = NULL;
    int is_dummy = 0;

    if (!jb->save_ahead_factor) {
        if (DLIST_LEN(&jb->active_buffers) <= DLIST_LEN(&jb->free_buffers)) {
            /*
             * Put the system into save-ahead mode. Either the network is lossy or sender's clock
             * has skew (slower). So try to pick one packet after every certain packets and delay
             * its mixing by one frame interval. Do this until in queue becomes full.
             * Also increasing the queue sizes by 1.
             */
            if (!DLIST_LEN(&jb->active_buffers)) {
                jb->save_ahead_factor = 1;
                jb->dummy_type = PLAY_EMPTY;
            }
            else if (DLIST_LEN(&jb->active_buffers) <= DLIST_LEN(&jb->free_buffers) / 3) {
                jb->save_ahead_factor = 25;
                jb->dummy_type = PLAY_LAST;
            } else {
                jb->save_ahead_factor = 50;
                jb->dummy_type = PLAY_LAST;
            }
            if (jb->sent_first_packet)
                jb_buffer_grow(jb, JB_BUF_INCREMENTS);

            jb->save_ahead_count = 1;
        }
    } else {
        switch(jb->save_ahead_factor) {
        case 50:
            if (DLIST_LEN(&jb->active_buffers) <= DLIST_LEN(&jb->free_buffers) / 3) {
                jb->save_ahead_factor = 25;
                jb->dummy_type = PLAY_LAST;
            } else if (!DLIST_LEN(&jb->active_buffers)) {
                jb->save_ahead_factor = 1;
                jb->dummy_type = PLAY_EMPTY;
            }
            break;

        case 25:
            if (jb->been_in_slow_save_zone) {
                jb->jb_exhaustion_count++;
                jb->been_in_slow_save_zone = 0;
            }
            if (DLIST_LEN(&jb->active_buffers) > DLIST_LEN(&jb->free_buffers)) {
                jb->save_ahead_factor = 50;
                jb->dummy_type = PLAY_LAST;
                jb->been_in_slow_save_zone = 1;
            } else if (!DLIST_LEN(&jb->active_buffers)){
                jb->save_ahead_factor = 1;
                jb->dummy_type = PLAY_EMPTY;
            }
            break;

        case 1:
            if (jb->been_in_slow_save_zone) {
                jb->jb_exhaustion_count++;
                jb->been_in_slow_save_zone = 0;
            }
            if (jb->sent_first_packet && DLIST_LEN(&jb->active_buffers) > DLIST_LEN(&jb->free_buffers)) {
                jb->save_ahead_factor = 50;
                jb->dummy_type = PLAY_LAST;
                jb->been_in_slow_save_zone = 1;
            }
            break;
        }
    }

    if (jb->save_ahead_factor) {
        if (jb->save_ahead_count >= jb->save_ahead_factor) {
            is_dummy = 1;
            if (jb->dummy_type == PLAY_EMPTY)
                rframe = &jb->null_frame;
            else
                rframe = &jb->last_frame;
            jb->save_ahead_count = 1;
            goto _done;
        } else {
            jb->save_ahead_count++;
        }
    }

    node = (jb_node_t *) DLIST_HEAD(&jb->active_buffers);
    switch_assert(node);
    DLIST_REMOVE(&jb->active_buffers, node);
    DLIST_INSERT(&jb->free_buffers, node);
    rframe = &node->frame;

_done:
    jb->last_frame = *rframe;
    if (is_dummy) {
        if (jb->sent_first_packet) {
            jb->last_frame.ts = jb->next_out_ts;
            jb->next_out_ts += jb->samples_per_packet;
            jb->last_frame.seq = jb->next_out_seq++;
        }
    } else {
        if (jb->last_rd_seq)
            jb->missed_count += jb->last_frame.seq - jb->last_rd_seq - 1;

        jb->last_rd_seq = jb->last_frame.seq;

        if (!jb->sent_first_packet) {
            jb->next_out_ts = jb->last_frame.ts + jb->samples_per_packet;
            jb->next_out_seq = jb->last_frame.seq + 1;
        } else {
            jb->last_frame.ts = jb->next_out_ts;
            jb->next_out_ts += jb->samples_per_packet;
            jb->last_frame.seq = jb->next_out_seq++;
        }
    }

    if (!jb->sent_first_packet)
        jb->sent_first_packet = 1;

    return &jb->last_frame;
}

static void jb_reset(jb_t *jb)
{
    jb_node_t *n;

    jb->last_rd_seq = 0;
    jb->next_out_seq = 0;
    jb->next_out_ts = 0;

    jb->dummy_type = PLAY_EMPTY;
    jb->save_ahead_factor = 0;
    jb->save_ahead_count = 0;

    jb->max_drift = 0;
    jb->total_count = 0;
    jb->missed_count = 0;
    jb->most_qlen = 0;
    jb->overflow_drop_count = 0;
    jb->dropped_too_late_count = 0;
    jb->out_of_order_count = 0;
    jb->cumulative_drift = 0;

    n = (jb_node_t *) DLIST_HEAD(&jb->active_buffers);
    while (n) {
        DLIST_REMOVE(&jb->active_buffers, n);
        DLIST_INSERT(&jb->free_buffers, n);

        n = (jb_node_t *) DLIST_HEAD(&jb->active_buffers);
    }
}

static uint32_t jb_get_buffer_size(jb_t *jb)
{
    return DLIST_LEN(&jb->active_buffers) + DLIST_LEN(&jb->free_buffers);
}

#else
static void jb_callback(stfu_instance_t *i, void *udata)
{
       switch_core_session_t *session = (switch_core_session_t *) udata;
       stfu_report_t r = { 0 };

       stfu_n_report(i, &r);

       switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG8,
                                         "%s JB REPORT:\nlen: %u\nin: %u\nclean: %u\ngood: %u\nbad: %u\n",
                                         switch_core_session_get_name(session),
                                         r.qlen,
                                         r.packet_in_count,
                                         r.clean_count,
                                         r.consecutive_good_count,
                                         r.consecutive_bad_count
                                         );

}

#endif

static switch_status_t rtp_sendto(switch_rtp_t *rtp_session, switch_socket_t *sock,
                                       switch_sockaddr_t *where, int32_t flags, const char *buf, switch_size_t *len)
{
    if (*len == (switch_size_t)-1) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "rtp_sendto len is -1\n");
        return -1;
    }
    if (rtp_session && rtp_session->rtp_conn && where) {
        return fuze_transport_socket_write(rtp_session->rtp_conn, (const uint8_t *) buf, *len);
    } 
    return SWITCH_STATUS_SUCCESS;
}

#define LONG_TIME_BETWEEN_READS 100000

static switch_status_t rtp_recvfrom(switch_rtp_t *rtp_session, switch_sockaddr_t *from,
                                        switch_socket_t *sock, int32_t flags, char *buf, size_t *len)
{
    if (rtp_session && rtp_session->rtp_conn) {
        __sockaddr_t saddr;
        switch_status_t ret = SWITCH_STATUS_FALSE;
        switch_time_t now = switch_time_now();
        transport_status_t tret = TR_STATUS_FALSE;
        switch_time_t threshold = 0;

        /*
         * If the session is muted then transport will just drop the packets
         * don't even bother going doing to transport except every once in a while
         * to see if any events are waiting
         */
        if (rtp_session->ignore_rtp_size == 1500) {
            rtp_session->ignore_rtp_cnt += 1;
            if (rtp_session->ignore_rtp_cnt >= 50) {
                rtp_session->ignore_rtp_cnt = 0;
            } else {
                *len = 0;
                return SWITCH_STATUS_SUCCESS;
            }
        }

        tret = (switch_status_t) fuze_transport_socket_read(rtp_session->rtp_conn, &saddr, (uint8_t *) buf, len);

#if 0
        if ((switch_time_now() - now) > 1000 && rtp_session->ignore_rtp_size == 0) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                              "Took a long time to read from Fuze Transport %" PRId64 " tret=%d "
                              "len=%" PRId64 "\n", switch_time_now() - now, tret, *len);
        }
#endif

        if (switch_core_session_get_cn_state(rtp_session->session)) {
            threshold = LONG_TIME_BETWEEN_READS * 10;
        } else {
            threshold = LONG_TIME_BETWEEN_READS;
        }

        if (rtp_session->last_read) {
            switch_time_t delta = now - rtp_session->last_read;
            if (delta > threshold && rtp_session->ignore_rtp_size == 0) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                  "Long time since last read: %" PRId64 "ms\n", delta/1000);
            }
            rtp_session->last_read = now;
            if (*len) {
                if (rtp_session->last_read_w_data) {
                    delta = now - rtp_session->last_read_w_data;
                    if ((now - rtp_session->last_read_log_time) > LONG_TIME_BETWEEN_READS*10*10 && rtp_session->ignore_rtp_size == 0) {
                        if (rtp_session->last_read_log_time_cnt) {
                            if (delta > threshold) {
                                int bucket = delta/(1000*LAST_READ_BUCKET_SIZE);
                                rtp_session->last_read_log_time_cnt += 1;
                                bucket = (bucket >= N_LAST_READ_BUCKETS) ? (N_LAST_READ_BUCKETS-1) : bucket;
                                rtp_session->last_read_bucket[bucket] += 1;
                            }
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                              "Delay rx'ing data: cnt(%u) [%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u]\n",
                                              rtp_session->last_read_log_time_cnt,
                                              rtp_session->last_read_bucket[0], rtp_session->last_read_bucket[1],
                                              rtp_session->last_read_bucket[2], rtp_session->last_read_bucket[3],
                                              rtp_session->last_read_bucket[4], rtp_session->last_read_bucket[5],
                                              rtp_session->last_read_bucket[6], rtp_session->last_read_bucket[7],
                                              rtp_session->last_read_bucket[8], rtp_session->last_read_bucket[9],
                                              rtp_session->last_read_bucket[10], rtp_session->last_read_bucket[11],
                                              rtp_session->last_read_bucket[12], rtp_session->last_read_bucket[13],
                                              rtp_session->last_read_bucket[14], rtp_session->last_read_bucket[15],
                                              rtp_session->last_read_bucket[16], rtp_session->last_read_bucket[17],
                                              rtp_session->last_read_bucket[18], rtp_session->last_read_bucket[19]);
                            rtp_session->last_read_log_time_cnt = 0;
                            memset(rtp_session->last_read_bucket, 0, N_LAST_READ_BUCKETS*sizeof(uint32_t));
                        } else if (delta > threshold) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                              "Delay rx'ing data: %" PRId64"ms\n", delta/1000);
                        }
                        rtp_session->last_read_log_time = now;
                    } else {
                        if (delta > threshold) {
                            int bucket = delta/(1000*LAST_READ_BUCKET_SIZE);
                            rtp_session->last_read_log_time_cnt += 1;
                            bucket = (bucket >= N_LAST_READ_BUCKETS) ? (N_LAST_READ_BUCKETS-1) : bucket;
                            rtp_session->last_read_bucket[bucket] += 1;
                        }
                    }
                }
                rtp_session->last_read_w_data = now;
            }
        } else {
            rtp_session->last_read = now;
            if (*len) {
                rtp_session->last_read_w_data = now;
            }
        }

        switch (tret) {
            case TR_STATUS_SUCCESS:
                ret = SWITCH_STATUS_SUCCESS;
                break;
            case TR_STATUS_DISCONNECTED:
                ret = SWITCH_STATUS_BREAK;
                break;
            case TR_STATUS_SOCKET_ERROR:
                ret = SWITCH_STATUS_SOCKERR;
                break;
            default:
            case TR_STATUS_FALSE:
                break;
        }
        
        if (ret == SWITCH_STATUS_SUCCESS) {
            switch_set_sockaddr_v4(from, ntohl(saddr.sa.sin.sin_addr.s_addr), ntohs(saddr.sa.sin.sin_port));
        }
        return ret;
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t rtcp_sendto(switch_rtp_t *rtp_session, switch_socket_t *sock,
                                   switch_sockaddr_t *where, int32_t flags, const char *buf, switch_size_t *len)
{
    if (*len == (switch_size_t)-1) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "rtcp_sendto len is -1\n");
        return -1;
    }

    if (rtp_session && rtp_session->rtcp_conn && where) {
        return fuze_transport_socket_write(rtp_session->rtcp_conn, (const uint8_t *) buf, *len);
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t rtcp_recvfrom(switch_rtp_t *rtp_session, switch_sockaddr_t *from,
                                     switch_socket_t *sock, int32_t flags, char *buf, size_t *len)
{
    if (rtp_session && rtp_session->rtcp_conn) {
        __sockaddr_t saddr;
        switch_status_t ret = SWITCH_STATUS_FALSE;

        transport_status_t tret = (switch_status_t) fuze_transport_socket_read(rtp_session->rtcp_conn, &saddr, (uint8_t *) buf, len);
        
        switch (tret) {
            case TR_STATUS_SUCCESS:
                ret = SWITCH_STATUS_SUCCESS;
                break;
            case TR_STATUS_DISCONNECTED:
                ret = SWITCH_STATUS_BREAK;
                break;
            case TR_STATUS_SOCKET_ERROR:
                ret = SWITCH_STATUS_SOCKERR;
                break;
            default:
            case TR_STATUS_FALSE:
                break;
        }
        
        if (ret == SWITCH_STATUS_SUCCESS) {
            switch_set_sockaddr_v4(from, ntohl(saddr.sa.sin.sin_addr.s_addr), ntohs(saddr.sa.sin.sin_port));
        }
        return ret;
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_bool_t do_2833(switch_rtp_t *rtp_session);

#define rtp_type(rtp_session) rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] ? "video" : "audio"

/* xxx */
SWITCH_DECLARE(void) switch_close_transport(switch_channel_t *channel) {
    switch_rtp_t *rtp_session;

    if (channel == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_close_transport channel is NULL\n");
        return;
    }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (rtp_session) {
        __sockaddr_t saddr;
        size_t len;
        uint8_t buf[SWITCH_RTP_MAX_BUF_LEN];

        if (rtp_session->rtp_conn) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session), SWITCH_LOG_INFO, "fuze transport close rtp connection\n");
            len = SWITCH_RTP_MAX_BUF_LEN;
            while (fuze_transport_socket_read(rtp_session->rtp_conn, &saddr, (uint8_t *) buf, &len) == TR_STATUS_SUCCESS) {
                len = SWITCH_RTP_MAX_BUF_LEN;
            }
            fuze_transport_close_connection(rtp_session->rtp_conn);
            rtp_session->rtp_conn = NULL;
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session), SWITCH_LOG_INFO, "fuze transport NOT close rtp connection\n");
        }

        if (rtp_session->rtcp_conn) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session), SWITCH_LOG_INFO, "fuze transport close rtcp connection\n");
            len = SWITCH_RTP_MAX_BUF_LEN;
            while (fuze_transport_socket_read(rtp_session->rtcp_conn, &saddr, (uint8_t *) buf, &len) == TR_STATUS_SUCCESS) {
                len = SWITCH_RTP_MAX_BUF_LEN;
            }
            fuze_transport_close_connection(rtp_session->rtcp_conn);
            rtp_session->rtcp_conn = NULL;
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session), SWITCH_LOG_INFO, "fuze transport NOT close rtcp connection\n");
        }
    }
}

SWITCH_DECLARE(void) switch_set_dont_wait_for_packets(switch_channel_t *channel) {
    switch_rtp_t *rtp_session;

    if (channel == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_set_dont_wait_for_packets channel=null\n");
        return;
    }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (rtp_session) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "switch_set_dont_wait_for_packets channel\n");
        rtp_session->dontwait = SWITCH_TRUE;
    }
}

SWITCH_DECLARE(switch_bool_t) switch_get_dont_wait_for_packets(switch_channel_t *channel) {
    switch_rtp_t *rtp_session;
    switch_bool_t ret = SWITCH_FALSE;

    if (channel == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_set_dont_wait_for_packets channel=null\n");
        return ret;
    }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (rtp_session) {
        ret = rtp_session->dontwait;
    }
    return ret;
}

SWITCH_DECLARE(void) switch_set_rtp_session_email(switch_rtp_t *rtp_session, char *email) {

    if (rtp_session == NULL || email == NULL) {
        return;
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "switch_set_rtp_session_email %s\n", email);
    strncpy(rtp_session->email, email, MAX_EMAIL_LEN);

    return;
}

SWITCH_DECLARE(switch_bool_t) switch_get_rtp_session_email(switch_channel_t *channel, char *email, int len) {
    switch_rtp_t *rtp_session;

    if (channel == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_get_rtp_session_email channel=null\n");
        return SWITCH_FALSE;
    }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (rtp_session && strlen(rtp_session->email) > 0) {
        strncpy(email, rtp_session->email, len);
        email[len-1] = 0;
        return SWITCH_TRUE;
    }
    return SWITCH_FALSE;
}

SWITCH_DECLARE(switch_bool_t) switch_get_rtp_session_phone(switch_channel_t *channel, char *phone, int len) {
    switch_rtp_t *rtp_session;

    if (channel == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_get_rtp_session_phone channel=null\n");
        return SWITCH_FALSE;
    }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (rtp_session && strlen(rtp_session->phone) > 0) {
        strncpy(phone, rtp_session->phone, len);
        phone[len-1] = 0;
        return SWITCH_TRUE;
    }
    return SWITCH_FALSE;
}

SWITCH_DECLARE(void) switch_set_rtp_session_phone(switch_rtp_t *rtp_session, char *phone) {

    if (rtp_session == NULL || phone == NULL) {
        return;
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "switch_set_rtp_session_phone %s\n", phone);

    strncpy(rtp_session->phone, phone, MAX_PHONE_LEN);

    return;
}

SWITCH_DECLARE(switch_bool_t) switch_get_rtp_session_description(switch_channel_t *channel, char *description, int len) {
    switch_rtp_t *rtp_session;

    if (channel == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_get_rtp_session_description channel=null\n");
        return SWITCH_FALSE;
    }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (rtp_session) {
        sprintf(description, "%s l=(%s:%u)/r=(%s:%u)", rtp_session->rtp_conn_name, 
                rtp_session->local_host_str, rtp_session->local_port,
                rtp_session->remote_host_str, rtp_session->remote_port);
        return SWITCH_TRUE;
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_get_rtp_session_description failed to get rtp session for channel\n");
    }

    return SWITCH_FALSE;
}

SWITCH_DECLARE(switch_bool_t) switch_set_rtcp_passthru(switch_channel_t *channel) {
    switch_rtp_t *rtp_session;

    if (channel == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_set_rtcp_passthru\n");
        return SWITCH_FALSE;
    }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (rtp_session) {
        switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_RTCP_PASSTHRU);
        switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_ENABLE_RTCP);

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "%s RTCP passthru enabled. Remote Port: %d\n", 
                          rtp_session->rtcp_conn_name, rtp_session->remote_rtcp_port);
        return SWITCH_TRUE;
    }
    return SWITCH_FALSE;
}

static handle_rfc2833_result_t handle_rfc2833(switch_rtp_t *rtp_session, switch_size_t bytes, int *do_cng)
{

    if (rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON]) {
        rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON]++;

        if (rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON] > DTMF_SANITY) {
            rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON] = 0;
        } else {
            rtp_session->stats.inbound.last_processed_seq = 0;
        }
    }


#ifdef DEBUG_2833
    if (rtp_session->dtmf_data.in_digit_sanity && !(rtp_session->dtmf_data.in_digit_sanity % 100)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "sanity %d %ld\n", rtp_session->dtmf_data.in_digit_sanity, bytes);
    }
#endif

    if (rtp_session->dtmf_data.in_digit_sanity && !--rtp_session->dtmf_data.in_digit_sanity) {
        switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
        rtp_session->dtmf_data.last_digit = 0;
        rtp_session->dtmf_data.in_digit_ts = 0;
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Failed DTMF sanity check.\n");
    }

    /* RFC2833 ... like all RFC RE: VoIP, guaranteed to drive you to insanity!
       We know the real rules here, but if we enforce them, it's an interop nightmare so,
       we put up with as much as we can so we don't have to deal with being punished for
       doing it right. Nice guys finish last!
    */

    if (bytes > rtp_header_len && !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] &&
        rtp_session->recv_te && rtp_session->recv_msg.header.pt == rtp_session->recv_te) {
        switch_size_t len = bytes - rtp_header_len;
        unsigned char *packet = (unsigned char *) RTP_BODY(rtp_session);
        int end;
        uint16_t duration;
        char key;
        uint16_t in_digit_seq;
        uint32_t ts;

        rtp_session->stats.inbound.last_processed_seq = 0;

        if (!(packet[0] || packet[1] || packet[2] || packet[3]) && len >= 8) {

            switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
            packet += 4;
            len -= 4;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "DTMF payload offset by 4 bytes.\n");
        }

        if (!(packet[0] || packet[1] || packet[2] || packet[3]) && rtp_session->dtmf_data.in_digit_ts) {
            switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Failed DTMF payload check.\n");
            rtp_session->dtmf_data.last_digit = 0;
            rtp_session->dtmf_data.in_digit_ts = 0;
            rtp_session->dtmf_data.in_digit_sanity = 0;
        }

        end = packet[1] & 0x80 ? 1 : 0;
        duration = (packet[2] << 8) + packet[3];
        key = switch_rfc2833_to_char(packet[0]);
        in_digit_seq = ntohs((uint16_t) rtp_session->recv_msg.header.seq);
        ts = htonl(rtp_session->recv_msg.header.ts);

        if (rtp_session->flags[SWITCH_RTP_FLAG_PASS_RFC2833]) {

            if (end) {
                rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON] = DTMF_SANITY - 3;
            } else if (!rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON]) {
                rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON] = 1;
            }

            return RESULT_CONTINUE;
        }

        if (in_digit_seq < rtp_session->dtmf_data.in_digit_seq) {
            if (rtp_session->dtmf_data.in_digit_seq - in_digit_seq > 100) {
                rtp_session->dtmf_data.in_digit_seq = 0;
            }
        }
#ifdef DEBUG_2833
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "packet[%d]: %02x %02x %02x %02x\n", (int) len, (unsigned char) packet[0], (unsigned char) packet[1], (unsigned char) packet[2], (unsigned char) packet[3]);
#endif

        if (in_digit_seq > rtp_session->dtmf_data.in_digit_seq) {

            rtp_session->dtmf_data.in_digit_seq = in_digit_seq;
#ifdef DEBUG_2833

            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "read: %c %u %u %u %u %d %d %s\n",
                              key, in_digit_seq, rtp_session->dtmf_data.in_digit_seq,
                   ts, duration, rtp_session->recv_msg.header.m, end, end && !rtp_session->dtmf_data.in_digit_ts ? "ignored" : "");
#endif

            if (!rtp_session->dtmf_data.in_digit_queued && rtp_session->dtmf_data.in_digit_ts) {
                if ((rtp_session->rtp_bugs & RTP_BUG_IGNORE_DTMF_DURATION)) {
                    switch_dtmf_t dtmf = { key, switch_core_min_dtmf_duration(0), 0, SWITCH_DTMF_RTP };
#ifdef DEBUG_2833
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Early Queuing digit %c:%d\n", dtmf.digit, dtmf.duration / 8);
#endif
                    switch_rtp_queue_rfc2833_in(rtp_session, &dtmf);
                    rtp_session->dtmf_data.in_digit_queued = 1;
                }

                if (rtp_session->jb && (rtp_session->rtp_bugs & RTP_BUG_FLUSH_JB_ON_DTMF)) {
                    stfu_n_reset(rtp_session->jb);
                }

            }

            /* only set sanity if we do NOT ignore the packet */
            if (rtp_session->dtmf_data.in_digit_ts) {
                rtp_session->dtmf_data.in_digit_sanity = 2000;
            }

            if (rtp_session->dtmf_data.last_duration > duration &&
                rtp_session->dtmf_data.last_duration > 0xFC17 && ts == rtp_session->dtmf_data.in_digit_ts) {
                rtp_session->dtmf_data.flip++;
            }

            if (end) {
                if (!rtp_session->dtmf_data.in_digit_ts && rtp_session->dtmf_data.last_in_digit_ts != ts) {
#ifdef DEBUG_2833
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "start with end packet %d\n", ts);
#endif
                    rtp_session->dtmf_data.last_in_digit_ts = ts;
                    rtp_session->dtmf_data.in_digit_ts = ts;
                    rtp_session->dtmf_data.first_digit = key;
                    rtp_session->dtmf_data.in_digit_sanity = 2000;
                }
                if (rtp_session->dtmf_data.in_digit_ts) {
                    switch_dtmf_t dtmf = { key, duration, 0, SWITCH_DTMF_RTP };

                    if (ts > rtp_session->dtmf_data.in_digit_ts) {
                        dtmf.duration += (ts - rtp_session->dtmf_data.in_digit_ts);
                    }
                    if (rtp_session->dtmf_data.flip) {
                        dtmf.duration += rtp_session->dtmf_data.flip * 0xFFFF;
                        rtp_session->dtmf_data.flip = 0;
#ifdef DEBUG_2833
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "you're welcome!\n");
#endif
                    }
#ifdef DEBUG_2833
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "done digit=%c ts=%u start_ts=%u dur=%u ddur=%u\n",
                           dtmf.digit, ts, rtp_session->dtmf_data.in_digit_ts, duration, dtmf.duration);
#endif

                    if (!(rtp_session->rtp_bugs & RTP_BUG_IGNORE_DTMF_DURATION) && !rtp_session->dtmf_data.in_digit_queued) {
#ifdef DEBUG_2833
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Queuing digit %c:%d\n", dtmf.digit, dtmf.duration / 8);
#endif
                        switch_rtp_queue_rfc2833_in(rtp_session, &dtmf);
                    }

                    rtp_session->dtmf_data.last_digit = rtp_session->dtmf_data.first_digit;

                    rtp_session->dtmf_data.in_digit_ts = 0;
                    rtp_session->dtmf_data.in_digit_sanity = 0;
                    rtp_session->dtmf_data.in_digit_queued = 0;
                    *do_cng = 1;
                } else {
                    if (!switch_rtp_ready(rtp_session)) {
                        return RESULT_GOTO_END;
                    }
                    if (!rtp_session->dontwait) {
                        switch_cond_next();
                    }
                    return RESULT_GOTO_RECVFROM;
                }

            } else if (!rtp_session->dtmf_data.in_digit_ts) {
#ifdef DEBUG_2833
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "start %d [%c]\n", ts, key);
#endif
                rtp_session->dtmf_data.in_digit_ts = ts;
                rtp_session->dtmf_data.last_in_digit_ts = ts;
                rtp_session->dtmf_data.first_digit = key;
                rtp_session->dtmf_data.in_digit_sanity = 2000;
            }

            rtp_session->dtmf_data.last_duration = duration;
        } else {
#ifdef DEBUG_2833
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "drop: %c %u %u %u %u %d %d\n",
                   key, in_digit_seq, rtp_session->dtmf_data.in_digit_seq, ts, duration, rtp_session->recv_msg.header.m, end);
#endif
            if (!rtp_session->dontwait) {
                switch_cond_next();
            }
            return RESULT_GOTO_RECVFROM;
        }
    }

    if (bytes && rtp_session->dtmf_data.in_digit_ts) {
        if (!switch_rtp_ready(rtp_session)) {
            return RESULT_GOTO_END;
        }

        if (!rtp_session->dtmf_data.in_interleaved && rtp_session->recv_msg.header.pt != rtp_session->recv_te) {
            /* Drat, they are sending audio still as well as DTMF ok fine..... *sigh* */
            rtp_session->dtmf_data.in_interleaved = 1;
        }

        if (rtp_session->dtmf_data.in_interleaved || (rtp_session->rtp_bugs & RTP_BUG_IGNORE_DTMF_DURATION)) {
            if (rtp_session->recv_msg.header.pt == rtp_session->recv_te) {
                return RESULT_GOTO_RECVFROM;
            }
        } else {
            *do_cng = 1;
            return RESULT_GOTO_TIMERCHECK;
        }
    }

    return RESULT_CONTINUE;
}

static int global_init = 0;
static int rtp_common_write(switch_rtp_t *rtp_session,
                            rtp_msg_t *send_msg, void *data, uint32_t datalen, switch_payload_t payload, uint32_t timestamp, switch_frame_flag_t *flags);


static switch_status_t ice_out(switch_rtp_t *rtp_session, switch_rtp_ice_t *ice)
{
    uint8_t buf[256] = { 0 };
    switch_stun_packet_t *packet;
    unsigned int elapsed;
    switch_size_t bytes;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    //switch_sockaddr_t *remote_addr = rtp_session->remote_addr;
    switch_socket_t *sock_output = rtp_session->sock_output;
    switch_time_t now = switch_micro_time_now();

    if (ice->next_run && ice->next_run > now) {
        return SWITCH_STATUS_BREAK;
    }

    ice->next_run = now + RTP_STUN_FREQ;

    if (ice == &rtp_session->rtcp_ice && rtp_session->rtcp_sock_output) {
        sock_output = rtp_session->rtcp_sock_output;
    }

    if (!sock_output) {
        return SWITCH_STATUS_FALSE;
    }

    switch_assert(rtp_session != NULL);
    switch_assert(ice->ice_user != NULL);

    READ_INC(rtp_session);

    if (rtp_session->last_stun) {
        elapsed = (unsigned int) ((switch_micro_time_now() - rtp_session->last_stun) / 1000);

        if (elapsed > 30000) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "No %s stun for a long time!\n", rtp_type(rtp_session));
            rtp_session->last_stun = switch_micro_time_now();
            //status = SWITCH_STATUS_GENERR;
            //goto end;
        }
    }

    packet = switch_stun_packet_build_header(SWITCH_STUN_BINDING_REQUEST, NULL, buf);
    switch_stun_packet_attribute_add_username(packet, ice->ice_user, (uint16_t)strlen(ice->ice_user));

    memcpy(ice->last_sent_id, packet->header.id, 12);

    //if (ice->pass && ice->type == ICE_GOOGLE_JINGLE) {
    //  switch_stun_packet_attribute_add_password(packet, ice->pass, (uint16_t)strlen(ice->pass));
    //}

    if ((ice->type & ICE_VANILLA)) {
        char sw[128] = "";

        switch_stun_packet_attribute_add_priority(packet, ice->ice_params->cands[ice->ice_params->chosen[ice->proto]][ice->proto].priority);

        switch_snprintf(sw, sizeof(sw), "FreeSWITCH (%s)", switch_version_revision_human());
        switch_stun_packet_attribute_add_software(packet, sw, (uint16_t)strlen(sw));

        if ((ice->type & ICE_CONTROLLED)) {
            switch_stun_packet_attribute_add_controlled(packet);
        } else {
            switch_stun_packet_attribute_add_controlling(packet);
            switch_stun_packet_attribute_add_use_candidate(packet);
        }

        switch_stun_packet_attribute_add_integrity(packet, ice->rpass);
        switch_stun_packet_attribute_add_fingerprint(packet);
    }


    bytes = switch_stun_packet_length(packet);

#ifdef DEBUG_EXTRA
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_CRIT, "%s send %s stun\n", rtp_session_name(rtp_session), rtp_type(rtp_session));
#endif
    
    rtp_sendto(rtp_session, sock_output, ice->addr, 0, (void *) packet, &bytes);
    //switch_socket_sendto(sock_output, ice->addr, 0, (void *) packet, &bytes);

    ice->sending = 3;

    // end:
    READ_DEC(rtp_session);

    return status;
}


static void handle_ice(switch_rtp_t *rtp_session, switch_rtp_ice_t *ice, void *data, switch_size_t len)
{
    switch_stun_packet_t *packet;
    switch_stun_packet_attribute_t *attr;
    void *end_buf;
    char username[34] = { 0 };
    unsigned char buf[512] = { 0 };
    switch_size_t cpylen = len;
    int xlen = 0;
    int ok = 1;
    uint32_t *pri = NULL;
    int is_rtcp = ice == &rtp_session->rtcp_ice;
    uint32_t elapsed;


    if (!switch_rtp_ready(rtp_session) || zstr(ice->user_ice) || zstr(ice->ice_user)) {
        return;
    }

    READ_INC(rtp_session);
    WRITE_INC(rtp_session);

    if (!switch_rtp_ready(rtp_session)) {
        goto end;
    }

    if (cpylen > sizeof(buf)) {
        cpylen = sizeof(buf);
    }


    memcpy(buf, data, cpylen);
    packet = switch_stun_packet_parse(buf, (uint32_t)cpylen);
    if (!packet) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Invalid STUN/ICE packet received %ld bytes\n", (long)cpylen);
        goto end;

    }

    if (!rtp_session->last_stun) {
        elapsed = 0;
    } else {
        elapsed = (unsigned int) ((switch_micro_time_now() - rtp_session->last_stun) / 1000);
    }

    end_buf = buf + ((sizeof(buf) > packet->header.length) ? packet->header.length : sizeof(buf));

    rtp_session->last_stun = switch_micro_time_now();

    switch_stun_packet_first_attribute(packet, attr);

    do {
        switch (attr->type) {
        case SWITCH_STUN_ATTR_ERROR_CODE:
            {
                switch_stun_error_code_t *err = (switch_stun_error_code_t *) attr->value;
                uint32_t code = (err->code * 100) + err->number;

                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "%s got stun binding response %u %s\n",
                                  rtp_session_name(rtp_session),
                                  code,
                                  err->reason
                                  );

                if ((ice->type & ICE_VANILLA) && code == 487) {
                    if ((ice->type & ICE_CONTROLLED)) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "Changing role to CONTROLLING\n");
                        ice->type &= ~ICE_CONTROLLED;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "Changing role to CONTROLLED\n");
                        ice->type |= ICE_CONTROLLED;
                    }
                    packet->header.type = SWITCH_STUN_BINDING_RESPONSE;
                }

            }
            break;
        case SWITCH_STUN_ATTR_MAPPED_ADDRESS:
            if (attr->type) {
                char ip[16];
                uint16_t port;
                switch_stun_packet_attribute_get_mapped_address(attr, ip, &port);
            }
            break;
        case SWITCH_STUN_ATTR_USERNAME:
            if (attr->type) {
                switch_stun_packet_attribute_get_username(attr, username, sizeof(username));
            }
            break;

        case SWITCH_STUN_ATTR_PRIORITY:
            {
                pri = (uint32_t *) attr->value;
                ok = *pri == ice->ice_params->cands[ice->ice_params->chosen[ice->proto]][ice->proto].priority;
            }
            break;
        }

        if (!switch_stun_packet_next_attribute(attr, end_buf)) {
            break;
        }
        xlen += 4 + switch_stun_attribute_padded_length(attr);
    } while (xlen <= packet->header.length);

    if ((ice->type & ICE_GOOGLE_JINGLE) && ok) {
        ok = !strcmp(ice->user_ice, username);
    }

    if ((ice->type & ICE_VANILLA)) {
        char foo1[13] = "", foo2[13] = "";
        if (!ok) ok = !strncmp(packet->header.id, ice->last_sent_id, 12);



        if (packet->header.type == SWITCH_STUN_BINDING_RESPONSE) {
            ok = 1;
            if (!ice->rready) {
                if (rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
                    rtp_session->ice.rready = 1;
                    rtp_session->rtcp_ice.rready = 1;
                } else {
                    ice->rready = 1;
                }

                switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_FLUSH);
            }
        }

        strncpy(foo1, packet->header.id, 12);
        strncpy(foo2, ice->last_sent_id, 12);

        if (!ok && ice == &rtp_session->ice && rtp_session->rtcp_ice.ice_params && pri &&
            *pri == rtp_session->rtcp_ice.ice_params->cands[rtp_session->rtcp_ice.ice_params->chosen[1]][1].priority) {
            ice = &rtp_session->rtcp_ice;
            ok = 1;
        }

        if (!zstr(username)) {
            if (!strcmp(username, ice->user_ice)) {
                ok = 1;
            } else if(!zstr(rtp_session->rtcp_ice.user_ice) && !strcmp(username, rtp_session->rtcp_ice.user_ice)) {
                ice = &rtp_session->rtcp_ice;
                ok = 1;
            }
        }

        if (ok) {
            ice->missed_count = 0;
        } else {
            switch_rtp_ice_t *icep[2] = { &rtp_session->ice, &rtp_session->rtcp_ice };
            switch_port_t port = 0;
            char *host = NULL;

            if (elapsed > 24000 && pri) {
                int i, j;
                uint32_t old;
                //const char *tx_host;
                const char *old_host, *err = NULL;
                //char bufa[30];
                char bufb[30];
                char adj_port[6];
                switch_channel_t *channel = NULL;


                ice->missed_count++;
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "missed %d\n", ice->missed_count);


                if (rtp_session->session) {
                    channel = switch_core_session_get_channel(rtp_session->session);
                }

                //ice->ice_params->cands[ice->ice_params->chosen][ice->proto].priority;
                for (j = 0; j < 2; j++) {
                    for (i = 0; i < icep[j]->ice_params->cand_idx; i++) {
                        if (icep[j]->ice_params->cands[i][icep[j]->proto].priority == *pri) {
                            if (j == IPR_RTP) {
                                icep[j]->ice_params->chosen[j] = i;
                                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Change candidate index to %d\n", i);
                            }

                            ice = icep[j];
                            ok = 1;

                            if (j != IPR_RTP) {
                                break;
                            }

                            old = rtp_session->remote_port;

                            //tx_host = switch_get_addr(bufa, sizeof(bufa), rtp_session->from_addr);
                            old_host = switch_get_addr(bufb, sizeof(bufb), rtp_session->remote_addr);

                            host = ice->ice_params->cands[ice->ice_params->chosen[ice->proto]][ice->proto].con_addr;
                            port = ice->ice_params->cands[ice->ice_params->chosen[ice->proto]][ice->proto].con_port;

                            if (!host || !port) {
                                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error setting remote host!\n");
                                return;
                            }

                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                                              "ICE Auto Changing port from %s:%u to %s:%u\n", old_host, old, host, port);


                            if (channel) {
                                switch_channel_set_variable(channel, "remote_media_ip_reported", switch_channel_get_variable(channel, "remote_media_ip"));
                                switch_channel_set_variable(channel, "remote_media_ip", host);
                                switch_channel_set_variable(channel, "rtp_auto_adjust_ip", host);
                                switch_snprintf(adj_port, sizeof(adj_port), "%u", port);
                                switch_channel_set_variable(channel, "remote_media_port_reported", switch_channel_get_variable(channel, "remote_media_port"));
                                switch_channel_set_variable(channel, "remote_media_port", adj_port);
                                switch_channel_set_variable(channel, "rtp_auto_adjust_port", adj_port);
                                switch_channel_set_variable(channel, "rtp_auto_candidate_adjust", "true");
                            }
                            rtp_session->auto_adj_used = 1;


                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "calling switch_rtp_set_remote_address h=%s p=%u",
                                              host, port);
                            switch_rtp_set_remote_address(rtp_session, host, port, 0, SWITCH_FALSE, &err);
                            if (switch_sockaddr_info_get(&ice->addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS ||
                                !ice->addr) {
                                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error setting remote host!\n");
                                return;
                            }

                            switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_AUTOADJ);

                        }
                    }
                }
            }
        }
    }

    if (ice->missed_count > 5 && !(ice->type & ICE_GOOGLE_JINGLE)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "missed too many: %d, looking for new ICE dest.\n",
                          ice->missed_count);
        ice->rready = 0;
        ok = 1;
    }

    if (ok) {
        const char *host = NULL, *host2 = NULL;
        switch_port_t port = 0, port2 = 0;
        char buf[80] = "";
        char buf2[80] = "";
        const char *err = "";

        if (packet->header.type == SWITCH_STUN_BINDING_REQUEST) {
            uint8_t stunbuf[512];
            switch_stun_packet_t *rpacket;
            const char *remote_ip;
            switch_size_t bytes;
            char ipbuf[25];
            switch_sockaddr_t *from_addr = rtp_session->from_addr;
            switch_socket_t *sock_output = rtp_session->sock_output;

            if (is_rtcp) {
                from_addr = rtp_session->rtcp_from_addr;
                sock_output = rtp_session->rtcp_sock_output;
            }

            if (!ice->ready) {
                ice->ready = 1;
                switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_FLUSH);
            }

            memset(stunbuf, 0, sizeof(stunbuf));
            rpacket = switch_stun_packet_build_header(SWITCH_STUN_BINDING_RESPONSE, packet->header.id, stunbuf);

            if ((ice->type & ICE_GOOGLE_JINGLE)) {
                switch_stun_packet_attribute_add_username(rpacket, username, (uint16_t)strlen(username));
            }

            remote_ip = switch_get_addr(ipbuf, sizeof(ipbuf), from_addr);
            switch_stun_packet_attribute_add_xor_binded_address(rpacket, (char *) remote_ip, switch_sockaddr_get_port(from_addr));

            if (!switch_cmp_addr(from_addr, ice->addr)) {
                host = switch_get_addr(buf, sizeof(buf), from_addr);
                port = switch_sockaddr_get_port(from_addr);
                host2 = switch_get_addr(buf2, sizeof(buf2), ice->addr);
                port2 = switch_sockaddr_get_port(ice->addr);
            }

            if ((ice->type & ICE_VANILLA)) {
                switch_stun_packet_attribute_add_integrity(rpacket, ice->pass);
                switch_stun_packet_attribute_add_fingerprint(rpacket);
            } else {
                if (!switch_cmp_addr(from_addr, ice->addr)) {
                    switch_sockaddr_info_get(&ice->addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool);

                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_NOTICE,
                                      "ICE Auto Changing %s media address from %s:%u to %s:%u\n", is_rtcp ? "rtcp" : "rtp",
                                      host2, port2,
                                      host, port);

                    if (!is_rtcp || rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "calling switch_rtp_set_remote_address h=%s p=%u",
                                          host, port);
                        switch_rtp_set_remote_address(rtp_session, host, port, 0, SWITCH_FALSE, &err);
                    }

                    if (is_rtcp && !rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
                        ice->addr = rtp_session->rtcp_remote_addr;
                    } else {
                        ice->addr = rtp_session->remote_addr;
                    }

                }
            }

            bytes = switch_stun_packet_length(rpacket);

            if (!ice->rready && (ice->type & ICE_VANILLA) && ice->ice_params && !switch_cmp_addr(from_addr, ice->addr)) {
                int i = 0;

                ice->missed_count = 0;
                ice->rready = 1;




                for (i = 0; i <= ice->ice_params->cand_idx; i++) {
                    if (ice->ice_params->cands[i][ice->proto].con_port == port) {
                        if (!ice->ice_params->cands[i][ice->proto].con_addr ||
                            !ice->ice_params->cands[i][ice->proto].cand_type) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                              "Invalid ICE param addr:%d type:%d\n",
                                              ice->ice_params->cands[i][ice->proto].con_addr != 0,
                                              ice->ice_params->cands[i][ice->proto].cand_type != 0);
                            continue;
                        }
                        if (!strcmp(ice->ice_params->cands[i][ice->proto].con_addr, host) &&
                            !strcmp(ice->ice_params->cands[i][ice->proto].cand_type, "relay")) {

                            if (elapsed != 0 && elapsed < 5000) {
                                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                                  "Skiping RELAY stun/%s/dtls port change from %s:%u to %s:%u\n", is_rtcp ? "rtcp" : "rtp",
                                                  host2, port2,
                                                  host, port);

                                goto end;
                            }

                            break;
                        }
                    }
                }

                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_NOTICE,
                                  "Auto Changing stun/%s/dtls port from %s:%u to %s:%u\n", is_rtcp ? "rtcp" : "rtp",
                                  host2, port2,
                                  host, port);

                ice->ice_params->cands[ice->ice_params->chosen[ice->proto]][ice->proto].con_addr = switch_core_strdup(rtp_session->pool, host);
                ice->ice_params->cands[ice->ice_params->chosen[ice->proto]][ice->proto].con_port = port;
                ice->missed_count = 0;

                switch_sockaddr_info_get(&ice->addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool);

                if (!is_rtcp || rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "calling switch_rtp_set_remote_address h=%s p=%u",
                                      host, port);
                    switch_rtp_set_remote_address(rtp_session, host, port, 0, SWITCH_FALSE, &err);
                }

                if (rtp_session->dtls) {

                    if (!is_rtcp || rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
                        switch_sockaddr_info_get(&rtp_session->dtls->remote_addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool);
                    }

                    if (is_rtcp && !rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {

                        switch_sockaddr_info_get(&rtp_session->rtcp_remote_addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool);
                        if (rtp_session->rtcp_dtls) {
                            //switch_sockaddr_info_get(&rtp_session->rtcp_dtls->remote_addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool);
                            rtp_session->rtcp_dtls->remote_addr = rtp_session->rtcp_remote_addr;
                            rtp_session->rtcp_dtls->sock_output = rtp_session->rtcp_sock_output;
                        }

                    }
                }

            }

            rtp_sendto(rtp_session, sock_output, from_addr, 0, (void *) rpacket, &bytes);
        }
    } else if (packet->header.type == SWITCH_STUN_BINDING_ERROR_RESPONSE) {

        if (rtp_session->session) {
            switch_core_session_message_t msg = { 0 };
            msg.from = __FILE__;
            msg.numeric_arg = packet->header.type;
            msg.pointer_arg = packet;
            msg.message_id = SWITCH_MESSAGE_INDICATE_STUN_ERROR;
            switch_core_session_receive_message(rtp_session->session, &msg);
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG,
                              "STUN/ICE binding error received on %s channel\n", rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] ? "video" : "audio");
        }

    }




 end:

    READ_DEC(rtp_session);
    WRITE_DEC(rtp_session);
}

#ifdef ENABLE_ZRTP
SWITCH_STANDARD_SCHED_FUNC(zrtp_cache_save_callback)
{
    zrtp_status_t status = zrtp_status_ok;

    status = zrtp_def_cache_store(zrtp_global);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Saving ZRTP cache: %s\n", zrtp_status_ok == status ? "OK" : "FAIL");
    task->runtime = switch_epoch_time_now(NULL) + 900;
}

static int zrtp_send_rtp_callback(const zrtp_stream_t *stream, char *rtp_packet, unsigned int rtp_packet_length)
{
    switch_rtp_t *rtp_session = zrtp_stream_get_userdata(stream);
    switch_size_t len = rtp_packet_length;
    zrtp_status_t status = zrtp_status_ok;

    switch_socket_sendto(rtp_session->sock_output, rtp_session->remote_addr, 0, rtp_packet, &len);
    return status;
}

static void zrtp_event_callback(zrtp_stream_t *stream, unsigned event)
{
    switch_rtp_t *rtp_session = zrtp_stream_get_userdata(stream);
    zrtp_session_info_t zrtp_session_info;

    switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);
    switch_event_t *fsevent = NULL;
    const char *type;

    type = rtp_type(rtp_session);

    switch (event) {
    case ZRTP_EVENT_IS_SECURE:
        {
            rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_SEND] = 1;
            rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_RECV] = 1;
            if (!rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
                rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_SEND] = 1;
                rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_RECV] = 1;
            }
            if (zrtp_status_ok == zrtp_session_get(stream->session, &zrtp_session_info)) {
                if (zrtp_session_info.sas_is_ready) {

                    switch_channel_set_variable_name_printf(channel, "true", "zrtp_secure_media_confirmed_%s", type);
                    switch_channel_set_variable_name_printf(channel, stream->session->sas1.buffer, "zrtp_sas1_string_%s", type);
                    switch_channel_set_variable_name_printf(channel, stream->session->sas2.buffer, "zrtp_sas2_string", type);
                    zrtp_verified_set(zrtp_global, &stream->session->zid, &stream->session->peer_zid, (uint8_t)1);
                }
            }

            if (!rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {


                if (rtp_session->session) {
                    switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);
                    switch_rtp_t *video_rtp_session = switch_channel_get_private(channel, "__zrtp_video_rtp_session");

                    if (!video_rtp_session) {
                        video_rtp_session = switch_channel_get_private_partner(channel, "__zrtp_video_rtp_session");
                    }

                    if (video_rtp_session) {
                        if (zrtp_status_ok != zrtp_stream_attach(stream->session, &video_rtp_session->zrtp_stream)) {
                            abort();
                        }
                        zrtp_stream_set_userdata(video_rtp_session->zrtp_stream, video_rtp_session);
                        if (switch_true(switch_channel_get_variable(channel, "zrtp_enrollment"))) {
                            zrtp_stream_registration_start(video_rtp_session->zrtp_stream, video_rtp_session->ssrc);
                        } else {
                            zrtp_stream_start(video_rtp_session->zrtp_stream, video_rtp_session->ssrc);
                        }
                    }
                }
            }

            if (switch_event_create(&fsevent, SWITCH_EVENT_CALL_SECURE) == SWITCH_STATUS_SUCCESS) {
                switch_event_add_header(fsevent, SWITCH_STACK_BOTTOM, "secure_media_type", "%s", type);
                switch_event_add_header(fsevent, SWITCH_STACK_BOTTOM, "secure_type", "zrtp:%s:%s", stream->session->sas1.buffer,
                                        stream->session->sas2.buffer);
                switch_event_add_header_string(fsevent, SWITCH_STACK_BOTTOM, "caller-unique-id", switch_channel_get_uuid(channel));
                switch_event_fire(&fsevent);
            }
        }
        break;
#if 0
    case ZRTP_EVENT_NO_ZRTP_QUICK:
        {
            if (stream != NULL) {
                zrtp_stream_stop(stream);
            }
        }
        break;
#endif
    case ZRTP_EVENT_IS_CLIENT_ENROLLMENT:
        {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Enrolled complete!\n");
            switch_channel_set_variable_name_printf(channel, "true", "zrtp_enroll_complete_%s", type);
        }
        break;

    case ZRTP_EVENT_USER_ALREADY_ENROLLED:
        {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "User already enrolled!\n");
            switch_channel_set_variable_name_printf(channel, "true", "zrtp_already_enrolled_%s", type);
        }
        break;

    case ZRTP_EVENT_NEW_USER_ENROLLED:
        {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "New user enrolled!\n");
            switch_channel_set_variable_name_printf(channel, "true", "zrtp_new_user_enrolled_%s", type);
        }
        break;

    case ZRTP_EVENT_USER_UNENROLLED:
        {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "User unenrolled!\n");
            switch_channel_set_variable_name_printf(channel, "true", "zrtp_user_unenrolled_%s", type);
        }
        break;

    case ZRTP_EVENT_IS_PENDINGCLEAR:
        {
            switch_channel_set_variable_name_printf(channel, "false", "zrtp_secure_media_confirmed_%s", type);
            rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_SEND] = 0;
            rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_RECV] = 0;
            rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_SEND] = 0;
            rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_RECV] = 0;
            rtp_session->zrtp_mitm_tries = 0;
        }
        break;

    case ZRTP_EVENT_NO_ZRTP:
        {
            switch_channel_set_variable_name_printf(channel, "false", "zrtp_secure_media_confirmed_%s", type);
        }
        break;

    default:
        break;
    }
}

static void zrtp_logger(int level, const char *data, int len, int offset)
{
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s", data);
}
#endif

SWITCH_DECLARE(void) switch_rtp_init(switch_memory_pool_t *pool)
{
#ifdef ENABLE_ZRTP
    const char *zid_string = switch_core_get_variable_pdup("switch_serial", pool);
    const char *zrtp_enabled = switch_core_get_variable_pdup("zrtp_enabled", pool);
    zrtp_config_t zrtp_config;
    char zrtp_cache_path[256] = "";
    zrtp_on = zrtp_enabled ? switch_true(zrtp_enabled) : 0;
#endif
    if (global_init) {
        return;
    }
    switch_core_hash_init(&alloc_hash);
#ifdef ENABLE_ZRTP
    if (zrtp_on) {
        uint32_t cache_len;
        zrtp_config_defaults(&zrtp_config);
        strcpy(zrtp_config.client_id, "FreeSWITCH");
        zrtp_config.is_mitm = 1;
        zrtp_config.lic_mode = ZRTP_LICENSE_MODE_ACTIVE;
        switch_snprintf(zrtp_cache_path, sizeof(zrtp_cache_path), "%s%szrtp.dat", SWITCH_GLOBAL_dirs.db_dir, SWITCH_PATH_SEPARATOR);
        cache_len=(uint32_t)strlen(zrtp_cache_path);
        ZSTR_SET_EMPTY(zrtp_config.def_cache_path);
        zrtp_config.def_cache_path.length = cache_len > zrtp_config.def_cache_path.max_length ? zrtp_config.def_cache_path.max_length : (uint16_t)cache_len;
        strncpy(zrtp_config.def_cache_path.buffer, zrtp_cache_path, zrtp_config.def_cache_path.max_length);
        zrtp_config.cb.event_cb.on_zrtp_protocol_event = (void (*)(zrtp_stream_t*,zrtp_protocol_event_t))zrtp_event_callback;
        zrtp_config.cb.misc_cb.on_send_packet = zrtp_send_rtp_callback;
        zrtp_config.cb.event_cb.on_zrtp_security_event = (void (*)(zrtp_stream_t*,zrtp_security_event_t))zrtp_event_callback;
        zrtp_log_set_log_engine((zrtp_log_engine *) zrtp_logger);
        zrtp_log_set_level(4);
        if (zrtp_status_ok == zrtp_init(&zrtp_config, &zrtp_global)) {
            memcpy(zid, zid_string, 12);
            switch_scheduler_add_task(switch_epoch_time_now(NULL) + 900, zrtp_cache_save_callback, "zrtp_cache_save", "core", 0, NULL,
                                      SSHF_NONE | SSHF_NO_DEL);
        } else {
            switch_core_set_variable("zrtp_enabled", NULL);
            zrtp_on = 0;
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "ZRTP init failed!\n");
        }
    }
#endif
#ifdef ENABLE_SRTP
    srtp_init();
#endif
    switch_mutex_init(&port_lock, SWITCH_MUTEX_NESTED, pool);
    global_init = 1;
}

static uint8_t get_next_write_ts(switch_rtp_t *rtp_session, uint32_t timestamp)
{
    uint8_t m = 0;

    if (rtp_session->rtp_bugs & RTP_BUG_SEND_LINEAR_TIMESTAMPS) {
        rtp_session->ts += rtp_session->samples_per_interval;
        if (rtp_session->ts <= rtp_session->last_write_ts && rtp_session->ts > 0) {
            rtp_session->ts = rtp_session->last_write_ts + rtp_session->samples_per_interval;
        }
    } else if (timestamp) {
        rtp_session->ts = (uint32_t) timestamp;
        /* Send marker bit if timestamp is lower/same as before (resetted/new timer) */
        if (rtp_session->ts <= rtp_session->last_write_ts && !(rtp_session->rtp_bugs & RTP_BUG_NEVER_SEND_MARKER)) {
            m++;
        }
    } else if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER)) {
        rtp_session->ts = rtp_session->timer.samplecount * rtp_session->timestamp_multiplier;

        if (rtp_session->ts <= rtp_session->last_write_ts && rtp_session->ts > 0) {
            rtp_session->ts = rtp_session->last_write_ts + rtp_session->samples_per_interval;
        }
    } else {
        rtp_session->ts += rtp_session->samples_per_interval;
        if (rtp_session->ts <= rtp_session->last_write_ts && rtp_session->ts > 0) {
            rtp_session->ts = rtp_session->last_write_ts + rtp_session->samples_per_interval;
        }
    }

    return m;
}

static switch_status_t rtcp_write(switch_rtp_t *rtp_session, switch_size_t rtcp_bytes)
{
    switch_status_t ret = SWITCH_STATUS_SUCCESS;

#ifdef ENABLE_SRTP
    if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_SECURE_SEND)) {
        int sbytes = (int) rtcp_bytes;
        int stat = srtp_protect_rtcp(rtp_session->send_ctx[rtp_session->srtp_idx_rtcp], &rtp_session->rtcp_send_msg.header, &sbytes);
        if (stat) {
            switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error: SRTP RTCP protection failed with code %d\n", stat);
        }
        rtcp_bytes = sbytes;
    }
#endif

#ifdef ENABLE_ZRTP
    /* ZRTP Send */
    if (zrtp_on && !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_PROXY_MEDIA)) {
        unsigned int sbytes = (int) rtcp_bytes;
        zrtp_status_t stat = zrtp_status_fail;

        stat = zrtp_process_rtcp(rtp_session->zrtp_stream, (void *) &rtp_session->rtcp_send_msg, &sbytes);

        switch (stat) {
            case zrtp_status_ok:
                break;
            case zrtp_status_drop:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection drop with code %d\n", stat);
                ret = (int)rtcp_bytes;
                goto end;
                break;
            case zrtp_status_fail:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection fail with code %d\n", stat);
                break;
            default:
                break;
        }

        rtcp_bytes = sbytes;
    }
#endif

    if ((ret = rtcp_sendto(rtp_session, rtp_session->rtcp_sock_output, rtp_session->rtcp_remote_addr, 0,
                (void *)&rtp_session->rtcp_send_msg, &rtcp_bytes)) != SWITCH_STATUS_SUCCESS) {
        switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,"RTCP packet not written\n");
    }

    return ret;
}

#define NUM_ARRAY_ELEMS(a) (sizeof(a) / sizeof(a[0]))
#define STRUCT_ELEM_OFFSET(s, e) (long) (&((s *) 0)->e)

static void send_fir(switch_rtp_t *rtp_session)
{

    if (!rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] && rtp_session->ice.ice_user) {
        return;
    }

    if (rtp_session->remote_ssrc == 0) {
        rtp_session->remote_ssrc = rtp_session->stats.rtcp.peer_ssrc;
    }

    if (rtp_session->remote_ssrc == 0) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Peer ssrc not known yet for FIR\n");
        return;
    }

    if (rtp_session->rtcp_sock_output && rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP]) {
        rtcp_fir_t *fir = (rtcp_fir_t *) rtp_session->rtcp_ext_send_msg.body;
        switch_size_t rtcp_bytes;

        rtp_session->rtcp_ext_send_msg.header.version = 2;
        rtp_session->rtcp_ext_send_msg.header.p = 0;
        rtp_session->rtcp_ext_send_msg.header.fmt = 4;
        rtp_session->rtcp_ext_send_msg.header.pt = 206;

        rtp_session->rtcp_ext_send_msg.header.send_ssrc = htonl(rtp_session->ssrc);
        rtp_session->rtcp_ext_send_msg.header.recv_ssrc = 0;//htonl(rtp_session->stats.rtcp.peer_ssrc);

        //fir->ssrc = htonl(rtp_session->stats.rtcp.peer_ssrc);
        fir->ssrc = htonl(rtp_session->remote_ssrc);
        fir->seq = ++rtp_session->fir_seq;
        fir->r1 = fir->r2 = fir->r3 = 0;

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1, "Sending RTCP FIR %d\n", rtp_session->fir_seq);

        rtcp_bytes = sizeof(switch_rtcp_ext_hdr_t) + sizeof(rtcp_fir_t);
        rtp_session->rtcp_ext_send_msg.header.length = htons((u_short)(rtcp_bytes / 4) - 1);


#ifdef ENABLE_SRTP
        if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND]) {
            int sbytes = (int) rtcp_bytes;
            int stat = srtp_protect_rtcp(rtp_session->send_ctx[rtp_session->srtp_idx_rtcp], &rtp_session->rtcp_ext_send_msg.header, &sbytes);

            if (stat) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: SRTP RTCP protection failed with code %d\n", stat);
                goto end;
            } else {
                rtcp_bytes = sbytes;
            }

        }
#endif

#ifdef ENABLE_ZRTP
        /* ZRTP Send */
        if (zrtp_on && !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA]) {
            unsigned int sbytes = (int) rtcp_bytes;
            zrtp_status_t stat = zrtp_status_fail;

            stat = zrtp_process_rtcp(rtp_session->zrtp_stream, (void *) &rtp_session->rtcp_ext_send_msg, &sbytes);

            switch (stat) {
            case zrtp_status_ok:
                break;
            case zrtp_status_drop:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection drop with code %d\n", stat);
                goto end;
                break;
            case zrtp_status_fail:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection fail with code %d\n", stat);
                break;
            default:
                break;
            }

            rtcp_bytes = sbytes;
        }
#endif

#ifdef DEBUG_EXTRA
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_CRIT, "%s SEND %s RTCP %ld\n",
                          rtp_session_name(rtp_session),
                          rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] ? "video" : "audio", rtcp_bytes);
#endif
        if (rtp_sendto(rtp_session, rtp_session->rtcp_sock_output, rtp_session->rtcp_remote_addr, 0, (void *)&rtp_session->rtcp_ext_send_msg, &rtcp_bytes ) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG,"RTCP packet not written\n");
        } else {
            rtp_session->stats.inbound.period_packet_count = 0;
        }
    }

#ifdef ENABLE_SRTP
 end:
#endif

    return;
}



static void send_pli(switch_rtp_t *rtp_session)
{

    if (!rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] && rtp_session->ice.ice_user) {
        return;
    }

    if (rtp_session->rtcp_sock_output && rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP]) {
        switch_size_t rtcp_bytes;

        rtp_session->rtcp_ext_send_msg.header.version = 2;
        rtp_session->rtcp_ext_send_msg.header.p = 0;
        rtp_session->rtcp_ext_send_msg.header.fmt = 1;
        rtp_session->rtcp_ext_send_msg.header.pt = 206;

        rtp_session->rtcp_ext_send_msg.header.send_ssrc = htonl(rtp_session->ssrc);
        rtp_session->rtcp_ext_send_msg.header.recv_ssrc = 0;

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1, "Sending RTCP PLI\n");

        rtcp_bytes = sizeof(switch_rtcp_ext_hdr_t);
        rtp_session->rtcp_ext_send_msg.header.length = htons((u_short)(rtcp_bytes / 4) - 1);


#ifdef ENABLE_SRTP
        if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND]) {
            int sbytes = (int) rtcp_bytes;
            int stat = srtp_protect_rtcp(rtp_session->send_ctx[rtp_session->srtp_idx_rtcp], &rtp_session->rtcp_ext_send_msg.header, &sbytes);

            if (stat) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: SRTP RTCP protection failed with code %d\n", stat);
                goto end;
            } else {
                rtcp_bytes = sbytes;
            }

        }
#endif

#ifdef ENABLE_ZRTP
        /* ZRTP Send */
        if (zrtp_on && !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA]) {
            unsigned int sbytes = (int) rtcp_bytes;
            zrtp_status_t stat = zrtp_status_fail;

            stat = zrtp_process_rtcp(rtp_session->zrtp_stream, (void *) &rtp_session->rtcp_ext_send_msg, &sbytes);

            switch (stat) {
            case zrtp_status_ok:
                break;
            case zrtp_status_drop:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection drop with code %d\n", stat);
                goto end;
                break;
            case zrtp_status_fail:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection fail with code %d\n", stat);
                break;
            default:
                break;
            }

            rtcp_bytes = sbytes;
        }
#endif

#ifdef DEBUG_EXTRA
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_CRIT, "%s SEND %s RTCP %ld\n",
                          rtp_session_name(rtp_session),
                          rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] ? "video" : "audio", rtcp_bytes);
#endif
        
        if (rtp_sendto(rtp_session, rtp_session->rtcp_sock_output, rtp_session->rtcp_remote_addr, 0, (void *)&rtp_session->rtcp_ext_send_msg, &rtcp_bytes ) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG,"RTCP packet not written\n");
        } else {
            rtp_session->stats.inbound.period_packet_count = 0;
        }
    }

#ifdef ENABLE_SRTP
 end:
#endif
    return;
}

static void do_mos(switch_rtp_t *rtp_session, int force) {

    if ((switch_size_t)rtp_session->stats.inbound.recved < rtp_session->stats.inbound.flaws) {
        rtp_session->stats.inbound.flaws = 0;
    }

    if (rtp_session->stats.inbound.recved > 0 &&
        rtp_session->stats.inbound.flaws && (force || rtp_session->stats.inbound.last_flaw != rtp_session->stats.inbound.flaws)) {
        int R;
        double prev_mos;

        if (rtp_session->consecutive_flaws++) {
            int diff, penalty;

            diff = (rtp_session->stats.inbound.flaws - rtp_session->stats.inbound.last_flaw);

            if (diff < 1) diff = 1;

            penalty = diff * 2;

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1, "%s %s %d consecutive flaws, adding %d flaw penalty\n",
                              rtp_session_name(rtp_session), rtp_type(rtp_session),
                              rtp_session->consecutive_flaws, penalty);

            rtp_session->stats.inbound.flaws += penalty;
        }

        R = (int)((double)((double)(rtp_session->stats.inbound.recved - rtp_session->stats.inbound.flaws) / (double)rtp_session->stats.inbound.recved) * 100.0);

        if (R < 0 || R > 100) R = 100;

        prev_mos = rtp_session->stats.inbound.mos;
        rtp_session->stats.inbound.R = R;
        rtp_session->stats.inbound.mos = 1 + (0.035) * R + (.000007) * R * (R-60) * (100-R);
        rtp_session->stats.inbound.last_flaw = rtp_session->stats.inbound.flaws;
        
        if (abs(prev_mos - rtp_session->stats.inbound.mos) > 0.2) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s %s stat %0.2f %ld/%d flaws: %ld mos: %0.2f v: %0.2f %0.2f/%0.2f\n",
                              rtp_session_name(rtp_session),
                              rtp_type(rtp_session),
                              rtp_session->stats.inbound.R,
                              (long int)(rtp_session->stats.inbound.recved - rtp_session->stats.inbound.flaws), rtp_session->stats.inbound.recved,
                              (long int)rtp_session->stats.inbound.flaws,
                              rtp_session->stats.inbound.mos,
                              rtp_session->stats.inbound.variance,
                              rtp_session->stats.inbound.min_variance,
                              rtp_session->stats.inbound.max_variance
                              );
        }
        
    } else {
        rtp_session->consecutive_flaws = 0;
    }
}

void burstr_calculate ( int loss[], int received, double *burstr, double *lossr )
{
    int lost = 0;
    int bursts = 0;
    int i;

    for ( i = 0; i < LOST_BURST_ANALYZE; i++ ) {
        lost += i * loss[i];
        bursts += loss[i];
    }
    if (received > 0 && bursts > 0) {
        *burstr = (double)((double)lost / (double)bursts) / (double)(1.0 / ( 1.0 - (double)lost / (double)received ));
        if (*burstr < 0) {
            *burstr = - *burstr;
        }
    } else {
        *burstr = 0;
    }
    if (received > 0) {
        *lossr = (double)((double)lost / (double)received);
    } else {
        *lossr = 0;
    }
}

static void reset_jitter_seq(switch_rtp_t *rtp_session)
{
    rtp_session->stats.inbound.last_proc_time = 0;
    rtp_session->stats.inbound.last_processed_seq = 0;
    rtp_session->jitter_lead = 0;
    rtp_session->consecutive_flaws = 0;
    rtp_session->stats.inbound.last_flaw = 0;
}

static void check_jitter(switch_rtp_t *rtp_session)
{
    switch_time_t current_time;
    int64_t diff_time = 0, cur_diff = 0;
    int seq;

    current_time = switch_micro_time_now() / 1000;

    if (rtp_session->flags[SWITCH_RTP_FLAG_PAUSE] || rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON] || rtp_session->dtmf_data.in_digit_ts) {
        reset_jitter_seq(rtp_session);
        return;
    }

    if (++rtp_session->jitter_lead < JITTER_LEAD_FRAMES || !rtp_session->stats.inbound.last_proc_time) {
        rtp_session->stats.inbound.last_proc_time = current_time;
        return;
    }

    diff_time = (current_time - rtp_session->stats.inbound.last_proc_time);
    seq = (int)(uint16_t) ntohs((uint16_t) rtp_session->recv_msg.header.seq);

    /* Burst and Packet Loss */
    rtp_session->stats.inbound.recved++;

    if (rtp_session->stats.inbound.last_processed_seq > 0 && seq > (int)(rtp_session->stats.inbound.last_processed_seq + 1)) {
        int lost = (seq - rtp_session->stats.inbound.last_processed_seq - 1);

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1, "%s Got: %s seq %d but expected: %d lost: %d\n",
                          rtp_session_name(rtp_session),
                          rtp_type(rtp_session),
                          seq,
                          (rtp_session->stats.inbound.last_processed_seq + 1), lost);
        rtp_session->stats.inbound.last_loss++;

        if (rtp_session->stats.inbound.last_loss > 0 && rtp_session->stats.inbound.last_loss < LOST_BURST_CAPTURE) {
            rtp_session->stats.inbound.loss[rtp_session->stats.inbound.last_loss] += lost;
        }

        rtp_session->stats.inbound.flaws += lost;

    } else {
        rtp_session->stats.inbound.last_loss = 0;
    }

    rtp_session->stats.inbound.last_processed_seq = seq;

    /* Burst and Packet Loss */

    if (current_time > rtp_session->next_stat_check_time) {
        rtp_session->next_stat_check_time = current_time + 5000;
        burstr_calculate(rtp_session->stats.inbound.loss, rtp_session->stats.inbound.recved,
                         &(rtp_session->stats.inbound.burstrate), &(rtp_session->stats.inbound.lossrate));
        do_mos(rtp_session, SWITCH_TRUE);
    } else {
        do_mos(rtp_session, SWITCH_FALSE);
    }


    if ( diff_time < 0 ) {
        diff_time = -diff_time;
    }

    rtp_session->stats.inbound.jitter_n++;
    rtp_session->stats.inbound.jitter_add += diff_time;

    cur_diff = (int64_t)(diff_time - rtp_session->stats.inbound.mean_interval);

    rtp_session->stats.inbound.jitter_addsq += (cur_diff * cur_diff);
    rtp_session->stats.inbound.last_proc_time = current_time;

    if (rtp_session->stats.inbound.jitter_n > 0) {
        double ipdv;

        rtp_session->stats.inbound.mean_interval = (double)rtp_session->stats.inbound.jitter_add / (double)rtp_session->stats.inbound.jitter_n;

        if (!rtp_session->old_mean) {
            rtp_session->old_mean = rtp_session->stats.inbound.mean_interval;
        }

        rtp_session->stats.inbound.variance = (double)rtp_session->stats.inbound.jitter_addsq / (double)rtp_session->stats.inbound.jitter_n;

        //printf("CHECK %d +%ld +%ld %f %f\n", rtp_session->timer.samplecount, diff_time, (diff_time * diff_time), rtp_session->stats.inbound.mean_interval, rtp_session->stats.inbound.variance);

        ipdv = rtp_session->old_mean - rtp_session->stats.inbound.mean_interval;

        if ( ipdv > IPDV_THRESHOLD ) { /* It shows Increasing Delays */
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1, "Calculated Instantaneous Packet Delay Variation: %s packet %lf\n",
                              rtp_type(rtp_session), ipdv);
        }

        if ( rtp_session->stats.inbound.variance < rtp_session->stats.inbound.min_variance || rtp_session->stats.inbound.min_variance == 0 ) {
            rtp_session->stats.inbound.min_variance = rtp_session->stats.inbound.variance;
        }

        if ( rtp_session->stats.inbound.variance > rtp_session->stats.inbound.max_variance ) {
            rtp_session->stats.inbound.max_variance = rtp_session->stats.inbound.variance;
        }

        rtp_session->old_mean = rtp_session->stats.inbound.mean_interval;
    }
}


static int add_rx_congestion(switch_rtp_t *rtp_session, void *body, switch_rtcp_hdr_t *pHeader)
{
    switch_rtcp_app_rx_congestion_t *rx_congestion = (switch_rtcp_app_rx_congestion_t *) body;
    int i, pad, nbytes = sizeof(switch_rtcp_app_rx_congestion_t);

    pHeader->version = 2;
    pHeader->p = 0;
    pHeader->count = 1;

    pHeader->type = 204;

    rx_congestion->ssrc = htonl(rtp_session->ssrc);
    rx_congestion->name = htonl(0x66757a72);

    rx_congestion->version = 1;

    rx_congestion->jitter = htons(rtp_session->stats.last_jitter);
    rx_congestion->degraded = htons(rtp_session->stats.rx_congestion_state);

    rx_congestion->active = rtp_session->active;
    rx_congestion->muted = rtp_session->muted;
    rx_congestion->cn = switch_core_session_get_cn_state(rtp_session->session);

    if (rtp_session->stats.last_lost_percent > 0) {
        rx_congestion->lost_percent = htons(rtp_session->stats.last_lost_percent);
    } else {
        rx_congestion->lost_percent = 0;
    }

#if 0
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                      "RTCP app specific lost=%u%% jitter=%ums\n",
                      rtp_session->stats.last_lost_percent, rtp_session->stats.last_jitter);
#endif

    for (i = 0; i < APP_RX_NUM_STATS; i++) {
        int idx = rtp_session->stats.recv_rate_history_idx - (i+1);
        idx = (idx < 0) ? idx + RTP_STATS_RATE_HISTORY : idx;
        rx_congestion->rx[i] = htons(rtp_session->stats.recv_rate_history[idx]);
    }

    /*Make sure the total length is aligned with 32-bit boundary; Pad it with NULL bytes*/
    pad = nbytes % 4;
    if (pad) {
        pad = 4 - pad;
        memset(((char *) body) + nbytes, 0, pad);
        nbytes += pad;
    }

    pHeader->length = htons((u_short)(nbytes / 4));

    return nbytes + 4;
}

static int add_cname(switch_rtp_t *rtp_session, void *body, switch_rtcp_hdr_t *pHeader)
{
    struct switch_rtcp_s_desc_trunk *cname_item = (struct switch_rtcp_s_desc_trunk *)body;
    char bufa[40];
    int nbytes, pad;
    const char *str_cname;

    pHeader->version = 0x02;
    pHeader->p = 0;
    pHeader->count = 1;
    pHeader->type = 202;

    cname_item->ssrc = htonl(rtp_session->ssrc);
    cname_item->cname = 0x1;

    memset(bufa, 0, 40);
    str_cname = switch_get_addr(bufa, sizeof(bufa), rtp_session->rtcp_local_addr);
    cname_item->length = (uint8_t)strlen(str_cname);
    memcpy ((char*)cname_item->text, str_cname, strlen(str_cname));

    // nbytes = sizeof(struct switch_rtcp_s_desc_trunk)+cname_item->length;
    nbytes = 6 + cname_item->length + 1;

    /*Make sure the total length is aligned with 32-bit boundary; Pad it with NULL bytes*/
    pad = nbytes % 4;
    if (pad) {
        pad = 4 - pad;
        memset(((char *) body) + nbytes, 0, pad);
        nbytes += pad;
    }

    pHeader->length = htons((u_short)(nbytes / 4));

    return nbytes;
}

#if 0
static void switch_rtp_reset_expected_packets(switch_rtp_t *rtp_session)
{
    int exp_total;

    if (!rtp_session) { return; }

    if (rtp_session->seq_rollover) {
        exp_total = (rtp_session->seq_rollover - 1) * ((int) 0xffff + 1) +
            (0xffff - rtp_session->base_seq) + rtp_session->last_seq + 2;
    } else {
        exp_total = (rtp_session->last_seq == rtp_session->base_seq) ? 0 :
            rtp_session->last_seq - rtp_session->base_seq + 1;
    }
    rtp_session->total_received = exp_total;
}
#endif

static int check_rtcp_and_ice(switch_rtp_t *rtp_session)
{
    int ret = 0;
    switch_time_t now = switch_time_now();

    if (rtp_session->fir_countdown) {
        //if (rtp_session->fir_countdown == FIR_COUNTDOWN) {
        //  do_flush(rtp_session, SWITCH_TRUE);
        //}

        if (rtp_session->fir_countdown == FIR_COUNTDOWN || (rtp_session->fir_countdown == FIR_COUNTDOWN / 2) || rtp_session->fir_countdown == 1) {
            if (rtp_session->flags[SWITCH_RTP_FLAG_PLI]) {
                send_pli(rtp_session);
            } else {
                send_fir(rtp_session);
            }
        }

        rtp_session->fir_countdown--;
    }

    /* Send an RTCP packet at least every 20 seconds! */
    if ((now - rtp_session->last_rtcp_send) > (20*1000*1000) && rtp_session->send_rtcp == 0) {
        /* too long since rtcp ... send! */
        rtp_session->send_rtcp = SWITCH_RTCP_NORMAL;
    }

    if (rtp_session->rtcp_sock_output &&
        switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_ENABLE_RTCP) &&
        !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_RTCP_PASSTHRU)
        && rtp_session->send_rtcp) {

        switch_size_t rtcp_bytes = 0;
        switch_bool_t reset_period_data = SWITCH_TRUE;

        if (rtp_session->send_rtcp & SWITCH_RTCP_NORMAL) {
            struct switch_rtcp_report *rep = NULL;
            int recv_interval, exp_interval, cycles, exp_total, nbytes;
            switch_time_t delay_since_last;
            int16_t dlsr_msw, dlsr_lsw;
            switch_rtcp_hdr_t *pHeader = &rtp_session->rtcp_send_msg.header;
            switch_rtcp_hdr_t *pHeaderRXC;

            pHeader->version = 2;
            pHeader->p = 0;
            pHeader->count = 1;

            memset(rtp_session->rtcp_send_msg.body, 0, sizeof(rtp_session->rtcp_send_msg.body));

            if (!rtp_session->stats.outbound.period_packet_count) {
                struct switch_rtcp_receiverinfo *rr = (struct switch_rtcp_receiverinfo *) rtp_session->rtcp_send_msg.body;

                pHeader->type = 201;

                rr->ssrc = htonl(rtp_session->ssrc);
                rep = &rr->reports;
                rtcp_bytes = sizeof(switch_rtcp_hdr_t) + STRUCT_ELEM_OFFSET(struct switch_rtcp_receiverinfo, reports.items);
            } else {
                struct switch_rtcp_senderinfo *sr = (struct switch_rtcp_senderinfo*) rtp_session->rtcp_send_msg.body;
                switch_time_t when;
                pHeader->type = 200;

                sr->ssrc = htonl(rtp_session->ssrc);

                if (rtp_session->send_time) {
                    when = rtp_session->send_time;
                } else {
                    when = switch_micro_time_now();
                }

                sr->ntp_msw = htonl((u_long)(when / 1000000 + 2208988800UL));
                /*
                 * sr->ntp_lsw = htonl((u_long)(when % 1000000 * ((UINT_MAX * 1.0)/ 1000000.0)));
                 */
                sr->ntp_lsw = htonl((u_long)(rtp_session->send_time % 1000000 * 4294.967296));
                sr->ts = htonl(rtp_session->last_write_ts);
                sr->pc = htonl(rtp_session->stats.outbound.packet_count);
                sr->oc = htonl((rtp_session->stats.outbound.raw_bytes - rtp_session->stats.outbound.packet_count * sizeof(srtp_hdr_t)));
                rtp_session->stats.rtcp.last_sr_time = (int64_t) when;
                rep = &sr->reports;
                rtcp_bytes = sizeof(switch_rtcp_hdr_t) + STRUCT_ELEM_OFFSET(struct switch_rtcp_senderinfo, reports.items);
            }

            /* TBD need to put more accurate stats here. */

            cycles = rtp_session->seq_rollover - rtp_session->stats.rtcp.last_seq_rollover;
            rtp_session->stats.rtcp.last_seq_rollover = rtp_session->seq_rollover;
            if (cycles) {
                exp_interval = (cycles - 1) * ((int) 0xffff + 1) +
                    (0xffff - rtp_session->stats.rtcp.last_expected) +
                    rtp_session->last_seq + 2;
            } else {
                exp_interval = rtp_session->last_seq - rtp_session->stats.rtcp.last_expected + 1;
            }
            rtp_session->stats.rtcp.last_expected = rtp_session->last_seq;

            recv_interval = rtp_session->total_received - rtp_session->stats.rtcp.last_received;
            rtp_session->stats.rtcp.last_received = rtp_session->total_received;

            if (rtp_session->seq_rollover) {
                exp_total = (rtp_session->seq_rollover - 1) * ((int) 0xffff + 1) +
                    (0xffff - rtp_session->base_seq) + rtp_session->last_seq + 2;
            } else {
                exp_total = (rtp_session->last_seq == rtp_session->base_seq) ? 0 :
                    rtp_session->last_seq - rtp_session->base_seq + 1;
            }
            delay_since_last = switch_micro_time_now() - rtp_session->stats.rtcp.last_rr_time;
            dlsr_msw = delay_since_last / 1000000; //in sec
            dlsr_lsw = (delay_since_last - (dlsr_msw * 1000000ul)) / 1000; //in msec

            rep->sr_source.ssrc1 = htonl(rtp_session->stats.rtcp.peer_ssrc);
            if (exp_interval > 0)
                rep->sr_source.fraction_lost = ((exp_interval - recv_interval) << 8) / exp_interval;
            else
                rep->sr_source.fraction_lost = 0;
            rep->sr_source.cumulative_lost = htonl(exp_total - rtp_session->total_received);
            rep->sr_source.hi_seq_recieved = htonl(rtp_session->last_seq + (rtp_session->seq_rollover << 16));
            rep->sr_source.interarrival_jitter = htonl (rtp_session->stats.rtcp.jitter);
            rep->sr_source.lsr = (rtp_session->stats.rtcp.peer_ntp_msw << 16) | (rtp_session->stats.rtcp.peer_ntp_lsw >> 16);
            rep->sr_source.lsr = htonl (rep->sr_source.lsr);
            rep->sr_source.lsr_delay = (dlsr_msw << 16) | ((uint16_t) ((dlsr_lsw * 65536u) / 1000));
            rep->sr_source.lsr_delay = htonl (rep->sr_source.lsr_delay);

            pHeader->length = htons((sizeof(struct switch_rtcp_senderinfo)
                                     - sizeof(struct switch_rtcp_report)
                                     + sizeof(struct switch_rtcp_source))/4);

            if (switch_core_session_get_cn_state(rtp_session->session)) {
                rtp_session->total_received = exp_total;
                rtp_session->stats.cumulative_lost = 0;
                rep->sr_source.fraction_lost = 0;
            } else {
                rtp_session->stats.cumulative_lost = exp_total - rtp_session->total_received;
            }

            /* Source Description */
            nbytes = add_cname(rtp_session, (void *)((char *)&rep->sr_desc_head + sizeof(switch_rtcp_hdr_t)), &rep->sr_desc_head);

            rtcp_bytes += (nbytes);

            pHeaderRXC = (switch_rtcp_hdr_t *) (((char *) pHeader) + rtcp_bytes);

            if (rtp_session->stats.time > RTP_STATS_RATE_HISTORY) {
                nbytes = add_rx_congestion(rtp_session, (void *)((char *)pHeaderRXC + sizeof(switch_rtcp_hdr_t)), pHeaderRXC);
                rtcp_bytes += (nbytes);
            }

            if (rtcp_write(rtp_session, rtcp_bytes) != SWITCH_STATUS_SUCCESS) {
                reset_period_data = SWITCH_FALSE;
            } else {
                rtp_session->last_rtcp_send = now;
            }
        } else if (rtp_session->send_rtcp & SWITCH_RTCP_RX_CONGESTION && rtp_session->stats.time > RTP_STATS_RATE_HISTORY) {
            memset(rtp_session->rtcp_send_msg.body, 0, sizeof(rtp_session->rtcp_send_msg.body));

            rtcp_bytes = add_rx_congestion(rtp_session, rtp_session->rtcp_send_msg.body, &rtp_session->rtcp_send_msg.header);

            if (rtcp_write(rtp_session, rtcp_bytes) != SWITCH_STATUS_SUCCESS) {
                reset_period_data = SWITCH_FALSE;
            } else {
                rtp_session->last_rtcp_send = now;
            }
        }

        if (reset_period_data == SWITCH_TRUE) {
            rtp_session->stats.inbound.period_packet_count = 0;
            rtp_session->stats.outbound.period_packet_count = 0;

            rtp_session->been_active_talker = 0;
            memset(rtp_session->stats.jb_period_chop_events, 0, sizeof(rtp_session->stats.jb_period_chop_events));
        }

        if (rtp_session->rtcp_ice.ice_user) {
            ice_out(rtp_session, &rtp_session->rtcp_ice);
        }
    }

    if (rtp_session->ice.ice_user) {
        if (ice_out(rtp_session, &rtp_session->ice) == SWITCH_STATUS_GENERR) {
            ret = -1;
            goto end;
        }
    }

    if (!rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
        if (rtp_session->rtcp_ice.ice_user) {
            if (ice_out(rtp_session, &rtp_session->rtcp_ice) == SWITCH_STATUS_GENERR) {
                ret = -1;
                goto end;
            }
        }
    }

 end:
    rtp_session->send_rtcp = 0;
    return ret;
}

SWITCH_DECLARE(void) switch_rtp_ping(switch_rtp_t *rtp_session)
{
    check_rtcp_and_ice(rtp_session);
}

SWITCH_DECLARE(void) switch_rtp_get_random(void *buf, uint32_t len)
{
#ifdef ENABLE_SRTP
    crypto_get_random(buf, len);
#else
    switch_stun_random_string(buf, len, NULL);
#endif
}


SWITCH_DECLARE(void) switch_rtp_shutdown(void)
{
    switch_core_port_allocator_t *alloc = NULL;
    switch_hash_index_t *hi;
    const void *var;
    void *val;

    if (!global_init) {
        return;
    }

    switch_mutex_lock(port_lock);

    for (hi = switch_core_hash_first(alloc_hash); hi; hi = switch_core_hash_next(&hi)) {
        switch_core_hash_this(hi, &var, NULL, &val);
        if ((alloc = (switch_core_port_allocator_t *) val)) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Destroy port allocator for %s\n", (char *) var);
            switch_core_port_allocator_destroy(&alloc);
        }
    }

    switch_core_hash_destroy(&alloc_hash);
    switch_mutex_unlock(port_lock);

#ifdef ENABLE_ZRTP
    if (zrtp_on) {
        zrtp_status_t status = zrtp_status_ok;

        status = zrtp_def_cache_store(zrtp_global);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Saving ZRTP cache: %s\n", zrtp_status_ok == status ? "OK" : "FAIL");
        zrtp_down(zrtp_global);
    }
#endif
#ifdef ENABLE_SRTP
    crypto_kernel_shutdown();
#endif

}

SWITCH_DECLARE(switch_port_t) switch_rtp_set_start_port(switch_port_t port)
{
    if (port) {
        if (port_lock) {
            switch_mutex_lock(port_lock);
        }
        START_PORT = port;
        if (port_lock) {
            switch_mutex_unlock(port_lock);
        }
    }
    return START_PORT;
}

SWITCH_DECLARE(switch_port_t) switch_rtp_set_end_port(switch_port_t port)
{
    if (port) {
        if (port_lock) {
            switch_mutex_lock(port_lock);
        }
        END_PORT = port;
        if (port_lock) {
            switch_mutex_unlock(port_lock);
        }
    }
    return END_PORT;
}

SWITCH_DECLARE(void) switch_rtp_release_port(const char *ip, switch_port_t port)
{
    switch_core_port_allocator_t *alloc = NULL;

    if (!ip || !port) {
        return;
    }

    switch_mutex_lock(port_lock);
    if ((alloc = switch_core_hash_find(alloc_hash, ip))) {
        switch_core_port_allocator_free_port(alloc, port);
    }
    switch_mutex_unlock(port_lock);

}

#define MAX_TRIES_TO_ALLOCATE_PORT 100

SWITCH_DECLARE(switch_port_t) switch_rtp_request_port(const char *ip)
{
    switch_port_t port = 0;
    switch_core_port_allocator_t *alloc = NULL;

    switch_mutex_lock(port_lock);

    alloc = switch_core_hash_find(alloc_hash, ip);
    if (!alloc) {
        if (switch_core_port_allocator_new(ip, START_PORT, END_PORT, SPF_EVEN, &alloc) != SWITCH_STATUS_SUCCESS) {
            abort();
        }

        switch_core_hash_insert(alloc_hash, ip, alloc);
    }

    for (int i = 0; i < MAX_TRIES_TO_ALLOCATE_PORT; i++) {
        if (switch_core_port_allocator_request_port(alloc, &port) != SWITCH_STATUS_SUCCESS) {
            port = 0;
            break;
        }
        if (fuze_udp_port_available(port, ip) == 0 && 
            fuze_udp_port_available(port+1, ip) == 0) {
            /* Reserve the port for 10 seconds */
            if (fuze_reserve_udp_port(10000, port, ip) == 0) {
                if (fuze_reserve_udp_port(10000, port+1, ip) == 0) {
                    break;
                }
                else {
                    /* Failed to reserve RTCP - retry from beginning */
                    fuze_release_udp_port(port);
                }
            }
        }
    }

    switch_mutex_unlock(port_lock);
    return port;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_set_payload_map(switch_rtp_t *rtp_session, payload_map_t **pmap)
{

    if (rtp_session) {
        switch_mutex_lock(rtp_session->flag_mutex);
        rtp_session->pmaps = pmap;
        switch_mutex_unlock(rtp_session->flag_mutex);
        return SWITCH_STATUS_SUCCESS;
    }

    return SWITCH_STATUS_FALSE;
}

SWITCH_DECLARE(void) switch_rtp_intentional_bugs(switch_rtp_t *rtp_session, switch_rtp_bug_flag_t bugs)
{
    rtp_session->rtp_bugs = bugs;

    if ((rtp_session->rtp_bugs & RTP_BUG_START_SEQ_AT_ZERO)) {
        rtp_session->seq = 0;
    }

}


static switch_status_t enable_remote_rtcp_socket(switch_rtp_t *rtp_session, const char **err) {

    switch_status_t status = SWITCH_STATUS_SUCCESS;

    if (rtp_session->remote_rtcp_address_set) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "enable_remote_rtcp_socket called but address already set in fuze transport\n");
        *err = "Warning address already set.";
        return SWITCH_STATUS_SUCCESS;
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP]) {

        if (switch_sockaddr_info_get(&rtp_session->rtcp_remote_addr, rtp_session->eff_remote_host_str, SWITCH_UNSPEC,
                                     rtp_session->remote_rtcp_port, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS || !rtp_session->rtcp_remote_addr) {
            *err = "RTCP Remote Address Error!";
            return SWITCH_STATUS_FALSE;
        } else {
            const char *host;
            char bufa[30];
            host = switch_get_addr(bufa, sizeof(bufa), rtp_session->rtcp_remote_addr);

            if (rtp_session->rtcp_conn) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Setting remote RTCP %s:%d\n", host, rtp_session->remote_rtcp_port);
                if (fuze_transport_connection_set_remote_address(rtp_session->rtcp_conn, host, rtp_session->remote_rtcp_port) < 0) {
                    *err = "Error on setting Remote RTCP.";
                } else {
                    rtp_session->remote_rtcp_address_set = SWITCH_TRUE;
                }
            }
        }

        if (rtp_session->rtcp_sock_input && switch_sockaddr_get_family(rtp_session->rtcp_remote_addr) ==
            switch_sockaddr_get_family(rtp_session->rtcp_local_addr)) {
            rtp_session->rtcp_sock_output = rtp_session->rtcp_sock_input;
        } else {

            if (rtp_session->rtcp_sock_output && rtp_session->rtcp_sock_output != rtp_session->rtcp_sock_input) {
                switch_socket_close(rtp_session->rtcp_sock_output);
            }

            if ((status = switch_socket_create(&rtp_session->rtcp_sock_output,
                                               switch_sockaddr_get_family(rtp_session->rtcp_remote_addr),
                                               SOCK_DGRAM, 0, rtp_session->pool)) != SWITCH_STATUS_SUCCESS) {
                *err = "RTCP Socket Error!";
            }
        }

    } else {
        *err = "RTCP NOT ACTIVE!";
    }

    return status;

}

static switch_status_t enable_local_rtcp_socket(switch_rtp_t *rtp_session, void *tbase, const char **err) {

    const char *host = rtp_session->local_host_str;
    switch_port_t port = rtp_session->local_port;
    switch_socket_t *rtcp_new_sock = NULL, *rtcp_old_sock = NULL;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char bufa[30];

    if (rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP]) {
        if (switch_sockaddr_info_get(&rtp_session->rtcp_local_addr, host, SWITCH_UNSPEC, port+1, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS) {
            *err = "RTCP Local Address Error!";
            goto done;
        }

        if (!tbase) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Enabling RTCP socket using standard transport.\n");
            if (switch_socket_create(&rtcp_new_sock, switch_sockaddr_get_family(rtp_session->rtcp_local_addr), SOCK_DGRAM, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS) {
                *err = "RTCP Socket Error!";
                goto done;
            }

            if (switch_socket_opt_set(rtcp_new_sock, SWITCH_SO_REUSEADDR, 1) != SWITCH_STATUS_SUCCESS) {
                *err = "RTCP Socket Error!";
                goto done;
            }

            if (switch_socket_bind(rtcp_new_sock, rtp_session->rtcp_local_addr) != SWITCH_STATUS_SUCCESS) {
                *err = "RTCP Bind Error!";
                goto done;
            }

            rtcp_old_sock = rtp_session->rtcp_sock_input;
            rtp_session->rtcp_sock_input = rtcp_new_sock;
            rtcp_new_sock = NULL;

            switch_socket_create_pollset(&rtp_session->rtcp_read_pollfd, rtp_session->rtcp_sock_input, SWITCH_POLLIN | SWITCH_POLLERR, rtp_session->pool);
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Enabling RTCP socket using fuze transport.\n");
            if (!(rtp_session->rtcp_conn = fuze_transport_tbase_create_connection(tbase, CONN_UDP, 1, rtp_session->use_webrtc_neteq))) {
                *err = "Error on creating connection.";
                goto done;
            }
            sprintf(rtp_session->rtcp_conn_name, "BRTCP%04x", rtp_session->id);
            fuze_transport_set_connection_name(rtp_session->rtcp_conn, rtp_session->rtcp_conn_name);

            if (fuze_transport_connection_set_local_address(rtp_session->rtcp_conn, host, port+1) < 0) {
                *err = "Error on fuze_transport_connection_set_local_address";
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error on setting local address: %s:%u.\n", host, port);
                goto done;
            }

            if ((switch_status_t) fuze_transport_connection_start(rtp_session->rtcp_conn) != SWITCH_STATUS_SUCCESS) {
                *err = "Erron on fuze_transport_connection_start";
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error while starting fuze transport rtcp %s:%u.\n", host, port);
                goto done;
            } else {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Starting fuze transport for rtcp %s:%u.\n", host, port);
            }

        }

        if (switch_sockaddr_info_get(&rtp_session->rtcp_from_addr, switch_get_addr(bufa, sizeof(bufa), rtp_session->from_addr),
                                             SWITCH_UNSPEC, switch_sockaddr_get_port(rtp_session->from_addr) + 1, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS) {
            *err = "RTCP From Address Error!";
            goto done;
        }


 done:

        if (*err) {

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error allocating rtcp [%s]\n", *err);
            status = SWITCH_STATUS_FALSE;
        }

        if (rtcp_new_sock) {
            switch_socket_close(rtcp_new_sock);
        }

        if (rtcp_old_sock) {
            switch_socket_close(rtcp_old_sock);
        }
    } else {
        status = SWITCH_STATUS_FALSE;
    }

    return status;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_set_local_address(switch_rtp_t *rtp_session, void *tbase,
                                                    const char *host, switch_port_t port, const char **err)
{
    switch_socket_t *new_sock = NULL, *old_sock = NULL;
    switch_status_t status = SWITCH_STATUS_FALSE;
    int j = 0;
#ifndef WIN32
    char o[5] = "TEST", i[5] = "";
    switch_size_t len, ilen = 0;
    int x;
#endif

    if (rtp_session->ready != 1) {
        if (!switch_rtp_ready(rtp_session)) {
            return SWITCH_STATUS_FALSE;
        }

        WRITE_INC(rtp_session);
        READ_INC(rtp_session);

        if (!switch_rtp_ready(rtp_session)) {
            goto done;
        }
    }


    *err = NULL;

    if (zstr(host) || !port) {
        *err = "Address Error";
        goto done;
    }


    rtp_session->local_host_str = switch_core_strdup(rtp_session->pool, host);
    rtp_session->local_port = port;


    if (switch_sockaddr_info_get(&rtp_session->local_addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS) {
        *err = "Local Address Error!";
        goto done;
    }

    if (!tbase) {
        if (rtp_session->sock_input) {
            switch_rtp_kill_socket(rtp_session);
        }

        if (switch_socket_create(&new_sock, switch_sockaddr_get_family(rtp_session->local_addr), SOCK_DGRAM, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS) {
            *err = "Socket Error!";
            goto done;
        }

        if (switch_socket_opt_set(new_sock, SWITCH_SO_REUSEADDR, 1) != SWITCH_STATUS_SUCCESS) {
            *err = "Socket Error!";
            goto done;
        }

    if ((j = atoi(host)) && j > 223 && j < 240) { /* mcast */
        if (switch_mcast_interface(new_sock, rtp_session->local_addr) != SWITCH_STATUS_SUCCESS) {
            *err = "Multicast Socket interface Error";
            goto done;
        }

        if (switch_mcast_join(new_sock, rtp_session->local_addr, NULL, NULL) != SWITCH_STATUS_SUCCESS) {
            *err = "Multicast Error";
            goto done;
        }

        if (rtp_session->session) {
            switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);
            const char *var;

            if ((var = switch_channel_get_variable(channel, "multicast_ttl"))) {
                int ttl = atoi(var);

                if (ttl > 0 && ttl < 256) {
                    if (switch_mcast_hops(new_sock, (uint8_t) ttl) != SWITCH_STATUS_SUCCESS) {
                        *err = "Mutlicast TTL set failed";
                        goto done;
                    }

                }
            }

        }

    }



#ifndef WIN32
    len = sizeof(i);
    switch_socket_opt_set(new_sock, SWITCH_SO_NONBLOCK, TRUE);

        if (switch_socket_opt_set(new_sock, SWITCH_SO_IP_TOS, 0xE0) != SWITCH_STATUS_SUCCESS) {
            switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "ERROR on setting TOS Value.\n");
        }
        
        rtp_sendto(rtp_session, new_sock, rtp_session->local_addr, 0, (void *) o, &len);

        x = 0;
        while (!ilen) {
            switch_status_t status;
            ilen = len;
            status = rtp_recvfrom(rtp_session, rtp_session->from_addr, new_sock, 0, (void *) i, &ilen);

            if (status != SWITCH_STATUS_SUCCESS && status != SWITCH_STATUS_BREAK) {
                break;
            }

            if (++x > 1000) {
                break;
            }
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "This shouldn't be called\n");
            switch_cond_next();
        }
        switch_socket_opt_set(new_sock, SWITCH_SO_NONBLOCK, FALSE);

#endif

        old_sock = rtp_session->sock_input;
        rtp_session->sock_input = new_sock;
        new_sock = NULL;

        if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER) || switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_NOBLOCK)) {
            switch_socket_opt_set(rtp_session->sock_input, SWITCH_SO_NONBLOCK, TRUE);
            switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_NOBLOCK);
        }

        switch_socket_create_pollset(&rtp_session->read_pollfd, rtp_session->sock_input, SWITCH_POLLIN | SWITCH_POLLERR, rtp_session->pool);
    } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Enabling RTP socket using fuze transport.\n");
        if (!(rtp_session->rtp_conn = fuze_transport_tbase_create_connection(tbase, CONN_UDP, 0, rtp_session->use_webrtc_neteq))) {
            *err = "Error on creating connection.";
            goto done;
        }
        sprintf(rtp_session->rtp_conn_name, "BRTP%04x", rtp_session->id);
        fuze_transport_set_connection_name(rtp_session->rtp_conn, rtp_session->rtp_conn_name);

        if (rtp_session->is_ivr == SWITCH_TRUE && !rtp_session->is_bridge) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "session is IVR -> BRIDGE\n");
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s ivr -> bridge (%u) seq=%u ssrc(%8x) remote_ssrc(%8x)\n",
                              rtp_session->rtp_conn_name, rtp_session->write_count, rtp_session->seq, rtp_session->ssrc, rtp_session->remote_ssrc);
            rtp_session->write_count = 0;
            rtp_session->is_bridge = SWITCH_TRUE;
            rtp_session->anchor_base_ts = rtp_session->anchor_next_seq;
            rtp_session->anchor_base_seq = rtp_session->anchor_next_seq;
        }
        if (!rtp_session->is_bridge) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "session is BRIDGE ssrc(%8x) remote_ssrc(%8x)\n",
                              rtp_session->ssrc, rtp_session->remote_ssrc);
            rtp_session->is_bridge = SWITCH_TRUE;
        }

        if (fuze_transport_connection_set_local_address(rtp_session->rtp_conn, host, port) < 0) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error on setting local address: %s:%u.\n", host, port);
            goto done;
        }

        if ((switch_status_t) fuze_transport_connection_start(rtp_session->rtp_conn) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error while starting transport rtp %s:%u.\n", host, port);
            goto done;
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Starting fuze transport for rtcp %s:%u.\n", host, port);
        }

    }

    if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_ENABLE_RTCP)) {
        if ((status = enable_local_rtcp_socket(rtp_session, tbase, err)) == SWITCH_STATUS_SUCCESS) {
            *err = "Success";
        }
    } else {
        status = SWITCH_STATUS_SUCCESS;
        *err = "Success";
    }

    switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_IO);

 done:

    if (*err) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "RTP-CONN-INFO: %s ret=%d.\n", *err, errno);
    }

    if (new_sock) {
        switch_socket_close(new_sock);
    }

    if (old_sock) {
        switch_socket_close(old_sock);
    }


    if (rtp_session->ready != 1) {
        WRITE_DEC(rtp_session);
        READ_DEC(rtp_session);
    }

    return status;
}

SWITCH_DECLARE(void) switch_rtp_set_max_missed_packets(switch_rtp_t *rtp_session, uint32_t max)
{
    if (rtp_session->missed_count >= max) {

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                          "new max missed packets(%d->%d) greater than current missed packets(%d). RTP will timeout.\n",
                          rtp_session->missed_count, max, rtp_session->missed_count);
    }

    rtp_session->max_missed_packets = max;
}

SWITCH_DECLARE(void) switch_rtp_reset_media_timer(switch_rtp_t *rtp_session)
{
    rtp_session->missed_count = 0;
}

SWITCH_DECLARE(char *) switch_rtp_get_remote_host(switch_rtp_t *rtp_session)
{
    return zstr(rtp_session->remote_host_str) ? "0.0.0.0" : rtp_session->remote_host_str;
}

SWITCH_DECLARE(switch_port_t) switch_rtp_get_remote_port(switch_rtp_t *rtp_session)
{
    return rtp_session->remote_port;
}

static void ping_socket(switch_rtp_t *rtp_session)
{
    uint32_t o = UINT_MAX;
    switch_size_t len = sizeof(o);
    
    rtp_sendto(rtp_session, rtp_session->sock_input, rtp_session->local_addr, 0, (void *) &o, &len);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                      "RTCP (ping) packet sent rtcp_bytes=%" PRId64 "\n", len);

    if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_ENABLE_RTCP) && rtp_session->rtcp_sock_input) {
        rtcp_sendto(rtp_session, rtp_session->rtcp_sock_input, rtp_session->rtcp_local_addr, 0, (void *) &o, &len);
    }
}

SWITCH_DECLARE(switch_status_t) switch_rtp_udptl_mode(switch_rtp_t *rtp_session)
{
    switch_socket_t *sock;

    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_PROXY_MEDIA)) {
        ping_socket(rtp_session);
    }

    READ_INC(rtp_session);
    WRITE_INC(rtp_session);

    if (rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER] || rtp_session->timer.timer_interface) {
        switch_core_timer_destroy(&rtp_session->timer);
        memset(&rtp_session->timer, 0, sizeof(rtp_session->timer));
        switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER);
    }

    rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP] = 0;

    if (rtp_session->rtcp_sock_input) {
        ping_socket(rtp_session);
        switch_socket_shutdown(rtp_session->rtcp_sock_input, SWITCH_SHUTDOWN_READWRITE);
    }

    if (rtp_session->rtcp_sock_output && rtp_session->rtcp_sock_output != rtp_session->rtcp_sock_input) {
        switch_socket_shutdown(rtp_session->rtcp_sock_output, SWITCH_SHUTDOWN_READWRITE);
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
        rtp_session->rtcp_sock_input = NULL;
        rtp_session->rtcp_sock_output = NULL;
    } else {
        if ((sock = rtp_session->rtcp_sock_input)) {
            rtp_session->rtcp_sock_input = NULL;
            switch_socket_close(sock);

            if (rtp_session->rtcp_sock_output && rtp_session->rtcp_sock_output != sock) {
                if ((sock = rtp_session->rtcp_sock_output)) {
                    rtp_session->rtcp_sock_output = NULL;
                    switch_socket_close(sock);
                }
            }
        }
    }

    switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_UDPTL);
    switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_PROXY_MEDIA);
    switch_socket_opt_set(rtp_session->sock_input, SWITCH_SO_NONBLOCK, FALSE);
    switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_NOBLOCK);

    WRITE_DEC(rtp_session);
    READ_DEC(rtp_session);

    switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_STICKY_FLUSH);
    switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_FLUSH);

    switch_rtp_break(rtp_session);

    return SWITCH_STATUS_SUCCESS;

}


SWITCH_DECLARE(switch_status_t) switch_rtp_set_remote_address(switch_rtp_t *rtp_session, const char *host, switch_port_t port, switch_port_t remote_rtcp_port,
                                                              switch_bool_t change_adv_addr, const char **err)
{
    switch_sockaddr_t *remote_addr;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    *err = "Success";

    if (rtp_session->remote_rtp_address_set) {
#if 0
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "switch_rtp_set_remote_address called but address already set in fuze transport\n");
#endif
        *err = "Warning remote RTP address already set!";
        return SWITCH_STATUS_SUCCESS;
    }

    if (switch_sockaddr_info_get(&remote_addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS || !remote_addr) {
        *err = "Remote Address Error!";
        return SWITCH_STATUS_FALSE;
    }


    switch_mutex_lock(rtp_session->write_mutex);

    if (rtp_session->rtp_conn) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Setting remote %s:%d\n", host, port);
        if (fuze_transport_connection_set_remote_address(rtp_session->rtp_conn, host, port) < 0) {
            *err = "Error on setting Remote RTP.";
        } else {
            rtp_session->remote_rtp_address_set = SWITCH_TRUE;
        }
    }

    rtp_session->remote_addr = remote_addr;

    if (change_adv_addr) {
        rtp_session->remote_host_str = switch_core_strdup(rtp_session->pool, host);
        rtp_session->remote_port = port;
    }

    rtp_session->eff_remote_host_str = switch_core_strdup(rtp_session->pool, host);
    rtp_session->eff_remote_port = port;

    if (rtp_session->sock_input && switch_sockaddr_get_family(rtp_session->remote_addr) == switch_sockaddr_get_family(rtp_session->local_addr)) {
        rtp_session->sock_output = rtp_session->sock_input;
    } else {
        if (rtp_session->sock_output && rtp_session->sock_output != rtp_session->sock_input) {
            switch_socket_close(rtp_session->sock_output);
        }
        if ((status = switch_socket_create(&rtp_session->sock_output,
                                           switch_sockaddr_get_family(rtp_session->remote_addr),
                                           SOCK_DGRAM, 0, rtp_session->pool)) != SWITCH_STATUS_SUCCESS) {
            *err = "Socket Error!";
        }
    }


    if (rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP] && !rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
        if (remote_rtcp_port) {
            rtp_session->remote_rtcp_port = remote_rtcp_port;
        } else {
            rtp_session->remote_rtcp_port = rtp_session->eff_remote_port + 1;
        }
        status = enable_remote_rtcp_socket(rtp_session, err);
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP] && rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
        rtp_session->rtcp_remote_addr = rtp_session->remote_addr;
    }

    switch_mutex_unlock(rtp_session->write_mutex);

    return status;
}


static const char *dtls_state_names_t[] = {"HANDSHAKE", "SETUP", "READY", "FAIL", "INVALID"};
static const char *dtls_state_names(dtls_state_t s)
{
    if (s > DS_INVALID) {
        s = DS_INVALID;
    }

    return dtls_state_names_t[s];
}


#define dtls_set_state(_dtls, _state) switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Changing %s DTLS state from %s to %s\n", rtp_type(rtp_session), dtls_state_names(_dtls->state), dtls_state_names(_state)); _dtls->new_state = 1; _dtls->last_state = _dtls->state; _dtls->state = _state

#define cr_keylen 16
#define cr_saltlen 14
#define cr_kslen 30

static int dtls_state_setup(switch_rtp_t *rtp_session, switch_dtls_t *dtls)
{
    X509 *cert;
    int r = 0;

    if ((dtls->type & DTLS_TYPE_SERVER)) {
        r = 1;
    } else if ((cert = SSL_get_peer_certificate(dtls->ssl))) {
        switch_core_cert_extract_fingerprint(cert, dtls->remote_fp);
        r = switch_core_cert_verify(dtls->remote_fp);
        X509_free(cert);
    }

    if (!r) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s Fingerprint Verification Failed!\n", rtp_type(rtp_session));
        dtls_set_state(dtls, DS_FAIL);
        return -1;
    } else {
        uint8_t raw_key_data[cr_kslen*2] = { 0 };
        unsigned char *local_key, *remote_key, *local_salt, *remote_salt;
        unsigned char local_key_buf[cr_kslen] = {0}, remote_key_buf[cr_kslen] = {0};

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s Fingerprint Verified.\n", rtp_type(rtp_session));

#ifdef HAVE_OPENSSL_DTLS_SRTP
        if (!SSL_export_keying_material(dtls->ssl, raw_key_data, sizeof(raw_key_data), "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s Key material export failure\n", rtp_type(rtp_session));
            dtls_set_state(dtls, DS_FAIL);
            return -1;
        }
#else
        return -1;
#endif

        if ((dtls->type & DTLS_TYPE_CLIENT)) {
            local_key = raw_key_data;
            remote_key = local_key + cr_keylen;
            local_salt = remote_key + cr_keylen;
            remote_salt = local_salt + cr_saltlen;

        } else {
            remote_key = raw_key_data;
            local_key = remote_key + cr_keylen;
            remote_salt = local_key + cr_keylen;
            local_salt = remote_salt + cr_saltlen;
        }

        memcpy(local_key_buf, local_key, cr_keylen);
        memcpy(local_key_buf + cr_keylen, local_salt, cr_saltlen);

        memcpy(remote_key_buf, remote_key, cr_keylen);
        memcpy(remote_key_buf + cr_keylen, remote_salt, cr_saltlen);

        if (dtls == rtp_session->rtcp_dtls && rtp_session->rtcp_dtls != rtp_session->dtls) {
            switch_rtp_add_crypto_key(rtp_session, SWITCH_RTP_CRYPTO_SEND_RTCP, 0, AES_CM_128_HMAC_SHA1_80, local_key_buf, cr_kslen);
            switch_rtp_add_crypto_key(rtp_session, SWITCH_RTP_CRYPTO_RECV_RTCP, 0, AES_CM_128_HMAC_SHA1_80, remote_key_buf, cr_kslen);
        } else {
            switch_rtp_add_crypto_key(rtp_session, SWITCH_RTP_CRYPTO_SEND, 0, AES_CM_128_HMAC_SHA1_80, local_key_buf, cr_kslen);
            switch_rtp_add_crypto_key(rtp_session, SWITCH_RTP_CRYPTO_RECV, 0, AES_CM_128_HMAC_SHA1_80, remote_key_buf, cr_kslen);
        }
    }

    dtls_set_state(dtls, DS_READY);

    return 0;
}

static int dtls_state_ready(switch_rtp_t *rtp_session, switch_dtls_t *dtls)
{

    if (dtls->new_state) {
        if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
            switch_core_session_t *other_session;
            rtp_session->fir_countdown = FIR_COUNTDOWN;

            if (rtp_session->session && switch_core_session_get_partner(rtp_session->session, &other_session) == SWITCH_STATUS_SUCCESS) {
                switch_core_session_refresh_video(other_session);
                switch_core_session_rwunlock(other_session);
            }
        }
        dtls->new_state = 0;
    }
    return 0;
}

static int dtls_state_fail(switch_rtp_t *rtp_session, switch_dtls_t *dtls)
{
    if (rtp_session->session) {
        switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);
        switch_channel_hangup(channel, SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER);
    }

    return -1;
}


static int dtls_state_handshake(switch_rtp_t *rtp_session, switch_dtls_t *dtls)
{
    int ret;

    if ((ret = SSL_do_handshake(dtls->ssl)) != 1){
        switch((ret = SSL_get_error(dtls->ssl, ret))){
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_NONE:
            break;
        default:
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s Handshake failure %d\n", rtp_type(rtp_session), ret);
            dtls_set_state(dtls, DS_FAIL);
            return -1;
        }
    }

    if (SSL_is_init_finished(dtls->ssl)) {
        dtls_set_state(dtls, DS_SETUP);
    }

    return 0;
}

static void free_dtls(switch_dtls_t **dtlsp)
{
    switch_dtls_t *dtls;

    if (!dtlsp) {
        return;
    }

    dtls = *dtlsp;
    *dtlsp = NULL;

    if (dtls->ssl) {
        SSL_free(dtls->ssl);
    }

    if (dtls->ssl_ctx) {
        SSL_CTX_free(dtls->ssl_ctx);
    }
}

static int do_dtls(switch_rtp_t *rtp_session, switch_dtls_t *dtls)
{
    int r = 0, ret = 0, len;
    switch_size_t bytes;
    unsigned char buf[4096] = "";
    int ready = rtp_session->ice.ice_user ? (rtp_session->ice.rready && rtp_session->ice.ready) : 1;


    if (!dtls->bytes && !ready) {
        return 0;
    }

    if ((ret = BIO_write(dtls->read_bio, dtls->data, (int)dtls->bytes)) != (int)dtls->bytes && dtls->bytes > 0) {
        ret = SSL_get_error(dtls->ssl, ret);
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s DTLS packet read err %d\n", rtp_type(rtp_session), ret);
    }

    r = dtls_states[dtls->state](rtp_session, dtls);

    if ((len = BIO_read(dtls->write_bio, buf, sizeof(buf))) > 0) {
        bytes = len;

        if (rtp_sendto(rtp_session, dtls->sock_output, dtls->remote_addr, 0, (void *)buf, &bytes ) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s DTLS packet not written\n", rtp_type(rtp_session));
        }
    }



    return r;
}

#if VERIFY
static int cb_verify_peer(int preverify_ok, X509_STORE_CTX *ctx)
{
    SSL *ssl = NULL;
    switch_dtls_t *dtls;
    X509 *cert;
    int r = 0;

    ssl = X509_STORE_CTX_get_app_data(ctx);
    dtls = (switch_dtls_t *) SSL_get_app_data(ssl);

    if (!(ssl && dtls)) {
        return 0;
    }

    if ((cert = SSL_get_peer_certificate(dtls->ssl))) {
        switch_core_cert_extract_fingerprint(cert, dtls->remote_fp);

        r = switch_core_cert_verify(dtls->remote_fp);

        X509_free(cert);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(dtls->rtp_session->session), SWITCH_LOG_ERROR, "%s CERT ERR!\n", rtp_type(dtls->rtp_session));
    }

    return r;
}
#endif

SWITCH_DECLARE(int) switch_rtp_has_dtls(void) {
#ifdef HAVE_OPENSSL_DTLS_SRTP
    return 1;
#else
    return 0;
#endif
}

SWITCH_DECLARE(switch_status_t) switch_rtp_del_dtls(switch_rtp_t *rtp_session, dtls_type_t type)
{

    if (!rtp_session->dtls && !rtp_session->rtcp_dtls) {
        return SWITCH_STATUS_FALSE;
    }

    if ((type & DTLS_TYPE_RTP)) {
        if (rtp_session->dtls && rtp_session->dtls == rtp_session->rtcp_dtls) {
            rtp_session->rtcp_dtls = NULL;
        }

        if (rtp_session->dtls) {
            free_dtls(&rtp_session->dtls);
        }

        if (rtp_session->jb) {
            stfu_n_reset(rtp_session->jb);
        }

    }

    if ((type & DTLS_TYPE_RTCP) && rtp_session->rtcp_dtls) {
        free_dtls(&rtp_session->rtcp_dtls);
    }


#ifdef ENABLE_SRTP
    if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND]) {
        int x;
        for(x = 0; x < 2; x++) {
            if (rtp_session->send_ctx[x]) {
                srtp_dealloc(rtp_session->send_ctx[x]);
                rtp_session->send_ctx[x] = NULL;
            }
        }
        rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND] = 0;
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV]) {
        int x;
        for (x = 0; x < 2; x++) {
            if (rtp_session->recv_ctx[x]) {
                srtp_dealloc(rtp_session->recv_ctx[x]);
                rtp_session->recv_ctx[x] = NULL;
            }
        }
        rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV] = 0;
    }
#endif

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_add_dtls(switch_rtp_t *rtp_session, dtls_fingerprint_t *local_fp, dtls_fingerprint_t *remote_fp, dtls_type_t type)
{
    switch_dtls_t *dtls;
    int ret;
    const char *kind = "";

#ifndef HAVE_OPENSSL_DTLS_SRTP
    return SWITCH_STATUS_FALSE;
#endif

    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    if (!((type & DTLS_TYPE_RTP) || (type & DTLS_TYPE_RTCP)) || !((type & DTLS_TYPE_CLIENT) || (type & DTLS_TYPE_SERVER))) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_CRIT, "INVALID TYPE!\n");
    }

    switch_rtp_del_dtls(rtp_session, type);

    if ((type & DTLS_TYPE_RTP) && (type & DTLS_TYPE_RTCP)) {
        kind = "RTP/RTCP";
    } else if ((type & DTLS_TYPE_RTP)) {
        kind = "RTP";
    } else {
        kind = "RTCP";
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                      "Activate %s %s DTLS %s\n", kind, rtp_type(rtp_session), (type & DTLS_TYPE_SERVER) ? "server" : "client");

    if (((type & DTLS_TYPE_RTP) && rtp_session->dtls) || ((type & DTLS_TYPE_RTCP) && rtp_session->rtcp_dtls)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "DTLS ALREADY INIT\n");
        return SWITCH_STATUS_FALSE;
    }

    dtls = switch_core_alloc(rtp_session->pool, sizeof(*dtls));

    dtls->pem = switch_core_sprintf(rtp_session->pool, "%s%s%s.pem", SWITCH_GLOBAL_dirs.certs_dir, SWITCH_PATH_SEPARATOR, DTLS_SRTP_FNAME);

    if (switch_file_exists(dtls->pem, rtp_session->pool) == SWITCH_STATUS_SUCCESS) {
        dtls->pvt = dtls->rsa = dtls->pem;
    } else {
        dtls->pvt = switch_core_sprintf(rtp_session->pool, "%s%s%s.key", SWITCH_GLOBAL_dirs.certs_dir, SWITCH_PATH_SEPARATOR, DTLS_SRTP_FNAME);
        dtls->rsa = switch_core_sprintf(rtp_session->pool, "%s%s%s.crt", SWITCH_GLOBAL_dirs.certs_dir, SWITCH_PATH_SEPARATOR, DTLS_SRTP_FNAME);
    }

    dtls->ca = switch_core_sprintf(rtp_session->pool, "%s%sca-bundle.crt", SWITCH_GLOBAL_dirs.certs_dir, SWITCH_PATH_SEPARATOR);

    dtls->ssl_ctx = SSL_CTX_new(DTLSv1_method());
    switch_assert(dtls->ssl_ctx);

    SSL_CTX_set_mode(dtls->ssl_ctx, SSL_MODE_AUTO_RETRY);

    SSL_CTX_set_verify(dtls->ssl_ctx, SSL_VERIFY_NONE, NULL);
    {
        EC_KEY *p_ecdh = EC_KEY_new_by_curve_name(NID_secp384r1);
        if (p_ecdh) {
            if (SSL_CTX_set_tmp_ecdh(dtls->ssl_ctx, p_ecdh) != 1) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s DTLS SSL_CTX_set_tmp_ecdh error\n",
                                  rtp_type(rtp_session));
            }
            EC_KEY_free(p_ecdh);
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s DTLS EC_KEY_new_by_curve_name error\n",
                              rtp_type(rtp_session));
        }
    }
    SSL_CTX_set_cipher_list(dtls->ssl_ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    SSL_CTX_set_session_cache_mode(dtls->ssl_ctx, SSL_SESS_CACHE_OFF);

#ifdef HAVE_OPENSSL_DTLS_SRTP
    SSL_CTX_set_tlsext_use_srtp(dtls->ssl_ctx, "SRTP_AES128_CM_SHA1_80");
#endif

    dtls->type = type;
    dtls->read_bio = BIO_new(BIO_s_mem());
    switch_assert(dtls->read_bio);

    dtls->write_bio = BIO_new(BIO_s_mem());
    switch_assert(dtls->write_bio);

    BIO_set_mem_eof_return(dtls->read_bio, -1);
    BIO_set_mem_eof_return(dtls->write_bio, -1);

    if ((ret=SSL_CTX_use_certificate_file(dtls->ssl_ctx, dtls->rsa, SSL_FILETYPE_PEM)) != 1) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s DTLS cert err [%d]\n", rtp_type(rtp_session), SSL_get_error(dtls->ssl, ret));
        return SWITCH_STATUS_FALSE;
    }

    if ((ret=SSL_CTX_use_PrivateKey_file(dtls->ssl_ctx, dtls->pvt, SSL_FILETYPE_PEM)) != 1) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s DTLS key err [%d]\n", rtp_type(rtp_session), SSL_get_error(dtls->ssl, ret));
        return SWITCH_STATUS_FALSE;
    }

    if (SSL_CTX_check_private_key(dtls->ssl_ctx) == 0) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s DTLS check key failed\n", rtp_type(rtp_session));
        return SWITCH_STATUS_FALSE;
    }

    if (!zstr(dtls->ca) && switch_file_exists(dtls->ca, rtp_session->pool) == SWITCH_STATUS_SUCCESS
        && (ret = SSL_CTX_load_verify_locations(dtls->ssl_ctx, dtls->ca, NULL)) != 1) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s DTLS check chain cert failed [%d]\n",
                          rtp_type(rtp_session) ,
                          SSL_get_error(dtls->ssl, ret));
        return SWITCH_STATUS_FALSE;
    }

    dtls->ssl = SSL_new(dtls->ssl_ctx);

    SSL_set_bio(dtls->ssl, dtls->read_bio, dtls->write_bio);
    SSL_set_mode(dtls->ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_read_ahead(dtls->ssl, 1);
    //SSL_set_verify(dtls->ssl, (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT), cb_verify_peer);
    SSL_set_verify(dtls->ssl, SSL_VERIFY_NONE, NULL);
    SSL_set_app_data(dtls->ssl, dtls);

    BIO_ctrl(dtls->read_bio, BIO_CTRL_DGRAM_SET_MTU, 1400, NULL);
    BIO_ctrl(dtls->write_bio, BIO_CTRL_DGRAM_SET_MTU, 1400, NULL);
    SSL_set_mtu(dtls->ssl, 1400);
    BIO_ctrl(dtls->write_bio, BIO_C_SET_BUFF_SIZE, 1400, NULL);
    BIO_ctrl(dtls->read_bio, BIO_C_SET_BUFF_SIZE, 1400, NULL);



    dtls->local_fp = local_fp;
    dtls->remote_fp = remote_fp;
    dtls->rtp_session = rtp_session;

    switch_core_cert_expand_fingerprint(remote_fp, remote_fp->str);

    if ((type & DTLS_TYPE_RTP)) {
        rtp_session->dtls = dtls;
        dtls->sock_output = rtp_session->sock_output;
        dtls->remote_addr = rtp_session->remote_addr;
    }

    if ((type & DTLS_TYPE_RTCP)) {
        rtp_session->rtcp_dtls = dtls;
        if (!(type & DTLS_TYPE_RTP)) {
            dtls->sock_output = rtp_session->rtcp_sock_output;
            dtls->remote_addr = rtp_session->rtcp_remote_addr;
        }
    }

    if ((type & DTLS_TYPE_SERVER)) {
        SSL_set_accept_state(dtls->ssl);
    } else {
        SSL_set_connect_state(dtls->ssl);
    }

    rtp_session->flags[SWITCH_RTP_FLAG_VIDEO_BREAK] = 1;
    switch_rtp_break(rtp_session);

    return SWITCH_STATUS_SUCCESS;

}


SWITCH_DECLARE(switch_status_t) switch_rtp_add_crypto_key(switch_rtp_t *rtp_session,
                                                          switch_rtp_crypto_direction_t direction,
                                                          uint32_t index, switch_rtp_crypto_key_type_t type, unsigned char *key, switch_size_t keylen)
{
#ifndef ENABLE_SRTP
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_CRIT, "SRTP NOT SUPPORTED IN THIS BUILD!\n");
    return SWITCH_STATUS_FALSE;
#else
    switch_rtp_crypto_key_t *crypto_key;
    srtp_policy_t *policy;
    err_status_t stat;
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);
    switch_event_t *fsevent = NULL;
    int idx = 0;
    const char *var;

    if (direction >= SWITCH_RTP_CRYPTO_MAX || keylen > SWITCH_RTP_MAX_CRYPTO_LEN) {
        return SWITCH_STATUS_FALSE;
    }

    crypto_key = switch_core_alloc(rtp_session->pool, sizeof(*crypto_key));

    if (direction == SWITCH_RTP_CRYPTO_RECV_RTCP) {
        direction = SWITCH_RTP_CRYPTO_RECV;
        rtp_session->srtp_idx_rtcp = idx = 1;
    } else if (direction == SWITCH_RTP_CRYPTO_SEND_RTCP) {
        direction = SWITCH_RTP_CRYPTO_SEND;
        rtp_session->srtp_idx_rtcp = idx = 1;
    }

    if (direction == SWITCH_RTP_CRYPTO_RECV) {
        policy = &rtp_session->recv_policy[idx];
    } else {
        policy = &rtp_session->send_policy[idx];
    }

    crypto_key->type = type;
    crypto_key->index = index;
    memcpy(crypto_key->key, key, keylen);
    crypto_key->next = rtp_session->crypto_keys[direction];
    rtp_session->crypto_keys[direction] = crypto_key;

    memset(policy, 0, sizeof(*policy));

    /* many devices can't handle gaps in SRTP streams */
    if (!((var = switch_channel_get_variable(channel, "srtp_allow_idle_gaps"))
          && switch_true(var))
        && (!(var = switch_channel_get_variable(channel, "send_silence_when_idle"))
            || !(atoi(var)))) {
        switch_channel_set_variable(channel, "send_silence_when_idle", "-1");
    }

    switch (crypto_key->type) {
    case AES_CM_128_HMAC_SHA1_80:
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtp);
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtcp);

        if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
            switch_channel_set_variable(channel, "rtp_has_crypto", "AES_CM_128_HMAC_SHA1_80");
        }
        break;
    case AES_CM_128_HMAC_SHA1_32:
        crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy->rtp);
        crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtcp);


        if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
            switch_channel_set_variable(channel, "rtp_has_crypto", "AES_CM_128_HMAC_SHA1_32");
        }
        break;

    case AEAD_AES_256_GCM_8:
        crypto_policy_set_aes_gcm_256_8_auth(&policy->rtp);
        crypto_policy_set_aes_gcm_256_8_auth(&policy->rtcp);

        if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
            switch_channel_set_variable(channel, "rtp_has_crypto", "AEAD_AES_256_GCM_8");
        }
        break;

    case AEAD_AES_128_GCM_8:
        crypto_policy_set_aes_gcm_128_8_auth(&policy->rtp);
        crypto_policy_set_aes_gcm_128_8_auth(&policy->rtcp);

        if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
            switch_channel_set_variable(channel, "rtp_has_crypto", "AEAD_AES_128_GCM_8");
        }
        break;

    case AES_CM_256_HMAC_SHA1_80:
        crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy->rtp);
        crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy->rtcp);
        if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
            switch_channel_set_variable(channel, "rtp_has_crypto", "AES_CM_256_HMAC_SHA1_80");
        }
        break;
    case AES_CM_128_NULL_AUTH:
        crypto_policy_set_aes_cm_128_null_auth(&policy->rtp);
        crypto_policy_set_aes_cm_128_null_auth(&policy->rtcp);

        if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
            switch_channel_set_variable(channel, "rtp_has_crypto", "AES_CM_128_NULL_AUTH");
        }
        break;
    default:
        break;
    }

    policy->key = (uint8_t *) crypto_key->key;
    policy->next = NULL;

    policy->window_size = 1024;
    policy->allow_repeat_tx = 1;

    //policy->rtp.sec_serv = sec_serv_conf_and_auth;
    //policy->rtcp.sec_serv = sec_serv_conf_and_auth;

    switch (direction) {
    case SWITCH_RTP_CRYPTO_RECV:
        policy->ssrc.type = ssrc_any_inbound;

        if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV] && idx == 0 && rtp_session->recv_ctx[idx]) {
            rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV_RESET] = 1;
        } else {
            if ((stat = srtp_create(&rtp_session->recv_ctx[idx], policy))) {
                status = SWITCH_STATUS_FALSE;
            }

            if (status == SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Activating %s Secure %s RECV\n",
                                  rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] ? "Video" : "Audio", idx ? "RTCP" : "RTP");
                rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV] = 1;
            } else {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error allocating srtp [%d]\n", stat);
                return status;
            }
        }
        break;
    case SWITCH_RTP_CRYPTO_SEND:
        policy->ssrc.type = ssrc_any_outbound;
        //policy->ssrc.type = ssrc_specific;
        //policy->ssrc.value = rtp_session->ssrc;

        if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND] && idx == 0 && rtp_session->send_ctx[idx]) {
            rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND_RESET] = 1;
        } else {
            if ((stat = srtp_create(&rtp_session->send_ctx[idx], policy))) {
                status = SWITCH_STATUS_FALSE;
            }

            if (status == SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Activating %s Secure %s SEND\n",
                                  rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] ? "Video" : "Audio", idx ? "RTCP" : "RTP");
                rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND] = 1;
            } else {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error allocating SRTP [%d]\n", stat);
                return status;
            }
        }

        break;
    default:
        abort();
        break;
    }

    if (switch_event_create(&fsevent, SWITCH_EVENT_CALL_SECURE) == SWITCH_STATUS_SUCCESS) {
        if (rtp_session->dtls) {
            switch_event_add_header(fsevent, SWITCH_STACK_BOTTOM, "secure_type", "srtp:dtls:AES_CM_128_HMAC_SHA1_80");
        } else {
            switch_event_add_header(fsevent, SWITCH_STACK_BOTTOM, "secure_type", "srtp:sdes:%s", switch_channel_get_variable(channel, "rtp_has_crypto"));
        }
        switch_event_add_header_string(fsevent, SWITCH_STACK_BOTTOM, "caller-unique-id", switch_channel_get_uuid(channel));
        switch_event_fire(&fsevent);
    }


    return SWITCH_STATUS_SUCCESS;
#endif
}

SWITCH_DECLARE(switch_status_t) switch_rtp_set_interval(switch_rtp_t *rtp_session, uint32_t ms_per_packet, uint32_t samples_per_interval)
{
    rtp_session->ms_per_packet = ms_per_packet;
    rtp_session->samples_per_interval = rtp_session->conf_samples_per_interval = samples_per_interval;
    rtp_session->missed_count = 0;
    rtp_session->samples_per_second =
        (uint32_t) ((double) (1000.0f / (double) (rtp_session->ms_per_packet / 1000)) * (double) rtp_session->samples_per_interval);

    rtp_session->one_second = (rtp_session->samples_per_second / rtp_session->samples_per_interval);

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_change_interval(switch_rtp_t *rtp_session, uint32_t ms_per_packet, uint32_t samples_per_interval)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    int change_timer = 0;

    if (rtp_session->ms_per_packet && rtp_session->ms_per_packet != ms_per_packet) {
        change_timer = 1;
    }

    switch_rtp_set_interval(rtp_session, ms_per_packet, samples_per_interval);

    if (change_timer && rtp_session->timer_name) {
        READ_INC(rtp_session);
        WRITE_INC(rtp_session);

        if (rtp_session->timer.timer_interface) {
            switch_core_timer_destroy(&rtp_session->timer);
        }
        if ((status = switch_core_timer_init(&rtp_session->timer,
                                             rtp_session->timer_name, ms_per_packet / 1000,
                                             samples_per_interval, rtp_session->pool)) == SWITCH_STATUS_SUCCESS) {

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG,
                              "RE-Starting timer [%s] %d bytes per %dms\n", rtp_session->timer_name, samples_per_interval, ms_per_packet / 1000);
        } else {

            memset(&rtp_session->timer, 0, sizeof(rtp_session->timer));
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR,
                              "Problem RE-Starting timer [%s] %d bytes per %dms\n", rtp_session->timer_name, samples_per_interval, ms_per_packet / 1000);
        }

        WRITE_DEC(rtp_session);
        READ_DEC(rtp_session);
    }

    return status;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_set_ssrc(switch_rtp_t *rtp_session, uint32_t ssrc)
{
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                      "New ssrc %8x -> %8x\n", rtp_session->ssrc, ssrc);
    rtp_session->ssrc = ssrc;
    rtp_session->send_msg.header.ssrc = htonl(rtp_session->ssrc);

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_set_remote_ssrc(switch_rtp_t *rtp_session, uint32_t ssrc)
{
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                      "New remote ssrc %8x -> %8x\n", rtp_session->ssrc, ssrc);

    rtp_session->remote_ssrc = ssrc;

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_create(switch_rtp_t **new_rtp_session,
                                                  switch_payload_t payload,
                                                  uint32_t samples_per_interval,
                                                  uint32_t ms_per_packet,
                                                  switch_rtp_flag_t flags[SWITCH_RTP_FLAG_INVALID], char *timer_name, const char **err, switch_memory_pool_t *pool)
{
    switch_rtp_t *rtp_session = NULL;
    switch_core_session_t *session = switch_core_memory_pool_get_data(pool, "__session");
    switch_channel_t *channel = NULL;
    static unsigned short id = 0;

    if (session) channel = switch_core_session_get_channel(session);

    *new_rtp_session = NULL;

    if (samples_per_interval > SWITCH_RTP_MAX_BUF_LEN) {
        *err = "Packet Size Too Large!";
        return SWITCH_STATUS_FALSE;
    }

    if (!(rtp_session = switch_core_alloc(pool, sizeof(*rtp_session)))) {
        *err = "Memory Error!";
        return SWITCH_STATUS_MEMERR;
    }

    rtp_session->id = id++;

    rtp_session->pool = pool;
    rtp_session->te = 101;
    rtp_session->recv_te = 101;
    rtp_session->session = session;

    switch_mutex_init(&rtp_session->flag_mutex, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&rtp_session->read_mutex, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&rtp_session->write_mutex, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&rtp_session->dtmf_data.dtmf_mutex, SWITCH_MUTEX_NESTED, pool);
    switch_queue_create(&rtp_session->dtmf_data.dtmf_queue, 100, rtp_session->pool);
    switch_queue_create(&rtp_session->dtmf_data.dtmf_inqueue, 100, rtp_session->pool);

    switch_rtp_set_flags(rtp_session, flags);

    /* for from address on recvfrom calls */
    switch_sockaddr_create(&rtp_session->from_addr, pool);

    if (rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP]) {
        switch_sockaddr_create(&rtp_session->rtcp_from_addr, pool);
    }
    rtp_session->seq = (uint16_t) rand();
    rtp_session->ssrc = (uint32_t) ((intptr_t) rtp_session + (uint32_t) switch_epoch_time_now(NULL));

    rtp_session->stats.inbound.R = 100.0;
    rtp_session->stats.inbound.mos = 4.5;
    rtp_session->send_msg.header.ssrc = htonl(rtp_session->ssrc);
    rtp_session->send_msg.header.ts = 0;
    rtp_session->send_msg.header.m = 0;
    rtp_session->send_msg.header.pt = (switch_payload_t) htonl(payload);
    rtp_session->send_msg.header.version = 2;
    rtp_session->send_msg.header.p = 0;
    rtp_session->send_msg.header.x = 0;
    rtp_session->send_msg.header.cc = 0;

    rtp_session->recv_msg.header.ssrc = 0;
    rtp_session->recv_msg.header.ts = 0;
    rtp_session->recv_msg.header.seq = 0;
    rtp_session->recv_msg.header.m = 0;
    rtp_session->recv_msg.header.pt = (switch_payload_t) htonl(payload);
    rtp_session->recv_msg.header.version = 2;
    rtp_session->recv_msg.header.p = 0;
    rtp_session->recv_msg.header.x = 0;
    rtp_session->recv_msg.header.cc = 0;

    rtp_session->payload = payload;

    rtp_session->timestamp_multiplier = 1;

    switch_rtp_set_interval(rtp_session, ms_per_packet, samples_per_interval);
    rtp_session->conf_samples_per_interval = samples_per_interval;

    if (rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER] && zstr(timer_name)) {
        timer_name = "soft";
    }

    if (!zstr(timer_name) && !strcasecmp(timer_name, "none")) {
        timer_name = NULL;
    }

    if (!zstr(timer_name)) {
        rtp_session->timer_name = switch_core_strdup(pool, timer_name);
        switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER);
        switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_NOBLOCK);

        if (switch_core_timer_init(&rtp_session->timer, timer_name, ms_per_packet / 1000, samples_per_interval, pool) == SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG,
                              "Starting timer [%s] %d bytes per %dms\n", timer_name, samples_per_interval, ms_per_packet / 1000);
        } else {
            memset(&rtp_session->timer, 0, sizeof(rtp_session->timer));
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR,
                              "Error Starting timer [%s] %d bytes per %dms, async RTP disabled\n", timer_name, samples_per_interval, ms_per_packet / 1000);
            switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER);
        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Not using a timer\n");
        switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER);
        switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_NOBLOCK);
    }


    if (channel) {
        switch_channel_set_private(channel, "__rtcp_audio_rtp_session", rtp_session);
    }

#ifdef ENABLE_ZRTP
    if (zrtp_on && session && channel && !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA]) {
        switch_rtp_t *master_rtp_session = NULL;

        int initiator = 0;
        const char *zrtp_enabled = switch_channel_get_variable(channel, "zrtp_secure_media");
        int srtp_enabled = switch_channel_test_flag(channel, CF_SECURE);

        if (srtp_enabled && switch_true(zrtp_enabled)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                              "You can not have ZRTP and SRTP enabled simultaneously, ZRTP will be disabled for this call!\n");
            switch_channel_set_variable(channel, "zrtp_secure_media", NULL);
            zrtp_enabled = NULL;
        }


        if (switch_true(zrtp_enabled)) {
            if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
                switch_channel_set_private(channel, "__zrtp_video_rtp_session", rtp_session);
                master_rtp_session = switch_channel_get_private(channel, "__zrtp_audio_rtp_session");
            } else {
                switch_channel_set_private(channel, "__zrtp_audio_rtp_session", rtp_session);
                master_rtp_session = rtp_session;
            }


            if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
                initiator = 1;
            }

            if (rtp_session == master_rtp_session) {
                rtp_session->zrtp_profile = switch_core_alloc(rtp_session->pool, sizeof(*rtp_session->zrtp_profile));
                zrtp_profile_defaults(rtp_session->zrtp_profile, zrtp_global);

                rtp_session->zrtp_profile->allowclear = 0;
                rtp_session->zrtp_profile->disclose_bit = 0;
                rtp_session->zrtp_profile->cache_ttl = (uint32_t) -1;

                if (zrtp_status_ok != zrtp_session_init(zrtp_global, rtp_session->zrtp_profile, zid, initiator, &rtp_session->zrtp_session)) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error! zRTP INIT Failed\n");
                    zrtp_session_down(rtp_session->zrtp_session);
                    rtp_session->zrtp_session = NULL;
                    goto end;
                }

                zrtp_session_set_userdata(rtp_session->zrtp_session, session);


                if (zrtp_status_ok != zrtp_stream_attach(master_rtp_session->zrtp_session, &rtp_session->zrtp_stream)) {
                    abort();
                }

                zrtp_stream_set_userdata(rtp_session->zrtp_stream, rtp_session);

                if (switch_true(switch_channel_get_variable(channel, "zrtp_enrollment"))) {
                    zrtp_stream_registration_start(rtp_session->zrtp_stream, rtp_session->ssrc);
                } else {
                    zrtp_stream_start(rtp_session->zrtp_stream, rtp_session->ssrc);
                }
            }

        }
    }

 end:

#endif

    /* Jitter */
    rtp_session->stats.inbound.last_proc_time = switch_time_now() / 1000;
    rtp_session->stats.inbound.jitter_n = 0;
    rtp_session->stats.inbound.jitter_add = 0;
    rtp_session->stats.inbound.jitter_addsq = 0;
    rtp_session->stats.inbound.min_variance = 0;
    rtp_session->stats.inbound.max_variance = 0;

    /* Burst and Packet Loss */
    rtp_session->stats.inbound.lossrate = 0;
    rtp_session->stats.inbound.burstrate = 0;
    memset(rtp_session->stats.inbound.loss, 0, sizeof(rtp_session->stats.inbound.loss));
    rtp_session->stats.inbound.last_loss = 0;
    rtp_session->stats.inbound.last_processed_seq = -1;
    rtp_session->stats.call_start_time = switch_time_now();
    rtp_session->stats.time = 0;
    rtp_session->stats.duration = 0;

    rtp_session->ready = 1;
    *new_rtp_session = rtp_session;

    /* fuze specifics for initialization */
    rtp_session->base_seq_set = SWITCH_FALSE;
    rtp_session->is_bridge = SWITCH_FALSE;
    rtp_session->is_fuze_app = SWITCH_FALSE;
    rtp_session->is_ivr = SWITCH_FALSE;
    rtp_session->is_conf = SWITCH_FALSE;

    rtp_session->remote_rtp_address_set = SWITCH_FALSE;
    rtp_session->remote_rtcp_address_set = SWITCH_FALSE;

    rtp_session->high_drift_packets = 0;
    rtp_session->high_drift_log_suppress = 0;
    rtp_session->total_sent = 0;
    rtp_session->total_bytes_sent = 0;
    rtp_session->total_bad_sent = 0;
    rtp_session->total_bad_bytes_sent = 0;
    rtp_session->out_of_order_sent = 0;

    rtp_session->last_seq_set = SWITCH_FALSE;
    rtp_session->write_count = 0;
    rtp_session->srtp_protect_error = SWITCH_FALSE;
    rtp_session->dontwait = SWITCH_FALSE;

    rtp_session->use_next_ts = SWITCH_TRUE;
    rtp_session->last_write_ts_set = SWITCH_FALSE;
    rtp_session->next_ts = 0;

    rtp_session->sync_seq_no = SWITCH_FALSE;

    rtp_session->ts_ooo_count = 0;
    rtp_session->rtp_send_fail_count = 0;

    rtp_session->stats.last_jitter = -1;
    rtp_session->stats.last_recv_level = -1;
    rtp_session->stats.last_send_level = -1;
    rtp_session->stats.last_active_speaker = -1;
    rtp_session->stats.last_recv_rate = -1;
    rtp_session->stats.last_send_rate = -1;
    rtp_session->stats.last_cumulative_lost = -1;
    rtp_session->stats.last_lost_percent = -1;
    rtp_session->stats.last_mos = -1;
    rtp_session->stats.last_r = -1;
    rtp_session->stats.last_variance = -1;
    rtp_session->stats.last_flaws = -1;

    rtp_session->anchor_base_ts = 0;
    rtp_session->anchor_next_ts = 0;
    rtp_session->anchor_base_seq = 0;
    rtp_session->anchor_next_seq = 0;
    rtp_session->anchor_next_set = SWITCH_FALSE;

    rtp_session->last_adjust_cn_count = switch_time_now();
    rtp_session->bad_packet_size_recv = 0;
    rtp_session->ignore_rtp_size = 0;

    rtp_session->low_level_duration = 0;
    rtp_session->low_level_start = 0;

    rtp_session->level_out = -1;
    rtp_session->level_in = -1;

    rtp_session->last_rtcp_send = switch_time_now();

    rtp_session->stats.recv_rate_history_idx = 0;
    rtp_session->stats.rx_congestion_state = RTP_RX_CONGESTION_GOOD;
    memset(rtp_session->stats.recv_rate_history, 0, sizeof(uint16_t)*RTP_STATS_RATE_HISTORY);

    for (int i = 0; i < STATS_MAX; i++) {
        memset(rtp_session->stats.str[i], 0, sizeof(rtp_session->stats.str[i]));
        rtp_session->stats.eos[i] = rtp_session->stats.str[i];
        rtp_session->stats.len[i] = RTP_STATS_STR_SIZE;
    }

    rtp_session->stats.duration = 0;

#ifdef TRACE_READ
    memset(rtp_session->trace_buffer, 0, 1024);
    rtp_session->trace_cnt = 0;
#endif

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(void) switch_rtp_apply_timestamp_multiplier(switch_rtp_t *rtp_session,
                            uint8_t multiplier)
{
    if (!rtp_session)
        return;

    rtp_session->timestamp_multiplier = multiplier;
        rtp_session->samples_per_interval *= multiplier;
        rtp_session->samples_per_second *= multiplier;
        rtp_session->conf_samples_per_interval *= multiplier;
        rtp_session->rsamples_per_interval *= multiplier;
}

SWITCH_DECLARE(switch_rtp_t *) switch_rtp_new(void *tbase,
                                              const char *rx_host,
                                              switch_port_t rx_port,
                                              const char *tx_host,
                                              switch_port_t tx_port,
                                              switch_payload_t payload,
                                              uint32_t samples_per_interval,
                                              uint32_t ms_per_packet,
                                              switch_rtp_flag_t flags[SWITCH_RTP_FLAG_INVALID], char *timer_name, const char **err, switch_memory_pool_t *pool)
{ 
    switch_rtp_t *rtp_session = NULL;

    if (zstr(rx_host)) {
        *err = "Missing local host";
        goto end;
    }

    if (!rx_port) {
        *err = "Missing local port";
        goto end;
    }

    if (zstr(tx_host)) {
        *err = "Missing remote host";
        goto end;
    }

    if (!tx_port) {
        *err = "Missing remote port";
        goto end;
    }

    if (switch_rtp_create(&rtp_session, payload, samples_per_interval, ms_per_packet, flags, timer_name, err, pool) != SWITCH_STATUS_SUCCESS) {
        goto end;
    }

    switch_mutex_lock(rtp_session->flag_mutex);

    if (switch_rtp_set_local_address(rtp_session, tbase, rx_host, rx_port, err) != SWITCH_STATUS_SUCCESS) {
        switch_mutex_unlock(rtp_session->flag_mutex);
        rtp_session = NULL;
        goto end;
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "calling switch_rtp_set_remote_address h=%s p=%u",
                      tx_host, tx_port);
    if (switch_rtp_set_remote_address(rtp_session, tx_host, tx_port, 0, SWITCH_TRUE, err) != SWITCH_STATUS_SUCCESS) {
        switch_mutex_unlock(rtp_session->flag_mutex);
        rtp_session = NULL;
        goto end;
    }

 end:

    if (rtp_session) {
        switch_mutex_unlock(rtp_session->flag_mutex);
        rtp_session->ready = 2;
        rtp_session->rx_host = switch_core_strdup(rtp_session->pool, rx_host);
        rtp_session->rx_port = rx_port;
        switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_FLUSH);
    } else {
        switch_rtp_release_port(rx_host, rx_port);
    }

    return rtp_session;
}

SWITCH_DECLARE(void) switch_rtp_set_telephony_event(switch_rtp_t *rtp_session, switch_payload_t te)
{
    if (te > 95) {
        rtp_session->te = te;
    }
}


SWITCH_DECLARE(void) switch_rtp_set_telephony_recv_event(switch_rtp_t *rtp_session, switch_payload_t te)
{
    if (te > 95) {
        rtp_session->recv_te = te;
    }
}


SWITCH_DECLARE(void) switch_rtp_set_cng_pt(switch_rtp_t *rtp_session, switch_payload_t pt)
{
    rtp_session->cng_pt = pt;
    rtp_session->flags[SWITCH_RTP_FLAG_AUTO_CNG] = 1;
}

SWITCH_DECLARE(jb_t *) switch_rtp_get_jitter_buffer(switch_rtp_t *rtp_session)
{
    if (!switch_rtp_ready(rtp_session) || !rtp_session->jb) {
        return NULL;
    }

    return rtp_session->jb;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_pause_jitter_buffer(switch_rtp_t *rtp_session, switch_bool_t pause)
{

    if (!switch_rtp_ready(rtp_session) || !rtp_session->jb) {
        return SWITCH_STATUS_FALSE;
    }

    if (!!pause == !!rtp_session->pause_jb) {
        return SWITCH_STATUS_FALSE;
    }

    if (rtp_session->pause_jb && !pause) {
#ifdef _USE_NEW_JB_
        jb_reset(rtp_session->jb);
#else
        stfu_n_reset(rtp_session->jb);
#endif
    }

    rtp_session->pause_jb = pause ? 1 : 0;

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_deactivate_jitter_buffer(switch_rtp_t *rtp_session)
{

    if (!switch_rtp_ready(rtp_session) || !rtp_session->jb) {
        return SWITCH_STATUS_FALSE;
    }

    READ_INC(rtp_session);
    stfu_n_destroy(&rtp_session->jb);
    rtp_session->jb = NULL;
    READ_DEC(rtp_session);

    return SWITCH_STATUS_SUCCESS;
}

static void jb_logger(const char *file, const char *func, int line, int level, const char *fmt, ...)
{
    int ret;
    char *data;
    va_list ap;

    va_start(ap, fmt);
    ret = switch_vasprintf(&data, fmt, ap);
    if (ret != -1) {
        switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, func, line, NULL, SWITCH_LOG_CONSOLE, "%s", data);
        free(data);
    }

    //switch_log_printf(SWITCH_CHANNEL_ID_LOG_CLEAN, file, func, line, NULL, level, fmt, ap);
    va_end(ap);
}

SWITCH_DECLARE(switch_status_t) switch_rtp_debug_jitter_buffer(switch_rtp_t *rtp_session, const char *name)
{

    if (!switch_rtp_ready(rtp_session) || !rtp_session->jb) {
        return SWITCH_STATUS_FALSE;
    }

#ifndef _USE_NEW_JB_
    stfu_n_debug(rtp_session->jb, name);
    stfu_global_set_logger(jb_logger);
#endif

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_activate_jitter_buffer(switch_rtp_t *rtp_session,
                                                                  uint32_t queue_frames,
                                                                  uint32_t max_queue_frames,
                                                                  uint32_t samples_per_packet,
                                                                  uint32_t samples_per_second,
                                                                  uint32_t max_drift)
{

    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    if (rtp_session->use_webrtc_neteq == TRUE)
        return SWITCH_STATUS_FALSE;

    if (queue_frames < 1) {
        queue_frames = 3;
    }

    if (max_queue_frames < queue_frames) {
        max_queue_frames = queue_frames * 3;
    }

    READ_INC(rtp_session);
    if (rtp_session->jb) {
#ifdef _USE_NEW_JB_
        if (jb_get_buffer_size(rtp_session->jb) < queue_frames)
            jb_buffer_grow(rtp_session->jb, queue_frames - jb_get_buffer_size(rtp_session->jb));
#else
        stfu_n_resize(rtp_session->jb, queue_frames);
#endif
    } else {
#ifdef _USE_NEW_JB_
        rtp_session->jb = jb_init(rtp_session->pool, queue_frames,
                                max_queue_frames ? max_queue_frames : 50,
                                samples_per_packet, samples_per_second);
#else
        rtp_session->jb = stfu_n_init(queue_frames, max_queue_frames ? max_queue_frames : 50, samples_per_packet, samples_per_second, max_drift);
#endif
        register_log_cb(switch_log_print);
    }
    READ_DEC(rtp_session);

    if (rtp_session->jb) {
#ifndef _USE_NEW_JB_
        switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
                stfu_n_call_me(rtp_session->jb, jb_callback, session);
#endif
        return SWITCH_STATUS_SUCCESS;
    }

    return SWITCH_STATUS_FALSE;
}


SWITCH_DECLARE(switch_status_t) switch_rtp_activate_rtcp(switch_rtp_t *rtp_session, void *tbase, int send_rate, switch_port_t remote_port, switch_bool_t mux)
{
    const char *err = NULL;

    if (!rtp_session->ms_per_packet) {
        return SWITCH_STATUS_FALSE;
    }

    rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP] = 1;

    if (!(rtp_session->remote_rtcp_port = remote_port)) {
        rtp_session->remote_rtcp_port = rtp_session->remote_port + 1;
    }

    if (mux) {
        rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]++;
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "RTCP mux on\n");
    }


    if (send_rate == -1) {
        rtp_session->flags[SWITCH_RTP_FLAG_RTCP_PASSTHRU] = 1;
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "RTCP passthru enabled. Remote Port: %d\n", rtp_session->remote_rtcp_port);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "RTCP send rate is: %d and packet rate is: %d Remote Port: %d\n",                           send_rate, rtp_session->ms_per_packet, rtp_session->remote_rtcp_port);

        rtp_session->rtcp_interval = send_rate/(rtp_session->ms_per_packet/1000);
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {

        if (switch_sockaddr_info_get(&rtp_session->rtcp_remote_addr, rtp_session->eff_remote_host_str, SWITCH_UNSPEC,
                                     rtp_session->remote_rtcp_port, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS || !rtp_session->rtcp_remote_addr) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "RTCP MUX Remote Address Error!");
            return SWITCH_STATUS_FALSE;
        }

        rtp_session->rtcp_local_addr = rtp_session->local_addr;
        rtp_session->rtcp_from_addr = rtp_session->from_addr;
        rtp_session->rtcp_sock_input = rtp_session->sock_input;
        rtp_session->rtcp_sock_output = rtp_session->sock_output;

        rtp_session->rtcp_recv_msg_p = (rtcp_msg_t *) &rtp_session->recv_msg;

        return enable_remote_rtcp_socket(rtp_session, &err);
    } else {
        rtp_session->rtcp_recv_msg_p = (rtcp_msg_t *) &rtp_session->rtcp_recv_msg;
    }

    return enable_local_rtcp_socket(rtp_session, tbase, &err) || enable_remote_rtcp_socket(rtp_session, &err);

}

SWITCH_DECLARE(switch_status_t) switch_rtp_activate_ice(switch_rtp_t *rtp_session, char *login, char *rlogin,
                                                        const char *password, const char *rpassword, ice_proto_t proto,
                                                        switch_core_media_ice_type_t type, ice_t *ice_params)
{
    char ice_user[80];
    char user_ice[80];
    switch_rtp_ice_t *ice;
    char *host = NULL;
    switch_port_t port = 0;
    char bufc[30];


    if (proto == IPR_RTP) {
        ice = &rtp_session->ice;
    } else {
        ice = &rtp_session->rtcp_ice;
    }

    ice->proto = proto;

    if ((type & ICE_VANILLA)) {
        switch_snprintf(ice_user, sizeof(ice_user), "%s:%s", login, rlogin);
        switch_snprintf(user_ice, sizeof(user_ice), "%s:%s", rlogin, login);
        ice->ready = ice->rready = 0;
    } else {
        switch_snprintf(ice_user, sizeof(ice_user), "%s%s", login, rlogin);
        switch_snprintf(user_ice, sizeof(user_ice), "%s%s", rlogin, login);
        ice->ready = ice->rready = 1;
    }

    ice->ice_user = switch_core_strdup(rtp_session->pool, ice_user);
    ice->user_ice = switch_core_strdup(rtp_session->pool, user_ice);
    ice->type = type;
    ice->ice_params = ice_params;
    ice->pass = "";
    ice->rpass = "";
    ice->next_run = switch_micro_time_now();

    if (password) {
        ice->pass = switch_core_strdup(rtp_session->pool, password);
    }

    if (rpassword) {
        ice->rpass = switch_core_strdup(rtp_session->pool, rpassword);
    }

    if ((ice->type & ICE_VANILLA) && ice->ice_params) {
        host = ice->ice_params->cands[ice->ice_params->chosen[ice->proto]][ice->proto].con_addr;
        port = ice->ice_params->cands[ice->ice_params->chosen[ice->proto]][ice->proto].con_port;

        if (!host || !port || switch_sockaddr_info_get(&ice->addr, host, SWITCH_UNSPEC, port, 0, rtp_session->pool) != SWITCH_STATUS_SUCCESS || !ice->addr) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error setting remote host!\n");
            return SWITCH_STATUS_FALSE;
        }
    } else {
        if (proto == IPR_RTP) {
            ice->addr = rtp_session->remote_addr;
        } else {
            ice->addr = rtp_session->rtcp_remote_addr;
        }

        host = (char *)switch_get_addr(bufc, sizeof(bufc), ice->addr);
        port = switch_sockaddr_get_port(ice->addr);
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_NOTICE, "Activating %s %s ICE: %s %s:%d\n",
                      proto == IPR_RTP ? "RTP" : "RTCP", rtp_type(rtp_session), ice_user, host, port);


    rtp_session->rtp_bugs |= RTP_BUG_ACCEPT_ANY_PACKETS;


    if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
        rtp_session->flags[SWITCH_RTP_FLAG_VIDEO_BREAK] = 1;
        switch_rtp_break(rtp_session);
    }

    return SWITCH_STATUS_SUCCESS;
}


SWITCH_DECLARE(void) switch_rtp_flush(switch_rtp_t *rtp_session)
{
    if (!switch_rtp_ready(rtp_session)) {
        return;
    }

    switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_FLUSH);
}

SWITCH_DECLARE(void) switch_rtp_video_refresh(switch_rtp_t *rtp_session)
{
    if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] &&
        (rtp_session->ice.ice_user || rtp_session->flags[SWITCH_RTP_FLAG_FIR] || rtp_session->flags[SWITCH_RTP_FLAG_PLI])) {
        if (!rtp_session->fir_countdown) {
            rtp_session->fir_countdown = FIR_COUNTDOWN;
        }
    }
}

SWITCH_DECLARE(void) switch_rtp_break(switch_rtp_t *rtp_session)
{
    if (!switch_rtp_ready(rtp_session)) {
        return;
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
        int ret = 1;

        if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO_BREAK]) {
            rtp_session->flags[SWITCH_RTP_FLAG_VIDEO_BREAK] = 0;
            ret = 0;
        } else if (rtp_session->session) {
            switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);
            if (switch_channel_test_flag(channel, CF_VIDEO_BREAK)) {
                switch_channel_clear_flag(channel, CF_VIDEO_BREAK);
                ret = 0;
            }
        }

        if (ret) return;

        switch_rtp_video_refresh(rtp_session);
    }

    switch_mutex_lock(rtp_session->flag_mutex);
    rtp_session->flags[SWITCH_RTP_FLAG_BREAK] = 1;

    if (rtp_session->flags[SWITCH_RTP_FLAG_NOBLOCK]) {
        switch_mutex_unlock(rtp_session->flag_mutex);
        return;
    }

    if (rtp_session->sock_input) {
        ping_socket(rtp_session);
    }

    switch_mutex_unlock(rtp_session->flag_mutex);
}

SWITCH_DECLARE(void) switch_rtp_kill_socket(switch_rtp_t *rtp_session)
{
    switch_assert(rtp_session != NULL);
    switch_mutex_lock(rtp_session->flag_mutex);
    if (rtp_session->flags[SWITCH_RTP_FLAG_IO]) {
        rtp_session->flags[SWITCH_RTP_FLAG_IO] = 0;
        if (rtp_session->sock_input) {
            ping_socket(rtp_session);
            switch_socket_shutdown(rtp_session->sock_input, SWITCH_SHUTDOWN_READWRITE);
        }
        if (rtp_session->sock_output && rtp_session->sock_output != rtp_session->sock_input) {
            switch_socket_shutdown(rtp_session->sock_output, SWITCH_SHUTDOWN_READWRITE);
        }

        if (rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP]) {
            if (rtp_session->rtcp_sock_input) {
                ping_socket(rtp_session);
                switch_socket_shutdown(rtp_session->rtcp_sock_input, SWITCH_SHUTDOWN_READWRITE);
            }
            if (rtp_session->rtcp_sock_output && rtp_session->rtcp_sock_output != rtp_session->rtcp_sock_input) {
                switch_socket_shutdown(rtp_session->rtcp_sock_output, SWITCH_SHUTDOWN_READWRITE);
            }
        }
    }
    switch_mutex_unlock(rtp_session->flag_mutex);
}

SWITCH_DECLARE(uint8_t) switch_rtp_ready(switch_rtp_t *rtp_session)
{
    uint8_t ret;

    if (!rtp_session) {
        return 0;
    }
    
    if (!rtp_session->flag_mutex || rtp_session->flags[SWITCH_RTP_FLAG_SHUTDOWN]) {
        return 0;
    }

    switch_mutex_lock(rtp_session->flag_mutex);
        
    ret = (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_IO) &&
           (rtp_session->sock_input || rtp_session->rtp_conn) &&
           rtp_session->sock_output &&
           rtp_session->remote_addr &&
           rtp_session->ready == 2) ? 1 : 0;
    switch_mutex_unlock(rtp_session->flag_mutex);

    return ret;
}

SWITCH_DECLARE(void) switch_rtp_destroy(switch_rtp_t **rtp_session)
{
    void *pop;
    switch_socket_t *sock;
#ifdef ENABLE_SRTP
    int x;
#endif

    if (!rtp_session || !*rtp_session || !(*rtp_session)->ready) {
        return;
    }

    (*rtp_session)->flags[SWITCH_RTP_FLAG_SHUTDOWN] = 1;

    READ_INC((*rtp_session));
    WRITE_INC((*rtp_session));

    (*rtp_session)->ready = 0;

    READ_DEC((*rtp_session));
    WRITE_DEC((*rtp_session));

    do_mos(*rtp_session, SWITCH_TRUE);

    switch_mutex_lock((*rtp_session)->flag_mutex);

    switch_rtp_kill_socket(*rtp_session);

    while (switch_queue_trypop((*rtp_session)->dtmf_data.dtmf_inqueue, &pop) == SWITCH_STATUS_SUCCESS) {
        switch_safe_free(pop);
    }

    while (switch_queue_trypop((*rtp_session)->dtmf_data.dtmf_queue, &pop) == SWITCH_STATUS_SUCCESS) {
        switch_safe_free(pop);
    }

#ifndef _USE_NEW_JB_
    if ((*rtp_session)->jb) {
            stfu_n_destroy(&(*rtp_session)->jb);
    }
#endif

    if ((*rtp_session)->dtls && (*rtp_session)->dtls == (*rtp_session)->rtcp_dtls) {
        (*rtp_session)->rtcp_dtls = NULL;
    }

    if ((*rtp_session)->dtls) {
        free_dtls(&(*rtp_session)->dtls);
    }

    if ((*rtp_session)->rtcp_dtls) {
        free_dtls(&(*rtp_session)->rtcp_dtls);
    }


    sock = (*rtp_session)->sock_input;
    (*rtp_session)->sock_input = NULL;
    if (sock)
        switch_socket_close(sock);

    if ((*rtp_session)->sock_output != sock) {
        sock = (*rtp_session)->sock_output;
        (*rtp_session)->sock_output = NULL;
        if (sock)
            switch_socket_close(sock);
    }

    if ((sock = (*rtp_session)->rtcp_sock_input)) {
        (*rtp_session)->rtcp_sock_input = NULL;
        switch_socket_close(sock);

        if ((*rtp_session)->rtcp_sock_output && (*rtp_session)->rtcp_sock_output != sock) {
            if ((sock = (*rtp_session)->rtcp_sock_output)) {
                (*rtp_session)->rtcp_sock_output = NULL;
                switch_socket_close(sock);
            }
        }
    }

    if ((*rtp_session)->flags[SWITCH_RTP_FLAG_VAD]) {
        switch_rtp_disable_vad(*rtp_session);
    }

#ifdef ENABLE_SRTP
    if ((*rtp_session)->flags[SWITCH_RTP_FLAG_SECURE_SEND]) {
        for(x = 0; x < 2; x++) {
            if ((*rtp_session)->send_ctx[x]) {
                srtp_dealloc((*rtp_session)->send_ctx[x]);
                (*rtp_session)->send_ctx[x] = NULL;
            }
        }
        (*rtp_session)->flags[SWITCH_RTP_FLAG_SECURE_SEND] = 0;
    }

    if ((*rtp_session)->flags[SWITCH_RTP_FLAG_SECURE_RECV]) {
        for (x = 0; x < 2; x++) {
            if ((*rtp_session)->recv_ctx[x]) {
                srtp_dealloc((*rtp_session)->recv_ctx[x]);
                (*rtp_session)->recv_ctx[x] = NULL;
            }
        }
        (*rtp_session)->flags[SWITCH_RTP_FLAG_SECURE_RECV] = 0;
    }
#endif

#ifdef ENABLE_ZRTP
    /* ZRTP */
    if (zrtp_on && !(*rtp_session)->flags[SWITCH_RTP_FLAG_PROXY_MEDIA]) {

        if ((*rtp_session)->zrtp_stream != NULL) {
            zrtp_stream_stop((*rtp_session)->zrtp_stream);
        }

        if ((*rtp_session)->flags[SWITCH_ZRTP_FLAG_SECURE_SEND]) {
            (*rtp_session)->flags[SWITCH_ZRTP_FLAG_SECURE_SEND] = 0;
        }

        if ((*rtp_session)->flags[SWITCH_ZRTP_FLAG_SECURE_RECV]) {
            (*rtp_session)->flags[SWITCH_ZRTP_FLAG_SECURE_RECV] = 0;
        }

        if ((*rtp_session)->zrtp_session) {
            zrtp_session_down((*rtp_session)->zrtp_session);
            (*rtp_session)->zrtp_session = NULL;
        }
    }
#endif
    if ((*rtp_session)->timer.timer_interface) {
        switch_core_timer_destroy(&(*rtp_session)->timer);
    }

    switch_rtp_release_port((*rtp_session)->rx_host, (*rtp_session)->rx_port);

    if ((*rtp_session)->rtp_conn) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session), SWITCH_LOG_INFO, "fuze transport close rtp connection\n");
        fuze_transport_close_connection((*rtp_session)->rtp_conn);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session), SWITCH_LOG_INFO, "fuze transport NOT close rtp connection\n");
    }

    if ((*rtp_session)->rtcp_conn) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session), SWITCH_LOG_INFO, "fuze transport close rtcp connection\n");
        fuze_transport_close_connection((*rtp_session)->rtcp_conn);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session), SWITCH_LOG_INFO, "fuze transport NOT close rtcp connection\n");
    }

    switch_mutex_unlock((*rtp_session)->flag_mutex);

    return;
}

SWITCH_DECLARE(void) switch_rtp_set_interdigit_delay(switch_rtp_t *rtp_session, uint32_t delay)
{
    rtp_session->interdigit_delay = delay;
}

SWITCH_DECLARE(switch_socket_t *) switch_rtp_get_rtp_socket(switch_rtp_t *rtp_session)
{
    return rtp_session->sock_input;
}

SWITCH_DECLARE(uint32_t) switch_rtp_get_default_samples_per_interval(switch_rtp_t *rtp_session)
{
    return rtp_session->samples_per_interval;
}

SWITCH_DECLARE(void) switch_rtp_set_default_payload(switch_rtp_t *rtp_session, switch_payload_t payload)
{
    rtp_session->payload = payload;
}

SWITCH_DECLARE(uint32_t) switch_rtp_get_default_payload(switch_rtp_t *rtp_session)
{
    return rtp_session->payload;
}

SWITCH_DECLARE(void) switch_rtp_set_invald_handler(switch_rtp_t *rtp_session, switch_rtp_invalid_handler_t on_invalid)
{
    rtp_session->invalid_handler = on_invalid;
}

SWITCH_DECLARE(void) switch_rtp_set_flags(switch_rtp_t *rtp_session, switch_rtp_flag_t flags[SWITCH_RTP_FLAG_INVALID])
{
    int i;

    for(i = 0; i < SWITCH_RTP_FLAG_INVALID; i++) {
        if (flags[i]) {
            rtp_session->flags[i] = flags[i];

            if (i == SWITCH_RTP_FLAG_AUTOADJ) {
                rtp_session->autoadj_window = 20;
                rtp_session->autoadj_tally = 0;
                rtp_flush_read_buffer(rtp_session, SWITCH_RTP_FLUSH_ONCE);
            } else if (i == SWITCH_RTP_FLAG_NOBLOCK && rtp_session->sock_input) {
                switch_socket_opt_set(rtp_session->sock_input, SWITCH_SO_NONBLOCK, TRUE);
            }
        }
    }
}

SWITCH_DECLARE(void) switch_rtp_clear_flags(switch_rtp_t *rtp_session, switch_rtp_flag_t flags[SWITCH_RTP_FLAG_INVALID])
{
    int i;

    for(i = 0; i < SWITCH_RTP_FLAG_INVALID; i++) {
        if (flags[i]) {
            rtp_session->flags[i] = 0;
        }
    }
}

SWITCH_DECLARE(void) switch_rtp_set_flag(switch_rtp_t *rtp_session, switch_rtp_flag_t flag)
{

    switch_mutex_lock(rtp_session->flag_mutex);
    rtp_session->flags[flag] = 1;
    switch_mutex_unlock(rtp_session->flag_mutex);

    if (flag == SWITCH_RTP_FLAG_DTMF_ON) {
        rtp_session->stats.inbound.last_processed_seq = 0;
    } else if (flag == SWITCH_RTP_FLAG_FLUSH) {
        reset_jitter_seq(rtp_session);
    } else if (flag == SWITCH_RTP_FLAG_AUTOADJ) {
        rtp_session->autoadj_window = 20;
        rtp_session->autoadj_threshold = 10;
        rtp_session->autoadj_tally = 0;
        if (rtp_session->session) {
            switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);
            const char *x = switch_channel_get_variable(channel, "rtp_auto_adjust_threshold");
            if (x && *x) {
                int xn = atoi(x);
                if (xn > 0 && xn <= 65535) {
                    rtp_session->autoadj_window = xn*2;
                    rtp_session->autoadj_threshold = xn;
                }
            }
        }
        rtp_flush_read_buffer(rtp_session, SWITCH_RTP_FLUSH_ONCE);
        if (rtp_session->jb) {
            stfu_n_reset(rtp_session->jb);
        }
    } else if (flag == SWITCH_RTP_FLAG_NOBLOCK && rtp_session->sock_input) {
        switch_socket_opt_set(rtp_session->sock_input, SWITCH_SO_NONBLOCK, TRUE);
    }

}

SWITCH_DECLARE(uint32_t) switch_rtp_test_flag(switch_rtp_t *rtp_session, switch_rtp_flag_t flags)
{
    return (uint32_t) rtp_session->flags[flags];
}

SWITCH_DECLARE(void) switch_rtp_clear_flag(switch_rtp_t *rtp_session, switch_rtp_flag_t flag)
{

    switch_mutex_lock(rtp_session->flag_mutex);
    rtp_session->flags[flag] = 0;
    switch_mutex_unlock(rtp_session->flag_mutex);

    if (flag == SWITCH_RTP_FLAG_DTMF_ON) {
        rtp_session->stats.inbound.last_processed_seq = 0;
    } else if (flag == SWITCH_RTP_FLAG_PAUSE) {
        reset_jitter_seq(rtp_session);
    } else if (flag == SWITCH_RTP_FLAG_NOBLOCK && rtp_session->sock_input) {
        switch_socket_opt_set(rtp_session->sock_input, SWITCH_SO_NONBLOCK, FALSE);
    }
}

static void set_dtmf_delay(switch_rtp_t *rtp_session, uint32_t ms, uint32_t max_ms)
{
    int upsamp, max_upsamp;


    if (!max_ms) max_ms = ms;

    upsamp = ms * (rtp_session->samples_per_second / 1000);
    max_upsamp = max_ms * (rtp_session->samples_per_second / 1000);

    rtp_session->queue_delay = upsamp;

    if (rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER]) {
        rtp_session->max_next_write_samplecount = rtp_session->timer.samplecount + max_upsamp;
        rtp_session->next_write_samplecount = rtp_session->timer.samplecount + upsamp;
        rtp_session->last_write_ts += upsamp;
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Queue digit delay of %dms\n", ms);
}

static switch_bool_t do_2833(switch_rtp_t *rtp_session)
{
    switch_frame_flag_t flags = 0;
    uint32_t samples = rtp_session->samples_per_interval;
    switch_bool_t ret = SWITCH_FALSE;

    if (!rtp_session->last_write_ts) {
        return ret;
    }

    if (rtp_session->dtmf_data.out_digit_dur > 0) {
        int x, loops = 1;

        rtp_session->dtmf_data.out_digit_sofar += samples;
        rtp_session->dtmf_data.out_digit_sub_sofar += samples;

        if (rtp_session->dtmf_data.out_digit_sub_sofar > 0xFFFF) {
            rtp_session->dtmf_data.out_digit_sub_sofar = samples;
            rtp_session->dtmf_data.timestamp_dtmf += 0xFFFF;
        }

        if (rtp_session->dtmf_data.out_digit_sofar >= rtp_session->dtmf_data.out_digit_dur) {
            rtp_session->dtmf_data.out_digit_packet[1] |= 0x80;
            loops = 3;
        }

        rtp_session->dtmf_data.out_digit_packet[2] = (unsigned char) (rtp_session->dtmf_data.out_digit_sub_sofar >> 8);
        rtp_session->dtmf_data.out_digit_packet[3] = (unsigned char) rtp_session->dtmf_data.out_digit_sub_sofar;

        for (x = 0; x < loops; x++) {
            switch_size_t wrote = switch_rtp_write_manual(rtp_session,
                                                          rtp_session->dtmf_data.out_digit_packet, 4, 0,
                                                          rtp_session->te, rtp_session->dtmf_data.timestamp_dtmf, &flags);
            ret = SWITCH_TRUE;

            rtp_session->stats.outbound.raw_bytes += wrote;
            rtp_session->stats.outbound.dtmf_packet_count++;

            if (loops == 1) {
                if (rtp_session->rtp_bugs & RTP_BUG_SONUS_SEND_INVALID_TIMESTAMP_2833) {
                    rtp_session->dtmf_data.timestamp_dtmf = rtp_session->last_write_ts;
                }
            }

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Send %s packet for [%c] ts=%u dur=%d/%d/%d seq=%d lw=%u\n",
                              loops == 1 ? "middle" : "end", rtp_session->dtmf_data.out_digit,
                              rtp_session->dtmf_data.timestamp_dtmf,
                              rtp_session->dtmf_data.out_digit_sofar,
                              rtp_session->dtmf_data.out_digit_sub_sofar, rtp_session->dtmf_data.out_digit_dur,
                              rtp_session->last_bridge_seq[1], rtp_session->last_write_ts);
        }

        if (loops != 1) {
            rtp_session->sending_dtmf = 0;
            rtp_session->sync_seq_no = SWITCH_TRUE;
            rtp_session->need_mark = 1;

            if (rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER]) {
                rtp_session->last_write_samplecount = rtp_session->timer.samplecount;
            }

            rtp_session->dtmf_data.out_digit_dur = 0;

            if (rtp_session->interdigit_delay) {
                set_dtmf_delay(rtp_session, rtp_session->interdigit_delay, rtp_session->interdigit_delay * 10);
            }

            return ret;
        }
    }

    if (!rtp_session->dtmf_data.out_digit_dur && rtp_session->dtmf_data.dtmf_queue && switch_queue_size(rtp_session->dtmf_data.dtmf_queue)) {
        void *pop;

        if (rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER]) {
            if (rtp_session->timer.samplecount < rtp_session->next_write_samplecount) {
                return ret;
            }

            if (rtp_session->timer.samplecount >= rtp_session->max_next_write_samplecount) {
                rtp_session->queue_delay = 0;
            }

        } else if (rtp_session->queue_delay) {
            if (rtp_session->delay_samples >= rtp_session->samples_per_interval) {
                rtp_session->delay_samples -= rtp_session->samples_per_interval;
            } else {
                rtp_session->delay_samples = 0;
            }

            if (!rtp_session->delay_samples) {
                rtp_session->queue_delay = 0;
            }
        }

        if (rtp_session->queue_delay) {
            return ret;
        }


        if (!rtp_session->sending_dtmf) {
            rtp_session->sending_dtmf = 1;
        }

        if (switch_queue_trypop(rtp_session->dtmf_data.dtmf_queue, &pop) == SWITCH_STATUS_SUCCESS) {
            switch_dtmf_t *rdigit = pop;
            switch_size_t wrote;

            if (rdigit->digit == 'w') {
                set_dtmf_delay(rtp_session, 500, 0);
                free(rdigit);
                return ret;
            }

            if (rdigit->digit == 'W') {
                set_dtmf_delay(rtp_session, 1000, 0);
                free(rdigit);
                return ret;
            }



            memset(rtp_session->dtmf_data.out_digit_packet, 0, 4);
            rtp_session->dtmf_data.out_digit_sofar = samples;
            rtp_session->dtmf_data.out_digit_sub_sofar = samples;
            rtp_session->dtmf_data.out_digit_dur = rdigit->duration;
            rtp_session->dtmf_data.out_digit = rdigit->digit;
            rtp_session->dtmf_data.out_digit_packet[0] = (unsigned char) switch_char_to_rfc2833(rdigit->digit);
            rtp_session->dtmf_data.out_digit_packet[1] = 13;
            rtp_session->dtmf_data.out_digit_packet[2] = (unsigned char) (rtp_session->dtmf_data.out_digit_sub_sofar >> 8);
            rtp_session->dtmf_data.out_digit_packet[3] = (unsigned char) rtp_session->dtmf_data.out_digit_sub_sofar;


            rtp_session->dtmf_data.timestamp_dtmf = rtp_session->last_write_ts + samples;
            rtp_session->last_write_ts = rtp_session->dtmf_data.timestamp_dtmf;
            rtp_session->flags[SWITCH_RTP_FLAG_RESET] = 0;

            wrote = switch_rtp_write_manual(rtp_session,
                                            rtp_session->dtmf_data.out_digit_packet,
                                            4,
                                            rtp_session->rtp_bugs & RTP_BUG_CISCO_SKIP_MARK_BIT_2833 ? 0 : 1,
                                            rtp_session->te, rtp_session->dtmf_data.timestamp_dtmf, &flags);

            ret = SWITCH_TRUE;

            rtp_session->stats.outbound.raw_bytes += wrote;
            rtp_session->stats.outbound.dtmf_packet_count++;

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Send start packet for [%c] ts=%u dur=%d/%d/%d seq=%d lw=%u\n",
                              rtp_session->dtmf_data.out_digit,
                              rtp_session->dtmf_data.timestamp_dtmf,
                              rtp_session->dtmf_data.out_digit_sofar,
                              rtp_session->dtmf_data.out_digit_sub_sofar, rtp_session->dtmf_data.out_digit_dur, rtp_session->seq, rtp_session->last_write_ts);

            free(rdigit);
        }
    }

    return ret;
}

SWITCH_DECLARE(void) rtp_flush_read_buffer(switch_rtp_t *rtp_session, switch_rtp_flush_t flush)
{

    if (rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] ||
        rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] ||
        rtp_session->flags[SWITCH_RTP_FLAG_UDPTL]) {
        return;
    }


    if (switch_rtp_ready(rtp_session)) {
        rtp_session->flags[SWITCH_RTP_FLAG_RESET] = 1;
        rtp_session->flags[SWITCH_RTP_FLAG_FLUSH] = 1;
        reset_jitter_seq(rtp_session);

        switch (flush) {
        case SWITCH_RTP_FLUSH_STICK:
            switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_STICKY_FLUSH);
            break;
        case SWITCH_RTP_FLUSH_UNSTICK:
            switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_STICKY_FLUSH);
            break;
        default:
                break;
        }
    }
}

static int jb_valid(switch_rtp_t *rtp_session)
{
    if (rtp_session->ice.ice_user) {
        if (!rtp_session->ice.ready && rtp_session->ice.rready) {
            return 0;
        }
    }

    if (rtp_session->dtls && rtp_session->dtls->state != DS_READY) {
        return 0;
    }

    return 1;
}


static void do_flush(switch_rtp_t *rtp_session, int force)
{
    int was_blocking = 0;
    switch_size_t bytes;
    uint32_t flushed = 0;

    if (!switch_rtp_ready(rtp_session)) {
        return;
    }
    reset_jitter_seq(rtp_session);

    if (!force) {
        if (rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] ||
            rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] ||
            rtp_session->flags[SWITCH_RTP_FLAG_UDPTL] ||
            rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON]
            ) {
            return;
        }
    }

    READ_INC(rtp_session);

    if (switch_rtp_ready(rtp_session) ) {

        if (rtp_session->jb && !rtp_session->pause_jb && jb_valid(rtp_session)) {
            goto end;
        }

        if (rtp_session->flags[SWITCH_RTP_FLAG_DEBUG_RTP_READ]) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session),
                  SWITCH_LOG_CONSOLE, "%s FLUSH\n",
                  rtp_session->session ? switch_channel_get_name(switch_core_session_get_channel(rtp_session->session)) : "NoName"
                  );
        }

        if (!rtp_session->flags[SWITCH_RTP_FLAG_NOBLOCK]) {
            was_blocking = 1;
            switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_NOBLOCK);
            switch_socket_opt_set(rtp_session->sock_input, SWITCH_SO_NONBLOCK, TRUE);
        }

        do {
            if (switch_rtp_ready(rtp_session)) {
                switch_status_t status;
                bytes = sizeof(rtp_msg_t);
                status = rtp_recvfrom(rtp_session, rtp_session->from_addr, rtp_session->sock_input, 0, (void *) &rtp_session->recv_msg, &bytes);

                if (status != SWITCH_STATUS_SUCCESS) {
                    break;
                }
                if (bytes) {
                    int do_cng = 0;

                    /* Make sure to handle RFC2833 packets, even if we're flushing the packets */
                    if (bytes > rtp_header_len && rtp_session->recv_te && rtp_session->recv_msg.header.pt == rtp_session->recv_te) {
                        handle_rfc2833(rtp_session, bytes, &do_cng);
#ifdef DEBUG_2833
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "*** RTP packet handled in flush loop %d ***\n", do_cng);
#endif
                    }

                    flushed++;

                    rtp_session->stats.inbound.raw_bytes += bytes;
                    rtp_session->stats.inbound.flush_packet_count++;
                    rtp_session->stats.inbound.packet_count++;
                }
            } else {
                break;
            }
        } while (bytes > 0);

#ifndef _USE_NEW_JB_
    if (rtp_session->jb && flushed) {
            stfu_n_sync(rtp_session->jb, flushed);
        }
#endif

        if (was_blocking && switch_rtp_ready(rtp_session)) {
            switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_NOBLOCK);
            switch_socket_opt_set(rtp_session->sock_input, SWITCH_SO_NONBLOCK, FALSE);
        }
    }

 end:

    READ_DEC(rtp_session);
}

static int check_recv_payload(switch_rtp_t *rtp_session)
{
    int ok = 1;

    if (rtp_session->pmaps && *rtp_session->pmaps) {
        payload_map_t *pmap;
        ok = 0;

        switch_mutex_lock(rtp_session->flag_mutex);

        for (pmap = *rtp_session->pmaps; pmap && pmap->allocated; pmap = pmap->next) {
            if (!pmap->negotiated) {
                continue;
            }

            if (rtp_session->recv_msg.header.pt == pmap->pt) {
                ok = 1;
            }
        }
        switch_mutex_unlock(rtp_session->flag_mutex);
    }

    return ok;
}

#define return_cng_frame() do_cng = 1; goto timer_check

/* fuze: xxx */
static switch_status_t read_rtp_packet(switch_rtp_t *rtp_session, switch_size_t *bytes, switch_frame_flag_t *flags, switch_bool_t return_jb_packet)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    jb_frame_t *jb_frame;
    uint32_t ts = 0;
    unsigned char *b = NULL;
    int sync = 0;
    switch_time_t now = switch_time_now();
    switch_size_t xcheck_jitter = 0;
    switch_size_t ebytes;
    switch_assert(bytes);

 more:

    now = switch_time_now();

    *bytes = sizeof(rtp_msg_t);
    sync = 0;

    memset(&rtp_session->recv_msg, 0, sizeof(rtp_session->recv_msg));

    status = rtp_recvfrom(rtp_session, rtp_session->from_addr, rtp_session->sock_input, 0, (void *) &rtp_session->recv_msg, bytes);
    now = switch_time_now() - now;
    if (now > 1000) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG10,
                          "long rtp_recvfrom %" PRId64 "\n", now);
    }
    ts = ntohl(rtp_session->recv_msg.header.ts);

    ebytes = *bytes;

    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    
    if (*bytes) {
        rtp_session->missed_count = 0;
    }

    if (!rtp_session->jb || rtp_session->pause_jb || !jb_valid(rtp_session)) {
        if (*bytes > rtp_header_len && (rtp_session->recv_msg.header.version == 2 && check_recv_payload(rtp_session))) {
            xcheck_jitter = *bytes;
            check_jitter(rtp_session);
        }
    }

    if (check_rtcp_and_ice(rtp_session) == -1) {
        return SWITCH_STATUS_GENERR;
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_UDPTL]) {
        goto udptl;
    }

    if (*bytes) {
        b = (unsigned char *) &rtp_session->recv_msg;

        *flags &= ~SFF_PROXY_PACKET;

        if (*b == 0 || *b == 1) {
            if (rtp_session->ice.ice_user) {
                handle_ice(rtp_session, &rtp_session->ice, (void *) &rtp_session->recv_msg, *bytes);
            }
            *bytes = 0;
            ebytes = 0;
            sync = 1;
        }
    }

    if (rtp_session->dtls) {

        if (rtp_session->rtcp_dtls && rtp_session->rtcp_dtls != rtp_session->dtls) {
            rtp_session->rtcp_dtls->bytes = 0;
            rtp_session->rtcp_dtls->data = NULL;
            do_dtls(rtp_session, rtp_session->rtcp_dtls);
        }

        rtp_session->dtls->bytes = 0;

        if (*bytes) {
            char *b = (char *) &rtp_session->recv_msg;

            if ((*b >= 20) && (*b <= 64)) {
                rtp_session->dtls->bytes = *bytes;
                rtp_session->dtls->data = (void *) &rtp_session->recv_msg;
            } else {
                rtp_session->dtls->bytes = 0;
                rtp_session->dtls->data = NULL;

                if (*b != 0 && *b != 1 && rtp_session->dtls->state != DS_READY) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1,
                                      "Drop %s packet %ld bytes (dtls not ready!) b=%u\n", rtp_type(rtp_session), (long)*bytes, *b);
                    *bytes = 0;
                    ebytes = 0;
                }

            }
        }

        do_dtls(rtp_session, rtp_session->dtls);

        if (rtp_session->dtls->bytes) {
            *bytes = 0;
            ebytes = 0;
            sync = 1;
        }
    }

    if (rtp_session->recv_msg.header.m) {
        *flags |= SFF_MARKER;
    } else {
        *flags &= ~SFF_MARKER;
    }

    if (rtp_session->recv_msg.header.version == 2 &&
        rtp_session->recv_msg.header.m == 1 &&
        rtp_session->recv_msg.header.pt > 71 && rtp_session->recv_msg.header.pt < 81) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "received rtcp packet on RTP channel pt=%u\n", rtp_session->recv_msg.header.pt);
            *flags |= SFF_RTCP;
            rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]++;
            //*bytes = 0;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                              "dropping\n");
            return SWITCH_STATUS_SUCCESS;
    }

    /* xxx: rtcp mux */
    if (status == SWITCH_STATUS_SUCCESS && *bytes) {
        if (rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
            *flags &= ~SFF_RTCP;
            if (!check_recv_payload(rtp_session)  &&
                (!rtp_session->recv_te || rtp_session->recv_msg.header.pt != rtp_session->recv_te) &&
                (!rtp_session->cng_pt || rtp_session->recv_msg.header.pt != rtp_session->cng_pt) &&
                rtp_session->rtcp_recv_msg_p->header.version == 2 &&
                rtp_session->rtcp_recv_msg_p->header.type > 199 && rtp_session->rtcp_recv_msg_p->header.type < 208) { //rtcp muxed
                *flags |= SFF_RTCP;
                return SWITCH_STATUS_SUCCESS;
            }
        }
    }


    if (*bytes && rtp_session->flags[SWITCH_RTP_FLAG_DEBUG_RTP_READ]) {
        const char *tx_host;
        const char *old_host;
        const char *my_host;

        char bufa[30], bufb[30], bufc[30];


        tx_host = switch_get_addr(bufa, sizeof(bufa), rtp_session->from_addr);
        old_host = switch_get_addr(bufb, sizeof(bufb), rtp_session->remote_addr);
        my_host = switch_get_addr(bufc, sizeof(bufc), rtp_session->local_addr);

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG_CLEAN(rtp_session->session), SWITCH_LOG_CONSOLE,
                          "R %s b=%4ld %s:%u %s:%u %s:%u seq=%d ts=%u m=%d\n",
                          //"R %s b=%4ld %s:%u %s:%u %s:%u pt=%d ts=%u m=%d\n",
                          rtp_session->session ? switch_channel_get_name(switch_core_session_get_channel(rtp_session->session)) : "No-Name",
                          (long) *bytes,
                          my_host, switch_sockaddr_get_port(rtp_session->local_addr),
                          old_host, rtp_session->remote_port,
                          tx_host, switch_sockaddr_get_port(rtp_session->from_addr),
                          ntohs(rtp_session->recv_msg.header.seq), ntohl(rtp_session->recv_msg.header.ts), rtp_session->recv_msg.header.m);
                          // rtp_session->recv_msg.header.pt, ntohl(rtp_session->recv_msg.header.ts), rtp_session->recv_msg.header.m);

    }


    if (sync) {
        if (!rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER] && rtp_session->timer.interval && !rtp_session->dontwait) {
            switch_core_timer_sync(&rtp_session->timer);
            reset_jitter_seq(rtp_session);
        }
        goto more;
    }


 udptl:

    ts = 0;
    rtp_session->recv_msg.ebody = NULL;
    now = switch_micro_time_now();

    if (*bytes && rtp_session->recv_msg.header.version == 2) {
        uint16_t seq = ntohs((uint16_t) rtp_session->recv_msg.header.seq);
        ts = ntohl(rtp_session->recv_msg.header.ts);

        if (!rtp_session->stats.cur_period_start_time) {
            rtp_session->stats.cur_period_start_time = switch_micro_time_now();
            rtp_session->stats.period_received = 0;
            rtp_session->stats.period_skip_packet_count = 0;
        }
        rtp_session->total_received++;
        rtp_session->stats.period_received++;
        /* set over audio threshold flag, it will be cleared if under threshold is signalled */
        *flags |= SFF_RTP_AUDIO_OVER_THR;

        if (!rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] && !rtp_session->flags[SWITCH_RTP_FLAG_UDPTL] &&
            rtp_session->recv_msg.header.version == 2 && rtp_session->recv_msg.header.x) { /* header extensions */
            uint16_t length;
            uint16_t profile;
            uint8_t ext_audio_level;

            rtp_session->recv_msg.ext = (switch_rtp_hdr_ext_t *) rtp_session->recv_msg.body;
            rtp_session->recv_msg.audio_lvl = (switch_rtp_audio_lvl_t *)(&rtp_session->recv_msg.body[4]);
            length = ntohs((uint16_t)rtp_session->recv_msg.ext->length);
            profile = ntohs((uint16_t)rtp_session->recv_msg.ext->profile);

            if (profile == 0xBEDE) {
                /* check ID */
                ext_audio_level = rtp_session->recv_msg.audio_lvl->audio_level;

                if (ext_audio_level > 51) {
                    /*clear flag SFF_RTP_AUDIO_OVER_THR */
                    *flags &= ~SFF_RTP_AUDIO_OVER_THR;
                }
            } else {
                /* something isn't quite right as we don't expect other profiles today */
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR,
                                  "ERROR: RTP Packet with extension bit set profile=0x%x len=%d pt=%d. Dropping it.\n",
                                  profile, length, rtp_session->recv_msg.header.pt);
                *bytes = 0;
                return SWITCH_STATUS_SUCCESS;
            }

            if (length < SWITCH_RTP_MAX_BUF_LEN_WORDS) {
                rtp_session->recv_msg.ebody = rtp_session->recv_msg.body + (length * 4) + 4;
                *bytes -= ((length * 4) + 4);
            }
        }

        if (rtp_session->last_seq && rtp_session->last_seq+1 != seq) {
            //2012-11-28 18:33:11.799070 [ERR] switch_rtp.c:2883 Missed -65536 RTP frames from sequence [65536] to [-1] (missed). Time since last read [20021]
            switch_size_t flushed_packets_diff = rtp_session->stats.inbound.flush_packet_count - rtp_session->last_flush_packet_count;
            switch_size_t num_missed = (switch_size_t)seq - (rtp_session->last_seq+1);

            if (num_missed == 1) { /* We missed one packet */
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG10, "Missed one RTP frame with sequence [%d]%s. Time since last read [%ld]\n",
                                  rtp_session->last_seq+1, (flushed_packets_diff == 1) ? " (flushed by FS)" : " (missed)",
                                  rtp_session->last_read_time ? now-rtp_session->last_read_time : 0);
            } else { /* We missed multiple packets */
                if (flushed_packets_diff == 0) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG10,
                                      "Missed %ld RTP frames from sequence [%d] to [%d] (missed). Time since last read [%ld]\n",
                                      num_missed, rtp_session->last_seq+1, seq-1,
                                      rtp_session->last_read_time ? now-rtp_session->last_read_time : 0);
                } else if (flushed_packets_diff == num_missed) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG10,
                                      "Missed %ld RTP frames from sequence [%d] to [%d] (flushed by FS). Time since last read [%ld]\n",
                                      num_missed, rtp_session->last_seq+1, seq-1,
                                      rtp_session->last_read_time ? now-rtp_session->last_read_time : 0);
                } else if (num_missed > flushed_packets_diff) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG10,
                                      "Missed %ld RTP frames from sequence [%d] to [%d] (%ld packets flushed by FS, %ld packets missed)."
                                      " Time since last read [%ld]\n",
                                      num_missed, rtp_session->last_seq+1, seq-1,
                                      flushed_packets_diff, num_missed-flushed_packets_diff,
                                      rtp_session->last_read_time ? now-rtp_session->last_read_time : 0);
                } else {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG10,
                                      "Missed %ld RTP frames from sequence [%d] to [%d] (%ld packets flushed by FS). Time since last read [%ld]\n",
                                      num_missed, rtp_session->last_seq+1, seq-1,
                                      flushed_packets_diff, rtp_session->last_read_time ? now-rtp_session->last_read_time : 0);
                }
            }

        }
        if ((seq < rtp_session->last_seq) &&
                (rtp_session->last_seq - seq > UINT16_MAX - rtp_session->last_seq + seq)) {
            rtp_session->seq_rollover++;
        }
        rtp_session->last_seq = seq;

        if (!rtp_session->base_seq) {
            rtp_session->base_seq = seq;
            rtp_session->stats.rtcp.last_expected = seq;
            if (rtp_session->use_webrtc_neteq != SWITCH_TRUE) {
                rtp_session->seq += 1;
            }
            rtp_session->base_seq_set = SWITCH_TRUE;
        }

        /*
         * Lets ignore the out of order and rolledover
         * timestamps for jitter calculations.
         */
        now = switch_micro_time_now();

        if (rtp_session->high_drift_log_suppress > 0) {
            rtp_session->high_drift_log_suppress -= 1;
        }

        if (rtp_session->last_read_time && rtp_session->last_ts && (ts > rtp_session->last_ts)) {
            uint32_t samples_diff;
            int32_t drift, drift_ms;

            samples_diff = ((now - rtp_session->last_read_time) * rtp_session->samples_per_second) / 1000000;
            drift = samples_diff - (ts - rtp_session->last_ts);
            if (drift < 0)
                drift = -1 * drift;

            drift_ms = (drift * 1000) / rtp_session->samples_per_second;
            if (drift_ms > RTP_EVENT_DRIFT_THRESHOLD_MS) {
                rtp_session->stats.rtcp.last_drift = drift_ms;
                *flags |= SFF_RTP_EVENT;
                rtp_session->stats.last_event |= RTP_EVENT_HIGH_DRIFT;
                
                rtp_session->high_drift_packets += 1;

                if (rtp_session->high_drift_log_suppress == 0) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                                      "High drift cnt:%u ms:%u ssrc=%#x samples_diff=%u now=%lu last=%lu ts=%u last_ts=%u jitter=%u seq=%u.\n",
                                      rtp_session->high_drift_packets, drift_ms, ntohl(rtp_session->recv_msg.header.ssrc), samples_diff, now,
                                      rtp_session->last_read_time, ts, rtp_session->last_ts, rtp_session->stats.rtcp.jitter, seq);
                    rtp_session->high_drift_log_suppress = 50;
                }
            } else if (!(rtp_session->stats.last_event & RTP_EVENT_HIGH_DRIFT)) {
                rtp_session->stats.rtcp.last_drift = drift_ms;
            }
            if (drift_ms > rtp_session->stats.rtcp.max_drift)
                rtp_session->stats.rtcp.max_drift = drift_ms;

            rtp_session->stats.rtcp.jitter += (1.0/16.0) * ((double)drift - rtp_session->stats.rtcp.jitter);
            if (rtp_session->stats.rtcp.jitter > rtp_session->stats.rtcp.max_jitter)
                rtp_session->stats.rtcp.max_jitter = rtp_session->stats.rtcp.jitter;
        }

        if (!rtp_session->time_of_first_rx_ts || (abs(ts - rtp_session->last_ts) > 16000)) {
            rtp_session->time_of_first_rx_ts = now;
            rtp_session->first_rx_ts = ts;
        }

        rtp_session->last_read_time = now;
        rtp_session->last_ts = ts;
    }

    rtp_session->last_flush_packet_count = rtp_session->stats.inbound.flush_packet_count;

    /* MQT-2858 */
    if (rtp_session->use_webrtc_neteq == SWITCH_TRUE) {
        if (!rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] && !rtp_session->flags[SWITCH_RTP_FLAG_UDPTL] && !rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] &&
            *bytes && (!rtp_session->recv_te || rtp_session->recv_msg.header.pt != rtp_session->recv_te) &&
            ts && !rtp_session->jb && !rtp_session->pause_jb && jb_valid(rtp_session) && ts == rtp_session->last_cng_ts) {
            /* we already sent this frame..... */
            *bytes = 0;
            return SWITCH_STATUS_SUCCESS;
        }
    }

    if (*bytes) {
        rtp_session->stats.inbound.raw_bytes += *bytes;
        if (rtp_session->recv_te && rtp_session->recv_msg.header.pt == rtp_session->recv_te) {
            rtp_session->stats.inbound.dtmf_packet_count++;
        } else if (rtp_session->cng_pt && (rtp_session->recv_msg.header.pt == rtp_session->cng_pt || rtp_session->recv_msg.header.pt == 13)) {
            rtp_session->stats.inbound.cng_packet_count++;
        } else {
            rtp_session->stats.inbound.media_packet_count++;
            rtp_session->stats.inbound.media_bytes += *bytes;
        }

        rtp_session->stats.inbound.packet_count++;


        if (!rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] && !rtp_session->flags[SWITCH_RTP_FLAG_UDPTL]) {
#ifdef ENABLE_ZRTP
            /* ZRTP Recv */
            if (zrtp_on) {

                unsigned int sbytes = (unsigned int) ebytes;
                zrtp_status_t stat = 0;

                stat = zrtp_process_srtp(rtp_session->zrtp_stream, (void *) &rtp_session->recv_msg, &sbytes);

                switch (stat) {
                case zrtp_status_ok:
                    *bytes = sbytes;
                    break;
                case zrtp_status_drop:
                    /* switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Error: zRTP protection drop with code %d\n", stat); */
                    *bytes = 0;
                    return SWITCH_STATUS_SUCCESS;
                case zrtp_status_fail:
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection fail with code %d\n", stat);
                    return SWITCH_STATUS_FALSE;
                default:
                    break;
                }
            }
#endif

#ifdef ENABLE_SRTP
            if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV] && rtp_session->recv_msg.header.version == 2 &&
                ((check_recv_payload(rtp_session) ||
                 (rtp_session->recv_te && rtp_session->recv_msg.header.pt == rtp_session->recv_te) ||
                 (rtp_session->cng_pt && rtp_session->recv_msg.header.pt == rtp_session->cng_pt)) ||
                 (rtp_session->recv_msg.header.pt == 13))) {
                //if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV] && (!rtp_session->ice.ice_user || rtp_session->recv_msg.header.version == 2)) {
                int sbytes = (int) ebytes;
                err_status_t stat = 0;

                if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV_RESET]) {
                    switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_SECURE_RECV_RESET);
                    srtp_dealloc(rtp_session->recv_ctx[rtp_session->srtp_idx_rtp]);
                    rtp_session->recv_ctx[rtp_session->srtp_idx_rtp] = NULL;
                    if ((stat = srtp_create(&rtp_session->recv_ctx[rtp_session->srtp_idx_rtp], &rtp_session->recv_policy[rtp_session->srtp_idx_rtp]))) {

                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error! RE-Activating Secure RTP RECV\n");
                        return SWITCH_STATUS_FALSE;
                    } else {

                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "RE-Activating Secure RTP RECV\n");
                        rtp_session->srtp_errs[rtp_session->srtp_idx_rtp] = 0;
                    }
                }

                if (!(*flags & SFF_PLC)) {
                    stat = srtp_unprotect(rtp_session->recv_ctx[rtp_session->srtp_idx_rtp], &rtp_session->recv_msg.header, &sbytes);
                }

                if (stat && rtp_session->recv_msg.header.pt != rtp_session->recv_te && rtp_session->recv_msg.header.pt != rtp_session->cng_pt &&
                    rtp_session->recv_msg.header.pt != 13) {
                    if (++rtp_session->srtp_errs[rtp_session->srtp_idx_rtp] >= MAX_SRTP_ERRS && stat != 10) {

                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR,
                                          "Error: SRTP %s unprotect failed with code %d%s %ld\n", rtp_type(rtp_session), stat,
                                          stat == err_status_replay_fail ? " (replay check failed)" : stat ==
                                          err_status_auth_fail ? " (auth check failed)" : "", (long)sbytes);
                        return SWITCH_STATUS_GENERR;
                    } else {
                        sbytes = 0;
                    }
                } else {
                    rtp_session->srtp_errs[rtp_session->srtp_idx_rtp] = 0;
                }

                *bytes = sbytes;
                    
            }
#endif
        }
    }

    if ((rtp_session->recv_te && rtp_session->recv_msg.header.pt == rtp_session->recv_te) ||
        (*bytes < rtp_header_len && *bytes > 0) ||
        rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] || rtp_session->flags[SWITCH_RTP_FLAG_UDPTL]) {
        return SWITCH_STATUS_SUCCESS;
    }


    if (ts) {
        rtp_session->last_read_ts = ts;
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_BYTESWAP] && check_recv_payload(rtp_session)) {
        switch_swap_linear((int16_t *)RTP_BODY(rtp_session), (int) *bytes - rtp_header_len);
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_KILL_JB]) {
        rtp_session->flags[SWITCH_RTP_FLAG_KILL_JB] = 0;
        if (rtp_session->jb) {
            stfu_n_destroy(&rtp_session->jb);
        }
    }


    if (rtp_session->jb && !rtp_session->pause_jb && jb_valid(rtp_session) && rtp_session->recv_msg.header.version == 2 && *bytes) {
        if (rtp_session->recv_msg.header.m && rtp_session->recv_msg.header.pt != rtp_session->recv_te &&
            !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_VIDEO) && !(rtp_session->rtp_bugs & RTP_BUG_IGNORE_MARK_BIT)) {
#ifdef _USE_NEW_JB_
            jb_reset(rtp_session->jb);
#else
            stfu_n_reset(rtp_session->jb);
#endif
        }

        if (!rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER] && rtp_session->timer.interval) {
            if (!rtp_session->dontwait) {
                switch_core_timer_sync(&rtp_session->timer);
            }
            reset_jitter_seq(rtp_session);
        }

#ifdef _USE_NEW_JB_
        if ((jb_add_frame(rtp_session->jb, rtp_session->last_read_ts,
                       ntohs((uint16_t) rtp_session->recv_msg.header.seq),
                       rtp_session->recv_msg.header.pt,
                       rtp_session->recv_msg.body, *bytes - rtp_header_len,
                        rtp_session->timer.samplecount)) ==
                        SWITCH_STATUS_TIMEOUT) {
#else
        if (stfu_n_eat(rtp_session->jb, rtp_session->last_read_ts,
                        ntohs((uint16_t) rtp_session->recv_msg.header.seq),
                        rtp_session->recv_msg.header.pt,
                        rtp_session->recv_msg.body, *bytes - rtp_header_len, rtp_session->timer.samplecount) == STFU_ITS_TOO_LATE) {
                        rtp_session->stats.inbound.jb_toolate_drop_count++;
#endif
            goto more;
        }

        status = SWITCH_STATUS_FALSE;
        *bytes = 0;

        if (!return_jb_packet) {
            return status;
        }

    }

    if (rtp_session->jb && !rtp_session->pause_jb) {
#ifdef _USE_NEW_JB_
        if ((jb_frame = jb_read_frame(rtp_session->jb))) {
#else
        if ((jb_frame = stfu_n_read_a_frame(rtp_session->jb))) {
#endif
            memcpy(RTP_BODY(rtp_session), jb_frame->data, jb_frame->dlen);

            if (jb_frame->plc) {
                (*flags) |= SFF_PLC;
                rtp_session->stats.inbound.skip_packet_count++;
                rtp_session->stats.period_skip_packet_count++;
                rtp_session->stats.consecutive_skip_packet++;
                if (rtp_session->stats.consecutive_skip_packet >= RTP_EVENT_CONSECUTIVE_PACKET_LOSS_THRESHOLD) {
                    *flags |= SFF_RTP_EVENT;
                    rtp_session->stats.last_event |= RTP_EVENT_HIGH_CONSECUTIVE_PACKET_LOSS;
                    rtp_session->stats.consecutive_skip_packet = 0;
                    rtp_session->stats.last_period_skip_packet = rtp_session->stats.period_skip_packet_count;
                    rtp_session->stats.last_period_received =  rtp_session->stats.period_received;
                }
            } else {
                rtp_session->stats.inbound.jb_packet_count++;
                rtp_session->stats.consecutive_skip_packet = 0;
            }
            *bytes = jb_frame->dlen + rtp_header_len;
            rtp_session->recv_msg.header.version = 2;
            rtp_session->recv_msg.header.x = 0;
            rtp_session->recv_msg.header.ts = htonl(jb_frame->ts);
            
            rtp_session->recv_msg.header.pt = jb_frame->pt;
            rtp_session->recv_msg.header.seq = htons(jb_frame->seq);
            status = SWITCH_STATUS_SUCCESS;
            if (!xcheck_jitter) {
                check_jitter(rtp_session);
                xcheck_jitter = *bytes;
            }

        }
    }

    return status;
}

static switch_status_t process_rtcp_packet(switch_rtp_t *rtp_session, switch_size_t *bytes, switch_frame_flag_t *flags)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    int16_t rtt;
    uint32_t peer_dlsr;
    uint32_t peer_lsr;
    uint32_t cur_time;

    switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");

    if (*bytes == 0) {
        return status;
    }

    if (rtp_session->rtcp_recv_msg.header.version == 2) {
        if (rtp_session->rtcp_recv_msg.header.type == 200) {
            switch_time_t now;
            struct switch_rtcp_senderinfo* sr = (struct switch_rtcp_senderinfo*)rtp_session->rtcp_recv_msg.body;
            struct switch_rtcp_app_specific *app = (struct switch_rtcp_app_specific *) rtp_session->rtcp_recv_msg.body;

            if (ntohl(app->name) == 0x66757a65) {
                return SWITCH_STATUS_SUCCESS;
            }

            now = switch_micro_time_now();
            rtp_session->rtcp_fresh_frame = 1;

            rtp_session->stats.rtcp.packet_count += ntohl(sr->pc);
            rtp_session->stats.rtcp.octet_count += ntohl(sr->oc);
            rtp_session->stats.rtcp.peer_ssrc = ntohl(sr->ssrc);
            rtp_session->stats.rtcp.peer_ntp_msw = ntohl(sr->ntp_msw);
            rtp_session->stats.rtcp.peer_ntp_lsw = ntohl(sr->ntp_lsw);
            rtp_session->stats.rtcp.last_rr_time = now;

            /* sender report */
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG10,
                              "Received an RTCP SR with %d report blocks, " \
                              "length in words = %d, " \
                              "SSRC = 0x%X, " \
                              "NTP MSW = %u, " \
                              "NTP LSW = %u, " \
                              "RTP timestamp = %u, " \
                              "Sender Packet Count = %u, " \
                              "Sender Octet Count = %u, " \
                              "LSR Delay: %u, " \
                              "LSR: %u\n", 
                              rtp_session->rtcp_recv_msg.header.count,
                              ntohs((uint16_t)rtp_session->rtcp_recv_msg.header.length),
                              ntohl(sr->ssrc),
                              ntohl(sr->ntp_msw),
                              ntohl(sr->ntp_lsw),
                              ntohl(sr->ts),
                              ntohl(sr->pc),
                              ntohl(sr->oc),
                              ntohl(sr->reports.sr_source.lsr_delay),
                              ntohl(sr->reports.sr_source.lsr));

            if(rtp_session->stats.rtcp.last_sr_time) {
                peer_dlsr = ntohl(sr->reports.sr_source.lsr_delay);
                peer_dlsr = ((peer_dlsr >> 16) * 1000000) + ((peer_dlsr & 0xffff) / 65536.) * 1000000;
                peer_lsr = ntohl(sr->reports.sr_source.lsr);
                peer_lsr = ((peer_lsr >> 16) * 1000000) + ((peer_lsr & 0xffff) / 65536.) * 1000000;
                cur_time = (((u_long)(now / 1000000 + 2208988800UL)) & 0xffff) * 1000000;
                cur_time += ((((u_long)(now % 1000000 * 4294.967296)) >> 16) / 65536.) * 1000000;
                if (!(peer_lsr == 0 && peer_dlsr == 0)) {
                    rtt = (cur_time - peer_lsr - peer_dlsr) / 1000;
                    if (rtt > 0) {
                        rtp_session->stats.rtcp.last_rtt = rtt;
                        if (rtt > rtp_session->stats.rtcp.max_rtt)
                            rtp_session->stats.rtcp.max_rtt = rtt;
                        rtp_session->stats.rtcp.avg_rtt = ((rtp_session->stats.rtcp.avg_rtt * rtp_session->stats.rtcp.rr_count) + rtt) / (rtp_session->stats.rtcp.rr_count + 1);
                        if (rtt > RTP_EVENT_RTT_THRESHOLD_MS) {
                            *flags |= SFF_RTP_EVENT;
                            rtp_session->stats.last_event |= RTP_EVENT_HIGH_RTT;
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                                              "HIGH_RTT: RTCP rtt=%u ssrc=%#x cur_time=%u peer_lsr=%u dlsr=%u now=%lu last_sr=%lu.\n",
                                              rtt, (int) rtp_session->stats.rtcp.peer_ssrc, cur_time,
                                              peer_lsr, (uint32_t) peer_dlsr, now, rtp_session->stats.rtcp.last_sr_time);
                        }
                    }
                }
            }
            rtp_session->stats.rtcp.rr_count++;
        }
        status = SWITCH_STATUS_SUCCESS;
    } else {
        if (rtp_session->rtcp_recv_msg.header.version != 2) {
            if (rtp_session->rtcp_recv_msg.header.version == 0) {
                if (rtp_session->ice.ice_user) {
                    handle_ice(rtp_session, &rtp_session->rtcp_ice, (void *) &rtp_session->rtcp_recv_msg, *bytes);
                }
            } else {

                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session),
                                  SWITCH_LOG_DEBUG, "Received an unsupported RTCP packet version %d\nn", rtp_session->rtcp_recv_msg.header.version);
            }
        }

        status = SWITCH_STATUS_SUCCESS;
    }

    return status;
}




static switch_status_t read_rtcp_packet(switch_rtp_t *rtp_session, switch_size_t *bytes, switch_frame_flag_t *flags)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_port_t cur_rtcp_port, old_rtcp_port;
    uint32_t cur_rtcp_ip, old_rtcp_ip;
    switch_core_session_t *session;

    if (!switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_ENABLE_RTCP)) {
        return SWITCH_STATUS_FALSE;
    }

    switch_assert(bytes);

    *bytes = sizeof(rtcp_msg_t);
    if ((status = rtcp_recvfrom(rtp_session, rtp_session->rtcp_from_addr, rtp_session->rtcp_sock_input, 0, (void *) &rtp_session->rtcp_recv_msg, bytes))
        != SWITCH_STATUS_SUCCESS) {
        *bytes = 0;
    }

    if (!rtp_session->rtcp_remote_addr) {
        session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
        if (switch_get_sockaddr_v4(rtp_session->rtcp_from_addr, &cur_rtcp_ip, &cur_rtcp_port) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error getting RTCP info.\n");
            return SWITCH_STATUS_FALSE;
        }

        rtp_session->remote_rtcp_port = cur_rtcp_port;

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
            "Setting New Remote RTCP port=%u\n", (uint16_t) rtp_session->remote_rtcp_port);

        if (switch_sockaddr_info_get(&rtp_session->rtcp_remote_addr,
                    rtp_session->eff_remote_host_str, SWITCH_UNSPEC,
                    rtp_session->remote_rtcp_port, 0,
                    rtp_session->pool) != SWITCH_STATUS_SUCCESS ||
                !rtp_session->rtcp_remote_addr) {
            switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error Setting RTCP address: %s:%u",
                                rtp_session->eff_remote_host_str, rtp_session->remote_rtcp_port);
        }
    } else if (!rtp_session->rtp_conn) { //Only for legacy transport
        if (switch_get_sockaddr_v4(rtp_session->rtcp_from_addr, &cur_rtcp_ip, &cur_rtcp_port) == SWITCH_STATUS_SUCCESS &&
            switch_get_sockaddr_v4(rtp_session->rtcp_remote_addr, &old_rtcp_ip, &old_rtcp_port) == SWITCH_STATUS_SUCCESS) {
            if (cur_rtcp_ip != old_rtcp_ip || cur_rtcp_port != old_rtcp_port) {
                rtp_session->remote_rtcp_port = cur_rtcp_port;
                switch_set_sockaddr_v4(rtp_session->rtcp_remote_addr, cur_rtcp_ip, cur_rtcp_port);

                session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                    "Setting New Remote RTCP port=%u\n", (uint16_t) rtp_session->remote_rtcp_port);
            }
        }
    }

    if (rtp_session->rtcp_dtls) {
        char *b = (char *) &rtp_session->rtcp_recv_msg;

        if (*b == 0 || *b == 1) {
            if (rtp_session->rtcp_ice.ice_user) {
                handle_ice(rtp_session, &rtp_session->rtcp_ice, (void *) &rtp_session->rtcp_recv_msg, *bytes);
            }
            *bytes = 0;
        }

        if (*bytes && (*b >= 20) && (*b <= 64)) {
            rtp_session->rtcp_dtls->bytes = *bytes;
            rtp_session->rtcp_dtls->data = (void *) &rtp_session->rtcp_recv_msg;
        } else {
            rtp_session->rtcp_dtls->bytes = 0;
            rtp_session->rtcp_dtls->data = NULL;
        }

        do_dtls(rtp_session, rtp_session->rtcp_dtls);


        if (rtp_session->rtcp_dtls->bytes) {
            *bytes = 0;
        }
    }


#ifdef ENABLE_SRTP
    if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV] && rtp_session->rtcp_recv_msg_p->header.version == 2) {
        //if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_RECV] && (!rtp_session->ice.ice_user || rtp_session->rtcp_recv_msg_p->header.version == 2)) {
        int sbytes = (int) *bytes;
        err_status_t stat = 0;


        if ((stat = srtp_unprotect_rtcp(rtp_session->recv_ctx[rtp_session->srtp_idx_rtcp], &rtp_session->rtcp_recv_msg_p->header, &sbytes))) {
            //++rtp_session->srtp_errs[rtp_session->srtp_idx_rtp]++;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "RTCP UNPROTECT ERR\n");
        } else {
            //rtp_session->srtp_errs[rtp_session->srtp_idx_rtp] = 0;
        }

        *bytes = sbytes;

    }
#endif


#ifdef ENABLE_ZRTP
    if (zrtp_on && !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] && rtp_session->rtcp_recv_msg_p->header.version == 2) {
        /* ZRTP Recv */
        if (bytes) {
            unsigned int sbytes = (int) *bytes;
            zrtp_status_t stat = 0;

            stat = zrtp_process_srtcp(rtp_session->zrtp_stream, (void *) rtp_session->rtcp_recv_msg_p, &sbytes);

            switch (stat) {
            case zrtp_status_ok:
                *bytes = sbytes;
                break;
            case zrtp_status_drop:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection drop with code %d\n", stat);
                *bytes = 0;
                break;
            case zrtp_status_fail:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection fail with code %d\n", stat);
                *bytes = 0;
                break;
            default:
                break;
            }
        }
    }
#endif


    if (*bytes) {
        return process_rtcp_packet(rtp_session, bytes, flags);
    }

    return status;
}

static int using_ice(switch_rtp_t *rtp_session)
{
    if (rtp_session->ice.ice_user || rtp_session->rtcp_ice.ice_user) {
        return 1;
    }

    return 0;
}

//#define TRACE_READ 1
static int rtp_common_read(switch_rtp_t *rtp_session, switch_payload_t *payload_type,
                           payload_map_t **pmapP, switch_frame_flag_t *flags, switch_io_flag_t io_flags)
{

    switch_channel_t *channel = NULL;
    switch_size_t bytes = 0;
    switch_size_t rtcp_bytes = 0;
    switch_status_t status = SWITCH_STATUS_SUCCESS, poll_status = SWITCH_STATUS_SUCCESS;
    switch_status_t rtcp_status = SWITCH_STATUS_SUCCESS, rtcp_poll_status = SWITCH_STATUS_SUCCESS;
    int check = 0;
    int ret = -1;
    int sleep_mss = 1000;
    int poll_sec = 5;
    int poll_loop = 0;
    int fdr = 0;
    int rtcp_fdr = 0;
    int hot_socket = 0;
    int read_loops = 0;
    switch_bool_t sent_digits;
#ifdef TRACE_READ
    char trace_buffer[1024];

    memset(trace_buffer, 0, 1024);
#endif

    if (!switch_rtp_ready(rtp_session)) {
        return -1;
    }

    if (rtp_session->session) {
        channel = switch_core_session_get_channel(rtp_session->session);
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER]) {
        sleep_mss = rtp_session->timer.interval * 1000;
    }

    READ_INC(rtp_session);

    while (switch_rtp_ready(rtp_session)) {
        int do_cng = 0, do_cng_dtmf = 0;
        int read_pretriggered = 0;
        int has_rtcp = 0;

        bytes = 0;

        if (read_loops > MAX_RTP_READ_LOOPS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "%s Exceeded max read loops\n",
                              rtp_session_name(rtp_session));
            return -1;
        }

        if (rtp_session->use_webrtc_neteq == SWITCH_TRUE) {
            *flags |= SFF_WEBRTC_NETEQ;
        }

        if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER)) {
            if ((switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_AUTOFLUSH) || switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_STICKY_FLUSH)) &&
                !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_PROXY_MEDIA) &&
                !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_VIDEO) &&
                !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_UDPTL) &&
                (rtp_session->read_pollfd || rtp_session->rtp_conn)) {

                if ((rtp_session->rtp_conn && (switch_status_t) fuze_transport_socket_poll(rtp_session->rtp_conn, 0) == SWITCH_STATUS_SUCCESS) ||
                    (!rtp_session->rtp_conn && switch_poll(rtp_session->read_pollfd, 1, &fdr, 0) == SWITCH_STATUS_SUCCESS)) {

                    status = read_rtp_packet(rtp_session, &bytes, flags, SWITCH_FALSE);

#ifdef TRACE_READ
                    if (((rtp_session->cng_pt && rtp_session->recv_msg.header.pt == rtp_session->cng_pt) || rtp_session->recv_msg.header.pt == 13)) {
                        strncat(trace_buffer, "read_cng,", 1024);
                    } else {
                        strncat(trace_buffer, "read_normal,", 1024);
                    }
                    if (status == SWITCH_STATUS_SUCCESS) {
                        strncat(trace_buffer, "read_success,", 1024);
                    } else {
                        strncat(trace_buffer, "read_fail,", 1024);
                    }
                    {
                        char tmpbuf[32];
                        switch_snprintf(tmpbuf, 32, "(%" PRId64 "),", bytes);
                        strncat(trace_buffer, tmpbuf, 1023);
                    }
#endif
                    
                    if (status == SWITCH_STATUS_GENERR) {
                        ret = -1;
                        goto end;
                    }
                    if ((*flags & SFF_RTCP)) {
                        *flags &= ~SFF_RTCP;
                        has_rtcp = 1;
                        read_pretriggered = 0;
                        goto rtcp;
                    }

                    /* switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Initial (%i) %d\n", status, bytes); */
                    if (status != SWITCH_STATUS_FALSE) {
#ifdef TRACE_READ
                        strncat(trace_buffer, "pretrigger,", 1024);
#endif
                        read_pretriggered = 1;
                    }

                    if (bytes) {
                        if ((rtp_session->rtp_conn && (switch_status_t) fuze_transport_socket_poll(rtp_session->rtp_conn, 0) == SWITCH_STATUS_SUCCESS) ||
                                (!rtp_session->rtp_conn && switch_poll(rtp_session->read_pollfd, 1, &fdr, 0) == SWITCH_STATUS_SUCCESS)) {
                            hot_socket = 1;
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG10, "%s more data left in socket, read again\n",
                                              rtp_session_name(rtp_session));
                        } else {
                            hot_socket = 0;
                        }
                    }
                } else {
                    hot_socket = 0;
                }
            }

            /* indicate to the caller that there is more data waiting in the socket */
            if (hot_socket) {
                *flags |= SFF_HOT_READ;
            }
            /* if there's no more data waiting, wait for the next timer ... though this is a little weird as it
             * delays the current packet by 20ms!
             */
            if (!rtp_session->dontwait && !hot_socket) {
                switch_core_timer_next(&rtp_session->timer);
            }
        }

        rtp_session->stats.read_count++;

    recvfrom:

        if (!read_pretriggered) {
            bytes = 0;
        }
        read_loops++;
        //poll_loop = 0;

        if (!switch_rtp_ready(rtp_session)) {
            break;
        }

        if (!switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER) && (rtp_session->read_pollfd || rtp_session->rtp_conn)) {
            int pt = poll_sec * 1000000;

            sent_digits = do_2833(rtp_session);

            if (sent_digits) {
                *flags |= SFF_RFC2833;
            }

            if (rtp_session->dtmf_data.out_digit_dur > 0 || rtp_session->dtmf_data.in_digit_sanity || rtp_session->sending_dtmf ||
                switch_queue_size(rtp_session->dtmf_data.dtmf_queue) || switch_queue_size(rtp_session->dtmf_data.dtmf_inqueue)) {
                pt = 20000;
            }


            if ((io_flags & SWITCH_IO_FLAG_NOBLOCK)) {
                pt = 0;
            }

            poll_status = (rtp_session->rtp_conn ? (switch_status_t) fuze_transport_socket_poll(rtp_session->rtp_conn, pt)
                                                 : switch_poll(rtp_session->read_pollfd, 1, &fdr, pt));

            if (rtp_session->dtmf_data.out_digit_dur > 0) {
                return_cng_frame();
            }

            if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] && rtp_session->flags[SWITCH_RTP_FLAG_BREAK]) {
                switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_BREAK);
                bytes = 0;
                reset_jitter_seq(rtp_session);
                return_cng_frame();
            }

        }


        if (poll_status == SWITCH_STATUS_SUCCESS) {
            if (read_pretriggered) {
#ifdef TRACE_READ
                strncat(trace_buffer, "pretrigger_reset,", 1024);
#endif
                read_pretriggered = 0;
            } else {

                status = read_rtp_packet(rtp_session, &bytes, flags, SWITCH_TRUE);

#ifdef TRACE_READ
                if (((rtp_session->cng_pt && rtp_session->recv_msg.header.pt == rtp_session->cng_pt) || rtp_session->recv_msg.header.pt == 13)) {
                    strncat(trace_buffer, "read_cng2,", 1024);
                } else {
                    strncat(trace_buffer, "read_normal2,", 1024);
                }
                if (status == SWITCH_STATUS_SUCCESS) {
                    strncat(trace_buffer, "read_success2,", 1024);
                } else {
                    strncat(trace_buffer, "read_fail2,", 1024);
                }
                {
                    char tmpbuf[32];
                    switch_snprintf(tmpbuf, 32, "(%"PRId64"),", bytes);
                    strncat(trace_buffer, tmpbuf, 1023);
                }
#endif

                if (status == SWITCH_STATUS_GENERR) {
                    ret = -1;
                    goto end;
                }

                if (rtp_session->max_missed_packets && read_loops == 1 && !rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
                    if (bytes) {
                        rtp_session->missed_count = 0;
                    } else if (++rtp_session->missed_count >= rtp_session->max_missed_packets) {
                        ret = -2;
                        goto end;
                    }
                }

                if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
                    //switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_CRIT, "Read bytes (%i) %ld\n", status, bytes);

                    if (bytes == 0) {
                        if (check_rtcp_and_ice(rtp_session) == -1) {
                            ret = -1;
                            goto end;
                        }
                        // This is dumb
                        //switch_rtp_video_refresh(rtp_session);
                        goto  rtcp;
                    }
                }

                if ((*flags & SFF_PROXY_PACKET)) {
                    ret = (int) bytes;
                    goto end;
                }

                if ((*flags & SFF_RTCP)) {
                    *flags &= ~SFF_RTCP;
                    has_rtcp = 1;
                    goto rtcp;
                }


            }
            poll_loop = 0;
        } else {
            if (!SWITCH_STATUS_IS_BREAK(poll_status) && poll_status != SWITCH_STATUS_TIMEOUT) {
                char tmp[128] = "";
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Poll failed with error: %d [%s]\n",
                    poll_status, switch_strerror_r(poll_status, tmp, sizeof(tmp)));
                ret = -1;
                goto end;
            }

            if (!rtp_session->flags[SWITCH_RTP_FLAG_UDPTL] && !rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
                rtp_session->missed_count += (poll_sec * 1000) / (rtp_session->ms_per_packet ? rtp_session->ms_per_packet / 1000 : 20);
                bytes = 0;

                if (rtp_session->max_missed_packets) {
                    if (rtp_session->missed_count >= rtp_session->max_missed_packets) {
                        ret = -2;
                        goto end;
                    }
                }
            }

            if (using_ice(rtp_session)) {
                if (check_rtcp_and_ice(rtp_session) == -1) {
                    ret = -1;
                    goto end;
                }
            }

            if ((!(io_flags & SWITCH_IO_FLAG_NOBLOCK)) &&
                (rtp_session->dtmf_data.out_digit_dur == 0)) {
                return_cng_frame();
            }
        }

    rtcp:

        if (rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP]) {
            rtcp_poll_status = SWITCH_STATUS_FALSE;

            /* fuze rtcp: end up here */
            if (rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX] && has_rtcp) {
                if (rtp_session->rtcp_recv_msg_p->header.version == 2) { //rtcp muxed
                    rtp_session->rtcp_from_addr = rtp_session->from_addr;
                    rtcp_status = rtcp_poll_status = SWITCH_STATUS_SUCCESS;
                    rtcp_bytes = bytes;
                    bytes = 0;

                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s MUXed RTCP packet bytes=%lld\n",
                                      rtp_session_name(rtp_session), (long long)rtcp_bytes);
                }
            }
        }

        if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_ENABLE_RTCP) &&
            (rtp_session->rtcp_conn || rtp_session->rtcp_read_pollfd)) {

            rtcp_poll_status = (rtp_session->rtcp_conn ? (switch_status_t) fuze_transport_socket_poll(rtp_session->rtcp_conn, 0)
                                                       : switch_poll(rtp_session->rtcp_read_pollfd, 1, &rtcp_fdr, 0));

            if (rtcp_poll_status == SWITCH_STATUS_SUCCESS) {
                if (!rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
                    rtcp_status = read_rtcp_packet(rtp_session, &rtcp_bytes, flags);
                }

                if (rtcp_status == SWITCH_STATUS_SUCCESS) {
                    switch_rtp_reset_media_timer(rtp_session);

                    if (rtp_session->flags[SWITCH_RTP_FLAG_RTCP_PASSTHRU] || rtp_session->rtcp_recv_msg_p->header.type == 206) {
                        switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);
                        const char *uuid = switch_channel_get_partner_uuid(channel);

                        if (uuid) {
                            switch_core_session_t *other_session;
                            switch_rtp_t *other_rtp_session = NULL;

                            if ((other_session = switch_core_session_locate(uuid))) {
                                switch_channel_t *other_channel = switch_core_session_get_channel(other_session);
                                if ((other_rtp_session = switch_channel_get_private(other_channel, "__rtcp_audio_rtp_session")) &&
                                    other_rtp_session->rtcp_sock_output &&
                                    switch_rtp_test_flag(other_rtp_session, SWITCH_RTP_FLAG_ENABLE_RTCP)) {
                                    other_rtp_session->rtcp_send_msg = rtp_session->rtcp_recv_msg;

                                    if (rtp_session->rtcp_recv_msg_p->header.type == 206) {
                                        rtcp_ext_msg_t *extp = (rtcp_ext_msg_t *) rtp_session->rtcp_recv_msg_p;
                                        extp->header.recv_ssrc = htonl(other_rtp_session->ssrc);
                                    }
                                    if (rtp_session->rtcp_recv_msg_p->header.type == 200) {
                                        struct switch_rtcp_senderinfo *sr = (struct switch_rtcp_senderinfo*) other_rtp_session->rtcp_send_msg.body;
                                        struct switch_rtcp_report *rep = &sr->reports;
                                        sr->ssrc = htonl(other_rtp_session->ssrc);
                                        rep->sr_source.ssrc1 = htonl(other_rtp_session->stats.rtcp.peer_ssrc);
                                    }


#ifdef ENABLE_SRTP
                                    if (switch_rtp_test_flag(other_rtp_session, SWITCH_RTP_FLAG_SECURE_SEND)) {
                                        int sbytes = (int) rtcp_bytes;
                                        int stat = srtp_protect_rtcp(other_rtp_session->send_ctx[rtp_session->srtp_idx_rtcp], &other_rtp_session->rtcp_send_msg.header, &sbytes);
                                        if (stat) {
                                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: SRTP RTCP protection failed with code %d\n", stat);
                                        }
                                        rtcp_bytes = sbytes;

                                    }
#endif

#ifdef ENABLE_ZRTP
                                    /* ZRTP Send */
                                    if (zrtp_on && !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA]) {
                                        unsigned int sbytes = (unsigned int) bytes;
                                        zrtp_status_t stat = zrtp_status_fail;

                                        stat = zrtp_process_rtcp(other_rtp_session->zrtp_stream, (void *) &other_rtp_session->rtcp_send_msg, &sbytes);

                                        switch (stat) {
                                        case zrtp_status_ok:
                                            break;
                                        case zrtp_status_drop:
                                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection drop with code %d\n", stat);
                                            ret = (int) bytes;
                                            goto end;
                                            break;
                                        case zrtp_status_fail:
                                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection fail with code %d\n", stat);
                                            break;
                                        default:
                                            break;
                                        }

                                        bytes = sbytes;
                                        
                                    }
#endif

                                    if (rtcp_sendto(other_rtp_session, other_rtp_session->rtcp_sock_output, other_rtp_session->rtcp_remote_addr, 0,
                                                             (const char*)&other_rtp_session->rtcp_send_msg, &rtcp_bytes ) != SWITCH_STATUS_SUCCESS) {
                                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG,"RTCP packet not written\n");
                                    }
                                }
                                switch_core_session_rwunlock(other_session);
                            }
                        }

                    }

                    if (rtp_session->flags[SWITCH_RTP_FLAG_RTCP_MUX]) {
                        if (rtcp_bytes) {
                            process_rtcp_packet(rtp_session, &rtcp_bytes, flags);
                            ret = 1;

                            if (!rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER] && rtp_session->timer.interval) {
                                if (!rtp_session->dontwait) {
                                    switch_core_timer_sync(&rtp_session->timer);
                                }
                                reset_jitter_seq(rtp_session);
                            }


                            goto recvfrom;
                        }
                    }
                }
            }
        }

        if (bytes && rtp_session->recv_msg.header.version == 2 &&
            !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] && !rtp_session->flags[SWITCH_RTP_FLAG_UDPTL] &&
            rtp_session->recv_msg.header.pt != 13 &&
            rtp_session->recv_msg.header.pt != rtp_session->recv_te &&
            (!rtp_session->cng_pt || rtp_session->recv_msg.header.pt != rtp_session->cng_pt)) {
            int accept_packet = 1;


            if (rtp_session->pmaps && *rtp_session->pmaps) {
                payload_map_t *pmap;
                accept_packet = 0;

                switch_mutex_lock(rtp_session->flag_mutex);
                for (pmap = *rtp_session->pmaps; pmap && pmap->allocated; pmap = pmap->next) {

                    if (!pmap->negotiated) {
                        continue;
                    }

                    if (rtp_session->recv_msg.header.pt == pmap->pt) {
                        accept_packet = 1;
                        if (pmapP) {
                            *pmapP = pmap;
                        }
                        break;
                    }
                }
                switch_mutex_unlock(rtp_session->flag_mutex);
            }

            if (!accept_packet &&
                !(rtp_session->rtp_bugs & RTP_BUG_ACCEPT_ANY_PAYLOAD) && !(rtp_session->rtp_bugs & RTP_BUG_ACCEPT_ANY_PACKETS)) {
                /* drop frames of incorrect payload number and return CNG frame instead */
                return_cng_frame();
            }
        }

        if (!bytes && (io_flags & SWITCH_IO_FLAG_NOBLOCK)) {
            rtp_session->missed_count = 0;
            ret = 0;
            goto end;
        }

        check = !bytes;

        if (rtp_session->flags[SWITCH_RTP_FLAG_FLUSH]) {
            if (!rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
                do_flush(rtp_session, SWITCH_FALSE);
                bytes = 0;
            }
            switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_FLUSH);
        }

        if (rtp_session->flags[SWITCH_RTP_FLAG_BREAK] || (bytes && bytes == 4 && *((int *) &rtp_session->recv_msg) == UINT_MAX)) {
            switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_BREAK);

            if (!rtp_session->flags[SWITCH_RTP_FLAG_NOBLOCK] || !rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER] ||
                rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] || rtp_session->flags[SWITCH_RTP_FLAG_UDPTL] ||
                (bytes && bytes < 5) || (!bytes && poll_loop)) {
                bytes = 0;
                reset_jitter_seq(rtp_session);
                return_cng_frame();
            }
        }

        if (bytes && bytes < 5) {
            continue;
        }

        if (!bytes && poll_loop) {
#ifdef TRACE_READ
            strncat(trace_buffer, "recvfrom1,", 1024);
#endif
            goto recvfrom;
        }

        if (bytes && rtp_session->recv_msg.header.m && rtp_session->recv_msg.header.pt != rtp_session->recv_te &&
            !rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] && !(rtp_session->rtp_bugs & RTP_BUG_IGNORE_MARK_BIT)) {
            rtp_flush_read_buffer(rtp_session, SWITCH_RTP_FLUSH_ONCE);
        }


        if (bytes && switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_DEBUG_RTP_READ)) {
            switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
            const char *tx_host;
            const char *old_host;
            const char *my_host;

            char bufa[30], bufb[30], bufc[30];


            tx_host = switch_get_addr(bufa, sizeof(bufa), rtp_session->from_addr);
            old_host = switch_get_addr(bufb, sizeof(bufb), rtp_session->remote_addr);
            my_host = switch_get_addr(bufc, sizeof(bufc), rtp_session->local_addr);

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG_CLEAN(session), SWITCH_LOG_CONSOLE,
                              "R %s b=%4ld %s:%u %s:%u %s:%u pt=%d ts=%u m=%d\n",
                              session ? switch_channel_get_name(switch_core_session_get_channel(session)) : "NoName",
                              (long) bytes,
                              my_host, switch_sockaddr_get_port(rtp_session->local_addr),
                              old_host, rtp_session->remote_port,
                              tx_host, switch_sockaddr_get_port(rtp_session->from_addr),
                              rtp_session->recv_msg.header.pt, ntohl(rtp_session->recv_msg.header.ts), rtp_session->recv_msg.header.m);

        }

        if (((rtp_session->cng_pt && rtp_session->recv_msg.header.pt == rtp_session->cng_pt) || rtp_session->recv_msg.header.pt == 13)) {
            *flags |= SFF_NOT_AUDIO;
        } else {
            *flags &= ~SFF_NOT_AUDIO; /* If this flag was already set, make sure to remove it when we get real audio */
        }


        /* ignore packets not meant for us unless the auto-adjust window is open */
        if (bytes) {
            /*
             * If a call starts muted it will only send comfort noise.  This ensures that we don't send any packets
             * to the conference node (if this is an anchor node) for this call until it gets a packet other than
             * comfort noise.  This doesn't work so ... ifdef this out.  A subsequent change below put a CN check around
             * the autoadj decrement so we'll stay in the autoadj window.
             */
#if 0
            if (rtp_session->flags[SWITCH_RTP_FLAG_AUTOADJ]) {
                if (((rtp_session->cng_pt && rtp_session->recv_msg.header.pt == rtp_session->cng_pt) || rtp_session->recv_msg.header.pt == 13)) {
#ifdef TRACE_READ
            strncat(trace_buffer, "recvfrom2,", 1024);
#endif
                    goto recvfrom;
                }
            } else 
#endif
                if (!(rtp_session->rtp_bugs & RTP_BUG_ACCEPT_ANY_PACKETS) && !switch_cmp_addr(rtp_session->from_addr, rtp_session->remote_addr)
                    && !rtp_session->rtp_conn) {
                goto recvfrom;

            }
        }

        if (bytes && switch_sockaddr_get_port(rtp_session->from_addr)) {
            if (rtp_session->rtp_conn) {
                if (!switch_cmp_addr(rtp_session->from_addr, rtp_session->remote_addr)) {
                    char bufa[30];
                    const char *err;
                    const char *tx_host = switch_get_addr(bufa, sizeof(bufa), rtp_session->from_addr);

                    rtp_session->auto_adj_used = 1;
#if 0
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "calling switch_rtp_set_remote_address h=%s p=%u",
                                      tx_host, switch_sockaddr_get_port(rtp_session->from_addr));
#endif
                    switch_rtp_set_remote_address(rtp_session, tx_host, switch_sockaddr_get_port(rtp_session->from_addr), 0, SWITCH_FALSE, &err);
                }
            } else if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_AUTOADJ)) {
                if (!switch_cmp_addr(rtp_session->from_addr, rtp_session->remote_addr)) {
                    if (++rtp_session->autoadj_tally >= 10) {
                        const char *err;
                        uint32_t old = rtp_session->remote_port;
                        const char *tx_host;
                        const char *old_host;
                        char bufa[30], bufb[30];
                        char adj_port[6];

                        tx_host = switch_get_addr(bufa, sizeof(bufa), rtp_session->from_addr);
                        old_host = switch_get_addr(bufb, sizeof(bufb), rtp_session->remote_addr);

                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                                "Auto Changing port from %s:%u to %s:%u\n", old_host, old, tx_host,
                                switch_sockaddr_get_port(rtp_session->from_addr));

                        if (channel) {
                            switch_channel_set_variable(channel, "remote_media_ip_reported", switch_channel_get_variable(channel, "remote_media_ip"));
                            switch_channel_set_variable(channel, "rtp_auto_adjust_ip", tx_host);
                            switch_channel_set_variable(channel, "remote_media_ip", tx_host);
                            switch_snprintf(adj_port, sizeof(adj_port), "%u", switch_sockaddr_get_port(rtp_session->from_addr));
                            switch_channel_set_variable(channel, "remote_media_port_reported", switch_channel_get_variable(channel, "remote_media_port"));
                            switch_channel_set_variable(channel, "remote_media_port", adj_port);
                            switch_channel_set_variable(channel, "rtp_auto_adjust_port", adj_port);
                            switch_channel_set_variable(channel, "rtp_auto_adjust", "true");
                        }

                        rtp_session->auto_adj_used = 1;
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "calling switch_rtp_set_remote_address h=%s p=%u",
                                          tx_host, switch_sockaddr_get_port(rtp_session->from_addr));
                        switch_rtp_set_remote_address(rtp_session, tx_host, switch_sockaddr_get_port(rtp_session->from_addr), 0, SWITCH_FALSE, &err);
                        switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_AUTOADJ);
                    }
                } else {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Correct ip/port confirmed.\n");
                    switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_AUTOADJ);
                    rtp_session->auto_adj_used = 0;
                }
            }
        }

        if (bytes && rtp_session->autoadj_window) {
            if (!(((rtp_session->cng_pt && rtp_session->recv_msg.header.pt == rtp_session->cng_pt) || rtp_session->recv_msg.header.pt == 13))) {
                if (--rtp_session->autoadj_window == 0) {
                    switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_AUTOADJ);
                }
            }
        }

        if (bytes && (rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] || rtp_session->flags[SWITCH_RTP_FLAG_UDPTL])) {
            /* Fast PASS! */
            *flags |= SFF_PROXY_PACKET;

            if (rtp_session->flags[SWITCH_RTP_FLAG_UDPTL]) {
#if 0
                if (rtp_session->recv_msg.header.version == 2 && check_recv_payload(rtp_session)) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                      "Ignoring udptl packet of size of %ld bytes that looks strikingly like a RTP packet.\n", (long)bytes);
                    bytes = 0;
                    goto do_continue;
                }
#endif
                *flags |= SFF_UDPTL_PACKET;
            }

            ret = (int) bytes;
            goto end;
        }

        if (bytes) {
            rtp_session->missed_count = 0;

            if (bytes < rtp_header_len && bytes != 6) {
                if (rtp_session->bad_packet_size_recv % 500 == 0) {
                    uint8_t *dptr = (uint8_t *)&rtp_session->recv_msg.header;
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                      "Ignoring invalid RTP packet size of %ld bytes cnt %u bytes[] = [%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x]\n",
                                      (long)bytes, rtp_session->bad_packet_size_recv,
                                      dptr[0],  dptr[1],  dptr[2],  dptr[3],  dptr[4],  dptr[5],  dptr[6],  dptr[7],  dptr[8],  dptr[9],
                                      dptr[10], dptr[11], dptr[12], dptr[13], dptr[14], dptr[15], dptr[16], dptr[17], dptr[18], dptr[19]);
                }
                rtp_session->bad_packet_size_recv += 1;
                bytes = 0;
                goto do_continue;
            }

            if (rtp_session->recv_msg.header.pt && (rtp_session->recv_msg.header.pt == rtp_session->cng_pt || rtp_session->recv_msg.header.pt == 13)) {
                return_cng_frame();
            }
        }

        if (check || bytes) {
            sent_digits = do_2833(rtp_session);
            if (sent_digits) {
                *flags |= SFF_RFC2833;
            }
        }

        if (bytes && rtp_session->recv_msg.header.version != 2) {
            uint8_t *data = (uint8_t *) RTP_BODY(rtp_session);

            if (rtp_session->recv_msg.header.version == 0) {
                if (rtp_session->ice.ice_user) {
                    handle_ice(rtp_session, &rtp_session->ice, (void *) &rtp_session->recv_msg, bytes);
                    goto recvfrom;
                }
            }

            if (rtp_session->invalid_handler) {
                rtp_session->invalid_handler(rtp_session, rtp_session->sock_input, (void *) &rtp_session->recv_msg, bytes, rtp_session->from_addr);
            }

            memset(data, 0, 2);
            data[0] = 65;


            rtp_session->recv_msg.header.pt = (uint32_t) rtp_session->cng_pt ? rtp_session->cng_pt : SWITCH_RTP_CNG_PAYLOAD;
            *flags |= (SFF_CNG | SFF_TIMEOUT);
#ifdef TRACE_READ
            strncat(trace_buffer, "timeout1,", 1024);
#endif
            *payload_type = (switch_payload_t) rtp_session->recv_msg.header.pt;
            ret = 2 + rtp_header_len;
            goto end;
        } else if (bytes) {
            rtp_session->stats.inbound.period_packet_count++;
        }

        /* Handle incoming RFC2833 packets */
        switch (handle_rfc2833(rtp_session, bytes, &do_cng_dtmf)) {
        case RESULT_GOTO_END:
            do_cng |= do_cng_dtmf;
            goto end;
        case RESULT_GOTO_RECVFROM:
            do_cng |= do_cng_dtmf;
            goto recvfrom;
        case RESULT_GOTO_TIMERCHECK:
            if (do_cng_dtmf) {
                *flags |= SFF_TIMEOUT;
#ifdef TRACE_READ
                strncat(trace_buffer, "timeout2,", 1024);
#endif
                do_cng = do_cng_dtmf;
            }
            goto timer_check;
        case RESULT_CONTINUE:
            if (do_cng_dtmf) {
                *flags |= SFF_TIMEOUT;
#ifdef TRACE_READ
                strncat(trace_buffer, "timeout3,", 1024);
#endif
                do_cng = do_cng_dtmf;
            }
            goto result_continue;
        default:
            do_cng |= do_cng_dtmf;
            break;
        }

    result_continue:
    timer_check:


        if (rtp_session->recv_msg.header.pt && (rtp_session->recv_msg.header.pt == rtp_session->cng_pt || rtp_session->recv_msg.header.pt == 13)) {
            if (rtp_session->cng_pt) {
                rtp_session->recv_msg.header.pt = (uint32_t) rtp_session->cng_pt;
            } else {
                rtp_session->recv_msg.header.pt = (uint32_t) 13;
            }
            *flags |= SFF_CNG;
            *payload_type = (switch_payload_t) rtp_session->recv_msg.header.pt;
            ret = 2 + rtp_header_len;
            goto end;
        } else if ((do_cng || !bytes) && rtp_session->use_webrtc_neteq == SWITCH_TRUE) {
            ret = 0;
            goto end;
        }

        if (do_cng) {
            uint8_t *data = (uint8_t *) RTP_BODY(rtp_session);

            sent_digits = do_2833(rtp_session);
            if (sent_digits) {
                *flags |= SFF_RFC2833;
            }

            if (rtp_session->last_cng_ts == rtp_session->last_read_ts + rtp_session->samples_per_interval) {
                rtp_session->last_cng_ts = 0;
            } else {
                rtp_session->last_cng_ts = rtp_session->last_read_ts + rtp_session->samples_per_interval;
            }

            memset(data, 0, 2);
            data[0] = 65;
            rtp_session->recv_msg.header.pt = (uint32_t) rtp_session->cng_pt ? rtp_session->cng_pt : SWITCH_RTP_CNG_PAYLOAD;
            
            /* fuze: firefox is triggering this
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "PT=%u\n", rtp_session->recv_msg.header.pt);
            */

            *flags |= (SFF_CNG);
            *flags |= (SFF_TIMEOUT);
            *payload_type = (switch_payload_t) rtp_session->recv_msg.header.pt;
            ret = 2 + rtp_header_len;

            /* When CN is flowing this will cause 1: loss in the stats report and 2: lots of consecutive loss events */
#if 0
            rtp_session->stats.inbound.skip_packet_count++;
            rtp_session->stats.period_skip_packet_count++;
            rtp_session->stats.consecutive_skip_packet++;
            if (rtp_session->stats.consecutive_skip_packet >= RTP_EVENT_CONSECUTIVE_PACKET_LOSS_THRESHOLD) {
                *flags |= SFF_RTP_EVENT;
                rtp_session->stats.last_event |= RTP_EVENT_HIGH_CONSECUTIVE_PACKET_LOSS;
                rtp_session->stats.consecutive_skip_packet = 0;
                rtp_session->stats.last_period_skip_packet = rtp_session->stats.period_skip_packet_count;
                rtp_session->stats.last_period_received =  rtp_session->stats.period_received;
            }
#endif
            goto end;
        }

        if (check || (bytes && !rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER])) {
            if (!bytes && rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER]) {  /* We're late! We're Late! */
                if (!rtp_session->flags[SWITCH_RTP_FLAG_NOBLOCK] && status == SWITCH_STATUS_BREAK) {
                    if (!rtp_session->dontwait) {
                        switch_cond_next();
                    }
                    continue;
                }



                if (!rtp_session->flags[SWITCH_RTP_FLAG_PAUSE] && !rtp_session->flags[SWITCH_RTP_FLAG_DTMF_ON] && !rtp_session->dtmf_data.in_digit_ts
                    && rtp_session->cng_count > (rtp_session->one_second * 2) && rtp_session->jitter_lead > JITTER_LEAD_FRAMES) {

                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1, "%s %s timeout\n",
                                      rtp_session_name(rtp_session), rtp_type(rtp_session));

                    rtp_session->stats.inbound.flaws++;
                    do_mos(rtp_session, SWITCH_FALSE);
                }

                *flags |= SFF_TIMEOUT;
#ifdef TRACE_READ
                strncat(trace_buffer, "timeout4,", 1024);
#endif
                rtp_session->cng_count++;
                return_cng_frame();
            }
        }

        rtp_session->cng_count = 0;

        if (status == SWITCH_STATUS_BREAK || bytes == 0) {
            if (!(io_flags & SWITCH_IO_FLAG_SINGLE_READ) && rtp_session->flags[SWITCH_RTP_FLAG_DATAWAIT]) {
                goto do_continue;
            }
            return_cng_frame();
        }

        if (rtp_session->flags[SWITCH_RTP_FLAG_GOOGLEHACK] && rtp_session->recv_msg.header.pt == 102) {
            rtp_session->recv_msg.header.pt = 97;
        }

        if (!(*flags & SFF_PLC))
            rtp_session->stats.consecutive_skip_packet = 0;
        break;

    do_continue:

        if (!bytes && !rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER]) {
            switch_yield(sleep_mss);
        }

    }

    if (switch_rtp_ready(rtp_session)) {
        *payload_type = (switch_payload_t) rtp_session->recv_msg.header.pt;

        if (*payload_type == SWITCH_RTP_CNG_PAYLOAD) {
            *flags |= SFF_CNG;
        }

        ret = (int) bytes;
    } else {
        ret = -1;
    }

 end:
    
    READ_DEC(rtp_session);

#ifdef TRACE_READ
    if (bytes == 0) {
        if (strncmp(rtp_session->trace_buffer, trace_buffer, 1024) != 0) {
            strncpy(rtp_session->trace_buffer, trace_buffer, 1024);
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "rtp_common_read (%s): CNG %s%s\n",
                              rtp_session->rtp_conn_name, (*flags & SFF_TIMEOUT ? "timeout " : ""), trace_buffer);
        }
    }
#endif

    return ret;
}


SWITCH_DECLARE(switch_byte_t) switch_rtp_check_auto_adj(switch_rtp_t *rtp_session)
{
    return rtp_session->auto_adj_used;
}

SWITCH_DECLARE(switch_size_t) switch_rtp_has_dtmf(switch_rtp_t *rtp_session)
{
    switch_size_t has = 0;

    if (switch_rtp_ready(rtp_session)) {
        switch_mutex_lock(rtp_session->dtmf_data.dtmf_mutex);
        has = switch_queue_size(rtp_session->dtmf_data.dtmf_inqueue);
        switch_mutex_unlock(rtp_session->dtmf_data.dtmf_mutex);
    }

    return has;
}

SWITCH_DECLARE(switch_size_t) switch_rtp_dequeue_dtmf(switch_rtp_t *rtp_session, switch_dtmf_t *dtmf)
{
    switch_size_t bytes = 0;
    switch_dtmf_t *_dtmf = NULL;
    void *pop;

    if (!switch_rtp_ready(rtp_session)) {
        return bytes;
    }

    switch_mutex_lock(rtp_session->dtmf_data.dtmf_mutex);
    if (switch_queue_trypop(rtp_session->dtmf_data.dtmf_inqueue, &pop) == SWITCH_STATUS_SUCCESS) {

        _dtmf = (switch_dtmf_t *) pop;
        *dtmf = *_dtmf;
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "RTP RECV DTMF %c:%d\n", dtmf->digit, dtmf->duration);
        bytes++;
        free(pop);
    }
    switch_mutex_unlock(rtp_session->dtmf_data.dtmf_mutex);

    return bytes;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_queue_rfc2833(switch_rtp_t *rtp_session, const switch_dtmf_t *dtmf)
{

    switch_dtmf_t *rdigit;

    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    if ((rdigit = malloc(sizeof(*rdigit))) != 0) {
        *rdigit = *dtmf;
        if (rdigit->duration < switch_core_min_dtmf_duration(0)) {
            rdigit->duration = switch_core_min_dtmf_duration(0);
        }

        if ((switch_queue_trypush(rtp_session->dtmf_data.dtmf_queue, rdigit)) != SWITCH_STATUS_SUCCESS) {
            free(rdigit);
            return SWITCH_STATUS_FALSE;
        }
    } else {
        abort();
    }

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_queue_rfc2833_in(switch_rtp_t *rtp_session, const switch_dtmf_t *dtmf)
{
    switch_dtmf_t *rdigit;

    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    if ((rdigit = malloc(sizeof(*rdigit))) != 0) {
        *rdigit = *dtmf;
        if (rdigit->duration < switch_core_min_dtmf_duration(0)) {
            rdigit->duration = switch_core_min_dtmf_duration(0);
        }

        if ((switch_queue_trypush(rtp_session->dtmf_data.dtmf_inqueue, rdigit)) != SWITCH_STATUS_SUCCESS) {
            free(rdigit);
            return SWITCH_STATUS_FALSE;
        }
    } else {
        abort();
    }

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_read(switch_rtp_t *rtp_session, void *data, uint32_t *datalen,
                                                switch_payload_t *payload_type, switch_frame_flag_t *flags, switch_io_flag_t io_flags)
{
    int bytes = 0;

    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    bytes = rtp_common_read(rtp_session, payload_type, NULL, flags, io_flags);

    if (bytes < 0) {
        *datalen = 0;
        return bytes == -2 ? SWITCH_STATUS_TIMEOUT : SWITCH_STATUS_GENERR;
    } else if (bytes == 0) {
        *datalen = 0;
        return SWITCH_STATUS_BREAK;
    } else {
        if (bytes > rtp_header_len) {
            bytes -= rtp_header_len;
        }
    }

    *datalen = bytes;

    memcpy(data, RTP_BODY(rtp_session), bytes);

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtcp_zerocopy_read_frame(switch_rtp_t *rtp_session, switch_rtcp_frame_t *frame)
{
    if (!rtp_session->flags[SWITCH_RTP_FLAG_ENABLE_RTCP]) {
        return SWITCH_STATUS_FALSE;
    }

    /* A fresh frame has been found! */
    if (rtp_session->rtcp_fresh_frame) {
        struct switch_rtcp_senderinfo* sr = (struct switch_rtcp_senderinfo*)rtp_session->rtcp_recv_msg_p->body;
        int i = 0;

        /* turn the flag off! */
        rtp_session->rtcp_fresh_frame = 0;

        frame->ssrc = ntohl(sr->ssrc);
        frame->packet_type = (uint16_t)rtp_session->rtcp_recv_msg_p->header.type;
        frame->ntp_msw = ntohl(sr->ntp_msw);
        frame->ntp_lsw = ntohl(sr->ntp_lsw);
        frame->timestamp = ntohl(sr->ts);
        frame->packet_count =  ntohl(sr->pc);
        frame->octect_count = ntohl(sr->oc);

        for (i = 0; i < (int)rtp_session->rtcp_recv_msg_p->header.count && i < MAX_REPORT_BLOCKS ; i++) {
            struct switch_rtcp_report_block* report = (struct switch_rtcp_report_block*) (rtp_session->rtcp_recv_msg_p->body + (sizeof(struct switch_rtcp_sr_head) + (i * sizeof(struct switch_rtcp_report_block))));
            frame->reports[i].ssrc = ntohl(report->ssrc);
            frame->reports[i].fraction = (uint8_t)ntohl(report->fraction);
            frame->reports[i].lost = ntohl(report->lost);
            frame->reports[i].highest_sequence_number_received = ntohl(report->highest_sequence_number_received);
            frame->reports[i].jitter = ntohl(report->jitter);
            frame->reports[i].lsr = ntohl(report->lsr);
            frame->reports[i].dlsr = ntohl(report->dlsr);
            if (i >= MAX_REPORT_BLOCKS) {
                break;
            }
        }
        frame->report_count = (uint16_t)i;

        return SWITCH_STATUS_SUCCESS;
    }

    return SWITCH_STATUS_TIMEOUT;
}

int32_t switch_rtp_max_data_value(uint8_t payload, uint8_t *data, int len) {
    int32_t ret = -1;
    int32_t max = 0;
    if (payload == 0) {
        for (int i = 0; i < len; i++) {
            short val = abs(ulaw_to_linear_table(data[i]));
            if (val > max) {
                max = val;
            }
        }
        ret = max;
    } else if (payload == 8) {
        for (int i = 0; i < len; i++) {
            short val = abs(alaw_to_linear_table(data[i]));
            if (val > max) {
                max = val;
            }
        }
        ret = max;
    }
    return ret;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_zerocopy_read_frame(switch_rtp_t *rtp_session, switch_frame_t *frame, switch_io_flag_t io_flags)
{
    int bytes = 0;

    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    bytes = rtp_common_read(rtp_session, &frame->payload, &frame->pmap, &frame->flags, io_flags);

    frame->data = RTP_BODY(rtp_session);
    frame->packet = &rtp_session->recv_msg;
    frame->packetlen = bytes;
    frame->source = __FILE__;

    switch_set_flag(frame, SFF_RAW_RTP);
    if (frame->payload == rtp_session->recv_te) {
        switch_set_flag(frame, SFF_RFC2833);
    }
    frame->timestamp = ntohl(rtp_session->recv_msg.header.ts);
    frame->seq = (uint16_t) ntohs((uint16_t) rtp_session->recv_msg.header.seq);
    frame->ssrc = ntohl(rtp_session->recv_msg.header.ssrc);
    frame->m = rtp_session->recv_msg.header.m ? SWITCH_TRUE : SWITCH_FALSE;
    frame->x = rtp_session->recv_msg.header.x ? SWITCH_TRUE : SWITCH_FALSE;

#ifdef ENABLE_ZRTP
    if (zrtp_on && rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_RECV]) {
        zrtp_session_info_t zrtp_session_info;

        if (rtp_session->zrtp_session && (zrtp_status_ok == zrtp_session_get(rtp_session->zrtp_session, &zrtp_session_info))) {
            if (zrtp_session_info.sas_is_ready) {

                switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);

                const char *uuid = switch_channel_get_partner_uuid(channel);
                if (uuid) {
                    switch_core_session_t *other_session;

                    if ((other_session = switch_core_session_locate(uuid))) {
                        switch_channel_t *other_channel = switch_core_session_get_channel(other_session);
                        switch_rtp_t *other_rtp_session = switch_channel_get_private(other_channel, "__zrtp_audio_rtp_session");

                        if (other_rtp_session) {
                            if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_INBOUND) {
                                switch_mutex_lock(other_rtp_session->read_mutex);
                                if (zrtp_status_ok == zrtp_session_get(other_rtp_session->zrtp_session, &zrtp_session_info)) {
                                    if (rtp_session->zrtp_mitm_tries > ZRTP_MITM_TRIES) {
                                        switch_rtp_clear_flag(other_rtp_session, SWITCH_ZRTP_FLAG_SECURE_MITM_RECV);
                                        switch_rtp_clear_flag(other_rtp_session, SWITCH_ZRTP_FLAG_SECURE_MITM_SEND);
                                        rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_RECV] = 0;
                                        rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_SEND] = 0;
                                    } else if (zrtp_status_ok == zrtp_resolve_mitm_call(other_rtp_session->zrtp_stream, rtp_session->zrtp_stream)) {
                                        rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_RECV] = 0;
                                        rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_SEND] = 0;
                                        switch_rtp_clear_flag(other_rtp_session, SWITCH_ZRTP_FLAG_SECURE_MITM_RECV);
                                        switch_rtp_clear_flag(other_rtp_session, SWITCH_ZRTP_FLAG_SECURE_MITM_SEND);
                                        rtp_session->zrtp_mitm_tries++;
                                    }
                                }
                                switch_mutex_unlock(other_rtp_session->read_mutex);
                            }
                        }

                        switch_core_session_rwunlock(other_session);
                    }
                }
            }
        } else {
            rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_RECV] = 0;
            rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_SEND] = 0;
        }
    }
#endif

    if (bytes < 0) {
        frame->datalen = 0;
        return bytes == -2 ? SWITCH_STATUS_TIMEOUT : SWITCH_STATUS_GENERR;
    } else if (bytes < rtp_header_len) {
        frame->datalen = 0;
        return SWITCH_STATUS_BREAK;
    } else {
        bytes -= rtp_header_len;
    }

    /* fuze: optional 10 bytes at end of packet for srtp? */
    if (frame->payload == 9 || frame->payload == 8 || frame->payload == 0) {
        int frames = bytes / 80;
        bytes = frames * 80;
    }

    if (!rtp_session->use_webrtc_neteq) {
        int32_t max = switch_rtp_max_data_value(frame->payload, (uint8_t *)frame->data, bytes);
        if (max > rtp_session->level_in) {
            rtp_session->level_in = max;
        }
    }

    frame->datalen = bytes;
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_zerocopy_read(switch_rtp_t *rtp_session,
                                                         void **data, uint32_t *datalen, switch_payload_t *payload_type, switch_frame_flag_t *flags,
                                                         switch_io_flag_t io_flags)
{
    int bytes = 0;

    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    bytes = rtp_common_read(rtp_session, payload_type, NULL, flags, io_flags);
    *data = RTP_BODY(rtp_session);

    if (bytes < 0) {
        *datalen = 0;
        return SWITCH_STATUS_GENERR;
    } else {
        if (bytes > rtp_header_len) {
            bytes -= rtp_header_len;
        }
    }

    *datalen = bytes;

    return SWITCH_STATUS_SUCCESS;
}

static int rtp_write_ready(switch_rtp_t *rtp_session, uint32_t bytes, int line)
{
    if (rtp_session->ice.ice_user && !(rtp_session->ice.rready)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1, "Skip sending %s packet %ld bytes (ice not ready @ line %d!)\n",
                          rtp_type(rtp_session), (long)bytes, line);
        return 0;
    }

    if (rtp_session->dtls && rtp_session->dtls->state != DS_READY) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG1, "Skip sending %s packet %ld bytes (dtls not ready @ line %d!)\n",
                          rtp_type(rtp_session), (long)bytes, line);
        return 0;
    }

    return 1;
}




static int rtp_common_write(switch_rtp_t *rtp_session,
                            rtp_msg_t *send_msg, void *data, uint32_t datalen, switch_payload_t payload, uint32_t timestamp, switch_frame_flag_t *flags)
{
    switch_size_t bytes;
    uint8_t send = 1;
    uint32_t this_ts = 0;
    int ret;
    switch_time_t now;
    uint8_t m = 0;
    switch_bool_t bpath = SWITCH_FALSE;
    uint32_t adjust_ts_step = (datalen < 80) ? 160 : datalen;

    rtp_session->total_sent += 1;
    rtp_session->total_bytes_sent += datalen;

    if (rtp_session->total_sent >= LOG_OUT_FREQUENCY) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, 
                          "rtp_common_write %s sent=%u bytes=%u bad=%u\n",
                          rtp_session->rtp_conn_name,
                          rtp_session->total_sent, rtp_session->total_bytes_sent,
                          rtp_session->total_bad_sent);
        rtp_session->total_sent = 0;
        rtp_session->total_bytes_sent = 0;
    }

    if (!switch_rtp_ready(rtp_session)) {
        rtp_session->total_bad_sent += 1;
        return -1;
    }

    if (!rtp_write_ready(rtp_session, datalen, __LINE__)) {
        rtp_session->total_bad_sent += 1;
        return 0;
    }

    if (datalen == (uint32_t)-1) {
        rtp_session->total_bad_sent += 1;
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "rtp_common_write called with datalen == -1!\n");
        return 0;
    }

    WRITE_INC(rtp_session);

    if (send_msg) {
        bytes = datalen;

        /* seems to be in the bridging path */
        bpath = SWITCH_TRUE;

        if (bytes == (switch_size_t)-1) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "trying to send bad number of bytes (%zu)!\n", bytes);
            bytes = 0;
            rtp_session->total_bad_sent += 1;
        }
        
        /* removed conditions
         * check_recv_payload(rtp_session) << checks received payload type
         *
         */
        *flags &= ~SFF_RTCP;
        if (send_msg->header.version == 2 &&
            send_msg->header.m &&
            (send_msg->header.pt > 71 && send_msg->header.pt < 81)) {
            *flags |= SFF_RTCP;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "rtcp packet on RTP channel pt=%u\n", send_msg->header.pt);
        }

        m = (uint8_t) send_msg->header.m;

        if (flags && *flags & SFF_RFC2833) {
            send_msg->header.pt = rtp_session->te;
            
        }
        data = send_msg->body;
        if (datalen > rtp_header_len) {
            datalen -= rtp_header_len;
        }
    } else {
        /* seems to be in the conferencing path */
        
        if (*flags & SFF_RFC2833) {
            payload = rtp_session->te;
        }

        send_msg = &rtp_session->send_msg;

        send_msg->header.pt = payload;

#define FIX_TS
#ifdef FIX_TS
        if (!rtp_session->use_next_ts) {
            m = get_next_write_ts(rtp_session, timestamp);
        } else {
            rtp_session->ts = rtp_session->next_ts;
        }

        if (rtp_session->ts == rtp_session->last_write_ts && rtp_session->last_write_ts_set) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR,
                              "timestamp same as timestamp for previous packet (ts=%u)\n", rtp_session->ts);
        }

        /* set next_ts */
        /* ts += samples */
        rtp_session->send_msg.header.ts = htonl(rtp_session->ts);

        if (rtp_session->use_next_ts) {
            rtp_session->next_ts += adjust_ts_step;
        }
#else
        m = get_next_write_ts(rtp_session, timestamp);
        rtp_session->send_msg.header.ts = htonl(rtp_session->ts);
        if (rtp_session->ts == rtp_session->last_write_ts && rtp_session->last_write_ts_set) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR,
                              "timestamp same as timestamp for previous packet (ts=%u)\n", rtp_session->ts);
        }
#endif

        memcpy(send_msg->body, data, datalen);
        bytes = datalen + rtp_header_len;

    }
    
    if (!switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_VIDEO)) {
        if ((rtp_session->rtp_bugs & RTP_BUG_NEVER_SEND_MARKER)) {
            m = 0;
        } else {
            if ((rtp_session->last_write_ts != RTP_TS_RESET && rtp_session->ts > (rtp_session->last_write_ts + (rtp_session->samples_per_interval * 10)))
                || rtp_session->ts == rtp_session->samples_per_interval) {
                m++;
            }
            if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_USE_TIMER) &&
                (rtp_session->timer.samplecount - rtp_session->last_write_samplecount) * rtp_session->timestamp_multiplier > rtp_session->samples_per_interval * 10) {
                m++;
            }
            if (rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER] &&
                (rtp_session->timer.samplecount - rtp_session->last_write_samplecount) > rtp_session->samples_per_interval * 10) {
                m++;
            }
            if (!rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER] &&
                ((unsigned) ((switch_micro_time_now() - rtp_session->last_write_timestamp))) > (rtp_session->ms_per_packet * 10)) {
                m++;
            }
            if (rtp_session->cn && (payload != rtp_session->cng_pt && payload != 13)) {
                rtp_session->cn = 0;
                m++;
            }
            if (rtp_session->need_mark && !rtp_session->sending_dtmf) {
                m++;
                rtp_session->need_mark = 0;
            }
        }

        if (m) {
            rtp_session->flags[SWITCH_RTP_FLAG_RESET] = 1;
            rtp_session->ts = 0;
        }

        /* If the marker was set, and the timestamp seems to have started over - set a new SSRC, to indicate this is a new stream */
        if (m && !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_SECURE_SEND) && (rtp_session->rtp_bugs & RTP_BUG_CHANGE_SSRC_ON_MARKER) &&
            (rtp_session->flags[SWITCH_RTP_FLAG_RESET] || (rtp_session->ts <= rtp_session->last_write_ts && rtp_session->last_write_ts > 0))) {
            switch_rtp_set_ssrc(rtp_session, (uint32_t) ((intptr_t) rtp_session + (uint32_t) switch_epoch_time_now(NULL)));
        }

        if (!switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_VIDEO) && !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_UDPTL)) {
            send_msg->header.m = (m && !(rtp_session->rtp_bugs & RTP_BUG_NEVER_SEND_MARKER)) ? 1 : 0;
        }
    }


    if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_VIDEO)) {
        /* Normalize the timestamps to our own base by generating a made up starting point then adding the measured deltas to that base
           so if the timestamps and ssrc of the source change, it will not break the other end's jitter bufffer / decoder etc *cough* CHROME *cough*
         */

        if (!rtp_session->ts_norm.ts) {
            rtp_session->ts_norm.ts = (uint32_t) rand() % 1000000 + 1;
        }

        if (!rtp_session->ts_norm.last_ssrc || send_msg->header.ssrc != rtp_session->ts_norm.last_ssrc) {
            if (rtp_session->ts_norm.last_ssrc) {
                rtp_session->ts_norm.m = 1;
                rtp_session->ts_norm.delta_ct = 1;
                rtp_session->ts_norm.delta_ttl = 0;
                if (rtp_session->ts_norm.delta) {
                    rtp_session->ts_norm.ts += rtp_session->ts_norm.delta;
                }
            }
            rtp_session->ts_norm.last_ssrc = send_msg->header.ssrc;
            rtp_session->ts_norm.last_frame = ntohl(send_msg->header.ts);
        }


        if (ntohl(send_msg->header.ts) != rtp_session->ts_norm.last_frame) {
            rtp_session->ts_norm.delta = ntohl(send_msg->header.ts) - rtp_session->ts_norm.last_frame;

            if (rtp_session->ts_norm.delta > 0) {
                rtp_session->ts_norm.delta_ct++;
                if (rtp_session->ts_norm.delta_ct == 1000) {
                    rtp_session->ts_norm.delta_ct = 1;
                    rtp_session->ts_norm.delta_ttl = 0;
                }

                rtp_session->ts_norm.delta_ttl += rtp_session->ts_norm.delta;
                rtp_session->ts_norm.delta_avg = rtp_session->ts_norm.delta_ttl / rtp_session->ts_norm.delta_ct;
                rtp_session->ts_norm.delta_delta = abs(rtp_session->ts_norm.delta_avg - rtp_session->ts_norm.delta);
                rtp_session->ts_norm.delta_percent = (double)((double)rtp_session->ts_norm.delta / (double)rtp_session->ts_norm.delta_avg) * 100.0f;


                //if (rtp_session->ts_norm.delta_ct > 50 && rtp_session->ts_norm.delta_percent > 150.0) {
                    //printf("%s diff %d %d (%.2f)\n",rtp_session_name(rtp_session),
                    //rtp_session->ts_norm.delta, rtp_session->ts_norm.delta_avg, rtp_session->ts_norm.delta_percent);
                    //switch_rtp_video_refresh(rtp_session);
                    //}
            }
            rtp_session->ts_norm.ts += rtp_session->ts_norm.delta;
        }

        rtp_session->ts_norm.last_frame = ntohl(send_msg->header.ts);
        send_msg->header.ts = htonl(rtp_session->ts_norm.ts);

        /* wait for a marked frame since we just switched streams */
        if (rtp_session->ts_norm.m) {
            if (send_msg->header.m) {
                rtp_session->ts_norm.m = 0;
            } else {
                send = 0;
            }
        }
    }

    send_msg->header.ssrc = htonl(rtp_session->ssrc);

    if (rtp_session->flags[SWITCH_RTP_FLAG_GOOGLEHACK] && rtp_session->send_msg.header.pt == 97) {
        rtp_session->recv_msg.header.pt = 102;
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_VAD] &&
        rtp_session->recv_msg.header.pt == rtp_session->vad_data.read_codec->implementation->ianacode) {

        int16_t decoded[SWITCH_RECOMMENDED_BUFFER_SIZE / sizeof(int16_t)] = { 0 };
        uint32_t rate = 0;
        uint32_t codec_flags = 0;
        uint32_t len = sizeof(decoded);
        time_t now = switch_epoch_time_now(NULL);
        send = 0;

        if (rtp_session->vad_data.scan_freq && rtp_session->vad_data.next_scan <= now) {
            rtp_session->vad_data.bg_count = rtp_session->vad_data.bg_level = 0;
            rtp_session->vad_data.next_scan = now + rtp_session->vad_data.scan_freq;
        }

        if (switch_core_codec_decode(&rtp_session->vad_data.vad_codec,
                                     rtp_session->vad_data.read_codec,
                                     data,
                                     datalen,
                                     rtp_session->vad_data.read_codec->implementation->actual_samples_per_second,
                                     decoded, &len, &rate, &codec_flags) == SWITCH_STATUS_SUCCESS) {

            uint32_t energy = 0;
            uint32_t x, y = 0, z = len / sizeof(int16_t);
            uint32_t score = 0;
            int divisor = 0;
            if (z) {

                if (!(divisor = rtp_session->vad_data.read_codec->implementation->actual_samples_per_second / 8000)) {
                    divisor = 1;
                }

                for (x = 0; x < z; x++) {
                    energy += abs(decoded[y]);
                    y += rtp_session->vad_data.read_codec->implementation->number_of_channels;
                }

                if (++rtp_session->vad_data.start_count < rtp_session->vad_data.start) {
                    send = 1;
                } else {
                    score = (energy / (z / divisor));
                    if (score && (rtp_session->vad_data.bg_count < rtp_session->vad_data.bg_len)) {
                        rtp_session->vad_data.bg_level += score;
                        if (++rtp_session->vad_data.bg_count == rtp_session->vad_data.bg_len) {
                            rtp_session->vad_data.bg_level /= rtp_session->vad_data.bg_len;
                        }
                        send = 1;
                    } else {
                        if (score > rtp_session->vad_data.bg_level && !switch_test_flag(&rtp_session->vad_data, SWITCH_VAD_FLAG_TALKING)) {
                            uint32_t diff = score - rtp_session->vad_data.bg_level;

                            if (rtp_session->vad_data.hangover_hits) {
                                rtp_session->vad_data.hangover_hits--;
                            }

                            if (diff >= rtp_session->vad_data.diff_level || ++rtp_session->vad_data.hangunder_hits >= rtp_session->vad_data.hangunder) {

                                switch_set_flag(&rtp_session->vad_data, SWITCH_VAD_FLAG_TALKING);
                                if (!(rtp_session->rtp_bugs & RTP_BUG_NEVER_SEND_MARKER)) {
                                    send_msg->header.m = 1;
                                }
                                rtp_session->vad_data.hangover_hits = rtp_session->vad_data.hangunder_hits = rtp_session->vad_data.cng_count = 0;
                                if (switch_test_flag(&rtp_session->vad_data, SWITCH_VAD_FLAG_EVENTS_TALK)) {

                                    if ((rtp_session->vad_data.fire_events & VAD_FIRE_TALK)) {
                                        switch_event_t *event;
                                        if (switch_event_create(&event, SWITCH_EVENT_TALK) == SWITCH_STATUS_SUCCESS) {
                                            switch_channel_event_set_data(switch_core_session_get_channel(rtp_session->vad_data.session), event);
                                            switch_event_fire(&event);
                                        }
                                    }
                                }
                            }
                        } else {
                            if (rtp_session->vad_data.hangunder_hits) {
                                rtp_session->vad_data.hangunder_hits--;
                            }
                            if (switch_test_flag(&rtp_session->vad_data, SWITCH_VAD_FLAG_TALKING)) {
                                if (++rtp_session->vad_data.hangover_hits >= rtp_session->vad_data.hangover) {
                                    switch_clear_flag(&rtp_session->vad_data, SWITCH_VAD_FLAG_TALKING);
                                    rtp_session->vad_data.hangover_hits = rtp_session->vad_data.hangunder_hits = rtp_session->vad_data.cng_count = 0;
                                    if (switch_test_flag(&rtp_session->vad_data, SWITCH_VAD_FLAG_EVENTS_NOTALK)) {

                                        if ((rtp_session->vad_data.fire_events & VAD_FIRE_NOT_TALK)) {
                                            switch_event_t *event;
                                            if (switch_event_create(&event, SWITCH_EVENT_NOTALK) == SWITCH_STATUS_SUCCESS) {
                                                switch_channel_event_set_data(switch_core_session_get_channel(rtp_session->vad_data.session), event);
                                                switch_event_fire(&event);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if (switch_test_flag(&rtp_session->vad_data, SWITCH_VAD_FLAG_TALKING)) {
                    send = 1;
                }
            }
        } else {
            rtp_session->total_bad_sent += 1;
            ret = -1;
            goto end;
        }
    }

    if (*flags & SFF_CNG) {
        if (!rtp_session->is_fuze_app) {
            send = 0;
        } else if (*flags & SFF_TIMEOUT) {
            send = 0;
        } else if (*flags & SFF_IVR_FRAME) {
            send = 0;
        }
    }

    if (send && !switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_VIDEO)) {
        uint16_t this_seq = ntohs(send_msg->header.seq);
        this_ts = ntohl(send_msg->header.ts);

        if (abs(rtp_session->last_write_ts - this_ts) > 16000) {
            rtp_session->flags[SWITCH_RTP_FLAG_RESET] = 1;
        }

        if (rtp_session->sending_dtmf) {
            rtp_session->ts_ooo_count = 0;
            send = 0;
        } else if (!switch_rtp_ready(rtp_session) || !this_ts ||
                   (rtp_session->use_webrtc_neteq && !rtp_session->flags[SWITCH_RTP_FLAG_RESET] && this_ts < rtp_session->last_write_ts)) {
            if (send_msg->header.pt != rtp_session->payload) {
                if (rtp_session->ts_ooo_count == 0) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                      "%s dropping because of lower timestamp and sequence number curr=(%d,%u) prev=(%d,%u) pt=%d len=%u cn=%d\n",
                                      rtp_session->rtp_conn_name, this_seq, this_ts, rtp_session->last_seq, rtp_session->last_write_ts,
                                      send_msg->header.pt, datalen, (*flags & SFF_CNG) != 0);
                }
                rtp_session->ts_ooo_count += 1;
                send = 0;
            } else {
                if (rtp_session->write_count > 1) {
                    if (rtp_session->ts_ooo_count == 0) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                          "%s out of order TS because of lower timestamp and sequence number curr=(%d,%u) prev=(%d,%u) pt=%d len=%u cn=%d\n",
                                          rtp_session->rtp_conn_name, this_seq, this_ts, rtp_session->last_seq, rtp_session->last_write_ts,
                                          send_msg->header.pt, datalen, (*flags & SFF_CNG) != 0);
                    }
                    rtp_session->ts_ooo_count += 1;
                }
            }
        } else {
            if (rtp_session->ts_ooo_count > 1) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                  "%s out of order TS back to normal curr=(%d,%u) prev=(%d,%u) pt=%d len=%u cn=%d after %d packets\n",
                                  rtp_session->rtp_conn_name, this_seq, this_ts, rtp_session->last_seq, rtp_session->last_write_ts,
                                  send_msg->header.pt, datalen, (*flags & SFF_CNG) != 0, rtp_session->ts_ooo_count);
            }
            rtp_session->ts_ooo_count = 0;
        }
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_PAUSE]) {
        rtp_session->total_bad_sent += 1;
        send = 0;
    }

    /* fuze */
    if (send) {
        switch_time_t cn_delta = (switch_time_now() - rtp_session->last_adjust_cn_count)/(1000*1000); /* seconds */

        if (rtp_session->use_webrtc_neteq) {
            /* this is the case where we have a jitter buffer and we're just generating our own sequence numbers */
            send_msg->header.seq = htons(++rtp_session->seq);
            rtp_session->last_pkt_sent  = switch_time_now();
            if (!rtp_session->is_conf) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "session is CONFERENCE\n");;
                rtp_session->is_conf = SWITCH_TRUE;
            }
        } else if (*flags & SFF_IVR_FRAME) {
            switch_time_t now = switch_time_now();
            uint32_t diff = 0;

            /* this is the case where we are an IVR session and we're just generating our own sequence numbers */
            if (rtp_session->is_ivr == SWITCH_FALSE) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "session is IVR\n");
                rtp_session->is_ivr = SWITCH_TRUE;
                rtp_session->write_count = 0;
                rtp_session->last_ivr_send_time = now;
            }

            diff = (now - rtp_session->last_ivr_send_time)/1000;

            if (diff > 500) {
                uint32_t old_ts = ntohl(send_msg->header.ts);
                uint32_t new_ts = old_ts + ((diff/20)-1) * adjust_ts_step;
                send_msg->header.ts = htonl(new_ts);
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "timestamp adjustment of %u after %ums gap %u -> %u\n",
                                  diff*8, diff, old_ts, ntohl(send_msg->header.ts));
                send_msg->header.m = 1;
                rtp_session->next_ts = new_ts;
            }

            rtp_session->last_ivr_send_time = now;

            if (rtp_session->write_count % LOG_OUT_FREQUENCY == 0) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s ivr write (%u) seq=%u bpath=%d\n",
                                  rtp_session->rtp_conn_name, rtp_session->write_count, rtp_session->seq, bpath);
            }

            send_msg->header.seq = htons(++rtp_session->seq);
            rtp_session->write_count += 1;
        } else {
            /* we're in bridging/ivr mode and sequence numbers need to be set from the input sequence numbers */
            uint16_t new_seq_no = rtp_session->seq;
            uint16_t seq_no_from_rtp = ntohs(send_msg->header.seq);
            switch_bool_t out_of_order = SWITCH_FALSE;

            if (rtp_session->is_ivr == SWITCH_TRUE && !rtp_session->is_bridge) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "session is IVR -> BRIDGE\n");
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s ivr -> bridge (%u) seq=%u bpath=%d x=%d\n",
                                  rtp_session->rtp_conn_name, rtp_session->write_count, rtp_session->seq, bpath, send_msg->header.x);
                // rtp_session->is_ivr = SWITCH_FALSE; REMEMBER THAT WE WERE AN IVR SESSION
                rtp_session->write_count = 0;
                rtp_session->is_bridge = SWITCH_TRUE;
                rtp_session->anchor_base_ts = rtp_session->anchor_next_seq;
                rtp_session->anchor_base_seq = rtp_session->anchor_next_seq;
            }
            if (!rtp_session->is_bridge) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "session is BRIDGE\n");;
                rtp_session->is_bridge = SWITCH_TRUE;
            }

            if (rtp_session->write_count % LOG_OUT_FREQUENCY == 0) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s bridge write (%u) seq=%u bpath=%d x=%d\n",
                                  rtp_session->rtp_conn_name, rtp_session->write_count, rtp_session->seq, bpath, send_msg->header.x);
            }

            if (!rtp_session->last_seq_set) {
                rtp_session->last_seq_set = SWITCH_TRUE;
            } else if (rtp_session->last_bridge_seq[0] == seq_no_from_rtp) {
                new_seq_no += 1;
                rtp_session->seq += 1;
            } else if ((rtp_session->last_bridge_seq[0] + 1) != seq_no_from_rtp) {
                out_of_order = SWITCH_TRUE;
            }

            if (rtp_session->write_count == 0) {
                rtp_session->base_seq = seq_no_from_rtp;
            }

            if (out_of_order && *flags & SFF_TIMEOUT) {
                ret = (int) bytes;
                goto end;
            }

            if (*flags & SFF_CNG) {
                if (rtp_session->cng_pt) {
                    if (send_msg->header.pt != rtp_session->cng_pt) {
                        send_msg->header.pt = rtp_session->cng_pt;
                    }
                } else {
                    if (send_msg->header.pt != 13) {
                        send_msg->header.pt = 13;
                    }
                }

                /* make sure we track that we're muted! */
                if (!rtp_session->muted) {
                    rtp_session->muted = SWITCH_TRUE;
                }

            } else {
                int32_t max = switch_rtp_max_data_value(send_msg->header.pt, (uint8_t *)rtp_session->recv_msg.body, datalen);
                if (max > rtp_session->level_out) {
                    rtp_session->level_out = max;
                }
                if (rtp_session->muted) {
                    rtp_session->muted = SWITCH_FALSE;
                }
            }

            send_msg->header.m = 0;

            if (rtp_session->is_bridge) {
                uint16_t bseq;
                uint32_t bts;

                if (rtp_session->anchor_next_set) {
                    bseq = rtp_session->anchor_next_seq + rtp_session->anchor_base_seq;
                    bts = rtp_session->anchor_next_ts + rtp_session->anchor_base_ts;
                } else {
                    bseq = rtp_session->seq;
                    bts = ntohl(send_msg->header.ts);
                }

                send_msg->header.seq = htons(bseq);
                send_msg->header.ts = htonl(bts);
                send_msg->header.ssrc = htonl(rtp_session->ssrc);

                rtp_session->last_bridge_seq[0] = bseq;
                rtp_session->last_write_ts = bts;
                new_seq_no = bseq;
            }

            if (rtp_session->write_count == 0) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s wr=%u seq=%u base=%u from_rtp=%u new=%u\n",
                                  rtp_session->rtp_conn_name, rtp_session->write_count, rtp_session->seq,
                                  rtp_session->base_seq, seq_no_from_rtp, new_seq_no);
            }

            rtp_session->write_count += 1;

            if (rtp_session->write_count % LOG_OUT_FREQUENCY == 0) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "%s write cnt=%u from_seq=%u to_seq=%u (0x%x) out of order=%u\n",
                                  rtp_session->rtp_conn_name, rtp_session->write_count, seq_no_from_rtp, new_seq_no, htons(new_seq_no),
                                  rtp_session->out_of_order_sent);
            }
        }

        if (*flags & SFF_CNG) {
            if (rtp_session->in_cn_period == 0 && cn_delta > 10) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "start CN period pt:%d seq:%u ts:%u\n",
                                  send_msg->header.pt, ntohs(send_msg->header.seq), ntohl(send_msg->header.ts));
            }
            rtp_session->in_cn_period += 1;
        } else {
            if (rtp_session->in_cn_period > 0 && cn_delta > 10) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "stop CN period pt:%d seq:%u ts:%u after:%u pkts\n",
                                  send_msg->header.pt, ntohs(send_msg->header.seq), ntohl(send_msg->header.ts), rtp_session->in_cn_period);
                rtp_session->in_cn_period = 0;
            }
        }

        if (rtp_session->flags[SWITCH_RTP_FLAG_BYTESWAP] && send_msg->header.pt == rtp_session->payload) {
            switch_swap_linear((int16_t *)send_msg->body, (int) datalen);
        }

#ifdef ENABLE_SRTP
        if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND]) {
            int sbytes = (int) bytes;
            err_status_t stat;


            if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND_RESET]) {

                switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_SECURE_SEND_RESET);
                srtp_dealloc(rtp_session->send_ctx[rtp_session->srtp_idx_rtp]);
                rtp_session->send_ctx[rtp_session->srtp_idx_rtp] = NULL;
                if ((stat = srtp_create(&rtp_session->send_ctx[rtp_session->srtp_idx_rtp], &rtp_session->send_policy[rtp_session->srtp_idx_rtp]))) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error! RE-Activating Secure RTP SEND\n");
                    ret = -1;
                    rtp_session->total_bad_sent += 1;
                    goto end;
                } else {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "RE-Activating Secure RTP SEND\n");
                }
            }

            /* fuze(xxx): error with SRTP protection */
            stat = srtp_protect(rtp_session->send_ctx[rtp_session->srtp_idx_rtp], &send_msg->header, &sbytes);
            
            if (sbytes == -1) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "srtp_protect created -1 bytes!\n");
            }

            if (stat) {
                if (rtp_session->write_count % LOG_OUT_FREQUENCY == 0 || !rtp_session->srtp_protect_error) {
                    uint64_t srtp_index;
                    srtp_index = srtp_protect_get_index(rtp_session->send_ctx[rtp_session->srtp_idx_rtp],  &send_msg->header);
                    
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: %s SRTP protection failed on pkt=%u with code (%u) %d idx=%llu\n",
                                      rtp_session->rtp_conn_name, rtp_session->write_count, ntohs(send_msg->header.seq), stat, (long long unsigned int)srtp_index);
                    rtp_session->srtp_protect_error = SWITCH_TRUE;
                }
            } else if (rtp_session->srtp_protect_error) {
                rtp_session->srtp_protect_error = SWITCH_FALSE;
            }

            bytes = sbytes;
        }
#endif
#ifdef ENABLE_ZRTP
        /* ZRTP Send */
        if (zrtp_on && !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA]) {
            unsigned int sbytes = (int) bytes;
            zrtp_status_t stat = zrtp_status_fail;


            stat = zrtp_process_rtp(rtp_session->zrtp_stream, (void *) send_msg, &sbytes);

            switch (stat) {
            case zrtp_status_ok:
                break;
            case zrtp_status_drop:
                /* switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Error: zRTP protection drop with code %d\n", stat); */
                ret = (int) bytes;
                goto end;
                break;
            case zrtp_status_fail:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection fail with code %d\n", stat);
                break;
            default:
                break;
            }

            bytes = sbytes;
        }
#endif

        now = switch_micro_time_now();
#ifdef RTP_DEBUG_WRITE_DELTA
        {
            int64_t delta = (int64_t) (now - rtp_session->send_time) / 1000;
            if (delta > 30) switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "WRITE %d delta %" PRId64 "\n", (int) bytes, delta);
        }
#endif
        rtp_session->send_time = now;

        if (switch_rtp_test_flag(rtp_session, SWITCH_RTP_FLAG_DEBUG_RTP_WRITE)) {
            switch_core_session_t *session = switch_core_memory_pool_get_data(rtp_session->pool, "__session");
            const char *tx_host;
            const char *old_host;
            const char *my_host;

            char bufa[30], bufb[30], bufc[30];


            tx_host = switch_get_addr(bufa, sizeof(bufa), rtp_session->from_addr);
            old_host = switch_get_addr(bufb, sizeof(bufb), rtp_session->remote_addr);
            my_host = switch_get_addr(bufc, sizeof(bufc), rtp_session->local_addr);

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG_CLEAN(session), SWITCH_LOG_CONSOLE,
                              "W %s b=%4ld %s:%u %s:%u %s:%u pt=%d ts=%u m=%d\n",
                              session ? switch_channel_get_name(switch_core_session_get_channel(session)) : "NoName",
                              (long) bytes,
                              my_host, switch_sockaddr_get_port(rtp_session->local_addr),
                              old_host, rtp_session->remote_port,
                              tx_host, switch_sockaddr_get_port(rtp_session->from_addr),
                              send_msg->header.pt, ntohl(send_msg->header.ts), send_msg->header.m);

        }
        
        send_msg->header.ssrc = htonl(rtp_session->ssrc);

        if (rtp_sendto(rtp_session, rtp_session->sock_output, rtp_session->remote_addr, 0, (void *) send_msg, &bytes) != SWITCH_STATUS_SUCCESS) {
            if (rtp_session->rtp_send_fail_count == 0) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "rtp_sendto of seq=%u %zu bytes failed START\n", rtp_session->seq, bytes);
            }
            rtp_session->rtp_send_fail_count += 1;
            rtp_session->seq--;
            ret = -1;
            rtp_session->total_bad_sent += 1;
            goto end;
        } else {
            if (rtp_session->rtp_send_fail_count > 0) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "rtp_sendto of seq=%u %zu bytes failed STOP after %u sends\n", 
                                  rtp_session->seq, bytes, rtp_session->rtp_send_fail_count);
            }
            rtp_session->rtp_send_fail_count = 0;
        }
        rtp_session->stats.outbound.period_packet_count++;
        rtp_session->last_write_ts = this_ts;

        if (!rtp_session->last_write_ts_set || rtp_session->flags[SWITCH_RTP_FLAG_RESET]) {
            rtp_session->time_of_first_ts = switch_time_now();
            rtp_session->time_of_last_ts_check = rtp_session->time_of_first_ts;
            rtp_session->first_ts = this_ts;
        }

        /*
         * Only check conf timestamps here.  Bridging timestamps are checked separately across both
         * channels.
         */
        if (rtp_session->last_write_ts_set && rtp_session->use_webrtc_neteq) {
            switch_time_t now = switch_time_now();
            if ((now - rtp_session->time_of_last_ts_check) > 10000000) {
                switch_time_t delta = (now - rtp_session->time_of_first_ts)/1000; // ms
                uint64_t delta_ts = (this_ts - rtp_session->first_ts)/8; // ms
                int64_t difference = delta_ts - delta;
                uint64_t delta_thresold = (datalen/8)*2;
                if (abs(difference) > delta_thresold) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                      "Timestamp delta %" PRId64 " [ts delta:%" PRId64 " vs time delta:%" PRId64 "] first=%u curr=%u\n",
                                      difference, delta_ts, delta, rtp_session->first_ts, this_ts);
                }
                if (abs(difference) < (abs(rtp_session->ts_delta)-20)) {
#if 0
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING,
                                      "Timestamp delta %" PRId64 " decreased from %d\n",
                                      difference, rtp_session->ts_delta);
#endif
                    rtp_session->ts_delta = difference;
                }
                if (abs(difference) > abs(rtp_session->ts_delta)) {
                    rtp_session->ts_delta = difference;
                }
                rtp_session->time_of_last_ts_check = now;
            }
        }

        rtp_session->last_write_ts_set = SWITCH_TRUE;

        rtp_session->flags[SWITCH_RTP_FLAG_RESET] = 0;

        if (rtp_session->queue_delay) {
            rtp_session->delay_samples = rtp_session->queue_delay;
            rtp_session->queue_delay = 0;
        }

        rtp_session->stats.outbound.raw_bytes += bytes;
        rtp_session->stats.outbound.packet_count++;

        if (rtp_session->cng_pt && send_msg->header.pt == rtp_session->cng_pt) {
            rtp_session->stats.outbound.cng_packet_count++;
        } else {
            rtp_session->stats.outbound.media_packet_count++;
            rtp_session->stats.outbound.media_bytes += bytes;
        }

        if (rtp_session->flags[SWITCH_RTP_FLAG_USE_TIMER]) {
            rtp_session->last_write_samplecount = rtp_session->timer.samplecount;
        } else {
            rtp_session->last_write_timestamp = switch_micro_time_now();
        }
    } /* if (send) */

    ret = (int) bytes;

 end:

    WRITE_DEC(rtp_session);

    return ret;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_disable_vad(switch_rtp_t *rtp_session)
{

    if (!rtp_session) {
        return SWITCH_STATUS_FALSE;
    }

    if (!rtp_session->flags[SWITCH_RTP_FLAG_VAD]) {
        return SWITCH_STATUS_GENERR;
    }
    switch_core_codec_destroy(&rtp_session->vad_data.vad_codec);
    switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_VAD);
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_rtp_enable_vad(switch_rtp_t *rtp_session, switch_core_session_t *session, switch_codec_t *codec,
                                                      switch_vad_flag_t flags)
{
    if (!switch_rtp_ready(rtp_session)) {
        return SWITCH_STATUS_FALSE;
    }

    if (rtp_session->flags[SWITCH_RTP_FLAG_VAD]) {
        return SWITCH_STATUS_GENERR;
    }

    memset(&rtp_session->vad_data, 0, sizeof(rtp_session->vad_data));

    if (switch_true(switch_channel_get_variable(switch_core_session_get_channel(rtp_session->session), "fire_talk_events"))) {
        rtp_session->vad_data.fire_events |= VAD_FIRE_TALK;
    }

    if (switch_true(switch_channel_get_variable(switch_core_session_get_channel(rtp_session->session), "fire_not_talk_events"))) {
        rtp_session->vad_data.fire_events |= VAD_FIRE_NOT_TALK;
    }


    if (switch_core_codec_init(&rtp_session->vad_data.vad_codec,
                               codec->implementation->iananame,
                               NULL,
                               codec->implementation->samples_per_second,
                               codec->implementation->microseconds_per_packet / 1000,
                               codec->implementation->number_of_channels,
                               SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL, rtp_session->pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Can't load codec?\n");
        return SWITCH_STATUS_FALSE;
    }
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_DEBUG, "Activate VAD codec %s %dms\n", codec->implementation->iananame,
                      codec->implementation->microseconds_per_packet / 1000);
    rtp_session->vad_data.diff_level = 400;
    rtp_session->vad_data.hangunder = 15;
    rtp_session->vad_data.hangover = 40;
    rtp_session->vad_data.bg_len = 5;
    rtp_session->vad_data.bg_count = 5;
    rtp_session->vad_data.bg_level = 300;
    rtp_session->vad_data.read_codec = codec;
    rtp_session->vad_data.session = session;
    rtp_session->vad_data.flags = flags;
    rtp_session->vad_data.cng_freq = 50;
    rtp_session->vad_data.ts = 1;
    rtp_session->vad_data.start = 0;
    rtp_session->vad_data.next_scan = switch_epoch_time_now(NULL);
    rtp_session->vad_data.scan_freq = 0;
    switch_rtp_set_flag(rtp_session, SWITCH_RTP_FLAG_VAD);
    switch_set_flag(&rtp_session->vad_data, SWITCH_VAD_FLAG_CNG);
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(int) switch_rtp_write_frame(switch_rtp_t *rtp_session, switch_frame_t *frame)
{
    uint8_t fwd = 0;
    void *data = NULL;
    uint32_t len, ts = 0;
    switch_payload_t payload = 0;
    rtp_msg_t *send_msg = NULL;

    if (!switch_rtp_ready(rtp_session) || !rtp_session->remote_addr) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "switch_rtp_write_frame ret -1\n");
        return -1;
    }

    if (!rtp_write_ready(rtp_session, frame->datalen, __LINE__)) {
        return 0;
    }

    //if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
    //  rtp_session->flags[SWITCH_RTP_FLAG_DEBUG_RTP_READ]++;
    //  rtp_session->flags[SWITCH_RTP_FLAG_DEBUG_RTP_WRITE]++;
    //}


    if (switch_test_flag(frame, SFF_PROXY_PACKET) || switch_test_flag(frame, SFF_UDPTL_PACKET) ||
        rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] || rtp_session->flags[SWITCH_RTP_FLAG_UDPTL]) {

        //if (rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA] || rtp_session->flags[SWITCH_RTP_FLAG_UDPTL]) {
        switch_size_t bytes;
        //char bufa[30];

        /* Fast PASS! */
        if (!switch_test_flag(frame, SFF_PROXY_PACKET) && !switch_test_flag(frame, SFF_UDPTL_PACKET)) {
            return 0;
        }
        bytes = frame->packetlen;
        //tx_host = switch_get_addr(bufa, sizeof(bufa), rtp_session->remote_addr);

        send_msg = frame->packet;

        if (!rtp_session->flags[SWITCH_RTP_FLAG_UDPTL] && !switch_test_flag(frame, SFF_UDPTL_PACKET)) {

            if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO] && rtp_session->payload > 0) {
                send_msg->header.pt = rtp_session->payload;
            }

            send_msg->header.ssrc = htonl(rtp_session->ssrc);
            send_msg->header.seq = htons(++rtp_session->seq);
        }

        if (rtp_sendto(rtp_session, rtp_session->sock_output, rtp_session->remote_addr, 0, frame->packet, &bytes) != SWITCH_STATUS_SUCCESS) {
            return -1;
        }


        rtp_session->stats.outbound.raw_bytes += bytes;
        rtp_session->stats.outbound.media_bytes += bytes;
        rtp_session->stats.outbound.media_packet_count++;
        rtp_session->stats.outbound.packet_count++;
        return (int) bytes;
    }
#ifdef ENABLE_ZRTP
    if (zrtp_on && rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_SEND]) {
        zrtp_session_info_t zrtp_session_info;

        if (zrtp_status_ok == zrtp_session_get(rtp_session->zrtp_session, &zrtp_session_info)) {
            if (zrtp_session_info.sas_is_ready) {

                switch_channel_t *channel = switch_core_session_get_channel(rtp_session->session);

                const char *uuid = switch_channel_get_partner_uuid(channel);
                if (uuid) {
                    switch_core_session_t *other_session;

                    if ((other_session = switch_core_session_locate(uuid))) {
                        switch_channel_t *other_channel = switch_core_session_get_channel(other_session);
                        switch_rtp_t *other_rtp_session = switch_channel_get_private(other_channel, "__zrtp_audio_rtp_session");


                        if (other_rtp_session) {
                            if (zrtp_status_ok == zrtp_session_get(other_rtp_session->zrtp_session, &zrtp_session_info)) {
                                if (rtp_session->zrtp_mitm_tries > ZRTP_MITM_TRIES) {
                                    rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_RECV] = 0;
                                    rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_SEND] = 0;
                                    switch_rtp_clear_flag(other_rtp_session, SWITCH_ZRTP_FLAG_SECURE_MITM_RECV);
                                    switch_rtp_clear_flag(other_rtp_session, SWITCH_ZRTP_FLAG_SECURE_MITM_SEND);
                                } else if (zrtp_status_ok == zrtp_resolve_mitm_call(other_rtp_session->zrtp_stream, rtp_session->zrtp_stream)) {
                                    rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_RECV] = 0;
                                    rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_MITM_SEND] = 0;
                                    switch_rtp_clear_flag(other_rtp_session, SWITCH_ZRTP_FLAG_SECURE_MITM_RECV);
                                    switch_rtp_clear_flag(other_rtp_session, SWITCH_ZRTP_FLAG_SECURE_MITM_SEND);
                                    rtp_session->zrtp_mitm_tries++;
                                }
                                rtp_session->zrtp_mitm_tries++;
                            }
                        }

                        switch_core_session_rwunlock(other_session);
                    }
                }
            }
        }
    }
#endif

    fwd = (rtp_session->flags[SWITCH_RTP_FLAG_RAW_WRITE] && switch_test_flag(frame, SFF_RAW_RTP)) ? 1 : 0;

    if (!fwd && !rtp_session->sending_dtmf && !rtp_session->queue_delay &&
        rtp_session->flags[SWITCH_RTP_FLAG_RAW_WRITE] && (rtp_session->rtp_bugs & RTP_BUG_GEN_ONE_GEN_ALL)) {

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "Generating RTP locally but timestamp passthru is configured, disabling....\n");
        rtp_session->flags[SWITCH_RTP_FLAG_RAW_WRITE] = 0;
        rtp_session->flags[SWITCH_RTP_FLAG_RESET] = 1;
    }

    switch_assert(frame != NULL);

    if (switch_test_flag(frame, SFF_CNG)) {
        if (rtp_session->cng_pt) {
            payload = rtp_session->cng_pt;
        } else {
            payload = 13;
            // return (int) frame->packetlen;
        }
    } else {
        payload = rtp_session->payload;
#if 0
        if (rtp_session->pmaps && *rtp_session->pmaps) {
            payload_map_t *pmap;
            for (pmap = *rtp_session->pmaps; pmap; pmap = pmap->next) {
                if (pmap->current) {
                    payload = pmap->pt;
                }
            }
        }
#endif
    }

    if (switch_test_flag(frame, SFF_RTP_HEADER)) {
        switch_size_t wrote = switch_rtp_write_manual(rtp_session, frame->data, frame->datalen,
                                                      frame->m, frame->payload, (uint32_t) (frame->timestamp), &frame->flags);

        rtp_session->stats.outbound.raw_bytes += wrote;
        rtp_session->stats.outbound.media_bytes += wrote;
        rtp_session->stats.outbound.media_packet_count++;
        rtp_session->stats.outbound.packet_count++;
    }

    if (frame->pmap && rtp_session->pmaps && *rtp_session->pmaps) {
        payload_map_t *pmap;

        switch_mutex_lock(rtp_session->flag_mutex);
        for (pmap = *rtp_session->pmaps; pmap; pmap = pmap->next) {
            if (pmap->negotiated && pmap->hash == frame->pmap->hash) {
                payload = pmap->recv_pt;
                break;
            }
        }
        switch_mutex_unlock(rtp_session->flag_mutex);
    }

    if (fwd) {
        send_msg = frame->packet;
        len = frame->packetlen;

        if (len == (uint32_t)-1) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "len == -1\n");
        }

        ts = 0;
        // Trying this based on http://jira.freeswitch.org/browse/MODSOFIA-90
        //if (frame->codec && frame->codec->agreed_pt == frame->payload) {

        send_msg->header.pt = payload;
        //}
    } else {
        data = frame->data;
        len = frame->datalen;

        if (len == (uint32_t)-1) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "len == -1\n");
        }

        ts = rtp_session->flags[SWITCH_RTP_FLAG_RAW_WRITE] ? (uint32_t) frame->timestamp : 0;
    }

    /*
      if (rtp_session->flags[SWITCH_RTP_FLAG_VIDEO]) {
      send_msg->header.pt = rtp_session->payload;
      }
    */

    return rtp_common_write(rtp_session, send_msg, data, len, payload, ts, &frame->flags);
}

SWITCH_DECLARE(switch_rtp_stats_t *) switch_rtp_get_stats(switch_rtp_t *rtp_session, switch_memory_pool_t *pool)
{
    switch_rtp_stats_t *s;

    if (!rtp_session)
        return NULL;

    if (pool) {
        s = switch_core_alloc(pool, sizeof(*s));
        *s = rtp_session->stats;
    } else {
        s = &rtp_session->stats;
    }

    if (rtp_session->jb) {
#ifndef _USE_NEW_JB_
        s->inbound.jb_max_len = stfu_n_get_most_qlen(rtp_session->jb);
        s->inbound.jb_lost_count = stfu_n_get_miss_count(rtp_session->jb);
#else
        s->inbound.jb_max_len = rtp_session->jb->most_qlen;
        s->inbound.jb_lost_count = rtp_session->jb->missed_count;
        s->inbound.jb_overflow_drop_count = rtp_session->jb->overflow_drop_count;
        s->inbound.jb_toolate_drop_count = rtp_session->jb->dropped_too_late_count;
        s->inbound.jb_total_outoforder_count = rtp_session->jb->out_of_order_count;
        s->inbound.jb_exhaustion_count = rtp_session->jb->jb_exhaustion_count;
        s->inbound.jb_max_drift = rtp_session->jb->max_drift * 1000 / rtp_session->samples_per_second;
        if (rtp_session->jb->total_count)
            s->inbound.jb_average_drift = (rtp_session->jb->cumulative_drift / rtp_session->jb->total_count) *
                                1000 / rtp_session->samples_per_second;
#endif
    }

    do_mos(rtp_session, SWITCH_FALSE);

    switch_mutex_unlock(rtp_session->flag_mutex);

    return s;
}

SWITCH_DECLARE(int) switch_rtp_write_manual(switch_rtp_t *rtp_session,
                                            void *data, uint32_t datalen, uint8_t m, switch_payload_t payload, uint32_t ts, switch_frame_flag_t *flags)
{
    switch_size_t bytes;
    int ret = -1;
    uint16_t new_seq_no;

    if (!switch_rtp_ready(rtp_session) || !rtp_session->remote_addr || datalen > SWITCH_RTP_MAX_BUF_LEN) {
        return -1;
    }

    if (!rtp_write_ready(rtp_session, datalen, __LINE__)) {
        return 0;
    }

    WRITE_INC(rtp_session);

    rtp_session->write_msg = rtp_session->send_msg;
    // rtp_session->write_msg.header.seq = htons(++rtp_session->seq);
    rtp_session->write_msg.header.ts = htonl(ts);
    rtp_session->write_msg.header.pt = payload;
    rtp_session->write_msg.header.m = m;
    memcpy(rtp_session->write_msg.body, data, datalen);

    new_seq_no = rtp_session->last_bridge_seq[1] + 1;
    rtp_session->write_count += 1;
    rtp_session->write_msg.header.seq = htons(new_seq_no);
    rtp_session->last_bridge_seq[1] = new_seq_no;

    bytes = rtp_header_len + datalen;

#ifdef ENABLE_SRTP
    if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND]) {

        int sbytes = (int) bytes;
        err_status_t stat;

        if (rtp_session->flags[SWITCH_RTP_FLAG_SECURE_SEND_RESET]) {
            switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_SECURE_SEND_RESET);
            srtp_dealloc(rtp_session->send_ctx[rtp_session->srtp_idx_rtp]);
            rtp_session->send_ctx[rtp_session->srtp_idx_rtp] = NULL;
            if ((stat = srtp_create(&rtp_session->send_ctx[rtp_session->srtp_idx_rtp], &rtp_session->send_policy[rtp_session->srtp_idx_rtp]))) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error! RE-Activating Secure RTP SEND\n");
                ret = -1;
                goto end;
            } else {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "RE-Activating Secure RTP SEND\n");
            }
        }

        stat = srtp_protect(rtp_session->send_ctx[rtp_session->srtp_idx_rtp], &rtp_session->write_msg.header, &sbytes);
        if (stat) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: SRTP protection failed with code %d\n", stat);
        }
        bytes = sbytes;
    }
#endif
#ifdef ENABLE_ZRTP
    /* ZRTP Send */
    if (zrtp_on && !rtp_session->flags[SWITCH_RTP_FLAG_PROXY_MEDIA]) {
        unsigned int sbytes = (int) bytes;
        zrtp_status_t stat = zrtp_status_fail;

        stat = zrtp_process_rtp(rtp_session->zrtp_stream, (void *) &rtp_session->write_msg, &sbytes);

        switch (stat) {
        case zrtp_status_ok:
            break;
        case zrtp_status_drop:
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection drop with code %d\n", stat);
            ret = (int) bytes;
            goto end;
            break;
        case zrtp_status_fail:
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_ERROR, "Error: zRTP protection fail with code %d\n", stat);
            break;
        default:
            break;
        }

        bytes = sbytes;
    }
#endif
    
    if (rtp_sendto(rtp_session, rtp_session->sock_output, rtp_session->remote_addr, 0, (void *) &rtp_session->write_msg, &bytes) != SWITCH_STATUS_SUCCESS) {
        rtp_session->seq--;
        ret = -1;
        goto end;
    }

    if (((*flags) & SFF_RTP_HEADER)) {
        rtp_session->last_write_ts = ts;
        rtp_session->flags[SWITCH_RTP_FLAG_RESET] = 0;
    }

    ret = (int) bytes;

 end:

    WRITE_DEC(rtp_session);

    return ret;
}

SWITCH_DECLARE(uint32_t) switch_rtp_get_ssrc(switch_rtp_t *rtp_session)
{
    return rtp_session->ssrc;
}

SWITCH_DECLARE(void) switch_rtp_set_private(switch_rtp_t *rtp_session, void *private_data)
{
    rtp_session->private_data = private_data;
}

SWITCH_DECLARE(void *) switch_rtp_get_private(switch_rtp_t *rtp_session)
{
    return rtp_session->private_data;
}

SWITCH_DECLARE(uint32_t) switch_rtp_get_samples_per_second(switch_rtp_t *rtp_session)
{
    return rtp_session->samples_per_second;
}

SWITCH_DECLARE(uint32_t) switch_rtp_get_packets_received(switch_rtp_t *rtp_session)
{
    return rtp_session->total_received;
}

SWITCH_DECLARE(void) switch_rtp_set_fuze_app(switch_channel_t *channel, switch_bool_t val)
{
    switch_rtp_t *rtp_session;

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (!rtp_session) {
        return;
    }

    rtp_session->is_fuze_app = val;

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "switch_rtp_set_fuze_app %s\n",
                      (val ? "TRUE" : "FALSE"));
}

#define MAX_DESCRIPTION_LEN 1024

SWITCH_DECLARE(void) switch_rtp_set_webrtc_neteq(switch_rtp_t *rtp_session, switch_bool_t val)
{
    char description[MAX_DESCRIPTION_LEN];

    if (!rtp_session)
        return;

    if (rtp_session->jb)
        switch_rtp_deactivate_jitter_buffer(rtp_session);

    rtp_session->use_webrtc_neteq = val;

    sprintf(rtp_session->rtp_conn_name, "CRTP%04x", rtp_session->id);
    sprintf(rtp_session->rtcp_conn_name, "CRTCP%04x", rtp_session->id);

    rtp_session->is_bridge = SWITCH_FALSE;
    // switch_rtp_clear_flag(rtp_session, SWITCH_RTP_FLAG_PROXY_MEDIA);

    fuze_transport_set_connection_name(rtp_session->rtp_conn, rtp_session->rtp_conn_name);
    fuze_transport_set_connection_name(rtp_session->rtcp_conn, rtp_session->rtcp_conn_name);

    sprintf(description, "%s l=(%s:%u)/r=(%s:%u)", rtp_session->rtp_conn_name, 
            rtp_session->local_host_str, rtp_session->local_port,
            rtp_session->remote_host_str, rtp_session->remote_port);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "conference description %s\n",
                      description);
}

SWITCH_DECLARE(switch_bool_t) switch_rtp_get_webrtc_neteq(switch_rtp_t *rtp_session)
{
    return (rtp_session ? rtp_session->use_webrtc_neteq : SWITCH_FALSE);
}

SWITCH_DECLARE(void) switch_rtp_reset_rtp_stats(switch_channel_t *channel)
{
    switch_rtp_t *rtp_session;

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (!rtp_session) {
        return;
    }

    for (int i = 0; i < STATS_MAX; i++) {
        memset(rtp_session->stats.str[i], 0, sizeof(rtp_session->stats.str[i]));
        rtp_session->stats.eos[i] = rtp_session->stats.str[i];
        rtp_session->stats.len[i] = RTP_STATS_STR_SIZE;
    }

    rtp_session->stats.duration = 0;
}

#define rtp_stat_add_value(rtp_session, rtpstat, type_str, value, last_value) \
    { \
        int statno = rtpstat-RTP_RECV_RATE; \
        if (value != last_value || rtp_session->stats.len[statno] == RTP_STATS_STR_SIZE) { \
            if (rtp_session->stats.len[statno] < RTP_STATS_STR_SIZE) { \
                strncat(rtp_session->stats.eos[statno], ":", rtp_session->stats.len[statno]); \
                rtp_session->stats.eos[statno] += 1; \
                rtp_session->stats.len[statno] -= 1; \
            } \
            switch_snprintf(rtp_session->stats.eos[statno], rtp_session->stats.len[statno], type_str ",%" PRId64 "", value, rtp_session->stats.time); \
            rtp_session->stats.len[statno] -= strlen(rtp_session->stats.eos[statno]); \
            rtp_session->stats.eos[statno] += strlen(rtp_session->stats.eos[statno]); \
            last_value = value; \
        }\
    }

#define MAX_WAITING_TIME_TO_CHECK 50

SWITCH_DECLARE(void) switch_rtp_update_rtp_stats(switch_channel_t *channel, int level_in, int level_out, int active)
{
    switch_rtp_t *rtp_session;
    void *neteq_inst;
    WebRtcNetEQ_NetworkStatistics nwstats;
    WebRtcNetEQ_ProcessingActivity processing;
    int jbuf = -1;
    uint16_t local_send = 0, local_recv = 0;
    int rawframeswaiting = 0, waiting_times_ms[MAX_WAITING_TIME_TO_CHECK];
    int max_proc_time = 0;
    short loss = 0;

//  int pkts_in_buffer, max_pkts_in_buffer
// void WebRtcNetEQ_GetProcessingActivity(void* inst, WebRtcNetEQ_ProcessingActivity* stat, int clear);
// void WebRtcNetEQ_GetJitterBufferSize(void* inst, WebRtcNetEQ_ProcessingActivity* stat);

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (!rtp_session) {
        return;
    }

    neteq_inst = switch_core_get_neteq_inst(rtp_session->session);
    if (neteq_inst) {
        rawframeswaiting = WebRtcNetEQ_GetRawFrameWaitingTimes(neteq_inst, MAX_WAITING_TIME_TO_CHECK, waiting_times_ms);
        WebRtcNetEQ_GetJitterBufferSize(neteq_inst, &processing);
        if (WebRtcNetEQ_GetNetworkStatistics(neteq_inst, &nwstats) == 0) {
            jbuf = nwstats.currentBufferSize;
            loss = (short)(((float)nwstats.currentPacketLossRate/16384.0)*100);
            for (int i = 0; i < rawframeswaiting; i++) {
                if (waiting_times_ms[i] > max_proc_time) {
                    max_proc_time = waiting_times_ms[i];
                }
            }
            if ((jbuf > 250 && rtp_session->stats.last_jitter < 250) ||
                (jbuf < 250 && rtp_session->stats.last_jitter > 250) ||
                (nwstats.preferredBufferSize > 250 && rtp_session->stats.last_pref_jbuf < 250) ||
                (nwstats.preferredBufferSize < 250 && rtp_session->stats.last_pref_jbuf > 250) ||
                abs(jbuf - nwstats.preferredBufferSize) > 100 ||
                (max_proc_time > 250 && rtp_session->stats.last_proc_time < 250) ||
                (max_proc_time < 250 && rtp_session->stats.last_proc_time > 250)) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                                  "jitter buffer stats: curr:%d pref:%d pkts:%d "
                                  "wait[%d]=[%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d]\n",
                                  jbuf, nwstats.preferredBufferSize,
                                  processing.pkts_in_buffer, rawframeswaiting,
                                  waiting_times_ms[0],  waiting_times_ms[1],  waiting_times_ms[2],  waiting_times_ms[3],  waiting_times_ms[4],
                                  waiting_times_ms[5],  waiting_times_ms[6],  waiting_times_ms[7],  waiting_times_ms[8],  waiting_times_ms[9],
                                  waiting_times_ms[10], waiting_times_ms[11], waiting_times_ms[12], waiting_times_ms[13], waiting_times_ms[14],
                                  waiting_times_ms[15], waiting_times_ms[16], waiting_times_ms[17], waiting_times_ms[18], waiting_times_ms[19]);
            }
        }
    } else {
        jbuf = rtp_session->stats.rtcp.jitter;
    }

    /*
     * switch_rtp.c:2459 audio stat 49.00 467/947 flaws: 480 mos: 2.52 v: 444.73 15.47/444.73
     */
    if (jbuf != -1) {
        rtp_stat_add_value(rtp_session, RTP_JITTER_BUFFER, "%d", jbuf, rtp_session->stats.last_jitter);
        if (rtp_session->stats.duration % 10 == 0) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "jitter buffer size:%d\n", jbuf);
        }
        if (neteq_inst) {
            rtp_stat_add_value(rtp_session, RTP_PREF_JBUF, "%d", nwstats.preferredBufferSize, rtp_session->stats.last_pref_jbuf);
            rtp_stat_add_value(rtp_session, RTP_JBUF_PKTS, "%d", processing.pkts_in_buffer, rtp_session->stats.last_jbuf_pkts);
            rtp_stat_add_value(rtp_session, RTP_MAX_PROC_TIME, "%d", max_proc_time, rtp_session->stats.last_proc_time);
            rtp_stat_add_value(rtp_session, RTP_PER_LOST, "%d", loss, rtp_session->stats.last_lost_percent);
        }
    }

    if (jbuf == -1 || !neteq_inst) {
        if (rtp_session->stats.inbound.lossrate) {
            short loss;
            loss = ((short)(rtp_session->stats.inbound.lossrate*100)/100);
            rtp_stat_add_value(rtp_session, RTP_PER_LOST, "%d", loss, rtp_session->stats.last_lost_percent);
        }
    }

    if (level_in == -1 && rtp_session->level_in > -1) {
        level_in = rtp_session->level_in;
        rtp_session->level_in = -1;
    }

    if (level_in > -1) {
        rtp_stat_add_value(rtp_session, RTP_RECV_LEVEL, "%d", level_in, rtp_session->stats.last_recv_level);
    }

    if (rtp_session->stats.inbound.mos) {
        float mos;
        mos = ((float)(int)(rtp_session->stats.inbound.mos*100)/100);
        rtp_stat_add_value(rtp_session, RTP_MOS, "%0.2f", mos, rtp_session->stats.last_mos);
    }

    if (rtp_session->stats.inbound.R) {
        float r;
        r = ((float)(int)(rtp_session->stats.inbound.R*100)/100);
        rtp_stat_add_value(rtp_session, RTP_R, "%0.2f", r, rtp_session->stats.last_r);
    }

#if 0
    if (rtp_session->stats.inbound.variance) {
        rtp_stat_add_value(rtp_session, RTP_VARIANCE, "%0.2f", rtp_session->stats.inbound.variance, rtp_session->stats.last_variance);
    }
#endif

    if (rtp_session->stats.inbound.flaws) {
        rtp_stat_add_value(rtp_session, RTP_FLAWS, "%0ld", rtp_session->stats.inbound.flaws, rtp_session->stats.last_flaws);
    }

    if (level_out == -1 && rtp_session->level_out > -1) {
        level_out = rtp_session->level_out;
        rtp_session->level_out = -1;
    }

    if (level_out > -1) {
        rtp_stat_add_value(rtp_session, RTP_SEND_LEVEL, "%d", level_out, rtp_session->stats.last_send_level);

        if (level_out < 300) {
            if (rtp_session->low_level_duration == 0) {
                rtp_session->low_level_start = switch_time_now();
            }
            rtp_session->low_level_duration += 1;
        } else if (rtp_session->low_level_duration >= 3) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO, "Normal output level (%d) after %ds at low level\n",
                              level_out, rtp_session->low_level_duration);
            rtp_session->low_level_duration = 0;
        }
    }


    if (active > -1) {
        rtp_stat_add_value(rtp_session, RTP_ACTIVE_SPEAKER, "%d", active, rtp_session->stats.last_active_speaker);
    }

    if (rtp_session->rtp_conn) {
        fuze_transport_get_rates(rtp_session->rtp_conn, &local_send, &local_recv);
        rtp_stat_add_value(rtp_session, RTP_SEND_RATE, "%d", local_send, rtp_session->stats.last_send_rate);
        rtp_stat_add_value(rtp_session, RTP_RECV_RATE, "%d", local_recv, rtp_session->stats.last_recv_rate);
#if 0
        if (local_send == 0 || (!switch_core_session_get_cn_state(rtp_session->session) && local_recv == 0)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "bad local send(%d) or recv(%d)\n",
                              local_send, local_recv);
        }
#endif

        rtp_session->stats.recv_rate_history[rtp_session->stats.recv_rate_history_idx] = local_recv;
        rtp_session->stats.recv_rate_history_idx = (rtp_session->stats.recv_rate_history_idx + 1) % RTP_STATS_RATE_HISTORY;
        if (neteq_inst && rtp_session->stats.time > RTP_STATS_RATE_HISTORY) {
            if (!switch_core_session_get_cn_state(rtp_session->session)) {
                if (rtp_session->stats.ignore_rate_period > 0) {
                    rtp_session->stats.ignore_rate_period -= 1;
                } else {
                    float delta = 0.0;
                    if (rtp_session->stats.rx_congestion_state == RTP_RX_CONGESTION_GOOD) {
                        for (int i = 0; i < RTP_STATS_RATE_HISTORY_BAD; i++) {
                            int idx = rtp_session->stats.recv_rate_history_idx - (i+1);
                            idx = (idx < 0) ? (idx + RTP_STATS_RATE_HISTORY) : idx;
                            delta += abs(rtp_session->stats.recv_rate_history[idx] - 68);
                        }
                        delta = delta / (float)RTP_STATS_RATE_HISTORY_BAD;
                        if ((delta > 5 || jbuf > 750)) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "Transition to bad rx congestion state: delta:%f\n",
                                              delta);
                            rtp_session->send_rtcp |=  (SWITCH_RTCP_NORMAL | SWITCH_RTCP_RX_CONGESTION);
                            rtp_session->stats.rx_congestion_state = RTP_RX_CONGESTION_BAD;
                        }
                    } else {
                        for (int i = 0; i < RTP_STATS_RATE_HISTORY_GOOD; i++) {
                            int idx = rtp_session->stats.recv_rate_history_idx - (i+1);
                            idx = (idx < 0) ? (idx + RTP_STATS_RATE_HISTORY) : idx;
                            delta += abs(rtp_session->stats.recv_rate_history[idx] - 68);
                        }
                        delta = delta / (float)RTP_STATS_RATE_HISTORY_GOOD;
                        if (delta < 2 && jbuf < 500) {
                            delta = 0;
                            rtp_session->stats.rx_congestion_state = RTP_RX_CONGESTION_GOOD;
                            rtp_session->send_rtcp |=  (SWITCH_RTCP_NORMAL | SWITCH_RTCP_RX_CONGESTION);
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_WARNING, "Transition to good congestion state: delta:%f\n",
                                              delta);
                        }
                    }
                }
            } else {
                rtp_session->stats.ignore_rate_period = RTP_STATS_RATE_HISTORY;
            }
        }
    }

    rtp_session->stats.time += 1;
    rtp_session->stats.duration += 1;
}

SWITCH_DECLARE(void) switch_rtp_set_event(switch_rtp_t *rtp_session, rtp_events_t event)
{
    switch_time_t now;
    int exp_period;

    if (!rtp_session)
        return;

    rtp_session->stats.last_event |= event;
    switch(event)
    {
        case RTP_EVENT_HIGH_CONSECUTIVE_PACKET_LOSS:
            now = switch_micro_time_now();
            exp_period = (rtp_session->samples_per_second / rtp_session->samples_per_interval) * ((now - rtp_session->stats.cur_period_start_time) / 1000000.);
            if (!switch_core_session_get_cn_state(rtp_session->session)) {
                rtp_session->stats.period_lost_count = exp_period - rtp_session->stats.period_received;
            } else {
                rtp_session->stats.period_lost_count = 0;
            }
            rtp_session->stats.last_period_received = rtp_session->stats.period_received;

            if (rtp_session->use_webrtc_neteq == SWITCH_FALSE) {
                rtp_session->stats.consecutive_skip_packet = 0;
                rtp_session->stats.last_period_skip_packet = rtp_session->stats.period_skip_packet_count;
            }
            break;

        case RTP_EVENT_PERIODIC:
            now = switch_micro_time_now();
            exp_period = (rtp_session->samples_per_second / rtp_session->samples_per_interval) * ((now - rtp_session->stats.cur_period_start_time) / 1000000.);
            rtp_session->stats.cur_period_start_time = now;
            if (!switch_core_session_get_cn_state(rtp_session->session)) {
                rtp_session->stats.period_lost_count = exp_period - rtp_session->stats.period_received;
            } else {
                rtp_session->stats.period_lost_count = 0;
            }
            rtp_session->stats.last_period_received = rtp_session->stats.period_received;
            rtp_session->stats.period_received = 0;

            if (rtp_session->use_webrtc_neteq == SWITCH_FALSE) {
                rtp_session->stats.last_period_skip_packet = rtp_session->stats.period_skip_packet_count;
                rtp_session->stats.period_skip_packet_count = 0;
            }
            break;

        default:;
    }
}

SWITCH_DECLARE(int) switch_rtp_get_rtcp_interval(switch_rtp_t *rtp_session)
{
    return (rtp_session ? rtp_session->rtcp_interval : 0);
}

SWITCH_DECLARE(void) switch_rtp_set_send_rtcp(switch_rtp_t *rtp_session, int val)
{
    if (rtp_session) {
        rtp_session->send_rtcp = val;
    }
}

SWITCH_DECLARE(void) switch_rtp_set_been_active_talker(switch_rtp_t *rtp_session, int val)
{
    if (rtp_session) {
        rtp_session->been_active_talker = val;
    }
}

SWITCH_DECLARE(void) switch_rtp_update_ts(switch_channel_t *channel, int increment) {
    switch_rtp_t *rtp_session;

    if (!channel) { return;}

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (!rtp_session) {
        return;
    }

    if (rtp_session->use_next_ts) {
        rtp_session->next_ts += increment;
    }
}


SWITCH_DECLARE(void) switch_bridge_channel_get_ts_and_seq(switch_channel_t *chana, switch_channel_t *chanb) {
    switch_rtp_t *rtp_session_a, *rtp_session_b;

    if (!chana || !chanb) { return; }

    rtp_session_a = switch_channel_get_private(chana, "__rtcp_audio_rtp_session");
    rtp_session_b = switch_channel_get_private(chanb, "__rtcp_audio_rtp_session");

    if (!rtp_session_a || !rtp_session_b) {
        return;
    }

    if (rtp_session_b->anchor_next_seq != rtp_session_b->last_bridge_seq[0]) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session_a->session), SWITCH_LOG_WARNING,
                          "missed a send seq=%u ts=%u\n", rtp_session_b->anchor_next_seq, rtp_session_b->anchor_next_ts);
    }
    if ((rtp_session_b->anchor_next_seq+1) != (rtp_session_a->last_seq)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session_a->session), SWITCH_LOG_WARNING,
                          "missed a send prev seq=%u curr seq=%u base=%u\n", rtp_session_b->anchor_next_seq, rtp_session_a->last_seq, rtp_session_b->anchor_base_seq);
    }

    rtp_session_b->anchor_next_ts = rtp_session_a->last_ts;
    rtp_session_b->anchor_next_seq = rtp_session_a->last_seq;
    rtp_session_a->anchor_next_set = SWITCH_TRUE;
    rtp_session_b->anchor_next_set = SWITCH_TRUE;
}


SWITCH_DECLARE(void) switch_check_bridge_channel_timestamps(switch_channel_t *chana, switch_channel_t *chanb) {
    switch_rtp_t *rtp_session_a, *rtp_session_b;
    switch_time_t rx_delta_time[2], tx_delta_time[2];
    uint32_t rx_delta_ts[2], tx_delta_ts[2];
    switch_time_t now = switch_time_now();
    int64_t diff[2][2];
    int64_t diff_rx_tx[2];

    if (!chana || !chanb) { return; }

    rtp_session_a = switch_channel_get_private(chana, "__rtcp_audio_rtp_session");
    rtp_session_b = switch_channel_get_private(chanb, "__rtcp_audio_rtp_session");

    if (!rtp_session_a || !rtp_session_b) {
        return;
    }

    if (now - rtp_session_a->time_of_last_xchannel_ts_check < 1000*1000*10) {
        return;
    }

    /* check chan a rx and chan b tx */
    rx_delta_time[0] = (now - rtp_session_a->time_of_first_rx_ts)/1000;
    rx_delta_ts[0] = (rtp_session_a->last_ts - rtp_session_a->first_rx_ts)/8;
    diff[0][0] = rx_delta_time[0] - rx_delta_ts[0];

    tx_delta_time[0] = (now - rtp_session_b->time_of_first_ts)/1000;
    tx_delta_ts[0] = (rtp_session_b->last_write_ts - rtp_session_b->first_ts)/8;
    diff[0][1] = tx_delta_time[0] - tx_delta_ts[0];
    diff_rx_tx[0] = diff[0][1] - diff[0][0];

    /* check chan b rx and chan a tx */
    rx_delta_time[1] = (now - rtp_session_b->time_of_first_rx_ts)/1000;
    rx_delta_ts[1] = (rtp_session_b->last_ts - rtp_session_b->first_rx_ts)/8;
    diff[1][0] = rx_delta_time[1] - rx_delta_ts[1];

    tx_delta_time[1] = (now - rtp_session_a->time_of_first_ts)/1000;
    tx_delta_ts[1] = (rtp_session_a->last_write_ts - rtp_session_a->first_ts)/8;
    diff[1][1] = tx_delta_time[1] - tx_delta_ts[1];
    diff_rx_tx[1] = diff[1][1] - diff[1][0];

    if (abs(diff_rx_tx[0]) > 60) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session_a->session), SWITCH_LOG_WARNING,
                          "TS delta A->B %" PRId64 " [tx(%" PRId64 " - %u) - rx (%" PRId64 " - %u)]\n",
                          diff_rx_tx[0], tx_delta_time[0], tx_delta_ts[0], rx_delta_time[0], rx_delta_ts[0]);
    }
    if (abs(diff_rx_tx[1]) > 60) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session_b->session), SWITCH_LOG_WARNING,
                          "TS delta B->A %" PRId64 " [tx(%" PRId64 " - %u) - rx (%" PRId64 " - %u)]\n",
                          diff_rx_tx[1], tx_delta_time[1], tx_delta_ts[1], rx_delta_time[1], rx_delta_ts[1]);
    }
    rtp_session_a->time_of_last_xchannel_ts_check = now;
    rtp_session_b->time_of_last_xchannel_ts_check = now;
}

SWITCH_DECLARE(void) switch_rtp_silence_transport(switch_channel_t *channel, int size)
{
    switch_rtp_t *rtp_session;

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (!rtp_session) {
        return;
    }

    if (rtp_session->ignore_rtp_size != size && !rtp_session->flags[SWITCH_ZRTP_FLAG_SECURE_RECV]) {
        if (size > 0) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                              "Silencing session for packets < %d bytes\n", size);
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(rtp_session->session), SWITCH_LOG_INFO,
                              "Disabling silencing for session\n");
        }

        fuze_transport_ignore_packets(rtp_session->rtp_conn, size);
        rtp_session->ignore_rtp_size = size;
    }
    return;
}

SWITCH_DECLARE(void) switch_rtp_set_active(switch_channel_t *channel, switch_bool_t active)
{
    switch_rtp_t *rtp_session;

    if (!channel) { return; }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (!rtp_session) {
        return;
    }

    rtp_session->active = active;
}

SWITCH_DECLARE(void) switch_rtp_set_muted(switch_channel_t *channel, switch_bool_t muted)
{
    switch_rtp_t *rtp_session;

    if (!channel) { return; }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (!rtp_session) {
        return;
    }

    rtp_session->muted = muted;
}

SWITCH_DECLARE(switch_bool_t) switch_rtp_get_muted(switch_channel_t *channel)
{
    switch_rtp_t *rtp_session;

    if (!channel) { return SWITCH_FALSE; }

    rtp_session = switch_channel_get_private(channel, "__rtcp_audio_rtp_session");

    if (!rtp_session) {
        return SWITCH_FALSE;
    }

	return rtp_session->muted;
}


/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
