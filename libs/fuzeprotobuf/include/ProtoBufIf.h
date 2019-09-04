//
//  ProtoBufIf.h
//
//  Created by Raghavendra Thodime on 02/04/14
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __PROTO_BUF_IF_H__
#define __PROTO_BUF_IF_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __EXT_LOG_CB__
typedef void (*log_cb_fp)(int16_t level, const char * format, ...);
#define __EXT_LOG_CB__
#endif

extern log_cb_fp app_log_cb;
void proto_buf_register_logcb(log_cb_fp log_cb);

/*
 * RTCP Application Extension interface
 * encoded : [output] Buffer where encoded stream will be present on success.
 * len : [input] maximum size of the encoded buffer [output] contains the output encoded length
 * returns 0 on success.
 */
typedef struct {
    uint32_t    jb_depth;
    uint8_t     late_and_lost_percent;
    uint8_t     been_active_talker;
    uint16_t    chop_events[10];
} rtcp_app_extn_t;

int protos_encode_rtcp_app_extn(rtcp_app_extn_t *app_extn, char *encoded, int *len);

int protos_decode_rtcp_app_extn(char *encoded, int len, rtcp_app_extn_t *app_extn);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
