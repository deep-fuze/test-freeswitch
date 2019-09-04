#ifndef __WEBRTC_NETEQ_H__
#define __WEBRTC_NETEQ_H__

#include "interface/webrtc_neteq_internal.h"

typedef void* (*app_memory_alloc_t) (void *pool, uint32_t size);

typedef enum {
	WebRtcNetEQ_NOT_STARTED = -2,
	WebRtcNetEQ_ERROR = -1,
	WebRtcNetEQ_SUCCESS = 0,
} WebRtcNetEQ_status_t;

WebRtcNetEQ_status_t WebRtcNetEQ_Init_inst(void **inst, app_memory_alloc_t alloc_cb, void *mempool, 
			void *decoder, uint32_t rate, uint32_t payload, 
			const char *codecname, uint16_t packet_ms, void **resampler, 
			resampler_create_cb_t resampler_create_cb, resample_cb_t resample_cb);

WebRtcNetEQ_status_t WebRtcNetEQ_Insert(void *inst, int8_t *payload, uint32_t payload_len, 
				uint8_t payload_type, uint16_t seqno,
				uint32_t ts, uint32_t ssrc, uint8_t marker);

WebRtcNetEQ_status_t WebRtcNetEQ_Extract(void *inst, int8_t *pcm_data, 
				uint32_t *outlen, uint16_t *consecutive_lost, uint32_t *total_decoded, uint8_t suppress_lost);

void *WebRtcNetEQ_Inst(void *inst);

#ifndef __EXT_LOG_CB__
typedef void (*log_cb_fp)(int16_t level, const char * format, ...);
#define __EXT_LOG_CB__
#endif

extern log_cb_fp app_log_cb;
void WebRtcNetEQ_RegisterLogCB(log_cb_fp log_cb);

#endif
