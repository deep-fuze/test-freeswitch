#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include "interface/webrtc_neteq.h"
#include "interface/webrtc_neteq_help_macros.h"
#include "interface/webrtc_neteq_if.h"

#include "g722_interface.h"
#include "g711_interface.h"
#include "opus_interface.h"

#define CONVERT_STATUS(ret) ((ret) == 0 ? WebRtcNetEQ_SUCCESS : \
				((ret == -2) ? WebRtcNetEQ_NOT_STARTED : WebRtcNetEQ_ERROR))

typedef struct {
	void *main_inst;
	uint16_t local_seqno;
	uint16_t last_rd_seqno;	
	uint16_t pkt_ms;
	uint32_t rate;
	uint16_t ts_increment;
} neteq_inst_t;

WebRtcNetEQ_status_t WebRtcNetEQ_Init_inst(void **inst, app_memory_alloc_t alloc_cb, void *mempool, 
			void *decoder, uint32_t rate, uint32_t payload, 
			const char *codecname, uint16_t packet_ms, void **resampler,
			resampler_create_cb_t resampler_create_cb, resample_cb_t resample_cb)
{
	int memorySize = 0;
	enum WebRtcNetEQDecoder usedCodec;
	int16_t *jb_buffer;
	int max_pkts = 0, buf_size = 0, overhead = 0;
	WebRtcNetEQ_CodecDef codecInst;
	char cmd[64] = "";
	neteq_inst_t *neteq_inst;

	if (inst == NULL || codecname == NULL) {
		strncpy(cmd, "Invalid-Parameters", sizeof(cmd) - 1);
		goto error;	
	}

	if (packet_ms == 0 || packet_ms % 10) {
		strncpy(cmd, "packet_ms not multiple of ten", sizeof(cmd) - 1);
		goto error;	
	}

	/*
	 * We will allocate memory to store both neteq's internal instance and 
	 * neteq_inst_t structures. neteq_inst_t is stored at the top and 
	 * neteq_inst_t->main_inst will point to the rest of the memory.
	 */
	WebRtcNetEQ_AssignSize(&memorySize);
	memorySize += sizeof(neteq_inst_t);
	if ((neteq_inst = (neteq_inst_t *) alloc_cb(mempool, memorySize)) == NULL) {
		strncpy(cmd, "alloc_cb", sizeof(cmd) - 1);
		goto error;	
	}

	if (WebRtcNetEQ_Assign(&neteq_inst->main_inst, neteq_inst + 1)) {
		strncpy(cmd, "WebRtcNetEQ_Assign", sizeof(cmd) - 1);
		goto error;	
	}

	/*
	 * We will initialize neteq to run at 10ms frame rate.
         * When initialized at higher rates, issues have been observed while neteq
	 * tries to do agressive expand on bursty losses.
	 */
	if (WebRtcNetEQ_Init(neteq_inst->main_inst, rate, 10)) {
		strncpy(cmd, "WebRtcNetEQ_Init", sizeof(cmd) - 1);
		goto error;	
	}

	if (WebRtcNetEQ_SetAVTPlayout(neteq_inst->main_inst, 0)) {
		strncpy(cmd, "WebRtcNetEQ_SetAVTPlayout", sizeof(cmd) - 1);
		goto error;	
	}

	if (WebRtcNetEQ_SetPlayoutMode(neteq_inst->main_inst, kPlayoutOn)) {
		strncpy(cmd, "WebRtcNetEQ_SetPlayoutMode", sizeof(cmd) - 1);
		goto error;	
	}

	switch (payload) {
	case 0:
		{
		usedCodec = kDecoderPCMu;

		app_log_cb(6, "INFO: Created PCMU interface. rate=%u\n", rate);		
		SET_CODEC_PAR(codecInst, usedCodec, payload, NULL, rate);
		SET_PCMU_FUNCTIONS(codecInst);
		break;
		}

	case 8:
		{
		usedCodec = kDecoderPCMa;

		app_log_cb(6, "INFO: Created PCMA interface. rate=%u\n", rate);		
		SET_CODEC_PAR(codecInst, usedCodec, payload, NULL, rate);
		SET_PCMA_FUNCTIONS(codecInst);
		break;
		}

	case 9:
		{
		G722DecInst *dec_inst;

		usedCodec = kDecoderG722;

		app_log_cb(6, "INFO: Created G722 interface. rate=%u\n", rate);
		if (WebRtcG722_AssignDecoder(&dec_inst, decoder)) {
			strncpy(cmd, "WebRtcG722_AssignDecoder", sizeof(cmd) - 1);
			goto error;	
		}

		SET_CODEC_PAR(codecInst, usedCodec, payload, dec_inst, rate);
		SET_G722_FUNCTIONS(codecInst);
		break;
		}

	default:
		if (payload >= 96) {
			if (!strcasecmp(codecname, "opus")) {
				OpusDecInst *dec_inst = (OpusDecInst*)alloc_cb(mempool, sizeof(OpusDecInst *));

				if (rate != 48000){
					*resampler = NULL;
				} else {
					*resampler = NULL;
					resample_cb = NULL;
				}		
				
				usedCodec = kDecoderOpus;

				/*if (WebRtcOpus_AssignDecoder(dec_inst, decoder, *resampler,
						resample_cb, rate)) {
					strncpy(cmd, "WebRtcOpus_AssignDecoder", sizeof(cmd) - 1);
					goto error;
				}*/
				if (WebRtcOpus_AssignDecoder(dec_inst, decoder)) {
				 strncpy(cmd, "WebRtcOpus_AssignDecoder", sizeof(cmd) - 1);
				 goto error;
				}

				if (WebRtcOpus_DecoderInit(dec_inst)) {
					strncpy(cmd, "WebRtcOpus_DecoderInit", sizeof(cmd) - 1);
					goto error;	
				}

				app_log_cb(6, "INFO: Created OPUS interface: %u\n", rate);		

				SET_CODEC_PAR(codecInst, usedCodec, payload, dec_inst, rate);
				SET_OPUS_FUNCTIONS(codecInst);
				break;
			}
		} else {
			strncpy(cmd, "Invalid Payload", sizeof(cmd) - 1);
			goto error;	
		}
	}

	if (WebRtcNetEQ_CodecDbAdd(neteq_inst->main_inst, &codecInst)) {
		strncpy(cmd, "WebRtcNetEQ_CodecDbAdd", sizeof(cmd) - 1);
		goto error;	
	}

	if (WebRtcNetEQ_GetRecommendedBufferSize(neteq_inst->main_inst, &usedCodec, 1, 
					kTCPLargeJitter, &max_pkts, &buf_size, &overhead)) {
		strncpy(cmd, "WebRtcNetEQ_GetRecommendedBufferSize", sizeof(cmd) - 1);
		goto error;	
	}

	jb_buffer = (int16_t *) alloc_cb(mempool, buf_size);
	if (WebRtcNetEQ_AssignBuffer(neteq_inst->main_inst, max_pkts, jb_buffer, buf_size)) {
		strncpy(cmd, "WebRtcNetEQ_AssignBuffer", sizeof(cmd) - 1);
		goto error;	
	}

	neteq_inst->local_seqno = neteq_inst->last_rd_seqno = 0;
	neteq_inst->pkt_ms = packet_ms;
	neteq_inst->rate = rate;
	/*
	 * For G722, timestamps always jump at 8Khz even though codec itself
	 * operates at 16Khz.
	 */
	if (payload == 9)
		neteq_inst->ts_increment = neteq_inst->pkt_ms * 8;
	else 
		neteq_inst->ts_increment = ((rate / 8000) * neteq_inst->pkt_ms * 8);

	*inst = neteq_inst;
	return WebRtcNetEQ_SUCCESS;

error:
	*inst = NULL;
	app_log_cb(3, "%s memorySize=%d rate=%u payload=%u codec=%s packet_ms=%u max_pkts=%u buf_size=%u overhead=%u\n", 
					cmd, memorySize, rate, payload, codecname, packet_ms, max_pkts, buf_size, overhead);
	return WebRtcNetEQ_ERROR;
}

static const uint32_t kMaskTimestamp = 0x03ffffff;
WebRtcNetEQ_status_t WebRtcNetEQ_Insert(void *inst, int8_t *payload, uint32_t payload_len,
										uint8_t payload_type, uint16_t seqno,
										uint32_t ts, uint32_t ssrc, uint8_t marker)
{
	WebRtcNetEQ_RTPInfo rtpinfo;
	struct timespec spec;
	uint32_t now_in_ms, time_ms;
	neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;
    int ret;

	rtpinfo.payloadType = payload_type;
	rtpinfo.SSRC = ssrc;
	rtpinfo.markerBit = marker;
	rtpinfo.sequenceNumber = seqno;
	rtpinfo.timeStamp = ts;

	/*
	 * Now convert timestamp into timestamp units of codec.
	 * Mask the MSb to avoid overflow due to multiplication.
	 */
	clock_gettime(CLOCK_REALTIME, &spec);
	time_ms = (spec.tv_sec) * 1000 + (spec.tv_nsec) / 1000000 ;
	now_in_ms = (time_ms & kMaskTimestamp) * (neteq_inst->ts_increment / 10);

    ret = WebRtcNetEQ_RecInRTPStruct(neteq_inst->main_inst, &rtpinfo, payload, payload_len, now_in_ms);

    if (ret != 0) {
        char errorName[2000];
        if (WebRtcNetEQ_GetErrorName(WebRtcNetEQ_GetErrorCode(neteq_inst->main_inst),
                                     errorName, 2000) != 0) {
            errorName[0] = 0;
        }


        app_log_cb(3, "WebRtcNetEQ_Insert bad return code: %d (error_code=%d/%s) ssrc=%u m=%u seq=%u ts=%u now=%u", 
                   ret, WebRtcNetEQ_GetErrorCode(neteq_inst->main_inst), errorName, ssrc, marker, seqno, ts, now_in_ms);
    }

	return CONVERT_STATUS(ret);

}

WebRtcNetEQ_status_t WebRtcNetEQ_Extract(void *inst, int8_t *pcm_data, uint32_t *outlen, 
                                         uint16_t *consecutive_lost, uint32_t *total_decoded, uint8_t suppress_lost)
{
	int ret, iter;
	int16_t olen; 
	uint16_t clost = 0;
	neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;

	if (neteq_inst == NULL) {
		app_log_cb(3, "WebRtcNetEQ_Extract() : Invalid neteq_inst.\n");
		return WebRtcNetEQ_ERROR;
	}

	if (pcm_data == NULL || outlen == NULL || consecutive_lost == NULL) {
		app_log_cb(3, "WebRtcNetEQ_Extract() : Invalid Parameters.\n");
		return WebRtcNetEQ_ERROR;
	}

	*outlen = 0;
	*consecutive_lost = 0;
	for (iter = 0; iter < neteq_inst->pkt_ms; iter += 10) {
		ret = WebRtcNetEQ_RecOut(neteq_inst->main_inst, (int16_t *) pcm_data, &olen, &clost, total_decoded, suppress_lost);

		if (CONVERT_STATUS(ret) != WebRtcNetEQ_SUCCESS) {
                	return (*outlen) ? WebRtcNetEQ_SUCCESS : CONVERT_STATUS(ret);
		}

		*outlen += (olen * 2);
		pcm_data += (olen * 2);
        if (clost) {
            clost /= (neteq_inst->pkt_ms / 10);
		    if (*consecutive_lost < clost) {
                *consecutive_lost = clost;
            }
        }
	}
    *total_decoded = (*total_decoded) / (neteq_inst->pkt_ms / 10);

	return CONVERT_STATUS(ret);
}

log_cb_fp app_log_cb = NULL;
void WebRtcNetEQ_RegisterLogCB(log_cb_fp log_cb)
{
	app_log_cb = log_cb;
}

void *WebRtcNetEQ_Inst(void *inst)
{
	neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;
	
	return (neteq_inst) ? neteq_inst->main_inst : NULL;
}

int WebRtcNetEQ_PlayoutPause(void *inst, int on)
{
  neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;
  int ret = -1;
  if (inst) {
      return WebRtcNetEQ_SetPlayoutMode(neteq_inst->main_inst, on ? kPlayoutOff : kPlayoutOn);
  }
}
