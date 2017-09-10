#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include "include/webrtc/typedefs.h"
#include "interface/webrtc_neteq_if.h"
#include "include/webrtc/common_types.h"
#include "include/webrtc/modules/include/module_common_types.h"
#include "include/webrtc/modules/audio_coding/neteq/include/neteq.h"
#include "include/webrtc/modules/audio_coding/neteq/neteq_decoder_enum.h"
#include "include/webrtc/api/audio_codecs/builtin_audio_decoder_factory.h"
#include "include/webrtc/modules/audio_coding/neteq/neteq_decoder_enum.h"

#define CONVERT_STATUS(ret) ((ret) == 0 ? WebRtcNetEQ_SUCCESS : \
                                ((ret == -2) ? WebRtcNetEQ_NOT_STARTED : WebRtcNetEQ_ERROR))

class t_WebRTC {
public:
  rtc::scoped_refptr<webrtc::AudioDecoderFactory> decoder_factory;
  bool initialized;
  t_WebRTC(): initialized(true), decoder_factory(webrtc::CreateBuiltinAudioDecoderFactory()) {
  }
};

t_WebRTC g_WebRTC;

typedef struct {
  void *main_inst;
  uint16_t local_seqno;
  uint16_t last_rd_seqno; 
  uint16_t pkt_ms;
  uint32_t rate;
  uint16_t ts_increment;
  uint16_t samples_per_10ms;
  webrtc::NetEq::Config config;
  bool receiving;
} neteq_inst_t;

/*
 * Create the jitter buffer
 */
WebRtcNetEQ_status_t WebRtcNetEQ_Init_inst(void **inst, app_memory_alloc_t alloc_cb, void *mempool, 
					   uint32_t rate, uint32_t payload, const char *codecname, uint16_t packet_ms)
{
  neteq_inst_t *neteq_inst;

  if (inst == NULL || codecname == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Init_inst: ERROR unexpected null input parameter inst or codecname %s\n", codecname);
    return WebRtcNetEQ_ERROR;
  }

  if (packet_ms == 0 || packet_ms % 10) {
    app_log_cb(3, "WebRtcNetEQ_Init_inst: ERROR back packet_ms %d\n", packet_ms);
    return WebRtcNetEQ_ERROR;
  }


  neteq_inst = new neteq_inst_t();
  *inst = neteq_inst;

  /*
   * new memory (outside of FS memory allocation)
   */
  
  webrtc::NetEq *neteq;
 
  neteq = webrtc::NetEq::Create(neteq_inst->config, g_WebRTC.decoder_factory);
  neteq_inst->main_inst = neteq;

  if (!neteq) {
    app_log_cb(3, "WebRtcNetEQ_Init_inst: ERROR couldn't create webrtc::NetEq %d\n");
    return WebRtcNetEQ_ERROR;
  } else {
    app_log_cb(1, "WebRtcNetEQ_Init_inst: Created webrtc::NetEq %p NetEqInst %p\n",
	       neteq, neteq_inst);
  }

  switch (payload) {
  case 0:
    neteq->RegisterPayloadType(webrtc::NetEqDecoder::kDecoderPCMu, "g.711u", 0);
    app_log_cb(1, "WebRtcNetEQ_Init_inst: registered decoder pt=%d name=%s rate=%d\n", payload, codecname, rate);
    break;
  case 8:
    neteq->RegisterPayloadType(webrtc::NetEqDecoder::kDecoderPCMa, "g.711a", 8);
    app_log_cb(1, "WebRtcNetEQ_Init_inst: registered decoder pt=%d name=%s rate=%d\n", payload, codecname, rate);
    break;
  case 9:
    neteq->RegisterPayloadType(webrtc::NetEqDecoder::kDecoderG722, "g.722", 9);
    app_log_cb(1, "WebRtcNetEQ_Init_inst: registered decoder pt=%d name=%s rate=%d\n", payload, codecname, rate);
    break;
  default:
    if (payload > 95 && !strcasecmp(codecname, "opus") && rate == 48000) {
      neteq->RegisterPayloadType(webrtc::NetEqDecoder::kDecoderOpus, "opus", payload);
      app_log_cb(1, "WebRtcNetEQ_Init_inst: registered decoder pt=%d name=%s rate=%d\n", payload, codecname, rate);
    } else {
      app_log_cb(3, "WebRtcNetEQ_Init_inst: ERROR bad payload type pt=%d name=%s rate=%d\n", payload, codecname, rate);
      return WebRtcNetEQ_ERROR;
    }
  }

  // kDecoderCNGnb,
  // kDecoderCNGwb,

  neteq_inst->local_seqno = neteq_inst->last_rd_seqno = 0;
  neteq_inst->pkt_ms = packet_ms;
  neteq_inst->rate = rate;
  neteq_inst->receiving = false;
  if (payload == 9) {
    neteq_inst->ts_increment = neteq_inst->pkt_ms * 8;
    neteq_inst->samples_per_10ms = 160;
  } else {
    neteq_inst->ts_increment = ((rate / 8000) * neteq_inst->pkt_ms * 8);
    neteq_inst->samples_per_10ms = rate/100;
  }

  return WebRtcNetEQ_SUCCESS;
}

static const uint32_t kMaskTimestamp = 0x03ffffff;
WebRtcNetEQ_status_t WebRtcNetEQ_Insert(void *inst, int8_t *payload, uint32_t payload_len,
					uint8_t payload_type, uint16_t seqno,
					uint32_t ts, uint32_t ssrc, uint8_t marker)
{
  webrtc::RTPHeader header;
  neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;

  if (inst == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Insert Error inst == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  webrtc::NetEq *neteq = (webrtc::NetEq *)neteq_inst->main_inst;

  if (neteq == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Insert Error neteq == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }
  
  struct timespec spec;
  uint32_t now_in_ms, time_ms;
  int ret = 0;

  header.markerBit = marker;
  header.payloadType = payload_type;
  header.sequenceNumber = seqno;
  header.timestamp = ts;
  header.ssrc = ssrc;
  header.numCSRCs = 0;
  header.paddingLength = 0;
  header.headerLength = 12;
  header.payload_type_frequency = neteq_inst->rate;

  /*
   * Now convert timestamp into timestamp units of codec.
   * Mask the MSb to avoid overflow due to multiplication.
   */
  clock_gettime(CLOCK_REALTIME, &spec);
  time_ms = (spec.tv_sec) * 1000 + (spec.tv_nsec) / 1000000 ;
  now_in_ms = (time_ms & kMaskTimestamp) * (neteq_inst->ts_increment / 10);

  if (payload_len <= (neteq_inst->samples_per_10ms*8)) {
    ret = neteq->InsertPacket(header, rtc::ArrayView<const uint8_t>((const uint8_t*)payload, payload_len), now_in_ms);
  } else {
    app_log_cb(3, "WebRtcNetEQ_Insert Error payload len too long %d\n", payload_len);
  }

  if (ret != 0) {
    int errorCode = neteq->LastError();
    app_log_cb(3, "WebRtcNetEQ_Insert Error bad insert code: %d ret:%d\n", errorCode, ret);
  }
#ifdef DEBUG
  else {
    app_log_cb(1, "WebRtcNetEQ_Inserted: inserted packet pt:%d seq:%u bytes:%d \n", payload_type, seqno, payload_len);
  }
#endif

  return CONVERT_STATUS(ret);
}

WebRtcNetEQ_status_t WebRtcNetEQ_Extract(void *inst, int8_t *pcm_data, uint32_t *outlen, 
                                         uint16_t *consecutive_lost, uint32_t *total_decoded, uint8_t suppress_lost)
{
  neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;

  if (inst == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Extract Error inst == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  webrtc::NetEq *neteq = (webrtc::NetEq *)neteq_inst->main_inst;

  if (neteq == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Extract Error neteq == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  int ret, iter;
  uint16_t clost = 0;

  if (pcm_data == NULL || outlen == NULL || consecutive_lost == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Extract() : Invalid Parameters.\n");
    return WebRtcNetEQ_ERROR;
  }

  *outlen = 0;
  *consecutive_lost = 0;
  *total_decoded = 0;
  
  for (iter = 0; iter < neteq_inst->pkt_ms; iter += 10) {
    int16_t olen = 0;

    // defined in include/webrtc/modules/include/module_common_types.h
    webrtc::AudioFrame audio_frame;
    bool muted = false;

    ret = neteq->GetAudio(&audio_frame, &muted);

    olen = audio_frame.samples_per_channel_;

    if (ret == 0) {
      if (!muted) {
	const int8_t *data = (int8_t *)audio_frame.data();
	if (audio_frame.sample_rate_hz_ == neteq_inst->rate) {
	  memcpy(pcm_data, data, audio_frame.samples_per_channel_*2);
	  neteq_inst->receiving = true;
	} else {
	  app_log_cb(2, "WebRtcNetEQ_Extract extract s/c=%lld r=%d (actual %d) nc=%lld t=%d va=%d\n",
		     audio_frame.samples_per_channel_, audio_frame.sample_rate_hz_, neteq_inst->rate,
		     audio_frame.num_channels_, audio_frame.speech_type_, audio_frame.vad_activity_);
	  memset(pcm_data, 0, neteq_inst->samples_per_10ms*2);
	}
#if DEBUG
	app_log_cb(1, "WebRtcNetEQ_Extract extract s/c=%lld r=%d nc=%lld t=%d va=%d\n",
		   audio_frame.samples_per_channel_, audio_frame.sample_rate_hz_, audio_frame.num_channels_,
		   audio_frame.speech_type_, audio_frame.vad_activity_);
#endif
      } else {
	memset(pcm_data, 0, neteq_inst->samples_per_10ms*2);
      }
    } else {
      app_log_cb(3, "WebRtcNetEQ_Extract Error extract ret == %d\n", ret);
      return WebRtcNetEQ_ERROR;
    }

    if (CONVERT_STATUS(ret) != WebRtcNetEQ_SUCCESS) {
      return (*outlen) ? WebRtcNetEQ_SUCCESS : CONVERT_STATUS(ret);
    }
    
    *outlen += (olen * 2);
    pcm_data += (olen * 2);
  }
  
  *consecutive_lost = 0;
  *total_decoded = (*total_decoded) / (neteq_inst->pkt_ms / 10);

  return CONVERT_STATUS(ret);
}

log_cb_fp app_log_cb = NULL;
void WebRtcNetEQ_RegisterLogCB(log_cb_fp log_cb)
{
  app_log_cb = log_cb;
}

int WebRtcNetEQ_PlayoutPause(void *inst, int on)
{
  neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;

  if (inst == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Purge Error inst == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  webrtc::NetEq *neteq = (webrtc::NetEq *)neteq_inst->main_inst;

  if (neteq == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Purge Error neteq == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  /* probably deprecated */
  if (on) {
    neteq_inst->config.playout_mode = webrtc::kPlayoutOff;
  } else {
    neteq_inst->config.playout_mode = webrtc::kPlayoutOn;
  }

  return CONVERT_STATUS(0);
}

WebRtcNetEQ_status_t WebRtcNetEQ_Purge(void *inst)
{
  neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;

  if (inst == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Purge Error inst == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  webrtc::NetEq *neteq = (webrtc::NetEq *)neteq_inst->main_inst;

  if (neteq == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Purge Error neteq == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  app_log_cb(1, "WebRtcNetEQ_Purge before FlushBuffers\n");
  neteq->FlushBuffers();
  app_log_cb(1, "WebRtcNetEQ_Purge after FlushBuffers\n");

  return CONVERT_STATUS(0);
}

WebRtcNetEQ_status_t WebRtcNetEQ_CurrentPacketBufferStatistics(void *inst, int* current_num_packets, int* max_num_packets)
{
  neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;

  if (inst == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Purge Error inst == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  webrtc::NetEq *neteq = (webrtc::NetEq *)neteq_inst->main_inst;

  if (neteq == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Purge Error neteq == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  *current_num_packets = 0;
  *max_num_packets = 0;

  if (neteq_inst->receiving) {
    neteq->PacketBufferStatistics(current_num_packets, max_num_packets);
  }

  return CONVERT_STATUS(0);
}

WebRtcNetEQ_status_t WebRtcNetEQ_GetNetworkStatistics(void *inst, NetEqNetworkStatistics *ret_stats)
{
  neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;

  if (inst == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Purge Error inst == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  webrtc::NetEq *neteq = (webrtc::NetEq *)neteq_inst->main_inst;

  if (neteq == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Purge Error neteq == %d\n", 0);
    return WebRtcNetEQ_ERROR;
  }

  webrtc::NetEqNetworkStatistics stats;
  int ret = 0;

  if (neteq_inst->receiving) {
    ret = neteq->NetworkStatistics(&stats);
    if (!ret) {
      memcpy(ret_stats, &stats, sizeof(NetEqNetworkStatistics));
    }
  }

  return CONVERT_STATUS(ret);
}

void WebRtcNetEQ_Destroy(void *inst)
{
  neteq_inst_t *neteq_inst = (neteq_inst_t *)inst;

  if (inst == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Destroy Error inst == %d\n", 0);
    return;
  }

  webrtc::NetEq *neteq = (webrtc::NetEq *)neteq_inst->main_inst;

  if (neteq == NULL) {
    app_log_cb(3, "WebRtcNetEQ_Destroy Error neteq == %d\n", 0);
    return;
  }

  delete neteq;
  delete neteq_inst;
}
