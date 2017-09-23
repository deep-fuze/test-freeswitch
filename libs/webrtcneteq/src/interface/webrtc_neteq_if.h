#ifndef __WEBRTC_NETEQ_H__
#define __WEBRTC_NETEQ_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef void* (*app_memory_alloc_t) (void *pool, uint32_t size);

typedef enum {
	WebRtcNetEQ_NOT_STARTED = -2,
	WebRtcNetEQ_ERROR = -1,
	WebRtcNetEQ_SUCCESS = 0,
} WebRtcNetEQ_status_t;

WebRtcNetEQ_status_t WebRtcNetEQ_Init_inst(void **inst, app_memory_alloc_t alloc_cb, void *mempool,
					   uint32_t rate, uint32_t payload, const char *codecname, uint16_t packet_ms);

WebRtcNetEQ_status_t WebRtcNetEQ_Insert(void *inst, int8_t *payload, uint32_t payload_len, 
				uint8_t payload_type, uint16_t seqno,
				uint32_t ts, uint32_t ssrc, uint8_t marker);

WebRtcNetEQ_status_t WebRtcNetEQ_Extract(void *inst, int8_t *pcm_data, 
				uint32_t *outlen, uint16_t *consecutive_lost, uint32_t *total_decoded, uint8_t suppress_lost);

int WebRtcNetEQ_PlayoutPause(void *inst, int on);

#ifndef __EXT_LOG_CB__
typedef void (*log_cb_fp)(int16_t level, const char * format, ...);
#define __EXT_LOG_CB__
#endif

extern log_cb_fp app_log_cb;
void WebRtcNetEQ_RegisterLogCB(log_cb_fp log_cb);

WebRtcNetEQ_status_t WebRtcNetEQ_Purge(void *inst);
WebRtcNetEQ_status_t WebRtcNetEQ_CurrentPacketBufferStatistics(void *inst, int* current_num_packets, int* max_num_packets);

// from libwebrtc/out/webrtc/src/webrtc/common_types.h
typedef struct {
  // current jitter buffer size in ms
  uint16_t currentBufferSize;
  // preferred (optimal) buffer size in ms
  uint16_t preferredBufferSize;
  // adding extra delay due to "peaky jitter"
  uint32_t jitterPeaksFound;
  // Loss rate (network + late); fraction between 0 and 1, scaled to Q14.
  uint16_t currentPacketLossRate;
  // Late loss rate; fraction between 0 and 1, scaled to Q14.
  uint16_t currentDiscardRate;
  // fraction (of original stream) of synthesized audio inserted through
  // expansion (in Q14)
  uint16_t currentExpandRate;
  // fraction (of original stream) of synthesized speech inserted through
  // expansion (in Q14)
  uint16_t currentSpeechExpandRate;
  // fraction of synthesized speech inserted through pre-emptive expansion
  // (in Q14)
  uint16_t currentPreemptiveRate;
  // fraction of data removed through acceleration (in Q14)
  uint16_t currentAccelerateRate;
  // fraction of data coming from secondary decoding (in Q14)
  uint16_t currentSecondaryDecodedRate;
  // clock-drift in parts-per-million (negative or positive)
  int32_t clockDriftPPM;
  // average packet waiting time in the jitter buffer (ms)
  int meanWaitingTimeMs;
  // median packet waiting time in the jitter buffer (ms)
  int medianWaitingTimeMs;
  // min packet waiting time in the jitter buffer (ms)
  int minWaitingTimeMs;
  // max packet waiting time in the jitter buffer (ms)
  int maxWaitingTimeMs;
  // added samples in off mode due to packet loss
  size_t addedSamples;
  } NetEqNetworkStatistics;

WebRtcNetEQ_status_t WebRtcNetEQ_GetNetworkStatistics(void *inst, NetEqNetworkStatistics *ret_stats);
WebRtcNetEQ_status_t WebRtcNetEQ_SetMaximumDelay(void *inst, int delay);
WebRtcNetEQ_status_t WebRtcNetEQ_SetMinimumDelay(void *inst, int delay);

void WebRtcNetEQ_Destroy(void *inst);

#ifdef __cplusplus
} //  extern "C" {
#endif

#endif
