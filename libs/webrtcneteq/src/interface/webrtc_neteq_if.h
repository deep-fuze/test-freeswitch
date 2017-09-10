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

typedef struct {
  uint16_t current_buffer_size_ms;  // Current jitter buffer size in ms.                                                                                                            
  uint16_t preferred_buffer_size_ms;  // Target buffer size in ms.                                                                                                                  
  uint16_t jitter_peaks_found;  // 1 if adding extra delay due to peaky                                                                                                             
                                // jitter; 0 otherwise.                                                                                                                             
  uint16_t packet_loss_rate;  // Loss rate (network + late) in Q14.                                                                                                                 
  uint16_t packet_discard_rate;  // Late loss rate in Q14.                                                                                                                          
  uint16_t expand_rate;  // Fraction (of original stream) of synthesized                                                                                                            
                         // audio inserted through expansion (in Q14).                                                                                                              
  uint16_t speech_expand_rate;  // Fraction (of original stream) of synthesized                                                                                                     
                                // speech inserted through expansion (in Q14).                                                                                                      
  uint16_t preemptive_rate;  // Fraction of data inserted through pre-emptive                                                                                                       
                             // expansion (in Q14).                                                                                                                                 
  uint16_t accelerate_rate;  // Fraction of data removed through acceleration                                                                                                       
                             // (in Q14).                                                                                                                                           
  uint16_t secondary_decoded_rate;  // Fraction of data coming from secondary                                                                                                       
                                    // decoding (in Q14).                                                                                                                           
  int32_t clockdrift_ppm;  // Average clock-drift in parts-per-million                                                                                                              
                           // (positive or negative).                                                                                                                               
  size_t added_zero_samples;  // Number of zero samples added in "off" mode.                                                                                                        
  // Statistics for packet waiting times, i.e., the time between a packet                                                                                                           
  // arrives until it is decoded.                                                                                                                                                   
  int mean_waiting_time_ms;
  int median_waiting_time_ms;
  int min_waiting_time_ms;
  int max_waiting_time_ms;
} NetEqNetworkStatistics;

WebRtcNetEQ_status_t WebRtcNetEQ_GetNetworkStatistics(void *inst, NetEqNetworkStatistics *ret_stats);
WebRtcNetEQ_status_t WebRtcNetEQ_SetMaximumDelay(void *inst, int delay);
WebRtcNetEQ_status_t WebRtcNetEQ_SetMinimumDelay(void *inst, int delay);

void WebRtcNetEQ_Destroy(void *inst);

#ifdef __cplusplus
} //  extern "C" {
#endif

#endif
