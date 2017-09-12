/*
 * FreeSWITCH Moular Media Switching Software Library / Soft-Switch Application
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
 * Michael Jerris <mike@jerris.com>
 * Paul D. Tinsley <pdt at jackhammer.org>
 * Seven Du <dujinfang@gmail.com>
 *
 *
 * switch_core_io.c -- Main Core Library (Media I/O)
 *
 */

#include <switch.h>
#include "private/switch_core_pvt.h"
#include "interface/webrtc_neteq_if.h"
#if OLD_WEBRTC
#include "interface/webrtc_neteq_internal.h"
#endif

SWITCH_DECLARE(switch_status_t) switch_core_session_write_video_frame(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags,
                                                                      int stream_id)
{
    switch_io_event_hook_video_write_frame_t *ptr;
    switch_status_t status = SWITCH_STATUS_FALSE;

    if (switch_channel_down(session->channel)) {
        return SWITCH_STATUS_FALSE;
    }

    if (switch_channel_test_flag(session->channel, CF_VIDEO_PAUSE)) {
        return SWITCH_STATUS_SUCCESS;
    }

    if (session->endpoint_interface->io_routines->write_video_frame) {
        if ((status = session->endpoint_interface->io_routines->write_video_frame(session, frame, flags, stream_id)) == SWITCH_STATUS_SUCCESS) {
            for (ptr = session->event_hooks.video_write_frame; ptr; ptr = ptr->next) {
                if ((status = ptr->video_write_frame(session, frame, flags, stream_id)) != SWITCH_STATUS_SUCCESS) {
                    break;
                }
            }
        }
    }
    return status;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_read_video_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags,
                                                                     int stream_id)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_io_event_hook_video_read_frame_t *ptr;

    switch_assert(session != NULL);

    if (switch_channel_down(session->channel)) {
        return SWITCH_STATUS_FALSE;
    }

    if (switch_channel_test_flag(session->channel, CF_VIDEO_PAUSE)) {
        *frame = &runtime.dummy_cng_frame;
        switch_yield(20000);
        return SWITCH_STATUS_SUCCESS;
    }

    if (session->endpoint_interface->io_routines->read_video_frame) {
        if ((status = session->endpoint_interface->io_routines->read_video_frame(session, frame, flags, stream_id)) == SWITCH_STATUS_SUCCESS) {
            for (ptr = session->event_hooks.video_read_frame; ptr; ptr = ptr->next) {
                if ((status = ptr->video_read_frame(session, frame, flags, stream_id)) != SWITCH_STATUS_SUCCESS) {
                    break;
                }
            }
        }
    }

    if (status == SWITCH_STATUS_INUSE) {
        *frame = &runtime.dummy_cng_frame;
        switch_yield(20000);
        return SWITCH_STATUS_SUCCESS;
    }

    if (status != SWITCH_STATUS_SUCCESS) {
        goto done;
    }

    if (!(*frame)) {
        goto done;
    }

    switch_assert(*frame != NULL);

    if (switch_test_flag(*frame, SFF_CNG)) {
        status = SWITCH_STATUS_SUCCESS;
        goto done;
    }

  done:

    return status;
}

SWITCH_DECLARE(void) switch_core_gen_encoded_silence(unsigned char *data, const switch_codec_implementation_t *read_impl, switch_size_t len)
{
    unsigned char g729_filler[] = {
        114, 170, 250, 103, 54, 211, 203, 194, 94, 64, 
        229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
        114, 170, 250, 103, 54, 211, 203, 194, 94, 64, 
        229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
        114, 170, 250, 103, 54, 211, 203, 194, 94, 64, 
        229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
        114, 170, 250, 103, 54, 211, 203, 194, 94, 64, 
        229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
        114, 170, 250, 103, 54, 211, 203, 194, 94, 64, 
        229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
        114, 170, 250, 103, 54, 211, 203, 194, 94, 64, 
        229, 127, 79, 96, 207, 82, 216, 110, 245, 81,
        114, 170, 250, 103, 54, 211, 203, 194, 94, 64, 
        229, 127, 79, 96, 207, 82, 216, 110, 245, 81
    };

    
    if (read_impl->ianacode == 18 || switch_stristr("g729", read_impl->iananame)) {
        memcpy(data, g729_filler, len);
    } else {
        memset(data, 255, len);
    }

}

static void* memory_alloc_cb(void *pool, uint32_t size)
{                              
       return switch_core_alloc((switch_memory_pool_t *) pool, size);
}
        
static uint16_t purge_jitterbuffer(switch_core_session_t *session, switch_frame_t **frame)
{
    WebRtcNetEQ_Purge(switch_core_get_neteq_inst(session));

    (*frame)->datalen = 0;
    (*frame)->flags = 0;
    if (switch_test_flag((*frame), SFF_RTP_EVENT)) {
        (*frame)->flags |= SFF_RTP_EVENT;
    }

    return 0;
}

SWITCH_DECLARE(uint32_t) switch_core_session_get_low_energy(switch_core_session_t *session) {
    switch_assert(session != NULL);
    return session->audio_level_low_count;
}

SWITCH_DECLARE(switch_bool_t) switch_core_session_get_cn_state(switch_core_session_t *session) {
    switch_assert(session != NULL);
    return session->in_cn_period;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags,
                                                               int stream_id)
{
    switch_time_t time_after_wait;
    return switch_core_session_read_frame_w_time(session, frame, flags, stream_id, &time_after_wait);
}

SWITCH_DECLARE(void) switch_core_session_get_webrtc_counts(switch_core_session_t *session, uint32_t *read, 
                                                           uint32_t *insert, uint32_t *hot_read, uint32_t *errors, 
                                                           uint32_t *skip_read, uint32_t *empty) {
    switch_assert(session != NULL);
    *read = session->read;
    *insert = session->insert;
    *hot_read = session->hot_read;
    *errors = session->errors;
    *skip_read = session->skip_read;
    *empty = session->empty;
    session->read = 0;
    session->insert = 0;
    session->hot_read = 0;
    session->errors = 0;
    session->skip_read = 0;
    session->empty = 0;
}

#define PAUSE_THRESHOLD 20

SWITCH_DECLARE(switch_status_t) switch_core_session_fast_read_frame_from_jitterbuffer(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags,
                                                                                      int stream_id)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    int i;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_bool_t dontwait = switch_get_dont_wait_for_packets(channel);
    switch_time_t now;
    void *neteq_inst;

    switch_assert(session != NULL);

    now = switch_time_now();

    if (!session->paused && !(flags & SWITCH_IO_FLAG_CANT_SPEAK) &&
        session->last_jbuf_time[0] && (now-session->last_jbuf_time[0]) > 60000) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                          "Long time since switch_core_session_fast_read_frame_from_jitterbuffer was called %" PRId64 "ms\n",
                          (now-session->last_jbuf_time[0])/1000);
    }
    session->last_jbuf_time[0] = now;

    if (switch_mutex_trylock(session->codec_read_mutex) == SWITCH_STATUS_SUCCESS) {
        switch_mutex_unlock(session->codec_read_mutex);
    } else {
        *frame = &runtime.dummy_cng_frame;
        return SWITCH_STATUS_SUCCESS;
    }

    switch_mutex_lock(session->codec_read_mutex);
    switch_mutex_lock(session->read_codec->mutex);

    for(i = 0; i < 2; i++) {
        if (session->dmachine[i]) {
            switch_channel_dtmf_lock(session->channel);
            switch_ivr_dmachine_ping(session->dmachine[i], NULL);
            switch_channel_dtmf_unlock(session->channel);
        }
    }
    

    if (switch_channel_down(session->channel) || !switch_core_codec_ready(session->read_codec)) {
        *frame = NULL;
        status = SWITCH_STATUS_FALSE;
        goto even_more_done;
    }

    *frame = NULL;

    if (switch_channel_test_flag(session->channel, CF_HOLD)) {
        switch_yield(session->read_impl.microseconds_per_packet);
        status = SWITCH_STATUS_BREAK;
        goto even_more_done;
    }

    neteq_inst = switch_core_get_neteq_inst(session);

    if (neteq_inst) {
        if (session->paused) {
            if (!(flags & SWITCH_IO_FLAG_CANT_SPEAK || session->audio_level_low_count >= 50)) {
                if (WebRtcNetEQ_PlayoutPause(neteq_inst, 0) == 0) {
                    session->paused = SWITCH_FALSE;
                    session->paused_threshold = 0;
                    session->last_jbuf_time[2] = now; /* adjust this as it's the normal case and we don't want to log an error */
                }
            }
        } else {
            int current_num_packets = 0, max_num_packets = 0;
            WebRtcNetEQ_status_t ret;
            ret = WebRtcNetEQ_CurrentPacketBufferStatistics(neteq_inst, &current_num_packets, &max_num_packets);

            if (flags & SWITCH_IO_FLAG_CANT_SPEAK || session->audio_level_low_count >= 50) {
                if (session->paused_threshold > PAUSE_THRESHOLD) {
                    if (WebRtcNetEQ_PlayoutPause(neteq_inst, 1) == 0) {
                        session->paused = SWITCH_TRUE;
                    }
                } else {
                    if (ret == WebRtcNetEQ_SUCCESS && current_num_packets == 0) {
                        session->paused_threshold += 1;
                    }
                }
            } else {
                session->paused_threshold = 0;
            }
        } // paused
    } // neteq_inst

    /* Normally this function would return an empty frame if there was nothing waiting in the socket.  That's obviously not right.
     * Here, even if we fail to read something out of the socket, we'll try to read out of the jitter buffer.  This path only works
     * with the webrtc neteq jitter buffer as that jitter buffer decodes encoded packets internally.
     */
    if (dontwait && session->neteq_inst) {
        WebRtcNetEQ_status_t ret_status;
        uint16_t lost_count = 0;

#if 0
        now = switch_time_now();
        if (session->last_jbuf_time[1] && (now-session->last_jbuf_time[1]) > 60000) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                              "Long time since jbuf read %" PRId64 "ms %s low=%d\n",
                              (now-session->last_jbuf_time[1])/1000,
                              (flags & SWITCH_IO_FLAG_CANT_SPEAK ? "can't speak" : "speak ok"),
                              session->audio_level_low_count);
        }
        session->last_jbuf_time[1] = now;
#endif

        if (!session->paused) {
            /* we need to try to extract */
            switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */
            now = switch_time_now();
            if ((ret_status = WebRtcNetEQ_Extract(session->neteq_inst,
                                                  session->raw_read_frame.data,
                                                  &session->raw_read_frame.datalen,
                                                  &lost_count, &session->total_decoded,
                                                  session->suppress_lost)) == WebRtcNetEQ_SUCCESS) {
                status = SWITCH_STATUS_SUCCESS;
                session->read += 1;
                *frame = &session->raw_read_frame;

                if (session->last_jbuf_time[2] && (now-session->last_jbuf_time[2]) > 60000) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "Long time since jitter buffer extract succeeded %" PRId64 "ms fail:%u\n",
                                      (now-session->last_jbuf_time[2])/1000, session->jbuf_fail);
                }
                session->last_jbuf_time[2] = now;
                session->jbuf_fail = 0;
            } else {
                session->jbuf_fail += 1;
                session->empty += 1;
            }
            switch_thread_rwlock_unlock(session->bug_rwlock);
        }
    }

even_more_done:
    if (!(*frame)) {
        *frame = &runtime.dummy_cng_frame;
        status = SWITCH_STATUS_FALSE;
    }
    switch_mutex_unlock(session->read_codec->mutex);
    switch_mutex_unlock(session->codec_read_mutex);
    
    if (status == SWITCH_STATUS_SUCCESS && switch_channel_get_callstate(session->channel) == CCS_UNHELD) {
        switch_channel_set_callstate(session->channel, CCS_ACTIVE);
    }
    
    return status;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_fast_read_frame_from_socket(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags,
                                                                                int stream_id)
{
    switch_io_event_hook_read_frame_t *ptr;
    switch_status_t status = SWITCH_STATUS_FALSE;
    int need_codec, perfect,  is_cng = 0;
    switch_codec_implementation_t codec_impl;
    unsigned int flag = 0;
    switch_time_t read_time = switch_micro_time_now() / 1000;
    switch_bool_t prevcantspeak;
    switch_bool_t wasskipping = SWITCH_FALSE;
    uint32_t read_packets = 0;
    
    switch_assert(session != NULL);
    
    if (switch_mutex_trylock(session->codec_read_mutex) == SWITCH_STATUS_SUCCESS) {
        switch_mutex_unlock(session->codec_read_mutex);
    } else {
        *frame = &runtime.dummy_cng_frame;
        return SWITCH_STATUS_SUCCESS;
    }

    if (switch_thread_rwlock_trywrlock_timeout(session->bug_rwlock, 20) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Couldn't acquire bug_rwlock!\n");
        *frame = &runtime.dummy_cng_frame;
        return SWITCH_STATUS_SUCCESS;
    } else {
        switch_thread_rwlock_unlock(session->bug_rwlock);
    }
    
    if (!(session->read_codec && session->read_codec->implementation && switch_core_codec_ready(session->read_codec))) {
        if (switch_channel_test_flag(session->channel, CF_PROXY_MODE) || switch_channel_get_state(session->channel) == CS_HIBERNATE) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "%s reading on a session with no media!\n",
                              switch_channel_get_name(session->channel));
            *frame = &runtime.dummy_cng_frame;
            return SWITCH_STATUS_SUCCESS;
        }
        
        if (switch_channel_test_flag(session->channel, CF_AUDIO_PAUSE)) {
            *frame = &runtime.dummy_cng_frame;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Media Paused!!!!\n");
            return SWITCH_STATUS_SUCCESS;
        }
        
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s has no read codec.\n", switch_channel_get_name(session->channel));
        switch_channel_hangup(session->channel, SWITCH_CAUSE_INCOMPATIBLE_DESTINATION);
        return SWITCH_STATUS_FALSE;
    }
    
    switch_mutex_lock(session->codec_read_mutex);
    
    if (!switch_core_codec_ready(session->read_codec)) {
        switch_mutex_unlock(session->codec_read_mutex);
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s has no read codec.\n", switch_channel_get_name(session->channel));
        switch_channel_hangup(session->channel, SWITCH_CAUSE_INCOMPATIBLE_DESTINATION);
        *frame = &runtime.dummy_cng_frame;
        return SWITCH_STATUS_FALSE;
    }
    
    switch_mutex_lock(session->read_codec->mutex);
    
    if (switch_channel_down(session->channel) || !switch_core_codec_ready(session->read_codec)) {
        *frame = NULL;
        status = SWITCH_STATUS_FALSE;
        goto even_more_done;
    }
    
    status = SWITCH_STATUS_FALSE;
    need_codec = perfect = 0;
    
    *frame = NULL;
    
    if (session->read_codec && !session->track_id && session->track_duration) {
        if (session->read_frame_count == 0) {
            switch_event_t *event;
            switch_core_session_message_t msg = { 0 };
            
            session->read_frame_count = (session->read_impl.samples_per_second / session->read_impl.samples_per_packet) * session->track_duration;
            
            msg.message_id = SWITCH_MESSAGE_HEARTBEAT_EVENT;
            msg.numeric_arg = session->track_duration;
            switch_core_session_receive_message(session, &msg);
            
            switch_event_create(&event, SWITCH_EVENT_SESSION_HEARTBEAT);
            switch_channel_event_set_data(session->channel, event);
            switch_event_fire(&event);
        } else {
            session->read_frame_count--;
        }
    }
    
    if (switch_channel_test_flag(session->channel, CF_HOLD)) {
        switch_yield(session->read_impl.microseconds_per_packet);
        status = SWITCH_STATUS_BREAK;
        goto even_more_done;
    }
    
read_again:
    /* fuze: read out the frame! */
    if (session->endpoint_interface->io_routines->read_frame) {
        switch_mutex_unlock(session->read_codec->mutex);
        switch_mutex_unlock(session->codec_read_mutex);
        if ((status = session->endpoint_interface->io_routines->read_frame(session, frame, flags, stream_id)) == SWITCH_STATUS_SUCCESS) {
            for (ptr = session->event_hooks.read_frame; ptr; ptr = ptr->next) {
                if ((status = ptr->read_frame(session, frame, flags, stream_id)) != SWITCH_STATUS_SUCCESS) { /* xxx */
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s read a frame\n", switch_channel_get_name(session->channel));
                    break;
                }
            }
        }

        if (status == SWITCH_STATUS_INUSE) {
            *frame = &runtime.dummy_cng_frame;
            return SWITCH_STATUS_SUCCESS;
        }
        
        if (!SWITCH_READ_ACCEPTABLE(status) || !session->read_codec || !switch_core_codec_ready(session->read_codec)) {
            *frame = NULL;
            return SWITCH_STATUS_FALSE;
        }
        
        switch_mutex_lock(session->codec_read_mutex);
        
        if (!switch_core_codec_ready(session->read_codec)) {
            switch_mutex_unlock(session->codec_read_mutex);
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s has no read codec.\n", switch_channel_get_name(session->channel));
            switch_channel_hangup(session->channel, SWITCH_CAUSE_INCOMPATIBLE_DESTINATION);
            *frame = &runtime.dummy_cng_frame;
            switch_mutex_unlock(session->codec_read_mutex);
            return SWITCH_STATUS_FALSE;
        }
        
        switch_mutex_lock(session->read_codec->mutex);
        if (!switch_core_codec_ready(session->read_codec)) {
            *frame = NULL;
            status = SWITCH_STATUS_FALSE;
            goto even_more_done;
        }
    }
    /* fuze: end of read out frame */
    /* Normally this function would return an empty frame if there was nothing waiting in the socket.  That's obviously not right.
     * Here, even if we fail to read something out of the socket, we'll try to read out of the jitter buffer.  This path only works
     * with the webrtc neteq jitter buffer as that jitter buffer decodes encoded packets internally.
     */
    if (status != SWITCH_STATUS_SUCCESS) {
        goto done;
    }
    
    if (!(*frame)) {
        goto done;
    }
    
    switch_assert(*frame != NULL);
    read_packets += 1;
    
    
    switch_assert((*frame)->codec != NULL);
    
    if (!(session->read_codec && (*frame)->codec && (*frame)->codec->implementation) && switch_core_codec_ready((*frame)->codec)) {
        status = SWITCH_STATUS_FALSE;
        goto done;
    }
    
    prevcantspeak = session->cantspeak;
    
    if (prevcantspeak) {
        wasskipping = SWITCH_TRUE;
    }
    
    if (flags & SWITCH_IO_FLAG_CANT_SPEAK) {
        if (!session->cantspeak) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "state changed from speak to can't speak %d\n", prevcantspeak);
            session->cantspeak = SWITCH_TRUE;
        }
    } else {
        if (session->cantspeak) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "state changed from can't speak to speak %d\n", prevcantspeak);
            session->cantspeak = SWITCH_FALSE;
        }
    }
    
    codec_impl = *(*frame)->codec->implementation;
    
    if (session->read_codec->implementation->impl_id != codec_impl.impl_id) {
        need_codec = TRUE;
    }
    
    if (switch_test_flag(*frame, SFF_MARKER) || (!switch_test_flag(*frame, SFF_CNG) && !switch_test_flag(*frame, SFF_RFC2833))) {
        if (session->in_cn_period) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "state changed from comfort noise to NO comfort noise\n");
            session->in_cn_period = SWITCH_FALSE;
        }
    }
    
    /* fuze: so we don't init the plc anymore but webrtc neteq has a built in plc so ... */
    if (switch_test_flag(*frame, SFF_CNG) && !switch_test_flag(*frame, SFF_TIMEOUT)) {
        if (!session->in_cn_period) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "state changed from NO comfort noise to comfort noise\n");
            session->in_cn_period = SWITCH_TRUE;
        }
        
        if (!session->bugs && !session->plc) {
            status = SWITCH_STATUS_SUCCESS;
            goto done;
        }
        
        is_cng = 1;
        need_codec = 1;
    } else if (switch_test_flag(*frame, SFF_NOT_AUDIO)) {
        need_codec = 0;
    }
    
    if (switch_test_flag(session, SSF_READ_CODEC_RESET)) {
        switch_core_codec_reset(session->read_codec);
        switch_clear_flag(session, SSF_READ_CODEC_RESET);
    }
    
    if (status == SWITCH_STATUS_SUCCESS && need_codec) {
        switch_frame_t *read_frame = *frame;
        
        switch_set_flag(session, SSF_READ_TRANSCODE);
        
        if (read_frame->codec || is_cng) {
            session->raw_read_frame.datalen = session->raw_read_frame.buflen;
            
            if (is_cng) {
                memset(session->raw_read_frame.data, 255, read_frame->codec->implementation->decoded_bytes_per_packet);
                
                session->raw_read_frame.timestamp = 0;
                session->raw_read_frame.datalen = read_frame->codec->implementation->decoded_bytes_per_packet;
                session->raw_read_frame.samples = session->raw_read_frame.datalen / sizeof(int16_t);
                read_frame = &session->raw_read_frame;
                status = SWITCH_STATUS_SUCCESS;
            } else {
                switch_codec_t *use_codec = read_frame->codec;
                switch_codec_t *codec;

                if (!session->rtcp_interval) {
                    switch_core_ioctl_stats(session, GET_RTCP_INTERVAL, &session->rtcp_interval);
                } else if (++session->total_reads % session->rtcp_interval == 0) {
                    uint32_t val;
                    if (session->neteq_inst) {
                        NetEqNetworkStatistics nwstats;
                        void *neteq_internal = switch_core_get_neteq_inst(session);

                        if (neteq_internal && WebRtcNetEQ_GetNetworkStatistics(neteq_internal, &nwstats) == 0) {
                            val = nwstats.current_buffer_size_ms;
                            switch_core_ioctl_stats(session, SET_JB_SIZE, &val);
                        }
                    }
                    
                    val = session->total_decoded - session->last_total;
                    if (val) {
                        val = (session->total_lost * 100) / (session->total_lost + val);
                        switch_core_ioctl_stats(session, SET_LOST_PERCENT, &val);
                    }
                    session->last_total = session->total_decoded;
                    session->total_lost = 0;
                    
                    
                    val = SWITCH_RTCP_NORMAL;
                    switch_core_ioctl_stats(session, SET_SEND_RTCP, &val);
                }
                
                session->raw_read_frame.flags = 0;
                codec = use_codec->implementation?use_codec:read_frame->codec;
                if (!session->neteq_inst) {

                    if (!codec->implementation || !switch_core_codec_ready(codec)) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
                                          "INFO: Codec is not initialized yet. Skipping Decode.\n");
                        *frame = NULL;
                        goto done;
                    }
                    
                    if (!codec->implementation->decoder) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                          "INFO: Decoder is not initialized. Skipping Decode.\n");
                        *frame = NULL;
                        goto done;
                    }

                    if (switch_test_flag(*frame, SFF_CNG) || switch_test_flag(*frame, SFF_TIMEOUT)) {
                        *frame = NULL;
                        goto done;
                    }
                    
                    if (!read_frame->datalen) {
                        /*
                         * Wait until we read first frame. We need payload information because
                         * dynamic payload number could be different in the packet from what was
                         * initialized for codec.
                         */
                        *frame = NULL;
                        goto done;
                    }
                    
                    /*
                     * Lets pass the session->pool instead of codec's one because we will access
                     * neteq_inst to fetch stats at the end. By this time codec could have been
                     * destroyed.
                     */
                    if (WebRtcNetEQ_Init_inst(&session->neteq_inst, memory_alloc_cb, session->pool,
                                              codec->implementation->actual_samples_per_second,
                                              read_frame->payload, codec->implementation->iananame,
                                              codec->implementation->microseconds_per_packet / 1000) != WebRtcNetEQ_SUCCESS) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                          "ERROR: WebRtcNetEQ_Init_inst() for codec=%s:%d.\n",
                                          codec->implementation->iananame, codec->implementation->ianacode);
                        *frame = NULL;
                        goto done;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                                          "Created webrtc neteq for payload %d\n", read_frame->payload);
                    }
                }
                
                switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */
                
                if (read_frame->datalen) {
                    if (session->zero_read_count) {
                        if (session->zero_read_count > 3 || (*frame)->seq > session->last_rtp_seq + 1 ||
                            (session->jb_size_before_zero < session->zero_read_count - 2))  {
                            
                            session->pkt_errors += 1;
                            
                            if ((read_time - session->period_start) >= FUZE_TIMER_MISS_INTERVAL) {
                                if (session->pkt_errors > 5) {
                                    int current_num_packets = 0, max_num_packets = 0;
                                    WebRtcNetEQ_CurrentPacketBufferStatistics(switch_core_get_neteq_inst(session), &current_num_packets, &max_num_packets);
                                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                                                      "Packet Errors: %d/%lld ssrc=%#x cur-jb-size=%d max-jb-size=%d.\n",
                                                      session->pkt_errors, (long long)(read_time - session->period_start),
                                                      (*frame)->ssrc, current_num_packets, max_num_packets);
                                }
                                session->pkt_errors = 0;
                                session->period_start = read_time;
                            }
                        }
                        
                        session->zero_read_count = 0;
                    }
                    session->last_rtp_seq = (*frame)->seq;
                    
                    /* mqt-1769: check if channel is an active speaker, if:
                     * (1) It is an active speaker then put packets into jitter buffer & process
                     * (2) It is not an active speaker then check whether the rtp packet contain an energy level?  If:
                     *     (2a) It doesn't contain an energy level then insert into the jitter buffer & continue as per normal
                     *     (2b) It does contain an energy level and the energy level is >= MIN_SPKR_THRESH then insert into the jitter buffer.
                     *          It does contain an energy level and the energy level is < MIN_SPKR_THRESH (for 1 second) then throw away the packet & return
                     */
                    if (!(flags & SWITCH_IO_FLAG_ACTIVE_TALKER)) {
                        /* flag set when below power threshold */
                        if  (!switch_test_flag(read_frame, SFF_RTP_AUDIO_OVER_THR)) {
                            session->audio_level_low_count += 1;
                        } else {
                            if (session->audio_level_low_count >= 50) {
                                wasskipping = SWITCH_TRUE;
                            }
                            session->audio_level_low_count = 0;
                        }
                    } else {
                        if (session->audio_level_low_count >= 50) {
                            wasskipping = SWITCH_TRUE;
                        }
                        session->audio_level_low_count = 0;
                    }
                    
                    if (!(flags & SWITCH_IO_FLAG_CANT_SPEAK) && session->audio_level_low_count < 50) {
                        if (wasskipping) {
                            NetEqNetworkStatistics nwstats;
                            void *neteq_internal = switch_core_get_neteq_inst(session);
                            if (neteq_internal) {
                                WebRtcNetEQ_GetNetworkStatistics(neteq_internal, &nwstats);
                            }
                            
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                                              "get_frame stats: read/skip=%d/%d insert/skip=%d/%d jbsize=%dms jfpref=%d peaks=%d\n",
                                              session->read, session->skip_read, session->insert, session->skip_insert,
                                              nwstats.current_buffer_size_ms, nwstats.preferred_buffer_size_ms, nwstats.jitter_peaks_found);
                            read_frame->m = 1;
                        }

                        if (read_frame->payload != 13 && !(switch_test_flag(read_frame, SFF_CNG))) {
                            if (WebRtcNetEQ_Insert(session->neteq_inst, read_frame->data,
                                                   read_frame->datalen, read_frame->payload, read_frame->seq,
                                                   read_frame->timestamp, read_frame->ssrc, read_frame->m) != WebRtcNetEQ_SUCCESS) {

                                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
                                                  "ERROR: WebRtcNetEQ_Insert: codec=%s datalen=%d payload=%d.\n",
                                                  codec->implementation->iananame, read_frame->datalen,
                                                  read_frame->payload);
                            } else {
                                session->insert += 1;
                            }
                        }
                    } else {
                        session->skip_insert += 1;
                    }
                    
                    if (switch_test_flag(read_frame, SFF_HOT_READ)) {
                        session->hot_read += 1;
                        switch_clear_flag(read_frame, SFF_HOT_READ);
                        switch_thread_rwlock_unlock(session->bug_rwlock);
                        goto read_again;
                    }
                    
                } /* rdlock */

                switch_thread_rwlock_unlock(session->bug_rwlock);
            }
        }
    }
done:
    if (!(*frame)) {
        status = SWITCH_STATUS_FALSE;
    } else {
        if (flag & SFF_CNG) {
            switch_set_flag((*frame), SFF_CNG);
        }
        if (flag & SFF_TIMEOUT) {
            switch_set_flag((*frame), SFF_TIMEOUT);
        }
    }
even_more_done:
    
    if (!*frame ||
        (!switch_test_flag(*frame, SFF_PROXY_PACKET) &&
         (!(*frame)->codec || !(*frame)->codec->implementation || !switch_core_codec_ready((*frame)->codec)))) {
            *frame = &runtime.dummy_cng_frame;
        }
    
    switch_mutex_unlock(session->read_codec->mutex);
    switch_mutex_unlock(session->codec_read_mutex);
    
    if (status == SWITCH_STATUS_SUCCESS && switch_channel_get_callstate(session->channel) == CCS_UNHELD) {
        switch_channel_set_callstate(session->channel, CCS_ACTIVE);
    }
    
    return status;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_read_frame_w_time(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags,
                                                                      int stream_id, switch_time_t *time_after_wait)
{
    switch_io_event_hook_read_frame_t *ptr;
    switch_status_t status = SWITCH_STATUS_FALSE;
    int need_codec, perfect, do_bugs = 0, do_resample = 0, is_cng = 0, tap_only = 0;
    switch_codec_implementation_t codec_impl;
    unsigned int flag = 0;
    int i;
    switch_time_t read_time = switch_micro_time_now() / 1000;
    switch_bool_t prevcantspeak;
    switch_bool_t wasskipping = SWITCH_FALSE;
    switch_bool_t dont_wait = (flags & SWITCH_IO_FLAG_DONT_WAIT) != 0;

    switch_assert(session != NULL);

    *time_after_wait = switch_micro_time_now();

    tap_only = switch_test_flag(session, SSF_MEDIA_BUG_TAP_ONLY);

    if (!dont_wait) {
        switch_os_yield();
    }

    if (switch_mutex_trylock(session->codec_read_mutex) == SWITCH_STATUS_SUCCESS) {
        switch_mutex_unlock(session->codec_read_mutex);
    } else {
        if (!dont_wait) {
            switch_cond_next();
        }
        *frame = &runtime.dummy_cng_frame;
        (*frame)->flags |= SFF_TIMEOUT;
        return SWITCH_STATUS_SUCCESS;
    }

    if (!(session->read_codec && session->read_codec->implementation && switch_core_codec_ready(session->read_codec))) {
        if (switch_channel_test_flag(session->channel, CF_PROXY_MODE) || switch_channel_get_state(session->channel) == CS_HIBERNATE) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "%s reading on a session with no media!\n",
                              switch_channel_get_name(session->channel));
            if (!dont_wait) {
                switch_cond_next();
            }
            *frame = &runtime.dummy_cng_frame;
            (*frame)->flags |= SFF_TIMEOUT;
            return SWITCH_STATUS_SUCCESS;
        }

        if (switch_channel_test_flag(session->channel, CF_AUDIO_PAUSE)) {
            if (!dont_wait) {
                switch_yield(20000);
            }
            *frame = &runtime.dummy_cng_frame;
            (*frame)->flags |= SFF_TIMEOUT;
            // switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Media Paused!!!!\n");
            return SWITCH_STATUS_SUCCESS;
        }

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s has no read codec.\n", switch_channel_get_name(session->channel));
        switch_channel_hangup(session->channel, SWITCH_CAUSE_INCOMPATIBLE_DESTINATION);
        return SWITCH_STATUS_FALSE;
    }

    switch_mutex_lock(session->codec_read_mutex);

    if (!switch_core_codec_ready(session->read_codec)) {
        switch_mutex_unlock(session->codec_read_mutex);
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s has no read codec.\n", switch_channel_get_name(session->channel));
        switch_channel_hangup(session->channel, SWITCH_CAUSE_INCOMPATIBLE_DESTINATION);
        *frame = &runtime.dummy_cng_frame;
        return SWITCH_STATUS_FALSE;
    }

    switch_mutex_lock(session->read_codec->mutex);

 top:
    
    for(i = 0; i < 2; i++) {
        if (session->dmachine[i]) {
            switch_channel_dtmf_lock(session->channel);
            switch_ivr_dmachine_ping(session->dmachine[i], NULL);
            switch_channel_dtmf_unlock(session->channel);
        }
    }
    
    if (switch_channel_down(session->channel) || !switch_core_codec_ready(session->read_codec)) {
        *frame = NULL;
        status = SWITCH_STATUS_FALSE;
        goto even_more_done;
    }


    status = SWITCH_STATUS_FALSE;
    need_codec = perfect = 0;

    *frame = NULL;

    if (session->read_codec && !session->track_id && session->track_duration) {
        if (session->read_frame_count == 0) {
            switch_event_t *event;
            switch_core_session_message_t msg = { 0 };

            session->read_frame_count = (session->read_impl.samples_per_second / session->read_impl.samples_per_packet) * session->track_duration;

            msg.message_id = SWITCH_MESSAGE_HEARTBEAT_EVENT;
            msg.numeric_arg = session->track_duration;
            switch_core_session_receive_message(session, &msg);
            
            switch_event_create(&event, SWITCH_EVENT_SESSION_HEARTBEAT);
            switch_channel_event_set_data(session->channel, event);
            switch_event_fire(&event);
        } else {
            session->read_frame_count--;
        }
    }


    if (switch_channel_test_flag(session->channel, CF_HOLD)) {
        switch_yield(session->read_impl.microseconds_per_packet);
        status = SWITCH_STATUS_BREAK;
        goto even_more_done;
    }

    if (session->endpoint_interface->io_routines->read_frame) {
        switch_mutex_unlock(session->read_codec->mutex);
        switch_mutex_unlock(session->codec_read_mutex);
        if ((status = session->endpoint_interface->io_routines->read_frame(session, frame, flags, stream_id)) == SWITCH_STATUS_SUCCESS) {
            for (ptr = session->event_hooks.read_frame; ptr; ptr = ptr->next) {
                if ((status = ptr->read_frame(session, frame, flags, stream_id)) != SWITCH_STATUS_SUCCESS) { /* xxx */
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s read a frame\n", switch_channel_get_name(session->channel));
                    break;
                }
            }
        }

        if (status == SWITCH_STATUS_INUSE) {
            *frame = &runtime.dummy_cng_frame;
            switch_set_flag(*frame, SFF_TIMEOUT);
            /* Luke TBD: yield in path */
            switch_yield(20000);
            return SWITCH_STATUS_SUCCESS;
        }

        if (*frame == NULL || !SWITCH_READ_ACCEPTABLE(status) || !session->read_codec || !switch_core_codec_ready(session->read_codec)) {
            *frame = NULL;
            return SWITCH_STATUS_FALSE;
        }

#if 0
        if (*frame && switch_test_flag(*frame, SFF_HOT_READ)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                              "hot read\n");
        }
#endif

        switch_mutex_lock(session->codec_read_mutex);

        if (!switch_core_codec_ready(session->read_codec)) {
            switch_mutex_unlock(session->codec_read_mutex);
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s has no read codec.\n", switch_channel_get_name(session->channel));
            switch_channel_hangup(session->channel, SWITCH_CAUSE_INCOMPATIBLE_DESTINATION);
            *frame = &runtime.dummy_cng_frame;
            switch_set_flag(*frame, SFF_TIMEOUT);
            return SWITCH_STATUS_FALSE;
        }

        switch_mutex_lock(session->read_codec->mutex);
        if (!switch_core_codec_ready(session->read_codec)) {
            *frame = NULL;
            status = SWITCH_STATUS_FALSE;
            goto even_more_done;
        }
    }

    if (status != SWITCH_STATUS_SUCCESS) {
        goto done;
    }

    if (!(*frame)) {
        goto done;
    }

    switch_assert(*frame != NULL);

    if (switch_test_flag(*frame, SFF_PROXY_PACKET)) {
        /* Fast PASS! */
        status = SWITCH_STATUS_SUCCESS;
        goto done;
    }

    switch_assert((*frame)->codec != NULL);

    if (!(session->read_codec && (*frame)->codec && (*frame)->codec->implementation) && switch_core_codec_ready((*frame)->codec)) {
        status = SWITCH_STATUS_FALSE;
        goto done;
    }

    prevcantspeak = session->cantspeak;

    if (prevcantspeak) {
        wasskipping = SWITCH_TRUE;
    }

    if (flags & SWITCH_IO_FLAG_CANT_SPEAK) {
        if (!session->cantspeak) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "state changed from speak to can't speak %d\n", prevcantspeak);
            session->cantspeak = SWITCH_TRUE;
        }
    } else {
        if (session->cantspeak) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "state changed from can't speak to speak %d\n", prevcantspeak);
            session->cantspeak = SWITCH_FALSE;
        }
    }

    if (session->bugs && !((*frame)->flags & SFF_CNG) && !((*frame)->flags & SFF_NOT_AUDIO)) {
        switch_media_bug_t *bp;
        switch_bool_t ok = SWITCH_TRUE;
        int prune = 0;

        switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */

        for (bp = session->bugs; bp; bp = bp->next) {
            ok = SWITCH_TRUE;

            if (switch_channel_test_flag(session->channel, CF_PAUSE_BUGS) && !switch_core_media_bug_test_flag(bp, SMBF_NO_PAUSE)) {
                continue;
            }
            
            if (!switch_channel_test_flag(session->channel, CF_ANSWERED) && switch_core_media_bug_test_flag(bp, SMBF_ANSWER_REQ)) {
                continue;
            }
            if (switch_test_flag(bp, SMBF_PRUNE)) {
                prune++;
                continue;
            }
            
            if (bp->ready) {
                if (switch_test_flag(bp, SMBF_TAP_NATIVE_READ)) {
                    if ((*frame)->codec && (*frame)->codec->implementation && 
                        (*frame)->codec->implementation->encoded_bytes_per_packet && 
                        (*frame)->datalen != (*frame)->codec->implementation->encoded_bytes_per_packet) {
                        switch_set_flag((*frame), SFF_CNG);
                        break;
                    }
                    if (bp->callback) {
                        bp->native_read_frame = *frame;
                        ok = bp->callback(bp, bp->user_data, SWITCH_ABC_TYPE_TAP_NATIVE_READ);
                        bp->native_read_frame = NULL;
                    }
                }
            }
            
            if ((bp->stop_time && bp->stop_time <= switch_epoch_time_now(NULL)) || ok == SWITCH_FALSE) {
                switch_set_flag(bp, SMBF_PRUNE);
                prune++;
            }
        }
        switch_thread_rwlock_unlock(session->bug_rwlock);

        if (prune) {
            switch_core_media_bug_prune(session);
        }
    }

    codec_impl = *(*frame)->codec->implementation;

    if (session->read_codec->implementation->impl_id != codec_impl.impl_id) {
        need_codec = TRUE;
        tap_only = 0;
    } 
    
    if (codec_impl.actual_samples_per_second != session->read_impl.actual_samples_per_second) {
        do_resample = 1;
    }

    if (tap_only) {
        switch_media_bug_t *bp;
        switch_bool_t ok = SWITCH_TRUE;
        int prune = 0;

        if (session->bugs && switch_test_flag((*frame), SFF_CNG)) {
            switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */
            for (bp = session->bugs; bp; bp = bp->next) {
                ok = SWITCH_TRUE;

                if (switch_channel_test_flag(session->channel, CF_PAUSE_BUGS) && !switch_core_media_bug_test_flag(bp, SMBF_NO_PAUSE)) {
                    continue;
                }
                
                if (!switch_channel_test_flag(session->channel, CF_ANSWERED) && switch_core_media_bug_test_flag(bp, SMBF_ANSWER_REQ)) {
                    continue;
                }
                if (switch_test_flag(bp, SMBF_PRUNE)) {
                    prune++;
                    continue;
                }
                
                if (bp->ready && (*frame)->codec && (*frame)->codec->implementation && (*frame)->codec->implementation->encoded_bytes_per_packet) {
                    if (switch_test_flag(bp, SMBF_TAP_NATIVE_READ)) {
                        if (bp->callback) {
                            switch_frame_t tmp_frame = {0};
                            unsigned char data[SWITCH_RECOMMENDED_BUFFER_SIZE] = {0};
                            
                            
                            tmp_frame.codec = (*frame)->codec;
                            tmp_frame.datalen = (*frame)->codec->implementation->encoded_bytes_per_packet;
                            tmp_frame.samples = (*frame)->codec->implementation->samples_per_packet;
                            tmp_frame.data = data;
                            
                            switch_core_gen_encoded_silence(data, (*frame)->codec->implementation, tmp_frame.datalen);
                            
                            bp->native_read_frame = &tmp_frame;
                            ok = bp->callback(bp, bp->user_data, SWITCH_ABC_TYPE_TAP_NATIVE_READ);
                            bp->native_read_frame = NULL;
                        }
                    }
                }
                
                if ((bp->stop_time && bp->stop_time <= switch_epoch_time_now(NULL)) || ok == SWITCH_FALSE) {
                    switch_set_flag(bp, SMBF_PRUNE);
                    prune++;
                }
            }
            switch_thread_rwlock_unlock(session->bug_rwlock);

            if (prune) {
                switch_core_media_bug_prune(session);
            }
            
            
        }


        goto done;
    } else if (session->bugs && !need_codec) {
        do_bugs = 1;
        need_codec = 1;
    }

    /* xxx */
    if (switch_test_flag(*frame, SFF_MARKER)) {
        if (session->in_cn_period) {
            session->in_cn_period = SWITCH_FALSE;
        }
    }

    /* fuze: so we don't init the plc anymore but webrtc neteq has a built in plc so ... */
    if (switch_test_flag(*frame, SFF_CNG)) {

        if (!session->in_cn_period && !switch_test_flag(*frame, SFF_TIMEOUT)) {
            session->in_cn_period = SWITCH_TRUE;
        }

        if (!session->bugs && !session->plc) {
            /* Check if other session has bugs */
            unsigned int other_session_bugs = 0;
            switch_core_session_t *other_session = NULL;
            if (switch_channel_test_flag(switch_core_session_get_channel(session), CF_BRIDGED) &&
                switch_core_session_get_partner(session, &other_session) == SWITCH_STATUS_SUCCESS) {
                if (other_session->bugs && !switch_test_flag(other_session, SSF_MEDIA_BUG_TAP_ONLY)) {
                    other_session_bugs = 1;
                }
                switch_core_session_rwunlock(other_session);
            }

            /* Don't process CNG frame */
            if (!other_session_bugs) {
                status = SWITCH_STATUS_SUCCESS;
                goto done;
            }
        }

        is_cng = 1;
        need_codec = 1;
    } else if (switch_test_flag(*frame, SFF_NOT_AUDIO)) {
        do_resample = 0;
        do_bugs = 0;
        need_codec = 0;
    }

    if (switch_test_flag(session, SSF_READ_TRANSCODE) && !need_codec && switch_core_codec_ready(session->read_codec)) {
        switch_core_session_t *other_session;
        const char *uuid = switch_channel_get_partner_uuid(switch_core_session_get_channel(session));
        switch_clear_flag(session, SSF_READ_TRANSCODE);
        
        if (uuid && (other_session = switch_core_session_locate(uuid))) {
            switch_set_flag(other_session, SSF_READ_CODEC_RESET);
            switch_set_flag(other_session, SSF_READ_CODEC_RESET);
            switch_set_flag(other_session, SSF_WRITE_CODEC_RESET);
            switch_core_session_rwunlock(other_session);
        }
    }

    if (switch_test_flag(session, SSF_READ_CODEC_RESET)) {
        switch_core_codec_reset(session->read_codec);
        switch_clear_flag(session, SSF_READ_CODEC_RESET);
    }

    *time_after_wait = switch_micro_time_now();
    
    if (status == SWITCH_STATUS_SUCCESS && need_codec) {
        switch_frame_t *enc_frame, *read_frame = *frame;
        int rtp_event_set = 0;

        switch_set_flag(session, SSF_READ_TRANSCODE);

        if (!switch_test_flag(session, SSF_WARN_TRANSCODE)) {
            switch_core_session_message_t msg = { 0 };

            msg.message_id = SWITCH_MESSAGE_INDICATE_TRANSCODING_NECESSARY;
            switch_core_session_receive_message(session, &msg);
            switch_set_flag(session, SSF_WARN_TRANSCODE);
        }

        if (read_frame->codec || is_cng) {
            session->raw_read_frame.datalen = session->raw_read_frame.buflen;

            if (is_cng) {
                if (session->plc) {
                    plc_fillin(session->plc, session->raw_read_frame.data, read_frame->codec->implementation->decoded_bytes_per_packet / 2);
                    is_cng = 0;
                    flag &= ~SFF_CNG;
                } else {
                    memset(session->raw_read_frame.data, 255, read_frame->codec->implementation->decoded_bytes_per_packet);
                }

                session->raw_read_frame.timestamp = 0;
                session->raw_read_frame.datalen = read_frame->codec->implementation->decoded_bytes_per_packet;
                session->raw_read_frame.samples = session->raw_read_frame.datalen / sizeof(int16_t);
                rtp_event_set = switch_test_flag(read_frame, SFF_RTP_EVENT);
                read_frame = &session->raw_read_frame;
                status = SWITCH_STATUS_SUCCESS;
            } else {
                switch_codec_t *use_codec = read_frame->codec;
                if (do_bugs) {
                    switch_thread_rwlock_wrlock(session->bug_rwlock); /* ok */
                    if (!session->bugs) {
                        switch_thread_rwlock_unlock(session->bug_rwlock);
                        goto done;
                    }

                    if (!switch_core_codec_ready(&session->bug_codec) && switch_core_codec_ready(read_frame->codec)) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Setting BUG Codec %s:%d\n",
                                          read_frame->codec->implementation->iananame, read_frame->codec->implementation->ianacode);
                        switch_core_codec_copy(read_frame->codec, &session->bug_codec, NULL);
                        if (!switch_core_codec_ready(&session->bug_codec)) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s Error setting BUG codec %s!\n", 
                                              switch_core_session_get_name(session), read_frame->codec->implementation->iananame);
                        }
                    }

                    if (switch_core_codec_ready(&session->bug_codec)) {
                        use_codec = &session->bug_codec;
                    }
                    switch_thread_rwlock_unlock(session->bug_rwlock);

                    if (switch_thread_rwlock_trywrlock_timeout(session->bug_rwlock, 20) == SWITCH_STATUS_SUCCESS) {
                        if (!session->bugs) {
                            do_bugs = 0;
                        }
                        switch_thread_rwlock_unlock(session->bug_rwlock);
                    }
                    if (!do_bugs) goto done;
                }

                if (!session->rtcp_interval) {
                    switch_core_ioctl_stats(session, GET_RTCP_INTERVAL, &session->rtcp_interval);
                } else if (++session->total_reads % session->rtcp_interval == 0) {
                    int val;
                    if (session->neteq_inst) {
                        NetEqNetworkStatistics nwstats;
                        void *neteq_internal = switch_core_get_neteq_inst(session);
                        if (neteq_internal && WebRtcNetEQ_GetNetworkStatistics(neteq_internal, &nwstats) == 0) {
                            val = nwstats.current_buffer_size_ms;
                            switch_core_ioctl_stats(session, SET_JB_SIZE, &val);
                        }
                    }

                    val = session->total_decoded - session->last_total;
                    if (val) {
                        val = (session->total_lost * 100) / (session->total_lost + val);
                        switch_core_ioctl_stats(session, SET_LOST_PERCENT, &val);
                    }
                    session->last_total = session->total_decoded;
                    session->total_lost = 0;


                    val = 1;
                    switch_core_ioctl_stats(session, SET_SEND_RTCP, &val);
                }

                if (!switch_test_flag(*frame, SFF_WEBRTC_NETEQ) && 
                    switch_test_flag(read_frame, SFF_PLC)) {
                    session->raw_read_frame.datalen = read_frame->codec->implementation->decoded_bytes_per_packet;
                    session->raw_read_frame.samples = session->raw_read_frame.datalen / sizeof(int16_t);
                    memset(session->raw_read_frame.data, 255, session->raw_read_frame.datalen);
                    status = SWITCH_STATUS_SUCCESS;
                } else if (switch_test_flag(*frame, SFF_WEBRTC_NETEQ)) {
                    switch_codec_t *use_codec = read_frame->codec;
                    WebRtcNetEQ_status_t ret_status;
                    switch_codec_t *codec;
                    uint16_t lost_count = 0;

                    session->raw_read_frame.flags = 0;
                    codec = use_codec->implementation?use_codec:read_frame->codec;
                    if (!session->neteq_inst) {
                        if (!codec->implementation || !switch_core_codec_ready(codec)) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
                                              "INFO: Codec is not initialized yet. Skipping Decode.\n");
                            *frame = NULL;
                            goto done;
                        }

                        if (!codec->implementation->decoder) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                              "INFO: Decoder is not initialized. Skipping Decode.\n");
                            *frame = NULL;
                            goto done;
                        }

                        if (!read_frame->datalen) {
                            /*
                             * Wait until we read first frame. We need payload information because
                             * dynamic payload number could be different in the packet from what was
                             * initialized for codec.
                             */
                            *frame = NULL;
                            goto done;
                        }

                        /*
                         * Lets pass the session->pool instead of codec's one because we will access
                         * neteq_inst to fetch stats at the end. By this time codec could have been 
                         * destroyed.
                         */
                        if (WebRtcNetEQ_Init_inst(&session->neteq_inst, memory_alloc_cb, session->pool,
                                                  codec->implementation->actual_samples_per_second,
                                                  read_frame->payload, codec->implementation->iananame,
                                                  codec->implementation->microseconds_per_packet / 1000) != WebRtcNetEQ_SUCCESS) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                              "ERROR: WebRtcNetEQ_Init_inst() for codec=%s:%d.\n",
                                              codec->implementation->iananame, codec->implementation->ianacode);
                            *frame = NULL;
                            goto done;
                        }
                    }

                    switch_thread_rwlock_rdlock(session->bug_rwlock);

                    if (read_frame->datalen) {
                        if (session->zero_read_count) {
                            if (session->zero_read_count > 3 || (*frame)->seq > session->last_rtp_seq + 1 ||
                                (session->jb_size_before_zero < session->zero_read_count - 2))  {
                                
                                session->pkt_errors += 1;
                                
                                if ((read_time - session->period_start) >= FUZE_TIMER_MISS_INTERVAL) {
                                    if (session->pkt_errors > 5) {
                                        int current_num_packets = 0, max_num_packets = 0;
                                        WebRtcNetEQ_CurrentPacketBufferStatistics(switch_core_get_neteq_inst(session), &current_num_packets, &max_num_packets);
                                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, 
                                                          "Packet Errors: %d/%lld ssrc=%#x cur-jb-size=%d max-jb-size=%d.\n",
                                                          session->pkt_errors, (long long)(read_time - session->period_start),
                                                          (*frame)->ssrc, current_num_packets, max_num_packets);
                                    }
                                    session->pkt_errors = 0;
                                    session->period_start = read_time;
                                }
                            }

                            session->zero_read_count = 0;
                        }
                        session->last_rtp_seq = (*frame)->seq;

#if 0
                        /* mqt-1766: check if channel is muted, if it is then throw away it's packets */
                        if (flags & SWITCH_IO_FLAG_CANT_SPEAK) {
                            purge_jitterbuffer(session, frame);
                            status = SWITCH_STATUS_FALSE;
                            switch_thread_rwlock_unlock(session->bug_rwlock);
                            goto even_more_done;
                        }
#endif

                        /* mqt-1769: check if channel is an active speaker, if:
                         * (1) It is an active speaker then put packets into jitter buffer & process
                         * (2) It is not an active speaker then check whether the rtp packet contain an energy level?  If:
                         *     (2a) It doesn't contain an energy level then insert into the jitter buffer & continue as per normal
                         *     (2b) It does contain an energy level and the energy level is >= MIN_SPKR_THRESH then insert into the jitter buffer.
                         *          It does contain an energy level and the energy level is < MIN_SPKR_THRESH (for 1 second) then throw away the packet & return
                         */
                        if (!(flags & SWITCH_IO_FLAG_ACTIVE_TALKER)) {
                            /* flag set when below power threshold */
                            if  (!switch_test_flag(read_frame, SFF_RTP_AUDIO_OVER_THR)) {
                                session->audio_level_low_count += 1;
#if 0
                                if (session->audio_level_low_count >= 50) {
                                    purge_jitterbuffer(session, frame);
                                    status = SWITCH_STATUS_FALSE;
                                    switch_thread_rwlock_unlock(session->bug_rwlock);
                                    goto even_more_done;
                                }
#endif
                            } else {
                                if (session->audio_level_low_count >= 50) {
                                    wasskipping = SWITCH_TRUE;
                                }
                                session->audio_level_low_count = 0;
                            }
                        } else {
                            if (session->audio_level_low_count >= 50) {
                                wasskipping = SWITCH_TRUE;
                            }
                            session->audio_level_low_count = 0;
                        }

                        if (!(flags & SWITCH_IO_FLAG_CANT_SPEAK) && session->audio_level_low_count < 50) {
                            if (wasskipping) {
                                NetEqNetworkStatistics nwstats;
                                void *neteq_internal = switch_core_get_neteq_inst(session);
                                if (neteq_internal) {
                                    WebRtcNetEQ_GetNetworkStatistics(neteq_internal, &nwstats);
                                }

                                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                                                  "get_frame stats: read/skip=%d/%d insert/skip=%d/%d jbsize=%dms jfpref=%d peaks=%d\n",
                                                  session->read, session->skip_read, session->insert, session->skip_insert,
                                                  nwstats.current_buffer_size_ms, nwstats.preferred_buffer_size_ms,nwstats.jitter_peaks_found);
                                read_frame->m = 1;
                            }
                            if (WebRtcNetEQ_Insert(session->neteq_inst, read_frame->data,
                                                   read_frame->datalen, read_frame->payload, read_frame->seq,
                                                   read_frame->timestamp, read_frame->ssrc, read_frame->m) != WebRtcNetEQ_SUCCESS) {
                                
                                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
                                                  "ERROR: WebRtcNetEQ_Insert: codec=%s datalen=%d payload=%d.\n",
                                                  codec->implementation->iananame, read_frame->datalen,
                                                  read_frame->payload);
                            } else {
                                session->insert += 1;
                            }
                        } else {
                            session->skip_insert += 1;
                        }
                        
                        /* xxx fuze: insert into conference queue as well ... we can just forward encoded frames if it makes sense to */

                        if (switch_test_flag(read_frame, SFF_HOT_READ)) {
                            (*frame)->datalen = 0;
                            (*frame)->flags = 0;
                            if (switch_test_flag(read_frame, SFF_RTP_EVENT))
                                (*frame)->flags |= SFF_RTP_EVENT;
                            status = SWITCH_STATUS_FALSE;
                            session->suppress_lost = true;
                            switch_clear_flag(read_frame, SFF_HOT_READ);
                            switch_thread_rwlock_unlock(session->bug_rwlock);
                            goto even_more_done;
                        }
                    }
                    session->suppress_lost = false;
                    if (flags & SWITCH_IO_FLAG_CANT_SPEAK || session->audio_level_low_count >= 50) {
                        purge_jitterbuffer(session, frame);
                        *frame = NULL;
                        status = SWITCH_STATUS_FALSE;
                        session->skip_read += 1;
                        switch_thread_rwlock_unlock(session->bug_rwlock);
                        goto even_more_done;
                    } else {
                        if ((ret_status = WebRtcNetEQ_Extract(session->neteq_inst,
                                                              session->raw_read_frame.data,
                                                              &session->raw_read_frame.datalen,
                                                              &lost_count, &session->total_decoded,
                                                              session->suppress_lost)) == WebRtcNetEQ_SUCCESS) {
                            if (switch_test_flag(read_frame, SFF_RTP_EVENT)) 
                                session->raw_read_frame.flags |= SFF_RTP_EVENT;
                            status = SWITCH_STATUS_SUCCESS;
                            session->read += 1;
                            /* switch_thread_rwlock_unlock(session->bug_rwlock); -- should hit this below? */
                        } else if (!session->in_cn_period && ret_status == WebRtcNetEQ_ERROR) {
                            
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
                                              "ERROR: WebRtcNetEQ_Extract: codec=%s\n", codec->implementation->iananame);
                            *frame = NULL; //We need to play something; So let it send some dummy packet.
                            status = SWITCH_STATUS_BREAK;
                            switch_thread_rwlock_unlock(session->bug_rwlock);
                            goto even_more_done;
                        }
                    }

                    /* bug_rwlock xxx */
                    session->suppress_lost = SWITCH_FALSE;
                    
                    if ((flags & SWITCH_IO_FLAG_CLEAR_LOST) || session->in_cn_period) {
                        lost_count = 0;
                    }
                    if (lost_count) {
                        session->total_lost += lost_count;
                        if (lost_count >= RTP_EVENT_CONSECUTIVE_PACKET_LOSS_THRESHOLD) {
                            switch_set_flag(read_frame, SFF_RTP_EVENT);
                            switch_core_ioctl_stats(session, SET_EVENT_HIGH_CONSECUTIVE_PACKET_LOSS, NULL);
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                                              "CONSECUTIVE LOSS current=%u total=%u)\n",
                                              lost_count, session->total_lost);
                        }

                        switch_core_ioctl_stats(session, SET_CHOP_EVENT, &lost_count);
                    }

                    if (!read_frame->datalen) {
                        if (!session->zero_read_count) {
                            int current_num_packets = 0, max_num_packets = 0;
                            WebRtcNetEQ_CurrentPacketBufferStatistics(switch_core_get_neteq_inst(session), &current_num_packets, &max_num_packets);
                            session->jb_size_before_zero = current_num_packets;
                        }
                        session->zero_read_count++;
                    }

                    switch_thread_rwlock_unlock(session->bug_rwlock);
                } else {
                    switch_codec_t *codec = use_codec;

                    if (!switch_core_codec_ready(codec)) {
                        codec = read_frame->codec;
                    }

                    switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */
                    codec->cur_frame = read_frame;
                    session->read_codec->cur_frame = read_frame;
                    status = switch_core_codec_decode(codec,
                                                      session->read_codec,
                                                      read_frame->data,
                                                      read_frame->datalen,
                                                      session->read_impl.actual_samples_per_second,
                                                      session->raw_read_frame.data, &session->raw_read_frame.datalen, &session->raw_read_frame.rate, 
                                                      &read_frame->flags);
                    codec->cur_frame = NULL;
                    session->read_codec->cur_frame = NULL;
                    switch_thread_rwlock_unlock(session->bug_rwlock);

                }
                
                if (status == SWITCH_STATUS_SUCCESS) {
                    if ((switch_channel_test_flag(session->channel, CF_JITTERBUFFER_PLC) || switch_channel_test_flag(session->channel, CF_CNG_PLC)) 
                        && !session->plc) {
                        session->plc = plc_init(NULL);
                    }
                    
                    if (session->plc) {
                        if (switch_test_flag(read_frame, SFF_PLC)) {
                            plc_fillin(session->plc, session->raw_read_frame.data, session->raw_read_frame.datalen / 2);
                            switch_clear_flag(read_frame, SFF_PLC);
                        } else {
                            plc_rx(session->plc, session->raw_read_frame.data, session->raw_read_frame.datalen / 2);
                        }
                    }
                }


            }

            if (do_resample && ((status == SWITCH_STATUS_SUCCESS) || is_cng)) {
                status = SWITCH_STATUS_RESAMPLE;
            }

            switch (status) {
            case SWITCH_STATUS_RESAMPLE:
                if (!session->read_resampler) {
                    switch_mutex_lock(session->resample_mutex);

                    status = switch_resample_create(&session->read_resampler,
                                                    read_frame->codec->implementation->actual_samples_per_second,
                                                    session->read_impl.actual_samples_per_second,
                                                    session->read_impl.decoded_bytes_per_packet, SWITCH_RESAMPLE_QUALITY, 1);

                    switch_mutex_unlock(session->resample_mutex);

                    if (status != SWITCH_STATUS_SUCCESS) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Unable to allocate resampler\n");
                        status = SWITCH_STATUS_FALSE;
                        goto done;
                    } else {
                        switch_core_session_message_t msg = { 0 };
                        msg.numeric_arg = 1;
                        msg.message_id = SWITCH_MESSAGE_RESAMPLE_EVENT;
                        switch_core_session_receive_message(session, &msg);

                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "Activating read resampler\n");
                    }
                }
            case SWITCH_STATUS_SUCCESS:
                session->raw_read_frame.samples = session->raw_read_frame.datalen / sizeof(int16_t);
                session->raw_read_frame.rate = read_frame->rate;
                if (read_frame->codec->implementation->samples_per_packet != session->read_impl.samples_per_packet) {
                    session->raw_read_frame.timestamp = 0;
                } else {
                    session->raw_read_frame.timestamp = read_frame->timestamp;
                }
                session->raw_read_frame.ssrc = read_frame->ssrc;
                session->raw_read_frame.seq = read_frame->seq;
                session->raw_read_frame.m = read_frame->m;
                session->raw_read_frame.payload = read_frame->payload;
                session->raw_read_frame.flags = 0;
                if (switch_test_flag(read_frame, SFF_PLC)) {
                    session->raw_read_frame.flags |= SFF_PLC;
                } else if (switch_test_flag(read_frame, SFF_RTP_EVENT) || rtp_event_set) {
                    session->raw_read_frame.flags |= SFF_RTP_EVENT;
                }
                read_frame = &session->raw_read_frame;
                break;
            case SWITCH_STATUS_NOOP:
                if (session->read_resampler) {
                    switch_mutex_lock(session->resample_mutex);
                    switch_resample_destroy(&session->read_resampler);
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "Deactivating read resampler\n");
                    switch_mutex_unlock(session->resample_mutex);

                    {
                        switch_core_session_message_t msg = { 0 };
                        msg.numeric_arg = 0;
                        msg.message_id = SWITCH_MESSAGE_RESAMPLE_EVENT;
                        switch_core_session_receive_message(session, &msg);
                    }

                }

                status = SWITCH_STATUS_SUCCESS;
                break;
            case SWITCH_STATUS_BREAK:
                memset(session->raw_read_frame.data, 255, read_frame->codec->implementation->decoded_bytes_per_packet);
                session->raw_read_frame.datalen = read_frame->codec->implementation->decoded_bytes_per_packet;
                session->raw_read_frame.samples = session->raw_read_frame.datalen / sizeof(int16_t);
                session->raw_read_frame.timestamp = read_frame->timestamp;
                session->raw_read_frame.rate = read_frame->rate;
                session->raw_read_frame.ssrc = read_frame->ssrc;
                session->raw_read_frame.seq = read_frame->seq;
                session->raw_read_frame.m = read_frame->m;
                session->raw_read_frame.payload = read_frame->payload;
                session->raw_read_frame.flags = 0;
                if (switch_test_flag(read_frame, SFF_PLC)) {
                    session->raw_read_frame.flags |= SFF_PLC;
                } else if (switch_test_flag(read_frame, SFF_RTP_EVENT) || rtp_event_set) {
                    session->raw_read_frame.flags |= SFF_RTP_EVENT;
                }

                read_frame = &session->raw_read_frame;
                status = SWITCH_STATUS_SUCCESS;
                break;
            case SWITCH_STATUS_NOT_INITALIZED:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec init error!\n");
                goto done;
            default:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec %s decoder error! [%d]\n",
                                  session->read_codec->codec_interface->interface_name, status);

                if (++session->decoder_errors < 10) {
                    status = SWITCH_STATUS_SUCCESS;
                } else {
                    goto done;
                }
            }

            session->decoder_errors = 0;
        }

        if (session->bugs) {
            switch_media_bug_t *bp;
            switch_bool_t ok = SWITCH_TRUE;
            int prune = 0;
            switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */

            for (bp = session->bugs; bp; bp = bp->next) {
                ok = SWITCH_TRUE;

                if (switch_channel_test_flag(session->channel, CF_PAUSE_BUGS) && !switch_core_media_bug_test_flag(bp, SMBF_NO_PAUSE)) {
                    continue;
                }

                if (!switch_channel_test_flag(session->channel, CF_ANSWERED) && switch_core_media_bug_test_flag(bp, SMBF_ANSWER_REQ)) {
                    continue;
                }

                if (!switch_channel_test_flag(session->channel, CF_BRIDGED) && switch_core_media_bug_test_flag(bp, SMBF_BRIDGE_REQ)) {
                    continue;
                }

                if (switch_test_flag(bp, SMBF_PRUNE)) {
                    prune++;
                    continue;
                }

                if (ok && switch_test_flag(bp, SMBF_READ_REPLACE)) {
                    do_bugs = 0;
                    if (bp->callback) {
                        bp->read_replace_frame_in = read_frame;
                        bp->read_replace_frame_out = read_frame;
                        bp->read_demux_frame = NULL;
                        if ((ok = bp->callback(bp, bp->user_data, SWITCH_ABC_TYPE_READ_REPLACE)) == SWITCH_TRUE) {
                            read_frame = bp->read_replace_frame_out;
                        }
                    }
                }

                if ((bp->stop_time && bp->stop_time <= switch_epoch_time_now(NULL)) || ok == SWITCH_FALSE) {
                    switch_set_flag(bp, SMBF_PRUNE);
                    prune++;
                }


            }
            switch_thread_rwlock_unlock(session->bug_rwlock);
            if (prune) {
                switch_core_media_bug_prune(session);
            }
        }

        if (session->bugs) {
            switch_media_bug_t *bp;
            switch_bool_t ok = SWITCH_TRUE;
            int prune = 0;
            switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */

            for (bp = session->bugs; bp; bp = bp->next) {
                ok = SWITCH_TRUE;

                if (switch_channel_test_flag(session->channel, CF_PAUSE_BUGS) && !switch_core_media_bug_test_flag(bp, SMBF_NO_PAUSE)) {
                    continue;
                }

                if (!switch_channel_test_flag(session->channel, CF_ANSWERED) && switch_core_media_bug_test_flag(bp, SMBF_ANSWER_REQ)) {
                    continue;
                }

                if (!switch_channel_test_flag(session->channel, CF_BRIDGED) && switch_core_media_bug_test_flag(bp, SMBF_BRIDGE_REQ)) {
                    continue;
                }

                if (switch_test_flag(bp, SMBF_PRUNE)) {
                    prune++;
                    continue;
                }

                if (ok && bp->ready && switch_test_flag(bp, SMBF_READ_STREAM)) {
                    switch_mutex_lock(bp->read_mutex);
                    if (bp->read_demux_frame) {
                        uint8_t data[SWITCH_RECOMMENDED_BUFFER_SIZE];
                        int bytes = read_frame->datalen / 2;

                        memcpy(data, read_frame->data, read_frame->datalen);
                        switch_unmerge_sln((int16_t *)data, bytes, bp->read_demux_frame->data, bytes);
                        switch_buffer_write(bp->raw_read_buffer, data, read_frame->datalen);
                    } else {
                        switch_buffer_write(bp->raw_read_buffer, read_frame->data, read_frame->datalen);
                    }

                    if (bp->callback) {
                        ok = bp->callback(bp, bp->user_data, SWITCH_ABC_TYPE_READ);
                    }
                    switch_mutex_unlock(bp->read_mutex);
                }

                if ((bp->stop_time && bp->stop_time <= switch_epoch_time_now(NULL)) || ok == SWITCH_FALSE) {
                    switch_set_flag(bp, SMBF_PRUNE);
                    prune++;
                }
            }
            switch_thread_rwlock_unlock(session->bug_rwlock);
            if (prune) {
                switch_core_media_bug_prune(session);
            }
        }

        if (do_bugs || tap_only) {
            goto done;
        }

        if (session->read_codec) {
            if (session->read_resampler) {
                short *data = read_frame->data;
                switch_mutex_lock(session->resample_mutex);
                switch_resample_process(session->read_resampler, data, (int) read_frame->datalen / 2);
                memcpy(data, session->read_resampler->to, session->read_resampler->to_len * 2);
                read_frame->samples = session->read_resampler->to_len;
                read_frame->datalen = session->read_resampler->to_len * 2;
                read_frame->rate = session->read_resampler->to_rate;
                switch_mutex_unlock(session->resample_mutex);
            }

            if (read_frame->datalen == session->read_impl.decoded_bytes_per_packet) {
                perfect = TRUE;
            } else {
                if (!session->raw_read_buffer) {
                    switch_size_t bytes = session->read_impl.decoded_bytes_per_packet;
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Engaging Read Buffer at %u bytes vs %u\n",
                                      (uint32_t) bytes, (uint32_t) (*frame)->datalen);
                    switch_buffer_create_dynamic(&session->raw_read_buffer, bytes * SWITCH_BUFFER_BLOCK_FRAMES, bytes * SWITCH_BUFFER_START_FRAMES, 0);
                }

                if (read_frame->datalen && (!switch_buffer_write(session->raw_read_buffer, read_frame->data, read_frame->datalen))) {
                    status = SWITCH_STATUS_MEMERR;
                    goto done;
                }
            }
            
            if (perfect || switch_buffer_inuse(session->raw_read_buffer) >= session->read_impl.decoded_bytes_per_packet) {
                if (perfect) {
                    enc_frame = read_frame;
                    session->raw_read_frame.rate = read_frame->rate;
                } else {
                    session->raw_read_frame.datalen = (uint32_t) switch_buffer_read(session->raw_read_buffer,
                                                                                    session->raw_read_frame.data,
                                                                                    session->read_impl.decoded_bytes_per_packet);

                    session->raw_read_frame.rate = session->read_impl.actual_samples_per_second;
                    enc_frame = &session->raw_read_frame;
                }
                session->enc_read_frame.datalen = session->enc_read_frame.buflen;

                switch_assert(session->read_codec != NULL);
                switch_assert(enc_frame != NULL);
                switch_assert(enc_frame->data != NULL);
                session->read_codec->cur_frame = enc_frame;
                enc_frame->codec->cur_frame = enc_frame;
                status = switch_core_codec_encode(session->read_codec,
                                                  enc_frame->codec,
                                                  enc_frame->data,
                                                  enc_frame->datalen,
                                                  session->read_impl.actual_samples_per_second,
                                                  session->enc_read_frame.data, &session->enc_read_frame.datalen, &session->enc_read_frame.rate, &flag);
                session->read_codec->cur_frame = NULL;
                enc_frame->codec->cur_frame = NULL;
                switch (status) {
                case SWITCH_STATUS_RESAMPLE:
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Fixme 1\n");
                case SWITCH_STATUS_SUCCESS:
                    session->enc_read_frame.samples = session->read_impl.decoded_bytes_per_packet / sizeof(int16_t);
                    if (perfect) {
                        if (enc_frame->codec->implementation->samples_per_packet != session->read_impl.samples_per_packet) {
                            session->enc_read_frame.timestamp = 0;
                        } else {
                            session->enc_read_frame.timestamp = read_frame->timestamp;
                        }
                        session->enc_read_frame.rate = read_frame->rate;
                        session->enc_read_frame.ssrc = read_frame->ssrc;
                        session->enc_read_frame.seq = read_frame->seq;
                        session->enc_read_frame.m = read_frame->m;
                        session->enc_read_frame.payload = session->read_impl.ianacode;
                    }
                    *frame = &session->enc_read_frame;
                    break;
                case SWITCH_STATUS_NOOP:
                    session->raw_read_frame.samples = enc_frame->codec->implementation->samples_per_packet;
                    session->raw_read_frame.timestamp = read_frame->timestamp;
                    session->raw_read_frame.payload = enc_frame->codec->implementation->ianacode;
                    session->raw_read_frame.m = read_frame->m;
                    session->raw_read_frame.ssrc = read_frame->ssrc;
                    session->raw_read_frame.seq = read_frame->seq;
                    *frame = enc_frame;
                    status = SWITCH_STATUS_SUCCESS;
                    break;
                case SWITCH_STATUS_NOT_INITALIZED:
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec init error!\n");
                    *frame = NULL;
                    status = SWITCH_STATUS_GENERR;
                    break;
                default:
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec %s encoder error!\n",
                                      session->read_codec->codec_interface->interface_name);
                    *frame = NULL;
                    status = SWITCH_STATUS_GENERR;
                    break;
                }
            } else {
                goto top;
            }
        }
    } // need codec

 done:
    if (!(*frame)) {
        status = SWITCH_STATUS_FALSE;
    } else {
        if (flag & SFF_CNG) {
            switch_set_flag((*frame), SFF_CNG);
        }
        if (flag & SFF_TIMEOUT) {
            switch_set_flag((*frame), SFF_TIMEOUT);
        }
        if (session->bugs) {
            switch_media_bug_t *bp;
            switch_bool_t ok = SWITCH_TRUE;
            int prune = 0;
            switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */
            for (bp = session->bugs; bp; bp = bp->next) {
                ok = SWITCH_TRUE;

                if (switch_channel_test_flag(session->channel, CF_PAUSE_BUGS) && !switch_core_media_bug_test_flag(bp, SMBF_NO_PAUSE)) {
                    continue;
                }

                if (!switch_channel_test_flag(session->channel, CF_ANSWERED) && switch_core_media_bug_test_flag(bp, SMBF_ANSWER_REQ)) {
                    continue;
                }

                if (!switch_channel_test_flag(session->channel, CF_BRIDGED) && switch_core_media_bug_test_flag(bp, SMBF_BRIDGE_REQ)) {
                    continue;
                }

                if (switch_test_flag(bp, SMBF_PRUNE)) {
                    prune++;
                    continue;
                }

                if (bp->ready && switch_test_flag(bp, SMBF_READ_PING)) {
                    switch_mutex_lock(bp->read_mutex);
                    bp->ping_frame = *frame;
                    if (bp->callback) {
                        if (bp->callback(bp, bp->user_data, SWITCH_ABC_TYPE_READ_PING) == SWITCH_FALSE
                            || (bp->stop_time && bp->stop_time <= switch_epoch_time_now(NULL))) {
                            ok = SWITCH_FALSE;
                        }
                    }
                    bp->ping_frame = NULL;
                    switch_mutex_unlock(bp->read_mutex);
                }

                if (ok == SWITCH_FALSE) {
                    switch_set_flag(bp, SMBF_PRUNE);
                    prune++;
                }
            }
            switch_thread_rwlock_unlock(session->bug_rwlock);
            if (prune) {
                switch_core_media_bug_prune(session);
            }
        }
    }

 even_more_done:

    if (!*frame ||
        (!switch_test_flag(*frame, SFF_PROXY_PACKET) &&
         (!(*frame)->codec || !(*frame)->codec->implementation || !switch_core_codec_ready((*frame)->codec)))) {
        *frame = &runtime.dummy_cng_frame;
    }

    switch_mutex_unlock(session->read_codec->mutex);
    switch_mutex_unlock(session->codec_read_mutex);

    
    if (status == SWITCH_STATUS_SUCCESS && switch_channel_get_callstate(session->channel) == CCS_UNHELD) {
        switch_channel_set_callstate(session->channel, CCS_ACTIVE);
    }


    return status;
}

static switch_status_t perform_write_timed(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags, int stream_id, switch_time_t *timed)
{
    switch_io_event_hook_write_frame_t *ptr;
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_time_t b4_time;

    *timed = 0;

    if (session->bugs && !(frame->flags & SFF_NOT_AUDIO)) {
        switch_media_bug_t *bp;
        switch_bool_t ok = SWITCH_TRUE;
        int prune = 0;

        switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */

        for (bp = session->bugs; bp; bp = bp->next) {
            ok = SWITCH_TRUE;

            if (switch_channel_test_flag(session->channel, CF_PAUSE_BUGS) && !switch_core_media_bug_test_flag(bp, SMBF_NO_PAUSE)) {
                continue;
            }
            
            if (!switch_channel_test_flag(session->channel, CF_ANSWERED) && switch_core_media_bug_test_flag(bp, SMBF_ANSWER_REQ)) {
                continue;
            }
            if (switch_test_flag(bp, SMBF_PRUNE)) {
                prune++;
                continue;
            }
            
            if (bp->ready) {
                if (switch_test_flag(bp, SMBF_TAP_NATIVE_WRITE)) {
                    if (bp->callback) {
                        bp->native_write_frame = frame;
                        ok = bp->callback(bp, bp->user_data, SWITCH_ABC_TYPE_TAP_NATIVE_WRITE);
                        bp->native_write_frame = NULL;
                    }
                }
            }
            
            if ((bp->stop_time && bp->stop_time <= switch_epoch_time_now(NULL)) || ok == SWITCH_FALSE) {
                switch_set_flag(bp, SMBF_PRUNE);
                prune++;
            }
        }
        switch_thread_rwlock_unlock(session->bug_rwlock);

        if (prune) {

            switch_core_media_bug_prune(session);
        }
    }

    b4_time = switch_micro_time_now();
    if (session->endpoint_interface->io_routines->write_frame) {
        if ((status = session->endpoint_interface->io_routines->write_frame(session, frame, flags, stream_id)) == SWITCH_STATUS_SUCCESS) {
            for (ptr = session->event_hooks.write_frame; ptr; ptr = ptr->next) {
                if ((status = ptr->write_frame(session, frame, flags, stream_id)) != SWITCH_STATUS_SUCCESS) {
                    *timed += (switch_micro_time_now() - b4_time);
                    break;
                }
            }
        }
    }
    *timed += (switch_micro_time_now() - b4_time);

    return status;
}

static switch_status_t perform_write(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags, int stream_id)
{
    switch_time_t timed;
    return perform_write_timed(session, frame, flags, stream_id, &timed);
}

SWITCH_DECLARE(switch_status_t) switch_core_session_write_frame_core(switch_core_session_t *session, switch_frame_t *frame,
                                                                     switch_io_flag_t flags, int stream_id,
                                                                     switch_frame_t **ret_enc_frame)
{

    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_frame_t *enc_frame = NULL, *write_frame = frame;
    unsigned int flag = 0, need_codec = 0, perfect = 0, do_bugs = 0, do_write = 0, do_resample = 0, ptime_mismatch = 0, pass_cng = 0, resample = 0;
    int did_write_resample = 0;
    bool encoder_path = (ret_enc_frame != NULL);

    switch_frame_flag_t before_flags = frame->flags;

    switch_assert(session != NULL);
    switch_assert(frame != NULL);

    if (!switch_channel_ready(session->channel)) {
        return SWITCH_STATUS_FALSE;
    }

    if (switch_mutex_trylock(session->codec_write_mutex) == SWITCH_STATUS_SUCCESS) {
        switch_mutex_unlock(session->codec_write_mutex);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s write mutex is already locked.\n", switch_channel_get_name(session->channel));
        return SWITCH_STATUS_SUCCESS;
    }

    if (switch_test_flag(frame, SFF_CNG)) {
#if 1
        /* fuze: we want to pass CNG packets through */
        pass_cng = 1;
#else
        if (switch_channel_test_flag(session->channel, CF_ACCEPT_CNG)) {
            pass_cng = 1;
        } else {
            return SWITCH_STATUS_SUCCESS;
        }
#endif
    }

    if (switch_channel_test_flag(session->channel, CF_AUDIO_PAUSE)) {
        return SWITCH_STATUS_SUCCESS;
    }

    if (!(session->write_codec && switch_core_codec_ready(session->write_codec)) && !pass_cng) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s has no write codec.\n", switch_channel_get_name(session->channel));
        switch_channel_hangup(session->channel, SWITCH_CAUSE_INCOMPATIBLE_DESTINATION);
        return SWITCH_STATUS_FALSE;
    }

    if (switch_channel_test_flag(session->channel, CF_HOLD)) {
        return SWITCH_STATUS_SUCCESS;
    }

    if (switch_test_flag(frame, SFF_PROXY_PACKET) || pass_cng) {
        /* Fast PASS! */
        switch_mutex_lock(session->codec_write_mutex);
        if (frame->flags != before_flags) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s flags don't match 0x%x != 0x%x\n", 
                              switch_channel_get_name(session->channel), before_flags, frame->flags);
        }
        if (!encoder_path) { status = perform_write(session, frame, flag, stream_id); }
        switch_mutex_unlock(session->codec_write_mutex);
        return status;
    }

    switch_mutex_lock(session->codec_write_mutex);

    if (!(frame->codec && frame->codec->implementation)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s has received a bad frame with no codec!\n", 
                          switch_channel_get_name(session->channel));
        switch_channel_hangup(session->channel, SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER);
        switch_mutex_unlock(session->codec_write_mutex);
        return SWITCH_STATUS_FALSE;
    }

    switch_assert(frame->codec != NULL);
    switch_assert(frame->codec->implementation != NULL);

    if (!(switch_core_codec_ready(session->write_codec) && frame->codec) ||
        !switch_channel_ready(session->channel) || !switch_channel_media_ready(session->channel)) {
        switch_mutex_unlock(session->codec_write_mutex);
        return SWITCH_STATUS_FALSE;
    }

    switch_mutex_lock(session->write_codec->mutex);
    switch_mutex_lock(frame->codec->mutex);

    if (!(switch_core_codec_ready(session->write_codec) && switch_core_codec_ready(frame->codec))) goto error;
    
    if ((session->write_codec && frame->codec && session->write_codec->implementation != frame->codec->implementation)) {
        if (session->write_impl.codec_id == frame->codec->implementation->codec_id ||
            session->write_impl.microseconds_per_packet != frame->codec->implementation->microseconds_per_packet) {
            ptime_mismatch = TRUE;
            if ((switch_test_flag(frame->codec, SWITCH_CODEC_FLAG_PASSTHROUGH) || switch_test_flag(session->read_codec, SWITCH_CODEC_FLAG_PASSTHROUGH)) ||
                switch_channel_test_flag(session->channel, CF_PASSTHRU_PTIME_MISMATCH)) {
                if (frame->flags != before_flags) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s flags don't match 0x%x != 0x%x\n", 
                                      switch_channel_get_name(session->channel), before_flags, frame->flags);
                }
                if (!encoder_path) { status = perform_write(session, frame, flags, stream_id); }
                goto error;
            }
        }
        need_codec = TRUE;
    }

    if (session->write_codec && !frame->codec) {
        need_codec = TRUE;
    }

    if (session->bugs && !need_codec && !switch_test_flag(session, SSF_MEDIA_BUG_TAP_ONLY)) {
        do_bugs = TRUE;
        need_codec = TRUE;
    }

    if (frame->codec->implementation->actual_samples_per_second != session->write_impl.actual_samples_per_second) {
        need_codec = TRUE;
        do_resample = TRUE;
    }


    if ((frame->flags & SFF_NOT_AUDIO)) {
        do_resample = 0;
        do_bugs = 0;
        need_codec = 0;
    }

    if (switch_test_flag(session, SSF_WRITE_TRANSCODE) && !need_codec && switch_core_codec_ready(session->write_codec)) {
        switch_core_session_t *other_session;
        const char *uuid = switch_channel_get_partner_uuid(switch_core_session_get_channel(session));

        if (uuid && (other_session = switch_core_session_locate(uuid))) {
            switch_set_flag(other_session, SSF_READ_CODEC_RESET);
            switch_set_flag(other_session, SSF_READ_CODEC_RESET);
            switch_set_flag(other_session, SSF_WRITE_CODEC_RESET);
            switch_core_session_rwunlock(other_session);
        }
        
        switch_clear_flag(session, SSF_WRITE_TRANSCODE);
    }


    if (switch_test_flag(session, SSF_WRITE_CODEC_RESET)) {
        switch_core_codec_reset(session->write_codec);
        switch_clear_flag(session, SSF_WRITE_CODEC_RESET);
    }

    if (!need_codec) {
        do_write = TRUE;
        write_frame = frame;
        goto done;
    }

    if (!switch_test_flag(session, SSF_WARN_TRANSCODE)) {
        switch_core_session_message_t msg = { 0 };

        msg.message_id = SWITCH_MESSAGE_INDICATE_TRANSCODING_NECESSARY;
        switch_core_session_receive_message(session, &msg);
        switch_set_flag(session, SSF_WARN_TRANSCODE);
    }

    if (frame->codec) {
        session->raw_write_frame.datalen = session->raw_write_frame.buflen;
        frame->codec->cur_frame = frame;
        session->write_codec->cur_frame = frame;
        status = switch_core_codec_decode(frame->codec,
                                          session->write_codec,
                                          frame->data,
                                          frame->datalen,
                                          session->write_impl.actual_samples_per_second,
                                          session->raw_write_frame.data, &session->raw_write_frame.datalen, &session->raw_write_frame.rate, &frame->flags);
        frame->codec->cur_frame = NULL;
        session->write_codec->cur_frame = NULL;
        if (do_resample && status == SWITCH_STATUS_SUCCESS) {
            status = SWITCH_STATUS_RESAMPLE;
        }
        
        switch (status) {
        case SWITCH_STATUS_RESAMPLE:
            resample++;
            write_frame = &session->raw_write_frame;
            write_frame->rate = frame->codec->implementation->actual_samples_per_second;
            if (!session->write_resampler) {
                switch_mutex_lock(session->resample_mutex);
                status = switch_resample_create(&session->write_resampler,
                                                frame->codec->implementation->actual_samples_per_second,
                                                session->write_impl.actual_samples_per_second,
                                                session->write_impl.decoded_bytes_per_packet, SWITCH_RESAMPLE_QUALITY, 1);


                switch_mutex_unlock(session->resample_mutex);
                if (status != SWITCH_STATUS_SUCCESS) {
                    goto done;
                } else {
                    switch_core_session_message_t msg = { 0 };
                    msg.numeric_arg = 1;
                    msg.message_id = SWITCH_MESSAGE_RESAMPLE_EVENT;
                    switch_core_session_receive_message(session, &msg);

                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "Activating write resampler\n");
                }
            }
            break;
        case SWITCH_STATUS_SUCCESS:
            session->raw_write_frame.samples = session->raw_write_frame.datalen / sizeof(int16_t);
            session->raw_write_frame.timestamp = frame->timestamp;
            session->raw_write_frame.rate = frame->rate;
            session->raw_write_frame.m = frame->m;
            session->raw_write_frame.ssrc = frame->ssrc;
            session->raw_write_frame.seq = frame->seq;
            session->raw_write_frame.payload = frame->payload;
            session->raw_write_frame.flags = 0;
            if (switch_test_flag(frame, SFF_PLC)) {
                session->raw_write_frame.flags |= SFF_PLC;
            } 

            write_frame = &session->raw_write_frame;
            break;
        case SWITCH_STATUS_BREAK:
            status = SWITCH_STATUS_SUCCESS;
            goto error;
        case SWITCH_STATUS_NOOP:
            if (session->write_resampler) {
                switch_mutex_lock(session->resample_mutex);
                switch_resample_destroy(&session->write_resampler);
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "Deactivating write resampler\n");
                switch_mutex_unlock(session->resample_mutex);

                {
                    switch_core_session_message_t msg = { 0 };
                    msg.numeric_arg = 0;
                    msg.message_id = SWITCH_MESSAGE_RESAMPLE_EVENT;
                    switch_core_session_receive_message(session, &msg);
                }

            }
            write_frame = frame;
            status = SWITCH_STATUS_SUCCESS;
            break;
        default:

            if (status == SWITCH_STATUS_NOT_INITALIZED) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec init error!\n");
                goto error;
            }
            if (ptime_mismatch && status != SWITCH_STATUS_GENERR) {
                if (frame->flags != before_flags) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s flags don't match 0x%x != 0x%x\n", 
                                      switch_channel_get_name(session->channel), before_flags, frame->flags);
                }
                if (!encoder_path) { status = perform_write(session, frame, flags, stream_id); }
                status = SWITCH_STATUS_SUCCESS;
                goto error;
            }

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec %s decoder error!\n",
                              frame->codec->codec_interface->interface_name);
            goto error;
        }
    }
    


    if (session->write_resampler) {
        short *data = write_frame->data;

        switch_mutex_lock(session->resample_mutex);
        if (session->write_resampler) {

            switch_resample_process(session->write_resampler, data, write_frame->datalen / 2);

            memcpy(data, session->write_resampler->to, session->write_resampler->to_len * 2);

            write_frame->samples = session->write_resampler->to_len;

            write_frame->datalen = write_frame->samples * 2;

            write_frame->rate = session->write_resampler->to_rate;

            if (!encoder_path) { did_write_resample = 1; }
        }
        switch_mutex_unlock(session->resample_mutex);
    }



    if (session->bugs) {
        switch_media_bug_t *bp;
        int prune = 0;

        switch_thread_rwlock_rdlock(session->bug_rwlock); /* ok */
        for (bp = session->bugs; bp; bp = bp->next) {
            switch_bool_t ok = SWITCH_TRUE;

            if (!bp->ready) {
                continue;
            }

            if (switch_channel_test_flag(session->channel, CF_PAUSE_BUGS) && !switch_core_media_bug_test_flag(bp, SMBF_NO_PAUSE)) {
                continue;
            }

            if (!switch_channel_test_flag(session->channel, CF_ANSWERED) && switch_core_media_bug_test_flag(bp, SMBF_ANSWER_REQ)) {
                continue;
            }

            if (switch_test_flag(bp, SMBF_PRUNE)) {
                prune++;
                continue;
            }

            if (switch_test_flag(bp, SMBF_WRITE_STREAM)) {
                switch_mutex_lock(bp->write_mutex);
                switch_buffer_write(bp->raw_write_buffer, write_frame->data, write_frame->datalen);
                switch_mutex_unlock(bp->write_mutex);
                
                if (bp->callback) {
                    ok = bp->callback(bp, bp->user_data, SWITCH_ABC_TYPE_WRITE);
                }
            }

            if (switch_test_flag(bp, SMBF_WRITE_REPLACE)) {
                do_bugs = 0;
                if (bp->callback) {
                    bp->write_replace_frame_in = write_frame;
                    bp->write_replace_frame_out = write_frame;
                    if ((ok = bp->callback(bp, bp->user_data, SWITCH_ABC_TYPE_WRITE_REPLACE)) == SWITCH_TRUE) {
                        write_frame = bp->write_replace_frame_out;
                    }
                }
            }

            if (bp->stop_time && bp->stop_time <= switch_epoch_time_now(NULL)) {
                ok = SWITCH_FALSE;
            }


            if (ok == SWITCH_FALSE) {
                switch_set_flag(bp, SMBF_PRUNE);
                prune++;
            }
        }
        switch_thread_rwlock_unlock(session->bug_rwlock);
        if (prune) {
            switch_core_media_bug_prune(session);
        }
    }

    if (do_bugs) {
        do_write = TRUE;
        write_frame = frame;
        goto done;
    }

    if (session->write_codec) {
        if (!ptime_mismatch && write_frame->codec && write_frame->codec->implementation &&
            write_frame->codec->implementation->decoded_bytes_per_packet == session->write_impl.decoded_bytes_per_packet) {
            perfect = TRUE;
        }



        if (perfect) {

            if (write_frame->datalen < session->write_impl.decoded_bytes_per_packet) {
                memset(write_frame->data, 255, session->write_impl.decoded_bytes_per_packet - write_frame->datalen);
                write_frame->datalen = session->write_impl.decoded_bytes_per_packet;
            }

            enc_frame = write_frame;
            session->enc_write_frame.datalen = session->enc_write_frame.buflen;
            session->write_codec->cur_frame = frame;
            frame->codec->cur_frame = frame;
            status = switch_core_codec_encode(session->write_codec,
                                              frame->codec,
                                              enc_frame->data,
                                              enc_frame->datalen,
                                              session->write_impl.actual_samples_per_second,
                                              session->enc_write_frame.data, &session->enc_write_frame.datalen, &session->enc_write_frame.rate, &flag);

            session->write_codec->cur_frame = NULL;
            frame->codec->cur_frame = NULL;
            switch (status) {
            case SWITCH_STATUS_RESAMPLE:
                resample++;
                /* switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Fixme 2\n"); */
            case SWITCH_STATUS_SUCCESS:
                session->enc_write_frame.codec = session->write_codec;
                session->enc_write_frame.samples = enc_frame->datalen / sizeof(int16_t);
                if (frame->codec->implementation->samples_per_packet != session->write_impl.samples_per_packet) {
                    session->enc_write_frame.timestamp = 0;
                } else {
                    session->enc_write_frame.timestamp = frame->timestamp;
                }
                session->enc_write_frame.payload = session->write_impl.ianacode;
                session->enc_write_frame.m = frame->m;
                session->enc_write_frame.ssrc = frame->ssrc;
                session->enc_write_frame.seq = frame->seq;
                session->enc_write_frame.flags = 0;
                if (!encoder_path) {
                    write_frame = &session->enc_write_frame;
                } else {
                    *ret_enc_frame = &session->enc_write_frame;
                }
                break;
            case SWITCH_STATUS_NOOP:
                enc_frame->codec = session->write_codec;
                enc_frame->samples = enc_frame->datalen / sizeof(int16_t);
                enc_frame->timestamp = frame->timestamp;
                enc_frame->m = frame->m;
                enc_frame->seq = frame->seq;
                enc_frame->ssrc = frame->ssrc;
                enc_frame->payload = enc_frame->codec->implementation->ianacode;
                write_frame = enc_frame;
                status = SWITCH_STATUS_SUCCESS;
                if (encoder_path) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "nothing to do - wrong!\n");
                    *ret_enc_frame = NULL;
                }
                break;
            case SWITCH_STATUS_NOT_INITALIZED:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec init error!\n");
                if (!encoder_path) {
                    write_frame = NULL;
                } else {
                    *ret_enc_frame = NULL;
                }
                goto error;
            default:
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec %s encoder error!\n",
                                  session->read_codec->codec_interface->interface_name);
                if (!encoder_path) {
                    write_frame = NULL;
                } else {
                    *ret_enc_frame = NULL;
                }
                goto error;
            }
            if (flag & SFF_CNG) {
                switch_set_flag(write_frame, SFF_CNG);
            }
            if (before_flags & SFF_IVR_FRAME) {
                switch_set_flag(write_frame, SFF_IVR_FRAME);
            }
            /* this is the path taken by IVR frames */
            if (write_frame->flags != before_flags) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s (wr)flags don't match 0x%x != 0x%x\n", 
                                  switch_channel_get_name(session->channel), before_flags, write_frame->flags);
            }
            if (!encoder_path) { status = perform_write(session, write_frame, flags, stream_id); }
            goto error;
        } else if (!encoder_path) {
            if (!session->raw_write_buffer) {
                switch_size_t bytes_per_packet = session->write_impl.decoded_bytes_per_packet;
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
                                  "Engaging Write Buffer at %u bytes to accommodate %u->%u\n",
                                  (uint32_t) bytes_per_packet, write_frame->datalen, session->write_impl.decoded_bytes_per_packet);
                if ((status = switch_buffer_create_dynamic(&session->raw_write_buffer,
                                                           bytes_per_packet * SWITCH_BUFFER_BLOCK_FRAMES,
                                                           bytes_per_packet * SWITCH_BUFFER_START_FRAMES, 0)) != SWITCH_STATUS_SUCCESS) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Write Buffer Failed!\n");
                    goto error;
                }

                /* Need to retrain the recording data */
                switch_core_media_bug_flush_all(session);
            }

            if (!(switch_buffer_write(session->raw_write_buffer, write_frame->data, write_frame->datalen))) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Write Buffer %u bytes Failed!\n", write_frame->datalen);
                status = SWITCH_STATUS_MEMERR;
                goto error;
            }

            status = SWITCH_STATUS_SUCCESS;

            while (switch_buffer_inuse(session->raw_write_buffer) >= session->write_impl.decoded_bytes_per_packet) {
                int rate;

                if (switch_channel_down(session->channel) || !session->raw_write_buffer) {
                    goto error;
                }
                if ((session->raw_write_frame.datalen = (uint32_t)
                     switch_buffer_read(session->raw_write_buffer, session->raw_write_frame.data, session->write_impl.decoded_bytes_per_packet)) == 0) {
                    goto error;
                }

                enc_frame = &session->raw_write_frame;
                session->raw_write_frame.rate = session->write_impl.actual_samples_per_second;
                session->enc_write_frame.datalen = session->enc_write_frame.buflen;
                session->enc_write_frame.timestamp = 0;


                if (frame->codec && frame->codec->implementation && switch_core_codec_ready(frame->codec)) {
                    rate = frame->codec->implementation->actual_samples_per_second;
                } else {
                    rate = session->write_impl.actual_samples_per_second;
                }

                session->write_codec->cur_frame = frame;
                frame->codec->cur_frame = frame;
                status = switch_core_codec_encode(session->write_codec,
                                                  frame->codec,
                                                  enc_frame->data,
                                                  enc_frame->datalen,
                                                  rate,
                                                  session->enc_write_frame.data, &session->enc_write_frame.datalen, &session->enc_write_frame.rate, &flag);

                session->write_codec->cur_frame = NULL;
                frame->codec->cur_frame = NULL;
                switch (status) {
                case SWITCH_STATUS_RESAMPLE:
                    resample++;
                    session->enc_write_frame.codec = session->write_codec;
                    session->enc_write_frame.samples = enc_frame->datalen / sizeof(int16_t);
                    session->enc_write_frame.m = frame->m;
                    session->enc_write_frame.ssrc = frame->ssrc;
                    session->enc_write_frame.payload = session->write_impl.ianacode;
                    write_frame = &session->enc_write_frame;
                    if (!session->write_resampler) {
                        switch_mutex_lock(session->resample_mutex);
                        if (!session->write_resampler) {
                            status = switch_resample_create(&session->write_resampler,
                                                            frame->codec->implementation->actual_samples_per_second,
                                                            session->write_impl.actual_samples_per_second,
                                                            session->write_impl.decoded_bytes_per_packet, SWITCH_RESAMPLE_QUALITY, 1);
                        }
                        switch_mutex_unlock(session->resample_mutex);



                        if (status != SWITCH_STATUS_SUCCESS) {
                            goto done;
                        } else {
                            switch_core_session_message_t msg = { 0 };
                            msg.numeric_arg = 1;
                            msg.message_id = SWITCH_MESSAGE_RESAMPLE_EVENT;
                            switch_core_session_receive_message(session, &msg);
                            

                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "Activating write resampler\n");
                        }
                    }
                    break;
                case SWITCH_STATUS_SUCCESS:
                    session->enc_write_frame.codec = session->write_codec;
                    session->enc_write_frame.samples = enc_frame->datalen / sizeof(int16_t);
                    session->enc_write_frame.m = frame->m;
                    session->enc_write_frame.ssrc = frame->ssrc;
                    session->enc_write_frame.payload = session->write_impl.ianacode;
                    session->enc_write_frame.flags = 0;
                    write_frame = &session->enc_write_frame;
                    break;
                case SWITCH_STATUS_NOOP:
                    if (session->write_resampler) {
                        switch_core_session_message_t msg = { 0 };
                        int ok = 0;

                        switch_mutex_lock(session->resample_mutex);
                        if (session->write_resampler) {                 
                            switch_resample_destroy(&session->write_resampler);
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "Deactivating write resampler\n");
                            ok = 1;
                        }
                        switch_mutex_unlock(session->resample_mutex);

                        if (ok) {
                            msg.numeric_arg = 0;
                            msg.message_id = SWITCH_MESSAGE_RESAMPLE_EVENT;
                            switch_core_session_receive_message(session, &msg);
                        }

                    }
                    enc_frame->codec = session->write_codec;
                    enc_frame->samples = enc_frame->datalen / sizeof(int16_t);
                    enc_frame->m = frame->m;
                    enc_frame->ssrc = frame->ssrc;
                    enc_frame->payload = enc_frame->codec->implementation->ianacode;
                    write_frame = enc_frame;
                    status = SWITCH_STATUS_SUCCESS;
                    break;
                case SWITCH_STATUS_NOT_INITALIZED:
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec init error!\n");
                    write_frame = NULL;
                    goto error;
                default:
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Codec %s encoder error %d!\n",
                                      session->read_codec->codec_interface->interface_name, status);
                    write_frame = NULL;
                    goto error;
                }

                if (!did_write_resample && session->read_resampler) {
                    short *data = write_frame->data;
                    switch_mutex_lock(session->resample_mutex);
                    if (session->read_resampler) {
                        switch_resample_process(session->read_resampler, data, write_frame->datalen / 2);
                        memcpy(data, session->read_resampler->to, session->read_resampler->to_len * 2);
                        write_frame->samples = session->read_resampler->to_len;
                        write_frame->datalen = session->read_resampler->to_len * 2;
                        write_frame->rate = session->read_resampler->to_rate;
                    }
                    switch_mutex_unlock(session->resample_mutex);

                }

                if (flag & SFF_CNG) {
                    switch_set_flag(write_frame, SFF_CNG);
                }

                if (ptime_mismatch || resample) {
                    write_frame->timestamp = 0;
                }

                if (write_frame->flags != before_flags) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s (wr)flags don't match 0x%x != 0x%x\n", 
                                      switch_channel_get_name(session->channel), before_flags, write_frame->flags);
                }
                if ((status = perform_write(session, write_frame, flags, stream_id)) != SWITCH_STATUS_SUCCESS) {
                    break;
                }

            }

            goto error;
        }
    }





  done:

    if (ptime_mismatch || resample) {
        write_frame->timestamp = 0;
    }

    if (do_write) {
        if (write_frame->flags != before_flags) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s (wr)flags don't match 0x%x != 0x%x\n", 
                              switch_channel_get_name(session->channel), before_flags, write_frame->flags);
        }
        if (!encoder_path) { status = perform_write(session, write_frame, flags, stream_id); }
    }

  error:
    switch_mutex_unlock(frame->codec->mutex);
    switch_mutex_unlock(session->write_codec->mutex);
    switch_mutex_unlock(session->codec_write_mutex);

    return status;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_enc_frame(switch_core_session_t *session, switch_frame_t *frame,
                                                              switch_io_flag_t flags, int stream_id,
                                                              switch_frame_t **ret_enc_frame)
{
    return switch_core_session_write_frame_core(session, frame, flags, stream_id, ret_enc_frame);
}

SWITCH_DECLARE(switch_status_t) switch_core_session_write_enc_frame(switch_core_session_t *session, switch_frame_t *frame,
                                                                    switch_io_flag_t flags, int stream_id, switch_time_t *timed)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_frame_t *enc_frame = frame;
    switch_frame_t *write_frame = enc_frame;
    switch_mutex_lock(session->codec_write_mutex);
    switch_mutex_lock(session->write_codec->mutex);
    /* switch_mutex_lock(frame->codec->mutex); */
    status = perform_write_timed(session, write_frame, flags, stream_id, timed);
    /* switch_mutex_unlock(frame->codec->mutex); */
    switch_mutex_unlock(session->write_codec->mutex);
    switch_mutex_unlock(session->codec_write_mutex);
    return status;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_write_frame(switch_core_session_t *session, switch_frame_t *frame,
                                                                switch_io_flag_t flags, int stream_id)
{
    return switch_core_session_write_frame_core(session, frame, flags, stream_id, NULL);
}

static char *SIG_NAMES[] = {
    "NONE",
    "KILL",
    "XFER",
    "BREAK",
    NULL
};

SWITCH_DECLARE(switch_status_t) switch_core_session_perform_kill_channel(switch_core_session_t *session,
                                                                         const char *file, const char *func, int line, switch_signal_t sig)
{
    switch_io_event_hook_kill_channel_t *ptr;
    switch_status_t status = SWITCH_STATUS_FALSE;

    switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, func, line, switch_core_session_get_uuid(session), SWITCH_LOG_DEBUG, "Send signal %s [%s]\n",
                      switch_channel_get_name(session->channel), SIG_NAMES[sig]);

    if (session->endpoint_interface->io_routines->kill_channel) {
        if ((status = session->endpoint_interface->io_routines->kill_channel(session, sig)) == SWITCH_STATUS_SUCCESS) {
            for (ptr = session->event_hooks.kill_channel; ptr; ptr = ptr->next) {
                if ((status = ptr->kill_channel(session, sig)) != SWITCH_STATUS_SUCCESS) {
                    break;
                }
            }
        }
    }
    return status;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_recv_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf)
{
    switch_io_event_hook_recv_dtmf_t *ptr;
    switch_status_t status;
    switch_dtmf_t new_dtmf;
    int fed = 0;
    
    if (switch_channel_down(session->channel)) {
        return SWITCH_STATUS_FALSE;
    }

    if (switch_test_flag(dtmf, DTMF_FLAG_SENSITIVE)) {  
        return SWITCH_STATUS_SUCCESS;
    }

    switch_assert(dtmf);

    new_dtmf = *dtmf;

    if (new_dtmf.duration > switch_core_max_dtmf_duration(0)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG1, "%s EXCESSIVE DTMF DIGIT [%c] LEN [%d]\n",
                          switch_channel_get_name(session->channel), new_dtmf.digit, new_dtmf.duration);
        new_dtmf.duration = switch_core_max_dtmf_duration(0);
    } else if (new_dtmf.duration < switch_core_min_dtmf_duration(0)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG1, "%s SHORT DTMF DIGIT [%c] LEN [%d]\n",
                          switch_channel_get_name(session->channel), new_dtmf.digit, new_dtmf.duration);
        new_dtmf.duration = switch_core_min_dtmf_duration(0);
    } else if (!new_dtmf.duration) {
        new_dtmf.duration = switch_core_default_dtmf_duration(0);
    }
    
    if (!switch_test_flag(dtmf, DTMF_FLAG_SKIP_PROCESS)) {
        if (session->dmachine[0]) {
            char str[2] = { dtmf->digit, '\0' };
            switch_ivr_dmachine_feed(session->dmachine[0], str, NULL);
            fed = 1;
        }

        for (ptr = session->event_hooks.recv_dtmf; ptr; ptr = ptr->next) {
            if ((status = ptr->recv_dtmf(session, &new_dtmf, SWITCH_DTMF_RECV)) != SWITCH_STATUS_SUCCESS) {
                return status;
            }
        }
    }

    return fed ? SWITCH_STATUS_FALSE : SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_send_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf)
{
    switch_io_event_hook_send_dtmf_t *ptr;
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_dtmf_t new_dtmf;

    if (switch_channel_down(session->channel)) {
        return SWITCH_STATUS_FALSE;
    }

    if (switch_test_flag(dtmf, DTMF_FLAG_SENSITIVE)) {  
        return SWITCH_STATUS_SUCCESS;
    }

    if (switch_channel_test_flag(session->channel, CF_DROP_DTMF)) {
        const char *file = switch_channel_get_variable_dup(session->channel, "drop_dtmf_masking_file", SWITCH_FALSE, -1);

        if (!zstr(file)) {
            switch_ivr_broadcast(switch_core_session_get_uuid(session), file, SMF_ECHO_ALEG);
        }
        return SWITCH_STATUS_SUCCESS;
    }

    switch_assert(dtmf);

    new_dtmf = *dtmf;
    
    if (new_dtmf.digit != 'w' && new_dtmf.digit != 'W') {
        if (new_dtmf.duration > switch_core_max_dtmf_duration(0)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "%s EXCESSIVE DTMF DIGIT [%c] LEN [%d]\n",
                              switch_channel_get_name(session->channel), new_dtmf.digit, new_dtmf.duration);
            new_dtmf.duration = switch_core_max_dtmf_duration(0);
        } else if (new_dtmf.duration < switch_core_min_dtmf_duration(0)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "%s SHORT DTMF DIGIT [%c] LEN [%d]\n",
                          switch_channel_get_name(session->channel), new_dtmf.digit, new_dtmf.duration);
            new_dtmf.duration = switch_core_min_dtmf_duration(0);
        } 
    }

    if (!new_dtmf.duration) {
        new_dtmf.duration = switch_core_default_dtmf_duration(0);
    }

    if (!switch_test_flag(dtmf, DTMF_FLAG_SKIP_PROCESS)) {  
        for (ptr = session->event_hooks.send_dtmf; ptr; ptr = ptr->next) {
            if ((status = ptr->send_dtmf(session, dtmf, SWITCH_DTMF_SEND)) != SWITCH_STATUS_SUCCESS) {
                return SWITCH_STATUS_SUCCESS;
            }
        }
        if (session->dmachine[1]) {
            char str[2] = { new_dtmf.digit, '\0' };
            switch_ivr_dmachine_feed(session->dmachine[1], str, NULL);
            return SWITCH_STATUS_SUCCESS;
        }
    }


    if (session->endpoint_interface->io_routines->send_dtmf) {
        int send = 0;
        status = SWITCH_STATUS_SUCCESS;
        
        if (switch_channel_test_cap(session->channel, CC_QUEUEABLE_DTMF_DELAY) && (dtmf->digit == 'w' || dtmf->digit == 'W')) {
            send = 1;
        } else {
            if (dtmf->digit == 'w') {
                switch_yield(500000);
            } else if (dtmf->digit == 'W') {
                switch_yield(1000000);
            } else {
                send = 1;
            }
        }

        if (send) {
            status = session->endpoint_interface->io_routines->send_dtmf(session, &new_dtmf);
        }
    }
    return status;
}

SWITCH_DECLARE(switch_status_t) switch_core_session_send_dtmf_string(switch_core_session_t *session, const char *dtmf_string)
{
    char *p;
    switch_dtmf_t dtmf = { 0, switch_core_default_dtmf_duration(0), DTMF_FLAG_SKIP_PROCESS, 0};
    int sent = 0, dur;
    char *string;
    int i, argc;
    char *argv[256];
    int dur_total = 0;

    switch_assert(session != NULL);

    if (zstr(dtmf_string)) {
        return SWITCH_STATUS_FALSE;
    }

    if (*dtmf_string == '~') {
        dtmf_string++;
        dtmf.flags = 0;
    }

    if (switch_channel_down(session->channel)) {
        return SWITCH_STATUS_FALSE;
    }


    if (strlen(dtmf_string) > 99) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Attempt to send very large dtmf string ignored!\n");
        return SWITCH_STATUS_FALSE;
    }

    string = switch_core_session_strdup(session, dtmf_string);
    argc = switch_separate_string(string, '+', argv, (sizeof(argv) / sizeof(argv[0])));

    if (argc) {
        switch_channel_pre_answer(session->channel);
    }

    for (i = 0; i < argc; i++) {
        dtmf.duration = switch_core_default_dtmf_duration(0);
        dur = switch_core_default_dtmf_duration(0) / 8;
        if ((p = strchr(argv[i], '@'))) {
            *p++ = '\0';
            if ((dur = atoi(p)) > (int)switch_core_min_dtmf_duration(0) / 8) {
                dtmf.duration = dur * 8;
            }
        }


        for (p = argv[i]; p && *p; p++) {
            if (is_dtmf(*p)) {
                dtmf.digit = *p;

                if (dtmf.digit != 'w' && dtmf.digit != 'W') {
                    if (dtmf.duration > switch_core_max_dtmf_duration(0)) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "%s EXCESSIVE DTMF DIGIT [%c] LEN [%d]\n",
                                          switch_channel_get_name(session->channel), dtmf.digit, dtmf.duration);
                        dtmf.duration = switch_core_max_dtmf_duration(0);
                    } else if (dtmf.duration < switch_core_min_dtmf_duration(0)) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "%s SHORT DTMF DIGIT [%c] LEN [%d]\n",
                                          switch_channel_get_name(session->channel), dtmf.digit, dtmf.duration);
                        dtmf.duration = switch_core_min_dtmf_duration(0);
                    } 
                }

                if (!dtmf.duration) {
                    dtmf.duration = switch_core_default_dtmf_duration(0);
                }
                

                if (switch_core_session_send_dtmf(session, &dtmf) == SWITCH_STATUS_SUCCESS) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s send dtmf\ndigit=%c ms=%u samples=%u\n",
                                      switch_channel_get_name(session->channel), dtmf.digit, dur, dtmf.duration);
                    sent++;
                    dur_total += dtmf.duration + 2000;  /* account for 250ms pause */
                }
            }
        }

        if (dur_total) {
            char tmp[32] = "";
            switch_snprintf(tmp, sizeof(tmp), "%d", dur_total / 8);
            switch_channel_set_variable(session->channel, "last_dtmf_duration", tmp);
        }

    }
    return sent ? SWITCH_STATUS_SUCCESS : SWITCH_STATUS_FALSE;
}

SWITCH_DECLARE(void) switch_core_log_periodic(switch_core_session_t *session, switch_bool_t force, switch_bool_t flush)
{
    switch_channel_t *channel;
    
    channel = switch_core_session_get_channel(session);
    if (!channel) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "NULL channel. Can't report periodic stats.\n");
        return;
    }
    switch_channel_publish_call_events(channel, force, flush);  
}


SWITCH_DECLARE(void) switch_core_set_log_filter_cb(switch_core_session_t *session, log_check_t log_check)
{
    if (session)
        session->log_check = log_check;
}

SWITCH_DECLARE(switch_status_t) switch_core_ioctl_stats(switch_core_session_t *session, int cmd, void *arg)
{
    if (session && session->endpoint_interface && session->endpoint_interface->stats_ioctl)
        return session->endpoint_interface->stats_ioctl(session, cmd, arg); 

    return SWITCH_STATUS_FALSE;
}

typedef struct switch_conference_encoder_state conference_encoder_state_t;

SWITCH_DECLARE(conference_encoder_state_t *) switch_core_conference_encode_alloc(switch_memory_pool_t *pool)
{
    return switch_core_alloc(pool, sizeof(conference_encoder_state_t));
}

SWITCH_DECLARE(switch_status_t) switch_core_conference_encode_init(conference_encoder_state_t *encoder_state, switch_codec_t *write_codec, switch_memory_pool_t *pool, int loss)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    encoder_state->raw_write_frame.data = encoder_state->raw_write_buf;
    encoder_state->raw_write_frame.buflen = sizeof(encoder_state->raw_write_buf);

    encoder_state->enc_write_frame.data = encoder_state->enc_write_buf;
    encoder_state->enc_write_frame.buflen = sizeof(encoder_state->enc_write_buf);

    encoder_state->raw_write_buffer = NULL;
    encoder_state->write_resampler = NULL;

    switch_core_codec_copy(write_codec, &encoder_state->write_codec, pool);
    encoder_state->write_impl = encoder_state->write_codec.implementation;

    switch_core_codec_reset(&encoder_state->write_codec);
    if (loss > 0) {
        switch_core_ctl(&encoder_state->write_codec, 1, &loss);
    }

    return status;
}

SWITCH_DECLARE(void) switch_core_conference_encode_destroy(conference_encoder_state_t *encoder_state)
{
    if (encoder_state->write_resampler) {
        switch_resample_destroy(&encoder_state->write_resampler);
    }
    if (encoder_state->raw_write_buffer) {
        switch_buffer_destroy(&encoder_state->raw_write_buffer);
    }
    switch_core_codec_destroy(&encoder_state->write_codec);
}

//#define TRACE_ENCODE

SWITCH_DECLARE(switch_status_t) switch_core_conference_encode_frame(conference_encoder_state_t *encoder_state, switch_frame_t *frame,
                                                                    switch_io_flag_t flags, switch_frame_t **ret_enc_frame)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_frame_t *enc_frame = NULL, *write_frame = frame;
    unsigned int flag = 0, do_resample = 0, resample = 0;
    switch_frame_flag_t before_flags = frame->flags;
#ifdef TRACE_ENCODE
    char debug_path[1024];
    char tmp[128];
    memset(debug_path, 0, 1024);
#endif

    switch_assert(frame != NULL);

    if (frame->codec == NULL || frame->codec->implementation == NULL) {
#ifdef TRACE_ENCODE
        strncat(debug_path, "no_frame_codec,", 1024);
#endif
        goto done;
    }

    switch_assert(frame->codec != NULL);
    switch_assert(frame->codec->implementation != NULL);

#ifdef TRACE_ENCODE
    switch_snprintf(debug_path, sizeof(debug_path), "(%s,%d,%d)->(%s,%d),",
                    frame->codec->implementation->iananame, frame->datalen, frame->codec->implementation->actual_samples_per_second,
                    encoder_state->write_impl->iananame, encoder_state->write_impl->actual_samples_per_second);
#endif

    if (frame->codec->implementation->actual_samples_per_second != encoder_state->write_impl->actual_samples_per_second) {
        do_resample = TRUE;
#ifdef TRACE_ENCODE
        strncat(debug_path, "resample,", 1024);
#endif
    }

    encoder_state->raw_write_frame.datalen = encoder_state->raw_write_frame.buflen;
    frame->codec->cur_frame = frame;
    encoder_state->write_codec.cur_frame = frame;
    status = switch_core_codec_decode(frame->codec,
                                      &encoder_state->write_codec,
                                      frame->data,
                                      frame->datalen,
                                      encoder_state->write_impl->actual_samples_per_second,
                                      encoder_state->raw_write_frame.data,
                                      &encoder_state->raw_write_frame.datalen,
                                      &encoder_state->raw_write_frame.rate,
                                      &frame->flags);
    frame->codec->cur_frame = NULL;
    encoder_state->write_codec.cur_frame = NULL;
    if (do_resample && status == SWITCH_STATUS_SUCCESS) {
        status = SWITCH_STATUS_RESAMPLE;
    }

#ifdef TRACE_ENCODE
    switch_snprintf(tmp, 128, "ret:%d,", status);
    strncat(debug_path, tmp, 1023);
#endif

    switch (status) {
    case SWITCH_STATUS_RESAMPLE:
        resample++;
        write_frame = &encoder_state->raw_write_frame;
        write_frame->rate = frame->codec->implementation->actual_samples_per_second;
        if (!encoder_state->write_resampler) {
#ifdef TRACE_ENCODE
            strncat(debug_path, "resample_create,", 1024);
#endif
            status = switch_resample_create(&encoder_state->write_resampler,
                                            frame->codec->implementation->actual_samples_per_second,
                                            encoder_state->write_impl->actual_samples_per_second,
                                            encoder_state->write_impl->decoded_bytes_per_packet,
                                            SWITCH_RESAMPLE_QUALITY, 1);
            if (status != SWITCH_STATUS_SUCCESS) {
                goto done;
            }
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Activating write resampler\n");
        }
        break;
    case SWITCH_STATUS_SUCCESS:
#ifdef TRACE_ENCODE
        strncat(debug_path, "decode_success,", 1024);
#endif
        encoder_state->raw_write_frame.samples = encoder_state->raw_write_frame.datalen / sizeof(int16_t);
        encoder_state->raw_write_frame.timestamp = frame->timestamp;
        encoder_state->raw_write_frame.rate = frame->rate;
        encoder_state->raw_write_frame.m = frame->m;
        encoder_state->raw_write_frame.ssrc = frame->ssrc;
        encoder_state->raw_write_frame.seq = frame->seq;
        encoder_state->raw_write_frame.payload = frame->payload;
        encoder_state->raw_write_frame.flags = 0;
        write_frame = &encoder_state->raw_write_frame;
        break;
    case SWITCH_STATUS_BREAK:
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "status == break!\n");
        status = SWITCH_STATUS_SUCCESS;
        goto error;
    case SWITCH_STATUS_NOOP:
        if (encoder_state->write_resampler) {
            switch_resample_destroy(&encoder_state->write_resampler);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Deactivating write resampler\n");
        }
        write_frame = frame;
        status = SWITCH_STATUS_SUCCESS;
        break;
    default:
        if (status == SWITCH_STATUS_NOT_INITALIZED) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Codec init error!\n");
            goto error;
        }
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Codec %s decoder error!\n",
                          frame->codec->codec_interface->interface_name);
        goto error;
    }

    if (encoder_state->write_resampler) {
        short *data = write_frame->data;
        if (encoder_state->write_resampler) {
#ifdef TRACE_ENCODE
            strncat(debug_path, "resampling,", 1024);
#endif
            switch_resample_process(encoder_state->write_resampler, data, write_frame->datalen / 2);
            memcpy(data, encoder_state->write_resampler->to, encoder_state->write_resampler->to_len * 2);
            write_frame->samples = encoder_state->write_resampler->to_len;
            write_frame->datalen = write_frame->samples * 2;
            write_frame->rate = encoder_state->write_resampler->to_rate;
        }
    }

    if (write_frame->datalen < encoder_state->write_impl->decoded_bytes_per_packet) {
#ifdef TRACE_ENCODE
        switch_snprintf(tmp, 128, "change_datalen:%d->%d,", write_frame->datalen, (encoder_state->write_impl->decoded_bytes_per_packet));
        strncat(debug_path, tmp, 1023);
#endif
        memset(write_frame->data, 255, encoder_state->write_impl->decoded_bytes_per_packet - write_frame->datalen);
        write_frame->datalen = encoder_state->write_impl->decoded_bytes_per_packet;
    }

    enc_frame = write_frame;
    encoder_state->enc_write_frame.datalen = encoder_state->enc_write_frame.buflen;
    encoder_state->write_codec.cur_frame = frame;
    frame->codec->cur_frame = frame;
    status = switch_core_codec_encode(&encoder_state->write_codec,
                                      frame->codec,
                                      enc_frame->data,
                                      enc_frame->datalen,
                                      encoder_state->write_impl->actual_samples_per_second,
                                      encoder_state->enc_write_frame.data,
                                      &encoder_state->enc_write_frame.datalen,
                                      &encoder_state->enc_write_frame.rate,
                                      &flag);
#ifdef TRACE_ENCODE
    switch_snprintf(tmp, 128, "encode:(%d,%d)->(%d,%d)=%d,",
                    enc_frame->datalen, encoder_state->write_impl->actual_samples_per_second,
                    encoder_state->enc_write_frame.datalen, encoder_state->enc_write_frame.rate,
                    status);
    strncat(debug_path, tmp, 1023);
#endif

    encoder_state->write_codec.cur_frame = NULL;
    frame->codec->cur_frame = NULL;
    switch (status) {
    case SWITCH_STATUS_RESAMPLE:
        resample++;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "status == resample!\n");
        break;
    case SWITCH_STATUS_SUCCESS:
        encoder_state->enc_write_frame.codec = &encoder_state->write_codec;
        encoder_state->enc_write_frame.samples = enc_frame->datalen / sizeof(int16_t);
        encoder_state->enc_write_frame.payload = encoder_state->write_impl->ianacode;
        enc_frame->timestamp = 0;
        encoder_state->enc_write_frame.m = 0;
        encoder_state->enc_write_frame.ssrc = 0;
        encoder_state->enc_write_frame.seq = 0;
        encoder_state->enc_write_frame.flags = 0;
        *ret_enc_frame = &encoder_state->enc_write_frame;
        break;
    case SWITCH_STATUS_NOOP:
        enc_frame->codec = &encoder_state->write_codec;
        enc_frame->samples = enc_frame->datalen / sizeof(int16_t);
        enc_frame->timestamp = 0;
        enc_frame->m = 0;
        enc_frame->seq = frame->seq;
        enc_frame->ssrc = frame->ssrc;
        enc_frame->payload = enc_frame->codec->implementation->ianacode;
        write_frame = enc_frame;
        status = SWITCH_STATUS_SUCCESS;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "nothing to do - wrong!\n");
        *ret_enc_frame = NULL;
        break;
    case SWITCH_STATUS_NOT_INITALIZED:
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Codec init error!\n");
        *ret_enc_frame = NULL;
        goto error;
    default:
        *ret_enc_frame = NULL;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "status == default!\n");
        goto error;
    }
    if (before_flags & SFF_IVR_FRAME) {
        switch_set_flag(write_frame, SFF_IVR_FRAME);
    }

 done:
    /* nothing */
 error:
    /* nothing */

#ifdef TRACE_ENCODE
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s\n", debug_path);
#endif

    return status;
}


SWITCH_DECLARE(switch_status_t) switch_core_session_send_conference_frame(switch_core_session_t *session, switch_frame_t *frame,
                                                                          switch_io_flag_t flags, int stream_id, switch_time_t *timed)
{
    return perform_write_timed(session, frame, flags, stream_id, timed);
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
