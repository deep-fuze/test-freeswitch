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
 * Brian K. West <brian@freeswitch.org>
 * Noel Morgan <noel@vwci.com>
 *
 * mod_opus.c -- The OPUS ultra-low delay audio codec (http://www.opus-codec.org/)
 *
 */

#include "switch.h"
#include "opus.h"


SWITCH_MODULE_LOAD_FUNCTION(mod_opus_load);
SWITCH_MODULE_DEFINITION(mod_opus, mod_opus_load, NULL, NULL);

#define SWITCH_OPUS_MIN_BITRATE 6000
#define SWITCH_OPUS_MAX_BITRATE 510000
#define FUZE_OPUS_MAX_BITRATE 64000
#define SWITCH_OPUS_MIN_FEC_BITRATE 12400

/*! \brief Various codec settings */
struct opus_codec_settings {
    int useinbandfec;
    int usedtx;
    int maxaveragebitrate;
    int maxplaybackrate;
    int stereo;
    int cbr;
    int sprop_maxcapturerate;
    int sprop_stereo;
    int maxptime;
    int minptime;
    int ptime;
    int samplerate;
};
typedef struct opus_codec_settings opus_codec_settings_t;

static opus_codec_settings_t default_codec_settings = {
    /*.useinbandfec */ 1,
    /*.usedtx */ 0,
    /*.maxaveragebitrate */ FUZE_OPUS_MAX_BITRATE,
    /*.maxplaybackrate */ 48000,
    /*.stereo*/ 0,
    /*.cbr*/ 0,
    /*.sprop_maxcapturerate*/ 0,
    /*.sprop_stereo*/ 0,
    /*.maxptime*/ 0,
    /*.minptime*/ 0,
    /*.ptime*/ 0,
    /*.samplerate*/ 0
};

struct dec_stats {
    uint32_t fec_counter;
    uint32_t plc_counter;
    uint32_t frame_counter;
};
typedef struct dec_stats dec_stats_t;

struct enc_stats {
    uint32_t frame_counter;
    uint32_t encoded_bytes;
    uint32_t encoded_msec;
    uint32_t fec_counter;
};
typedef struct enc_stats enc_stats_t;

struct codec_control_state {
    int keep_fec;
    opus_int32 current_bitrate;
    opus_int32 wanted_bitrate;
    uint32_t increase_step;
    uint32_t decrease_step;
};
typedef struct codec_control_state codec_control_state_t;

#define NAME_LEN 128

struct saved_debug_state {
    opus_int32 inbandfec, bitrate, loss, bandwidth;
    int nb_samples, nb_opus_frames;
    char audiobandwidth_str[32];
    char has_fec;
    switch_time_t last;
    int audiobandwidth;
};
typedef struct saved_debug_state saved_debug_state_t;

struct opus_context {
    OpusEncoder *encoder_object;
    OpusDecoder *decoder_object;
    uint32_t enc_frame_size;
    uint32_t dec_frame_size;
    uint32_t old_plpct;
    uint32_t debug;
    opus_codec_settings_t codec_settings;
    int look_check;
    int look_ts;
    int complexity;
    dec_stats_t decoder_stats;
    enc_stats_t encoder_stats;
    codec_control_state_t control_state;
    char name[NAME_LEN];
    saved_debug_state_t debug_state;
    int channels;
};

struct {
    int use_vbr;
    int use_dtx;
    int complexity;
    int maxaveragebitrate;
    int maxplaybackrate;
    int sprop_maxcapturerate;
    int plpct;
    int asymmetric_samplerates;
    int bitrate_negotiation;
    int keep_fec;
    int fec_decode;
    int adjust_bitrate;
    int debuginfo;
    switch_mutex_t *mutex;
} opus_prefs;

static struct {
    int debug;
} globals;

static uint32_t switch_opus_encoder_set_audio_bandwidth(OpusEncoder *encoder_object,int enc_samplerate)
{
    if (enc_samplerate == 8000) { /* Audio Bandwidth: 0-4000Hz  Sampling Rate: 8000Hz */
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_opus_encoder_set_audio_bandwidth NB %d\n", enc_samplerate);
        opus_encoder_ctl(encoder_object, OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
        opus_encoder_ctl(encoder_object, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
        opus_encoder_ctl(encoder_object, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
        return OPUS_BANDWIDTH_NARROWBAND;
    } else if (enc_samplerate == 12000) { /* Audio Bandwidth: 0-6000Hz  Sampling Rate: 12000Hz */
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_opus_encoder_set_audio_bandwidth NB %d\n", enc_samplerate);
        opus_encoder_ctl(encoder_object, OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_MEDIUMBAND));
        opus_encoder_ctl(encoder_object, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_MEDIUMBAND));
        opus_encoder_ctl(encoder_object, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
        return OPUS_BANDWIDTH_MEDIUMBAND;
    } else if (enc_samplerate == 16000) { /* Audio Bandwidth: 0-8000Hz  Sampling Rate: 16000Hz */
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_opus_encoder_set_audio_bandwidth WB %d\n", enc_samplerate);
        opus_encoder_ctl(encoder_object, OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
        opus_encoder_ctl(encoder_object, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
        opus_encoder_ctl(encoder_object, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
        return OPUS_BANDWIDTH_WIDEBAND;
    } else if (enc_samplerate == 24000) {  /* Audio Bandwidth: 0-12000Hz Sampling Rate: 24000Hz */
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_opus_encoder_set_audio_bandwidth SWB %d\n", enc_samplerate);
        opus_encoder_ctl(encoder_object, OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_SUPERWIDEBAND));
        opus_encoder_ctl(encoder_object, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_SUPERWIDEBAND));
        opus_encoder_ctl(encoder_object, OPUS_SET_SIGNAL(OPUS_AUTO));
        return OPUS_BANDWIDTH_SUPERWIDEBAND;
    }
    /* Audio Bandwidth: 0-20000Hz Sampling Rate: 48000Hz */
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_opus_encoder_set_audio_bandwidth AUTO %d\n", enc_samplerate);
    opus_encoder_ctl(encoder_object, OPUS_SET_BANDWIDTH(OPUS_AUTO));
    opus_encoder_ctl(encoder_object, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND));
    opus_encoder_ctl(encoder_object, OPUS_SET_SIGNAL(OPUS_AUTO));
    return OPUS_BANDWIDTH_FULLBAND;
}


/* this is only useful for fs = 8000 hz, the map is only used
 * at the beginning of the call. */
static int switch_opus_get_fec_bitrate(int fs, int loss)
{
    int threshold_bitrates_8k[25] = {
        15600,15200,15200,15200,14800,
        14800,14800,14800,14400,14400,
        14400,14000,14000,14000,13600,
        13600,13600,13600,13200,13200,
        13200,12800,12800,12800,12400
    };

    int threshold_bitrates_16k[25] = {
        20400, 20400, 20000, 20000, 19600,
        19600, 19600, 19200, 19200, 18800,
        18800, 18800, 18400, 18400, 18000,
        18000, 18000, 17600, 17600, 17200,
        17200, 17200, 16800, 16800, 16400
    };

    if (loss <= 0){
        return SWITCH_STATUS_FALSE;
    }

    if (fs == 8000) {
        if (loss >=25) {
            return threshold_bitrates_8k[24];
        } else {
            return threshold_bitrates_8k[loss-1];
        }
    } else if (fs == 16000) {
        if (loss >=25) {
            return threshold_bitrates_16k[24];
        } else {
            return threshold_bitrates_16k[loss-1];
        }
    }

    return SWITCH_STATUS_FALSE;
}

static switch_bool_t switch_opus_acceptable_rate(int rate)
{
    if (rate != 8000 && rate != 12000 && rate != 16000 && rate != 24000 && rate != 48000) {
        return SWITCH_FALSE;
    }
    return SWITCH_TRUE;
}

static switch_status_t switch_opus_fmtp_parse(const char *fmtp, switch_codec_fmtp_t *codec_fmtp)
{
    if (codec_fmtp) {
        opus_codec_settings_t local_settings = { 0 };
        opus_codec_settings_t *codec_settings = &local_settings;
        
        if (codec_fmtp->private_info) {
            codec_settings = codec_fmtp->private_info;
            if (zstr(fmtp)) {
                memcpy(codec_settings, &default_codec_settings, sizeof(*codec_settings));
            }
        }
        
        if (fmtp) {
            int x, argc;
            char *argv[10];
            char *fmtp_dup = strdup(fmtp);
            
            switch_assert(fmtp_dup);
            
            argc = switch_separate_string(fmtp_dup, ';', argv, (sizeof(argv) / sizeof(argv[0])));
            for (x = 0; x < argc; x++) {
                char *data = argv[x];
                char *arg;
                switch_assert(data);
                while (*data == ' ') {
                    data++;
                }
                
                
                if ((arg = strchr(data, '='))) {
                    *arg++ = '\0';
                    
                    if (codec_settings) {
                        if (!strcasecmp(data, "useinbandfec")) {
                            codec_settings->useinbandfec = switch_true(arg);
                        }
                        
                        if (!strcasecmp(data, "usedtx")) {
                            codec_settings->usedtx = switch_true(arg);
                        }

                        if (!strcasecmp(data, "cbr")) {
                            codec_settings->cbr = switch_true(arg);
                        }
                        
                        if (!strcasecmp(data, "sprop-maxcapturerate")) {
                            codec_settings->sprop_maxcapturerate = atoi(arg);
                            if (!switch_opus_acceptable_rate(codec_settings->sprop_maxcapturerate)) {
                                codec_settings->sprop_maxcapturerate = 0; /* value not supported */
                            }
                        }
                        
                        if (!strcasecmp(data, "maxptime")) {
                            codec_settings->maxptime = atoi(arg);
                        }
                        
                        if (!strcasecmp(data, "minptime")) {
                            codec_settings->minptime = atoi(arg);
                        }
                        
                        if (!strcasecmp(data, "ptime")) {
                            codec_settings->ptime = atoi(arg);
                            codec_fmtp->microseconds_per_packet = codec_settings->ptime * 1000;
                        }
                        
                        if (!strcasecmp(data, "samplerate")) {
                            codec_settings->samplerate = atoi(arg);
                            codec_fmtp->actual_samples_per_second = codec_settings->samplerate;
                        }

                        if (!strcasecmp(data, "stereo")) {
                            codec_settings->stereo = atoi(arg);
                            codec_fmtp->stereo = codec_settings->stereo;
                        }

#if 0
                        if (!strcasecmp(data, "sprop-stereo")) {
                            codec_settings->sprop_stereo = atoi(arg);
                        }
#endif
                        if (!strcasecmp(data, "maxaveragebitrate")) {
                            codec_settings->maxaveragebitrate = atoi(arg);
                            if (codec_settings->maxaveragebitrate < SWITCH_OPUS_MIN_BITRATE || codec_settings->maxaveragebitrate > SWITCH_OPUS_MAX_BITRATE) {
                                codec_settings->maxaveragebitrate = 0; /* values outside the range between 6000 and 510000 SHOULD be ignored */
                            }
                        }

                        if (!strcasecmp(data, "maxplaybackrate")) {
                            codec_settings->maxplaybackrate = atoi(arg);
                            if (!switch_opus_acceptable_rate(codec_settings->maxplaybackrate)) {
                                codec_settings->maxplaybackrate = 0; /* value not supported */
                            }
                        }
                    }
                }
            }
            free(fmtp_dup);
        }
        //codec_fmtp->bits_per_second = bit_rate;
        return SWITCH_STATUS_SUCCESS;
    }
    return SWITCH_STATUS_FALSE;
}

static char *gen_fmtp(opus_codec_settings_t *settings, switch_memory_pool_t *pool)
{
    char buf[256] = "";
    
    if (settings->useinbandfec) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "useinbandfec=1;");
    }
    
#ifdef ALLOW_DTX
    if (settings->usedtx) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "usedtx=1;");
    }
#endif

    if (settings->cbr) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "cbr=1;");
    } else {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "cbr=0;");
    }
    
    if (settings->maxaveragebitrate) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "maxaveragebitrate=%d;", settings->maxaveragebitrate);
    }

    if (settings->maxplaybackrate) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "maxplaybackrate=%d;", settings->maxplaybackrate);
    }

    if (settings->sprop_maxcapturerate) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "sprop-maxcapturerate=%d;", settings->sprop_maxcapturerate);
    }
    
    if (settings->ptime) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "ptime=%d;", settings->ptime);
    }
    
    if (settings->minptime) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "minptime=%d;", settings->minptime);
    }
    
    if (settings->maxptime) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "maxptime=%d;", settings->maxptime);
    }
    
    if (settings->samplerate) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "samplerate=%d;", settings->samplerate);
    }

    if (settings->stereo) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "stereo=%d;", settings->stereo);
    }

    if (settings->sprop_stereo) {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "sprop-stereo=%d;", settings->sprop_stereo);
    }
    
    if (end_of(buf) == ';') {
        end_of(buf) = '\0';
    }
    
    return switch_core_strdup(pool, buf);
    
}

static switch_bool_t switch_opus_has_fec(struct opus_context *context, const uint8_t* payload,int payload_length_bytes)
{
    /* nb_silk_frames: number of silk-frames (10 or 20 ms) in an opus frame:  0, 1, 2 or 3 */
    /* computed from the 5 MSB (configuration) of the TOC byte (payload[0]) */
    /* nb_opus_frames: number of opus frames in the packet */
    /* computed from the 2 LSB (p0p1) of the TOC byte */
    /* p0p1 = 0  => nb_opus_frames = 1 */
    /* p0p1 = 1 or 2  => nb_opus_frames = 2 */
    /* p0p1 = 3  =>  given by the 6 LSB of payload[1] */

    int nb_silk_frames, nb_opus_frames, n, i;
    opus_int16 frame_sizes[48];
    const unsigned char *frame_data[48];

    if (payload == NULL || payload_length_bytes <= 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] corrupted packet (invalid size)\n", context->name);
        return SWITCH_FALSE;
    }
    if (payload[0] & 0x80) {
        /* this scares users and its harmless so commenting it */
        //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "FEC in CELT_ONLY mode ?!\n");
        return SWITCH_FALSE;
    }

    if ((nb_opus_frames = opus_packet_parse(payload, payload_length_bytes, NULL, frame_data, frame_sizes, NULL)) <= 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] OPUS_INVALID_PACKET ! nb_opus_frames: %d\n", context->name, nb_opus_frames);
        return SWITCH_FALSE;
    }
    nb_silk_frames  = 0;

    if ((payload[0] >> 3 ) < 12) { /* config in silk-only : NB,MB,WB */
        nb_silk_frames = (payload[0] >> 3) & 0x3;
        if(nb_silk_frames  == 0) {
            nb_silk_frames = 1;
        }
        if ((nb_silk_frames == 1) && (nb_opus_frames == 1)) {
            for (n = 0; n <= (payload[0]&0x4) ; n++) { /* mono or stereo: 10,20 ms */
                if (frame_data[0][0] & (0x80 >> ((n + 1) * (nb_silk_frames + 1) - 1))) {
                    return SWITCH_TRUE; /* frame has FEC */
                }
            }
        } else {
            opus_int16 LBRR_flag = 0 ;
            for (i=0 ; i < nb_opus_frames; i++ ) { /* only mono Opus frames */
                LBRR_flag = (frame_data[i][0] >> (7 - nb_silk_frames)) & 0x1;
                if (LBRR_flag) {
                    return SWITCH_TRUE; /* one of the silk frames has FEC */
                }
            }
        }

        return SWITCH_FALSE;
    }

    return  SWITCH_FALSE;
}

static switch_bool_t switch_opus_show_audio_bandwidth(int audiobandwidth,char *audiobandwidth_str)
{
    if (audiobandwidth == OPUS_BANDWIDTH_NARROWBAND) {
        strncpy(audiobandwidth_str, "NARROWBAND",10);
        return SWITCH_TRUE;
    } else if (audiobandwidth == OPUS_BANDWIDTH_MEDIUMBAND) {
        strncpy(audiobandwidth_str, "MEDIUMBAND",10);
        return SWITCH_TRUE;
    } else if (audiobandwidth == OPUS_BANDWIDTH_WIDEBAND) {
        strncpy(audiobandwidth_str,"WIDEBAND",8);
        return SWITCH_TRUE;
    } else if (audiobandwidth == OPUS_BANDWIDTH_SUPERWIDEBAND) {
        strncpy(audiobandwidth_str, "SUPERWIDEBAND",13);
        return SWITCH_TRUE;
    } else if (audiobandwidth == OPUS_BANDWIDTH_FULLBAND) {
        strncpy(audiobandwidth_str, "FULLBAND",8);
        return SWITCH_TRUE;
    }
    return SWITCH_FALSE;
}

static switch_status_t switch_opus_info(struct opus_context *context, void * encoded_data, uint32_t len, uint32_t samples_per_second, char *print_text)
{
    int nb_samples, nb_opus_frames, nb_channels;
    int audiobandwidth;
    char audiobandwidth_str[32] = {0};
    opus_int16 frame_sizes[48];
    const unsigned char *frame_data[48];
    char has_fec = 0;
    uint8_t * payload = encoded_data;
    opus_int32 inbandfec, bitrate, loss, bandwidth;
    switch_time_t now = switch_time_now()/1000;

    if (!encoded_data) {
        /* print stuff, even if encoded_data is NULL. eg: "PLC correction" */
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "opus[%s] %s", context->name, print_text);
        return SWITCH_STATUS_FALSE;
    }

    audiobandwidth = opus_packet_get_bandwidth(encoded_data);

    if (!switch_opus_show_audio_bandwidth(audiobandwidth,audiobandwidth_str)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] %s: OPUS_INVALID_PACKET !\n", context->name, print_text);
    }

    if ((nb_opus_frames = opus_packet_parse(encoded_data, len, NULL, frame_data, frame_sizes, NULL)) <= 0 ) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] %s: OPUS_INVALID_PACKET ! frames: %d\n",
                          context->name, print_text, nb_opus_frames);
        return SWITCH_STATUS_FALSE;
    }

    nb_samples = opus_packet_get_samples_per_frame(encoded_data, samples_per_second) * nb_opus_frames;

    has_fec = switch_opus_has_fec(context, payload, len);

    nb_channels = opus_packet_get_nb_channels(payload);

    opus_encoder_ctl(context->encoder_object, OPUS_GET_INBAND_FEC(&inbandfec));
    opus_encoder_ctl(context->encoder_object, OPUS_GET_BITRATE(&bitrate));
    opus_encoder_ctl(context->encoder_object, OPUS_GET_PACKET_LOSS_PERC(&loss));
    opus_encoder_ctl(context->encoder_object, OPUS_GET_BANDWIDTH(&bandwidth));

    if (context->debug_state.inbandfec != inbandfec ||
        context->debug_state.bitrate != bitrate ||
        context->debug_state.loss != loss ||
        context->debug_state.bandwidth != bandwidth ||
        context->debug_state.nb_opus_frames != nb_opus_frames ||
        context->debug_state.nb_samples != nb_samples ||
        context->debug_state.has_fec != has_fec ||
        context->debug_state.audiobandwidth != audiobandwidth ||
        (context->debug_state.last - now) > 1000) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "opus[%s] %s: opus_frames [%d] samples [%d] audio bandwidth [%s]"
                          " bytes [%d] FEC[%s/%s] channels[%d] c=[%d/%d/%d]\n",
                          context->name, print_text, nb_opus_frames, nb_samples, audiobandwidth_str, len, has_fec ? "yes" : "no",
                          inbandfec ? "yes" : "no", nb_channels, bitrate, loss, bandwidth);
        context->debug_state.inbandfec = inbandfec;
        context->debug_state.bitrate = bitrate;
        context->debug_state.loss = loss;
        context->debug_state.bandwidth = bandwidth;
        context->debug_state.nb_opus_frames = nb_opus_frames;
        context->debug_state.nb_samples = nb_samples;
        context->debug_state.has_fec = has_fec;
        context->debug_state.audiobandwidth = audiobandwidth;
    }
    context->debug_state.last = now;

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t switch_opus_init(switch_codec_t *codec, switch_codec_flag_t flags, const switch_codec_settings_t *codec_settings)
{
    struct opus_context *context = NULL;
    int encoding = (flags & SWITCH_CODEC_FLAG_ENCODE);
    int decoding = (flags & SWITCH_CODEC_FLAG_DECODE);
    switch_codec_fmtp_t codec_fmtp, codec_fmtp_only_remote = { 0 };
    opus_codec_settings_t opus_codec_settings = { 0 };
    opus_codec_settings_t opus_codec_settings_remote = { 0 };

    if (!(encoding || decoding) || (!(context = switch_core_alloc(codec->memory_pool, sizeof(*context))))) {
        return SWITCH_STATUS_FALSE;
    }

    context->enc_frame_size = codec->implementation->actual_samples_per_second *
        (codec->implementation->microseconds_per_packet / 1000) / 1000;

    memset(&codec_fmtp, '\0', sizeof(struct switch_codec_fmtp));
    codec_fmtp.private_info = &opus_codec_settings;
    switch_opus_fmtp_parse(codec->fmtp_in, &codec_fmtp);
    
    if (opus_prefs.asymmetric_samplerates || opus_prefs.bitrate_negotiation) {
        /* save the remote fmtp values, before processing */
        codec_fmtp_only_remote.private_info = &opus_codec_settings_remote;
        switch_opus_fmtp_parse(codec->fmtp_in, &codec_fmtp_only_remote);
    }

    /* If bitrate negotiation is allowed, verify whether remote is asking for a smaller maxaveragebitrate */
    if (opus_prefs.maxaveragebitrate &&
        (!opus_prefs.bitrate_negotiation ||
         (opus_prefs.maxaveragebitrate < opus_codec_settings_remote.maxaveragebitrate) ||
         !opus_codec_settings_remote.maxaveragebitrate)) {
        opus_codec_settings.maxaveragebitrate = opus_prefs.maxaveragebitrate;
    } else {
        opus_codec_settings.maxaveragebitrate = opus_codec_settings_remote.maxaveragebitrate;
    }

    if (codec_settings) {
        if (codec_settings->bits_per_second < opus_codec_settings.maxaveragebitrate ||
            (codec_settings->bits_per_second > 0 && opus_codec_settings.maxaveragebitrate == OPUS_AUTO)) {
            opus_codec_settings.maxaveragebitrate = codec_settings->bits_per_second;
        }
    }

    /* If asymmetric sample rates are allowed, verify whether remote is asking for a smaller maxplaybackrate */
    if (opus_prefs.maxplaybackrate &&
        (!opus_prefs.asymmetric_samplerates ||
         (opus_prefs.maxplaybackrate < opus_codec_settings_remote.maxplaybackrate) ||
         !opus_codec_settings_remote.maxplaybackrate)) {
        opus_codec_settings.maxplaybackrate = opus_prefs.maxplaybackrate;
    } else {
        opus_codec_settings.maxplaybackrate=opus_codec_settings_remote.maxplaybackrate;
    }

    /* If asymmetric sample rates are allowed, verify whether remote is asking for a smaller sprop_maxcapturerate */
    if (opus_prefs.sprop_maxcapturerate &&
        (!opus_prefs.asymmetric_samplerates ||
         (opus_prefs.sprop_maxcapturerate < opus_codec_settings_remote.sprop_maxcapturerate) ||
         !opus_codec_settings_remote.sprop_maxcapturerate)) {
        opus_codec_settings.sprop_maxcapturerate = opus_prefs.sprop_maxcapturerate;
    } else {
        opus_codec_settings.sprop_maxcapturerate = opus_codec_settings_remote.sprop_maxcapturerate;
    }

    opus_codec_settings.useinbandfec = opus_prefs.fec_decode;

    opus_codec_settings.cbr = !opus_prefs.use_vbr;

    opus_codec_settings.usedtx = opus_prefs.use_dtx;

    if (codec_settings) {
        if (codec_settings->channels > 0) {
            opus_codec_settings.stereo = codec_settings->channels == 2;
            opus_codec_settings.sprop_stereo = codec_settings->channels == 2;
        }
    }

    codec->fmtp_out = gen_fmtp(&opus_codec_settings, codec->memory_pool);
    
    if (encoding) {
        /* come up with a way to specify these */
        int bitrate_bps = opus_codec_settings.maxaveragebitrate ? opus_codec_settings.maxaveragebitrate : OPUS_AUTO;
        int use_vbr = opus_prefs.use_vbr;
        int complexity = 10 /*opus_prefs.complexity*/;
        int err;
        int enc_samplerate =
            opus_codec_settings.samplerate ? opus_codec_settings.samplerate : codec->implementation->actual_samples_per_second;
        int inbandfec = 1;
        int nchannels = 0;

        if (codec_settings) {
            if (codec_settings->channels > 0) {
                nchannels = codec_settings->channels;
            }
        }

        if (opus_prefs.asymmetric_samplerates) {
            /* If an entity receives an fmtp: maxplaybackrate=R1,sprop-maxcapturerate=R2 and sends an fmtp with:
             * maxplaybackrate=R3,sprop-maxcapturerate=R4
             * then it should start the encoder at sample rate: min(R1, R4) and the decoder at sample rate: min(R3, R2)*/
            if (codec_fmtp.private_info) {
                opus_codec_settings_t *settings = codec_fmtp_only_remote.private_info;
                if (opus_codec_settings.sprop_maxcapturerate || settings->maxplaybackrate) {
                    enc_samplerate = opus_codec_settings.sprop_maxcapturerate; /*R4*/
                    if (settings->maxplaybackrate < enc_samplerate && settings->maxplaybackrate) {
                        enc_samplerate = settings->maxplaybackrate; /*R1*/
                        context->enc_frame_size = enc_samplerate * (codec->implementation->microseconds_per_packet / 1000) / 1000;
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                          "opus[%s] Opus encoder will be created at sample rate %d hz\n",
                                          context->name, enc_samplerate);
                    } else {
                        enc_samplerate = codec->implementation->actual_samples_per_second;
                    }
                }
            }
        }

        context->control_state.wanted_bitrate = bitrate_bps;
        context->control_state.current_bitrate = context->control_state.wanted_bitrate;
        context->old_plpct = opus_prefs.plpct;
        context->complexity = 10; /*opus_prefs.complexity;*/

        if (!nchannels) {
            nchannels = codec->implementation->number_of_channels;
            context->channels = nchannels;
            if (nchannels == 0) {
                nchannels = 1;
            }
        }

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                          "opus[%s] Create OPUS encoder: bps=%d vbr=%d complexity=%d samplerate=%d inbandfec=%d n_channels=%d\n",
                          context->name, bitrate_bps, use_vbr, complexity, enc_samplerate, 
                          inbandfec, nchannels);

        context->encoder_object = opus_encoder_create(enc_samplerate,
                                                      nchannels,
                                                      OPUS_APPLICATION_VOIP, &err);

        if (err != OPUS_OK) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] Cannot create encoder: %s\n",
                              context->name, opus_strerror(err));
            return SWITCH_STATUS_GENERR;
        }

        /* https://tools.ietf.org/html/rfc7587  */
        if (opus_codec_settings.maxaveragebitrate) {
            opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(opus_codec_settings.maxaveragebitrate));
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                              "opus[%s] Opus encoder: set bitrate based on maxaveragebitrate value found in SDP or local config [%dbps]\n",
                              context->name, opus_codec_settings.maxaveragebitrate);
        } else {
            opus_encoder_ctl(context->encoder_object, OPUS_SET_BANDWIDTH(OPUS_AUTO));
            opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(bitrate_bps)); /* OPUS_AUTO */
            opus_encoder_ctl(context->encoder_object, OPUS_GET_BITRATE(&bitrate_bps)); /* return average bps for this audio bandwidth */
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "opus[%s] Opus encoder: set bitrate to local settings [%dbps]\n",
                              context->name, bitrate_bps);
        }

        /* Another fmtp setting from https://tools.ietf.org/html/rfc7587 - "RTP Payload Format for the Opus Speech and Audio Codec" */
        if (opus_codec_settings.maxplaybackrate) {
            opus_int32 audiobandwidth;
            char audiobandwidth_str[32] = {0};

            audiobandwidth = switch_opus_encoder_set_audio_bandwidth(context->encoder_object,opus_codec_settings.maxplaybackrate);
            if (!switch_opus_show_audio_bandwidth(audiobandwidth,audiobandwidth_str)) {
                memset(audiobandwidth_str,0,sizeof(audiobandwidth_str));
                strncpy(audiobandwidth_str, "OPUS_AUTO",sizeof(audiobandwidth_str)-1);
            }
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                              "opus[%s] Opus encoder: set audio bandwidth to [%s] based on maxplaybackrate "
                              "value found in SDP or local config [%dHz]\n",
                              context->name, audiobandwidth_str, opus_codec_settings.maxplaybackrate);
        }
        
        if (use_vbr) {
            opus_encoder_ctl(context->encoder_object, OPUS_SET_VBR(use_vbr));
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "opus[%s] Opus encoder: CBR mode enabled\n", context->name);
            opus_encoder_ctl(context->encoder_object, OPUS_SET_VBR(0));
        }

        if (complexity) {
            opus_encoder_ctl(context->encoder_object, OPUS_SET_COMPLEXITY(complexity));
        }

        if (context->old_plpct) {
            opus_encoder_ctl(context->encoder_object, OPUS_SET_PACKET_LOSS_PERC((int)context->old_plpct));
        }

        if (inbandfec) {
            /* FEC on the encoder: start the call with a preconfigured packet loss percentage */
            int fec_bitrate = opus_codec_settings.maxaveragebitrate;

            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "opus[%s] Opus encoder: OPUS_SET_INBAND_FEC %d\n", context->name, inbandfec);
            opus_encoder_ctl(context->encoder_object, OPUS_SET_INBAND_FEC(inbandfec));
            opus_encoder_ctl(context->encoder_object, OPUS_SET_PACKET_LOSS_PERC((int)context->old_plpct));
            if (opus_prefs.keep_fec){
                fec_bitrate = switch_opus_get_fec_bitrate(enc_samplerate, context->old_plpct);
                /* keep a bitrate for which the encoder will always add FEC */
                if (fec_bitrate != SWITCH_STATUS_FALSE) {
                    opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(fec_bitrate));
                    /* will override the maxaveragebitrate set in opus.conf.xml  */
                    opus_codec_settings.maxaveragebitrate = fec_bitrate;
                }
                context->control_state.keep_fec = opus_prefs.keep_fec;
            }
        }
        
        if (opus_codec_settings.usedtx) {
            opus_encoder_ctl(context->encoder_object, OPUS_SET_DTX(opus_codec_settings.usedtx));
        }

    }
    
    if (decoding) {
        int err;
        int dec_samplerate = codec->implementation->actual_samples_per_second;

        if (opus_prefs.asymmetric_samplerates) {
            if (codec_fmtp.private_info) {
                opus_codec_settings_t *settings = codec_fmtp_only_remote.private_info;
                if (opus_codec_settings.maxplaybackrate || settings->sprop_maxcapturerate) {
                    dec_samplerate = opus_codec_settings.maxplaybackrate; /* R3 */
                    if (dec_samplerate > settings->sprop_maxcapturerate && settings->sprop_maxcapturerate) {
                        dec_samplerate = settings->sprop_maxcapturerate; /* R2 */
                        context->dec_frame_size = dec_samplerate*(codec->implementation->microseconds_per_packet / 1000) / 1000;
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                          "opus[%s] Opus decoder will be created at sample rate %d hz\n",
                                          context->name, dec_samplerate);
                    } else {
                        dec_samplerate = codec->implementation->actual_samples_per_second;
                    }
                }
            }
        }

        context->decoder_object = opus_decoder_create(dec_samplerate,
                                                      codec->implementation->number_of_channels, &err);

        if (err != OPUS_OK) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] Cannot create decoder: %s\n",
                              context->name, opus_strerror(err));
            
            if (context->encoder_object) {
                opus_encoder_destroy(context->encoder_object);
                context->encoder_object = NULL;
            }
            
            return SWITCH_STATUS_GENERR;
        }
    }

    context->codec_settings = opus_codec_settings;
    codec->private_info = context;
    
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t switch_opus_destroy(switch_codec_t *codec)
{
    struct opus_context *context = codec->private_info;
    
    if (context) {
        if (context->decoder_object) {
            opus_decoder_destroy(context->decoder_object);
            context->decoder_object = NULL;
        }
        if (context->encoder_object) {
            opus_encoder_destroy(context->encoder_object);
            context->encoder_object = NULL;
        }
    }
    
    codec->private_info = NULL;
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t switch_opus_encode(switch_codec_t *codec,
                                          switch_codec_t *other_codec,
                                          void *decoded_data,
                                          uint32_t decoded_data_len,
                                          uint32_t decoded_rate, void *encoded_data, uint32_t *encoded_data_len, uint32_t *encoded_rate,
                                          unsigned int *flag)
{
    struct opus_context *context = codec->private_info;
    int bytes = 0;
    int16_t d2[4096];
    void *fdata = decoded_data;

    if (!context) {
        return SWITCH_STATUS_FALSE;
    }
    
    if (context->channels == 2) {
        //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Encode %d decoded %d encoded %d channels\n",
        //                  decoded_data_len, *encoded_data_len, context->channels);
        if (decoded_data_len == 960) {
            /* hmm */
        } else if (decoded_data_len == 1920) {
            int16_t *p = (int16_t *)decoded_data;
            for (int i = 0; i < decoded_data_len/2; i++) {
                d2[i*2] = p[i];
                d2[i*2+1] = p[i];
            }
            fdata = (void *)d2;
        } else if (decoded_data_len == 3840) {
            fdata = decoded_data;
        }
        bytes = opus_encode(context->encoder_object, (void *) fdata,
                            context->enc_frame_size, (unsigned char *) encoded_data, *encoded_data_len);
    } else {
        bytes = opus_encode(context->encoder_object, (void *) decoded_data,
                            context->enc_frame_size, (unsigned char *) encoded_data, *encoded_data_len);
    }
    if (globals.debug || context->debug > 1) {
        int samplerate = context->enc_frame_size * 1000 / (codec->implementation->microseconds_per_packet / 1000);
        switch_opus_info(context, encoded_data, bytes, samplerate, "encode");
    }

    // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Encode %d decoded %d encoded %d channels\n",
    //                decoded_data_len, *encoded_data_len, context->channels);

    if (bytes > 0) {
        *encoded_data_len = (uint32_t) bytes;

        context->encoder_stats.frame_counter++;
        if (context->enc_frame_size > 0) {
            context->encoder_stats.encoded_msec += codec->implementation->microseconds_per_packet / 1000;
        }
        context->encoder_stats.encoded_bytes += (uint32_t)bytes;

        if (globals.debug || context->debug > 1) {
            // This stat is expensive, so get it only when in debug mode
            if (switch_opus_has_fec(context, (uint8_t *)encoded_data, bytes)) {
                context->encoder_stats.fec_counter++;
            }
        }

        return SWITCH_STATUS_SUCCESS;
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] Encoder Error!\n", context->name);
    return SWITCH_STATUS_GENERR;
}

static switch_status_t switch_opus_keep_fec_enabled(switch_codec_t *codec)
{
    struct opus_context *context = codec->private_info;
    opus_int32 current_bitrate;
    opus_int32 current_loss;
    uint32_t LBRR_threshold_bitrate, LBRR_rate_thres_bps, real_target_bitrate;
    opus_int32 a32, b32;
    uint32_t fs = context->enc_frame_size * 1000 / (codec->implementation->microseconds_per_packet / 1000);
    float frame_rate =(float)(1000 / (codec->implementation->microseconds_per_packet / 1000));
    uint32_t step = (codec->implementation->microseconds_per_packet / 1000) != 60 ? 8000 /
        (codec->implementation->microseconds_per_packet / 1000 ) : 134 ;

    opus_encoder_ctl(context->encoder_object, OPUS_GET_BITRATE(&current_bitrate));
    opus_encoder_ctl(context->encoder_object, OPUS_GET_PACKET_LOSS_PERC(&current_loss));

    if (current_loss == 0) {
        opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(opus_prefs.maxaveragebitrate));
        return SWITCH_STATUS_SUCCESS;
    }

    if (fs == 8000) {
        LBRR_rate_thres_bps = 12000; /*LBRR_NB_MIN_RATE_BPS*/
    } else if (fs == 12000) {
        LBRR_rate_thres_bps = 14000; /*LBRR_MB_MIN_RATE_BPS*/
    } else {
        LBRR_rate_thres_bps = 16000; /*LBRR_WB_MIN_RATE_BPS*/
    }
    /*see opus-1.1/src/opus_encoder.c , opus_encode_native() */
    real_target_bitrate =  (uint32_t)(8 * (current_bitrate * context->enc_frame_size / ( fs * 8 ) - 1) * frame_rate );
    /*check if the internally used bitrate is above the threshold defined in opus-1.1/silk/control_codec.c  */
    a32 =  LBRR_rate_thres_bps * (125 -(((current_loss) < (25)) ? (current_loss) :  (25)));
    b32 =  ((opus_int32)((0.01) * ((opus_int64)1 << (16)) + 0.5));
    LBRR_threshold_bitrate =  (a32 >> 16) * (opus_int32)((opus_int16)b32) + (((a32 & 0x0000FFFF) * (opus_int32)((opus_int16)b32)) >> 16);

    if ((!real_target_bitrate || !LBRR_threshold_bitrate)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] Opus encoder: error while controlling FEC params\n",
                          context->name);
        return SWITCH_STATUS_FALSE;
    }

    /* Is there any FEC at the current bitrate and requested packet loss ?
     * If yes, then keep the current bitrate. If not, modify bitrate to keep FEC on. */

    if (real_target_bitrate > LBRR_threshold_bitrate) {
        /*FEC is already enabled, do nothing*/
        if (globals.debug || context->debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "opus[%s] Opus encoder: FEC is enabled\n",
                              context->name);
        }
        return SWITCH_STATUS_SUCCESS;
    } else {
        while (real_target_bitrate <= LBRR_threshold_bitrate) {
            current_bitrate += step;
            real_target_bitrate =  (uint32_t)(8 * (current_bitrate * context->enc_frame_size / ( fs * 8 ) - 1) * frame_rate);
        }

        opus_encoder_ctl(context->encoder_object,OPUS_SET_BITRATE(current_bitrate));

        if (globals.debug || context->debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                              "opus[%s] Opus encoder: increased bitrate to [%d] to keep FEC enabled\n",
                              context->name, current_bitrate);
        }

        return SWITCH_STATUS_SUCCESS;
    }
}

static switch_status_t switch_opus_ctl(switch_codec_t *codec,
                                       uint32_t flag,
                                       void *data)
{
    struct opus_context *context = codec->private_info;

    if (!context) {
        return SWITCH_STATUS_FALSE;
    }

    switch (flag) {
    case 1:
        {
            uint32_t plpct = *((uint32_t *) data);
            uint32_t calc;

            if (plpct > 100) {
                plpct = 100;
            }

            calc = plpct % 10;
            plpct = plpct - calc + ( calc ? 10 : 0);

            if (opus_prefs.keep_fec) {
                opus_encoder_ctl(context->encoder_object, OPUS_SET_PACKET_LOSS_PERC(plpct));
            }

            if (plpct != context->old_plpct) {
                if (opus_prefs.keep_fec) {
                    if (plpct > 10) {
                        /* this will increase bitrate a little bit, just to keep FEC enabled */
                        switch_opus_keep_fec_enabled(codec);
                    }
                } else {
                    /* this can have no effect because FEC is F(bitrate,packetloss), let the codec decide if FEC is to be used or not */
                    opus_encoder_ctl(context->encoder_object, OPUS_SET_PACKET_LOSS_PERC(plpct));
                }

                if (globals.debug || context->debug) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                      "opus[%s] Opus encoder: Adjusting packet loss percent from %d%% to %d%%!\n",
                                      context->name, context->old_plpct, plpct);
                }
            }
            if (opus_prefs.adjust_bitrate) {
                /* make bitrate adjust the step , but keep it as a  multiple of 400 (see OpusFAQ).
                 * usual RTCP interval is 5 seconds  which is long time - the step should be bigger. */
                /* step's value should depend on packet loss too, to decrease more abrubtly
                 * at high packet loss. */
                int base_step = 400; /*bps*/
                int range = context->codec_settings.maxaveragebitrate - SWITCH_OPUS_MIN_BITRATE;
                float steps = (float)((float)(range / 100) / base_step);
                int br_step = (int)(round(steps) * base_step) * plpct;
                if (globals.debug || context->debug) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                      "opus[%s] Opus encoder: bitrate increase/decrease step now is: %d bps, range:%d\n",
                                      context->name, br_step, range);
                }
                context->control_state.increase_step = context->control_state.decrease_step = br_step;
            }
            context->old_plpct = plpct;
        }
        break;
    case 2:
        {
            if (context->complexity > 1) {
                context->complexity -= 1;
                opus_encoder_ctl(context->encoder_object, OPUS_SET_COMPLEXITY(context->complexity));
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "opus[%s] Adjusted OPUS codec complexity down to %d\n",
                                  context->name, context->complexity);
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "opus[%s] OPUS codec complexity already minimum\n",
                                  context->name);
            }
        }
        break;
    case 3:
        {
            if (context->complexity < 10) {
                context->complexity += 1;
                opus_encoder_ctl(context->encoder_object, OPUS_SET_COMPLEXITY(context->complexity));
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "opus[%s] Adjusted OPUS codec complexity up to %d\n",
                                  context->name, context->complexity);
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "opus[%s] OPUS codec complexity already maximum\n",
                                  context->name);
            }
        }
        break;
    case 8:
        {
            uint32_t *bitrate = (uint32_t *)data;
            opus_int32 prev_bitrate;
            opus_encoder_ctl(context->encoder_object, OPUS_GET_BITRATE(&prev_bitrate));
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "opus[%s] OPUS codec get bitrate %d\n",
                              context->name, prev_bitrate);
            *bitrate = (uint32_t)prev_bitrate;
        }
        break;
    case 9:
        {
            uint32_t *bitrate = (uint32_t *)data;
            *bitrate = (uint32_t)context->control_state.wanted_bitrate;
        }
        break;
    case 11:
        {
            uint32_t *channels = (uint32_t *)data;
            *channels = context->channels;
        }
        break;
    case 4:
        {
            uint32_t bitrate = *((uint32_t *) data);
            opus_int32 prev_bitrate, next_bitrate;
            context->control_state.current_bitrate = bitrate;
            context->control_state.wanted_bitrate = bitrate;
            opus_encoder_ctl(context->encoder_object, OPUS_GET_BITRATE(&prev_bitrate));
            opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(bitrate));
            opus_encoder_ctl(context->encoder_object, OPUS_GET_BITRATE(&next_bitrate));
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "opus[%s] ctl set bitrate %d -> %d (result: %d)\n",
                              context->name, prev_bitrate, bitrate, next_bitrate);
        }
        break;
    case 5:
        {
            uint32_t bw = *((uint32_t *) data);
            opus_int32 prev_bandwidth, next_bandwidth;
            opus_encoder_ctl(context->encoder_object, OPUS_GET_BANDWIDTH(&prev_bandwidth));
            switch_opus_encoder_set_audio_bandwidth(context->encoder_object, bw);
            opus_encoder_ctl(context->encoder_object, OPUS_GET_BANDWIDTH(&next_bandwidth));
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "opus[%s] ctl set bandwidth %d -> %d (result: %d)\n",
                              context->name, prev_bandwidth, bw, next_bandwidth);
        }
        break;
    case 7:
        {
            const char *name = (const char *)data;
            strncpy(context->name, name, NAME_LEN);
        }
        break;
    case 10:
        {
            const char *cmd = (const char *)data;

            if (!zstr(cmd)) {
                opus_int32 current_bitrate=context->control_state.current_bitrate;
                if (!strcasecmp(cmd, "increase")) {
                    /* https://wiki.xiph.org/OpusFAQ
                       "[...]Opus scales from about 6 to 512 kb/s, in increments of 0.4 kb/s (one byte with 20 ms frames).
                       Opus can have more than 1200 possible bitrates[...]" */
                    int br_step = context->control_state.increase_step?context->control_state.increase_step:400;
                    opus_encoder_ctl(context->encoder_object, OPUS_GET_BITRATE(&current_bitrate));
                    if (opus_prefs.maxaveragebitrate > current_bitrate) {
                        opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(current_bitrate+br_step));
                        if ((context->control_state.keep_fec) && (current_bitrate > SWITCH_OPUS_MIN_FEC_BITRATE)) {
                            /* enable back FEC if it was disabled by SCC_AUDIO_ADJUST_BITRATE, we have enough network bandwidth now */
                            opus_prefs.keep_fec = 1;
                        }
                        if (globals.debug || context->debug) {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                              "opus[%s] Opus encoder: Adjusting bitrate to %d (increase)\n",
                                              context->name, current_bitrate+br_step);
                        }
                    }
                } else if (!strcasecmp(cmd, "decrease")) {
                    int br_step = context->control_state.decrease_step?context->control_state.decrease_step:400;
                    opus_encoder_ctl(context->encoder_object, OPUS_GET_BITRATE(&current_bitrate));
                    if (current_bitrate > SWITCH_OPUS_MIN_BITRATE) {
                        if (context->control_state.keep_fec) {
                            /* no point to try to keep FEC enabled anymore,
                             * we're low on network bandwidth (that's why we ended up here) */
                            opus_prefs.keep_fec = 0;
                        }
                        opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(current_bitrate-br_step));
                        if (globals.debug || context->debug) {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                              "opus[%s] Opus encoder: Adjusting bitrate to %d (decrease)\n",
                                              context->name, current_bitrate-br_step);
                        }
                    }
                } else if (!strcasecmp(cmd, "default")) {
                    /*restore default bitrate */
                    opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(opus_prefs.maxaveragebitrate));
                    if (context->control_state.keep_fec) {
                        opus_prefs.keep_fec = 1; /* enable back FEC, we have enough network bandwidth now */
                    }
                    if (globals.debug || context->debug) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                          "opus[%s] Opus encoder: Adjusting bitrate to %d (configured maxaveragebitrate)\n",
                                          context->name, opus_prefs.maxaveragebitrate);
                    }
                } else {
                    /* set Opus minimum bitrate */
                    opus_encoder_ctl(context->encoder_object, OPUS_SET_BITRATE(SWITCH_OPUS_MIN_BITRATE));
                    if (context->control_state.keep_fec) {
                        opus_prefs.keep_fec = 0; /* do not enforce FEC anymore, we're low on network bandwidth */
                    }
                    if (globals.debug || context->debug) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                          "opus[%s] Opus encoder: Adjusting bitrate to %d (minimum)\n",
                                          context->name, SWITCH_OPUS_MIN_BITRATE);
                    }
                }
            }
        }
        break;
    default:
        break;
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t switch_opus_decode(switch_codec_t *codec,
                                          switch_codec_t *other_codec,
                                          void *encoded_data,
                                          uint32_t encoded_data_len,
                                          uint32_t encoded_rate, void *decoded_data, uint32_t *decoded_data_len, uint32_t *decoded_rate,
                                          unsigned int *flag)
{
    struct opus_context *context = codec->private_info;
    int samples = 0;
    
    if (!context) {
        return SWITCH_STATUS_FALSE;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "opus[%s] Not Used!\n", context->name);


    samples = opus_decode(context->decoder_object, (*flag & SFF_PLC) ? NULL : encoded_data, encoded_data_len, decoded_data, *decoded_data_len, 0);
    
    if (samples < 0) {
        return SWITCH_STATUS_GENERR;
    }
    
    *decoded_data_len = samples * 2;
    return SWITCH_STATUS_SUCCESS;
}

static void* switch_opus_decoder(switch_codec_t *codec)
{
    struct opus_context *context;

    if (!codec)
        return NULL;
    context = codec->private_info;

    return (context ? context->decoder_object : NULL);
}

/*
 * [Raghu]: When opus decoder is configured for less than 48000, then the output from decoder
 * is garlbed for some reason. So it forces us to configure the code at the rate of 48000. 
 * But if we are using webrtc's neteq, then it is not built to work anything above 32Khz. 
 * Also opus is supposed to work at 8Khz, 16Khz and 24Khz (only multiples of 8Khz). Whereas
 * neteq works at 8Khz, 16Khz and 32Khz. So maximum common rate is 16Khz. 
 * 
 * Since decoder at anything less than 48Khz is causing problems, we will initialize only decoder 
 * at 48Khz and rest of the codec (encoder and freeswitch data structures) at 16Khz. Before output 
 * from decoder (at 48Khz) is fed into neteq, we use speex's resampler to downsample it to 16Khz.
 */
static switch_status_t opus_load_config(switch_bool_t reload)
{
    char *cf = "opus.conf";
    switch_xml_t cfg, xml = NULL, param, settings;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    
    if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Opening of %s failed\n", cf);
        return status;
    }

    memset(&opus_prefs, 0, sizeof(opus_prefs));

    opus_prefs.keep_fec = 1;
    opus_prefs.use_dtx = 1;
    opus_prefs.plpct = 20;
    opus_prefs.use_vbr = 1;
    opus_prefs.fec_decode = 1;
    opus_prefs.complexity = 10;
    opus_prefs.bitrate_negotiation = 1;
    opus_prefs.fec_decode = 1;
    opus_prefs.adjust_bitrate = 1;
    opus_prefs.maxaveragebitrate = FUZE_OPUS_MAX_BITRATE;

    if ((settings = switch_xml_child(cfg, "settings"))) {
        for (param = switch_xml_child(settings, "param"); param; param = param->next) {
            char *key = (char *) switch_xml_attr_soft(param, "name");
            char *val = (char *) switch_xml_attr_soft(param, "value");

            if (!strcasecmp(key, "use-vbr") && !zstr(val)) {
                opus_prefs.use_vbr = atoi(val);
            } else if (!strcasecmp(key, "use-dtx")) {
                opus_prefs.use_dtx = atoi(val);
            } else if (!strcasecmp(key, "complexity")) {
                opus_prefs.complexity = atoi(val);
            } else if (!strcasecmp(key, "packet-loss-percent")) {
                opus_prefs.plpct = atoi(val);
            } else if (!strcasecmp(key, "asymmetric-sample-rates")) {
                opus_prefs.asymmetric_samplerates = atoi(val);
            } else if (!strcasecmp(key, "bitrate-negotiation")) {
                opus_prefs.bitrate_negotiation = atoi(val);
            } else if (!strcasecmp(key, "keep-fec-enabled")) { /* encoder */
                opus_prefs.keep_fec = atoi(val);
            } else if (!strcasecmp(key, "advertise-useinbandfec")) {
                /*decoder, has meaning only for FMTP: useinbandfec=1 by default */
                opus_prefs.fec_decode = atoi(val);
            } else if (!strcasecmp(key, "adjust-bitrate")) {
                /* encoder, this setting will make the encoder adjust its bitrate \
                   based on a feedback loop (RTCP). This is not "VBR".*/
                opus_prefs.adjust_bitrate = atoi(val);
            } else if (!strcasecmp(key, "maxaveragebitrate")) {
                opus_prefs.maxaveragebitrate = atoi(val);
                if (opus_prefs.maxaveragebitrate < SWITCH_OPUS_MIN_BITRATE ||
                    opus_prefs.maxaveragebitrate > SWITCH_OPUS_MAX_BITRATE) {
                    opus_prefs.maxaveragebitrate = 0; /* values outside the range between 6000 and 510000 SHOULD be ignored */
                }
            } else if (!strcasecmp(key, "maxplaybackrate")) {
                opus_prefs.maxplaybackrate = atoi(val);
                if (!switch_opus_acceptable_rate(opus_prefs.maxplaybackrate)) {
                    opus_prefs.maxplaybackrate = 0; /* value not supported */
                }
            } else if (!strcasecmp(key, "sprop-maxcapturerate")) {
                opus_prefs.sprop_maxcapturerate = atoi(val);
                if (!switch_opus_acceptable_rate(opus_prefs.sprop_maxcapturerate)) {
                    opus_prefs.sprop_maxcapturerate = 0; /* value not supported */
                }
            }
        }
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Opus Config\n"
                      "\tuse-vbr: %d\n"
                      "\tuse-dtx: %d\n"
                      "\tcomplexity: %d\n"
                      "\tpacket-loss-percent: %d\n"
                      "\tasymmetric-sample-rates: %d\n"
                      "\tbitrate-negotiation: %d\n"
                      "\tkeep-fec-enabled: %d\n"
                      "\tadvertise-useinbandfec: %d\n"
                      "\tadjust-bitrate: %d\n"
                      "\tmaxaveragebitrate: %d\n"
                      "\tmaxplaybackrate: %d\n"
                      "\tsprop-maxcapturerate: %d\n",
                      opus_prefs.use_vbr, opus_prefs.use_dtx, opus_prefs.complexity, opus_prefs.plpct,
                      opus_prefs.asymmetric_samplerates, opus_prefs.bitrate_negotiation, opus_prefs.keep_fec,
                      opus_prefs.fec_decode, opus_prefs.adjust_bitrate, opus_prefs.maxaveragebitrate,
                      opus_prefs.maxplaybackrate, opus_prefs.sprop_maxcapturerate);
    
    if (xml) {
        switch_xml_free(xml);
    }
    
    return status;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_opus_load)
{
    switch_codec_interface_t *codec_interface;
    int samples = 480;
    int bytes = 960;
    int mss = 10000;
    int x = 0;
    int rate = 48000;
    int bits = 0;
    int multiplier = 3;
    char *dft_fmtp = NULL;
    opus_codec_settings_t settings = { 0 };
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    globals.debug = 0;

    if ((status = opus_load_config(SWITCH_FALSE)) != SWITCH_STATUS_SUCCESS) {
        return status;
    }

    /* connect my internal structure to the blank pointer passed to me */
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    SWITCH_ADD_CODEC(codec_interface, "OPUS (STANDARD)");

    codec_interface->parse_fmtp = switch_opus_fmtp_parse;

    settings = default_codec_settings;

    settings = default_codec_settings;

    settings.useinbandfec = opus_prefs.fec_decode;

    settings.cbr = !opus_prefs.use_vbr;

    settings.usedtx = opus_prefs.use_dtx;

    if (opus_prefs.maxaveragebitrate) {
        settings.maxaveragebitrate = opus_prefs.maxaveragebitrate;
    }

    if (opus_prefs.maxplaybackrate) {
        settings.maxplaybackrate = opus_prefs.maxplaybackrate;
    }

    if (opus_prefs.sprop_maxcapturerate) {
        settings.sprop_maxcapturerate = opus_prefs.sprop_maxcapturerate;
    }

    for (x = 0; x < 3; x++) {

        settings.ptime = mss / 1000;
        settings.maxptime = settings.ptime;
        settings.minptime = settings.ptime;
        settings.samplerate = rate;
        dft_fmtp = gen_fmtp(&settings, pool);

        for (int y = 1; y < 3; y++) {
            switch_core_codec_add_implementation_w_ctl(pool, codec_interface, SWITCH_CODEC_TYPE_AUDIO,    /* enumeration defining the type of the codec */
                                                       116,   /* the IANA code number */
                                                       "opus",/* the IANA code name */
                                                       dft_fmtp,      /* default fmtp to send (can be overridden by the init function) */
                                                       48000, /* samples transferred per second */
                                                       rate,  /* actual samples transferred per second */
                                                       bits,  /* bits transferred per second */
                                                       mss,   /* number of microseconds per frame */
                                                       samples,       /* number of samples per frame */
                                                       bytes, /* number of bytes per frame decompressed */
                                                       0,     /* number of bytes per frame compressed */
                                                       y,     /* number of channels represented */
                                                       1,     /* number of frames per network packet */
                                                       switch_opus_init,      /* function to initialize a codec handle using this implementation */
                                                       switch_opus_encode,    /* function to encode raw data into encoded data */
                                                       switch_opus_decode,    /* function to decode encoded data into raw data */
                                                       switch_opus_destroy,
                                                       switch_opus_ctl);  /* deinitalize a codec handle using this implementation */
            switch_core_codec_implementation_set_decoder(codec_interface, switch_opus_decoder);
            switch_core_codec_add_ctl_implementation(codec_interface, switch_opus_ctl);
            switch_core_codec_set_timestamp_multiplier(codec_interface, multiplier);
        }

        bytes *= 2;
        samples *= 2;
        mss *= 2;

    }

    samples = 80;
    bytes = 160;
    mss = 10000;
    rate = 8000;

    for (x = 0; x < 3; x++) {

        settings.ptime = mss / 1000;
        settings.maxptime = settings.ptime;
        settings.minptime = settings.ptime;
        settings.samplerate = rate;
        dft_fmtp = gen_fmtp(&settings, pool);

        for (int y = 1; y < 3; y++) {
            switch_core_codec_add_implementation_w_ctl(pool, codec_interface, SWITCH_CODEC_TYPE_AUDIO,    /* enumeration defining the type of the codec */
                                                       116,    /* the IANA code number */
                                                       "opus",/* the IANA code name */
                                                       dft_fmtp,       /* default fmtp to send (can be overridden by the init function) */
                                                       48000,  /* samples transferred per second */
                                                       rate,   /* actual samples transferred per second */
                                                       bits,   /* bits transferred per second */
                                                       mss,    /* number of microseconds per frame */
                                                       samples,        /* number of samples per frame */
                                                       bytes,  /* number of bytes per frame decompressed */
                                                       0,      /* number of bytes per frame compressed */
                                                       y,      /* number of channels represented */
                                                       1,      /* number of frames per network packet */
                                                       switch_opus_init,       /* function to initialize a codec handle using this implementation */
                                                       switch_opus_encode,     /* function to encode raw data into encoded data */
                                                       switch_opus_decode,     /* function to decode encoded data into raw data */
                                                       switch_opus_destroy,
                                                       switch_opus_ctl);   /* deinitalize a codec handle using this implementation */
            switch_core_codec_implementation_set_decoder(codec_interface, switch_opus_decoder);
            switch_core_codec_add_ctl_implementation(codec_interface, switch_opus_ctl);
            switch_core_codec_set_timestamp_multiplier(codec_interface, multiplier);
        }

        bytes += 160;
        samples += 80;
        mss += 10000;

    }


    /*
     * For opus, the rtp timestamp is based on assumption that 48K samples per second
     * have been sent out irrespective of what actual rate was.
     * For more info, refer to: http://tools.ietf.org/html/draft-spittka-payload-rtp-opus-03
     */

    /* indicate that the module should continue to be loaded */
    return SWITCH_STATUS_SUCCESS;
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
