#include <switch.h>

#include "conference_optimization.h"

#define CONF_BUFFER_SIZE SWITCH_RECOMMENDED_BUFFER_SIZE
#define CONF_DBLOCK_SIZE CONF_BUFFER_SIZE
#define CONF_DBUFFER_SIZE CONF_BUFFER_SIZE

//#define SIMULATE_LOAD 30

static switch_bool_t cwc_set_frame(conference_write_codec_t *cwc, uint32_t read_idx, switch_frame_t *frame);
static switch_frame_t *cwc_get_frame(conference_write_codec_t *cwc, uint32_t read_idx, int16_t *max);
static switch_bool_t cwc_frame_encoded(conference_write_codec_t *cwc, uint32_t read_idx);

SWITCH_DECLARE(conference_encoder_state_t *) switch_core_conference_encode_alloc(switch_memory_pool_t *pool);
SWITCH_DECLARE(switch_status_t) switch_core_conference_encode_init(conference_encoder_state_t *encoder_state, switch_codec_t *write_codec,
                                                                   switch_memory_pool_t *pool, int loss, int channels, int bitrate);
SWITCH_DECLARE(void) switch_core_conference_encode_destroy(conference_encoder_state_t *encoder_state);
SWITCH_DECLARE(switch_status_t) switch_core_conference_encode_frame(conference_encoder_state_t *encoder_state, switch_frame_t *frame,
                                                                    switch_io_flag_t flags, switch_frame_t **ret_enc_frame);
SWITCH_DECLARE(switch_status_t) switch_core_conference_encoder_adjust_complexity(conference_encoder_state_t *encoder_state, int direction);
SWITCH_DECLARE(switch_status_t) switch_core_conference_encoder_control(conference_encoder_state_t *encoder_state, int command, uint32_t *data);

void cwc_print(conference_write_codec_t *cwc, switch_core_session_t *session, int rd_idx) {
    switch_mutex_lock(cwc->codec_mutex);
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "CWC codec(%d) wr_idx(%d) rd_idx(%d)\n",
                      (int)cwc->codec_id, cwc->write_idx, rd_idx);
    switch_mutex_unlock(cwc->codec_mutex);
}

void cwc_next(conference_write_codec_t *cwc) {
    int idx;

    switch_mutex_lock(cwc->codec_mutex);

    if (cwc->num_conf_frames == 1) {
        idx = 0;
    } else {
        idx = (cwc->write_idx + 1) % cwc->num_conf_frames;
    }

    if (cwc->frames[cwc->write_idx].written) {
        cwc->write_idx = idx;
        cwc->frames[idx].encoded = SWITCH_FALSE;
        cwc->frames[idx].written = SWITCH_FALSE;
    }

    if (cwc->num_conf_frames > 1) {
        idx = (idx + 1) % cwc->num_conf_frames;
        cwc->frames[idx].encoded = SWITCH_FALSE;
        cwc->frames[idx].written = SWITCH_FALSE;
    }

    switch_mutex_unlock(cwc->codec_mutex);
}

switch_bool_t cwc_initialize(conference_write_codec_t *cwc, switch_memory_pool_t *mutex_pool,
                             switch_memory_pool_t *frame_pool, switch_bool_t create_encoder,
                             switch_codec_t *frame_codec, int channels, int bitrate)
{
    
    switch_mutex_init(&cwc->codec_mutex, SWITCH_MUTEX_NESTED, mutex_pool);

    cwc->next = NULL;

    cwc->codec_id = 0;
    cwc->impl_id = 0;
    cwc->write_idx = 0;

    if (create_encoder) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "cwc_initialize create_encoder channels=%d bitrate=%d\n",
                          channels, bitrate);
        cwc->encoder = switch_core_conference_encode_alloc(frame_pool);
        switch_core_codec_copy(frame_codec, &cwc->frame_codec, frame_pool, channels, bitrate);
        switch_core_codec_reset(&cwc->frame_codec);
        cwc->num_conf_frames = 1;
    } else {
        cwc->encoder = NULL;
        cwc->num_conf_frames = 10;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "cwc_initialize cwc->num_conf_frames=%d\n",
                      cwc->num_conf_frames);

    cwc->frames = switch_core_alloc(frame_pool, cwc->num_conf_frames*sizeof(conference_frame_t));

    for (int i = 0; i < cwc->num_conf_frames; i++) {
        memset(&cwc->frames[i].frame, 0, sizeof(switch_frame_t));

        if ((cwc->frames[i].frame.data = switch_core_alloc(frame_pool, ENC_FRAME_DATA))== 0){
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no memory for new frame data\n");
        }
        cwc->frames[i].frame.datalen = 0; /*ENC_FRAME_DATA;*/
        cwc->frames[i].frame.codec = &cwc->frame_codec;
        switch_set_flag(&cwc->frames[i].frame, SFF_DYNAMIC);

        cwc->frames[i].encoded = SWITCH_FALSE;
        cwc->frames[i].written = SWITCH_FALSE;
        cwc->frames[i].time = 0;
    }

    return SWITCH_TRUE;
}

void cwc_destroy(conference_write_codec_t *cwc) {
    if (cwc->encoder) {
        switch_core_conference_encode_destroy(cwc->encoder);
        switch_core_codec_destroy(&cwc->frame_codec);
    }
}

switch_bool_t cwc_write_and_encode_buffer(conference_write_codec_t *cwc,
                                          int16_t *data_mono, int16_t *data_stereo,
                                          uint32_t bytes, int16_t max) {
#ifndef SIMULATE_LOAD
    int simulate_load = 0;
#else
    int simulate_load = 1;
#endif
    if (bytes > ENC_FRAME_DATA) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cwc_write_buffer = %d\n", bytes);
        return SWITCH_FALSE;
    }

    if (cwc->last_write_size != bytes) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "cwc_write_buffer = %d (last = %d)\n", bytes, cwc->last_write_size);
        cwc->last_write_size = bytes;
    }

    switch_mutex_lock(cwc->codec_mutex);

    /* now encode here! */
    if (cwc->encoder && (cwc->listener_count > 0 || simulate_load) && !cwc->frames[cwc->write_idx].encoded) {
        switch_status_t encode_status;
        switch_io_flag_t flags = SWITCH_IO_FLAG_NONE;
        switch_frame_t *ret_enc_frame;
        uint32_t samples;

        samples = bytes/2;
        if (cwc->channels <= 1) {
            //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Encode mono %d bytes %d channels %d samples\n",
            //                bytes, cwc->channels, samples);
            memcpy(cwc->frames[cwc->write_idx].frame.data, data_mono, bytes);
        } else {
            bytes *= 2;
            if (data_stereo) {
                memcpy(cwc->frames[cwc->write_idx].frame.data, data_stereo, bytes);
            } else {
                int16_t *interleave = (int16_t *)cwc->frames[cwc->write_idx].frame.data;
                for (int i = 0; i < samples; i++) {
                    interleave[i*2] = data_mono[i];
                    interleave[i*2+1] = data_mono[i];
                }
            }
            //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Encode stereo %d bytes %d channels %d samples\n",
            //                bytes, cwc->channels, samples);
        }
        cwc->frames[cwc->write_idx].frame.datalen = bytes;
        cwc->frames[cwc->write_idx].written = SWITCH_TRUE;
        cwc->frames[cwc->write_idx].frame.samples = samples;
        cwc->frames[cwc->write_idx].frame.codec = &cwc->frame_codec;
        cwc->frames[cwc->write_idx].time = switch_time_now();
        cwc->frames[cwc->write_idx].max = max;

        //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_core_conference_encode_frame loss_idx=%d sr=%d br=%d channels=%d\n",
        //                  cwc->loss_idx, cwc->samplerate, cwc->bitrate, cwc->channels);

        encode_status = switch_core_conference_encode_frame(cwc->encoder, &cwc->frames[cwc->write_idx].frame, flags, &ret_enc_frame);
        if (encode_status == SWITCH_STATUS_SUCCESS && ret_enc_frame) {
            cwc_set_frame(cwc, cwc->write_idx, ret_enc_frame);
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "switch_core_conference_encode_frame returned %d and ret=%s\n",
                              encode_status, (ret_enc_frame ? "set" : "null"));
        }
    }
    switch_mutex_unlock(cwc->codec_mutex);

    return SWITCH_TRUE;
}

switch_bool_t cwc_write_and_copy_buffer(conference_write_codec_t *cwc, conference_write_codec_t *cwc0, int16_t *data, uint32_t bytes, int16_t max) {
    if (bytes > ENC_FRAME_DATA) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cwc_write_buffer = %d\n", bytes);
        return SWITCH_FALSE;
    }

    if (cwc->last_write_size != bytes) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "cwc_write_buffer = %d\n", bytes);
        cwc->last_write_size = bytes;
    }

    switch_mutex_lock(cwc->codec_mutex);

    if (cwc0->frames[cwc0->write_idx].written && cwc0->frames[cwc0->write_idx].encoded && !cwc->frames[cwc->write_idx].encoded) {
        cwc_set_frame(cwc, cwc->write_idx, &cwc0->frames[cwc0->write_idx].frame);
        cwc->frames[cwc->write_idx].written = SWITCH_TRUE;
        cwc->frames[cwc->write_idx].time = cwc0->frames[cwc0->write_idx].time;
        cwc->frames[cwc->write_idx].max = max;
    }
    switch_mutex_unlock(cwc->codec_mutex);

    return SWITCH_TRUE;
}

switch_bool_t cwc_set_frame(conference_write_codec_t *cwc, uint32_t idx, switch_frame_t *frame) {
    switch_mutex_lock(cwc->codec_mutex);
    if (switch_frame_copy(frame, &cwc->frames[idx].frame, frame->datalen) == SWITCH_STATUS_SUCCESS) {
        cwc->frames[idx].encoded = SWITCH_TRUE;
        switch_mutex_unlock(cwc->codec_mutex);
        return SWITCH_TRUE;
    } else {
        switch_mutex_unlock(cwc->codec_mutex);
        return SWITCH_FALSE;
    }
}

static switch_frame_t *cwc_get_frame(conference_write_codec_t *cwc, uint32_t read_idx, int16_t *max) {
    if (cwc->frames[read_idx].encoded == SWITCH_TRUE) {
        *max = cwc->frames[read_idx].max;
        return &cwc->frames[read_idx].frame;
    } else {
        *max = 0;
        return NULL;
    }
}

switch_bool_t cwc_frame_written(conference_write_codec_t *cwc, uint32_t read_idx) {
    return cwc->frames[read_idx].written;
}

switch_bool_t cwc_frame_encoded(conference_write_codec_t *cwc, uint32_t read_idx) {
    return cwc->frames[read_idx].encoded;
}

/* Conference Encoder Optimization Functions */
void ceo_start_write(conf_encoder_optimization_t *ceo) {
    for (int i = 0; i < N_CWC; i++) {
        for (conference_write_codec_t *wp_ptr = ceo->cwc[i];
             wp_ptr != NULL;
             wp_ptr = wp_ptr->next) {
            cwc_next(wp_ptr);
        }
    }
}

void ceo_set_listener_count(conf_encoder_optimization_t *ceo, int ianacode, int loss_idx, uint32_t count) {
    for (conference_write_codec_t *wp_ptr = ceo->cwc[0];
         wp_ptr != NULL;
         wp_ptr = wp_ptr->next) {
        if (wp_ptr->ianacode == ianacode) {
            if (loss_idx < 0) {
                wp_ptr->listener_count = count;
                return;
            } else {
                if (wp_ptr->loss_idx == loss_idx) {
                    wp_ptr->listener_count = count;
                    return;
                }
            }
        }
    }
}

void ceo_set_listener_count_incr(conf_encoder_optimization_t *ceo, int ianacode, int loss_idx, uint32_t count) {
    for (conference_write_codec_t *wp_ptr = ceo->cwc[0];
         wp_ptr != NULL;
         wp_ptr = wp_ptr->next) {
        if (wp_ptr->ianacode == ianacode) {
            if (loss_idx < 0) {
                wp_ptr->listener_count += count;
                return;
            } else {
                if (wp_ptr->loss_idx == loss_idx) {
                    wp_ptr->listener_count += count;
                    return;
                }
            }
        }
    }
}

switch_bool_t ceo_initilialize(conf_encoder_optimization_t *ceo, switch_memory_pool_t *pool) {

    for (int i = 0; i < N_CWC; i++) {
        ceo->cwc[i] = NULL;
    }
    ceo->write_codecs_pool = pool;
    ceo->enc_frame_pool = pool;
    ceo->enabled = SWITCH_TRUE;
    return SWITCH_TRUE;
}

void ceo_destroy(conf_encoder_optimization_t *ceo, char *name) {
    for (int i = 0; i < N_CWC; i++) {
        for (conference_write_codec_t *wp_ptr = ceo->cwc[i];
             wp_ptr != NULL;
             wp_ptr = wp_ptr->next) {
            cwc_destroy(wp_ptr);
        }
        ceo->cwc[i] = NULL;
    }
}

void ceo_complexity_adjust(conf_encoder_optimization_t *ceo, int direction) {
    for (conference_write_codec_t *wp_ptr = ceo->cwc[0];
         wp_ptr != NULL;
         wp_ptr = wp_ptr->next) {
        if (wp_ptr->ianacode > 95 && wp_ptr->encoder) {
            switch_core_conference_encoder_adjust_complexity(wp_ptr->encoder, direction);
        }
    }
}

//#define SIMULATE_ENCODER_LOSS
switch_bool_t ceo_write_buffer(conf_encoder_optimization_t *ceo,
                               int16_t *data_mono,
                               int16_t *data_stereo,
                               uint32_t bytes, int16_t max) {
#ifdef SIMULATE_ENCODER_LOSS
    int randoms = rand() % 10;
#endif
    switch_bool_t stereo = SWITCH_FALSE;

    if (data_mono) {
        memcpy(ceo->buffer_mono, data_mono, bytes);
        ceo->bytes = bytes;
        ceo->max = max;
    } else {
#ifdef SIMULATE_ENCODER_LOSS
        randoms = 0;
#endif
        data_mono = ceo->buffer_mono;
        bytes = ceo->bytes;
    }

    if (data_stereo) {
        memcpy(ceo->buffer_stereo, data_stereo, bytes*2);
        stereo = SWITCH_TRUE;
    }

    for (conference_write_codec_t *wp_ptr = ceo->cwc[0];
         wp_ptr != NULL;
         wp_ptr = wp_ptr->next) {
#ifdef SIMULATE_ENCODER_LOSS
        if (randoms < 8) {
            cwc_write_and_encode_buffer(wp_ptr, data, bytes, max);
        } else {
            wp_ptr->frames[wp_ptr->write_idx].written = SWITCH_TRUE;
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "skipping\n");
        }
#else
        cwc_write_and_encode_buffer(wp_ptr, data_mono, stereo ? ceo->buffer_stereo : NULL, bytes, max);
#endif
    }

    for (int i = 1; i < N_CWC; i++) {
        conference_write_codec_t *cwc0 = ceo->cwc[0];
        for (conference_write_codec_t *wp_ptr = ceo->cwc[i];
             wp_ptr != NULL;
             wp_ptr = wp_ptr->next) {
#ifdef SIMULATE_ENCODER_LOSS
            if (randoms < 8) {
                cwc_write_and_copy_buffer(wp_ptr, cwc0, data_mono, bytes, max);
                cwc0 = cwc0->next;
            }
#else
            cwc_write_and_copy_buffer(wp_ptr, cwc0, data_mono, bytes, max);
            cwc0 = cwc0->next;
#endif
        }
    }

    return SWITCH_TRUE;
}

switch_status_t ceo_write_new_wc(conf_encoder_optimization_t *ceo, switch_codec_t *frame_codec, switch_codec_t *write_codec,
                                 int codec_id, int impl_id, int ianacode, uint32_t bitrate, uint32_t samplerate, int loss,
                                 int loss_idx, int channels, char *name) {
    conference_write_codec_t *new_write_codec;
#ifdef SIMULATE_LOAD
    loss_percent += SIMULATE_LOAD;
#endif

    for (int i = 0; i < N_CWC; i++) {
        if ((new_write_codec = switch_core_alloc(ceo->write_codecs_pool, sizeof(*new_write_codec))) == 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no memory for new codec\n");
            return SWITCH_STATUS_FALSE;
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                              " created new codec_id=%d impl_id=%d ianacode=%d bitrate=%d samplerate=%d loss=%d%%\n",
                              codec_id, impl_id, ianacode, bitrate, samplerate, loss);
            memset(new_write_codec, 0, sizeof(*new_write_codec));

            cwc_initialize(new_write_codec, ceo->write_codecs_pool, ceo->enc_frame_pool, (i == 0), frame_codec, channels, bitrate);
            if (new_write_codec->encoder) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "switch_core_conference_encode_init channels=%d bitrate=%d\n",
                                  channels, bitrate);
                switch_core_conference_encode_init(new_write_codec->encoder, write_codec, ceo->enc_frame_pool, loss, channels, bitrate);
                if (strlen(name)) {
                    switch_core_conference_encoder_control(new_write_codec->encoder, 7, (uint32_t *)name);
                }
                if (samplerate) {
                    // switch_core_conference_encoder_control(new_write_codec->encoder, 5, &samplerate);
                }
                if (bitrate) {
                    switch_core_conference_encoder_control(new_write_codec->encoder, 4, &bitrate);
                }
            }
            new_write_codec->ianacode = ianacode;
            new_write_codec->codec_id = codec_id;
            new_write_codec->impl_id = impl_id;
            new_write_codec->loss_idx = loss_idx;
            new_write_codec->channels = channels;
            new_write_codec->bitrate = bitrate;
            new_write_codec->samplerate = samplerate;
            new_write_codec->next = ceo->cwc[i];
            new_write_codec->cwc_idx = i;
            ceo->cwc[i] = new_write_codec;
        }
    }

    return SWITCH_STATUS_SUCCESS;
}


/* Conference frames */
void meo_initialize(conf_member_encoder_optimization_t *meo) {
    meo->cwc = NULL;
    meo->output_loop_initialized = SWITCH_FALSE;
    meo->read_idx = 0;
    fc_init(&meo->cursor);
}

void meo_start(conf_member_encoder_optimization_t *meo) {
    meo->output_loop_initialized = SWITCH_TRUE;
}

switch_bool_t meo_ready(conf_member_encoder_optimization_t *meo) {
    return meo->output_loop_initialized;
}

void meo_destroy(conf_member_encoder_optimization_t *meo) {
    meo->cwc = NULL;
    meo->output_loop_initialized = SWITCH_FALSE;
    meo->read_idx = 0;
}

void meo_print(conf_member_encoder_optimization_t *meo, switch_core_session_t *session) {
    cwc_print(meo->cwc, session, meo->read_idx);
}
  
switch_bool_t meo_next_frame(conf_member_encoder_optimization_t *meo) {
    if (meo->cwc->num_conf_frames > 1) {
        if (cwc_frame_written(meo->cwc, meo->read_idx) && cwc_frame_encoded(meo->cwc, meo->read_idx)) {
            meo->read_idx = (meo->read_idx + 1) % meo->cwc->num_conf_frames;
            return cwc_frame_written(meo->cwc, meo->read_idx);
        }
    }
    return SWITCH_FALSE;
}

switch_bool_t meo_encoder_exists(conf_member_encoder_optimization_t *meo) {
    if (meo && meo->cwc) {
        if (meo->cwc->encoder) {
            return SWITCH_TRUE;
        }
    }
    return SWITCH_FALSE;
}

/* xxx */
switch_frame_t *meo_get_frame(conf_member_encoder_optimization_t *meo, int16_t *max) {
    return cwc_get_frame(meo->cwc, meo->read_idx, max);
}

switch_bool_t meo_frame_written(conf_member_encoder_optimization_t *meo) {
    return cwc_frame_written(meo->cwc, meo->read_idx);
}

void meo_reset_idx(conf_member_encoder_optimization_t *meo) {
    meo->read_idx = meo->cwc ? meo->cwc->write_idx : 0;
}

switch_bool_t meo_file_exists(conf_member_encoder_optimization_t *meo, char *fname) {
    encoded_file_t *file;
    file = eif_file_exists(meo->filelist->files, fname);
    return (file == NULL) ? SWITCH_FALSE : SWITCH_TRUE;
}

/* File Related */
play_frame_t *pf_new_frame(switch_memory_pool_t *pool, uint32_t size) {
    play_frame_t *new_frame;
    
    if ((new_frame = switch_core_alloc(pool, sizeof(play_frame_t))) == 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no memory for new play frame\n");
        return NULL;
    }

    memset(new_frame, 0, sizeof(play_frame_t));

    if ((new_frame->frame.data = switch_core_alloc(pool, size)) == 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no memory for new play frame data\n");
        return NULL;
    }
    
    switch_set_flag(&new_frame->frame, SFF_DYNAMIC);
    
    new_frame->encoded = SWITCH_FALSE;
    new_frame->next = NULL;
    new_frame->size = size;

    return new_frame;
}

switch_bool_t pf_set_frame(play_frame_t *pf, switch_frame_t *frame) {
    if (switch_frame_copy(frame, &pf->frame, frame->datalen) == SWITCH_STATUS_SUCCESS) {
        pf->encoded = SWITCH_TRUE;
        return SWITCH_TRUE;
    } else {
        return SWITCH_FALSE;
    }
}

encoded_file_t *eif_new_file(char *fname, switch_memory_pool_t *pool) {
    encoded_file_t *file;
    
    if ((file = switch_core_alloc(pool, sizeof(encoded_file_t))) == 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no memory for new file\n");
        return NULL;
    }
    
    switch_mutex_init(&file->file_mutex, SWITCH_MUTEX_NESTED, pool);
    
    file->next = NULL;
    file->frames = NULL;
    
    file->bytes = 0;

    file->pool = pool;
    file->writing = SWITCH_TRUE;
    strncpy(file->name, fname, MAX_FILENAME);
    file->done = SWITCH_FALSE;
    
    return file;
}

encoded_file_t *eif_file_exists(encoded_file_t *files, char *fname) {
    encoded_file_t *file;
    
    for (file = files; file != NULL; file = file->next) {
        if (strncmp(fname, file->name, MAX_FILENAME) == 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "eif_file_exists: found %s\n", fname);
            return file;
        }
    }
    return NULL;
}

switch_bool_t eif_file_complete(encoded_file_t *file) {
    return file->done;
}

void fc_init(file_cursor_t *cursor) {
    cursor->active = SWITCH_FALSE;
    cursor->file = NULL;
    cursor->pCurr = NULL;
    cursor->bytes_left = 0;
}


switch_bool_t fc_start_replay(file_cursor_t *cursor, filelist_t *filelist, char *fname) {
    encoded_file_t *file;
    
    if ((file = eif_file_exists(filelist->files, fname))) {
        cursor->file = file;
        cursor->pCurr = file->frames;
        cursor->active = SWITCH_TRUE;
        cursor->pCurrPlayed = SWITCH_FALSE;
        cursor->bytes_left = file->bytes;
        cursor->started = SWITCH_FALSE;
        return SWITCH_TRUE;
    }
    cursor->active = SWITCH_FALSE;
    return SWITCH_FALSE;
}

switch_bool_t fc_create_file(file_cursor_t *cursor, filelist_t *filelist, char *fname) {
    encoded_file_t *file;

    if (!(file = eif_file_exists(filelist->files, fname))) {
        if ((file = eif_new_file(fname, filelist->pool))) {
            cursor->file = file;
            cursor->pCurr = NULL;
            cursor->active = SWITCH_TRUE;
            cursor->pCurrPlayed = SWITCH_FALSE;
            cursor->bytes_left = 0;
            cursor->started = SWITCH_FALSE;
            file->next = filelist->files;
            filelist->files = file;
            
            return SWITCH_TRUE;
        }
    }
    cursor->active = SWITCH_FALSE;
    return SWITCH_FALSE;
}

switch_bool_t fc_add_frame(file_cursor_t *cursor, switch_frame_t *pFrame) {
    play_frame_t *frame;

    if (!pFrame || !cursor) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "fc_add_frame: cursor %s and pFrame %s\n",
                          (cursor == NULL ? "null" : "not null"),
                          (pFrame == NULL ? "null" : "not null"));
        return SWITCH_FALSE;
    }

    if (!cursor->active) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "fc_add_frame: cursor not active\n");
        return SWITCH_FALSE;
    }

    if (!(frame = pf_new_frame(cursor->file->pool, pFrame->datalen))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "fc_add_frame: failed to alloc frame\n");
        return SWITCH_FALSE;
    }
    if (!pf_set_frame(frame, pFrame)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "fc_add_frame: failed to set frame\n");
        return SWITCH_FALSE;
    }

    if (cursor->pCurr == NULL) {
        if (cursor->file->frames == NULL) {
            /* first frame */
            cursor->file->frames = frame;
        } else {
            /* last frame */
            /* shouldn't get in here */
        }
    } else {
        /* last frame */
        if (cursor->pCurr->next == NULL) {
            cursor->pCurr->next = frame;
        }
    }
    cursor->file->bytes += pFrame->datalen;
    cursor->pCurr = frame;
    cursor->pCurrPlayed = SWITCH_TRUE;
    return SWITCH_TRUE;
}

void fc_complete(file_cursor_t *cursor) {
    if (cursor->active) {
        cursor->file->done = SWITCH_TRUE;
        cursor->active = SWITCH_FALSE;
    }
}

switch_frame_t *fc_get_frame(file_cursor_t *cursor) {
    play_frame_t *pFrame = NULL;
    
    if (cursor->active) {
        if (!cursor->started && cursor->pCurr == NULL) {
            cursor->started = SWITCH_TRUE;
            if (cursor->file->frames) {
                cursor->pCurr = cursor->file->frames;
                pFrame = cursor->pCurr;
            } else {
                return NULL;
            }
        } else if (cursor->pCurr == NULL) {
            /* exhausted all frames */
            return NULL;
        } else {
            if (!cursor->pCurrPlayed) {
                pFrame = cursor->pCurr;

                if (cursor->pCurr->next == NULL) {
                    cursor->pCurrPlayed = SWITCH_TRUE;
                } else {
                    cursor->pCurr = cursor->pCurr->next;
                }
            } else {
                if (cursor->pCurr->next == NULL) {
                    return NULL;
                } else {
                    cursor->pCurr = cursor->pCurr->next;
                    pFrame = cursor->pCurr;
                    cursor->pCurrPlayed = SWITCH_TRUE;
                }
            }
        }
    }
    if (!cursor->started) {
        cursor->started = SWITCH_TRUE;
    }
    if (pFrame) {
        cursor->bytes_left -= pFrame->frame.datalen;
        return &pFrame->frame;
    } else {
        return NULL;
    }
}

switch_bool_t filelist_init(filelist_t *pl, switch_memory_pool_t *pool) {
    switch_mutex_init(&pl->filesmutex, SWITCH_MUTEX_NESTED, pool);
    pl->next = NULL;
    pl->pool = pool;
    pl->files = NULL;
    pl->codec_id = 0;
    pl->impl_id = 0;
    pl->stats_cnt = 0;
    pl->encode_cnt = 0;
    pl->rd_cnt = 0;
    return SWITCH_TRUE;
}

filelist_t *filelist_get(filelist_t *pl, int codec_id, int impl_id) {
    for (filelist_t *ret = pl; ret != NULL; ret = ret->next) {
        if (ret->codec_id == codec_id && ret->impl_id == impl_id) {
            return ret;
        }
    }
    return NULL;
}

conference_write_codec_t *cwc_get(conference_write_codec_t *cwc, int codec_id, int impl_id, int loss_idx) {
    for (conference_write_codec_t *ret = cwc; ret != NULL; ret = ret->next) {
        if (ret->codec_id == codec_id && ret->impl_id == impl_id) {
            if (loss_idx == -1) {
                return ret;
            }
            if (loss_idx == ret->loss_idx) {
                return ret;
            }
        }
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cwc_get failed to find codec id:%d impl:%d loss:%d\n",
                      codec_id, impl_id, loss_idx); 
    return NULL;
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
