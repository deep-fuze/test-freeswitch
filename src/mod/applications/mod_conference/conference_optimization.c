#include <switch.h>

#include "conference_optimization.h"

#define CONF_BUFFER_SIZE SWITCH_RECOMMENDED_BUFFER_SIZE
#define CONF_DBLOCK_SIZE CONF_BUFFER_SIZE
#define CONF_DBUFFER_SIZE CONF_BUFFER_SIZE

//#define ENC_FRAME_DATA (640)
#define ENC_FRAME_DATA (4096)

uint32_t cwc_get_idx(conference_write_codec_t *cwc) {
    return cwc->write_idx;
}

void cwc_print(conference_write_codec_t *cwc, switch_core_session_t *session, int rd_idx) {
  switch_mutex_lock(cwc->codec_mutex);
  switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "CWC codec(%d) wr_idx(%d) rd_idx(%d)\n",
                    (int)cwc->codec_id, cwc->write_idx, rd_idx);
  for (int i = 0; i < MAX_CONF_FRAMES; i++) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "frame(%d): e(%d) w(%d) b(%lld)\n",
                        i, cwc->frames[i].encoded, cwc->frames[i].written, (long long) switch_buffer_inuse(cwc->frames[i].buffer));
  }
  switch_mutex_unlock(cwc->codec_mutex);
}

void cwc_next(conference_write_codec_t *cwc) {
    int idx;
    
    switch_mutex_lock(cwc->codec_mutex);
    if (cwc->frames[cwc->write_idx].written) {
        idx = (cwc->write_idx + 1) % MAX_CONF_FRAMES;
        cwc->write_idx = idx;
        cwc->stats_cnt += 1;
        cwc->frames[idx].encoded = SWITCH_FALSE;
        cwc->frames[idx].written = SWITCH_FALSE;
        switch_buffer_zero(cwc->frames[idx].buffer);
        
        /* reset the next one as well as it should be done */
        idx = (idx + 1) % MAX_CONF_FRAMES;
        cwc->frames[idx].encoded = SWITCH_FALSE;
        cwc->frames[idx].written = SWITCH_FALSE;
        switch_buffer_zero(cwc->frames[idx].buffer);
    }
    switch_mutex_unlock(cwc->codec_mutex);
}

switch_bool_t cwc_initialize(conference_write_codec_t *cwc, switch_memory_pool_t *mutex_pool,
                             switch_memory_pool_t *frame_pool) {
    
    switch_mutex_init(&cwc->codec_mutex, SWITCH_MUTEX_NESTED, mutex_pool);

    cwc->next = NULL;

    cwc->codec_id = 0;
    cwc->impl_id = 0;
    cwc->write_idx = 0;
    cwc->stats_cnt = 0;
    cwc->encode_cnt = 0;
    cwc->rd_cnt = 0;
    cwc->ivr_encode_cnt = 0;

    for (int i = 0; i < MAX_CONF_FRAMES; i++) {
        memset(&cwc->frames[i].frame, 0, sizeof(switch_frame_t));

        if (switch_buffer_create_dynamic(&cwc->frames[i].buffer, CONF_DBLOCK_SIZE, CONF_DBUFFER_SIZE, 0) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Memory Error Creating Audio Buffer!\n");
            return SWITCH_FALSE;
        }
        
        if ((cwc->frames[i].frame.data = switch_core_alloc(frame_pool, ENC_FRAME_DATA))== 0){
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no memory for new frame data\n");
        }
        cwc->frames[i].frame.datalen = 0; /*ENC_FRAME_DATA;*/
        switch_set_flag(&cwc->frames[i].frame, SFF_DYNAMIC);
        
        cwc->frames[i].encoded = SWITCH_FALSE;
        cwc->frames[i].written = SWITCH_FALSE;
    }
    
    return SWITCH_TRUE;
}

void cwc_destroy(conference_write_codec_t *cwc) {
    for (int i = 0; i < MAX_CONF_FRAMES; i++) {
        switch_buffer_destroy(&cwc->frames[i].buffer);
    }
}

switch_size_t cwc_read_buffer(conference_write_codec_t *cwc, uint32_t read_idx, uint8_t *data, uint32_t bytes) {
    return switch_buffer_read(cwc->frames[read_idx].buffer, data, bytes);
}

switch_bool_t cwc_write_buffer(conference_write_codec_t *cwc, int16_t *data, uint32_t bytes) {
    switch_bool_t ret = SWITCH_FALSE;

    if (bytes > ENC_FRAME_DATA) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "cwc_write_buffer = %d\n", bytes);
        return SWITCH_FALSE;
    }

    if (cwc->last_write_size != bytes) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "cwc_write_buffer = %d\n", bytes);
        cwc->last_write_size = bytes;
    }

    switch_mutex_lock(cwc->codec_mutex);
    cwc->frames[cwc->write_idx].encoded = SWITCH_FALSE;
    cwc->frames[cwc->write_idx].written = SWITCH_FALSE;

    ret = (switch_buffer_write(cwc->frames[cwc->write_idx].buffer, data, bytes) == bytes);
    if (ret) {
      cwc->frames[cwc->write_idx].written = SWITCH_TRUE;
    }
    switch_mutex_unlock(cwc->codec_mutex);
    return ret;
}

switch_bool_t cwc_set_frame(conference_write_codec_t *cwc, uint32_t read_idx, switch_frame_t *frame) {
    if (switch_frame_copy(frame, &cwc->frames[read_idx].frame, frame->datalen) == SWITCH_STATUS_SUCCESS) {
        cwc->frames[read_idx].encoded = SWITCH_TRUE;
        return SWITCH_TRUE;
    } else {
        return SWITCH_FALSE;
    }
}

switch_frame_t *cwc_get_frame(conference_write_codec_t *cwc, uint32_t read_idx) {
    return (cwc->frames[read_idx].encoded == SWITCH_TRUE) ? &cwc->frames[read_idx].frame : NULL;
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

switch_bool_t ceo_initilialize(conf_encoder_optimization_t *ceo, switch_memory_pool_t *pool) {

    for (int i = 0; i < N_CWC; i++) {
        ceo->cwc[i] = NULL;
    }
    ceo->write_codecs_pool = pool;
    ceo->enc_frame_pool = pool;
#if 0
    if (switch_core_new_memory_pool(&ceo->write_codecs_pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error in Allocating write codecs pool.\n");
        return SWITCH_FALSE;
    }
    if (switch_core_new_memory_pool(&ceo->enc_frame_pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error in Allocating encoded frame pool.\n");
        return SWITCH_FALSE;
    }
#endif
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
#if 0
    if (ceo->write_codecs_pool) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "release codec memory for Conference: '%s'\n", name);
        switch_core_destroy_memory_pool(&ceo->write_codecs_pool);
        ceo->write_codecs_pool = NULL;
    }
    if (ceo->enc_frame_pool ){
        switch_core_destroy_memory_pool(&ceo->enc_frame_pool);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "release encoded frame memory for Conference: '%s'\n", name);
        ceo->enc_frame_pool = NULL;
    }
#endif
}

switch_bool_t ceo_write_buffer(conf_encoder_optimization_t *ceo, int16_t *data, uint32_t bytes) {

    for (int i = 0; i < N_CWC; i++) {

        for (conference_write_codec_t *wp_ptr = ceo->cwc[i];
             wp_ptr != NULL;
             wp_ptr = wp_ptr->next) {
            cwc_write_buffer(wp_ptr, data, bytes);
        }
    }
    return SWITCH_TRUE;
}

switch_status_t ceo_write_new_wc(conf_encoder_optimization_t *ceo, int codec_id, int impl_id, int ianacode) {
    conference_write_codec_t *new_write_codec;

    for (int i = 0; i < N_CWC; i++) {
        if ((new_write_codec = switch_core_alloc(ceo->write_codecs_pool, sizeof(*new_write_codec))) == 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no memory for new codec\n");
            return SWITCH_STATUS_FALSE;
        } else {

            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, " created new codec_id=%d impl_id=%d ianacode=%d\n",
                              codec_id, impl_id, ianacode);

            memset(new_write_codec, 0, sizeof(*new_write_codec));

            cwc_initialize(new_write_codec, ceo->write_codecs_pool, ceo->enc_frame_pool);

            new_write_codec->codec_id = codec_id;
            new_write_codec->impl_id = impl_id;

            new_write_codec->next = ceo->cwc[i];
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
    meo->stats_cnt = 0;
    meo->individual_encode_cnt = 0;
    meo->shared_copy_cnt = 0;
    meo->shared_encode_cnt = 0;
    meo->mute_cnt = 0;
    meo->ivr_encode_cnt = 0;
    meo->ivr_copy_cnt = 0;
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

switch_size_t meo_read_buffer(conf_member_encoder_optimization_t *meo, uint8_t *data, uint32_t bytes) {
    return cwc_read_buffer(meo->cwc, meo->read_idx, data, bytes);
}

void meo_print(conf_member_encoder_optimization_t *meo, switch_core_session_t *session) {
  cwc_print(meo->cwc, session, meo->read_idx);
}
  

switch_bool_t meo_next_frame(conf_member_encoder_optimization_t *meo) {
    if (cwc_frame_written(meo->cwc, meo->read_idx) && cwc_frame_encoded(meo->cwc, meo->read_idx)) {
        meo->read_idx = (meo->read_idx + 1) % MAX_CONF_FRAMES;
        return cwc_frame_written(meo->cwc, meo->read_idx);
    } else {
        return SWITCH_FALSE;
    }
}

/* xxx */
switch_frame_t *meo_get_frame(conf_member_encoder_optimization_t *meo) {
    return cwc_get_frame(meo->cwc, meo->read_idx);
}

switch_bool_t meo_frame_written(conf_member_encoder_optimization_t *meo) {
    return cwc_frame_written(meo->cwc, meo->read_idx);
}

switch_bool_t meo_frame_encoded(conf_member_encoder_optimization_t *meo) {
    return cwc_frame_encoded(meo->cwc, meo->read_idx);
}

switch_bool_t meo_set_frame(conf_member_encoder_optimization_t *meo, switch_frame_t *frame) {
  return cwc_set_frame(meo->cwc, meo->read_idx, frame);
}

void meo_reset_idx(conf_member_encoder_optimization_t *meo) {
    meo->read_idx = meo->cwc->write_idx;
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

    if (!cursor->active) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "fc_add_frame: cursor not active\n");
        return SWITCH_FALSE;
    }

    if (!(frame = pf_new_frame(cursor->file->pool, ENC_FRAME_DATA /*pFrame->datalen*/))) {
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

conference_write_codec_t *cwc_get(conference_write_codec_t *cwc, int codec_id, int impl_id) {
  for (conference_write_codec_t *ret = cwc; ret != NULL; ret = ret->next) {
    if (ret->codec_id == codec_id && ret->impl_id == impl_id) {
      return ret;
    }
  }
  return NULL;
}

