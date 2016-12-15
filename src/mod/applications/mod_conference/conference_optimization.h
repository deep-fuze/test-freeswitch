#ifndef CONFERENCE_OPTIMIZATION_H
#define CONFERENCE_OPTIMIZATION_H

#define MAX_CONF_FRAMES 5
#define MAX_FILENAME 2048

/* This is a frame.  Each codec will have a queue of frames. */
typedef struct play_frame {
    struct play_frame *next;
    switch_frame_t frame;
    int size;
    switch_bool_t encoded;
} play_frame_t;

typedef struct encoded_file {
    struct encoded_file *next;
    
    switch_mutex_t *file_mutex;

    play_frame_t *frames;
    switch_memory_pool_t *pool;
    char name[MAX_FILENAME];
    
    uint32_t bytes;
    
    switch_bool_t done;
    switch_bool_t writing;
} encoded_file_t;

typedef struct file_cursor {
    encoded_file_t *file;
    play_frame_t *pCurr;
    switch_bool_t active;
    switch_bool_t pCurrPlayed;
    switch_bool_t started;
    uint32_t bytes_left;
} file_cursor_t;

/* This is a file list for each codec
 */
typedef struct filelist {
    struct filelist *next;
    switch_mutex_t *filesmutex;
    
    switch_memory_pool_t *pool;
    
    encoded_file_t *files;
    
    uint32_t codec_id;
    uint32_t impl_id;
    
    uint32_t stats_cnt;
    uint32_t encode_cnt;
    uint32_t rd_cnt;
} filelist_t;


/* This is a frame.  Each codec will have a queue of frames. */
typedef struct conference_frame {
    switch_buffer_t *buffer;
    switch_frame_t frame;
    
    switch_bool_t encoded;
    switch_bool_t written;
} conference_frame_t;

/* This is a codec.
 * Each conference has a set of codecs
 * Each member points to one of these codecs
 */
typedef struct conference_write_codec {
    struct conference_write_codec *next;
    switch_mutex_t *codec_mutex;

    conference_frame_t frames[MAX_CONF_FRAMES];
    
    uint32_t codec_id;
    uint32_t impl_id;
    
    uint32_t write_idx;
    
    uint64_t stats_cnt;
    uint64_t encode_cnt;
    uint64_t rd_cnt;
    uint64_t ivr_encode_cnt;
  uint32_t last_write_size;
} conference_write_codec_t;

/* This is a member object.
 * Each member has one of these
 */
typedef struct conf_member_encoder_optimization {
    conference_write_codec_t *cwc;
    
    filelist_t *filelist;
    
    file_cursor_t cursor;
    
    switch_bool_t output_loop_initialized;
    uint32_t read_idx;
    
    uint64_t stats_cnt;
    uint64_t individual_encode_cnt;
    uint64_t shared_encode_cnt;
    uint64_t shared_copy_cnt;
    uint64_t mute_cnt;
    uint64_t ivr_encode_cnt;
    uint64_t ivr_copy_cnt;
} conf_member_encoder_optimization_t;

#define N_CWC 4

/* This is a conference object.
 * Each conference has one of these
 */
typedef struct conf_encoder_optimization {
    switch_memory_pool_t *write_codecs_pool;
    switch_memory_pool_t *enc_frame_pool;
    conference_write_codec_t *cwc[N_CWC];
    
    switch_bool_t enabled;
} conf_encoder_optimization_t;

uint32_t cwc_get_idx(conference_write_codec_t *cwc);
void cwc_next(conference_write_codec_t *cwc);
switch_bool_t cwc_initialize(conference_write_codec_t *cwc, switch_memory_pool_t *mutex_pool, switch_memory_pool_t *frame_pool);
void cwc_destroy(conference_write_codec_t *cwc);
switch_size_t cwc_read_buffer(conference_write_codec_t *cwc, uint32_t read_idx, uint8_t *data, uint32_t bytes);
switch_bool_t cwc_write_buffer(conference_write_codec_t *cwc, int16_t *data,
                               uint32_t bytes);
switch_bool_t cwc_set_frame(conference_write_codec_t *cwc, uint32_t read_idx, switch_frame_t *frame);
switch_frame_t *cwc_get_frame(conference_write_codec_t *cwc, uint32_t read_idx);
switch_bool_t cwc_frame_written(conference_write_codec_t *cwc, uint32_t read_idx);
switch_bool_t cwc_frame_encoded(conference_write_codec_t *cwc, uint32_t read_idx);
conference_write_codec_t *cwc_get(conference_write_codec_t *cwc, int codec_id, int impl_id);

/* Conference Encoder Optimization Functions */
void ceo_start_write(conf_encoder_optimization_t *ceo);
switch_bool_t ceo_initilialize(conf_encoder_optimization_t *ceo, switch_memory_pool_t *pool);
void ceo_destroy(conf_encoder_optimization_t *ceo, char *name);
switch_bool_t ceo_write_buffer(conf_encoder_optimization_t *ceo, int16_t *data, uint32_t bytes);
switch_status_t ceo_write_new_wc(conf_encoder_optimization_t *ceo, int codec_id, int impl_id, int ianacode);

/* Conference frames */
void meo_initialize(conf_member_encoder_optimization_t *meo);
void meo_start(conf_member_encoder_optimization_t *meo);
switch_bool_t meo_ready(conf_member_encoder_optimization_t *meo);
void meo_destroy(conf_member_encoder_optimization_t *meo);
switch_size_t meo_read_buffer(conf_member_encoder_optimization_t *meo, uint8_t *data, uint32_t bytes);

switch_bool_t meo_next_frame(conf_member_encoder_optimization_t *meo);
switch_frame_t *meo_get_frame(conf_member_encoder_optimization_t *meo);
switch_bool_t meo_frame_written(conf_member_encoder_optimization_t *meo);
switch_bool_t meo_frame_encoded(conf_member_encoder_optimization_t *meo);
switch_bool_t meo_set_frame(conf_member_encoder_optimization_t *meo, switch_frame_t *frame);
void meo_reset_idx(conf_member_encoder_optimization_t *meo);
switch_bool_t meo_file_exists(conf_member_encoder_optimization_t *meo, char *fname);

/* Files */
switch_bool_t filelist_init(filelist_t *pl, switch_memory_pool_t *pool);
filelist_t *filelist_get(filelist_t *pl, int codec_id, int impl_id);

/* Play Frames */
play_frame_t *pf_new_frame(switch_memory_pool_t *pool, uint32_t size);
switch_bool_t pf_set_frame(play_frame_t *pf, switch_frame_t *frame);

/* Encoded Files */
encoded_file_t *eif_new_file(char *fname, switch_memory_pool_t *pool);
encoded_file_t *eif_file_exists(encoded_file_t *files, char *fname);
switch_bool_t eif_file_complete(encoded_file_t *file);

/* Cursors */
void fc_init(file_cursor_t *cursor);
switch_bool_t fc_start_replay(file_cursor_t *cursor, filelist_t *filelist, char *fname);
switch_bool_t fc_create_file(file_cursor_t *cursor, filelist_t *filelist, char *fname);
switch_bool_t fc_add_frame(file_cursor_t *cursor, switch_frame_t *pFrame);
void fc_complete(file_cursor_t *cursor);
switch_frame_t *fc_get_frame(file_cursor_t *cursor);

void meo_print(conf_member_encoder_optimization_t *meo, switch_core_session_t *session);

#endif
