/*
 * ivr.h -- IVRC Engine
 */

#ifndef _IVRE_H_
#define _IVRE_H_

struct ivre_data
{
    char dtmf_stored[128];
    int dtmf_received;
    char dtmf_accepted[128][16];
    int result;
    switch_bool_t audio_stopped;
    switch_bool_t recorded_audio;
    const char *potentialMatch;
    int potentialMatchCount;
    const char *completeMatch;
    char terminate_key;
    const char *record_tone;
};
typedef struct ivre_data ivre_data_t;

#define RES_WAITFORMORE 0
#define RES_FOUND 1
#define RES_INVALID 3
#define RES_TIMEOUT 4
#define RES_BREAK 5
#define RES_RECORD 6
#define RES_BUFFER_OVERFLOW 99

#define MAX_DTMF_SIZE_OPTION 32

switch_status_t ivre_init(ivre_data_t *loc, char **dtmf_accepted, ivre_data_t *loc_stored);
switch_status_t ivre_playback(switch_core_session_t *session, ivre_data_t *loc, const char *macro_name,  const char *data, switch_event_t *event, const char *lang, int timeout);
switch_status_t ivre_record(switch_core_session_t *session, ivre_data_t *loc, switch_event_t *event, const char *file_path, switch_file_handle_t *fh, int max_record_len, switch_size_t *record_len);

switch_status_t ivre_playback_dtmf_buffered(switch_core_session_t *session, const char *macro_name,  const char *data, switch_event_t *event, const char *lang, int timeout);
#endif
