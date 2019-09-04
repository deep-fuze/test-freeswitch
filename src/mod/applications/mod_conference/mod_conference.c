/*
 * Freeswitch Modular Media Switching Software Library / Soft-Switch Application
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
 * Neal Horman <neal at wanlink dot com>
 * Bret McDanel <trixter at 0xdecafbad dot com>
 * Dale Thatcher <freeswitch at dalethatcher dot com>
 * Chris Danielson <chris at maxpowersoft dot com>
 * Rupa Schomaker <rupa@rupa.com>
 * David Weekly <david@weekly.org>
 * Joao Mesquita <jmesquita@gmail.com>
 * Raymond Chandler <intralanman@freeswitch.org>
 * Seven Du <dujinfang@gmail.com>
 * Emmanuel Schmidbauer <e.schmidbauer@gmail.com>
 *
 * mod_conference.c -- Software Conference Bridge
 *
 */
#include <switch.h>
#include "interface/webrtc_neteq_if.h"
#include "switch_monitor.h"
#include "conference_optimization.h"

#define DEFAULT_AGC_LEVEL 1100
#define CONFERENCE_UUID_VARIABLE "conference_uuid"

SWITCH_MODULE_LOAD_FUNCTION(mod_conference_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_conference_shutdown);
SWITCH_MODULE_DEFINITION(mod_conference, mod_conference_load, mod_conference_shutdown, NULL);

#define CPU_UTIL_PERIOD (5*6*500)
#define MINUTES_INACTIVE_TO_END 90

typedef enum {
    CONF_SILENT_REQ = (1 << 0),
    CONF_SILENT_DONE = (1 << 1)
} conf_app_flag_t;

static const char global_app_name[] = "conference";
static char *global_cf_name = "conference.conf";
static char *cf_pin_url_param_name = "X-ConfPin=";
static char *api_syntax;
static int EC = 0;

/* Size to allocate for audio buffers */
#define CONF_BUFFER_SIZE 1024 * 128
#define CONF_EVENT_MAINT "conference::maintenance"
#define CONF_EVENT_CDR "conference::cdr"
#define CONF_DEFAULT_LEADIN 20
#define CONF_ALONE_LEADIN 40

#define CONF_DBLOCK_SIZE CONF_BUFFER_SIZE
#define CONF_DBUFFER_SIZE CONF_BUFFER_SIZE
#define CONF_DBUFFER_MAX 0
#define CONF_CHAT_PROTO "conf"

#define MAX_NUM_FRAMES_BUFFERED 10

#ifndef MIN
#define MIN(a, b) ((a)<(b)?(a):(b))
#endif

/* the rate at which the infinite impulse response filter on speaker score will decay. */
#define SCORE_DECAY 0.8
/* the maximum value for the IIR score [keeps loud & longwinded people from getting overweighted] */
#define SCORE_MAX_IIR 25000
/* the minimum score for which you can be considered to be loud enough to now have the floor */
#define SCORE_IIR_SPEAKING_MAX 300
/* the threshold below which you cede the floor to someone loud (see above value). */
#define SCORE_IIR_SPEAKING_MIN 100


#define test_eflag(conference, flag) ((conference)->eflags & flag)

typedef enum {
    FILE_STOP_CURRENT,
    FILE_STOP_ALL,
    FILE_STOP_ASYNC
} file_stop_t;

/* forward declaration for conference_obj and caller_control */
struct conference_member;
typedef struct conference_member conference_member_t;

typedef struct conference_cdr_node_s {
    switch_caller_profile_t *cp;
    char *record_path;
    switch_time_t join_time;
    switch_time_t leave_time;
    uint32_t flags;
    uint32_t id;
    conference_member_t *member;
    switch_event_t *var_event;
    struct conference_cdr_node_s *next;
} conference_cdr_node_t;

typedef enum {
    CDRR_LOCKED = 1,
    CDRR_PIN,
    CDRR_MAXMEMBERS
} cdr_reject_reason_t;

typedef struct conference_cdr_reject_s {
    switch_caller_profile_t *cp;
    switch_time_t reject_time;
    cdr_reject_reason_t reason;
    struct conference_cdr_reject_s *next;
} conference_cdr_reject_t;

typedef enum {
    CDRE_NONE,
    CDRE_AS_CONTENT,
    CDRE_AS_FILE
} cdr_event_mode_t;


struct call_list {
    char *string;
    int iteration;
    struct call_list *next;
};
typedef struct call_list call_list_t;

struct caller_control_actions;

typedef struct caller_control_actions {
    char *binded_dtmf;
    char *data;
    char *expanded_data;
} caller_control_action_t;

typedef struct caller_control_menu_info {
    switch_ivr_menu_t *stack;
    char *name;
} caller_control_menu_info_t;

typedef enum {
    MFLAG_RUNNING = (1 << 0),
    MFLAG_CAN_SPEAK = (1 << 1),
    MFLAG_CAN_HEAR = (1 << 2),
    MFLAG_KICKED = (1 << 3),
    MFLAG_ITHREAD = (1 << 4),
    MFLAG_NOCHANNEL = (1 << 5),
    MFLAG_INTREE = (1 << 6),
    MFLAG_FLUSH_BUFFER = (1 << 7),
    MFLAG_ENDCONF = (1 << 8),
    MFLAG_HAS_AUDIO = (1 << 9),
    MFLAG_TALKING = (1 << 10),
    MFLAG_RESTART = (1 << 11),
    MFLAG_MINTWO = (1 << 12),
    MFLAG_MUTE_DETECT = (1 << 13),
    MFLAG_DIST_DTMF = (1 << 14),
    MFLAG_MOD = (1 << 15),
    MFLAG_INDICATE_MUTE = (1 << 16),
    MFLAG_INDICATE_UNMUTE = (1 << 17),
    MFLAG_NOMOH = (1 << 18),
    MFLAG_USE_FAKE_MUTE = (1 << 19),
    MFLAG_INDICATE_MUTE_DETECT = (1 << 20),
    MFLAG_PAUSE_RECORDING = (1 << 21),
    MFLAG_ACTIVE_TALKER = (1 << 22),
    MFLAG_NOTIFY_ACTIVITY = (1 << 23),
    MFLAG_LOG_STATS = (1 << 24),
    MFLAG_INDICATE_LOCK_MUTE = (1 << 25),
    MFLAG_INDICATE_UNLOCK_MUTE = (1 << 26),
    MFLAG_CAN_MUTE = (1 << 27),
    MFLAG_MUTELOCKABLE = (1 << 28),
    MFLAG_GHOST = (1 << 30),
    MFLAG_JOIN_ONLY = (1 << 31)
} member_flag_t;

typedef enum {
    CFLAG_RUNNING = (1 << 0),
    CFLAG_DYNAMIC = (1 << 1),
    CFLAG_ENFORCE_MIN = (1 << 2),
    CFLAG_DESTRUCT = (1 << 3),
    CFLAG_LOCKED = (1 << 4),
    CFLAG_ANSWERED = (1 << 5),
    CFLAG_BRIDGE_TO = (1 << 6),
    CFLAG_WAIT_MOD = (1 << 7),
    CFLAG_VID_FLOOR = (1 << 8),
    CFLAG_WASTE_FLAG = (1 << 9),
    CFLAG_OUTCALL = (1 << 10),
    CFLAG_INHASH = (1 << 11),
    CFLAG_EXIT_SOUND = (1 << 12),
    CFLAG_ENTER_SOUND = (1 << 13),
    CFLAG_VIDEO_BRIDGE = (1 << 14),
    CFLAG_AUDIO_ALWAYS = (1 << 15),
    CFLAG_ENDCONF_FORCED = (1 << 16),
    CFLAG_RFC4579 = (1 << 17),
    CFLAG_INDICATE_MUTE = (1 << 18),
    CFLAG_DISABLE_ATTENDEE_MUTE = (1 << 19),
    CFLAG_DEBUG_STATS_ACTIVE = (1 << 20),
    CFLAG_MODERATOR_MAX_MEMBERS_NOTIFIED_ALREADY = (1 << 21),
    CFLAG_STARTED = (1 << 22),
    CFLAG_INDICATE_LOCK_MUTE = ( 1 << 23),
    CFLAG_INDICATE_MUTE_NONMODERATOR = (1 << 24),
    CFLAG_FLOOR_CHANGE = (1 << 25),
    CFLAG_VID_FLOOR_LOCK = (1 << 26),
    CFLAG_JSON_EVENTS = (1 << 27),
    CFLAG_LIVEARRAY_SYNC = (1 << 28),
    CFLAG_CONF_RESTART_AUTO_RECORD = (1 << 29)
} conf_flag_t;

typedef enum {
    RFLAG_CAN_SPEAK = (1 << 0),
    RFLAG_CAN_HEAR = (1 << 1)
} relation_flag_t;

typedef enum {
    NODE_TYPE_FILE,
    NODE_TYPE_SPEECH,
    NODE_TYPE_CURSOR
} node_type_t;

typedef enum {
    NFLAG_NONE = (1 << 0),
    NFLAG_PAUSE = (1 << 1)
} node_flag_t;

typedef enum {
    EFLAG_ADD_MEMBER = (1 << 0),
    EFLAG_DEL_MEMBER = (1 << 1),
    EFLAG_ENERGY_LEVEL = (1 << 2),
    EFLAG_VOLUME_LEVEL = (1 << 3),
    EFLAG_GAIN_LEVEL = (1 << 4),
    EFLAG_DTMF = (1 << 5),
    EFLAG_STOP_TALKING = (1 << 6),
    EFLAG_START_TALKING = (1 << 7),
    EFLAG_MUTE_MEMBER = (1 << 8),
    EFLAG_UNMUTE_MEMBER = (1 << 9),
    EFLAG_DEAF_MEMBER = (1 << 10),
    EFLAG_UNDEAF_MEMBER = (1 << 11),
    EFLAG_KICK_MEMBER = (1 << 12),
    EFLAG_DTMF_MEMBER = (1 << 13),
    EFLAG_ENERGY_LEVEL_MEMBER = (1 << 14),
    EFLAG_VOLUME_IN_MEMBER = (1 << 15),
    EFLAG_VOLUME_OUT_MEMBER = (1 << 16),
    EFLAG_PLAY_FILE = (1 << 17),
    EFLAG_PLAY_FILE_MEMBER = (1 << 18),
    EFLAG_SPEAK_TEXT = (1 << 19),
    EFLAG_SPEAK_TEXT_MEMBER = (1 << 20),
    EFLAG_LOCK = (1 << 21),
    EFLAG_UNLOCK = (1 << 22),
    EFLAG_TRANSFER = (1 << 23),
    EFLAG_BGDIAL_RESULT = (1 << 24),
    EFLAG_FLOOR_CHANGE = (1 << 25),
    EFLAG_MUTE_DETECT = (1 << 26),
    EFLAG_RECORD = (1 << 27),
    EFLAG_HUP_MEMBER = (1 << 28),
    EFLAG_PLAY_FILE_DONE = (1 << 29),
    EFLAG_LOCK_MUTE_MEMBER = (1 << 30),
    EFLAG_UNLOCK_MUTE_MEMBER = (1 << 31),
} event_type_t;

typedef struct conference_file_node {
    switch_file_handle_t fh;
    switch_speech_handle_t *sh;
    node_flag_t flags;
    node_type_t type;
    uint8_t done;
    uint8_t async;
    switch_memory_pool_t *pool;
    uint32_t leadin;
    struct conference_file_node *next;
    char *file;
    uint8_t exclusive_play;
    switch_bool_t mux;
    file_cursor_t cursor;
    uint32_t member_id;
} conference_file_node_t;

typedef enum {
    REC_ACTION_STOP = 1,
    REC_ACTION_PAUSE,
    REC_ACTION_RESUME
} recording_action_type_t;

/* conference xml config sections */
typedef struct conf_xml_cfg {
    switch_xml_t profile;
    switch_xml_t controls;
} conf_xml_cfg_t;

struct vid_helper {
    conference_member_t *member_a;
    conference_member_t *member_b;
    int up;
};

#define MAX_ACTIVE_TALKERS 3

#define NUM_SECS_DBG_STATS 30
typedef struct {
    uint32_t active_talker_map[NUM_SECS_DBG_STATS];
    uint32_t audio_mux_map[NUM_SECS_DBG_STATS];
    uint32_t audio_receiver_map[NUM_SECS_DBG_STATS];
    uint32_t audio_substract_map[NUM_SECS_DBG_STATS];
    uint32_t last_tick; //when the last stats collected
    uint16_t timer_ticks; //mux ticks between two stat collection
    uint16_t cur_index;

    /*per member stats; Can store for first 32 members*/
    char member_name[32][32];
    uint32_t highest_score_iir[32];
    uint32_t audio_buffer_tossed_bytes[32];
    uint32_t audio_buffer_tossed_count[32];
} debug_stats_t;

/*
 * MAX_NUMBER_OF_OUTPUT_NTHREADS: Threads that are used to run conference mixers
 * MAX_NUMBER_OF_OUTPUT_OTHREADS: Threads that are used for conference overflow
 */
#define MAX_NUMBER_OF_OUTPUT_NTHREADS 12
#define MAX_NUMBER_OF_OUTPUT_OTHREADS ((N_CWC-1)*MAX_NUMBER_OF_OUTPUT_NTHREADS)
#define MAX_NUMBER_OF_OUTPUT_THREADS (MAX_NUMBER_OF_OUTPUT_NTHREADS+MAX_NUMBER_OF_OUTPUT_OTHREADS)

/* Fuze Encoder Optimization */

typedef enum {
    INPUT_LOOP_RET_DONE = 0,
    INPUT_LOOP_RET_YIELD = 1,
    INPUT_LOOP_RET_NO_FRAME = 2,
    INPUT_LOOP_RET_CNG = 3,
    INPUT_LOOP_RET_BREAK = 4
} INPUT_LOOP_RET;

typedef struct {
    // switch_event_t *event;
    conference_member_t *member;
    switch_channel_t *channel;
    uint32_t flush_len, loops;
    switch_frame_t *read_frame;
    uint32_t hangover, hangunder, hangover_hits, hangunder_hits, diff_level;
    switch_core_session_t *session;
    char var_val[32];
    int pending_event;
    int leadin_over;
    switch_io_flag_t io_flags;
    switch_time_t last_stat_report_time_ms;
    switch_thread_id_t tid;

    switch_time_t rx_time, max_time, rx_period_start;
} input_loop_data_t;

struct output_loop;
typedef struct output_loop output_loop_t;

struct output_loop {
    struct output_loop *next;
    input_loop_data_t *ild;
    int list_idx;
    switch_channel_t *channel;
    switch_frame_t write_frame;

    /* accumlate function */
    switch_frame_t acc_frame;
    uint8_t frame_cnt;

    uint8_t *data;
    uint32_t interval;
    uint32_t samples;
    uint32_t tsamples;
    uint32_t flush_len;
    uint32_t low_count, bytes;
    uint32_t sanity;
    switch_codec_implementation_t read_impl;
    switch_status_t st;
    switch_thread_id_t tid, oldtid;
    switch_bool_t individual;
    switch_bool_t new_ol;
    int ticks, check_ticks, monitor_ticks;
    int ticks_per_interval, ticks_per_stats_check;
    int ticks_per_heartbeat;

    switch_time_t rx_time, max_time, rx_period_start;

    switch_bool_t initialized;

    conference_member_t *member;
    switch_bool_t starting, stopped;
    int stopping;

    /* condition variable to synchronize "overflow" threads */
    switch_thread_cond_t *cond;
    switch_mutex_t *cond_mutex;
};

#define PROCESS_AVG_CNT 3

typedef struct {
    switch_mutex_t *lock;
    output_loop_t *loop;
    switch_thread_id_t tid;
    int idx;
    int count;
    int process_avg_idx;

    float process_avg[PROCESS_AVG_CNT];
    float process_avg_min[PROCESS_AVG_CNT];

    switch_thread_cond_t *cond;
    switch_mutex_t *cond_mutex;

} output_loop_list_t;

/* Global Values */
static struct {
    switch_memory_pool_t *conference_pool;
    switch_memory_pool_t *playlist_pool;
    switch_memory_pool_t *thread_pool;

    switch_mutex_t *conference_mutex;
    switch_hash_t *conference_hash;
    switch_mutex_t *id_mutex;
    switch_mutex_t *hash_mutex;
    switch_mutex_t *setup_mutex;
    uint32_t id_pool;
    int32_t running;
    uint32_t threads;
    switch_event_channel_id_t event_channel_id;

    /* for IVRs */
    filelist_t *filelist[MAX_NUMBER_OF_OUTPUT_THREADS];
    switch_mutex_t *filelist_mutex;

    /* global threads for conference processing */
    int number_of_output_threads;
    int start;
    switch_mutex_t *outputlllock;
    output_loop_list_t outputll[MAX_NUMBER_OF_OUTPUT_THREADS];
    switch_thread_t *output_thread[MAX_NUMBER_OF_OUTPUT_THREADS];
    switch_time_t output_thread_time[MAX_NUMBER_OF_OUTPUT_THREADS];
    int output_thread_dead[MAX_NUMBER_OF_OUTPUT_THREADS];
} globals;

struct conference_obj;

/* Record Node */
typedef struct conference_record {
    struct conference_obj *conference;
    char *path;
    switch_memory_pool_t *pool;
    switch_bool_t autorec;
    struct conference_record *next;
} conference_record_t;


#define MAX_MEETING_ID_LEN 20
#define MAX_INSTANCE_ID_LEN 20
#define MAX_MEMBERNAME_LEN 60

#define NUMBER_OF_MEMBER_LISTS 3
typedef enum {
    eMemberListTypes_Speakers = 0,
    eMemberListTypes_Listeners = 1,
    eMemberListTypes_Recorders = 2
} eMemberListTypes;

typedef struct {
    uint32_t samples;
    uint32_t bytes;
    uint8_t prev_ready;
    // switch_event_t *event;
    uint8_t *file_frame;
    uint8_t *async_file_frame;
    
    int divisor;
    int history_slot_count;
    int reset_slot_count;
    int mindex;
    switch_thread_id_t tid;
    uint32_t fuze_ticks;
    int prev_has_file_data;
    switch_bool_t active;

} conference_loop_t;

/* Conference Object */
typedef struct conference_obj {
    char *name;
    char *la_name;
    char *la_event_channel;
    char *desc;
    char *timer_name;
    char *tts_engine;
    char *tts_voice;
    char *enter_sound;
    char *exit_sound;
    char *chimes_on_sound;
    char *chimes_off_sound;
    char *alone_sound;
    char *alone_sound_attendee;
    char *perpetual_sound;
    char *moh_sound;
    char *ack_sound;
    char *nack_sound;
    char *muted_sound;
    char *mute_detect_sound;
    char *muted_all_sound;
    char *unmuted_all_sound;
    char *unmuted_sound;
    char *locked_sound;
    char *is_locked_sound;
    char *is_unlocked_sound;
    char *kicked_sound;
    char *recording_started_sound;
    char *recording_stopped_sound;
    char *join_only_sound;
    char *caller_id_name;
    char *caller_id_number;
    char *sound_prefix;
    char *special_announce;
    char *auto_record;
    char *record_filename;
    char *outcall_templ;
    char *mutes_locked_sound;
    char *mutes_unlocked_sound;
    char *lock_muted_sound;
    uint32_t terminate_on_silence;
    uint32_t max_members;
    uint32_t doc_version;
    char *maxmember_sound;
    char *maxmember_sound_attendee;
    uint32_t announce_count;
    char *pin;
    char *mpin;
    char *pin_sound;
    char *bad_pin_sound;
    char *profile_name;
    char *domain;
    char *caller_controls;
    char *moderator_controls;
    char *operator_phone_number;
    char *sip_trunk_ip_list;
    switch_live_array_t *la;
    uint32_t flags;
    member_flag_t mflags;
    switch_call_cause_t bridge_hangup_cause;
    switch_mutex_t *flag_mutex;
    uint32_t rate;
    uint32_t interval;
    switch_mutex_t *mutex;
    
    /* */
    conference_member_t *member_lists[NUMBER_OF_MEMBER_LISTS];
    
    /* */
    conference_member_t *floor_holder;
    conference_member_t *video_floor_holder;
    switch_mutex_t *member_mutex;
    conference_file_node_t *fnode;
    conference_file_node_t *async_fnode;
    switch_memory_pool_t *pool;
    switch_thread_rwlock_t *rwlock;
    uint32_t count;
    int32_t energy_level;
    uint8_t min;
    switch_speech_handle_t lsh;
    switch_speech_handle_t *sh;
    switch_byte_t *not_talking_buf;
    uint32_t not_talking_buf_len;
    int pin_retries;
    int broadcast_chat_messages;
    int comfort_noise_level;
    int auto_recording;
    int is_recording;
    int record_count;
    int min_recording_participants;
    int video_running;
    int ivr_dtmf_timeout;
    int ivr_input_timeout;
    uint32_t eflags;
    uint32_t verbose_events;
    int end_count;
    uint32_t count_ghosts;
    /* allow extra time after 'endconf' member leaves */
    switch_time_t endconf_time;
    int endconf_grace_time;

    uint32_t relationship_total;
    uint32_t score;
    int mux_loop_count;
    int member_loop_count;
    int agc_level;

    uint32_t avg_score;
    uint32_t avg_itt;
    uint32_t avg_tally;
    switch_time_t run_time;
    char *uuid_str;
    uint32_t originating;
    switch_call_cause_t cancel_cause;
    conference_cdr_node_t *cdr_nodes;
    conference_cdr_reject_t *cdr_rejected;
    switch_time_t start_time;
    switch_time_t end_time;
    char *log_dir;
    cdr_event_mode_t cdr_event_mode;
    struct vid_helper vh[2];
    struct vid_helper mh;
    
    /* Keep track of top active talkers*/
    conference_member_t *last_active_talkers[MAX_ACTIVE_TALKERS];
    conference_member_t *last_active_speaker; /* this is the real last one */

    uint16_t member_id_counter;
    switch_memory_pool_t *debug_stats_pool;
    debug_stats_t *debug_stats;
    switch_bool_t notify_active_talkers;
    uint16_t history_time_period; //msec
    uint16_t history_reset_time_period; //msec

    char *begin_sound;
    conference_record_t *rec_node_head;

    /* fuze */
    char meeting_id[MAX_MEETING_ID_LEN];
    char instance_id[MAX_INSTANCE_ID_LEN];
    
    switch_time_t start_of_interval;
    switch_time_t missed_ms;

    float avgruntime;
    int avgruntime_cnt;

    /* Fuze encoder optimization */
    conference_loop_t cloop;
    conf_encoder_optimization_t ceo;

    int list_idx;
    switch_bool_t processed;

    int min_inactive_to_end;
    switch_time_t last_time_active;
    switch_bool_t ending_due_to_inactivity;

    switch_bool_t stopping;
} conference_obj_t;

/* Relationship with another member */
typedef struct conference_relationship {
    uint32_t id;
    uint32_t flags;
    struct conference_relationship *next;
} conference_relationship_t;

/* Conference Member Object */
struct conference_member {
    uint32_t id;
    switch_core_session_t *session;
    switch_channel_t *channel;
    conference_obj_t *conference;
    switch_memory_pool_t *pool;
    switch_buffer_t *audio_buffer;
    switch_buffer_t *mux_buffer;
    switch_buffer_t *resample_buffer;
    uint32_t flags;
    uint32_t score;
    uint32_t last_score;
    uint32_t score_iir;
    switch_mutex_t *flag_mutex;
    switch_mutex_t *write_mutex;
    switch_mutex_t *audio_in_mutex;
    switch_mutex_t *audio_out_mutex;
    switch_mutex_t *read_mutex;
    switch_mutex_t *fnode_mutex;
    switch_thread_rwlock_t *rwlock;
    switch_codec_implementation_t read_impl;
    switch_codec_implementation_t orig_read_impl;
    switch_codec_t read_codec;
    switch_codec_t write_codec;
    char *rec_path;
    switch_time_t rec_time;
    conference_record_t *rec;
    uint8_t *frame;
    uint8_t *last_frame;
    uint32_t frame_size;
    uint8_t *mux_frame;
    uint32_t read;
    uint32_t vol_period;
    int32_t energy_level;
    int32_t agc_volume_in_level;
    int32_t volume_in_level;
    int32_t volume_out_level;
    int32_t agc_concur;
    int32_t nt_tally;
    switch_time_t join_time;
    switch_time_t last_talking;
    uint32_t native_rate;
    switch_audio_resampler_t *read_resampler;
    int16_t *resample_out;
    uint32_t resample_out_len;
    conference_file_node_t *fnode;
    conference_relationship_t *relationships;
    switch_speech_handle_t lsh;
    switch_speech_handle_t *sh;
    uint32_t verbose_events;
    uint32_t avg_score;
    uint32_t avg_itt;
    uint32_t avg_tally;
    struct conference_member *next;
    switch_ivr_dmachine_t *dmachine;
    conference_cdr_node_t *cdr_node;
    char *kicked_sound;
    switch_queue_t *dtmf_queue;
    switch_thread_t *output_thread;
    switch_bool_t one_of_active;
    uint16_t roll_no;
    uint16_t consecutive_active_slots;
    uint16_t consecutive_inactive_slots;
    cJSON *json;
    cJSON *status_field;
    uint8_t loop_loop;

    uint32_t flush_len;
    uint32_t low_count;

    /* Fuze */
    uint8_t muted_state;

    const char *sdpname;
    char mname[MAX_MEMBERNAME_LEN];

    switch_time_t last_time_active;
    switch_bool_t was_active;
    
    switch_time_t in_start_of_interval;
    switch_time_t in_missed_ms;
    
    switch_time_t out_start_of_interval;
    switch_time_t out_missed_ms;
    switch_time_t out_last_sent;

    switch_time_t low_level_ms;
    switch_bool_t in_low_level;
    switch_bool_t notified_low_level;
    
    conf_member_encoder_optimization_t meo;

    float out_avgruntime;
    float out_avgsendtime;
    int out_avgruntime_cnt;
    float in_avgruntime;
    int in_avgruntime_cnt;

    /* */
    switch_bool_t fuze_app;
    uint8_t frame_max_on_mute;
    uint8_t frame_max;
};

typedef enum {
    CONF_API_SUB_ARGS_SPLIT,
    CONF_API_SUB_MEMBER_TARGET,
    CONF_API_SUB_ARGS_AS_ONE
} conference_fntype_t;

typedef void (*void_fn_t) (void);

/* API command parser */
typedef struct api_command {
    char *pname;
    void_fn_t pfnapicmd;
    conference_fntype_t fntype;
    char *pcommand;
    char *psyntax;
} api_command_t;

typedef enum {
    CONFERENCE_LOOP_RET_OK = 0,
    CONFERENCE_LOOP_RET_STOP = 1,
    CONFERENCE_LOOP_RET_BAD_BUFFER_WRITE = 2
} CONFERENCE_LOOP_RET;

/* Function Prototypes */
static int setup_media(conference_member_t *member, conference_obj_t *conference);
static uint32_t next_member_id(void);
static conference_relationship_t *member_get_relationship(conference_member_t *member, conference_member_t *other_member);
static conference_member_t *conference_member_get(conference_obj_t *conference, uint32_t id);
static conference_relationship_t *member_add_relationship(conference_member_t *member, uint32_t id);
static switch_status_t member_del_relationship(conference_member_t *member, uint32_t id);
static switch_status_t conference_add_member(conference_obj_t *conference, conference_member_t *member);
static switch_status_t conference_del_member(conference_obj_t *conference, conference_member_t *member);
static CONFERENCE_LOOP_RET conference_thread_run(conference_obj_t *conference);
#if 0
static void *SWITCH_THREAD_FUNC conference_video_thread_run(switch_thread_t *thread, void *obj);
#endif
static void *SWITCH_THREAD_FUNC conference_loop_output(switch_thread_t *thread, void *obj);
static uint32_t conference_stop_file(conference_obj_t *conference, file_stop_t stop);
static switch_status_t conference_play_file(conference_obj_t *conference, char *file, uint32_t leadin, switch_channel_t *channel, uint8_t async, uint8_t exclusive);
static void conference_send_all_dtmf(conference_member_t *member, conference_obj_t *conference, const char *dtmf);
static switch_status_t conference_say(conference_obj_t *conference, const char *text, uint32_t leadin);
static void conference_list(conference_obj_t *conference, switch_stream_handle_t *stream, char *delim);
static conference_obj_t *conference_find(char *name, char *domain);
static void member_bind_controls(conference_member_t *member, const char *controls);
static void conference_send_presence(conference_obj_t *conference);
static void conference_play_alone_sound(conference_obj_t *conference, conference_member_t *member);
static conference_member_t* find_moderator(conference_obj_t *conference);
static uint8_t get_moderator_count(conference_obj_t *conference);
static switch_status_t call_operator(conference_obj_t *conference);
static switch_status_t conf_api_mute_lock_all(conference_obj_t *conference, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_lock_mute(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_unmute_lock_all(conference_obj_t *conference, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_unlock_mute(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_unlock_and_unmute(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static int output_loop_list_add(conference_obj_t *conference, output_loop_t *ol);
static int output_loop_list_remove(conference_obj_t *conference, output_loop_t *ol);

SWITCH_STANDARD_API(conf_api_main);

static switch_status_t conference_outcall(conference_obj_t *conference,
                                          char *conference_name,
                                          switch_core_session_t *session,
                                          char *bridgeto, uint32_t timeout,
                                          char *flags,
                                          char *cid_name,
                                          char *cid_num,
                                          char *profile,
                                          switch_call_cause_t *cause,
                                          switch_call_cause_t *cancel_cause, switch_event_t *var_event);
static switch_status_t conference_outcall_bg(conference_obj_t *conference,
                                             char *conference_name,
                                             switch_core_session_t *session, char *bridgeto, uint32_t timeout, const char *flags, const char *cid_name,
                                             const char *cid_num, const char *call_uuid, const char *profile, switch_call_cause_t *cancel_cause, switch_event_t **var_event);
SWITCH_STANDARD_APP(conference_function);
#if 0
static void launch_conference_thread(conference_obj_t *conference);
static void launch_conference_video_thread(conference_obj_t *conference);
static int launch_conference_video_bridge_thread(conference_member_t *member_a, conference_member_t *member_b);
#endif
static INPUT_LOOP_RET conference_loop_input(input_loop_data_t *il);
static switch_status_t conference_loop_input_setup(input_loop_data_t *il);
static switch_status_t conference_local_play_file(conference_obj_t *conference, switch_core_session_t *session, char *path, uint32_t leadin, void *buf,
                                                  uint32_t buflen);
static switch_status_t conference_member_play_file(conference_member_t *member, char *file, uint32_t leadin, uint8_t exclusive);
static switch_status_t conference_member_say(conference_member_t *member, char *text, uint32_t leadin);
static uint32_t conference_member_stop_file(conference_member_t *member, file_stop_t stop);
static conference_obj_t *conference_new(char *name, conf_xml_cfg_t cfg, switch_core_session_t *session, switch_memory_pool_t *pool);
static switch_status_t chat_send(switch_event_t *message_event);


static void launch_conference_record_thread(conference_obj_t *conference, char *path, switch_bool_t autorec);

typedef switch_status_t (*conf_api_args_cmd_t) (conference_obj_t *, switch_stream_handle_t *, int, char **);
typedef switch_status_t (*conf_api_member_cmd_t) (conference_member_t *, switch_stream_handle_t *, void *);
typedef switch_status_t (*conf_api_text_cmd_t) (conference_obj_t *, switch_stream_handle_t *, const char *);

static void conference_member_itterator(conference_obj_t *conference, switch_stream_handle_t *stream, uint8_t non_mod, conf_api_member_cmd_t pfncallback, void *data);
static switch_status_t conf_api_mute(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_unmute(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_mute_all(conference_obj_t *conference, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_unmute_all(conference_obj_t *conference, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_mute_non_moderator(conference_obj_t *conference, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_unmute_non_moderator(conference_obj_t *conference, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_mute(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_tmute(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_unmute(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_deaf(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_undeaf(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conference_add_event_data(conference_obj_t *conference, switch_event_t *event);
static switch_status_t conference_add_event_member_data(conference_member_t *member, switch_event_t *event);
static switch_status_t conf_api_sub_floor(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_enforce_floor(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static int conference_can_log_key(const char *key);
static switch_status_t conf_api_sub_vid_floor(conference_member_t *member, switch_stream_handle_t *stream, void *data);
static switch_status_t conf_api_sub_clear_vid_floor(conference_obj_t *conference, switch_stream_handle_t *stream, void *data);

#define lock_member(_member) switch_mutex_lock(_member->write_mutex); switch_mutex_lock(_member->read_mutex)
#define unlock_member(_member) switch_mutex_unlock(_member->read_mutex); switch_mutex_unlock(_member->write_mutex)

static const char* log_filter[] =
{
    "direction",
    "location",
    "uuid",
    "session_id",
    "sip_from_uri",
    "channel_name",
    "channel_type",
    "sofia_profile_name",
    "sip_req_uri",
    "sip_to_uri",
    "sip_call_id",
    "switch_r_sdp",
    "sip_local_sdp_str",
    "current_application_data",
    "conference_id",
    "conference_member_id",
    "conference_moderator",
    "conference_uuid",
    "proto_specific_hangup_cause",
    "hangup_cause",
    "digits_dialed",
    "start_stamp",
    "answer_stamp",
    "end_stamp",
    "duration",
    "rtp_samples_per_second",
    "rtp_audio_in_media_bytes",
    "rtp_audio_in_packet_count",
    "rtp_audio_rtcp_jitter_ms",
    "rtp_audio_rtcp_max_jitter_ms",
    "rtp_audio_rtcp_last_drift_ms",
    "rtp_audio_rtcp_max_drift_ms",
    "rtp_audio_rtcp_last_rtt_ms",
    "rtp_audio_rtcp_avg_rtt_ms",
    "rtp_audio_rtcp_max_rtt_ms",
    "rtp_audio_in_skip_packet_count",
    "rtp_audio_rtcp_total_lost_from_client",
    "rtp_audio_neteq_max_qlen",
    "rtp_audio_neteq_acceleate_samples",
    "rtp_audio_neteq_expand_samples",
    "rtp_audio_neteq_preemptive_expand_samples",
    "rtp_audio_neteq_merge_expand_samples",
    "rtp_audio_neteq_total_insert_errors",
    "rtp_audio_neteq_total_extract_errors",
    "rtp_audio_cur_jb_size",
    "jitterbuffer",
    "conference",
    "dialplan",
};


static void memberFlagToString(member_flag_t flag, char *str)
{
    if (flag == 0) {
        strcpy(str, "none");
        return;
    } else {
        strcpy(str, "");
    }
    if (flag & MFLAG_RUNNING)   { strcat(str,"run "); }
    if (flag & MFLAG_CAN_SPEAK) { strcat(str,"can_speak "); }
    if (flag & MFLAG_CAN_HEAR)  { strcat(str,"can_hear "); }
    if (flag & MFLAG_KICKED)    { strcat(str,"kicked "); }
    if (flag & MFLAG_ITHREAD)   { strcat(str,"ithread "); }

    if (flag & MFLAG_NOCHANNEL) { strcat(str,"no_channel "); }
    if (flag & MFLAG_INTREE)    { strcat(str,"intree "); }
    if (flag & MFLAG_FLUSH_BUFFER) { strcat(str,"flush_buffer "); }
    if (flag & MFLAG_ENDCONF)   { strcat(str,"end_conf "); }
    if (flag & MFLAG_HAS_AUDIO) { strcat(str,"has_audio "); }

    if (flag & MFLAG_TALKING)   { strcat(str,"talking "); }
    if (flag & MFLAG_RESTART)   { strcat(str,"restart "); }
    if (flag & MFLAG_MINTWO)    { strcat(str,"mintwo "); }
    if (flag & MFLAG_MUTE_DETECT) { strcat(str,"mute_detect "); }
    if (flag & MFLAG_DIST_DTMF) { strcat(str,"dist_dtmf "); }

    if (flag & MFLAG_MOD)       { strcat(str,"mod "); }
    if (flag & MFLAG_INDICATE_MUTE) { strcat(str,"ind_mute "); }
    if (flag & MFLAG_INDICATE_UNMUTE) { strcat(str,"ind_unmute "); }
    if (flag & MFLAG_NOMOH)     { strcat(str,"no_moh "); }
    if (flag & MFLAG_USE_FAKE_MUTE) { strcat(str,"fmute "); }

    if (flag & MFLAG_INDICATE_MUTE_DETECT) { strcat(str,"ind_mute_detect "); }
    if (flag & MFLAG_PAUSE_RECORDING) { strcat(str,"pause_recording "); }
    if (flag & MFLAG_ACTIVE_TALKER) { strcat(str,"active_talker "); }
    if (flag & MFLAG_NOTIFY_ACTIVITY) { strcat(str,"notify_activity "); }
    if (flag & MFLAG_LOG_STATS) { strcat(str,"log_stats "); }

    if (flag & MFLAG_INDICATE_LOCK_MUTE) { strcat(str,"ind_lock_mute "); }
    if (flag & MFLAG_INDICATE_UNLOCK_MUTE) { strcat(str,"ind_unlock_mute "); }
    if (flag & MFLAG_CAN_MUTE)  { strcat(str,"can_mute "); }
    if (flag & MFLAG_MUTELOCKABLE) { strcat(str,"mute_lockable "); }
    
    if (flag & MFLAG_GHOST)     { strcat(str,"ghost "); }
    if (flag & MFLAG_JOIN_ONLY) { strcat(str,"join_only "); }
}


static void confFlagToString(conf_flag_t flag, char *str)
{
    if (flag == 0) {
        strcpy(str, "none");
        return;
    } else {
        strcpy(str, "");
    }

    if (flag & CFLAG_RUNNING)   { strcat(str,"run "); }
    if (flag & CFLAG_DYNAMIC) { strcat(str,"dynamic "); }
    if (flag & CFLAG_ENFORCE_MIN)  { strcat(str,"enforce_min "); }
    if (flag & CFLAG_DESTRUCT)    { strcat(str,"destruct "); }
    if (flag & CFLAG_LOCKED)   { strcat(str,"locked "); }
    
    if (flag & CFLAG_ANSWERED) { strcat(str,"answered "); }
    if (flag & CFLAG_BRIDGE_TO)    { strcat(str,"bridge_to "); }
    if (flag & CFLAG_WAIT_MOD) { strcat(str,"wait_mod "); }
    if (flag & CFLAG_VID_FLOOR)   { strcat(str,"vid_floor "); }
    if (flag & CFLAG_WASTE_FLAG) { strcat(str,"waste_flag "); }
    
    if (flag & CFLAG_OUTCALL)   { strcat(str,"outcall "); }
    if (flag & CFLAG_INHASH)   { strcat(str,"inhash "); }
    if (flag & CFLAG_EXIT_SOUND)    { strcat(str,"exit_sound "); }
    if (flag & CFLAG_ENTER_SOUND) { strcat(str,"enter_sound "); }
    if (flag & CFLAG_VIDEO_BRIDGE) { strcat(str,"vid_bridge "); }
    
    if (flag & CFLAG_AUDIO_ALWAYS)       { strcat(str,"audio_always "); }
    if (flag & CFLAG_ENDCONF_FORCED) { strcat(str,"end_conf_forced "); }
    if (flag & CFLAG_RFC4579) { strcat(str,"rfc4579 "); }
    if (flag & CFLAG_INDICATE_MUTE)     { strcat(str,"ind_mute "); }
    if (flag & CFLAG_DISABLE_ATTENDEE_MUTE) { strcat(str,"dis_attendee_mute "); }
    
    if (flag & CFLAG_DEBUG_STATS_ACTIVE) { strcat(str,"debug_stats_active "); }
    if (flag & CFLAG_MODERATOR_MAX_MEMBERS_NOTIFIED_ALREADY) { strcat(str,"mod_max_notified "); }
    if (flag & CFLAG_STARTED) { strcat(str,"started "); }
    if (flag & CFLAG_INDICATE_LOCK_MUTE) { strcat(str,"ind_lock_mute "); }
    if (flag & CFLAG_INDICATE_MUTE_NONMODERATOR) { strcat(str,"ind_mute_nmod "); }
    
    if (flag & CFLAG_FLOOR_CHANGE) { strcat(str,"floor_change "); }
    if (flag & CFLAG_VID_FLOOR_LOCK) { strcat(str,"vid_floor_lock "); }
    if (flag & CFLAG_JSON_EVENTS)  { strcat(str,"json_events "); }
    if (flag & CFLAG_LIVEARRAY_SYNC) { strcat(str,"livearray_sync "); }
    if (flag & CFLAG_CONF_RESTART_AUTO_RECORD) { strcat(str,"restart_auto_record "); }
}

static void log_member_state(int32_t line, conference_member_t *omember, member_flag_t flag, switch_bool_t set)
{
    char *mname = "unknown";
    char *meeting_id = "unknown";
    char *instance_id = "unknown";
    char flag_name[100];
    char flags[1500];
    
    if (!switch_test_flag(omember, MFLAG_RUNNING)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "log_member_state for member that's not running\n");
        return;
    }

    if (omember->conference)
    {
        if (omember->conference->meeting_id)
        {
            meeting_id = omember->conference->meeting_id;
        }
        if (omember->conference->instance_id)
        {
            instance_id = omember->conference->instance_id;
        }
    }
    
    if (omember->mname && strlen(omember->mname) > 0)
    {
        mname = omember->mname;
    }
    
    memberFlagToString(flag, flag_name);
    memberFlagToString((omember)->flags, flags);
    
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(omember->session), SWITCH_LOG_INFO, "mod_conference.c:%d M(%s)/I(%s):U(%s) %s state %s (%s)\n",
                      line, meeting_id, instance_id, mname, (set ? "set" : "clear"), flag_name, flags);
}

#define set_member_state(omember, flag, locked) SET_MEMBER_STATE(__LINE__, omember, flag, locked)

static void SET_MEMBER_STATE(int32_t line, conference_member_t *omember, member_flag_t flag, switch_bool_t locked)
{
    if (!switch_test_flag(omember, flag))
    {
        log_member_state(line, omember, flag, SWITCH_TRUE);
    }
    if (locked)
    {
        switch_set_flag_locked(omember, flag);
    }
    else
    {
        switch_set_flag(omember, flag);
    }
}

#define set_member_state_unlocked(omember, flag) SET_MEMBER_STATE_UNLOCKED(__LINE__, omember, flag)

static void SET_MEMBER_STATE_UNLOCKED(int32_t line, conference_member_t *omember, member_flag_t flag)
{
    SET_MEMBER_STATE(line, omember, flag, SWITCH_FALSE);
}

#define set_member_state_locked(omember, flag) SET_MEMBER_STATE_LOCKED(__LINE__, omember, flag)

static void SET_MEMBER_STATE_LOCKED(int32_t line, conference_member_t *omember, member_flag_t flag)
{
    SET_MEMBER_STATE(line, omember, flag, SWITCH_TRUE);
}

#define clear_member_state(omember, flag, locked) CLEAR_MEMBER_STATE(__LINE__, omember, flag, locked)

static void CLEAR_MEMBER_STATE(int32_t line, conference_member_t *omember, member_flag_t flag, switch_bool_t locked)
{
    if (switch_test_flag(omember, flag))
    {
        log_member_state(line, omember, flag, SWITCH_FALSE);
    }
    if (locked)
    {
        switch_clear_flag_locked(omember, flag);
    }
    else
    {
        switch_clear_flag(omember, flag);
    }
}

#define clear_member_state_unlocked(omember, flag) CLEAR_MEMBER_STATE_UNLOCKED(__LINE__, omember, flag)

static void CLEAR_MEMBER_STATE_UNLOCKED(int32_t line, conference_member_t *omember, member_flag_t flag)
{
    CLEAR_MEMBER_STATE(line, omember, flag, SWITCH_FALSE);
}

#define clear_member_state_locked(omember, flag) CLEAR_MEMBER_STATE_LOCKED(__LINE__, omember, flag)

static void CLEAR_MEMBER_STATE_LOCKED(int32_t line, conference_member_t *omember, member_flag_t flag)
{
    CLEAR_MEMBER_STATE(line, omember, flag, SWITCH_TRUE);
}


static void log_conference_state(int32_t line, conference_obj_t *conference, conf_flag_t flag, switch_bool_t set)
{
    char *meeting_id = conference->meeting_id ? conference->meeting_id : "unknown";
    char *instance_id = conference->instance_id ? conference->instance_id : "unknown";
    char flag_name[100];
    char flags[1500];
    
    confFlagToString(flag, flag_name);
    confFlagToString(conference->flags, flags);
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "mod_conference.c:%d M(%s)/I(%s) %s state %s (%s)\n",
                      line, meeting_id, instance_id, (set ? "set" : "clear"), flag_name, flags);
}

#define set_conference_state(conference, flag, locked) SET_CONFERENCE_STATE(__LINE__, conference, flag, locked)

static void SET_CONFERENCE_STATE(int32_t line, conference_obj_t *conference, conf_flag_t flag, switch_bool_t locked)
{
    if (!switch_test_flag(conference, flag))
    {
        log_conference_state(line, conference, flag, SWITCH_TRUE);
    }
    if (locked)
    {
        switch_set_flag_locked(conference, flag);
    }
    else
    {
        switch_set_flag(conference, flag);
    }
}

#define set_conference_state_unlocked(conference, flag) SET_CONFERENCE_STATE_UNLOCKED(__LINE__, conference, flag)

static void SET_CONFERENCE_STATE_UNLOCKED(int32_t line, conference_obj_t *conference, conf_flag_t flag)
{
    SET_CONFERENCE_STATE(line, conference, flag, SWITCH_FALSE);
}

#define set_conference_state_locked(conference, flag)  SET_CONFERENCE_STATE_LOCKED(__LINE__,conference, flag)

static void SET_CONFERENCE_STATE_LOCKED(int32_t line, conference_obj_t *conference, conf_flag_t flag)
{
    SET_CONFERENCE_STATE(line, conference, flag, SWITCH_TRUE);
}

#define clear_conference_state(conference, flag, locked) CLEAR_CONFERENCE_STATE(__LINE__, conference, flag, locked)

static void CLEAR_CONFERENCE_STATE(int32_t line, conference_obj_t *conference, conf_flag_t flag, switch_bool_t locked)
{
    if (switch_test_flag(conference, flag))
    {
        log_conference_state(line, conference, flag, SWITCH_FALSE);
    }
    if (locked)
    {
        switch_clear_flag_locked(conference, flag);
    }
    else
    {
        switch_clear_flag(conference, flag);
    }
}

#define clear_conference_state_unlocked(conference, flag) CLEAR_CONFERENCE_STATE_UNLOCKED(__LINE__, conference, flag)

static void CLEAR_CONFERENCE_STATE_UNLOCKED(int32_t line, conference_obj_t *conference, conf_flag_t flag)
{
    CLEAR_CONFERENCE_STATE(line, conference, flag, SWITCH_FALSE);
}

#define clear_conference_state_locked(conference, flag) CLEAR_CONFERENCE_STATE_LOCKED(__LINE__, conference, flag)

static void CLEAR_CONFERENCE_STATE_LOCKED(int32_t line, conference_obj_t *conference, conf_flag_t flag)
{
    CLEAR_CONFERENCE_STATE(line, conference, flag, SWITCH_TRUE);
}


//#define lock_member(_member) switch_mutex_lock(_member->write_mutex)
//#define unlock_member(_member) switch_mutex_unlock(_member->write_mutex)


static void conference_cdr_del(conference_member_t *member)
{
    if (member->channel) {
        switch_channel_get_variables(member->channel, &member->cdr_node->var_event);
    }
    member->cdr_node->leave_time = switch_epoch_time_now(NULL);
    member->cdr_node->flags = member->flags;
    member->cdr_node->member = NULL;
}

static void conference_cdr_add(conference_member_t *member)
{
    conference_cdr_node_t *np;
    switch_caller_profile_t *cp;
    switch_channel_t *channel;

    np = switch_core_alloc(member->conference->pool, sizeof(*np));

    np->next = member->conference->cdr_nodes;
    member->conference->cdr_nodes = member->cdr_node = np;
    member->cdr_node->join_time = switch_epoch_time_now(NULL);
    member->cdr_node->member = member;

    if (!member->session) {
        member->cdr_node->record_path = switch_core_strdup(member->conference->pool, member->rec_path);
        return;
    }

    channel = switch_core_session_get_channel(member->session);

    if (!(cp = switch_channel_get_caller_profile(channel))) {
        return;
    }

    member->cdr_node->cp = switch_caller_profile_dup(member->conference->pool, cp);

    member->cdr_node->id = member->id;



}

static void conference_cdr_rejected(conference_obj_t *conference, switch_channel_t *channel, cdr_reject_reason_t reason)
{
    conference_cdr_reject_t *rp;
    switch_caller_profile_t *cp;

    rp = switch_core_alloc(conference->pool, sizeof(*rp));

    rp->next = conference->cdr_rejected;
    conference->cdr_rejected = rp;
    rp->reason = reason;
    rp->reject_time = switch_epoch_time_now(NULL);

    if (!(cp = switch_channel_get_caller_profile(channel))) {
        return;
    }

    rp->cp = switch_caller_profile_dup(conference->pool, cp);
}

static const char *audio_flow(conference_member_t *member)
{
    const char *flow = "sendrecv";

    if (!switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        flow = "recvonly";
    }

    if (member->channel && switch_channel_test_flag(member->channel, CF_HOLD)) {
        flow = switch_test_flag(member, MFLAG_CAN_SPEAK) ? "sendonly" : "inactive";
    }

    return flow;
}

static char *conference_rfc4579_render(conference_obj_t *conference, switch_event_t *event, switch_event_t *revent)
{
    switch_xml_t xml, x_tag, x_tag1, x_tag2, x_tag3, x_tag4;
    char tmp[30];
    const char *domain;    const char *name;
    char *dup_domain = NULL;
    char *uri;
    int off = 0, off1 = 0, off2 = 0, off3 = 0, off4 = 0;
    conference_cdr_node_t *np;
    char *tmpp = tmp;
    char *xml_text = NULL;

    if (!(xml = switch_xml_new("conference-info"))) {
        abort();
    }

    switch_mutex_lock(conference->mutex);
    switch_snprintf(tmp, sizeof(tmp), "%u", conference->doc_version);
    conference->doc_version++;
    switch_mutex_unlock(conference->mutex);

    if (!event || !(name = switch_event_get_header(event, "conference-name"))) {
        if (!(name = conference->name)) {
            name = "conference";
        }
    }

    if (!event || !(domain = switch_event_get_header(event, "conference-domain"))) {
        if (!(domain = conference->domain)) {
            dup_domain = switch_core_get_domain(SWITCH_TRUE);
            if (!(domain = dup_domain)) {
                domain = "cluecon.com";
            }
        }
    }

    switch_xml_set_attr_d(xml, "version", tmpp);

    switch_xml_set_attr_d(xml, "state", "full");
    switch_xml_set_attr_d(xml, "xmlns", "urn:ietf:params:xml:ns:conference-info");


    uri = switch_mprintf("sip:%s@%s", name, domain);
    switch_xml_set_attr_d(xml, "entity", uri);

    if (!(x_tag = switch_xml_add_child_d(xml, "conference-description", off++))) {
        abort();
    }

    if (!(x_tag1 = switch_xml_add_child_d(x_tag, "display-text", off1++))) {
        abort();
    }
    switch_xml_set_txt_d(x_tag1, conference->desc ? conference->desc : "FreeSWITCH Conference");


    if (!(x_tag1 = switch_xml_add_child_d(x_tag, "conf-uris", off1++))) {
        abort();
    }

    if (!(x_tag2 = switch_xml_add_child_d(x_tag1, "entry", off2++))) {
        abort();
    }

    if (!(x_tag3 = switch_xml_add_child_d(x_tag2, "uri", off3++))) {
        abort();
    }
    switch_xml_set_txt_d(x_tag3, uri);



    if (!(x_tag = switch_xml_add_child_d(xml, "conference-state", off++))) {
        abort();
    }
    if (!(x_tag1 = switch_xml_add_child_d(x_tag, "user-count", off1++))) {
        abort();
    }
    switch_snprintf(tmp, sizeof(tmp), "%u", conference->count);
    switch_xml_set_txt_d(x_tag1, tmpp);

#if 0
    if (conference->count == 0) {
        switch_event_add_header(revent, SWITCH_STACK_BOTTOM, "notfound", "true");
    }
#endif

    if (!(x_tag1 = switch_xml_add_child_d(x_tag, "active", off1++))) {
        abort();
    }
    switch_xml_set_txt_d(x_tag1, "true");

    off1 = off2 = off3 = off4 = 0;

    if (!(x_tag = switch_xml_add_child_d(xml, "users", off++))) {
        abort();
    }

    switch_mutex_lock(conference->member_mutex);

    for (np = conference->cdr_nodes; np; np = np->next) {
        char *user_uri = NULL;
        switch_channel_t *channel = NULL;

        if (!np->cp || (np->member && !np->member->session) || np->leave_time) { /* for now we'll remove participants when the leave */
            continue;
        }

        if (np->member && np->member->session) {
            channel = switch_core_session_get_channel(np->member->session);
        }

        if (!(x_tag1 = switch_xml_add_child_d(x_tag, "user", off1++))) {
            abort();
        }

        if (channel) {
            const char *uri = switch_channel_get_variable_dup(channel, "conference_invite_uri", SWITCH_FALSE, -1);

            if (uri) {
                user_uri = strdup(uri);
            }
        }

        if (!user_uri) {
            user_uri = switch_mprintf("sip:%s@%s", np->cp->caller_id_number, domain);
        }


        switch_xml_set_attr_d(x_tag1, "state", "full");
        switch_xml_set_attr_d(x_tag1, "entity", user_uri);

        if (!(x_tag2 = switch_xml_add_child_d(x_tag1, "display-text", off2++))) {
            abort();
        }
        switch_xml_set_txt_d(x_tag2, np->cp->caller_id_name);


        if (!(x_tag2 = switch_xml_add_child_d(x_tag1, "endpoint", off2++))) {
            abort();
        }
        switch_xml_set_attr_d(x_tag2, "entity", user_uri);

        if (!(x_tag3 = switch_xml_add_child_d(x_tag2, "display-text", off3++))) {
            abort();
        }
        switch_xml_set_txt_d(x_tag3, np->cp->caller_id_name);


        if (!(x_tag3 = switch_xml_add_child_d(x_tag2, "status", off3++))) {
            abort();
        }
        switch_xml_set_txt_d(x_tag3, np->leave_time ? "disconnected" : "connected");


        if (!(x_tag3 = switch_xml_add_child_d(x_tag2, "joining-info", off3++))) {
            abort();
        }
        if (!(x_tag4 = switch_xml_add_child_d(x_tag3, "when", off4++))) {
            abort();
        } else {
            switch_time_exp_t tm;
            switch_size_t retsize;
            const char *fmt = "%Y-%m-%dT%H:%M:%S%z";
            char *p;

            switch_time_exp_lt(&tm, (switch_time_t) conference->start_time * 1000000);
            switch_strftime_nocheck(tmp, &retsize, sizeof(tmp), fmt, &tm);
            p = end_of_p(tmpp) -1;
            snprintf(p, 4, ":00");


            switch_xml_set_txt_d(x_tag4, tmpp);
        }




        /** ok so this is in the rfc but not the xsd
        if (!(x_tag3 = switch_xml_add_child_d(x_tag2, "joining-method", off3++))) {
            abort();
        }
        switch_xml_set_txt_d(x_tag3, np->cp->direction == SWITCH_CALL_DIRECTION_INBOUND ? "dialed-in" : "dialed-out");
        */

        if (np->member) {
            const char *var;
            //char buf[1024];

            //switch_snprintf(buf, sizeof(buf), "conf_%s_%s_%s", conference->name, conference->domain, np->cp->caller_id_number);
            //switch_channel_set_variable(channel, "conference_call_key", buf);

            if (!(x_tag3 = switch_xml_add_child_d(x_tag2, "media", off3++))) {
                abort();
            }

            snprintf(tmp, sizeof(tmp), "%ua", np->member->id);
            switch_xml_set_attr_d(x_tag3, "id", tmpp);


            if (!(x_tag4 = switch_xml_add_child_d(x_tag3, "type", off4++))) {
                abort();
            }
            switch_xml_set_txt_d(x_tag4, "audio");

            if ((var = switch_channel_get_variable(channel, "rtp_use_ssrc"))) {
                if (!(x_tag4 = switch_xml_add_child_d(x_tag3, "src-id", off4++))) {
                    abort();
                }
                switch_xml_set_txt_d(x_tag4, var);
            }

            if (!(x_tag4 = switch_xml_add_child_d(x_tag3, "status", off4++))) {
                abort();
            }
            switch_xml_set_txt_d(x_tag4, audio_flow(np->member));


            if (switch_channel_test_flag(channel, CF_VIDEO)) {
                off4 = 0;

                if (!(x_tag3 = switch_xml_add_child_d(x_tag2, "media", off3++))) {
                    abort();
                }

                snprintf(tmp, sizeof(tmp), "%uv", np->member->id);
                switch_xml_set_attr_d(x_tag3, "id", tmpp);


                if (!(x_tag4 = switch_xml_add_child_d(x_tag3, "type", off4++))) {
                    abort();
                }
                switch_xml_set_txt_d(x_tag4, "video");

                if ((var = switch_channel_get_variable(channel, "rtp_use_video_ssrc"))) {
                    if (!(x_tag4 = switch_xml_add_child_d(x_tag3, "src-id", off4++))) {
                        abort();
                    }
                    switch_xml_set_txt_d(x_tag4, var);
                }

                if (!(x_tag4 = switch_xml_add_child_d(x_tag3, "status", off4++))) {
                    abort();
                }
                switch_xml_set_txt_d(x_tag4, switch_channel_test_flag(channel, CF_HOLD) ? "sendonly" : "sendrecv");

            }
        }

        switch_safe_free(user_uri);
    }

    switch_mutex_unlock(conference->member_mutex);

    off1 = off2 = off3 = off4 = 0;

    xml_text = switch_xml_toxml(xml, SWITCH_TRUE);
    switch_xml_free(xml);

    switch_safe_free(dup_domain);
    switch_safe_free(uri);

    return xml_text;
}

static void conference_cdr_render(conference_obj_t *conference)
{
    switch_xml_t cdr, x_ptr, x_member, x_members, x_conference, x_cp, x_flags, x_tag, x_rejected, x_attempt;
    conference_cdr_node_t *np;
    conference_cdr_reject_t *rp;
    int cdr_off = 0, conf_off = 0;
    char str[512];
    char *path = NULL, *xml_text;
    int fd;

    if (zstr(conference->log_dir) && (conference->cdr_event_mode == CDRE_NONE)) return;

    if (!conference->cdr_nodes && !conference->cdr_rejected) return;

    if (!(cdr = switch_xml_new("cdr"))) {
        abort();
    }

    if (!(x_conference = switch_xml_add_child_d(cdr, "conference", cdr_off++))) {
        abort();
    }

    if (!(x_ptr = switch_xml_add_child_d(x_conference, "name", conf_off++))) {
        abort();
    }
    switch_xml_set_txt_d(x_ptr, conference->name);

    if (!(x_ptr = switch_xml_add_child_d(x_conference, "hostname", conf_off++))) {
        abort();
    }
    switch_xml_set_txt_d(x_ptr, switch_core_get_hostname());

    if (!(x_ptr = switch_xml_add_child_d(x_conference, "rate", conf_off++))) {
        abort();
    }
    switch_snprintf(str, sizeof(str), "%d", conference->rate);
    switch_xml_set_txt_d(x_ptr, str);

    if (!(x_ptr = switch_xml_add_child_d(x_conference, "interval", conf_off++))) {
        abort();
    }
    switch_snprintf(str, sizeof(str), "%d", conference->interval);
    switch_xml_set_txt_d(x_ptr, str);


    if (!(x_ptr = switch_xml_add_child_d(x_conference, "start_time", conf_off++))) {
        abort();
    }
    switch_xml_set_attr_d(x_ptr, "type", "UNIX-epoch");
    switch_snprintf(str, sizeof(str), "%ld", (long)conference->start_time);
    switch_xml_set_txt_d(x_ptr, str);


    if (!(x_ptr = switch_xml_add_child_d(x_conference, "end_time", conf_off++))) {
        abort();
    }
    switch_xml_set_attr_d(x_ptr, "endconf_forced", switch_test_flag(conference, CFLAG_ENDCONF_FORCED) ? "true" : "false");
    switch_xml_set_attr_d(x_ptr, "type", "UNIX-epoch");
    switch_snprintf(str, sizeof(str), "%ld", (long)conference->end_time);
    switch_xml_set_txt_d(x_ptr, str);



    if (!(x_members = switch_xml_add_child_d(x_conference, "members", conf_off++))) {
        abort();
    }

    for (np = conference->cdr_nodes; np; np = np->next) {
        int member_off = 0;
        int flag_off = 0;


        if (!(x_member = switch_xml_add_child_d(x_members, "member", conf_off++))) {
            abort();
        }

        switch_xml_set_attr_d(x_member, "type", np->cp ? "caller" : "recording_node");

        if (!(x_ptr = switch_xml_add_child_d(x_member, "join_time", member_off++))) {
            abort();
        }
        switch_xml_set_attr_d(x_ptr, "type", "UNIX-epoch");
        switch_snprintf(str, sizeof(str), "%ld", (long) np->join_time);
        switch_xml_set_txt_d(x_ptr, str);


        if (!(x_ptr = switch_xml_add_child_d(x_member, "leave_time", member_off++))) {
            abort();
        }
        switch_xml_set_attr_d(x_ptr, "type", "UNIX-epoch");
        switch_snprintf(str, sizeof(str), "%ld", (long) np->leave_time);
        switch_xml_set_txt_d(x_ptr, str);

        if (np->cp) {
            x_flags = switch_xml_add_child_d(x_member, "flags", member_off++);
            switch_assert(x_flags);

            x_tag = switch_xml_add_child_d(x_flags, "is_moderator", flag_off++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(np, MFLAG_MOD) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "end_conference", flag_off++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(np, MFLAG_ENDCONF) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "was_kicked", flag_off++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(np, MFLAG_KICKED) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "is_ghost", flag_off++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(np, MFLAG_GHOST) ? "true" : "false");

            if (!(x_cp = switch_xml_add_child_d(x_member, "caller_profile", member_off++))) {
                abort();
            }
            switch_ivr_set_xml_profile_data(x_cp, np->cp, 0);
        }

        if (!zstr(np->record_path)) {
            if (!(x_ptr = switch_xml_add_child_d(x_member, "record_path", member_off++))) {
                abort();
            }
            switch_xml_set_txt_d(x_ptr, np->record_path);
        }


    }

    if (!(x_rejected = switch_xml_add_child_d(x_conference, "rejected", conf_off++))) {
        abort();
    }

    for (rp = conference->cdr_rejected; rp; rp = rp->next) {
        int attempt_off = 0;
        int tag_off = 0;

        if (!(x_attempt = switch_xml_add_child_d(x_rejected, "attempt", attempt_off++))) {
            abort();
        }

        if (!(x_ptr = switch_xml_add_child_d(x_attempt, "reason", tag_off++))) {
            abort();
        }
        if (rp->reason == CDRR_LOCKED) {
            switch_xml_set_txt_d(x_ptr, "conference_locked");
        } else if (rp->reason == CDRR_MAXMEMBERS) {
            switch_xml_set_txt_d(x_ptr, "max_members_reached");
        } else     if (rp->reason == CDRR_PIN) {
            switch_xml_set_txt_d(x_ptr, "invalid_pin");
        }

        if (!(x_ptr = switch_xml_add_child_d(x_attempt, "reject_time", tag_off++))) {
            abort();
        }
        switch_xml_set_attr_d(x_ptr, "type", "UNIX-epoch");
        switch_snprintf(str, sizeof(str), "%ld", (long) rp->reject_time);
        switch_xml_set_txt_d(x_ptr, str);

        if (rp->cp) {
            if (!(x_cp = switch_xml_add_child_d(x_attempt, "caller_profile", attempt_off++))) {
                abort();
            }
            switch_ivr_set_xml_profile_data(x_cp, rp->cp, 0);
        }
    }

    xml_text = switch_xml_toxml(cdr, SWITCH_TRUE);


    if (!zstr(conference->log_dir)) {
        path = switch_mprintf("%s%s%s.cdr.xml", conference->log_dir, SWITCH_PATH_SEPARATOR, conference->uuid_str);



#ifdef _MSC_VER
        if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) > -1) {
#else
        if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) > -1) {
#endif
            int wrote;
            wrote = write(fd, xml_text, (unsigned) strlen(xml_text));
            wrote++;
            close(fd);
            fd = -1;
        } else {
            char ebuf[512] = { 0 };
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error writing [%s][%s]\n",
                    path, switch_strerror_r(errno, ebuf, sizeof(ebuf)));
        }

        if (conference->cdr_event_mode != CDRE_NONE) {
            switch_event_t *event;

            if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_CDR) == SWITCH_STATUS_SUCCESS)
        //    if (switch_event_create(&event, SWITCH_EVENT_CDR) == SWITCH_STATUS_SUCCESS)
            {
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "CDR-Source", CONF_EVENT_CDR);
                if (conference->cdr_event_mode == CDRE_AS_CONTENT) {
                    switch_event_set_body(event, xml_text);
                } else {
                    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "CDR-Path", path);
                }
                switch_event_fire(&event);
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not create CDR event");
            }
        }
    }

       switch_safe_free(path);
    switch_safe_free(xml_text);
    switch_xml_free(cdr);
}

static cJSON *conference_json_render(conference_obj_t *conference, cJSON *req)
{
    char tmp[30];
    const char *domain;    const char *name;
    char *dup_domain = NULL;
    char *uri;
    conference_cdr_node_t *np;
    char *tmpp = tmp;
    cJSON *json = cJSON_CreateObject(), *jusers = NULL, *jold_users = NULL, *juser = NULL, *jvars = NULL;

    switch_assert(json);

    switch_mutex_lock(conference->mutex);
    switch_snprintf(tmp, sizeof(tmp), "%u", conference->doc_version);
    conference->doc_version++;
    switch_mutex_unlock(conference->mutex);

    if (!(name = conference->name)) {
        name = "conference";
    }

    if (!(domain = conference->domain)) {
        dup_domain = switch_core_get_domain(SWITCH_TRUE);
        if (!(domain = dup_domain)) {
            domain = "cluecon.com";
        }
    }


    uri = switch_mprintf("%s@%s", name, domain);
    json_add_child_string(json, "entity", uri);
    json_add_child_string(json, "conferenceDescription", conference->desc ? conference->desc : "FreeSWITCH Conference");
    json_add_child_string(json, "conferenceState", "active");
    switch_snprintf(tmp, sizeof(tmp), "%u", conference->count);
    json_add_child_string(json, "userCount", tmp);

    jusers = json_add_child_array(json, "users");
    jold_users = json_add_child_array(json, "oldUsers");

    switch_mutex_lock(conference->member_mutex);

    for (np = conference->cdr_nodes; np; np = np->next) {
        char *user_uri = NULL;
        switch_channel_t *channel = NULL;
        switch_time_exp_t tm;
        switch_size_t retsize;
        const char *fmt = "%Y-%m-%dT%H:%M:%S%z";
        char *p;

        if (np->record_path || !np->cp) {
            continue;
        }

        //if (!np->cp || (np->member && !np->member->session) || np->leave_time) { /* for now we'll remove participants when they leave */
        //continue;
        //}

        if (np->member && np->member->session) {
            channel = switch_core_session_get_channel(np->member->session);
        }

        juser = cJSON_CreateObject();

        if (channel) {
            const char *uri = switch_channel_get_variable_dup(channel, "conference_invite_uri", SWITCH_FALSE, -1);

            if (uri) {
                user_uri = strdup(uri);
            }
        }

        if (np->cp) {

            if (!user_uri) {
                user_uri = switch_mprintf("%s@%s", np->cp->caller_id_number, domain);
            }

            json_add_child_string(juser, "entity", user_uri);
            json_add_child_string(juser, "displayText", np->cp->caller_id_name);
        }

        //if (np->record_path) {
            //json_add_child_string(juser, "recordingPATH", np->record_path);
        //}

        json_add_child_string(juser, "status", np->leave_time ? "disconnected" : "connected");

        switch_time_exp_lt(&tm, (switch_time_t) conference->start_time * 1000000);
        switch_strftime_nocheck(tmp, &retsize, sizeof(tmp), fmt, &tm);
        p = end_of_p(tmpp) -1;
        snprintf(p, 4, ":00");

        json_add_child_string(juser, "joinTime", tmpp);

        snprintf(tmp, sizeof(tmp), "%u", np->id);
        json_add_child_string(juser, "memberId", tmp);

        jvars = cJSON_CreateObject();

        if (!np->member && np->var_event) {
            switch_json_add_presence_data_cols(np->var_event, jvars, "PD-");
        } else if (np->member) {
            const char *var;
            const char *prefix = NULL;
            switch_event_t *var_event = NULL;
            switch_event_header_t *hp;
            int all = 0;

            switch_channel_get_variables(channel, &var_event);

            if ((prefix = switch_event_get_header(var_event, "json_conf_var_prefix"))) {
                all = strcasecmp(prefix, "__all__");
            } else {
                prefix = "json_";
            }

            for(hp = var_event->headers; hp; hp = hp->next) {
                if (all || !strncasecmp(hp->name, prefix, strlen(prefix))) {
                    json_add_child_string(jvars, hp->name, hp->value);
                }
            }

            switch_json_add_presence_data_cols(var_event, jvars, "PD-");

            switch_event_destroy(&var_event);

            if ((var = switch_channel_get_variable(channel, "rtp_use_ssrc"))) {
                json_add_child_string(juser, "rtpAudioSSRC", var);
            }

            json_add_child_string(juser, "rtpAudioDirection", audio_flow(np->member));


            if (switch_channel_test_flag(channel, CF_VIDEO)) {
                if ((var = switch_channel_get_variable(channel, "rtp_use_video_ssrc"))) {
                    json_add_child_string(juser, "rtpVideoSSRC", var);
                }

                json_add_child_string(juser, "rtpVideoDirection", switch_channel_test_flag(channel, CF_HOLD) ? "sendonly" : "sendrecv");
            }
        }

        if (jvars) {
            json_add_child_obj(juser, "variables", jvars);
        }

        cJSON_AddItemToArray(np->leave_time ? jold_users : jusers, juser);

        switch_safe_free(user_uri);
    }

    switch_mutex_unlock(conference->member_mutex);

    switch_safe_free(dup_domain);
    switch_safe_free(uri);

    return json;
}

static void conference_la_event_channel_handler(const char *event_channel, cJSON *json, const char *key, switch_event_channel_id_t id)
{
    switch_live_array_parse_json(json, globals.event_channel_id);
}

static void conference_event_channel_handler(const char *event_channel, cJSON *json, const char *key, switch_event_channel_id_t id)
{
    char *domain = NULL, *name = NULL;
    conference_obj_t *conference = NULL;
    cJSON *data, *reply = NULL, *conf_desc = NULL;
    const char *action = NULL;
    char *dup = NULL;

    if ((data = cJSON_GetObjectItem(json, "data"))) {
        action = cJSON_GetObjectCstr(data, "action");
    }

    if (!action) action = "";

    reply = cJSON_Duplicate(json, 1);
    cJSON_DeleteItemFromObject(reply, "data");

    if ((name = strchr(event_channel, '.'))) {
        dup = strdup(name + 1);
        switch_assert(dup);
        name = dup;

        if ((domain = strchr(name, '@'))) {
            *domain++ = '\0';
        }
    }

    if (!strcasecmp(action, "bootstrap")) {
        if (!zstr(name) && (conference = conference_find(name, domain))) {
            conf_desc = conference_json_render(conference, json);
        } else {
            conf_desc = cJSON_CreateObject();
            json_add_child_string(conf_desc, "conferenceDescription", "FreeSWITCH Conference");
            json_add_child_string(conf_desc, "conferenceState", "inactive");
            json_add_child_array(conf_desc, "users");
            json_add_child_array(conf_desc, "oldUsers");
        }
    } else {
        conf_desc = cJSON_CreateObject();
        json_add_child_string(conf_desc, "error", "Invalid action");
    }

    json_add_child_string(conf_desc, "action", "conferenceDescription");

    cJSON_AddItemToObject(reply, "data", conf_desc);

    switch_safe_free(dup);

    switch_event_channel_broadcast(event_channel, &reply, modname, globals.event_channel_id);
}


static switch_status_t conference_add_event_data(conference_obj_t *conference, switch_event_t *event)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Conference-Name", conference->name);
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Conference-Size", "%u", conference->count);
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Conference-Ghosts", "%u", conference->count_ghosts);
    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Conference-Profile-Name", conference->profile_name);
    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Conference-Unique-ID", conference->uuid_str);

    return status;
}

static switch_status_t conference_add_event_member_data(conference_member_t *member, switch_event_t *event)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    if (!member)
        return status;

    if (member->conference) {
        status = conference_add_event_data(member->conference, event);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Floor", "%s", (member == member->conference->floor_holder) ? "true" : "false" );
    }

    if (member->session) {
        switch_channel_t *channel = switch_core_session_get_channel(member->session);

        if (member->verbose_events) {
            switch_channel_event_set_data(channel, event);
        } else {
            switch_channel_event_set_basic_data(channel, event);
        }
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Video", "%s",
                                switch_channel_test_flag(switch_core_session_get_channel(member->session), CF_VIDEO) ? "true" : "false" );

    }

    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Hear", "%s", switch_test_flag(member, MFLAG_CAN_HEAR) ? "true" : "false" );
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Speak", "%s", switch_test_flag(member, MFLAG_CAN_SPEAK) ? "true" : "false");
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Talking", "%s", switch_test_flag(member, MFLAG_TALKING) ? "true" : "false" );
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Mute-Detect", "%s", switch_test_flag(member, MFLAG_MUTE_DETECT) ? "true" : "false" );
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Mute-Fake", "%s", switch_test_flag(member, MFLAG_USE_FAKE_MUTE) ? "true" : "false" );
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Mute-Locked", "%s", switch_test_flag(member, MFLAG_CAN_MUTE) ? "false" : "true" );
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Member-ID", "%u", member->id);
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Member-Type", "%s", switch_test_flag(member, MFLAG_MOD) ? "moderator" : "member");
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Member-Ghost", "%s", switch_test_flag(member, MFLAG_GHOST) ? "true" : "false");
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Energy-Level", "%d", member->energy_level);
    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Current-Energy", "%d", member->score);

    return status;
}

/* Return a Distinct ID # */
static uint32_t next_member_id(void)
{
    uint32_t id;

    switch_mutex_lock(globals.id_mutex);
    id = ++globals.id_pool;
    switch_mutex_unlock(globals.id_mutex);

    return id;
}

/* if other_member has a relationship with member, produce it */
static conference_relationship_t *member_get_relationship(conference_member_t *member, conference_member_t *other_member)
{
    conference_relationship_t *rel = NULL, *global = NULL;

    if (member == NULL || other_member == NULL || member->relationships == NULL)
        return NULL;

    lock_member(member);
    lock_member(other_member);

    for (rel = member->relationships; rel; rel = rel->next) {
        if (rel->id == other_member->id) {
            break;
        }

        /* 0 matches everyone. (We will still test the others because a real match carries more clout) */
        if (rel->id == 0) {
            global = rel;
        }
    }

    unlock_member(other_member);
    unlock_member(member);

    return rel ? rel : global;
}
    
static conference_member_t *find_member_in_list(conference_member_t *list, uint32_t id) {
    conference_member_t *member = NULL;

    for (member = list; member; member = member->next) {
        
        if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
            continue;
        }
        
        if (member->id == id) {
            break;
        }
    }
    return member;
}

static conference_member_t *find_member_in_conference(conference_obj_t *conference, uint32_t id)
{
    conference_member_t *member = NULL;

    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        if ((member = find_member_in_list(conference->member_lists[i], id))) {
            break;
        }
    }
    return member;
}

/* traverse the conference member list for the specified member id and return it's pointer */
static conference_member_t *conference_member_get(conference_obj_t *conference, uint32_t id)
{
    conference_member_t *member = NULL;

    switch_assert(conference != NULL);
    if (!id) {
        return NULL;
    }

    switch_mutex_lock(conference->member_mutex);
    member = find_member_in_conference(conference, id);

    if (member) {
        if (!switch_test_flag(member, MFLAG_INTREE) ||
            switch_test_flag(member, MFLAG_KICKED) ||
            (member->session && !switch_channel_up(switch_core_session_get_channel(member->session)))) {

            /* member is kicked or hanging up so forget it */
            member = NULL;
        }
    }

    if (member) {
        if (switch_thread_rwlock_tryrdlock(member->rwlock) != SWITCH_STATUS_SUCCESS) {
            /* if you cant readlock it's way to late to do anything */
            member = NULL;
        }
    }

    switch_mutex_unlock(conference->member_mutex);

    return member;
}

/* stop the specified recording */
static switch_status_t conference_record_stop(conference_obj_t *conference, switch_stream_handle_t *stream, char *path)
{
    conference_member_t *member = NULL;
    int count = 0;

    switch_assert(conference != NULL);
    switch_mutex_lock(conference->member_mutex);
    for (member = conference->member_lists[eMemberListTypes_Recorders]; member; member = member->next) {
        if (switch_test_flag(member, MFLAG_NOCHANNEL) && (!path || !strcmp(path, member->rec_path))) {
            if (!switch_test_flag(conference, CFLAG_CONF_RESTART_AUTO_RECORD) && member->rec && member->rec->autorec) {
                stream->write_function(stream, "Stopped AUTO recording file %s (Auto Recording Now Disabled)\n", member->rec_path);
                conference->auto_record = 0;
            } else {
                stream->write_function(stream, "Stopped recording file %s\n", member->rec_path);
            }

            clear_member_state_locked(member, MFLAG_RUNNING);
            count++;

        }
    }

    conference->record_count -= count;

    switch_mutex_unlock(conference->member_mutex);
    return count;
}
/* stop/pause/resume the specified recording */
static switch_status_t conference_record_action(conference_obj_t *conference, char *path, recording_action_type_t action)
{
    conference_member_t *member = NULL;
    int count = 0;
    //switch_file_handle_t *fh = NULL;

    switch_assert(conference != NULL);
    switch_mutex_lock(conference->member_mutex);
    for (member = conference->member_lists[eMemberListTypes_Recorders]; member; member = member->next)
    {
        if (switch_test_flag(member, MFLAG_NOCHANNEL) && (!path || !strcmp(path, member->rec_path)))
        {
            //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,    "Action: %d\n", action);
            switch (action)
            {
                case REC_ACTION_STOP:
                        clear_member_state_locked(member, MFLAG_RUNNING);
                        count++;
                        break;
                case REC_ACTION_PAUSE:
                        set_member_state_locked(member, MFLAG_PAUSE_RECORDING);
                        count = 1;
                        break;
                case REC_ACTION_RESUME:
                        clear_member_state_locked(member, MFLAG_PAUSE_RECORDING);
                        count = 1;
                        break;
                    }
                }
    }
    switch_mutex_unlock(conference->member_mutex);
    return count;
}


/* Add a custom relationship to a member */
static conference_relationship_t *member_add_relationship(conference_member_t *member, uint32_t id)
{
    conference_relationship_t *rel = NULL;

    if (member == NULL || id == 0 || !(rel = switch_core_alloc(member->pool, sizeof(*rel))))
        return NULL;

    rel->id = id;


    lock_member(member);
    switch_mutex_lock(member->conference->member_mutex);
    member->conference->relationship_total++;
    switch_mutex_unlock(member->conference->member_mutex);
    rel->next = member->relationships;
    member->relationships = rel;
    unlock_member(member);

    return rel;
}

/* Remove a custom relationship from a member */
static switch_status_t member_del_relationship(conference_member_t *member, uint32_t id)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    conference_relationship_t *rel, *last = NULL;

    if (member == NULL || id == 0)
        return status;

    lock_member(member);
    for (rel = member->relationships; rel; rel = rel->next) {
        if (rel->id == id) {
            /* we just forget about rel here cos it was allocated by the member's pool
               it will be freed when the member is */
            status = SWITCH_STATUS_SUCCESS;
            if (last) {
                last->next = rel->next;
            } else {
                member->relationships = rel->next;
            }

            switch_mutex_lock(member->conference->member_mutex);
            member->conference->relationship_total--;
            switch_mutex_unlock(member->conference->member_mutex);

        }
        last = rel;
    }
    unlock_member(member);

    return status;
}

static void send_json_event(conference_obj_t *conference)
{
    cJSON *event, *conf_desc = NULL;
    char *name = NULL, *domain = NULL, *dup_domain = NULL;
    char *event_channel = NULL;

    if (!switch_test_flag(conference, CFLAG_JSON_EVENTS)) {
        return;
    }

    conf_desc = conference_json_render(conference, NULL);

    if (!(name = conference->name)) {
        name = "conference";
    }

    if (!(domain = conference->domain)) {
        dup_domain = switch_core_get_domain(SWITCH_TRUE);
        if (!(domain = dup_domain)) {
            domain = "cluecon.com";
        }
    }

    event_channel = switch_mprintf("conference.%q@%q", name, domain);

    event = cJSON_CreateObject();

    json_add_child_string(event, "eventChannel", event_channel);
    cJSON_AddItemToObject(event, "data", conf_desc);

    switch_event_channel_broadcast(event_channel, &event, modname, globals.event_channel_id);

    switch_safe_free(dup_domain);
    switch_safe_free(event_channel);
}

static void send_rfc_event(conference_obj_t *conference)
{
    switch_event_t *event;
    char *body;
    char *name = NULL, *domain = NULL, *dup_domain = NULL;

    if (!switch_test_flag(conference, CFLAG_RFC4579)) {
        return;
    }

    if (!(name = conference->name)) {
        name = "conference";
    }

    if (!(domain = conference->domain)) {
        dup_domain = switch_core_get_domain(SWITCH_TRUE);
        if (!(domain = dup_domain)) {
            domain = "cluecon.com";
        }
    }


    if (switch_event_create(&event, SWITCH_EVENT_CONFERENCE_DATA) == SWITCH_STATUS_SUCCESS) {
        event->flags |= EF_UNIQ_HEADERS;

        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "conference-name", name);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "conference-domain", domain);

        body = conference_rfc4579_render(conference, NULL, event);
        switch_event_add_body(event, "%s", body);
        free(body);
        switch_event_fire(&event);
    }

    switch_safe_free(dup_domain);

}



static void send_conference_notify(conference_obj_t *conference, const char *status, const char *call_id, switch_bool_t final)
{
    switch_event_t *event;
    char *name = NULL, *domain = NULL, *dup_domain = NULL;

    if (!switch_test_flag(conference, CFLAG_RFC4579)) {
        return;
    }

    if (!(name = conference->name)) {
        name = "conference";
    }

    if (!(domain = conference->domain)) {
        dup_domain = switch_core_get_domain(SWITCH_TRUE);
        if (!(domain = dup_domain)) {
            domain = "cluecon.com";
        }
    }


    if (switch_event_create(&event, SWITCH_EVENT_CONFERENCE_DATA) == SWITCH_STATUS_SUCCESS) {
        event->flags |= EF_UNIQ_HEADERS;

        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "conference-name", name);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "conference-domain", domain);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "conference-event", "refer");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "call_id", call_id);

        if (final) {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "final", "true");
        }


        switch_event_add_body(event, "%s", status);
        switch_event_fire(&event);
    }

    switch_safe_free(dup_domain);

}

static void member_update_status_field(conference_member_t *member)
{
    char *str, *vstr = "", display[128] = "";

    if (!member->conference->la) {
        return;
    }

    switch_live_array_lock(member->conference->la);

    if (!switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        if (switch_test_flag(member, MFLAG_USE_FAKE_MUTE)) {
            str = "MUTE (FAKE)";
        } else {
            str = "MUTE";
        }
    } else if (switch_channel_test_flag(member->channel, CF_HOLD)) {
        str = "HOLD";
    } else if (member == member->conference->floor_holder) {
        if (switch_test_flag(member, MFLAG_TALKING)) {
            str = "TALKING (FLOOR)";
        } else {
            str = "FLOOR";
        }
    } else if (switch_test_flag(member, MFLAG_TALKING)) {
        str = "TALKING";
    } else {
        str = "ACTIVE";
    }

    switch_snprintf(display, sizeof(display), "%s%s", str, vstr);


    free(member->status_field->valuestring);
    member->status_field->valuestring = strdup(display);

    switch_live_array_add(member->conference->la, switch_core_session_get_uuid(member->session), -1, &member->json, SWITCH_FALSE);
    switch_live_array_unlock(member->conference->la);
}

static void adv_la(conference_obj_t *conference, conference_member_t *member, switch_bool_t join)
{
    if (conference && conference->la && member->session) {
        cJSON *msg, *data;
        const char *uuid = switch_core_session_get_uuid(member->session);
        const char *cookie = switch_channel_get_variable(member->channel, "event_channel_cookie");

        msg = cJSON_CreateObject();
        data = json_add_child_obj(msg, "pvtData", NULL);

        cJSON_AddItemToObject(msg, "eventChannel", cJSON_CreateString(uuid));
        cJSON_AddItemToObject(msg, "eventType", cJSON_CreateString("channelPvtData"));

        cJSON_AddItemToObject(data, "action", cJSON_CreateString(join ? "conference-liveArray-join" : "conference-liveArray-part"));
        cJSON_AddItemToObject(data, "laChannel", cJSON_CreateString(conference->la_event_channel));
        cJSON_AddItemToObject(data, "laName", cJSON_CreateString(conference->la_name));

        if (cookie) {
            switch_event_channel_permission_modify(cookie, conference->la_event_channel, join);
        }

        switch_event_channel_broadcast(uuid, &msg, modname, globals.event_channel_id);
    }
}

static void remove_member_from_list(conference_member_t **list, conference_obj_t *conference, conference_member_t *member) {
    conference_member_t *imember, *last = NULL;
    
    for (imember = *list; imember; imember = imember->next) {
        if (imember == member) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                              "M(%s)/I(%s):U(%s) removing from meeting loop\n",
                              conference->meeting_id, conference->instance_id, member->mname);
            if (last) {
                last->next = imember->next;
            } else {
                *list = imember->next;
            }
            break;
        }
        last = imember;
    }
}

static void add_member_to_list(conference_member_t **list, conference_member_t *member) {
    member->next = *list;
    *list = member;
}

/* Gain exclusive access and add the member to the list */
static switch_status_t conference_add_member(conference_obj_t *conference, conference_member_t *member)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_event_t *event;
    char msg[512];                /* conference count announcement */
    call_list_t *call_list = NULL;
    switch_channel_t *channel = NULL;
    const char *controls = NULL;
    conference_member_t *exist_mem;
    filelist_t *pFL;
    switch_codec_implementation_t impl ={0};
    conference_write_codec_t *new_write_codec;

    switch_assert(conference != NULL);
    switch_assert(member != NULL);

    switch_mutex_lock(conference->mutex);
    switch_mutex_lock(member->audio_in_mutex);
    switch_mutex_lock(member->audio_out_mutex);
    lock_member(member);
    switch_mutex_lock(conference->member_mutex);

    member->join_time = switch_epoch_time_now(NULL);
    member->conference = conference;
    member->energy_level = conference->energy_level;
    member->score_iir = 0;
    member->verbose_events = conference->verbose_events;
    member->was_active = SWITCH_FALSE;

    meo_initialize(&member->meo);
    
    switch_queue_create(&member->dtmf_queue, 100, member->pool);

    if (!switch_test_flag(member,MFLAG_NOCHANNEL)){

        /* get a pointer to the codec implementation */
        impl = member->orig_read_impl;

        /* Check to see if this codec already exists for this conference */
        for (new_write_codec = conference->ceo.cwc[0]; new_write_codec; new_write_codec = new_write_codec->next) {
            if ((new_write_codec->codec_id == impl.codec_id) && (new_write_codec->impl_id == impl.impl_id)){
                /* codec already in the list */
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, " codec already registered codec_id=%d impl_id=%d ianacode=%d\n",
                                  impl.codec_id, impl.impl_id, impl.ianacode);
                break;
            }
        }
        
        /* Didn't find the codec so add it */
        if (new_write_codec == NULL)
        {
            /* add new conference write codec, allocate new conference entry */
            if (ceo_write_new_wc(&conference->ceo, impl.codec_id, impl.impl_id, impl.ianacode) != SWITCH_STATUS_SUCCESS) {
                switch_mutex_unlock(conference->member_mutex);
                unlock_member(member);
                switch_mutex_unlock(member->audio_out_mutex);
                switch_mutex_unlock(member->audio_in_mutex);
                switch_mutex_lock(conference->mutex);
                return SWITCH_STATUS_FALSE;
            }
        }

        switch_mutex_lock(globals.filelist_mutex);
        for (pFL = globals.filelist[0]; pFL != NULL; pFL = pFL->next) {
            if ((pFL->codec_id == impl.codec_id) && (pFL->impl_id == impl.impl_id)){
                /* codec already in the list */
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, " play listcodec already registered codec_id=%d ianacode=%d\n",
                                  impl.codec_id, impl.ianacode);
                break;
            }
        }

        if (pFL == NULL) {
            for (int i = 0; i < MAX_NUMBER_OF_OUTPUT_THREADS; i++) {
                /* add new conference write codec, allocate new conference entry */
                if ((pFL = switch_core_alloc(globals.playlist_pool, sizeof(*pFL))) == 0) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "no memory for new filelist\n");
                    switch_mutex_unlock(globals.filelist_mutex);
                    switch_mutex_unlock(conference->member_mutex);
                    unlock_member(member);
                    switch_mutex_unlock(member->audio_out_mutex);
                    switch_mutex_unlock(member->audio_in_mutex);
                    switch_mutex_lock(conference->mutex);
                    return SWITCH_STATUS_FALSE;
                }
                memset(pFL, 0, sizeof(*pFL));

                filelist_init(pFL, globals.playlist_pool);
                pFL->codec_id = impl.codec_id;
                pFL->impl_id = impl.impl_id;
                pFL->next = globals.filelist[i];
                globals.filelist[i] = pFL;
            }
            member->meo.filelist = filelist_get(globals.filelist[0], impl.codec_id, impl.impl_id);
        } else {
            member->meo.filelist = pFL;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                              " Filelist already in use id %d, codec implementation %d\n",
                              pFL->codec_id, pFL->impl_id);
        }
        switch_mutex_unlock(globals.filelist_mutex);
    }
    
    if (switch_test_flag(conference, CFLAG_INDICATE_MUTE))
    {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "Conference mute all flag enabled\n");
        clear_member_state_locked(member, MFLAG_CAN_SPEAK);
        clear_member_state_locked(member, MFLAG_TALKING);
        
        set_member_state_locked(member, MFLAG_INDICATE_MUTE);
    }
    /* check for mute_nonmoderator conference flag */
    /* temporary comment this because i'm not sure if we still need it
    if (!switch_test_flag(member, MFLAG_MOD) &&
        switch_test_flag(conference, CFLAG_INDICATE_MUTE_NONMODERATOR))
    {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Conference mute non_moderator flag enabled\n");
        clear_member_state_locked(member, MFLAG_CAN_SPEAK);
        clear_member_state_locked(member, MFLAG_TALKING);
    }*/
        /* check for {un}mute locked conference state */
    if (switch_test_flag(conference, CFLAG_INDICATE_LOCK_MUTE))
    {
        conf_api_sub_lock_mute(member, NULL, NULL);
    }
    
    member->next = NULL;

    if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, 
                          "Adding member %d to speakers list\n", member->id);
        add_member_to_list(&conference->member_lists[eMemberListTypes_Speakers], member);

    } else if (member->rec) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                          "Adding member %d to recorders list\n", member->id);
        add_member_to_list(&conference->member_lists[eMemberListTypes_Recorders], member);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, 
                          "Adding member %d to listeners list\n", member->id);
        add_member_to_list(&conference->member_lists[eMemberListTypes_Listeners], member);

        member->frame_max = member->frame_max_on_mute;
    }

    set_member_state_locked(member, MFLAG_INTREE);
    switch_mutex_unlock(conference->member_mutex);
    conference_cdr_add(member);

    if (!switch_test_flag(member, MFLAG_NOCHANNEL)) {
        if (switch_test_flag(member, MFLAG_GHOST)) {
            conference->count_ghosts++;
        } else {
            conference->count++;
        }

        if (switch_test_flag(member, MFLAG_ENDCONF)) {
            if (conference->end_count++) {
                conference->endconf_time = 0;
            }
        }

        conference_send_presence(conference);

        channel = switch_core_session_get_channel(member->session);

        switch_channel_set_variable_printf(channel, "conference_member_id", "%d", member->id);
        switch_channel_set_variable_printf(channel, "conference_moderator", "%s", switch_test_flag(member, MFLAG_MOD) ? "true" : "false");
        switch_channel_set_variable_printf(channel, "conference_ghost", "%s", switch_test_flag(member, MFLAG_GHOST) ? "true" : "false");
        switch_channel_set_variable(channel, "conference_recording", conference->record_filename);
        switch_channel_set_variable(channel, CONFERENCE_UUID_VARIABLE, conference->uuid_str);

        /* fuze */
        /* get attendee's name (and meeting id/instance id)! */
        member->sdpname = switch_channel_get_variable(channel, "email-sdp");
        if (!member->sdpname || strlen(member->sdpname) == 0) {
            member->sdpname = switch_channel_get_variable(channel, "phone-sdp");
        }

        if (switch_channel_get_variable(channel, "fuze_app")) {
            member->fuze_app = SWITCH_TRUE;
            member->frame_max_on_mute = 8;
        } else {
            member->fuze_app = SWITCH_TRUE;
            member->frame_max_on_mute = 1;
        }


        if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
            member->frame_max = 1;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "mid:%s/%d member->frame_max = %d\n",
                              member->mname, member->id, member->frame_max);
        } else if (!member->rec) {
            member->frame_max = member->frame_max_on_mute;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "mid:%s/%d member->frame_max = %d\n",
                              member->mname, member->id, member->frame_max);
        }

        memset(member->mname, 0, MAX_MEMBERNAME_LEN);

        if (member->sdpname) {
            char meeting_id[MAX_MEETING_ID_LEN];
            char instance_id[MAX_INSTANCE_ID_LEN];
            char *pch, *ech;
            int len;

            meeting_id[0] = 0;
            instance_id[0] = 0;

            /* e=sip:LSurazski@fuze.com;transport=tls;ak=K07e263539dfd55f9;id=6669902;inst=5033486 */
            pch = strchr(member->sdpname,'i');
            
            if ((pch = strstr(member->sdpname, "sip:")) != 0) {
                if ((ech = strstr(pch, ";")) != 0) {
                    len = (ech - pch);
                    if (len > (MAX_MEMBERNAME_LEN-10)) {
                        len = MAX_MEMBERNAME_LEN - 10;
                    }
                    strncpy(member->mname, pch+4, len-4);
                } else {
                    switch_snprintf(member->mname, sizeof(member->mname)-1, "m%d", member->id);
                }
            }
            if ((pch = strstr(member->sdpname, "id=")) != 0) {
                if ((ech = strstr(pch, ";")) != 0) {
                    len = (ech - pch);
                    if (len > (MAX_MEETING_ID_LEN-1)) {
                        len = MAX_MEETING_ID_LEN-1;
                    }
                    strncpy(meeting_id, pch+3, len-3);
                }
            }
            if ((pch = strstr(member->sdpname, "inst=")) != 0) {
                len = strlen(member->sdpname) - (pch-member->sdpname);
                if (len > (MAX_INSTANCE_ID_LEN-1)) {
                    len = MAX_INSTANCE_ID_LEN-1;
                }
                strncpy(instance_id, pch+5, len-5);
            }

            if (strstr(member->sdpname, "(chrome)") != 0) {
                strncat(member->mname, "(chrome)", MAX_MEMBERNAME_LEN);
            } else if (strstr(member->sdpname,"(mozilla)") != 0) {
                strncat(member->mname, "(firefox)", MAX_MEMBERNAME_LEN);
            }

            if (strlen(member->mname) == 0) {
                switch_snprintf(member->mname, sizeof(member->mname)-1, "m%d", member->id);
            }

            if (strlen(meeting_id) > 0) {
                if (strlen(conference->meeting_id) > 0) {
                    if (strcmp(conference->meeting_id, meeting_id) != 0) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR,
                                          "Conference member %s came in with meeting id %s previous meeting id %s\n",
                                          member->mname, meeting_id, conference->meeting_id);
                        strncpy(conference->meeting_id, meeting_id, strlen(meeting_id));
                    }
                } else {
                    strncpy(conference->meeting_id, meeting_id, strlen(meeting_id));
                }
            } else {
                if (strlen(conference->meeting_id) == 0) {
                    switch_snprintf(conference->meeting_id, sizeof(conference->meeting_id)-1, "%s", conference->name);
                }
            }
            if (strlen(instance_id) > 0) {
                if (strlen(conference->instance_id) > 0) {
                    if (strcmp(conference->instance_id, instance_id) != 0) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Conference member %s came in with instance id %s previous instance id %s\n",
                                          member->mname, instance_id, conference->instance_id);
                    }
                } else {
                    strncpy(conference->instance_id, instance_id, strlen(instance_id));
                }
            }
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "Meeting Id: %s Instance Id: %s Conference member's name: %s\n",
                              conference->meeting_id, conference->instance_id, member->mname);
        } else {
            if (strlen(conference->meeting_id) == 0) {
                switch_snprintf(conference->meeting_id, sizeof(conference->meeting_id)-1, "%s", conference->name);
            }
            if (strlen(member->mname) == 0) {
                switch_snprintf(member->mname, sizeof(member->mname)-1, "m%d", member->id);
            }
        }

        if (switch_channel_test_flag(channel, CF_VIDEO)) {
            if (switch_test_flag(conference, CFLAG_VIDEO_BRIDGE)) {
                switch_channel_set_flag(channel, CF_VIDEO_ECHO);
                switch_channel_clear_flag(channel, CF_VIDEO_PASSIVE);
            } else {
                switch_channel_clear_flag(channel, CF_VIDEO_ECHO);
            }
            /* Tell the channel to request a fresh vid frame */
            switch_core_session_refresh_video(member->session);

            if (conference->video_floor_holder) {
                switch_mutex_lock(conference->mutex);
                if (conference->video_floor_holder) {
                    switch_core_session_refresh_video(conference->video_floor_holder->session);
                }
                switch_mutex_unlock(conference->mutex);
            }
        }

        if (!switch_channel_get_variable(channel, "conference_call_key")) {
            char *key = switch_core_session_sprintf(member->session, "conf_%s_%s_%s",
            conference->name, conference->domain, switch_channel_get_variable(channel, "caller_id_number"));
            switch_channel_set_variable(channel, "conference_call_key", key);
        }

        if (conference->count > 1 && !switch_test_flag(conference, CFLAG_STARTED)) {
            /*
             * We play conference-starting prompt when:
             *     1. first moderator joins while one or more attendees waiting, or
             *      2. first attendee joins while moderator is waiting.
             */
            if ((conference->count > 1 && find_moderator(conference)) ||
                (switch_test_flag(member, MFLAG_MOD) && get_moderator_count(conference) == 1)) {
                for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
                    for (exist_mem = conference->member_lists[i]; exist_mem; exist_mem = exist_mem->next)
                    {
                        if (!switch_test_flag(exist_mem, MFLAG_NOCHANNEL)) {
                            conference_member_play_file(exist_mem,
                                conference->begin_sound, CONF_DEFAULT_LEADIN, 1);
                        }
                    }
                }
                set_conference_state_unlocked(conference, CFLAG_STARTED);
            }
        }

        if (switch_test_flag(conference, CFLAG_WAIT_MOD) && switch_test_flag(member, MFLAG_MOD)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "Seen moderator first time for: %s. Clearing CFLAG_WAIT_MOD.\n",
                                        conference->name);
                          clear_conference_state_unlocked(conference, CFLAG_WAIT_MOD);
        }

        if (conference->count > 1) {
            if (conference->moh_sound && !switch_test_flag(conference, CFLAG_WAIT_MOD)) {
                                /* stop MoH if any */
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Stopping the async_file for : %s.\n",
                                  conference->name);
                conference_stop_file(conference, FILE_STOP_ASYNC);
            }

            if (!switch_channel_test_app_flag_key("conf_silent", channel, CONF_SILENT_REQ) && !zstr(conference->enter_sound)
                && conference->count < 50) {
                const char * enter_sound = switch_channel_get_variable(channel, "conference_enter_sound");
                if (switch_test_flag(conference, CFLAG_ENTER_SOUND)) {
                    if (!zstr(enter_sound)) {
                        conference_play_file(conference, (char *)enter_sound, CONF_DEFAULT_LEADIN,
                                             switch_core_session_get_channel(member->session), !switch_test_flag(conference, CFLAG_WAIT_MOD) ? 0 : 1, 0);
                    } else {
                        conference_play_file(conference, conference->enter_sound, CONF_DEFAULT_LEADIN, switch_core_session_get_channel(member->session),
                                             !switch_test_flag(conference, CFLAG_WAIT_MOD) ? 0 : 1, 0);
                    }
                }
            } else {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                                  "Skipping enter sound because more than 50 participants (count=%d)\n",
                                  conference->count < 50);
            }
        }

        if (conference->is_recording && conference->recording_started_sound)
        {
            conference_member_play_file(member, conference->recording_started_sound, CONF_DEFAULT_LEADIN, 1);
        }

        call_list = (call_list_t *) switch_channel_get_private(channel, "_conference_autocall_list_");

        if (call_list) {
            char saymsg[1024];
            switch_snprintf(saymsg, sizeof(saymsg), "Auto Calling %d parties", call_list->iteration);
            conference_member_say(member, saymsg, 0);
        } else {

            if (!switch_channel_test_app_flag_key("conf_silent", channel, CONF_SILENT_REQ)) {
                /* announce the total number of members in the conference */
                if (conference->count >= conference->announce_count && conference->announce_count > 1) {
                    switch_snprintf(msg, sizeof(msg), "There are %d callers", conference->count);
                    conference_member_say(member, msg, CONF_DEFAULT_LEADIN);
                } else if (conference->count == 1 && !conference->perpetual_sound) {
                    /* as long as its not a bridge_to conference, announce if person is alone */
                    if (!switch_test_flag(conference, CFLAG_BRIDGE_TO)) {
                        conference_play_alone_sound(conference, member);
                    }
                }
            }
        }

        if (conference->min && conference->count >= conference->min) {
            set_conference_state_unlocked(conference, CFLAG_ENFORCE_MIN);
        }

        if (!switch_channel_test_app_flag_key("conf_silent", channel, CONF_SILENT_REQ) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_member_data(member, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "add-member");
            switch_event_fire(&event);
        }

        switch_channel_clear_app_flag_key("conf_silent", channel, CONF_SILENT_REQ);
        switch_channel_set_app_flag_key("conf_silent", channel, CONF_SILENT_DONE);

        controls = switch_channel_get_variable(channel, "conference_controls");

        if (zstr(controls)) {
            if (!switch_test_flag(member, MFLAG_MOD) || !conference->moderator_controls) {
                controls = conference->caller_controls;
            } else {
                controls = conference->moderator_controls;
            }
        }

        if (zstr(controls)) {
            controls = "default";
        }

        if (strcasecmp(controls, "none")) {
            switch_ivr_dmachine_create(&member->dmachine, "mod_conference", NULL,
                                       conference->ivr_dtmf_timeout, conference->ivr_input_timeout, NULL, NULL, NULL);
            member_bind_controls(member, controls);
        }

    }
    unlock_member(member);
    switch_mutex_unlock(member->audio_out_mutex);
    switch_mutex_unlock(member->audio_in_mutex);

    if (conference->la && member->channel) {
        member->json = cJSON_CreateArray();
        cJSON_AddItemToArray(member->json, cJSON_CreateStringPrintf("%0.4d", member->id));
        cJSON_AddItemToArray(member->json, cJSON_CreateString(switch_channel_get_variable(member->channel, "caller_id_number")));
        cJSON_AddItemToArray(member->json, cJSON_CreateString(switch_channel_get_variable(member->channel, "caller_id_name")));

        cJSON_AddItemToArray(member->json, cJSON_CreateStringPrintf("%s@%s",
                                                                    switch_channel_get_variable(member->channel, "original_read_codec"),
                                                                    switch_channel_get_variable(member->channel, "original_read_rate")
                                                                    ));

        member->status_field = cJSON_CreateString("");
        cJSON_AddItemToArray(member->json, member->status_field);
        member_update_status_field(member);
        //switch_live_array_add_alias(conference->la, switch_core_session_get_uuid(member->session), "conference");
        adv_la(conference, member, SWITCH_TRUE);
        switch_live_array_add(conference->la, switch_core_session_get_uuid(member->session), -1, &member->json, SWITCH_FALSE);

    }

    member->roll_no = conference->member_id_counter++;
    if (channel && switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) &&
            conference->debug_stats_pool &&
                    member->roll_no < 32) {
        strncpy(conference->debug_stats->member_name[member->roll_no],
                        switch_channel_get_caller_profile(channel)->caller_id_number, 31);
    }
    member->one_of_active = SWITCH_FALSE;
    member->consecutive_active_slots = 0;
    member->consecutive_inactive_slots = 0;
    clear_member_state_unlocked(member, MFLAG_ACTIVE_TALKER);


    send_rfc_event(conference);
    send_json_event(conference);

    switch_mutex_unlock(conference->mutex);
    status = SWITCH_STATUS_SUCCESS;

    return status;
}
    
static void conference_reconcile_member_lists(conference_obj_t *conference) {
    conference_member_t *member = NULL, *last = NULL;
    
    switch_mutex_lock(conference->mutex);
    switch_mutex_lock(conference->member_mutex);
    
    for (member = conference->member_lists[eMemberListTypes_Speakers]; member;) {
        if (switch_test_flag(member, MFLAG_NOCHANNEL) || !switch_test_flag(member, MFLAG_RUNNING)) {
            last = member;
            member = member->next;
            continue;
        }
        
        if (!(switch_test_flag(member, MFLAG_CAN_SPEAK) || switch_test_flag(member, MFLAG_USE_FAKE_MUTE)) ||
            switch_core_session_get_cn_state(member->session)) {

            /* shouldn't be in the speakers list */
            /* frame_max: how many frames to buffer before sending a packet out ... just for fun we buffer more frames
             * in an effort to send less packets when we're muted.
             */
            member->frame_max = member->frame_max_on_mute;

            if (last) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, 
                                  "Moving member %d from speakers to listeners\n", member->id);
                last->next = member->next;
                member->next = conference->member_lists[eMemberListTypes_Listeners];
                conference->member_lists[eMemberListTypes_Listeners] = member;

                clear_member_state_locked(member, MFLAG_TALKING);
                switch_set_flag(member, MFLAG_NOTIFY_ACTIVITY);

                member = last->next;
            } else {
                conference_member_t *member_next = member->next;
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, 
                                  "Moving member %d from speakers to listeners\n", member->id);
                member->next = conference->member_lists[eMemberListTypes_Listeners];
                conference->member_lists[eMemberListTypes_Listeners] = member;
                conference->member_lists[eMemberListTypes_Speakers] = member_next;

                clear_member_state_locked(member, MFLAG_TALKING);
                switch_set_flag(member, MFLAG_NOTIFY_ACTIVITY);

                member = member_next;
            }
        } else {
            last = member;
            member = member->next;
        }
    }
    
    last = NULL;
    
    for (member = conference->member_lists[eMemberListTypes_Listeners]; member;) {
        if (switch_test_flag(member, MFLAG_NOCHANNEL) || !switch_test_flag(member, MFLAG_RUNNING)) {
            last = member;
            member = member->next;
            continue;
        }
        
        if ((switch_test_flag(member, MFLAG_CAN_SPEAK) || switch_test_flag(member, MFLAG_USE_FAKE_MUTE)) &&
            !switch_core_session_get_cn_state(member->session)) {

            /* shouldn't be in the listeners list */
            /* frame_max: how many frames to buffer before sending a packet out ... just for fun we buffer more frames
             * in an effort to send less packets when we're muted */
            member->frame_max = 1;

            if (last) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, 
                                  "Moving member %d from listeners to speakers\n", member->id);
                last->next = member->next;
                member->next = conference->member_lists[eMemberListTypes_Speakers];
                conference->member_lists[eMemberListTypes_Speakers] = member;
                member = last->next;
            } else {
                conference_member_t *member_next = member->next;
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, 
                                  "Moving member %d from listeners to speakers\n", member->id);

                member->next = conference->member_lists[eMemberListTypes_Speakers];
                conference->member_lists[eMemberListTypes_Speakers] = member;
                conference->member_lists[eMemberListTypes_Listeners] = member_next;
                member = member_next;
            }
        } else {
            last = member;
            member = member->next;
        }
    }
    switch_mutex_unlock(conference->member_mutex);
    switch_mutex_unlock(conference->mutex);
}

static void conference_set_video_floor_holder(conference_obj_t *conference, conference_member_t *member, switch_bool_t force)
{
    switch_event_t *event;
    conference_member_t *old_member = NULL, *imember = NULL;
    int old_id = 0;

    if (!member) {
        clear_conference_state_unlocked(conference, CFLAG_VID_FLOOR_LOCK);
    }

    if (switch_test_flag(conference, CFLAG_VIDEO_BRIDGE) || (!force && switch_test_flag(conference, CFLAG_VID_FLOOR_LOCK))) {
        return;
    }

    if (conference->video_floor_holder) {
        if (conference->video_floor_holder == member) {
            return;
        } else {
            old_member = conference->video_floor_holder;
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "Dropping video floor %s\n",
                              switch_channel_get_name(old_member->channel));
        }
    }


    switch_mutex_lock(conference->mutex);
    if (!member) {
        for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
            for (imember = conference->member_lists[i]; imember; imember = imember->next) {
                if (imember != conference->video_floor_holder && imember->channel && switch_channel_test_flag(imember->channel, CF_VIDEO)) {
                    member = imember;
                    break;
                }
            }
        }
    }

    if (member) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "Adding video floor %s\n",
                          switch_channel_get_name(member->channel));
        //switch_channel_set_flag(member->channel, CF_VIDEO_PASSIVE);
        switch_core_session_refresh_video(member->session);
        conference->video_floor_holder = member;
        member_update_status_field(member);
    } else {
        conference->video_floor_holder = NULL;
    }

    if (old_member) {
        old_id = old_member->id;
        member_update_status_field(old_member);
        //switch_channel_clear_flag(old_member->channel, CF_VIDEO_PASSIVE);
    }

    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        for (imember = conference->member_lists[i]; imember; imember = imember->next) {
            if (!imember->channel || !switch_channel_test_flag(imember->channel, CF_VIDEO)) {
                continue;
            }
            switch_channel_clear_flag(imember->channel, CF_VIDEO_ECHO);

            if (imember == conference->video_floor_holder) {
                switch_channel_set_flag(imember->channel, CF_VIDEO_PASSIVE);
            } else {
                switch_channel_clear_flag(imember->channel, CF_VIDEO_PASSIVE);
            }

            switch_channel_set_flag(imember->channel, CF_VIDEO_BREAK);
            switch_core_session_kill_channel(imember->session, SWITCH_SIG_BREAK);
            switch_core_session_refresh_video(imember->session);
        }
    }
    
    set_conference_state_unlocked(conference, CFLAG_FLOOR_CHANGE);
    switch_mutex_unlock(conference->mutex);

    if (test_eflag(conference, EFLAG_FLOOR_CHANGE)) {
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT);
        conference_add_event_data(conference, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "video-floor-change");
        if (old_id) {
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Old-ID", "%d", old_id);
        } else {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Old-ID", "none");
        }
        if (conference->video_floor_holder) {
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-ID", "%d", conference->video_floor_holder->id);
        } else {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "New-ID", "none");
        }
        switch_event_fire(&event);
    }

}

static void conference_set_floor_holder(conference_obj_t *conference, conference_member_t *member)
{
    switch_event_t *event;
    conference_member_t *old_member = NULL;
    int old_id = 0;

    if (!switch_test_flag(conference, CFLAG_VIDEO_BRIDGE) &&
        ((conference->video_floor_holder && !member) ||
            (member && member->channel && switch_channel_test_flag(member->channel, CF_VIDEO)))) {
        conference_set_video_floor_holder(conference, member, SWITCH_FALSE);
    }

    if (conference->floor_holder) {
        if (conference->floor_holder == member) {
            return;
        } else {
            old_member = conference->floor_holder;
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "Dropping floor %s\n",
                              switch_channel_get_name(old_member->channel));

        }
    }

    switch_mutex_lock(conference->mutex);
    if (member) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG1, "Adding floor %s\n",
                          switch_channel_get_name(member->channel));

        conference->floor_holder = member;
        member_update_status_field(member);
    } else {
        conference->floor_holder = NULL;
    }


    if (old_member) {
        old_id = old_member->id;
        member_update_status_field(old_member);
    }

    set_conference_state_unlocked(conference, CFLAG_FLOOR_CHANGE);
    switch_mutex_unlock(conference->mutex);

    if (test_eflag(conference, EFLAG_FLOOR_CHANGE)) {
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT);
        conference_add_event_data(conference, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "floor-change");
        if (old_id) {
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Old-ID", "%d", old_id);
        } else {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Old-ID", "none");
        }

        if (conference->floor_holder) {
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-ID", "%d", conference->floor_holder->id);
        } else {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "New-ID", "none");
        }

        switch_event_fire(&event);
    }

}

static switch_status_t conference_file_close(conference_obj_t *conference, conference_file_node_t *node)
{
    switch_event_t *event;
    conference_member_t *member = NULL;

    if (test_eflag(conference, EFLAG_PLAY_FILE_DONE) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {

        conference_add_event_data(conference, event);

        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "seconds", "%ld", (long) node->fh.samples_in / node->fh.native_rate);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "milliseconds", "%ld", (long) node->fh.samples_in / (node->fh.native_rate / 1000));
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "samples", "%ld", (long) node->fh.samples_in);

        if (node->fh.params) {
            switch_event_merge(event, node->fh.params);
        }

        if (node->member_id) {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "play-file-member-done");

            if ((member = conference_member_get(conference, node->member_id))) {
                conference_add_event_member_data(member, event);
                switch_thread_rwlock_unlock(member->rwlock);
            }

        } else {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "play-file-done");
        }

        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "File", node->file);

        if (node->async) {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Async", "true");
        }

        switch_event_fire(&event);
    }

    return switch_core_file_close(&node->fh);
}
    
/* Gain exclusive access and remove the member from the list */
static switch_status_t conference_del_member(conference_obj_t *conference, conference_member_t *member)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_event_t *event;
    conference_file_node_t *member_fnode;
    switch_speech_handle_t *member_sh;
    const char *exit_sound = NULL;
    int i;

    switch_assert(conference != NULL);
    switch_assert(member != NULL);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                      "M(%s)/I(%s):U(%s) conference_del_member\n",
                      conference->meeting_id, conference->instance_id, member->mname);

    switch_thread_rwlock_wrlock(member->rwlock);

    if (member->session && (exit_sound = switch_channel_get_variable(switch_core_session_get_channel(member->session), "conference_exit_sound"))) {
        conference_play_file(conference, (char *)exit_sound, CONF_DEFAULT_LEADIN,
                             switch_core_session_get_channel(member->session), !switch_test_flag(conference, CFLAG_WAIT_MOD) ? 0 : 1, 0);
    }

    lock_member(member);


    conference_cdr_del(member);


    member_fnode = member->fnode;
    member_sh = member->sh;
    member->fnode = NULL;
    member->sh = NULL;
    unlock_member(member);

    if (member->dmachine) {
        switch_ivr_dmachine_destroy(&member->dmachine);
    }

    switch_mutex_lock(conference->mutex);
    switch_mutex_lock(conference->member_mutex);
    switch_mutex_lock(member->audio_in_mutex);
    switch_mutex_lock(member->audio_out_mutex);
    lock_member(member);
    clear_member_state_unlocked(member, MFLAG_INTREE);
    
    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        remove_member_from_list(&conference->member_lists[i], conference, member);
    }
    
    switch_thread_rwlock_unlock(member->rwlock);

    /* Close Unused Handles */
    if (member_fnode) {
        conference_file_node_t *fnode, *cur;
        switch_memory_pool_t *pool;

        fnode = member_fnode;
        while (fnode) {
            cur = fnode;
            fnode = fnode->next;

            if (cur->type == NODE_TYPE_FILE) {
                conference_file_close(conference, cur);
            }

            pool = cur->pool;
            switch_core_destroy_memory_pool(&pool);
        }
    }

    if (member_sh) {
        switch_speech_flag_t flags = SWITCH_SPEECH_FLAG_NONE;
        switch_core_speech_close(&member->lsh, &flags);
    }

    if (member == member->conference->floor_holder) {
        conference_set_floor_holder(member->conference, NULL);
    }


    if (member == member->conference->video_floor_holder) {
        conference_set_video_floor_holder(member->conference, NULL, SWITCH_TRUE);
    }

    member->conference = NULL;

    if (!switch_test_flag(member, MFLAG_NOCHANNEL)) {
        switch_channel_t *channel = switch_core_session_get_channel(member->session);
        if (switch_test_flag(member, MFLAG_GHOST)) {
            conference->count_ghosts--;
        } else {
            conference->count--;
        }

        if (switch_test_flag(member, MFLAG_ENDCONF)) {
            if (!--conference->end_count) {
                //set_conference_state_locked(conference, CFLAG_DESTRUCT);
                conference->endconf_time = switch_epoch_time_now(NULL);
            }
        }

        conference_send_presence(conference);
        switch_channel_set_variable(channel, "conference_call_key", NULL);

        if ((conference->min && switch_test_flag(conference, CFLAG_ENFORCE_MIN) && (conference->count + conference->count_ghosts) < conference->min)
            || (switch_test_flag(conference, CFLAG_DYNAMIC) && (conference->count + conference->count_ghosts == 0))) {
            set_conference_state_unlocked(conference, CFLAG_DESTRUCT);
        } else {
            if (!exit_sound && conference->exit_sound && switch_test_flag(conference, CFLAG_EXIT_SOUND)) {
                conference_play_file(conference, conference->exit_sound, 0, channel, 0, 0);
            }

            if (conference->count == 1 && conference->alone_sound && !switch_test_flag(conference, CFLAG_WAIT_MOD) && !switch_test_flag(member, MFLAG_GHOST) && !conference->is_recording) {
                conference_stop_file(conference, FILE_STOP_ASYNC);
                conference_play_file(conference, conference->alone_sound, 0, channel, 1, 0);
            }
        }

        if (test_eflag(conference, EFLAG_DEL_MEMBER) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_member_data(member, event);
            conference_add_event_data(conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "del-member");
            switch_event_fire(&event);
        }
    }
    switch_mutex_unlock(conference->member_mutex);
    unlock_member(member);
    switch_mutex_unlock(member->audio_out_mutex);
    switch_mutex_unlock(member->audio_in_mutex);


    if (conference->la && member->session) {
        switch_live_array_del(conference->la, switch_core_session_get_uuid(member->session));
        //switch_live_array_clear_alias(conference->la, switch_core_session_get_uuid(member->session), "conference");
        adv_la(conference, member, SWITCH_FALSE);
    }

    send_rfc_event(conference);
    send_json_event(conference);

    for (i = 0; i < MAX_ACTIVE_TALKERS; ++i) {
        if (conference->last_active_talkers[i] == member) {

            if (test_eflag(conference, EFLAG_STOP_TALKING) &&
                switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
                conference_add_event_member_data(member, event);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "stop-talking");
                switch_event_fire(&event);
            }

            conference->last_active_talkers[i] = NULL;
            break;
        }
    }

    switch_mutex_unlock(conference->mutex);
    status = SWITCH_STATUS_SUCCESS;

    return status;
}

#if 0
/* Thread bridging video between two members, there will be two threads if video briding is used */
static void *SWITCH_THREAD_FUNC conference_video_bridge_thread_run(switch_thread_t *thread, void *obj)
{
    struct vid_helper *vh = obj;
    switch_core_session_t *session_a = vh->member_a->session;
    switch_core_session_t *session_b = vh->member_b->session;
    switch_channel_t *channel_a = switch_core_session_get_channel(session_a);
    switch_channel_t *channel_b = switch_core_session_get_channel(session_b);
    switch_status_t status;
    switch_frame_t *read_frame;
    conference_obj_t *conference = vh->member_a->conference;

    switch_thread_rwlock_rdlock(conference->rwlock);
    switch_thread_rwlock_rdlock(vh->member_a->rwlock);
    switch_thread_rwlock_rdlock(vh->member_b->rwlock);


    switch_channel_set_flag(channel_a, CF_VIDEO_PASSIVE);

    /* Acquire locks for both sessions so the helper object and member structures don't get destroyed before we exit */
    switch_core_session_read_lock(session_a);
    switch_core_session_read_lock(session_b);

    vh->up = 1;
    while (vh->up == 1 && switch_test_flag(vh->member_a, MFLAG_RUNNING) && switch_test_flag(vh->member_b, MFLAG_RUNNING) &&
           switch_channel_ready(channel_a) && switch_channel_ready(channel_b))  {

        if (switch_channel_test_flag(channel_a, CF_VIDEO_REFRESH_REQ)) {
            switch_core_session_refresh_video(session_b);
            switch_channel_clear_flag(channel_a, CF_VIDEO_REFRESH_REQ);
        }

        status = switch_core_session_read_video_frame(session_a, &read_frame, SWITCH_IO_FLAG_NONE, 0);
        if (!SWITCH_READ_ACCEPTABLE(status)) {
            break;
        }

        if (!switch_test_flag(read_frame, SFF_CNG)) {
            if (switch_core_session_write_video_frame(session_b, read_frame, SWITCH_IO_FLAG_NONE, 0) != SWITCH_STATUS_SUCCESS) {
                break;
            }
        }
    }
    switch_channel_clear_flag(channel_a, CF_VIDEO_PASSIVE);

    switch_thread_rwlock_unlock(vh->member_b->rwlock);
    switch_thread_rwlock_unlock(vh->member_a->rwlock);

    switch_core_session_rwunlock(session_a);
    switch_core_session_rwunlock(session_b);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s video thread ended.\n", switch_channel_get_name(channel_a));

    switch_thread_rwlock_unlock(conference->rwlock);

    vh->up = 0;
    return NULL;
}
#endif

#if 0
/* Main video monitor thread (1 per distinct conference room) */
static void *SWITCH_THREAD_FUNC conference_video_thread_run(switch_thread_t *thread, void *obj)
{
    conference_obj_t *conference = (conference_obj_t *) obj;
    conference_member_t *imember;
    switch_frame_t *vid_frame = NULL;
    switch_status_t status;
    int want_refresh = 0;
    int yield = 0;
    switch_core_session_t *session;
    char buf[65536];
    conference_member_t *floor_holder = NULL;

    conference->video_running = 1;
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Video thread started for conference %s\n", conference->name);

    while (conference->video_running == 1 && globals.running && !switch_test_flag(conference, CFLAG_DESTRUCT)) {
        if (yield) {
            switch_yield(yield);
            yield = 0;
        }

        switch_mutex_lock(conference->mutex);

        if (conference->video_floor_holder) {
            floor_holder = conference->video_floor_holder;
        } else {
            floor_holder = NULL;
        }


        if (!floor_holder) {
            yield = 100000;
            goto do_continue;
        }

        if (!floor_holder->session || !floor_holder->channel || !switch_channel_test_flag(floor_holder->channel, CF_VIDEO)) {
            yield = 100000;
            goto do_continue;
        }

        session = floor_holder->session;

        if ((status = switch_core_session_read_lock(session)) == SWITCH_STATUS_SUCCESS) {
            switch_mutex_unlock(conference->mutex);
            if (!switch_channel_ready(switch_core_session_get_channel(session))) {
                status = SWITCH_STATUS_FALSE;
            } else {
                status = switch_core_session_read_video_frame(session, &vid_frame, SWITCH_IO_FLAG_NONE, 0);
            }
            switch_mutex_lock(conference->mutex);
            switch_core_session_rwunlock(session);
        }

        if (!SWITCH_READ_ACCEPTABLE(status)) {
            yield = 100000;
            goto do_continue;
        }

        if (vid_frame && switch_test_flag(vid_frame, SFF_CNG)) {
            yield = 10000;
            goto do_continue;
        }

        memcpy(buf, vid_frame->packet, vid_frame->packetlen);

        switch_mutex_unlock(conference->mutex);
        switch_mutex_lock(conference->mutex);
        want_refresh = 0;

        if (switch_test_flag(conference, CFLAG_FLOOR_CHANGE)) {
            clear_conference_state_unlocked(conference, CFLAG_FLOOR_CHANGE);
        }

        for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
            for (imember = conference->member_lists[i]; imember; imember = imember->next) {
                switch_core_session_t *isession = imember->session;
                switch_channel_t *ichannel;

                if (!isession || switch_core_session_read_lock(isession) != SWITCH_STATUS_SUCCESS) {
                    continue;
                }

                ichannel = switch_core_session_get_channel(imember->session);

                if (switch_channel_test_flag(ichannel, CF_VIDEO_REFRESH_REQ)) {
                    want_refresh++;
                    switch_channel_clear_flag(ichannel, CF_VIDEO_REFRESH_REQ);
                }

                if (isession && switch_channel_test_flag(ichannel, CF_VIDEO)) {
                    memcpy(vid_frame->packet, buf, vid_frame->packetlen);
                    switch_core_session_write_video_frame(imember->session, vid_frame, SWITCH_IO_FLAG_NONE, 0);
                }

                switch_core_session_rwunlock(isession);
            }
        }
        
        if (want_refresh && session) {
            switch_core_session_refresh_video(session);
            want_refresh = 0;
        }

    do_continue:
        switch_mutex_unlock(conference->mutex);
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Video thread ending for conference %s\n", conference->name);
    conference->video_running = 0;

    return NULL;
}
#endif

static int notify_activity(conference_obj_t *conference, conference_member_t *member,
                           int history_slot_count, int reset_slot_count)
{
    switch_event_t *event;

    if (conference->notify_active_talkers == SWITCH_FALSE)
        return 0;

    if (!(switch_test_flag(member, MFLAG_NOTIFY_ACTIVITY) ||
        member->consecutive_inactive_slots > 0 || member->consecutive_active_slots > 0))
        return 0;

    /* not talking */
    if (!switch_test_flag(member, MFLAG_TALKING)) {
        /* not talking but is active talker */
        if (switch_test_flag(member, MFLAG_ACTIVE_TALKER)) {
            member->consecutive_inactive_slots++;
            member->consecutive_active_slots = 0;
            if (member->consecutive_inactive_slots >= history_slot_count) {
                if (test_eflag(conference, EFLAG_STOP_TALKING) &&
                    switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) ==
                    SWITCH_STATUS_SUCCESS) {
                    conference_add_event_member_data(member, event);
                    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "stop-talking");
                    switch_event_fire(&event);

                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "event fire stop-talking member:%s/%d\n",
                                      member->mname, member->id);
                }
                clear_member_state_unlocked(member, MFLAG_ACTIVE_TALKER);
                return 1;
            }
        }
        /* not talking and is not active talker */
        else {
            if (member->consecutive_active_slots > 0) {
                member->consecutive_inactive_slots++;
                if (member->consecutive_inactive_slots >= reset_slot_count)
                    member->consecutive_active_slots = 0;
            }
        }
    } else {
        /* MFLAG_TALKING and MFLAG_ACTIVE_TALKER are set */
        if (switch_test_flag(member, MFLAG_ACTIVE_TALKER)) {
            if (member->consecutive_inactive_slots > 0) {
                member->consecutive_active_slots++;
                if (member->consecutive_active_slots >= reset_slot_count)
                    member->consecutive_inactive_slots = 0;
            }
        }
        /* talking but it is not active talker yet */
        else {
            member->consecutive_active_slots++;
            member->consecutive_inactive_slots = 0;
            /* make it active talker */
            if (member->consecutive_active_slots >= history_slot_count) {
                if (test_eflag(conference, EFLAG_START_TALKING) &&
                    switch_test_flag(member, MFLAG_CAN_SPEAK) &&
                    switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) ==
                    SWITCH_STATUS_SUCCESS) {
                    int val;

                    conference_add_event_member_data(member, event);
                    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "start-talking");
                    switch_event_fire(&event);

                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "event fire start-talking member:%s/%d\n",
                                      member->mname, member->id);

                    val = 1;
                    switch_core_ioctl_stats(member->session, SET_ACTIVE_TALKER_FLAG, &val);
                }
                set_member_state_unlocked(member, MFLAG_ACTIVE_TALKER);
                return 1;
            }
        }
    }

    return 0;
}

static void conference_command_handler(switch_live_array_t *la, const char *cmd, const char *sessid, cJSON *jla, void *user_data)
{


}
 
void check_conference_thread(conference_obj_t *conf, switch_time_t now) {
    if (!conf) { return; }
    if ((now - conf->start_of_interval) >= 2*FUZE_TIMER_MISS_INTERVAL) {
        char *meeting_id = "";
        char *instance_id = "";
        if (conf->meeting_id) { meeting_id = conf->meeting_id; }
        if (conf->instance_id) { instance_id = conf->instance_id; }
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                          "Meeting Id: %s Instance Id: %s CONF Thread seems INACTIVE: %lldms\n",
                          meeting_id, instance_id, (long long)(now - conf->start_of_interval));
    }
}

void check_output_thread(conference_member_t *member, switch_time_t now) {
    if (!member) { return; }
    if (!member->conference) { return; }
    if (!switch_test_flag(member, MFLAG_RUNNING)) { return; }
    if ((now - member->out_start_of_interval) >= 2*FUZE_TIMER_MISS_INTERVAL) {
        char *meeting_id = "";
        char *instance_id = "";
        char *mname = "";
        if (member->conference->meeting_id) { meeting_id = member->conference->meeting_id; }
        if (member->conference->instance_id) { instance_id = member->conference->instance_id; }
        if (member->mname) { mname = member->mname; }
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR,
                          "Meeting Id: %s Instance Id: %s Member ID: %d (%s) OUTPUT Thread seems INACTIVE: %lldms\n",
                          meeting_id, instance_id, member->id,
                          mname, (long long)(now - member->out_start_of_interval));
    }
}
    
/* Main monitor thread (1 per distinct conference room) */
static void conference_loop_init(conference_obj_t *conference)
{
    conference_loop_t *cl = &conference->cloop;
    switch_event_t *event;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "initializing conference loop!\n");

    memset(cl, 0, sizeof(conference_loop_t));
    cl->samples = switch_samples_per_packet(conference->rate, conference->interval);
    cl->bytes = cl->samples * 2;
    cl->history_slot_count = conference->history_time_period / conference->interval;
    cl->reset_slot_count = conference->history_reset_time_period / conference->interval;
    cl->tid = switch_thread_self();
    
    if (!(cl->divisor = conference->rate / 8000)) {
        cl->divisor = 1;
    }
    
    cl->file_frame = switch_core_alloc(conference->pool, SWITCH_RECOMMENDED_BUFFER_SIZE);
    cl->async_file_frame = switch_core_alloc(conference->pool, SWITCH_RECOMMENDED_BUFFER_SIZE);
    
    switch_mutex_lock(globals.hash_mutex);
    globals.threads++;
    switch_mutex_unlock(globals.hash_mutex);
    
    conference->is_recording = 0;
    conference->record_count = 0;
    for (int i = 0; i < MAX_ACTIVE_TALKERS; ++i) {
        conference->last_active_talkers[i] = NULL;
    }
    conference->last_active_speaker = NULL;

    set_conference_state_locked(conference, CFLAG_RUNNING);

    switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT);
    conference_add_event_data(conference, event);
    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "conference-create");
    switch_event_fire(&event);
    
    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        conference->member_lists[i] = NULL;
    }

    if (switch_test_flag(conference, CFLAG_LIVEARRAY_SYNC)) {
        char *p;
        
        if (strchr(conference->name, '@')) {
            conference->la_event_channel = switch_core_sprintf(conference->pool, "conference-liveArray.%s", conference->name);
        } else {
            conference->la_event_channel = switch_core_sprintf(conference->pool, "conference-liveArray.%s@%s", conference->name, conference->domain);
        }
        
        conference->la_name = switch_core_strdup(conference->pool, conference->name);
        if ((p = strchr(conference->la_name, '@'))) {
            *p = '\0';
        }
        
        switch_live_array_create(conference->la_event_channel, conference->la_name, globals.event_channel_id, &conference->la);
        switch_live_array_set_user_data(conference->la, conference);
        switch_live_array_set_command_handler(conference->la, conference_command_handler);
    }
    
    conference->start_of_interval = switch_micro_time_now() / 1000;
    conference->missed_ms = 0;
    
    conference->avgruntime_cnt = 0;
    conference->avgruntime = 0;

    conference->list_idx = -1;
    conference->processed = SWITCH_FALSE;
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Conference Info: interval:%u rate: %u\n",
                      conference->interval, conference->rate);

    return;
}

/* Main monitor thread (1 per distinct conference room) */
static CONFERENCE_LOOP_RET conference_thread_run(conference_obj_t *conference)
{
    conference_loop_t *cl = &conference->cloop;
    uint32_t samples = cl->samples;
    
    /* in loop vars */
    switch_size_t file_sample_len = samples;
    switch_size_t file_data_len = samples * 2;
    uint32_t bytes = cl->bytes;
    int has_file_data = 0, exclusive_play = 0;
    int no_active_speakers = 0;
    int no_can_speak;
    // uint32_t conf_energy = 0;
    int nomoh = 0;
    int i, j, m, n;
    conference_member_t *floor_holder, *temp_member;
    uint8_t ready = 0, total = 0;
    conference_member_t *imember, *omember;
    conference_member_t *temp_active_talkers[MAX_ACTIVE_TALKERS];
    switch_time_t now, now_ms;
    int16_t *bptr;
    uint32_t x = 0;
    // int32_t z = 0;
    int32_t main_frame[SWITCH_RECOMMENDED_BUFFER_SIZE / 2];
    int16_t main_frame_16[SWITCH_RECOMMENDED_BUFFER_SIZE / 2];

    /* in loop vars */

    now = switch_time_now();
    now_ms = now/1000;

    if (!(globals.running && !switch_test_flag(conference, CFLAG_DESTRUCT))) {
        return CONFERENCE_LOOP_RET_STOP;
    }
    
    conference_reconcile_member_lists(conference);

    switch_mutex_lock(conference->mutex);

    has_file_data = ready = total = 0;

    floor_holder = conference->floor_holder;

    /*
     * To keep memory for debug stats not persistent,
      * we manage it as necessary.
     */
    if (switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) &&
            conference->debug_stats_pool == NULL) {
        do {
            const char *caller_id_number;
            if (0 && switch_core_new_memory_pool(&conference->debug_stats_pool)
                    != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error in Allocating debug_stats pool.\n");
                clear_conference_state_unlocked(conference, CFLAG_DEBUG_STATS_ACTIVE);
                break;
            }

            conference->debug_stats = switch_core_alloc (conference->debug_stats_pool,
                                sizeof(*conference->debug_stats));
            memset(conference->debug_stats, 0, sizeof(*conference->debug_stats));
            
            for (int i = 0; i < eMemberListTypes_Recorders; i++) {
                for (imember = conference->member_lists[i]; imember; imember = imember->next) {
                    if (!imember->session || switch_test_flag(imember, MFLAG_NOCHANNEL)) {
                        continue;
                    }

                    if (imember->roll_no >= 32)
                        continue;

                    caller_id_number = switch_channel_get_caller_profile(
                                switch_core_session_get_channel(imember->session))->caller_id_number;
                    if(caller_id_number) {
                        strncpy(conference->debug_stats->member_name[imember->roll_no],
                                        caller_id_number, 31);
                    }
                }
            }
            conference->debug_stats->timer_ticks = 1000/20; /* luke timer.interval == 20? */
            conference->debug_stats->cur_index = NUM_SECS_DBG_STATS - 1;

        } while (0); //Just escape loop

    } else if (!switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) &&
            conference->debug_stats_pool) {
        switch_core_destroy_memory_pool(&conference->debug_stats_pool);
        conference->debug_stats_pool = NULL;
        conference->debug_stats = NULL;
    }

    for (imember = conference->member_lists[eMemberListTypes_Speakers]; imember; imember = imember->next) {
        uint32_t buf_read = 0;
        switch_bool_t has_audio;
        switch_size_t buf_in_use;

        total++;
        imember->read = 0;

        if (switch_test_flag(imember, MFLAG_RUNNING) && imember->session) {
            if ((!floor_holder || (imember->score_iir > SCORE_IIR_SPEAKING_MAX && (floor_holder->score_iir < SCORE_IIR_SPEAKING_MIN)))) {// &&
                //(!switch_test_flag(conference, CFLAG_VID_FLOOR) || switch_channel_test_flag(channel, CF_VIDEO))) {
                floor_holder = imember;
            }

            if (switch_test_flag(imember, MFLAG_NOMOH)) {
                nomoh++;
            }
        }

        
        has_audio = switch_test_flag(imember, MFLAG_HAS_AUDIO);
        
        switch_clear_flag_locked(imember, MFLAG_HAS_AUDIO);

        switch_mutex_lock(imember->audio_in_mutex);

        if (switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) && conference->debug_stats && imember->roll_no < 32) {
            if (conference->debug_stats->highest_score_iir[imember->roll_no] < imember->score_iir)
                conference->debug_stats->highest_score_iir[imember->roll_no] = imember->score_iir;
        }

        buf_in_use = switch_buffer_inuse(imember->audio_buffer);
        if (buf_in_use >= bytes) {
            if (buf_in_use >= bytes * (MAX_NUM_FRAMES_BUFFERED + 1)) {
                switch_buffer_toss(imember->audio_buffer, buf_in_use - (bytes * MAX_NUM_FRAMES_BUFFERED));

                if (switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) && conference->debug_stats && imember->roll_no < 32) {
                    conference->debug_stats->audio_buffer_tossed_bytes[imember->roll_no] +=
                                                        buf_in_use - (bytes * MAX_NUM_FRAMES_BUFFERED);
                    conference->debug_stats->audio_buffer_tossed_count[imember->roll_no]++;
                }
            }

            if ((buf_read = (uint32_t) switch_buffer_read(imember->audio_buffer, imember->frame, bytes))) {
                imember->read = buf_read;
                switch_set_flag_locked(imember, MFLAG_HAS_AUDIO);
                ready++;
            }
        }
        
        if (has_audio != switch_test_flag(imember, MFLAG_HAS_AUDIO))
        {
            log_member_state(__LINE__, imember, MFLAG_HAS_AUDIO, switch_test_flag(imember, MFLAG_HAS_AUDIO));
        }

        switch_mutex_unlock(imember->audio_in_mutex);
    }

    cl->fuze_ticks += 1;

    /* Encoder Optimization: Start the next cycle of output */
    ceo_start_write(&conference->ceo);

    /* Fuze Step 1: init temp_active_talkers */
    for (i = 0; i < MAX_ACTIVE_TALKERS; ++i) {
        temp_active_talkers[i] = NULL;
    }

    /* Fuze Step 2: Find max active talkers */
    for (imember = conference->member_lists[eMemberListTypes_Speakers]; imember; imember = imember->next) {
        int min_score_index = -1;

        switch_clear_flag(imember, MFLAG_NOTIFY_ACTIVITY);
        if (!switch_test_flag(imember, MFLAG_HAS_AUDIO) &&
            !switch_test_flag(imember, MFLAG_TALKING))
            continue;

        for (i = 0; i < MAX_ACTIVE_TALKERS; ++i) {
            if (temp_active_talkers[i] == NULL) {
                temp_active_talkers[i] = imember;
                break;
            }

            if (min_score_index == -1 ||
                (temp_active_talkers[min_score_index] &&
                 temp_active_talkers[i]->score_iir <
                    temp_active_talkers[min_score_index]->score_iir))
                min_score_index = i;
        }

        if (min_score_index != -1 && i == MAX_ACTIVE_TALKERS) {
            if (temp_active_talkers[min_score_index]->score_iir < imember->score_iir)
                temp_active_talkers[min_score_index] = imember;
        }
    }
    
    no_can_speak = 0;
    for (imember = conference->member_lists[eMemberListTypes_Speakers]; imember; imember = imember->next) {
        if (switch_test_flag(imember, MFLAG_CAN_SPEAK) || switch_test_flag(imember, MFLAG_USE_FAKE_MUTE)) {
            no_can_speak += 1;
            if (!imember->in_low_level && imember->score < 10) {
                imember->in_low_level = SWITCH_TRUE;
                imember->low_level_ms = now_ms;
            } else if (imember->in_low_level && imember->score >= 10) {
                if (imember->notified_low_level) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(imember->session), SWITCH_LOG_INFO,
                                      "M(%s)/I(%s):U(%s) back to normal input level (%d) after low for %lld ms\n",
                                      conference->meeting_id, conference->instance_id, imember->mname,
                                      imember->score,
                                      (long long)(now_ms - imember->low_level_ms));
                }
                imember->in_low_level = SWITCH_FALSE;
                imember->notified_low_level = SWITCH_FALSE;
            }
            if (imember->in_low_level) {
                if (!imember->notified_low_level && (now_ms - imember->low_level_ms) > 10000) {
                    imember->notified_low_level = SWITCH_TRUE;
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(imember->session), SWITCH_LOG_INFO,
                                      "M(%s)/I(%s):U(%s) low input level (%d) for > %lld ms\n",
                                      conference->meeting_id, conference->instance_id, imember->mname,
                                      imember->score,
                                      (long long)(now_ms - imember->low_level_ms));
                }
            }
        }
    }

    if (cl->fuze_ticks % 3000 == 1) {
        /* Fuze Debug Info: print this 10s */
        int total_members = 0;
        int muted_members = 0;
        int low_energy_members = 0;
        int active_speakers = 0;
        int low_energy_signal_members = 0;
        char *mname[MAX_ACTIVE_TALKERS];
        char mname_null[10] = "none";
        
        for (int i = 0; i < eMemberListTypes_Recorders; i++) {
            for (imember = conference->member_lists[i]; imember; imember = imember->next) {
                uint32_t low_frame_count = 0;

                if (imember->session) {
                   low_frame_count = switch_core_session_get_low_energy(imember->session);
                }
                total_members += 1;
                if (!switch_test_flag(imember, MFLAG_CAN_SPEAK) || switch_test_flag(imember, MFLAG_USE_FAKE_MUTE)) {
                    muted_members += 1;
                }
                if (low_frame_count > 0) {
                    low_energy_members += 1;
                }
                if (imember->one_of_active) {
                    active_speakers += 1;
                }

                if (switch_test_flag(imember, MFLAG_CAN_SPEAK)) {
                    if (imember->in_low_level) {
                        low_energy_signal_members += 1;
                    }
                }
            }
        }
        
        for (int j = 0; j < MAX_ACTIVE_TALKERS; j++) {
            mname[j] = (temp_active_talkers[j] == NULL) ?
                mname_null : temp_active_talkers[j]->mname;
        }
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                          "Periodic Conference Description Meeting Id: %s Instance Id: %s Count=%d Active=%d"
                          " Muted=%d Low=(%d+%d) AS1=%s AS2=%s AS3=%s\n",
                          conference->meeting_id, conference->instance_id,
                          total_members, active_speakers, muted_members, low_energy_members, low_energy_signal_members,
                          mname[0], mname[1], mname[2]);
    }
        
    /*
     * Fuze Step 3: Find the new talkers
     * This is just used to set up the MFLAG_NOTIFY_ACTIVITY flag
     */
    for (i = 0; i < MAX_ACTIVE_TALKERS; ++i) {
        if (temp_active_talkers[i] == NULL)
            break;

        for (j = 0; j < MAX_ACTIVE_TALKERS; ++j) {
            if (conference->last_active_talkers[j] == NULL)
                break;

            if (temp_active_talkers[i] == conference->last_active_talkers[j]) {
                break;
            }
        }

        if (j == MAX_ACTIVE_TALKERS || conference->last_active_talkers[j] == NULL) {
            /*
             * New Active Member
             */
            if (strlen(temp_active_talkers[i]->mname) > 0) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(temp_active_talkers[i]->session), SWITCH_LOG_INFO, "Meeting Id: %s Instance Id: %s start speaking %s/%u score %u energy %u\n",
                                  conference->meeting_id, conference->instance_id,
                                  temp_active_talkers[i]->mname, temp_active_talkers[i]->id,
                                  temp_active_talkers[i]->score_iir, temp_active_talkers[i]->score);
            }
            
            switch_set_flag(temp_active_talkers[i], MFLAG_NOTIFY_ACTIVITY);
            // set_member_state_unlocked(temp_active_talkers[i], MFLAG_NOTIFY_ACTIVITY);
        } else {
            switch_set_flag(temp_active_talkers[i], MFLAG_NOTIFY_ACTIVITY);
            //set_member_state_unlocked(temp_active_talkers[i], MFLAG_NOTIFY_ACTIVITY);
        }

    }

    /*
     * Fuze Step 4: Find the participants who just became non-active
     * This is just used to set up the MFLAG_NOTIFY_ACTIVITY flag
     */
    if (conference->last_active_talkers[0]) {
        conference->last_time_active = now;
    } else {
        if (conference->min_inactive_to_end) {
            int min_inactive = (int)((now - conference->last_time_active)/(60*1000*1000));
            if (min_inactive > conference->min_inactive_to_end) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                                  "Meeting Id: %s Instance Id: %s no active speakers for %d minutes, ending meeting!\n",
                                  conference->meeting_id, conference->instance_id, min_inactive);
                conference->ending_due_to_inactivity = SWITCH_TRUE;
                set_conference_state_unlocked(conference, CFLAG_DESTRUCT);
            }
        }
    }
    for (i = 0; i < MAX_ACTIVE_TALKERS; ++i) {
        if (conference->last_active_talkers[i] == NULL)
            break;

        conference->last_active_talkers[i]->one_of_active = SWITCH_FALSE;
        conference->last_active_talkers[i]->last_time_active = now;

        for (j = 0; j < MAX_ACTIVE_TALKERS; ++j) {
            if (temp_active_talkers[j] == NULL)
                break;

            if (conference->last_active_talkers[i] == temp_active_talkers[j]) {
                break;
            }
        }

        if (j == MAX_ACTIVE_TALKERS || temp_active_talkers[j] == NULL) {
            /*
             * Out of the list
             */
            switch_set_flag(conference->last_active_talkers[i], MFLAG_NOTIFY_ACTIVITY);
            // set_member_state_unlocked(conference->last_active_talkers[i], MFLAG_NOTIFY_ACTIVITY);

            if (switch_test_flag(conference->last_active_talkers[i], MFLAG_RUNNING)) {
                /* we're ready to start consuming from the common audio source again */
                meo_reset_idx(&conference->last_active_talkers[i]->meo);
                if (strlen(conference->last_active_talkers[i]->mname) > 0) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(conference->last_active_talkers[i]->session), SWITCH_LOG_INFO,
                                      "Meeting Id: %s Instance Id: %s stop speaking %s/%u score %u energy %u\n",
                                      conference->meeting_id, conference->instance_id,
                                      conference->last_active_talkers[i]->mname, conference->last_active_talkers[i]->id,
                                      conference->last_active_talkers[i]->score_iir, conference->last_active_talkers[i]->score);
                }
            
            }
        }
    }

    /*
     * Fuze Step 5: Update the active talker list
     * Used for notifications next time
     */
    no_active_speakers = 0;
    for (i = 0, j = 0; i < MAX_ACTIVE_TALKERS; ++i) {
        if (temp_active_talkers[i]) {
            temp_active_talkers[i]->one_of_active = SWITCH_TRUE;
            temp_active_talkers[i]->was_active = SWITCH_TRUE;
            j++;
            no_active_speakers += 1;
        }

        conference->last_active_talkers[i] = temp_active_talkers[i];
    }

    /*
     * Fuze Step 6:
     * Sort so that the loudest two speakers are at the top
     * Bring the top 2 callers to top. Why only two? Becos we let two callers
     * into the bridge when the whole conference is silent.
     */
    if (j > 2) {
        if (conference->last_active_talkers[0]->score_iir >=
            conference->last_active_talkers[1]->score_iir) {
            m = 0; n = 1;
        } else {
            m = 1; n = 0;
        }

        for (i = 2; i < j; ++i) {
            if (conference->last_active_talkers[i]->score_iir >
                conference->last_active_talkers[m]->score_iir) {
                n = m;
                m = i;
            } else if (conference->last_active_talkers[i]->score_iir >
                conference->last_active_talkers[n]->score_iir) {
                n = i;
            }
        }

        if (!((m == 0 && n == 1) || (m == 1 && n == 0))) {
            if (m != 0) {
                temp_member = conference->last_active_talkers[m];
                conference->last_active_talkers[m] = conference->last_active_talkers[0];
                conference->last_active_talkers[0] = temp_member;

                if (n == 0)
                    n = m;
            }

            if (n != 1) {
                temp_member = conference->last_active_talkers[n];
                conference->last_active_talkers[n] = conference->last_active_talkers[1];
                conference->last_active_talkers[1] = temp_member;
            }
        }
    } /* fuze step 6 */

    /* Fuze Step 7: Send notifications */
    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (imember = conference->member_lists[i]; imember; imember = imember->next) {
            notify_activity(conference, imember, cl->history_slot_count, cl->reset_slot_count);
        }
    }
        
    /* Debug Code Start */
    /* Read one frame of audio from each member channel and save it for redistribution */
    if (switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) &&
                    conference->debug_stats) {

        conference->debug_stats->last_tick++;

        if (conference->debug_stats->last_tick % conference->debug_stats->timer_ticks == 1) {
            if (++conference->debug_stats->cur_index == NUM_SECS_DBG_STATS)
                conference->debug_stats->cur_index = 0;

            conference->debug_stats->active_talker_map[conference->debug_stats->cur_index] = 0;
            conference->debug_stats->audio_mux_map[conference->debug_stats->cur_index] = 0;
            conference->debug_stats->audio_receiver_map[conference->debug_stats->cur_index] = 0;
            conference->debug_stats->audio_substract_map[conference->debug_stats->cur_index] = 0;

            for (i = 0; i < MAX_ACTIVE_TALKERS; i++) {
                if (conference->last_active_talkers[i] &&
                        conference->last_active_talkers[i]->roll_no < 32) {
                    conference->debug_stats->active_talker_map[conference->debug_stats->cur_index] |=
                                    (1 << conference->last_active_talkers[i]->roll_no);
                }
            }
        }
    }
    /* Debug code end */

    /* video floor */
    if (floor_holder != conference->floor_holder) {
        conference_set_floor_holder(conference, floor_holder);
    }

    /* ivr stuff? */
    if (conference->perpetual_sound && !conference->async_fnode) {
        conference_play_file(conference, conference->perpetual_sound, CONF_DEFAULT_LEADIN, NULL, 1, 0);
    } else if (conference->moh_sound && !conference->is_recording && ((nomoh == 0 && conference->count == 1)
                                         || switch_test_flag(conference, CFLAG_WAIT_MOD)) && !conference->async_fnode) {
        if (!switch_test_flag(conference, CFLAG_WAIT_MOD)) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Playing MOH without wait_mod : %s.\n", conference->name);
        }
        conference_play_file(conference, conference->moh_sound, CONF_DEFAULT_LEADIN, NULL, 1, 0);
    }

    /* stop conference if there are no speakers for a period of time.  not used by fuze */
    /* Find if no one talked for more than x number of second */
    if (conference->terminate_on_silence && conference->count > 1) {
        int is_talking = 0;

        for (imember = conference->member_lists[eMemberListTypes_Speakers]; imember; imember = imember->next) {
            if (switch_epoch_time_now(NULL) - imember->join_time <= conference->terminate_on_silence) {
                is_talking++;
            } else if (imember->last_talking != 0 && switch_epoch_time_now(NULL) - imember->last_talking <= conference->terminate_on_silence) {
                is_talking++;
            }
        }
        if (is_talking == 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Conference has been idle for over %d seconds, terminating\n", conference->terminate_on_silence);
            set_conference_state_unlocked(conference, CFLAG_DESTRUCT);
        }
    }

    /* not used by fuze */
    /* Start auto recording if there's the minimum number of required participants. */
    if (conference->auto_record && !conference->is_recording && conference->count > 1) {
        conference->is_recording = 1;
        conference->record_count++;
        imember = conference->member_lists[eMemberListTypes_Speakers] ?
            conference->member_lists[eMemberListTypes_Speakers] : conference->member_lists[eMemberListTypes_Listeners];
        
        if (imember) {
            switch_channel_t *channel = switch_core_session_get_channel(imember->session);
            char *rfile = switch_channel_expand_variables(channel, conference->auto_record);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Auto recording file: %s\n", rfile);
            launch_conference_record_thread(conference, rfile, SWITCH_TRUE);

            if (rfile != conference->auto_record) {
                conference->record_filename = switch_core_strdup(conference->pool, rfile);
                switch_safe_free(rfile);
            } else {
                conference->record_filename = switch_core_strdup(conference->pool, conference->auto_record);
            }
            /* Set the conference recording variable for each member */
            for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
                for (omember = conference->member_lists[i]; omember; omember = omember->next) {
                    channel = switch_core_session_get_channel(omember->session);
                    switch_channel_set_variable(channel, "conference_recording", conference->record_filename);
                }
            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Auto Record Failed.  No members in conference.\n");
        }
    }
    
    /* If a file or speech event is being played */
    if (conference->fnode && !switch_test_flag(conference->fnode, NFLAG_PAUSE)) {
        /* Lead in time */
        if (conference->fnode->leadin) {
            conference->fnode->leadin--;
            exclusive_play = conference->fnode->exclusive_play;
        } else if (!conference->fnode->done) {
            file_sample_len = cl->samples;
            if (conference->fnode->type == NODE_TYPE_SPEECH) {
                switch_speech_flag_t flags = SWITCH_SPEECH_FLAG_BLOCKING;

                if (switch_core_speech_read_tts(conference->fnode->sh, cl->file_frame, &file_data_len, &flags) == SWITCH_STATUS_SUCCESS) {
                    file_sample_len = file_data_len / 2;
                } else {
                    file_sample_len = file_data_len = 0;
                }
            } else if (conference->fnode->type == NODE_TYPE_FILE) {
                switch_core_file_read(&conference->fnode->fh, cl->file_frame, &file_sample_len);
                if (conference->fnode->fh.vol) {
                    switch_change_sln_volume_granular((void *)cl->file_frame, (uint32_t)file_sample_len, conference->fnode->fh.vol);
                }
            }

            if (file_sample_len <= 0) {
                conference->fnode->done++;
                has_file_data = 0;
            } else {
                has_file_data = 1;
                exclusive_play = conference->fnode->exclusive_play;
            }
        }
    }

    /* file play */
    if (conference->async_fnode) {
        /* Lead in time */
        if (conference->async_fnode->leadin) {
            conference->async_fnode->leadin--;
            exclusive_play = conference->async_fnode->exclusive_play;
        } else if (!conference->async_fnode->done) {
            file_sample_len = samples;
            switch_core_file_read(&conference->async_fnode->fh, cl->async_file_frame, &file_sample_len);
            if (file_sample_len <= 0) {
                conference->async_fnode->done++;
            } else {
                if (has_file_data) {
                    switch_size_t x;

                    for (x = 0; x < file_sample_len; x++) {
                        int32_t z;
                        int16_t *muxed;

                        muxed = (int16_t *) cl->file_frame;
                        bptr = (int16_t *) cl->async_file_frame;
                        z = muxed[x] + bptr[x];
                        switch_normalize_to_16bit(z);
                        muxed[x] = (int16_t) z;
                    }
                } else {
                    memcpy(cl->file_frame, cl->async_file_frame, file_sample_len * 2);
                    has_file_data = 1;
                    exclusive_play = conference->async_fnode->exclusive_play;
                }
            }
        }
    }

    if (conference->async_fnode && conference->async_fnode->done) {
        switch_memory_pool_t *pool;
        conference_file_close(conference, conference->async_fnode);
        pool = conference->async_fnode->pool;
        conference->async_fnode = NULL;
        switch_core_destroy_memory_pool(&pool);
        has_file_data = 0;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "async file close\n");
    }


    if ((ready != cl->prev_ready) || (has_file_data != cl->prev_has_file_data)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                          "changed conf state: ready now %d -> %d has_file_data %d -> %d conf->count=%d act_spkrs=%d\n",
                          cl->prev_ready, ready, cl->prev_has_file_data, has_file_data, conference->count, no_active_speakers);
        cl->prev_ready = ready;
        cl->prev_has_file_data = has_file_data;
    }

    /* Fuze Step 8: output mix */
    /* Encoder optimization: added condition that we go in here if more than 1 participant and no active speakers */
    /* Use more bits in the main_frame to preserve the exact sum of the audio samples. */
    memset(main_frame, 0, SWITCH_RECOMMENDED_BUFFER_SIZE);

    /* Fuze: Init the main frame with file data if there is any (conference wide announcement) */
    bptr = (int16_t *) cl->file_frame;
    if (has_file_data && file_sample_len) {
        for (x = 0; x < bytes / 2; x++) {
            if (x <= file_sample_len) {
                main_frame[x] = (int32_t) (bptr[x]);
            } else {
                memset(&main_frame[x], 255, sizeof(main_frame[x]));
            }
        }
    }

    conference->mux_loop_count = 0;
    conference->member_loop_count = 0;

    /* Copy audio from every member known to be producing audio into the main frame. */
    for (omember = conference->member_lists[eMemberListTypes_Speakers]; omember && !exclusive_play; omember = omember->next) {
        conference->member_loop_count++;

        if (!(switch_test_flag(omember, MFLAG_RUNNING) && switch_test_flag(omember, MFLAG_HAS_AUDIO)))
            continue;

        /* Encoder Optimization: condition of !can_speak was added to this condition but I think that this
         * isn't necessary */
        if (omember->one_of_active == SWITCH_FALSE)
            continue;
        
        /* changed this to continue if "can't speak and not fake mute" */
        if (!switch_test_flag(omember, MFLAG_CAN_SPEAK) && !switch_test_flag(omember, MFLAG_USE_FAKE_MUTE))
            continue;

        if (switch_test_flag(omember, MFLAG_USE_FAKE_MUTE) && switch_core_session_get_cn_state(omember->session))
            continue;

        /* Fuze: Ok we finally made it down here so copy this speakers audio in */
        bptr = (int16_t *) omember->frame;
        for (x = 0; x < omember->read / 2; x++) {
            main_frame[x] += (int32_t) bptr[x];
        }

        if (switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) &&
                    conference->debug_stats) {
            if (conference->debug_stats->last_tick % conference->debug_stats->timer_ticks == 1) {
                if (omember->roll_no < 32) {
                        conference->debug_stats->audio_mux_map[conference->debug_stats->cur_index] |=  (1 << omember->roll_no);
                }
            }
        }
    }
    /* Fuze: at this point main_frame = sum(active speakers) + conference_ivr */

#if 0
    /* Fuze: Should we just make sure that this isn't called? */
    if (conference->agc_level && conference->member_loop_count) {
        conf_energy = 0;

        for (x = 0; x < bytes / 2; x++) {
            z = abs(main_frame[x]);
            switch_normalize_to_16bit(z);
            conf_energy += (int16_t) z;
        }

        conference->score = conf_energy / ((bytes / 2) / cl->divisor) / conference->member_loop_count;

        conference->avg_tally += conference->score;
        conference->avg_score = conference->avg_tally / ++conference->avg_itt;
        if (!conference->avg_itt) conference->avg_tally = conference->score;
    }
#endif

    for (x = 0; x < bytes / 2; x++) {
        int32_t z;
        z = main_frame[x];
        switch_normalize_to_16bit(z);
        main_frame_16[x] = (int16_t) z;
    }

    /* Encoder Optimization: Write the conference mix to the Conference Encoder Optimization object */
    ceo_write_buffer(&conference->ceo, main_frame_16, bytes);
    
    /* Create write frame once per member who is not deaf for each sample in the main frame
       check if our audio is involved and if so, subtract it from the sample so we don't hear ourselves.
       Since main frame was 32 bit int, we did not lose any detail, now that we have to convert to 16 bit we can
       cut it off at the min and max range if need be and write the frame to the output buffer.
     */
    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        if (i == eMemberListTypes_Listeners) {
            continue;
        }
        for (omember = conference->member_lists[i]; omember; omember = omember->next) {
            int16_t write_frame_raw[SWITCH_RECOMMENDED_BUFFER_SIZE / 2];
            switch_size_t ok = 1;
            switch_bool_t individual_mix = SWITCH_FALSE;
            switch_bool_t one_of_active = SWITCH_FALSE;

            if (!switch_test_flag(omember, MFLAG_RUNNING)) {
                continue;
            }

            if (!switch_test_flag(omember, MFLAG_CAN_HEAR)) {
                continue;
            }

            one_of_active = omember->one_of_active && (switch_test_flag(omember, MFLAG_CAN_SPEAK) ||
                                                       (!switch_test_flag(omember, MFLAG_CAN_SPEAK) &&
                                                        switch_test_flag(omember, MFLAG_USE_FAKE_MUTE) &&
                                                        !switch_core_session_get_cn_state(omember->session)));

            individual_mix = (!omember->fnode && one_of_active) || (conference->is_recording && omember->rec);

            if (!individual_mix) {
                continue;
            }

            memset(write_frame_raw, 0, bytes);

            /* Fuze: Everybody is muted or not speaking */
            if ((no_active_speakers == 0) && (omember->conference->count > 1)) {
                /* already cleared above */
            } else {

                bptr = (int16_t *) omember->frame;
                for (x = 0; x < bytes / 2; x++) {
                    int32_t z;

                    z = (int32_t) main_frame[x];

                    if (!exclusive_play) {
                        /* bptr[x] represents my own contribution to this audio sample */
                        if (switch_test_flag(omember, MFLAG_HAS_AUDIO) && x <= omember->read / 2 && one_of_active) {
                            z -= (int32_t) (bptr[x]);
                        }

                        /* when there are relationships, we have to do more work by scouring all the members to see if there are any
                         * reasons why we should not be hearing a paticular member, and if not, delete their samples as well.
                         */
                        if (conference->relationship_total) {
                            for (imember = conference->member_lists[eMemberListTypes_Speakers]; imember; imember = imember->next) {
                                if (imember != omember && switch_test_flag(imember, MFLAG_HAS_AUDIO)) {
                                    conference_relationship_t *rel;
                                    switch_size_t found = 0;
                                    int16_t *rptr = (int16_t *) imember->frame;
                                    for (rel = imember->relationships; rel; rel = rel->next) {
                                        if ((rel->id == omember->id || rel->id == 0) && !switch_test_flag(rel, RFLAG_CAN_SPEAK)) {
                                            z -= (int32_t) rptr[x];
                                            found = 1;
                                            break;
                                        }
                                    }
                                    if (!found) {
                                        for (rel = omember->relationships; rel; rel = rel->next) {
                                            if ((rel->id == imember->id || rel->id == 0) && !switch_test_flag(rel, RFLAG_CAN_HEAR)) {
                                                z -= (int32_t) rptr[x];
                                                break;
                                            }
                                        }
                                    }

                                }
                            }
                        }
                    }

                    /* Now we can convert to 16 bit. */
                    switch_normalize_to_16bit(z);
                    write_frame_raw[x] = (int16_t) z;
                }
            }

            if (switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) &&
                        conference->debug_stats) {
                if (conference->debug_stats->last_tick % conference->debug_stats->timer_ticks == 1) {
                    if (omember->roll_no < 32) {
                            if (switch_test_flag(omember, MFLAG_HAS_AUDIO) && omember->one_of_active == SWITCH_TRUE) {
                                conference->debug_stats->audio_substract_map[conference->debug_stats->cur_index]  |=
                                                                        (1 << omember->roll_no);
                            }

                            conference->debug_stats->audio_receiver_map[conference->debug_stats->cur_index] |=
                                                                        (1 << omember->roll_no);
                    }
                }
            }

            switch_mutex_lock(omember->audio_out_mutex);
            
            ok = switch_buffer_write(omember->mux_buffer, write_frame_raw, bytes);

            switch_mutex_unlock(omember->audio_out_mutex);

            if (!ok) {
                switch_mutex_unlock(conference->mutex);
                return CONFERENCE_LOOP_RET_BAD_BUFFER_WRITE;
            }
        }
    }

    if (conference->fnode && conference->fnode->done) {
        conference_file_node_t *fnode;
        switch_memory_pool_t *pool;

        if (conference->fnode->type == NODE_TYPE_FILE) {
            conference_file_close(conference, conference->fnode);
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Not closing file because not NODE_TYPE_FILE\n");
        }

        fnode = conference->fnode;
        conference->fnode = conference->fnode->next;

        pool = fnode->pool;
        fnode = NULL;
        switch_core_destroy_memory_pool(&pool);
    }

    if (!conference->end_count && conference->endconf_time &&
            switch_epoch_time_now(NULL) - conference->endconf_time > conference->endconf_grace_time) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Conference %s: endconf grace time exceeded (%u)\n",
                conference->name, conference->endconf_grace_time);
        set_conference_state_unlocked(conference, CFLAG_DESTRUCT | CFLAG_ENDCONF_FORCED);
    }

    switch_mutex_unlock(conference->mutex);

    return CONFERENCE_LOOP_RET_OK;
}
    
static void conference_thread_stop(conference_obj_t *conference)
{
    // conference_loop_t *cl = &conference->cloop;
    conference_member_t *imember;
    switch_event_t *event;

    if (conference->stopping) {
        return;
    }

    /* Fuze: Conference is done ... clean things up! */
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Ending Conference: '%s' M:%s I:%s\n",
                      conference->name, conference->meeting_id, conference->instance_id);

    if (conference->debug_stats_pool) {
        clear_conference_state_unlocked(conference, CFLAG_DEBUG_STATS_ACTIVE);
        switch_core_destroy_memory_pool(&conference->debug_stats_pool);
        conference->debug_stats_pool = NULL;
        conference->debug_stats = NULL;
    }

    if (switch_test_flag(conference, CFLAG_OUTCALL)) {
        conference->cancel_cause = SWITCH_CAUSE_ORIGINATOR_CANCEL;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Ending pending outcall channels for Conference: '%s'\n", conference->name);
        while(conference->originating) {
            switch_yield(200000);
        }
    }

    switch_mutex_lock(conference->mutex);

    if (conference->stopping) {
        switch_mutex_unlock(conference->mutex);
        return;
    } else {
        conference->stopping = SWITCH_TRUE;
    }

    conference_send_presence(conference);

    conference_stop_file(conference, FILE_STOP_ASYNC);
    conference_stop_file(conference, FILE_STOP_ALL);

    for (conference_cdr_node_t *np = conference->cdr_nodes; np; np = np->next) {
        if (np->var_event) {
            switch_event_destroy(&np->var_event);
        }
    }

    /* Close Unused Handles */
    if (conference->fnode) {
        conference_file_node_t *fnode, *cur;
        switch_memory_pool_t *pool;

        fnode = conference->fnode;
        while (fnode) {
            cur = fnode;
            fnode = fnode->next;

            if (cur->type == NODE_TYPE_FILE) {
                conference_file_close(conference, cur);
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Not closing file because not NODE_TYPE_FILE\n");
            }

            pool = cur->pool;
            switch_core_destroy_memory_pool(&pool);
        }
        conference->fnode = NULL;
    }

    if (conference->async_fnode) {
        switch_memory_pool_t *pool;
        conference_file_close(conference, conference->async_fnode);
        pool = conference->async_fnode->pool;
        conference->async_fnode = NULL;
        switch_core_destroy_memory_pool(&pool);
    }

    ceo_destroy(&conference->ceo, conference->name);
    
    switch_mutex_lock(conference->member_mutex);
    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        for (imember = conference->member_lists[i]; imember; imember = imember->next) {
            switch_channel_t *channel;

            if (!switch_test_flag(imember, MFLAG_NOCHANNEL)) {
                channel = switch_core_session_get_channel(imember->session);

                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(imember->session), SWITCH_LOG_INFO, "Hanging up session due to meeting ended (inactive=%d)\n", conference->ending_due_to_inactivity);
                
                if (!switch_false(switch_channel_get_variable(channel, "hangup_after_conference"))) {
                    /* add this little bit to preserve the bridge cause code in case of an early media call that */
                    /* never answers */
                    if (conference->ending_due_to_inactivity) {
                        switch_channel_hangup(channel, SWITCH_CAUSE_CONFERENCE_INACTIVE);
                    } else if (switch_test_flag(conference, CFLAG_ANSWERED)) {
                        switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
                    } else {
                        /* put actual cause code from outbound channel hangup here */
                        switch_channel_hangup(channel, conference->bridge_hangup_cause);
                    }
                }
            }

            clear_member_state_locked(imember, MFLAG_RUNNING);
        }
    }
    switch_mutex_unlock(conference->member_mutex);
    switch_mutex_unlock(conference->mutex);

    /* allow other threads to give up mutex? */
    switch_yield(1000000);

    if (conference->vh[0].up == 1) {
        conference->vh[0].up = -1;
    }

    if (conference->vh[1].up == 1) {
        conference->vh[1].up = -1;
    }

    while (conference->vh[0].up || conference->vh[1].up) {
        switch_cond_next();
    }

    if (conference->video_running == 1) {
        conference->video_running = -1;
        while (conference->video_running) {
            switch_cond_next();
        }
    }

    switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT);
    if (event) {
        conference_add_event_data(conference, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "conference-destroy");
        switch_event_fire(&event);
    }
    switch_mutex_lock(globals.hash_mutex);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Check conference %s in hash %d\n", conference->name, switch_test_flag(conference, CFLAG_INHASH));
    if (switch_test_flag(conference, CFLAG_INHASH)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Delete conference %s from hash %d\n", conference->name, switch_test_flag(conference, CFLAG_INHASH));
        switch_core_hash_delete(globals.conference_hash, conference->name);
        clear_conference_state_unlocked(conference, CFLAG_INHASH);
    }
    switch_mutex_unlock(globals.hash_mutex);

    /* Wait till everybody is out */
    clear_conference_state_locked(conference, CFLAG_RUNNING);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Write Lock ON\n");
    switch_thread_rwlock_wrlock(conference->rwlock);
    switch_thread_rwlock_unlock(conference->rwlock);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Write Lock OFF\n");

    if (conference->la) {
        switch_live_array_destroy(&conference->la);
    }

    if (conference->sh) {
        switch_speech_flag_t flags = SWITCH_SPEECH_FLAG_NONE;
        switch_core_speech_close(&conference->lsh, &flags);
        conference->sh = NULL;
    }

    conference->end_time = switch_epoch_time_now(NULL);
    conference_cdr_render(conference);

    /* xxxxx */

    if (conference->pool) {
        switch_memory_pool_t *pool = conference->pool;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Destroy conference pool\n");
        switch_core_destroy_memory_pool(&pool);
    }

    switch_mutex_lock(globals.hash_mutex);
    globals.threads--;
    switch_mutex_unlock(globals.hash_mutex);

    return;
}

static void conference_loop_fn_floor_toggle(conference_member_t *member, caller_control_action_t *action)
{
    if (member == NULL) return;

    conf_api_sub_floor(member, NULL, NULL);
}

static void conference_loop_fn_enforce_floor(conference_member_t *member, caller_control_action_t *action)
{
    if (member == NULL) return;

    conf_api_sub_enforce_floor(member, NULL, NULL);
}

static switch_status_t conf_api_mute(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    return conf_api_sub_mute(member, stream, data);
}

static switch_status_t conf_api_unmute(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    return conf_api_sub_unmute(member, stream, data);
}

static switch_status_t conf_api_mute_non_moderator(conference_obj_t *conference, switch_stream_handle_t *stream, void *data)
{
        conference_member_t *member;
        switch_bool_t attendee_list_empty = SWITCH_TRUE;

        for (int i = 0; i < eMemberListTypes_Recorders; i++) {
            for (member = conference->member_lists[i]; member; member = member->next) {
                    if (switch_test_flag(member, MFLAG_MOD)) {
                            if (!conference->async_fnode)
                                    conference_member_play_file (member, conference->muted_all_sound, CONF_DEFAULT_LEADIN, 1);
                            continue;
                    }

                    if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                            continue;
                    }

                    attendee_list_empty = SWITCH_FALSE;
                    conf_api_sub_mute(member, stream, data);
            }
        }
    
        if (attendee_list_empty && stream)
        {
                stream->write_function(stream, "OK mute");
        }

        set_conference_state_unlocked(conference, CFLAG_INDICATE_MUTE_NONMODERATOR);
        return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_unmute_non_moderator(conference_obj_t *conference, switch_stream_handle_t *stream, void *data)
{
        conference_member_t *member;
        switch_bool_t attendee_list_empty = SWITCH_TRUE;

        for (int i = 0; i < eMemberListTypes_Recorders; i++) {
            for (member = conference->member_lists[i]; member; member = member->next) {
                    if (switch_test_flag(member, MFLAG_MOD)) {
                            if (!conference->async_fnode)
                                    conference_member_play_file (member, conference->unmuted_all_sound, CONF_DEFAULT_LEADIN, 1);
                            continue;
                    }

                    if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                            continue;
                    }

                    attendee_list_empty = SWITCH_FALSE;
                    conf_api_sub_unmute(member, stream, data);
            }
        }
    
        if (attendee_list_empty && stream)
        {
                stream->write_function(stream, "OK unmute");
        }

        clear_conference_state_unlocked(conference, CFLAG_INDICATE_MUTE_NONMODERATOR);
        return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_mute_all(conference_obj_t *conference, switch_stream_handle_t *stream, void *data)
{
    conference_member_t *member = NULL;
    conference_member_t *cmd_member = NULL;
    switch_bool_t attendee_list_empty = SWITCH_TRUE;
    uint32_t member_id = 0;

    if (data == NULL) {
        if (stream) {
            stream->write_function(stream, "INCORRECT SYNTAX mute all missing caller_id");
        }
        return SWITCH_STATUS_GENERR;
    }

    member_id = strtoul(data, NULL, 0);
    if(member_id == 0) {
        if (stream) {
            stream->write_function(stream, "INCORRECT SYNTAX mute all missing caller_id");
        }
        return SWITCH_STATUS_GENERR;
    }

    for (member = conference->member_lists[eMemberListTypes_Speakers]; member; member = member->next) {
        if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
            continue;
        }

        if (member->id == member_id) {
            cmd_member = member;
            continue;
        }

        attendee_list_empty = SWITCH_FALSE;
        conf_api_sub_mute(member, stream, NULL);
    }
    
    if (!cmd_member) {
        cmd_member = find_member_in_conference(conference, member_id);
    }

    if (cmd_member && !conference->async_fnode) {
        conference_member_play_file (cmd_member, conference->muted_all_sound, CONF_DEFAULT_LEADIN, 1);
    }

    if (attendee_list_empty && stream)
    {
        stream->write_function(stream, "OK mute");
    }

    set_conference_state_unlocked(conference, CFLAG_INDICATE_MUTE);
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_unmute_all(conference_obj_t *conference, switch_stream_handle_t *stream, void *data)
{
    conference_member_t *member = NULL;
    conference_member_t *cmd_member = NULL;
    switch_bool_t attendee_list_empty = SWITCH_TRUE;
    uint32_t member_id = 0;

    if (data == NULL) {
        if (stream) {
            stream->write_function(stream, "INCORRECT SYNTAX mute all missing caller_id");
        }
        return SWITCH_STATUS_GENERR;
    }

    member_id = strtoul(data, NULL, 0);
    if(member_id == 0) {
        if (stream) {
            stream->write_function(stream, "INCORRECT SYNTAX mute all missing caller_id");
        }
        return SWITCH_STATUS_GENERR;
    }

    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                continue;
            }

            if (member->id == member_id) {
                cmd_member = member;
                continue;
            }

            attendee_list_empty = SWITCH_FALSE;
            conf_api_sub_unmute(member, stream, NULL);
        }
    }
    
    if (cmd_member && !conference->async_fnode) {
        conference_member_play_file (cmd_member, conference->unmuted_all_sound, CONF_DEFAULT_LEADIN, 1);
    }


    if (attendee_list_empty && stream)
    {
        stream->write_function(stream, "OK unmute");
    }

    clear_conference_state_unlocked(conference, CFLAG_INDICATE_MUTE);
    return SWITCH_STATUS_SUCCESS;
}


static void conference_loop_mute_toggle(conference_member_t *member, caller_control_action_t *action)
{
    if (member == NULL)
        return;

    if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        conf_api_sub_mute(member, NULL, NULL);
    } else {
        if(switch_test_flag(member, MFLAG_MOD) && !switch_test_flag(member, MFLAG_CAN_MUTE)) {
          /* unlock moderator members */
          conf_api_unlock_and_unmute(member, NULL, NULL);
          return;
        }
        conf_api_sub_unmute(member, NULL, NULL);
        if (!switch_test_flag(member, MFLAG_CAN_HEAR)) {
            conf_api_sub_undeaf(member, NULL, NULL);
        }
    }
}

static void conference_loop_mutelock_toggle(conference_member_t *member, caller_control_action_t *action)
{
    /* if member is already mute unlocked , mute and mute lock it */
    if (switch_test_flag(member, MFLAG_CAN_MUTE)) {
        conf_api_sub_lock_mute(member, NULL, NULL);
    } else {
        conf_api_unlock_and_unmute(member, NULL, NULL);
    }
}

/*static void conference_loop_fn_mute_toggle(conference_member_t *member, caller_control_action_t *action)
{
    if (member == NULL)
        return;

    if (switch_test_flag(member->conference, CFLAG_DISABLE_ATTENDEE_MUTE)) {
        if (!switch_test_flag(member, MFLAG_MOD))
            return;
    }

    conference_loop_mute_toggle(member, action);
}
*/
static void conference_loop_fn_mute_lock_all_toggle(conference_member_t *member, caller_control_action_t *action)
{
    if (member == NULL)
        return;

    if(switch_test_flag(member->conference, CFLAG_INDICATE_LOCK_MUTE)) {
        conf_api_unmute_lock_all(member->conference, NULL, NULL);
    } else {
        conf_api_mute_lock_all(member->conference, NULL, NULL);
    }
}

static void conference_loop_fn_mute_all_toggle(conference_member_t *cmd_member, caller_control_action_t *action)
{
    conference_obj_t *conference;
    conference_member_t *member = NULL;

    if (cmd_member == NULL) {
        return;
    }

    conference = cmd_member->conference;
    if (conference == NULL) {
        return;
    }

    switch_mutex_lock(conference->mutex);

    /*
     * (un)mute-all by host overwrites attendee's preference.
     */
    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                continue;
            }

            if (member == cmd_member) {
                continue;
            }

            if (!switch_test_flag(conference, CFLAG_INDICATE_MUTE)) {
                if (!switch_test_flag(member, MFLAG_CAN_SPEAK)) {
                    /*
                     * If a member was already self-muted, then on mute-all
                     * that member should remain silent.
                     */
                    continue;
                }
            } else if (switch_test_flag(conference, CFLAG_INDICATE_MUTE)) {
                if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
                    /*
                     * If a member was already in unmuted state, then
                     * unmute-all should keep the member in the unmuted state only.
                     */
                    continue;
                }
            }

            conference_loop_mute_toggle(member, action);
        }
    }
    
    if (switch_test_flag(conference, CFLAG_INDICATE_MUTE)) {
        if (cmd_member && !conference->async_fnode)
            conference_member_play_file (cmd_member, conference->unmuted_all_sound, CONF_DEFAULT_LEADIN, 1);
        clear_conference_state_unlocked(conference, CFLAG_INDICATE_MUTE);
    } else {
        if (cmd_member && !conference->async_fnode)
            conference_member_play_file (cmd_member, conference->muted_all_sound, CONF_DEFAULT_LEADIN, 1);
        set_conference_state_unlocked(conference, CFLAG_INDICATE_MUTE);
    }

    switch_mutex_unlock(conference->mutex);
}

static switch_status_t conf_api_mute_lock_all(conference_obj_t *conference, switch_stream_handle_t *stream, void *data)
{
    conference_member_t *member;
    switch_bool_t attendee_list_empty = SWITCH_TRUE;

    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                continue;
            }

            attendee_list_empty = SWITCH_FALSE;
            conf_api_sub_lock_mute(member, stream, data);
        }
    }
    
    if (attendee_list_empty && stream)
    {
        stream->write_function(stream, "OK mute lock\n");
    }

    set_conference_state_unlocked(conference, CFLAG_INDICATE_LOCK_MUTE);
    set_conference_state_unlocked(conference, CFLAG_INDICATE_MUTE_NONMODERATOR);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_lock_mute(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    /* check if thie member can be mute locked first */
    if (!switch_test_flag(member, MFLAG_MUTELOCKABLE)) {
        if (stream != NULL) {
        stream->write_function(stream, "%u is non lockabe member!\n", member->id);
        }

        return SWITCH_STATUS_SUCCESS;
    }

    if(switch_test_flag(member,MFLAG_CAN_MUTE)) {
        /* first mute this member because we are will disable it's mute capability */
        conf_api_sub_mute(member, stream, NULL);

        clear_member_state_locked(member,MFLAG_CAN_MUTE);
        set_member_state_unlocked(member, MFLAG_INDICATE_LOCK_MUTE);

        if (stream != NULL) {
            stream->write_function(stream, "OK mute lock %u\n", member->id);
        }

        if (test_eflag(member->conference, EFLAG_LOCK_MUTE_MEMBER) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "lock-mute-member");
        switch_event_fire(&event);
            }
            else {
                if (stream != NULL) {
                    stream->write_function(stream, "%u is already mute locked!\n", member->id);
                }
            }
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_unmute_lock_all(conference_obj_t *conference, switch_stream_handle_t *stream, void *data)
{
    conference_member_t *member;
    switch_bool_t attendee_list_empty = SWITCH_TRUE;

    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                continue;
            }

            attendee_list_empty = SWITCH_FALSE;
            conf_api_sub_unlock_mute(member, stream, data);
        }
    }
    
    if (attendee_list_empty && stream)
    {
        stream->write_function(stream, "OK unlock mute\n");
    }

    clear_conference_state_unlocked(conference, CFLAG_INDICATE_LOCK_MUTE);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_unlock_mute(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if(!switch_test_flag(member,MFLAG_CAN_MUTE)) {
      set_member_state_locked(member, MFLAG_CAN_MUTE);

      /* we set MFLAG_INDICATE_UNLOCK_MUTE only if we dont have UNMUTE passed as parameter */
      if( zstr(data) || strcasecmp((char *)data, "UNMUTE") )
        set_member_state_unlocked(member, MFLAG_INDICATE_UNLOCK_MUTE);

      if (stream != NULL) {
          stream->write_function(stream, "OK unlock mute %u\n", member->id);
      }

      if (test_eflag(member->conference, EFLAG_UNLOCK_MUTE_MEMBER) &&
          switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
          conference_add_event_member_data(member, event);
          switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "unlock-mute-member");
          switch_event_fire(&event);
      }
    }
    else {
      if (stream != NULL) {
        stream->write_function(stream, "%u is already mute unlocked!\n", member->id);
      }
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_unlock_and_unmute(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    if (member == NULL)
        return SWITCH_STATUS_GENERR;
    /* indicate that the user will be unmuted right after unlock to prevent playing prompt */
    conf_api_sub_unlock_mute(member, stream, "UNMUTE");
    /* now unmute member */
    conf_api_sub_unmute(member, stream, data);

  return SWITCH_STATUS_SUCCESS;
}

static void conference_loop_fn_vid_floor_toggle(conference_member_t *member, caller_control_action_t *action)
{
    if (member == NULL) return;

    conf_api_sub_vid_floor(member, NULL, NULL);
}

static void conference_loop_fn_vid_floor_force(conference_member_t *member, caller_control_action_t *action)
{
    if (member == NULL) return;

    conf_api_sub_vid_floor(member, NULL, "force");
}

static void conference_loop_fn_count(conference_member_t *member, caller_control_action_t *action)
{
    char text[128];

    if (!member || member->conference->count <= 1)
        return;


    switch_snprintf(text, sizeof(text), "There are %d callers in the conference.",
                        member->conference->count);

    conference_member_say(member, text, 0);
}

static void conference_loop_fn_operator(conference_member_t *member, caller_control_action_t *action)
{
    switch_status_t status = call_operator(member->conference);
    if (status != SWITCH_STATUS_SUCCESS) {
        conference_member_say(member, "Operator is not available", 0);
    }
}

static void conference_loop_fn_mute_on(conference_member_t *member, caller_control_action_t *action)
{
    if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        conf_api_mute(member, NULL, NULL);
    }
}

static void conference_loop_fn_mute_off(conference_member_t *member, caller_control_action_t *action)
{
    if (!switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        conf_api_unmute(member, NULL, NULL);
        if (!switch_test_flag(member, MFLAG_CAN_HEAR)) {
            conf_api_sub_undeaf(member, NULL, NULL);
        }
    }
}

static void conference_loop_fn_lock_toggle(conference_member_t *member, caller_control_action_t *action)
{
    switch_event_t *event;

    if (member == NULL)
        return;

    if (switch_test_flag(member->conference, CFLAG_WAIT_MOD) && !switch_test_flag(member, MFLAG_MOD) )
        return;

    if (!switch_test_flag(member->conference, CFLAG_LOCKED)) {
        if (member->conference->is_locked_sound) {
            conference_play_file(member->conference, member->conference->is_locked_sound, CONF_DEFAULT_LEADIN, NULL, 0, 0);
        }

        set_conference_state_locked(member->conference, CFLAG_LOCKED);
        if (test_eflag(member->conference, EFLAG_LOCK) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(member->conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "lock");
            switch_event_fire(&event);
        }
    } else {
        if (member->conference->is_unlocked_sound) {
            conference_play_file(member->conference, member->conference->is_unlocked_sound, CONF_DEFAULT_LEADIN, NULL, 0, 0);
        }

        clear_conference_state_locked(member->conference, CFLAG_LOCKED);
        if (test_eflag(member->conference, EFLAG_UNLOCK) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(member->conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "unlock");
            switch_event_fire(&event);
        }
    }

}

static void conference_loop_fn_deafmute_toggle(conference_member_t *member, caller_control_action_t *action)
{
    if (member == NULL)
        return;

    if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        conf_api_sub_mute(member, NULL, NULL);
        if (switch_test_flag(member, MFLAG_CAN_HEAR)) {
            conf_api_sub_deaf(member, NULL, NULL);
        }
    } else {
        conf_api_sub_unmute(member, NULL, NULL);
        if (!switch_test_flag(member, MFLAG_CAN_HEAR)) {
            conf_api_sub_undeaf(member, NULL, NULL);
        }
    }
}

static void conference_loop_fn_energy_up(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512], str[30] = "";
    switch_event_t *event;
    char *p;

    if (member == NULL)
        return;


    member->energy_level += 200;
    if (member->energy_level > 1800) {
        member->energy_level = 1800;
    }

    if (test_eflag(member->conference, EFLAG_ENERGY_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "energy-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->energy_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Energy level %d", member->energy_level);
    //conference_member_say(member, msg, 0);

    switch_snprintf(str, sizeof(str), "%d", abs(member->energy_level) / 200);
    for (p = str; p && *p; p++) {
        switch_snprintf(msg, sizeof(msg), "digits/%c.wav", *p);
        conference_member_play_file(member, msg, 0, 1);
    }




}

static void conference_loop_fn_energy_equ_conf(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512], str[30] = "", *p;
    switch_event_t *event;

    if (member == NULL)
        return;

    member->energy_level = member->conference->energy_level;

    if (test_eflag(member->conference, EFLAG_ENERGY_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "energy-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->energy_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Energy level %d", member->energy_level);
    //conference_member_say(member, msg, 0);

    switch_snprintf(str, sizeof(str), "%d", abs(member->energy_level) / 200);
    for (p = str; p && *p; p++) {
        switch_snprintf(msg, sizeof(msg), "digits/%c.wav", *p);
        conference_member_play_file(member, msg, 0, 1);
    }

}

static void conference_loop_fn_energy_dn(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512], str[30] = "", *p;
    switch_event_t *event;

    if (member == NULL)
        return;

    member->energy_level -= 200;
    if (member->energy_level < 0) {
        member->energy_level = 0;
    }

    if (test_eflag(member->conference, EFLAG_ENERGY_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "energy-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->energy_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Energy level %d", member->energy_level);
    //conference_member_say(member, msg, 0);

    switch_snprintf(str, sizeof(str), "%d", abs(member->energy_level) / 200);
    for (p = str; p && *p; p++) {
        switch_snprintf(msg, sizeof(msg), "digits/%c.wav", *p);
        conference_member_play_file(member, msg, 0, 1);
    }

}

static void conference_loop_fn_volume_talk_up(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512];
    switch_event_t *event;

    if (member == NULL)
        return;

    member->volume_out_level++;
    switch_normalize_volume(member->volume_out_level);

    if (test_eflag(member->conference, EFLAG_VOLUME_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "volume-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->volume_out_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Volume level %d", member->volume_out_level);
    //conference_member_say(member, msg, 0);

    if (member->volume_out_level < 0) {
        switch_snprintf(msg, sizeof(msg), "currency/negative.wav", member->volume_out_level);
        conference_member_play_file(member, msg, 0, 1);
    }

    switch_snprintf(msg, sizeof(msg), "digits/%d.wav", abs(member->volume_out_level));
    conference_member_play_file(member, msg, 0, 1);
}

static void conference_loop_fn_volume_talk_zero(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512];
    switch_event_t *event;

    if (member == NULL)
        return;

    member->volume_out_level = 0;

    if (test_eflag(member->conference, EFLAG_VOLUME_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "volume-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->volume_out_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Volume level %d", member->volume_out_level);
    //conference_member_say(member, msg, 0);


    if (member->volume_out_level < 0) {
        switch_snprintf(msg, sizeof(msg), "currency/negative.wav", member->volume_out_level);
        conference_member_play_file(member, msg, 0, 1);
    }

    switch_snprintf(msg, sizeof(msg), "digits/%d.wav", abs(member->volume_out_level));
    conference_member_play_file(member, msg, 0, 1);
}

static void conference_loop_fn_volume_talk_dn(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512];
    switch_event_t *event;

    if (member == NULL)
        return;

    member->volume_out_level--;
    switch_normalize_volume(member->volume_out_level);

    if (test_eflag(member->conference, EFLAG_VOLUME_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "volume-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->volume_out_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Volume level %d", member->volume_out_level);
    //conference_member_say(member, msg, 0);

    if (member->volume_out_level < 0) {
        switch_snprintf(msg, sizeof(msg), "currency/negative.wav", member->volume_out_level);
        conference_member_play_file(member, msg, 0, 1);
    }

    switch_snprintf(msg, sizeof(msg), "digits/%d.wav", abs(member->volume_out_level));
    conference_member_play_file(member, msg, 0, 1);
}

static void conference_loop_fn_volume_listen_up(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512];
    switch_event_t *event;

    if (member == NULL)
        return;

    member->volume_in_level++;
    switch_normalize_volume(member->volume_in_level);

    if (test_eflag(member->conference, EFLAG_GAIN_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "gain-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->volume_in_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Gain level %d", member->volume_in_level);
    //conference_member_say(member, msg, 0);

    if (member->volume_in_level < 0) {
        switch_snprintf(msg, sizeof(msg), "currency/negative.wav", member->volume_in_level);
        conference_member_play_file(member, msg, 0, 1);
    }

    switch_snprintf(msg, sizeof(msg), "digits/%d.wav", abs(member->volume_in_level));
    conference_member_play_file(member, msg, 0, 1);

}

static void conference_loop_fn_volume_listen_zero(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512];
    switch_event_t *event;

    if (member == NULL)
        return;

    member->volume_in_level = 0;

    if (test_eflag(member->conference, EFLAG_GAIN_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "gain-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->volume_in_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Gain level %d", member->volume_in_level);
    //conference_member_say(member, msg, 0);

    if (member->volume_in_level < 0) {
        switch_snprintf(msg, sizeof(msg), "currency/negative.wav", member->volume_in_level);
        conference_member_play_file(member, msg, 0, 1);
    }

    switch_snprintf(msg, sizeof(msg), "digits/%d.wav", abs(member->volume_in_level));
    conference_member_play_file(member, msg, 0, 1);

}

static void conference_loop_fn_volume_listen_dn(conference_member_t *member, caller_control_action_t *action)
{
    char msg[512];
    switch_event_t *event;

    if (member == NULL)
        return;

    member->volume_in_level--;
    switch_normalize_volume(member->volume_in_level);

    if (test_eflag(member->conference, EFLAG_GAIN_LEVEL) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "gain-level");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-Level", "%d", member->volume_in_level);
        switch_event_fire(&event);
    }

    //switch_snprintf(msg, sizeof(msg), "Gain level %d", member->volume_in_level);
    //conference_member_say(member, msg, 0);

    if (member->volume_in_level < 0) {
        switch_snprintf(msg, sizeof(msg), "currency/negative.wav", member->volume_in_level);
        conference_member_play_file(member, msg, 0, 1);
    }

    switch_snprintf(msg, sizeof(msg), "digits/%d.wav", abs(member->volume_in_level));
    conference_member_play_file(member, msg, 0, 1);

}

static void conference_loop_fn_event(conference_member_t *member, caller_control_action_t *action)
{
    switch_event_t *event;
    if (test_eflag(member->conference, EFLAG_DTMF) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "dtmf");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "DTMF-Key", action->binded_dtmf);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Data", action->expanded_data);
        switch_event_fire(&event);
    }
}

static void conference_loop_fn_transfer(conference_member_t *member, caller_control_action_t *action)
{
    char *exten = NULL;
    char *dialplan = "XML";
    char *context = "default";

    char *argv[3] = { 0 };
    int argc;
    char *mydata = NULL;
    switch_event_t *event;

    if (test_eflag(member->conference, EFLAG_DTMF) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "transfer");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Dialplan", action->expanded_data);
        switch_event_fire(&event);
    }
    clear_member_state_locked(member, MFLAG_RUNNING);

    if ((mydata = switch_core_session_strdup(member->session, action->expanded_data))) {
        if ((argc = switch_separate_string(mydata, ' ', argv, (sizeof(argv) / sizeof(argv[0]))))) {
            if (argc > 0) {
                exten = argv[0];
            }
            if (argc > 1) {
                dialplan = argv[1];
            }
            if (argc > 2) {
                context = argv[2];
            }

        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Empty transfer string [%s]\n", (char *) action->expanded_data);
            goto done;
        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Unable to allocate memory to duplicate transfer data.\n");
        goto done;
    }
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG, "Transfering to: %s, %s, %s\n", exten, dialplan, context);

    switch_ivr_session_transfer(member->session, exten, dialplan, context);

  done:
    return;
}

static void conference_loop_fn_exec_app(conference_member_t *member, caller_control_action_t *action)
{
    char *app = NULL;
    char *arg = "";

    char *argv[2] = { 0 };
    int argc;
    char *mydata = NULL;
    switch_event_t *event = NULL;
    switch_channel_t *channel = NULL;

    if (!action->expanded_data) return;

    if (test_eflag(member->conference, EFLAG_DTMF) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "execute_app");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Application", action->expanded_data);
        switch_event_fire(&event);
    }

    mydata = strdup(action->expanded_data);
    switch_assert(mydata);

    if ((argc = switch_separate_string(mydata, ' ', argv, (sizeof(argv) / sizeof(argv[0]))))) {
        if (argc > 0) {
            app = argv[0];
        }
        if (argc > 1) {
            arg = argv[1];
        }

    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Empty execute app string [%s]\n",
                          (char *) action->expanded_data);
        goto done;
    }

    if (!app) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Unable to find application.\n");
        goto done;
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG, "Execute app: %s, %s\n", app, arg);

    channel = switch_core_session_get_channel(member->session);

    switch_channel_set_app_flag(channel, CF_APP_TAGGED);
    switch_core_session_set_read_codec(member->session, NULL);
    switch_core_session_execute_application(member->session, app, arg);
    switch_core_session_set_read_codec(member->session, &member->read_codec);
    switch_channel_clear_app_flag(channel, CF_APP_TAGGED);

  done:

    switch_safe_free(mydata);

    return;
}

static void conference_loop_fn_hangup(conference_member_t *member, caller_control_action_t *action)
{
    clear_member_state_locked(member, MFLAG_RUNNING);
}


static int noise_gate_check(conference_member_t *member)
{
    int r = 0;


    if (member->conference->agc_level && member->agc_volume_in_level != 0) {
        int target_score = 0;

        target_score = (member->energy_level + (25 * member->agc_volume_in_level));

        if (target_score < 0) target_score = 0;

        r = (int)member->score > target_score;

    } else {
        r = (int32_t)member->score > member->energy_level;
    }

    return r;
}

static void clear_avg(conference_member_t *member)
{

    member->avg_score = 0;
    member->avg_itt = 0;
    member->avg_tally = 0;
    member->agc_concur = 0;
}

static void check_agc_levels(conference_member_t *member)
{
    int x = 0;

    if (!member->avg_score) return;

    if ((int)member->avg_score < member->conference->agc_level - 100) {
        member->agc_volume_in_level++;
        switch_normalize_volume_granular(member->agc_volume_in_level);
        x = 1;
    } else if ((int)member->avg_score > member->conference->agc_level + 100) {
        member->agc_volume_in_level--;
        switch_normalize_volume_granular(member->agc_volume_in_level);
        x = -1;
    }

    if (x) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG7,
                          "AGC %s:%d diff:%d level:%d cur:%d avg:%d vol:%d %s\n",
                          member->conference->name,
                          member->id, member->conference->agc_level - member->avg_score, member->conference->agc_level,
                          member->score, member->avg_score, member->agc_volume_in_level, x > 0 ? "+++" : "---");

        clear_avg(member);
    }
}


#define MIN_STAT_REPORT_INTERVAL_MS 2 * 1000 //2 sec(s)
#define STATS_LEADIN_TIME_MS (5 * 1000) //5secs; Initial time to ignore to compensate for media lag after signaling


void init_input_loop(input_loop_data_t *il, conference_member_t *member) {

    memset(il, 0, sizeof(input_loop_data_t));
    il->member = member;
    il->hangover = 40;
    il->hangunder = 5;
    il->diff_level = 400;
    il->session = member->session;
    il->io_flags = SWITCH_IO_FLAG_NONE;
    il->last_stat_report_time_ms = switch_micro_time_now() / 1000;
    il->tid = switch_thread_self();
    il->session = member->session;
    il->channel = switch_core_session_get_channel(il->session);
    il->rx_time = 0;
}

/* marshall frames from the call leg to the conference thread for muxing to other call legs */
static switch_status_t conference_loop_input_setup(input_loop_data_t *il)
{
    conference_member_t *member = il->member;
    switch_core_session_t *session = member->session;
    switch_channel_t *channel = il->channel;
    
    if (switch_core_session_read_lock(session) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "switch_core_session_read_lock failed\n");
        clear_member_state_locked(member, MFLAG_ITHREAD);
        return SWITCH_STATUS_FALSE;
    }

    clear_member_state_locked(member, MFLAG_TALKING);
    switch_core_session_get_read_impl(session, &member->read_impl);

    switch_snprintf(il->var_val, sizeof(il->var_val), "%u", member->read_impl.actual_samples_per_second);
    switch_channel_set_variable(channel, "rtp_samples_per_second", il->var_val);

    if (switch_channel_get_variable(channel, "use_webrtc_neteq")) {
        il->io_flags |= SWITCH_IO_FLAG_RETURN_ON_ZERO_READ;
    }

    /* luke: what's this? */
    switch_channel_audio_sync(channel);

    il->flush_len = switch_samples_per_packet(member->conference->rate, member->conference->interval) * 6;

    /* As long as we have a valid read, feed that data into an input buffer where the conference thread will take it
       and mux it with any audio from other channels. */
    
    il->rx_period_start = switch_time_now();

    switch_set_dont_wait_for_packets(channel);

    set_member_state_locked(member, MFLAG_ITHREAD);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "input processing setup done!\n");

    return SWITCH_STATUS_SUCCESS;
}

static void process_dtmf(conference_member_t *member)
{
    switch_channel_t *channel = member->channel;
    switch_core_session_t *session = member->session;

    if (switch_channel_has_dtmf(channel)) {
        char dtmf[128] = "";

        switch_channel_dequeue_dtmf_string(channel, dtmf, sizeof(dtmf));

        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                          "DTMF! %s\n", dtmf);

        if (switch_test_flag(member, MFLAG_DIST_DTMF)) {
            conference_send_all_dtmf(member, member->conference, dtmf);
        } else if (member->dmachine) {
            char *p;
            char str[2] = "";
            for (p = dtmf; p && *p; p++) {
                str[0] = *p;
                switch_ivr_dmachine_feed(member->dmachine, str, NULL);
            }
        }
    } else if (member->dmachine) {
        switch_ivr_dmachine_ping(member->dmachine, NULL);
    }
    if (switch_queue_size(member->dtmf_queue)) {
        switch_dtmf_t *dt;
        void *pop;

        if (switch_queue_trypop(member->dtmf_queue, &pop) == SWITCH_STATUS_SUCCESS) {
            dt = (switch_dtmf_t *) pop;
            switch_core_session_send_dtmf(member->session, dt);
            free(dt);
        }
    }
}

/* marshall frames from the call leg to the conference thread for muxing to other call legs */
static INPUT_LOOP_RET conference_loop_input(input_loop_data_t *il)
{
    conference_member_t *member = il->member;
    switch_core_session_t *session = member->session;
    switch_channel_t *channel = il->channel;
    switch_status_t status;
    switch_time_t send_time;
    switch_bool_t can_speak = SWITCH_FALSE;

    if (!(switch_test_flag(member, MFLAG_RUNNING) && switch_channel_ready(channel))) {
        return INPUT_LOOP_RET_DONE;
    }

    if (!switch_test_flag(member, MFLAG_ITHREAD)) {
        return INPUT_LOOP_RET_DONE;
    }


    if (switch_channel_ready(channel) && switch_channel_test_app_flag(channel, CF_APP_TAGGED)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Input Timer: switch yield\n");
        /* switch_yield(100000); */
        return INPUT_LOOP_RET_YIELD;
    }

    /* Read a frame */
    /* MQT-1766 */
    if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        /* not muted */
        if (il->io_flags & SWITCH_IO_FLAG_CANT_SPEAK) {
            il->io_flags |= SWITCH_IO_FLAG_CLEAR_LOST;
        }
        il->io_flags &= ~SWITCH_IO_FLAG_CANT_SPEAK;
    } else {
#ifdef BEFORE_RADUS_CHANGE
        /* muted, purge jitter buffer when entering muted state, or when using encoded frame rather than doing encoding */
        il->io_flags |= SWITCH_IO_FLAG_CANT_SPEAK;
#else
        if (switch_test_flag(member, MFLAG_USE_FAKE_MUTE)) {
            /* muted on the client side, we keep it unmuted here */
            il->io_flags &= ~SWITCH_IO_FLAG_CANT_SPEAK;
        } else {
            /* muted, purge jitter buffer when entering muted state, or when using encoded frame rather than doing encoding */
            il->io_flags |= SWITCH_IO_FLAG_CANT_SPEAK;
        }
#endif
    }
    /* put packets into active speaker jitter buffer if not muted */
    if ((member->one_of_active == SWITCH_TRUE) && (switch_test_flag(member, MFLAG_TALKING))) {
        il->io_flags |= SWITCH_IO_FLAG_ACTIVE_TALKER;
    } else {
        il->io_flags &= ~SWITCH_IO_FLAG_ACTIVE_TALKER;
    }

#if 0
    status = switch_core_session_read_frame_w_time(session, &il->read_frame, il->io_flags, 0, &send_time);
#else
    status = switch_core_session_fast_read_frame_from_socket(session, &il->read_frame, il->io_flags, 0, &send_time);
    status = switch_core_session_fast_read_frame_from_jitterbuffer(session, &il->read_frame, il->io_flags, 0, &send_time);
#endif

    if (!il->leadin_over && il->read_frame) {
        switch_time_t now = switch_micro_time_now();
        if (now/1000 > il->last_stat_report_time_ms + STATS_LEADIN_TIME_MS) {
            switch_clear_flag(il->read_frame, SFF_RTP_EVENT);
            il->leadin_over = 1;
        }
    } else if (il->read_frame && ((il->read_frame->flags & SFF_RTP_EVENT) || il->pending_event)) {
        switch_time_t now = switch_micro_time_now();
        if (now/1000 > il->last_stat_report_time_ms + MIN_STAT_REPORT_INTERVAL_MS) {
            switch_set_flag_locked(member, MFLAG_LOG_STATS);
            il->last_stat_report_time_ms = now/1000;
            il->pending_event = 0;
        } else {
            il->pending_event = 1;
        }
        switch_clear_flag(il->read_frame, SFF_RTP_EVENT);
    }

    if (status == SWITCH_STATUS_FALSE || !il->read_frame || !il->read_frame->datalen) {
        /*
         * Can happen if webrtc neteq is enabled and read socket is hot
         */
        uint32_t low_frame_count = 0;

        if (session) {
            low_frame_count = switch_core_session_get_low_energy(session);
        }

        process_dtmf(member);

        if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
            if (low_frame_count > 50) {
                if (low_frame_count % 3000 == 1) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                                      "conference: %s member: %s rtp audio level is less than 51dB (%d times)\n",
                                      member->conference->meeting_id, member->mname, low_frame_count);
                }
            }
        }
        
        switch_mutex_unlock(member->read_mutex);

        return INPUT_LOOP_RET_NO_FRAME;
    }

    switch_mutex_lock(member->read_mutex);

    /* end the loop, if appropriate */
    if (!SWITCH_READ_ACCEPTABLE(status) || !switch_test_flag(member, MFLAG_RUNNING)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                          "conference: %s member: %s ending loop run=%d read_acceptable=%d\n",
                          member->conference->meeting_id, member->mname, switch_test_flag(member, MFLAG_RUNNING), 
                          SWITCH_READ_ACCEPTABLE(status));
        switch_mutex_unlock(member->read_mutex);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                          "end input loop mid:%s/%d status:%d\n", member->mname, member->id, status);
        return INPUT_LOOP_RET_BREAK;
    }
    
    /* if we have caller digits, feed them to the parser to find an action */
    process_dtmf(member);

    if (switch_test_flag(il->read_frame, SFF_CNG)) {
        if (member->conference->agc_level) {
            member->nt_tally++;
        }
        
        if (il->hangunder_hits) {
            il->hangunder_hits--;
        }
        if (switch_test_flag(member, MFLAG_TALKING)) {
            if (++il->hangover_hits >= il->hangover) {
                il->hangover_hits = il->hangunder_hits = 0;
                clear_member_state_locked(member, MFLAG_TALKING);
                member_update_status_field(member);
                check_agc_levels(member);
                clear_avg(member);
                member->score_iir = 0;
            }
        }
        
        switch_mutex_unlock(member->read_mutex);

        return INPUT_LOOP_RET_CNG;
    }
    
    if (member->nt_tally > (int32_t)(member->read_impl.actual_samples_per_second / member->read_impl.samples_per_packet) * 3) {
        member->agc_volume_in_level = 0;
        clear_avg(member);
    }

    /* Check for input volume adjustments */
    if (!member->conference->agc_level) {
        member->conference->agc_level = 0;
        clear_avg(member);
    }

    can_speak = switch_test_flag(member, MFLAG_CAN_SPEAK) || (!switch_test_flag(member, MFLAG_CAN_SPEAK) &&
                                                              switch_test_flag(member, MFLAG_USE_FAKE_MUTE) &&
                                                              !switch_core_session_get_cn_state(member->session));

    /* if the member can speak, compute the audio energy level and */
    /* generate events when the level crosses the threshold        */
    if (can_speak || switch_test_flag(member, MFLAG_MUTE_DETECT)) {
        uint32_t energy = 0, i = 0, samples = 0, j = 0;
        int16_t *data;
        int agc_period = (member->read_impl.actual_samples_per_second / member->read_impl.samples_per_packet) / 4;

        data = il->read_frame->data;
        member->score = 0;

        if (member->volume_in_level) {
            switch_change_sln_volume(il->read_frame->data, il->read_frame->datalen / 2, member->volume_in_level);
        }

        if (member->agc_volume_in_level) {
            switch_change_sln_volume_granular(il->read_frame->data, il->read_frame->datalen / 2, member->agc_volume_in_level);
        }

        if ((samples = il->read_frame->datalen / sizeof(*data))) {
            for (i = 0; i < samples; i++) {
                energy += abs(data[j]);
                j += member->read_impl.number_of_channels;
            }

            member->score = energy / samples;
        }

        if (member->vol_period) {
            member->vol_period--;
        }

        if (member->conference->agc_level && member->score && can_speak && noise_gate_check(member)) {
            int last_shift = abs(member->last_score - member->score);

            if (member->score && member->last_score && last_shift > 900) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG7,
                                  "AGC %s:%d drop anomalous shift of %d\n",
                                  member->conference->name,
                                  member->id, last_shift);
            } else {
                member->avg_tally += member->score;
                member->avg_itt++;
                if (!member->avg_itt) member->avg_itt++;
                member->avg_score = member->avg_tally / member->avg_itt;
            }

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG7,
                              "AGC %s:%d diff:%d level:%d cur:%d avg:%d vol:%d\n",
                              member->conference->name,
                              member->id, member->conference->agc_level - member->avg_score, member->conference->agc_level,
                              member->score, member->avg_score, member->agc_volume_in_level);
            
            if (++member->agc_concur >= agc_period) {
                if (!member->vol_period) {
                    check_agc_levels(member);
                }
                member->agc_concur = 0;
            }
        } else {
            member->nt_tally++;
        }

        member->score_iir = (int) (((1.0 - SCORE_DECAY) * (float) member->score) + (SCORE_DECAY * (float) member->score_iir));

        if (member->score_iir > SCORE_MAX_IIR) {
            member->score_iir = SCORE_MAX_IIR;
        }

        if (noise_gate_check(member)) {
            uint32_t diff = member->score - member->energy_level;
            if (il->hangover_hits) {
                il->hangover_hits--;
            }

            if (member->conference->agc_level) {
                member->nt_tally = 0;
            }

            if (diff >= il->diff_level || ++il->hangunder_hits >= il->hangunder) {
                il->hangover_hits = il->hangunder_hits = 0;
                member->last_talking = switch_epoch_time_now(NULL);
                if (!switch_test_flag(member, MFLAG_TALKING)) {
                    set_member_state_locked(member, MFLAG_TALKING);
                    if (switch_test_flag(member, MFLAG_MUTE_DETECT) && !can_speak) {
                        switch_event_t *event;
                        if (!zstr(member->conference->mute_detect_sound)) {
                            set_member_state_unlocked(member, MFLAG_INDICATE_MUTE_DETECT);
                        }
                        if (test_eflag(member->conference, EFLAG_MUTE_DETECT) &&
                            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
                            conference_add_event_member_data(member, event);
                            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "mute-detect");
                            switch_event_fire(&event);
                        }
                    }
                }
            }
        } else {
            if (il->hangunder_hits) {
                il->hangunder_hits--;
            }
            
            if (member->conference->agc_level) {
                member->nt_tally++;
            }
            
            if (switch_test_flag(member, MFLAG_TALKING) && can_speak) {
                if (++il->hangover_hits >= il->hangover) {
                    il->hangover_hits = il->hangunder_hits = 0;
                    clear_member_state_locked(member, MFLAG_TALKING);
                    member_update_status_field(member);
                    check_agc_levels(member);
                    clear_avg(member);
                }
            }
        }
        
        
        member->last_score = member->score;
    }
    
    il->loops++;
    
    if (switch_channel_test_flag(member->channel, CF_CONFERENCE_RESET_MEDIA)) {
        switch_channel_clear_flag(member->channel, CF_CONFERENCE_RESET_MEDIA);
        
        if (il->loops > 500) {
            member->loop_loop = 1;
            
            if (setup_media(member, member->conference)) {
                switch_mutex_unlock(member->read_mutex);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                                  "end input loop mid:%s/%d reset media\n", member->mname, member->id);
                return INPUT_LOOP_RET_BREAK;
            }
        }
        
    }
    
    /* skip frames that are not actual media or when we are muted or silent */
/* xxx this is where i left off with can_speak */
    if ((switch_test_flag(member, MFLAG_TALKING) || 
         member->energy_level == 0 || 
         switch_test_flag(member->conference, CFLAG_AUDIO_ALWAYS) || 
         member->conference->last_active_talkers[0] == member || 
         member->conference->last_active_talkers[1] == member)
        && can_speak &&    !switch_test_flag(member->conference, CFLAG_WAIT_MOD) &&
        (member->conference->count > 1 || member->conference->is_recording)) {
        switch_audio_resampler_t *read_resampler = member->read_resampler;
        void *data;
        uint32_t datalen;
        
        if (read_resampler) {
            int16_t *bptr = (int16_t *) il->read_frame->data;
            int len = (int) il->read_frame->datalen;
            
            switch_resample_process(read_resampler, bptr, len / 2);
            memcpy(member->resample_out, read_resampler->to, read_resampler->to_len * 2);
            len = read_resampler->to_len * 2;
            datalen = len;
            data = member->resample_out;
        } else {
            data = il->read_frame->data;
            datalen = il->read_frame->datalen;
        }
        
        
        if (datalen) {
            switch_size_t ok = 1;
            
            /* Write the audio into the input buffer */
            switch_mutex_lock(member->audio_in_mutex);
            if (switch_buffer_inuse(member->audio_buffer) > il->flush_len) {
                switch_buffer_zero(member->audio_buffer);
                switch_channel_audio_sync(channel);
            }
            ok = switch_buffer_write(member->audio_buffer, data, datalen);
            switch_mutex_unlock(member->audio_in_mutex);
            if (!ok) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "CRITICAL: Cannot write the audio in the input buffer");
                switch_mutex_unlock(member->read_mutex);
                return INPUT_LOOP_RET_BREAK;
            }
        }
    }
    
    switch_mutex_unlock(member->read_mutex);

    return INPUT_LOOP_RET_DONE;
}

static void conference_loop_input_cleanup(input_loop_data_t *il)
{
    conference_member_t *member = il->member;
    switch_core_session_t *session = member->session;

    if (!switch_test_flag(il->member, MFLAG_ITHREAD)) {
        return;
    }

    if (switch_queue_size(member->dtmf_queue)) {
        switch_dtmf_t *dt;
        void *pop;

        while (switch_queue_trypop(member->dtmf_queue, &pop) == SWITCH_STATUS_SUCCESS) {
            dt = (switch_dtmf_t *) pop;
            free(dt);
        }
    }

    if (member->read_resampler) {
        switch_resample_destroy(&member->read_resampler);
        member->read_resampler = NULL;
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO,
                      "M(%s)/I(%s):U(%s) (id:%d) input thread stopping\n",
                      member->conference->meeting_id, member->conference->instance_id, member->mname, member->id);

    clear_member_state_locked(member, MFLAG_ITHREAD);

    switch_core_session_rwunlock(session);

    return;
}

static void set_ols_stopping(output_loop_t *ols) {
    if (ols) {
        ols->stopping = 1;
#if 0
        if (!ols->stopping) {
            ols->stopping = 1 + (rand() % 20);
        }
#endif
    }
}

static void member_add_file_data(conference_member_t *member, int16_t *data, switch_size_t file_data_len)
{
    switch_size_t file_sample_len = file_data_len / 2;
    int16_t file_frame[SWITCH_RECOMMENDED_BUFFER_SIZE / 2] = { 0 };

    memset(file_frame, 0, SWITCH_RECOMMENDED_BUFFER_SIZE);

    switch_mutex_lock(member->fnode_mutex);

    if (!member->fnode) {
        goto done;
    }

    /* if we are done, clean it up */
    if (member->fnode->done) {
        conference_file_node_t *fnode;
        switch_memory_pool_t *pool;

        if (switch_test_flag((&member->fnode->fh), SWITCH_FILE_OPEN)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                              "mid:%d  closing file\n", member->id);
            conference_file_close(member->conference, member->fnode);
        }

        fnode = member->fnode;
        member->fnode = member->fnode->next;

        pool = fnode->pool;
        fnode = NULL;
        switch_core_destroy_memory_pool(&pool);
    } else {
        /* skip this frame until leadin time has expired */
        if (member->fnode->leadin) {
            member->fnode->leadin--;
        } else {
            if (member->fnode->type == NODE_TYPE_SPEECH) {
                switch_speech_flag_t flags = SWITCH_SPEECH_FLAG_BLOCKING;

                if (switch_core_speech_read_tts(member->fnode->sh, file_frame, &file_data_len, &flags) == SWITCH_STATUS_SUCCESS) {
                    file_sample_len = file_data_len / 2;
                } else {
                    file_sample_len = file_data_len = 0;
                }
            } else if (member->fnode->type == NODE_TYPE_FILE) {
                switch_core_file_read(&member->fnode->fh, file_frame, &file_sample_len);
                file_data_len = file_sample_len * 2;
            } else if (member->fnode->type == NODE_TYPE_CURSOR) {
                goto done;
            }

            if (file_sample_len <= 0) {
                member->fnode->done++;
            } else {            /* there is file node data to mix into the frame */
                int32_t i, sample;

                /* Check for output volume adjustments */
                if (member->volume_out_level) {
                    switch_change_sln_volume(file_frame, (uint32_t)file_sample_len, member->volume_out_level);
                }

                /* Fuze added clearing of data */
                if (!member->fnode->mux) {
                    memset(data, 0, SWITCH_RECOMMENDED_BUFFER_SIZE);
                }
                
                for (i = 0; i < (int)file_sample_len; i++) {
                    if (member->fnode->mux) {
                        sample = data[i] + file_frame[i];
                        switch_normalize_to_16bit(sample);
                        data[i] = (int16_t)sample;
                    } else {
                        data[i] = file_frame[i];
                    }
                }

            }
        }
    }

 done:

    switch_mutex_unlock(member->fnode_mutex);
}


/* launch an input thread for the call leg */
static void launch_conference_loop_output(int i, switch_memory_pool_t *pool)
{
    switch_threadattr_t *thd_attr = NULL;

    switch_threadattr_create(&thd_attr, pool);
    switch_threadattr_detach_set(thd_attr, 1);
    switch_threadattr_priority_set(thd_attr, SWITCH_PRI_REALTIME);
    switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
    
    switch_mutex_lock(globals.hash_mutex);
    switch_mutex_unlock(globals.hash_mutex);

    switch_thread_create(&globals.output_thread[i], thd_attr, conference_loop_output, &globals.outputll[i], pool);
}
    
#define PERIODIC_STATS_INTERVAL_MS (5 * 60 * 1000) //5 mins

switch_frame_t *process_file_play(conference_member_t *member,
                                  switch_frame_t *write_frame,
                                  switch_bool_t exclusive_play) {
    switch_frame_t *frame = NULL;
    
    if (member->fnode) {
        if (member->fnode->exclusive_play || exclusive_play) {
            memset(write_frame->data, 255, write_frame->datalen);
        }

        member_add_file_data(member, write_frame->data, write_frame->datalen);

        if (member->fnode && (member->fnode->exclusive_play || exclusive_play)) {
            if (member->fnode->cursor.active && member->fnode->cursor.file) {
                /* yyy */
                if (member->fnode->cursor.file->writing) {
                    switch_mutex_lock(member->fnode->cursor.file->file_mutex);
                    if (!(frame = fc_get_frame(&member->fnode->cursor))) {
                        /* encode and add our buffer */
                        if (switch_core_session_enc_frame(member->session, write_frame, SWITCH_IO_FLAG_NONE, 0,
                                                          &frame) != SWITCH_STATUS_SUCCESS) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "member %d failed to encode\n", member->id);
                            switch_mutex_unlock(member->fnode->cursor.file->file_mutex);
                            return NULL;
                        } else {
                            member->meo.ivr_encode_cnt += 1;
                            member->meo.cwc->ivr_encode_cnt += 1;
                        }
                        if (!fc_add_frame(&member->fnode->cursor, frame)) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "member %d add frame failed\n", member->id);
                            switch_mutex_unlock(member->fnode->cursor.file->file_mutex);
                            return NULL;
                        } else {
                            if (member->fnode->done) {
                                /* complete! */
                                member->fnode->cursor.file->writing = SWITCH_FALSE;
                                fc_complete(&member->fnode->cursor);
                                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "member %d file=%s done\n",
                                                  member->id, member->fnode->cursor.file->name);
                            }
                        }
                    }
                    switch_mutex_unlock(member->fnode->cursor.file->file_mutex);
                } else {
                    if (!(frame = fc_get_frame(&member->fnode->cursor))) {
                        conference_file_node_t *fnode;
                        switch_memory_pool_t *pool;

                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "member %d done reading file %s\n",
                                          member->id, member->fnode->cursor.file->name);
                        member->fnode->done = SWITCH_TRUE;

                        if (member->fnode && switch_test_flag((&member->fnode->fh), SWITCH_FILE_OPEN)) {
                            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                                              "mid:%d  closing file\n", member->id);
                            conference_file_close(member->conference, member->fnode);
                        }

                        fnode = member->fnode;
                        member->fnode = member->fnode->next;
                            
                        pool = fnode->pool;
                        fnode = NULL;
                        switch_core_destroy_memory_pool(&pool);
                    } else {
                        member->meo.ivr_copy_cnt += 1;
                    }
                }
            }
        }
    }
    return frame;
}
    
void init_output_loop(output_loop_t *ol, conference_member_t *member, switch_thread_id_t tid) {
    memset(ol, 0, sizeof(output_loop_t));

    ol->tid = tid;
    ol->oldtid = tid;
    ol->individual = SWITCH_FALSE;

    ol->rx_time = 0;

    switch_core_session_get_read_impl(member->session, &ol->read_impl);
    ol->member = member;
    ol->sanity = 2000;
    
    ol->channel = switch_core_session_get_channel(member->session);
    ol->interval = member->conference->interval;
    ol->samples = switch_samples_per_packet(member->conference->rate, ol->interval);

    ol->tsamples = member->orig_read_impl.samples_per_packet;
    ol->bytes = ol->samples * 2;
    
    ol->ticks_per_interval = PERIODIC_STATS_INTERVAL_MS / ol->interval;
    ol->ticks_per_stats_check = MIN_STAT_REPORT_INTERVAL_MS / ol->interval;
    ol->ticks_per_heartbeat = DEFAULT_MIN_HEARTBEAT_INTERVAL_MS / ol->interval;

    switch_assert(member->conference != NULL);
    ol->flush_len = switch_samples_per_packet(member->conference->rate, member->conference->interval) * 10;

    ol->write_frame.data = ol->data = switch_core_session_alloc(member->session, SWITCH_RECOMMENDED_BUFFER_SIZE);
    ol->write_frame.buflen = SWITCH_RECOMMENDED_BUFFER_SIZE;
    
    ol->write_frame.codec = &member->write_codec;

    ol->acc_frame.data = ol->data = switch_core_session_alloc(member->session, SWITCH_RECOMMENDED_BUFFER_SIZE);
    ol->acc_frame.buflen = SWITCH_RECOMMENDED_BUFFER_SIZE;

    ol->acc_frame.codec = &member->write_codec;

    ol->frame_cnt = 0;

    member->out_start_of_interval = switch_micro_time_now() / 1000;
    member->out_last_sent = member->out_start_of_interval;
    
    ol->starting = SWITCH_TRUE;
    ol->new_ol = SWITCH_TRUE;
    ol->initialized = SWITCH_FALSE;

    switch_mutex_init(&ol->cond_mutex, SWITCH_MUTEX_NESTED, member->pool);
    switch_thread_cond_create(&ol->cond, member->pool);
}
    
typedef enum {
    OUTPUT_LOOP_OK = 0,
    OUTPUT_LOOP_FAILED = 1,
    OUTPUT_LOOP_HANGUP = 2,
    OUTPUT_LOOP_TOO_SOON = 3,
    OUTPUT_LOOP_ALREADY_STOPPED =4
} OUTPUT_LOOP_RET;

OUTPUT_LOOP_RET process_output_loop(output_loop_t *ols, switch_timer_t *timer);
OUTPUT_LOOP_RET process_output_loop_end_member(output_loop_t *ols);
SWITCH_DECLARE(void) switch_close_transport(switch_channel_t *channel);

/* marshall frames from the conference (or file or tts output) to the call leg */
/* NB. this starts the input thread after some initial setup for the call leg */
/* todo:
 * replace: switch_core_get_monitor_index(member->session)
 */
static void start_conference_loops(conference_member_t *member)
{
    output_loop_t ols;
    input_loop_data_t ils;
    switch_thread_id_t tid = switch_thread_self();
    switch_core_session_t *session = member->session;
    int ret;

    init_output_loop(&ols, member, tid);
    init_input_loop(&ils, member);
    ols.ild = &ils;

    if (!switch_test_flag(member->conference, CFLAG_ANSWERED)) {
        switch_channel_answer(ols.channel);
    }

    ret = output_loop_list_add(member->conference, &ols);

    if (ret != -1) {
        int idx = ret / MAX_NUMBER_OF_OUTPUT_NTHREADS;
        member->meo.cwc = cwc_get(member->conference->ceo.cwc[idx], member->orig_read_impl.codec_id, member->orig_read_impl.impl_id);
        member->meo.filelist = filelist_get(globals.filelist[ret], member->orig_read_impl.codec_id, member->orig_read_impl.impl_id);
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "start_conference_loops mid:%s/%d output_loop_list_added to %d\n",
                      member->mname, member->id, ret);

    switch_mutex_lock(ols.cond_mutex);
    switch_thread_cond_wait(ols.cond, ols.cond_mutex);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "and we're back from the wait conf:%s mid:%s/%d\n",
                      member->conference->meeting_id, member->mname, member->id);

    switch_channel_change_thread(ols.channel);

    output_loop_list_remove(member->conference, &ols);

    while (1) {
        OUTPUT_LOOP_RET oret;

        if (ols.stopping) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols.member->session), SWITCH_LOG_INFO,
                              "Conference Output stopping:%d stopped:%d ret:%d\n",
                              ols.stopping, ols.stopped, ret);

            oret = process_output_loop_end_member(&ols);

            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols.member->session), SWITCH_LOG_INFO,
                              "stopping ret=%d\n", oret);

            if (oret == OUTPUT_LOOP_OK) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols.member->session), SWITCH_LOG_INFO,
                                  "process_output_loop_end_member returned ok!\n");
                break;
            }
            switch_yield(10000);
        } else {
            break;
        }
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                      "Execution on another output channel's thread is done!.  mid:%s/%d idx:%d Wait here!\n",
                      member->mname, member->id, ols.list_idx);

    return;
}

/* 10 seconds * 1000ms/s * 1000us/ms */
#define PROCESSING_PERIOD (10*1000*1000)

static void check_conference_loops(int idx)
{
    switch_time_t now = switch_time_now();
    
    for (int i = 0; i < MAX_NUMBER_OF_OUTPUT_NTHREADS; i++) {
        /* 1 second */
        if (globals.outputll[i].count > 0) {
            if (now - globals.output_thread_time[i] > 1000000) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Loop %d appears to be dead (%lldus) found by %d\n",
                                  i, (long long)(now - globals.output_thread_time[i]), idx);
                globals.output_thread_dead[i] += 1;
            }
        }
    }
}


static void *SWITCH_THREAD_FUNC conference_loop_output(switch_thread_t *thread, void *obj)
{
    output_loop_list_t *list = (output_loop_list_t *)obj;

    switch_timer_t timer = {0};

    uint32_t interval = 20;
    uint32_t tsamples = 160;
    uint64_t loop_count = 0;
    switch_thread_id_t tid = switch_thread_self();
    switch_time_t min_time = 20000, loop_period_start;
    switch_time_t loop_now = switch_time_now();
    switch_time_t next_wake_up;
    switch_time_t time_asleep_sum = 0;
    uint32_t behind = 0;

    /*
     * There's an edge case where we might have 2 threads processing a single queue.  The last thread
     * to set the tid will be the one true owner.
     */
    switch_mutex_lock(globals.outputlllock);
    list->tid = tid;
    switch_mutex_unlock(globals.outputlllock);
    
    if (switch_core_timer_init(&timer, "soft", interval, tsamples, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Timer Setup Failed.  Conference Cannot Start\n");
        return NULL;
    }

    /* Fair WARNING, If you expect the caller to hear anything or for digit handling to be processed,      */
    /* you better not block this thread loop for more than the duration of member->conference->timer_name!  */
    loop_period_start = switch_time_now();

    /*
     * for overflows threads: run on condition variable
     * for normal threads: wake up every 20ms
     */
    if (list->idx >= MAX_NUMBER_OF_OUTPUT_NTHREADS) {
        switch_mutex_lock(globals.outputll[list->idx].cond_mutex);
    }
    next_wake_up = switch_time_now() + 20000;

    while (1) {
        globals.output_thread_time[list->idx] = loop_now;

        /* luke todo put in a stop condition */

        if ((loop_now - loop_period_start) > PROCESSING_PERIOD) {
            float ppp = 0;

            list->process_avg[list->process_avg_idx] = (float)(time_asleep_sum)/((loop_now - loop_period_start)/(20*1000));
            list->process_avg_min[list->process_avg_idx] = (float)min_time;

            if (list->count) {
                ppp = list->process_avg[list->process_avg_idx]/list->count;
            }

            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                              "loop %d processing cnt:%d avg:%.2fus min:%.0fus time/participant:%.2fus\n",
                              list->idx, list->count, list->process_avg[list->process_avg_idx],
                              list->process_avg_min[list->process_avg_idx], ppp);
            list->process_avg_idx = (list->process_avg_idx + 1) % PROCESS_AVG_CNT;

            check_conference_loops(list->idx);

            loop_period_start = loop_now;
            time_asleep_sum = 0;
            min_time = 20000;
        }

        switch_mutex_lock(list->lock);
        for (output_loop_t *ols = list->loop; ols; ols = ols->next) {
            INPUT_LOOP_RET ret;
            switch_time_t now = switch_time_now();

            if (ols->stopping) { 
                continue; 
            }

            /* if conference belongs to this thread */
            if (ols->member->conference->list_idx == list->idx && ols->member->conference->processed) {
                ols->member->conference->processed = SWITCH_FALSE;
            }

            if ((now - ols->ild->rx_period_start) > PROCESSING_PERIOD) {
                ols->ild->rx_period_start = now;
                ols->ild->max_time = 0;
                ols->ild->rx_time = 0;
            }

            now = switch_time_now();
            ret = conference_loop_input(ols->ild);
            now = switch_time_now() - now;

            ols->ild->rx_time += now;
            if (now > ols->ild->max_time) {
                ols->ild->max_time = now;
            }

            if (ret == INPUT_LOOP_RET_YIELD) {
                /* ok */
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                                  "input loop %d processing mid:%s/%d yield\n",
                                  list->idx, ols->member->mname, ols->member->id);
            } else if (ret == INPUT_LOOP_RET_NO_FRAME) {
                /* ok */
            } else if (ret == INPUT_LOOP_RET_CNG) {
                /* ok */
            } else if (ret == INPUT_LOOP_RET_BREAK) {
                /* oh no! */
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                                  "input loop %d processing mid:%s/%d break\n",
                                  list->idx, ols->member->mname, ols->member->id);
                conference_loop_input_cleanup(ols->ild); /* luke todo!!!! */
            }
        }
        switch_mutex_unlock(list->lock);

        if (list->idx >= MAX_NUMBER_OF_OUTPUT_NTHREADS) {
            switch_time_t time_asleep = switch_time_now();

            switch_thread_cond_wait(globals.outputll[list->idx].cond, globals.outputll[list->idx].cond_mutex);

            time_asleep = switch_time_now() - time_asleep;

            if (time_asleep > 20000) {
                time_asleep = 20000;
            }
            time_asleep_sum += time_asleep;
            if (time_asleep < min_time) {
                min_time = time_asleep;
            }

            loop_now = switch_time_now();
        }

        if (list->idx < MAX_NUMBER_OF_OUTPUT_NTHREADS) {
            switch_mutex_lock(list->lock);
            for (output_loop_t *ols = list->loop; ols; ols = ols->next) {
                CONFERENCE_LOOP_RET ret;
                switch_bool_t stop = SWITCH_FALSE;

                if (ols->stopping) {
                    continue;
                }

                /* if conference belongs to this thread */
                if (ols->member->conference->list_idx != list->idx || ols->member->conference->processed) {
                    continue;
                }

                /* Main monitor thread (1 per distinct conference room) */
                ret = conference_thread_run(ols->member->conference);

                ols->member->conference->processed = SWITCH_TRUE;

                switch (ret) {
                case CONFERENCE_LOOP_RET_STOP:
                    /* conference is over ... end */
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                                      "conference stopping\n");
                    stop = SWITCH_TRUE;
                    break;
                case CONFERENCE_LOOP_RET_BAD_BUFFER_WRITE:
                    /* end the conference */
                    stop = SWITCH_TRUE;
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                                      "conference stopping due to CONFERENCE_LOOP_RET_BAD_BUFFER_WRITE\n");
                    break;
                case CONFERENCE_LOOP_RET_OK:
                default:
                    /* do nothing! */
                    break;
                }

                if (stop) {
                    /* we need to stop all channels in this loop? */
                    for (output_loop_t *ols = list->loop; ols; ols = ols->next) {
                        set_ols_stopping(ols);
                        if (ols->ild) {
                            switch_close_transport(ols->ild->channel);
                        }
                        switch_monitor_change_tid(ols->oldtid, switch_core_get_monitor_index(ols->member->session));
                        switch_thread_cond_signal(ols->cond);
                    }
                    break;
                }
            }
            switch_mutex_unlock(list->lock);

            for (int idx = list->idx+MAX_NUMBER_OF_OUTPUT_NTHREADS; idx < MAX_NUMBER_OF_OUTPUT_THREADS; idx += MAX_NUMBER_OF_OUTPUT_NTHREADS) {
                if (globals.outputll[idx].count > 0) {
                    switch_thread_cond_signal(globals.outputll[idx].cond);
                }
            }
        }

        switch_mutex_lock(list->lock);
        for (output_loop_t *ols = list->loop; ols; ols = ols->next) {
            OUTPUT_LOOP_RET ret = OUTPUT_LOOP_OK;

            if (ols->stopping) { 
                continue;
                if (ols->stopping == 1) {
                    switch_monitor_change_tid(ols->oldtid, switch_core_get_monitor_index(ols->member->session));
                    switch_thread_cond_signal(ols->cond);
                } else {
                    ols->stopping -= 1;
                }
            }
            if (!ols->member->meo.cwc) { continue; }

            if (!ols->initialized) {
                switch_mutex_lock(ols->member->meo.cwc->codec_mutex);
                meo_reset_idx(&ols->member->meo);
                switch_mutex_unlock(ols->member->meo.cwc->codec_mutex);
                meo_start(&ols->member->meo);
                ols->initialized = SWITCH_TRUE;
            }

            if (ols->new_ol) {
                ols->new_ol = SWITCH_FALSE;

                if (conference_loop_input_setup(ols->ild) != SWITCH_STATUS_SUCCESS) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols->member->session), SWITCH_LOG_ERROR,
                                      "Failed to create input loop for mid:%s/%d\n",
                                      ols->member->mname, ols->member->id);
                }

                ols->tid = tid;
                switch_monitor_change_tid(tid, switch_core_get_monitor_index(ols->member->session));
                switch_monitor_change_desc(tid, switch_core_get_monitor_index(ols->member->session), "conference_loop_output");
                switch_channel_change_thread(ols->channel);
            }

            if (ols->starting && !switch_test_flag(ols->member, MFLAG_ITHREAD) && ols->sanity > 0) {
                ols->sanity -= 1;
                continue;
            } else if (ols->starting && switch_test_flag(ols->member, MFLAG_ITHREAD)) {
                ols->starting = SWITCH_FALSE;
                ols->sanity = 0;
            }
        
            if (!switch_test_flag(ols->member, MFLAG_RUNNING) || !switch_test_flag(ols->member, MFLAG_ITHREAD) ||
                !switch_channel_ready(ols->channel) || ols->member->loop_loop) {
                set_ols_stopping(ols);
                if (ols->ild) {
                    switch_close_transport(ols->ild->channel);
                }
                switch_monitor_change_tid(ols->oldtid, switch_core_get_monitor_index(ols->member->session));
                switch_thread_cond_signal(ols->cond);
                continue;
            }
    
            if (!ols->stopping) {
                switch_time_t now = switch_time_now();

                if ((now - ols->rx_period_start) > PROCESSING_PERIOD) {
                    ols->rx_period_start = now;
                    ols->max_time = 0;
                    ols->rx_time = 0;
                }

                now = switch_time_now();
                ret = process_output_loop(ols, &timer);
                now = switch_time_now() - now;

                ols->rx_time += now;
                if (now > ols->max_time) {
                    ols->max_time = now;
                }
            }
        
            if (!ols->stopping && ret != OUTPUT_LOOP_OK) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols->member->session), SWITCH_LOG_INFO,
                                  "Conference Output stopping:%d stopped:%d ret:%d\n",
                                  ols->stopping, ols->stopped, ret);

                if (ret ==  OUTPUT_LOOP_FAILED) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols->member->session), SWITCH_LOG_INFO,
                                      "Loop failed\n");
                } else if (ret == OUTPUT_LOOP_HANGUP) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols->member->session), SWITCH_LOG_INFO,
                                      "Hangup\n");
                } else if (ols->stopping && !ols->stopped) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols->member->session), SWITCH_LOG_INFO,
                                      "Stopping\n");
                }

                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols->member->session), SWITCH_LOG_INFO,
                                  "stopping ret=%d\n", ret);

                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ols->member->session), SWITCH_LOG_INFO,
                                  "process_output_loop_end_member returned ok!\n");
                set_ols_stopping(ols);
                if (ols->ild) {
                    switch_close_transport(ols->ild->channel);
                }
                switch_monitor_change_tid(ols->oldtid, switch_core_get_monitor_index(ols->member->session));
                switch_thread_cond_signal(ols->cond);
                continue;
            }
        } /* for */
        switch_mutex_unlock(list->lock);

        loop_count += 1;

        if (list->idx < MAX_NUMBER_OF_OUTPUT_NTHREADS) {
            switch_time_t current_time = switch_time_now();
            switch_time_t wake_up_delta = (current_time < next_wake_up) ? (next_wake_up - current_time) : 0;
            switch_time_t time_asleep;

            if (current_time < next_wake_up) {
                switch_time_t delta2;
                if (wake_up_delta > 1000) {
                    switch_sleep(wake_up_delta);
                    delta2 = switch_time_now() - current_time;
                    if (wake_up_delta > 0 && (delta2 - wake_up_delta) > 10000) {
                        if (behind == 0) {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "output loop %d count=%d overslept sleep_target=%" PRId64 " actual=%" PRId64 "\n",
                                              list->idx, list->count, wake_up_delta, delta2);
                        }
                        behind += 1;
                    } else {
                        if (behind > 1) {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "output loop %d count=%d caught up after %d cycles\n",
                                              list->idx, list->count, behind);
                        }
                        behind = 0;
                    }
                    time_asleep =  wake_up_delta;
                } else {
                    if (behind == 0) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "output loop %d count=%d short sleep ... skipping sleep delta=%" PRId64 "\n",
                                          list->idx, list->count, wake_up_delta);
                    }
                    behind += 1;
                    time_asleep = 0;
                }
            } else {
                if (behind == 0) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "output loop %d count=%d falling behind, skipping sleep delta=%" PRId64 "\n",
                                      list->idx, list->count, wake_up_delta);
                }
                behind += 1;
                time_asleep = 0;
            }
            next_wake_up += 20000;
            time_asleep_sum += time_asleep;
            if (time_asleep < min_time) {
                min_time = time_asleep;
            }
            loop_now = switch_time_now();
            // switch_core_timer_next(&timer);
        }
    } /* while */

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "output loop %d stopping count=%d list->tid=%lld tid=%lld\n",
                      list->idx,
                      list->count, (long long)list->tid, (long long)tid);

    switch_core_timer_destroy(&timer);
    
    return NULL;
}

switch_status_t accumulate_and_send(output_loop_t *ol, switch_frame_t *from_frame,
                                    switch_frame_t *to_frame, switch_time_t *before_send_time) {

    conference_member_t *member = ol->member;
    switch_bool_t send = SWITCH_FALSE;
    switch_bool_t equal = SWITCH_FALSE;

    if (!from_frame) { return SWITCH_STATUS_FALSE; }

    /* add data to acc_frame */
    if (member->frame_max <= 1 && ol->frame_cnt == 0) {
        /* just send! */
        to_frame = from_frame;
        send = SWITCH_TRUE;
        equal = SWITCH_TRUE;
    } else {
        if (switch_frame_append(to_frame, from_frame, from_frame->datalen) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "member %d failed to switch_frame_append\n", member->id);
        } else {
            if (ol->frame_cnt == 0) {
                to_frame->timestamp = from_frame->timestamp;
            }
            ol->frame_cnt += 1;
        }
        if (ol->frame_cnt >= member->frame_max) {
            send = SWITCH_TRUE;
        }
    }

    if (send) {
        if (to_frame->datalen < 160) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING, "member %d sending frame w/ %d bytes (from frame %d bytes) eq:%d cnt:%d max:%d\n",
                              member->id, to_frame->datalen, from_frame->datalen, equal, ol->frame_cnt, member->frame_max);
        }
        if (switch_core_session_write_enc_frame(member->session, to_frame,
                                                SWITCH_IO_FLAG_NONE, 0, before_send_time) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING, "member %d failed to write_enc_frame\n", member->id);
            return SWITCH_STATUS_FALSE;
        } else {
            ol->frame_cnt = 0;
            if (!equal) {
                switch_frame_reset(to_frame);
                to_frame->samples = 0;
            }
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

OUTPUT_LOOP_RET process_output_loop(output_loop_t *ols, switch_timer_t *timer)
{
    switch_event_t *event;
    switch_buffer_t *use_buffer = NULL;
    uint32_t mux_used = 0;
    switch_time_t mutex_time = 0;
    conference_member_t *member = ols->member;
    switch_channel_t *channel = ols->channel;
    switch_time_t send_time = 0;
    switch_time_t sent_time = 0;
    switch_time_t before_mutex_time = 0;
    switch_time_t before_send_time;

    switch_mutex_lock(ols->member->write_mutex);

    if (++ols->monitor_ticks >= ols->ticks_per_heartbeat) {
        switch_monitor_alive(ols->tid, switch_core_get_monitor_index(member->session));
        ols->monitor_ticks = 0;
    }

    if (ols->check_ticks++ >= ols->ticks_per_stats_check) {
        void *neteq_inst = switch_core_get_neteq_inst(member->session);
        if (neteq_inst) {
            WebRtcNetEQ_NetworkStatistics nwstats;
            if (WebRtcNetEQ_GetNetworkStatistics(neteq_inst, &nwstats) == 0) {
                    int val = nwstats.currentBufferSize;

                if (val > RTP_EVENT_JB_SIZE_THRESHOLD_MS) {
                    switch_core_ioctl_stats(member->session, SET_JB_SIZE, &val);
                    switch_core_ioctl_stats(member->session, SET_EVENT_LONG_JB, NULL);
                    switch_set_flag(member, MFLAG_LOG_STATS);
                }
            }
        }
        ols->check_ticks = 0;
    }
    
    if (ols->ticks++ >= ols->ticks_per_interval || switch_test_flag(member, MFLAG_LOG_STATS)) {
        if (switch_test_flag(member, MFLAG_LOG_STATS)) {
            switch_bool_t do_event = SWITCH_TRUE;
            switch_clear_flag_locked(member, MFLAG_LOG_STATS);
            switch_core_ioctl_stats(member->session, UPDATE_PERIODIC_STATS, &do_event);
            switch_core_log_periodic(member->session, SWITCH_FALSE, SWITCH_FALSE);
        } else {
            switch_bool_t do_event = SWITCH_FALSE;
            switch_core_ioctl_stats(member->session, UPDATE_PERIODIC_STATS, &do_event);
            ols->ticks = 0;
            switch_core_log_periodic(member->session, SWITCH_TRUE, SWITCH_FALSE);
        }
    }
    
    if (switch_channel_test_flag(member->channel, CF_CONFERENCE_ADV)) {
        if (member->conference->la) {
            adv_la(member->conference, member, SWITCH_TRUE);
        }
        switch_channel_clear_flag(member->channel, CF_CONFERENCE_ADV);
    }
    
    if (switch_core_session_dequeue_event(member->session, &event, SWITCH_FALSE) == SWITCH_STATUS_SUCCESS) {
        if (event->event_id == SWITCH_EVENT_MESSAGE) {
            char *from = switch_event_get_header(event, "from");
            char *to = switch_event_get_header(event, "to");
            char *body = switch_event_get_body(event);
            
            if (to && from && body) {
                if (strchr(to, '+') && strncmp(to, CONF_CHAT_PROTO, strlen(CONF_CHAT_PROTO))) {
                    switch_event_del_header(event, "to");
                    switch_event_add_header(event, SWITCH_STACK_BOTTOM,
                                            "to", "%s+%s@%s", CONF_CHAT_PROTO, member->conference->name, member->conference->domain);
                } else {
                    switch_event_del_header(event, "to");
                    switch_event_add_header(event, SWITCH_STACK_BOTTOM, "to", "%s", member->conference->name);
                }
                chat_send(event);
            }
        }
        switch_event_destroy(&event);
    }
    
    if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
        /* test to see if outbound channel has answered */
        if (switch_channel_test_flag(channel, CF_ANSWERED) && !switch_test_flag(member->conference, CFLAG_ANSWERED)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG,
                              "Outbound conference channel answered, setting CFLAG_ANSWERED\n");
            set_conference_state_unlocked(member->conference, CFLAG_ANSWERED);
        }
    } else {
        if (switch_test_flag(member->conference, CFLAG_ANSWERED) && !switch_channel_test_flag(channel, CF_ANSWERED)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG, "CLFAG_ANSWERED set, answering inbound channel\n");
            switch_channel_answer(channel);
        }
    }
    
    use_buffer = NULL;
    mux_used = (uint32_t) switch_buffer_inuse(member->mux_buffer);
    
    if (mux_used) {
        if (mux_used < ols->bytes) {
            if (++ols->low_count >= 5) {
                
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG,
                                  "Member %d partial frame (%d bytes) for %d cycles flushing buffer\n", member->id, mux_used, ols->low_count);
                
                /* partial frame sitting around this long is useless and builds delay */
                set_member_state_locked(member, MFLAG_FLUSH_BUFFER);
            }
        } else if (mux_used > ols->flush_len) {
            /* getting behind, clear the buffer */
            
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG,
                              "Member %d too much data (%d bytes > %d flush threshold bytes) flushing buffer\n", member->id, mux_used, ols->flush_len);
            
            set_member_state_locked(member, MFLAG_FLUSH_BUFFER);
        }
    }
    member->meo.stats_cnt += 1;
    
    if (!switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        member->meo.mute_cnt += 1;
    }
    
    if (switch_channel_test_app_flag(channel, CF_APP_TAGGED)) {
        set_member_state_locked(member, MFLAG_FLUSH_BUFFER);
    } else if ((mux_used >= ols->bytes) && member->one_of_active) {
        switch_frame_t *frame = NULL;
        
        /* Flush the output buffer and write all the data (presumably muxed) back to the channel */
        /* locked above when copying in a new set of samples/buffer */
        switch_mutex_lock(member->audio_out_mutex);
        use_buffer = member->mux_buffer;
        ols->low_count = 0;

        /* Encoder Optimization: Output Loop */
        /* Fuze: If the speaker is:
         *         - active (and can speak -- redundant?)
         *         - can't hear [silent frame?]
         *         - has some independent volume adjustment
         *         - has an exclusive IVR playing
         *         - is in a codec type of their own
         *   then send a frame through the individual encode path ... NORMAL path
         */
        
        if (ols->individual == SWITCH_FALSE) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                              "member %d 1 F -> T s=%d one_of_active=%d fnode=%d energy=%d mux_used=%lld\n", member->id, timer->samplecount,
                              member->one_of_active, (member->fnode != NULL), member->score, (long long)mux_used);
            ols->individual = SWITCH_TRUE;
        }

        /* If we have data in here we should process it as our own */
        if ((ols->write_frame.datalen = (uint32_t) switch_buffer_read(use_buffer, ols->write_frame.data, ols->bytes))) {
            
            /* Fuze: this part hasn't changed */
            ols->write_frame.samples = ols->write_frame.datalen / 2;
            ols->write_frame.timestamp = timer->samplecount;
            
            if(!switch_test_flag(member, MFLAG_CAN_HEAR)) {
                memset(ols->write_frame.data, 255, ols->write_frame.datalen);
            } else {
                /* Check for output volume adjustments */
                if (member->volume_out_level) {
                    switch_change_sln_volume(ols->write_frame.data, ols->write_frame.samples, member->volume_out_level);
                }
            }
        
            if (member->fnode) {
                // switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "member %d read file frame\n",member->id);
                frame = process_file_play(member, &ols->write_frame, SWITCH_FALSE);
            }
            if (!member->fnode || (member->fnode && !member->fnode->exclusive_play)) {
                /* Fuze: normal path encode */
                if (member->fnode) {
                    // switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "member %d encode file frame\n",member->id);
                }
                if (switch_core_session_enc_frame(member->session, &ols->write_frame, SWITCH_IO_FLAG_NONE, 0,
                                                  &frame) != SWITCH_STATUS_SUCCESS) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING, "member %d failed to encode\n", member->id);
                    switch_mutex_unlock(member->audio_out_mutex);
                    switch_mutex_unlock(member->write_mutex);
                    return OUTPUT_LOOP_FAILED;
                } else {
                    member->meo.individual_encode_cnt += 1;
                }
            }

            if (frame) {
                frame->timestamp = timer->samplecount;
                if (accumulate_and_send(ols, frame, &ols->acc_frame, &before_send_time) != SWITCH_STATUS_SUCCESS) {
                    switch_mutex_unlock(member->audio_out_mutex);
                    switch_mutex_unlock(member->write_mutex);
                    return OUTPUT_LOOP_FAILED;
                }
            }
        
            send_time += before_send_time; // (switch_micro_time_now() - before_send_time);
            
            sent_time = switch_micro_time_now() / 1000;
            if (sent_time - member->out_last_sent > 60) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING, "Loop %d Time since last send: %lld ms\n",
                                  ols->list_idx, (long long)(sent_time - member->out_last_sent));
            }
            member->out_last_sent = sent_time;
            
            switch_mutex_unlock(member->audio_out_mutex);
        }
        
    } else if (member->fnode) {
        switch_frame_t *frame = NULL;
        
        ols->write_frame.datalen = ols->bytes;
        ols->write_frame.samples = ols->samples;
        memset(ols->write_frame.data, 255, ols->write_frame.datalen);
        ols->write_frame.timestamp = timer->samplecount;
        
        if (ols->individual == SWITCH_FALSE) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                              "member %d 3 F -> T s=%d\n", member->id, timer->samplecount);
            ols->individual = SWITCH_TRUE;
        }
        
        frame = process_file_play(member, &ols->write_frame, SWITCH_TRUE);

        if (frame) {
            frame->timestamp = timer->samplecount;
            if (accumulate_and_send(ols, frame, &ols->acc_frame, &before_send_time) != SWITCH_STATUS_SUCCESS) {
                switch_channel_hangup(channel, SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER);
                switch_mutex_unlock(member->write_mutex);
                return OUTPUT_LOOP_HANGUP;
            }
        }
        send_time += before_send_time;
        
        sent_time = switch_micro_time_now() / 1000;
        if (sent_time - member->out_last_sent > 60) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Loop %d Time since last send: %lld ms\n",
                              ols->list_idx, (long long)(sent_time - member->out_last_sent));
        }
        member->out_last_sent = sent_time;
    } else if (!member->one_of_active) {
        switch_bool_t failed = SWITCH_FALSE;
        int sent_frames = 0;

        switch_mutex_lock(member->audio_out_mutex);

        /* xxx */
        if (ols->individual == SWITCH_TRUE) {
            before_mutex_time = switch_micro_time_now();
            switch_mutex_lock(member->meo.cwc->codec_mutex);
            meo_reset_idx(&member->meo);
            switch_mutex_unlock(member->meo.cwc->codec_mutex);
            mutex_time += (switch_micro_time_now() - before_mutex_time);
            
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                              "member %d 2 T -> F rd=%d wr=%d s=%d\n", member->id,
                              member->meo.read_idx, member->meo.cwc->write_idx,
                              timer->samplecount);
            ols->individual = SWITCH_FALSE;
        }
        
        for (int i = 0; i < MAX_CONF_FRAMES; ) {
            switch_frame_t  *rdframe = NULL;
            
            before_mutex_time = switch_micro_time_now();
            switch_mutex_lock(member->meo.cwc->codec_mutex);
            mutex_time += (switch_micro_time_now() - before_mutex_time);
            
            if (!meo_frame_written(&member->meo)) {
                switch_mutex_unlock(member->meo.cwc->codec_mutex);
                mutex_time += (switch_micro_time_now() - before_mutex_time);
                break;
            }
            
            if (i > 0) {
                member->meo.stats_cnt += 1;
                
                if (!switch_test_flag(member, MFLAG_CAN_SPEAK)) {
                    member->meo.mute_cnt += 1;
                }
            }
            
            /* if we're the first to see this frame then encode it */
            if (!meo_frame_encoded(&member->meo)) {
                switch_frame_t *frame = NULL;
                ols->write_frame.samples = ols->write_frame.datalen / 2;
                ols->write_frame.timestamp = timer->samplecount;
                
                if ((ols->write_frame.datalen = (uint32_t)meo_read_buffer(&member->meo, ols->write_frame.data, ols->bytes))) {
                    
                    if (switch_core_session_enc_frame(member->session, &ols->write_frame, SWITCH_IO_FLAG_NONE, 0,
                                                      &frame) != SWITCH_STATUS_SUCCESS) {
                        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING,
                                          "member %d failed to encode\n", member->id);
                        failed = SWITCH_TRUE;
                        switch_mutex_unlock(member->meo.cwc->codec_mutex);
                        break;
                    }
                    member->meo.shared_encode_cnt += 1;
                    member->meo.cwc->encode_cnt += 1;
                } else {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING,
                                      "member %d read 0 bytes\n", member->id);
                    meo_print(&member->meo, member->session);
                    switch_mutex_unlock(member->meo.cwc->codec_mutex);
                    break;
                }
                
                if (!frame || !meo_set_frame(&member->meo, frame)) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING,
                                      "member %d failed to set frame 0x%lld\n",
                                      member->id, (long long)frame);
                    switch_mutex_unlock(member->meo.cwc->codec_mutex);
                    break;
                }
            } else {
                member->meo.shared_copy_cnt += 1;
                member->meo.cwc->rd_cnt += 1;
            }
            
            rdframe = meo_get_frame(&member->meo);
            
            if (rdframe == NULL) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING,
                                  "member %d null read frame\n",member->id);
                switch_mutex_unlock(member->meo.cwc->codec_mutex);
                break;
            }

            rdframe->timestamp = timer->samplecount;

            if (accumulate_and_send(ols, rdframe, &ols->acc_frame, &before_send_time) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING, "failed to send frame!\n");
                failed = SWITCH_TRUE;
                switch_mutex_unlock(member->meo.cwc->codec_mutex);
                break;
            } else {
                sent_frames += 1;
            }
            
            send_time += before_send_time;
            
            sent_time = switch_micro_time_now() / 1000;
            if (sent_time - member->out_last_sent > 60) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_WARNING, "Loop %d Time since last send: %lld ms\n",
                                  ols->list_idx, (long long)(sent_time - member->out_last_sent));
            }
            member->out_last_sent = sent_time;
            
            if (!meo_next_frame(&member->meo)) {
                switch_mutex_unlock(member->meo.cwc->codec_mutex);
                break;
            }
            i += 1;
            switch_mutex_unlock(member->meo.cwc->codec_mutex);
        } /* else not an active speaker */
        if (sent_frames > 2) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "sent %d frames\n", sent_frames);
        }

        switch_mutex_unlock(member->audio_out_mutex);
        if (failed) {
            switch_mutex_unlock(member->write_mutex);
            return OUTPUT_LOOP_FAILED;
        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Didn't match one of the other conditions\n");
    }
    
    if (switch_test_flag(member, MFLAG_FLUSH_BUFFER)) {
        if (switch_buffer_inuse(member->mux_buffer)) {
            switch_mutex_lock(member->audio_out_mutex);
            switch_buffer_zero(member->mux_buffer);
            switch_mutex_unlock(member->audio_out_mutex);
        }
        ols->low_count = 0;
        clear_member_state_locked(member, MFLAG_FLUSH_BUFFER);
    }
    switch_mutex_unlock(member->write_mutex);
    
    if (switch_test_flag(member, MFLAG_INDICATE_MUTE)) {
        if (!zstr(member->conference->muted_sound)) {
            conference_member_play_file(member, member->conference->muted_sound, 0, 1);
        } else {
            char msg[512];
            
            switch_snprintf(msg, sizeof(msg), "Muted");
            conference_member_say(member, msg, 0);
        }
        clear_member_state_unlocked(member, MFLAG_INDICATE_MUTE);
    }
    
    if (switch_test_flag(member, MFLAG_INDICATE_LOCK_MUTE)) {
        if (!zstr(member->conference->mutes_locked_sound)) {
            conference_member_play_file(member, member->conference->mutes_locked_sound, 0, 1);
        } else {
            char msg[512];
            
            switch_snprintf(msg, sizeof(msg), "Locked Mutes");
            conference_member_say(member, msg, 0);
        }
        clear_member_state_unlocked(member, MFLAG_INDICATE_LOCK_MUTE);
    }
    
    if (switch_test_flag(member, MFLAG_INDICATE_UNLOCK_MUTE)) {
        if (!zstr(member->conference->mutes_unlocked_sound)) {
            conference_member_play_file(member, member->conference->mutes_unlocked_sound, 0, 1);
        } else {
            char msg[512];
            
            switch_snprintf(msg, sizeof(msg), "Unlocked Mutes");
            conference_member_say(member, msg, 0);
        }
        clear_member_state_unlocked(member, MFLAG_INDICATE_UNLOCK_MUTE);
    }
    
    if (switch_test_flag(member, MFLAG_INDICATE_MUTE_DETECT)) {
        if (!zstr(member->conference->mute_detect_sound)) {
            conference_member_play_file(member, member->conference->mute_detect_sound, 0, 1);
        } else {
            char msg[512];
            
            switch_snprintf(msg, sizeof(msg), "Currently Muted");
            conference_member_say(member, msg, 0);
        }
        clear_member_state_unlocked(member, MFLAG_INDICATE_MUTE_DETECT);
    }
    
    if (switch_test_flag(member, MFLAG_INDICATE_UNMUTE)) {
        if (!zstr(member->conference->unmuted_sound)) {
            conference_member_play_file(member, member->conference->unmuted_sound, 0, 1);
        } else {
            char msg[512];
            
            switch_snprintf(msg, sizeof(msg), "Un-Muted");
            conference_member_say(member, msg, 0);
        }
        clear_member_state_unlocked(member, MFLAG_INDICATE_UNMUTE);
    }
    
    if (switch_core_session_private_event_count(member->session)) {
        switch_channel_set_app_flag(channel, CF_APP_TAGGED);
        switch_ivr_parse_all_events(member->session);
        switch_channel_clear_app_flag(channel, CF_APP_TAGGED);
        set_member_state_locked(member, MFLAG_FLUSH_BUFFER);
        switch_core_session_set_read_codec(member->session, &member->read_codec);
    } else {
        switch_ivr_parse_all_messages(member->session);
    }
    
    return OUTPUT_LOOP_OK;
}

OUTPUT_LOOP_RET process_output_loop_end_member(output_loop_t *ols) {
    
    conference_member_t *member = ols->member;
    switch_channel_t *channel = ols->channel;
    
    set_ols_stopping(ols);
    
    if (ols->stopped) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "already stopped\n");
        return OUTPUT_LOOP_ALREADY_STOPPED;
    }

    conference_loop_input_cleanup(ols->ild);
    ols->stopped = SWITCH_TRUE;
    clear_member_state_locked(member, MFLAG_RUNNING);

    if (member->meo.stats_cnt != 0 && member->meo.cwc->stats_cnt != 0) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                          "member summary %d encode stats cnt:%lld muted:%lld(%f%%) individual:%lld(%f%%) "
                          "shared enc/copy:%lld/%lld(%f%%) file enc/copy:%lld/%lld(%f%%)\n",
                          member->id, (long long)member->meo.stats_cnt,
                          (long long)member->meo.mute_cnt,
                          ((float)member->meo.mute_cnt/member->meo.stats_cnt)*100,
                          (long long)member->meo.individual_encode_cnt,
                          ((float)member->meo.individual_encode_cnt/member->meo.stats_cnt)*100,
                          (long long)member->meo.shared_encode_cnt,
                          (long long)member->meo.shared_copy_cnt,
                          ((float)(member->meo.shared_encode_cnt+member->meo.shared_copy_cnt)/member->meo.stats_cnt)*100,
                          (long long)member->meo.ivr_encode_cnt,
                          (long long)member->meo.ivr_copy_cnt,
                          ((float)(member->meo.ivr_encode_cnt+member->meo.ivr_copy_cnt)/member->meo.stats_cnt)*100);
    }

    //    switch_core_log_periodic(member->session, SWITCH_TRUE, SWITCH_TRUE);
    
    meo_destroy(&member->meo);

    if (channel) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                          "M(%s)/I(%s):U(%s) (id:%d) Channel leaving conference, cause: %s\n",
                          member->conference->meeting_id, member->conference->instance_id, member->mname, member->id,
                          switch_channel_cause2str(switch_channel_get_cause(channel)));
    }

    if (member->loop_loop) {
        
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR,
                          "M(%s)/I(%s):U(%s) (id:%d) Output loop returning!!!\n",
                          member->conference->meeting_id, member->conference->instance_id, member->mname, member->id);
        
        return OUTPUT_LOOP_OK;
    }
    
    /* if it's an outbound channel, store the release cause in the conference struct, we might need it */
    if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
        member->conference->bridge_hangup_cause = switch_channel_get_cause(channel);
    }
    
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                      "process_output_loop_end_member returning ok\n");

    return OUTPUT_LOOP_OK;
}

    
/* aaa */
/* Sub-Routine called by a record entity inside a conference */
static void *SWITCH_THREAD_FUNC conference_record_thread_run(switch_thread_t *thread, void *obj)
{
    int16_t *data_buf;
    switch_file_handle_t fh = { 0 };
    conference_member_t smember = { 0 }, *member;
    conference_record_t *rp, *last = NULL, *rec = (conference_record_t *) obj;
    conference_obj_t *conference = rec->conference;
    uint32_t samples = switch_samples_per_packet(conference->rate, conference->interval);
    uint32_t mux_used;
    char *vval;
    switch_timer_t timer = { 0 };
    uint32_t rlen;
    switch_size_t data_buf_len;
    switch_event_t *event;
    int no_data = 0;
    int lead_in = 20;
    switch_size_t len = 0;

    if (switch_thread_rwlock_tryrdlock(conference->rwlock) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Read Lock Fail\n");
        return NULL;
    }

    data_buf_len = samples * sizeof(int16_t);
    switch_zmalloc(data_buf, data_buf_len);

    switch_mutex_lock(globals.hash_mutex);
    globals.threads++;
    switch_mutex_unlock(globals.hash_mutex);

    if (conference->moh_sound)
    {
        conference_stop_file(conference, FILE_STOP_ASYNC);
    }

    switch_mutex_lock(conference->member_mutex);
    if (conference->recording_started_sound)
    {
        for (int i = 0; i < eMemberListTypes_Recorders; i++) {
            for (member = conference->member_lists[i]; member; member = member->next)
            {
                if (member->session && !switch_test_flag(member, MFLAG_NOCHANNEL)) {
                    conference_member_play_file(
                        member, conference->recording_started_sound, CONF_DEFAULT_LEADIN, 1
                    );
                }
            }
        }
    }
    switch_mutex_unlock(conference->member_mutex);

    member = &smember;

    member->flags = MFLAG_CAN_HEAR | MFLAG_NOCHANNEL | MFLAG_RUNNING;

    member->conference = conference;
    member->native_rate = conference->rate;
    member->rec_path = rec->path;
    member->rec_time = switch_epoch_time_now(NULL);
    fh.channels = 1;
    fh.samplerate = conference->rate;
    member->id = next_member_id();
    member->pool = rec->pool;
    member->rec = rec;
    member->frame_size = SWITCH_RECOMMENDED_BUFFER_SIZE;
    member->frame = switch_core_alloc(member->pool, member->frame_size);
    member->mux_frame = switch_core_alloc(member->pool, member->frame_size);

    switch_mutex_init(&member->write_mutex, SWITCH_MUTEX_NESTED, rec->pool);
    switch_mutex_init(&member->flag_mutex, SWITCH_MUTEX_NESTED, rec->pool);
    switch_mutex_init(&member->fnode_mutex, SWITCH_MUTEX_NESTED, rec->pool);
    switch_mutex_init(&member->audio_in_mutex, SWITCH_MUTEX_NESTED, rec->pool);
    switch_mutex_init(&member->audio_out_mutex, SWITCH_MUTEX_NESTED, rec->pool);
    switch_mutex_init(&member->read_mutex, SWITCH_MUTEX_NESTED, rec->pool);
    switch_thread_rwlock_create(&member->rwlock, rec->pool);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Conference Recording Info: id:%d interval:%u samples: %u rate: %u\n",
                      member->id, conference->interval, samples, member->native_rate);

    /* Setup an audio buffer for the incoming audio */
    if (switch_buffer_create_dynamic(&member->audio_buffer, CONF_DBLOCK_SIZE, CONF_DBUFFER_SIZE, 0) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Memory Error Creating Audio Buffer!\n");
        goto end;
    }

    /* Setup an audio buffer for the outgoing audio */
    if (switch_buffer_create_dynamic(&member->mux_buffer, CONF_DBLOCK_SIZE, CONF_DBUFFER_SIZE, 0) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Memory Error Creating Audio Buffer!\n");
        goto end;
    }

    if (conference_add_member(conference, member) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Joining Conference\n");
        goto end;
    }
    
    fh.pre_buffer_datalen = SWITCH_DEFAULT_FILE_BUFFER_LEN;

    if (switch_core_file_open(&fh,
                              rec->path, (uint8_t) 1, conference->rate, SWITCH_FILE_FLAG_WRITE | SWITCH_FILE_DATA_SHORT,
                              rec->pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Opening File [%s]\n", rec->path);


        if (test_eflag(conference, EFLAG_RECORD) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "start-recording");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Path", rec->path);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Error", "File could not be opened for recording");
            switch_event_fire(&event);
        }

        goto end;
    }


    if (switch_core_timer_init(&timer, conference->timer_name, conference->interval, samples, rec->pool) == SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Setup timer success interval: %u  samples: %u\n", conference->interval, samples);
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Timer Setup Failed.  Conference Cannot Start\n");
        goto end;
    }

    if ((vval = switch_mprintf("Conference %s", conference->name))) {
        switch_core_file_set_string(&fh, SWITCH_AUDIO_COL_STR_TITLE, vval);
        switch_safe_free(vval);
    }

    switch_core_file_set_string(&fh, SWITCH_AUDIO_COL_STR_ARTIST, "FreeSWITCH mod_conference Software Conference Module");

    if (test_eflag(conference, EFLAG_RECORD) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_data(conference, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "start-recording");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Path", rec->path);
        switch_event_fire(&event);
    }

    while (switch_test_flag(member, MFLAG_RUNNING) && switch_test_flag(conference, CFLAG_RUNNING) && (conference->count + conference->count_ghosts)) {

        len = 0;

        if (lead_in) {
            lead_in--;
            goto loop;
        }

        mux_used = (uint32_t) switch_buffer_inuse(member->mux_buffer);

        if (switch_test_flag(member, MFLAG_FLUSH_BUFFER)) {
            if (mux_used) {
                switch_mutex_lock(member->audio_out_mutex);
                switch_buffer_zero(member->mux_buffer);
                switch_mutex_unlock(member->audio_out_mutex);
                mux_used = 0;
            }
            clear_member_state_locked(member, MFLAG_FLUSH_BUFFER);
        }

    again:

        if (switch_test_flag((&fh), SWITCH_FILE_PAUSE)) {
            set_member_state_locked(member, MFLAG_FLUSH_BUFFER);
            goto loop;
        }

        if (mux_used >= data_buf_len) {
            /* Flush the output buffer and write all the data (presumably muxed) to the file */
            switch_mutex_lock(member->audio_out_mutex);
            //low_count = 0;

            if ((rlen = (uint32_t) switch_buffer_read(member->mux_buffer, data_buf, data_buf_len))) {
                len = (switch_size_t) rlen / sizeof(int16_t);
                no_data = 0;
            }
            switch_mutex_unlock(member->audio_out_mutex);
        }

        if (len == 0) {
            mux_used = (uint32_t) switch_buffer_inuse(member->mux_buffer);

            if (mux_used >= data_buf_len) {
                goto again;
            }

            if (++no_data < 2) {
                goto loop;
            }

            memset(data_buf, 255, (switch_size_t) data_buf_len);
            len = (switch_size_t) samples;
        }

        if (!switch_test_flag(member, MFLAG_PAUSE_RECORDING)) {
            if (!len || switch_core_file_write(&fh, data_buf, &len) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Write Failed\n");
                clear_member_state_locked(member, MFLAG_RUNNING);
            }
        }

    loop:

        switch_core_timer_next(&timer);
    }                            /* Rinse ... Repeat */

  end:

    while(!no_data) {
        switch_mutex_lock(member->audio_out_mutex);
        if ((rlen = (uint32_t) switch_buffer_read(member->mux_buffer, data_buf, data_buf_len))) {
            len = (switch_size_t) rlen / sizeof(int16_t);
            switch_core_file_write(&fh, data_buf, &len);
        } else {
            no_data = 1;
        }
        switch_mutex_unlock(member->audio_out_mutex);
    }

    conference->is_recording = 0;

    if (conference->recording_stopped_sound)
    {
        conference_play_file(
            conference, conference->recording_stopped_sound, CONF_DEFAULT_LEADIN, NULL, 1, 1
        );
    }

    switch_safe_free(data_buf);
    switch_core_timer_destroy(&timer);
    conference_del_member(conference, member);

    switch_buffer_destroy(&member->audio_buffer);
    switch_buffer_destroy(&member->mux_buffer);
    clear_member_state_locked(member, MFLAG_RUNNING);
    if (switch_test_flag((&fh), SWITCH_FILE_OPEN)) {
        switch_core_file_close(&fh);
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Recording of %s Stopped\n", rec->path);
    if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_data(conference, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "stop-recording");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Path", rec->path);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Samples-Out", "%ld", (long) fh.samples_out);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Samplerate", "%ld", (long) fh.samplerate);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Milliseconds-Elapsed", "%ld", (long) fh.samples_out / (fh.samplerate / 1000));
        switch_event_fire(&event);
    }

    if (rec->autorec && conference->auto_recording) {
        conference->auto_recording--;
    }

    switch_mutex_lock(conference->flag_mutex);
    for (rp = conference->rec_node_head; rp; rp = rp->next) {
        if (rec == rp) {
            if (last) {
                last->next = rp->next;
            } else {
                conference->rec_node_head = rp->next;
            }
        }
    }
    switch_mutex_unlock(conference->flag_mutex);


    if (rec->pool) {
        switch_memory_pool_t *pool = rec->pool;
        rec = NULL;
        switch_core_destroy_memory_pool(&pool);
    }

    switch_mutex_lock(globals.hash_mutex);
    globals.threads--;
    switch_mutex_unlock(globals.hash_mutex);

    switch_thread_rwlock_unlock(conference->rwlock);
    return NULL;
}

/* Make files stop playing in a conference either the current one or all of them */
static uint32_t conference_stop_file(conference_obj_t *conference, file_stop_t stop)
{
    uint32_t count = 0;
    conference_file_node_t *nptr;

    switch_assert(conference != NULL);

    switch_mutex_lock(conference->mutex);

    if (stop == FILE_STOP_ALL) {
        for (nptr = conference->fnode; nptr; nptr = nptr->next) {
            nptr->done++;
            count++;
        }
        if (conference->async_fnode) {
            conference->async_fnode->done++;
            count++;
        }
    } else if (stop == FILE_STOP_ASYNC) {
        if (conference->async_fnode) {
            conference->async_fnode->done++;
            count++;
        }
    } else {
        if (conference->fnode) {
            conference->fnode->done++;
            count++;
        }
    }

    switch_mutex_unlock(conference->mutex);

    return count;
}

/* stop playing a file for the member of the conference */
static uint32_t conference_member_stop_file(conference_member_t *member, file_stop_t stop)
{
    conference_file_node_t *nptr;
    uint32_t count = 0;

    if (member == NULL)
        return count;


    switch_mutex_lock(member->fnode_mutex);

    if (stop == FILE_STOP_ALL) {
        for (nptr = member->fnode; nptr; nptr = nptr->next) {
            nptr->done++;
            count++;
        }
    } else {
        if (member->fnode) {
            member->fnode->done++;
            count++;
        }
    }

    switch_mutex_unlock(member->fnode_mutex);

    return count;
}

static void conference_send_all_dtmf(conference_member_t *member, conference_obj_t *conference, const char *dtmf)
{
    conference_member_t *imember;

    switch_mutex_lock(conference->mutex);
    switch_mutex_lock(conference->member_mutex);

    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (imember = conference->member_lists[i]; imember; imember = imember->next) {
            /* don't send to self */
            if (imember->id == member->id) {
                continue;
            }
            if (imember->session) {
                const char *p;
                for (p = dtmf; p && *p; p++) {
                    switch_dtmf_t *dt, digit = { *p, SWITCH_DEFAULT_DTMF_DURATION };

                    switch_zmalloc(dt, sizeof(*dt));
                    *dt = digit;
                    switch_queue_push(imember->dtmf_queue, dt);
                    switch_core_session_kill_channel(imember->session, SWITCH_SIG_BREAK);
                }
            }
        }
    }
    
    switch_mutex_unlock(conference->member_mutex);
    switch_mutex_unlock(conference->mutex);
}

/* Play a file in the conference room */
static switch_status_t conference_play_file(conference_obj_t *conference, char *file, uint32_t leadin, switch_channel_t *channel, uint8_t async, uint8_t exclusive)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    conference_file_node_t *fnode, *nptr = NULL;
    switch_memory_pool_t *pool;
    uint32_t count;
    char *dfile = NULL, *expanded = NULL;
    int say = 0;

    switch_assert(conference != NULL);

    if (zstr(file)) {
        return SWITCH_STATUS_NOTFOUND;
    }

    switch_mutex_lock(conference->mutex);
    switch_mutex_lock(conference->member_mutex);
    count = conference->count;
    switch_mutex_unlock(conference->member_mutex);
    switch_mutex_unlock(conference->mutex);

    if (!count) {
        return SWITCH_STATUS_FALSE;
    }

    if (channel) {
        if ((expanded = switch_channel_expand_variables(channel, file)) != file) {
            file = expanded;
        } else {
            expanded = NULL;
        }
    }

    if (!strncasecmp(file, "say:", 4)) {
        say = 1;
    }

    if (!async && say) {
        status = conference_say(conference, file + 4, leadin);
        goto done;
    }

    if (!switch_is_file_path(file)) {
        if (!say && conference->sound_prefix) {
            if (!(dfile = switch_mprintf("%s%s%s", conference->sound_prefix, SWITCH_PATH_SEPARATOR, file))) {
                goto done;
            }
            file = dfile;
        } else if (!async) {
            status = conference_say(conference, file, leadin);
            goto done;
        } else {
            goto done;
        }
    }

    /* Setup a memory pool to use. */
    if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Pool Failure\n");
        status = SWITCH_STATUS_MEMERR;
        goto done;
    }

    /* Create a node object */
    if (!(fnode = switch_core_alloc(pool, sizeof(*fnode)))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Alloc Failure\n");
        switch_core_destroy_memory_pool(&pool);
        status = SWITCH_STATUS_MEMERR;
        goto done;
    }

    fnode->type = NODE_TYPE_FILE;
    fnode->leadin = leadin;

    /* Open the file */
    fnode->fh.pre_buffer_datalen = SWITCH_DEFAULT_FILE_BUFFER_LEN;
    if (switch_core_file_open(&fnode->fh, file, (uint8_t) 1, conference->rate, SWITCH_FILE_FLAG_READ | SWITCH_FILE_DATA_SHORT, pool) !=
        SWITCH_STATUS_SUCCESS) {
        switch_event_t *event;

        if (test_eflag(conference, EFLAG_PLAY_FILE) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(conference, event);

            if (fnode->fh.params) {
                switch_event_merge(event, conference->fnode->fh.params);
            }

            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "play-file");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "File", file);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Async", async ? "true" : "false");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Error", "File could not be played");
            switch_event_fire(&event);
        }

        switch_core_destroy_memory_pool(&pool);
        status = SWITCH_STATUS_NOTFOUND;
        goto done;
    }

    if (fnode->fh.params) {
        const char *vol = switch_event_get_header(fnode->fh.params, "vol");

        if (!zstr(vol)) {
            fnode->fh.vol = atoi(vol);
        }
    }

    fnode->pool = pool;
    fnode->async = async;
    fnode->file = switch_core_strdup(fnode->pool, file);
    fnode->exclusive_play = exclusive;

    /* Queue the node */
    switch_mutex_lock(conference->mutex);

    if (async) {
        if (conference->async_fnode) {
            nptr = conference->async_fnode;
        }
        conference->async_fnode = fnode;

        if (nptr) {
            switch_memory_pool_t *tmppool;
            conference_file_close(conference, nptr);
            tmppool = nptr->pool;
            switch_core_destroy_memory_pool(&tmppool);
        }

    } else {
        for (nptr = conference->fnode; nptr && nptr->next; nptr = nptr->next);

        if (nptr) {
            nptr->next = fnode;
        } else {
            conference->fnode = fnode;
        }
    }

    switch_mutex_unlock(conference->mutex);

  done:

    switch_safe_free(expanded);
    switch_safe_free(dfile);

    return status;
}

/* yyy */
/* Play a file in the conference room to a member */
static switch_status_t conference_member_play_file(conference_member_t *member, char *file, uint32_t leadin, uint8_t exclusive)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    char *dfile = NULL, *expanded = NULL;
    conference_file_node_t *fnode, *nptr = NULL;
    switch_memory_pool_t *pool;
    
    if (member == NULL || file == NULL || switch_test_flag(member, MFLAG_KICKED))
        return status;

    if ((expanded = switch_channel_expand_variables(switch_core_session_get_channel(member->session), file)) != file) {
        file = expanded;
    } else {
        expanded = NULL;
    }
    if (!strncasecmp(file, "say:", 4)) {
        if (!zstr(file + 4)) {
            status = conference_member_say(member, file + 4, leadin);
        }
        goto done;
    }
    if (!switch_is_file_path(file)) {
        if (member->conference->sound_prefix) {
            if (!(dfile = switch_mprintf("%s%s%s", member->conference->sound_prefix, SWITCH_PATH_SEPARATOR, file))) {
                goto done;
            }
            file = dfile;
        } else if (!zstr(file)) {
            status = conference_member_say(member, file, leadin);
            goto done;
        }
    }
    /* Setup a memory pool to use. */
    if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_CRIT, "Pool Failure\n");
        status = SWITCH_STATUS_MEMERR;
        goto done;
    }
    /* Create a node object */
    if (!(fnode = switch_core_alloc(pool, sizeof(*fnode)))) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_CRIT, "Alloc Failure\n");
        switch_core_destroy_memory_pool(&pool);
        status = SWITCH_STATUS_MEMERR;
        goto done;
    }
    fnode->type = NODE_TYPE_FILE;
    fnode->leadin = leadin;
    fnode->exclusive_play = exclusive;
    fnode->member_id = member->id;

    /* Let's see if we have this file in our encoded collection already */
    fc_init(&fnode->cursor);
    if (fnode->exclusive_play) {
        switch_mutex_lock(member->meo.filelist->filesmutex);
        if (fc_start_replay(&fnode->cursor, member->meo.filelist, file)) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "found file %s complete=%d\n",
                              file, fnode->cursor.file->done);
            if (eif_file_complete(fnode->cursor.file)) {
                fnode->type = NODE_TYPE_CURSOR;
            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "creating file %s\n", file);
            fc_create_file(&fnode->cursor, member->meo.filelist, file);
        }
        switch_mutex_unlock(member->meo.filelist->filesmutex);
    }
    
    /* Open the file */
    fnode->fh.pre_buffer_datalen = SWITCH_DEFAULT_FILE_BUFFER_LEN;
    if (fnode->type == NODE_TYPE_FILE) {
        if (switch_core_file_open(&fnode->fh,
                                  file, (uint8_t) 1, member->conference->rate, SWITCH_FILE_FLAG_READ | SWITCH_FILE_DATA_SHORT,
                                  pool) != SWITCH_STATUS_SUCCESS) {
            switch_core_destroy_memory_pool(&pool);
            status = SWITCH_STATUS_NOTFOUND;
            goto done;
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO,
                              "mid:%d opening file\n", member->id);
        }
    }
    fnode->pool = pool;
    fnode->file = switch_core_strdup(fnode->pool, file);
    /* Queue the node */
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG, "Queueing file '%s' for play\n", file);
    switch_mutex_lock(member->fnode_mutex);
    for (nptr = member->fnode; nptr && nptr->next; nptr = nptr->next);
    if (nptr) {
        nptr->next = fnode;
    } else {
        member->fnode = fnode;
    }
    switch_mutex_unlock(member->fnode_mutex);
    status = SWITCH_STATUS_SUCCESS;

  done:

    switch_safe_free(expanded);
    switch_safe_free(dfile);

    return status;
}

/* Say some thing with TTS in the conference room */
static switch_status_t conference_member_say(conference_member_t *member, char *text, uint32_t leadin)
{
    conference_obj_t *conference = (member != NULL ? member->conference : NULL);
    conference_file_node_t *fnode, *nptr;
    switch_memory_pool_t *pool;
    switch_speech_flag_t flags = SWITCH_SPEECH_FLAG_NONE;
    switch_status_t status = SWITCH_STATUS_FALSE;

    if (member == NULL || zstr(text))
        return SWITCH_STATUS_FALSE;

    switch_assert(conference != NULL);

    if (!(conference->tts_engine && conference->tts_voice)) {
        return SWITCH_STATUS_SUCCESS;
    }

    /* Setup a memory pool to use. */
    if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_CRIT, "Pool Failure\n");
        return SWITCH_STATUS_MEMERR;
    }

    /* Create a node object */
    if (!(fnode = switch_core_alloc(pool, sizeof(*fnode)))) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_CRIT, "Alloc Failure\n");
        switch_core_destroy_memory_pool(&pool);
        return SWITCH_STATUS_MEMERR;
    }

    fnode->type = NODE_TYPE_SPEECH;
    fnode->leadin = leadin;
    fnode->pool = pool;

    if (!member->sh) {
        memset(&member->lsh, 0, sizeof(member->lsh));
        if (switch_core_speech_open(&member->lsh, conference->tts_engine, conference->tts_voice,
                                    conference->rate, conference->interval, &flags, switch_core_session_get_pool(member->session)) !=
            SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_ERROR, "Invalid TTS module [%s]!\n", conference->tts_engine);
            return SWITCH_STATUS_FALSE;
        }
        member->sh = &member->lsh;
    }

    /* Queue the node */
    switch_mutex_lock(member->fnode_mutex);
    for (nptr = member->fnode; nptr && nptr->next; nptr = nptr->next);

    if (nptr) {
        nptr->next = fnode;
    } else {
        member->fnode = fnode;
    }

    fnode->sh = member->sh;
    /* Begin Generation */
    switch_sleep(200000);

    if (*text == '#') {
        char *tmp = (char *) text + 1;
        char *vp = tmp, voice[128] = "";
        if ((tmp = strchr(tmp, '#'))) {
            text = tmp + 1;
            switch_copy_string(voice, vp, (tmp - vp) + 1);
            switch_core_speech_text_param_tts(fnode->sh, "voice", voice);
        }
    } else {
        switch_core_speech_text_param_tts(fnode->sh, "voice", conference->tts_voice);
    }

    switch_core_speech_feed_tts(fnode->sh, text, &flags);
    switch_mutex_unlock(member->fnode_mutex);

    status = SWITCH_STATUS_SUCCESS;

    return status;
}

/* Say some thing with TTS in the conference room */
static switch_status_t conference_say(conference_obj_t *conference, const char *text, uint32_t leadin)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    conference_file_node_t *fnode, *nptr;
    switch_memory_pool_t *pool;
    switch_speech_flag_t flags = SWITCH_SPEECH_FLAG_NONE;
    uint32_t count;

    switch_assert(conference != NULL);

    if (zstr(text)) {
        return SWITCH_STATUS_GENERR;
    }

    switch_mutex_lock(conference->mutex);
    switch_mutex_lock(conference->member_mutex);
    count = conference->count;
    if (!(conference->tts_engine && conference->tts_voice)) {
        count = 0;
    }
    switch_mutex_unlock(conference->member_mutex);
    switch_mutex_unlock(conference->mutex);

    if (!count) {
        return SWITCH_STATUS_FALSE;
    }

    /* Setup a memory pool to use. */
    if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Pool Failure\n");
        return SWITCH_STATUS_MEMERR;
    }

    /* Create a node object */
    if (!(fnode = switch_core_alloc(pool, sizeof(*fnode)))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Alloc Failure\n");
        switch_core_destroy_memory_pool(&pool);
        return SWITCH_STATUS_MEMERR;
    }

    fnode->type = NODE_TYPE_SPEECH;
    fnode->leadin = leadin;

    if (!conference->sh) {
        memset(&conference->lsh, 0, sizeof(conference->lsh));
        if (switch_core_speech_open(&conference->lsh, conference->tts_engine, conference->tts_voice,
                                    conference->rate, conference->interval, &flags, NULL) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid TTS module [%s]!\n", conference->tts_engine);
            return SWITCH_STATUS_FALSE;
        }
        conference->sh = &conference->lsh;
    }

    fnode->pool = pool;

    /* Queue the node */
    switch_mutex_lock(conference->mutex);
    for (nptr = conference->fnode; nptr && nptr->next; nptr = nptr->next);

    if (nptr) {
        nptr->next = fnode;
    } else {
        conference->fnode = fnode;
    }

    fnode->sh = conference->sh;
    if (*text == '#') {
        char *tmp = (char *) text + 1;
        char *vp = tmp, voice[128] = "";
        if ((tmp = strchr(tmp, '#'))) {
            text = tmp + 1;
            switch_copy_string(voice, vp, (tmp - vp) + 1);
            switch_core_speech_text_param_tts(fnode->sh, "voice", voice);
        }
    } else {
        switch_core_speech_text_param_tts(fnode->sh, "voice", conference->tts_voice);
    }

    /* Begin Generation */
    switch_sleep(200000);
    switch_core_speech_feed_tts(fnode->sh, (char *) text, &flags);
    switch_mutex_unlock(conference->mutex);
    status = SWITCH_STATUS_SUCCESS;

    return status;
}

/* send a message to every member of the conference */
static void chat_message_broadcast(conference_obj_t *conference, switch_stream_handle_t *stream, const char *data, const char *chat_from, const char *ouuid)
{
    conference_member_t *member = NULL;
    char *argv[2] = { 0 };
    char *dup = NULL;
    switch_core_session_message_t msg = { 0 };

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (!(dup = strdup(chat_from))) {
        return;
    }
    switch_separate_string(dup, '@', argv, (sizeof(argv) / sizeof(argv[0])));

    msg.message_id = SWITCH_MESSAGE_INDICATE_MESSAGE;
    msg.string_array_arg[2] = data;
    msg.string_array_arg[3] = ouuid;
    msg.from = __FILE__;

    switch_mutex_lock(conference->member_mutex);
    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            if (member->session && !switch_test_flag(member, MFLAG_NOCHANNEL)) {
                switch_core_session_t *lsession = NULL;

                lsession = member->session;

                switch_core_session_receive_message(lsession, &msg);
            }
        }
    }
    switch_mutex_unlock(conference->member_mutex);
}

/* execute a callback for every member of the conference */
static void conference_member_itterator(conference_obj_t *conference, switch_stream_handle_t *stream, uint8_t non_mod, conf_api_member_cmd_t pfncallback, void *data)
{
    conference_member_t *member = NULL;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);
    switch_assert(pfncallback != NULL);

    switch_mutex_lock(conference->member_mutex);
    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            if (!(non_mod && switch_test_flag(member, MFLAG_MOD))) {
                if (member->session && !switch_test_flag(member, MFLAG_NOCHANNEL)) {
                    pfncallback(member, stream, data);
                }
            } else {
                stream->write_function(stream, "Skipping moderator (member id %d).\n", member->id);
            }
        }
    }
    switch_mutex_unlock(conference->member_mutex);
}

static switch_status_t list_conferences(const char *line, const char *cursor, switch_console_callback_match_t **matches)
{
    switch_console_callback_match_t *my_matches = NULL;
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_hash_index_t *hi;
    void *val;
    const void *vvar;

    switch_mutex_lock(globals.hash_mutex);
    for (hi = switch_core_hash_first(globals.conference_hash); hi; hi = switch_core_hash_next(&hi)) {
        switch_core_hash_this(hi, &vvar, NULL, &val);
        switch_console_push_match(&my_matches, (const char *) vvar);
    }
    switch_mutex_unlock(globals.hash_mutex);

    if (my_matches) {
        *matches = my_matches;
        status = SWITCH_STATUS_SUCCESS;
    }

    return status;
}

static void conference_list_pretty(conference_obj_t *conference, switch_stream_handle_t *stream)
{
    conference_member_t *member = NULL;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    switch_mutex_lock(conference->member_mutex);

    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            switch_channel_t *channel;
            switch_caller_profile_t *profile;

            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                continue;
            }
            channel = switch_core_session_get_channel(member->session);
            profile = switch_channel_get_caller_profile(channel);

            stream->write_function(stream, "%u) %s (%s)\n", member->id, profile->caller_id_name, profile->caller_id_number);
        }
    }
    
    switch_mutex_unlock(conference->member_mutex);
}

static void conference_list(conference_obj_t *conference, switch_stream_handle_t *stream, char *delim)
{
    conference_member_t *member = NULL;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);
    switch_assert(delim != NULL);

    switch_mutex_lock(conference->member_mutex);

    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            switch_channel_t *channel;
            switch_caller_profile_t *profile;
            char *uuid;
            char *name;
            uint32_t count = 0;
            char *cid = "unknown";
            char *cin = "unknown";
            int time_since_active = -1;
            switch_time_t now;

            if (member->was_active) {
                now = switch_time_now()/1000;
                time_since_active = (int) ((now - member->last_time_active/1000)/60000);
            }
                

            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                continue;
            }

            uuid = switch_core_session_get_uuid(member->session);
            channel = switch_core_session_get_channel(member->session);
            profile = switch_channel_get_caller_profile(channel);
            name = switch_channel_get_name(channel);

            if (member->conference && member->conference->meeting_id) {
                cid = member->conference->meeting_id;
            }
            if (member->conference && member->conference->instance_id) {
                cin = member->conference->instance_id;
            }

            stream->write_function(stream, "%u%smtgid:%s%smtginst:%s%s%s%s%s%s%s%s%s%s%s%s%dmin%s",
                                   member->id, delim, cid, delim, cin, delim, member->mname, delim, name, delim, uuid, delim, profile->caller_id_name, delim, profile->caller_id_number, delim, time_since_active, delim);

            if (switch_test_flag(member, MFLAG_CAN_HEAR)) {
                stream->write_function(stream, "hear");
                count++;
            }

            if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "speak");
                count++;
            }

            if (switch_test_flag(member, MFLAG_CAN_MUTE)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "can_mute");
                count++;
            }

            if (switch_test_flag(member, MFLAG_TALKING)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "talking");
                count++;
            }

            if (switch_channel_test_flag(switch_core_session_get_channel(member->session), CF_VIDEO)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "video");
                count++;
            }

            if (member == member->conference->floor_holder) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "floor");
                count++;
            }

            if (switch_test_flag(member, MFLAG_MOD)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "moderator");
                count++;
            }

            if (switch_test_flag(member, MFLAG_GHOST)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "ghost");
                count++;
            }

            if (switch_test_flag(member, MFLAG_USE_FAKE_MUTE)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "fake_mute");
                count++;
            }


            stream->write_function(stream, "%s%d%s%d%s%d%s%d\n", delim,
                                   member->volume_in_level,
                                   delim,
                                   member->agc_volume_in_level,
                                   delim, member->volume_out_level, delim, member->energy_level);
        }
    }
    
    switch_mutex_unlock(conference->member_mutex);
}

static void conference_list_fuze(conference_obj_t *conference, switch_stream_handle_t *stream, char *delim)
{
    conference_member_t *member = NULL;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);
    switch_assert(delim != NULL);

    switch_mutex_lock(conference->member_mutex);

    for (int i = 0; i < NUMBER_OF_MEMBER_LISTS; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            uint32_t count = 0;
            char *cid = "unknown";
            char *cin = "unknown";
            int time_since_active = -1;
            switch_time_t now;

            if (member->was_active) {
                now = switch_time_now()/1000;
                time_since_active = (int) ((now - member->last_time_active/1000)/60000);
            }

            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                continue;
            }

            if (member->conference && member->conference->meeting_id) {
                cid = member->conference->meeting_id;
            }
            if (member->conference && member->conference->instance_id) {
                cin = member->conference->instance_id;
            }

            stream->write_function(stream, "%u mtgid:%s mtginst:%s name:%s time since active:%d minutes ",
                                   member->id, cid, cin, member->mname, time_since_active);

            if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "speak");
                count++;
            }

            if (switch_test_flag(member, MFLAG_CAN_MUTE)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "can_mute");
                count++;
            }

            if (switch_test_flag(member, MFLAG_TALKING)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "talking");
                count++;
            }

            if (switch_test_flag(member, MFLAG_MOD)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "moderator");
                count++;
            }

            if (switch_test_flag(member, MFLAG_USE_FAKE_MUTE)) {
                stream->write_function(stream, "%s%s", count ? "|" : "", "fake_mute");
                count++;
            }


            stream->write_function(stream, "%s%d%s%d%s%d%s%d\n", delim,
                                   member->volume_in_level,
                                   delim,
                                   member->agc_volume_in_level,
                                   delim, member->volume_out_level, delim, member->energy_level);
        }
    }

    switch_mutex_unlock(conference->member_mutex);
}

static void conference_list_count_only(conference_obj_t *conference, switch_stream_handle_t *stream)
{
    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    stream->write_function(stream, "%d", conference->count);
}

static switch_status_t conf_api_sub_mute(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if (member->session) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "conf_api_sub_mute member:%s/%d\n", member->mname, member->id);
    }

    if(!switch_test_flag(member,MFLAG_CAN_SPEAK)) {
        if (stream != NULL) {
            stream->write_function(stream, "%u is already muted\n", member->id);
        }
        return SWITCH_STATUS_GENERR;
    }

    if(!switch_test_flag(member,MFLAG_CAN_MUTE)) {
        if (stream != NULL) {
            stream->write_function(stream, "unable to mute %u is mute-locked\n", member->id);
        }
        return SWITCH_STATUS_GENERR;
    }

    clear_member_state_locked(member, MFLAG_CAN_SPEAK);
    clear_member_state_locked(member, MFLAG_TALKING);

    if (!(data) || !strstr((char *) data, "quiet")) {
        set_member_state_unlocked(member, MFLAG_INDICATE_MUTE);
    }
    member->score_iir = 0;

    if (stream != NULL) {
        stream->write_function(stream, "OK %smute %u\n", switch_test_flag(member,MFLAG_USE_FAKE_MUTE) ? "fake " : "", member->id);
    }

    if (test_eflag(member->conference, EFLAG_MUTE_MEMBER) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "mute-member");
        switch_event_fire(&event);
    }

    member_update_status_field(member);

    return SWITCH_STATUS_SUCCESS;
}


static switch_status_t conf_api_sub_tmute(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if (switch_test_flag(member, MFLAG_CAN_SPEAK)) {
        return conf_api_mute(member, stream, data);
    }

    return conf_api_unmute(member, stream, data);
}

static switch_status_t conf_api_sub_agc(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    int level;
    int on = 0;

    if (argc == 2) {
        stream->write_function(stream, "+OK CURRENT AGC LEVEL IS %d\n", conference->agc_level);
        return SWITCH_STATUS_SUCCESS;
    }


    if (!(on = !strcasecmp(argv[2], "on"))) {
        stream->write_function(stream, "+OK AGC DISABLED\n");
        conference->agc_level = 0;
        return SWITCH_STATUS_SUCCESS;
    }

    if (argc > 3) {
        level = atoi(argv[3]);
    } else {
        level = DEFAULT_AGC_LEVEL;
    }

    if (level > conference->energy_level) {
        conference->avg_score = 0;
        conference->avg_itt = 0;
        conference->avg_tally = 0;
        conference->agc_level = level;

        if (stream) {
            stream->write_function(stream, "OK AGC ENABLED %d\n", conference->agc_level);
        }

    } else {
        if (stream) {
            stream->write_function(stream, "-ERR invalid level\n");
        }
    }




    return SWITCH_STATUS_SUCCESS;

}

static switch_status_t conf_api_sub_unmute(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if (member->session) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "conf_api_sub_unmute member:%s/%d\n", member->mname, member->id);
    }

    if(switch_test_flag(member,MFLAG_CAN_SPEAK)) {
        if (stream != NULL) {
            stream->write_function(stream, "%u is already unmuted\n", member->id);
        }
        return SWITCH_STATUS_GENERR;
    }

    if(!switch_test_flag(member,MFLAG_CAN_MUTE) ) {
        if (stream != NULL) {
            stream->write_function(stream, "unable to unmute %u is mute-locked\n", member->id);
        }
        return SWITCH_STATUS_GENERR;
    }

    set_member_state_locked(member, MFLAG_CAN_SPEAK);
    if (!(data) || !strstr((char *) data, "quiet")) {
        set_member_state_unlocked(member, MFLAG_INDICATE_UNMUTE);
    }

    if (stream != NULL) {
        stream->write_function(stream, "OK %sunmute %u\n", switch_test_flag(member,MFLAG_USE_FAKE_MUTE) ? "fake " : "", member->id);
    }

    if (test_eflag(member->conference, EFLAG_UNMUTE_MEMBER) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "unmute-member");
        switch_event_fire(&event);
    }

    member_update_status_field(member);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_deaf(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    clear_member_state_locked(member, MFLAG_CAN_HEAR);
    if (stream != NULL) {
        stream->write_function(stream, "OK deaf %u\n", member->id);
    }
    if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "deaf-member");
        switch_event_fire(&event);
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_undeaf(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    set_member_state_locked(member, MFLAG_CAN_HEAR);
    if (stream != NULL) {
        stream->write_function(stream, "OK undeaf %u\n", member->id);
    }
    if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "undeaf-member");
        switch_event_fire(&event);
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_hup(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL) {
        return SWITCH_STATUS_GENERR;
    }

    clear_member_state_locked(member, MFLAG_RUNNING);

    if (stream != NULL) {
        stream->write_function(stream, "OK hup %u\n", member->id);
    }

    if (member->conference && test_eflag(member->conference, EFLAG_HUP_MEMBER)) {
        if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_member_data(member, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "hup-member");
            switch_event_fire(&event);
        }
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_kick(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "conf_api_sub_kick\n");

    if (member == NULL) {
        return SWITCH_STATUS_GENERR;
    }

    clear_member_state_unlocked(member, MFLAG_RUNNING);
    set_member_state_locked(member, MFLAG_KICKED);
    switch_core_session_kill_channel(member->session, SWITCH_SIG_BREAK);

    if (data && member->session) {
        member->kicked_sound = switch_core_session_strdup(member->session, (char *) data);
    }

    if (stream != NULL) {
        stream->write_function(stream, "OK kicked %u\n", member->id);
    }

    if (member->conference && test_eflag(member->conference, EFLAG_KICK_MEMBER)) {
        if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_member_data(member, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "kick-member");
            switch_event_fire(&event);
        }
    }

    return SWITCH_STATUS_SUCCESS;
}


static switch_status_t conf_api_sub_dtmf(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;
    char *dtmf = (char *) data;

    if (member == NULL) {
        stream->write_function(stream, "Invalid member!\n");
        return SWITCH_STATUS_GENERR;
    }

    if (zstr(dtmf)) {
        stream->write_function(stream, "Invalid input!\n");
        return SWITCH_STATUS_GENERR;
    } else {
        char *p;

        for(p = dtmf; p && *p; p++) {
            switch_dtmf_t *dt, digit = { *p, SWITCH_DEFAULT_DTMF_DURATION };

            switch_zmalloc(dt, sizeof(*dt));
            *dt = digit;

            switch_queue_push(member->dtmf_queue, dt);
            switch_core_session_kill_channel(member->session, SWITCH_SIG_BREAK);
        }
    }

    if (stream != NULL) {
        stream->write_function(stream, "OK sent %s to %u\n", (char *) data, member->id);
    }

    if (test_eflag(member->conference, EFLAG_DTMF_MEMBER) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "dtmf-member");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Digits", dtmf);
        switch_event_fire(&event);
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_energy(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if (data) {
        lock_member(member);
        member->energy_level = atoi((char *) data);
        unlock_member(member);
    }
    if (stream != NULL) {
        stream->write_function(stream, "Energy %u = %d\n", member->id, member->energy_level);
    }
    if (test_eflag(member->conference, EFLAG_ENERGY_LEVEL_MEMBER) &&
        data && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "energy-level-member");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Energy-Level", "%d", member->energy_level);
        switch_event_fire(&event);
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_volume_in(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if (data) {
        lock_member(member);
        member->volume_in_level = atoi((char *) data);
        switch_normalize_volume(member->volume_in_level);
        unlock_member(member);
    }
    if (stream != NULL) {
        stream->write_function(stream, "Volume IN %u = %d\n", member->id, member->volume_in_level);
    }
    if (test_eflag(member->conference, EFLAG_VOLUME_IN_MEMBER) &&
        data && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "volume-in-member");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Volume-Level", "%d", member->volume_in_level);
        switch_event_fire(&event);
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_mutelockable(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if (member->session) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_INFO, "conf_api_sub_mutelockable member:%s/%d\n", member->mname, member->id);
    }

    if (data) {
        lock_member(member);
        /* change mute lockable flag */
        if(strcasecmp(data, "True") == 0){
            set_member_state_unlocked(member, MFLAG_MUTELOCKABLE);
        }
        else if (strcasecmp(data, "False") == 0) {
            clear_member_state_unlocked(member, MFLAG_MUTELOCKABLE);
        }
        unlock_member(member);
    }
    if (stream != NULL) {
        stream->write_function(stream, "member %u is now mute %s\n", member->id, (switch_test_flag(member, MFLAG_MUTELOCKABLE)) ? "lockable" : "non lockable");
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_volume_out(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if (data) {
        lock_member(member);
        member->volume_out_level = atoi((char *) data);
        switch_normalize_volume(member->volume_out_level);
        unlock_member(member);
    }
    if (stream != NULL) {
        stream->write_function(stream, "Volume OUT %u = %d\n", member->id, member->volume_out_level);
    }
    if (test_eflag(member->conference, EFLAG_VOLUME_OUT_MEMBER) && data &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "volume-out-member");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Volume-Level", "%d", member->volume_out_level);
        switch_event_fire(&event);
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_list(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    int ret_status = SWITCH_STATUS_GENERR;
    int count = 0;
    switch_hash_index_t *hi;
    void *val;
    char *d = ";";
    int pretty = 0;
    int fuze = 0;
    int summary = 0;
    int countonly = 0;
    int argofs = (argc >= 2 && strcasecmp(argv[1], "list") == 0);    /* detect being called from chat vs. api */

    if (argv[1 + argofs]) {
        if (argv[2 + argofs] && !strcasecmp(argv[1 + argofs], "delim")) {
            d = argv[2 + argofs];

            if (*d == '"') {
                if (++d) {
                    char *p;
                    if ((p = strchr(d, '"'))) {
                        *p = '\0';
                    }
                } else {
                    d = ";";
                }
            }
        } else if (strcasecmp(argv[1 + argofs], "pretty") == 0) {
            pretty = 1;
        } else if (strcasecmp(argv[1 + argofs], "summary") == 0) {
            summary = 1;
        } else if (strcasecmp(argv[1 + argofs], "fuze") == 0) {
            fuze = 1;
        } else if (strcasecmp(argv[1 + argofs], "count") == 0) {
            countonly = 1;
        }
    }

    if (conference == NULL) {
        switch_mutex_lock(globals.hash_mutex);
        for (hi = switch_core_hash_first(globals.conference_hash); hi; hi = switch_core_hash_next(&hi)) {
            int fcount = 0;
            switch_core_hash_this(hi, NULL, NULL, &val);
            conference = (conference_obj_t *) val;

            stream->write_function(stream, "Conference %s (%u member%s rate: %u%s flags: ",
                                   conference->name,
                                   conference->count,
                                   conference->count == 1 ? "" : "s", conference->rate, switch_test_flag(conference, CFLAG_LOCKED) ? " locked" : "");

            if (switch_test_flag(conference, CFLAG_LOCKED)) {
                stream->write_function(stream, "%slocked", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_DESTRUCT)) {
                stream->write_function(stream, "%sdestruct", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_WAIT_MOD)) {
                stream->write_function(stream, "%swait_mod", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_AUDIO_ALWAYS)) {
                stream->write_function(stream, "%saudio_always", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_RUNNING)) {
                stream->write_function(stream, "%srunning", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_ANSWERED)) {
                stream->write_function(stream, "%sanswered", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_ENFORCE_MIN)) {
                stream->write_function(stream, "%senforce_min", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_BRIDGE_TO)) {
                stream->write_function(stream, "%sbridge_to", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_DYNAMIC)) {
                stream->write_function(stream, "%sdynamic", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_EXIT_SOUND)) {
                stream->write_function(stream, "%sexit_sound", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_ENTER_SOUND)) {
                stream->write_function(stream, "%senter_sound", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_INDICATE_LOCK_MUTE)) {
                stream->write_function(stream, "%slocked_mutes", fcount ? "|" : "");
                fcount++;
            }

            if (conference->record_count > 0) {
                stream->write_function(stream, "%srecording", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_VIDEO_BRIDGE)) {
                stream->write_function(stream, "%svideo_bridge", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_VID_FLOOR)) {
                stream->write_function(stream, "%svideo_floor_only", fcount ? "|" : "");
                fcount++;
            }

            if (switch_test_flag(conference, CFLAG_RFC4579)) {
                stream->write_function(stream, "%svideo_rfc4579", fcount ? "|" : "");
                fcount++;
            }

            if (!fcount) {
                stream->write_function(stream, "none");
            }

            stream->write_function(stream, ")\n");

            count++;
            if (!summary) {
                if (fuze) {
                    conference_list_fuze(conference, stream, d);
                } else if (pretty) {
                    conference_list_pretty(conference, stream);
                } else {
                    conference_list(conference, stream, d);
                }
            }
        }
        switch_mutex_unlock(globals.hash_mutex);
    } else {
        count++;
        if (countonly) {
            conference_list_count_only(conference, stream);
        } else if (pretty) {
            conference_list_pretty(conference, stream);
        } else {
            conference_list(conference, stream, d);
        }
    }

    if (!count) {
        stream->write_function(stream, "No active conferences.\n");
    }

    ret_status = SWITCH_STATUS_SUCCESS;

    return ret_status;
}

static switch_status_t conf_api_sub_floor(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    switch_mutex_lock(member->conference->mutex);

    if (member->conference->floor_holder == member) {
        conference_set_floor_holder(member->conference, NULL);
        if (stream != NULL) {
            stream->write_function(stream, "OK floor none\n");
        }
    } else if (member->conference->floor_holder == NULL) {
        conference_set_floor_holder(member->conference, member);
        if (stream != NULL) {
            stream->write_function(stream, "OK floor %u\n", member->id);
        }
    } else {
        if (stream != NULL) {
            stream->write_function(stream, "ERR floor is held by %u\n", member->conference->floor_holder->id);
        }
    }

    switch_mutex_unlock(member->conference->mutex);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_enforce_floor(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    switch_event_t *event;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    switch_mutex_lock(member->conference->mutex);

    if (member->conference->floor_holder != member) {
        conference_member_t *old_member = member->conference->floor_holder;
        member->conference->floor_holder = member;
        if (test_eflag(member->conference, EFLAG_FLOOR_CHANGE)) {
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT);
            conference_add_event_data(member->conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "floor-change");
            if (old_member == NULL) {
                switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Old-ID", "none");
            } else {
                switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Old-ID", "%d", old_member->id);
            }
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "New-ID", "%d", member->id);
            switch_event_fire(&event);
            if (stream != NULL) {
                stream->write_function(stream, "OK floor %u\n", member->id);
            }
        }

        if (switch_core_session_read_lock(member->session) == SWITCH_STATUS_SUCCESS) {
            /* Tell the channel to request a fresh vid frame */
            switch_channel_set_flag(switch_core_session_get_channel(member->session), CF_VIDEO_REFRESH_REQ);
            switch_core_session_rwunlock(member->session);
        }
    }

    switch_mutex_unlock(member->conference->mutex);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_clear_vid_floor(conference_obj_t *conference, switch_stream_handle_t *stream, void *data)
{

    if (switch_test_flag(conference, CFLAG_VIDEO_BRIDGE)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                          "conference %s is in video bridge mode, this functionality is not compatible\n", conference->name);
        return SWITCH_STATUS_FALSE;
    }

    switch_mutex_lock(conference->mutex);
    clear_conference_state_unlocked(conference, CFLAG_VID_FLOOR_LOCK);
    //conference_set_video_floor_holder(conference, NULL);
    switch_mutex_unlock(conference->mutex);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_vid_floor(conference_member_t *member, switch_stream_handle_t *stream, void *data)
{
    int force = 0;

    if (member == NULL)
        return SWITCH_STATUS_GENERR;

    if (!switch_channel_test_flag(member->channel, CF_VIDEO)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Channel %s does not have video capability!\n", switch_channel_get_name(member->channel));
        return SWITCH_STATUS_FALSE;
    }

    if (switch_test_flag(member->conference, CFLAG_VIDEO_BRIDGE)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                          "conference %s is in video bridge mode, this functionality is not compatible\n", member->conference->name);
        return SWITCH_STATUS_FALSE;
    }

    switch_mutex_lock(member->conference->mutex);

    if (data && switch_stristr("force", (char *) data)) {
        force = 1;
    }

    if (member->conference->video_floor_holder == member && switch_test_flag(member->conference, CFLAG_VID_FLOOR_LOCK)) {
        clear_conference_state_unlocked(member->conference, CFLAG_VID_FLOOR_LOCK);

        conference_set_floor_holder(member->conference, member);
        if (stream == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "conference %s OK video floor auto\n", member->conference->name);
        } else {
            stream->write_function(stream, "OK floor none\n");
        }

    } else if (force || member->conference->video_floor_holder == NULL) {
        set_conference_state_unlocked(member->conference, CFLAG_VID_FLOOR_LOCK);
        conference_set_video_floor_holder(member->conference, member, SWITCH_TRUE);
        if (test_eflag(member->conference, EFLAG_FLOOR_CHANGE)) {
            if (stream == NULL) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "conference %s OK video floor %d %s\n",
                                  member->conference->name, member->id, switch_channel_get_name(member->channel));
            } else {
                stream->write_function(stream, "OK floor %u\n", member->id);
            }
        }
    } else {
        if (stream == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "conference %s floor already held by %d %s\n",
                              member->conference->name, member->id, switch_channel_get_name(member->channel));
        } else {
            stream->write_function(stream, "ERR floor is held by %u\n", member->conference->video_floor_holder->id);
        }
    }

    switch_mutex_unlock(member->conference->mutex);

    return SWITCH_STATUS_SUCCESS;
}

static switch_xml_t add_x_tag(switch_xml_t x_member, const char *name, const char *value, int off)
{
    switch_size_t dlen;
    char *data;
    switch_xml_t x_tag;

    if (!value) {
        return 0;
    }

    dlen = strlen(value) * 3 + 1;

    x_tag = switch_xml_add_child_d(x_member, name, off);
    switch_assert(x_tag);

    switch_zmalloc(data, dlen);

    switch_url_encode(value, data, dlen);
    switch_xml_set_txt_d(x_tag, data);
    free(data);

    return x_tag;
}

static void conference_xlist(conference_obj_t *conference, switch_xml_t x_conference, int off)
{
    conference_member_t *member = NULL;
    switch_xml_t x_member = NULL, x_members = NULL, x_flags;
    int moff = 0;
    char i[30] = "";
    char *ival = i;
    switch_assert(conference != NULL);
    switch_assert(x_conference != NULL);

    switch_xml_set_attr_d(x_conference, "name", conference->name);
    switch_snprintf(i, sizeof(i), "%d", conference->count);
    switch_xml_set_attr_d(x_conference, "member-count", ival);
    switch_snprintf(i, sizeof(i), "%d", conference->count_ghosts);
    switch_xml_set_attr_d(x_conference, "ghost-count", ival);
    switch_snprintf(i, sizeof(i), "%u", conference->rate);
    switch_xml_set_attr_d(x_conference, "rate", ival);
    switch_xml_set_attr_d(x_conference, "uuid", conference->uuid_str);

    if (switch_test_flag(conference, CFLAG_LOCKED)) {
        switch_xml_set_attr_d(x_conference, "locked", "true");
    }

    if (switch_test_flag(conference, CFLAG_DESTRUCT)) {
        switch_xml_set_attr_d(x_conference, "destruct", "true");
    }

    if (switch_test_flag(conference, CFLAG_WAIT_MOD)) {
        switch_xml_set_attr_d(x_conference, "wait_mod", "true");
    }

    if (switch_test_flag(conference, CFLAG_AUDIO_ALWAYS)) {
        switch_xml_set_attr_d(x_conference, "audio_always", "true");
    }

    if (switch_test_flag(conference, CFLAG_RUNNING)) {
        switch_xml_set_attr_d(x_conference, "running", "true");
    }

    if (switch_test_flag(conference, CFLAG_ANSWERED)) {
        switch_xml_set_attr_d(x_conference, "answered", "true");
    }

    if (switch_test_flag(conference, CFLAG_ENFORCE_MIN)) {
        switch_xml_set_attr_d(x_conference, "enforce_min", "true");
    }

    if (switch_test_flag(conference, CFLAG_BRIDGE_TO)) {
        switch_xml_set_attr_d(x_conference, "bridge_to", "true");
    }

    if (switch_test_flag(conference, CFLAG_DYNAMIC)) {
        switch_xml_set_attr_d(x_conference, "dynamic", "true");
    }

    if (switch_test_flag(conference, CFLAG_EXIT_SOUND)) {
        switch_xml_set_attr_d(x_conference, "exit_sound", "true");
    }

    if (switch_test_flag(conference, CFLAG_ENTER_SOUND)) {
        switch_xml_set_attr_d(x_conference, "enter_sound", "true");
    }

    if (conference->max_members > 0) {
        switch_snprintf(i, sizeof(i), "%d", conference->max_members);
        switch_xml_set_attr_d(x_conference, "max_members", ival);
    }

    if (conference->record_count > 0) {
        switch_xml_set_attr_d(x_conference, "recording", "true");
    }

    if (conference->endconf_grace_time > 0) {
        switch_snprintf(i, sizeof(i), "%u", conference->endconf_grace_time);
        switch_xml_set_attr_d(x_conference, "endconf_grace_time", ival);
    }

    if (switch_test_flag(conference, CFLAG_VIDEO_BRIDGE)) {
        switch_xml_set_attr_d(x_conference, "video_bridge", "true");
    }

    if (switch_test_flag(conference, CFLAG_VID_FLOOR)) {
        switch_xml_set_attr_d(x_conference, "video_floor_only", "true");
    }

    if (switch_test_flag(conference, CFLAG_RFC4579)) {
        switch_xml_set_attr_d(x_conference, "video_rfc4579", "true");
    }

    if (switch_test_flag(conference, CFLAG_INDICATE_LOCK_MUTE)) {
        switch_xml_set_attr_d(x_conference, "locked_mutes", "true");
    }

    switch_snprintf(i, sizeof(i), "%d", switch_epoch_time_now(NULL) - conference->run_time);
    switch_xml_set_attr_d(x_conference, "run_time", ival);

    if (conference->agc_level) {
        char tmp[30] = "";
        switch_snprintf(tmp, sizeof(tmp), "%d", conference->agc_level);
        switch_xml_set_attr_d_buf(x_conference, "agc", tmp);
    }

    x_members = switch_xml_add_child_d(x_conference, "members", 0);
    switch_assert(x_members);

    switch_mutex_lock(conference->member_mutex);

    for (int j = 0; j < NUMBER_OF_MEMBER_LISTS; j++) {
        for (member = conference->member_lists[j]; member; member = member->next) {
            switch_channel_t *channel;
            switch_caller_profile_t *profile;
            char *uuid;
            //char *name;
            uint32_t count = 0;
            switch_xml_t x_tag;
            int toff = 0;
            char tmp[50] = "";

            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                if (member->rec_path) {
                    x_member = switch_xml_add_child_d(x_members, "member", moff++);
                    switch_assert(x_member);
                    switch_xml_set_attr_d(x_member, "type", "recording_node");
                    /* or:
                    x_member = switch_xml_add_child_d(x_members, "recording_node", moff++);
                    */

                    x_tag = switch_xml_add_child_d(x_member, "record_path", count++);
                    if (switch_test_flag(member, MFLAG_PAUSE_RECORDING)) {
                        switch_xml_set_attr_d(x_tag, "status", "paused");
                    }
                    switch_xml_set_txt_d(x_tag, member->rec_path);

                    x_tag = switch_xml_add_child_d(x_member, "join_time", count++);
                    switch_xml_set_attr_d(x_tag, "type", "UNIX-epoch");
                    switch_snprintf(i, sizeof(i), "%d", member->rec_time);
                    switch_xml_set_txt_d(x_tag, i);
                }
                continue;
            }

            uuid = switch_core_session_get_uuid(member->session);
            channel = switch_core_session_get_channel(member->session);
            profile = switch_channel_get_caller_profile(channel);
            //name = switch_channel_get_name(channel);


            x_member = switch_xml_add_child_d(x_members, "member", moff++);
            switch_assert(x_member);
            switch_xml_set_attr_d(x_member, "type", "caller");

            switch_snprintf(i, sizeof(i), "%d", member->id);

            add_x_tag(x_member, "id", i, toff++);
            add_x_tag(x_member, "uuid", uuid, toff++);
            add_x_tag(x_member, "caller_id_name", profile->caller_id_name, toff++);
            add_x_tag(x_member, "caller_id_number", profile->caller_id_number, toff++);


            switch_snprintf(i, sizeof(i), "%d", switch_epoch_time_now(NULL) - member->join_time);
            add_x_tag(x_member, "join_time", i, toff++);

            switch_snprintf(i, sizeof(i), "%d", switch_epoch_time_now(NULL) - member->last_talking);
            add_x_tag(x_member, "last_talking", member->last_talking ? i : "N/A", toff++);

            switch_snprintf(i, sizeof(i), "%d", member->energy_level);
            add_x_tag(x_member, "energy", i, toff++);

            switch_snprintf(i, sizeof(i), "%d", member->volume_in_level);
            add_x_tag(x_member, "volume_in", i, toff++);

            switch_snprintf(i, sizeof(i), "%d", member->volume_out_level);
            add_x_tag(x_member, "volume_out", i, toff++);

            x_flags = switch_xml_add_child_d(x_member, "flags", count++);
            switch_assert(x_flags);

            x_tag = switch_xml_add_child_d(x_flags, "can_hear", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_CAN_HEAR) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "can_speak", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_CAN_SPEAK) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "can_mute", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_CAN_MUTE) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "mute_detect", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_MUTE_DETECT) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "talking", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_TALKING) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "has_video", count++);
            switch_xml_set_txt_d(x_tag, switch_channel_test_flag(switch_core_session_get_channel(member->session), CF_VIDEO) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "fake_mute", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_USE_FAKE_MUTE) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "has_floor", count++);
            switch_xml_set_txt_d(x_tag, (member == member->conference->floor_holder) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "is_moderator", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_MOD) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "end_conference", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_ENDCONF) ? "true" : "false");

            x_tag = switch_xml_add_child_d(x_flags, "is_ghost", count++);
            switch_xml_set_txt_d(x_tag, switch_test_flag(member, MFLAG_GHOST) ? "true" : "false");

            switch_snprintf(tmp, sizeof(tmp), "%d", member->volume_out_level);
            add_x_tag(x_member, "output-volume", tmp, toff++);

            switch_snprintf(tmp, sizeof(tmp), "%d", member->agc_volume_in_level ? member->agc_volume_in_level : member->volume_in_level);
            add_x_tag(x_member, "input-volume", tmp, toff++);

            switch_snprintf(tmp, sizeof(tmp), "%d", member->agc_volume_in_level);
            add_x_tag(x_member, "auto-adjusted-input-volume", tmp, toff++);

        }
    }
    
    switch_mutex_unlock(conference->member_mutex);
}
static switch_status_t conf_api_sub_xml_list(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    int count = 0;
    switch_hash_index_t *hi;
    void *val;
    switch_xml_t x_conference, x_conferences;
    int off = 0;
    char *ebuf;

    x_conferences = switch_xml_new("conferences");
    switch_assert(x_conferences);

    if (conference == NULL) {
        switch_mutex_lock(globals.hash_mutex);
        for (hi = switch_core_hash_first(globals.conference_hash); hi; hi = switch_core_hash_next(&hi)) {
            switch_core_hash_this(hi, NULL, NULL, &val);
            conference = (conference_obj_t *) val;

            x_conference = switch_xml_add_child_d(x_conferences, "conference", off++);
            switch_assert(conference);

            count++;
            conference_xlist(conference, x_conference, off);

        }
        switch_mutex_unlock(globals.hash_mutex);
    } else {
        x_conference = switch_xml_add_child_d(x_conferences, "conference", off++);
        switch_assert(conference);
        count++;
        conference_xlist(conference, x_conference, off);
    }


    ebuf = switch_xml_toxml(x_conferences, SWITCH_TRUE);

    stream->write_function(stream, "%s", ebuf);

    switch_xml_free(x_conferences);
    free(ebuf);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_pause_play(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    if (argc == 2) {
        switch_mutex_lock(conference->mutex);
        if (conference->fnode) {
            if (switch_test_flag(conference->fnode, NFLAG_PAUSE)) {
                stream->write_function(stream, "+OK Resume\n");
                switch_clear_flag(conference->fnode, NFLAG_PAUSE);
            } else {
                stream->write_function(stream, "+OK Pause\n");
                switch_set_flag(conference->fnode, NFLAG_PAUSE);
            }
        }
        switch_mutex_unlock(conference->mutex);

        return SWITCH_STATUS_SUCCESS;
    }

    return SWITCH_STATUS_GENERR;
}

static switch_status_t conf_api_sub_file_seek(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    if (argc == 3) {
        unsigned int samps = 0;
        unsigned int pos = 0;

        switch_mutex_lock(conference->mutex);

        if (conference->fnode && conference->fnode->type == NODE_TYPE_FILE) {
            if (*argv[2] == '+' || *argv[2] == '-') {
                int step;
                int32_t target;
                if (!(step = atoi(argv[2]))) {
                    step = 1000;
                }
                samps = step * (conference->fnode->fh.native_rate / 1000);
                target = (int32_t)conference->fnode->fh.pos + samps;

                if (target < 0) {
                    target = 0;
                }

                stream->write_function(stream, "+OK seek to position %d\n", target);
                switch_core_file_seek(&conference->fnode->fh, &pos, target, SEEK_SET);

            } else {
                samps = switch_atoui(argv[2]) * (conference->fnode->fh.native_rate / 1000);
                stream->write_function(stream, "+OK seek to position %d\n", samps);
                switch_core_file_seek(&conference->fnode->fh, &pos, samps, SEEK_SET);
            }
        }
        switch_mutex_unlock(conference->mutex);

        return SWITCH_STATUS_SUCCESS;
    }

    return SWITCH_STATUS_GENERR;
}

static switch_status_t conf_api_sub_play(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    int ret_status = SWITCH_STATUS_GENERR;
    switch_event_t *event;
    uint8_t async = 0;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if ((argc == 4 && !strcasecmp(argv[3], "async")) || (argc == 5 && !strcasecmp(argv[4], "async"))) {
        argc--;
        async++;
    }

    if (argc == 3) {
        if (conference_play_file(conference, argv[2], 0, NULL, async, 0) == SWITCH_STATUS_SUCCESS) {
            stream->write_function(stream, "(play) Playing file %s\n", argv[2]);
            if (test_eflag(conference, EFLAG_PLAY_FILE) &&
                switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
                conference_add_event_data(conference, event);

                if (conference->fnode && conference->fnode->fh.params) {
                    switch_event_merge(event, conference->fnode->fh.params);
                }

                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "play-file");
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "File", argv[2]);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Async", async ? "true" : "false");
                switch_event_fire(&event);
            }
        } else {
            stream->write_function(stream, "(play) File: %s not found.\n", argv[2] ? argv[2] : "(unspecified)");
        }
        ret_status = SWITCH_STATUS_SUCCESS;
    } else if (argc >= 4) {
        uint32_t id = atoi(argv[3]);
        conference_member_t *member;

        if ((member = conference_member_get(conference, id))) {
            if (conference_member_play_file(member, argv[2], 0, 1) == SWITCH_STATUS_SUCCESS) {
                stream->write_function(stream, "(play) Playing file %s to member %u\n", argv[2], id);
                if (test_eflag(conference, EFLAG_PLAY_FILE_MEMBER) &&
                    switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
                    conference_add_event_member_data(member, event);

                    if (member->fnode->fh.params) {
                        switch_event_merge(event, member->fnode->fh.params);
                    }

                    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "play-file-member");
                    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "File", argv[2]);
                    switch_event_fire(&event);
                }
            } else {
                stream->write_function(stream, "(play) File: %s not found.\n", argv[2] ? argv[2] : "(unspecified)");
            }
            switch_thread_rwlock_unlock(member->rwlock);
            ret_status = SWITCH_STATUS_SUCCESS;
        } else {
            stream->write_function(stream, "Member: %u not found.\n", id);
        }
    }

    return ret_status;
}

static switch_status_t conf_api_sub_say(conference_obj_t *conference, switch_stream_handle_t *stream, const char *text)
{
    switch_event_t *event;

    if (zstr(text)) {
        stream->write_function(stream, "(say) Error! No text.\n");
        return SWITCH_STATUS_GENERR;
    }

    if (conference_say(conference, text, 0) != SWITCH_STATUS_SUCCESS) {
        stream->write_function(stream, "(say) Error!\n");
        return SWITCH_STATUS_GENERR;
    }

    stream->write_function(stream, "(say) OK\n");
    if (test_eflag(conference, EFLAG_SPEAK_TEXT) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_data(conference, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "speak-text");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Text", text);
        switch_event_fire(&event);
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_saymember(conference_obj_t *conference, switch_stream_handle_t *stream, const char *text)
{
    int ret_status = SWITCH_STATUS_GENERR;
    char *expanded = NULL;
    char *start_text = NULL;
    char *workspace = NULL;
    uint32_t id = 0;
    conference_member_t *member = NULL;
    switch_event_t *event;

    if (zstr(text)) {
        stream->write_function(stream, "(saymember) No Text!\n");
        goto done;
    }

    if (!(workspace = strdup(text))) {
        stream->write_function(stream, "(saymember) Memory Error!\n");
        goto done;
    }

    if ((start_text = strchr(workspace, ' '))) {
        *start_text++ = '\0';
        text = start_text;
    }

    id = atoi(workspace);

    if (!id || zstr(text)) {
        stream->write_function(stream, "(saymember) No Text!\n");
        goto done;
    }

    if (!(member = conference_member_get(conference, id))) {
        stream->write_function(stream, "(saymember) Unknown Member %u!\n", id);
        goto done;
    }

    if ((expanded = switch_channel_expand_variables(switch_core_session_get_channel(member->session), (char *) text)) != text) {
        text = expanded;
    } else {
        expanded = NULL;
    }

    if (!text || conference_member_say(member, (char *) text, 0) != SWITCH_STATUS_SUCCESS) {
        stream->write_function(stream, "(saymember) Error!\n");
        goto done;
    }

    stream->write_function(stream, "(saymember) OK\n");
    if (test_eflag(member->conference, EFLAG_SPEAK_TEXT_MEMBER) &&
        switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_member_data(member, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "speak-text-member");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Text", text);
        switch_event_fire(&event);
    }
    ret_status = SWITCH_STATUS_SUCCESS;

  done:

    if (member) {
        switch_thread_rwlock_unlock(member->rwlock);
    }

    switch_safe_free(workspace);
    switch_safe_free(expanded);
    return ret_status;
}

static switch_status_t conf_api_sub_stop(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    uint8_t current = 0, all = 0, async = 0;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc > 2) {
        current = strcasecmp(argv[2], "current") ? 0 : 1;
        all = strcasecmp(argv[2], "all") ? 0 : 1;
        async = strcasecmp(argv[2], "async") ? 0 : 1;
    } else {
        all = 1;
    }

    if (!(current || all || async))
        return SWITCH_STATUS_GENERR;

    if (argc == 4) {
        uint32_t id = atoi(argv[3]);
        conference_member_t *member;

        if ((member = conference_member_get(conference, id))) {
            uint32_t stopped = conference_member_stop_file(member, async ? FILE_STOP_ASYNC : current ? FILE_STOP_CURRENT : FILE_STOP_ALL);
            stream->write_function(stream, "Stopped %u files.\n", stopped);
            switch_thread_rwlock_unlock(member->rwlock);
        } else {
            stream->write_function(stream, "Member: %u not found.\n", id);
        }
    } else {
        uint32_t stopped = conference_stop_file(conference, async ? FILE_STOP_ASYNC : current ? FILE_STOP_CURRENT : FILE_STOP_ALL);
        stream->write_function(stream, "Stopped %u files.\n", stopped);
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_relate(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    uint8_t nospeak = 0, nohear = 0, clear = 0;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc <= 4)
        return SWITCH_STATUS_GENERR;

    nospeak = strstr(argv[4], "nospeak") ? 1 : 0;
    nohear = strstr(argv[4], "nohear") ? 1 : 0;

    if (!strcasecmp(argv[4], "clear")) {
        clear = 1;
    }

    if (!(clear || nospeak || nohear)) {
        return SWITCH_STATUS_GENERR;
    }

    if (clear) {
        conference_member_t *member = NULL;
        uint32_t id = atoi(argv[2]);
        uint32_t oid = atoi(argv[3]);

        if ((member = conference_member_get(conference, id))) {
            member_del_relationship(member, oid);
            stream->write_function(stream, "relationship %u->%u cleared.\n", id, oid);
            switch_thread_rwlock_unlock(member->rwlock);
        } else {
            stream->write_function(stream, "relationship %u->%u not found.\n", id, oid);
        }
        return SWITCH_STATUS_SUCCESS;
    }

    if (nospeak || nohear) {
        conference_member_t *member = NULL, *other_member = NULL;
        uint32_t id = atoi(argv[2]);
        uint32_t oid = atoi(argv[3]);

        if ((member = conference_member_get(conference, id))) {
            other_member = conference_member_get(conference, oid);
        }

        if (member && other_member) {
            conference_relationship_t *rel = NULL;

            if ((rel = member_get_relationship(member, other_member))) {
                rel->flags = 0;
            } else {
                rel = member_add_relationship(member, oid);
            }

            if (rel) {
                switch_set_flag(rel, RFLAG_CAN_SPEAK | RFLAG_CAN_HEAR);
                if (nospeak) {
                    switch_clear_flag(rel, RFLAG_CAN_SPEAK);
                    switch_clear_flag_locked(member, MFLAG_TALKING);
                }
                if (nohear) {
                    switch_clear_flag(rel, RFLAG_CAN_HEAR);
                }
                stream->write_function(stream, "ok %u->%u set\n", id, oid);
            } else {
                stream->write_function(stream, "error!\n");
            }
        } else {
            stream->write_function(stream, "relationship %u->%u not found.\n", id, oid);
        }

        if (member) {
            switch_thread_rwlock_unlock(member->rwlock);
        }

        if (other_member) {
            switch_thread_rwlock_unlock(other_member->rwlock);
        }
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_lock(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_event_t *event;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (conference->is_locked_sound) {
        conference_play_file(conference, conference->is_locked_sound, CONF_DEFAULT_LEADIN, NULL, 0, 0);
    }

    if (conference->meeting_id) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "conf_api_sub_lock conference:%s\n", conference->meeting_id);
    }

    set_conference_state_locked(conference, CFLAG_LOCKED);
    stream->write_function(stream, "OK %s locked\n", argv[0]);
    if (test_eflag(conference, EFLAG_LOCK) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_data(conference, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "lock");
        switch_event_fire(&event);
    }

    return 0;
}

static switch_status_t conf_api_sub_unlock(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_event_t *event;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (conference->is_unlocked_sound) {
        conference_play_file(conference, conference->is_unlocked_sound, CONF_DEFAULT_LEADIN, NULL, 0, 0);
    }

    if (conference->meeting_id) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "conf_api_sub_unlock conference:%s\n", conference->meeting_id);
    }

    clear_conference_state_locked(conference, CFLAG_LOCKED);
    stream->write_function(stream, "OK %s unlocked\n", argv[0]);
    if (test_eflag(conference, EFLAG_UNLOCK) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
        conference_add_event_data(conference, event);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "unlock");
        switch_event_fire(&event);
    }

    return 0;
}

static void conference_play_to_moderator(conference_obj_t *conference, char *file, uint32_t leadin)
{
    conference_member_t *member;
    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            if (switch_test_flag(member, MFLAG_MOD)) {
                if (!conference->async_fnode) {
                    conference_member_play_file (member, file, leadin, 1);
                }
            }
        }
    }
}

static switch_status_t conf_api_sub_exit_sound(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_event_t *event;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc <= 2) {
        stream->write_function(stream, "Not enough args\n");
        return SWITCH_STATUS_GENERR;
    }

    if ( !strcasecmp(argv[2], "on") ) {
        set_conference_state_locked(conference, CFLAG_EXIT_SOUND);
        stream->write_function(stream, "OK %s exit sounds on (%s)\n", argv[0], conference->exit_sound);
        if (test_eflag(conference, EFLAG_LOCK) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "exit-sounds-on");
            switch_event_fire(&event);
        }
    } else if ( !strcasecmp(argv[2], "off") || !strcasecmp(argv[2], "none") ) {
        clear_conference_state_locked(conference, CFLAG_EXIT_SOUND);
        stream->write_function(stream, "OK %s exit sounds off (%s)\n", argv[0], conference->exit_sound);
        if (test_eflag(conference, EFLAG_LOCK) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "exit-sounds-off");
            switch_event_fire(&event);
        }
    } else if ( !strcasecmp(argv[2], "file") ) {
        if (! argv[3]) {
            stream->write_function(stream, "No filename specified\n");
        } else {
            /* TODO: if possible, verify file exists before setting it */
            stream->write_function(stream,"Old exit sound: [%s]\n", conference->exit_sound);
            conference->exit_sound = switch_core_strdup(conference->pool, argv[3]);
            stream->write_function(stream, "OK %s exit sound file set to %s\n", argv[0], conference->exit_sound);
            if (test_eflag(conference, EFLAG_LOCK) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
                conference_add_event_data(conference, event);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "exit-sound-file-changed");
                switch_event_fire(&event);
            }
        }
    } else {
        stream->write_function(stream, "Bad args\n");
        return SWITCH_STATUS_GENERR;
    }

    return 0;
}

static switch_status_t conf_api_sub_enter_sound(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_event_t *event;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc <= 2) {
        stream->write_function(stream, "Not enough args\n");
        return SWITCH_STATUS_GENERR;
    }

    if (conference->count > 50) {
        return SWITCH_STATUS_SUCCESS;
    }

    if ( !strcasecmp(argv[2], "on") ) {
        set_conference_state_locked(conference, CFLAG_ENTER_SOUND);
        stream->write_function(stream, "OK %s enter sounds on (%s)\n", argv[0], conference->enter_sound);
        conference_play_to_moderator(conference, conference->chimes_on_sound, CONF_DEFAULT_LEADIN);
        if (test_eflag(conference, EFLAG_LOCK) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "enter-sounds-on");
            switch_event_fire(&event);
        }
    } else if ( !strcasecmp(argv[2], "off") || !strcasecmp(argv[2], "none") ) {
        clear_conference_state_locked(conference, CFLAG_ENTER_SOUND);
        stream->write_function(stream, "OK %s enter sounds off (%s)\n", argv[0], conference->enter_sound);
        conference_play_to_moderator(conference, conference->chimes_off_sound, CONF_DEFAULT_LEADIN);
        if (test_eflag(conference, EFLAG_LOCK) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "enter-sounds-off");
            switch_event_fire(&event);
        }
    } else if ( !strcasecmp(argv[2], "file") ) {
        if (! argv[3]) {
            stream->write_function(stream, "No filename specified\n");
        } else {
            /* TODO: verify file exists before setting it */
            conference->enter_sound = switch_core_strdup(conference->pool, argv[3]);
            stream->write_function(stream, "OK %s enter sound file set to %s\n", argv[0], conference->enter_sound);
            if (test_eflag(conference, EFLAG_LOCK) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
                conference_add_event_data(conference, event);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "enter-sound-file-changed");
                switch_event_fire(&event);
            }
        }
    } else {
        stream->write_function(stream, "Bad args\n");
        return SWITCH_STATUS_GENERR;
    }

    return 0;
}


static switch_status_t conf_api_sub_dial(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_call_cause_t cause;

    switch_assert(stream != NULL);

    if (argc <= 2) {
        stream->write_function(stream, "Bad Args\n");
        return SWITCH_STATUS_GENERR;
    }

    if (conference) {
        conference_outcall(conference, NULL, NULL, argv[2], 60, NULL, argv[4], argv[3], NULL, &cause, NULL, NULL);
    } else {
        conference_outcall(NULL, argv[0], NULL, argv[2], 60, NULL, argv[4], argv[3], NULL, &cause, NULL, NULL);
    }
    stream->write_function(stream, "Call Requested: result: [%s]\n", switch_channel_cause2str(cause));

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_bgdial(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_uuid_t uuid;
    char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1];

    switch_assert(stream != NULL);

    if (argc <= 2) {
        stream->write_function(stream, "Bad Args\n");
        return SWITCH_STATUS_GENERR;
    }

    switch_uuid_get(&uuid);
    switch_uuid_format(uuid_str, &uuid);

    if (conference) {
        conference_outcall_bg(conference, NULL, NULL, argv[2], 60, NULL, argv[4], argv[3], uuid_str, NULL, NULL, NULL);
    } else {
        conference_outcall_bg(NULL, argv[0], NULL, argv[2], 60, NULL, argv[4], argv[3], uuid_str, NULL, NULL, NULL);
    }

    stream->write_function(stream, "OK Job-UUID: %s\n", uuid_str);

    return SWITCH_STATUS_SUCCESS;
}



static switch_status_t conf_api_sub_transfer(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_status_t ret_status = SWITCH_STATUS_SUCCESS;
    char *conf_name = NULL, *profile_name;
    switch_event_t *params = NULL;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc > 3 && !zstr(argv[2])) {
        int x;

        conf_name = strdup(argv[2]);

        if ((profile_name = strchr(conf_name, '@'))) {
            *profile_name++ = '\0';
        } else {
            profile_name = "default";
        }

        for (x = 3; x < argc; x++) {
            conference_member_t *member = NULL;
            uint32_t id = atoi(argv[x]);
            switch_channel_t *channel;
            switch_event_t *event;
            char *xdest = NULL;

            if (!id || !(member = conference_member_get(conference, id))) {
                stream->write_function(stream, "No Member %u in conference %s.\n", id, conference->name);
                continue;
            }

            channel = switch_core_session_get_channel(member->session);
            xdest = switch_core_session_sprintf(member->session, "conference:%s@%s", conf_name, profile_name);
            switch_ivr_session_transfer(member->session, xdest, "inline", NULL);

            switch_channel_set_variable(channel, "last_transfered_conference", conf_name);

            stream->write_function(stream, "OK Member '%d' sent to conference %s.\n", member->id, argv[2]);

            /* tell them what happened */
            if (test_eflag(conference, EFLAG_TRANSFER) &&
                switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
                conference_add_event_member_data(member, event);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Old-Conference-Name", conference->name);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "New-Conference-Name", argv[3]);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "transfer");
                switch_event_fire(&event);
            }

            switch_thread_rwlock_unlock(member->rwlock);
        }
    } else {
        ret_status = SWITCH_STATUS_GENERR;
    }

    if (params) {
        switch_event_destroy(&params);
    }

    switch_safe_free(conf_name);

    return ret_status;
}

static switch_status_t conf_api_sub_check_record(conference_obj_t *conference, switch_stream_handle_t *stream, int arc, char **argv)
{
    conference_record_t *rec;
    int x = 0;

    switch_mutex_lock(conference->flag_mutex);
    for (rec = conference->rec_node_head; rec; rec = rec->next) {
        stream->write_function(stream, "Record file %s%s%s\n", rec->path, rec->autorec ? " " : "", rec->autorec ? "(Auto)" : "");
        x++;
    }

    if (!x) {
        stream->write_function(stream, "Conference is not being recorded.\n");
    }
    switch_mutex_unlock(conference->flag_mutex);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_record(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc <= 2) {
        return SWITCH_STATUS_GENERR;
    }

    if (conference->meeting_id) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "conf_api_sub_record conference:%s\n", conference->meeting_id);
    }

    stream->write_function(stream, "Record file %s\n", argv[2]);
    conference->record_filename = switch_core_strdup(conference->pool, argv[2]);
    conference->record_count++;
    launch_conference_record_thread(conference, argv[2], SWITCH_FALSE);
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_norecord(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    int all, before = conference->record_count, ttl = 0;
    switch_event_t *event;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc <= 2)
        return SWITCH_STATUS_GENERR;

    if (conference->meeting_id) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "conf_api_sub_norecord conference:%s\n", conference->meeting_id);
    }

    all = (strcasecmp(argv[2], "all") == 0);

    if (!conference_record_stop(conference, stream, all ? NULL : argv[2]) && !all) {
        stream->write_function(stream, "non-existant recording '%s'\n", argv[2]);
    } else {
        if (test_eflag(conference, EFLAG_RECORD) &&
                switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "stop-recording");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Path", all ? "all" : argv[2]);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Other-Recordings", conference->record_count ? "true" : "false");
            switch_event_fire(&event);
        }
    }

    ttl = before - conference->record_count;
    stream->write_function(stream, "Stopped recording %d file%s\n", ttl, ttl == 1 ? "" : "s");

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_pauserec(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_event_t *event;
    recording_action_type_t action;

    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc <= 2)
        return SWITCH_STATUS_GENERR;

    if (strcasecmp(argv[1], "pause") == 0) {
        action = REC_ACTION_PAUSE;
    } else if (strcasecmp(argv[1], "resume") == 0) {
        action = REC_ACTION_RESUME;
    } else {
        return SWITCH_STATUS_GENERR;
    }
    stream->write_function(stream, "%s recording file %s\n",
            action == REC_ACTION_PAUSE ? "Pause" : "Resume", argv[2]);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,    "%s recording file %s\n",
            action == REC_ACTION_PAUSE ? "Pause" : "Resume", argv[2]);

    if (!conference_record_action(conference, argv[2], action)) {
        stream->write_function(stream, "non-existant recording '%s'\n", argv[2]);
    } else {
        if (test_eflag(conference, EFLAG_RECORD) && switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS)
        {
            conference_add_event_data(conference, event);
            if (action == REC_ACTION_PAUSE) {
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "pause-recording");
            } else {
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "resume-recording");
            }
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Path", argv[2]);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Other-Recordings", conference->record_count ? "true" : "false");
            switch_event_fire(&event);
        }
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t conf_api_sub_recording(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if (argc > 2 && argc <= 3) {
        if (strcasecmp(argv[2], "stop") == 0 || strcasecmp(argv[2], "check") == 0) {
            argv[3] = "all";
            argc++;
        }
    }

    if (argc <= 3) {
        /* It means that old syntax is used */
        return conf_api_sub_record(conference,stream,argc,argv);
    } else {
        /* for new syntax call existing functions with fixed parameter list */
        if (strcasecmp(argv[2], "start") == 0) {
            argv[1] = argv[2];
            argv[2] = argv[3];
            return conf_api_sub_record(conference,stream,4,argv);
        } else if (strcasecmp(argv[2], "stop") == 0) {
            argv[1] = argv[2];
            argv[2] = argv[3];
            return conf_api_sub_norecord(conference,stream,4,argv);
        } else if (strcasecmp(argv[2], "check") == 0) {
            argv[1] = argv[2];
            argv[2] = argv[3];
            return conf_api_sub_check_record(conference,stream,4,argv);
        } else if (strcasecmp(argv[2], "pause") == 0) {
            argv[1] = argv[2];
            argv[2] = argv[3];
            return conf_api_sub_pauserec(conference,stream,4,argv);
        } else if (strcasecmp(argv[2], "resume") == 0) {
            argv[1] = argv[2];
            argv[2] = argv[3];
            return conf_api_sub_pauserec(conference,stream,4,argv);
        } else {
            return SWITCH_STATUS_GENERR;
        }
    }
}

static switch_status_t conf_api_sub_file_vol(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    if (argc >= 1) {
        conference_file_node_t *fnode;
        int vol = 0;
        int ok = 0;

        if (argc < 2) {
            stream->write_function(stream, "missing args\n");
            return SWITCH_STATUS_GENERR;
        }

        switch_mutex_lock(conference->mutex);

        fnode = conference->fnode;

        vol = atoi(argv[2]);

        if (argc > 3) {
            if (strcasecmp(argv[3], "async")) {
                fnode = conference->async_fnode;
            }
        }

        if (fnode && fnode->type == NODE_TYPE_FILE) {
            fnode->fh.vol = vol;
            ok = 1;
        }
        switch_mutex_unlock(conference->mutex);


        if (ok) {
            stream->write_function(stream, "volume changed\n");
            return SWITCH_STATUS_SUCCESS;
        } else {
            stream->write_function(stream, "File not playing\n");
            return SWITCH_STATUS_GENERR;
        }


    } else {
        stream->write_function(stream, "Invalid parameters:\n");
        return SWITCH_STATUS_GENERR;
    }
}

static switch_status_t conf_api_sub_pin(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    if ((argc == 4) && (!strcmp(argv[2], "mod"))) {
        conference->mpin = switch_core_strdup(conference->pool, argv[3]);
        stream->write_function(stream, "Moderator Pin for conference %s set: %s\n", argv[0], conference->mpin);
        return SWITCH_STATUS_SUCCESS;
    } else if ((argc == 3) && (!strcmp(argv[1], "pin"))) {
        conference->pin = switch_core_strdup(conference->pool, argv[2]);
        stream->write_function(stream, "Pin for conference %s set: %s\n", argv[0], conference->pin);
        return SWITCH_STATUS_SUCCESS;
    } else if (argc == 2 && (!strcmp(argv[1], "nopin"))) {
        conference->pin = NULL;
        stream->write_function(stream, "Pin for conference %s deleted\n", argv[0]);
        return SWITCH_STATUS_SUCCESS;
    } else {
        stream->write_function(stream, "Invalid parameters:\n");
        return SWITCH_STATUS_GENERR;
    }
}

static void write_debug_stats(conference_obj_t *conference, switch_stream_handle_t *stream)
{
    int i, j, k;

    switch_mutex_lock(conference->mutex);
    if (!switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) || !conference->debug_stats) {
        switch_mutex_unlock(conference->mutex);
        return;
    }

    stream->write_function(stream, "%s\n\n", "Member Details:");
    stream->write_function(stream, "%s\n", "ID    CallerID        higest_score         tossed_bytes            toss_count");
    for (i = 0; i < 32; i++) {
        if (conference->debug_stats->member_name[i][0] == '\0')
            continue;

        stream->write_function(stream, "%u      %s             %u            %u                %u\n",
                                                i, conference->debug_stats->member_name[i],
                                                conference->debug_stats->highest_score_iir[i],
                                                conference->debug_stats->audio_buffer_tossed_bytes[i],
                                                conference->debug_stats->audio_buffer_tossed_count[i]);
    }

    stream->write_function(stream, "\nLast %d secs bridge stats (Latest first):\n\n", NUM_SECS_DBG_STATS);

    i = conference->debug_stats->cur_index;
    k = 1;
    do {
        if (conference->debug_stats->active_talker_map[i] ||
                conference->debug_stats->audio_mux_map[i] ||
                    conference->debug_stats->audio_receiver_map[i] ||
                        conference->debug_stats->audio_substract_map[i]) {

            stream->write_function(stream, "Slot-%d:\n", k);
            stream->write_function(stream, "%s =",    "    Active-Talkers");
            for (j = 0; j < 32; ++j) {
                if ((conference->debug_stats->active_talker_map[i] & (1 << j)))
                    stream->write_function(stream, " %d", j);
            }
            stream->write_function(stream, "%s", "\n");

            stream->write_function(stream, "%s =",    "    Mixed Members");
            for (j = 0; j < 32; ++j) {
                if ((conference->debug_stats->audio_mux_map[i] & (1 << j)))
                    stream->write_function(stream, " %d", j);
            }
            stream->write_function(stream, "%s", "\n");

            stream->write_function(stream, "%s =",    "    Receiving Members");
            for (j = 0; j < 32; ++j) {
                if ((conference->debug_stats->audio_receiver_map[i] & (1 << j)))
                    stream->write_function(stream, " %d", j);
            }
            stream->write_function(stream, "%s", "\n");

            stream->write_function(stream, "%s =",    "    Substracted Members");
            for (j = 0; j < 32; ++j) {
                if ((conference->debug_stats->audio_substract_map[i] & (1 << j)))
                    stream->write_function(stream, " %d", j);
            }
            stream->write_function(stream, "%s", "\n");
        }

        i = (i == 0) ? NUM_SECS_DBG_STATS - 1 : i - 1;
        ++k;
    } while (i != conference->debug_stats->cur_index);


    switch_mutex_unlock(conference->mutex);
}

static switch_status_t conf_api_sub_get(conference_obj_t *conference,
        switch_stream_handle_t *stream, int argc, char **argv) {
    int ret_status = SWITCH_STATUS_GENERR;

    if (argc != 3) {
        ret_status = SWITCH_STATUS_FALSE;
    } else {
        ret_status = SWITCH_STATUS_SUCCESS;
        if (strcasecmp(argv[2], "run_time") == 0) {
            stream->write_function(stream, "%ld",
                    switch_epoch_time_now(NULL) - conference->run_time);
        } else if (strcasecmp(argv[2], "count") == 0) {
            stream->write_function(stream, "%d",
                    conference->count);
        } else if (strcasecmp(argv[2], "count_ghosts") == 0) {
            stream->write_function(stream, "%d",
                    conference->count_ghosts);
        } else if (strcasecmp(argv[2], "max_members") == 0) {
            stream->write_function(stream, "%d",
                    conference->max_members);
        } else if (strcasecmp(argv[2], "rate") == 0) {
            stream->write_function(stream, "%d",
                    conference->rate);
        } else if (strcasecmp(argv[2], "profile_name") == 0) {
            stream->write_function(stream, "%s",
                    conference->profile_name);
        } else if (strcasecmp(argv[2], "sound_prefix") == 0) {
            stream->write_function(stream, "%s",
                    conference->sound_prefix);
        } else if (strcasecmp(argv[2], "caller_id_name") == 0) {
            stream->write_function(stream, "%s",
                    conference->caller_id_name);
        } else if (strcasecmp(argv[2], "caller_id_number") == 0) {
            stream->write_function(stream, "%s",
                    conference->caller_id_number);
        } else if (strcasecmp(argv[2], "is_locked") == 0) {
            stream->write_function(stream, "%s",
                    switch_test_flag(conference, CFLAG_LOCKED) ? "locked" : "");
        } else if (strcasecmp(argv[2], "endconf_grace_time") == 0) {
            stream->write_function(stream, "%d",
                    conference->endconf_grace_time);
        } else if (strcasecmp(argv[2], "uuid") == 0) {
            stream->write_function(stream, "%s",
                    conference->uuid_str);
        } else if (strcasecmp(argv[2], "wait_mod") == 0) {
            stream->write_function(stream, "%s",
                    switch_test_flag(conference, CFLAG_WAIT_MOD) ? "true" : "");
        } else if (strcasecmp(argv[2], "disable_attendee_mute") == 0) {
            stream->write_function(stream, "%s",
                    switch_test_flag(conference, CFLAG_DISABLE_ATTENDEE_MUTE) ? "on" : "off");
        } else if (strcasecmp(argv[2], "enable_debug_stats") == 0) {
            stream->write_function(stream, "%s",
                    switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) ? "on" : "off");
        } else if (strcasecmp(argv[2], "debug_stats") == 0) {
            write_debug_stats(conference, stream);
        } else if (strcasecmp(argv[2], "operator_phone_number") == 0) {
            stream->write_function(stream, "%s",
                    conference->operator_phone_number ? conference->operator_phone_number : "<Not-Set>");
        } else if (strcasecmp(argv[2], "sip_trunk_ip_list") == 0) {
            stream->write_function(stream, "%s",
                    conference->sip_trunk_ip_list ? conference->sip_trunk_ip_list : "<Not-Set>");
        } else if (strcasecmp(argv[2], "moh_sound") == 0) {
            stream->write_function(stream, "%s",
                    conference->moh_sound ? conference->moh_sound : "<Not-Set>");
        } else {
            ret_status = SWITCH_STATUS_FALSE;
        }
    }

    return ret_status;
}

static switch_status_t conf_api_sub_set(conference_obj_t *conference,
        switch_stream_handle_t *stream, int argc, char **argv) {
    int ret_status = SWITCH_STATUS_GENERR;

    if (argc != 4 || zstr(argv[3])) {
        ret_status = SWITCH_STATUS_FALSE;
    } else {
        ret_status = SWITCH_STATUS_SUCCESS;
        if (strcasecmp(argv[2], "max_members") == 0) {
            int new_max = atoi(argv[3]);
            if (new_max >= 0) {
                stream->write_function(stream, "%d", conference->max_members);
                conference->max_members = new_max;
            } else {
                ret_status = SWITCH_STATUS_FALSE;
            }
        } else     if (strcasecmp(argv[2], "sound_prefix") == 0) {
            stream->write_function(stream, "%s",conference->sound_prefix);
            conference->sound_prefix = switch_core_strdup(conference->pool, argv[3]);
        } else     if (strcasecmp(argv[2], "caller_id_name") == 0) {
            stream->write_function(stream, "%s",conference->caller_id_name);
            conference->caller_id_name = switch_core_strdup(conference->pool, argv[3]);
        } else     if (strcasecmp(argv[2], "caller_id_number") == 0) {
            stream->write_function(stream, "%s",conference->caller_id_number);
            conference->caller_id_number = switch_core_strdup(conference->pool, argv[3]);
        } else if (strcasecmp(argv[2], "endconf_grace_time") == 0) {
                int new_gt = atoi(argv[3]);
                if (new_gt >= 0) {
                    stream->write_function(stream, "%d", conference->endconf_grace_time);
                    conference->endconf_grace_time = new_gt;
                } else {
                    ret_status = SWITCH_STATUS_FALSE;
                }
        } else if (strcasecmp(argv[2], "disable_attendee_mute") == 0) {
            stream->write_function(stream, "%s",
                    switch_test_flag(conference, CFLAG_DISABLE_ATTENDEE_MUTE) ? "on" : "off");

            if (strcasecmp(argv[3], "on") == 0) {
                set_conference_state_unlocked(conference, CFLAG_DISABLE_ATTENDEE_MUTE);
            } else {
                // if the conference is in mutes locked state do not allow enable attendee mute
                if(!switch_test_flag(conference,CFLAG_INDICATE_LOCK_MUTE)) {
                    clear_conference_state_unlocked(conference, CFLAG_DISABLE_ATTENDEE_MUTE);
                }
            }
        } else if (strcasecmp(argv[2], "enable_debug_stats") == 0) {
            stream->write_function(stream, "%s",
                    switch_test_flag(conference, CFLAG_DEBUG_STATS_ACTIVE) ? "on" : "off");

            if (strcasecmp(argv[3], "on") == 0) {
                set_conference_state_unlocked(conference, CFLAG_DEBUG_STATS_ACTIVE);
            } else {
                clear_conference_state_unlocked(conference, CFLAG_DEBUG_STATS_ACTIVE);
            }
        } else if (strcasecmp(argv[2], "operator_phone_number") == 0) {
            stream->write_function(stream, "%s",
                conference->operator_phone_number ? conference->operator_phone_number : "<Not-Set>"
            );
            conference->operator_phone_number = switch_core_strdup(conference->pool, argv[3]);
        } else if (strcasecmp(argv[2], "sip_trunk_ip_list") == 0) {
            stream->write_function(stream, "%s",
                conference->sip_trunk_ip_list ? conference->sip_trunk_ip_list : "<Not-Set>"
            );
            conference->sip_trunk_ip_list = switch_core_strdup(conference->pool, argv[3]);
        } else if (strcasecmp(argv[2], "moh_sound") == 0) {
            stream->write_function(stream, "%s",
                conference->moh_sound ? conference->moh_sound : "<Not-Set>"
            );
            if (strcasecmp(argv[3], "false") == 0) {
                conference->moh_sound = NULL;
            }
        } else if (strcasecmp(argv[2], "audio_started") == 0) {
          if (strcasecmp(argv[3], "on") == 0) {
            clear_conference_state_unlocked(conference, CFLAG_WAIT_MOD);
            stream->write_function(stream, "%s", switch_test_flag(conference, CFLAG_WAIT_MOD) ? "on" : "off");
          }
        }
        else {
            ret_status = SWITCH_STATUS_FALSE;
        }
    }

    return ret_status;
}

static switch_status_t conf_api_sub_call_operator(conference_obj_t *conference,
                                                  switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_status_t status = call_operator(conference);
    if (status == SWITCH_STATUS_SUCCESS) {
        stream->write_function(stream, "Call-Operator successful");
    } else {
        stream->write_function(stream, "Call-Operator failed");
    }
    return status;
}

typedef enum {
    CONF_API_COMMAND_LIST = 0,
    CONF_API_COMMAND_ENERGY,
    CONF_API_COMMAND_VOLUME_IN,
    CONF_API_COMMAND_VOLUME_OUT,
    CONF_API_COMMAND_PLAY,
    CONF_API_COMMAND_SAY,
    CONF_API_COMMAND_SAYMEMBER,
    CONF_API_COMMAND_STOP,
    CONF_API_COMMAND_DTMF,
    CONF_API_COMMAND_KICK,
    CONF_API_COMMAND_MUTE,
    CONF_API_COMMAND_UNMUTE,
    CONF_API_COMMAND_DEAF,
    CONF_API_COMMAND_UNDEAF,
    CONF_API_COMMAND_RELATE,
    CONF_API_COMMAND_LOCK,
    CONF_API_COMMAND_UNLOCK,
    CONF_API_COMMAND_DIAL,
    CONF_API_COMMAND_BGDIAL,
    CONF_API_COMMAND_TRANSFER,
    CONF_API_COMMAND_RECORD,
    CONF_API_COMMAND_NORECORD,
    CONF_API_COMMAND_EXIT_SOUND,
    CONF_API_COMMAND_ENTER_SOUND,
    CONF_API_COMMAND_PIN,
    CONF_API_COMMAND_NOPIN,
    CONF_API_COMMAND_GET,
    CONF_API_COMMAND_SET,
} api_command_type_t;

/* API Interface Function sub-commands */
/* Entries in this list should be kept in sync with the enum above */
static api_command_t conf_api_sub_commands[] = {
    {"list", (void_fn_t) & conf_api_sub_list, CONF_API_SUB_ARGS_SPLIT, "list", "[delim <string>]|[count]"},
    {"xml_list", (void_fn_t) & conf_api_sub_xml_list, CONF_API_SUB_ARGS_SPLIT, "xml_list", ""},
    {"energy", (void_fn_t) & conf_api_sub_energy, CONF_API_SUB_MEMBER_TARGET, "energy", "<member_id|all|last|non_moderator> [<newval>]"},
    {"volume_in", (void_fn_t) & conf_api_sub_volume_in, CONF_API_SUB_MEMBER_TARGET, "volume_in", "<member_id|all|last|non_moderator> [<newval>]"},
    {"volume_out", (void_fn_t) & conf_api_sub_volume_out, CONF_API_SUB_MEMBER_TARGET, "volume_out", "<member_id|all|last|non_moderator> [<newval>]"},
    {"play", (void_fn_t) & conf_api_sub_play, CONF_API_SUB_ARGS_SPLIT, "play", "<file_path> [async|<member_id>]"},
    {"pause_play", (void_fn_t) & conf_api_sub_pause_play, CONF_API_SUB_ARGS_SPLIT, "pause", ""},
    {"file_seek", (void_fn_t) & conf_api_sub_file_seek, CONF_API_SUB_ARGS_SPLIT, "file_seek", "[+-]<val>"},
    {"say", (void_fn_t) & conf_api_sub_say, CONF_API_SUB_ARGS_AS_ONE, "say", "<text>"},
    {"saymember", (void_fn_t) & conf_api_sub_saymember, CONF_API_SUB_ARGS_AS_ONE, "saymember", "<member_id> <text>"},
    {"stop", (void_fn_t) & conf_api_sub_stop, CONF_API_SUB_ARGS_SPLIT, "stop", "<[current|all|async|last]> [<member_id>]"},
    {"dtmf", (void_fn_t) & conf_api_sub_dtmf, CONF_API_SUB_MEMBER_TARGET, "dtmf", "<[member_id|all|last|non_moderator]> <digits>"},
    {"kick", (void_fn_t) & conf_api_sub_kick, CONF_API_SUB_MEMBER_TARGET, "kick", "<[member_id|all|last|non_moderator]> [<optional sound file>]"},
    {"hup", (void_fn_t) & conf_api_sub_hup, CONF_API_SUB_MEMBER_TARGET, "hup", "<[member_id|all|last|non_moderator]>"},
    {"mute", (void_fn_t) & conf_api_mute, CONF_API_SUB_MEMBER_TARGET, "mute", "<[member_id|all]|last|non_moderator>"},
    {"tmute", (void_fn_t) & conf_api_sub_tmute, CONF_API_SUB_MEMBER_TARGET, "tmute", "<[member_id|all]|last|non_moderator>"},
    {"unmute", (void_fn_t) & conf_api_unmute, CONF_API_SUB_MEMBER_TARGET, "unmute", "<[member_id|all]|last|non_moderator>"},
    {"deaf", (void_fn_t) & conf_api_sub_deaf, CONF_API_SUB_MEMBER_TARGET, "deaf", "<[member_id|all]|last|non_moderator>"},
    {"undeaf", (void_fn_t) & conf_api_sub_undeaf, CONF_API_SUB_MEMBER_TARGET, "undeaf", "<[member_id|all]|last|non_moderator>"},
    {"relate", (void_fn_t) & conf_api_sub_relate, CONF_API_SUB_ARGS_SPLIT, "relate", "<member_id> <other_member_id> [nospeak|nohear|clear]"},
    {"lock", (void_fn_t) & conf_api_sub_lock, CONF_API_SUB_ARGS_SPLIT, "lock", ""},
    {"unlock", (void_fn_t) & conf_api_sub_unlock, CONF_API_SUB_ARGS_SPLIT, "unlock", ""},
    {"agc", (void_fn_t) & conf_api_sub_agc, CONF_API_SUB_ARGS_SPLIT, "agc", ""},
    {"dial", (void_fn_t) & conf_api_sub_dial, CONF_API_SUB_ARGS_SPLIT, "dial", "<endpoint_module_name>/<destination> <callerid number> <callerid name>"},
    {"bgdial", (void_fn_t) & conf_api_sub_bgdial, CONF_API_SUB_ARGS_SPLIT, "bgdial", "<endpoint_module_name>/<destination> <callerid number> <callerid name>"},
    {"transfer", (void_fn_t) & conf_api_sub_transfer, CONF_API_SUB_ARGS_SPLIT, "transfer", "<conference_name> <member id> [...<member id>]"},
    {"record", (void_fn_t) & conf_api_sub_record, CONF_API_SUB_ARGS_SPLIT, "record", "<filename>"},
    {"chkrecord", (void_fn_t) & conf_api_sub_check_record, CONF_API_SUB_ARGS_SPLIT, "chkrecord", "<confname>"},
    {"norecord", (void_fn_t) & conf_api_sub_norecord, CONF_API_SUB_ARGS_SPLIT, "norecord", "<[filename|all]>"},
    {"pause", (void_fn_t) & conf_api_sub_pauserec, CONF_API_SUB_ARGS_SPLIT, "pause", "<filename>"},
    {"resume", (void_fn_t) & conf_api_sub_pauserec, CONF_API_SUB_ARGS_SPLIT, "resume", "<filename>"},
    {"recording", (void_fn_t) & conf_api_sub_recording, CONF_API_SUB_ARGS_SPLIT, "recording", "[start|stop|check|pause|resume] [<filename>|all]"},
    {"exit_sound", (void_fn_t) & conf_api_sub_exit_sound, CONF_API_SUB_ARGS_SPLIT, "exit_sound", "on|off|none|file <filename>"},
    {"enter_sound", (void_fn_t) & conf_api_sub_enter_sound, CONF_API_SUB_ARGS_SPLIT, "enter_sound", "on|off|none|file <filename>"},
    {"pin", (void_fn_t) & conf_api_sub_pin, CONF_API_SUB_ARGS_SPLIT, "pin", "<pin#>"},
    {"nopin", (void_fn_t) & conf_api_sub_pin, CONF_API_SUB_ARGS_SPLIT, "nopin", ""},
    {"get", (void_fn_t) & conf_api_sub_get, CONF_API_SUB_ARGS_SPLIT, "get", "<parameter-name>"},
    {"set", (void_fn_t) & conf_api_sub_set, CONF_API_SUB_ARGS_SPLIT, "set", "<max_members|sound_prefix|caller_id_name|caller_id_number|endconf_grace_time|disable_attendee_mute|enable_debug_stats|operator_phone_number|sip_trunk_ip_list|audio_started|moh_sound> <value>"},
    {"file-vol", (void_fn_t) & conf_api_sub_file_vol, CONF_API_SUB_ARGS_SPLIT, "file-vol", "<vol#>"},
    {"floor", (void_fn_t) & conf_api_sub_floor, CONF_API_SUB_MEMBER_TARGET, "floor", "<member_id|last>"},
    {"enforce_floor", (void_fn_t) & conf_api_sub_enforce_floor, CONF_API_SUB_MEMBER_TARGET, "enforce_floor", "<member_id|last>"},
    {"call_operator", (void_fn_t) & conf_api_sub_call_operator, CONF_API_SUB_ARGS_SPLIT, "call_operator", ""},
    {"unlock_n_unmute", (void_fn_t) & conf_api_unlock_and_unmute, CONF_API_SUB_MEMBER_TARGET, "unlock_n_unmute", "<[member_id]>"},
    {"mute_lockable", (void_fn_t) & conf_api_sub_mutelockable, CONF_API_SUB_MEMBER_TARGET, "mute_lockable", "<[member_id]> [<newval>]"},
    {"vid-floor", (void_fn_t) & conf_api_sub_vid_floor, CONF_API_SUB_MEMBER_TARGET, "vid-floor", "<member_id|last> [force]"},
    {"clear-vid-floor", (void_fn_t) & conf_api_sub_clear_vid_floor, CONF_API_SUB_ARGS_AS_ONE, "clear-vid-floor", ""}
};

#define CONFFUNCAPISIZE (sizeof(conf_api_sub_commands)/sizeof(conf_api_sub_commands[0]))

switch_status_t conf_api_dispatch(conference_obj_t *conference, switch_stream_handle_t *stream, int argc, char **argv, const char *cmdline, int argn)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    uint32_t i, found = 0;
    switch_assert(conference != NULL);
    switch_assert(stream != NULL);

    /* loop through the command table to find a match */
    for (i = 0; i < CONFFUNCAPISIZE && !found; i++) {
        if (strcasecmp(argv[argn], conf_api_sub_commands[i].pname) == 0) {
            found = 1;
            switch (conf_api_sub_commands[i].fntype) {

                /* commands that we've broken the command line into arguments for */
            case CONF_API_SUB_ARGS_SPLIT:
                {
                    conf_api_args_cmd_t pfn = (conf_api_args_cmd_t) conf_api_sub_commands[i].pfnapicmd;

                    if (pfn(conference, stream, argc, argv) != SWITCH_STATUS_SUCCESS) {
                        /* command returned error, so show syntax usage */
                        stream->write_function(stream, "%s %s", conf_api_sub_commands[i].pcommand, conf_api_sub_commands[i].psyntax);
                    }
                }
                break;

                /* member specific command that can be iterated */
            case CONF_API_SUB_MEMBER_TARGET:
                {
                    uint32_t id = 0;
                    uint8_t all = 0;
                    uint8_t last = 0;
                    uint8_t non_mod = 0;
                    uint8_t lock = 0;

                    if (argv[argn + 1]) {
                        if (!(id = atoi(argv[argn + 1]))) {
                            all = strcasecmp(argv[argn + 1], "all") ? 0 : 1;
                            non_mod = strcasecmp(argv[argn + 1], "non_moderator") ? 0 : 1;
                            last = strcasecmp(argv[argn + 1], "last") ? 0 : 1;
                        }
                    }
                    if (non_mod) {
                        /* check for lock command passed */
                        if (argv[argn + 2]) {
                            lock = strcasecmp(argv[argn + 2], "lock") ? 0 : 1;
                        }

                        if (strcasecmp(conf_api_sub_commands[i].pname, "mute") == 0) {
                            if(lock) {
                                conf_api_mute_lock_all(conference, stream, argv[argn + 3]);
                                continue;
                            }

                            conf_api_mute_non_moderator(conference, stream, argv[argn + 2]);
                        } else if (strcasecmp(conf_api_sub_commands[i].pname, "unmute") == 0) {
                            if(lock) {
                                conf_api_unmute_lock_all(conference, stream, argv[argn + 4]);
                                continue;
                            }

                            conf_api_unmute_non_moderator(conference, stream, argv[argn + 2]);
                        } else {
                            conference_member_itterator(conference, stream, non_mod, (conf_api_member_cmd_t) conf_api_sub_commands[i].pfnapicmd, argv[argn + 2]);
                        }
                    } else if (all) {
                        if (strcasecmp(conf_api_sub_commands[i].pname, "mute") == 0) {
                            conf_api_mute_all(conference, stream, argv[argn + 2]);
                        } else if (strcasecmp(conf_api_sub_commands[i].pname, "unmute") == 0) {
                            conf_api_unmute_all(conference, stream, argv[argn + 2]);
                        } else {
                            conference_member_itterator(conference, stream, non_mod, (conf_api_member_cmd_t) conf_api_sub_commands[i].pfnapicmd, argv[argn + 2]);
                        }
                    } else if (last) {
                        conference_member_t *member = NULL;
                        conference_member_t *last_member = NULL;

                        switch_mutex_lock(conference->member_mutex);

                        /* find last (oldest) member */
                        for (int i = 0; i < eMemberListTypes_Recorders; i++) {
                            member = conference->member_lists[i];
                            while (member != NULL) {
                                if (last_member == NULL || member->id > last_member->id) {
                                    last_member = member;
                                }
                                member = member->next;
                            }
                        }

                        /* exec functio on last (oldest) member */
                        if (last_member != NULL && last_member->session && !switch_test_flag(last_member, MFLAG_NOCHANNEL)) {
                            conf_api_member_cmd_t pfn = (conf_api_member_cmd_t) conf_api_sub_commands[i].pfnapicmd;
                            pfn(last_member, stream, argv[argn + 2]);
                        }

                        switch_mutex_unlock(conference->member_mutex);
                    } else if (id) {
                        conf_api_member_cmd_t pfn = (conf_api_member_cmd_t) conf_api_sub_commands[i].pfnapicmd;
                        conference_member_t *member = conference_member_get(conference, id);
                        /* check for lock command passed */
                        if (argv[argn + 2]) {
                            lock = strcasecmp(argv[argn + 2], "lock") ? 0 : 1;
                        }
                        if (member != NULL) {
                            if(lock && (strcasecmp(conf_api_sub_commands[i].pname, "mute") == 0)) {
                                pfn(member, stream, argv[argn + 2]);
                                /* apply mute lock only if the conference is in mute lock state */
                                if(switch_test_flag(conference, CFLAG_INDICATE_LOCK_MUTE)) {
                                  conf_api_sub_lock_mute(member, stream, argv[argn + 3]);
                                }
                            } else if (lock && (strcasecmp(conf_api_sub_commands[i].pname, "unmute") == 0)) {
                                conf_api_sub_unlock_mute(member, stream, argv[argn + 3]);
                            } else {
                                pfn(member, stream, argv[argn + 2]);
                            }
                            switch_thread_rwlock_unlock(member->rwlock);
                        } else {
                            stream->write_function(stream, "Non-Existant ID %u\n", id);
                        }
                    } else {
                        stream->write_function(stream, "%s %s", conf_api_sub_commands[i].pcommand, conf_api_sub_commands[i].psyntax);
                    }
                }
                break;

                /* commands that deals with all text after command */
            case CONF_API_SUB_ARGS_AS_ONE:
                {
                    conf_api_text_cmd_t pfn = (conf_api_text_cmd_t) conf_api_sub_commands[i].pfnapicmd;
                    char *start_text;
                    const char *modified_cmdline = cmdline;
                    const char *cmd = conf_api_sub_commands[i].pname;

                    if (!zstr(modified_cmdline) && (start_text = strstr(modified_cmdline, cmd))) {
                        modified_cmdline = start_text + strlen(cmd);
                        while (modified_cmdline && (*modified_cmdline == ' ' || *modified_cmdline == '\t')) {
                            modified_cmdline++;
                        }
                    }

                    /* call the command handler */
                    if (pfn(conference, stream, modified_cmdline) != SWITCH_STATUS_SUCCESS) {
                        /* command returned error, so show syntax usage */
                        stream->write_function(stream, "%s %s", conf_api_sub_commands[i].pcommand, conf_api_sub_commands[i].psyntax);
                    }
                }
                break;
            }
        }
    }

    if (!found) {
        stream->write_function(stream, "Conference command '%s' not found.\n", argv[argn]);
    } else {
        status = SWITCH_STATUS_SUCCESS;
    }

    return status;
}

/* API Interface Function */
SWITCH_STANDARD_API(conf_api_main)
{
    char *lbuf = NULL;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char *http = NULL, *type = NULL;
    int argc;
    char *argv[25] = { 0 };

    if (!cmd) {
        cmd = "help";
    }

    if (stream->param_event) {
        http = switch_event_get_header(stream->param_event, "http-host");
        type = switch_event_get_header(stream->param_event, "content-type");
    }

    if (http) {
        /* Output must be to a web browser */
        if (type && !strcasecmp(type, "text/html")) {
            stream->write_function(stream, "<pre>\n");
        }
    }

    if (!(lbuf = strdup(cmd))) {
        return status;
    }

    argc = switch_separate_string(lbuf, ' ', argv, (sizeof(argv) / sizeof(argv[0])));

    /* try to find a command to execute */
    if (argc && argv[0]) {
        conference_obj_t *conference = NULL;

        if ((conference = conference_find(argv[0], NULL))) {
            if (argc >= 2) {
                conf_api_dispatch(conference, stream, argc, argv, cmd, 1);
            } else {
                stream->write_function(stream, "Conference command, not specified.\nTry 'help'\n");
            }
            switch_thread_rwlock_unlock(conference->rwlock);

        } else if (argv[0]) {
            /* special case the list command, because it doesn't require a conference argument */
            if (strcasecmp(argv[0], "list") == 0) {
                conf_api_sub_list(NULL, stream, argc, argv);
            } else if (strcasecmp(argv[0], "xml_list") == 0) {
                conf_api_sub_xml_list(NULL, stream, argc, argv);
            } else if (strcasecmp(argv[0], "help") == 0 || strcasecmp(argv[0], "commands") == 0) {
                stream->write_function(stream, "%s\n", api_syntax);
            } else if (argv[1] && strcasecmp(argv[1], "dial") == 0) {
                if (conf_api_sub_dial(NULL, stream, argc, argv) != SWITCH_STATUS_SUCCESS) {
                    /* command returned error, so show syntax usage */
                    stream->write_function(stream, "%s %s", conf_api_sub_commands[CONF_API_COMMAND_DIAL].pcommand,
                                           conf_api_sub_commands[CONF_API_COMMAND_DIAL].psyntax);
                }
            } else if (argv[1] && strcasecmp(argv[1], "bgdial") == 0) {
                if (conf_api_sub_bgdial(NULL, stream, argc, argv) != SWITCH_STATUS_SUCCESS) {
                    /* command returned error, so show syntax usage */
                    stream->write_function(stream, "%s %s", conf_api_sub_commands[CONF_API_COMMAND_BGDIAL].pcommand,
                                           conf_api_sub_commands[CONF_API_COMMAND_BGDIAL].psyntax);
                }
            } else {
                stream->write_function(stream, "Conference %s not found\n", argv[0]);
            }
        }

    } else {
        int i;

        for (i = 0; i < CONFFUNCAPISIZE; i++) {
            stream->write_function(stream, "<conf name> %s %s\n", conf_api_sub_commands[i].pcommand, conf_api_sub_commands[i].psyntax);
        }
    }


    switch_safe_free(lbuf);

    return status;
}

/* generate an outbound call from the conference */
static switch_status_t conference_outcall(conference_obj_t *conference,
                                          char *conference_name,
                                          switch_core_session_t *session,
                                          char *bridgeto, uint32_t timeout,
                                          char *flags, char *cid_name,
                                          char *cid_num,
                                          char *profile,
                                          switch_call_cause_t *cause,
                                          switch_call_cause_t *cancel_cause, switch_event_t *var_event)
{
    switch_core_session_t *peer_session = NULL;
    switch_channel_t *peer_channel;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_channel_t *caller_channel = NULL;
    char appdata[512];
    int rdlock = 0;
    switch_bool_t have_flags = SWITCH_FALSE;
    const char *outcall_flags;
    int track = 0;
    const char *call_id = NULL;

    if (var_event && switch_true(switch_event_get_header(var_event, "conference_track_status"))) {
        track++;
        call_id = switch_event_get_header(var_event, "conference_track_call_id");
    }

    *cause = SWITCH_CAUSE_NORMAL_CLEARING;

    if (conference == NULL) {
        char *dialstr = switch_mprintf("{ignore_early_media=true}%s", bridgeto);
        status = switch_ivr_originate(NULL, &peer_session, cause, dialstr, 60, NULL, cid_name, cid_num, NULL, var_event, SOF_NO_LIMITS, NULL);
        switch_safe_free(dialstr);

        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }

        peer_channel = switch_core_session_get_channel(peer_session);
        rdlock = 1;
        goto callup;
    }

    conference_name = conference->name;

    if (switch_thread_rwlock_tryrdlock(conference->rwlock) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Read Lock Fail\n");
        return SWITCH_STATUS_FALSE;
    }

    if (session != NULL) {
        caller_channel = switch_core_session_get_channel(session);
    }

    if (zstr(cid_name)) {
        cid_name = conference->caller_id_name;
    }

    if (zstr(cid_num)) {
        cid_num = conference->caller_id_number;
    }

    /* establish an outbound call leg */

    switch_mutex_lock(conference->mutex);
    conference->originating++;
    switch_mutex_unlock(conference->mutex);

    if (track) {
        send_conference_notify(conference, "SIP/2.0 100 Trying\r\n", call_id, SWITCH_FALSE);
    }


    status = switch_ivr_originate(session, &peer_session, cause, bridgeto, timeout, NULL, cid_name, cid_num, NULL, var_event, SOF_NO_LIMITS, cancel_cause);
    switch_mutex_lock(conference->mutex);
    conference->originating--;
    switch_mutex_unlock(conference->mutex);

    if (status != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Cannot create outgoing channel, cause: %s\n",
                          switch_channel_cause2str(*cause));
        if (caller_channel) {
            switch_channel_hangup(caller_channel, *cause);
        }

        if (track) {
            send_conference_notify(conference, "SIP/2.0 481 Failure\r\n", call_id, SWITCH_TRUE);
        }

        goto done;
    }

    if (track) {
        send_conference_notify(conference, "SIP/2.0 200 OK\r\n", call_id, SWITCH_TRUE);
    }

    rdlock = 1;
    peer_channel = switch_core_session_get_channel(peer_session);

    /* make sure the conference still exists */
    if (!switch_test_flag(conference, CFLAG_RUNNING)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Conference is gone now, nevermind..\n");
        if (caller_channel) {
            switch_channel_hangup(caller_channel, SWITCH_CAUSE_NO_ROUTE_DESTINATION);
        }
        switch_channel_hangup(peer_channel, SWITCH_CAUSE_NO_ROUTE_DESTINATION);
        goto done;
    }

    if (caller_channel && switch_channel_test_flag(peer_channel, CF_ANSWERED)) {
        switch_channel_answer(caller_channel);
    }

  callup:

    /* if the outbound call leg is ready */
    if (switch_channel_test_flag(peer_channel, CF_ANSWERED) || switch_channel_test_flag(peer_channel, CF_EARLY_MEDIA)) {
        switch_caller_extension_t *extension = NULL;

        /* build an extension name object */
        if ((extension = switch_caller_extension_new(peer_session, conference_name, conference_name)) == 0) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Memory Error!\n");
            status = SWITCH_STATUS_MEMERR;
            goto done;
        }

        if ((outcall_flags = switch_channel_get_variable(peer_channel, "outcall_flags"))) {
            if (!zstr(outcall_flags)) {
                flags = (char *)outcall_flags;
            }
        }

        if (flags && strcasecmp(flags, "none")) {
            have_flags = SWITCH_TRUE;
        }
        /* add them to the conference */

        switch_snprintf(appdata, sizeof(appdata), "%s%s%s%s%s%s", conference_name,
                profile?"@":"", profile?profile:"",
                have_flags?"+flags{":"", have_flags?flags:"", have_flags?"}":"");
        switch_caller_extension_add_application(peer_session, extension, (char *) global_app_name, appdata);

        switch_channel_set_caller_extension(peer_channel, extension);
        switch_channel_set_state(peer_channel, CS_EXECUTE);

    } else {
        switch_channel_hangup(peer_channel, SWITCH_CAUSE_NO_ANSWER);
        status = SWITCH_STATUS_FALSE;
        goto done;
    }

  done:
    if (conference) {
        switch_thread_rwlock_unlock(conference->rwlock);
    }
    if (rdlock && peer_session) {
        switch_core_session_rwunlock(peer_session);
    }

    return status;
}

struct bg_call {
    conference_obj_t *conference;
    switch_core_session_t *session;
    char *bridgeto;
    uint32_t timeout;
    char *flags;
    char *cid_name;
    char *cid_num;
    char *conference_name;
    char *uuid;
    char *profile;
    switch_call_cause_t *cancel_cause;
    switch_event_t *var_event;
    switch_memory_pool_t *pool;
};

static void *SWITCH_THREAD_FUNC conference_outcall_run(switch_thread_t *thread, void *obj)
{
    struct bg_call *call = (struct bg_call *) obj;

    if (call) {
        switch_call_cause_t cause;
        switch_event_t *event;


        conference_outcall(call->conference, call->conference_name,
                           call->session, call->bridgeto, call->timeout,
                           call->flags, call->cid_name, call->cid_num, call->profile, &cause, call->cancel_cause, call->var_event);

        if (call->conference && test_eflag(call->conference, EFLAG_BGDIAL_RESULT) &&
            switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT) == SWITCH_STATUS_SUCCESS) {
            conference_add_event_data(call->conference, event);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "bgdial-result");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Result", switch_channel_cause2str(cause));
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Job-UUID", call->uuid);
            switch_event_fire(&event);
        }

        if (call->var_event) {
            switch_event_destroy(&call->var_event);
        }

        switch_safe_free(call->bridgeto);
        switch_safe_free(call->flags);
        switch_safe_free(call->cid_name);
        switch_safe_free(call->cid_num);
        switch_safe_free(call->conference_name);
        switch_safe_free(call->uuid);
        switch_safe_free(call->profile);
        if (call->pool) {
            switch_core_destroy_memory_pool(&call->pool);
        }
        switch_safe_free(call);
    }

    return NULL;
}

static switch_status_t conference_outcall_bg(conference_obj_t *conference,
                                             char *conference_name,
                                             switch_core_session_t *session, char *bridgeto, uint32_t timeout, const char *flags, const char *cid_name,
                                             const char *cid_num, const char *call_uuid, const char *profile, switch_call_cause_t *cancel_cause, switch_event_t **var_event)
{
    struct bg_call *call = NULL;
    switch_thread_t *thread;
    switch_threadattr_t *thd_attr = NULL;
    switch_memory_pool_t *pool = NULL;

    if (!(call = malloc(sizeof(*call))))
        return SWITCH_STATUS_MEMERR;

    memset(call, 0, sizeof(*call));
    call->conference = conference;
    call->session = session;
    call->timeout = timeout;
    call->cancel_cause = cancel_cause;

    if (var_event) {
        call->var_event = *var_event;
        var_event = NULL;
    }

    if (conference) {
        pool = conference->pool;
    } else {
        switch_core_new_memory_pool(&pool);
        call->pool = pool;
    }

    if (bridgeto) {
        call->bridgeto = strdup(bridgeto);
    }
    if (flags) {
        call->flags = strdup(flags);
    }
    if (cid_name) {
        call->cid_name = strdup(cid_name);
    }
    if (cid_num) {
        call->cid_num = strdup(cid_num);
    }

    if (conference_name) {
        call->conference_name = strdup(conference_name);
    }

    if (call_uuid) {
        call->uuid = strdup(call_uuid);
    }

        if (profile) {
                call->profile = strdup(profile);
        }

    switch_threadattr_create(&thd_attr, pool);
    switch_threadattr_detach_set(thd_attr, 1);
    switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
    switch_thread_create(&thread, thd_attr, conference_outcall_run, call, pool);
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Launching BG Thread for outcall\n");

    return SWITCH_STATUS_SUCCESS;
}

/* Play a file */
static switch_status_t conference_local_play_file(conference_obj_t *conference, switch_core_session_t *session, char *path, uint32_t leadin, void *buf,
                                                  uint32_t buflen)
{
    uint32_t x = 0;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_channel_t *channel;
    char *expanded = NULL;
    switch_input_args_t args = { 0 }, *ap = NULL;

    if (buf) {
        args.buf = buf;
        args.buflen = buflen;
        ap = &args;
    }

    /* generate some space infront of the file to be played */
    for (x = 0; x < leadin; x++) {
        switch_frame_t *read_frame;
        status = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);

        if (!SWITCH_READ_ACCEPTABLE(status)) {
            break;
        }
    }

    /* if all is well, really play the file */
    if (status == SWITCH_STATUS_SUCCESS) {
        char *dpath = NULL;

        channel = switch_core_session_get_channel(session);
        if ((expanded = switch_channel_expand_variables(channel, path)) != path) {
            path = expanded;
        } else {
            expanded = NULL;
        }

        if (!strncasecmp(path, "say:", 4)) {
            if (!(conference->tts_engine && conference->tts_voice)) {
                status = SWITCH_STATUS_FALSE;
            } else {
                status = switch_ivr_speak_text(session, conference->tts_engine, conference->tts_voice, path + 4, ap);
            }
            goto done;
        }

        if (!switch_is_file_path(path) && conference->sound_prefix) {
            if (!(dpath = switch_mprintf("%s%s%s", conference->sound_prefix, SWITCH_PATH_SEPARATOR, path))) {
                status = SWITCH_STATUS_MEMERR;
                goto done;
            }
            path = dpath;
        }

        status = switch_ivr_play_file(session, NULL, path, ap);
        switch_safe_free(dpath);
    }

  done:
    switch_safe_free(expanded);

    return status;
}

static void set_mflags(const char *flags, member_flag_t *f)
{
    if (flags) {
        char *dup = strdup(flags);
        char *p;
        char *argv[10] = { 0 };
        int i, argc = 0;

        for (p = dup; p && *p; p++) {
            if (*p == ',') {
                *p = '|';
            }
        }

        argc = switch_separate_string(dup, '|', argv, (sizeof(argv) / sizeof(argv[0])));

        for (i = 0; i < argc && argv[i]; i++) {
            if (!strcasecmp(argv[i], "mute")) {
                *f &= ~MFLAG_CAN_SPEAK;
                *f &= ~MFLAG_TALKING;
            } else if (!strcasecmp(argv[i], "deaf")) {
                *f &= ~MFLAG_CAN_HEAR;
            } else if (!strcasecmp(argv[i], "mute-detect")) {
                *f |= MFLAG_MUTE_DETECT;
            } else if (!strcasecmp(argv[i], "dist-dtmf")) {
                *f |= MFLAG_DIST_DTMF;
            } else if (!strcasecmp(argv[i], "moderator")) {
                *f |= MFLAG_MOD;
            } else if (!strcasecmp(argv[i], "nomoh")) {
                *f |= MFLAG_NOMOH;
            } else if (!strcasecmp(argv[i], "endconf")) {
                *f |= MFLAG_ENDCONF;
            } else if (!strcasecmp(argv[i], "mintwo")) {
                *f |= MFLAG_MINTWO;
            /* MFLAG_VIDEO_BRIDGE has been removed
            } else if (!strcasecmp(argv[i], "video-bridge")) {
                *f |= MFLAG_VIDEO_BRIDGE; */
            } else if (!strcasecmp(argv[i], "mute_lockable")) {
                *f |= MFLAG_MUTELOCKABLE;
            } else if (!strcasecmp(argv[i], "ghost")) {
                *f |= MFLAG_GHOST;
            } else if (!strcasecmp(argv[i], "join-only")) {
                *f |= MFLAG_JOIN_ONLY;
            } else if (!strcasecmp(argv[i], "fake_mute")) {
                *f |= MFLAG_USE_FAKE_MUTE;
            }
        }

        free(dup);
    }
}



static void set_cflags(const char *flags, uint32_t *f)
{
    if (flags) {
        char *dup = strdup(flags);
        char *p;
        char *argv[10] = { 0 };
        int i, argc = 0;

        for (p = dup; p && *p; p++) {
            if (*p == ',') {
                *p = '|';
            }
        }

        argc = switch_separate_string(dup, '|', argv, (sizeof(argv) / sizeof(argv[0])));

        for (i = 0; i < argc && argv[i]; i++) {
            if (!strcasecmp(argv[i], "wait-mod")) {
                *f |= CFLAG_WAIT_MOD;
            } else if (!strcasecmp(argv[i], "video-floor-only")) {
                *f |= CFLAG_VID_FLOOR;
            } else if (!strcasecmp(argv[i], "video-bridge")) {
                *f |= CFLAG_VIDEO_BRIDGE;
            } else if (!strcasecmp(argv[i], "audio-always")) {
                *f |= CFLAG_AUDIO_ALWAYS;
            } else if (!strcasecmp(argv[i], "restart-auto-record")) {
                *f |= CFLAG_CONF_RESTART_AUTO_RECORD;
            } else if (!strcasecmp(argv[i], "json-events")) {
                *f |= CFLAG_JSON_EVENTS;
            } else if (!strcasecmp(argv[i], "livearray-sync")) {
                *f |= CFLAG_LIVEARRAY_SYNC;
            } else if (!strcasecmp(argv[i], "rfc-4579")) {
                *f |= CFLAG_RFC4579;
            }


        }

        free(dup);
    }
}


static void clear_eflags(char *events, uint32_t *f)
{
    char buf[512] = "";
    char *next = NULL;
    char *event = buf;

    if (events) {
        switch_copy_string(buf, events, sizeof(buf));

        while (event) {
            next = strchr(event, ',');
            if (next) {
                *next++ = '\0';
            }

            if (!strcmp(event, "add-member")) {
                *f &= ~EFLAG_ADD_MEMBER;
            } else if (!strcmp(event, "del-member")) {
                *f &= ~EFLAG_DEL_MEMBER;
            } else if (!strcmp(event, "energy-level")) {
                *f &= ~EFLAG_ENERGY_LEVEL;
            } else if (!strcmp(event, "volume-level")) {
                *f &= ~EFLAG_VOLUME_LEVEL;
            } else if (!strcmp(event, "gain-level")) {
                *f &= ~EFLAG_GAIN_LEVEL;
            } else if (!strcmp(event, "dtmf")) {
                *f &= ~EFLAG_DTMF;
            } else if (!strcmp(event, "stop-talking")) {
                *f &= ~EFLAG_STOP_TALKING;
            } else if (!strcmp(event, "start-talking")) {
                *f &= ~EFLAG_START_TALKING;
            } else if (!strcmp(event, "mute-detect")) {
                *f &= ~EFLAG_MUTE_DETECT;
            } else if (!strcmp(event, "mute-member")) {
                *f &= ~EFLAG_MUTE_MEMBER;
            } else if (!strcmp(event, "unmute-member")) {
                *f &= ~EFLAG_UNMUTE_MEMBER;
            } else if (!strcmp(event, "lock-mute-member")) {
                *f &= ~EFLAG_LOCK_MUTE_MEMBER;
            } else if (!strcmp(event, "unlock-mute-member")) {
                *f &= ~EFLAG_UNLOCK_MUTE_MEMBER;
            } else if (!strcmp(event, "kick-member")) {
                *f &= ~EFLAG_KICK_MEMBER;
            } else if (!strcmp(event, "dtmf-member")) {
                *f &= ~EFLAG_DTMF_MEMBER;
            } else if (!strcmp(event, "energy-level-member")) {
                *f &= ~EFLAG_ENERGY_LEVEL_MEMBER;
            } else if (!strcmp(event, "volume-in-member")) {
                *f &= ~EFLAG_VOLUME_IN_MEMBER;
            } else if (!strcmp(event, "volume-out-member")) {
                *f &= ~EFLAG_VOLUME_OUT_MEMBER;
            } else if (!strcmp(event, "play-file")) {
                *f &= ~EFLAG_PLAY_FILE;
            } else if (!strcmp(event, "play-file-done")) {
                *f &= ~EFLAG_PLAY_FILE;
            } else if (!strcmp(event, "play-file-member")) {
                *f &= ~EFLAG_PLAY_FILE_MEMBER;
            } else if (!strcmp(event, "speak-text")) {
                *f &= ~EFLAG_SPEAK_TEXT;
            } else if (!strcmp(event, "speak-text-member")) {
                *f &= ~EFLAG_SPEAK_TEXT_MEMBER;
            } else if (!strcmp(event, "lock")) {
                *f &= ~EFLAG_LOCK;
            } else if (!strcmp(event, "unlock")) {
                *f &= ~EFLAG_UNLOCK;
            } else if (!strcmp(event, "transfer")) {
                *f &= ~EFLAG_TRANSFER;
            } else if (!strcmp(event, "bgdial-result")) {
                *f &= ~EFLAG_BGDIAL_RESULT;
            } else if (!strcmp(event, "floor-change")) {
                *f &= ~EFLAG_FLOOR_CHANGE;
            } else if (!strcmp(event, "record")) {
                *f &= ~EFLAG_RECORD;
            }

            event = next;
        }
    }
}

SWITCH_STANDARD_APP(conference_auto_function)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);
    call_list_t *call_list, *np;

    call_list = switch_channel_get_private(channel, "_conference_autocall_list_");

    if (zstr(data)) {
        call_list = NULL;
    } else {
        np = switch_core_session_alloc(session, sizeof(*np));
        switch_assert(np != NULL);

        np->string = switch_core_session_strdup(session, data);
        if (call_list) {
            np->next = call_list;
            np->iteration = call_list->iteration + 1;
        } else {
            np->iteration = 1;
        }
        call_list = np;
    }
    switch_channel_set_private(channel, "_conference_autocall_list_", call_list);
}


static int setup_media(conference_member_t *member, conference_obj_t *conference)
{
    switch_codec_implementation_t read_impl = { 0 };
    switch_core_session_get_read_impl(member->session, &read_impl);

    if (switch_core_codec_ready(&member->read_codec)) {
        switch_core_codec_destroy(&member->read_codec);
        memset(&member->read_codec, 0, sizeof(member->read_codec));
    }

    if (switch_core_codec_ready(&member->write_codec)) {
        switch_core_codec_destroy(&member->write_codec);
        memset(&member->write_codec, 0, sizeof(member->write_codec));
    }

    if (member->read_resampler) {
        switch_resample_destroy(&member->read_resampler);
    }


    switch_core_session_get_read_impl(member->session, &member->orig_read_impl);
    member->native_rate = read_impl.samples_per_second;

    /* Setup a Signed Linear codec for reading audio. */
    if (switch_core_codec_init(&member->read_codec,
                               "L16",
                               NULL, read_impl.actual_samples_per_second, read_impl.microseconds_per_packet / 1000,
                               1, SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL, member->pool) == SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG,
                          "Raw Codec Activation Success L16@%uhz 1 channel %dms\n",
                          read_impl.actual_samples_per_second, read_impl.microseconds_per_packet / 1000);

    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG, "Raw Codec Activation Failed L16@%uhz 1 channel %dms\n",
                          read_impl.actual_samples_per_second, read_impl.microseconds_per_packet / 1000);

        goto done;
    }

    if (!member->frame_size) {
        member->frame_size = SWITCH_RECOMMENDED_BUFFER_SIZE;
        member->frame = switch_core_alloc(member->pool, member->frame_size);
        member->mux_frame = switch_core_alloc(member->pool, member->frame_size);
    }

    if (read_impl.actual_samples_per_second != conference->rate) {
        if (switch_resample_create(&member->read_resampler,
                                   read_impl.actual_samples_per_second,
                                   conference->rate, member->frame_size, SWITCH_RESAMPLE_QUALITY, 1) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_CRIT, "Unable to create resampler!\n");
            goto done;
        }


        member->resample_out = switch_core_alloc(member->pool, member->frame_size);
        member->resample_out_len = member->frame_size;

        /* Setup an audio buffer for the resampled audio */
        if (!member->resample_buffer && 
            switch_buffer_create_dynamic(&member->resample_buffer, CONF_DBLOCK_SIZE, CONF_DBUFFER_SIZE, CONF_DBUFFER_MAX)
            != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_CRIT, "Memory Error Creating Audio Buffer!\n");
            goto done;
        }
    }


    /* Setup a Signed Linear codec for writing audio. */
    if (switch_core_codec_init(&member->write_codec,
                               "L16",
                               NULL,
                               conference->rate,
                               read_impl.microseconds_per_packet / 1000,
                               1, SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL, member->pool) == SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG,
                          "Raw Codec Activation Success L16@%uhz 1 channel %dms\n", conference->rate, read_impl.microseconds_per_packet / 1000);
    } else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_DEBUG, "Raw Codec Activation Failed L16@%uhz 1 channel %dms\n",
                          conference->rate, read_impl.microseconds_per_packet / 1000);
        goto codec_done2;
    }

    /* Setup an audio buffer for the incoming audio */
    if (switch_buffer_create_dynamic(&member->audio_buffer, CONF_DBLOCK_SIZE, CONF_DBUFFER_SIZE, CONF_DBUFFER_MAX) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_CRIT, "Memory Error Creating Audio Buffer!\n");
        goto codec_done1;
    }

    /* Setup an audio buffer for the outgoing audio */
    if (switch_buffer_create_dynamic(&member->mux_buffer, CONF_DBLOCK_SIZE, CONF_DBUFFER_SIZE, CONF_DBUFFER_MAX) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(member->session), SWITCH_LOG_CRIT, "Memory Error Creating Audio Buffer!\n");
        goto codec_done1;
    }

    return 0;

  codec_done1:
    switch_core_codec_destroy(&member->read_codec);
  codec_done2:
    switch_core_codec_destroy(&member->write_codec);
  done:

    return -1;


}

static void conference_play_alone_sound(conference_obj_t *conference, conference_member_t *member)
{
    char *alone_sound = NULL;
    if(!switch_test_flag(member, MFLAG_GHOST))
    {
        if (switch_test_flag(member, MFLAG_MOD))
        {
            alone_sound = conference->alone_sound;
        }
        else
        {
            alone_sound = conference->alone_sound_attendee;
        }

        if (alone_sound)
        {
            conference_stop_file(conference, FILE_STOP_ASYNC);
            conference_play_file(
                conference, alone_sound, CONF_ALONE_LEADIN,
                switch_core_session_get_channel(member->session), 1, 0
            );
        }
    }
}

static conference_member_t* find_moderator(conference_obj_t *conference)
{
    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (conference_member_t *member = conference->member_lists[i]; member; member = member->next)
        {
            if (switch_test_flag(member, MFLAG_MOD))
            {
                return member;
            }
        }
    }
    return NULL;
}

static uint8_t get_moderator_count(conference_obj_t *conference)
{
    uint8_t count = 0;
    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (conference_member_t *member = conference->member_lists[i]; member; member = member->next)
        {
            if (switch_test_flag(member, MFLAG_MOD))
                count++;
        }
    }
    return count;
}

static switch_status_t call_operator(conference_obj_t *conference)
{
    switch_uuid_t uuid;
    char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1] = "";
    char sip_trunk[1024] = "";
    char *name = 0;
    switch_status_t status = SWITCH_STATUS_FALSE;

    if (conference == NULL) {
        return status;
    }

    name = conference->name ? conference->name : "<NONE>";

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
        "Live operator help is requested for conference: %s\n", name
    );

    if (conference->operator_phone_number == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
            "Operator for conference: %s is not available. "
            "Error: phone number is not provided.\n", name
        );
        return status;
    }

    if (conference->sip_trunk_ip_list == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
            "Operator for conference: %s is not available. "
            "Error: sip trunk is not provided.\n", name
        );
        return status;
    }

    switch_uuid_get(&uuid);
    switch_uuid_format(uuid_str, &uuid);

    switch_snprintf(sip_trunk, sizeof(sip_trunk), "sofia/external/%s@%s",
        conference->operator_phone_number, conference->sip_trunk_ip_list
    );

    status = conference_outcall_bg(conference, NULL, NULL, sip_trunk, 60,
        NULL, "FuzeSymphony", "*0", uuid_str, NULL, NULL, NULL
    );
    if (status != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
            "Calling operator for conference failed: %s\n", name
        );
        return status;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
        "Connection to an operator for conference established: %s\n", name
    );

    return status;
}

#define validate_pin(buf, pin, mpin) \
    pin_valid = (!zstr(pin) && strcmp(buf, pin) == 0);    \
    if (!pin_valid && !zstr(mpin) && strcmp(buf, mpin) == 0) {            \
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Moderator PIN found!\n"); \
        pin_valid = 1; \
        mpin_matched = 1; \
    }
/* Application interface function that is called from the dialplan to join the channel to a conference */
SWITCH_STANDARD_APP(conference_function)
{
    switch_codec_t *read_codec = NULL;
    //uint32_t flags = 0;
    conference_member_t member = { 0 };
    conference_obj_t *conference = NULL;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    char *mydata = NULL;
    char *conf_name = NULL;
    char *bridge_prefix = "bridge:";
    char *flags_prefix = "+flags{";
    char *bridgeto = NULL;
    char *profile_name = NULL;
    switch_xml_t cxml = NULL, cfg = NULL, profiles = NULL;
    const char *flags_str, *v_flags_str;
    member_flag_t mflags = 0;
    switch_core_session_message_t msg = { 0 };
    uint8_t rl = 0, isbr = 0;
    char *dpin = "";
    const char *mdpin = "";
    conf_xml_cfg_t xml_cfg = { 0 };
    switch_event_t *params = NULL;
    int locked = 0;
    int mpin_matched = 0;
    uint32_t *mid;
    int wait = 0;

    if (!switch_channel_test_app_flag_key("conf_silent", channel, CONF_SILENT_DONE) &&
        (switch_channel_test_flag(channel, CF_RECOVERED) || switch_true(switch_channel_get_variable(channel, "conference_silent_entry")))) {
        switch_channel_set_app_flag_key("conf_silent", channel, CONF_SILENT_REQ);
    }

    switch_core_session_video_reset(session);

    switch_channel_set_flag(channel, CF_CONFERENCE);
    switch_channel_set_flag(channel, CF_VIDEO_PASSIVE);


    if (switch_channel_answer(channel) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Channel answer failed.\n");
        goto end;
    }

    /* Save the original read codec. */
    if (!(read_codec = switch_core_session_get_read_codec(session))) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Channel has no media!\n");
        goto end;
    }


    if (zstr(data)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Invalid arguments\n");
        goto end;
    }

    mydata = switch_core_session_strdup(session, data);

    if (!mydata) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Pool Failure\n");
        goto end;
    }

    if ((flags_str = strstr(mydata, flags_prefix))) {
        char *p;
        *((char *) flags_str) = '\0';
        flags_str += strlen(flags_prefix);
        if ((p = strchr(flags_str, '}'))) {
            *p = '\0';
        }
    }

    if ((v_flags_str = switch_channel_get_variable(channel, "conference_member_flags"))) {
        if (zstr(flags_str)) {
            flags_str = v_flags_str;
        } else {
            flags_str = switch_core_session_sprintf(session, "%s|%s", flags_str, v_flags_str);
        }
    }

    /* is this a bridging conference ? */
    if (!strncasecmp(mydata, bridge_prefix, strlen(bridge_prefix))) {
        isbr = 1;
        mydata += strlen(bridge_prefix);
        if ((bridgeto = strchr(mydata, ':'))) {
            *bridgeto++ = '\0';
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Config Error!\n");
            goto done;
        }
    }

    conf_name = mydata;

    /* eat all leading spaces on conference name, which can cause problems */
    while (*conf_name == ' ') {
        conf_name++;
    }

    /* is there a conference pin ? */
    if ((dpin = strchr(conf_name, '+'))) {
        *dpin++ = '\0';
    } else dpin = "";

    /* is there profile specification ? */
    if ((profile_name = strrchr(conf_name, '@'))) {
        *profile_name++ = '\0';
    } else {
        profile_name = "default";
    }

#if 0
    if (0) {
        member.dtmf_parser = conference->dtmf_parser;
    } else {

    }
#endif

    if (switch_channel_test_flag(channel, CF_RECOVERED)) {
        const char *check = switch_channel_get_variable(channel, "last_transfered_conference");

        if (!zstr(check)) {
            conf_name = (char *) check;
        }
    }

    switch_event_create(&params, SWITCH_EVENT_COMMAND);
    switch_assert(params);
    switch_event_add_header_string(params, SWITCH_STACK_BOTTOM, "conf_name", conf_name);
    switch_event_add_header_string(params, SWITCH_STACK_BOTTOM, "profile_name", profile_name);

    /* Open the config from the xml registry */
    if (!(cxml = switch_xml_open_cfg(global_cf_name, &cfg, params))) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Open of %s failed\n", global_cf_name);
        goto done;
    }

    if ((profiles = switch_xml_child(cfg, "profiles"))) {
        xml_cfg.profile = switch_xml_find_child(profiles, "profile", "name", profile_name);
    }

    /* if this is a bridging call, and it's not a duplicate, build a */
    /* conference object, and skip pin handling, and locked checking */

    if (!locked) {
        switch_mutex_lock(globals.setup_mutex);
        locked = 1;
    }

    if (isbr) {
        char *uuid = switch_core_session_get_uuid(session);

        if (!strcmp(conf_name, "_uuid_")) {
            conf_name = uuid;
        }

        if ((conference = conference_find(conf_name, NULL))) {
            switch_thread_rwlock_unlock(conference->rwlock);
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Conference %s already exists!\n", conf_name);
            goto done;
        }

        /* Create the conference object. */
        conference = conference_new(conf_name, xml_cfg, session, NULL);

        if (!conference) {
            goto done;
        }

        if (locked) {
            switch_mutex_unlock(globals.setup_mutex);
            locked = 0;
        }

        switch_channel_set_variable(channel, "conference_id", conference->name);

        /* Set the minimum number of members (once you go above it you cannot go below it) */
        conference->min = 2;

        /* Indicate the conference is dynamic */
        set_conference_state_locked(conference, CFLAG_DYNAMIC);

        /* Indicate the conference has a bridgeto party */
        set_conference_state_locked(conference, CFLAG_BRIDGE_TO);

        /* Start the conference thread for this conference */
        conference_loop_init(conference);
#if 0
        launch_conference_thread(conference);
#endif

    } else {
        int enforce_security =  switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_INBOUND;
        const char *pvar = switch_channel_get_variable(channel, "conference_enforce_security");

        if (pvar) {
            enforce_security = switch_true(pvar);
        }

        if ((conference = conference_find(conf_name, NULL))) {
            if (locked) {
                switch_mutex_unlock(globals.setup_mutex);
                locked = 0;
            }
        }

        /* if the conference exists, get the pointer to it */
        if (!conference) {
            const char *max_members_str;
            const char *endconf_grace_time_str;
            const char *auto_record_str;

            /* no conference yet, so check for join-only flag */
            if (flags_str) {
                set_mflags(flags_str,&mflags);
                if (mflags & MFLAG_JOIN_ONLY) {
                    switch_event_t *event;
                    switch_xml_t jos_xml;
                    char *val;
                    /* send event */
                    switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, CONF_EVENT_MAINT);
                    switch_channel_event_set_basic_data(channel, event);
                    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Conference-Name", conf_name);
                    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Conference-Profile-Name", profile_name);
                    switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Action", "rejected-join-only");
                    switch_event_fire(&event);
                    /* check what sound file to play */
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Cannot create a conference since join-only flag is set\n");
                    jos_xml = switch_xml_find_child(xml_cfg.profile, "param", "name", "join-only-sound");
                    if (jos_xml && (val = (char *) switch_xml_attr_soft(jos_xml, "value"))) {
                            switch_channel_answer(channel);
                            switch_ivr_play_file(session, NULL, val, NULL);
                    }
                    if (!switch_false(switch_channel_get_variable(channel, "hangup_after_conference"))) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "hangup_after_conference!!! SWITCH_CAUSE_NORMAL_CLEARING\n");
                        switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
                    }
                    goto done;
                }
            }

            /* couldn't find the conference, create one */
            conference = conference_new(conf_name, xml_cfg, session, NULL);

            if (!conference) {
                goto done;
            }

            if (locked) {
                switch_mutex_unlock(globals.setup_mutex);
                locked = 0;
            }

            switch_channel_set_variable(channel, "conference_id", conference->name);

            /* Set MOH from variable if not set */
            if (zstr(conference->moh_sound)) {
                conference->moh_sound = switch_core_strdup(conference->pool, switch_channel_get_variable(channel, "conference_moh_sound"));
            }

            /* Set perpetual-sound from variable if not set */
            if (zstr(conference->perpetual_sound)) {
                conference->perpetual_sound = switch_core_strdup(conference->pool, switch_channel_get_variable(channel, "conference_perpetual_sound"));
            }

            /* Override auto-record profile parameter from variable */
            if (!zstr(auto_record_str = switch_channel_get_variable(channel, "conference_auto_record"))) {
                conference->auto_record = switch_core_strdup(conference->pool, auto_record_str);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                  "conference_auto_record set from variable to %s\n", auto_record_str);
            }

            /* Set the minimum number of members (once you go above it you cannot go below it) */
            conference->min = 1;

            /* check for variable used to specify override for max_members */
            if (!zstr(max_members_str = switch_channel_get_variable(channel, "conference_max_members"))) {
                uint32_t max_members_val;
                errno = 0;        /* sanity first */
                max_members_val = strtol(max_members_str, NULL, 0);    /* base 0 lets 0x... for hex 0... for octal and base 10 otherwise through */
                if (errno == ERANGE || errno == EINVAL || (int32_t) max_members_val < 0 || max_members_val == 1) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                                      "conference_max_members variable %s is invalid, not setting a limit\n", max_members_str);
                } else {
                    conference->max_members = max_members_val;
                }
            }
            else
            {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "No channel override for conference max_members\n");
            }

            /* check for variable to override endconf_grace_time profile value */
            if (!zstr(endconf_grace_time_str = switch_channel_get_variable(channel, "conference_endconf_grace_time"))) {
                uint32_t grace_time_val;
                errno = 0;        /* sanity first */
                grace_time_val = strtol(endconf_grace_time_str, NULL, 0);    /* base 0 lets 0x... for hex 0... for octal and base 10 otherwise through */
                if (errno == ERANGE || errno == EINVAL || (int32_t) grace_time_val < 0) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                                      "conference_endconf_grace_time variable %s is invalid, not setting a time limit\n", endconf_grace_time_str);
                } else {
                    conference->endconf_grace_time = grace_time_val;
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                      "conference endconf_grace_time set from variable to %d\n", grace_time_val);
                }
            }

            /* check for variable to override endconf_grace_time profile value */
            if (!zstr(endconf_grace_time_str = switch_channel_get_variable(channel, "conference_endconf_grace_time"))) {
                uint32_t grace_time_val;
                errno = 0;        /* sanity first */
                grace_time_val = strtol(endconf_grace_time_str, NULL, 0);    /* base 0 lets 0x... for hex 0... for octal and base 10 otherwise through */
                if (errno == ERANGE || errno == EINVAL || (int32_t) grace_time_val < 0) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                                      "conference_endconf_grace_time variable %s is invalid, not setting a time limit\n", endconf_grace_time_str);
                } else {
                    conference->endconf_grace_time = grace_time_val;
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                      "conference endconf_grace_time set from variable to %d\n", grace_time_val);
                }
            }

            /* Indicate the conference is dynamic */
            set_conference_state_locked(conference, CFLAG_DYNAMIC);

            /* acquire a read lock on the thread so it can't leave without us */
            if (switch_thread_rwlock_tryrdlock(conference->rwlock) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Read Lock Fail\n");
                goto done;
            }

            rl++;

            /* Start the conference thread for this conference */
            conference_loop_init(conference);
#if 0
            launch_conference_thread(conference);
#endif
        } else {                /* setup user variable */
            switch_channel_set_variable(channel, "conference_id", conference->name);
            rl++;
        }

        /* Moderator PIN as a channel variable */
        mdpin = switch_channel_get_variable(channel, "conference_moderator_pin");

        if (zstr(dpin) && conference->pin) {
            dpin = conference->pin;
        }
        if (zstr(mdpin) && conference->mpin) {
            mdpin = conference->mpin;
        }


        /* if this is not an outbound call, deal with conference pins */
        if (enforce_security && (!zstr(dpin) || !zstr(mdpin))) {
            char pin_buf[80] = "";
            int pin_retries = conference->pin_retries;
            int pin_valid = 0;
            switch_status_t status = SWITCH_STATUS_SUCCESS;
            char *supplied_pin_value;

            /* Answer the channel */
            switch_channel_answer(channel);

            /* look for PIN in channel variable first.  If not present or invalid revert to prompting user */
            supplied_pin_value = switch_core_strdup(conference->pool, switch_channel_get_variable(channel, "supplied_pin"));
            if (!zstr(supplied_pin_value)) {
                char *supplied_pin_value_start;
                int i = 0;
                if ((supplied_pin_value_start = (char *) switch_stristr(cf_pin_url_param_name, supplied_pin_value))) {
                    /* pin supplied as a URL parameter, move pointer to start of actual pin value */
                    supplied_pin_value = supplied_pin_value_start + strlen(cf_pin_url_param_name);
                }
                while (*supplied_pin_value != 0 && *supplied_pin_value != ';') {
                    pin_buf[i++] = *supplied_pin_value++;
                }

                validate_pin(pin_buf, dpin, mdpin);
                memset(pin_buf, 0, sizeof(pin_buf));
            }

            if (!conference->pin_sound) {
                conference->pin_sound = switch_core_strdup(conference->pool, "conference/conf-pin.wav");
            }

            if (!conference->bad_pin_sound) {
                conference->bad_pin_sound = switch_core_strdup(conference->pool, "conference/conf-bad-pin.wav");
            }

            while (!pin_valid && pin_retries && status == SWITCH_STATUS_SUCCESS) {
                size_t dpin_length = dpin ? strlen(dpin) : 0;
                size_t mdpin_length = mdpin ? strlen(mdpin) : 0;
                int maxpin = dpin_length > mdpin_length ? (int)dpin_length : (int)mdpin_length;
                switch_status_t pstatus = SWITCH_STATUS_FALSE;

                /* be friendly */
                if (conference->pin_sound) {
                    pstatus = conference_local_play_file(conference, session, conference->pin_sound, 20, pin_buf, sizeof(pin_buf));
                } else if (conference->tts_engine && conference->tts_voice) {
                    pstatus =
                        switch_ivr_speak_text(session, conference->tts_engine, conference->tts_voice, "please enter the conference pin number", NULL);
                } else {
                    pstatus = switch_ivr_speak_text(session, "flite", "slt", "please enter the conference pin number", NULL);
                }

                if (pstatus != SWITCH_STATUS_SUCCESS && pstatus != SWITCH_STATUS_BREAK) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Cannot ask the user for a pin, ending call\n");
                    switch_channel_hangup(channel, SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER);
                }

                /* wait for them if neccessary */
                if ((int)strlen(pin_buf) < maxpin) {
                    char *buf = pin_buf + strlen(pin_buf);
                    char term = '\0';

                    status = switch_ivr_collect_digits_count(session,
                                                             buf,
                                                             sizeof(pin_buf) - strlen(pin_buf), maxpin - strlen(pin_buf), "#", &term, 10000, 0, 0);
                    if (status == SWITCH_STATUS_TIMEOUT) {
                        status = SWITCH_STATUS_SUCCESS;
                    }
                }

                if (status == SWITCH_STATUS_SUCCESS) {
                    validate_pin(pin_buf, dpin, mdpin);
                }

                if (!pin_valid) {
                    /* zero the collected pin */
                    memset(pin_buf, 0, sizeof(pin_buf));

                    /* more friendliness */
                    if (conference->bad_pin_sound) {
                        conference_local_play_file(conference, session, conference->bad_pin_sound, 20, NULL, 0);
                    }
                    switch_channel_flush_dtmf(channel);
                }
                pin_retries--;
            }

            if (!pin_valid) {
                conference_cdr_rejected(conference, channel, CDRR_PIN);
                goto done;
            }
        }

        if (conference->special_announce && !switch_channel_test_app_flag_key("conf_silent", channel, CONF_SILENT_REQ)) {
            conference_local_play_file(conference, session, conference->special_announce, CONF_DEFAULT_LEADIN, NULL, 0);
        }

        /* don't allow more callers if the conference is locked, unless we invited them */
        if (switch_test_flag(conference, CFLAG_LOCKED) && enforce_security) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "Conference %s is locked.\n", conf_name);
            conference_cdr_rejected(conference, channel, CDRR_LOCKED);
            if (conference->locked_sound) {
                /* Answer the channel */
                switch_channel_answer(channel);
                conference_local_play_file(conference, session, conference->locked_sound, 20, NULL, 0);
            }
            goto done;
        }

        /* dont allow more callers than the max_members allows for -- I explicitly didnt allow outbound calls
         * someone else can add that (see above) if they feel that outbound calls should be able to violate the
         * max_members limit
         */
        if (conference->max_members > 0)
        {
            /*
             * Reserve a slot for the moderator
             */
            member_flag_t channel_member_flags = 0;
            uint32_t max_members_count = conference->max_members;
            conference_member_t *moderator = find_moderator(conference);

            set_mflags(flags_str, &channel_member_flags);

            if (!moderator && !(channel_member_flags & MFLAG_MOD))
            {
                max_members_count--;
            }

            if (conference->count >= max_members_count) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "Conference %s is full.\n", conf_name);
                conference_cdr_rejected(conference, channel, CDRR_MAXMEMBERS);

                if (moderator && conference->maxmember_sound && !switch_test_flag(conference, CFLAG_MODERATOR_MAX_MEMBERS_NOTIFIED_ALREADY))
                {
                    set_conference_state_locked(conference, CFLAG_MODERATOR_MAX_MEMBERS_NOTIFIED_ALREADY);
                    conference_play_to_moderator(conference, conference->maxmember_sound, CONF_DEFAULT_LEADIN);
                }

                if (conference->maxmember_sound_attendee) {
                    /* Answer the channel */
                    switch_channel_answer(channel);
                    conference_stop_file(conference, FILE_STOP_ALL);
                    conference_local_play_file(conference, session, conference->maxmember_sound_attendee, 20, NULL, 0);
                }
                goto done;
            }
        }

    }

    /* Release the config registry handle */
    if (cxml) {
        switch_xml_free(cxml);
        cxml = NULL;
    }

    /* if we're using "bridge:" make an outbound call and bridge it in */
    if (!zstr(bridgeto) && strcasecmp(bridgeto, "none")) {
        switch_call_cause_t cause;
        if (conference_outcall(conference, NULL, session, bridgeto, 60, NULL, NULL, NULL, NULL, &cause, NULL, NULL) != SWITCH_STATUS_SUCCESS) {
            goto done;
        }
    } else {
        /* if we're not using "bridge:" set the conference answered flag */
        /* and this isn't an outbound channel, answer the call */
        if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_INBOUND)
            set_conference_state_unlocked(conference, CFLAG_ANSWERED);
    }

    member.session = session;
    member.channel = switch_core_session_get_channel(session);
    member.pool = switch_core_session_get_pool(session);

    if (setup_media(&member, conference)) {
        //flags = 0;
        goto done;
    }


    if (!(mid = switch_channel_get_private(channel, "__confmid"))) {
        mid = switch_core_session_alloc(session, sizeof(*mid));
        *mid = next_member_id();
        switch_channel_set_private(channel, "__confmid", mid);
    }

    switch_channel_set_variable_printf(channel, "conference_member_id", "%u", *mid);

    /* Prepare MUTEXS */
    member.id = *mid;
    switch_mutex_init(&member.flag_mutex, SWITCH_MUTEX_NESTED, member.pool);
    switch_mutex_init(&member.write_mutex, SWITCH_MUTEX_NESTED, member.pool);
    switch_mutex_init(&member.read_mutex, SWITCH_MUTEX_NESTED, member.pool);
    switch_mutex_init(&member.fnode_mutex, SWITCH_MUTEX_NESTED, member.pool);
    switch_mutex_init(&member.audio_in_mutex, SWITCH_MUTEX_NESTED, member.pool);
    switch_mutex_init(&member.audio_out_mutex, SWITCH_MUTEX_NESTED, member.pool);
    switch_thread_rwlock_create(&member.rwlock, member.pool);

    /* Install our Signed Linear codec so we get the audio in that format */
    switch_core_session_set_read_codec(member.session, &member.read_codec);

    mflags = conference->mflags;
    set_mflags(flags_str, &mflags);
    mflags |= MFLAG_RUNNING;
    if (mpin_matched) {
        mflags |= MFLAG_MOD;
    }
    set_member_state_locked((&member), mflags);

    if (mflags & MFLAG_MINTWO) {
        conference->min = 2;
    }

    member.rec = NULL;

    /* Add the caller to the conference */
    if (conference_add_member(conference, &member) != SWITCH_STATUS_SUCCESS) {
        switch_core_codec_destroy(&member.read_codec);
        goto done;
    }

    msg.from = __FILE__;

    /* Tell the channel we are going to be in a bridge */
    msg.message_id = SWITCH_MESSAGE_INDICATE_BRIDGE;
    switch_core_session_receive_message(session, &msg);

    /* Set the log filter callback, that gets called to filter the logs
       at the end of the session */
    switch_core_set_log_filter_cb(session, conference_can_log_key);

    /* Run the conference loop */
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "start_conference_loops mid:%s/%d \n", member.mname, member.id);
    start_conference_loops(&member);
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "start_conference_loops returned mid:%s/%d\n", member.mname, member.id);
    switch_monitor_change_desc(switch_thread_self(), switch_core_get_monitor_index(member.session), "conference_function");

    switch_channel_set_private(channel, "_conference_autocall_list_", NULL);

    /* Tell the channel we are no longer going to be in a bridge */
    msg.message_id = SWITCH_MESSAGE_INDICATE_UNBRIDGE;
    switch_core_session_receive_message(session, &msg);

    if (member.conference->ending_due_to_inactivity) {
        switch_channel_hangup(channel, SWITCH_CAUSE_CONFERENCE_INACTIVE);
    }

    wait = (member.id % 50) * 1000000;
    switch_yield(wait);
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Wait for member cleanup mid:%d wait %d for real\n",
                      member.id, wait);

    /* Remove the caller from the conference */
    conference_del_member(member.conference, &member);

    /* Put the original codec back */
    switch_core_session_set_read_codec(member.session, NULL);

    /* Clean Up. */

#if 0
    wait = (member.id % 50) * 1000000;
    switch_yield(wait);
#else
#endif

  done:

    if (locked) {
        switch_mutex_unlock(globals.setup_mutex);
    }

    if (member.read_resampler) {
        switch_resample_destroy(&member.read_resampler);
    }

    switch_event_destroy(&params);
    switch_buffer_destroy(&member.resample_buffer);
    switch_buffer_destroy(&member.audio_buffer);
    switch_buffer_destroy(&member.mux_buffer);

    if (conference) {
        switch_mutex_lock(conference->mutex);
        if (switch_test_flag(conference, CFLAG_DYNAMIC) && conference->count == 0) {
            set_conference_state_locked(conference, CFLAG_DESTRUCT);
        }
        switch_mutex_unlock(conference->mutex);
    }

    /* Release the config registry handle */
    if (cxml) {
        switch_xml_free(cxml);
    }

    if (conference && switch_test_flag(&member, MFLAG_KICKED) && conference->kicked_sound) {
        char *toplay = NULL;
        char *dfile = NULL;
        char *expanded = NULL;
        char *src = member.kicked_sound ? member.kicked_sound : conference->kicked_sound;


        if (!strncasecmp(src, "say:", 4)) {
            if (conference->tts_engine && conference->tts_voice) {
                switch_ivr_speak_text(session, conference->tts_engine, conference->tts_voice, src + 4, NULL);
            }
        } else {
            if ((expanded = switch_channel_expand_variables(switch_core_session_get_channel(session), src)) != src) {
                toplay = expanded;
            } else {
                expanded = NULL;
                toplay = src;
            }

            if (!switch_is_file_path(toplay) && conference->sound_prefix) {
                dfile = switch_mprintf("%s%s%s", conference->sound_prefix, SWITCH_PATH_SEPARATOR, toplay);
                switch_assert(dfile);
                toplay = dfile;
            }

            switch_ivr_play_file(session, NULL, toplay, NULL);
            switch_safe_free(dfile);
            switch_safe_free(expanded);
        }
    }

    switch_core_session_reset(session, SWITCH_TRUE, SWITCH_TRUE);

    /* release the readlock */
    if (rl) {
        switch_thread_rwlock_unlock(conference->rwlock);
    }

    if (conference) {
        if ((conference->min && switch_test_flag(conference, CFLAG_ENFORCE_MIN) && (conference->count + conference->count_ghosts) < conference->min)
            || (switch_test_flag(conference, CFLAG_DYNAMIC) && (conference->count + conference->count_ghosts == 0))
            || switch_test_flag(conference, CFLAG_DESTRUCT)) {
            conference_thread_stop(conference);
        }
    }

    switch_channel_set_variable(channel, "last_transfered_conference", NULL);

 end:

    switch_channel_clear_flag(channel, CF_CONFERENCE);
    switch_channel_clear_flag(channel, CF_VIDEO_PASSIVE);

    //    switch_core_session_video_reset(session);
}


static void launch_conference_record_thread(conference_obj_t *conference, char *path, switch_bool_t autorec)
{
    switch_thread_t *thread;
    switch_threadattr_t *thd_attr = NULL;
    switch_memory_pool_t *pool;
    conference_record_t *rec;

    /* Setup a memory pool to use. */
    if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Pool Failure\n");
    }

    /* Create a node object */
    if (!(rec = switch_core_alloc(pool, sizeof(*rec)))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Alloc Failure\n");
        switch_core_destroy_memory_pool(&pool);
        return;
    }

    conference->is_recording = 1;

    rec->conference = conference;
    rec->path = switch_core_strdup(pool, path);
    rec->pool = pool;
    rec->autorec = autorec;

    switch_mutex_lock(conference->flag_mutex);
    rec->next = conference->rec_node_head;
    conference->rec_node_head = rec;
    switch_mutex_unlock(conference->flag_mutex);

    switch_threadattr_create(&thd_attr, rec->pool);
    switch_threadattr_detach_set(thd_attr, 1);
    switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
    switch_thread_create(&thread, thd_attr, conference_record_thread_run, rec, rec->pool);
}

static switch_status_t chat_send(switch_event_t *message_event)
{
    char name[512] = "", *p, *lbuf = NULL;
    conference_obj_t *conference = NULL;
    switch_stream_handle_t stream = { 0 };
    const char *proto;
    const char *from;
    const char *to;
    //const char *subject;
    const char *body;
    //const char *type;
    const char *hint;
    const char *ouuid;

    proto = switch_event_get_header(message_event, "proto");
    from = switch_event_get_header(message_event, "from");
    to = switch_event_get_header(message_event, "to");
    //subject = switch_event_get_header(message_event, "subject");
    body = switch_event_get_body(message_event);
    //type = switch_event_get_header(message_event, "type");
    hint = switch_event_get_header(message_event, "hint");
    ouuid = switch_event_get_header(message_event, "Channel-Call-UUID");

    if ((p = strchr(to, '+'))) {
        to = ++p;
    }

    if (!body) {
        return SWITCH_STATUS_SUCCESS;
    }

    if ((p = strchr(to, '@'))) {
        switch_copy_string(name, to, ++p - to);
    } else {
        switch_copy_string(name, to, sizeof(name));
    }

    if (!(conference = conference_find(name, NULL))) {
        switch_core_chat_send_args(proto, CONF_CHAT_PROTO, to, hint && strchr(hint, '/') ? hint : from, "",
                                   "Conference not active.", NULL, NULL, SWITCH_FALSE);
        return SWITCH_STATUS_FALSE;
    }

    SWITCH_STANDARD_STREAM(stream);

    if (body != NULL && (lbuf = strdup(body))) {
        /* special case list */
        if (conference->broadcast_chat_messages) {
            chat_message_broadcast(conference, &stream, body, from, ouuid);
        } else if (switch_stristr("list", lbuf)) {
            conference_list_pretty(conference, &stream);
            /* provide help */
        } else {
            return SWITCH_STATUS_SUCCESS;
        }
    }

    switch_safe_free(lbuf);

    switch_core_chat_send_args(proto, CONF_CHAT_PROTO, to, hint && strchr(hint, '/') ? hint : from, "", stream.data, NULL, NULL, SWITCH_FALSE);
    switch_safe_free(stream.data);
    switch_thread_rwlock_unlock(conference->rwlock);

    return SWITCH_STATUS_SUCCESS;
}

static conference_obj_t *conference_find(char *name, char *domain)
{
    conference_obj_t *conference;

    switch_mutex_lock(globals.hash_mutex);
    if ((conference = switch_core_hash_find(globals.conference_hash, name))) {
        if (switch_test_flag(conference, CFLAG_DESTRUCT)) {
            switch_core_hash_delete(globals.conference_hash, conference->name);
            clear_conference_state_unlocked(conference, CFLAG_INHASH);
            conference = NULL;
        } else if (!zstr(domain) && conference->domain && strcasecmp(domain, conference->domain)) {
            conference = NULL;
        }
    }
    if (conference) {
        if (switch_thread_rwlock_tryrdlock(conference->rwlock) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Read Lock Fail\n");
            conference = NULL;
        }
    }
    switch_mutex_unlock(globals.hash_mutex);

    return conference;
}

/* create a new conferene with a specific profile */
static conference_obj_t *conference_new(char *name, conf_xml_cfg_t cfg, switch_core_session_t *session, switch_memory_pool_t *pool)
{
    conference_obj_t *conference;
    switch_xml_t xml_kvp;
    char *timer_name = NULL;
    char *domain = NULL;
    char *desc = NULL;
    char *name_domain = NULL;
    char *tts_engine = NULL;
    char *tts_voice = NULL;
    char *enter_sound = NULL;
    char *sound_prefix = NULL;
    char *exit_sound = NULL;
    char *chimes_on_sound = NULL;
    char *chimes_off_sound = NULL;
    char *alone_sound = NULL;
    char *alone_sound_attendee = NULL;
    char *ack_sound = NULL;
    char *nack_sound = NULL;
    char *muted_sound = NULL;
    char *mute_detect_sound = NULL;
    char *unmuted_sound = NULL;
    char *muted_all_sound = NULL;
    char *unmuted_all_sound = NULL;
    char *mutes_locked_sound = NULL;
    char *mutes_unlocked_sound = NULL;
    char *locked_sound = NULL;
    char *is_locked_sound = NULL;
    char *is_unlocked_sound = NULL;
    char *kicked_sound = NULL;
    char *recording_started_sound = NULL;
    char *recording_stopped_sound = NULL;
    char *join_only_sound = NULL;
    char *pin = NULL;
    char *mpin = NULL;
    char *pin_sound = NULL;
    char *bad_pin_sound = NULL;
    char *energy_level = NULL;
    char *auto_gain_level = NULL;
    char *caller_id_name = NULL;
    char *caller_id_number = NULL;
    char *caller_controls = NULL;
    char *moderator_controls = NULL;
    char *member_flags = NULL;
    char *conference_flags = NULL;
    char *perpetual_sound = NULL;
    char *moh_sound = NULL;
    char *outcall_templ = NULL;
    uint32_t max_members = 0;
    uint32_t announce_count = 0;
    char *maxmember_sound = NULL;
    char *maxmember_sound_attendee = NULL;
    uint32_t rate = 8000, interval = 20;
    int broadcast_chat_messages = 0;
    int comfort_noise_level = 0;
    int pin_retries = 3;
    int ivr_dtmf_timeout = 500;
    int ivr_input_timeout = 0;
    char *suppress_events = NULL;
    char *verbose_events = NULL;
    char *auto_record = NULL;
    int min_recording_participants = 2;
    char *conference_log_dir = NULL;
    char *cdr_event_mode = NULL;
    char *terminate_on_silence = NULL;
    char *endconf_grace_time = NULL;
    char uuid_str[SWITCH_UUID_FORMATTED_LENGTH+1];
    switch_uuid_t uuid;
    switch_codec_implementation_t read_impl = { 0 };
    switch_channel_t *channel = NULL;
    const char *force_rate = NULL, *force_interval = NULL, *presence_id = NULL;
    uint32_t force_rate_i = 0, force_interval_i = 0;
    switch_bool_t notify_active_talkers = SWITCH_TRUE;
    uint16_t history_time_period = 2000;
    uint16_t history_reset_time_period = 500;
    char *begin_sound = NULL;

    /* Validate the conference name */
    if (zstr(name)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid Record! no name.\n");
        return NULL;
    }

    if (session) {
        uint32_t tmp;

        switch_core_session_get_read_impl(session, &read_impl);
        channel = switch_core_session_get_channel(session);

        presence_id = switch_channel_get_variable(channel, "presence_id");

        if ((force_rate = switch_channel_get_variable(channel, "conference_force_rate"))) {
            if (!strcasecmp(force_rate, "auto")) {
                force_rate_i = read_impl.actual_samples_per_second;
            } else {
                tmp = atoi(force_rate);

                if (tmp == 8000 || tmp == 12000 || tmp == 16000 || tmp == 24000 || tmp == 32000 || tmp == 48000) {
                    force_rate_i = rate = tmp;
                }
            }
        }

        if ((force_interval = switch_channel_get_variable(channel, "conference_force_interval"))) {
            if (!strcasecmp(force_interval, "auto")) {
                force_interval_i = read_impl.microseconds_per_packet / 1000;
            } else {
                tmp = atoi(force_interval);

                if (SWITCH_ACCEPTABLE_INTERVAL(tmp)) {
                    force_interval_i = interval = tmp;
                }
            }
        }
    }

    switch_mutex_lock(globals.hash_mutex);

    /* parse the profile tree for param values */
    if (cfg.profile)
        for (xml_kvp = switch_xml_child(cfg.profile, "param"); xml_kvp; xml_kvp = xml_kvp->next) {
            char *var = (char *) switch_xml_attr_soft(xml_kvp, "name");
            char *val = (char *) switch_xml_attr_soft(xml_kvp, "value");
            char buf[128] = "";
            char *p;
            if ((p = strchr(var, '_'))) {
                switch_copy_string(buf, var, sizeof(buf));
                for (p = buf; *p; p++) {
                    if (*p == '_') {
                        *p = '-';
                    }
                }
                var = buf;
            }

            if (!force_rate_i && !strcasecmp(var, "rate") && !zstr(val)) {
                uint32_t tmp = atoi(val);
                if (session && tmp == 0) {
                    if (!strcasecmp(val, "auto")) {
                        rate = read_impl.actual_samples_per_second;
                    }
                } else {
                    if (tmp == 8000 || tmp == 12000 || tmp == 16000 || tmp == 24000 || tmp == 32000 || tmp == 48000) {
                        rate = tmp;
                    }
                }
            } else if (!strcasecmp(var, "domain") && !zstr(val)) {
                domain = val;
            } else if (!strcasecmp(var, "description") && !zstr(val)) {
                desc = val;
            } else if (!force_interval_i && !strcasecmp(var, "interval") && !zstr(val)) {
                uint32_t tmp = atoi(val);

                if (session && tmp == 0) {
                    if (!strcasecmp(val, "auto")) {
                        interval = read_impl.microseconds_per_packet / 1000;
                    }
                } else {
                    if (SWITCH_ACCEPTABLE_INTERVAL(tmp)) {
                        interval = tmp;
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                            "Interval must be multipe of 10 and less than %d, Using default of 20\n", SWITCH_MAX_INTERVAL);
                    }
                }
            } else if (!strcasecmp(var, "timer-name") && !zstr(val)) {
                timer_name = val;
            } else if (!strcasecmp(var, "tts-engine") && !zstr(val)) {
                tts_engine = val;
            } else if (!strcasecmp(var, "tts-voice") && !zstr(val)) {
                tts_voice = val;
            } else if (!strcasecmp(var, "enter-sound") && !zstr(val)) {
                enter_sound = val;
            } else if (!strcasecmp(var, "outcall-templ") && !zstr(val)) {
                outcall_templ = val;
            } else if (!strcasecmp(var, "exit-sound") && !zstr(val)) {
                exit_sound = val;
            } else if (!strcasecmp(var, "chimes-on-sound") && !zstr(val)) {
                chimes_on_sound = val;
            } else if (!strcasecmp(var, "chimes-off-sound") && !zstr(val)) {
                chimes_off_sound = val;
            } else if (!strcasecmp(var, "alone-sound") && !zstr(val)) {
                alone_sound = val;
            } else if (!strcasecmp(var, "alone-sound-attendee") && !zstr(val)) {
                alone_sound_attendee = val;
            } else if (!strcasecmp(var, "perpetual-sound") && !zstr(val)) {
                perpetual_sound = val;
            } else if (!strcasecmp(var, "moh-sound") && !zstr(val)) {
                moh_sound = val;
            } else if (!strcasecmp(var, "ack-sound") && !zstr(val)) {
                ack_sound = val;
            } else if (!strcasecmp(var, "nack-sound") && !zstr(val)) {
                nack_sound = val;
            } else if (!strcasecmp(var, "muted-sound") && !zstr(val)) {
                muted_sound = val;
            } else if (!strcasecmp(var, "mute-detect-sound") && !zstr(val)) {
                mute_detect_sound = val;
            } else if (!strcasecmp(var, "unmuted-sound") && !zstr(val)) {
                unmuted_sound = val;
            } else if (!strcasecmp(var, "muted-all-sound") && !zstr(val)) {
                muted_all_sound = val;
            } else if (!strcasecmp(var, "unmuted-all-sound") && !zstr(val)) {
                unmuted_all_sound = val;
            } else if (!strcasecmp(var, "mutes-locked-sound") && !zstr(val)) {
                mutes_locked_sound = val;
            } else if (!strcasecmp(var, "mutes-unlocked-sound") && !zstr(val)) {
                mutes_unlocked_sound = val;
            } else if (!strcasecmp(var, "locked-sound") && !zstr(val)) {
                locked_sound = val;
            } else if (!strcasecmp(var, "is-locked-sound") && !zstr(val)) {
                is_locked_sound = val;
            } else if (!strcasecmp(var, "is-unlocked-sound") && !zstr(val)) {
                is_unlocked_sound = val;
            } else if (!strcasecmp(var, "member-flags") && !zstr(val)) {
                member_flags = val;
            } else if (!strcasecmp(var, "conference-flags") && !zstr(val)) {
                conference_flags = val;
            } else if (!strcasecmp(var, "cdr-log-dir") && !zstr(val)) {
                conference_log_dir = val;
            } else if (!strcasecmp(var, "cdr-event-mode") && !zstr(val)) {
                cdr_event_mode = val;
            } else if (!strcasecmp(var, "kicked-sound") && !zstr(val)) {
                kicked_sound = val;
            } else if (!strcasecmp(var, "recording-started-sound") && !zstr(val)) {
                recording_started_sound = val;
            } else if (!strcasecmp(var, "recording-stopped-sound") && !zstr(val)) {
                recording_stopped_sound = val;
            } else if (!strcasecmp(var, "join-only-sound") && !zstr(val)) {
                join_only_sound = val;
            } else if (!strcasecmp(var, "pin") && !zstr(val)) {
                pin = val;
            } else if (!strcasecmp(var, "moderator-pin") && !zstr(val)) {
                mpin = val;
            } else if (!strcasecmp(var, "pin-retries") && !zstr(val)) {
                int tmp = atoi(val);
                if (tmp >= 0) {
                    pin_retries = tmp;
                }
            } else if (!strcasecmp(var, "pin-sound") && !zstr(val)) {
                pin_sound = val;
            } else if (!strcasecmp(var, "bad-pin-sound") && !zstr(val)) {
                bad_pin_sound = val;
            } else if (!strcasecmp(var, "energy-level") && !zstr(val)) {
                energy_level = val;
            } else if (!strcasecmp(var, "auto-gain-level") && !zstr(val)) {
                auto_gain_level = val;
            } else if (!strcasecmp(var, "caller-id-name") && !zstr(val)) {
                caller_id_name = val;
            } else if (!strcasecmp(var, "caller-id-number") && !zstr(val)) {
                caller_id_number = val;
            } else if (!strcasecmp(var, "caller-controls") && !zstr(val)) {
                caller_controls = val;
            } else if (!strcasecmp(var, "ivr-dtmf-timeout") && !zstr(val)) {
                ivr_dtmf_timeout = atoi(val);
                if (ivr_dtmf_timeout < 500) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "not very smart value for ivr-dtmf-timeout found (%d), defaulting to 500ms\n", ivr_dtmf_timeout);
                    ivr_dtmf_timeout = 500;
                }
            } else if (!strcasecmp(var, "ivr-input-timeout") && !zstr(val)) {
                ivr_input_timeout = atoi(val);
                if (ivr_input_timeout != 0 && ivr_input_timeout < 500) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "not very smart value for ivr-input-timeout found (%d), defaulting to 500ms\n", ivr_input_timeout);
                    ivr_input_timeout = 5000;
                }
            } else if (!strcasecmp(var, "moderator-controls") && !zstr(val)) {
                moderator_controls = val;
            } else if (!strcasecmp(var, "broadcast-chat-messages") && !zstr(val) && switch_true(val)) {
                broadcast_chat_messages = 1;
            } else if (!strcasecmp(var, "comfort-noise") && !zstr(val)) {
                int tmp;
                tmp = atoi(val);
                if (tmp > 1 && tmp < 10000) {
                    comfort_noise_level = tmp;
                } else if (switch_true(val)) {
                    comfort_noise_level = 1400;
                }
            } else if (!strcasecmp(var, "sound-prefix") && !zstr(val)) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "override sound-prefix with: %s\n", val);
                sound_prefix = val;
            } else if (!strcasecmp(var, "max-members") && !zstr(val)) {
                errno = 0;        /* sanity first */
                max_members = strtol(val, NULL, 0);    /* base 0 lets 0x... for hex 0... for octal and base 10 otherwise through */
                if (errno == ERANGE || errno == EINVAL || (int32_t) max_members < 0 || max_members == 1) {
                    /* a negative wont work well, and its foolish to have a conference limited to 1 person unless the outbound
                     * stuff is added, see comments above
                     */
                    max_members = 0;    /* set to 0 to disable max counts */
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "max-members %s is invalid, not setting a limit\n", val);
                }
            } else if (!strcasecmp(var, "max-members-sound") && !zstr(val)) {
                maxmember_sound = val;
            } else if (!strcasecmp(var, "max-members-sound-attendee") && !zstr(val)) {
                maxmember_sound_attendee = val;
            } else if (!strcasecmp(var, "announce-count") && !zstr(val)) {
                errno = 0;        /* safety first */
                announce_count = strtol(val, NULL, 0);
                if (errno == ERANGE || errno == EINVAL) {
                    announce_count = 0;
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "announce-count is invalid, not anouncing member counts\n");
                }
            } else if (!strcasecmp(var, "suppress-events") && !zstr(val)) {
                suppress_events = val;
            } else if (!strcasecmp(var, "verbose-events") && !zstr(val)) {
                verbose_events = val;
            } else if (!strcasecmp(var, "auto-record") && !zstr(val)) {
                auto_record = val;
            } else if (!strcasecmp(var, "min-required-recording-participants") && !zstr(val)) {
                if (!strcmp(val, "1")) {
                    min_recording_participants = 1;
                } else if (!strcmp(val, "2")) {
                    min_recording_participants = 2;
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "min-required-recording-participants is invalid, leaving set to %d\n", min_recording_participants);
                }
            } else if (!strcasecmp(var, "terminate-on-silence") && !zstr(val)) {
                terminate_on_silence = val;
            } else if (!strcasecmp(var, "endconf-grace-time") && !zstr(val)) {
                endconf_grace_time = val;
            } else if (!strcasecmp(var, "notify-active-talker") && !zstr(val)) {
                notify_active_talkers = switch_true(val) ? SWITCH_TRUE : SWITCH_FALSE;
            } else if (!strcasecmp(var, "active-talker-history-time") && !zstr(val)) {
                history_time_period = strtol(val, NULL, 0);
            } else if (!strcasecmp(var, "active-talker-reset-time") && !zstr(val)) {
                history_reset_time_period = strtol(val, NULL, 0);
            } else if (!strcasecmp(var, "begin-sound") && !zstr(val)) {
                begin_sound = val;
            }
        }

        /* Set defaults and various paramaters */

        /* Timer module to use */
        if (zstr(timer_name)) {
            timer_name = "soft";
        }

        /* Caller ID Name */
        if (zstr(caller_id_name)) {
            caller_id_name = (char *) global_app_name;
        }

        /* Caller ID Number */
        if (zstr(caller_id_number)) {
            caller_id_number = SWITCH_DEFAULT_CLID_NUMBER;
        }

        if (!pool) {
            /* Setup a memory pool to use. */
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Create conference pool\n");
            if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Pool Failure\n");
                conference = NULL;
                goto end;
            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Using Existing Pool\n");
        }

        /* Create the conference object. */
        if (!(conference = switch_core_alloc(pool, sizeof(*conference)))) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Memory Error!\n");
            conference = NULL;
            goto end;
        }

        conference->start_time = switch_epoch_time_now(NULL);
        conference->last_time_active = switch_time_now();
        conference->min_inactive_to_end = MINUTES_INACTIVE_TO_END;
        conference->ending_due_to_inactivity = SWITCH_FALSE;

        conference->stopping = SWITCH_FALSE;

        /* initialize the conference object with settings from the specified profile */
        conference->pool = pool;
        conference->profile_name = switch_core_strdup(conference->pool, cfg.profile ? switch_xml_attr_soft(cfg.profile, "name") : "none");
        if (timer_name) {
            conference->timer_name = switch_core_strdup(conference->pool, timer_name);
        }
        if (tts_engine) {
            conference->tts_engine = switch_core_strdup(conference->pool, tts_engine);
        }
        if (tts_voice) {
            conference->tts_voice = switch_core_strdup(conference->pool, tts_voice);
        }

        conference->comfort_noise_level = comfort_noise_level;
        conference->pin_retries = pin_retries;
        conference->caller_id_name = switch_core_strdup(conference->pool, caller_id_name);
        conference->caller_id_number = switch_core_strdup(conference->pool, caller_id_number);
        conference->caller_controls = switch_core_strdup(conference->pool, caller_controls);
        conference->moderator_controls = switch_core_strdup(conference->pool, moderator_controls);
        conference->broadcast_chat_messages = broadcast_chat_messages;

        if (outcall_templ) {
            conference->outcall_templ = switch_core_strdup(conference->pool, outcall_templ);
        }
        conference->run_time = switch_epoch_time_now(NULL);

        if (!zstr(conference_log_dir)) {
            char *path;

            if (!strcmp(conference_log_dir, "auto")) {
                path = switch_core_sprintf(conference->pool, "%s%sconference_cdr", SWITCH_GLOBAL_dirs.log_dir, SWITCH_PATH_SEPARATOR);
            } else if (!switch_is_file_path(conference_log_dir)) {
                path = switch_core_sprintf(conference->pool, "%s%s%s", SWITCH_GLOBAL_dirs.log_dir, SWITCH_PATH_SEPARATOR, conference_log_dir);
            } else {
                path = switch_core_strdup(conference->pool, conference_log_dir);
            }

            switch_dir_make_recursive(path, SWITCH_DEFAULT_DIR_PERMS, conference->pool);
            conference->log_dir = path;

        }

        if (!zstr(cdr_event_mode)) {
            if (!strcmp(cdr_event_mode, "content")) {
                conference->cdr_event_mode = CDRE_AS_CONTENT;
            } else if (!strcmp(cdr_event_mode, "file")) {
                if (!zstr(conference->log_dir)) {
                    conference->cdr_event_mode = CDRE_AS_FILE;
                } else {
                    conference->cdr_event_mode = CDRE_NONE;
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "'cdr-log-dir' parameter not set; CDR event mode 'file' ignored");
                }
            } else {
                conference->cdr_event_mode = CDRE_NONE;
            }
        }

        if (!zstr(perpetual_sound)) {
            conference->perpetual_sound = switch_core_strdup(conference->pool, perpetual_sound);
        }

        conference->mflags = MFLAG_CAN_SPEAK | MFLAG_CAN_HEAR | MFLAG_CAN_MUTE;

        if (!zstr(moh_sound) && switch_is_moh(moh_sound)) {
            conference->moh_sound = switch_core_strdup(conference->pool, moh_sound);
        }

        if (member_flags) {
            set_mflags(member_flags, &conference->mflags);
        }

        if (conference_flags) {
            set_cflags(conference_flags, &conference->flags);
        }

        if (!zstr(sound_prefix)) {
            conference->sound_prefix = switch_core_strdup(conference->pool, sound_prefix);
        } else {
            const char *val;
            if ((val = switch_channel_get_variable(channel, "sound_prefix")) && !zstr(val)) {
                /* if no sound_prefix was set, use the channel sound_prefix */
                conference->sound_prefix = switch_core_strdup(conference->pool, val);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "using channel sound prefix: %s\n", conference->sound_prefix);
            }
        }

        if (!zstr(enter_sound)) {
            conference->enter_sound = switch_core_strdup(conference->pool, enter_sound);
        }

        if (!zstr(exit_sound)) {
            conference->exit_sound = switch_core_strdup(conference->pool, exit_sound);
        }

        if (!zstr(chimes_on_sound)) {
            conference->chimes_on_sound = switch_core_strdup(conference->pool, chimes_on_sound);
        }

        if (!zstr(chimes_off_sound)) {
            conference->chimes_off_sound = switch_core_strdup(conference->pool, chimes_off_sound);
        }

        if (!zstr(ack_sound)) {
            conference->ack_sound = switch_core_strdup(conference->pool, ack_sound);
        }

        if (!zstr(nack_sound)) {
            conference->nack_sound = switch_core_strdup(conference->pool, nack_sound);
        }

        if (!zstr(muted_sound)) {
            conference->muted_sound = switch_core_strdup(conference->pool, muted_sound);
        }

        if (zstr(mute_detect_sound)) {
            if (!zstr(muted_sound)) {
                conference->mute_detect_sound = switch_core_strdup(conference->pool, muted_sound);
            }
        } else {
            conference->mute_detect_sound = switch_core_strdup(conference->pool, mute_detect_sound);
        }

        if (!zstr(unmuted_sound)) {
            conference->unmuted_sound = switch_core_strdup(conference->pool, unmuted_sound);
        }

        if (!zstr(muted_all_sound)) {
            conference->muted_all_sound = switch_core_strdup(conference->pool, muted_all_sound);
        }

        if (!zstr(unmuted_all_sound)) {
            conference->unmuted_all_sound = switch_core_strdup(conference->pool, unmuted_all_sound);
        }

        if (!zstr(mutes_locked_sound)) {
            conference->mutes_locked_sound = switch_core_strdup(conference->pool, mutes_locked_sound);
        }

        if (!zstr(mutes_unlocked_sound)) {
            conference->mutes_unlocked_sound = switch_core_strdup(conference->pool, mutes_unlocked_sound);
        }

        if (!zstr(kicked_sound)) {
            conference->kicked_sound = switch_core_strdup(conference->pool, kicked_sound);
        }

        if (!zstr(recording_started_sound)) {
            conference->recording_started_sound = switch_core_strdup(conference->pool, recording_started_sound);
        }

        if (!zstr(recording_stopped_sound)) {
            conference->recording_stopped_sound = switch_core_strdup(conference->pool, recording_stopped_sound);
            if (!zstr(join_only_sound)) {
                conference->join_only_sound = switch_core_strdup(conference->pool, join_only_sound);
            }

            if (!zstr(pin_sound)) {
                conference->pin_sound = switch_core_strdup(conference->pool, pin_sound);
            }

            if (!zstr(bad_pin_sound)) {
                conference->bad_pin_sound = switch_core_strdup(conference->pool, bad_pin_sound);
            }

            if (!zstr(pin)) {
                conference->pin = switch_core_strdup(conference->pool, pin);
            }

            if (!zstr(mpin)) {
                conference->mpin = switch_core_strdup(conference->pool, mpin);
            }

            if (!zstr(alone_sound)) {
                conference->alone_sound = switch_core_strdup(conference->pool, alone_sound);
            }

            if (!zstr(alone_sound_attendee)) {
                conference->alone_sound_attendee = switch_core_strdup(conference->pool, alone_sound_attendee);
            }

            if (!zstr(locked_sound)) {
                conference->locked_sound = switch_core_strdup(conference->pool, locked_sound);
            }

            if (!zstr(is_locked_sound)) {
                conference->is_locked_sound = switch_core_strdup(conference->pool, is_locked_sound);
            }

            if (!zstr(is_unlocked_sound)) {
                conference->is_unlocked_sound = switch_core_strdup(conference->pool, is_unlocked_sound);
            }

            if (!zstr(energy_level)) {
                conference->energy_level = atoi(energy_level);
                if (conference->energy_level < 0) {
                    conference->energy_level = 0;
                }
            }

            if (!zstr(auto_gain_level)) {
                int level = 0;

                if (switch_true(auto_gain_level) && !switch_is_number(auto_gain_level)) {
                    level = DEFAULT_AGC_LEVEL;
                } else {
                    level = atoi(auto_gain_level);
                }

                if (level > 0 && level > conference->energy_level) {
                    conference->agc_level = level;
                }
            }

            if (!zstr(maxmember_sound)) {
                conference->maxmember_sound = switch_core_strdup(conference->pool, maxmember_sound);
            }

            if (!zstr(maxmember_sound_attendee)) {
                conference->maxmember_sound_attendee = switch_core_strdup(conference->pool, maxmember_sound_attendee);
            }

            /* its going to be 0 by default, set to a value otherwise so this should be safe */
            conference->max_members = max_members;
            conference->announce_count = announce_count;

            conference->name = switch_core_strdup(conference->pool, name);

            if ((name_domain = strchr(conference->name, '@'))) {
                name_domain++;
                conference->domain = switch_core_strdup(conference->pool, name_domain);
            } else if (domain) {
                conference->domain = switch_core_strdup(conference->pool, domain);
            } else if (presence_id && (name_domain = strchr(presence_id, '@'))) {
                name_domain++;
                conference->domain = switch_core_strdup(conference->pool, name_domain);
            } else {
                conference->domain = "cluecon.com";
            }

            conference->rate = rate;
            conference->interval = interval;
            conference->ivr_dtmf_timeout = ivr_dtmf_timeout;
            conference->ivr_input_timeout = ivr_input_timeout;

            conference->eflags = 0xFFFFFFFF;
            if (!zstr(suppress_events)) {
                clear_eflags(suppress_events, &conference->eflags);
            }

            if (!zstr(auto_record)) {
                conference->auto_record = switch_core_strdup(conference->pool, auto_record);
            }

            conference->min_recording_participants = min_recording_participants;

            if (!zstr(desc)) {
                conference->desc = switch_core_strdup(conference->pool, desc);
            }

            if (!zstr(terminate_on_silence)) {
                conference->terminate_on_silence = atoi(terminate_on_silence);
            }
            if (!zstr(endconf_grace_time)) {
                conference->endconf_grace_time = atoi(endconf_grace_time);
            }

            if (!zstr(verbose_events) && switch_true(verbose_events)) {
                conference->verbose_events = 1;
            }
        }

        /* Create the conference unique identifier */
        switch_uuid_get(&uuid);
        switch_uuid_format(uuid_str, &uuid);
        conference->uuid_str = switch_core_strdup(conference->pool, uuid_str);

        /* Set enter sound and exit sound flags so that default is on */
        set_conference_state_unlocked(conference, CFLAG_ENTER_SOUND);
        set_conference_state_unlocked(conference, CFLAG_EXIT_SOUND);

        /* Activate the conference mutex for exclusivity */
        switch_mutex_init(&conference->mutex, SWITCH_MUTEX_NESTED, conference->pool);
        switch_mutex_init(&conference->flag_mutex, SWITCH_MUTEX_NESTED, conference->pool);
        switch_thread_rwlock_create(&conference->rwlock, conference->pool);
        switch_mutex_init(&conference->member_mutex, SWITCH_MUTEX_NESTED, conference->pool);

        switch_mutex_lock(globals.hash_mutex);
        set_conference_state_unlocked(conference, CFLAG_INHASH);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Insert conference %s in hash\n", conference->name);
        switch_core_hash_insert(globals.conference_hash, conference->name, conference);
        switch_mutex_unlock(globals.hash_mutex);

        conference->member_id_counter = 0;
        conference->debug_stats_pool = NULL;

        conference->notify_active_talkers = notify_active_talkers;
        conference->history_time_period = history_time_period;
        conference->history_reset_time_period = history_reset_time_period;

        conference->meeting_id[0] = 0;
        conference->instance_id[0] = 0;

        if (!zstr(begin_sound)) {
            conference->begin_sound = switch_core_strdup(conference->pool, begin_sound);
        }
    
        /* fuze encoder optimization: allocation */
        ceo_initilialize(&conference->ceo, conference->pool);

end:

        switch_mutex_unlock(globals.hash_mutex);

        return conference;
}

/* 15000us or 15ms */
#define MIN_PROCESS_AVG 5000.0
#define MAX_PARTICIPANTS 400

float calculate_thread_utilization(int idx) {
    float avg = 0;
    for (int j = 0; j < PROCESS_AVG_CNT; j++) {
        avg += globals.outputll[idx].process_avg[j]/PROCESS_AVG_CNT;
    }
    return avg;
}

static int output_loop_list_add(conference_obj_t *conference, output_loop_t *ol) {
    int lowest = 0;
    float highest_avg = 0, avg = 0;
    int start;
    switch_bool_t first;
    int idx;

    switch_mutex_lock(globals.outputlllock);
    first = (conference->list_idx == -1);
    if (first) {
        int i;
        for (i = 0; i < MAX_NUMBER_OF_OUTPUT_NTHREADS; i++) {
            if (globals.output_thread_dead[i] > 10) {
                continue;
            }
            if (globals.outputll[i].count == 0) {
                start = i;
                break;
            }
        }
        if (i == MAX_NUMBER_OF_OUTPUT_NTHREADS) {
            start = globals.start;
            globals.start = (globals.start + 1) % MAX_NUMBER_OF_OUTPUT_NTHREADS;
        }
    } else {
        start = conference->list_idx;
    }
    if (first) {
        for (int i = 0; i < MAX_NUMBER_OF_OUTPUT_NTHREADS; i++) {
            avg = 0;
            idx = (start + i) % MAX_NUMBER_OF_OUTPUT_NTHREADS;

            if (globals.output_thread_dead[idx] > 100) {
                if (idx == lowest) {
                    lowest = (lowest + 1) % MAX_NUMBER_OF_OUTPUT_NTHREADS;
                }
                continue;
            }

            avg = calculate_thread_utilization(idx);

            if  (avg > MIN_PROCESS_AVG && globals.outputll[idx].count < MAX_PARTICIPANTS) {
                lowest = idx;
                break;
            } else {
                if (idx == start) {
                    highest_avg = avg;
                } else if (avg > highest_avg && globals.outputll[idx].count < MAX_PARTICIPANTS) {
                    highest_avg = avg;
                    lowest = idx;
                }
            }
        }
    } else {
        for (idx = conference->list_idx; idx < MAX_NUMBER_OF_OUTPUT_THREADS; idx += MAX_NUMBER_OF_OUTPUT_NTHREADS) {
            if (globals.outputll[idx].count < MAX_PARTICIPANTS) {
                lowest = idx;
                break;
            }
        }
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ol->member->session), SWITCH_LOG_INFO, "Adding member to list: %d utilization:%f part=%d first=%d\n",
                      lowest, calculate_thread_utilization(lowest), globals.outputll[lowest].count, first);

    switch_mutex_lock(globals.outputll[lowest].lock);
    if (globals.outputll[lowest].loop) {
        output_loop_t *olp;
        for (olp = globals.outputll[lowest].loop; olp->next; olp = olp->next) {
        }
        olp->next = ol;
        ol->next = NULL;
    } else {
        ol->next = globals.outputll[lowest].loop;
        globals.outputll[lowest].loop = ol;
    }
    ol->list_idx = lowest;
    if (first) {
        conference->list_idx = lowest;
    }
    globals.outputll[lowest].count += 1;
    switch_mutex_unlock(globals.outputll[lowest].lock);
    switch_mutex_unlock(globals.outputlllock);

    return lowest;
}

int output_loop_list_remove(conference_obj_t *conference, output_loop_t *ol) {
    int idx = ol->list_idx;
    int ret;
    output_loop_t *iol, *iollast = NULL;

    switch_mutex_lock(globals.outputlllock);
    switch_mutex_lock(globals.outputll[idx].lock);
    for (iol = globals.outputll[idx].loop; iol; iol = iol->next) {
        if (iol == ol) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(ol->member->session), SWITCH_LOG_INFO,
                              "Removing from output loop list!\n");
            if (iollast) {
                iollast->next = ol->next;
            } else {
                globals.outputll[idx].loop = ol->next;
            }
            break;
        }
        iollast = iol;
    }

    globals.outputll[idx].count -= 1;

    ret = globals.outputll[idx].count;

    switch_mutex_unlock(globals.outputll[idx].lock);
    switch_mutex_unlock(globals.outputlllock);

    return ret;
}

static void conference_send_presence(conference_obj_t *conference)
{
    switch_event_t *event;

    if (switch_event_create(&event, SWITCH_EVENT_PRESENCE_IN) == SWITCH_STATUS_SUCCESS) {
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "proto", CONF_CHAT_PROTO);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "login", conference->name);
        if (strchr(conference->name, '@')) {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "from", conference->name);
        } else {
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "from", "%s@%s", conference->name, conference->domain);
        }

        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "event_type", "presence");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "alt_event_type", "dialog");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "event_count", "%d", EC++);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "unique-id", conference->name);

        if (conference->count) {
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "force-status", "Active (%d caller%s)", conference->count, conference->count == 1 ? "" : "s");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "channel-state", "CS_ROUTING");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "answer-state", conference->count == 1 ? "early" : "confirmed");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "presence-call-direction", conference->count == 1 ? "outbound" : "inbound");
        } else {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "force-status", "Inactive");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "channel-state", "CS_HANGUP");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "answer-state", "terminated");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "call-direction", "inbound");
        }



        switch_event_fire(&event);
    }

}
#if 0
static uint32_t kickall_matching_var(conference_obj_t *conference, const char *var, const char *val)
{
    conference_member_t *member = NULL;
    const char *vval = NULL;
    uint32_t r = 0;

    switch_mutex_lock(conference->mutex);
    switch_mutex_lock(conference->member_mutex);

    for (int i = 0; i < eMemberListTypes_Recorders; i++) {
        for (member = conference->member_lists[i]; member; member = member->next) {
            switch_channel_t *channel = NULL;

            if (switch_test_flag(member, MFLAG_NOCHANNEL)) {
                continue;
            }

            channel = switch_core_session_get_channel(member->session);
            vval = switch_channel_get_variable(channel, var);

            if (vval && !strcmp(vval, val)) {
                set_member_state_locked(member, MFLAG_KICKED);
                clear_member_state_locked(member, MFLAG_RUNNING);
                switch_core_session_kill_channel(member->session, SWITCH_SIG_BREAK);
                r++;
            }
        }
    }
    
    switch_mutex_unlock(conference->member_mutex);
    switch_mutex_unlock(conference->mutex);

    return r;
}
#endif

static void call_setup_event_handler(switch_event_t *event)
{
    switch_status_t status = SWITCH_STATUS_FALSE;
    conference_obj_t *conference = NULL;
    char *conf = switch_event_get_header(event, "Target-Component");
    char *domain = switch_event_get_header(event, "Target-Domain");
    char *dial_str = switch_event_get_header(event, "Request-Target");
    char *dial_uri = switch_event_get_header(event, "Request-Target-URI");
    char *action = switch_event_get_header(event, "Request-Action");
    char *ext = switch_event_get_header(event, "Request-Target-Extension");
    char *ext_domain = switch_event_get_header(event, "Request-Target-Domain");
    char *full_url = switch_event_get_header(event, "full_url");
    char *call_id = switch_event_get_header(event, "Request-Call-ID");

    if (!ext) ext = dial_str;

    if (!zstr(conf) && !zstr(dial_str) && !zstr(action) && (conference = conference_find(conf, domain))) {
        switch_event_t *var_event;
        switch_event_header_t *hp;

        if (switch_test_flag(conference, CFLAG_RFC4579)) {
            char *key = switch_mprintf("conf_%s_%s_%s_%s", conference->name, conference->domain, ext, ext_domain);
            char *expanded = NULL, *ostr = dial_str;

            if (!strcasecmp(action, "call")) {
                if((conference->max_members > 0) && (conference->count >= conference->max_members)) {
                    // Conference member limit has been reached; do not proceed with setup request
                    status = SWITCH_STATUS_FALSE;
                } else {
                    if (switch_event_create_plain(&var_event, SWITCH_EVENT_CHANNEL_DATA) != SWITCH_STATUS_SUCCESS) {
                        abort();
                    }

                    for(hp = event->headers; hp; hp = hp->next) {
                        if (!strncasecmp(hp->name, "var_", 4)) {
                            switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, hp->name + 4, hp->value);
                        }
                    }

                    switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, "conference_call_key", key);
                    switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, "conference_destination_number", ext);

                    switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, "conference_invite_uri", dial_uri);

                    switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, "conference_track_status", "true");
                    switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, "conference_track_call_id", call_id);
                    switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, "sip_invite_domain", domain);
                    switch_event_add_header_string(var_event, SWITCH_STACK_BOTTOM, "sip_invite_contact_params", "~isfocus");

                    if (!strncasecmp(ostr, "url+", 4)) {
                        ostr += 4;
                    } else if (!switch_true(full_url) && conference->outcall_templ) {
                        if ((expanded = switch_event_expand_headers(var_event, conference->outcall_templ))) {
                            ostr = expanded;
                        }
                    }

                    status = conference_outcall_bg(conference, NULL, NULL, ostr, 60, NULL, NULL, NULL, NULL, NULL, NULL, &var_event);

                    if (expanded && expanded != conference->outcall_templ) {
                        switch_safe_free(expanded);
                    }
                }

            } else if (!strcasecmp(action, "end")) {
                if (switch_core_session_hupall_matching_var("conference_call_key", key, SWITCH_CAUSE_NORMAL_CLEARING)) {
                    send_conference_notify(conference, "SIP/2.0 200 OK\r\n", call_id, SWITCH_TRUE);
                } else {
                    send_conference_notify(conference, "SIP/2.0 481 Failure\r\n", call_id, SWITCH_TRUE);
                }
                status = SWITCH_STATUS_SUCCESS;
            }

            switch_safe_free(key);
        } else { // Conference found but doesn't support referral.
            status = SWITCH_STATUS_FALSE;
        }


        switch_thread_rwlock_unlock(conference->rwlock);
    } else { // Couldn't find associated conference.  Indicate failure on refer subscription
        status = SWITCH_STATUS_FALSE;
    }

    if(status != SWITCH_STATUS_SUCCESS) {
        // Unable to setup call, need to generate final NOTIFY
        if (switch_event_create(&event, SWITCH_EVENT_CONFERENCE_DATA) == SWITCH_STATUS_SUCCESS) {
            event->flags |= EF_UNIQ_HEADERS;

            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "conference-name", conf);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "conference-domain", domain);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "conference-event", "refer");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "call_id", call_id);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "final", "true");
            switch_event_add_body(event, "%s", "SIP/2.0 481 Failure\r\n");
            switch_event_fire(&event);
        }
    }

}

static void conf_data_event_handler(switch_event_t *event)
{
    switch_event_t *revent;
    char *name = switch_event_get_header(event, "conference-name");
    char *domain = switch_event_get_header(event, "conference-domain");
    conference_obj_t *conference = NULL;
    char *body = NULL;

    if (!zstr(name) && (conference = conference_find(name, domain))) {
        if (switch_test_flag(conference, CFLAG_RFC4579)) {
            switch_event_dup(&revent, event);
            revent->event_id = SWITCH_EVENT_CONFERENCE_DATA;
            revent->flags |= EF_UNIQ_HEADERS;
            switch_event_add_header(revent, SWITCH_STACK_TOP, "Event-Name", "CONFERENCE_DATA");

            body = conference_rfc4579_render(conference, event, revent);
            switch_event_add_body(revent, "%s", body);
            switch_event_fire(&revent);
            switch_safe_free(body);
        }
        switch_thread_rwlock_unlock(conference->rwlock);
    }
}


static void pres_event_handler(switch_event_t *event)
{
    char *to = switch_event_get_header(event, "to");
    char *domain_name = NULL;
    char *dup_to = NULL, *conf_name, *dup_conf_name = NULL;
    conference_obj_t *conference;

    if (!to || strncasecmp(to, "conf+", 5) || !strchr(to, '@')) {
        return;
    }

    if (!(dup_to = strdup(to))) {
        return;
    }


    conf_name = dup_to + 5;

    if ((domain_name = strchr(conf_name, '@'))) {
        *domain_name++ = '\0';
    }

    dup_conf_name = switch_mprintf("%q@%q", conf_name, domain_name);


    if ((conference = conference_find(conf_name, NULL)) || (conference = conference_find(dup_conf_name, NULL))) {
        if (switch_event_create(&event, SWITCH_EVENT_PRESENCE_IN) == SWITCH_STATUS_SUCCESS) {
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "proto", CONF_CHAT_PROTO);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "login", conference->name);
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "from", "%s@%s", conference->name, conference->domain);


            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "force-status", "Active (%d caller%s)", conference->count, conference->count == 1 ? "" : "s");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "event_type", "presence");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "alt_event_type", "dialog");
            switch_event_add_header(event, SWITCH_STACK_BOTTOM, "event_count", "%d", EC++);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "unique-id", conf_name);
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "channel-state", "CS_ROUTING");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "answer-state", conference->count == 1 ? "early" : "confirmed");
            switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "call-direction", conference->count == 1 ? "outbound" : "inbound");
            switch_event_fire(&event);
        }
        switch_thread_rwlock_unlock(conference->rwlock);
    } else if (switch_event_create(&event, SWITCH_EVENT_PRESENCE_IN) == SWITCH_STATUS_SUCCESS) {
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "proto", CONF_CHAT_PROTO);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "login", conf_name);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "from", to);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "force-status", "Idle");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "rpid", "unknown");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "event_type", "presence");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "alt_event_type", "dialog");
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "event_count", "%d", EC++);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "unique-id", conf_name);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "channel-state", "CS_HANGUP");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "answer-state", "terminated");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "call-direction", "inbound");
        switch_event_fire(&event);
    }

    switch_safe_free(dup_to);
    switch_safe_free(dup_conf_name);
}

static void send_presence(switch_event_types_t id)
{
    switch_xml_t cxml, cfg, advertise, room;
    switch_event_t *params = NULL;

    switch_event_create(&params, SWITCH_EVENT_COMMAND);
    switch_assert(params);
    switch_event_add_header_string(params, SWITCH_STACK_BOTTOM, "presence", "true");


    /* Open the config from the xml registry */
    if (!(cxml = switch_xml_open_cfg(global_cf_name, &cfg, params))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", global_cf_name);
        goto done;
    }

    if ((advertise = switch_xml_child(cfg, "advertise"))) {
        for (room = switch_xml_child(advertise, "room"); room; room = room->next) {
            char *name = (char *) switch_xml_attr_soft(room, "name");
            char *status = (char *) switch_xml_attr_soft(room, "status");
            switch_event_t *event;

            if (name && switch_event_create(&event, id) == SWITCH_STATUS_SUCCESS) {
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "proto", CONF_CHAT_PROTO);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "login", name);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "from", name);
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "force-status", status ? status : "Available");
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "rpid", "unknown");
                switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "event_type", "presence");
                switch_event_fire(&event);
            }
        }
    }

  done:
    switch_event_destroy(&params);

    /* Release the config registry handle */
    if (cxml) {
        switch_xml_free(cxml);
        cxml = NULL;
    }
}

typedef void (*conf_key_callback_t) (conference_member_t *, struct caller_control_actions *);

typedef struct {
    conference_member_t *member;
    caller_control_action_t action;
    conf_key_callback_t handler;
} key_binding_t;


static switch_status_t dmachine_dispatcher(switch_ivr_dmachine_match_t *match)
{
    key_binding_t *binding = match->user_data;
    switch_channel_t *channel;

    if (!binding) return SWITCH_STATUS_FALSE;

    channel = switch_core_session_get_channel(binding->member->session);
    switch_channel_set_variable(channel, "conference_last_matching_digits", match->match_digits);

    if (binding->action.data) {
        binding->action.expanded_data = switch_channel_expand_variables(channel, binding->action.data);
    }

    binding->handler(binding->member, &binding->action);

    if (binding->action.expanded_data != binding->action.data) {
        free(binding->action.expanded_data);
        binding->action.expanded_data = NULL;
    }

    set_member_state_locked(binding->member, MFLAG_FLUSH_BUFFER);

    return SWITCH_STATUS_SUCCESS;
}

static void do_binding(conference_member_t *member, conf_key_callback_t handler, const char *digits, const char *data)
{
    key_binding_t *binding;

    binding = switch_core_alloc(member->pool, sizeof(*binding));
    binding->member = member;

    binding->action.binded_dtmf = switch_core_strdup(member->pool, digits);

    if (data) {
        binding->action.data = switch_core_strdup(member->pool, data);
    }

    binding->handler = handler;
    switch_ivr_dmachine_bind(member->dmachine, "conf", digits, 0, dmachine_dispatcher, binding);

}

struct _mapping {
    const char *name;
    conf_key_callback_t handler;
};

static struct _mapping control_mappings[] = {
    {"mute", conference_loop_mute_toggle},
    {"mute on", conference_loop_fn_mute_on},
    {"mute off", conference_loop_fn_mute_off},
    {"mute all", conference_loop_fn_mute_all_toggle},
    {"deaf mute", conference_loop_fn_deafmute_toggle},
    {"energy up", conference_loop_fn_energy_up},
    {"energy equ", conference_loop_fn_energy_equ_conf},
    {"energy dn", conference_loop_fn_energy_dn},
    {"vol talk up", conference_loop_fn_volume_talk_up},
    {"vol talk zero", conference_loop_fn_volume_talk_zero},
    {"vol talk dn", conference_loop_fn_volume_talk_dn},
    {"vol listen up", conference_loop_fn_volume_listen_up},
    {"vol listen zero", conference_loop_fn_volume_listen_zero},
    {"vol listen dn", conference_loop_fn_volume_listen_dn},
    {"hangup", conference_loop_fn_hangup},
    {"event", conference_loop_fn_event},
    {"lock", conference_loop_fn_lock_toggle},
    {"transfer", conference_loop_fn_transfer},
    {"execute_application", conference_loop_fn_exec_app},
    {"floor", conference_loop_fn_floor_toggle},
    {"enforce_floor", conference_loop_fn_enforce_floor},
    {"caller count", conference_loop_fn_count},
    {"operator", conference_loop_fn_operator},
    {"mute lock", conference_loop_fn_mute_lock_all_toggle},
    {"mute lock self", conference_loop_mutelock_toggle},
    {"vid-floor", conference_loop_fn_vid_floor_toggle},
    {"vid-floor-force", conference_loop_fn_vid_floor_force}
};
#define MAPPING_LEN (sizeof(control_mappings)/sizeof(control_mappings[0]))

static void member_bind_controls(conference_member_t *member, const char *controls)
{
    switch_xml_t cxml, cfg, xgroups, xcontrol;
    switch_event_t *params;
    int i;

    switch_event_create(&params, SWITCH_EVENT_REQUEST_PARAMS);
    switch_event_add_header_string(params, SWITCH_STACK_BOTTOM, "Conf-Name", member->conference->name);
    switch_event_add_header_string(params, SWITCH_STACK_BOTTOM, "Action", "request-controls");
    switch_event_add_header_string(params, SWITCH_STACK_BOTTOM, "Controls", controls);

    if (!(cxml = switch_xml_open_cfg(global_cf_name, &cfg, params))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", global_cf_name);
        goto end;
    }

    if (!(xgroups = switch_xml_child(cfg, "caller-controls"))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Can't find caller-controls in %s\n", global_cf_name);
        goto end;
    }

    if (!(xgroups = switch_xml_find_child(xgroups, "group", "name", controls))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Can't find caller-controls in %s\n", global_cf_name);
        goto end;
    }


    for (xcontrol = switch_xml_child(xgroups, "control"); xcontrol; xcontrol = xcontrol->next) {
        const char *key = switch_xml_attr(xcontrol, "action");
        const char *digits = switch_xml_attr(xcontrol, "digits");
        const char *data = switch_xml_attr_soft(xcontrol, "data");

        if (zstr(key) || zstr(digits)) continue;

        for(i = 0; i < MAPPING_LEN; i++) {
            if (!strcasecmp(key, control_mappings[i].name)) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s binding '%s' to '%s'\n",
                                  switch_core_session_get_name(member->session), digits, key);

                do_binding(member, control_mappings[i].handler, digits, data);
            }
        }
    }

 end:

    /* Release the config registry handle */
    if (cxml) {
        switch_xml_free(cxml);
        cxml = NULL;
    }

    if (params) switch_event_destroy(&params);

}




/* Called by FreeSWITCH when the module loads */
SWITCH_MODULE_LOAD_FUNCTION(mod_conference_load)
{
    uint32_t i;
    size_t nl, ol = 0;
    char *p = NULL, *tmp = NULL;
    switch_chat_interface_t *chat_interface;
    switch_api_interface_t *api_interface;
    switch_application_interface_t *app_interface;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char cmd_str[256];

    memset(&globals, 0, sizeof(globals));

    /* Connect my internal structure to the blank pointer passed to me */
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    switch_console_add_complete_func("::conference::list_conferences", list_conferences);


    switch_event_channel_bind("conference", conference_event_channel_handler, &globals.event_channel_id);
    switch_event_channel_bind("conference-liveArray", conference_la_event_channel_handler, &globals.event_channel_id);

    /* build api interface help ".syntax" field string */
    p = strdup("");
    for (i = 0; i < CONFFUNCAPISIZE; i++) {
        nl = strlen(conf_api_sub_commands[i].pcommand) + strlen(conf_api_sub_commands[i].psyntax) + 5;

        switch_snprintf(cmd_str, sizeof(cmd_str), "add conference ::conference::list_conferences %s", conf_api_sub_commands[i].pcommand);
        switch_console_set_complete(cmd_str);

        if (p != NULL) {
            ol = strlen(p);
        }
        tmp = realloc(p, ol + nl);
        if (tmp != NULL) {
            p = tmp;
            strcat(p, "\t\t");
            strcat(p, conf_api_sub_commands[i].pcommand);
            if (!zstr(conf_api_sub_commands[i].psyntax)) {
                strcat(p, " ");
                strcat(p, conf_api_sub_commands[i].psyntax);
            }
            if (i < CONFFUNCAPISIZE - 1) {
                strcat(p, "\n");
            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't realloc\n");
            return SWITCH_STATUS_TERM;
        }

    }
    api_syntax = p;

    /* create/register custom event message type */
    if (switch_event_reserve_subclass(CONF_EVENT_MAINT) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!\n", CONF_EVENT_MAINT);
        return SWITCH_STATUS_TERM;
    }

    /* Setup the pool */
    if (switch_core_new_memory_pool(&globals.conference_pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Pool Failure\n");
        return SWITCH_STATUS_TERM;
    }

    /* Setup a hash to store conferences by name */
    switch_core_hash_init(&globals.conference_hash);
    switch_mutex_init(&globals.conference_mutex, SWITCH_MUTEX_NESTED, globals.conference_pool);
    switch_mutex_init(&globals.id_mutex, SWITCH_MUTEX_NESTED, globals.conference_pool);
    switch_mutex_init(&globals.hash_mutex, SWITCH_MUTEX_NESTED, globals.conference_pool);
    switch_mutex_init(&globals.setup_mutex, SWITCH_MUTEX_NESTED, globals.conference_pool);
    switch_mutex_init(&globals.filelist_mutex, SWITCH_MUTEX_NESTED, globals.conference_pool);

    for (int i = 0; i < MAX_NUMBER_OF_OUTPUT_THREADS; i++) {
        globals.filelist[i] = NULL;
    }

    globals.thread_pool = globals.conference_pool;

#if 0
    /* luke define this based on number of cores */
    if (switch_core_new_memory_pool(&globals.thread_pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Pool Failure\n");
        return SWITCH_STATUS_TERM;
    }
#endif

    switch_mutex_init(&globals.outputlllock, SWITCH_MUTEX_NESTED, globals.thread_pool);

    globals.number_of_output_threads = MAX_NUMBER_OF_OUTPUT_THREADS;
    globals.start = 0;

    globals.playlist_pool = globals.conference_pool;
#if 0
    if (switch_core_new_memory_pool(&globals.playlist_pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Pool Failure\n");
        return SWITCH_STATUS_TERM;
    }
#endif

    for (int i = MAX_NUMBER_OF_OUTPUT_THREADS-1; i >= 0; i--) {
        switch_mutex_init(&globals.outputll[i].lock, SWITCH_MUTEX_NESTED, globals.thread_pool);
        globals.output_thread_time[i] = switch_time_now();
        globals.output_thread_dead[i] = 0;
        globals.outputll[i].loop = NULL;
        globals.outputll[i].tid = 0;
        globals.outputll[i].count = 0;
        globals.outputll[i].idx = i;
        globals.outputll[i].process_avg_idx = 0;
        for (int j = 0; j < PROCESS_AVG_CNT; j++) {
            globals.outputll[i].process_avg[j] = 20000;
            globals.outputll[i].process_avg_min[j] = 20000;
        }

        switch_mutex_init(&globals.outputll[i].cond_mutex, SWITCH_MUTEX_NESTED, globals.thread_pool);
        switch_thread_cond_create(&globals.outputll[i].cond, globals.thread_pool);

        launch_conference_loop_output(i, globals.thread_pool);
    }

    /* Subscribe to presence request events */
    if (switch_event_bind(modname, SWITCH_EVENT_PRESENCE_PROBE, SWITCH_EVENT_SUBCLASS_ANY, pres_event_handler, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't subscribe to presence request events!\n");
    }

    if (switch_event_bind(modname, SWITCH_EVENT_CONFERENCE_DATA_QUERY, SWITCH_EVENT_SUBCLASS_ANY, conf_data_event_handler, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't subscribe to conference data query events!\n");
    }

    if (switch_event_bind(modname, SWITCH_EVENT_CALL_SETUP_REQ, SWITCH_EVENT_SUBCLASS_ANY, call_setup_event_handler, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't subscribe to conference data query events!\n");
    }

    SWITCH_ADD_API(api_interface, "conference", "Conference module commands", conf_api_main, p);
    SWITCH_ADD_APP(app_interface, global_app_name, global_app_name, NULL, conference_function, NULL, SAF_NONE);
    SWITCH_ADD_APP(app_interface, "conference_set_auto_outcall", "conference_set_auto_outcall", NULL, conference_auto_function, NULL, SAF_NONE);
    SWITCH_ADD_CHAT(chat_interface, CONF_CHAT_PROTO, chat_send);


    send_presence(SWITCH_EVENT_PRESENCE_IN);

    globals.running = 1;

    WebRtcNetEQ_RegisterLogCB(switch_log_print);

    /* indicate that the module should continue to be loaded */
    return status;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_conference_shutdown)
{
    if (globals.running) {

        /* signal all threads to shutdown */
        globals.running = 0;

        switch_event_channel_unbind(NULL, conference_event_channel_handler);
        switch_event_channel_unbind(NULL, conference_la_event_channel_handler);

        switch_console_del_complete_func("::conference::list_conferences");

        /* wait for all threads */
        while (globals.threads) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Waiting for %d threads\n", globals.threads);
            switch_yield(100000);
        }

        switch_event_unbind_callback(pres_event_handler);
        switch_event_unbind_callback(conf_data_event_handler);
        switch_event_unbind_callback(call_setup_event_handler);
        switch_event_free_subclass(CONF_EVENT_MAINT);

        /* free api interface help ".syntax" field string */
        switch_safe_free(api_syntax);
    }
    switch_core_hash_destroy(&globals.conference_hash);

    return SWITCH_STATUS_SUCCESS;
}

static int conference_can_log_key(const char *key)
{
    int i;
    int n = ARRAY_NUM_ELEM(log_filter);

    if (!key)
        return 0;

    /*
     * We need to store the filter elements in the sorted order so that
     * we can do binary search. But since we call this only at the end of the call
     * and since we have only limited keys, linear search is fine for now.
     */
    for(i = 0; i < n; i++)
    {
        if (!strcmp(log_filter[i], key))
            return 1;
    }

    return 0;
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