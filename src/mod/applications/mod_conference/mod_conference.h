#ifndef MOD_CONFERENCE_H
#define MOD_CONFERENCE_H

#include <switch.h>
#include "interface/webrtc_neteq_if.h"
#include "switch_monitor.h"
#include "conference_optimization.h"
#include "conference_utils.h"
#include <switch_cJSON.h>


//#define OPENAL_POSITIONING 1

#ifdef OPENAL_POSITIONING
#define AL_ALEXT_PROTOTYPES
#include <AL/al.h>
#include <AL/alc.h>
#include <AL/alext.h>
#endif

#define DEFAULT_AGC_LEVEL 1100
#define CONFERENCE_UUID_VARIABLE "conference_uuid"

#define CPU_UTIL_PERIOD (5*6*500)
#define MINUTES_INACTIVE_TO_END 120

typedef enum {
  CONF_SILENT_REQ = (1 << 0),
  CONF_SILENT_DONE = (1 << 1)
} conf_app_flag_t;

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
  MFLAG_CLIENT_SIDE_TONES = (1 << 24),
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
 * globals.othreads: Threads that are used for conference overflow                                                                                                                          
 */
//#define MAX_NUMBER_OF_OUTPUT_NTHREADS 12                                                                                                                                                  
//#define globals.othreads ((N_CWC-1)*MAX_NUMBER_OF_OUTPUT_NTHREADS)                                                                                                                        
//#define globals.tthreads (MAX_NUMBER_OF_OUTPUT_NTHREADS+globals.othreads)                                                                                                                 

/* Fuze Encoder Optimization */

/* Some things are different for Opus */
#define OPUS_CHECK_FREQ 10
#define OPUS_MIN_LOSS 0
#define OPUS_MAX_LOSS 50
#define OPUS_IANACODE 116

typedef struct {
  uint32_t loss;
  uint32_t samplerate;
  uint32_t bitrate;
  int channels;
} opus_profile_t;

//#define STEREO 1

#ifdef STEREO
#define OPUS_PROFILES 8
#else
#define OPUS_PROFILES 7
#endif

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
  switch_thread_id_t tid;
  switch_time_t rx_time, max_time, rx_period_start;
} input_loop_data_t;

struct participant_thread_data;
typedef struct participant_thread_data participant_thread_data_t;

struct participant_thread_data {
  struct participant_thread_data *next;
  input_loop_data_t *ild;
  int list_idx;
  int initial_list_idx;
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
  switch_bool_t debug;
  int stopping;

  /* condition variable to synchronize "overflow" threads */
  switch_thread_cond_t *cond;
  switch_mutex_t *cond_mutex;
};

#define PROCESS_AVG_CNT 3

typedef struct {
  switch_mutex_t *lock;
  participant_thread_data_t *loop;
  switch_thread_id_t tid;
  int idx;
  int count;
  int process_avg_idx;
  switch_bool_t full;

  float process_avg[PROCESS_AVG_CNT];
  float process_avg_min[PROCESS_AVG_CNT];

  switch_thread_cond_t *cond;
  switch_mutex_t *cond_mutex;

  switch_time_t lock_time;

  uint64_t signaled;
  uint64_t run;
} conference_thread_data_t;

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

#ifdef OPENAL_POSITIONING
typedef struct al_handle_s {
  switch_mutex_t *mutex;
  ALCdevice *device;
  ALCcontext *context;
  ALuint source;
  ALuint buffer_in[2];
  int setpos;
  ALfloat pos_x;
  ALfloat pos_y;
  ALfloat pos_z;

  float al_position;
  float al_offset;
  float al_sign;

} al_handle_t;

void conference_al_close(al_handle_t *al);
#else
typedef struct al_handle_s {
  int unsupported;
  switch_mutex_t *mutex;
} al_handle_t;
#endif

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
  switch_time_t mutex_time;

  /* */
  conference_member_t *member_lists[NUMBER_OF_MEMBER_LISTS];
  int speaker_count;
  int unmuted_count;
  int32_t speaker_energy;

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
  int ending_due_to_inactivity;

  switch_bool_t stopping;
  uint16_t stop_entry_tone_participants;
  uint16_t mute_on_entry_participants;

  uint32_t participants_per_thread[N_CWC];
  uint32_t g711acnt, g711ucnt, g722cnt, opuscnt, opuslosscnt[OPUS_PROFILES];
  int lineno;

  int check_opus_loss_cnt;

  switch_time_t conference_loop_time;
  int conference_loop_time_cnt;

  int noise_measurement_period;
  float noise_measurement_periodf;

  int noise_percentage_med;
  int noise_percentage_high;

  int min_when_no_one_speaking;
  int min_when_others_speaking;
  int min_when_no_one_speaking_med;
  int min_when_others_speaking_med;
  int min_when_no_one_speaking_high;
  int min_when_others_speaking_high;

  int noise_change_thresholds;

  float al_position;
  float al_offset;
  float al_sign;
  float al_bound;

  switch_bool_t stereo;

} conference_obj_t;

/* Relationship with another member */
typedef struct conference_relationship {
  uint32_t id;
  uint32_t flags;
  struct conference_relationship *next;
} conference_relationship_t;

typedef enum {
  MS_UNMUTED,
  MS_UNMUTING,
  MS_MUTED,
  MS_CN
} mute_state_t;

typedef enum {
  ME_PKTS,
  ME_CN,
  ME_MUTE,
  ME_UNMUTE
} mute_event_t;

typedef enum {
  NOISE_NONE,
  NOISE_MEDIUM,
  NOISE_HIGH
} member_noise_t;

/* Conference Member Object */
struct conference_member {
  uint32_t id;
  switch_core_session_t *session;
  switch_channel_t *channel;
  conference_obj_t *conference;
  switch_memory_pool_t *pool;
  switch_buffer_t *audio_buffer;
  switch_buffer_t *mux_buffer; /*_m;*/
  switch_buffer_t *mux_buffer_s;
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
  uint8_t *frame; /*_mono;*/
  uint8_t *frame_stereo;
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

  uint32_t flush_len;
  uint32_t low_count;

  switch_bool_t last_one_of_active;
  switch_bool_t last_individual_mix;

#define FUZE_PIN_LEN 4
#define FUZE_PIN_LEN_FIELD 10
  /* Fuze */
  uint8_t muted_state;
  char pin[FUZE_PIN_LEN_FIELD];
  switch_time_t last_pin_time;
  int authenticate;
  int audio_bridge;

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

  uint8_t ianacode;
  uint8_t codec_id;
  uint8_t impl_id;
  switch_time_t time_of_first_packet;
  uint64_t data_sent;

  switch_bool_t in_cn;
  mute_state_t ms;
  mute_state_t ms_cnt;
  mute_event_t me;

  switch_time_t audio_in_mutex_time;
  switch_time_t audio_out_mutex_time;
  int audio_in_mutex_line;
  int audio_out_mutex_line;

  int16_t max_out_level;
  int16_t max_input_level;

  switch_bool_t individual_codec;
  switch_bool_t skip_accumulation;
  switch_bool_t variable_encoded_length;
  conf_auth_profile_t auth_profile;
  float loss;
  float loss_target;
  int loss_idx;
  int channels;
  switch_bool_t stereo;
  uint32_t max_bitrate;
#ifdef SIMULATE_LOSS
  int loss_count;
#endif
  switch_bool_t contactive;
  char contactive_name[1024];
  char contactive_userid[1024];
  char contactive_email[1024];
  char corp_name[1025];

  float noise_probability; /* noise or echo */
  float crossed_threshold;
  uint64_t noise_cnt;

  member_noise_t noise_state;

  uint32_t min_iir_to_speak_when_others_speaking;
  uint32_t min_iir_to_speak_when_no_one_speaking;

  al_handle_t *al;
};

#define ALC_HRTF_SOFT  0x1992


#endif // MOD_CONFERENCE_H
