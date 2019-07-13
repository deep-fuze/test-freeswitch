#include "ivr.h"

#ifndef _CONFIG_H_
#define _CONFIG_H_

extern const char *global_cf;

struct ivrc_profile 
{
    const char *name;
    
    const char *domain;
    const char *id;
    
    int retry;
    switch_bool_t accepted;
    
    const char *menu_check_init;
    const char *menu_check_main;
    const char *menu_check_terminate;
    
    switch_bool_t authenticated;
    const char *meeting_instance_id;
    const char *conf_address;
    const char *conference_id;
    const char *extension;
    const char *corp_name;
    const char *uname;
    int is_retired;
    int moderator;

    /* contactive */
    const char *caller_name;
    const char *caller_userid;
    const char *caller_email;
    int number_auth_is_allowed;
    int caller_contactive_found;

    switch_bool_t loopback;

    const char *api_profile;
    
    switch_event_t *event_settings;
};
typedef struct ivrc_profile ivrc_profile_t;

struct ivrc_menu 
{
    const char *name;
    ivrc_profile_t *profile;
    
    switch_event_t *event_keys_action;
    switch_event_t *event_keys_dtmf;
    switch_event_t *event_keys_varname;
    switch_event_t *event_settings;
    switch_event_t *event_phrases;
    
    char *dtmfa[16];
    switch_event_t *phrase_params;
    ivre_data_t ivre_d;
    
    int ivr_maximum_attempts;
    int ivr_entry_timeout;
};
typedef struct ivrc_menu ivrc_menu_t;

ivrc_profile_t *get_profile(switch_core_session_t *session, const char *profile_name);
void free_profile(ivrc_profile_t *profile);

void menu_init(ivrc_profile_t *profile, ivrc_menu_t *menu);
void menu_instance_init(ivrc_menu_t *menu);
void menu_instance_free(ivrc_menu_t *menu);
void menu_free(ivrc_menu_t *menu);
const char *get_menu_name(const char *menu_tag);

#endif /* _CONFIG_H_ */
