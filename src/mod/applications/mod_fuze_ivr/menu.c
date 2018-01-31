/* 
 * menu.c -- IVRC Menu
 *
 */
#include <switch.h>

#include "ivr.h"
#include "menu.h"
#include "config.h"
#include "utils.h"

/*******************************************************************************/
const char *get_menu_name(const char *menu_tag) 
{
    int i = 0;

    if (menu_tag) {
	for (i=0; menu_list[i].name ; i++) {
	    if (!strcasecmp(menu_list[i].name, menu_tag)) {
		return menu_list[i].name;
	    }
	}
    }
    return NULL;
}

/*******************************************************************************/
/* Get channel values */
void std_menu_accept(switch_core_session_t *session, ivrc_profile_t *profile)
{
	ivrc_menu_t menu = { "std_menu_accept" };

	int retry;

	switch_channel_t *channel = switch_core_session_get_channel(session);

	/* Initialize Menu Configs */

	profile->accepted = SWITCH_FALSE;
	menu_init(profile, &menu);

	if (!menu.event_keys_dtmf || !menu.event_phrases) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "IVRC: Missing Menu Phrases or Keys in menu '%s'\n", menu.name);
		goto end;
	}


	for (retry = menu.ivr_maximum_attempts; switch_channel_ready(channel) && retry > 0; retry--) {
		menu_instance_init(&menu);
		switch_event_add_header(menu.phrase_params, SWITCH_STACK_BOTTOM, "IVR-Retry-Left", "%d", retry);

		ivre_init(&menu.ivre_d, menu.dtmfa, NULL);

		ivre_playback(session, &menu.ivre_d, switch_event_get_header(menu.event_phrases, "instructions"), NULL, menu.phrase_params, NULL, menu.ivr_entry_timeout);

		if (menu.ivre_d.result == RES_TIMEOUT) {
			//ivre_playback_dtmf_buffered(session, switch_event_get_header(menu.event_phrases, "timeout"), NULL, NULL, NULL, 0);
		}
		else if (menu.ivre_d.result == RES_INVALID) {
			ivre_playback_dtmf_buffered(session, switch_event_get_header(menu.event_phrases, "invalid"), NULL, NULL, NULL, 0);
		}
		else if (menu.ivre_d.result == RES_FOUND) {  /* Matching DTMF Key Pressed */
			const char *action = switch_event_get_header(menu.event_keys_dtmf, menu.ivre_d.dtmf_stored);

			/* Reset the try count */
			retry = menu.ivr_maximum_attempts;

			if (action) {
				if (!strcasecmp(action, "return")) { /* Return to the previous menu */
					retry = -1;
				}
				else if (!strcasecmp(action, "accept")) { /* Return to the previous menu */
					profile->accepted = SWITCH_TRUE;
					retry = -1;
				}
				else if (!strncasecmp(action, "play:", 5)) { /* Play and return to the previos menu */
					ivre_playback_dtmf_buffered(session, switch_event_get_header(menu.event_phrases, action+5), NULL, NULL, NULL, 0);
					retry = -1;
				}
				else if (!strncasecmp(action, "menu:", 5)) { /* Sub Menu */
					void (*fPtr)(switch_core_session_t *session, ivrc_profile_t *profile) = ivrc_get_menu_function(action+5);
					if (fPtr) {
						fPtr(session, profile);
					}
				}
			}
		}
		menu_instance_free(&menu);
	}
	// ???
	if (retry == 0) {
	}

end:
	menu_free(&menu);
}

/*******************************************************************************/
void std_menu_get_id(switch_core_session_t *session, ivrc_profile_t *profile) 
{
    ivrc_menu_t menu = { "std_menu_get_id" };
    const char *id = NULL, *user_mask;

    menu_init(profile, &menu);
    
    profile->authenticated = SWITCH_FALSE;
    user_mask = switch_event_get_header(menu.event_settings, "ID-Mask");
    menu.ivr_maximum_attempts = profile->retry;
	    
    id = ivrc_menu_get_input_set(session, profile, &menu, user_mask);

    profile->retry = menu.ivr_maximum_attempts;
    profile->id = id;
    if (id) 
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: ID: %s\n",profile->id);
    else
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: ID: %s\n","No entry");
    menu_free(&menu);
}
  
/*******************************************************************************/
char *ivrc_menu_get_input_set(switch_core_session_t *session, ivrc_profile_t *profile, ivrc_menu_t *menu, const char *input_mask) 
{
    char *result = NULL;
    ivre_data_t loc_stored_data;
    ivre_data_t *loc_stored = NULL;
    int retry;
    const char *terminate_key = NULL;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    
    if (!menu->event_keys_dtmf || !menu->event_phrases) {
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "IVRC: Missing Menu Phrases or Keys in menu '%s'\n", menu->name);
	goto end;
    }
    
    terminate_key = switch_event_get_header(menu->event_keys_action, "ivrengine:terminate_entry");
    
    for (retry = menu->ivr_maximum_attempts; switch_channel_ready(channel) && retry > 0; retry--) {
	int i;
	
	menu_instance_init(menu);
	
	switch_event_add_header(menu->phrase_params, SWITCH_STACK_BOTTOM, "IVR-Retry-Left", "%d", retry);
	
	/* Find the last entry and append this one to it */
	for (i=0; i < 16 && menu->dtmfa[i]; i++){
	}
	menu->dtmfa[i] = (char *) input_mask;
	
	ivre_init(&menu->ivre_d, menu->dtmfa, loc_stored);
	if (terminate_key) {
	    menu->ivre_d.terminate_key = terminate_key[0];
	}
	ivre_playback(session, &menu->ivre_d, switch_event_get_header(menu->event_phrases, "instructions"), NULL, menu->phrase_params, NULL, menu->ivr_entry_timeout);
	
	if (menu->ivre_d.result == RES_TIMEOUT) {
	    if (strlen(menu->ivre_d.dtmf_stored) >= 1) {
	        result = switch_core_session_strdup(session, menu->ivre_d.dtmf_stored);
	    } else {
	        ivre_playback_dtmf_buffered(session, switch_event_get_header(menu->event_phrases, "timeout"), NULL, NULL, NULL, 0);
		loc_stored = &loc_stored_data;
		menu->ivre_d.result = RES_WAITFORMORE;
		menu->ivre_d.audio_stopped = SWITCH_FALSE;
		memcpy(loc_stored, &(menu->ivre_d), sizeof(loc_stored_data));
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: ID stored: %s\n", menu->ivre_d.dtmf_stored);
	    }
	    menu->ivr_maximum_attempts = --retry;
	    retry = -1;
	} 
	else if (menu->ivre_d.result == RES_INVALID) {
	    ivre_playback_dtmf_buffered(session, switch_event_get_header(menu->event_phrases, "invalid"), NULL, NULL, NULL, 0);
	    loc_stored = NULL;
	} 
	else if (menu->ivre_d.result == RES_FOUND) {  /* Matching DTMF Key Pressed */
	    
	    /* Reset the try count */
	    // retry = menu->ivr_maximum_attempts;
	    
	    if (!strncasecmp(menu->ivre_d.completeMatch, input_mask, 1)) {
		result = switch_core_session_strdup(session, menu->ivre_d.dtmf_stored);
		menu->ivr_maximum_attempts = --retry;
		retry = -1;
	    }
	}
	menu_instance_free(menu);
    }
end:
    return result;
}

/*******************************************************************************/
void (*ivrc_get_menu_function(const char *menu_name))(switch_core_session_t *session, ivrc_profile_t *profile) 
{
    int i = 0;

    if (menu_name) {
	for (i=0; menu_list[i].name ; i++) {
	    if (!strcasecmp(menu_list[i].name, menu_name)) {
		return menu_list[i].pt2Func;
	    }
	}
    }
    return NULL;
}


