/* 
 * ivr.c -- IVRC Engine
 */

#include <switch.h>

#include "ivr.h"

static int match_dtmf(switch_core_session_t *session, ivre_data_t *loc)
{
	switch_bool_t is_invalid[128] = { SWITCH_FALSE };
	int i;
	loc->potentialMatch = NULL;
	loc->completeMatch = NULL;
	loc->potentialMatchCount = 0;

	for (i = 0; i < 16 && i < loc->dtmf_received; i++) {
		int j;
		loc->potentialMatchCount = 0;
		for (j = 0; j < 128 && !zstr(loc->dtmf_accepted[j]); j++) {
			switch_bool_t cMatch = SWITCH_FALSE;
			char test[2] = { 0 };

			if (is_invalid[j])
				continue;

			test[0] = loc->dtmf_stored[i];
			if (loc->dtmf_accepted[j][i] == 'N' && atoi(test) >= 2 && atoi(test) <= 9)
				cMatch = SWITCH_TRUE;
			if (loc->dtmf_accepted[j][i] == 'X' && atoi(test) >= 0 && atoi(test) <= 9) {
				cMatch = SWITCH_TRUE;
			}
			if (i >= strlen(loc->dtmf_accepted[j]) - 1 && loc->dtmf_accepted[j][strlen(loc->dtmf_accepted[j])-1] == '.')
				cMatch = SWITCH_TRUE;
			if (loc->dtmf_accepted[j][i] == loc->dtmf_stored[i])
				cMatch = SWITCH_TRUE;

			if (cMatch == SWITCH_FALSE) {
				is_invalid[j] = SWITCH_TRUE;
				continue;
			}

			if (i == strlen(loc->dtmf_accepted[j]) - 1 && loc->dtmf_accepted[j][strlen(loc->dtmf_accepted[j])-1] == '.') {
				loc->completeMatch = loc->dtmf_accepted[j];
			}
			if (i == loc->dtmf_received - 1 && loc->dtmf_received == strlen(loc->dtmf_accepted[j]) && loc->dtmf_accepted[j][strlen(loc->dtmf_accepted[j])-1] != '.') {
				loc->completeMatch = loc->dtmf_accepted[j];
				continue;
			}
			loc->potentialMatchCount++;
		}
	}

	return 1;
}

static switch_status_t cb_on_dtmf_ignore(switch_core_session_t *session, void *input, switch_input_type_t itype, void *buf, unsigned int buflen)
{
    switch (itype) {
    case SWITCH_INPUT_TYPE_DTMF:
    {
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_dtmf_t *dtmf = (switch_dtmf_t *) input;
	switch_channel_queue_dtmf(channel, dtmf);
	return SWITCH_STATUS_BREAK;
    }
    default:
	break;
    }
    return SWITCH_STATUS_SUCCESS;
}


static switch_status_t cb_on_dtmf_string(switch_core_session_t *session, void *input, switch_input_type_t itype, void *buf, unsigned int buflen)
{
	ivre_data_t *loc = (ivre_data_t*) buf;

	switch (itype) {
		case SWITCH_INPUT_TYPE_DTMF:
		{
			switch_dtmf_t *dtmf = (switch_dtmf_t *) input;
			switch_bool_t audio_was_stopped = loc->audio_stopped;
			loc->audio_stopped = SWITCH_TRUE;

			if (loc->dtmf_received >= sizeof(loc->dtmf_stored)) {
				loc->result = RES_BUFFER_OVERFLOW;
				break;
			}
			if (!loc->terminate_key || dtmf->digit != loc->terminate_key)
				loc->dtmf_stored[loc->dtmf_received++] = dtmf->digit;

			match_dtmf(session, loc);

			if (loc->terminate_key && dtmf->digit == loc->terminate_key && loc->result == RES_WAITFORMORE) {
				if (loc->potentialMatchCount == 1 && loc->completeMatch != NULL) {
					loc->result = RES_FOUND;
				}
				else {
					loc->result = RES_INVALID;
				}
				return SWITCH_STATUS_BREAK;
			}
			else {
				if (loc->potentialMatchCount == 0 && loc->completeMatch != NULL) {
					loc->result = RES_FOUND;
					return SWITCH_STATUS_BREAK;
				}
				else if (loc->potentialMatchCount > 0) {
					loc->result = RES_WAITFORMORE;
					if (!audio_was_stopped)
						return SWITCH_STATUS_BREAK;
				}
				else {
					loc->result = RES_INVALID;
					return SWITCH_STATUS_BREAK;
				}
			}
		}
		break;
		default:
			break;
	}

	return SWITCH_STATUS_SUCCESS;
}

switch_status_t ivre_init(ivre_data_t *loc, char **dtmf_accepted, ivre_data_t *loc_stored)
{
    int i;
    
    if (loc_stored) {
	memcpy(loc, loc_stored, sizeof(*loc));
    }
    else {
	memset(loc, 0, sizeof(*loc));
    }
    
    for (i = 0; dtmf_accepted[i] && i < 128; i++) {
	strncpy(loc->dtmf_accepted[i], dtmf_accepted[i], 16);
    }
    loc->record_tone = "%(1000, 0, 640)";
    
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t ivre_playback_dtmf_buffered(switch_core_session_t *session, const char *macro_name,  const char *data, switch_event_t *event, const char *lang, int timeout) 
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    
    if (switch_channel_ready(channel)) {
	switch_input_args_t args = { 0 };
	
	args.input_callback = cb_on_dtmf_ignore;

	if (macro_name) {
	    status = switch_ivr_phrase_macro_event(session, macro_name, data, event, lang, &args);
	}
    } else {
	status = SWITCH_STATUS_BREAK;
    }
    
    return status;
}


switch_status_t ivre_playback(switch_core_session_t *session, ivre_data_t *loc, const char *macro_name,  const char *data, switch_event_t *event, const char *lang, int timeout)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_channel_t *channel = switch_core_session_get_channel(session);

    if (switch_channel_ready(channel)) {
	switch_input_args_t args = { 0 };

	args.input_callback = cb_on_dtmf_string;
	args.buf = loc;

	if (macro_name && loc->audio_stopped == SWITCH_FALSE && loc->result == RES_WAITFORMORE) {
	    status = switch_ivr_phrase_macro_event(session, macro_name, data, event, lang, &args);
	}

	if (switch_channel_ready(channel) && (status == SWITCH_STATUS_SUCCESS || status == SWITCH_STATUS_BREAK) && timeout && loc->result == RES_WAITFORMORE) {
	    loc->audio_stopped = SWITCH_TRUE;
	    switch_ivr_collect_digits_callback(session, &args, timeout, 0);
	    if (loc->result == RES_WAITFORMORE) {
//		if (loc->potentialMatchCount == 1 && loc->completeMatch != NULL) {
//		    loc->result = RES_FOUND;
//		} else {
		    loc->result = RES_TIMEOUT;
//		}
	    }
	}
    } else {
	status = SWITCH_STATUS_BREAK;
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: Playback status: %d\n",loc->result);
    return status;
}
