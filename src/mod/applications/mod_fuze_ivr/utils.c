/* 
 *
 * utils.c
 *
 */

#include <switch.h>
#include "utils.h"

/*******************************************************************************/
const char *fuze_session_encode(switch_core_session_t *session, const char *string)
{
    switch_size_t new_len = 0;
    char *encode_buf;
    const char *p = NULL;
    new_len = (strlen(string) * 3) + 1;
    encode_buf = malloc(new_len);
    switch_url_encode(string, encode_buf, new_len);
    p = switch_core_session_strdup(session, encode_buf);
    switch_safe_free(encode_buf);
    return p;
}

/*******************************************************************************/
fuze_status_t fuze_curl_execute(switch_core_session_t *session, ivrc_profile_t *profile, const char *arguments) 
{
    fuze_status_t status = FUZE_STATUS_FOUND;
    switch_stream_handle_t stream = { 0 };
    cJSON *response, *body, *item;
    char *out = NULL;;

    SWITCH_STANDARD_STREAM(stream);

    switch_api_execute("curl", arguments, session, &stream);

    // TODO:
    profile->is_retired = -1;
    profile->meeting_instance_id = NULL;
    profile->conf_address = NULL;

    if (!stream.data || !(response = cJSON_Parse(stream.data)))
    {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: no data\n");
	return FUZE_STATUS_GENERR;
    }
    item = cJSON_GetObjectItem(response, "status_code");
    if (!item || !(out = cJSON_Print(item))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request status_code: none\n");
	status = FUZE_STATUS_GENERR;

    } else {
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request status_code: %s\n", out);
	if (strcasecmp(out,"200")) {
	    status = FUZE_STATUS_GENERR;
	}
	else {
	    status = FUZE_STATUS_FOUND; // response code is "200"
	    item = cJSON_GetObjectItem(response, "body"); 
	    if (!item || item->type != cJSON_String || !item->valuestring) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request: no body");
		status = FUZE_STATUS_GENERR;  
	    }
	}
    }
    switch_safe_free(out);
    if (status != FUZE_STATUS_FOUND) {
	cJSON_Delete(response);
	switch_safe_free(stream.data);
	return status;
    }
    body = cJSON_Parse(item->valuestring);

    if (body) {
	item = cJSON_GetObjectItem(body, "code"); 
	out = (item ? cJSON_Print(item) : NULL); 

	if (!out) {
	    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message code: none\n");
	}
	else {
	    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message code: %s\n", out);
	    if (!strcasecmp(out,"200")) {
		item = cJSON_GetObjectItem(body, "message");
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message response: %s\n", item ? item->valuestring : "none");

		item = cJSON_GetObjectItem(body, "is_retired");
		if (item) {
		    profile->is_retired = ((item->type&255) == cJSON_True) ? SWITCH_TRUE : SWITCH_FALSE;
		    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message is_retired: %s\n", profile->is_retired ? "true" : "false");
		}
		item = cJSON_GetObjectItem(body, "meeting_instance_id");
		if (item && item->valuestring && !zstr(item->valuestring)) {
		    profile->meeting_instance_id = fuze_session_encode(session, switch_core_session_strdup(session,item->valuestring));
		    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message encoded meeting_instance_id: %s\n", profile->meeting_instance_id);
		}
		item = cJSON_GetObjectItem(body, "conf_address");
		if (item && item->valuestring && !zstr(item->valuestring)) {
		    char *p;
		    char *vstr = switch_core_session_strdup(session,item->valuestring);
		    profile->conf_address = switch_core_session_strdup(session, vstr);
		    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message conf_address: %s\n", profile->conf_address);
		    profile->extension = fuze_session_encode(session, vstr);
		    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message encoded extension: %s\n", profile->extension);
		    *(p = strchr(item->valuestring,'@')) = '\0';
		    profile->conference_id = switch_core_session_sprintf(session,"%s", vstr);
		    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message encoded conference_id: %s\n", profile->conference_id);
		    status = FUZE_STATUS_SUCCESS;
		}
	    }
	    else if (!strcasecmp(out,"406")) {
		status = FUZE_STATUS_TIMEOUT;
	    }
	    else if  (!strcasecmp(out,"405")) {
		status = FUZE_STATUS_RESTRICTED;
	    }
	    else if  (!strcasecmp(out,"403") || 
		      !strcasecmp(out,"404")) {
		status = FUZE_STATUS_NOTFOUND;
	    }
	    switch_safe_free(out);
	}
	cJSON_Delete(body);
    }
    cJSON_Delete(response);
    switch_safe_free(stream.data);
    return status;
}

/*******************************************************************************/
switch_status_t ivrc_api_execute(switch_core_session_t *session, const char *apiname, const char *arguments) 
{
    switch_stream_handle_t stream = { 0 };
    switch_status_t status = SWITCH_STATUS_FALSE;

    SWITCH_STANDARD_STREAM(stream);
    switch_api_execute(apiname, arguments, session, &stream);
    switch_safe_free(stream.data);
    return status;
}