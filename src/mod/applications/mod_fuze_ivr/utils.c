/* 
 *
 * utils.c
 *
 */

#include <switch.h>
#include "utils.h"

#define PREPROD_MEETING_ID_LEN 7
#define PROD_MEETING_ID_LEN 8

SWITCH_DECLARE(void) switch_rtp_silence_transport_session(switch_core_session_t *session, int size);

int fuze_expected_meeting_id_len()
{
    const char *host = switch_core_get_hostname();

    if (strstr(host, "prod") != 0) {
        return PROD_MEETING_ID_LEN;
    } else {
        return PREPROD_MEETING_ID_LEN;
    }
}

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

    switch_rtp_silence_transport_session(session, 1500);

    switch_api_execute("curl", arguments, session, &stream);

    switch_rtp_silence_transport_session(session, 0);

    // TODO:
    profile->is_retired = -1;
    profile->meeting_instance_id = NULL;
    profile->conf_address = NULL;
    profile->caller_name = NULL;
    profile->caller_userid = NULL;
    profile->caller_email = NULL;
    profile->number_auth_is_allowed = 1;
    profile->caller_contactive_found = 0;
    profile->moderator = 0;

    if (!stream.data || !(response = cJSON_Parse(stream.data)))
    {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: no data\n");
        return FUZE_STATUS_GENERR;
    }
    cJSON_Print(response);
    item = cJSON_GetObjectItem(response, "status_code");
    if (!item || !(out = cJSON_Print(item))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request status_code: none\n");
        status = FUZE_STATUS_GENERR;
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request status_code: %s\n", out);
        if (strstr(out,"200") == NULL) {
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

        cJSON_Print(body);

        if (!out) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message code: none\n");
        }
        else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message code: %s\n", out);
            if (strstr(out,"200") != NULL) {
                item = cJSON_GetObjectItem(body, "message");
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message response: %s\n", item ? item->valuestring : "none");

                item = cJSON_GetObjectItem(body, "is_retired");
                if (item) {
                    profile->is_retired = ((item->type&255) == cJSON_True) ? SWITCH_TRUE : SWITCH_FALSE;
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message is_retired: %s\n", profile->is_retired ? "true" : "false");
                }
                item = cJSON_GetObjectItem(body, "corp_name");
                if (item) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message corp_name: %s\n", item->valuestring);
#if 1
                    if (!strncmp(item->valuestring, "TPN.", 4)) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: corp name (%s) matches required TPN pattern\n", item->valuestring);
                        profile->corp_name = fuze_session_encode(session, switch_core_session_strdup(session, item->valuestring+4));
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                          "IVRC: corp name (%s) doesn't match required TPN pattern. Contactive lookup disabled\n", item->valuestring);
                        profile->number_auth_is_allowed = SWITCH_FALSE;
                    }
#endif
                } else {
                  profile->number_auth_is_allowed = SWITCH_FALSE;
                }
                item = cJSON_GetObjectItem(body, "number_auth_is_allowed");
                if (item) {
                  profile->number_auth_is_allowed = ((item->type&255) == cJSON_True) ? SWITCH_TRUE : SWITCH_FALSE;
                  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                                    "IVRC: curl: message profile->number_auth_is_allowed: %s\n", profile->number_auth_is_allowed ? "true" : "false");
                }
                item = cJSON_GetObjectItem(body, "meeting_instance_id");
                if (item && item->valuestring && !zstr(item->valuestring)) {
                    profile->meeting_instance_id = fuze_session_encode(session, switch_core_session_strdup(session,item->valuestring));
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message encoded meeting_instance_id: %s\n", profile->meeting_instance_id);
                }
                item = cJSON_GetObjectItem(body, "role");
                if (item && item->valuestring && !zstr(item->valuestring)) {
                    if (!strncmp(item->valuestring, "Moderator", 9)) {
                        profile->moderator = 1;
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message encoded role: %s\n", item->valuestring);
                    }
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
            else if (strstr(out,"406")) {
                status = FUZE_STATUS_TIMEOUT;
            }
            else if  (strstr(out,"405")) {
                status = FUZE_STATUS_RESTRICTED;
            }
            else if  (strstr(out,"403") || 
                      strstr(out,"404")) {
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

fuze_status_t fuze_contactive_execute(switch_core_session_t *session, ivrc_profile_t *profile, const char *arguments) 
{
    fuze_status_t status = FUZE_STATUS_FOUND;
    switch_stream_handle_t stream = { 0 };
    cJSON *response, *item;
    char *out = NULL;;

    SWITCH_STANDARD_STREAM(stream);

    switch_rtp_silence_transport_session(session, 1500);
    switch_api_execute("curl", arguments, session, &stream);
    switch_rtp_silence_transport_session(session, 0);

    // TODO:
    profile->caller_name = NULL;
    profile->caller_userid = NULL;
    profile->caller_email = NULL;
    profile->caller_contactive_found = 0;

    if (!stream.data || !(response = cJSON_Parse(stream.data)))
    {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: no data\n");
        return FUZE_STATUS_GENERR;
    }
    cJSON_Print(response);
    item = cJSON_GetObjectItem(response, "status");
    if (!item || !(out = cJSON_Print(item))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request status_code: none\n");
        status = FUZE_STATUS_GENERR;
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request status_code: %s\n", out);
        if (strncmp(out, "0", 1)) {
            status = FUZE_STATUS_GENERR;
        }
        else {
            status = FUZE_STATUS_FOUND; // status code is not "0"
            item = cJSON_GetObjectItem(response, "data"); 
            if (!item || item->type != cJSON_Array) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request: no data item: %s type: %d/%d value:%s",
                                  item == NULL ? "null" : "not null", item->type != cJSON_String, item->type, item->valuestring);
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

    if (item) {
        int x = cJSON_GetArraySize(item);

        for (int i = 0; i < x; i++) {
            cJSON *data_item = cJSON_GetArrayItem(item, i);

            if (data_item && data_item->type == cJSON_Object) {
                cJSON *origins = cJSON_GetObjectItem(data_item, "origins");

                if (origins && origins->type == cJSON_Array) {
                    int osize = cJSON_GetArraySize(origins);
                    for (int j = 0; j < osize; j++) {
                        cJSON *oitem = cJSON_GetArrayItem(origins, j);
                        if (oitem && oitem->type == cJSON_Object) {
                            cJSON *name = cJSON_GetObjectItem(oitem, "name");
                            cJSON *email = cJSON_GetObjectItem(oitem, "email");
                            cJSON *userid = cJSON_GetObjectItem(oitem, "originItemId");
                            cJSON *originName = cJSON_GetObjectItem(oitem, "originName");

                            if (name && name->type == cJSON_Object) {
                                cJSON *first = cJSON_GetObjectItem(name, "firstName");
                                cJSON *last = cJSON_GetObjectItem(name, "lastName");
                                if (first && first->valuestring && last && first->valuestring) {
                                    profile->caller_name = fuze_session_encode(session, switch_core_session_sprintf(session, "%s %s", first->valuestring, last->valuestring));
                                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "caller_name %s\n", profile->caller_name);
                                }
                            }

                            if (userid && userid->type == cJSON_String && userid->valuestring) {
                                const char *uid = strstr(userid->valuestring, ":");
                                if (uid) {
                                    profile->caller_userid = fuze_session_encode(session, switch_core_session_strdup(session, uid+1));
                                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "userid %s\n", profile->caller_userid);
                                }
                            }

                            if (originName && originName->type == cJSON_String && originName->valuestring) {
                                if (!strcmp(originName->valuestring, "tpn")) {
                                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "tpn origin\n");
                                    profile->caller_contactive_found = 1;
                                    status = FUZE_STATUS_SUCCESS;
                                }
                            }

                            if (email && email->type == cJSON_Array) {
                              int esize = cJSON_GetArraySize(email);
                              for (int k = 0; k < esize; k++) {
                                  cJSON *eitem = cJSON_GetArrayItem(email, k);
                                  if (eitem && eitem->type == cJSON_Object) {
                                    cJSON *e = cJSON_GetObjectItem(eitem, "email");
                                    if (e && e->valuestring && e->type == cJSON_String) {
                                        profile->caller_email = fuze_session_encode(session, switch_core_session_strdup(session, e->valuestring));
                                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "email %s\n", profile->caller_email);
                                    }
                                  }
                              }
                            }
                        }
                    }
                }
            }
        }
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
