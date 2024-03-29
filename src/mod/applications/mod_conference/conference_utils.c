/* 
 *
 * utils.c
 *
 */

#include <switch.h>
#include "conference_utils.h"

#define AUTH_EMAIL "null-callwave_service@relay11.callwave.com"
#define AUTH_PASSWD "2ymkRlqIoDkuYhAOEXqfjTZoSktLXqCM"
#define CONTENT "Content-Type application/x-www-form-urlencoded"
#define BODY_FMT "auth_email=%s&auth_password=%s&mobile_number=%s&dialed_number=%s&iso_code=%s"
#define BODY_JSON_FMT "auth_email=%s&auth_password=%s&meeting_id=%s&instance_id=%s&ak=%s&pin=%s&call_info={\"caller_id_number\":\"%s\",\"destination_number\":\"%s\"}"
#define BRIDGE_BODY_FMT "auth_email=%s&auth_password=%s&meeting_id=%s&instance_id=%s&is_allowed=%s"
#define END_CONFERENCE_JSON_FMT "auth_email=%s&auth_password=%s&instance_id=%s"
#define VERIFY_PSTN_CALLER_SERVICE "/services/audio/verify_pstn_caller"
#define AUTHENTICATE_CALLER_SERVICE "/json/authenticate_caller"
#define AUDIO_CONFERENCE_ENDED_SERVICE "/json/end_instance"
#define AUDIO_BRIDGE_SERVICE "/json/audio_bridged"

#define PREPROD_MEETING_ID_LEN 7
#define PROD_MEETING_ID_LEN 8

SWITCH_DECLARE(void) switch_rtp_silence_transport_session(switch_core_session_t *session, int size);

struct server_iso_code {
    const char *server_name;
    const char *country_code;
};

typedef struct server_iso_code server_iso_code_t;

server_iso_code_t server_list[] =
  {
    {"ams", "NL"},
    {"nje", "US"},
    {"sjo", "US"},
    {"sin", "SG"},
    {"syd", "AU"},
    {"sof", "BG"},
    {"hkg", "HK"},
    {"fra", "DE"},
    { NULL, "US" }
  };

/*******************************************************************************/
const char *get_country_iso_code()
{
  int i = 0;

  const char *server_name = switch_core_get_hostname();
  if (server_name) {
    for (i=0; server_list[i].server_name ; i++) {
      if (!strncasecmp(server_list[i].server_name, server_name, 3)) {
        return server_list[i].country_code;
      }
    }
  }
  return "US";
}

int fuze_expected_meeting_id_len()
{
  const char *host = switch_core_get_hostname();

  if (strstr(host, "prod") != 0) {
    return PROD_MEETING_ID_LEN;
  } else {
    return PREPROD_MEETING_ID_LEN;
  }
}

const char *get_caller_url()
{
    const char *host = switch_core_get_hostname();

    if (strstr(host, "prod") != 0) {
        return "https://sjoprodlb-vip-api.fuzemeeting.com";
    } else if (strstr(host, "intg") != 0) {
        return "https://intg.fuzemeeting.com";
    } else if (strstr(host, "main") != 0) {
        return "https://main.fuzemeeting.com";
    }
    return "https://sjoprodlb-vip-api.fuzemeeting.com";
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
fuze_status_t fuze_curl_execute(switch_core_session_t *session, conf_auth_profile_t *profile, const char *arguments) 
{
    fuze_status_t status = FUZE_STATUS_FOUND;
    switch_stream_handle_t stream = { 0 };
    cJSON *response, *body, *item;
    char *out = NULL;

    SWITCH_STANDARD_STREAM(stream);

    switch_rtp_silence_transport_session(session, 1500);
    switch_api_execute("curl", arguments, session, &stream);
    switch_rtp_silence_transport_session(session, 0);

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
        if (strstr(out,"200") == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request status_code not 200!\n");
            status = FUZE_STATUS_GENERR;
        }
        else {
            status = FUZE_STATUS_FOUND; // response code is "200"
            item = cJSON_GetObjectItem(response, "body"); 
            if (!item || item->type != cJSON_String || !item->valuestring) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request: no body");
                status = FUZE_STATUS_GENERR;  
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request: body found\n");
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

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request: body=%s item->valuestring=%s\n", 
                      body == NULL ? "null" : "ok", item->valuestring);

    if (body) {
        item = cJSON_GetObjectItem(body, "code"); 
        out = (item ? cJSON_Print(item) : NULL); 

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: html request: code=%s item->valuestring=%s\n",
                      item == NULL ? "null" : "ok", out);

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "received body: %s\n", item->valuestring);

        if (!out) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message code: none\n");
        }
        else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: curl: message code: %s\n", out);
            if (strstr(out,"200")) {
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

fuze_status_t authenticate(switch_core_session_t *session, conf_auth_profile_t *profile, const char *conference_id,
                           const char *instance_id, const char *pin, switch_bool_t verify) 
{
    fuze_status_t status = FUZE_STATUS_FALSE;
    const char *caller_number;
    const char *dialed_number;
    const char *body, *cmd, *url, *body2, *cmd2, *full_to;
    char *ak;
    char akstr[30];

    switch_channel_t *channel = switch_core_session_get_channel(session);

    url = switch_channel_get_variable(channel, "fuze_callback_caller_url");
    akstr[0] = '\0';
    if (!url || zstr(url)) {
        url = switch_channel_get_variable(channel, "callback_caller_url");
    }
    if (!url || zstr(url)) {
        url = get_caller_url();
    }

    full_to = switch_channel_get_variable(channel, "sip_full_to");
    if (full_to) {
        ak = strstr(full_to, "AK=");
        if (ak) {
            char *eos;
            ak += 3;
            eos = ak+1;
            while ((eos-ak) < 30) {
                char c = *eos;
                if ((c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F') ||
                    (c >= '0' && c <= '9')) {
                    eos += 1;
                } else {
                    break;
                }
            }
            if (eos) {
                int len = (int)(eos - ak);
                if (len >= 30) {
                    len = 29;
                }
                strncpy(akstr, ak, len);
                akstr[len] = '\0';
                ak = akstr;
            }
        }
    }
    caller_number = switch_channel_get_variable(channel, "caller_id_number");
    dialed_number = switch_channel_get_variable(channel, "userfield");

    /* Post 1 */
    if (verify) {
        body = switch_core_session_sprintf(session, BODY_FMT, AUTH_EMAIL, AUTH_PASSWD, caller_number, dialed_number, get_country_iso_code());
        cmd = switch_core_session_sprintf(session, "%s%s json %s post %s", url, VERIFY_PSTN_CALLER_SERVICE, CONTENT, body);
        body2 = switch_core_session_sprintf(session, BODY_FMT, AUTH_EMAIL, "xxxxx", caller_number, dialed_number, get_country_iso_code());
        cmd2 = switch_core_session_sprintf(session, "%s%s json %s post %s", url, VERIFY_PSTN_CALLER_SERVICE, CONTENT, body2);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call verify_pstn_caller (cmd: %s)- dialed_number=%s callerid_number=%s\n",
                          cmd2, dialed_number, caller_number);
        status = fuze_curl_execute(session, profile, cmd);
    }

    /* Post 2 */
    body = switch_core_session_sprintf(session, BODY_JSON_FMT, AUTH_EMAIL, AUTH_PASSWD, conference_id, instance_id, akstr, pin, caller_number, dialed_number);
    cmd = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUTHENTICATE_CALLER_SERVICE, CONTENT, body);
    body2 = switch_core_session_sprintf(session, BODY_JSON_FMT, AUTH_EMAIL, "xxxxx", conference_id, instance_id, pin, caller_number, dialed_number);
    cmd2 = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUTHENTICATE_CALLER_SERVICE, CONTENT, body2);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call authenticate_caller (cmd: %s) - dialed_number=%s callerid_number=%s\n",
                      cmd2, dialed_number, caller_number);

    status = fuze_curl_execute(session, profile, cmd);


    return status;
}


fuze_status_t audio_bridge(switch_core_session_t *session, conf_auth_profile_t *profile,
                           const char *conference_id, const char *instance_id, int is_allowed)
{
  fuze_status_t status = FUZE_STATUS_FALSE;
  const char *body, *cmd, *url, *body2, *cmd2;

  switch_channel_t *channel = switch_core_session_get_channel(session);

  url = switch_channel_get_variable(channel, "fuze_callback_caller_url");
  if (!url || zstr(url)) {
    url = switch_channel_get_variable(channel, "callback_caller_url");
  }
  if (!url || zstr(url)) {
    url = get_caller_url();
  }

  /* Post 1 */
  body = switch_core_session_sprintf(session, BRIDGE_BODY_FMT, AUTH_EMAIL, AUTH_PASSWD, conference_id, instance_id, is_allowed ? "true" : "false");
  cmd = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUDIO_BRIDGE_SERVICE, CONTENT, body);
  body2 = switch_core_session_sprintf(session, BRIDGE_BODY_FMT, AUTH_EMAIL, "xxxxx", conference_id, instance_id, is_allowed ? "true" : "false");
  cmd2 = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUDIO_BRIDGE_SERVICE, CONTENT, body2);
  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call audio_bridge (cmd: %s)- meetingId: %s\n",
                    cmd2, conference_id);
  status = fuze_curl_execute(session, profile, cmd);

  return status;
}

fuze_status_t end_conference(switch_core_session_t *session, conf_auth_profile_t *profile, const char *instance_id)
{
  fuze_status_t status = FUZE_STATUS_FALSE;
  const char *body, *cmd, *url, *body2, *cmd2;

  switch_channel_t *channel = switch_core_session_get_channel(session);

  url = switch_channel_get_variable(channel, "fuze_callback_caller_url");
  if (!url || zstr(url)) {
    url = switch_channel_get_variable(channel, "callback_caller_url");
  }
  if (!url || zstr(url)) {
    url = get_caller_url();
  }


  body = switch_core_session_sprintf(session, END_CONFERENCE_JSON_FMT, AUTH_EMAIL, AUTH_PASSWD, instance_id);
  cmd = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUDIO_CONFERENCE_ENDED_SERVICE, CONTENT, body);
  body2 = switch_core_session_sprintf(session, END_CONFERENCE_JSON_FMT, AUTH_EMAIL, "xxxxx", instance_id);
  cmd2 = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUDIO_CONFERENCE_ENDED_SERVICE, CONTENT, body2);
  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call end_instance (cmd: %s)\n", cmd2);

  status = fuze_curl_execute(session, profile, cmd);

  return status;
}

