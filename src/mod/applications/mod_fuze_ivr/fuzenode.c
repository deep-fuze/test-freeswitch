/*
 * fuzenode.c --
 *
 */
#include <switch.h>

#include "menu.h"
#include "utils.h"
#include "fuzenode.h"


/*******************************************************************************/
/* List of available menus */
ivrc_menu_function_t menu_list[] =
{
        {"fuze_conference_accept", fuze_conference_accept},
        {"fuze_conference_authenticate", fuze_conference_authenticate},
        {"std_menu_accept", std_menu_accept},
        {"std_menu_get_id", std_menu_get_id},
        {"fuze_transfer", fuze_transfer},
        { NULL, NULL }
};

#define MAX_EMAIL_LEN 1024

/*******************************************************************************/
void fuze_session_bridge(switch_core_session_t *session, ivrc_profile_t *profile)
{
        switch_channel_t *channel = switch_core_session_get_channel(session);
        const char *destination_number;
        const char *extension = profile->conf_address; // TODO: to check encoing type
        char email[MAX_EMAIL_LEN];

        switch_channel_export_variable_var_check(channel, "conferense_id", profile->conference_id, SWITCH_EXPORT_VARS_VARIABLE, SWITCH_FALSE);

        if (!profile->meeting_instance_id || !strcasecmp(profile->meeting_instance_id,"")) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,"IVRC: meeting_instance_id field is missing\n");
                switch_channel_set_variable_var_check(channel, "meeting_instance_id", "", SWITCH_FALSE);
        }
        else {
                switch_channel_set_variable_var_check(channel, "meeting_instance_id", profile->meeting_instance_id, SWITCH_FALSE);
        }
        if (profile->is_retired == SWITCH_TRUE) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,"IVRC: destination number is retired\n");
                switch_ivr_phrase_macro(session, "retired@fuze_ivr", NULL, NULL, NULL);
        }
        if (switch_channel_get_variable(channel, "caller_id_number")) {
          switch_snprintf(email, MAX_EMAIL_LEN, "sip:%s@%s;", switch_channel_get_variable(channel, "caller_id_number"),
                          switch_core_get_hostname());
        }
        if (profile->id) {
          switch_snprintf(email, MAX_EMAIL_LEN, "%sid=%s;", email, profile->id);
        }
        if (profile->meeting_instance_id) {
          switch_snprintf(email, MAX_EMAIL_LEN, "%sinst=%s", email, profile->meeting_instance_id);
        }
        if (profile->caller_name) {
          switch_snprintf(email, MAX_EMAIL_LEN, "%s;contactive=true", email);
          switch_snprintf(email, MAX_EMAIL_LEN, "%s;contactive_name=%s", email, profile->caller_name);
        }
        if (profile->uname) {
          switch_snprintf(email, MAX_EMAIL_LEN, "%s;userid=%s", email, profile->uname);
        }
        if (profile->moderator) {
          switch_snprintf(email, MAX_EMAIL_LEN, "%s;moderator=true", email, profile->uname);
        }
        if (profile->caller_contactive_found) {
          switch_snprintf(email, MAX_EMAIL_LEN, "%s;contactive=true", email);
          if (profile->caller_userid) {
            switch_snprintf(email, MAX_EMAIL_LEN, "%s;userid=%s", email, profile->caller_userid);
          }
          if (profile->caller_email) {
            switch_snprintf(email, MAX_EMAIL_LEN, "%s;email=%s", email, profile->caller_email);
          }
        }
        if (profile->corp_name) {
          switch_snprintf(email, MAX_EMAIL_LEN, "%s;corp=%s", email, profile->corp_name);
        }
        switch_channel_set_variable(channel, "email-sdp", email);

        switch_channel_set_variable_var_check(channel, "extension", extension, SWITCH_FALSE);
        destination_number = switch_channel_get_variable(channel, "destination_number");
        switch_channel_set_variable_var_check(channel, "dn", destination_number, SWITCH_FALSE);
        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeCause_CONFERENCE_BRIDGED, SWITCH_FALSE);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: Bridge to conference (dn=%s; extension=%s email=%s)\n", destination_number, extension, email);
        switch_ivr_session_transfer(session, destination_number, "XML", "fuze_conference");
        return;
}

/*******************************************************************************/
/* Dialout */
/*******************************************************************************/

/*******************************************************************************/
static switch_bool_t is_moderator(switch_core_session_t *session)
{
        const char *conf_member_flags_str;
        switch_channel_t *channel = switch_core_session_get_channel(session);

        conf_member_flags_str = switch_channel_get_variable(channel, "conference_member_flags");
        if (conf_member_flags_str && !zstr(conf_member_flags_str) && (strstr(conf_member_flags_str,"moderator") != NULL)) {
                return SWITCH_TRUE;
        }
        else {
                switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_ATTENDEE_JOIN, SWITCH_FALSE);
                switch_log_printf(SWITCH_CHANNEL_CHANNEL_LOG(channel), SWITCH_LOG_DEBUG, "IVRC: Attendee is joining the call. Check the conference lock state.\n");
                return SWITCH_FALSE;
        }
}

/*******************************************************************************/
static switch_bool_t is_conference_locked(switch_core_session_t *session, const char *conference_id)
{
        char *mydata = NULL;
        switch_bool_t locked = SWITCH_FALSE;
        switch_channel_t *channel = switch_core_session_get_channel(session);
        switch_stream_handle_t stream = { 0 };
        SWITCH_STANDARD_STREAM(stream);


        mydata = switch_core_session_sprintf(session,"%s get is_locked", conference_id);
        switch_api_execute("conference", mydata, session, &stream);
        if (!strcasecmp(mydata, "locked")) {
                switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_CONFERENCE_LOCKED, SWITCH_FALSE);
                switch_log_printf(SWITCH_CHANNEL_CHANNEL_LOG(channel), SWITCH_LOG_DEBUG, "IVRC: Conference %s get is locked", conference_id);
                switch_ivr_phrase_macro(session, "locked@fuze_ivr",NULL,NULL,NULL);
                locked = SWITCH_TRUE;
        }
        switch_safe_free(stream.data);
        return locked;
}

/*******************************************************************************/
void fuze_conference_accept(switch_core_session_t *session, ivrc_profile_t *profile)
{
        const char *conference_id = NULL;
        void (*fPtr)(switch_core_session_t *session, ivrc_profile_t *profile) = ivrc_get_menu_function("std_menu_accept");

        switch_channel_t *channel = switch_core_session_get_channel(session);
        switch_channel_set_variable_var_check(channel, "channel_type", "CALL_OUT", SWITCH_FALSE);

        switch_channel_answer(channel); // ??? wait_for_answer
        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_CALL_ANSWERED, SWITCH_FALSE);

        conference_id = switch_channel_get_variable(channel, "conference_id");
        if (!conference_id || zstr(conference_id)) {
                switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_MISSING_CONF_ID, SWITCH_FALSE);
                return;
        }

        if (!is_moderator(session) && !profile->moderator) {
                if (is_conference_locked(session, conference_id)) {
                        return;
                }
        }
        else {
                switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_MODERATOR_JOIN, SWITCH_FALSE);
                switch_log_printf(SWITCH_CHANNEL_CHANNEL_LOG(channel), SWITCH_LOG_DEBUG, "IVRC: Moderator is joining the call. No check for conference lock state.");
        }

        if (fPtr) {
                fPtr(session, profile);
                if (profile->accepted) {
                        //switch_ivr_phrase_macro(session, "connected@fuze_ivr", NULL, NULL, NULL); // In menu :)
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_INPUT_OK, SWITCH_FALSE);
                        conference_id = switch_core_session_sprintf(session,"fuzedialout-%s",conference_id);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: Transfer to: %s)\n", conference_id);
                        switch_ivr_session_transfer(session, conference_id, "XML", "fuze_conference");
                        switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_FUZE_CONNECT, SWITCH_FALSE);
                }
        }
}

/*******************************************************************************/
/* Dialin */
/*******************************************************************************/

#define AUTH_EMAIL "null-callwave_service@relay11.callwave.com"
#define AUTH_PASSWD "2ymkRlqIoDkuYhAOEXqfjTZoSktLXqCM"
#define MAX_MEETING_NUMBER_LEN 10
#define PREPROD_MEETING_ID_LEN 7
#define PROD_MEETING_ID_LEN 8
#define CONTENT_URLENCODED "Content-Type application/x-www-form-urlencoded"
#define CONTENT_JSON "Content-Type application/json"
#define AUTHORIZATION "Authorization-Bearer %s"
#define BODY_FMT "auth_email=%s&auth_password=%s&mobile_number=%s&dialed_number=%s&iso_code=%s"
#define BODY_JSON_FMT "auth_email=%s&auth_password=%s&meeting_id=%s&pin=%s&call_info={\"caller_id_number\":\"%s\",\"destination_number\":\"%s\"}"
#define BODY2_JSON_FMT "auth_email=%s&auth_password=%s&meeting_id=%s&username=%s&call_info={\"caller_id_number\":\"%s\",\"destination_number\":\"%s\"}"


struct server_iso_code {
        const char *server_name;
        const char *country_code;
};

typedef struct server_iso_code server_iso_code_t;

/*******************************************************************************/
/* List of servers' iso country codes */
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

void fuze_conference_number_authenticate(switch_core_session_t *session, ivrc_profile_t *profile);

void fuze_conference_authenticate(switch_core_session_t *session, ivrc_profile_t *profile)
{
        fuze_status_t status = FUZE_STATUS_FALSE;
        const char *pin = "";
        const char *url = NULL;
        const char *email = NULL;
        const char *password = NULL;
        const char *caller_number = NULL;
        const char *dialed_number = NULL;
        switch_channel_t *channel = switch_core_session_get_channel(session);
        void (*fPtr)(switch_core_session_t *session, ivrc_profile_t *profile) = ivrc_get_menu_function("std_menu_get_id");
        switch_channel_set_variable_var_check(channel, "channel_type", "DIAL_IN_ALEG", SWITCH_FALSE);
        if (!fPtr) {
                switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_CALL_ANSWERED, SWITCH_FALSE);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "IVRC: Internal error\n");
                return;
        }

        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_CALL_ANSWERED, SWITCH_FALSE);

        url = switch_channel_get_variable(channel, "fuze_callback_caller_url");
        if (!url || zstr(url)) {
                url = switch_channel_get_variable(channel, "callback_caller_url");
        }
        email = switch_channel_get_variable(channel, "fuze_callback_caller_email");
        password = switch_channel_get_variable(channel, "fuze_callback_caller_password");
        if (!email || !password) {
          switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Fuze Conference Authenticate Fail email=%s password=%s\n",
                            email ? email : "null", password ? password : "null");
          return;
        }
        if (url && !zstr(url)) {
                const char *body, *body2, *cmd, *cmd2;
                int max_retries;
                const char *meeting_id = NULL;
                const char *userid = NULL;
                const char *corp = NULL;
                const char *name = NULL;

                switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_PREAUTH_CALL, SWITCH_FALSE);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: verify_pstn_caller_url: %s%s\n", url, VERIFY_PSTN_CALLER_SERVICE);


                caller_number = switch_channel_get_variable(channel, "caller_id_number");
                dialed_number = switch_channel_get_variable(channel, "destination_number");

                body = switch_core_session_sprintf(session, BODY_FMT, email, password, caller_number, dialed_number, get_country_iso_code());
                cmd = switch_core_session_sprintf(session, "%s%s json %s post %s", url, VERIFY_PSTN_CALLER_SERVICE, CONTENT_URLENCODED, body);
                body2 = switch_core_session_sprintf(session, BODY_FMT, email, "xxxxx", caller_number, dialed_number, get_country_iso_code());
                cmd2 = switch_core_session_sprintf(session, "%s%s json %s post %s", url, VERIFY_PSTN_CALLER_SERVICE, CONTENT_URLENCODED, body2);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call verify_pstn_caller (cmd: %s)- dialed_number=%s callerid_number=%s\n",
                        cmd2, dialed_number, caller_number);

                status = fuze_curl_execute(session, profile, cmd);
                //------------------------------------------------

                meeting_id = switch_channel_get_variable(channel, "sip_h_x-fuze-meetingid");
                userid = switch_channel_get_variable(channel, "sip_h_x-fuze-userid");
                corp = switch_channel_get_variable(channel, "sip_h_x-fuze-customer-code");
                name = switch_channel_get_variable(channel, "sip_h_x-fuze-user-fn");

                if (meeting_id) {
                  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: Found fuze meeting ID in sip message: %s\n", meeting_id);
                  profile->conference_id = switch_core_session_sprintf(session, "%s", meeting_id);
                  profile->id = switch_core_session_sprintf(session, "%s", meeting_id);
                }
                
                if (userid) {
                  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: Found fuze uname in sip message: %s\n", userid);
                  profile->uname = switch_core_session_sprintf(session, "%s", userid);
                }
                
                if (corp) {
                  profile->corp_name = switch_core_session_sprintf(session, "%s", corp);
                }

                if (meeting_id) {
                  body = switch_core_session_sprintf(session, BODY2_JSON_FMT,
                                                     email, password, meeting_id, userid, caller_number, dialed_number);
                  body2 = switch_core_session_sprintf(session, BODY2_JSON_FMT,
                                                      email, "xxxxx", meeting_id, userid, caller_number, dialed_number);
                  cmd = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUTHENTICATE_USER_SERVICE, CONTENT_URLENCODED, body);
                  cmd2 = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUTHENTICATE_USER_SERVICE, CONTENT_URLENCODED, body2);
                  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call authenticate_user (cmd: %s) - dialed_number=%s callerid_number=%s\n",
                                    cmd2, dialed_number, caller_number);
                  status = fuze_curl_execute(session, profile, cmd);
                }

                if (name) {
                  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: Found fuze name in sip message: %s\n", name);
                  profile->caller_name = switch_core_session_sprintf(session, "%s", name);
                }

                if (status == FUZE_STATUS_SUCCESS) { // 200 && 200 && conf_address
                        profile->authenticated = SWITCH_TRUE;
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_AUTH_OK, SWITCH_FALSE);
                        switch_ivr_phrase_macro(session, "connected@fuze_ivr", NULL, NULL, NULL);
                        fuze_session_bridge(session, profile);
                        return;
                }
                //      else if (status != FUZE_STATUS_FOUND) {
                //          switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_PREAUTH_FAILED, SWITCH_FALSE);
                //          switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: verify_caller failed:  %d\n", status);
                //          return;
                //      }
                switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_PREAUTH_CALL, SWITCH_FALSE);

                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: authenticate_caller_url: %s%s\n", url, AUTHENTICATE_CALLER_SERVICE);

                status = FUZE_STATUS_NOTFOUND;
                max_retries = profile->retry;

                while ((status  == FUZE_STATUS_NOTFOUND) && (profile->retry > 0) && (max_retries > 0)) { // [403|404]
                    //------------------------------------------ IVRC
                    profile->authenticated = SWITCH_FALSE;

                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: profile->retry=%d max_retries=%d\n",
                                      profile->retry, max_retries);

                    max_retries -= 1;

                    if (fPtr) {
                        int expected_meeting_id_len = fuze_expected_meeting_id_len();

                        fPtr(session, profile);

                        pin = "";

                        if (profile->id && !zstr(profile->id)) {
                            int len = strlen(profile->id);

                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: len=%d profile->id=%s\n", len, profile->id);

                            if (len > expected_meeting_id_len) {
                                char buf[MAX_MEETING_NUMBER_LEN + 1];
                                if (len >= (expected_meeting_id_len + 4)) {
                                    switch_snprintf(buf, 5, "%s", &profile->id[expected_meeting_id_len]);
                                    buf[4] = '\0';
                                    pin = switch_core_session_strdup(session, buf);
                                }
                                switch_snprintf(buf, expected_meeting_id_len+1, "%s", profile->id);
                                buf[expected_meeting_id_len] = '\0';
                                profile->id = switch_core_session_strdup(session, buf);
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: meeting#: %s pin : %s\n", profile->id, pin);
                            }
                        } else {
                        }
                    }

                    body = switch_core_session_sprintf(session, BODY_JSON_FMT,
                                                       email, password, profile->id, pin, caller_number, dialed_number);
                    cmd = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUTHENTICATE_CALLER_SERVICE, CONTENT_URLENCODED, body);
                    body2 = switch_core_session_sprintf(session, BODY_JSON_FMT,
                                                       email, "xxxxx", profile->id, pin, caller_number, dialed_number);
                    cmd2 = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUTHENTICATE_CALLER_SERVICE, CONTENT_URLENCODED, body2);
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call authenticate_caller (cmd: %s) - dialed_number=%s callerid_number=%s\n",
                                      cmd2, dialed_number, caller_number);

                    status = fuze_curl_execute(session, profile, cmd);
                    //--------------------------------------------------------------------------------------------------
                    if (status == FUZE_STATUS_SUCCESS) { // 200 && 200 && conf_address --> bridge/transfer to conference
                        profile->authenticated = SWITCH_TRUE;
                        break;
                    }
                    else if (profile->retry == 0) {
                      switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_UNKNOWN_CODE, SWITCH_FALSE); // json_code
                      switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                      switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: Internal authentication failed: %d meeting#: %s pin : %s\n", status, profile->id, pin);
                      switch_ivr_phrase_macro(session, "call_cannot_be_completed@fuze_ivr",NULL,NULL,NULL);
                      return;
                    }
                    else if (status == FUZE_STATUS_NOTFOUND) { // 403, 404
                       switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeCause_INVALID_PIN, SWITCH_FALSE); // json_code
                       switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                       switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: Invalid PIN entered meeting#: %s pin : %s\n", profile->id, pin); // %d times/num_attempts
                       switch_ivr_phrase_macro(session, "invalid_entry@fuze_ivr",NULL,NULL,NULL);
                    }
                    else if (status == FUZE_STATUS_RESTRICTED) { // 405
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_RESTRICTED_ACCESS, SWITCH_FALSE); // json_code
                        switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: International dial-in not authorized for the meeting the user is attempting to join\n");
                        switch_ivr_phrase_macro(session, "restricted@fuze_ivr",NULL,NULL,NULL);
                        return;
                    }
                    else if (status == FUZE_STATUS_TIMEOUT) { // 406
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_NO_MINUTES, SWITCH_FALSE);
                        switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC:  No minutes available for the account\n");
                        switch_ivr_phrase_macro(session, "no_minutes@fuze_ivr",NULL,NULL,NULL);
                        return;
                    }
                    else {
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_UNKNOWN_CODE, SWITCH_FALSE); // json_code
                        switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: Internal authentication failed: %d meeting#: %s pin : %s\n", status, profile->id, pin);
                        switch_ivr_phrase_macro(session, "call_cannot_be_completed@fuze_ivr",NULL,NULL,NULL);
                        return;
                    }
                } // while ((status  == FUZE_STATUS_NOTFOUND) && (profile->retry > 0))
        } // if (url)

        /* successfully authenticated ... now let's get info about the number */
        if (profile->number_auth_is_allowed) {
            fuze_conference_number_authenticate(session, profile);
            switch_channel_set_variable_var_check(channel, "caller_name" , profile->caller_name, SWITCH_FALSE);
            switch_channel_set_variable_var_check(channel, "caller_email" , profile->caller_email, SWITCH_FALSE);
            switch_channel_set_variable_var_check(channel, "caller_corp_name" , profile->corp_name, SWITCH_FALSE);
            switch_channel_set_variable_var_check(channel, "caller_userid" , profile->caller_userid, SWITCH_FALSE);
        }
        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_AUTH_OK, SWITCH_FALSE);
        switch_channel_set_variable_var_check(channel, "meeting_number", profile->id, SWITCH_FALSE);
        switch_channel_set_variable_var_check(channel, "meeting_pin", pin, SWITCH_FALSE);
        switch_channel_set_variable_var_check(channel, "dialed_number" , dialed_number, SWITCH_FALSE);

        switch_ivr_phrase_macro(session, "connected@fuze_ivr", NULL, NULL, NULL); // Why here?
        fuze_session_bridge(session, profile);

        return;
}

void fuze_conference_number_authenticate(switch_core_session_t *session, ivrc_profile_t *profile)
{
  fuze_status_t status = FUZE_STATUS_FALSE;
  const char *base_url, *url, *auth, *bearer;
  const char *caller_number, *full_from;
  const char *cmd;

  switch_channel_t *channel = switch_core_session_get_channel(session);

  base_url = switch_channel_get_variable(channel, "fuze_contactive_caller_url");
  auth = switch_channel_get_variable(channel, "fuze_contactive_caller_token");


  if (!base_url || !auth || !profile->corp_name) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Fuze Conference Authenticate Fail url=%s auth=%s corp_name=%s\n",
                      base_url ? "set" : "null", auth ? "set" : "null", profile->corp_name ? profile->corp_name : "null");
    return;
  }

  caller_number = switch_channel_get_variable(channel, "sip_from_user");
  full_from = switch_channel_get_variable(channel, "sip_full_from");

  if (!caller_number || !full_from) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "!caller_number || !full_from\n");
    return;
  }

#if 0
  if (!strstr(full_from, "user=phone")) {
    return;
  }
#endif

  url = switch_core_session_sprintf(session, base_url, profile->corp_name, caller_number);
  bearer = switch_core_session_sprintf(session, AUTHORIZATION, auth);
  
  cmd = switch_core_session_sprintf(session, "%s %s %s get", url, CONTENT_URLENCODED, bearer);

  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call contactive (cmd: %s\n", cmd);

  status = fuze_contactive_execute(session, profile, cmd);
  //------------------------------------------------                                                                                                                                                                                                                     
  if (status == FUZE_STATUS_SUCCESS) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ok!\n");
  } else {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "not ok!\n");
  }
}

void fuze_transfer(switch_core_session_t *session, ivrc_profile_t *profile)
{
        const char *meeting_pin = "";
        const char *meeting_number = "";
        const char *url;
        const char *caller_number;
        const char *dialed_number;
        const char *email, *password;

        fuze_status_t status = FUZE_STATUS_FALSE;

        switch_channel_t *channel = switch_core_session_get_channel(session);

        switch_channel_set_variable_var_check(channel, "channel_type", "DIAL_IN_ALEG", SWITCH_FALSE);
        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_CALL_REFER, SWITCH_FALSE);

        /* restore important channel variables to it's prime values */
        caller_number = switch_channel_get_variable(channel, "caller_id_number");
        dialed_number = switch_channel_get_variable(channel, "dialed_number");
        switch_channel_set_variable_var_check(channel,"destination_number", dialed_number, SWITCH_FALSE);

        url = switch_channel_get_variable(channel, "fuze_callback_caller_url");
        if (!url || zstr(url)) {
                url = switch_channel_get_variable(channel, "callback_caller_url");
        }

        if (url && !zstr(url)) {
                const char *body, *cmd, *body2, *cmd2;

                switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_ABOUT_TO_AUTH, SWITCH_FALSE);

                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: authenticate_caller_url: %s%s\n", url, AUTHENTICATE_CALLER_SERVICE);

                profile->authenticated = SWITCH_FALSE;
                meeting_pin = switch_channel_get_variable(channel, "meeting_pin");
                meeting_number = switch_channel_get_variable(channel, "meeting_number");
                switch_channel_del_variable_prefix(channel,"sip_refer_to");

                if(zstr(meeting_pin))
                        meeting_pin = "";

                email = switch_channel_get_variable(channel, "fuze_callback_caller_email");
                password = switch_channel_get_variable(channel, "fuze_callback_caller_password");
                if (!email || !password) {
                  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Fuze TRANSFER Authenticate Fail email=%s password=%s\n",
                                    email ? email : "null", password ? password : "null");
                  return;
                }

                body = switch_core_session_sprintf(session, BODY_JSON_FMT, email, password, meeting_number, meeting_pin, caller_number, dialed_number);
                cmd = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUTHENTICATE_CALLER_SERVICE, CONTENT_URLENCODED, body);
                body2 = switch_core_session_sprintf(session, BODY_JSON_FMT, email, "xxxxx", meeting_number, meeting_pin, caller_number, dialed_number);
                cmd2 = switch_core_session_sprintf(session, "%s%s json %s post %s", url, AUTHENTICATE_CALLER_SERVICE, CONTENT_URLENCODED, body2);

                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: About to call authenticate_caller (cmd: %s) - dialed_number=%s callerid_number=%s\n",
                        cmd2, dialed_number, caller_number);

                status = fuze_curl_execute(session, profile, cmd);
                //--------------------------------------------------------------------------------------------------
                if (status == FUZE_STATUS_SUCCESS) { // 200 && 200 && conf_address --> bridge/transfer to conference
                        profile->authenticated = SWITCH_TRUE;
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_AUTH_OK, SWITCH_FALSE);
                        switch_channel_set_variable(channel, "meeting_id", meeting_number);
                        fuze_session_bridge(session, profile);
                        return;
                }
                else if (status == FUZE_STATUS_NOTFOUND) { // 403, 404
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeCause_INVALID_PIN, SWITCH_FALSE);
                        switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "IVRC: Invalid PIN entered meeting_id=%s pin=%s\n", meeting_number, meeting_pin); // %d times/num_attempts
                        switch_ivr_phrase_macro(session, "invalid_entry@fuze_ivr",NULL,NULL,NULL);
                        return;
                }
                else if (status == FUZE_STATUS_RESTRICTED) { // 405
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_RESTRICTED_ACCESS, SWITCH_FALSE); // json_code
                        switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: International dial-in not authorized for the meeting the user is attempting to join\n");
                        switch_ivr_phrase_macro(session, "restricted@fuze_ivr",NULL,NULL,NULL);
                        return;
                }
                else if (status == FUZE_STATUS_TIMEOUT) { // 406
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_NO_MINUTES, SWITCH_FALSE);
                        switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC:  No minutes available for the account\n");
                        switch_ivr_phrase_macro(session, "no_minutes@fuze_ivr",NULL,NULL,NULL);
                        return;
                }
                else {
                        switch_channel_set_variable_var_check(channel, "fuze_progress", FuzeProgress_UNKNOWN_CODE, SWITCH_FALSE); // json_code
                        switch_channel_set_variable_var_check(channel, "fuze_cause", FuzeCause_AUTH_FAILED, SWITCH_FALSE);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: Internal authentication failed: %d meeting_id=%s pin=%s\n", status, meeting_number, meeting_pin);
                        switch_ivr_phrase_macro(session, "call_cannot_be_completed@fuze_ivr",NULL,NULL,NULL);
                        return;
                }

        }
}
