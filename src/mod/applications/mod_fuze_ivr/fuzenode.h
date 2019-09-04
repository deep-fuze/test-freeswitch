/* 
 *
 * fuzenode.h -- fuzenode constants
 *
 */
#ifndef _FUZENODE_H_
#define _FUZENODE_H_

/*******************************************************************************/
/* Status of fuze service UCAPI confernece authentication */
typedef enum 
{
    FUZE_STATUS_SUCCESS,
    FUZE_STATUS_GENERR,
    FUZE_STATUS_FALSE,
    FUZE_STATUS_NOTFOUND,
    FUZE_STATUS_IGNORE,
    FUZE_STATUS_FAILED,
    FUZE_STATUS_FOUND = 200,
    FUZE_STATUS_INVALID = 403,
    FUZE_STATUS_INVALID_PIN = 404,
    FUZE_STATUS_RESTRICTED = 405,
    FUZE_STATUS_TIMEOUT = 406
} fuze_status_t;

/*******************************************************************************/
/* Service part of url -- keep the leading slash */
#define VERIFY_PSTN_CALLER_SERVICE "/services/audio/verify_pstn_caller"
#define AUTHENTICATE_CALLER_SERVICE "/json/authenticate_caller"

/*******************************************************************************/
/* FuzeProgress */
#define FuzeProgress_CALL_ANSWERED "CALL_ANSWERED"
#define FuzeProgress_TOO_MANY_DIGITS "TOO_MANY_DIGITS"
#define FuzeProgress_DTMF_TIMEOUT "DTMF_TIMEOUT"
#define FuzeProgress_USER_INPUT "USER_INPUT"
#define FuzeProgress_INVALID_INPUT "INVALID_INPUT"
#define FuzeProgress_ABOUT_TO_AUTH "ABOUT_TO_AUTH"
#define FuzeProgress_AUTH_OK "AUTH_OK"
#define FuzeProgress_PREAUTH_CALL "PREAUTH_CALL"
#define FuzeProgress_PREAUTH_OK "PREAUTH_OK"
#define FuzeProgress_PREAUTH_NOK "PREAUTH_NOK"
#define FuzeProgress_PREAUTH_FAILED "PREAUTH_FAILED"
#define FuzeProgress_HTTP_CODE "HTTP_CODE"
#define FuzeProgress_INVALID_PIN "INVALID_PIN"
#define FuzeProgress_RESTRICTED_ACCESS "RESTRICTED_ACCESS"
#define FuzeProgress_NO_MINUTES "NO_MINUTES_AVAIL"
#define FuzeProgress_UNKNOWN_CODE "UNKNOWN_CODE"
#define FuzeProgress_ATTENDEE_JOIN "ATTENDEE_JOIN"
#define FuzeProgress_MODERATOR_JOIN "MODERATOR_JOIN"
#define FuzeProgress_INPUT_OK "INPUT_OK"
#define FuzeProgress_EMPTY_INPUT "EMPTY_INPUT"
#define FuzeProgress_DTMF_TEST_INPUT "DTMF_TEST_INPUT"
#define FuzeProgress_CALL_REFER "CALL_REFER"

/*******************************************************************************/
/* FuzeCause  */
#define FuzeCause_CONFERENCE_BRIDGED "CONFERENCE_BRIDGED"
#define FuzeCause_MAX_RETRIES "MAX_RETRIES"
#define FuzeCause_AUTH_FAILED "AUTH_FAILED"
#define FuzeCause_INVALID_PIN "INVALID_PIN"
#define FuzeCause_RESTRICTED_ACCESS "RESTRICTED_ACCESS" 
#define FuzeCause_NO_MINUTES "NO_MINUTES_AVAIL"
#define FuzeCause_AUTH_CODE "AUTH_CODE"
#define FuzeCause_CONFERENCE_LOCKED "CONFERENCE_LOCKED"
#define FuzeCause_FUZE_CONNECT "FUZE_CONNECT"
#define FuzeCause_USER_HANGUP "USER_HANGUP"
#define FuzeCause_MISSING_CONF_ID "MISSING_CONF_ID"
#define FuzeCause_DTMF_TEST_OK "DTMF_TEST_OK"
#define FuzeCause_CONFERENCE_TRANSFERED "CONFERENCE_TRANSFERED"

/*******************************************************************************/
/* FreeSWITCHSessionConstants  */
#define FreeSWITCHSessionConstants_CALL_DIRECTION "direction"
#define FreeSWITCHSessionConstants_CALLER_ID_NUMBER "caller_id_number"
#define FreeSWITCHSessionConstants_CALLER_DESTINATION_NUMBER "destination_number"
#define FreeSWITCHSessionConstants_ORIGINATION_CALLER_ID_NUMBER "origination_caller_id_number"
#define FreeSWITCHSessionConstants_NETWORK_ADDR "network_addr"
#define FreeSWITCHSessionConstants_SIP_LOCAL_NETWORK_ADDR "sip_local_network_addr"
#define FreeSWITCHSessionConstants_SIP_FROM_HOST "sip_from_host"
#define FreeSWITCHSessionConstants_SIP_TO_HOST "sip_to_host"
#define FreeSWITCHSessionConstants_SIP_NETWORK_IP "sip_network_ip"
#define FreeSWITCHSessionConstants_SIP_NETWORK_PORT "sip_network_port"
#define FreeSWITCHSessionConstants_REMOTE_MEDIA_IP "remote_media_ip"
#define FreeSWITCHSessionConstants_REMOTE_MEDIA_PORT "remote_media_port"
#define FreeSWITCHSessionConstants_LOCAL_MEDIA_IP "local_media_ip"
#define FreeSWITCHSessionConstants_LOCAL_MEDIA_PORT "local_media_port"
#define FreeSWITCHSessionConstants_CONFERENCE_ID "conference_id"

/*******************************************************************************/
/* Fuzenode menu interfaces  */
void fuze_conference_accept(switch_core_session_t *session, ivrc_profile_t *profile);
void fuze_conference_authenticate(switch_core_session_t *session, ivrc_profile_t *profile);
void fuze_transfer(switch_core_session_t *session, ivrc_profile_t *profile);

#endif
