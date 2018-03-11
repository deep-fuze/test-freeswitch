/* 
 *
 * utils.c -- Different utility that might need to go into the core (after cleanup)
 *
 */
#ifndef _UTIL_H_
#define _UTIL_H_

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

struct conf_auth_profile
{
  const char *conference_id;
  const char *conf_address;
  const char *meeting_instance_id;
  const char *extension; // x
  int is_retired; // x
};
typedef struct conf_auth_profile conf_auth_profile_t;

fuze_status_t authenticate(switch_core_session_t *session, conf_auth_profile_t *profile, const char *conference_id,
			   const char *instance_id, const char *pin, switch_bool_t verify);
fuze_status_t audio_bridge(switch_core_session_t *session, conf_auth_profile_t *profile, const char *conference_id, const char *instance_id, int is_allowed);

#endif /* _UTIL_H_ */

