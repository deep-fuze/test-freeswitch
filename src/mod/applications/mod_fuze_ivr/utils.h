/* 
 *
 * utils.c -- Different utility that might need to go into the core (after cleanup)
 *
 */
#ifndef _UTIL_H_
#define _UTIL_H_

#include "config.h"
#include "fuzenode.h"

const char *fuze_session_encode(switch_core_session_t *session, const char *string);
fuze_status_t fuze_curl_execute(switch_core_session_t *session, ivrc_profile_t *profile, const char *arguments);
switch_status_t ivrc_api_execute(switch_core_session_t *session, const char *apiname, const char *arguments);
#endif /* _UTIL_H_ */

