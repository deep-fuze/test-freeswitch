/* 
 * menu.h -- IVRC Menu Include
 *
 */
#ifndef _MENU_H_
#define _MENU_H_

#include "config.h"

void std_menu_accept(switch_core_session_t *session, ivrc_profile_t *profile);
void std_menu_get_id(switch_core_session_t *session, ivrc_profile_t *profile);

char *ivrc_menu_get_input_set(switch_core_session_t *session, ivrc_profile_t *profile, ivrc_menu_t *menu, const char *input_mask);


struct ivrc_menu_function {
    const char *name;
    void (*pt2Func)(switch_core_session_t *session, ivrc_profile_t *profile);
    
};
typedef struct ivrc_menu_function ivrc_menu_function_t;

extern ivrc_menu_function_t menu_list[];

void (*ivrc_get_menu_function(const char *menu_name))(switch_core_session_t *session, ivrc_profile_t *profile);

#endif /* _MENU_H_ */
