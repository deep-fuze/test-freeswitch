/* 
 * config.c -- Read configuration file and initialize the menu 
 */
#include <switch.h>
#include "config.h"

const char *global_cf = "fuze_ivr.conf";

/* from menu.c */
const char *get_menu_name(const char *menu_tag);

/* from */
static void append_event_profile(ivrc_menu_t *menu);
static void populate_dtmfa_from_event(ivrc_menu_t *menu);

/*******************************************************************************/
void menu_init(ivrc_profile_t *profile, ivrc_menu_t *menu) 
{
    switch_xml_t cfg, xml, x_profiles, x_profile, x_keys, x_phrases, x_menus, x_menu, x_settings;
    
    menu->profile = profile;
    
    if (!(xml = switch_xml_open_cfg(global_cf, &cfg, NULL))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "IVRC: Open of %s failed\n", global_cf);
        goto end;
    }
    if (!(x_profiles = switch_xml_child(cfg, "profiles"))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "IVRC: No profiles group\n");
        goto end;
    }
    
    if (profile->event_settings) {
        /* TODO Replace this with a switch_event_merge_not_set(...) */
        switch_event_t *menu_default;
        switch_event_create(&menu_default, SWITCH_EVENT_REQUEST_PARAMS);
        if (menu->event_settings) {
            switch_event_merge(menu_default, menu->event_settings);
            switch_event_destroy(&menu->event_settings);
        }
        
        switch_event_create(&menu->event_settings, SWITCH_EVENT_REQUEST_PARAMS);
        switch_event_merge(menu->event_settings, profile->event_settings);
        switch_event_merge(menu->event_settings, menu_default);
        switch_event_destroy(&menu_default);
    }
    
    {
        const char *s_max_attempts = switch_event_get_header(menu->event_settings, "IVR-Maximum-Attempts");
        const char *s_entry_timeout = switch_event_get_header(menu->event_settings, "IVR-Entry-Timeout");
        menu->ivr_maximum_attempts = atoi(s_max_attempts);
        menu->ivr_entry_timeout = atoi(s_entry_timeout);
    }
    
    if ((x_profile = switch_xml_find_child(x_profiles, "profile", "name", profile->name))) {
        if ((x_menus = switch_xml_child(x_profile, "menus"))) {
            if ((x_menu = switch_xml_find_child(x_menus, "menu", "name", menu->name))) {
                
                if ((x_keys = switch_xml_child(x_menu, "keys"))) {
                    switch_event_import_xml(switch_xml_child(x_keys, "key"), "dtmf", "action", &menu->event_keys_dtmf);
                    switch_event_import_xml(switch_xml_child(x_keys, "key"), "action", "dtmf", &menu->event_keys_action);
                    switch_event_import_xml(switch_xml_child(x_keys, "key"), "action", "variable", &menu->event_keys_varname);
                }
                if ((x_phrases = switch_xml_child(x_menu, "phrases"))) {
                    switch_event_import_xml(switch_xml_child(x_phrases, "phrase"), "name", "value", &menu->event_phrases);
                }
                if ((x_settings = switch_xml_child(x_menu, "settings"))) {
                    switch_event_import_xml(switch_xml_child(x_settings, "param"), "name", "value", &menu->event_settings);
                }
                
            }
        }
    }
    
    if (!menu->phrase_params) {
        switch_event_create(&menu->phrase_params, SWITCH_EVENT_REQUEST_PARAMS);
    }
    
end:
    if (xml)
        switch_xml_free(xml);
    return;
    
}

/*******************************************************************************/
void menu_instance_init(ivrc_menu_t *menu) 
{
    append_event_profile(menu);
    
    populate_dtmfa_from_event(menu);
}

/*******************************************************************************/
void menu_instance_free(ivrc_menu_t *menu) 
{
    if (menu->phrase_params) {
        switch_event_destroy(&menu->phrase_params);
        menu->phrase_params = NULL;
    }
    memset(&menu->ivre_d, 0, sizeof(menu->ivre_d));
}

/*******************************************************************************/
void menu_free(ivrc_menu_t *menu) 
{
    if (menu->event_keys_dtmf) {
        switch_event_destroy(&menu->event_keys_dtmf);
    }
    if (menu->event_keys_action) {
        switch_event_destroy(&menu->event_keys_action);
    }
        if (menu->event_keys_varname) {
            switch_event_destroy(&menu->event_keys_varname);
        }

        if (menu->event_phrases) {
                switch_event_destroy(&menu->event_phrases);
        }
        if (menu->event_settings) {
                switch_event_destroy(&menu->event_settings);
        }
}

/*******************************************************************************/
static void append_event_profile(ivrc_menu_t *menu) 
{
    if (!menu->phrase_params) {
        switch_event_create(&menu->phrase_params, SWITCH_EVENT_REQUEST_PARAMS);
    }
    
    /* Used for some appending function */
    if (menu->profile && menu->profile->name && menu->profile->id && menu->profile->domain) {
        switch_event_add_header(menu->phrase_params, SWITCH_STACK_BOTTOM, "VM-Profile", "%s", menu->profile->name);
        switch_event_add_header(menu->phrase_params, SWITCH_STACK_BOTTOM, "VM-Account-ID", "%s", menu->profile->id);
        switch_event_add_header(menu->phrase_params, SWITCH_STACK_BOTTOM, "VM-Account-Domain", "%s", menu->profile->domain);
    }
}

/*******************************************************************************/
static void populate_dtmfa_from_event(ivrc_menu_t *menu) 
{
    int i = 0;
    if (menu->event_keys_dtmf) {
        switch_event_header_t *hp;
        
        for (hp = menu->event_keys_dtmf->headers; hp; hp = hp->next) {
            if (strlen(hp->name) < 3 && hp->value) { /* TODO This is a hack to discard default FS Events ! */
                const char *varphrasename = switch_event_get_header(menu->event_keys_varname, hp->value);
                menu->dtmfa[i++] = hp->name;
                
                if (varphrasename && !zstr(varphrasename)) {
                    switch_event_add_header(menu->phrase_params, SWITCH_STACK_BOTTOM, varphrasename, "%s", hp->name);
                }
            }
        }
    }
    menu->dtmfa[i++] = '\0';
}

/*******************************************************************************/
ivrc_profile_t *get_profile(switch_core_session_t *session, const char *profile_name)
{
    const char *menu_name, *pc_retry;
    ivrc_profile_t *profile = NULL;
    switch_xml_t cfg, xml, x_profiles, x_profile, x_settings;
    
    if (!(xml = switch_xml_open_cfg(global_cf, &cfg, NULL))) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "IVRC: Open of %s failed\n", global_cf);
        return profile;
    }
    if (!(x_profiles = switch_xml_child(cfg, "profiles"))) {
        goto end;
    }
    
    if ((x_profile = switch_xml_find_child(x_profiles, "profile", "name", profile_name))) {
        if (!(profile = switch_core_session_alloc(session, sizeof(ivrc_profile_t)))) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "IVRC: Alloc Failure\n");
            goto end;   
        }
        
        profile->name = profile_name;
        profile->api_profile = profile->name;
        profile->loopback = SWITCH_FALSE;

        /* Populate default general settings */
        switch_event_create(&profile->event_settings, SWITCH_EVENT_REQUEST_PARAMS);
        switch_event_add_header(profile->event_settings, SWITCH_STACK_BOTTOM, "IVR-Maximum-Attempts", "%d", 3);
        switch_event_add_header(profile->event_settings, SWITCH_STACK_BOTTOM, "IVR-Entry-Timeout", "%d", 3000);
        switch_event_add_header(profile->event_settings, SWITCH_STACK_BOTTOM, "Exit-Purge", "%s", "true");
        switch_event_add_header(profile->event_settings, SWITCH_STACK_BOTTOM, "ID-Mask", "%s", "X.");
        
        if ((x_settings = switch_xml_child(x_profile, "settings"))) {
            switch_event_import_xml(switch_xml_child(x_settings, "param"), "name", "value", &profile->event_settings);
        }
        
        /* Default values */
        profile->menu_check_init = "std_menu_accept";
        profile->menu_check_main = "std_menu_get_id";

        profile->accepted = SWITCH_FALSE;
        profile->authenticated = SWITCH_FALSE;

        if ((menu_name = switch_event_get_header(profile->event_settings, "Init-Menu")) != NULL)
            profile->menu_check_init = get_menu_name(menu_name);
        if ((menu_name = switch_event_get_header(profile->event_settings, "Main-Menu")) != NULL)
            profile->menu_check_main = get_menu_name(menu_name);
        if ((pc_retry = switch_event_get_header(profile->event_settings, "IVR-Maximum-Attempts")) != NULL)
            profile->retry = atoi(pc_retry);
    }
    
end:
    switch_xml_free(xml);
    return profile;
}

/*******************************************************************************/
void free_profile(ivrc_profile_t *profile) 
{
    if (profile->event_settings) {
        switch_event_destroy(&profile->event_settings);
    }
}
