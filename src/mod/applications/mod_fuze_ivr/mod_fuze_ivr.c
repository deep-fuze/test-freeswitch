#include <switch.h>

#include "config.h"
#include "menu.h"
#include "fuzenode.h"

/* Prototypes
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_fuze_ivr_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_fuze_ivr_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_fuze_ivr_load);

/* SWITCH_MODULE_DEFINITION(name, load, shutdown, runtime)
 * Defines a switch_loadable_module_function_table_t and a static const char[] modname
 */
SWITCH_MODULE_DEFINITION(mod_fuze_ivr, mod_fuze_ivr_load, mod_fuze_ivr_shutdown, NULL);

// TODO: description :(
#define IVRC_DESC "fuze_ivr"
#define IVRC_USAGE "fuze_ivr"

/*******************************************************************************/
/* Get channel values */
static void mycb(switch_core_session_t *session, switch_channel_callstate_t callstate, switch_device_record_t *drec)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);

	switch_log_printf(SWITCH_CHANNEL_CHANNEL_LOG(channel), SWITCH_LOG_NOTICE, "IVRC: %s device: %s\nState: %s Dev State: %s/%s Total:%u Offhook:%u Active:%u Held:%u Hungup:%u Dur: %u %s\n",
							switch_channel_get_name(channel),
							drec->device_id,
							switch_channel_callstate2str(callstate),
							switch_channel_device_state2str(drec->last_state),
							switch_channel_device_state2str(drec->state),
							drec->stats.total,
							drec->stats.offhook,
							drec->stats.active,
							drec->stats.held,
							drec->stats.hup,
							drec->active_stop ? (uint32_t)(drec->active_stop - drec->active_start) / 1000 : 0,
							switch_channel_test_flag(channel, CF_FINAL_DEVICE_LEG) ? "FINAL LEG" : "");
}

/*******************************************************************************/
SWITCH_STANDARD_APP(fuze_ivr_function)
{
	const char *profile_name = NULL;
	ivrc_profile_t *profile = NULL;
	char *argv[6] = { 0 };
	char *x_conference[10] = { 0 };
	char *mydata = NULL;

	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_channel_set_variable_var_check(channel, "channel_type", "DIAL_IN_ALEG", SWITCH_FALSE);

	if (!zstr(data)) {
		mydata = switch_core_session_strdup(session, data);
		switch_separate_string(mydata, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
	}

	if (argv[0])
		profile_name = argv[0];

	if (profile_name) {
		profile = get_profile(session, profile_name);

		if (profile) {
			void(*fPtrInit)(switch_core_session_t *session, ivrc_profile_t *profile) = ivrc_get_menu_function(profile->menu_check_init);

			if (fPtrInit) {
				fPtrInit(session, profile);
			}

			if (profile->id && !strcasecmp(profile->menu_check_init,"std_menu_get_id")) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "IVRC: Test menu '%s'\n", profile->menu_check_init);
				switch_ivr_phrase_macro(session, "connected@fuze_ivr", NULL, NULL, NULL);
			}
			if (!profile->authenticated && !profile->accepted) {
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			}
			if(profile->conference_id ) {
				switch_separate_string_string((char *)profile->conference_id, "@", x_conference, 10);
					if(!_zstr(x_conference[0]))
						switch_channel_set_variable_var_check(channel, "conference_id", x_conference[0], SWITCH_FALSE);
			}
			free_profile(profile);
			return;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "IVRC: Profile '%s' not found\n", profile_name);
		}
	}
	switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	return;
}


/*******************************************************************************/
/*
 * switch_status_t mod_fuze_ivr_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool)
 */
SWITCH_MODULE_LOAD_FUNCTION(mod_fuze_ivr_load)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	switch_application_interface_t *app_interface;

	switch_channel_bind_device_state_handler(mycb, NULL);

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	SWITCH_ADD_APP(app_interface, "fuze_ivr", "fuze_ivr", IVRC_DESC, fuze_ivr_function, IVRC_USAGE, SAF_NONE);

	/* indicate that the module should continue to be loaded (status == SWITCH_STATUS_SUCCESS) */
	return status;
}

/*******************************************************************************/
/*
 * Called when the system shuts down
 * switch_status_t mod_fuze_ivr_shutdown()
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_fuze_ivr_shutdown)
{
	/* Cleanup dynamically allocated config settings
	 *
	 *       switch_channel_unbind_device_state_handler(mycb);
	 *       switch_xml_config_cleanup(instructions);
	 */

	return SWITCH_STATUS_SUCCESS;
}

