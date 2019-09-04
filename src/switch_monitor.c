//
//  switch_monitor.c
//
//  Created by Raghavendra Thodime on 01/30/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <syscall.h>
#include "switch_monitor.h"

typedef struct {
    switch_thread_id_t tid;
    switch_thread_id_t system_tid;
    char desc[128];
    int max_interval_ms;
    int heartbeat_count;
    switch_time_t last_heartbeat;
    uint8_t suspended;
} thread_info_t;

static struct {
    int max_threads;
    thread_info_t *tinfo;
    switch_timer_t dummy_timer;
} globals;

SWITCH_DECLARE(switch_status_t) switch_monitor_init(int max_threads, switch_memory_pool_t *pool)
{
    int i;

    globals.max_threads = max_threads;
    globals.tinfo = switch_core_alloc(pool, max_threads * sizeof(*globals.tinfo));

    for (i = 0; i < globals.max_threads; i++) {
        globals.tinfo[i].heartbeat_count = -1;
    }

    /* heartbeat every 30s */
    if (switch_core_timer_init(&globals.dummy_timer, "soft", 30000, 0, pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error while initializing the timer.\n");
        return SWITCH_STATUS_GENERR;
    }
   
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_monitor_start(switch_thread_id_t tid, const char *thread_desc, 
                                            int max_inactive_interval_ms, int *mindex)
{
    switch_time_t now;
    int i;

    for (i = 0; (i < globals.max_threads) && (globals.tinfo[i].heartbeat_count != -1); i++);
    
    if (i == globals.max_threads) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot monitor more than %d threads.\n", globals.max_threads);
        return SWITCH_STATUS_GENERR;
    }

    if (switch_core_timer_now_us(&globals.dummy_timer, &now) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error while getting the current time.\n");
        now = switch_time_now();
    }

    *mindex = i;
    globals.tinfo[i].heartbeat_count = 1;
    globals.tinfo[i].tid = tid;
    globals.tinfo[i].system_tid = syscall(SYS_gettid);
    globals.tinfo[i].max_interval_ms = max_inactive_interval_ms;
    globals.tinfo[i].last_heartbeat = now / 1000;
    strncpy(globals.tinfo[i].desc, thread_desc, sizeof(globals.tinfo[i].desc) - 1);
    globals.tinfo[i].desc[sizeof(globals.tinfo[i].desc) - 1] = '\0';
    globals.tinfo[i].suspended = 0;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Started Monitoring desc=%s index=%d tid=%lx systid=%lx\n",
                                                            thread_desc, i, tid, globals.tinfo[i].system_tid);
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_monitor_stop(switch_thread_id_t tid, int mindex)
{
    if (mindex < 0 || mindex >= globals.max_threads || globals.tinfo[mindex].tid != tid) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Wrong input parameters: %ld %d for stopping the monitor.\n",
                                                tid, mindex);
        return SWITCH_STATUS_GENERR;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Stopped Monitoring desc=%s index=%d tid=%lx systid=%lx\n",
                                                            globals.tinfo[mindex].desc, mindex, 
                                                            globals.tinfo[mindex].tid, globals.tinfo[mindex].system_tid);
    globals.tinfo[mindex].heartbeat_count = -1;

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_monitor_alive(switch_thread_id_t tid, int mindex)
{
    switch_time_t now;

    if (mindex < 0 || mindex >= globals.max_threads || globals.tinfo[mindex].tid != tid) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Wrong input parameters: %ld %d for stopping the monitor.\n",
                                                tid, mindex);
        return SWITCH_STATUS_GENERR;
    }
   
    if (switch_core_timer_now_us(&globals.dummy_timer, &now) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error while getting the current time.\n");
        now = switch_time_now();
    }

    if (++globals.tinfo[mindex].heartbeat_count <= 0) 
        globals.tinfo[mindex].heartbeat_count = 1; //rollover.

    globals.tinfo[mindex].last_heartbeat = now / 1000;
    globals.tinfo[mindex].suspended = 0;
    
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_monitor_suspend(switch_thread_id_t tid, int mindex)
{
    if (mindex < 0 || mindex >= globals.max_threads || globals.tinfo[mindex].tid != tid) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Wrong input parameters: %ld %d for suspending the thread.\n",
                                                tid, mindex);
        return SWITCH_STATUS_GENERR;
    }
   
    globals.tinfo[mindex].suspended = 1;

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_monitor_report(switch_stream_handle_t *stream, int argc, char **argv)
{
    switch_time_t now;
    int i, only_stuck;
    int display_count = 0;

    if (!stream)
        return SWITCH_STATUS_GENERR;

    if (argc <= 1 || !argv[1]) {
        stream->write_function(stream, "monitor threads <all|stuck>");
        return SWITCH_STATUS_SUCCESS;
    }

    if (switch_core_timer_now_us(&globals.dummy_timer, &now) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error while getting the current time.\n");
        now = switch_time_now();
    }

    if (strcasecmp(argv[1], "all") == 0) {
        only_stuck = 0;
    } else if (strcasecmp(argv[1], "stuck") == 0) {
        only_stuck = 1;
    } else {
        stream->write_function(stream, "monitor threads <all|stuck>");
        return SWITCH_STATUS_SUCCESS;
    }

    now = now / 1000;
    stream->write_function(stream, "tid, desc, heartbeat_count, last_heartbeat_ms, status\n\n");
    for (i = 0; i < globals.max_threads; i++) {
        if (globals.tinfo[i].heartbeat_count > 0) {
            int is_stuck = (!globals.tinfo[i].suspended) && (now - globals.tinfo[i].last_heartbeat > globals.tinfo[i].max_interval_ms);
            if (!only_stuck || is_stuck) {
                stream->write_function(stream, "%u, %s, %d, %u %s\n", globals.tinfo[i].system_tid, globals.tinfo[i].desc, 
                                            globals.tinfo[i].heartbeat_count, globals.tinfo[i].last_heartbeat / 1000,
                                            globals.tinfo[i].suspended ? "suspended" : (is_stuck ? "stuck" : "alive"));
                display_count++;
            } 
        }
    }

    stream->write_function(stream, "\n%d thread(s).\n", display_count);

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_monitor_change_desc(switch_thread_id_t tid, int mindex, const char *thread_desc)
{
    if (mindex < 0 || mindex >= globals.max_threads || globals.tinfo[mindex].tid != tid) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Wrong input parameters: %ld %d for changing the desc.\n",
                                                tid, mindex);
        return SWITCH_STATUS_GENERR;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Changed Desc desc=%s=>%s index=%d tid=%lx systid=%lx\n",
                                                            globals.tinfo[mindex].desc, thread_desc, mindex, 
                                                            globals.tinfo[mindex].tid, globals.tinfo[mindex].system_tid);
    strncpy(globals.tinfo[mindex].desc, thread_desc, sizeof(globals.tinfo[mindex].desc) - 1);
    globals.tinfo[mindex].desc[sizeof(globals.tinfo[mindex].desc) - 1] = '\0';

    return SWITCH_STATUS_SUCCESS;
}

SWITCH_DECLARE(switch_status_t) switch_monitor_change_tid(switch_thread_id_t tid, int mindex)
{
  if (mindex < 0 || mindex >= globals.max_threads) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Wrong input parameters: %ld %d for changing the desc.\n",
		      tid, mindex);
    return SWITCH_STATUS_GENERR;
  }

  globals.tinfo[mindex].tid = tid;
  return SWITCH_STATUS_SUCCESS;
}
