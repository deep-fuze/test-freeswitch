//
//  switch_monitor.h
//
//  Created by Raghavendra Thodime on 01/30/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#ifndef __SWITCH_MONITOR_H__
#define __SWITCH_MONITOR_H__

#include "switch.h"

#define DEFAULT_MAX_INACTIVE_MS 100 * 1000 //100 secs: Need enough to compensate for IVR digit collection
#define DEFAULT_MIN_HEARTBEAT_INTERVAL_MS 5 * 1000 //5 secs

/*
 * Initializes the monitor process. Need to be called once per process at the start.
 */
SWITCH_DECLARE(switch_status_t) switch_monitor_init(int max_threads, switch_memory_pool_t *pool);

/*
 * Starts the monitoring for a given thread. If monitoring is successfully started,
 * then thread's internal monitoring index is returned in mindex.
 */
SWITCH_DECLARE(switch_status_t) switch_monitor_start(switch_thread_id_t tid, const char *thread_desc,
                                    int max_inactive_interval_ms, int *mindex);

/*
 * Stops the monitoring for a given thread. mindex is the index provided at the 
 * time of monitor_start.
 */
SWITCH_DECLARE(switch_status_t) switch_monitor_stop(switch_thread_id_t tid, int mindex);

/*
 * Threads call this function to report their health. 
 */
SWITCH_DECLARE(switch_status_t) switch_monitor_alive(switch_thread_id_t tid, int mindex);

/*
 * Suspends the monitoring on a given thread untile next switch_montitor_alive().
 */
SWITCH_DECLARE(switch_status_t) switch_monitor_suspend(switch_thread_id_t tid, int mindex);

/*
 * Reports all the threads and their health based on the command issued.
 */
SWITCH_DECLARE(switch_status_t) switch_monitor_report(switch_stream_handle_t *stream, int argc, char **argv);

/*
 * Changes thread description while running
 */
SWITCH_DECLARE(switch_status_t) switch_monitor_change_desc(switch_thread_id_t tid, int mindex, const char *thread_desc);

SWITCH_DECLARE(switch_status_t) switch_monitor_change_tid(switch_thread_id_t tid, int mindex);

#endif
