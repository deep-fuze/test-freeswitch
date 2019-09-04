//
//  ProtoBufIf.cpp
//
//  Created by Raghavendra Thodime on 02/04/14
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include "AudioQoS.pb.h"
#include "include/ProtoBufIf.h"


using namespace AudioQoSProto;

void proto_buf_register_logcb(log_cb_fp log_cb)
{
    app_log_cb = log_cb;
}

#define NUM_ARRAY_ELEMS(a) (sizeof(a) / sizeof(a[0]))

int protos_encode_rtcp_app_extn(rtcp_app_extn_t *app_extn, char *encoded, int *len)
{
    QoSUpdate update;

    if (!app_extn || !encoded || *len <= 0) {
        if (app_log_cb)
            app_log_cb(3, "Invalid Parameters for rtcp_app encode: %lx %lx %d\n", (long) app_extn, (long) encoded, *len); 
        return -1;
    }

    update.set_jitter(app_extn->jb_depth);
    update.set_late_and_lost(app_extn->late_and_lost_percent);
    update.set_been_active_talker(app_extn->been_active_talker);

    int num_chop_events = NUM_ARRAY_ELEMS(app_extn->chop_events);
    for (int i = 0; i < num_chop_events; ++i) {
        update.add_chop_events(app_extn->chop_events[i]);
    }

    if (*len < update.ByteSize()) {
        if (app_log_cb)
            app_log_cb(3, "Not enough space. Required: %u provided: %d.\n", update.ByteSize(), *len);
        return -1;
    }

    update.SerializeToArray(encoded, *len);
    *len = update.ByteSize();

    return 0;
}

int protos_decode_rtcp_app_extn(char *encoded, int len, rtcp_app_extn_t *app_extn)
{
    QoSUpdate qosupdate;

    if (qosupdate.ParseFromArray(encoded, len)) {

        if (qosupdate.has_jitter()) {
            app_extn->jb_depth = qosupdate.jitter();
        }

        if (qosupdate.has_late_and_lost()) {
            app_extn->late_and_lost_percent = qosupdate.late_and_lost();
        }

        if (qosupdate.has_been_active_talker()) {
            app_extn->been_active_talker = qosupdate.been_active_talker();
        }

        if (qosupdate.chop_events_size() > 0) { 
            for (int i = 0; i < qosupdate.chop_events_size(); i++) {
                app_extn->chop_events[i] = qosupdate.chop_events(i);
            }
        }    
    } else {
        return -1;
    }

    return 0;
}
