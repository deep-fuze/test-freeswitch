//
//  Transport_c.h
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/16/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

/*
 * C interface for Transport library. Currently has only polling(asynchronous interface).
 * Can be extended as needed.
 */

#ifndef __FUZE_TRANSPORT_C_H__
#define __FUZE_TRANSPORT_C_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
#include <stdint.h>
#include <netinet/in.h>
#endif

typedef enum 
{
    PT_LOW,
    PT_MIDDLE,
    PT_HIGH,
    PT_MAX_PRIORITY
} transport_priority_t;

typedef enum
{
    CONN_INVALID,
    CONN_UDP,
    CONN_TCP,
    CONN_TCP_LISTENER,
    CONN_TLS,	

    CONN_MAX
} connection_type_t;

typedef enum
{
    TR_STATUS_SUCCESS,
    TR_STATUS_FALSE,
    TR_STATUS_SOCKET_ERROR,
    TR_STATUS_CONNECTED,
    TR_STATUS_DISCONNECTED,
} transport_status_t;

typedef struct {
    int family;
    union {
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    }sa;
} __sockaddr_t;

typedef void (*trace_cb_t)(int16_t level, const char *msg);
    
/*
 enum RateType
 {
    RT_LOCAL_SEND  = 0
    RT_LOCAL_RECV  = 1
    RT_REMOTE_SEND = 2
    RT_REMOTE_RECV = 3
 };
*/
typedef void (*rate_cb_t)(void*    conn,
                          uint16_t type, /* as shown above */
                          uint16_t rateKbps,
                          uint16_t count,
                          uint16_t arrivedTime);
void fuze_transport_register_rate_cb(rate_cb_t rate_cb);

extern void fuze_transport_init(int enable_server_mode);

//App can register its own tracer.
extern void fuze_transport_register_trace_cb(trace_cb_t trace_cb);

//Creates a transport base; Each base can hold multiple connections.
extern void* fuze_transport_create_transport_base();
extern void fuze_transport_destroy_transport_base(void *tbase);

//Creates a new connection within a given base.
extern void* fuze_transport_tbase_create_connection(void *tbase, connection_type_t conn_type, int rtcp, int conference);
extern void fuze_transport_close_connection(void *conn);

extern const char *fuze_transport_get_connection_name(void *conn);
extern void fuze_transport_set_connection_name(void *conn, const char *name);

//Set local address; If set, can be used to bind. 
extern int fuze_transport_connection_set_local_address(void *conn, const char *ip, uint16_t port);

//Set remote address; If set, can be used to connect or as remote target (for connection less transports).
extern int fuze_transport_connection_set_remote_address(void *conn, const char *ip, uint16_t port);

//Starts the connection. Internally initializes the sender and receiver for this connection.
extern transport_status_t fuze_transport_connection_start(void *conn);

/* Check to see if there is a pending read event. timeout_us is time to wait in case no event exists, 
 *  given in micro seconds. If timeout_us is zero, then it returns immediately. If it is -1, then
 *  waits until an event happens.
 */
extern transport_status_t fuze_transport_socket_poll(void *conn, int timeout_us);

/* Non-blocking read from socket. If blocking or timed-wait is required, then use in conjunction with above poll API.
 */
extern transport_status_t fuze_transport_socket_read(void *conn, __sockaddr_t* from, uint8_t *buf, size_t *bytes);

/* Writes to the rem_addr through the given connection object. For connection oriented transports,
 * rem_addr is ignored.
 */
extern transport_status_t fuze_transport_socket_writeto(void *conn, __sockaddr_t *rem_addr, 
					                        const uint8_t *buf, size_t bytes); 

/* Writes to the connection. Expects connection to be either already connected
 * or has been set remote_address previously (for connection less transports).
 */
extern transport_status_t fuze_transport_socket_write(void *conn, const uint8_t *buf, size_t bytes);

/* Checks the availablility of udp port in the system
 * return 0 for success and -1 for failure
 * if pIP is 0, then INADDR_ANY is used to test with the port
 */
extern int fuze_udp_port_available(uint16_t port, const char* pIP);
    
extern int fuze_reserve_udp_port(uint32_t holdTimeMs, uint16_t port, const char* pIP);
    
extern void fuze_release_udp_port(uint16_t port);

extern void fuze_transport_ignore_packets(void *conn, int size);

/* read local rates from transport */
extern transport_status_t fuze_transport_get_rates(void *conn, uint16_t *local_send, uint16_t *local_recv, uint16_t *local_send_cnt, uint16_t *local_recv_cnt);

extern transport_status_t fuze_transport_get_rxcnt(void *conn, size_t *rxcnt);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
