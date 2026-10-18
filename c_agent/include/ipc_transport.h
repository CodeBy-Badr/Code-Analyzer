#ifndef IPC_TRANSPORT_H
#define IPC_TRANSPORT_H

#include "agent_common.h"

typedef struct {
#ifdef _WIN32
    HANDLE hPipe;
#else
    int sock_fd;
#endif
    char endpoint_name[MAX_PATH_LEN];
    bool is_server;
    bool is_connected;
} IPCTransport;

// Initialize transport (client or server)
bool ipc_init_server(IPCTransport* transport, const char* endpoint_name);
bool ipc_init_client(IPCTransport* transport, const char* endpoint_name);

// Wait for a client connection (server mode)
bool ipc_accept_client(IPCTransport* transport);

// Send message packet
bool ipc_send_packet(IPCTransport* transport, const IPCMessagePacket* packet);

// Receive message packet
bool ipc_receive_packet(IPCTransport* transport, IPCMessagePacket* packet);

// Close transport
void ipc_close(IPCTransport* transport);

#endif // IPC_TRANSPORT_H

