#include "../include/ipc_transport.h"

#ifdef _WIN32

bool ipc_init_server(IPCTransport* transport, const char* endpoint_name) {
    if (!transport) return false;
    memset(transport, 0, sizeof(IPCTransport));

    const char* pipe_name = endpoint_name ? endpoint_name : DEFAULT_PIPE_NAME;
    strncpy(transport->endpoint_name, pipe_name, sizeof(transport->endpoint_name) - 1);
    transport->is_server = true;
    transport->is_connected = false;

    transport->hPipe = CreateNamedPipeA(
        transport->endpoint_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        sizeof(IPCMessagePacket) * 4,
        sizeof(IPCMessagePacket) * 4,
        5000,
        NULL
    );

    if (transport->hPipe == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to create Named Pipe: %s (Error: %lu)", transport->endpoint_name, GetLastError());
        return false;
    }

    LOG_INFO("Named Pipe Server initialized on: %s", transport->endpoint_name);
    return true;
}

bool ipc_accept_client(IPCTransport* transport) {
    if (!transport || transport->hPipe == INVALID_HANDLE_VALUE) return false;

    LOG_INFO("Waiting for Python Orchestrator to connect to pipe...");
    BOOL connected = ConnectNamedPipe(transport->hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (connected) {
        transport->is_connected = true;
        LOG_INFO("Python Orchestrator connected successfully!");
        return true;
    }
    return false;
}

bool ipc_init_client(IPCTransport* transport, const char* endpoint_name) {
    if (!transport) return false;
    memset(transport, 0, sizeof(IPCTransport));

    const char* pipe_name = endpoint_name ? endpoint_name : DEFAULT_PIPE_NAME;
    strncpy(transport->endpoint_name, pipe_name, sizeof(transport->endpoint_name) - 1);
    transport->is_server = false;

    // Retry loop
    for (int retry = 0; retry < 5; ++retry) {
        transport->hPipe = CreateFileA(
            transport->endpoint_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (transport->hPipe != INVALID_HANDLE_VALUE) {
            transport->is_connected = true;
            LOG_INFO("Connected to Named Pipe server: %s", transport->endpoint_name);
            return true;
        }

        if (GetLastError() == ERROR_PIPE_BUSY) {
            WaitNamedPipeA(transport->endpoint_name, 2000);
        } else {
            Sleep(500);
        }
    }

    LOG_ERROR("Could not connect to Named Pipe: %s (Error: %lu)", transport->endpoint_name, GetLastError());
    return false;
}

bool ipc_send_packet(IPCTransport* transport, const IPCMessagePacket* packet) {
    if (!transport || transport->hPipe == INVALID_HANDLE_VALUE || !packet) return false;

    DWORD bytesWritten = 0;
    BOOL success = WriteFile(
        transport->hPipe,
        packet,
        sizeof(IPCMessagePacket),
        &bytesWritten,
        NULL
    );

    if (!success || bytesWritten != sizeof(IPCMessagePacket)) {
        LOG_WARN("WriteFile failed or incomplete (Error: %lu)", GetLastError());
        return false;
    }

    FlushFileBuffers(transport->hPipe);
    return true;
}

bool ipc_receive_packet(IPCTransport* transport, IPCMessagePacket* packet) {
    if (!transport || transport->hPipe == INVALID_HANDLE_VALUE || !packet) return false;

    DWORD bytesRead = 0;
    BOOL success = ReadFile(
        transport->hPipe,
        packet,
        sizeof(IPCMessagePacket),
        &bytesRead,
        NULL
    );

    if (!success || bytesRead != sizeof(IPCMessagePacket)) {
        return false;
    }

    return (packet->magic == AGENT_MAGIC);
}

void ipc_close(IPCTransport* transport) {
    if (!transport) return;
    if (transport->hPipe != INVALID_HANDLE_VALUE && transport->hPipe != NULL) {
        if (transport->is_server && transport->is_connected) {
            DisconnectNamedPipe(transport->hPipe);
        }
        CloseHandle(transport->hPipe);
        transport->hPipe = INVALID_HANDLE_VALUE;
    }
    transport->is_connected = false;
}

#else

// POSIX implementation (FIFO / Unix domain socket placeholder for portability)
bool ipc_init_server(IPCTransport* transport, const char* endpoint_name) {
    return false;
}
bool ipc_accept_client(IPCTransport* transport) { return false; }
bool ipc_init_client(IPCTransport* transport, const char* endpoint_name) { return false; }
bool ipc_send_packet(IPCTransport* transport, const IPCMessagePacket* packet) { return false; }
bool ipc_receive_packet(IPCTransport* transport, IPCMessagePacket* packet) { return false; }
void ipc_close(IPCTransport* transport) {}

#endif

