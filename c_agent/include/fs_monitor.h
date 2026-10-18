#ifndef FS_MONITOR_H
#define FS_MONITOR_H

#include "agent_common.h"
#include "ipc_transport.h"

typedef void (*FileEventCallback)(const char* filepath, EventType event, void* user_data);

typedef struct {
    char watch_directory[MAX_PATH_LEN];
    bool is_running;
    IPCTransport* transport;
#ifdef _WIN32
    HANDLE hDir;
    HANDLE hThread;
#endif
} FSMonitor;

// Initialize monitor for target directory
bool fs_monitor_init(FSMonitor* monitor, const char* target_dir, IPCTransport* transport);

// Process single file event manually
bool fs_monitor_inspect_and_send(FSMonitor* monitor, const char* filepath, EventType event);

// Start monitoring loop (blocking or background)
void fs_monitor_start_loop(FSMonitor* monitor);

// Stop monitoring
void fs_monitor_stop(FSMonitor* monitor);

#endif // FS_MONITOR_H

