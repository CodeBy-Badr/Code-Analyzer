#include "../include/fs_monitor.h"
#include "../include/pe_parser.h"
#include "../include/elf_parser.h"

bool fs_monitor_init(FSMonitor* monitor, const char* target_dir, IPCTransport* transport) {
    if (!monitor || !target_dir) return false;
    memset(monitor, 0, sizeof(FSMonitor));

    strncpy(monitor->watch_directory, target_dir, sizeof(monitor->watch_directory) - 1);
    monitor->transport = transport;
    monitor->is_running = false;

#ifdef _WIN32
    monitor->hDir = CreateFileA(
        monitor->watch_directory,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (monitor->hDir == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to open directory for monitoring: %s (Error: %lu)", monitor->watch_directory, GetLastError());
        return false;
    }
#endif

    LOG_INFO("FS Monitor initialized on target directory: %s", monitor->watch_directory);
    return true;
}

bool fs_monitor_inspect_and_send(FSMonitor* monitor, const char* filepath, EventType event) {
    if (!filepath) return false;

    // Small delay to allow writing process to release file lock
#ifdef _WIN32
    Sleep(50);
#else
    usleep(50000);
#endif

    FILE* f = fopen(filepath, "rb");
    if (!f) {
        // Retry once after 100ms
#ifdef _WIN32
        Sleep(100);
#endif
        f = fopen(filepath, "rb");
        if (!f) {
            LOG_WARN("Could not read file (locked or removed): %s", filepath);
            return false;
        }
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    IPCMessagePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = AGENT_MAGIC;
    pkt.event_type = (uint32_t)event;
    pkt.file_size = (uint64_t)(fsize > 0 ? fsize : 0);
    strncpy(pkt.file_path, filepath, sizeof(pkt.file_path) - 1);
    pkt.file_path_len = (uint32_t)strlen(pkt.file_path);

    size_t to_read = (fsize > 0 && (size_t)fsize < HEADER_PREVIEW_LEN) ? (size_t)fsize : HEADER_PREVIEW_LEN;
    size_t n = fread(pkt.header_preview, 1, to_read, f);
    pkt.preview_len = (uint32_t)n;
    fclose(f);

    // Header inspection at maximum hardware speed
    if (n >= 64 && *(const uint16_t*)pkt.header_preview == 0x5A4D) {
        pkt.is_pe = 1;
    }
    if (n >= 4 && *(const uint32_t*)pkt.header_preview == 0x464C457F) {
        pkt.is_elf = 1;
    }

    LOG_INFO("Intercepted file event [%s]: %s (Size: %llu bytes, PE: %d, ELF: %d)",
             event == EVENT_FILE_CREATED ? "CREATED" : (event == EVENT_FILE_MODIFIED ? "MODIFIED" : "MANUAL"),
             filepath, (unsigned long long)pkt.file_size, pkt.is_pe, pkt.is_elf);

    if (monitor && monitor->transport && monitor->transport->is_connected) {
        return ipc_send_packet(monitor->transport, &pkt);
    }

    return true;
}

#ifdef _WIN32
void fs_monitor_start_loop(FSMonitor* monitor) {
    if (!monitor || monitor->hDir == INVALID_HANDLE_VALUE) return;

    monitor->is_running = true;
    LOG_INFO("Starting real-time directory event interception loop...");

    BYTE buffer[1024 * 16];
    DWORD bytesReturned = 0;

    while (monitor->is_running) {
        BOOL success = ReadDirectoryChangesW(
            monitor->hDir,
            buffer,
            sizeof(buffer),
            FALSE, // Subtree: monitor direct files in sandbox
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            &bytesReturned,
            NULL,
            NULL
        );

        if (!success || bytesReturned == 0) {
            LOG_WARN("ReadDirectoryChangesW returned error or 0 bytes (Error: %lu)", GetLastError());
            Sleep(500);
            continue;
        }

        FILE_NOTIFY_INFORMATION* notify = (FILE_NOTIFY_INFORMATION*)buffer;
        while (notify) {
            int fileNameLen = notify->FileNameLength / sizeof(WCHAR);
            char fileName[MAX_PATH_LEN] = {0};
            WideCharToMultiByte(CP_ACP, 0, notify->FileName, fileNameLen, fileName, sizeof(fileName) - 1, NULL, NULL);

            char fullPath[MAX_PATH_LEN] = {0};
            snprintf(fullPath, sizeof(fullPath), "%s\\%s", monitor->watch_directory, fileName);

            EventType ev = EVENT_UNKNOWN;
            if (notify->Action == FILE_ACTION_ADDED) {
                ev = EVENT_FILE_CREATED;
            } else if (notify->Action == FILE_ACTION_MODIFIED) {
                ev = EVENT_FILE_MODIFIED;
            }

            if (ev != EVENT_UNKNOWN) {
                fs_monitor_inspect_and_send(monitor, fullPath, ev);
            }

            if (notify->NextEntryOffset == 0) break;
            notify = (FILE_NOTIFY_INFORMATION*)((BYTE*)notify + notify->NextEntryOffset);
        }
    }
}
#else
void fs_monitor_start_loop(FSMonitor* monitor) {
    if (!monitor) return;
    monitor->is_running = true;
    while (monitor->is_running) {
        sleep(1);
    }
}
#endif

void fs_monitor_stop(FSMonitor* monitor) {
    if (!monitor) return;
    monitor->is_running = false;
#ifdef _WIN32
    if (monitor->hDir != INVALID_HANDLE_VALUE && monitor->hDir != NULL) {
        CloseHandle(monitor->hDir);
        monitor->hDir = INVALID_HANDLE_VALUE;
    }
#endif
    LOG_INFO("FS Monitor stopped.");
}

