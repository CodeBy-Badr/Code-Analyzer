#ifndef AGENT_COMMON_H
#define AGENT_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #define PATH_SEPARATOR "\\"
    #define DEFAULT_PIPE_NAME "\\\\.\\pipe\\MalwareAnalyzerPipe"
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #define PATH_SEPARATOR "/"
    #define DEFAULT_PIPE_NAME "/tmp/malware_analyzer.sock"
#endif

#define AGENT_MAGIC 0x4D414C57 // 'MALW' in ASCII
#define MAX_PATH_LEN 512
#define HEADER_PREVIEW_LEN 4096

// Event types sent across IPC
typedef enum {
    EVENT_UNKNOWN       = 0,
    EVENT_FILE_CREATED  = 1,
    EVENT_FILE_MODIFIED = 2,
    EVENT_MANUAL_SCAN   = 3,
    EVENT_HEARTBEAT     = 4,
    EVENT_AGENT_STOP    = 5
} EventType;

// Binary packet transferred over Named Pipe / Socket
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;                    // AGENT_MAGIC
    uint32_t event_type;               // EventType enum
    uint32_t file_path_len;            // Length of filepath string
    uint64_t file_size;                // Total file size on disk
    uint32_t preview_len;              // Length of raw header preview (up to HEADER_PREVIEW_LEN)
    uint32_t is_pe;                    // 1 if PE format detected
    uint32_t is_elf;                   // 1 if ELF format detected
    char     file_path[MAX_PATH_LEN];  // Null-terminated file path
    uint8_t  header_preview[HEADER_PREVIEW_LEN]; // Raw initial byte buffer
} IPCMessagePacket;
#pragma pack(pop)

// Log helpers
#define LOG_INFO(fmt, ...)  printf("[+] [AGENT-INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  printf("[!] [AGENT-WARN] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[-] [AGENT-ERROR] " fmt "\n", ##__VA_ARGS__)

#endif // AGENT_COMMON_H

