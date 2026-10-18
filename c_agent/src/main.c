#include "../include/agent_common.h"
#include "../include/pe_parser.h"
#include "../include/elf_parser.h"
#include "../include/ipc_transport.h"
#include "../include/fs_monitor.h"

static void print_banner(void) {
    printf("\n");
    printf("====================================================================\n");
    printf("      CYBERSHIELD LOW-LEVEL C AGENT - KERNEL & BINARY PROBE         \n");
    printf("====================================================================\n");
    printf(" [High-Performance System Interceptor & Raw PE/ELF Header Parser]   \n");
    printf("====================================================================\n\n");
}

static void print_usage(const char* prog) {
    printf("Usage:\n");
    printf("  %s --scan <file_path> [--pipe <pipe_name>]\n", prog);
    printf("  %s --watch <directory_path> [--pipe <pipe_name>]\n\n", prog);
    printf("Options:\n");
    printf("  --scan <file>    Inspect PE/ELF headers of a target file at hardware speed\n");
    printf("  --watch <dir>    Hook into directory notifications and stream events over IPC\n");
    printf("  --pipe <name>    Specify custom Named Pipe endpoint (Default: %s)\n", DEFAULT_PIPE_NAME);
    printf("  --help           Display this help screen\n\n");
}

int main(int argc, char* argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char* scan_file = NULL;
    const char* watch_dir = NULL;
    const char* pipe_name = DEFAULT_PIPE_NAME;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--scan") == 0 && i + 1 < argc) {
            scan_file = argv[++i];
        } else if (strcmp(argv[i], "--watch") == 0 && i + 1 < argc) {
            watch_dir = argv[++i];
        } else if (strcmp(argv[i], "--pipe") == 0 && i + 1 < argc) {
            pipe_name = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Mode 1: Direct File Header Inspection
    if (scan_file) {
        LOG_INFO("Running fast low-level inspection on: %s", scan_file);

        PEAnalysisResult pe_res;
        if (parse_pe_file(scan_file, &pe_res)) {
            print_pe_analysis(&pe_res);
        } else {
            ELFAnalysisResult elf_res;
            if (parse_elf_file(scan_file, &elf_res)) {
                print_elf_analysis(&elf_res);
            } else {
                LOG_WARN("File is neither a valid PE nor a valid ELF binary.");
            }
        }
        return 0;
    }

    // Mode 2: Watch Directory & Stream to IPC Pipe
    if (watch_dir) {
        LOG_INFO("Setting up Low-Level Monitoring on directory: %s", watch_dir);
        LOG_INFO("IPC Endpoint: %s", pipe_name);

        IPCTransport transport;
        if (!ipc_init_server(&transport, pipe_name)) {
            LOG_ERROR("Failed to initialize IPC server transport.");
            return 1;
        }

        FSMonitor monitor;
        if (!fs_monitor_init(&monitor, watch_dir, &transport)) {
            LOG_ERROR("Failed to initialize directory monitor.");
            ipc_close(&transport);
            return 1;
        }

        // Wait for the Python Orchestrator to connect before beginning event stream
        ipc_accept_client(&transport);

        LOG_INFO("Activating real-time filesystem monitor. Press Ctrl+C to abort.");
        fs_monitor_start_loop(&monitor);

        fs_monitor_stop(&monitor);
        ipc_close(&transport);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}

