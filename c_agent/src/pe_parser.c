#include "../include/pe_parser.h"

// PE signatures and magic numbers
#define DOS_MAGIC 0x5A4D       // "MZ"
#define NT_MAGIC  0x00004550   // "PE\0\0"
#define OPTIONAL_HDR32_MAGIC 0x10B
#define OPTIONAL_HDR64_MAGIC 0x20B

// Section characteristic flags
#define SCN_MEM_EXECUTE 0x20000000
#define SCN_MEM_READ    0x40000000
#define SCN_MEM_WRITE   0x80000000

// DllCharacteristics
#define DLL_HIGH_ENTROPY_VA 0x0020
#define DLL_DYNAMIC_BASE    0x0040 // ASLR
#define DLL_NX_COMPAT       0x0100 // DEP
#define DLL_NO_SEH          0x0400
#define DLL_GUARD_CF        0x4000 // Control Flow Guard

static const char* KNOWN_SUSPICIOUS_APIS[] = {
    "VirtualAlloc", "VirtualProtect", "VirtualAllocEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "InternetOpenA", "InternetOpenW", "HttpOpenRequestA", "URLDownloadToFileA",
    "WSAStartup", "connect", "send", "recv", "WSASocketA",
    "CryptEncrypt", "CryptDecrypt", "BitBlt", "GetAsyncKeyState",
    NULL
};

bool parse_pe_buffer(const uint8_t* buffer, size_t buffer_size, PEAnalysisResult* result) {
    if (!buffer || buffer_size < 64 || !result) {
        return false;
    }
    memset(result, 0, sizeof(PEAnalysisResult));

    // 1. Validate DOS Header
    uint16_t dos_magic = *(const uint16_t*)buffer;
    if (dos_magic != DOS_MAGIC) {
        return false;
    }

    uint32_t e_lfanew = *(const uint32_t*)(buffer + 0x3C);
    if (e_lfanew + 24 > buffer_size) {
        return false;
    }

    // 2. Validate PE Header
    const uint8_t* pe_hdr = buffer + e_lfanew;
    uint32_t pe_sig = *(const uint32_t*)pe_hdr;
    if (pe_sig != NT_MAGIC) {
        return false;
    }

    result->is_valid_pe = true;

    // 3. File Header
    const uint8_t* file_hdr = pe_hdr + 4;
    result->machine = *(const uint16_t*)(file_hdr + 0);
    result->number_of_sections = *(const uint16_t*)(file_hdr + 2);
    result->timestamp = *(const uint32_t*)(file_hdr + 4);
    uint16_t size_of_opt_hdr = *(const uint16_t*)(file_hdr + 16);

    if (result->number_of_sections > MAX_SECTIONS) {
        result->number_of_sections = MAX_SECTIONS;
    }

    // 4. Optional Header
    const uint8_t* opt_hdr = file_hdr + 20;
    if ((size_t)(opt_hdr - buffer + size_of_opt_hdr) > buffer_size) {
        return true; // Return partial info
    }

    uint16_t opt_magic = *(const uint16_t*)opt_hdr;
    if (opt_magic == OPTIONAL_HDR64_MAGIC) {
        result->is_64bit = true;
        result->entry_point = *(const uint32_t*)(opt_hdr + 16);
        result->image_base = *(const uint64_t*)(opt_hdr + 24);
        result->subsystem = *(const uint16_t*)(opt_hdr + 68);
        result->dll_characteristics = *(const uint16_t*)(opt_hdr + 70);
    } else if (opt_magic == OPTIONAL_HDR32_MAGIC) {
        result->is_64bit = false;
        result->entry_point = *(const uint32_t*)(opt_hdr + 16);
        result->image_base = *(const uint32_t*)(opt_hdr + 28);
        result->subsystem = *(const uint16_t*)(opt_hdr + 68);
        result->dll_characteristics = *(const uint16_t*)(opt_hdr + 70);
    }

    result->has_aslr = (result->dll_characteristics & DLL_DYNAMIC_BASE) != 0;
    result->has_dep_nx = (result->dll_characteristics & DLL_NX_COMPAT) != 0;
    result->has_seh = (result->dll_characteristics & DLL_NO_SEH) == 0;
    result->has_cfg = (result->dll_characteristics & DLL_GUARD_CF) != 0;

    // 5. Sections Table
    const uint8_t* sec_hdr = opt_hdr + size_of_opt_hdr;
    result->wx_section_count = 0;

    for (uint16_t i = 0; i < result->number_of_sections; ++i) {
        const uint8_t* cur_sec = sec_hdr + (i * 40);
        if ((size_t)(cur_sec - buffer + 40) > buffer_size) {
            break;
        }

        PESectionInfo* sinfo = &result->sections[i];
        memcpy(sinfo->name, cur_sec, 8);
        sinfo->name[8] = '\0';

        sinfo->virtual_size = *(const uint32_t*)(cur_sec + 8);
        sinfo->virtual_address = *(const uint32_t*)(cur_sec + 12);
        sinfo->raw_data_size = *(const uint32_t*)(cur_sec + 16);
        sinfo->raw_data_ptr = *(const uint32_t*)(cur_sec + 20);
        sinfo->characteristics = *(const uint32_t*)(cur_sec + 36);

        sinfo->is_executable = (sinfo->characteristics & SCN_MEM_EXECUTE) != 0;
        sinfo->is_writable = (sinfo->characteristics & SCN_MEM_WRITE) != 0;
        sinfo->is_wx = sinfo->is_executable && sinfo->is_writable;

        if (sinfo->is_wx) {
            result->wx_section_count++;
        }

        // Check for common packer sections
        if (strstr(sinfo->name, "UPX") || strstr(sinfo->name, ".aspack") ||
            strstr(sinfo->name, ".themida") || strstr(sinfo->name, ".vmp")) {
            result->is_likely_packed = true;
            strncpy(result->packer_hint, sinfo->name, sizeof(result->packer_hint) - 1);
        }

        // Suspicious section sizing check (RawData == 0 but VirtualSize > 0 indicates unpacking stub)
        if (sinfo->raw_data_size == 0 && sinfo->virtual_size > 0 && sinfo->is_executable) {
            result->is_likely_packed = true;
            if (result->packer_hint[0] == '\0') {
                strncpy(result->packer_hint, "VirtualAlloc-Stub", sizeof(result->packer_hint) - 1);
            }
        }
    }

    // 6. Fast scan for suspicious API strings in imports or data
    for (int k = 0; KNOWN_SUSPICIOUS_APIS[k] != NULL; ++k) {
        const char* target = KNOWN_SUSPICIOUS_APIS[k];
        size_t tlen = strlen(target);
        if (tlen > buffer_size) continue;

        // Perform fast memmem-style search in buffer
        for (size_t offset = 0; offset + tlen <= buffer_size; offset += 4) {
            if (buffer[offset] == target[0] &&
                memcmp(buffer + offset, target, tlen) == 0) {
                if (result->suspicious_import_count < MAX_SUSPICIOUS_IMPORTS) {
                    bool already_exists = false;
                    for (uint32_t e = 0; e < result->suspicious_import_count; ++e) {
                        if (strcmp(result->suspicious_imports[e], target) == 0) {
                            already_exists = true;
                            break;
                        }
                    }
                    if (!already_exists) {
                        strncpy(result->suspicious_imports[result->suspicious_import_count++],
                                target, 63);
                    }
                }
                break;
            }
        }
    }

    return true;
}

bool parse_pe_file(const char* filepath, PEAnalysisResult* result) {
    if (!filepath || !result) return false;

    FILE* f = fopen(filepath, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(f);
        return false;
    }

    // Limit buffer read to first 4MB for high performance
    size_t read_len = (size_t)fsize > (4 * 1024 * 1024) ? (4 * 1024 * 1024) : (size_t)fsize;
    uint8_t* buf = (uint8_t*)malloc(read_len);
    if (!buf) {
        fclose(f);
        return false;
    }

    size_t actual_read = fread(buf, 1, read_len, f);
    fclose(f);

    bool ok = parse_pe_buffer(buf, actual_read, result);
    free(buf);
    return ok;
}

void print_pe_analysis(const PEAnalysisResult* result) {
    if (!result || !result->is_valid_pe) {
        printf("[-] Not a valid PE binary.\n");
        return;
    }

    printf("=========================================\n");
    printf("   PE Binary Static Analysis Summary     \n");
    printf("=========================================\n");
    printf(" Architecture      : %s (Machine: 0x%04X)\n", result->is_64bit ? "x86_64 (64-bit)" : "x86 (32-bit)", result->machine);
    printf(" Sections Count    : %u\n", result->number_of_sections);
    printf(" Entry Point RVA   : 0x%08X\n", result->entry_point);
    printf(" Image Base        : 0x%llX\n", (unsigned long long)result->image_base);
    printf(" Security Flags    : ASLR=%s, DEP=%s, CFG=%s\n",
           result->has_aslr ? "YES" : "NO",
           result->has_dep_nx ? "YES" : "NO",
           result->has_cfg ? "YES" : "NO");
    printf(" W^X Violations    : %u (Writable + Executable Sections)\n", result->wx_section_count);
    printf(" Packer Detected   : %s %s\n", result->is_likely_packed ? "YES" : "NO",
           result->is_likely_packed ? result->packer_hint : "");

    printf("\nSections:\n");
    for (uint16_t i = 0; i < result->number_of_sections; ++i) {
        const PESectionInfo* s = &result->sections[i];
        printf("  [%02d] %-8s VSize:0x%06X RSize:0x%06X Perms:[%c%c%c]%s\n",
               i, s->name, s->virtual_size, s->raw_data_size,
               (s->characteristics & SCN_MEM_READ) ? 'R' : '-',
               (s->characteristics & SCN_MEM_WRITE) ? 'W' : '-',
               (s->characteristics & SCN_MEM_EXECUTE) ? 'X' : '-',
               s->is_wx ? " <--- SUSPICIOUS (W+X)" : "");
    }

    if (result->suspicious_import_count > 0) {
        printf("\nSuspicious API References (%u detected):\n", result->suspicious_import_count);
        for (uint32_t i = 0; i < result->suspicious_import_count; ++i) {
            printf("  -> %s\n", result->suspicious_imports[i]);
        }
    }
    printf("=========================================\n");
}

