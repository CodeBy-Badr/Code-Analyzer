#include "../include/elf_parser.h"

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4
#define PT_LOAD 1

bool parse_elf_buffer(const uint8_t* buffer, size_t buffer_size, ELFAnalysisResult* result) {
    if (!buffer || buffer_size < 52 || !result) {
        return false;
    }
    memset(result, 0, sizeof(ELFAnalysisResult));

    // 1. Verify Magic
    uint32_t magic = *(const uint32_t*)buffer;
    if (magic != ELF_MAGIC) {
        return false;
    }

    result->is_valid_elf = true;
    result->is_64bit = (buffer[4] == 2);
    result->is_little_endian = (buffer[5] == 1);
    result->os_abi = buffer[7];

    if (result->is_64bit) {
        if (buffer_size < 64) return true;
        result->type = *(const uint16_t*)(buffer + 16);
        result->machine = *(const uint16_t*)(buffer + 18);
        result->entry_point = *(const uint64_t*)(buffer + 24);
        result->ph_offset = *(const uint64_t*)(buffer + 32);
        result->sh_offset = *(const uint64_t*)(buffer + 40);
        result->ph_count = *(const uint16_t*)(buffer + 56);
        result->sh_count = *(const uint16_t*)(buffer + 60);

        // Check program headers for W+X segments
        if (result->ph_offset > 0 && result->ph_count > 0) {
            size_t phentsize = 56;
            for (uint16_t i = 0; i < result->ph_count; ++i) {
                size_t cur_offset = (size_t)result->ph_offset + (i * phentsize);
                if (cur_offset + phentsize > buffer_size) break;

                uint32_t p_type = *(const uint32_t*)(buffer + cur_offset);
                uint32_t p_flags = *(const uint32_t*)(buffer + cur_offset + 4);

                if (p_type == PT_LOAD) {
                    if ((p_flags & PF_W) && (p_flags & PF_X)) {
                        result->has_wx_segments = true;
                        break;
                    }
                }
            }
        }
    } else {
        // 32-bit ELF
        result->type = *(const uint16_t*)(buffer + 16);
        result->machine = *(const uint16_t*)(buffer + 18);
        result->entry_point = *(const uint32_t*)(buffer + 24);
        result->ph_offset = *(const uint32_t*)(buffer + 28);
        result->sh_offset = *(const uint32_t*)(buffer + 32);
        result->ph_count = *(const uint16_t*)(buffer + 44);
        result->sh_count = *(const uint16_t*)(buffer + 48);

        if (result->ph_offset > 0 && result->ph_count > 0) {
            size_t phentsize = 32;
            for (uint16_t i = 0; i < result->ph_count; ++i) {
                size_t cur_offset = (size_t)result->ph_offset + (i * phentsize);
                if (cur_offset + phentsize > buffer_size) break;

                uint32_t p_type = *(const uint32_t*)(buffer + cur_offset);
                uint32_t p_flags = *(const uint32_t*)(buffer + cur_offset + 24);

                if (p_type == PT_LOAD) {
                    if ((p_flags & PF_W) && (p_flags & PF_X)) {
                        result->has_wx_segments = true;
                        break;
                    }
                }
            }
        }
    }

    return true;
}

bool parse_elf_file(const char* filepath, ELFAnalysisResult* result) {
    if (!filepath || !result) return false;

    FILE* f = fopen(filepath, "rb");
    if (!f) return false;

    uint8_t hdr[4096];
    size_t n = fread(hdr, 1, sizeof(hdr), f);
    fclose(f);

    return parse_elf_buffer(hdr, n, result);
}

void print_elf_analysis(const ELFAnalysisResult* result) {
    if (!result || !result->is_valid_elf) {
        printf("[-] Not a valid ELF binary.\n");
        return;
    }

    printf("=========================================\n");
    printf("   ELF Binary Static Analysis Summary    \n");
    printf("=========================================\n");
    printf(" Architecture      : %s\n", result->is_64bit ? "ELF64" : "ELF32");
    printf(" Endianness        : %s\n", result->is_little_endian ? "Little Endian" : "Big Endian");
    printf(" Machine           : 0x%04X\n", result->machine);
    printf(" Type              : 0x%04X\n", result->type);
    printf(" Entry Point       : 0x%llX\n", (unsigned long long)result->entry_point);
    printf(" Program Headers   : %u (Offset: 0x%llX)\n", result->ph_count, (unsigned long long)result->ph_offset);
    printf(" Section Headers   : %u (Offset: 0x%llX)\n", result->sh_count, (unsigned long long)result->sh_offset);
    printf(" W^X Violation     : %s\n", result->has_wx_segments ? "YES (Writable+Executable PT_LOAD)" : "NO");
    printf("=========================================\n");
}

