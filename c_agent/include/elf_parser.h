#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include "agent_common.h"

#define ELF_MAGIC 0x464C457F // 0x7F, 'E', 'L', 'F'

typedef struct {
    bool is_valid_elf;
    bool is_64bit;
    bool is_little_endian;
    uint8_t os_abi;
    uint16_t type;            // ET_EXEC, ET_DYN, etc.
    uint16_t machine;         // x86, x86_64, ARM, etc.
    uint64_t entry_point;
    uint64_t ph_offset;       // Program header offset
    uint64_t sh_offset;       // Section header offset
    uint16_t ph_count;        // Number of program headers
    uint16_t sh_count;        // Number of section headers
    bool has_wx_segments;     // W+X segment detected in PT_LOAD
} ELFAnalysisResult;

bool parse_elf_buffer(const uint8_t* buffer, size_t buffer_size, ELFAnalysisResult* result);
bool parse_elf_file(const char* filepath, ELFAnalysisResult* result);
void print_elf_analysis(const ELFAnalysisResult* result);

#endif // ELF_PARSER_H

