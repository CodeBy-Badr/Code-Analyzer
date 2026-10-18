#ifndef PE_PARSER_H
#define PE_PARSER_H

#include "agent_common.h"

#define MAX_SECTIONS 64
#define MAX_SUSPICIOUS_IMPORTS 32

typedef struct {
    char name[9];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_data_size;
    uint32_t raw_data_ptr;
    uint32_t characteristics;
    bool is_executable;
    bool is_writable;
    bool is_wx; // Write + Execute violation (common in packers/malware)
} PESectionInfo;

typedef struct {
    bool is_valid_pe;
    bool is_64bit;
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t timestamp;
    uint64_t image_base;
    uint32_t entry_point;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    
    // Security mitigation flags
    bool has_aslr;
    bool has_dep_nx;
    bool has_seh;
    bool has_cfg;
    
    // Section analysis
    PESectionInfo sections[MAX_SECTIONS];
    uint32_t wx_section_count;
    
    // Indicator checks
    bool is_likely_packed;
    char packer_hint[32];
    
    // Suspicious API count found in import table
    uint32_t suspicious_import_count;
    char suspicious_imports[MAX_SUSPICIOUS_IMPORTS][64];
} PEAnalysisResult;

// Parse PE from memory buffer
bool parse_pe_buffer(const uint8_t* buffer, size_t buffer_size, PEAnalysisResult* result);

// Parse PE directly from file
bool parse_pe_file(const char* filepath, PEAnalysisResult* result);

// Print summary to stdout
void print_pe_analysis(const PEAnalysisResult* result);

#endif // PE_PARSER_H

