#include <stdio.h>
#include <windows.h>

// Simulated malware strings and indicators for sandbox classification testing
static const char* C2_BEACON_URL = "http://malicious-command-control.xyz/beacon.php";
static const char* BACKUP_IP = "194.26.29.112";
static const char* PERSISTENCE_REG = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdater";
static const char* INJECTION_TARGET = "explorer.exe";

// Harmless simulator referencing key indicators
void simulate_trojan_footprint(void) {
    printf("[SIMULATED-TROJAN] Target: %s\n", INJECTION_TARGET);
    printf("[SIMULATED-TROJAN] Beaconing to C2: %s (IP: %s)\n", C2_BEACON_URL, BACKUP_IP);
    printf("[SIMULATED-TROJAN] Installing Autostart: %s\n", PERSISTENCE_REG);

    // Call / reference APIs so import table & string extractor detect them
    volatile void* p1 = (void*)VirtualAlloc;
    volatile void* p2 = (void*)VirtualProtect;
    volatile void* p3 = (void*)WriteProcessMemory;
    volatile void* p4 = (void*)CreateRemoteThread;
    volatile void* p5 = (void*)IsDebuggerPresent;
    
    (void)p1; (void)p2; (void)p3; (void)p4; (void)p5;
}

int main(void) {
    printf("CyberShield Test Suite - Trojan Simulation Sample\n");
    simulate_trojan_footprint();
    return 0;
}

