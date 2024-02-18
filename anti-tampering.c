#include "anti_debugging.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>

int DetectDebuggerWithNTQuery() {
    HANDLE processHandle = GetCurrentProcess();
    BOOL debuggerPresent = FALSE;
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    status = NtQueryInformationProcess(processHandle, ProcessDebugPort, &debuggerPresent, sizeof(debuggerPresent), &returnLength);
    if (NT_SUCCESS(status) && debuggerPresent) {
        return 1;
    }

    return 0;
}

int DetectDebuggerWithInterrupts() {
    __try {
        __asm {
            int 3   // INT3
            int 0x2D // INT2D
            int 0x41 // Interrupt 0x41
            int 1    // SoftICE Interrupt
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }
    return 0;
}

int DetectDebuggerWithTiming() {
    unsigned long long start, end;
    start = __rdtsc();
    Sleep(100);
    end = __rdtsc();
    if ((end - start) < 100000000) {
        return 1;
    }
    return 0;
}

int DetectOllyDbg() {
    OutputDebugString(TEXT("OLLYDBG"));
    if (GetLastError() == 0) {
        return 1;
    }
    return 0;
}

#elif __linux__
#include <unistd.h>
#include <signal.h>
#include <time.h>

int DetectDebuggerWithProcFS() {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) {
                fclose(f);
                return 1;
            }
            break;
        }
    }
    fclose(f);
    return 0;
}

int DetectDebuggerWithSignal() {
    signal(SIGTRAP, SIG_IGN);
    __asm__("int3");
    return 0;
}

int DetectDebuggerWithTiming() {
    struct timespec ts;
    unsigned long long start, end;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    start = ts.tv_sec * 1000000000LL + ts.tv_nsec;
    sleep(1);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    end = ts.tv_sec * 1000000000LL + ts.tv_nsec;
    if ((end - start) < 1000000000) {
        return 1;
    }
    return 0;
}

#endif

int DetectDebugger() {
    if (DetectDebuggerWithNTQuery()) return 1;
    if (DetectDebuggerWithInterrupts()) return 1;
    if (DetectDebuggerWithTiming()) return 1;
    if (DetectOllyDbg()) return 1;
    if (DetectDebuggerWithProcFS()) return 1;
    if (DetectDebuggerWithSignal()) return 1;

    return 0;
}
