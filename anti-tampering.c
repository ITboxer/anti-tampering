#include "anti_debugging.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>

    typedef NTSTATUS(NTAPI* PFN_NTQUERYINFORMATIONPROCESS)(
        extern HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

static PFN_NTQUERYINFORMATIONPROCESS g_pfnNtQueryInformationProcess = NULL;

    void InitializeAntiDebugging() {
        // ntdll.dll에서 NtQueryInformationProcess 함수 주소를 얻음
        HMODULE hNtdll = GetModuleHandle("ntdll.dll");
        if (hNtdll) {
            g_pfnNtQueryInformationProcess = (PFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }
    
    int DetectDebuggerWithNTQuery() {
    if (g_pfnNtQueryInformationProcess == NULL) {
        printf("None dll imported.\n");
        return 0; // 함수가 로드되지 않았으면 탐지를 수행하지 않음
    }

    HANDLE processHandle = GetCurrentProcess();
    BOOL debuggerPresent = FALSE;
    NTSTATUS status;
    ULONG returnLength;

    status = g_pfnNtQueryInformationProcess(processHandle, ProcessDebugPort, &debuggerPresent, sizeof(debuggerPresent), &returnLength);
    if (NT_SUCCESS(status) && debuggerPresent) {
        return 1; // 디버거 존재
    }

    return 0;
}
    
#ifdef _WIN64
    extern   void Interupt_antiTamper();
#endif

    int DetectDebuggerWithInterrupts() {
        __try {
#ifdef _WIN64
            Interupt_antiTamper();
#endif
#ifdef _WIN32
#ifndef _WIN64
            __asm {
                int 3   // INT3dksi 
                int 0x2D // INT2D
                int 0x41 // Interrupt 0x41
                int 1    // SoftICE Interrupt
        }
#endif
#endif

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }

        return 1;
    }

    int DetectDebuggerWithTiming() {
        unsigned long long start, end;
        start = __rdtsc();
        Sleep(100);
        end = __rdtsc();
        if ((end - start) >= 100000000) {
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

#elif _LINUX_
    int DetectDebuggerWithProcFS() {
        FILE* f = fopen("/proc/self/status", "r");
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
        if ((end - start) >= 1000000000) {
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

#ifdef _LINUX_
        if (DetectDebuggerWithProcFS()) return 1;
        if (DetectDebuggerWithSignal()) return 1;
#endif

        return 0;
    }
