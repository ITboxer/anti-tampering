#include "anti_debugging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <time.h>
#include <setjmp.h>
#endif

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
     LONG_PTR debuggerPresent = FALSE;
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


#elif __linux__
   //proc/self/status 파일을 이용한 디버거 탐지 함수
    int DetectDebuggerWithProcFS() {

    FILE* f = fopen("/proc/self/status", "r");
        if (f == NULL) {
            perror("Failed to open /proc/self/status");
            return -1;
        }

        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                fclose(f);
                return pid != 0;
            }
        }

        fclose(f);
        return 0;
    }



    static sigjmp_buf jump_env;

    // SIGTRAP 시그널 핸들러
    void sigtrap_handler(int signo) {
        // SIGTRAP 시그널이 발생하면 여기로 점프
        siglongjmp(jump_env, 1);
    }

    int DetectDebuggerWithSignal() {
        // SIGTRAP 시그널 핸들러 설정
        signal(SIGTRAP, sigtrap_handler);

        if (sigsetjmp(jump_env, 1) == 0) {
            // 여기서 int3 인스트럭션을 실행하여 SIGTRAP 시그널을 유발
            __asm__("int3");
            // 디버거가 없으면, 여기로 돌아와서 정상실행
            // 디버거가 없다는 것을 나타내기 위해 1 반환
            return 1;
        }

         // 디버거가 있으면, sigtrap_handler에서 설정한 siglongjmp에 의해
        // 여기로 점프합니다. 이 경우, 디버거가 있다는 것을 나타내기 위해 0을 반환합니다.
        return 0;
        
    }

    int DetectDebuggerWithTiming() {
        struct timespec ts;
        unsigned long long start, end;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        start = ts.tv_sec * 1000000000LL + ts.tv_nsec;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        end = ts.tv_sec * 1000000000LL + ts.tv_nsec;
        if ((end - start) >= 1000000000) {
            return 1;
        }
        return 0;
    }

#endif

int DetectDebugger() {
#ifdef _WIN32
        if (DetectDebuggerWithNTQuery()) return 1;
        if (DetectDebuggerWithInterrupts()) return 1;
        if (DetectDebuggerWithTiming()) return 1;
#endif
#ifdef __linux__
        if (DetectDebuggerWithProcFS()) return 1;
        if(DetectDebuggerWithSignal()) return 1;
        if(DetectDebuggerWithTiming()) return 1;
#endif
        return 0;
    }
