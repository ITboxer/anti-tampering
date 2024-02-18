#include "anti_debugging.h"
#include <stdio.h>

int main() {
    if (DetectDebugger()) {
        printf("Debugger detected!\n");
        return 1;
    }

    printf("No debugger detected.\n");
    return 0;
}
