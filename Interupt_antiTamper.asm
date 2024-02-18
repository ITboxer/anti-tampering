; Interupt_antiTamper.asm
.code
Interupt_antiTamper PROC
          int 3           ; INT3
          int 1           ; SoftICE Interrupt
          ret
Interupt_antiTamper ENDP
END
