[bits 32]
[org 0x40000000]

entry:
    xor eax, eax
    xor ebx, ebx

.inner:
    inc eax
    jo .inc_inner
    jmp .inner

.inc_inner:
    inc ebx
    xor eax, eax
    
    cmp ebx, 0x100
    je .fuck

    jmp .inner

.fuck:  ; Cause GPF somehow
    hlt
