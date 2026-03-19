[org 0x40000000]

entry:
    xor eax, eax

.inner:
    inc eax
    jo .inc_inner
    jmp .inner

.inc_inner:
    inc ebx
    xor eax, eax
    jmp .inner
