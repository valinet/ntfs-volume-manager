.intel_syntax noprefix

.global sys_exit
.global sys_open
.global sys_write
.global sys_lseek
.global sys_read
.global sys_close
.global _start
.extern main

.text

_start:
    mov rdi, [rsp]
    lea rsi, [rsp + 8]
    sub rsp, 8
    call main
    mov rdi, rax
    mov rax, 60
    syscall

sys_exit:
    mov rax, 60
    syscall
    ret

sys_open:
    mov rax, 2
    syscall
    ret

sys_lseek:
    mov rax, 8
    syscall
    ret

sys_write:
    mov rax, 1
    syscall
    ret

sys_read:
    mov rax, 0
    syscall
    ret

sys_close:
    mov rax, 3
    syscall
    ret
