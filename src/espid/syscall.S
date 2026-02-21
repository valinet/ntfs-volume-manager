.intel_syntax noprefix

.global sys_open
.global sys_read
.global sys_close
.global sys_getdents64
.global sys_write
.global sys_exit
.global sys_lseek
.global sys_fsync
.global _start

.text

_start:
    mov rdi, [rsp]
    lea rsi, [rsp + 8]
    sub rsp, 8
    call main
    mov rdi, rax
    mov rax, 60
    syscall

sys_open:
    mov rax, 2
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

sys_getdents64:
    mov rax, 217
    syscall
    ret

sys_write:
    mov rax, 1
    syscall
    ret

sys_exit:
    mov rax, 60
    syscall
    ret

sys_lseek:
    mov rax, 8
    syscall
    ret

sys_fsync:
    mov rax, 74
    syscall
    ret
