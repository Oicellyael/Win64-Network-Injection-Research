EXTERN g_syscallAddr:QWORD

EXTERN g_ssn_allocate:DWORD
EXTERN g_ssn_protect:DWORD
EXTERN g_ssn_write:DWORD
EXTERN g_ssn_thread:DWORD

.code

GetMyPeb PROC
    mov rax, gs:[60h]
    ret
GetMyPeb ENDP            

Syscall_NtAllocateVirtualMemory PROC
    mov r10, rcx                
    mov eax, g_ssn_allocate     
    jmp qword ptr [g_syscallAddr] 
Syscall_NtAllocateVirtualMemory ENDP

Syscall_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn_protect  
    jmp qword ptr [g_syscallAddr]
Syscall_NtProtectVirtualMemory ENDP

Syscall_NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, g_ssn_write
    jmp qword ptr [g_syscallAddr]
Syscall_NtWriteVirtualMemory ENDP

Syscall_NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, g_ssn_thread
    jmp qword ptr [g_syscallAddr]
Syscall_NtCreateThreadEx ENDP



END