#pragma once
#include <windows.h>
#include <cstdint>

// ========== EXTERNAL ASM VARIABLES ==========
extern "C" {
    extern uintptr_t g_syscallAddr;

    extern DWORD g_ssn_allocate;
    extern DWORD g_ssn_protect;
    extern DWORD g_ssn_write;
    extern DWORD g_ssn_thread;

    uintptr_t GetMyPeb(); // Now returns the pointer directly
    extern uintptr_t ntdllBase;
}

// ========== OS STRUCTURES ==========
typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* LdrLoadDll)(
    PWSTR           SearchPath,       
    PULONG          DllCharacteristics, 
    PUNICODE_STRING DllName,
    PHANDLE         DllHandle         
    );

typedef struct _SYSCALL_BRIDGE {
    uintptr_t NtAllocateAddr;
    uintptr_t NtProtectAddr;
    uintptr_t NtWriteAddr;
    uintptr_t NtThreadAddr;
} SYSCALL_BRIDGE, *PSYSCALL_BRIDGE;

// =========== ASM FUNCTIONS (INDIRECT CALLS) ==========
extern "C" NTSTATUS Syscall_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS Syscall_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
extern "C" NTSTATUS Syscall_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
extern "C" NTSTATUS Syscall_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);