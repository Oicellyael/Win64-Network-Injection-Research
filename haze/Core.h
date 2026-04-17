#pragma once
#include "Native.h"

namespace Fog::Core {
    // Hashes of the functions we need (so as not to reveal strings)
    constexpr DWORD HASH_NT_ALLOCATE = 0xC86105CA;
    constexpr DWORD HASH_NT_PROTECT = 0xA4D0D586; 
    constexpr DWORD HASH_NT_WRITE = 0xFAE162D0; 
    constexpr DWORD HASH_NT_THREAD = 0xFE3E696E; 

    // Helper methods
    DWORD HashString(const char* word);
    uintptr_t GetModuleBase(const wchar_t* moduleName);
    uintptr_t GetExportAddress(uintptr_t moduleBase, DWORD targetHash);
    DWORD ExtractSSN(uintptr_t functionAddress);
}