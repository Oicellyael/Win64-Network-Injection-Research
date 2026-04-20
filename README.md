# 🌫️ BlackFog Framework

**BlackFog** is an educational Proof-of-Concept (PoC) project I created to study Windows Internals, C# Native AOT, and understand how modern EDR (Endpoint Detection and Response) systems monitor processes.

This project combines low-level **C++** with **C#** to create a standalone native executable without needing the .NET runtime.

---

## 🏗️ Architecture

### 1. `haze` (Stage 0: C++ Loader)
This is the starting point. It prepares the memory and loads the main logic.
* **Indirect Syscalls:** Instead of using standard Windows APIs (which are easily monitored), it uses custom Assembly stubs to talk directly to the kernel. This helps bypass standard user-mode hooks in `ntdll.dll`.
* **Telemetry Evasion:** Explores dynamic memory patching techniques (like patching `amsi.dll` and `EtwEventWrite` ) to understand how security logging can be blinded.
* **Optimized Build:** Compiled with size optimization and custom security flags to allow low-level memory manipulation.

### 2. `BlackFogCore` (Stage 1: C# Native AOT Payload)
This is the main logic module, written in C# but compiled into a standard native DLL.
* **Dependency-Free:** Thanks to Native AOT, it runs purely as native code and does not require .NET to be installed on the machine.
* **Syscall Bridging:** Uses `[UnmanagedCallersOnly]` to receive syscall pointers from the C++ loader. This allows the C# code to perform memory operations safely without triggering API monitors.

---

## 🛠️ Key Features
- [x] **C# Native AOT:** Running C# logic as a fully unmanaged DLL.
- [x] **Indirect Syscalls:** Manual invocation of `Nt*` functions to evade Ring-3 hooks.
- [x] **Defense Evasion Concepts:** Testing runtime memory patching.
- [x] **Network Discovery:** Basic network enumeration to simulate horizontal movement research.

---

<img width="880" height="716" alt="image" src="https://github.com/user-attachments/assets/4b8d43fe-5953-4c47-8a40-5ac6914d0bf5" />


> *"During tests, the discovery module might return only the local host address. This is often due to AP Isolation (Client Isolation) being enabled on the router. This security feature prevents peer-to-peer communication between devices in the same network, effectively blocking lateral movement research in a standard home/public Wi-Fi environment"*

## 💻 Tech Stack
* **C++:** For low-level process manipulation and loading.
* **C# / .NET 8 (Native AOT):** For application logic and networking.
* **x64 Assembly:** For indirect syscall implementation.

---

## ⚠️ Disclaimer
This project was built strictly for **educational purposes and security research**. The goal is to learn how Windows works under the hood and how defensive systems operate. I am not responsible for any misuse of this code.
