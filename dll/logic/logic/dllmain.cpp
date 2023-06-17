#include "pch.h"
#include <detours.h>
#include <string>
#include <TlHelp32.h>
#include <winternl.h>
#pragma comment(lib, "mincore")
#define EOF (-1)

DWORD dwDmpCount = 0;
HANDLE hFile;
// Classic technique
BOOL (WINAPI* TrueWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T size, SIZE_T* lpNumberOfBytesWritten)
{
    DWORD dwBytesWritten = 0;
    std::string szBuffer = "WriteProcessMemory for process with pid " + std::to_string(GetProcessId(hProcess)); szBuffer += '\n';
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    if (dwDmpCount < 50) {
        WCHAR* buffer = new WCHAR[260];
        const WCHAR name[12] = L"USERPROFILE";
        DWORD result = GetEnvironmentVariable(name, buffer, 260);
        if (result > 260) {
            delete[] buffer; buffer = new WCHAR[result];
            GetEnvironmentVariable(name, buffer, result);
        }
        std::wstring s(L"");
        s += buffer;
        s += L"\\Desktop\\wpm";
        s += std::to_wstring(dwDmpCount);
        s += L".dmp";
        HANDLE hDump = CreateFile(s.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        delete[] buffer;
        buffer = nullptr;
        WriteFile(hDump, lpBuffer, size, &dwBytesWritten, nullptr);
        CloseHandle(hDump);
        dwDmpCount++;
    }
    return TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, size, lpNumberOfBytesWritten);
}

LPVOID(WINAPI* TrueVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
LPVOID WINAPI HookedVirtualAlloc(LPVOID lpBaseAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    std::string szBuffer = "VirtualAlloc called\n";
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueVirtualAlloc(lpBaseAddress, dwSize, flAllocationType, flProtect);
}

PVOID(WINAPI* TrueVirtualAlloc2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG) = VirtualAlloc2;
PVOID WINAPI HookedVirtualAlloc2(HANDLE Process, PVOID BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection, MEM_EXTENDED_PARAMETER* ExtendedParameters, ULONG ParameterCount) {
    std::string szBuffer = "VirtualAlloc2 called for process with pid " + std::to_string(GetProcessId(Process)); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueVirtualAlloc2(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount);
}

LPVOID(WINAPI* TrueVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID lpBaseAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    std::string szBuffer = "VirtualAllocEx called for process with pid " + std::to_string(GetProcessId(hProcess)); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueVirtualAllocEx(hProcess, lpBaseAddress, dwSize, flAllocationType, flProtect);
}

BOOL(WINAPI* TrueCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
BOOL WINAPI HookedCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    std::string szBuffer = "CreateProcessA called for path " + std::to_string(*lpApplicationName); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL(WINAPI* TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
BOOL WINAPI HookedCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    std::string szBuffer = "CreateProcessW called for path " + std::to_string(*lpApplicationName); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

HANDLE(WINAPI* TrueOpenProcess)(DWORD, BOOL, DWORD) = OpenProcess;
HANDLE WINAPI HookedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    std::string szBuffer = "OpenProcess called for process with pid " + std::to_string(dwProcessId); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE(WINAPI* TrueCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    std::string szBuffer = "CreateRemoteThread called for process with pid " + std::to_string(GetProcessId(hProcess)); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE(WINAPI* TrueCreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) = CreateRemoteThreadEx;
HANDLE WINAPI HookedCreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId) {
    std::string szBuffer = "CreateRemoteThreadEx called for process with pid " + std::to_string(GetProcessId(hProcess)); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}

HANDLE(WINAPI* TrueCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateThread;
HANDLE WINAPI HookedCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD dwThreadId) {
    std::string szBuffer = "CreateThread called\n";
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, dwThreadId);
}
//Thread Hijacking
DWORD(WINAPI* TrueSuspendThread)(HANDLE) = SuspendThread;
DWORD WINAPI HookedSuspendThread(HANDLE hThread) {
    std::string szBuffer = "SuspendThread called for thread with tid " + std::to_string(GetThreadId(hThread)); szBuffer += (" for process with pid " + std::to_string(GetProcessIdOfThread(hThread))); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueSuspendThread(hThread);
}

HANDLE(WINAPI* TrueCreateToolhelp32Snapshot)(DWORD, DWORD) = CreateToolhelp32Snapshot;
HANDLE WINAPI HookedCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessId) {
    std::string szBuffer = "CreateToolhelp32Snapshot called\n";
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueCreateToolhelp32Snapshot(dwFlags, th32ProcessId);
}

BOOL(WINAPI* TrueGetThreadContext)(HANDLE, LPCONTEXT) = GetThreadContext;
BOOL WINAPI HookedGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    std::string szBuffer = "GetThreadContext called for thread with tid " + std::to_string(GetThreadId(hThread)); szBuffer += (" for process with pid " + std::to_string(GetProcessIdOfThread(hThread))); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueGetThreadContext(hThread, lpContext);
}

BOOL(WINAPI* TrueSetThreadContext)(HANDLE, const CONTEXT*) = SetThreadContext;
BOOL WINAPI HookedSetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    std::string szBuffer = "SetThreadContext called for thread with tid " + std::to_string(GetThreadId(hThread)); szBuffer += (" for process with pid " + std::to_string(GetProcessIdOfThread(hThread))); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueSetThreadContext(hThread, lpContext);
}

DWORD(WINAPI* TrueResumeThread)(HANDLE) = ResumeThread;
DWORD WINAPI HookedResumeThread(HANDLE hThread) {
    std::string szBuffer = "ResumeThread called for thread with tid " + std::to_string(GetThreadId(hThread)); szBuffer += (" for process with pid " + std::to_string(GetProcessIdOfThread(hThread))); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueResumeThread(hThread);
}

// MapView

typedef FARPROC(WINAPI* RtlCreateUserThread_t)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT CLIENT_ID* ClientId);

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN HANDLE FileHandle OPTIONAL);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer);

NtCreateSection_t pNtCreateSection = (NtCreateSection_t)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtCreateSection");
NTSTATUS NTAPI HookedNtCreateSection(PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG PageAttributes, ULONG SectionAttributes, HANDLE FileHandle) {
    std::string szBuffer = "NtCreateSection called\n";
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return pNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributes, SectionAttributes, FileHandle);
}

NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtMapViewOfSection");
NTSTATUS NTAPI HookedNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    std::string szBuffer = "NtMapViewOfSection called\n";
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return pNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "RtlCreateUserThread");
FARPROC WINAPI HookedRtlCreateUserThread(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, CLIENT_ID* ClientId) {
    std::string szBuffer = "RtlCreateUserThread called for process with pid " + std::to_string(GetProcessId(ProcessHandle)); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return pRtlCreateUserThread(ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserved, StackCommit, StartAddress, StartParameter, ThreadHandle, ClientId);
}

NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtCreateThreadEx");
NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer) {
    std::string szBuffer = "NtCreateThreadEx called for process with pid " + std::to_string(GetProcessId(ProcessHandle)); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return pNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
}

//user-mode APC
DWORD(WINAPI* TrueQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR) = QueueUserAPC;
DWORD WINAPI HookedQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData) {
    std::string szBuffer = "QueueUserAPC was called on thread with tid " + std::to_string(GetThreadId(hThread)); szBuffer += (" on process with pid " + std::to_string(GetProcessIdOfThread(hThread))); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return TrueQueueUserAPC(pfnAPC, hThread, dwData);
}

typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(
    IN HANDLE ThreadHandle,
    IN PIO_APC_ROUTINE ApcRoutine,
    IN PVOID ApcRoutineContext OPTIONAL,
    IN PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
    IN ULONG ApcReserved OPTIONAL
    );
NtQueueApcThread_t pNtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQueueApcThread");
NTSTATUS NTAPI HookedNtQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved) {
    std::string szBuffer = "NtQueueApcThread was called on thread with tid " + std::to_string(GetThreadId(ThreadHandle)); szBuffer += (" on process with pid " + std::to_string(GetProcessIdOfThread(ThreadHandle))); szBuffer += '\n';
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, szBuffer.c_str(), szBuffer.length(), &dwBytesWritten, nullptr);
    return pNtQueueApcThread(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID p)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
    {
        WCHAR* buffer = new WCHAR[200];
        const WCHAR name[12] = L"USERPROFILE";
        DWORD result = GetEnvironmentVariable(name, buffer, 200);
        if (result > 200) {
            delete[] buffer; buffer = new WCHAR[result];
            GetEnvironmentVariable(name, buffer, result);
        }
        std::wstring s(L"");    
        s += buffer;
        s += L"\\Desktop\\memapis.log";
        hFile = CreateFile(s.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        delete[] buffer;
        buffer = nullptr;
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
        DetourAttach(&(PVOID&)TrueVirtualAlloc, HookedVirtualAlloc);
        DetourAttach(&(PVOID&)TrueVirtualAlloc2, HookedVirtualAlloc2);
        DetourAttach(&(PVOID&)TrueVirtualAllocEx, HookedVirtualAllocEx);
        DetourAttach(&(PVOID&)TrueCreateProcessA, HookedCreateProcessA);
        DetourAttach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
        DetourAttach(&(PVOID&)TrueOpenProcess, HookedOpenProcess);
        DetourAttach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);
        DetourAttach(&(PVOID&)TrueCreateThread, HookedCreateThread);
        DetourAttach(&(PVOID&)TrueCreateRemoteThreadEx, HookedCreateRemoteThreadEx);
        DetourAttach(&(PVOID&)TrueSuspendThread, HookedSuspendThread);
        DetourAttach(&(PVOID&)TrueCreateToolhelp32Snapshot, HookedCreateToolhelp32Snapshot);
        DetourAttach(&(PVOID&)TrueGetThreadContext, HookedGetThreadContext);
        DetourAttach(&(PVOID&)TrueSetThreadContext, HookedSetThreadContext);
        DetourAttach(&(PVOID&)TrueResumeThread, HookedResumeThread);
        DetourAttach(&(PVOID&)pNtCreateSection, HookedNtCreateSection);
        DetourAttach(&(PVOID&)pNtMapViewOfSection, HookedNtMapViewOfSection);
        DetourAttach(&(PVOID&)pRtlCreateUserThread, HookedRtlCreateUserThread);
        DetourAttach(&(PVOID&)pNtCreateThreadEx, HookedNtCreateThreadEx);
        DetourAttach(&(PVOID&)TrueQueueUserAPC, HookedQueueUserAPC);
        DetourAttach(&(PVOID&)pNtQueueApcThread, HookedNtQueueApcThread);
        LONG lError = DetourTransactionCommit();
        if (lError != NO_ERROR) {
            MessageBox(HWND_DESKTOP, L"Failed to attach detours", L"Error", MB_ICONERROR | MB_OK);
            return false;
        }
    }
    break;

    case DLL_PROCESS_DETACH:
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
        DetourDetach(&(PVOID&)TrueVirtualAlloc, HookedVirtualAlloc);
        DetourDetach(&(PVOID&)TrueVirtualAlloc2, HookedVirtualAlloc2);
        DetourDetach(&(PVOID&)TrueVirtualAllocEx, HookedVirtualAllocEx);
        DetourDetach(&(PVOID&)TrueCreateProcessA, HookedCreateProcessA);
        DetourDetach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
        DetourDetach(&(PVOID&)TrueOpenProcess, HookedOpenProcess);
        DetourDetach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);
        DetourDetach(&(PVOID&)TrueCreateThread, HookedCreateThread);
        DetourDetach(&(PVOID&)TrueCreateRemoteThreadEx, HookedCreateRemoteThreadEx);
        DetourDetach(&(PVOID&)TrueSuspendThread, HookedSuspendThread);
        DetourDetach(&(PVOID&)TrueCreateToolhelp32Snapshot, HookedCreateToolhelp32Snapshot);
        DetourDetach(&(PVOID&)TrueGetThreadContext, HookedGetThreadContext);
        DetourDetach(&(PVOID&)TrueSetThreadContext, HookedSetThreadContext);
        DetourDetach(&(PVOID&)TrueResumeThread, HookedResumeThread);
        DetourDetach(&(PVOID&)pNtCreateSection, HookedNtCreateSection);
        DetourDetach(&(PVOID&)pNtMapViewOfSection, HookedNtMapViewOfSection);
        DetourDetach(&(PVOID&)pRtlCreateUserThread, HookedRtlCreateUserThread);
        DetourDetach(&(PVOID&)pNtCreateThreadEx, HookedNtCreateThreadEx);
        DetourDetach(&(PVOID&)TrueQueueUserAPC, HookedQueueUserAPC);
        DetourDetach(&(PVOID&)pNtQueueApcThread, HookedNtQueueApcThread);
        LONG lError = DetourTransactionCommit();
        if (lError != NO_ERROR) {
            MessageBox(HWND_DESKTOP, L"Failed to detach detours", L"Error", MB_ICONERROR | MB_OK);
            return false;
        }
        CloseHandle(hFile);
    }
    break;
    }

    return true;
}