#include "HookDefs.h"

#include <algorithm>
#include "HookManager.h"
#include "../ModuleManager/ModuleManager.h"

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::LdrGetDllHandle::HkLdrGetDllHandle(PCWSTR DllPath, PULONG DllCharacteristics,
                                                                            Ntdll::PCUNICODE_STRING DllName, PVOID* DllHandle)
{
	return reinterpret_cast<tLdrGetDllHandle>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::LDR_GET_DLL_HANDLE)->GetTrampoline())(DllPath, DllCharacteristics, DllName, DllHandle);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::LdrLoadDll::HkLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics,
	Ntdll::PCUNICODE_STRING DllName, PVOID* DllHandle)
{
	return reinterpret_cast<tLdrLoadDll>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::LDR_LOAD_DLL)->GetTrampoline())(DllPath, DllCharacteristics, DllName, DllHandle);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtProtectVirtualMemory::HkNtProtectVirtualMemory(HANDLE ProcessHandle,
	PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection)
{
	return reinterpret_cast<tNtProtectVirtualMemory>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_PROTECT_VIRTUAL_MEMORY)->GetTrampoline())(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtQueryVirtualMemory::HkNtQueryVirtualMemory(HANDLE ProcessHandle,
	PVOID BaseAddress, Ntdll::MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation,
	SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
	return reinterpret_cast<tNtQueryVirtualMemory>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_QUERY_VIRTUAL_MEMORY)->GetTrampoline())(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtAllocateVirtualMemory::HkNtAllocateVirtualMemory(HANDLE ProcessHandle,
	PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG PageProtection)
{
	return reinterpret_cast<tNtAllocateVirtualMemory>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_ALLOCATE_VIRTUAL_MEMORY)->GetTrampoline())(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, PageProtection);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtAllocateVirtualMemoryEx::HkAllocateVirtualMemoryEx(
	HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationType, ULONG PageProtection,
	PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParameterCount)
{
	return reinterpret_cast<tNtAllocateVirtualMemoryEx>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_ALLOCATE_VIRTUAL_MEMORY_EX)->GetTrampoline())(ProcessHandle, BaseAddress, RegionSize, AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount);
}

void WINAPI TG::Hooks::Functions::BASE_THREAD_INIT_THUNK::HkBaseThreadInitThunk(DWORD LdrReserved,
	LPTHREAD_START_ROUTINE StartAddr, LPVOID lpParameter)
{
	return reinterpret_cast<tBaseThreadInitThunk>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::BASE_THREAD_INIT_THUNK)->GetTrampoline())(LdrReserved, StartAddr, lpParameter);
}
