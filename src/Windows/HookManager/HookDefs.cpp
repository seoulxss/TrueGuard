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
	auto ret = _ReturnAddress();
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
	auto ret = _ReturnAddress();
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

BOOL WINAPI TG::Hooks::Functions::Module32FirstW::HkModule32FirstW(HANDLE hSnap, MODULEENTRY32W* pEntry)
{
	return reinterpret_cast<tModule32FirstW>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::MODULE_32_FIRST_W)->GetTrampoline())(hSnap, pEntry);
}

BOOL WINAPI TG::Hooks::Functions::Module32NextW::HkModule32NextW(HANDLE hSnap, MODULEENTRY32W* pEntry)
{
	return reinterpret_cast<tModule32NextW>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::MODULE_32_NEXT_W)->GetTrampoline())(hSnap, pEntry);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtWriteVirtualMemory::HkNtWriteVirtualMemory(HANDLE ProcessHandle,
	PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
	return reinterpret_cast<tNtWriteVirtualMemory>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_WRITE_VIRTUAL_MEMORY)->GetTrampoline())(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtReadVirtualMemory::HkNtReadVirtualMemory(HANDLE ProcessHandle,
	PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
	return reinterpret_cast<tNtReadVirtualMemory>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_READ_VIRTUAL_MEMORY)->GetTrampoline())(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtSetInformationProcess::HkNtSetInformationProcess(HANDLE ProcessHandle,
	Ntdll::PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	return reinterpret_cast<tNtSetInformationProcess>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_SET_INFORMATION_PROCESS)->GetTrampoline())(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtSetInformationThread::HkNtSetInformationThread(HANDLE ThreadHandle,
	Ntdll::THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
	return reinterpret_cast<tNtSetInformationThread>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_SET_INFORMATION_THREAD)->GetTrampoline())(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

Ntdll::NTSTATUS __fastcall TG::Hooks::Functions::Optional::LdrpLoadDllInternal::HkLdrpLoadDllInternal(Ntdll::PUNICODE_STRING FullPath,
	Ntdll::LDR_UNKSTRUCT* DllPathInited, ULONG Flags, ULONG LdrFlags, Ntdll::PLDR_DATA_TABLE_ENTRY LdrEntry,
	Ntdll::PLDR_DATA_TABLE_ENTRY LdrEntry2, Ntdll::PLDR_DATA_TABLE_ENTRY* DllEntry, NTSTATUS* pStatus, ULONG Zero)
{
	//Call orig, so we got data to work with.
	const auto stat = reinterpret_cast<tLdrpLoadDllInternal>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::LDR_PLOAD_DLL_INTERNAL)->GetTrampoline())(FullPath, DllPathInited, Flags, LdrFlags, LdrEntry, LdrEntry2, DllEntry, pStatus, Zero);

	//Lets add the module to the ModuleManager, as we also got the LdrEntry
	if (Globals::g_pModuleManager)
	{
		std::wstring modName = FullPath->Buffer;

		//lower it
		std::ranges::transform(modName, modName.begin(), [](const wchar_t c)
			{
				return std::tolower(c);
			});

		//Is it already there?
		const auto it = Globals::g_pModuleManager->GetMap().find(modName);
		if (it != Globals::g_pModuleManager->GetMap().end())
			return stat;

		//We add it, as it's not there!
		Ntdll::LDR_DATA_TABLE_ENTRY* Entry = *DllEntry;
		Globals::g_pModuleManager->GetMap().try_emplace(modName, &Entry->InInitializationOrderLinks, Entry, modName, Globals::g_pHookManager);
	}

	return stat;
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtSetContextThread::HkNtSetContextThread(HANDLE ThreadHandle,
	PCONTEXT ThreadContext)
{
	return reinterpret_cast<tNtSetContextThread>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_SET_CONTEXT_THREAD)->GetTrampoline())(ThreadHandle, ThreadContext);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtGetContextThread::HkNtGetContextThread(HANDLE ThreadHandle,
	PCONTEXT ThreadContext)
{
	return reinterpret_cast<tNtGetContextThread>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_GET_CONTEXT_THREAD)->GetTrampoline())(ThreadHandle, ThreadContext);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::LdrGetProcedureAddressForCaller::HkLdrGetProcedureAddressForCaller(
	HMODULE ModuleHandle, Ntdll::PANSI_STRING FunctionName, WORD Oridinal, PVOID* FunctionAddress, BOOL bValue,
	PVOID* CallbackAddress)
{
	return reinterpret_cast<tLdrGetProcedureAddressForCaller>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::LDR_GET_PROCEDURE_ADDRESS_FOR_CALLER)->GetTrampoline())(ModuleHandle, FunctionName, Oridinal, FunctionAddress, bValue, CallbackAddress);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtOpenProcess::HkOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
	Ntdll::PCOBJECT_ATTRIBUTES ObjectAttributes, Ntdll::PCLIENT_ID ClientId)
{
	return reinterpret_cast<tNtOpenProcess>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_OPEN_PROCESS)->GetTrampoline())(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtQuerySystemInformation::HkNtQuerySystemInformation(
	Ntdll::SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	return reinterpret_cast<tNtQuerySystemInformation>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_QUERY_SYSTEM_INFORMATION)->GetTrampoline())(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

Ntdll::NTSTATUS NTAPI TG::Hooks::Functions::NtQuerySystemInformationEx::HkNtQuerySystemInformationEx(
	Ntdll::SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength,
	PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	return reinterpret_cast<tNtQuerySystemInformationEx>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_QUERY_SYSTEM_INFORMATION_EX)->GetTrampoline())(SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength);
}

Ntdll::NTSTATUS TG::Hooks::Functions::NtMapViewOfSection::HkNtMapViewOfSection(HANDLE SectionHandle,
	HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize, Ntdll::SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG PageProtection)
{
	return reinterpret_cast<tNtMapViewOfSection>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_MAP_VIEW_OF_SECTION)->GetTrampoline())(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, PageProtection);
}

Ntdll::NTSTATUS TG::Hooks::Functions::NtMapViewOfSectionEx::HkNtMapViewOfSectionEx(HANDLE SectionHandle,
	HANDLE ProcessHandle, PVOID* BaseAddress, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
	ULONG PageProtection, PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParameterCount)
{
	return reinterpret_cast<tNtMapViewOfSectionEx>(Globals::g_pHookManager->GetHook(Windows::HOOK_IDENTIFIER::NT_MAP_VIEW_OF_SECTION_EX)->GetTrampoline())(SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize, AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount);
}
