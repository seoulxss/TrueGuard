#pragma once
#include <wchar.h>
#include <cmath>
#include <windows.h>
#include "../ntdll.h"

namespace TG::Hooks::Functions
{
	//initialize_onexit_table

	namespace LdrGetDllHandle
	{
		using tLdrGetDllHandle = Ntdll::NTSTATUS(NTAPI*)(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ Ntdll::PCUNICODE_STRING DllName, _Out_ PVOID* DllHandle);
		Ntdll::NTSTATUS NTAPI HkLdrGetDllHandle(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ Ntdll::PCUNICODE_STRING DllName, _Out_ PVOID* DllHandle);
	}

	namespace LdrLoadDll
	{
		using tLdrLoadDll = Ntdll::NTSTATUS(NTAPI*)(_In_opt_ PCWSTR DllPath,_In_opt_ PULONG DllCharacteristics,_In_ Ntdll::PCUNICODE_STRING DllName,_Out_ PVOID* DllHandle);
		Ntdll::NTSTATUS NTAPI HkLdrLoadDll(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ Ntdll::PCUNICODE_STRING DllName, _Out_ PVOID* DllHandle);
	}

	namespace BASE_THREAD_INIT_THUNK
	{
		using tBaseThreadInitThunk = void(WINAPI*)(DWORD LdrReserved, LPTHREAD_START_ROUTINE StartAddr, LPVOID lpParameter);
		void WINAPI HkBaseThreadInitThunk(DWORD LdrReserved, LPTHREAD_START_ROUTINE StartAddr, LPVOID lpParameter);
	}

	namespace NtProtectVirtualMemory
	{
		using tNtProtectVirtualMemory = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ProcessHandle,_Inout_ PVOID* BaseAddress,_Inout_ PSIZE_T RegionSize,_In_ ULONG NewProtection,_Out_ PULONG OldProtection);
		Ntdll::NTSTATUS NTAPI HkNtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtection, _Out_ PULONG OldProtection);
	}

	namespace NtQueryVirtualMemory
	{
		using tNtQueryVirtualMemory = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ProcessHandle,_In_opt_ PVOID BaseAddress,_In_ Ntdll::MEMORY_INFORMATION_CLASS MemoryInformationClass,_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,_In_ SIZE_T MemoryInformationLength,_Out_opt_ PSIZE_T ReturnLength);
		Ntdll::NTSTATUS NTAPI HkNtQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ Ntdll::MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
	}

	namespace NtAllocateVirtualMemory
	{
		using tNtAllocateVirtualMemory = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ProcessHandle,_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,_In_ ULONG_PTR ZeroBits,_Inout_ PSIZE_T RegionSize,_In_ ULONG AllocationType,_In_ ULONG PageProtection);
		Ntdll::NTSTATUS NTAPI HkNtAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG PageProtection);
	}

	namespace NtAllocateVirtualMemoryEx
	{
		using tNtAllocateVirtualMemoryEx = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ProcessHandle, _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG PageProtection, _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters, _In_ ULONG ExtendedParameterCount);
		Ntdll::NTSTATUS NTAPI HkAllocateVirtualMemoryEx(_In_ HANDLE ProcessHandle, _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG PageProtection, _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters, _In_ ULONG ExtendedParameterCount);
	}



}
