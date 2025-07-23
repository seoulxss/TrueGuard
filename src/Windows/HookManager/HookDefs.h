#pragma once
#include <wchar.h>
#include <cmath>
#include <windows.h>
#include "../ntdll.h"
#include "TlHelp32.h"

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

	namespace Module32FirstW
	{
		using tModule32FirstW = BOOL(WINAPI*)(HANDLE hSnap, MODULEENTRY32W* pEntry);
		BOOL WINAPI HkModule32FirstW(HANDLE hSnap, MODULEENTRY32W* pEntry);
	}

	namespace Module32NextW
	{
		using tModule32NextW = BOOL(WINAPI*)(HANDLE hSnap, MODULEENTRY32W* pEntry);
		BOOL WINAPI HkModule32NextW(HANDLE hSnap, MODULEENTRY32W* pEntry);
	}

	namespace NtWriteVirtualMemory
	{
		using tNtWriteVirtualMemory = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ProcessHandle,_In_opt_ PVOID BaseAddress,_In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,_In_ SIZE_T NumberOfBytesToWrite,_Out_opt_ PSIZE_T NumberOfBytesWritten);
		Ntdll::NTSTATUS NTAPI HkNtWriteVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer, _In_ SIZE_T NumberOfBytesToWrite, _Out_opt_ PSIZE_T NumberOfBytesWritten);
	}

	namespace NtReadVirtualMemory
	{
		using tNtReadVirtualMemory = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ProcessHandle,_In_opt_ PVOID BaseAddress,_Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,_In_ SIZE_T NumberOfBytesToRead,_Out_opt_ PSIZE_T NumberOfBytesRead);
		Ntdll::NTSTATUS NTAPI HkNtReadVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer, _In_ SIZE_T NumberOfBytesToRead, _Out_opt_ PSIZE_T NumberOfBytesRead);
	}

	namespace NtSetInformationProcess
	{
		using tNtSetInformationProcess = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ProcessHandle, _In_ Ntdll::PROCESSINFOCLASS ProcessInformationClass, _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength);
		Ntdll::NTSTATUS NTAPI HkNtSetInformationProcess(_In_ HANDLE ProcessHandle, _In_ Ntdll::PROCESSINFOCLASS ProcessInformationClass, _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength);
	}

	namespace NtSetInformationThread
	{
		using tNtSetInformationThread = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ThreadHandle,_In_ Ntdll::THREADINFOCLASS ThreadInformationClass,_In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,_In_ ULONG ThreadInformationLength);
		Ntdll::NTSTATUS NTAPI HkNtSetInformationThread(_In_ HANDLE ThreadHandle, _In_ Ntdll::THREADINFOCLASS ThreadInformationClass, _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation, _In_ ULONG ThreadInformationLength);
	}

	namespace NtSetContextThread
	{
		using tNtSetContextThread = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ThreadHandle,_In_ PCONTEXT ThreadContext);
		Ntdll::NTSTATUS NTAPI HkNtSetContextThread(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext);
	}

	namespace NtGetContextThread
	{
		using tNtGetContextThread = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext);
		Ntdll::NTSTATUS NTAPI HkNtGetContextThread(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext);

	}

	namespace NtOpenProcess
	{
		using tNtOpenProcess = Ntdll::NTSTATUS(NTAPI*)(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ Ntdll::PCOBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ Ntdll::PCLIENT_ID ClientId);
		Ntdll::NTSTATUS NTAPI HkOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ Ntdll::PCOBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ Ntdll::PCLIENT_ID ClientId);
	}

	namespace NtQuerySystemInformation
	{
		using tNtQuerySystemInformation = Ntdll::NTSTATUS(NTAPI*)(_In_ Ntdll::SYSTEM_INFORMATION_CLASS SystemInformationClass,
		                                                          _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
		                                                          _In_ ULONG SystemInformationLength,
		                                                          _Out_opt_ PULONG ReturnLength);

		Ntdll::NTSTATUS NTAPI HkNtQuerySystemInformation(_In_ Ntdll::SYSTEM_INFORMATION_CLASS SystemInformationClass,
			_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
			_In_ ULONG SystemInformationLength,
			_Out_opt_ PULONG ReturnLength);
	}

	namespace NtQuerySystemInformationEx
	{
		using tNtQuerySystemInformationEx = Ntdll::NTSTATUS(NTAPI*)(_In_ Ntdll::SYSTEM_INFORMATION_CLASS SystemInformationClass,
		                                                            _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
		                                                            _In_ ULONG InputBufferLength,
		                                                            _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
		                                                            _In_ ULONG SystemInformationLength,
		                                                            _Out_opt_ PULONG ReturnLength);

		Ntdll::NTSTATUS NTAPI HkNtQuerySystemInformationEx(_In_ Ntdll::SYSTEM_INFORMATION_CLASS SystemInformationClass,
			_In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
			_In_ ULONG InputBufferLength,
			_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
			_In_ ULONG SystemInformationLength,
			_Out_opt_ PULONG ReturnLength);
	}

	namespace NtMapViewOfSection
	{
		using tNtMapViewOfSection = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE SectionHandle,
			_In_ HANDLE ProcessHandle,
			_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
			_In_ ULONG_PTR ZeroBits,
			_In_ SIZE_T CommitSize,
			_Inout_opt_ PLARGE_INTEGER SectionOffset,
			_Inout_ PSIZE_T ViewSize,
			_In_ Ntdll::SECTION_INHERIT InheritDisposition,
			_In_ ULONG AllocationType,
			_In_ ULONG PageProtection);

		Ntdll::NTSTATUS NTAPI HkNtMapViewOfSection(_In_ HANDLE SectionHandle,
			_In_ HANDLE ProcessHandle,
			_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
			_In_ ULONG_PTR ZeroBits,
			_In_ SIZE_T CommitSize,
			_Inout_opt_ PLARGE_INTEGER SectionOffset,
			_Inout_ PSIZE_T ViewSize,
			_In_ Ntdll::SECTION_INHERIT InheritDisposition,
			_In_ ULONG AllocationType,
			_In_ ULONG PageProtection);

	}

	namespace NtMapViewOfSectionEx
	{
		using tNtMapViewOfSectionEx = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE SectionHandle,
			_In_ HANDLE ProcessHandle,
			_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
			_Inout_opt_ PLARGE_INTEGER SectionOffset,
			_Inout_ PSIZE_T ViewSize,
			_In_ ULONG AllocationType,
			_In_ ULONG PageProtection,
			_Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
			_In_ ULONG ExtendedParameterCount);

		Ntdll::NTSTATUS NTAPI HkNtMapViewOfSectionEx(_In_ HANDLE SectionHandle,
			_In_ HANDLE ProcessHandle,
			_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
			_Inout_opt_ PLARGE_INTEGER SectionOffset,
			_Inout_ PSIZE_T ViewSize,
			_In_ ULONG AllocationType,
			_In_ ULONG PageProtection,
			_Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
			_In_ ULONG ExtendedParameterCount);
	}

	namespace LdrGetProcedureAddressForCaller //GetProcAddress
	{
		using tLdrGetProcedureAddressForCaller = Ntdll::NTSTATUS(NTAPI*)(__in HMODULE ModuleHandle, __in_opt Ntdll::PANSI_STRING  FunctionName, __in_opt WORD          Oridinal, __out    PVOID* FunctionAddress, __in     BOOL          bValue, __in     PVOID* CallbackAddress);
		Ntdll::NTSTATUS NTAPI HkLdrGetProcedureAddressForCaller(__in HMODULE ModuleHandle, __in_opt Ntdll::PANSI_STRING  FunctionName, __in_opt WORD          Oridinal, __out    PVOID* FunctionAddress, __in     BOOL          bValue, __in     PVOID* CallbackAddress);

	}

	namespace NtOpenFile
	{
		using tNtOpenFile = Ntdll::NTSTATUS(NTAPI*)(_Out_ PHANDLE FileHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ Ntdll::PCOBJECT_ATTRIBUTES ObjectAttributes,
			_Out_ Ntdll::PIO_STATUS_BLOCK IoStatusBlock,
			_In_ ULONG ShareAccess,
			_In_ ULONG OpenOptions);

		Ntdll::NTSTATUS NTAPI HkNtOpenFile(_Out_ PHANDLE FileHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ Ntdll::PCOBJECT_ATTRIBUTES ObjectAttributes,
			_Out_ Ntdll::PIO_STATUS_BLOCK IoStatusBlock,
			_In_ ULONG ShareAccess,
			_In_ ULONG OpenOptions);

	}

	namespace Optional
	{
		namespace LdrpLoadDllInternal
		{
			using tLdrpLoadDllInternal = Ntdll::NTSTATUS(__fastcall*)(Ntdll::PUNICODE_STRING FullPath,
				Ntdll::LDR_UNKSTRUCT* DllPathInited, ULONG Flags,
				ULONG LdrFlags,
				Ntdll::PLDR_DATA_TABLE_ENTRY LdrEntry,
				Ntdll::PLDR_DATA_TABLE_ENTRY LdrEntry2,
				Ntdll::PLDR_DATA_TABLE_ENTRY* DllEntry,
				Ntdll::NTSTATUS* pStatus, ULONG Zero);

			Ntdll::NTSTATUS __fastcall HkLdrpLoadDllInternal(
				Ntdll::PUNICODE_STRING FullPath,
				Ntdll::LDR_UNKSTRUCT* DllPathInited, ULONG Flags,
				ULONG LdrFlags,
				Ntdll::PLDR_DATA_TABLE_ENTRY LdrEntry,
				Ntdll::PLDR_DATA_TABLE_ENTRY LdrEntry2,
				Ntdll::PLDR_DATA_TABLE_ENTRY* DllEntry,
				Ntdll::NTSTATUS* pStatus, ULONG Zero);

		}

	}
}
