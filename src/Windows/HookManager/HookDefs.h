#pragma once
#include "../ntdll.h"


namespace TG::Hooks::Functions
{
	namespace LDR_GET_DLL_HANDLE
	{
		using tLdrGetDllHandle = Ntdll::NTSTATUS(NTAPI*)(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ Ntdll::PCUNICODE_STRING DllName, _Out_ PVOID* DllHandle);
		Ntdll::NTSTATUS NTAPI HkLdrGetDllHandle(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ Ntdll::PCUNICODE_STRING DllName, _Out_ PVOID* DllHandle);
	}



}
