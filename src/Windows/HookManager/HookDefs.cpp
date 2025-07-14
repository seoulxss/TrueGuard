#include "HookDefs.h"

#include "HookManager.h"

Ntdll::NTSTATUS TG::Hooks::Functions::LDR_GET_DLL_HANDLE::HkLdrGetDllHandle(PCWSTR DllPath, PULONG DllCharacteristics,
                                                                            Ntdll::PCUNICODE_STRING DllName, PVOID* DllHandle)
{
	return reinterpret_cast<tLdrGetDllHandle>(TG::Globals::g_pHookManager.get()->GetHook(Windows::HOOK_IDENTIFIER::LDR_GET_DLL_HANDLE)->GetTrampoline())(DllPath, DllCharacteristics, DllName, DllHandle);
}
