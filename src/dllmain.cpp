#include "Windows/HookManager/HookManager.h"
#include "Windows/ModuleManager/ModuleManager.h"

void InitualizeHooks()
{
    TG::Globals::g_pHookManager = std::make_shared<TG::Windows::HookManager>();
    TG::Globals::g_pModuleManager = std::make_shared<TG::Windows::ModuleManager>(TG::Globals::g_pHookManager);
    TG::Globals::g_pHookManager->HookAll();

}

void UninitializeHooks()
{
    TG::Globals::g_pHookManager->UnHookAll();
    TG::Globals::g_pHookManager.reset();
    TG::Globals::g_pModuleManager.reset();
}

void Uninitialize()
{
    UninitializeHooks();
}

void wmain(HMODULE hMod)
{
    InitualizeHooks();
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    DisableThreadLibraryCalls(hModule);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(wmain), hModule, 0, nullptr));
        break;
    case DLL_PROCESS_DETACH:
        Uninitialize();
        break;
    }
    return TRUE;
}

