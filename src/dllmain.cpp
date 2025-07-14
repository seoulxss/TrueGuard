#include "Windows/ModuleManager/ModuleManager.h"

void wmain(HMODULE hMod)
{
  TG::Windows::ModuleManager mod(nullptr);


    FreeLibraryAndExitThread(hMod, 0);
}


//initialize_onexit_table

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(wmain), hModule, 0, nullptr));
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

