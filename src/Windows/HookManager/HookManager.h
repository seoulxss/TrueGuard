#pragma once
#include <polyhook2/Detour/NatDetour.hpp>
#include <polyhook2/PE/EatHook.hpp>
#include <polyhook2/PE/IatHook.hpp>

#include "HookDefs.h"
#include "../ModuleManager/ModuleManager.h"
#include "../PEHeader/PEHeader.h"


namespace TG::Windows
{

	enum class HOOK_IDENTIFIER : std::uint8_t
	{
		LDR_GET_DLL_HANDLE, //So we can catch GetModuleHandleW etc...
		LDR_LOAD_DLL, //Catch LoadLibrary etc..

		NT_ALLOCATE_VIRTUAL_MEMORY,
		NT_ALLOCATE_VIRTUAL_MEMORY_EX,

		NT_PROTECT_VIRTUAL_MEMORY,
		NT_QUERY_VIRTUAL_MEMORY,

		BASE_THREAD_INIT_THUNK,

		MODULE_32_FIRST_W,
		MODULE_32_NEXT_W,
	};

	class Hook
	{
	public:
		virtual ~Hook() = default;
		virtual void HookFunction() = 0;
		virtual void UnHookFunction() = 0;
		[[nodiscard]] virtual std::uint64_t GetTrampoline() const = 0;
		[[nodiscard]] virtual bool IsHooked() const = 0;

	protected:
		bool m_isHooked = false;
	};

	class IATHook final : public Hook
	{
	public:
		~IATHook() override;
		IATHook() = delete;
		IATHook(std::string_view dllName, std::string_view apiName, std::wstring_view ModuleName, std::uint64_t CallBack);

		void HookFunction() override;
		void UnHookFunction() override;

		[[nodiscard]] bool IsHooked() const override
		{
			return m_isHooked;
		}

		[[nodiscard]] std::uint64_t GetTrampoline() const override
		{
			return m_Trampoline;
		}

		[[nodiscard]] std::string_view GetApiName() const
		{
			return m_ApiName;
		}

		[[nodiscard]] std::wstring_view GetModuleName() const
		{
			return m_ModuleName;
		}

		[[nodiscard]] std::uintptr_t GetCallback() const
		{
			return m_Callback;
		}

		[[nodiscard]] std::string_view GetDllName() const
		{
			return m_DllName;
		}

	private:
		std::uint64_t m_Trampoline = 0;
		std::string m_ApiName;
		std::string m_DllName;
		std::wstring m_ModuleName;
		std::uintptr_t m_Callback = 0;
		std::unique_ptr<PLH::IatHook> m_pIATHook;
	};

	class EATHook final : public Hook
	{
	public:
		EATHook(std::string_view apiName, std::wstring_view moduleName, std::uintptr_t callback);
		~EATHook() override;

		EATHook(const EATHook&) = delete;
		EATHook& operator=(const EATHook&) = delete;

		void HookFunction() override;
		void UnHookFunction() override;


		[[nodiscard]] bool IsHooked() const override
		{
			return m_isHooked;
		}

		[[nodiscard]] std::uint64_t GetTrampoline() const override
		{
			return m_Trampoline;
		}

		[[nodiscard]] std::string_view GetApiName() const
		{
			return m_ApiName;
		}

		[[nodiscard]] std::wstring_view GetModuleName() const
		{
			return m_ModuleName;
		}

		[[nodiscard]] std::uintptr_t GetCallback() const
		{
			return m_Callback;
		}

	private:
		std::uint64_t m_Trampoline = 0;
		std::string m_ApiName;
		std::wstring m_ModuleName;
		std::uintptr_t m_Callback = 0;
		std::unique_ptr<PLH::EatHook> m_pEATHook;
	};
	
	class DetHook : public Hook
	{
	public:
		DetHook() = delete;
		~DetHook() override;

		DetHook(const DetHook&) = delete;
		DetHook& operator=(const DetHook&) = delete;
		DetHook(std::uint64_t FuncToHook, std::uint64_t Callback);

		void HookFunction() override;
		void UnHookFunction() override;


		[[nodiscard]] bool IsHooked() const override
		{
			return m_isHooked;
		}

		[[nodiscard]] std::uint64_t GetTrampoline() const override
		{
			return m_Trampoline;
		}

		[[nodiscard]] std::uintptr_t GetCallback() const
		{
			return m_Callback;
		}

		[[nodiscard]] std::uintptr_t GetFuncToHook() const
		{
			return m_FuncToHook;
		}

	private:
		std::uint64_t m_Trampoline = 0;
		std::uintptr_t m_Callback = 0;
		std::uint64_t m_FuncToHook = 0;
		std::unique_ptr<PLH::NatDetour> m_pDetHook;
	};

	class HookManager
	{
	public:
		HookManager()
		{
			//We create a temporary ModuleManager (This is so uselessly espensive..)
			ModuleManager manager(nullptr);

			//Nt (Ldr)
			AddHook(HOOK_IDENTIFIER::LDR_GET_DLL_HANDLE, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"ntdll.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("LdrGetDllHandle")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::LdrGetDllHandle::HkLdrGetDllHandle)));
			AddHook(HOOK_IDENTIFIER::LDR_LOAD_DLL, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"ntdll.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("LdrLoadDll")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::LdrLoadDll::HkLdrLoadDll)));

			//Kernel32
			AddHook(HOOK_IDENTIFIER::BASE_THREAD_INIT_THUNK, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"kernel32.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("BaseThreadInitThunk")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::BASE_THREAD_INIT_THUNK::HkBaseThreadInitThunk)));
			AddHook(HOOK_IDENTIFIER::MODULE_32_FIRST_W, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"kernel32.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("Module32FirstW")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::Module32FirstW::HkModule32FirstW)));
			AddHook(HOOK_IDENTIFIER::MODULE_32_NEXT_W, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"kernel32.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("Module32NextW")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::Module32NextW::HkModule32NextW)));

			//Nt
			AddHook(HOOK_IDENTIFIER::NT_PROTECT_VIRTUAL_MEMORY, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"ntdll.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("NtProtectVirtualMemory")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::NtProtectVirtualMemory::HkNtProtectVirtualMemory)));
			AddHook(HOOK_IDENTIFIER::NT_QUERY_VIRTUAL_MEMORY, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"ntdll.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("NtQueryVirtualMemory")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::NtQueryVirtualMemory::HkNtQueryVirtualMemory)));
			AddHook(HOOK_IDENTIFIER::NT_ALLOCATE_VIRTUAL_MEMORY, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"ntdll.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("NtAllocateVirtualMemory")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::NtAllocateVirtualMemory::HkNtAllocateVirtualMemory)));
			AddHook(HOOK_IDENTIFIER::NT_ALLOCATE_VIRTUAL_MEMORY_EX, std::make_unique<DetHook>(reinterpret_cast<std::uint64_t>(manager.GetModule(xorstr_(L"ntdll.dll")).value()->GetPEHeader().GetProcAddress(xorstr_("NtAllocateVirtualMemoryEx")).value()), reinterpret_cast<std::uint64_t>(&Hooks::Functions::NtAllocateVirtualMemoryEx::HkAllocateVirtualMemoryEx)));
		}

		~HookManager();

		template<typename HookType>
		void AddHook(HOOK_IDENTIFIER id, std::unique_ptr<HookType> hook)
		{
			m_Hooks.try_emplace(id, std::move(hook));
		}

		void HookAll() const;
		void UnHookAll() const;

		[[nodiscard]] Hook* GetHook(HOOK_IDENTIFIER id); 
		[[nodiscard]] const Hook* GetHook(HOOK_IDENTIFIER id) const;

	private:
		std::unordered_map<HOOK_IDENTIFIER, std::unique_ptr<Hook>, XXHash> m_Hooks;
	};
}

namespace TG::Globals
{
	inline std::shared_ptr<Windows::HookManager> g_pHookManager = nullptr;
}

