#include "HookManager.h"

#include <ranges>

TG::Windows::IATHook::~IATHook()
{
	IATHook::UnHookFunction();
	m_pIATHook.reset();
}

TG::Windows::IATHook::IATHook(std::string_view dllName, std::string_view apiName, std::wstring_view ModuleName,
	std::uint64_t CallBack) : m_Trampoline(0), m_ApiName(apiName), m_DllName(dllName), m_ModuleName(ModuleName), m_Callback(CallBack), m_pIATHook(std::make_unique<PLH::IatHook>(m_DllName, m_ApiName, m_Callback, &m_Trampoline, m_ModuleName))
{
}

void TG::Windows::IATHook::HookFunction()
{
	if (!m_isHooked)
	{
		m_pIATHook->hook();
		m_isHooked = true;
	}
}

void TG::Windows::IATHook::UnHookFunction()
{
	if (m_isHooked)
	{
		m_pIATHook->unHook();
		m_isHooked = false;
	}
}

TG::Windows::EATHook::EATHook(std::string_view apiName, std::wstring_view moduleName, std::uintptr_t callback) : m_ApiName(apiName), m_ModuleName(moduleName), m_Callback(callback), m_pEATHook(std::make_unique<PLH::EatHook>(std::string(apiName), std::wstring(moduleName), callback, &m_Trampoline))
{
}

TG::Windows::EATHook::~EATHook()
{
	EATHook::UnHookFunction();
	m_pEATHook.reset();
}

void TG::Windows::EATHook::HookFunction()
{
	if (!m_isHooked)
	{
		m_pEATHook->hook();
		m_isHooked = true;

	}
}

void TG::Windows::EATHook::UnHookFunction()
{
	if (m_isHooked)
	{
		m_pEATHook->unHook();
		m_isHooked = false;
	}

}

TG::Windows::DetHook::~DetHook()
{
	DetHook::UnHookFunction();
	m_pDetHook.reset();
}

TG::Windows::DetHook::DetHook(std::uint64_t FuncToHook, std::uint64_t Callback) : m_Trampoline(0), m_Callback(Callback), m_FuncToHook(FuncToHook), m_pDetHook(std::make_unique<PLH::NatDetour>(m_FuncToHook, m_Callback, &m_Trampoline))
{
}

void TG::Windows::DetHook::HookFunction()
{
	if (!m_isHooked)
	{
		m_pDetHook->hook();
		m_isHooked = true;
	}
}

void TG::Windows::DetHook::UnHookFunction()
{
	if (m_isHooked)
	{
		m_pDetHook->unHook();
		m_isHooked = false;
	}
}

TG::Windows::HookManager::~HookManager()
{
	//First unhook protect, then Alloc
	m_Hooks.find(HOOK_IDENTIFIER::NT_PROTECT_VIRTUAL_MEMORY)->second->UnHookFunction();
	m_Hooks.find(HOOK_IDENTIFIER::NT_ALLOCATE_VIRTUAL_MEMORY)->second->UnHookFunction();

	for (auto& val : m_Hooks | std::views::values)
		val.reset();
}

void TG::Windows::HookManager::HookAll() const
{
	for (const auto& val : m_Hooks | std::views::values)
		val->HookFunction();
}

void TG::Windows::HookManager::UnHookAll() const
{
	for (const auto& val : m_Hooks | std::views::values)
		val->UnHookFunction();
}

TG::Windows::Hook* TG::Windows::HookManager::GetHook(const HOOK_IDENTIFIER id)
{
	const auto it = m_Hooks.find(id);
	if (it != m_Hooks.end())
		return it->second.get();

	return nullptr;
}

const TG::Windows::Hook* TG::Windows::HookManager::GetHook(const HOOK_IDENTIFIER id) const
{
	const auto it = m_Hooks.find(id);
	if (it != m_Hooks.end())
		return it->second.get();

	return nullptr;
}
