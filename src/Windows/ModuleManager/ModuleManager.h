#pragma once
#include <memory>
#include <xxhash.h>
#include <unordered_map>
#include "../../Definitions.h"
#include "../PEHeader/PEHeader.h"

namespace TG::Windows
{
	enum class HOOK_IDENTIFIER : std::uint8_t;
}

namespace TG::Windows
{
	class HookManager;
	

	struct XXHash
	{
		template<typename Type>
		std::uint64_t operator()(const std::unique_ptr<Type>& data) const
		{
			return XXH64(data.get(), sizeof(data.get()), 0);
		}

		std::uint64_t operator()(const HOOK_IDENTIFIER& data) const
		{
			return XXH64(&data, sizeof(data), 0);
		}

		std::uint64_t operator()(const std::wstring& data) const
		{
			return XXH64(data.data(), data.size(), 0);
		}

		std::uint64_t operator()(const std::string& data) const
		{
			return XXH64(data.data(), data.size(), 0);
		}
	};

	class HiddenModule
	{
	public:
		HiddenModule(std::uintptr_t StartAddr, bool IsPE, std::shared_ptr<HookManager> pHookManager);

	private:
		std::unique_ptr<PEHeader> m_pPEHeader = nullptr; //Only used if dll has a valid PE-Header

		std::uintptr_t m_Size = 0;
		std::uintptr_t m_StartAddr = 0;
		bool m_IsSuspicious = false;
		std::shared_ptr<HookManager> m_pHookManager = nullptr;
	};

	class Module
	{
	public:
		Module(LIST_ENTRY* Entry, Ntdll::LDR_DATA_TABLE_ENTRY* DataTable, std::wstring DllName, std::shared_ptr<HookManager> pHookManager);



		/*		Methods to actually do sth with the module		*/

		//! Unlinks the module from the PEB-List, so it will be invincible 
		//! @return True if it was successfully
		std::expected<bool, TG_STATUS> HideModuleFromPEBList();

		//! Unlinks the module from the PEB-List, so it will be invincible  (Same as HideModuleFromPEBList)
		//! @return True if it was successfully
		std::expected<bool, TG_STATUS> UnlinkModuleInPEBList(); 

		//! Links the module back to the PEB-List
		//! @return True if it was successfully
		std::expected<bool, TG_STATUS> LinkModuleInPEBList();

		//! Erases the PEB-Header in memory, this can cause crashes
		//! @return True if it was successfully
		std::expected<bool, TG_STATUS> ErasePEHeader();



		/*						Checks							*/

		//! Checks if the module has a valid certificate, e.g. Discord or Medal...
		//! @return True if it has one, false if not.
		std::expected<bool, TG_STATUS> IsModuleSigned();

		//! Checks if the module has a PE-Header
		//! @return True if it has one
		std::expected<bool, TG_STATUS> HasModulePEHeader();

		//! Checks if the module is in the PEB-Linked List (currently)
		//! @return True if it is
		std::expected<bool, TG_STATUS> IsModuleInPEBList();



		/*						Getters							*/

		std::expected<Ntdll::LDR_DATA_TABLE_ENTRY*, TG_STATUS> GetDataTableEntry();

		[[nodiscard]] const PEHeader& GetPEHeader() const;

		[[nodiscard]] bool GetSuspicious() const;

		PEHeader& GetPEHeader();

		std::uint64_t GetModuleStartAddr() const;

		std::size_t GetModuleSize() const;


		/*						Setters							*/

		void SetSuspicious(bool val);

	private:
		Ntdll::LDR_DATA_TABLE_ENTRY* m_pDataTableEntry = nullptr;
		std::wstring m_ModuleName = {};
		std::wstring m_ModulePath = {};

		LIST_ENTRY* m_pEntry = nullptr;
		LIST_ENTRY* m_pPrevEntry = nullptr;
		LIST_ENTRY* m_pNextEntry = nullptr;

		PEHeader m_PEHeader;
		std::shared_ptr<HookManager> m_pHookManager = nullptr;
		bool m_IsSuspicious = false; 
	};

	//! Our ModuleManager which handles all the modules and checks them if they are modified or not.
	class ModuleManager
	{
	public:
		explicit ModuleManager(std::shared_ptr<HookManager> pHookManager);
		explicit ModuleManager(HookManager* TempManager);

		//! 
		//! @return The map which contains all the loaded modules
		std::unordered_map<std::wstring, Module, XXHash>& GetMap()
		{
			return m_Modules;
		}

		//! 
		//! @return The map which contains all the loaded modules
		[[nodiscard]] const std::unordered_map<std::wstring, Module, XXHash>& GetMap() const
		{
			return m_Modules;
		}

		//! 
		//! @return The map which contains all the hidden modules
		std::unordered_map<std::wstring, HiddenModule, XXHash>& GetHiddenMap()
		{
			return m_HiddenModules;
		}

		//! Rescans the PEB Linked list and adds the modules which are new to the Map.
		//! @return A vector with the new modules
		std::expected<std::vector<Module*>, TG_STATUS> RescanModules();

		//! Rescans the whole process to find new dll's & compares them to the orig map
		//! @return A vector with the new modules
		std::expected<std::vector<HiddenModule*>, TG_STATUS> RescanHiddenModules();

		//! 
		//! @return The map which contains all the hidden modules
		[[nodiscard]] const std::unordered_map<std::wstring, HiddenModule, XXHash>& GetHiddenMap() const
		{
			return m_HiddenModules;
		}

		//! Get the module
		//! @param name name of the module 
		//! @return Either the module as a pointer or an error 
		[[nodiscard]] std::expected<const TG::Windows::Module*, TG::TG_STATUS> GetModule(const std::wstring& name) const;

		//! Get the module
		//! @param name name of the module 
		//! @return Either the module as a pointer or an error 
		std::expected<TG::Windows::Module*, TG::TG_STATUS> GetModule(const std::wstring& name);

		//! Get the hidden module
		//! @param name name of the hidden module 
		//! @return Either the hidden module as a pointer or an error 
		[[nodiscard]] std::expected<const TG::Windows::HiddenModule*, TG::TG_STATUS> GetHiddenModule(const std::wstring& name) const;

		//! Get the hidden module
		//! @param name name of the hidden module 
		//! @return Either the hidden module as a pointer or an error 
		std::expected<TG::Windows::HiddenModule*, TG::TG_STATUS> GetHiddenModule(const std::wstring& name);

	private:
		std::unordered_map<std::wstring, Module, XXHash> m_Modules;
		std::unordered_map<std::wstring, HiddenModule, XXHash> m_HiddenModules;
		std::shared_ptr<HookManager> m_pHookManager = nullptr;
	};

}

namespace TG::Globals
{
	inline std::shared_ptr<Windows::ModuleManager> g_pModuleManager = nullptr;
}