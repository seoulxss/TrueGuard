#pragma once
#include <memory>
#include <xxhash.h>
#include <unordered_map>
#include "../../Definitions.h"
#include "../PEHeader/PEHeader.h"

namespace TG::Windows
{
	class HookManager;

	struct XXHash
	{
		std::uint64_t operator()(const std::wstring& data) const
		{
			return XXH64(data.data(), data.size(), 0);
		}

		std::uint64_t operator()(const std::string& data) const
		{
			return XXH64(data.data(), data.size(), 0);
		}
	};

	class Module
	{
	public:
		Module(LIST_ENTRY* Entry, LDR_DATA_TABLE_ENTRY* DataTable, std::wstring DllName, std::shared_ptr<HookManager> pHookManager);



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

		std::expected<LDR_DATA_TABLE_ENTRY*, TG_STATUS> GetDataTableEntry();

	private:
		LDR_DATA_TABLE_ENTRY* m_pDataTableEntry = nullptr;
		std::wstring m_ModuleName = {};
		std::wstring m_ModulePath = {};

		LIST_ENTRY* m_pEntry = nullptr;
		LIST_ENTRY* m_pPrevEntry = nullptr;
		LIST_ENTRY* m_pNextEntry = nullptr;

		PEHeader m_PEHeader;
		std::shared_ptr<HookManager> m_pHookManager = nullptr;
	};

	//! Our ModuleManager which handles all the modules and checks them if they are modified or not.
	class ModuleManager
	{
	public:
		ModuleManager(std::shared_ptr<HookManager> pHookManager);

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
		std::unordered_map<std::wstring, Module, XXHash>& GetHiddenMap()
		{
			return m_HiddenModules;
		}

		//! 
		//! @return The map which contains all the hidden modules
		[[nodiscard]] const std::unordered_map<std::wstring, Module, XXHash>& GetHiddenMap() const
		{
			return m_HiddenModules;
		}

		std::expected<const TG::Windows::Module*, TG::TG_STATUS> GetModule(const std::wstring& name) const;
		std::expected<TG::Windows::Module*, TG::TG_STATUS> GetModule(const std::wstring& name);

		std::expected<const TG::Windows::Module*, TG::TG_STATUS> GetHiddenModule(const std::wstring& name) const;
		std::expected<TG::Windows::Module*, TG::TG_STATUS> GetHiddenModule(const std::wstring& name);

	private:
		std::unordered_map<std::wstring, Module, XXHash> m_Modules;
		std::unordered_map<std::wstring, Module, XXHash> m_HiddenModules;
		std::shared_ptr<HookManager> m_pHookManager = nullptr;
	};


}
