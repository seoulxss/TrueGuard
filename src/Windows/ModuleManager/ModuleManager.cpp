#include "ModuleManager.h"
#include <algorithm>
#include <stdexcept>
#include "../../Definitions.h"
#include "../../../ext/XorStr/xorstr.h"
#include <algorithm>

#include <SoftPub.h>
#pragma comment(lib, "wintrust.lib")

TG::Windows::HiddenModule::HiddenModule(std::uintptr_t StartAddr, bool IsPE, std::shared_ptr<HookManager> pHookManager)
{
	if (IsPE)
		m_pPEHeader = std::make_unique<PEHeader>(reinterpret_cast<std::uintptr_t*>(StartAddr), pHookManager);
}

TG::Windows::Module::Module(LIST_ENTRY* Entry, Ntdll::LDR_DATA_TABLE_ENTRY* DataTable, std::wstring DllName, std::shared_ptr<HookManager> HookManager) : m_pDataTableEntry(DataTable), m_pEntry(Entry), m_PEHeader(this, HookManager), m_pHookManager(HookManager)
{
	if (!DataTable)
		throw std::runtime_error(xorstr_("Error parsing DataTable!"));
}

std::expected<bool, TG::TG_STATUS> TG::Windows::Module::HideModuleFromPEBList()
{
	return UnlinkModuleInPEBList();
}

std::expected<bool, TG::TG_STATUS> TG::Windows::Module::UnlinkModuleInPEBList()
{
	if (!m_pEntry)
		return std::unexpected<TG_STATUS>(TG::TG_STATUS::NULL_PTR);

	if (!m_pNextEntry)
		m_pNextEntry = m_pEntry->Flink;

	if (!m_pPrevEntry)
		m_pPrevEntry = m_pEntry->Blink;

	//check if we are already unlinked
	 if (m_pPrevEntry->Flink == m_pNextEntry)
	 	return true;
	
	 if (m_pNextEntry->Blink == m_pPrevEntry)
	 	return true;

	//Unlink
	m_pPrevEntry->Flink = m_pNextEntry;
	m_pNextEntry->Blink = m_pPrevEntry;
	return true;
}

std::expected<bool, TG::TG_STATUS> TG::Windows::Module::LinkModuleInPEBList()
{
	if (!m_pEntry)
		return std::unexpected<TG_STATUS>(TG::TG_STATUS::NULL_PTR);

	if (!m_pNextEntry or !m_pEntry or !m_pPrevEntry)
		return std::unexpected<TG_STATUS>(TG::TG_STATUS::NULL_PTR);

	//Check if we are already linked
	if (m_pPrevEntry->Flink == m_pEntry)
		return true;

	if (m_pNextEntry->Blink == m_pEntry)
		return true;

	//Link
	m_pPrevEntry->Flink = m_pEntry;
	m_pNextEntry->Blink = m_pEntry;
	return true;
}

std::expected<bool, TG::TG_STATUS> TG::Windows::Module::ErasePEHeader()
{
	return true;
}

std::expected<bool, TG::TG_STATUS> TG::Windows::Module::IsModuleSigned()
{
	if (!GetDataTableEntry().has_value())
		return std::unexpected<TG_STATUS>(TG::TG_STATUS::NULL_PTR);

	WINTRUST_FILE_INFO fileInfo = { 0 };
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = m_pDataTableEntry->FullDllName.Buffer;
	fileInfo.hFile = NULL;
	fileInfo.pgKnownSubject = NULL;

	WINTRUST_DATA winTrustData = { 0 };
	winTrustData.cbStruct = sizeof(WINTRUST_DATA);
	winTrustData.pPolicyCallbackData = NULL;
	winTrustData.pSIPClientData = NULL;
	winTrustData.dwUIChoice = WTD_UI_NONE; // No UI
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; // No revocation checking
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.pFile = &fileInfo;
	winTrustData.dwStateAction = 0;
	winTrustData.hWVTStateData = NULL;
	winTrustData.dwProvFlags = WTD_SAFER_FLAG;

	// GUID for verifying the signature
	GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	LONG result = WinVerifyTrust(nullptr, &actionGUID, &winTrustData);

	// Check the result
	switch (result) {
	case ERROR_SUCCESS:
		return true; // The file is signed and the signature is valid
	case TRUST_E_NOSIGNATURE:
		//std::wcout << L"No signature found on the file." << std::endl;
		return false;
	case TRUST_E_EXPLICIT_DISTRUST:
		//std::wcout << L"The signature is explicitly distrusted." << std::endl;
		return false;
	case TRUST_E_SUBJECT_NOT_TRUSTED:
		//std::wcout << L"The subject is not trusted." << std::endl;
		return false;
	case CRYPT_E_SECURITY_SETTINGS:
		//std::wcout << L"The hash representing the subject or publisher is not allowed." << std::endl;
		return false;
	default:
		//std::wcout << L"Error verifying signature: 0x" << std::hex << result << std::endl;
		return false;
	}
}

std::expected<bool, TG::TG_STATUS> TG::Windows::Module::HasModulePEHeader()
{
	return true;
}

std::expected<bool, TG::TG_STATUS> TG::Windows::Module::IsModuleInPEBList()
{
	Ntdll::PEB* peb = Ntdll::NtCurrentPeb();
	auto entry = &peb->Ldr->InMemoryOrderModuleList;

	auto next = entry->Flink;
	while (entry != next)
	{
		auto dll = CONTAINING_RECORD(next, Ntdll::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (dll == m_pDataTableEntry)
		{
			return true;
		}

		next = next->Flink;
	}

	return false;
}

std::expected<Ntdll::LDR_DATA_TABLE_ENTRY*, TG::TG_STATUS> TG::Windows::Module::GetDataTableEntry()
{
	if (m_pDataTableEntry)
		return m_pDataTableEntry;

	return std::unexpected<TG_STATUS>(TG_STATUS::ERROR);
}

const TG::Windows::PEHeader& TG::Windows::Module::GetPEHeader() const
{
	return m_PEHeader;
}

bool TG::Windows::Module::GetSuspicious() const
{
	return m_IsSuspicious;
}

TG::Windows::PEHeader& TG::Windows::Module::GetPEHeader()
{
	return m_PEHeader;
}

std::uint64_t TG::Windows::Module::GetModuleStartAddr() const
{
	if (m_pDataTableEntry)
		return reinterpret_cast<std::uint64_t>(m_pDataTableEntry->DllBase);

	return 0;
}

std::size_t TG::Windows::Module::GetModuleSize() const
{
	if (m_pDataTableEntry)
		return static_cast<std::size_t>(m_pDataTableEntry->SizeOfImage);

	return 0;
}

void TG::Windows::Module::SetSuspicious(const bool val)
{
	m_IsSuspicious = val;
}

TG::Windows::ModuleManager::ModuleManager(std::shared_ptr<HookManager> pHookManager) : m_pHookManager(pHookManager)
{
	m_Modules.reserve(300);

	Ntdll::PEB* peb = Ntdll::NtCurrentPeb();
	const auto entry = &peb->Ldr->InMemoryOrderModuleList;

	auto next = entry->Flink;
	while (entry != next)
	{
		auto dll = CONTAINING_RECORD(next, Ntdll::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (dll)
		{
			std::wstring dllname = dll->BaseDllName.Buffer;
			std::ranges::transform(dllname, dllname.begin(), [&](const wchar_t c)
				{
					return std::tolower(c);
				}
			);

			m_Modules.try_emplace(dllname, next, dll, dllname, m_pHookManager);
		}

		next = next->Flink;
	}
}

TG::Windows::ModuleManager::ModuleManager(HookManager* TempManager) : m_pHookManager(TempManager)
{
	m_Modules.reserve(300);

	Ntdll::PEB* peb = Ntdll::NtCurrentPeb();
	auto entry = &peb->Ldr->InMemoryOrderModuleList;

	auto next = entry->Flink;
	while (entry != next)
	{
		auto dll = CONTAINING_RECORD(next, Ntdll::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (dll)
		{
			std::wstring dllname = dll->BaseDllName.Buffer;
			std::ranges::transform(dllname, dllname.begin(), [&](const wchar_t c)
				{
					return std::tolower(c);
				}
			);

			m_Modules.try_emplace(dllname, next, dll, dllname, m_pHookManager);
		}

		next = next->Flink;
	}
}

std::expected<std::vector<TG::Windows::Module*>, TG::TG_STATUS> TG::Windows::ModuleManager::RescanModules()
{
	std::vector<Module*> NewMods;
	NewMods.reserve(10);

	Ntdll::PEB* peb = Ntdll::NtCurrentPeb();
	auto entry = &peb->Ldr->InMemoryOrderModuleList;

	auto next = entry->Flink;
	while (entry != next)
	{
		auto dll = CONTAINING_RECORD(next, Ntdll::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (dll)
		{
			std::wstring dllname = dll->BaseDllName.Buffer;
			std::ranges::transform(dllname, dllname.begin(), [&](const wchar_t c)
				{
					return std::tolower(c);
				}
			);

			auto it = m_Modules.find(dllname);
			if (it == m_Modules.end())
			{
				auto pair = m_Modules.try_emplace(dllname, next, dll, dllname, m_pHookManager);
				NewMods.emplace_back(&pair.first->second);
			}
		}

		next = next->Flink;
	}

	if (NewMods.empty())
		return std::unexpected(TG_STATUS::NOT_FOUND);

	return NewMods;
}

std::expected<std::vector<TG::Windows::HiddenModule*>, TG::TG_STATUS> TG::Windows::ModuleManager::RescanHiddenModules()
{
	std::uintptr_t* pAddr = nullptr;
	MEMORY_BASIC_INFORMATION mbi{};
	auto it = m_Modules.find(xorstr_(L"ntdll.dll"));
	if (it == m_Modules.end())
		return std::unexpected(TG_STATUS::NOT_FOUND);

	using tNtQueryVirtualMemory = Ntdll::NTSTATUS(NTAPI*)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_ Ntdll::MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);
	const auto func = it->second.GetPEHeader().GetProcAddress(xorstr_("NtQueryVirtualMemory"));

	auto Query = reinterpret_cast<tNtQueryVirtualMemory>(func.value());
	if (!Query)
		return std::unexpected(TG::TG_STATUS::NULL_PTR);

	std::vector<TG::Windows::HiddenModule*> hiddenModules;
	SIZE_T Ret = 0;
	while (NT_SUCCESS(Query(GetCurrentProcess(), pAddr, Ntdll::MemoryBasicInformation, &mbi, sizeof(mbi), &Ret)))
	{
		//Scan for PE-Header MZ
		if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
		{
			if (mbi.RegionSize >= sizeof(IMAGE_DOS_HEADER))
			{
				//Cast to it and check MZ
				auto dosHeader = static_cast<IMAGE_DOS_HEADER*>(mbi.BaseAddress);
				if (!dosHeader)
					continue;

				if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
				{
					if (mbi.RegionSize >= dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
					{
						auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uintptr_t>(dosHeader) + dosHeader->e_lfanew);
						if (!ntHeaders)
							continue;

						if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
						{
							// Valid PE file found, add to hidden modules
							hiddenModules.emplace_back(reinterpret_cast<TG::Windows::HiddenModule*>(dosHeader));
						}
					}
				}
			}
		}

		pAddr = reinterpret_cast<std::uintptr_t*>(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
	}

	return hiddenModules;
}

std::expected<const TG::Windows::Module*, TG::TG_STATUS> TG::Windows::ModuleManager::GetModule(
	const std::wstring& name) const
{
	if (name.empty())
		return std::unexpected(TG_STATUS::NOT_FOUND);

	std::wstring copy = name;
	std::ranges::transform(copy, copy.begin(), [&](const wchar_t c)
		{
			return std::tolower(c);
		}
	);

	const auto it = m_Modules.find(copy);
	if (it != m_Modules.end())
		return &it->second;

	return std::unexpected(TG_STATUS::NOT_FOUND);
}

std::expected<TG::Windows::Module*, TG::TG_STATUS> TG::Windows::ModuleManager::GetModule(const std::wstring& name)
{
	if (name.empty())
		return std::unexpected(TG_STATUS::NOT_FOUND);

	std::wstring copy = name;
	std::ranges::transform(copy, copy.begin(), [&](const wchar_t c)
		{
			return std::tolower(c);
		}
	);

	const auto it = m_Modules.find(copy);
	if (it != m_Modules.end())
		return &it->second;

	return std::unexpected(TG_STATUS::NOT_FOUND);
}

std::expected<const TG::Windows::HiddenModule*, TG::TG_STATUS> TG::Windows::ModuleManager::GetHiddenModule(
	const std::wstring& name) const
{
	if (name.empty())
		return std::unexpected(TG_STATUS::NOT_FOUND);

	std::wstring copy = name;
	std::ranges::transform(copy, copy.begin(), [&](const wchar_t c)
		{
			return std::tolower(c);
		}
	);

	const auto it = m_HiddenModules.find(copy);
	if (it != m_HiddenModules.end())
		return &it->second;
	
	return std::unexpected(TG_STATUS::NOT_FOUND);
}

std::expected<TG::Windows::HiddenModule*, TG::TG_STATUS> TG::Windows::ModuleManager::GetHiddenModule(const std::wstring& name)
{
	if (name.empty())
		return std::unexpected(TG_STATUS::NOT_FOUND);

	std::wstring copy = name;
	std::ranges::transform(copy, copy.begin(), [&](const wchar_t c)
		{
			return std::tolower(c);
		}
	);

	const auto it = m_HiddenModules.find(copy);
	if (it != m_HiddenModules.end())
		return &it->second;

	return std::unexpected(TG_STATUS::NOT_FOUND);
}
