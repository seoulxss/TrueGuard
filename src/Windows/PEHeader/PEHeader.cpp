#include "PEHeader.h"
#include <stdexcept>
#include "../../Wrapper/Hashing.h"
#include "../HookManager/HookManager.h"
#include "../ModuleManager/ModuleManager.h"

TG::Windows::PEHeader::PEHeader(Module* pModule, const std::shared_ptr<HookManager>& HookManager) : m_pModule(pModule), m_pHookManager(HookManager)
{
	if (!pModule or !pModule->GetDataTableEntry().has_value())
		throw std::runtime_error("");

	m_pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pModule->GetDataTableEntry().value()->DllBase);
	if (!m_pDosHeader)
		return;

	m_pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<std::byte*>(m_pDosHeader) + m_pDosHeader->e_lfanew);
	m_pOptionalHeader = &m_pNtHeaders->OptionalHeader;

	m_oHashOfTextSection = GetHashOfTextSection().value();
}

std::expected<std::uintptr_t*, TG::TG_STATUS> TG::Windows::PEHeader::GetProcAddress(const std::string& funcName) const
{
	auto dataTable = m_pModule->GetDataTableEntry();
	if (!dataTable.has_value()) 
		return std::unexpected(TG_STATUS::NULL_PTR);
	
	auto* baseAddress = static_cast<std::byte*>(dataTable.value()->DllBase);

	auto& exportDir = m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) 
		return std::unexpected(TG_STATUS::NO_EXPORT_DIRECTORY);

	auto* exportDesc = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(baseAddress + exportDir.VirtualAddress);

	// Get export tables
	const auto* names = reinterpret_cast<DWORD*>(baseAddress + exportDesc->AddressOfNames);
	auto* ordinals = reinterpret_cast<WORD*>(baseAddress + exportDesc->AddressOfNameOrdinals);
	auto* functions = reinterpret_cast<DWORD*>(baseAddress + exportDesc->AddressOfFunctions);

	// Search for function name
	for (DWORD i = 0; i < exportDesc->NumberOfNames; ++i)
	{
		auto* name = reinterpret_cast<const char*>(baseAddress + names[i]);

		if (std::strcmp(name, funcName.c_str()) == 0) 
		{
			const WORD ordinal = ordinals[i];
			if (ordinal >= exportDesc->NumberOfFunctions) 
				return std::unexpected(TG_STATUS::FUNCTION_NOT_FOUND);
			
			return reinterpret_cast<std::uintptr_t*>(baseAddress + functions[ordinal]);
		}
	}

	return std::unexpected(TG_STATUS::FUNCTION_NOT_FOUND);
}

const std::expected<const IMAGE_NT_HEADERS*, TG::TG_STATUS>& TG::Windows::PEHeader::GetImageNtHeaders() const
{
	if (m_pNtHeaders)
		return m_pNtHeaders;

	return std::unexpected<TG_STATUS>(TG_STATUS::NULL_PTR);
}

const std::expected<const IMAGE_OPTIONAL_HEADER*, TG::TG_STATUS>& TG::Windows::PEHeader::GetOptionalHeaders() const
{
	if (m_pNtHeaders)
		return m_pOptionalHeader;

	return std::unexpected<TG_STATUS>(TG_STATUS::NULL_PTR);
}

const std::expected<const IMAGE_DOS_HEADER*, TG::TG_STATUS>& TG::Windows::PEHeader::GetDosHeaders() const
{
	if (m_pNtHeaders)
		return m_pDosHeader;

	return std::unexpected<TG_STATUS>(TG_STATUS::NULL_PTR);
}

std::expected<std::uintptr_t*, TG::TG_STATUS> TG::Windows::PEHeader::GetTextSection()
{
	if (!m_pDosHeader or !m_pNtHeaders or !m_pModule)
		return std::unexpected<TG_STATUS>(TG_STATUS::NULL_PTR);

	const auto* sectionHeader = GetSectionHeader(xorstr_(L".text"));
	if (!sectionHeader)
		return std::unexpected<TG_STATUS>(TG_STATUS::NO_SECTION_FOUND);

	return reinterpret_cast<std::uintptr_t*>(static_cast<std::byte*>(m_pModule->GetDataTableEntry().value()->DllBase) + sectionHeader->VirtualAddress);
}

std::expected<std::size_t, TG::TG_STATUS> TG::Windows::PEHeader::GetTextSectionSize()
{
	if (!m_pDosHeader or !m_pNtHeaders or !m_pModule)
		return std::unexpected<TG_STATUS>(TG_STATUS::NULL_PTR);

	auto* sectionHeader = GetSectionHeader(xorstr_(L".text"));
	if (!sectionHeader)
		return std::unexpected<TG_STATUS>(TG_STATUS::NO_SECTION_FOUND);

	return static_cast<std::size_t>(sectionHeader->Misc.VirtualSize);
}

std::expected<std::vector<std::uint8_t>, TG::TG_STATUS> TG::Windows::PEHeader::GetHashOfTextSection()
{
	TG::Hashing::BlakeHash hasher;
	auto size = GetTextSectionSize();
	auto start = GetTextSection();

	std::lock_guard lock(m_Mutex);
	if (!size.has_value())
		return std::unexpected<TG::TG_STATUS>(size.error());

	if (!start.has_value())
		return std::unexpected<TG::TG_STATUS>(start.error());

	//Disable hooks if any are there!
	m_pHookManager->UnHookAll();
	hasher.Update(start.value(), size.value());
	auto hash = hasher.Finalize();
	m_pHookManager->HookAll();
	return hash;
}

std::expected<bool, TG::TG_STATUS> TG::Windows::PEHeader::IsValidFile() const
{
	if (!m_pDosHeader or !m_pNtHeaders or !m_pModule or !m_pOptionalHeader)
		return std::unexpected<TG_STATUS>(TG_STATUS::NULL_PTR);

	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	if (m_pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return false;

	return true;
}

const std::vector<std::uint8_t>& TG::Windows::PEHeader::GetOrigHashOfText() const
{
	return m_oHashOfTextSection;
}

std::expected<std::size_t, TG::TG_STATUS> TG::Windows::PEHeader::GetImageSize() const
{
	if (!m_pDosHeader or !m_pNtHeaders or !m_pOptionalHeader)
		return std::unexpected(TG_STATUS::NULL_PTR);

	return static_cast<std::size_t>(m_pOptionalHeader->SizeOfImage);
}

std::expected<std::uintptr_t*, TG::TG_STATUS> TG::Windows::PEHeader::GetStartAddr()
{
	if (!m_pDosHeader or !m_pNtHeaders or !m_pOptionalHeader)
		return std::unexpected(TG_STATUS::NULL_PTR);

	return reinterpret_cast<std::uintptr_t*>(m_pOptionalHeader->ImageBase);
}

IMAGE_SECTION_HEADER* TG::Windows::PEHeader::GetSectionHeader(const std::wstring& sectionName)
{
	if (!m_pNtHeaders)
		return nullptr;

	auto sec = (std::string(sectionName.begin(), sectionName.end()));

	auto section = IMAGE_FIRST_SECTION(m_pNtHeaders);
	for (WORD i = 0; i < m_pNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (std::strncmp(reinterpret_cast<const char*>(section[i].Name), sec.c_str(), IMAGE_SIZEOF_SHORT_NAME) == 0)
			return &section[i];
	}

	return nullptr;
}
