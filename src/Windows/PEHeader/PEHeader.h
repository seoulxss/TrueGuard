#pragma once
#include <memory>
#include <mutex>
#include <shared_mutex>

#include "../../Definitions.h"


namespace TG::Windows
{
	class HookManager;
	class Module;

	class PEHeader
	{
	public:
		using DllBase = std::uintptr_t;

		explicit PEHeader(Module* pModule, std::shared_ptr<HookManager> HookManager);
		explicit PEHeader(std::uintptr_t* Dos, std::shared_ptr<HookManager> HookManager);

		//! GetProcAddress
		//! @param funcName The functions to search
		//! @return The pointer to the func or an error value
		[[nodiscard]] std::expected<std::uintptr_t*, TG_STATUS> GetProcAddress(const std::string& funcName) const;

		//! 
		//! @return The pointer to the IMAGE_NT_HEADERS or an error value
		[[nodiscard]] const std::expected<const IMAGE_NT_HEADERS*, TG::TG_STATUS>& GetImageNtHeaders() const;

		//! 
		//! @return The pointer to the IMAGE_OPTIONAL_HEADER or an error value
		[[nodiscard]] const std::expected<const IMAGE_OPTIONAL_HEADER*, TG::TG_STATUS>& GetOptionalHeaders() const;

		//! 
		//! @return The pointer to the IMAGE_DOS_HEADER or an error value
		[[nodiscard]] const std::expected<const IMAGE_DOS_HEADER*, TG::TG_STATUS>& GetDosHeaders() const;

		//! 
		//! @return The pointer to the .text Section or an error value
		std::expected<std::uintptr_t*, TG_STATUS> GetTextSection();

		//! 
		//! @return The size of the .text section or an error value
		std::expected<std::size_t, TG_STATUS> GetTextSectionSize();

		//! Generates a blake3 hash of the .text section
		//! @return A std::vector<std::uint8_t> hash of the .text section 
		std::expected<std::vector<std::uint8_t>, TG_STATUS> GetHashOfTextSection();

		//! Checks if the file is valid (PE Header)
		//! @return True if it is, false of not, or an error value
		[[nodiscard]] std::expected<bool, TG_STATUS> IsValidFile() const;

		//! Returns the original .test hash at init
		//! @return Vector of the orig hash value
		[[nodiscard]] const std::vector<std::uint8_t>& GetOrigHashOfText() const;

		//! Gets the image size with the PE-Format
		//! @return The Image size or an error value
		std::expected<std::size_t, TG_STATUS> GetImageSize() const;

		//! Gets the start addr with the PE-Format
		//! @return The start addr  or an error value
		std::expected<std::uintptr_t*, TG_STATUS> GetStartAddr();


	private:
		DllBase m_DllBase = 0;
		IMAGE_NT_HEADERS* m_pNtHeaders = nullptr;
		IMAGE_OPTIONAL_HEADER* m_pOptionalHeader = nullptr;
		IMAGE_DOS_HEADER* m_pDosHeader = nullptr;
		TG::Windows::Module* m_pModule = nullptr;
		std::shared_ptr<HookManager> m_pHookManager = nullptr;
		std::vector<std::uint8_t> m_oHashOfTextSection = {};
		mutable std::shared_mutex m_Mutex;

		IMAGE_SECTION_HEADER* GetSectionHeader(const std::wstring& sectionName);
	};
}
