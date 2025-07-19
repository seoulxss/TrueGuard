#pragma once
#include <Windows.h>
#include <string>
#include <expected>
#include <vector>
#include "Windows/ntdll.h"
#include "../ext/XorStr/xorstr.h"


#ifdef ERROR
#undef ERROR
#endif

namespace TG
{
	enum class TG_STATUS : uint8_t
	{
		//General
		OK,
		ERROR,
		NULL_PTR,
		NOT_FOUND,

		//PE
		INVALID_FORMAT,
		NO_SECTION_FOUND,
		NO_IMPORT_FOUND,
		NO_EXPORT_FOUND,
		INVALID_HEADER,
		NO_EXPORT_DIRECTORY,
		NO_IMPORT_DIRECTORY,
		FUNCTION_NOT_FOUND,
	};


}