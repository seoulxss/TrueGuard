#pragma once
#include "../ModuleManager/ModuleManager.h"

namespace TG::Windows
{
	class ThreadManager
	{
	public:
		ThreadManager(std::shared_ptr<ModuleManager> mods);


	private:
		std::shared_ptr<ModuleManager> m_pModuleManager = nullptr;
	};
}

namespace TG::Globals
{
	inline std::shared_ptr<Windows::ThreadManager> g_pThreadManager = nullptr;
}