#pragma once
#include <Windows.h>

namespace DllLib {
	
	class DllLib {
		public:
			DllLib(PCWSTR pszLibFile, DWORD dwProcessId);
			DWORD injectDll();
			BOOL SetSePrivilege();
		private:
			PCWSTR m_pszLibFile;
			DWORD m_dwProcessId;
	};
}