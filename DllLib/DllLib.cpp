#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "DllLib.h"

namespace DllLib {
	
	DllLib::DllLib(PCWSTR pszLibFile, DWORD dwProcessId)
	{
		m_pszLibFile = pszLibFile;
		m_dwProcessId = dwProcessId;
	}
	BOOL DllLib::SetSePrivilege()
	{
		TOKEN_PRIVILEGES tp = { 0 };
		HANDLE hToken = NULL;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
				if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) == 0) {
					wprintf(TEXT("[-] Error: AdjustTokenPrivilege failed! %u\n"), GetLastError());

					if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
					{
						wprintf(TEXT("[*] Warning: The token does not have the specified privilege.\n"));
						return FALSE;
					}
				}

				CloseHandle(hToken);
			}
			else
				return FALSE;

			return TRUE;
		}
	}

	DWORD DllLib::injectDll()
	{
		// Calculate the number of bytes needed for the DLL's pathname
		DWORD dwSize = (lstrlenW(m_pszLibFile) + 1) * sizeof(wchar_t);

		// Get process handle passing in the process ID
		HANDLE hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION |
			PROCESS_CREATE_THREAD |
			PROCESS_VM_OPERATION |
			PROCESS_VM_WRITE,
			FALSE, m_dwProcessId);
		

		if (hProcess == NULL)
		{
			wprintf(TEXT("[-] Error: Could not open process for PID (%d).\n"), m_dwProcessId);
			return(1);
		}

		// Allocate space in the remote process for the pathname
		LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL)
		{
			wprintf(TEXT("[-] Error: Could not allocate memory inside PID (%d).\n"), m_dwProcessId);
			return(1);
		}

		// Copy the DLL's pathname to the remote process address space
		DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)m_pszLibFile, dwSize, NULL);
		if (n == 0)
		{
			wprintf(TEXT("[-] Error: Could not write any bytes into the PID [%d] address space.\n"), m_dwProcessId);
			return(1);
		}

		// Get the real address of LoadLibraryW in Kernel32.dll
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL)
		{
			wprintf(TEXT("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n"));
			return(1);
		}

		// Create a remote thread that calls LoadLibraryW(DLLPathname)
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
		if (hThread == NULL)
		{
			wprintf(TEXT("[-] Error: Could not create the Remote Thread.\n"));
			return(1);
		}
		else
			wprintf(TEXT("[+] Success: DLL injected via CreateRemoteThread().\n"));

		// Wait for the remote thread to terminate
		WaitForSingleObject(hThread, INFINITE);

		// Free the remote memory that contained the DLL's pathname and close Handles
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

		if (hThread != NULL)
			CloseHandle(hThread);

		if (hProcess != NULL)
			CloseHandle(hProcess);

		return(0);
	}

	
}
