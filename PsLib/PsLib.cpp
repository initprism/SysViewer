#include <stdexcept>
#include <iostream>
#include "PsLib\PsLib.h"

namespace pslib {


	PsLib::PsLib()
	{
		// Get the list of process identifiers.
		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
			throw  std::domain_error("non");
		}

		// Calculate how many process identifiers were returned.
		cProcesses = cbNeeded / sizeof(DWORD);
		
		for (unsigned int i = 0; i < cProcesses; i++)
		{
			if (aProcesses[i] != 0)
			{	
				auto ps1 = getProcessName(aProcesses[i]).first;
				auto ps2 = getProcessName(aProcesses[i]).second;
				if (ps1 != "<unknown>") {
					processs1.push_back(std::make_pair(ps1, aProcesses[i]));
					processs2.push_back(ps2);
				}
			}
		}
		numOfPro = processs1.size();
	}

	std::pair<std::string, std::string> PsLib::getProcessName(DWORD processID)
	{
		char szProcessName[MAX_PATH] = "<unknown>";
		char exeName[MAX_PATH + 1] = "\n";

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |	
			PROCESS_VM_READ,
			FALSE, processID);
		if (NULL != hProcess)
		{
			HMODULE hMod;
			DWORD cbNeeded;

			if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
				&cbNeeded))
			{
				GetModuleBaseNameA(hProcess, hMod, szProcessName,
					sizeof(szProcessName) / sizeof(TCHAR));
			}

			GetProcessImageFileNameA(hProcess, exeName, MAX_PATH);

		}

		return std::make_pair(std::string(szProcessName), std::string(exeName));
	}

	int PsLib::getNumOfPro()
	{
		return (int)numOfPro;
	}

}