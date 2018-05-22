#pragma once
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <utility>
#include <vector>
#include <psapi.h>

namespace pslib{
class PsLib
{
public:
	PsLib();
	std::vector<std::pair<std::string, int>> processs1;
	std::vector<std::string> processs2;

	int getNumOfPro();
private:
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int numOfPro;
	std::pair<std::string, std::string> getProcessName(DWORD processID);
};
}