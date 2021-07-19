#include "stdafx.h"

int main(int argc, char *argv[]) {

	BOOL success = true;

	// Initialize the Memory Manager object
	Memory* MemoryManager = new Memory();
	
	// Tests getting the base address of ntoskrnl.exe
	DWORD64 ntoskrnlBaseAddress = MemoryManager->GetKernelBase("ntoskrnl.exe");

	// Tests grabbing an EPROCESS struct of a process
	std::string processName = "explorer.exe";
	DWORD64 peprocess = MemoryManager->GetEPROCESSPointer(ntoskrnlBaseAddress, processName);
	if (peprocess == NULL) {
		Logger::Info("Failed to get EPROCESS of process!");
		Logger::ShowKeyPress();
		exit(1);
	}
	Logger::InfoHex("EPROCESS Address", peprocess);

	// Tests reading a value from the EPROCESS struct
	DWORD64 tableBase{};
	MemoryManager->VirtualRead(peprocess + EPROCESS_DIRECTORYTABLEBASE, &tableBase, sizeof(DWORD64));
	Logger::InfoHex("Table Base Address", tableBase);

	// Tests physical reads at address 0
	DWORD64 testPhysAddress{ 0 };
	DWORD64 testPhysRead{};
	MemoryManager->PhysicalRead(tableBase, &testPhysRead, sizeof(DWORD64));
	Logger::InfoHex("Test Phys Read", testPhysRead);

	// Pause to see info, lets me launch the exe outside the terminal
	Logger::ShowKeyPress();

}