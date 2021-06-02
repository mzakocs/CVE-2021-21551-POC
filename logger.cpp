#include "stdafx.h"

void Logger::Info(std::string InfoMessage) {
	// Logs an info message
	std::cout << "[+] " << InfoMessage << std::endl;
}

void Logger::Error(std::string ErrorMessage) {
	// Logs an error message
	std::cerr << "[x] " << ErrorMessage << std::endl;
}

void Logger::InfoHex(std::string InfoMessage, DWORD64 Number) {
	// Logs an info message : hex
	std::cout << "[+] " << InfoMessage << ": 0x" << std::hex << Number << std::endl;
}

void Logger::ShowKeyPress() {
	// Press any key to continue...
	// Pauses the console
	system("PAUSE");
}