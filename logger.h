#pragma once

#include "stdafx.h"

class Logger {
public:

	// Log an info string to console
	static void Info(std::string InfoMessage);

	// Log an error string to console
	static void Error(std::string ErrorMessage);

	// Log an info string and a hex value to console
	static void InfoHex(std::string InfoMessage, DWORD64 Number);

	// Equivalent to PAUSE in batch scripting
	static void ShowKeyPress();
}; 