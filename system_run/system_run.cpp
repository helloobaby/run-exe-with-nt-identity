#include <windows.h>
#include <iostream>
#include <Lmcons.h>
#include <comdef.h>
#include <string>

#include "util.h"

using namespace std;

//设置权限
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid; 

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	}
	else {
		tp.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("[-] The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}


wstring get_username() {
	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	wstring username_w(username);
	return username_w;
}

int wmain(int argc, wchar_t* argv[]) {

	if (argc != 3) {
		wprintf(L"USAGE: system_run.exe [Process PID]  [RunExePath]");
		return -1;
	}

	setlocale(LC_ALL, "chs");
	wprintf(L"[+] Current user is: %s\n", (get_username()).c_str());

	wstring wsPid(argv[1]);
	DWORD PID_TO_IMPERSONATE = stoull(wsPid, 0, 10);
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;

	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	HANDLE currentTokenHandle = NULL;

	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE)) {
		wprintf(L"[+] SeDebugPrivilege enabled!\n");
	}

	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);
	if (GetLastError() == NULL)
		wprintf(L"[+] OpenProcess() success!\n");
	else
	{
		HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
		if (GetLastError() == NULL) {
			wprintf(L"[+] OpenProcess() success!\n");
		}
		else
		{
			wprintf(L"[-]OpenProcess failed due to : ");
			DisplayError<decltype(&wprintf)>(wprintf);
			return -1;
		}
	}

	BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	if (GetLastError() == NULL)
		wprintf(L"[+] OpenProcessToken() success!\n");
	else
	{
		wprintf(L"[-]OpenProcessToken failed due to : ");
		DisplayError<decltype(&wprintf)>(wprintf);
		return -1;
	}

	BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
	if (GetLastError() == NULL)
	{
		wprintf(L"[+] ImpersonatedLoggedOnUser() success!\n");
		wprintf(L"[+] Current user is: %s\n", (get_username()).c_str());
		wprintf(L"[+] Reverting thread to original user context\n");
		RevertToSelf();
	}
	else
	{
		wprintf(L"[-]ImpersonateLoggedOnUser failed due to : ");
		DisplayError<decltype(&wprintf)>(wprintf);
		return -1;
	}


	BOOL duplicateToken = DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	if (GetLastError() == NULL)
		printf("[+] DuplicateTokenEx() success!\n");
	else
	{
		wprintf(L"[-]DuplicateTokenEx failed due to : ");
		DisplayError<decltype(&wprintf)>(wprintf);
		return -1;
	}


	BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, argv[2] , NULL, 0, NULL, NULL, &startupInfo, &processInformation);
	if (GetLastError() == NULL)
		printf("[+] Process spawned!\n");
	else
	{
		wprintf(L"[-]CreateProcessWithTokenW failed due to : ");
		DisplayError<decltype(&wprintf)>(wprintf);
		return -1;
	}

	return 0;
}