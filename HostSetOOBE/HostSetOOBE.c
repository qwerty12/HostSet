#include <SDKDDKVer.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <Psapi.h>
#include <ntlsa.h>
#include <strsafe.h>

// https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/master/winui/shell/appplatform/DragDropVisuals/ShellHelpers.h
static __inline HRESULT ResultFromKnownLastError() { const DWORD err = GetLastError(); return err == ERROR_SUCCESS ? E_FAIL : HRESULT_FROM_WIN32(err); }

// https://github.com/coderforlife/mingw-unicode-main/blob/master/mingw-unicode-gui.c
static LPWSTR GetRawArguments()
{
	LPWSTR lpCmdLine = GetCommandLineW();
	BOOL quoted = lpCmdLine[0] == L'"';
	++lpCmdLine; // skips the " or the first letter (all paths are at least 1 letter)
	if (!quoted) // avoids GetCommandLineW bug that does not always quote the program name if no arguments
		while (*lpCmdLine > L' ') ++lpCmdLine;
	while (*lpCmdLine) {
		if (quoted && lpCmdLine[0] == L'"') { quoted = FALSE; } // found end quote
		else if (!quoted && lpCmdLine[0] == L' ') {
			// found an unquoted space, now skip all spaces
			do { ++lpCmdLine; } while (lpCmdLine[0] == L' ');
			break;
		}
		++lpCmdLine;
	}
	return lpCmdLine;
}

// Courtesy of http://alter.org.ua/docs/win/args/
static PWCHAR* MyCommandLineToArgvW(PWCHAR CmdLine, PSIZE_T _argc)
{
	PWCHAR* argv;
	PWCHAR  _argv;
	SIZE_T   len;
	SIZE_T   argc;
	WCHAR   a;
	SIZE_T   i, j;

	BOOLEAN  in_QM;
	BOOLEAN  in_TEXT;
	BOOLEAN  in_SPACE;

	len = wcslen(CmdLine);
	i = ((len + 2) / 2) * (sizeof(PVOID) * 2);

	argv = (PWCHAR*)GlobalAlloc(GMEM_FIXED,
		i + (len + 2) * sizeof(WCHAR));

	_argv = (PWCHAR)(((PUCHAR)argv) + i);

	argc = 0;
	argv[argc] = _argv;
	in_QM = FALSE;
	in_TEXT = FALSE;
	in_SPACE = TRUE;
	i = 0;
	j = 0;

	while (a = CmdLine[i]) {
		if (in_QM) {
			if (a == '\"') {
				in_QM = FALSE;
			}
			else {
				_argv[j] = a;
				++j;
			}
		}
		else {
			switch (a) {
			case '\"':
				in_QM = TRUE;
				in_TEXT = TRUE;
				if (in_SPACE) {
					argv[argc] = _argv + j;
					++argc;
				}
				in_SPACE = FALSE;
				break;
			case ' ':
			case '\t':
			case '\n':
			case '\r':
				if (in_TEXT) {
					_argv[j] = '\0';
					++j;
				}
				in_TEXT = FALSE;
				in_SPACE = TRUE;
				break;
			default:
				in_TEXT = TRUE;
				if (in_SPACE) {
					argv[argc] = _argv + j;
					++argc;
				}
				_argv[j] = a;
				++j;
				in_SPACE = FALSE;
				break;
			}
		}
		++i;
	}
	_argv[j] = '\0';
	argv[argc] = NULL;

	(*_argc) = argc;
	return argv;
}

static BOOL GetArguments(BOOL *bOobe, BOOL *bPostHostSet, BOOL *bNetBios, LPWSTR *lpHostname)
{
	BOOL bRet = FALSE;
	SIZE_T nArgs;
	LPWSTR lpArgs = GetRawArguments();

	if (lpArgs && *lpArgs)
	{
		LPWSTR *szArglist = MyCommandLineToArgvW(lpArgs, &nArgs);
		if (szArglist) {
			if (nArgs < 3) {
				if (!_wcsicmp(szArglist[0], L"/OOBE"))
					*bOobe = TRUE;
				else if (!_wcsicmp(szArglist[0], L"/POST"))
					*bPostHostSet = TRUE;
				else if (!_wcsicmp(szArglist[0], L"/NETBIOS"))
					*bNetBios = TRUE;

				if (nArgs == !(*bOobe || *bPostHostSet || *bNetBios) + 1)
					goto out;

				LPCWSTR hostname = szArglist[nArgs == 2];
				if (*hostname == L'/')
					goto out;
				*lpHostname = wcsstr(lpArgs, hostname);
				*(*lpHostname + wcslen(hostname)) = L'\0'; // No need to do GetCommandLineW() again after GetArguments()
				bRet = TRUE;
			}
out:
			GlobalFree(szArglist);
		}
	}

	return bRet;
}

static VOID WriteToOutputW(HANDLE hStd, LPCWSTR lpMsg, DWORD cchMsg)
{
	if (lpMsg && hStd && hStd != INVALID_HANDLE_VALUE) {
		if (cchMsg == 0)
			cchMsg = (DWORD)wcslen(lpMsg);
		if (cchMsg > 0) {
			DWORD dwMode;
			if (GetFileType(hStd) == FILE_TYPE_CHAR && GetConsoleMode(hStd, &dwMode))
				WriteConsoleW(hStd, lpMsg, cchMsg, NULL, NULL);
			else
				WriteFile(hStd, lpMsg, cchMsg * (DWORD)sizeof(WCHAR), NULL, NULL);
		}
	}
}

static __inline VOID PrintNewline(HANDLE hStd) { WriteToOutputW(hStd, L"\n", 1); }

static VOID PrintErrAndMaybeDie(BOOL bDie, LPCSTR lpCallee, LPCWSTR lpFmt, ...)
{
	HANDLE hStdErr = GetStdHandle(STD_ERROR_HANDLE);

	if (hStdErr != INVALID_HANDLE_VALUE) {
		static DWORD modStrlen = -1;
		static CHAR szBase[MAX_PATH] = { '\0' };
		if (modStrlen == -1)
			modStrlen = GetModuleBaseNameA(GetCurrentProcess(), NULL, szBase, sizeof(szBase));

		if (modStrlen > 0) {
			if (WriteFile(hStdErr, szBase, modStrlen, NULL, NULL))
				WriteFile(hStdErr, ": ", 2, NULL, NULL);
		}

		if (lpCallee) {
			WriteFile(hStdErr, "(", 1, NULL, NULL);
			WriteFile(hStdErr, lpCallee, (DWORD)strlen(lpCallee), NULL, NULL);
			WriteFile(hStdErr, ") ", 2, NULL, NULL);
		}

		if (lpFmt) {
			WCHAR szMsg[1025];
			if (SUCCEEDED(StringCchLengthW(lpFmt, _countof(szMsg), NULL))) { // yes, yes, my overrun checks are lame
				va_list pArgs;
				INT cchWritten;

				va_start(pArgs, lpFmt);
				cchWritten = wvsprintf(szMsg, lpFmt, pArgs);
				va_end(pArgs);

				if (cchWritten > 0) {
					if (cchWritten <= 1024) {
						szMsg[cchWritten] = L'\0';
						WriteToOutputW(hStdErr, szMsg, cchWritten);
					} else {
						TerminateProcess(GetCurrentProcess(), EXIT_FAILURE); // time to GTFO
					}
				} 
			}
		}
	}
	if (bDie)
		ExitProcess(EXIT_FAILURE);
}

static LSA_HANDLE GetPolicyHandle()
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS ntsResult;
	LSA_HANDLE lsahPolicyHandle;

	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	// TODO: find out the corresponding bitmasks
	if ((ntsResult = LsaOpenPolicy(NULL, &ObjectAttributes, 9, &lsahPolicyHandle)) != STATUS_SUCCESS)
		PrintErrAndMaybeDie(TRUE, __FUNCTION__, L"Failed to open the LSA policy - (win32) %lu\n", LsaNtStatusToWinError(ntsResult));

	return lsahPolicyHandle;
}

static PPOLICY_ACCOUNT_DOMAIN_INFO GetAccountDomainInfo(LSA_HANDLE PolicyHandle)
{
	NTSTATUS ntsResult;
	PPOLICY_ACCOUNT_DOMAIN_INFO pPADInfo;

	if ((ntsResult = LsaQueryInformationPolicy(PolicyHandle, PolicyAccountDomainInformation, (PVOID *)&pPADInfo)) != STATUS_SUCCESS)
		PrintErrAndMaybeDie(TRUE, __FUNCTION__, L"Error obtaining account domain information from the LSA - (win32) %lu\n", LsaNtStatusToWinError(ntsResult));

	return pPADInfo;
}

static PPOLICY_DNS_DOMAIN_INFO GetDnsDomainInfo(LSA_HANDLE PolicyHandle)
{
	NTSTATUS ntsResult;
	PPOLICY_DNS_DOMAIN_INFO pPADInfo;

	if ((ntsResult = LsaQueryInformationPolicy(PolicyHandle, PolicyDnsDomainInformation, (PVOID *)&pPADInfo)) != STATUS_SUCCESS)
		PrintErrAndMaybeDie(TRUE, __FUNCTION__, L"Error obtaining DNS domain information from the LSA - (win32) %lu\n", LsaNtStatusToWinError(ntsResult));

	return pPADInfo;
}

DECLSPEC_NORETURN static VOID PrintHelpAndCurrentSettings()
{
	PrintErrAndMaybeDie(FALSE, NULL, L"Usage: [/OOBE | /POST | /NETBIOS] hostname\n"
		L"This program is very pedantic about the order of its arguments and accepts only one given switch at a time. The only validation of the hostname comes from the hostname-setting functions themselves!\n"
		L"Without any switches, this program sets the DNS hostname and exits. The change will be effective after rebooting.\n"
		L"Use /NETBIOS to set the physical NetBIOS hostname to <hostname>. This should only be needed if setting an actually-valid physical DNS hostname fails.\n"
		L"Use /OOBE to set the active hostname to <hostname>. Using this switch within a fully-booted Windows environment will cause problems!\n"
		L"Use /POST after setting the physical DNS hostname, and rebooting, to set the account domain name through LSA.");

	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdOut != INVALID_HANDLE_VALUE)
	{
		WCHAR buffer[256] = L"";
		DWORD dwBufSize = _countof(buffer);
		{
			LPCWSTR CONST szDescription[] = { L"NetBIOS: ",
				L"DNS hostname: ",
				L"DNS domain: ",
				L"DNS fully-qualified: ",
				L"Physical NetBIOS: ",
				L"Physical DNS hostname: ",
				L"Physical DNS domain: ",
				L"Physical DNS fully-qualified: " };

			WriteToOutputW(hStdOut, L"\n\nGetComputerNameEx:", 0);
			for (SIZE_T cnf = 0; cnf < _countof(szDescription); ++cnf)
			{
				if (!GetComputerNameExW((COMPUTER_NAME_FORMAT)cnf, buffer, &dwBufSize))
					PrintErrAndMaybeDie(TRUE, __FUNCTION__, L"GetComputerNameEx failed (%d)\n", GetLastError());
				else {
					PrintNewline(hStdOut);
					WriteToOutputW(hStdOut, szDescription[cnf], 0);
					WriteToOutputW(hStdOut, buffer, dwBufSize);
				}

				dwBufSize = _countof(buffer);
				ZeroMemory(buffer, sizeof(buffer));
			}
		}
		{
			WriteToOutputW(hStdOut, L"\n\nGetEnvironmentVariable (initially determined from GetComputerName and the LSA):", 0);
			LPCWSTR CONST szEnvVars[] = { L"COMPUTERNAME", L"LOGONSERVER", L"USERDOMAIN", L"USERDOMAIN_ROAMINGPROFILE" };
			for (SIZE_T i = 0; i < _countof(szEnvVars); ++i) {
				PrintNewline(hStdOut);
				WriteToOutputW(hStdOut, szEnvVars[i], 0);
				WriteToOutputW(hStdOut, L": ", 2);
				DWORD dwRet = GetEnvironmentVariableW(szEnvVars[i], buffer, dwBufSize);
				if (!dwRet || dwRet > _countof(buffer))
					WriteToOutputW(hStdOut, L"<error: either variable is not set or is too large to display>", 0);
				else
					WriteToOutputW(hStdOut, buffer, dwRet);
			}
		}
		{
			WriteToOutputW(hStdOut, L"\n\nLSA:", 0);
			LSA_HANDLE PolicyHandle = GetPolicyHandle();
			PPOLICY_ACCOUNT_DOMAIN_INFO pPADInfo = GetAccountDomainInfo(PolicyHandle);
			PPOLICY_DNS_DOMAIN_INFO pPDInfo = GetDnsDomainInfo(PolicyHandle);

			struct LsaNameTypes
			{
				LPCWSTR lpDnsDomainTypes;
				CONST PLSA_UNICODE_STRING szName;
			} CONST names[] = {
				{ L"Account domain name: ", &(pPADInfo->DomainName) },
				{ L"Primary domain name: ", &(pPDInfo->Name) },
				{ L"Primary domain DNS name: ", &(pPDInfo->DnsDomainName) },
				{ L"Primary domain DNS forest name: ", &(pPDInfo->DnsForestName) }
			};
			for (SIZE_T i = 0; i < _countof(names); ++i) {
				PrintNewline(hStdOut);
				WriteToOutputW(hStdOut, names[i].lpDnsDomainTypes, 0);
				if (names[i].szName->Length > 0)
					WriteToOutputW(hStdOut, names[i].szName->Buffer, names[i].szName->Length / sizeof(WCHAR));
			}
			LsaFreeMemory(pPDInfo);
			LsaFreeMemory(pPADInfo);

			LsaClose(PolicyHandle);
		}
	}
	ExitProcess(EXIT_FAILURE);
}

DECLSPEC_NORETURN VOID mainCRTStartup()
{
	LPWSTR lpHostname = NULL;
	BOOL OOBE = FALSE, POST = FALSE, NETBIOS = FALSE;

	__security_init_cookie();
	if (!GetArguments(&OOBE, &POST, &NETBIOS, &lpHostname))
		PrintHelpAndCurrentSettings();

	if (!POST && !NETBIOS) {
		if (!SetComputerNameExW(ComputerNamePhysicalDnsHostname, lpHostname)) {
			if (OOBE && ResultFromKnownLastError() == ERROR_INVALID_COMPUTERNAME) {
				PrintErrAndMaybeDie(FALSE, __FUNCTION__, L"Manually setting ComputerNamePhysicalNetBIOS due to mismatched code pages");
				NETBIOS = TRUE;
			}
			else {
				PrintErrAndMaybeDie(TRUE, __FUNCTION__, L"SetComputerNameExW failed to set the DNS hostname with error %d", GetLastError());
			}
		}
	}

	if (NETBIOS)
		if (!SetComputerNameExW(ComputerNamePhysicalNetBIOS, lpHostname))
			PrintErrAndMaybeDie(!OOBE, __FUNCTION__, L"SetComputerNameExW failed to set the NetBIOS name with error %d", GetLastError());

	if (OOBE) {
		CONST DWORD szHostname = (DWORD)(wcslen(lpHostname) + 1) * sizeof(WCHAR);
		LSTATUS regStatus = RegSetKeyValueW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", L"ComputerName", REG_SZ, lpHostname, szHostname);
		if (regStatus == ERROR_SUCCESS) {
			regStatus = RegSetKeyValueW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"Hostname", REG_SZ, lpHostname, szHostname);
			if (regStatus != ERROR_SUCCESS)
				PrintErrAndMaybeDie(TRUE, __FUNCTION__, L"Failed to set volatile hostname - %ld", regStatus);
		} 
		else {
			PrintErrAndMaybeDie(TRUE, __FUNCTION__, L"Failed to set active computer name - %ld", regStatus);
		}
	}

	if (OOBE || POST) {
		NTSTATUS ntsResult;
		LSA_HANDLE PolicyHandle = GetPolicyHandle();
		PPOLICY_ACCOUNT_DOMAIN_INFO pPADInfo = GetAccountDomainInfo(PolicyHandle);

		RtlInitUnicodeString((PUNICODE_STRING)&(pPADInfo->DomainName), lpHostname);
		if (NT_SUCCESS((ntsResult = LsaSetInformationPolicy(PolicyHandle, PolicyAccountDomainInformation, pPADInfo)))) {
			PPOLICY_DNS_DOMAIN_INFO pPDInfo = GetDnsDomainInfo(PolicyHandle);
			// Yes, AFAICT, nothing is done with the DNS domain info, so if it saves, it saves
			if ((ntsResult = LsaSetInformationPolicy(PolicyHandle, PolicyDnsDomainInformation, pPDInfo)) != STATUS_SUCCESS)
				PrintErrAndMaybeDie(FALSE, __FUNCTION__, L"Failed to save the new DNS Domain information in the LSA - (win32) %d", LsaNtStatusToWinError(ntsResult));
			LsaFreeMemory(pPDInfo);
		}
		else {
			PrintErrAndMaybeDie(TRUE, __FUNCTION__, L"Failed to save new account domain information in the LSA - (win32) %d", LsaNtStatusToWinError(ntsResult));
		}
		LsaFreeMemory(pPADInfo);
		LsaClose(PolicyHandle);
	}

	ExitProcess(EXIT_SUCCESS);
}
