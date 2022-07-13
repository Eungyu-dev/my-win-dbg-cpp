#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>

#include <iostream>
#include <string>

std::string GetLastErrorAsString()
{
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	/** Formats a message string.
		DWORD FormatMessage(
		  [in]           DWORD   dwFlags,
		  [in, optional] LPCVOID lpSource,
		  [in]           DWORD   dwMessageId,	// GetLastError() ERROR CODE
		  [in]           DWORD   dwLanguageId,
		  [out]          LPTSTR  lpBuffer,
		  [in]           DWORD   nSize,
		  [in, optional] va_list *Arguments
		);
	*/
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	/** Frees the specified local memory object and invalidates its handle.
		HLOCAL LocalFree(
		  [in] _Frees_ptr_opt_ HLOCAL hMem
		);*/
	LocalFree(messageBuffer);

	return message;
}

TCHAR* GetProcessNameFromID(DWORD processID) {
	/** Opens an existing local process object.
		HANDLE OpenProcess(
		  [in] DWORD dwDesiredAccess,	// 권한
		  [in] BOOL  bInheritHandle,	// 상속여부
		  [in] DWORD dwProcessId		// System process, Client Server Run-Time Subsystem, 0이면 실패.
		);*/
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		processID
	);

	if (hProcess == NULL) {
		_tprintf(TEXT("PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
		return nullptr;
	}

	HMODULE hModule;
	DWORD cbNeeded;
	TCHAR* szProcessName = nullptr;
	/** Retrieves a handle for each module in the specified process that meets the specified filter criteria.
		BOOL EnumProcessModulesEx(
		  [in]  HANDLE  hProcess,
		  [out] HMODULE *lphModule,
		  [in]  DWORD   cb,
		  [out] LPDWORD lpcbNeeded,
		  [in]  DWORD   dwFilterFlag
		);
	*/
	if (EnumProcessModulesEx(
		hProcess,
		&hModule,
		sizeof(hModule),
		&cbNeeded,
		LIST_MODULES_ALL
	)) {
		/** Retrieves the base name of the specified module.
			DWORD GetModuleBaseNameW(
			  [in]           HANDLE  hProcess,
			  [in, optional] HMODULE hModule,
			  [out]          LPWSTR  lpBaseName,
			  [in]           DWORD   nSize
			);
		*/
		szProcessName = (TCHAR*)calloc(MAX_PATH, sizeof(TCHAR));
		if (szProcessName == NULL) {
			_tprintf(TEXT("PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
			return nullptr;
		}

		/** Retrieves the base name of the specified module.
		  -> 디버거 개발용 함수. 다른 용도로 쓸꺼면 다른 함수 사용해야 함.
			DWORD GetModuleBaseNameA(
			  [in]           HANDLE  hProcess,
			  [in, optional] HMODULE hModule,
			  [out]          LPSTR   lpBaseName,
			  [in]           DWORD   nSize
			);
		*/
		GetModuleBaseName(hProcess, hModule, szProcessName, MAX_PATH - 1);
	}

	CloseHandle(hProcess);
	return szProcessName;
}


int wmain(int argc, wchar_t* argv[], wchar_t* envp[]){
	DWORD cProcesses, cbNeeded;
	DWORD* aProcesses = (DWORD*)calloc(16384, sizeof(DWORD));
	if (aProcesses == nullptr) {
		_tprintf(TEXT("LastError: %hs"), GetLastErrorAsString().c_str());
		return -1;
	}

	/** Retrieves the process identifier for each process object in the system.
		BOOL EnumProcesses(
		  [out] DWORD   *lpidProcess,
		  [in]  DWORD   cb,
		  [out] LPDWORD lpcbNeeded
		);
	*/
	if (!EnumProcesses(aProcesses, 16384 * sizeof(DWORD), &cbNeeded)) {
		_tprintf(TEXT("LastError: %hs"), GetLastErrorAsString().c_str());
		return -1;
	}

	// cProcesses: count Process, cb: count bytes
	cProcesses = cbNeeded / sizeof(DWORD);

	for (int i = 0; i < (size_t)cProcesses; i++) {
		if (aProcesses[i] != 0) {
			TCHAR* processName = GetProcessNameFromID(aProcesses[i]);
			if (processName != nullptr) {
				_tprintf(TEXT("PID %u\tName: %s\n"), aProcesses[i], processName);
			}
		}
	}

	return 0;
}