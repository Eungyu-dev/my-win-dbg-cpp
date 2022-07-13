#define PSAPI_VERSION 1

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>

#include <iostream>
#include <string>


const int MAX_PROCESS = 16384;
const int MAX_MODULES = 16384;


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
	// 다른 프로세스에 대해 모든 권한을 가지려면 SeDebugPrivilege 얻어야 함.
	// https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		processID
	);
	if (hProcess == NULL) {
		_tprintf(TEXT("@OpenProcess PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
		return nullptr;
	}

	HMODULE hModule;
	DWORD cbNeeded;

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
	) == 0) {
		_tprintf(TEXT("@EnumProcessModulesEx PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
		return nullptr;
	}

	/** Retrieves the base name of the specified module.
		DWORD GetModuleBaseNameW(
		  [in]           HANDLE  hProcess,
		  [in, optional] HMODULE hModule,
		  [out]          LPWSTR  lpBaseName,
		  [in]           DWORD   nSize
		);
	*/
	TCHAR* szProcessName = (TCHAR*)calloc(MAX_PATH, sizeof(TCHAR));
	if (szProcessName == NULL) {
		_tprintf(TEXT("@calloc PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
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
	if (GetModuleBaseName(hProcess, hModule, szProcessName, MAX_PATH) == 0) {
		_tprintf(TEXT("@GetModuleBaseName PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
		return nullptr;
	}

	CloseHandle(hProcess);
	return szProcessName;
}

TCHAR** GetLoadedModuleNameFromPrcoessID(DWORD processID) {
	HMODULE* hModules = (HMODULE*)calloc(MAX_MODULES, sizeof(HMODULE));
	if (hModules == NULL) {
		_tprintf(TEXT("@calloc PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
		return nullptr;
	}

	DWORD cbNeeded;
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		processID
	);
	if (hProcess == NULL) {
		_tprintf(TEXT("@OpenProcess PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
		return nullptr;
	}

	/** Retrieves a handle for each module in the specified process that meets the specified filter criteria.
		BOOL EnumProcessModulesEx(
		  [in]  HANDLE  hProcess,
		  [out] HMODULE *lphModule,
		  [in]  DWORD   cb,
		  [out] LPDWORD lpcbNeeded,
		  [in]  DWORD   dwFilterFlag
		);
	*/
	if (EnumProcessModulesEx(hProcess, hModules, MAX_MODULES * sizeof(HMODULE), &cbNeeded, LIST_MODULES_ALL) == 0) {
		_tprintf(TEXT("@EnumProcessModulesEx PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
		return nullptr;
	}

	TCHAR** aModuleName = (TCHAR**)calloc(cbNeeded / sizeof(HMODULE), sizeof(TCHAR*));
	if (aModuleName == NULL) {
		_tprintf(TEXT("@calloc PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
		return nullptr;
	}

	for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
		aModuleName[i] = (TCHAR*)calloc(MAX_PATH, sizeof(TCHAR));
		if (aModuleName[i] == NULL) {
			_tprintf(TEXT("@calloc PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
			return nullptr;
		}

		/** Retrieves the fully qualified path for the file containing the specified module.
			DWORD GetModuleFileNameExW(
			  [in]           HANDLE  hProcess,
			  [in, optional] HMODULE hModule,
			  [out]          LPWSTR  lpFilename,
			  [in]           DWORD   nSize
			);
		*/
		if (GetModuleFileNameEx(hProcess, hModules[i], aModuleName[i], MAX_PATH) == 0) {
			_tprintf(TEXT("@GetModuleFileNameEx PID %u\tLastError: %hs"), processID, GetLastErrorAsString().c_str());
			return nullptr;
		}
	}

	CloseHandle(hProcess);
	return aModuleName;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]){
	DWORD cProcesses, cModules, cbNeeded;
	DWORD* aProcesses = (DWORD*)calloc(MAX_PROCESS, sizeof(DWORD));
	if (aProcesses == nullptr) {
		_tprintf(TEXT("@calloc LastError: %hs"), GetLastErrorAsString().c_str());
		return -1;
	}

	/** Retrieves the process identifier for each process object in the system.
		BOOL EnumProcesses(
		  [out] DWORD   *lpidProcess,
		  [in]  DWORD   cb,
		  [out] LPDWORD lpcbNeeded
		);
	*/
	if (!EnumProcesses(aProcesses, MAX_PROCESS * sizeof(DWORD), &cbNeeded)) {
		_tprintf(TEXT("@EnumProcesses\tLastError: %hs"), GetLastErrorAsString().c_str());
		return -1;
	}

	// cProcesses: count Process, cb: count bytes
	cProcesses = cbNeeded / sizeof(DWORD);

	for (int i = 0; i < (size_t)cProcesses; i++) {
		if (aProcesses[i] != 0) {
			TCHAR* processName = GetProcessNameFromID(aProcesses[i]);
			if (processName == nullptr) {
				_tprintf(TEXT("@GetProcessNameFromID\tLastError: %hs"), GetLastErrorAsString().c_str());
				continue;
			}
			_tprintf(TEXT("PID %u\tProcess Name: %s\n"), aProcesses[i], processName);

			TCHAR** aModuleName = GetLoadedModuleNameFromPrcoessID(aProcesses[i]);
			if (aModuleName == nullptr) {
				_tprintf(TEXT("@GetModuleNameFromPrcoessID LastError: %hs"), GetLastErrorAsString().c_str());
				return -1;
			}
			cModules = (DWORD)_msize(aModuleName) / sizeof(TCHAR*);

			for (int j = 0; j < (size_t)cModules; j++) {
				_tprintf(TEXT("\t\tDLL: %s\n"), aModuleName[j]);
				free(aModuleName[j]);
			}
			free(aModuleName);
		}
		_tprintf(TEXT("\n"));
	}
	free(aProcesses);

	return 0;
}