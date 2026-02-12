//Copyright: Cisco Talos 2025
//License:   Apache 2.0
//Author:    David Zimmer <dzzie@yahoo.com>

//Command line injector for IDispLogger.dll - see /help for details

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <conio.h>

HANDLE hCon = 0;
HANDLE hConOut = 0;


// Check if VB debug window exists
HWND FindDebugWindow() {
	const char* vbIDEClassName = "ThunderFormDC";
	const char* vbEXEClassName = "ThunderRT6FormDC";
	const char* vbEXEClassName2 = "ThunderRT6Form";
	const char* vbWindowCaption = "Persistent Debug Print Window";

	HWND hWnd = FindWindowA(vbIDEClassName, vbWindowCaption);
	if (!hWnd) hWnd = FindWindowA(vbEXEClassName, vbWindowCaption);
	if (!hWnd) hWnd = FindWindowA(vbEXEClassName2, vbWindowCaption);

	return hWnd;
}

// Start debug window if not running
void EnsureDebugWindow() {
	if (FindDebugWindow()) {
		printf("[+] Debug window already running\n");
		return;
	}

	printf("[*] Starting debug window...\n");

	// Try current directory first
	if (GetFileAttributesA("dbgwindow.exe") != INVALID_FILE_ATTRIBUTES) {
		ShellExecuteA(NULL, "open", "dbgwindow.exe", NULL, NULL, SW_SHOW);
	}
	// Try parent directory
	else if (GetFileAttributesA("..\\dbgwindow.exe") != INVALID_FILE_ATTRIBUTES) {
		ShellExecuteA(NULL, "open", "..\\dbgwindow.exe", NULL, "..", SW_SHOW);
	}
	else {
		printf("[!] Warning: dbgwindow.exe not found, logging will use OutputDebugString\n");
		return;
	}

	// Wait a moment for window to start
	Sleep(1000);

	if (FindDebugWindow()) {
		printf("[+] Debug window started successfully\n");
	}
	else {
		printf("[!] Debug window may not have started properly\n");
	}
}

// Find process by name
DWORD FindProcess(const char* name) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_stricmp(pe32.szExeFile, name) == 0) {
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	CloseHandle(hSnapshot);
	return 0;
}

/* Inject DLL into process
BOOL InjectDll(DWORD pid, const char* dllPath, HANDLE* phProcess=0) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) {
		printf("[-] Failed to open process %d: %d\n", pid, GetLastError());
		return FALSE;
	}

	SIZE_T pathLen = strlen(dllPath) + 1;
	LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, pathLen,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemotePath) {
		printf("[-] VirtualAllocEx failed: %d\n", GetLastError());
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, pathLen, NULL)) {
		printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
		VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pLoadLibrary,
		pRemotePath, 0, NULL);
	if (!hThread) {
		printf("[-] CreateRemoteThread failed: %d\n", GetLastError());
		VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	DWORD exitCode;
	GetExitCodeThread(hThread, &exitCode);

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
	
	// Return the handle if requested
	if (phProcess) {
		*phProcess =hProcess;
	}
	else {
		CloseHandle(hProcess);
	}

	return exitCode != 0;
}*/

// Create process with DLL injected
BOOL CreateAndInject(const char* cmdLine, const char* dll, HANDLE* phProcess=0, HANDLE* phThread=0) {
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };

	// Make a writable copy of command line
	char cmdLineCopy[MAX_PATH * 2];
	strncpy_s(cmdLineCopy, sizeof(cmdLineCopy), cmdLine, _TRUNCATE);

	printf("[*] Creating process: %s\n", cmdLineCopy);

	if (!CreateProcessA(NULL, cmdLineCopy, NULL, NULL, FALSE,
		CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("[-] CreateProcess failed: %d\n", GetLastError());
		return FALSE;
	}

	printf("[+] Process created (PID: %d)\n", pi.dwProcessId);

	// Inject DLL
	char fullPath[MAX_PATH];
	GetFullPathNameA(dll, MAX_PATH, fullPath, NULL);

	SIZE_T pathLen = strlen(fullPath) + 1;
	LPVOID pRemotePath = VirtualAllocEx(pi.hProcess, NULL, pathLen,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	WriteProcessMemory(pi.hProcess, pRemotePath, fullPath, pathLen, NULL);

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pLoadLibrary,
		pRemotePath, 0, NULL);

	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		printf("[+] DLL injected successfully\n");
	}

	VirtualFreeEx(pi.hProcess, pRemotePath, 0, MEM_RELEASE);

	if (phThread) {
		*phThread = pi.hThread;  // caller will resume & close
	}
	else {
		ResumeThread(pi.hThread);
		CloseHandle(pi.hThread);
	}

	// Return the handle if requested
	if (phProcess) {
		*phProcess = pi.hProcess;
	}
	else {
		CloseHandle(pi.hProcess);
	}

	return TRUE;
}

void PrintUsage(const char* exe) {
	printf("Usage:\n");
	printf("  %s                           - Run cscript.exe TestScript.vbs (default)\n", exe);
	printf("  %s <script.vbs|js>           - Run cscript.exe with specified script\n", exe);
	printf("  %s <exe> <args...>           - Run exe with arguments\n", exe);
	printf("\nExamples:\n");
	printf("  %s                           - Runs: cscript.exe TestScript.vbs\n", exe);
	printf("  %s malware.js                - Runs: cscript.exe malware.js\n", exe);
	printf("  %s bad.exe                   - Runs: bad.exe\n", exe);
	printf("  %s wscript.exe test.vbs      - Runs: wscript.exe test.vbs\n", exe);
	printf("  %s powershell.exe -c \"...\"   - Runs: powershell.exe -c \"...\"\n", exe);
	printf("  %s python.exe -f script.py   - Runs: python.exe -f script.py\n", exe);
}

int is_help_flag(const char* s) {
	if (!s) return 0;

	// normalize leading slashes/dashes
	if (s[0] == '/' || s[0] == '-') s++;
	else if (s[0] == '-' && s[1] == '-') s += 2; // handles --help

	// now check for variations
	if (_stricmp(s, "h") == 0) return 1;
	if (_stricmp(s, "?") == 0) return 1;
	if (_stricmp(s, "help") == 0) return 1;

	return 0;
}

int main(int argc, char* argv[]) {

	HANDLE hChildProcess = NULL;

	hCon = GetStdHandle(STD_INPUT_HANDLE);
	hConOut = GetStdHandle(STD_OUTPUT_HANDLE);
	setvbuf(stdout, NULL, _IONBF, 0); //autoflush - allows external apps to read cmdline output in realtime..

	printf("=== IDispatch Hook Injector v2 ===\n");
	printf("For use with VB6 Debug Window\n\n");
	printf("Platform: %s\n", sizeof(void*) == 8 ? "x64 (64-bit)" : "x86 (32-bit)");

	if(argc > 1 && is_help_flag(argv[1])) {
		PrintUsage(argv[0]);
		return 0;
	}

	// Ensure debug window is running
	EnsureDebugWindow();
	printf("\n");

	// Find DLL
	const char* dllName = (sizeof(void*) == 8) ? "iDispLogger64.dll" : "iDispLogger.dll";

	char dllPath[MAX_PATH];
	char parentPath[MAX_PATH];

	_snprintf_s(parentPath, MAX_PATH, _TRUNCATE, "..\\%s", dllName);

	// Check current directory first
	if (GetFileAttributesA(dllName) != INVALID_FILE_ATTRIBUTES) {
		GetFullPathNameA(dllName, MAX_PATH, dllPath, NULL);
	}
	// Check parent directory
	else if (GetFileAttributesA(parentPath) != INVALID_FILE_ATTRIBUTES) {
		GetFullPathNameA(parentPath, MAX_PATH, dllPath, NULL);
		printf("[*] Found DLL in parent directory\n");
	}
	else {
		printf("[-] %s not found in current or parent directory\n", dllName);
		return 1;
	}

	printf("[*] Using DLL: %s\n\n", dllPath);

	char cmdLine[MAX_PATH * 2];

	// Parse command line
	if (argc == 1) {
		// No args: run default TestScript.vbs
		
		if (GetFileAttributesA("tests\\TestScript.vbs") == INVALID_FILE_ATTRIBUTES) {
			printf("[-] ./tests/TestScript.vbs not found\n");
			printf("    Create TestScript.vbs or specify a script to run\n\n");
			PrintUsage(argv[0]);
			return 1;
		}
		snprintf(cmdLine, sizeof(cmdLine), "cscript.exe tests\\TestScript.vbs");
	}
	else if (argc == 2) {
		// One arg: if it's a script file, use cscript, if its an exe thats ok too no need to add dummy args
		const char* script = argv[1];

		if (strstr(script, ".exe")){

			if (GetFileAttributesA(script) == INVALID_FILE_ATTRIBUTES) {
				printf("[-] Exe file not found: %s\n", script);
				return 1;
			}
			snprintf(cmdLine, sizeof(cmdLine), "%s", script);

		}	// Check if it looks like a script file
		else if (strstr(script, ".vbs") || strstr(script, ".js") || strstr(script, ".wsf") || strstr(script, ".hta")) {

			if (GetFileAttributesA(script) == INVALID_FILE_ATTRIBUTES) {
				printf("[-] Script file not found: %s\n", script);
				return 1;
			}
			snprintf(cmdLine, sizeof(cmdLine), "cscript.exe \"%s\"", script);
		}
		else {
			// Not a script, show usage
			printf("[-] Invalid arguments\n\n");
			PrintUsage(argv[0]);
			return 1;
		}
	}
	else {
		// Multiple args: first is exe, rest are arguments
		// Build full command line
		snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", argv[1]);

		for (int i = 2; i < argc; i++) {
			strcat_s(cmdLine, sizeof(cmdLine), " ");
			// Quote args with spaces
			if (strchr(argv[i], ' ')) {
				strcat_s(cmdLine, sizeof(cmdLine), "\"");
				strcat_s(cmdLine, sizeof(cmdLine), argv[i]);
				strcat_s(cmdLine, sizeof(cmdLine), "\"");
			}
			else {
				strcat_s(cmdLine, sizeof(cmdLine), argv[i]);
			}
		}
	}

	HANDLE hThread = 0;
	if (CreateAndInject(cmdLine, dllPath, &hChildProcess, &hThread)) { 
		printf("\n[+] Process launched with hooks installed\n");
		printf("[+] Check debug window for IDispatch activity\n");
		printf("[+] Waiting for child to finish\n");
		printf("=============================================\n\n");

		//otherwise we can interleave output with child...
		ResumeThread(hThread);
		CloseHandle(hThread);

		if (hChildProcess) {
			//must use non blocking powershell can tweak out if we dont ?
			while (WaitForSingleObject(hChildProcess, 100) == WAIT_TIMEOUT) {
				MSG msg;
				while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
					TranslateMessage(&msg);
					DispatchMessage(&msg);
				}
			}
			CloseHandle(hChildProcess);
		}
	}
	else {
		printf("\n[-] Failed to launch process with hooks\n");
		return 1;
	}

	HWND consoleWnd = GetConsoleWindow();
	DWORD consolePid;
	GetWindowThreadProcessId(consoleWnd, &consolePid);

	if (GetCurrentProcessId() == consolePid) {
		// We own the console (double-clicked)
		printf("\n\n=============================================\n");
		printf("Complete\nPress any key to Exit...\n");
		_getch();
	}

	return 0;
}