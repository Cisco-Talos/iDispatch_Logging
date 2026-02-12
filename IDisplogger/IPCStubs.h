// IPCStubs.h - IPC Communication using WM_COPYDATA to VB6 debug window
#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <strsafe.h>

// Global variables for IPC
static bool Warned = false;
static HWND hServer = 0;
static DWORD myPID = GetCurrentProcessId();

// Registry-based window finding 
HWND regFindWindow() {
    HKEY hKey;
    HWND hwnd = 0;
    char szValue[256] = {0};
    DWORD dwSize = sizeof(szValue)-1;
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\VB and VBA Program Settings\\DebugPrint\\Windows", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "hwnd", NULL, NULL, (LPBYTE)szValue, &dwSize) == ERROR_SUCCESS) {
            hwnd = (HWND)atoi(szValue);
            if (!IsWindow(hwnd)) hwnd = 0;
        }
        RegCloseKey(hKey);
    }
    return hwnd;
}

// Find the VB6 debug window
void FindVBWindow() {
    const char* vbIDEClassName = "ThunderFormDC";
    const char* vbEXEClassName = "ThunderRT6FormDC";
    const char* vbEXEClassName2 = "ThunderRT6Form";
    const char* vbWindowCaption = "Persistent Debug Print Window";
    
    hServer = FindWindowA(vbIDEClassName, vbWindowCaption);
    if (hServer == 0) hServer = FindWindowA(vbEXEClassName, vbWindowCaption);
    if (hServer == 0) hServer = FindWindowA(vbEXEClassName2, vbWindowCaption);
    if (hServer == 0) hServer = regFindWindow(); // if IDE is running as admin
    
    if (hServer == 0) {
        if (!Warned) {
            // Could not find window - silent fail or use OutputDebugString as fallback
            Warned = true;
        }
    } else {
        if (!Warned) {
            // First time we found the window
            Warned = true;
        }
    }
}

// Send message to VB6 debug window
int msg(const char* Buffer) {
    if (!IsWindow(hServer)) hServer = 0;
    if (hServer == 0) FindVBWindow();
    
    if (hServer == 0) {
        // Fallback to OutputDebugString if no VB window found
        OutputDebugStringA(Buffer);
        return 0;
    }
    
    // Prepare message with PID and TID prefix
    char msgbuf[0x1000];
    _snprintf_s(msgbuf, sizeof(msgbuf), _TRUNCATE, "[%x:%x] %s", myPID, GetCurrentThreadId(), Buffer);
    
    COPYDATASTRUCT cpStructData;
    memset(&cpStructData, 0, sizeof(COPYDATASTRUCT));
    cpStructData.dwData = 3;
    cpStructData.cbData = strlen(msgbuf);
    cpStructData.lpData = (void*)msgbuf;
    
    int ret = SendMessage(hServer, WM_COPYDATA, 0, (LPARAM)&cpStructData);
    return ret; // log UI can send us a response msg to trigger special reaction
}

// Formatted message function
void msgf(const char* format, ...) {
    DWORD dwErr = GetLastError();
    
    if (format) {
        char buf[1024];
        va_list args;
        va_start(args, format);
        try {
            _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, format, args);
            msg(buf);
        } catch(...) {}
        va_end(args);
    }
    
    SetLastError(dwErr);
}

// Wide string debug output
static void DBGW(const wchar_t* fmt, ...) {
    wchar_t wbuf[1024];
    va_list ap;
    va_start(ap, fmt);
    StringCchVPrintfW(wbuf, _countof(wbuf), fmt, ap);
    va_end(ap);
    
    // Convert to UTF-8 for msgf
    char buf[2048];
    int n = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, sizeof(buf), nullptr, nullptr);
    if (n <= 0) buf[0] = 0;
    msgf("%s", buf);
}

// ANSI string debug output
static void DBGA(const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    msgf("%s", buf);
}

// Wrapper for SendIPCMessage to match the interface used in main DLL
inline BOOL SendIPCMessage(const char* message) {
    msg(message);
    return TRUE;
}
