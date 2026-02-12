#pragma once
// ComDefs.h - COM interface definitions for WSH hooking
#pragma once

#include <windows.h>
#include <objbase.h>

// IDispatchEx interface ID (for scripting engines)
#ifndef __IDispatchEx_INTERFACE_DEFINED__
const IID IID_IDispatchEx = { 0xa6ef9860, 0xc720, 0x11d0, {0x93, 0x37, 0x00, 0xa0, 0xc9, 0x0d, 0xca, 0xa9} };
#endif

// IActiveScript interface ID
#ifndef __IActiveScript_INTERFACE_DEFINED__
const IID IID_IActiveScript = { 0xbb1a2ae1, 0xa4f9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64} };
#endif

// IActiveScriptParse interface ID
#ifndef __IActiveScriptParse_INTERFACE_DEFINED__
const IID IID_IActiveScriptParse = { 0xbb1a2ae2, 0xa4f9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64} };
#endif

// Common scripting CLSIDs
const CLSID CLSID_VBScript = { 0xb54f3741, 0x5b07, 0x11cf, {0xa4, 0xb0, 0x00, 0xaa, 0x00, 0x4a, 0x55, 0xe8} };
const CLSID CLSID_JScript = { 0xf414c260, 0x6ac0, 0x11cf, {0xb6, 0xd1, 0x00, 0xaa, 0x00, 0xbb, 0xbb, 0x58} };

// Common Scripting CLSIDs that malware uses
const CLSID CLSID_FileSystemObject = { 0x0d43fe01, 0xf093, 0x11cf, {0x89, 0x40, 0x00, 0xa0, 0xc9, 0x05, 0x42, 0x28} };
const CLSID CLSID_WshShell = { 0x72c24dd5, 0xd70a, 0x438b, {0x8a, 0x42, 0x98, 0x42, 0x4b, 0x88, 0xaf, 0xb8} };
const CLSID CLSID_WshNetwork = { 0x093ff999, 0x1ea0, 0x4079, {0x9c, 0xc2, 0xcc, 0x86, 0xe9, 0xdc, 0xbf, 0x67} };
const CLSID CLSID_XMLHTTPRequest = { 0xf6d90f11, 0x9c73, 0x11d3, {0xb3, 0x2e, 0x00, 0xc0, 0x4f, 0x99, 0x0b, 0xb4} };

// Helper macro for GUID comparison if not defined
#ifndef IsEqualIID
#define IsEqualIID(riid1, riid2) (memcmp(&(riid1), &(riid2), sizeof(IID)) == 0)
#endif

#ifndef IsEqualCLSID
#define IsEqualCLSID(rclsid1, rclsid2) (memcmp(&(rclsid1), &(rclsid2), sizeof(CLSID)) == 0)
#endif

// Helper function to get CLSID name for logging
inline const char* GetKnownCLSIDName(REFCLSID rclsid) {
	if (IsEqualCLSID(rclsid, CLSID_FileSystemObject)) return "FileSystemObject";
	if (IsEqualCLSID(rclsid, CLSID_WshShell)) return "WScript.Shell";
	if (IsEqualCLSID(rclsid, CLSID_WshNetwork)) return "WScript.Network";
	if (IsEqualCLSID(rclsid, CLSID_XMLHTTPRequest)) return "XMLHTTP";
	if (IsEqualCLSID(rclsid, CLSID_VBScript)) return "VBScript";
	if (IsEqualCLSID(rclsid, CLSID_JScript)) return "JScript";
	return NULL;
}

// Helper function to get IID name for logging
inline const char* GetKnownIIDName(REFIID riid) {
	if (IsEqualIID(riid, IID_IUnknown)) return "IUnknown";
	if (IsEqualIID(riid, IID_IDispatch)) return "IDispatch";
	if (IsEqualIID(riid, IID_IDispatchEx)) return "IDispatchEx";
	if (IsEqualIID(riid, IID_IActiveScript)) return "IActiveScript";
	if (IsEqualIID(riid, IID_IActiveScriptParse)) return "IActiveScriptParse";
	return NULL;
}