// IDispatch Late-Bound COM Test
// Works as both x86 and x64 — use VS platform dropdown to switch.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ole2.h>
#include <oleauto.h>
#include <stdio.h>
#include <conio.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Helper: invoke a method/property on an IDispatch by name
static HRESULT DispInvoke(IDispatch* pDisp, LPCOLESTR name, WORD wFlags,
	DISPPARAMS* pParams, VARIANT* pResult)
{
	DISPID dispid;
	HRESULT hr = pDisp->GetIDsOfNames(IID_NULL, (LPOLESTR*)&name,
		1, LOCALE_USER_DEFAULT, &dispid);
	if (FAILED(hr)) {
		printf("  GetIDsOfNames failed for '%ls': 0x%08lX\n", name, hr);
		return hr;
	}

	EXCEPINFO excep = { 0 };
	UINT argErr = 0;
	hr = pDisp->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT,
		wFlags, pParams, pResult, &excep, &argErr);
	if (FAILED(hr)) {
		printf("  Invoke failed for '%ls': 0x%08lX\n", name, hr);
		if (excep.bstrDescription) {
			printf("  Exception: %ls\n", excep.bstrDescription);
			SysFreeString(excep.bstrDescription);
		}
		if (excep.bstrSource) SysFreeString(excep.bstrSource);
		if (excep.bstrHelpFile) SysFreeString(excep.bstrHelpFile);
	}
	return hr;
}

// Helper: call a method with two VARIANT args (key, value)
static HRESULT DispCallMethod2(IDispatch* pDisp, LPCOLESTR name,
	VARIANT* arg1, VARIANT* arg2, VARIANT* pResult)
{
	// DISPPARAMS args are in reverse order
	VARIANT args[2];
	args[0] = *arg2;  // second param goes first in array
	args[1] = *arg1;
	DISPPARAMS dp = { args, NULL, 2, 0 };
	return DispInvoke(pDisp, name, DISPATCH_METHOD, &dp, pResult);
}

// Helper: get a property with one VARIANT arg
static HRESULT DispGetProp1(IDispatch* pDisp, LPCOLESTR name,
	VARIANT* arg, VARIANT* pResult)
{
	DISPPARAMS dp = { arg, NULL, 1, 0 };
	return DispInvoke(pDisp, name, DISPATCH_PROPERTYGET, &dp, pResult);
}

// Helper: get a property with no args
static HRESULT DispGetProp0(IDispatch* pDisp, LPCOLESTR name, VARIANT* pResult)
{
	DISPPARAMS dp = { NULL, NULL, 0, 0 };
	return DispInvoke(pDisp, name, DISPATCH_PROPERTYGET, &dp, pResult);
}

static IDispatch* CreateDispatchObject(LPCOLESTR progId)
{
	CLSID clsid;
	HRESULT hr = CLSIDFromProgID(progId, &clsid);
	if (FAILED(hr)) {
		printf("CLSIDFromProgID('%ls') failed: 0x%08lX\n", progId, hr);
		return NULL;
	}

	IDispatch* pDisp = NULL;
	hr = CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
		IID_IDispatch, (void**)&pDisp);
	if (FAILED(hr)) {
		printf("CoCreateInstance failed: 0x%08lX\n", hr);
		return NULL;
	}
	return pDisp;
}

// Prompt user to manually LoadLibrary the IDispatch logger DLL.
// Searches current dir and parent dir. Comment out the call to disable.
static HMODULE ManualLoadLogger(void)
{
	char fullPath[MAX_PATH];
	HMODULE hMod = NULL;
	const char* dllName = (sizeof(void*) == 8) ? "idispLogger64.dll" : "idispLogger.dll";
	const char* searchPaths[] = {
		".\\",
		"..\\",
	};

	if (GetModuleHandleA(dllName) != NULL) {
		printf("Logger dll already loaded...\n");
		return NULL; // not our responsibility to free
	}

	printf("Manually load %s? (y/n): ", dllName);
	int ch = _getch();
	printf("%c\n", ch);

	if (ch != 'y' && ch != 'Y') {
		printf("Skipping manual logger load.\n\n");
		return NULL;
	}

	for (int i = 0; i < _countof(searchPaths); i++) {
		_snprintf_s(fullPath, MAX_PATH, _TRUNCATE, "%s%s", searchPaths[i], dllName);

		DWORD attr = GetFileAttributesA(fullPath);
		if (attr != INVALID_FILE_ATTRIBUTES) {
			printf("Found: %s\n", fullPath);
			hMod = LoadLibraryA(fullPath);
			if (hMod) {
				printf("Loaded %s at %p\n\n", dllName, (void*)hMod);
				return hMod;
			}
			else {
				printf("LoadLibrary failed: %lu\n", GetLastError());
			}
		}
	}

	printf("Could not find %s in ./ or ../\n\n", dllName);
	return NULL;
}

int main(void)
{
	printf("=== IDispatch Late-Bound COM Test ===\n");
	printf("Platform: %s\n", sizeof(void*) == 8 ? "x64 (64-bit)" : "x86 (32-bit)");
	printf("sizeof(void*)    = %zu\n", sizeof(void*));
	printf("sizeof(VARIANT)  = %zu\n", sizeof(VARIANT));
	printf("sizeof(DISPID)   = %zu\n", sizeof(DISPID));
	printf("sizeof(BSTR)     = %zu\n", sizeof(BSTR));
	printf("\n");

	// Comment out the next line to disable manual DLL loading (useful for vs debugging)
	HMODULE hLogger = ManualLoadLogger();

	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		printf("CoInitializeEx failed: 0x%08lX\n", hr);
		return 1;
	}

	// --- Create Scripting.Dictionary via IDispatch ---
	printf("[1] Creating Scripting.Dictionary...\n");
	IDispatch* pDict = CreateDispatchObject(L"Scripting.Dictionary");
	if (!pDict) {
		printf("FAILED to create Scripting.Dictionary.\n");
		CoUninitialize();
		return 1;
	}
	printf("    OK. IDispatch* = %p\n\n", (void*)pDict);

	// --- Add some key/value pairs ---
	printf("[2] Adding entries via .Add(key, value)...\n");
	struct { LPCWSTR key; LPCWSTR value; } entries[] = {
		{ L"Platform", sizeof(void*) == 8 ? L"64-bit" : L"32-bit" },
		{ L"Language", L"C++" },
		{ L"Binding",  L"Late (IDispatch)" },
	};

	for (int i = 0; i < _countof(entries); i++) {
		VARIANT vKey, vVal;
		VariantInit(&vKey);
		VariantInit(&vVal);
		vKey.vt = VT_BSTR;
		vKey.bstrVal = SysAllocString(entries[i].key);
		vVal.vt = VT_BSTR;
		vVal.bstrVal = SysAllocString(entries[i].value);

		hr = DispCallMethod2(pDict, L"Add", &vKey, &vVal, NULL);
		printf("    Add(\"%ls\", \"%ls\") -> 0x%08lX %s\n",
			entries[i].key, entries[i].value, hr, SUCCEEDED(hr) ? "OK" : "FAIL");

		VariantClear(&vKey);
		VariantClear(&vVal);
	}
	printf("\n");

	// --- Read back .Count ---
	printf("[3] Reading .Count property...\n");
	{
		VARIANT vCount;
		VariantInit(&vCount);
		hr = DispGetProp0(pDict, L"Count", &vCount);
		if (SUCCEEDED(hr)) {
			VariantChangeType(&vCount, &vCount, 0, VT_I4);
			printf("    Count = %ld\n", vCount.lVal);
		}
		VariantClear(&vCount);
	}
	printf("\n");

	// --- Read back values by key using .Item(key) ---
	printf("[4] Reading values via .Item(key)...\n");
	for (int i = 0; i < _countof(entries); i++) {
		VARIANT vKey, vResult;
		VariantInit(&vKey);
		VariantInit(&vResult);
		vKey.vt = VT_BSTR;
		vKey.bstrVal = SysAllocString(entries[i].key);

		hr = DispGetProp1(pDict, L"Item", &vKey, &vResult);
		if (SUCCEEDED(hr) && vResult.vt == VT_BSTR) {
			printf("    Item(\"%ls\") = \"%ls\"\n", entries[i].key, vResult.bstrVal);
		}
		else {
			printf("    Item(\"%ls\") -> FAILED or unexpected type (vt=%d)\n",
				entries[i].key, vResult.vt);
		}
		VariantClear(&vKey);
		VariantClear(&vResult);
	}
	printf("\n");

	// --- Check .Exists(key) for a missing key ---
	printf("[5] Checking .Exists() for missing key...\n");
	{
		VARIANT vKey, vResult;
		VariantInit(&vKey);
		VariantInit(&vResult);
		vKey.vt = VT_BSTR;
		vKey.bstrVal = SysAllocString(L"NonExistent");

		DISPPARAMS dp = { &vKey, NULL, 1, 0 };
		hr = DispInvoke(pDict, L"Exists", DISPATCH_METHOD, &dp, &vResult);
		if (SUCCEEDED(hr)) {
			printf("    Exists(\"NonExistent\") = %s\n",
				(vResult.vt == VT_BOOL && vResult.boolVal) ? "True" : "False");
		}
		VariantClear(&vKey);
		VariantClear(&vResult);
	}
	printf("\n");

	// --- Enumerate keys via .Keys() ---
	printf("[6] Enumerating via .Keys()...\n");
	{
		VARIANT vKeys;
		VariantInit(&vKeys);
		DISPPARAMS dpEmpty = { NULL, NULL, 0, 0 };
		hr = DispInvoke(pDict, L"Keys", DISPATCH_METHOD, &dpEmpty, &vKeys);
		if (SUCCEEDED(hr) && (vKeys.vt & VT_ARRAY)) {
			SAFEARRAY* psa = (vKeys.vt & VT_BYREF) ? *vKeys.pparray : vKeys.parray;
			LONG lb, ub;
			SafeArrayGetLBound(psa, 1, &lb);
			SafeArrayGetUBound(psa, 1, &ub);
			for (LONG j = lb; j <= ub; j++) {
				VARIANT vElem;
				VariantInit(&vElem);
				SafeArrayGetElement(psa, &j, &vElem);
				if (vElem.vt == VT_BSTR) {
					printf("    Key[%ld] = \"%ls\"\n", j, vElem.bstrVal);
				}
				VariantClear(&vElem);
			}
		}
		VariantClear(&vKeys);
	}
	printf("\n");

	// --- Cleanup ---
	printf("[7] Releasing IDispatch...\n");
	ULONG refCount = pDict->Release();
	printf("    Release() returned refcount = %lu\n", refCount);

	CoUninitialize();
	printf("\n=== Done. ===\n");
	return 0;
}