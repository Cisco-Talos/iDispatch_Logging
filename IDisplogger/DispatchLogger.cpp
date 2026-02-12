// Demo IDispatch logging proxy for malware analysis
// Copyright: Cisco Talos 2025
// License:   Apache License 2.0
// Author:    David Zimmer <dzzie@yahoo.com> 

//NTHookEngine 
//Copyright: Daniel Pistelli <ntcore@gmail.com>
//License:   Public Domain
//Site:      http://www.ntcore.com/files/nthookengine.htm

//diStorm 3.5 
//Copyright(C) 2003 - 2021 Gil Dabah <distorm at gmail dot com>
//Licensed:  BSD license
//Site:      https://github.com/gdabah/distorm

#define _CRT_SECURE_NO_WARNINGS 

#include <windows.h>
#include <oleauto.h>
#include <stdio.h>
#include <stdarg.h>
#include <strsafe.h>
#include <map>
#include <string>
#include "./3rd_Party/NtHookEngine.h"

// Define IDispatchEx if not defined
#ifndef __IDispatchEx_INTERFACE_DEFINED__
const IID IID_IDispatchEx = { 0xa6ef9860, 0xc720, 0x11d0, {0x93, 0x37, 0x00, 0xa0, 0xc9, 0x0d, 0xca, 0xa9} };
#endif

// IPC Debug messaging using VB6 window
bool Warned = false;
HWND hServer = 0;
DWORD myPID = GetCurrentProcessId();

// Registry-based window finding (for elevated IDE)
HWND regFindWindow(void) {

	const char* baseKey = "Software\\VB and VBA Program Settings\\dbgWindow\\settings";
	char tmp[50] = { 0 };
	unsigned long l = sizeof(tmp)-1;
	HWND ret = 0;
	HKEY h;

	//printf("regFindWindow triggered\n");

	RegOpenKeyExA(HKEY_CURRENT_USER, baseKey, 0, KEY_READ, &h);
	RegQueryValueExA(h, "hwnd", 0, 0, (unsigned char*)tmp, &l);
	RegCloseKey(h);

	ret = (HWND)atoi(tmp);
	if (!IsWindow(ret)) ret = 0;
	return ret;
}

// Find VB6 debug window
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

			Warned = true;
		}
	}
	else {
		if (!Warned) {
			Warned = true;
		}
	}
}

// Send message to VB6 debug window
int msg(const char* Buffer, int raw = 0) {
	if (!IsWindow(hServer)) hServer = 0;
	if (hServer == 0) FindVBWindow();

	if (hServer == 0) {
		// Fallback to OutputDebugString if no VB window found
		OutputDebugStringA(Buffer);
		return 0;
	}

	// Prepare message with PID and TID prefix
	char msgbuf[0x1000];
	if (raw)
		_snprintf_s(msgbuf, sizeof(msgbuf), _TRUNCATE, "%s", Buffer);
	else
		_snprintf_s(msgbuf, sizeof(msgbuf), _TRUNCATE, "[%x:%x] %s", myPID, GetCurrentThreadId(), Buffer);

	COPYDATASTRUCT cpStructData;
	memset(&cpStructData, 0, sizeof(COPYDATASTRUCT));
	cpStructData.dwData = 3;
	cpStructData.cbData = strlen(msgbuf);
	cpStructData.lpData = (void*)msgbuf;

	int ret = SendMessage(hServer, WM_COPYDATA, 0, (LPARAM)&cpStructData);
	return ret;
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
		}
		catch (...) {}
		va_end(args);
	}

	SetLastError(dwErr);
}

// Use msgf as our debug function
#define SendDebug msgf

// Function pointer for original CoCreateInstance
typedef HRESULT(WINAPI* pCoCreateInstance)(
	REFCLSID rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD dwClsContext,
	REFIID riid,
	LPVOID* ppv
	);

pCoCreateInstance g_pOrigCoCreateInstance = NULL;

// Forward declarations
class DispatchProxy;
IDispatch* WrapDispatch(IDispatch* pOriginal, const char* objectName);

// Global tracking
std::map<IDispatch*, DispatchProxy*> g_ProxyMap;
CRITICAL_SECTION g_ProxyCS;
DWORD g_ProxyCounter = 0;

// Helper to convert VARIANT to string for logging
std::string VariantToString(VARIANT* pVar) {
	if (!pVar) return "NULL";

	char buf[512];
	switch (pVar->vt) {
	case VT_EMPTY: return "Empty";
	case VT_NULL: return "Null";
	case VT_I2: sprintf_s(buf, "%d", pVar->iVal); return buf;
	case VT_I4: sprintf_s(buf, "%d", pVar->lVal); return buf;
	case VT_R4: sprintf_s(buf, "%f", pVar->fltVal); return buf;
	case VT_R8: sprintf_s(buf, "%lf", pVar->dblVal); return buf;
	case VT_BSTR:
		if (pVar->bstrVal) {
			WideCharToMultiByte(CP_ACP, 0, pVar->bstrVal, -1, buf, sizeof(buf), NULL, NULL);
			return std::string("\"") + buf + "\"";
		}
		return "\"\"";
	case VT_DISPATCH:
		sprintf_s(buf, "IDispatch:0x%p", pVar->pdispVal);
		return buf;
	case VT_BOOL: return pVar->boolVal ? "True" : "False";
	case VT_VARIANT:
		if (pVar->pvarVal) return VariantToString(pVar->pvarVal);
		return "Variant:NULL";
	case VT_UNKNOWN:
		sprintf_s(buf, "IUnknown:0x%p", pVar->punkVal);
		return buf;
	case VT_I1: sprintf_s(buf, "%d", pVar->cVal); return buf;
	case VT_UI1: sprintf_s(buf, "%u", pVar->bVal); return buf;
	case VT_UI2: sprintf_s(buf, "%u", pVar->uiVal); return buf;
	case VT_UI4: sprintf_s(buf, "%u", pVar->ulVal); return buf;
	case VT_INT: sprintf_s(buf, "%d", pVar->intVal); return buf;
	case VT_UINT: sprintf_s(buf, "%u", pVar->uintVal); return buf;
	default:
		if (pVar->vt & VT_ARRAY) {
			sprintf_s(buf, "Array(VT=0x%x)", pVar->vt);
			return buf;
		}
		if (pVar->vt & VT_BYREF) {
			sprintf_s(buf, "ByRef(VT=0x%x)", pVar->vt);
			return buf;
		}
		sprintf_s(buf, "Unknown(VT=0x%x)", pVar->vt);
		return buf;
	}
}

// IEnumVARIANT Proxy - wraps enumerators to intercept items as they're enumerated
class EnumVARIANTProxy : public IEnumVARIANT {
private:
	LONG m_refCount;
	IEnumVARIANT* m_pOriginal;
	char m_enumName[256];

public:
	EnumVARIANTProxy(IEnumVARIANT* pOriginal, const char* name)
		: m_refCount(1), m_pOriginal(pOriginal) {
		strncpy_s(m_enumName, name ? name : "Unknown", sizeof(m_enumName) - 1);

		if (m_pOriginal) {
			m_pOriginal->AddRef();
		}

		SendDebug("[ENUM] Created enumerator proxy for '%s' (Original: 0x%p)", m_enumName, m_pOriginal);
	}

	virtual ~EnumVARIANTProxy() {
		SendDebug("[ENUM] Destroying enumerator proxy for '%s'", m_enumName);
		if (m_pOriginal) {
			m_pOriginal->Release();
			m_pOriginal = NULL;
		}
	}

	// IUnknown methods
	STDMETHOD(QueryInterface)(REFIID riid, void** ppv) {
		if (!ppv) return E_POINTER;

		if (riid == IID_IUnknown || riid == IID_IEnumVARIANT) {
			*ppv = static_cast<IEnumVARIANT*>(this);
			AddRef();
			return S_OK;
		}

		// Pass through to original
		if (m_pOriginal) {
			return m_pOriginal->QueryInterface(riid, ppv);
		}

		*ppv = NULL;
		return E_NOINTERFACE;
	}

	STDMETHOD_(ULONG, AddRef)() {
		return InterlockedIncrement(&m_refCount);
	}

	STDMETHOD_(ULONG, Release)() {
		LONG count = InterlockedDecrement(&m_refCount);
		if (count == 0) {
			delete this;
			return 0;
		}
		return count;
	}

	// IEnumVARIANT methods
	STDMETHOD(Next)(ULONG celt, VARIANT* rgVar, ULONG* pCeltFetched) {
		if (!m_pOriginal) return E_UNEXPECTED;

		HRESULT hr = m_pOriginal->Next(celt, rgVar, pCeltFetched);

		if (SUCCEEDED(hr) && rgVar) {
			ULONG fetched = pCeltFetched ? *pCeltFetched : celt;

			SendDebug("[ENUM] >>> Next: Fetched %d item(s) from '%s'", fetched, m_enumName);

			// Wrap each returned item if it's IDispatch or IUnknown that supports IDispatch
			for (ULONG i = 0; i < fetched; i++) {
				VARIANT* pVar = &rgVar[i];

				if (pVar->vt == VT_DISPATCH && pVar->pdispVal) {
					IDispatch* pOrigDispatch = pVar->pdispVal;

					char itemName[256];
					sprintf_s(itemName, "%s[item]", m_enumName);

					IDispatch* pProxy = WrapDispatch(pOrigDispatch, itemName);
					if (pProxy) {
						pVar->pdispVal = pProxy;
						pOrigDispatch->Release();
						SendDebug("[ENUM] !!! Wrapped enumerated IDispatch item #%d", i);
					}
				}
				else if (pVar->vt == VT_UNKNOWN && pVar->punkVal) {
					IUnknown* pUnk = pVar->punkVal;
					IDispatch* pDisp = NULL;

					HRESULT hrQI = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
					if (SUCCEEDED(hrQI) && pDisp) {
						SendDebug("[ENUM] !!! Enumerated IUnknown supports IDispatch - wrapping item #%d", i);

						char itemName[256];
						sprintf_s(itemName, "%s[item]", m_enumName);

						IDispatch* pProxy = WrapDispatch(pDisp, itemName);
						if (pProxy) {
							pVar->vt = VT_DISPATCH;
							pVar->pdispVal = pProxy;
							pUnk->Release();
							SendDebug("[ENUM] !!! Replaced IUnknown with IDispatch proxy for item #%d", i);
						}
						pDisp->Release();
					}
				}
			}
		}

		return hr;
	}

	STDMETHOD(Skip)(ULONG celt) {
		if (m_pOriginal) {
			return m_pOriginal->Skip(celt);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(Reset)() {
		if (m_pOriginal) {
			return m_pOriginal->Reset();
		}
		return E_NOTIMPL;
	}

	STDMETHOD(Clone)(IEnumVARIANT** ppEnum) {
		if (!m_pOriginal || !ppEnum) return E_NOTIMPL;

		IEnumVARIANT* pNewEnum = NULL;
		HRESULT hr = m_pOriginal->Clone(&pNewEnum);
		if (SUCCEEDED(hr) && pNewEnum) {
			*ppEnum = new EnumVARIANTProxy(pNewEnum, m_enumName);
			pNewEnum->Release(); // Proxy holds its own reference
		}
		return hr;
	}
};

// Dynamic IDispatch Proxy Implementation
class DispatchProxy : public IDispatch {
private:
	LONG m_refCount;
	IDispatch* m_pOriginal;
	char m_objectName[256];
	DWORD m_proxyId;

public:
	DispatchProxy(IDispatch* pOriginal, const char* name)
		: m_refCount(1), m_pOriginal(pOriginal) {
		m_proxyId = InterlockedIncrement((LONG*)&g_ProxyCounter);
		strncpy_s(m_objectName, name ? name : "Unknown", sizeof(m_objectName) - 1);

		if (m_pOriginal) {
			m_pOriginal->AddRef();
		}

		SendDebug("[PROXY] Created proxy #%d for %s (Original: 0x%p)",
			m_proxyId, m_objectName, m_pOriginal);
	}

	virtual ~DispatchProxy() {
		SendDebug("[PROXY] Destroying proxy #%d (%s)", m_proxyId, m_objectName);

		if (m_pOriginal) {
			m_pOriginal->Release();
			m_pOriginal = NULL;
		}
	}

	// IUnknown methods
	STDMETHOD(QueryInterface)(REFIID riid, void** ppv) {
		// Check for known interface names
		const char* iidName = NULL;
		if (memcmp(&riid, &IID_IUnknown, sizeof(IID)) == 0) iidName = "IUnknown";
		else if (memcmp(&riid, &IID_IDispatch, sizeof(IID)) == 0) iidName = "IDispatch";
		else if (memcmp(&riid, &IID_IDispatchEx, sizeof(IID)) == 0) iidName = "IDispatchEx";

		if (iidName) {
			SendDebug("[PROXY #%d] QueryInterface: %s for %s", m_proxyId, iidName, m_objectName);
		}
		else {
			SendDebug("[PROXY #%d] QueryInterface: %s", m_proxyId, m_objectName);
		}

		if (!ppv) return E_POINTER;

		// Support IDispatch, IDispatchEx and IUnknown
		//if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IDispatchEx) { <--crash we dont support IDispEx yet
		if (riid == IID_IUnknown || riid == IID_IDispatch) {
			*ppv = static_cast<IDispatch*>(this);
			AddRef();
			return S_OK;
		}

		// Pass through to original for other interfaces
		if (m_pOriginal) {
			HRESULT hr = m_pOriginal->QueryInterface(riid, ppv);
			SendDebug("[PROXY #%d] QueryInterface passthrough: HRESULT=0x%08X", m_proxyId, hr);
			return hr;
		}

		*ppv = NULL;
		return E_NOINTERFACE;
	}

	STDMETHOD_(ULONG, AddRef)() {
		LONG count = InterlockedIncrement(&m_refCount);
		SendDebug("[PROXY #%d] AddRef: %s -> RefCount=%d", m_proxyId, m_objectName, count);
		return count;
	}

	STDMETHOD_(ULONG, Release)() {
		LONG count = InterlockedDecrement(&m_refCount);
		SendDebug("[PROXY #%d] Release: %s -> RefCount=%d", m_proxyId, m_objectName, count);

		if (count == 0) {
			EnterCriticalSection(&g_ProxyCS);
			g_ProxyMap.erase(m_pOriginal);
			LeaveCriticalSection(&g_ProxyCS);

			delete this;
			return 0;
		}
		return count;
	}

	// IDispatch methods
	STDMETHOD(GetTypeInfoCount)(UINT* pctinfo) {
		SendDebug("[PROXY #%d] GetTypeInfoCount: %s", m_proxyId, m_objectName);

		if (!m_pOriginal) return E_UNEXPECTED;
		return m_pOriginal->GetTypeInfoCount(pctinfo);
	}

	STDMETHOD(GetTypeInfo)(UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo) {
		SendDebug("[PROXY #%d] GetTypeInfo: %s (Index=%u)", m_proxyId, m_objectName, iTInfo);

		if (!m_pOriginal) return E_UNEXPECTED;
		return m_pOriginal->GetTypeInfo(iTInfo, lcid, ppTInfo);
	}

	STDMETHOD(GetIDsOfNames)(REFIID riid, LPOLESTR* rgszNames, UINT cNames,
		LCID lcid, DISPID* rgDispId) {
		if (!m_pOriginal) return E_UNEXPECTED;

		HRESULT hr = m_pOriginal->GetIDsOfNames(riid, rgszNames, cNames, lcid, rgDispId);

		if (SUCCEEDED(hr) && cNames > 0 && rgszNames[0]) {
			char name[256];
			WideCharToMultiByte(CP_ACP, 0, rgszNames[0], -1, name, sizeof(name), NULL, NULL);
			SendDebug("[PROXY #%d] GetIDsOfNames: %s.%s -> DispID=0x%08X",
				m_proxyId, m_objectName, name, rgDispId[0]);
		}

		return hr;
	}

	STDMETHOD(Invoke)(DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags,
		DISPPARAMS* pDispParams, VARIANT* pVarResult,
		EXCEPINFO* pExcepInfo, UINT* puArgErr) {
		// Get method name if possible
		char methodName[256] = { 0 };
		ITypeInfo* pTypeInfo = NULL;
		if (SUCCEEDED(m_pOriginal->GetTypeInfo(0, lcid, &pTypeInfo))) {
			BSTR bstrName = NULL;
			if (SUCCEEDED(pTypeInfo->GetDocumentation(dispIdMember, &bstrName, NULL, NULL, NULL))) {
				WideCharToMultiByte(CP_ACP, 0, bstrName, -1, methodName, sizeof(methodName), NULL, NULL);
				SysFreeString(bstrName);
			}
			pTypeInfo->Release();
		}

		if (!methodName[0]) {
			sprintf_s(methodName, "DispID_0x%08X", dispIdMember);
		}

		// Log the call
		std::string flagStr;
		if (wFlags & DISPATCH_METHOD) flagStr += "METHOD ";
		if (wFlags & DISPATCH_PROPERTYGET) flagStr += "PROPGET ";
		if (wFlags & DISPATCH_PROPERTYPUT) flagStr += "PROPPUT ";
		if (wFlags & DISPATCH_PROPERTYPUTREF) flagStr += "PROPPUTREF ";

		SendDebug("[PROXY #%d] >>> Invoke: %s.%s (%s) ArgCount=%d",
			m_proxyId, m_objectName, methodName, flagStr.c_str(),
			pDispParams ? pDispParams->cArgs : 0);

		// Log arguments
		if (pDispParams && pDispParams->cArgs > 0) {
			for (UINT i = 0; i < pDispParams->cArgs; i++) {
				UINT argIndex = pDispParams->cArgs - 1 - i; // Args are in reverse order
				std::string argStr = VariantToString(&pDispParams->rgvarg[argIndex]);
				SendDebug("[PROXY #%d]     Arg[%d]: %s", m_proxyId, i, argStr.c_str());
			}
		}

		// Call original
		if (!m_pOriginal) return E_UNEXPECTED;

		HRESULT hr = m_pOriginal->Invoke(dispIdMember, riid, lcid, wFlags,
			pDispParams, pVarResult, pExcepInfo, puArgErr);

		// *** Log and wrap BYREF output parameters ***
		if (SUCCEEDED(hr) && pDispParams && pDispParams->cArgs > 0) {
			for (UINT i = 0; i < pDispParams->cArgs; i++) {
				UINT argIndex = pDispParams->cArgs - 1 - i; // Args are in reverse order
				VARIANT* pArg = &pDispParams->rgvarg[argIndex];

				// Check if it's a ByRef parameter
				if (pArg->vt & VT_BYREF) {
					VARIANT derefVar;
					VariantInit(&derefVar);

					// Handle different BYREF types
					VARTYPE baseType = pArg->vt & ~VT_BYREF;

					switch (baseType) {
					case VT_VARIANT:
						// ByRef to a VARIANT - need to dereference to see what's inside!
						if (pArg->pvarVal) {
							VARIANT* pInnerVar = pArg->pvarVal;

							// Check if the inner variant contains IDispatch
							if (pInnerVar->vt == VT_DISPATCH && pInnerVar->pdispVal) {
								IDispatch* pOrigDispatch = pInnerVar->pdispVal;

								char outName[256];
								sprintf_s(outName, "%s.%s[OUT:%d]", m_objectName, methodName, i);

								IDispatch* pProxy = WrapDispatch(pOrigDispatch, outName);
								if (pProxy) {
									pInnerVar->pdispVal = pProxy;
									pOrigDispatch->Release();

									SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF VARIANT->DISPATCH - WRAPPED): IDispatch:0x%p",
										m_proxyId, i, pProxy);
								}
							}
							// Check if the inner variant contains IUnknown
							else if (pInnerVar->vt == VT_UNKNOWN && pInnerVar->punkVal) {
								IUnknown* pUnk = pInnerVar->punkVal;
								IDispatch* pDisp = NULL;

								HRESULT hrQI = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
								if (SUCCEEDED(hrQI) && pDisp) {
									char outName[256];
									sprintf_s(outName, "%s.%s[OUT:%d]", m_objectName, methodName, i);

									IDispatch* pProxy = WrapDispatch(pDisp, outName);
									if (pProxy) {
										pInnerVar->vt = VT_DISPATCH;
										pInnerVar->pdispVal = pProxy;
										pUnk->Release();

										SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF VARIANT->UNKNOWN->DISPATCH - WRAPPED): IDispatch:0x%p",
											m_proxyId, i, pProxy);
									}
									pDisp->Release();
								}
								else {
									SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF VARIANT->UNKNOWN): %s",
										m_proxyId, i, VariantToString(pInnerVar).c_str());
								}
							}
							else {
								// Log whatever is in the variant
								SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF VARIANT): %s",
									m_proxyId, i, VariantToString(pInnerVar).c_str());
							}
						}
						else {
							SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF VARIANT): NULL",
								m_proxyId, i);
						}
						break;

					case VT_DISPATCH:
						// BYREF IDispatch - the most common case for output objects
						if (pArg->ppdispVal && *pArg->ppdispVal) {
							IDispatch* pOrigDispatch = *pArg->ppdispVal;

							// Build descriptive name for this output parameter
							char outName[256];
							sprintf_s(outName, "%s.%s[OUT:%d]", m_objectName, methodName, i);

							// Wrap the output IDispatch object!
							IDispatch* pProxy = WrapDispatch(pOrigDispatch, outName);
							if (pProxy) {
								// Replace the BYREF output with our proxy
								*pArg->ppdispVal = pProxy;
								pOrigDispatch->Release(); // Release original, proxy has its own ref

								derefVar.vt = VT_DISPATCH;
								derefVar.pdispVal = pProxy;
								SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF DISPATCH - WRAPPED): %s",
									m_proxyId, i, VariantToString(&derefVar).c_str());
							}
						}
						else {
							SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF DISPATCH): NULL",
								m_proxyId, i);
						}
						break;

					case VT_UNKNOWN:
						// BYREF IUnknown - might be dispatchable
						if (pArg->ppunkVal && *pArg->ppunkVal) {
							IUnknown* pUnk = *pArg->ppunkVal;

							// Try to QI for IDispatch
							IDispatch* pDisp = NULL;
							HRESULT hrQI = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
							if (SUCCEEDED(hrQI) && pDisp) {
								// It's dispatchable! Wrap it
								char outName[256];
								sprintf_s(outName, "%s.%s[OUT:%d]", m_objectName, methodName, i);

								IDispatch* pProxy = WrapDispatch(pDisp, outName);
								if (pProxy) {
									// Replace the BYREF output with our wrapped IDispatch
									pUnk->Release(); // Release the original IUnknown
									*pArg->ppunkVal = pProxy; // Replace with proxy

									derefVar.vt = VT_DISPATCH;
									derefVar.pdispVal = pProxy;
									SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF UNKNOWN->DISPATCH - WRAPPED): %s",
										m_proxyId, i, VariantToString(&derefVar).c_str());
								}
								pDisp->Release(); // Release our QI reference
							}
							else {
								// Not dispatchable, just log it
								derefVar.vt = VT_UNKNOWN;
								derefVar.punkVal = pUnk;
								SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF UNKNOWN - NOT DISPATCHABLE): %s",
									m_proxyId, i, VariantToString(&derefVar).c_str());
							}
						}
						else {
							SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF UNKNOWN): NULL",
								m_proxyId, i);
						}
						break;

					default:
						// For other BYREF types (integers, strings, etc.), just log them
						if (SUCCEEDED(VariantCopyInd(&derefVar, pArg))) {
							SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF): %s",
								m_proxyId, i, VariantToString(&derefVar).c_str());
							VariantClear(&derefVar);
						}
						else {
							SendDebug("[PROXY #%d]     OUT Arg[%d] (BYREF): <error dereferencing>",
								m_proxyId, i);
						}
						break;
					}
				}
			}
		}

		// Log result
		if (SUCCEEDED(hr)) {
			if (pVarResult && pVarResult->vt != VT_EMPTY) {
				std::string resultStr = VariantToString(pVarResult);
				SendDebug("[PROXY #%d] <<< Result: %s (HRESULT=0x%08X)",
					m_proxyId, resultStr.c_str(), hr);

				// CRITICAL: If result is IDispatch, wrap it!
				if (pVarResult->vt == VT_DISPATCH && pVarResult->pdispVal) {
					IDispatch* pOrigDispatch = pVarResult->pdispVal;

					// Build descriptive name for child object
					char childName[256];
					sprintf_s(childName, "%s.%s", m_objectName, methodName);

					IDispatch* pProxy = WrapDispatch(pOrigDispatch, childName);
					if (pProxy) {
						pVarResult->pdispVal = pProxy; // Replace with our proxy!
						pOrigDispatch->Release(); // Release original, proxy has its own ref
						SendDebug("[PROXY #%d] !!! Wrapped returned IDispatch as new proxy", m_proxyId);
					}
				}
				// ALSO wrap VT_UNKNOWN if it supports IDispatch (for enumerators and WMI objects)
				else if (pVarResult->vt == VT_UNKNOWN && pVarResult->punkVal) {
					IUnknown* pUnk = pVarResult->punkVal;

					// First try IEnumVARIANT (for _NewEnum results)
					IEnumVARIANT* pEnum = NULL;
					HRESULT hrEnum = pUnk->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);
					if (SUCCEEDED(hrEnum) && pEnum) {
						SendDebug("[PROXY #%d] !!! Returned IUnknown is IEnumVARIANT - wrapping enumerator!", m_proxyId);

						// Build descriptive name
						char enumName[256];
						sprintf_s(enumName, "%s.%s", m_objectName, methodName);

						EnumVARIANTProxy* pEnumProxy = new EnumVARIANTProxy(pEnum, enumName);
						pEnum->Release(); // Proxy holds its own reference

						// Replace with our enumerator proxy
						pVarResult->punkVal = pEnumProxy;
						pUnk->Release(); // Release original
						SendDebug("[PROXY #%d] !!! Replaced with EnumVARIANT proxy", m_proxyId);
					}
					else {
						// Try IDispatch
						IDispatch* pDisp = NULL;
						HRESULT hrQI = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
						if (SUCCEEDED(hrQI) && pDisp) {
							SendDebug("[PROXY #%d] !!! Returned IUnknown supports IDispatch - wrapping!", m_proxyId);

							// Build descriptive name
							char childName[256];
							sprintf_s(childName, "%s.%s", m_objectName, methodName);

							IDispatch* pProxy = WrapDispatch(pDisp, childName);
							if (pProxy) {
								// Change variant type to VT_DISPATCH and replace with proxy
								pVarResult->vt = VT_DISPATCH;
								pVarResult->pdispVal = pProxy;
								pUnk->Release(); // Release original IUnknown
								SendDebug("[PROXY #%d] !!! Replaced IUnknown with IDispatch proxy", m_proxyId);
							}
							pDisp->Release(); // Release the QI result
						}
					}
				}
			}
			else {
				SendDebug("[PROXY #%d] <<< Result: (void) HRESULT=0x%08X", m_proxyId, hr);
			}
		}
		else {
			SendDebug("[PROXY #%d] <<< FAILED: HRESULT=0x%08X", m_proxyId, hr);
			if (pExcepInfo && pExcepInfo->bstrDescription) {
				char errDesc[512];
				WideCharToMultiByte(CP_ACP, 0, pExcepInfo->bstrDescription, -1,
					errDesc, sizeof(errDesc), NULL, NULL);
				SendDebug("[PROXY #%d]     Error: %s", m_proxyId, errDesc);
			}
		}

		return hr;
	}
};


// ClassFactory wrapper to intercept CreateInstance calls
class ClassFactoryProxy : public IClassFactory {
private:
	IClassFactory* m_pOriginal;
	char m_clsidName[256];
	LONG m_refCount;

public:
	ClassFactoryProxy(IClassFactory* pOrig, const char* clsidName)
		: m_pOriginal(pOrig), m_refCount(1) {
		strncpy_s(m_clsidName, clsidName, sizeof(m_clsidName) - 1);
		if (m_pOriginal) m_pOriginal->AddRef();
		SendDebug("[FACTORY] Created factory proxy for %s", m_clsidName);
	}

	~ClassFactoryProxy() {
		SendDebug("[FACTORY] Destroying factory proxy for %s", m_clsidName);
		if (m_pOriginal) m_pOriginal->Release();
	}

	// IUnknown methods
	STDMETHOD(QueryInterface)(REFIID riid, void** ppv) {
		if (!ppv) return E_POINTER;

		if (riid == IID_IUnknown || riid == IID_IClassFactory) {
			*ppv = static_cast<IClassFactory*>(this);
			AddRef();
			return S_OK;
		}

		// Pass through for other interfaces (like IClassFactory3)
		return m_pOriginal->QueryInterface(riid, ppv);
	}

	STDMETHOD_(ULONG, AddRef)() {
		return InterlockedIncrement(&m_refCount);
	}

	STDMETHOD_(ULONG, Release)() {
		LONG count = InterlockedDecrement(&m_refCount);
		if (count == 0) {
			delete this;
			return 0;
		}
		return count;
	}

	// IClassFactory methods
	STDMETHOD(CreateInstance)(IUnknown* pUnkOuter, REFIID riid, void** ppv) {
		// Log what's being created
		const char* iidName = "Unknown";
		if (riid == IID_IUnknown) iidName = "IUnknown";
		else if (riid == IID_IDispatch) iidName = "IDispatch";

		SendDebug("[FACTORY] CreateInstance: %s requesting %s", m_clsidName, iidName);

		// Call original CreateInstance
		HRESULT hr = m_pOriginal->CreateInstance(pUnkOuter, riid, ppv);

		if (SUCCEEDED(hr) && ppv && *ppv) {
			SendDebug("[FACTORY] CreateInstance SUCCESS: Object at 0x%p", *ppv);

			// VBScript requests IUnknown first, we need to QI for IDispatch
			if (riid == IID_IUnknown) {
				IUnknown* pUnk = (IUnknown*)*ppv;
				IDispatch* pDisp = NULL;

				HRESULT hrQI = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
				if (SUCCEEDED(hrQI) && pDisp) {
					SendDebug("[FACTORY] Object supports IDispatch - WRAPPING!");

					// Create our proxy
					IDispatch* pProxy = WrapDispatch(pDisp, m_clsidName);
					if (pProxy) {
						// Replace the returned IUnknown with our proxy
						pUnk->Release();
						*ppv = pProxy;
						SendDebug("[FACTORY] !!! Replaced object with proxy!");
					}
					pDisp->Release();
				}
				else {
					SendDebug("[FACTORY] Object does NOT support IDispatch (hr=0x%08X)", hrQI);
				}
			}
			// Direct IDispatch request (rare from VBScript)
			else if (riid == IID_IDispatch) {
				IDispatch* pDisp = (IDispatch*)*ppv;
				IDispatch* pProxy = WrapDispatch(pDisp, m_clsidName);
				if (pProxy) {
					*ppv = pProxy;
					pDisp->Release();
					SendDebug("[FACTORY] !!! Wrapped IDispatch directly!");
				}
			}
		}
		else {
			SendDebug("[FACTORY] CreateInstance FAILED: hr=0x%08X", hr);
		}

		return hr;
	}

	STDMETHOD(LockServer)(BOOL fLock) {
		return m_pOriginal->LockServer(fLock);
	}
};


// Also hook CLSIDFromProgID to see what ProgIDs are being resolved
typedef HRESULT(WINAPI* pCLSIDFromProgID)(LPCOLESTR lpszProgID, LPCLSID lpclsid);
pCLSIDFromProgID g_pOrigCLSIDFromProgID = NULL;

HRESULT WINAPI Hook_CLSIDFromProgID(LPCOLESTR lpszProgID, LPCLSID lpclsid) {
	char progIdBuf[256] = { 0 };
	if (lpszProgID) {
		WideCharToMultiByte(CP_ACP, 0, lpszProgID, -1, progIdBuf, sizeof(progIdBuf), NULL, NULL);
	}

	HRESULT hr = g_pOrigCLSIDFromProgID(lpszProgID, lpclsid);

	if (SUCCEEDED(hr) && lpclsid) {
		LPOLESTR clsidStr = NULL;
		StringFromCLSID(*lpclsid, &clsidStr);
		char clsidBuf[256] = { 0 };
		if (clsidStr) {
			WideCharToMultiByte(CP_ACP, 0, clsidStr, -1, clsidBuf, sizeof(clsidBuf), NULL, NULL);
			CoTaskMemFree(clsidStr);
		}
		SendDebug("[CLSIDFromProgID] '%s' -> %s", progIdBuf, clsidBuf);
	}
	else {
		SendDebug("[CLSIDFromProgID] '%s' FAILED (0x%08X)", progIdBuf, hr);
	}

	return hr;
}

// Wrap IDispatch in proxy
IDispatch* WrapDispatch(IDispatch* pOriginal, const char* objectName) {
	if (!pOriginal) return NULL;

	// Check if already wrapped
	EnterCriticalSection(&g_ProxyCS);

	auto it = g_ProxyMap.find(pOriginal);
	if (it != g_ProxyMap.end()) {
		// Already wrapped, return existing proxy
		it->second->AddRef();
		LeaveCriticalSection(&g_ProxyCS);
		SendDebug("[WRAP] Object 0x%p already proxied, returning existing", pOriginal);
		return it->second;
	}

	// Create new proxy
	DispatchProxy* pProxy = new DispatchProxy(pOriginal, objectName);
	g_ProxyMap[pOriginal] = pProxy;

	LeaveCriticalSection(&g_ProxyCS);

	return pProxy;
}

// Hooked CoCreateInstance
HRESULT WINAPI Hook_CoCreateInstance(
	REFCLSID rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD dwClsContext,
	REFIID riid,
	LPVOID* ppv
) {
	// Convert CLSID to string for logging
	LPOLESTR clsidStr = NULL;
	StringFromCLSID(rclsid, &clsidStr);
	char clsidBuf[256] = { 0 };
	if (clsidStr) {
		WideCharToMultiByte(CP_ACP, 0, clsidStr, -1, clsidBuf, sizeof(clsidBuf), NULL, NULL);
		CoTaskMemFree(clsidStr);
	}

	// Convert IID to string for logging
	LPOLESTR iidStr = NULL;
	StringFromIID(riid, &iidStr);
	char iidBuf[256] = { 0 };
	if (iidStr) {
		WideCharToMultiByte(CP_ACP, 0, iidStr, -1, iidBuf, sizeof(iidBuf), NULL, NULL);
		CoTaskMemFree(iidStr);
	}

	// Identify known interfaces
	const char* iidName = "Unknown";
	if (riid == IID_IUnknown) iidName = "IUnknown";
	else if (riid == IID_IDispatch) iidName = "IDispatch";
	else if (riid == IID_IDispatchEx) iidName = "IDispatchEx";

	// Identify known CLSIDs
	const char* clsidName = NULL;
	const GUID CLSID_VBScript = { 0xb54f3741, 0x5b07, 0x11cf, {0xa4, 0xb0, 0x00, 0xaa, 0x00, 0x4a, 0x55, 0xe8} };
	const GUID CLSID_JScript = { 0xf414c260, 0x6ac0, 0x11cf, {0xb6, 0xd1, 0x00, 0xaa, 0x00, 0xbb, 0xbb, 0x58} };

	if (memcmp(&rclsid, &CLSID_VBScript, sizeof(GUID)) == 0) clsidName = "VBScript";
	else if (memcmp(&rclsid, &CLSID_JScript, sizeof(GUID)) == 0) clsidName = "JScript";

	if (clsidName) {
		SendDebug("[HOOK] CoCreateInstance: %s (%s) IID=%s Context=0x%08X",
			clsidName, clsidBuf, iidName, dwClsContext);
	}
	else {
		SendDebug("[HOOK] CoCreateInstance: CLSID=%s IID=%s (%s) Context=0x%08X",
			clsidBuf, iidName, iidBuf, dwClsContext);
	}

	// Call original
	HRESULT hr = g_pOrigCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

	if (SUCCEEDED(hr) && ppv && *ppv) {
		SendDebug("[HOOK] CoCreateInstance SUCCESS: Object=0x%p", *ppv);

		// Check if requested interface is IDispatch or IDispatchEx - cant cast it to IDisp could crash!
		if (riid == IID_IDispatch) { // || riid == IID_IDispatchEx) {
			SendDebug("[HOOK] Direct IDispatch/IDispatchEx request - wrapping!");
			IDispatch* pDisp = (IDispatch*)*ppv;
			IDispatch* pProxy = WrapDispatch(pDisp, clsidBuf);

			if (pProxy) {
				*ppv = pProxy;
				pDisp->Release(); // Release original, proxy holds reference
				SendDebug("[HOOK] !!! Wrapped IDispatch/IDispatchEx in proxy");
			}
		}
		// ALWAYS try to QI for IDispatch on IUnknown
		else if (riid == IID_IUnknown) {
			IUnknown* pUnk = (IUnknown*)*ppv;
			IDispatch* pDisp = NULL;

			SendDebug("[HOOK] IUnknown requested - checking for IDispatch support...");

			// Try IDispatchEx first (more specific), then IDispatch
			HRESULT hrQI = pUnk->QueryInterface(IID_IDispatchEx, (void**)&pDisp);
			if (FAILED(hrQI)) {
				hrQI = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
			}

			if (SUCCEEDED(hrQI) && pDisp) {
				SendDebug("[HOOK] Object supports IDispatch/IDispatchEx - WRAPPING!");

				IDispatch* pProxy = WrapDispatch(pDisp, clsidBuf);
				if (pProxy) {
					// Replace IUnknown with our proxy
					pUnk->Release();
					*ppv = pProxy;
					SendDebug("[HOOK] !!! Replaced IUnknown with IDispatch proxy");
				}
				pDisp->Release();
			}
			else {
				SendDebug("[HOOK] Object does not support IDispatch (HRESULT=0x%08X)", hrQI);
			}
		}
		else {
			SendDebug("[HOOK] Other interface requested: %s - not wrapping", iidBuf);
		}
	}
	else {
		SendDebug("[HOOK] CoCreateInstance FAILED: HRESULT=0x%08X", hr);
	}

	return hr;
}

// Enhanced CoGetClassObject hook that wraps the returned IClassFactory
typedef HRESULT(WINAPI* pCoGetClassObject)(REFCLSID rclsid, DWORD dwClsContext, LPVOID pServerInfo, REFIID riid, LPVOID* ppv);
pCoGetClassObject g_pOrigCoGetClassObject = NULL;

HRESULT WINAPI Hook_CoGetClassObject(
	REFCLSID rclsid,
	DWORD dwClsContext,
	LPVOID pServerInfo,
	REFIID riid,
	LPVOID* ppv
) {
	// Get CLSID string
	LPOLESTR clsidStr = NULL;
	StringFromCLSID(rclsid, &clsidStr);
	char clsidBuf[256] = { 0 };
	if (clsidStr) {
		WideCharToMultiByte(CP_ACP, 0, clsidStr, -1, clsidBuf, sizeof(clsidBuf), NULL, NULL);
		CoTaskMemFree(clsidStr);
	}

	// Identify important CLSIDs we want to wrap
	const GUID CLSID_FileSystemObject = { 0x0d43fe01, 0xf093, 0x11cf, {0x89, 0x40, 0x00, 0xa0, 0xc9, 0x05, 0x42, 0x28} };
	const GUID CLSID_WshShell = { 0x72c24dd5, 0xd70a, 0x438b, {0x8a, 0x42, 0x98, 0x42, 0x4b, 0x88, 0xaf, 0xb8} };
	const GUID CLSID_Dictionary = { 0xee09b103, 0x97e0, 0x11cf, {0x97, 0x8f, 0x00, 0xa0, 0x24, 0x63, 0xe0, 0x6f} };
	const GUID CLSID_XMLHTTP = { 0xf6d90f11, 0x9c73, 0x11d3, {0xb3, 0x2e, 0x00, 0xc0, 0x4f, 0x99, 0x0b, 0xb4} };

	const char* friendlyName = NULL;
	if (memcmp(&rclsid, &CLSID_FileSystemObject, sizeof(GUID)) == 0)
		friendlyName = "FileSystemObject";
	else if (memcmp(&rclsid, &CLSID_WshShell, sizeof(GUID)) == 0)
		friendlyName = "WScript.Shell";
	else if (memcmp(&rclsid, &CLSID_Dictionary, sizeof(GUID)) == 0)
		friendlyName = "Scripting.Dictionary";
	else if (memcmp(&rclsid, &CLSID_XMLHTTP, sizeof(GUID)) == 0)
		friendlyName = "MSXML2.XMLHTTP";

	if (friendlyName) {
		SendDebug("[CoGetClassObject] %s (%s) Context=0x%08X", friendlyName, clsidBuf, dwClsContext);
	}
	else {
		SendDebug("[CoGetClassObject] CLSID=%s Context=0x%08X", clsidBuf, dwClsContext);
	}

	// Call original
	HRESULT hr = g_pOrigCoGetClassObject(rclsid, dwClsContext, pServerInfo, riid, ppv);

	if (SUCCEEDED(hr) && ppv && *ppv) {
		// Check if it's IClassFactory
		if (riid == IID_IClassFactory) {
			// Wrap important factories
			//if (friendlyName) {
			SendDebug("[CoGetClassObject] Got IClassFactory for %s - WRAPPING!", friendlyName);

			IClassFactory* pOrigFactory = (IClassFactory*)*ppv;
			ClassFactoryProxy* pProxy = new ClassFactoryProxy(pOrigFactory, friendlyName ? friendlyName : clsidBuf);

			*ppv = pProxy;
			pOrigFactory->Release(); // Proxy holds its own reference

			SendDebug("[CoGetClassObject] !!! Factory wrapped!");
			/*}
			else {
				SendDebug("[CoGetClassObject] Got IClassFactory for %s (not wrapping)", clsidBuf);
			}*/
		}
	}

	return hr;
}



// Alternative approach: Hook IDispatch::Invoke on the script engine itself
// This would catch ALL script method calls

// Hook GetActiveObject - used for getting running instances
typedef HRESULT(WINAPI* pGetActiveObject)(REFCLSID rclsid, void* pvReserved, IUnknown** ppunk);
pGetActiveObject g_pOrigGetActiveObject = NULL;

// Hook CoGetObject - used by VB6 GetObject() for monikers
typedef HRESULT(WINAPI* pCoGetObject)(LPCWSTR pszName, BIND_OPTS* pBindOptions, REFIID riid, void** ppv);
pCoGetObject g_pOrigCoGetObject = NULL;

// Hook MkParseDisplayName - parses moniker display names  
typedef HRESULT(WINAPI* pMkParseDisplayName)(IBindCtx* pbc, LPCOLESTR szUserName, ULONG* pchEaten, IMoniker** ppmk);
pMkParseDisplayName g_pOrigMkParseDisplayName = NULL;

// Hook CoGetObject - captures VB6 GetObject() calls
HRESULT WINAPI Hook_CoGetObject(LPCWSTR pszName, BIND_OPTS* pBindOptions, REFIID riid, void** ppv) {
	char nameBuf[512] = { 0 };
	if (pszName) {
		WideCharToMultiByte(CP_ACP, 0, pszName, -1, nameBuf, sizeof(nameBuf), NULL, NULL);
	}

	// Get IID string
	LPOLESTR iidStr = NULL;
	StringFromIID(riid, &iidStr);
	char iidBuf[256] = { 0 };
	if (iidStr) {
		WideCharToMultiByte(CP_ACP, 0, iidStr, -1, iidBuf, sizeof(iidBuf), NULL, NULL);
		CoTaskMemFree(iidStr);
	}

	const char* iidName = NULL;
	if (memcmp(&riid, &IID_IUnknown, sizeof(IID)) == 0) iidName = "IUnknown";
	else if (memcmp(&riid, &IID_IDispatch, sizeof(IID)) == 0) iidName = "IDispatch";

	SendDebug("[HOOK] CoGetObject: Name='%s' IID=%s (%s)",
		nameBuf, iidName ? iidName : "Unknown", iidBuf);

	HRESULT hr = g_pOrigCoGetObject(pszName, pBindOptions, riid, ppv);

	if (SUCCEEDED(hr) && ppv && *ppv) {
		SendDebug("[HOOK] CoGetObject SUCCESS: Object=0x%p", *ppv);

		// Try to wrap if it's IDispatch or IUnknown
		if (riid == IID_IDispatch) {
			IDispatch* pDisp = (IDispatch*)*ppv;
			IDispatch* pProxy = WrapDispatch(pDisp, nameBuf);
			if (pProxy) {
				*ppv = pProxy;
				pDisp->Release();
				SendDebug("[HOOK] !!! CoGetObject result wrapped in proxy");
			}
		}
		else if (riid == IID_IUnknown) {
			IUnknown* pUnk = (IUnknown*)*ppv;
			IDispatch* pDisp = NULL;

			// Try to get IDispatch interface
			HRESULT hrQI = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
			if (SUCCEEDED(hrQI) && pDisp) {
				SendDebug("[HOOK] CoGetObject result supports IDispatch - WRAPPING!");
				IDispatch* pProxy = WrapDispatch(pDisp, nameBuf);
				if (pProxy) {
					pUnk->Release();
					*ppv = pProxy;
					SendDebug("[HOOK] !!! CoGetObject result wrapped");
				}
				pDisp->Release();
			}
		}
	}
	else {
		SendDebug("[HOOK] CoGetObject FAILED: HRESULT=0x%08X", hr);
	}

	return hr;
}

// IMoniker Proxy - wraps IMoniker to intercept BindToObject calls
class MonikerProxy : public IMoniker {
private:
	LONG m_refCount;
	IMoniker* m_pOriginal;
	char m_monikerName[512];

	// Original vtable pointer
	void** m_pOriginalVTable;
	void** m_pProxyVTable;

	// Store original BindToObject function
	static HRESULT(STDMETHODCALLTYPE* s_pOriginalBindToObject)(IMoniker*, IBindCtx*, IMoniker*, REFIID, void**);

public:
	MonikerProxy(IMoniker* pOriginal, const char* name)
		: m_refCount(1), m_pOriginal(pOriginal) {
		strncpy_s(m_monikerName, name ? name : "Unknown", sizeof(m_monikerName) - 1);

		if (m_pOriginal) {
			m_pOriginal->AddRef();
		}

		SendDebug("[MONIKER] Created moniker proxy for '%s' (Original: 0x%p)", m_monikerName, m_pOriginal);
	}

	virtual ~MonikerProxy() {
		SendDebug("[MONIKER] Destroying moniker proxy for '%s'", m_monikerName);
		if (m_pOriginal) {
			m_pOriginal->Release();
			m_pOriginal = NULL;
		}
	}

	// IUnknown methods
	STDMETHOD(QueryInterface)(REFIID riid, void** ppv) {
		if (!ppv) return E_POINTER;

		if (riid == IID_IUnknown || riid == IID_IMoniker || riid == IID_IPersist || riid == IID_IPersistStream) {
			*ppv = static_cast<IMoniker*>(this);
			AddRef();
			return S_OK;
		}

		// Pass through to original
		if (m_pOriginal) {
			return m_pOriginal->QueryInterface(riid, ppv);
		}

		*ppv = NULL;
		return E_NOINTERFACE;
	}

	STDMETHOD_(ULONG, AddRef)() {
		return InterlockedIncrement(&m_refCount);
	}

	STDMETHOD_(ULONG, Release)() {
		LONG count = InterlockedDecrement(&m_refCount);
		if (count == 0) {
			delete this;
			return 0;
		}
		return count;
	}

	// IPersist method
	STDMETHOD(GetClassID)(CLSID* pClassID) {
		if (m_pOriginal) {
			return m_pOriginal->GetClassID(pClassID);
		}
		return E_NOTIMPL;
	}

	// IPersistStream methods
	STDMETHOD(IsDirty)() {
		if (m_pOriginal) {
			return m_pOriginal->IsDirty();
		}
		return E_NOTIMPL;
	}

	STDMETHOD(Load)(IStream* pStm) {
		if (m_pOriginal) {
			return m_pOriginal->Load(pStm);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(Save)(IStream* pStm, BOOL fClearDirty) {
		if (m_pOriginal) {
			return m_pOriginal->Save(pStm, fClearDirty);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(GetSizeMax)(ULARGE_INTEGER* pcbSize) {
		if (m_pOriginal) {
			return m_pOriginal->GetSizeMax(pcbSize);
		}
		return E_NOTIMPL;
	}

	// IMoniker methods - the key one is BindToObject
	STDMETHOD(BindToObject)(IBindCtx* pbc, IMoniker* pmkToLeft, REFIID riidResult, void** ppvResult) {
		SendDebug("[MONIKER] >>> BindToObject called for '%s'", m_monikerName);

		// Get IID string
		LPOLESTR iidStr = NULL;
		StringFromIID(riidResult, &iidStr);
		char iidBuf[256] = { 0 };
		if (iidStr) {
			WideCharToMultiByte(CP_ACP, 0, iidStr, -1, iidBuf, sizeof(iidBuf), NULL, NULL);
			CoTaskMemFree(iidStr);
		}

		const char* iidName = NULL;
		if (memcmp(&riidResult, &IID_IUnknown, sizeof(IID)) == 0) iidName = "IUnknown";
		else if (memcmp(&riidResult, &IID_IDispatch, sizeof(IID)) == 0) iidName = "IDispatch";

		SendDebug("[MONIKER]     Requested IID: %s (%s)", iidName ? iidName : "Unknown", iidBuf);

		HRESULT hr = E_NOTIMPL;
		if (m_pOriginal) {
			hr = m_pOriginal->BindToObject(pbc, pmkToLeft, riidResult, ppvResult);
		}

		if (SUCCEEDED(hr) && ppvResult && *ppvResult) {
			SendDebug("[MONIKER] <<< BindToObject SUCCESS: Object=0x%p", *ppvResult);

			// Try to wrap the result if it's IDispatch or IUnknown
			if (riidResult == IID_IDispatch) {
				IDispatch* pDisp = (IDispatch*)*ppvResult;
				IDispatch* pProxy = WrapDispatch(pDisp, m_monikerName);
				if (pProxy) {
					*ppvResult = pProxy;
					pDisp->Release();
					SendDebug("[MONIKER] !!! Wrapped result in IDispatch proxy");
				}
			}
			else if (riidResult == IID_IUnknown) {
				IUnknown* pUnk = (IUnknown*)*ppvResult;
				IDispatch* pDisp = NULL;

				// Try to get IDispatch interface
				HRESULT hrQI = pUnk->QueryInterface(IID_IDispatch, (void**)&pDisp);
				if (SUCCEEDED(hrQI) && pDisp) {
					SendDebug("[MONIKER] Result supports IDispatch - WRAPPING!");
					IDispatch* pProxy = WrapDispatch(pDisp, m_monikerName);
					if (pProxy) {
						pUnk->Release();
						*ppvResult = pProxy;
						SendDebug("[MONIKER] !!! Wrapped result in proxy");
					}
					pDisp->Release();
				}
			}
		}
		else {
			SendDebug("[MONIKER] <<< BindToObject FAILED: HRESULT=0x%08X", hr);
		}

		return hr;
	}

	// Other IMoniker methods - pass through to original
	STDMETHOD(BindToStorage)(IBindCtx* pbc, IMoniker* pmkToLeft, REFIID riid, void** ppvObj) {
		if (m_pOriginal) {
			return m_pOriginal->BindToStorage(pbc, pmkToLeft, riid, ppvObj);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(Reduce)(IBindCtx* pbc, DWORD dwReduceHowFar, IMoniker** ppmkToLeft, IMoniker** ppmkReduced) {
		if (m_pOriginal) {
			return m_pOriginal->Reduce(pbc, dwReduceHowFar, ppmkToLeft, ppmkReduced);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(ComposeWith)(IMoniker* pmkRight, BOOL fOnlyIfNotGeneric, IMoniker** ppmkComposite) {
		if (m_pOriginal) {
			return m_pOriginal->ComposeWith(pmkRight, fOnlyIfNotGeneric, ppmkComposite);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(Enum)(BOOL fForward, IEnumMoniker** ppenumMoniker) {
		if (m_pOriginal) {
			return m_pOriginal->Enum(fForward, ppenumMoniker);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(IsEqual)(IMoniker* pmkOtherMoniker) {
		if (m_pOriginal) {
			return m_pOriginal->IsEqual(pmkOtherMoniker);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(Hash)(DWORD* pdwHash) {
		if (m_pOriginal) {
			return m_pOriginal->Hash(pdwHash);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(IsRunning)(IBindCtx* pbc, IMoniker* pmkToLeft, IMoniker* pmkNewlyRunning) {
		if (m_pOriginal) {
			return m_pOriginal->IsRunning(pbc, pmkToLeft, pmkNewlyRunning);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(GetTimeOfLastChange)(IBindCtx* pbc, IMoniker* pmkToLeft, FILETIME* pFileTime) {
		if (m_pOriginal) {
			return m_pOriginal->GetTimeOfLastChange(pbc, pmkToLeft, pFileTime);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(Inverse)(IMoniker** ppmk) {
		if (m_pOriginal) {
			return m_pOriginal->Inverse(ppmk);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(CommonPrefixWith)(IMoniker* pmkOther, IMoniker** ppmkPrefix) {
		if (m_pOriginal) {
			return m_pOriginal->CommonPrefixWith(pmkOther, ppmkPrefix);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(RelativePathTo)(IMoniker* pmkOther, IMoniker** ppmkRelPath) {
		if (m_pOriginal) {
			return m_pOriginal->RelativePathTo(pmkOther, ppmkRelPath);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(GetDisplayName)(IBindCtx* pbc, IMoniker* pmkToLeft, LPOLESTR* ppszDisplayName) {
		if (m_pOriginal) {
			return m_pOriginal->GetDisplayName(pbc, pmkToLeft, ppszDisplayName);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(ParseDisplayName)(IBindCtx* pbc, IMoniker* pmkToLeft, LPOLESTR pszDisplayName, ULONG* pchEaten, IMoniker** ppmkOut) {
		if (m_pOriginal) {
			return m_pOriginal->ParseDisplayName(pbc, pmkToLeft, pszDisplayName, pchEaten, ppmkOut);
		}
		return E_NOTIMPL;
	}

	STDMETHOD(IsSystemMoniker)(DWORD* pdwMksys) {
		if (m_pOriginal) {
			return m_pOriginal->IsSystemMoniker(pdwMksys);
		}
		return E_NOTIMPL;
	}
};

// Hook MkParseDisplayName - captures moniker parsing (alternative path for GetObject)
HRESULT WINAPI Hook_MkParseDisplayName(IBindCtx* pbc, LPCOLESTR szUserName, ULONG* pchEaten, IMoniker** ppmk) {

	char nameBuf[512] = { 0 };
	if (szUserName) {
		WideCharToMultiByte(CP_ACP, 0, szUserName, -1, nameBuf, sizeof(nameBuf), NULL, NULL);
	}

	SendDebug("[HOOK] MkParseDisplayName: Name='%s'", nameBuf);

	HRESULT hr = g_pOrigMkParseDisplayName(pbc, szUserName, pchEaten, ppmk);

	if (SUCCEEDED(hr) && ppmk && *ppmk) {
		SendDebug("[HOOK] MkParseDisplayName SUCCESS: Moniker=0x%p", *ppmk);

		// Wrap the moniker to intercept BindToObject calls
		IMoniker* pOrigMoniker = *ppmk;
		MonikerProxy* pProxy = new MonikerProxy(pOrigMoniker, nameBuf);
		*ppmk = pProxy;
		pOrigMoniker->Release(); // Proxy holds its own reference

		SendDebug("[HOOK] !!! Wrapped moniker in proxy to intercept BindToObject");
	}
	else {
		SendDebug("[HOOK] MkParseDisplayName FAILED: HRESULT=0x%08X", hr);
	}

	return hr;
}

HRESULT WINAPI Hook_GetActiveObject(REFCLSID rclsid, void* pvReserved, IUnknown** ppunk) {
	LPOLESTR clsidStr = NULL;
	StringFromCLSID(rclsid, &clsidStr);
	char clsidBuf[256] = { 0 };
	if (clsidStr) {
		WideCharToMultiByte(CP_ACP, 0, clsidStr, -1, clsidBuf, sizeof(clsidBuf), NULL, NULL);
		CoTaskMemFree(clsidStr);
	}

	SendDebug("[HOOK] GetActiveObject: CLSID=%s", clsidBuf);

	HRESULT hr = g_pOrigGetActiveObject(rclsid, pvReserved, ppunk);

	if (SUCCEEDED(hr) && ppunk && *ppunk) {
		IDispatch* pDisp = NULL;
		if (SUCCEEDED((*ppunk)->QueryInterface(IID_IDispatch, (void**)&pDisp))) {
			SendDebug("[HOOK] GetActiveObject returned IDispatch - wrapping!");
			IDispatch* pProxy = WrapDispatch(pDisp, clsidBuf);
			if (pProxy) {
				(*ppunk)->Release();
				*ppunk = pProxy;
			}
			pDisp->Release();
		}
	}

	return hr;
}

// Add these hooks in DllMain after the CoCreateInstance hook:
void InstallHooks() {

	SendDebug("========================================");
	SendDebug("[INIT] DispatchLogger injected into PID=%d", GetCurrentProcessId());
	SendDebug("[INIT] Debug window: 0x%p", hServer);

	// Hook CoCreateInstance
	HMODULE hOle32 = GetModuleHandleA("ole32.dll");
	if (!hOle32) {
		SendDebug("[ERROR] Failed to get ole32.dll handle");
		return;
	}

	ULONG_PTR pCoCreate = (ULONG_PTR)GetProcAddress(hOle32, "CoCreateInstance");
	if (!pCoCreate) {
		SendDebug("[ERROR] Failed to find CoCreateInstance");
		return;
	}

	SendDebug("[INIT] CoCreateInstance at 0x%p", (void*)pCoCreate);

	if (HookFunction(pCoCreate, (ULONG_PTR)Hook_CoCreateInstance,
		(char*)"CoCreateInstance", ht_jmp)) {
		g_pOrigCoCreateInstance = (pCoCreateInstance)GetOriginalFunction((ULONG_PTR)Hook_CoCreateInstance);
		SendDebug("[INIT] Successfully hooked CoCreateInstance!");
		SendDebug("[INIT] Original function: 0x%p", g_pOrigCoCreateInstance);
	}
	else {
		SendDebug("[ERROR] Failed to hook CoCreateInstance: %s", GetHookError());
	}

	// Hook CoGetClassObject
	ULONG_PTR pCoGetClass = (ULONG_PTR)GetProcAddress(hOle32, "CoGetClassObject");
	if (pCoGetClass) {
		if (HookFunction(pCoGetClass, (ULONG_PTR)Hook_CoGetClassObject,
			(char*)"CoGetClassObject", ht_jmp)) {
			g_pOrigCoGetClassObject = (pCoGetClassObject)GetOriginalFunction((ULONG_PTR)Hook_CoGetClassObject);
			SendDebug("[INIT] Hooked CoGetClassObject");
		}
	}

	// Hook CLSIDFromProgID
	ULONG_PTR lpCLSIDFromProgID = (ULONG_PTR)GetProcAddress(hOle32, "CLSIDFromProgID");
	if (lpCLSIDFromProgID) {
		if (HookFunction(lpCLSIDFromProgID, (ULONG_PTR)Hook_CLSIDFromProgID, (char*)"CLSIDFromProgID", ht_jmp)) {
			g_pOrigCLSIDFromProgID = (pCLSIDFromProgID)GetOriginalFunction((ULONG_PTR)Hook_CLSIDFromProgID);
			SendDebug("[INIT] Hooked CLSIDFromProgID");
		}
	}

	// Hook GetActiveObject (from oleaut32.dll)
	HMODULE hOleAut32 = GetModuleHandleA("oleaut32.dll");
	if (hOleAut32) {
		ULONG_PTR pGetActive = (ULONG_PTR)GetProcAddress(hOleAut32, "GetActiveObject");
		if (pGetActive) {
			if (HookFunction(pGetActive, (ULONG_PTR)Hook_GetActiveObject,
				(char*)"GetActiveObject", ht_jmp)) {
				g_pOrigGetActiveObject = (pGetActiveObject)GetOriginalFunction((ULONG_PTR)Hook_GetActiveObject);
				SendDebug("[INIT] Hooked GetActiveObject");
			}
		}
	}

	// Hook CoGetObject - captures VB6 GetObject() WMI calls
	ULONG_PTR pCoGetObj = (ULONG_PTR)GetProcAddress(hOle32, "CoGetObject");
	if (pCoGetObj) {
		if (HookFunction(pCoGetObj, (ULONG_PTR)Hook_CoGetObject,
			(char*)"CoGetObject", ht_jmp)) {
			g_pOrigCoGetObject = (pCoGetObject)GetOriginalFunction((ULONG_PTR)Hook_CoGetObject);
			SendDebug("[INIT] Hooked CoGetObject");
		}
	}

	// Hook MkParseDisplayName - alternative path for GetObject()
	ULONG_PTR pMkParse = (ULONG_PTR)GetProcAddress(hOle32, "MkParseDisplayName");
	if (pMkParse) {
		if (HookFunction(pMkParse, (ULONG_PTR)Hook_MkParseDisplayName,
			(char*)"MkParseDisplayName", ht_jmp)) {
			g_pOrigMkParseDisplayName = (pMkParseDisplayName)GetOriginalFunction((ULONG_PTR)Hook_MkParseDisplayName);
			SendDebug("[INIT] Hooked MkParseDisplayName");
		}
	}

	SendDebug("========================================");

}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH: {
		DisableThreadLibraryCalls(hModule);
		InitializeCriticalSection(&g_ProxyCS);
		FindVBWindow();
		msg("<cls>", 1);
		InstallHooks();
		break;
	}

	case DLL_PROCESS_DETACH: {
		SendDebug("[SHUTDOWN] DispatchLogger unloading...");

		// Disable hook
		DisableHook((ULONG_PTR)Hook_CoCreateInstance);

		// Clean up proxies
		EnterCriticalSection(&g_ProxyCS);
		g_ProxyMap.clear();
		LeaveCriticalSection(&g_ProxyCS);

		DeleteCriticalSection(&g_ProxyCS);
		SendDebug("[SHUTDOWN] Complete");
		break;
	}
	}

	return TRUE;
}

// Export for manual callback window setting
extern "C" __declspec(dllexport) void SetCallbackWindow(HWND hwnd) {
	hServer = hwnd;
	SendDebug("[API] Callback window set to 0x%p", hwnd);
}