// DispatchLogger.h - Header for IDispatch logging proxy

#pragma once

#include <windows.h>
#include <oleauto.h>
#include <map>
#include <string>

// IPC message callback
#define WM_DCOM_CALLBACK (WM_USER + 1002)

// External debug messaging
extern HWND hCallback;
void SendDebug(const char* format, ...);

// Forward declarations
class DispatchProxy;

// DispatchProxy - Main IDispatch logging proxy class
class DispatchProxy : public IDispatch {
private:
    LONG m_refCount;
    IDispatch* m_pOriginal;
    char m_objectName[256];
    DWORD m_proxyId;
    
public:
    // Constructor/Destructor
    DispatchProxy(IDispatch* pOriginal, const char* name);
    virtual ~DispatchProxy();
    
    // IUnknown methods
    STDMETHOD(QueryInterface)(REFIID riid, void** ppv);
    STDMETHOD_(ULONG, AddRef)();
    STDMETHOD_(ULONG, Release)();
    
    // IDispatch methods
    STDMETHOD(GetTypeInfoCount)(UINT* pctinfo);
    STDMETHOD(GetTypeInfo)(UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo);
    STDMETHOD(GetIDsOfNames)(REFIID riid, LPOLESTR* rgszNames, UINT cNames, 
                            LCID lcid, DISPID* rgDispId);
    STDMETHOD(Invoke)(DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags,
                     DISPPARAMS* pDispParams, VARIANT* pVarResult,
                     EXCEPINFO* pExcepInfo, UINT* puArgErr);
};

// Wrapper function to create proxy for IDispatch
IDispatch* WrapDispatch(IDispatch* pOriginal, const char* objectName);

// Helper to convert VARIANT to string for logging
std::string VariantToString(VARIANT* pVar);

// Function pointer type for original CoCreateInstance
typedef HRESULT (WINAPI *pCoCreateInstance)(
    REFCLSID rclsid,
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID *ppv
);

// Global tracking
extern std::map<IDispatch*, DispatchProxy*> g_ProxyMap;
extern CRITICAL_SECTION g_ProxyCS;
extern DWORD g_ProxyCounter;
extern pCoCreateInstance g_pOrigCoCreateInstance;

// Hooked CoCreateInstance function
HRESULT WINAPI Hook_CoCreateInstance(
    REFCLSID rclsid,
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID *ppv
);

// DLL Exports
#ifdef __cplusplus
extern "C" {
#endif

// Export for manual callback window setting
__declspec(dllexport) void SetCallbackWindow(HWND hwnd);

#ifdef __cplusplus
}
#endif

// For compatibility with your naming convention
class DispatchLogger : public DispatchProxy {
public:
    DispatchLogger(IDispatch* pOriginal, const char* name) 
        : DispatchProxy(pOriginal, name) {}
};
