
# DispatchLogger

Windows COM surveillance layer for script hosts, PowerShell, EXEs and anything that abuses late bound automation objects.

This DLL injects into a target process, hooks core COM activation paths, and wraps every `IDispatch` it can get its hands on with a live logging proxy. You get a real-time trace of what scripts are doing — including method calls, arguments, return values, spawned child COM objects, enumerators, moniker binds, and even ByRef out parameters.

It was built for malware analysis and red-team forensics, but it’s also just straight-up useful if you want to see what VBScript, JScript, HTA, Office macros, or PowerShell automation are really doing under the hood.

For more information please check out the full post on [Cisco Talos Blogs](https://blog.talosintelligence.com/transparent-com-instrumentation-for-malware-analysis)

Quick Start Notes: 
* All C projects were built using VS 2022
* An injector and log parser are included in the repo
* Injector and idispLogger.dll can be built for both 32/64 bit.
* You will need to run DebugView or an IPC debug message viewer to receive output:
  * [DebugView (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview)
  * [Persistent Debug Print Window (VBForums)](https://www.vbforums.com/showthread.php?874127-Persistent-Debug-Print-Window)

---

## What problems this solves ✅

Script malware leans on COM for everything:

* `Scripting.FileSystemObject` for file I/O
* `WScript.Shell` for process launch and registry writes
* `MSXML2.XMLHTTP` for download-and-execute
* WMI objects for recon
* `GetObject("winmgmts:...")` style live system access via monikers

Traditional sandboxes and string dumpers miss a lot of this because:

* The dangerous parts are runtime only
* Objects get passed around dynamically
* Child COM objects aren’t obvious from static code
* Some objects are only reachable through `GetObject()` / running object table, not normal `CoCreateInstance`

DispatchLogger attacks that directly by:

* Hooking COM activation itself
* Forcing anything that turns into `IDispatch` through our proxy
* Logging every call to `Invoke()` (methods, property gets/sets) with typed argument values and return values

---

## High-level architecture

### 1. API Hook Layer

We detour a bunch of COM-related APIs in `ole32.dll` and friends:

* `CoCreateInstance` – classic COM activation
* `CoGetClassObject` – fetches the class factory that actually builds script-facing objects
* `CLSIDFromProgID` – resolves `"Scripting.FileSystemObject"` → CLSID, so we can label objects with human-readable names
* `CoGetObject` – used by VB / VBScript `GetObject(...)` to bind monikers like WMI namespaces, running COM servers, etc.
* `GetActiveObject` – pulls from the Running Object Table (think “talk to an already-running instance of Excel”)
* `MkParseDisplayName` – parses moniker names so we can intercept and wrap those too

Each hook logs what was requested and then returns *our* wrapped object instead of the raw one when possible.
If the target only exposes `IUnknown`, we immediately `QueryInterface` for `IDispatch` and wrap that.

---

### 2. ClassFactoryProxy (factory-level interception)

When script code does `CreateObject("WScript.Shell")`, VBScript/JScript does **not** directly call `CoCreateInstance` for an `IDispatch`. It asks COM for the class factory, calls `IClassFactory::CreateInstance()` requesting **IUnknown**, and only afterwards asks for `IDispatch`. That means naive `CoCreateInstance` hooks miss most of it.

We solve that by wrapping the `IClassFactory` that `CoGetClassObject` returns:

```cpp
class ClassFactoryProxy : public IClassFactory {
    // Intercepts CreateInstance()
    // If the created object can speak IDispatch / IDispatchEx,
    // we replace it with our DispatchProxy before the script ever sees it.
}
```



This guarantees first-touch visibility into high-value ProgIDs like:

* `Scripting.FileSystemObject`
* `WScript.Shell`
* `Scripting.Dictionary`
* `MSXML2.XMLHTTP`
  (and anything else that flows through `CoGetClassObject`)

---

### 3. DispatchProxy (per-object interception)

Every COM object that supports `IDispatch` gets wrapped in a `DispatchProxy`. This proxy:

* Implements `IUnknown` / `IDispatch` so the script can keep using it normally
* Logs every call to `Invoke()`
* Resolves human-readable method/property names via `ITypeInfo`
* Dumps all arguments with variant types
* Logs the return value
* Recursively wraps any returned `IDispatch`, `IUnknown` (that QIs to `IDispatch`), or enumerator so child objects are tracked too

When your script calls something like:

```vbscript
set fso   = CreateObject("Scripting.FileSystemObject")
set fldr  = fso.GetFolder("C:\Temp")
for each f in fldr.Files
    WScript.Echo f.Path
next
```

You don’t just see “GetFolder called.”
You also get:

* A new wrapped proxy for the Folder
* A wrapped enumerator for `For Each`
* Every property get (`.Path`) logged with its returned string

---

## Advanced features in the current build

### ✔ Recursive wrapping of return values

If a method returns another COM object, we immediately wrap that child and keep tracking it under a descriptive name like `FileSystemObject.GetSpecialFolder`. You see the entire object graph, not just the root.

### ✔ Enumerator interception (`IEnumVARIANT`)

We proxy `IEnumVARIANT` too. That means even `For Each` loops are visible. Each yielded item is inspected, and if it’s a COM object it also gets wrapped before the script sees it. This catches WMI recordsets, file lists, etc.

### ✔ ByRef output parameter handling

A lot of COM APIs hand new objects back through `ByRef` params instead of return values.
During `Invoke()`, we walk the argument list, detect `VT_BYREF`, dereference it, and if what came back is a new COM object, we wrap and replace it in-place. You still get full logging downstream, with correct identity tracking.

### ✔ Moniker / `GetObject()` / WMI path logging

We hook:

* `CoGetObject` (VB `GetObject("winmgmts:...")`)
* `MkParseDisplayName` (moniker string → `IMoniker`)
  and we wrap the resulting moniker with `MonikerProxy`.

`MonikerProxy` intercepts `IMoniker::BindToObject`, logs what moniker was requested, what interface was asked for (`IUnknown` vs `IDispatch`), and again swaps in a `DispatchProxy` if it resolves to an automation object. This covers late-bound stuff like WMI and running COM servers that never hit `CoCreateInstance`.

### ✔ Running Object Table / `GetActiveObject`

If the script tries to grab an existing running COM server (Excel, Word, etc.) via `GetActiveObject`, we intercept that too, log the CLSID, and again wrap the returned automation object before handing it back.

### ✔ IDispatchEx-aware, but safe

We detect `IDispatchEx` and `IDispatch`, log interface queries in `QueryInterface`, and avoid lying about interfaces we don’t fully implement. This prevents script hosts from crashing when they probe for extended dispatch features.

### ✔ Real-time IPC to your debug console

All log lines are pushed over `WM_COPYDATA` into a VB6 “Persistent Debug Print Window,” with PID/TID prefixes for multi-process clarity. 

https://www.vbforums.com/showthread.php?874127-Persistent-Debug-Print-Window

If that window isn’t present, we fall back to `OutputDebugStringA`, so DebugView still sees it.

https://learn.microsoft.com/en-us/sysinternals/downloads/debugview

---

## Output style (sample)

You’ll see structured noise like:

```text
[HOOK] CoGetClassObject: WScript.Shell ({CLSID...}) Context=0x1
[CoGetClassObject] Got IClassFactory for WScript.Shell - WRAPPING!
[FACTORY] CreateInstance: WScript.Shell requesting IUnknown
[FACTORY] CreateInstance SUCCESS: Object at 0x12345678
[FACTORY] !!! Replaced object with proxy!

[PROXY #1] >>> Invoke: WScript.Shell.Run (METHOD) ArgCount=2
[PROXY #1]     Arg[0]: "cmd.exe /c whoami"
[PROXY #1]     Arg[1]: 0
[PROXY #1] <<< Result: 0x00000000 (HRESULT=0x00000000)

[PROXY #2] >>> Invoke: FileSystemObject.OpenTextFile (METHOD) ArgCount=2
[PROXY #2]     Arg[0]: "C:\Temp\dropper.exe"
[PROXY #2]     Arg[1]: 2
[PROXY #2] <<< Result: IDispatch:0x03AD6C14
[PROXY #2] !!! Wrapped returned IDispatch as new proxy
```

This is coming straight out of `DispatchProxy::Invoke()` and friends. It resolves method names using `ITypeInfo`, logs flags (`METHOD`, `PROPGET`, etc.), walks args in the correct reverse order, and logs return values, including strings, numbers, bools, arrays, and object pointers.

---

## Usage model

* You inject `DispatchLogger.dll` into a target process (wscript.exe, cscript.exe, powershell.exe, etc.).
* On load, `DllMain`/`InstallHooks()` locates `ole32.dll`, patches the relevant exports (like `CoCreateInstance`, `CoGetClassObject`, etc.) using your hook engine, and starts logging.

You can:

* Launch `wscript.exe script.vbs` under the injector to analyze classic VBS malware
* Launch `powershell.exe -File script.ps1` and watch COM automation from PowerShell
* Inject into an already-running process that’s abusing COM (even if it never touches WSH at all)

## Injector (SimpleInjector)

**Purpose**
`SimpleInjector` is the companion launcher for `iDispLogger.dll`. It creates or attaches to a target process and injects the logger DLL. If  dbgWindow.exe is found, it will be launched automatically.

**Key behaviour**

* Show usage for /h /? /help (and -h variants)
* If no args: runs `cscript.exe tests\TestScript.vbs` (default). (double click behavior)
* If single arg is a `.vbs`, `.js`, `.wsf`, `.hta` file: runs it under `cscript.exe "script"`; if single arg is an `.exe` it runs that exe directly.
* If multiple args: treats first arg as executable and passes the rest as parameters.
* Ensures `dbgwindow.exe` (the VB6 debug receiver) is running and will attempt to start it from the current or parent directory.
* Implements classic `LoadLibrary` remote-thread DLL injection into a suspended child process: create process suspended → write DLL path → CreateRemoteThread(LoadLibraryA) → resume thread.
* Waits for child to exit and pumps messages while waiting so GUI apps stay responsive.

**CLI examples**

```text
# default (if you have tests/TestScript.vbs) - just double click
injector.exe 

# run a script with cscript
injector.exe malware.js

# launch an arbitrary exe + args
injector.exe powershell.exe -File "analyze.ps1"

# run wscript with args
injector.exe "wscript.exe" "test.vbs"
```

**Notes & tips**

* The injector looks for `iDispLogger.dll` in the current directory or one level up; adjust paths if you store binaries elsewhere.
* If `dbgwindow.exe` is missing, the injector warns and the logger falls back to `OutputDebugStringA` (DebugView).
* The injector returns the child process handle (keeps the process open while you watch logs). It uses a message loop while waiting, so it won't block GUI message processing in the child. 

---

## Log parser — quick and practical

`log_parser.py` or `logRecon.exe` can be used to parse the verbose IPC logs into a human readable form. These tools show only the COM actions in an easy to digest format.

---

## Notes / limitations

* Windows only. This is COM.
* Requires DLL injection and runtime patching of system COM exports (`CoCreateInstance`, etc.).
* We currently present ourselves as `IDispatch` and proxy `IDispatchEx` instead of claiming full native `IDispatchEx` implementation. That avoids crashes from scripts that poke at dynamic members. Full `IDispatchEx` surfacing is on-deck.
* Objects that don’t expose automation at all (pure custom interfaces, no `IDispatch`/`IDispatchEx`) are still logged at creation but obviously won’t generate Invoke() traces. We’ll still log attempts to `QueryInterface` them and note failures.

---

## Credits

<pre>
NTCore Hooking Engine written by:
Daniel Pistelli <ntcore@gmail.com>
License: Public Domain
http://www.ntcore.com/files/nthookengine.htm

diStorm was written by Gil Dabah. 
Copyright (C) 2003-2012 Gil Dabah. diStorm at gmail dot com
License: BSD
https://github.com/gdabah/distorm

DispatchLogger built by Cisco Talos
License: Apache 2.0
Author: David Zimmer <dzzie@yahoo.com> 
</pre>


