
//This is a modified version of the open source x86/x64 
//NTCore Hooking Engine written by:
//Daniel Pistelli <ntcore@gmail.com>
//http://www.ntcore.com/files/nthookengine.htm
/*

As it's possible to see from the previous example, the hook engine isn't perfect, but it can easily be improved. 
I don't develop it further because I don't need a more powerful one (right now, I mean). 
I just needed an x86/x64 hook engine with no license restrictions. 

I wrote this engine and the article in just one day, it really wasn't much work. 
Most of the work in such a hook engine is writing the disassembler, which I didn't do. 
So, in my opinion, it doesn't make much sense paying for a hook engine. The only thing 
which I really can't provide in this engine is support for Itanium. That's because I don't 
have a disassembler for this platform. But I would rather write one myself than buying 
a hook engine. I might actually add an Itanium disassembler in the future, who knows...

I hope you can find this code useful.

Daniel Pistelli
*/

/*
On Monday, November 10, 2025 at 09:28:13 AM EST, NTCore <info@ntcore.com> wrote:
Hello Dave, no, it's public domain code. :) Cheers, Erik

On Sunday, November 9th, 2025 at 03:43, dzzie <dzzie@yahoo.com> wrote:
> Hi, is nthookengine released under any specific license? any limitations? thanks for any info -Dave
*/



//It uses the x86/x64 GPL disassembler engine
//diStorm was written by Gil Dabah. BSD License
//Copyright (C) 2003-2012 Gil Dabah. diStorm at gmail dot com.
/*
 BSD License:
	Permissive: You can use the software for any purpose, modify it, and redistribute it, even commercially.
	Attribution required: You must credit the original authors.
	No copyleft: Unlike the GPL, you don’t have to release your modified code under the same license.
	Disclaimer of warranty: The software is provided “as is” without any warranty.
*/

//Mods by David Zimmer <dzzie@yahoo.com>
//extern "C" {
	enum hookType { ht_jmp = 0, ht_pushret = 1, ht_jmp5safe = 2, ht_jmpderef = 3, ht_micro };
	enum hookErrors { he_None = 0, he_cantDisasm, he_cantHook, he_maxHooks, he_UnknownHookType };
	extern hookErrors lastErrorCode;
	extern int logLevel;

	//extern void InitHookEngine(void); handled automatically now...
	extern void(__cdecl* debugMsgHandler)(char* msg);
	extern char* __cdecl GetHookError(void);
	extern char* __cdecl GetDisasm(ULONG_PTR pAddress, int* retLen = NULL);
	extern int __cdecl DisableHook(ULONG_PTR Function);
	extern void __cdecl EnableHook(ULONG_PTR Function);
	extern ULONG_PTR __cdecl GetOriginalFunction(ULONG_PTR Hook);
	extern BOOL __cdecl HookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction, char* name, enum hookType ht);
//}
