#include"encryptShell.h"

void pedll::ldDll(char* tarpath){
	dllbuff = (byte*)LoadLibraryExA(tarpath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!dllbuff)
		MessageBox(0, L"ldDll failed", 0, 0);
}

