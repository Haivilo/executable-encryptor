#pragma once
#include <windows.h>

typedef struct StubConf
{
	DWORD oep;
	unsigned int key2[4];
	DWORD startAddr[10];
	DWORD size[10];
	BYTE  key;
	IMAGE_DATA_DIRECTORY relocDir;
	IMAGE_DATA_DIRECTORY importDir;
	DWORD oldimgbase;

}StubConf;