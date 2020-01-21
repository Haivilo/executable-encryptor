#include<Windows.h>
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
typedef struct{
	DWORD baseAddr;
	DWORD startOffset;
	PIMAGE_SECTION_HEADER stubSec;
	StubConf* conf;
}stubinfo;
class pE
{
public:
	bool rdfile();
	void rdDll();
	void addShell(pE& dllPe);
	bool addSection(unsigned int secSize = 0, const char* title="handsome");
	bool dump(const char* newpath = "123.exe");
	void input(pE &dllPe);
	void input(byte* src, const char * name, unsigned int size);
	PIMAGE_SECTION_HEADER findSec(const char* name);
	const char* path;
	void crepsEncryptAll(DWORD count, StubConf* g_conf, ...);
	void crepsEncryptAll(StubConf* g_conf);
	void EncryptBuffer(unsigned char* buffer, int size);
private:
	void EncryptTEA(unsigned int *firstChunk, unsigned int *secondChunk, unsigned int* key);
	unsigned int *key = (unsigned int *)"testkey123456789";
	unsigned char* FileBuffer=nullptr;
	unsigned int size;
	DWORD getAllignedVal(DWORD targetSize, DWORD singleUnit);
	PIMAGE_DOS_HEADER head;
	PIMAGE_NT_HEADERS nthead;
	PIMAGE_OPTIONAL_HEADER ophead;
	PIMAGE_FILE_HEADER fhead;
	PIMAGE_SECTION_HEADER sec1st;
	void initVars(unsigned char* buffer, DWORD Newsize = 0);
	void fixReloc(pE& filePe);
	void fixReloc(DWORD imgBase, DWORD offset);
	stubinfo dllstub;
	char* buffCompressed;
	unsigned int sizeCompressed;
	int ApLib(char * pData, char* &target, int nSize, int& outSize);
	int ApDecode(char * pData, int nSize);
	void cpresAndEncrypt(PIMAGE_SECTION_HEADER secTarget);
	void allignSecs(PIMAGE_SECTION_HEADER secTarget);
	void changeRelocTb(pE& dllPe);
};
