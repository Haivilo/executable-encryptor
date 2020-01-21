#include"PEstruct.h"
#include"aplib.h"
#pragma comment(lib,"aplib.lib")



bool pE::rdfile(){
	HANDLE File = CreateFileA(path, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (File == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, L"file does not exist",0,0);
		return 0;
	}
	//clean prev usage
	
	size = GetFileSize(File, NULL);

	byte* fbuff = new BYTE[size];
	//get the content from File
	DWORD RealRead = 0;
	ReadFile(File, fbuff, size, &RealRead, NULL);
	CloseHandle(File);
	initVars(fbuff);
	return 1;
}
bool pE::addSection(unsigned int secSize,const char* title){
	if (!secSize) 
		secSize = 0x600;//default size of section if not provided.
	DWORD memGranularity = ophead->SectionAlignment;
	DWORD fileGranularity = ophead->FileAlignment;
	DWORD memSize = getAllignedVal(secSize,memGranularity);
	DWORD fileSize = getAllignedVal(secSize, fileGranularity);
	int a = fhead->NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
	
	//PIMAGE_SECTION_HEADER secNew = PIMAGE_SECTION_HEADER((byte*)sec1st + fhead->NumberOfSections*sizeof(IMAGE_SECTION_HEADER));
	PIMAGE_SECTION_HEADER secNew = sec1st + fhead->NumberOfSections;
	
	//ptr to raw data : prev sec ptr + size
	secNew->PointerToRawData = (secNew - 1)->PointerToRawData + (secNew - 1)->SizeOfRawData;
	
	//misc,size = filesize
	secNew->Misc.PhysicalAddress = secSize;
	secNew->SizeOfRawData = fileSize;
	
	//VA = prevVa + prev mem size
	secNew->VirtualAddress = (secNew - 1)->VirtualAddress + getAllignedVal((secNew - 1)->SizeOfRawData,memGranularity);
	
	//E0 00 00 E0 characteristic of sec
	secNew->Characteristics = 0xe00000e0;
	
	//numofSections ++
	fhead->NumberOfSections++;
	
	//sizeofimage ++ 
	ophead->SizeOfImage += memSize;
	
	DWORD titleLen = strlen(title);
	//if title is smaller enough, add title
	if (titleLen <= 8)
		memcpy(&secNew->Name, title, titleLen);
	
	byte* fnew = new byte[size + fileSize];
	//add 0 in the end
	memset(fnew+size, 0, fileSize);
	//copy to a longer buffer;
	memcpy(fnew, FileBuffer, size);

	initVars(fnew,size+fileSize);
	
	return 1;

}

DWORD pE::getAllignedVal(DWORD targetSize, DWORD singleUnit){
	//get The Aligned value
	return targetSize%singleUnit ? (targetSize / singleUnit+1)*singleUnit : targetSize;
	//not already allgned  :  x/gran*(gran+1)
	//else: return x 
}
void pE::initVars(unsigned char* buffer,DWORD Newsize){
	if (FileBuffer)
		delete[] FileBuffer;
	if (Newsize)
		size = Newsize;
																//init all ptr variables
	FileBuffer = buffer;
	head = (PIMAGE_DOS_HEADER)FileBuffer;
	nthead = (PIMAGE_NT_HEADERS)(head->e_lfanew + FileBuffer);
	sec1st = IMAGE_FIRST_SECTION(nthead);
	ophead = &nthead->OptionalHeader;
	fhead = &nthead->FileHeader;
}
bool pE::dump(const char* newpath){
	HANDLE File = CreateFileA("123.exe", GENERIC_READ|GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, NULL, NULL);

	DWORD written = 0;
	WriteFile(File, FileBuffer, size, &written, 0);
	//create file,dump

	CloseHandle(File);
	return 1;
}

PIMAGE_SECTION_HEADER pE::findSec(const char* name){
	PIMAGE_SECTION_HEADER tempsec = sec1st;				//get 1st sec
	for (size_t i = 0; i < fhead->NumberOfSections; i++)
	{
		char nameSec[9] = "\0";
		memcpy(nameSec, tempsec->Name, 8);				//receive name str and compare
		if (!strcmp(nameSec, name)){
			return tempsec;
		}
		tempsec++;
	}
	return 0;
}

void pE::rdDll(){
	byte* buff;
	buff = (byte*)LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!buff)
		MessageBox(0, L"ldDll failed", 0, 0);
	else{
		initVars(buff);
												//init dll info
		dllstub.baseAddr = (DWORD)FileBuffer;
		dllstub.stubSec = findSec(".text");
		dllstub.startOffset = (DWORD)GetProcAddress((HMODULE)buff, "start")-dllstub.baseAddr-dllstub.stubSec->VirtualAddress;
		dllstub.conf = (StubConf*)GetProcAddress((HMODULE)buff, "g_conf");
	}
}

void pE::fixReloc(pE& filePe){
	DWORD imgBase = filePe.ophead->ImageBase;
	DWORD offset = filePe.findSec("shell")->VirtualAddress;
	DWORD oldimgbase = ophead->ImageBase;
	DWORD oldoffset = dllstub.stubSec->VirtualAddress;
																	//get reloc table
	IMAGE_BASE_RELOCATION* pRel = (IMAGE_BASE_RELOCATION*)
		(ophead->DataDirectory[5].VirtualAddress
		+ FileBuffer);
	while (pRel->SizeOfBlock)
	{
		typedef struct {
			WORD offset : 12;
			WORD type : 4;
		}TypeOffset;

		DWORD dwCount = (pRel->SizeOfBlock - 8) / 2;
		TypeOffset* pTypeOfs =
			(TypeOffset*)(pRel + 1);									//find size

		DWORD oldMem = 0;
		for (DWORD i = 0; i<dwCount; ++i)
		{
			if (pTypeOfs[i].type == 3)									//type must  = 3
			{

				DWORD* pFixAddr = (DWORD*)(pRel->VirtualAddress + pTypeOfs[i].offset + FileBuffer);
																		//get addr(base + Section RVA + offset)
				VirtualProtect(pFixAddr, 4, PAGE_READWRITE, &oldMem);	
				*pFixAddr = *pFixAddr + imgBase + offset - oldimgbase - oldoffset;	
				VirtualProtect(pFixAddr, 4, oldMem, &oldMem);
			}
		}

		//**********************************************************************************
		VirtualProtect(pRel, 4, PAGE_READWRITE, &oldMem);
		pRel->VirtualAddress = pRel->VirtualAddress+offset - oldoffset;					//change reloc table
		VirtualProtect(pRel, 4, oldMem, &oldMem);
		//change offset, not needed if no random imgbase.
		//only for repairing dll reloc
		//**********************************************************************************

		pRel = (IMAGE_BASE_RELOCATION*)
			((DWORD)pRel + pRel->SizeOfBlock);					//next reloc table

	}
}
void pE::changeRelocTb(pE& dllPe){
	IMAGE_DATA_DIRECTORY reloctb = dllPe.ophead->DataDirectory[5];
	addSection(reloctb.Size, "reloc");
	input(dllPe.FileBuffer + reloctb.VirtualAddress, "reloc", reloctb.Size);
	DWORD offset = findSec("reloc")->VirtualAddress;
	ophead->DataDirectory[5].VirtualAddress = offset;
	ophead->DataDirectory[5].Size = reloctb.Size;
}

void pE::fixReloc(DWORD imgBase, DWORD offset){

}

void pE::input(pE &dllPe){
	//take  dll ".text" section to exe ".shell" section
	DWORD buffer = dllPe.dllstub.baseAddr + dllPe.dllstub.stubSec->VirtualAddress;
	DWORD buffersize = dllPe.dllstub.stubSec->Misc.PhysicalAddress;
	DWORD foffset = findSec("shell")->PointerToRawData;
	memcpy(FileBuffer + foffset, (void*)buffer, buffersize);
}

void pE::input(byte* src, const char * name, unsigned int size){
	PIMAGE_SECTION_HEADER head = findSec("reloc");								//memset to 0 first for designated section
	if (!head)
		MessageBoxA(0, "sec not found", 0, 0);
	memset(FileBuffer + head->PointerToRawData, 0, head->SizeOfRawData);		//memcpy for size(not alligned)
	memcpy(FileBuffer + head->PointerToRawData, src, size);
}
void pE::addShell(pE& dllPe){
	//1. change reloc, import addr, imgbase, oep
	//2. disable import, change reloc in PE head
	//3. encrypt all secs(chars changed in func)
	//4. change key
	//5. add section
	//6. change exe oep
	//7. fix reloc, based on added sec
	
	dllPe.dllstub.conf->relocDir = ophead->DataDirectory[5];
	dllPe.dllstub.conf->importDir = ophead->DataDirectory[1];
	ophead->DataDirectory[1].VirtualAddress = 0;

	dllPe.dllstub.conf->oldimgbase = ophead->ImageBase;
	dllPe.dllstub.conf->oep = ophead->AddressOfEntryPoint;
	memcpy(dllPe.dllstub.conf->key2, key, 16);


	//crepsEncryptAll(1, dllPe.dllstub.conf, ".text");
	crepsEncryptAll(dllPe.dllstub.conf);
	addSection(dllPe.dllstub.stubSec->Misc.PhysicalAddress, "shell");			//add section to exe
	dllPe.fixReloc(*this); 
	changeRelocTb(dllPe);
	//fix reloc, based on "shell" RVA 


	DWORD offset = findSec("shell")->VirtualAddress;

	for (size_t i = 0; i < 15; i++)
	{
		if (i!=5)
		{
			ophead->DataDirectory[i].VirtualAddress = 0;
		}
	}

	ophead->AddressOfEntryPoint =
		offset + dllPe.dllstub.startOffset;										//change oep

	input(dllPe);
	dump();

	//StubConf* conf = (StubConf*)GetProcAddress((HMODULE)dllPe.FileBuffer, "g_conf");
																				//conf->oep,encrypt addr&size,key


	
	//char* compressedPtr;
	//int sizeAfterCpres;
	//ApLib((char*)FileBuffer + txtSec->PointerToRawData, compressedPtr, txtSec->Misc.PhysicalAddress, sizeAfterCpres);
	//DWORD newsize = getAllignedVal(sizeAfterCpres, ophead->FileAlignment);
	//memcpy(FileBuffer + txtSec->PointerToRawData, compressedPtr, sizeAfterCpres);
	//ApDecode(compressedPtr, sizeAfterCpres);
	//EncryptBuffer(FileBuffer + txtSec->PointerToRawData, txtSec->Misc.PhysicalAddress);


	//PIMAGE_SECTION_HEADER txtSec = findSec(".text");
	//conf->startAddr[0] = txtSec->VirtualAddress;
	//conf->size[0] = txtSec->Misc.PhysicalAddress;
	//disable random imagebase
	//ophead->DllCharacteristics &= (~0x40);
	//txtSec->Characteristics |= 0xe0000000;										//change .text characts, 
	//able to write in

}

void pE::crepsEncryptAll(DWORD count,StubConf* g_conf, ...){
	va_list args;																	   //get sections strings
	va_start(args, count);															 
	char** secLs = new char*[count];												 
	for (int i = 0; i < count; i++)													 
	{																				 
		char* id = va_arg(args, char*);												 
		secLs[i] = id;																 
	}																				 
	PIMAGE_SECTION_HEADER secTemp = sec1st;											   //get first section header
	DWORD encryptCount = -1;
	for (size_t i = 0; i < fhead->NumberOfSections; i++)							
	{			

		for (size_t i = 0; i < count; i++)											   //compare section name and strs
		{																				//if equal -> encrypt
			char title[9] = "\0";												
			memcpy(title, secTemp->Name, 8);									
			if (!strcmp(secLs[i], title)){										
				cpresAndEncrypt(secTemp);													//sec infos are all fixed values after encryption
				encryptCount++;																//(VA,sized),file ptr needs to be alligned later
				g_conf->startAddr[encryptCount] = secTemp->VirtualAddress;					//count encrypt index
				g_conf->size[encryptCount] = secTemp->Misc.PhysicalAddress;					//input to g_conf for specified index
				secTemp->Characteristics |= 0xe0000000;										//change .text characts, 
				break;
			 }																	
		}																		
		if (i){																	
			allignSecs(secTemp);													   //if not first section
		}																			   //move section upwards, in case of compression
		secTemp++;																	   
	}																				   
	size = (secTemp - 1)->PointerToRawData + (secTemp - 1)->SizeOfRawData;			   //change size to new size
} 

void pE::crepsEncryptAll(StubConf* g_conf){
	PIMAGE_SECTION_HEADER secTemp = sec1st;			//get first section header
	DWORD count = 0;
	for (size_t i = 0; i < fhead->NumberOfSections; i++)								
	{				
																	//sec infos are all fixed values after encryption
		if (i!=3)
		{
		cpresAndEncrypt(secTemp);														//(VA,sizes are good),file ptr needs to be alligned later
		g_conf->startAddr[count] = secTemp->VirtualAddress;									//count encrypt index
		g_conf->size[count] = secTemp->Misc.PhysicalAddress;								//input to g_conf for specified index
		secTemp->Characteristics |= 0xe0000000;											//change .text characts, 
		
		count++;
		}
		if (i){
			allignSecs(secTemp);													   //if not first section
		}																			   //move section upwards, in case of compression
		secTemp++;
	}
	size = (secTemp - 1)->PointerToRawData + (secTemp - 1)->SizeOfRawData;			   //change size to new size
}

void pE::cpresAndEncrypt(PIMAGE_SECTION_HEADER secTarget){
	char* compressedPtr;
	int sizeAfterCpres;
	ApLib((char*)FileBuffer + secTarget->PointerToRawData, compressedPtr, secTarget->SizeOfRawData, sizeAfterCpres);
	EncryptBuffer((unsigned char*)compressedPtr, sizeAfterCpres);						   //cmpres and encrypt
																						   //
	secTarget->Misc.PhysicalAddress = sizeAfterCpres;									   //change misc, real size
	DWORD newsize = getAllignedVal(sizeAfterCpres, ophead->FileAlignment);				   //change realsize to allgned size
	secTarget->SizeOfRawData = newsize;													   //change file size
																						   //
	memset(FileBuffer + secTarget->PointerToRawData,0,newsize); 						   //clean to 0 for target destination
	memcpy(FileBuffer + secTarget->PointerToRawData, compressedPtr, sizeAfterCpres);	   //cpy to des
	//在外面改掉这个区段的ptrdata，里面别动
}

void pE::allignSecs(PIMAGE_SECTION_HEADER secTarget){
	byte* src = secTarget->PointerToRawData + FileBuffer;
	DWORD desoffset = (secTarget - 1)->PointerToRawData + (secTarget - 1)->SizeOfRawData;
	byte* des = FileBuffer + desoffset;
	memcpy(des, src, secTarget->SizeOfRawData);
	//memset(des + secTarget->Misc.PhysicalAddress, 0, secTarget->SizeOfRawData - secTarget->Misc.PhysicalAddress);
	secTarget->PointerToRawData = desoffset;
}

void pE::EncryptTEA(unsigned int *firstChunk, unsigned int *secondChunk, unsigned int* key)
{
	unsigned int y = *firstChunk;
	unsigned int z = *secondChunk;
	unsigned int sum = 0;

	unsigned int delta = 0x9e3779b9;

	for (int i = 0; i < 8; i++)
	{
		sum += delta;
		y += ((z << 4) + key[0]) ^ (z + sum) ^ ((z >> 5) + key[1]);
		z += ((y << 4) + key[2]) ^ (y + sum) ^ ((y >> 5) + key[3]);
	}

	*firstChunk = y;
	*secondChunk = z;
}




void DecryptTEA(unsigned int *firstChunk, unsigned int *secondChunk, unsigned int* key)
{
	unsigned int  sum = 0;
	unsigned int  y = *firstChunk;
	unsigned int  z = *secondChunk;
	unsigned int  delta = 0x9e3779b9;

	sum = delta << 3; 

	for (int i = 0; i < 8; i++)
	{
		z -= (y << 4) + key[2] ^ y + sum ^ (y >> 5) + key[3];
		y -= (z << 4) + key[0] ^ z + sum ^ (z >> 5) + key[1];
		sum -= delta;
	}

	*firstChunk = y;
	*secondChunk = z;
}




void pE::EncryptBuffer(unsigned char* buffer, int size)
{
	unsigned char *p = buffer;

	int leftSize = size;

	while (p < buffer + size &&
		leftSize >= sizeof(unsigned int) * 2)
	{
		EncryptTEA((unsigned int *)p, (unsigned int *)(p + sizeof(unsigned int)), key);
		p += sizeof(unsigned int) * 2;

		leftSize -= sizeof(unsigned int) * 2;
	}
}


void DecryptBuffer(char* buffer, int size, unsigned int* key)
{
	char *p = buffer;

	int leftSize = size;

	while (p < buffer + size &&
		leftSize >= sizeof(unsigned int) * 2)
	{
		DecryptTEA((unsigned int *)p, (unsigned int *)(p + sizeof(unsigned int)), key);
		p += sizeof(unsigned int) * 2;

		leftSize -= sizeof(unsigned int) * 2;
	}
}


int pE::ApLib(char * pData, char* &target, int nSize, int& outSize)
{
	PCHAR pCloneData = NULL;
	UINT m_nSpaceSize = NULL;
	m_nSpaceSize = aP_workmem_size(nSize);                                               //计算工作空间大小
	CHAR *	m_pWorkSpace = (char*)VirtualAlloc(0, m_nSpaceSize, MEM_COMMIT, 0x40);       //申请工作空间

	target = (char*)VirtualAlloc(0, nSize * 2, MEM_COMMIT, 0x40);                    //申请工作空间
	memset(target, 0, nSize * 2);
	pCloneData = (char*)VirtualAlloc(0, nSize, MEM_COMMIT, 0x40);
	memcpy(pCloneData, pData, nSize);                    //复制原始数据到新空间
	//对原始数据进行压缩
	outSize = aPsafe_pack((PBYTE)pCloneData, (PBYTE)target, nSize, (PBYTE)m_pWorkSpace, 0, 0);
	VirtualFree(pCloneData, nSize, 0x4000);               // 释放空间
	pCloneData = NULL;
	if (target == 0) return 0; //压缩过程中发现错误

	return outSize;
}

int pE::ApDecode(char * pData, int nSize)
{
	UINT m_nSpaceSize = NULL;
	m_nSpaceSize = aP_workmem_size(nSize);               //计算工作空间大小
	CHAR *	m_pWorkSpace = new CHAR[m_nSpaceSize];       //申请工作空间

	size_t orig_size = aPsafe_get_orig_size(pData);     //解压后数据的大小
	char *data = new char[orig_size];

	int outlength = aPsafe_depack(pData, nSize, data, orig_size);

	return 0;
}
unsigned int pSize = 0;
