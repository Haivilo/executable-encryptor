#include <windows.h>
class pedll
{
public:
	void ldDll(char* tarpath);
private:
	char* path;
	byte* dllbuff;
};
