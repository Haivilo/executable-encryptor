#include"PEstruct.h"
int main(){
	
	pE mype;
	//mype.crepsEncryptAll(3, "123", "234", "435");
	mype.path = "C:\\Users\\Rongan Guo\\Desktop\\qqq.exe";
 	mype.rdfile();
	pE mydll;
 	mydll.path = "..\\Release\\shellDLl.dll";
	mydll.rdDll();
	mype.addShell(mydll);
	//mype.addSection(1800,"yeh");
	//mype.dump(); 

}