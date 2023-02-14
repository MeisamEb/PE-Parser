#include <windows.h>
#include <iostream>
#include "pe_info.h"


int main() {
	int argc = 0;
	LPWSTR* pArgvW = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc != 2) {
		std::cout << "Usage: PETool.exe sample.exe" << '\n';
		return 0;
	}
	LPTSTR lpFilePath = pArgvW[1];
	PE_info mype;
	if (mype.Is_PE_file(lpFilePath)) {
		std::cout << "This is PE format" << '\n';
		std::cout << "####################### start analyzing ######################" << '\n';
		std::cout << '\n';
		mype.SHOW_DOS_HEADER();
		mype.SHOW_NT_HEADER();
		mype.SHOW_SECTIONS();
		mype.SHOW_IMPORT_DIR_INFO();
		mype.SHOW_EXPORT_DIR_INFO();
	};
	LocalFree(pArgvW);

}