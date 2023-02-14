#include "pe_info.h"
#include <Windows.h>
#include <iostream>
#include <algorithm>
#include <Dbghelp.h>

#pragma comment(lib,"imageHlp.lib")


HANDLE ImageBase;
PIMAGE_DOS_HEADER pDH = NULL;
PIMAGE_NT_HEADERS pNTH = NULL;
PIMAGE_FILE_HEADER pFH = NULL;
PIMAGE_OPTIONAL_HEADER pOH = NULL;
PIMAGE_SECTION_HEADER pSH = NULL;
PIMAGE_IMPORT_DESCRIPTOR pID = NULL;
PIMAGE_EXPORT_DIRECTORY pED = NULL;
PIMAGE_THUNK_DATA dwThunk;
PIMAGE_IMPORT_BY_NAME pBN = NULL;


bool PE_info::Is_PE_file(LPTSTR lpFilePath) {
	HANDLE hFile;
	HANDLE hMapping;

	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;

	hFile = CreateFile(lpFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf_s("CreateFile failed with %d\n", GetLastError());
	}
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == INVALID_HANDLE_VALUE) {
		printf_s("CreateFileMapping failed with %d\n", GetLastError());
	}
	ImageBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (ImageBase == INVALID_HANDLE_VALUE) {
		CloseHandle(hMapping);
		CloseHandle(hFile);
		printf_s("MapViewOfFile failed with %d\n", GetLastError());
	}
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return false;
	}
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return false;
	}
	return true;
}

void PE_info::SHOW_DOS_HEADER() {
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	std::cout << "----------------------IMAGE DOS HEADER------------------------" << '\n';
	printf_s("\t0x%x\t\tMagic number\n", pDH->e_magic);
	printf_s("\t0x%x\t\tBytes on last page of file\n", pDH->e_cblp);
	printf_s("\t0x%x\t\tPages in file\n", pDH->e_cp);
	printf_s("\t0x%x\t\tRelocations\n", pDH->e_crlc);
	printf_s("\t0x%x\t\tSize of header in paragraphs\n", pDH->e_cparhdr);
	printf_s("\t0x%x\t\tMinimum extra paragraphs needed\n", pDH->e_minalloc);
	printf_s("\t0x%x\t\tMaximum extra paragraphs needed\n", pDH->e_maxalloc);
	printf_s("\t0x%x\t\tInitial (relative) SS value\n", pDH->e_ss);
	printf_s("\t0x%x\t\tInitial SP value\n", pDH->e_sp);
	printf_s("\t0x%x\t\tInitial SP value\n", pDH->e_sp);
	printf_s("\t0x%x\t\tChecksum\n", pDH->e_csum);
	printf_s("\t0x%x\t\tInitial IP value\n", pDH->e_ip);
	printf_s("\t0x%x\t\tInitial (relative) CS value\n", pDH->e_cs);
	printf_s("\t0x%x\t\tFile address of relocation table\n", pDH->e_lfarlc);
	printf_s("\t0x%x\t\tOverlay number\n", pDH->e_ovno);
	printf_s("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", pDH->e_oemid);
	printf_s("\t0x%x\t\tOEM information; e_oemid specific\n", pDH->e_oeminfo);
	printf_s("\t0x%x\t\tFile address of new exe header\n", pDH->e_lfanew);
}

void PE_info::SHOW_NT_HEADER() {
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	std::cout << '\n';
	std::cout << "NT header:" << '\n';
	SHOW_FILE_HEADER();
	SHOW_OPTIONAL_HEADER();
}

void PE_info::SHOW_FILE_HEADER() {

	pFH = &pNTH->FileHeader;
	if (!pFH) {
		return;
	}
	std::cout << '\n';
	std::cout << "IMAGE FILE HEADER: " << '\n';

	if (pFH->Machine == 332) {
		std::cout << "				Machine: x86 " << '\n';
	}
	else if (pFH->Machine == 512) 
	{
		std::cout << "				Machine: Intel Itanium " << '\n';
	}
	else if (pFH->Machine == 34404)
	{
		std::cout << "				Machine: x64 " << '\n';
	}

	std::cout << "					Number of Section: " << std::hex << pFH->NumberOfSections << '\n';
	std::cout << "					TImeDataStamp: " << std::hex << pFH->TimeDateStamp << '\n';
	std::cout << "					SizeofOptionalHeader: " << std::hex << pFH->SizeOfOptionalHeader << '\n';
	std::cout << "					Characteristics: " << std::hex << pFH->Characteristics << '\n';
}

void PE_info::SHOW_OPTIONAL_HEADER() {
	pOH = &pNTH->OptionalHeader;
	std::cout << '\n';
	std::cout << "IMAGE OPTINAL header: " << '\n';
	std::cout << "					Magic:" << std::hex << pOH->Magic << '\n';
	std::cout << "					MajorLinkerVersion:" << std::hex << pOH->MajorLinkerVersion << '\n';
	std::cout << "					MinorLinkerVersion:" << std::hex << pOH->MinorLinkerVersion << '\n';
	std::cout << "					SizeOfCode:" << std::hex << pOH->SizeOfCode << '\n';
	std::cout << "					SizeOfInitializedData:" << std::hex << pOH->SizeOfInitializedData << '\n';
	std::cout << "					SizeOfUninitializedData:" << std::hex << pOH->SizeOfUninitializedData << '\n';
	std::cout << "					AddressOfEntryPoint:" << std::hex << pOH->AddressOfEntryPoint << '\n';
	std::cout << "					BaseOfCode:" << std::hex << pOH->BaseOfCode << '\n';
	std::cout << "					BaseOfData:" << std::hex << pOH->BaseOfData << '\n';
	std::cout << "					ImageBase:" << std::hex << pOH->ImageBase << '\n';
	std::cout << "					SectionAlignment:" << std::hex << pOH->SectionAlignment << '\n';
	std::cout << "					FileAlignment:" << std::hex << pOH->FileAlignment << '\n';
	std::cout << "					MajorOperatingSystemVersion:" << std::hex << pOH->MajorOperatingSystemVersion << '\n';
	std::cout << "					MinorOperatingSystemVersion:" << std::hex << pOH->MinorOperatingSystemVersion << '\n';
	std::cout << "					MajorImageVersion:" << std::hex << pOH->MajorImageVersion << '\n';
	std::cout << "					MinorImageVersion:" << std::hex << pOH->MinorImageVersion << '\n';
	std::cout << "					MajorSubsystemVersion:" << std::hex << pOH->MajorSubsystemVersion << '\n';
	std::cout << "					MinorSubsystemVersion:" << std::hex << pOH->MinorSubsystemVersion << '\n';
	std::cout << "					Win32VersionValue:" << std::hex << pOH->Win32VersionValue << '\n';
	std::cout << "					SizeOfImage:" << std::hex << pOH->SizeOfImage << '\n';
	std::cout << "					SizeOfHeaders:" << std::hex << pOH->SizeOfHeaders << '\n';
	std::cout << "					CheckSum:" << std::hex << pOH->CheckSum << '\n';
	std::cout << "					Subsystem:" << std::hex << pOH->Subsystem << '\n';
	std::cout << "					DllCharacteristics:" << std::hex << pOH->DllCharacteristics << '\n';
	std::cout << "					SizeOfStackReserve:" << std::hex << pOH->SizeOfStackReserve << '\n';
	std::cout << "					SizeOfStackCommit:" << std::hex << pOH->SizeOfStackCommit << '\n';
	std::cout << "					SizeOfHeapReserve:" << std::hex << pOH->SizeOfHeapReserve << '\n';
	std::cout << "					SizeOfHeapCommit:" << std::hex << pOH->SizeOfHeapCommit << '\n';
	std::cout << "					LoaderFlags:" << std::hex << pOH->LoaderFlags << '\n';
	std::cout << "					NumberOfRvaAndSizes:" << std::hex << pOH->NumberOfRvaAndSizes << '\n';
	SHOW_DATADIR_INFO();
}

void PE_info::SHOW_DATADIR_INFO() {
	std::cout << "                  Data Directory:" << '\n';
	std:: cout << "                                 Export table RVA:" << std::hex << pOH->DataDirectory[0].VirtualAddress << '\n';
	std::cout << "                                 Export table size:" << std::hex << pOH->DataDirectory[0].Size << '\n';
	std::cout << "                                 Import table RVA:" << std::hex << pOH->DataDirectory[1].VirtualAddress << '\n';
	std::cout << "                                 Import table size:" << std::hex << pOH->DataDirectory[1].Size << '\n';
	std::cout << "                                 Resource table RVA:" << std::hex << pOH->DataDirectory[2].VirtualAddress << '\n';
	std::cout << "                                 Resource table size:" << std::hex << pOH->DataDirectory[2].Size << '\n';
}

void PE_info::SHOW_SECTIONS() {
	pSH = IMAGE_FIRST_SECTION(pNTH);
	std::cout << '\n';
	std::cout << "-------------------SECTION HEADER--------------------" << '\n';
	for (int i = 0; i < pFH->NumberOfSections; i++) {
		std::cout << "Section name:" << pSH->Name << '\n';
		std:: cout << "             Virtual Size:" << pSH->Misc.VirtualSize << '\n';
		std::cout << "             Virtual address:" << pSH->VirtualAddress << '\n';
		std::cout << "             SizeofRawData:" << pSH->SizeOfRawData << '\n';
		std::cout << "             PointertoRelocations:" << pSH->PointerToRelocations << '\n';
		std::cout << "             Characteristics:" << pSH->Characteristics << '\n';
		pSH++;
	}
}

void PE_info::SHOW_IMPORT_DIR_INFO() {
	DWORD dwDatastartRva;
	dwDatastartRva = pOH->DataDirectory[1].VirtualAddress;
	pID = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa(pNTH, ImageBase, dwDatastartRva, NULL);
	if (!pID) {
		int error = GetLastError();
		if (error == 0) {
			std::cout << "This file is not included with Import table!" << '\n';
		}
		else {
			std::cout << "Can't get Image Import Descriptor! error code: " << error << '\n';
		}
		return;
	}
	std::cout << '\n';
	std::cout << "------------------IMPORT DIR INFO-------------------" << '\n';
	while (pID->FirstThunk) {
		std::cout << "NameRva: " << std::hex << pID->Name << '\n';
		std::cout << "Name(String): " << std::hex << (char*)ImageRvaToVa(pNTH, ImageBase, pID->Name, NULL) << '\n';
		std::cout << "OrinalFirstThunk: " << std::hex << pID->OriginalFirstThunk << '\n';
		std::cout << "TimeDateStamp: " << std::hex << pID->TimeDateStamp << '\n';
		std::cout << "FirstThunk: " << std::hex << pID->FirstThunk << '\n';
		SHOW_IMPORT_FUNC();
		std::cout << '\n';
		pID++;
	}
}

void PE_info::SHOW_IMPORT_FUNC() {
	std::cout << "Function names:(IMAGE_IMPORT_BY_NAME) " << '\n';
	dwThunk = (PIMAGE_THUNK_DATA)ImageRvaToVa(pNTH, ImageBase, pID->OriginalFirstThunk, NULL);
	while (dwThunk->u1.AddressOfData) {
		pBN = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(pNTH, ImageBase, dwThunk->u1.AddressOfData, NULL);
		if (!pBN) {
			std::cout << "find Image Import by name failed! " << '\n';
			return;
		}
		std::cout << "               " << pBN->Name << '\n';
		dwThunk++;
	}
}

void PE_info::SHOW_EXPORT_DIR_INFO() {
	pED = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(pNTH, ImageBase, pOH->DataDirectory[0].VirtualAddress, NULL);
	if (!pED) {
		int error = GetLastError();
		if (error == 0) {
			std::cout << "This file is not included with Export table!" << '\n';
		}
		else {
			std::cout << "Can't get Export Directory error code: " << error << '\n';
		}
		return;
	}
	std::cout << '\n';
	std::cout << "------------------EXPORT DIR INFO-------------------" << '\n';
	std::cout << "Name: " << (char*)ImageRvaToVa(pNTH, ImageBase, pED->Name, NULL) << '\n';
	std::cout << "TimeDateStamp: " << std::hex << pED->TimeDateStamp << '\n';
	std::cout << "MajorVersion: " << std::hex << pED->MajorVersion << '\n';
	std::cout << "MinorVersion: " << std::hex << pED->MinorVersion << '\n';
	std::cout << "Base: " << std::hex << pED->Base << '\n';
	std::cout << "NumberofFunctions: " << std::hex << pED->NumberOfFunctions << '\n';
	std::cout << "NumberofNames: " << std::hex << pED->NumberOfNames << '\n';
	std::cout << "AddressofNames: " << std::hex << pED->AddressOfNames << '\n';
	std::cout << "AddressofFunctions: " << std::hex << pED->AddressOfFunctions << '\n';
	std::cout << "AddressofNameOrdinals: " << std::hex << pED->AddressOfNameOrdinals << '\n';
	SHOW_EXPORT_FUNC();
	
}

void PE_info::SHOW_EXPORT_FUNC() {
	PDWORD pdwFuncs, pdwNames;
	PWORD pdwOrd;

	pdwOrd = (PWORD)ImageRvaToVa(pNTH, ImageBase, pED->AddressOfNameOrdinals, NULL);
	pdwFuncs = (PDWORD)ImageRvaToVa(pNTH, ImageBase, pED->AddressOfFunctions, NULL);
	pdwNames = (PDWORD)ImageRvaToVa(pNTH, ImageBase, pED->AddressOfNames, NULL);

	for (int i = 0; i < (pED->NumberOfFunctions); i++) {
		if (*pdwFuncs) { //there is a function
			for (int j = 0; j < (pED->NumberOfNames); j++) {
				if (i == pdwOrd[j]) { // the jth element in the NameOridinal table is i
					std::cout << (char*)ImageRvaToVa(pNTH, ImageBase, pdwNames[j], NULL) << '\n';
				}
			}
		}
		pdwFuncs++;
	}
}