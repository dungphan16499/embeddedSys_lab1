#include "Windows.h"
#include <stdlib.h>
#include <stdio.h>
#include <winnt.h>

int main() {

	const char *fileName = "C:\\Users\\dungphan16499\\source\\repos\\MasterClass1\\pyshellext.amd64.dll" ;
	//const char* fileName = "C:\\Users\\dungphan16499\\source\\repos\\MasterClass1\\esscli.dll";
	//const char *fileName = "C:\\Users\\dungphan16499\\source\\repos\\MasterClass1\\Realterm.exe";
	HANDLE file = NULL;
	DWORD fileSize= NULL;
	DWORD bytesRead, bytesRead1  = NULL;
	//DWORD dwPos;
	LPVOID fileData= NULL;
	PIMAGE_DOS_HEADER dosHeader = {}; 
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader, sectionHeader2 = {};
	PIMAGE_SECTION_HEADER importSection, importSection2 = {};

	

	FILE* f;
	FILE* fbin;
	errno_t err = fopen_s(&f, "fOut.txt", "w+");

	if (f == NULL)
	{
		fprintf(f, "Error opening file!\n");
		exit(1);
	}

	errno_t err1 = fopen_s(&fbin, "bincode.bin", "w+");

	if (fbin == NULL)
	{
		fprintf(fbin, "Error opening file!\n");
		exit(1);
	}


	// open file
	file = CreateFileA(fileName,
		GENERIC_ALL,
		FILE_SHARE_READ, // Enables subsequent open operations on a file or device to request read access
		NULL, // the file or device associated with the returned handle is assigned a default security descriptor.
		OPEN_EXISTING, // Opens a file or device, only if it exists.
		FILE_ATTRIBUTE_NORMAL,  //default value --> can include any combination of the available file attributes
		NULL);

	
	if (file == INVALID_HANDLE_VALUE)
		fprintf(f, "Fail to read file");

	// allocate heap
	fileSize = GetFileSize(file, // Retrieves the size of the specified file, in bytes
							NULL); // A pointer to the variable where the high - order doubleword of the file size is returned --> the application does not require the high-order doubleword. ==> NULL
	
	fileData = HeapAlloc(GetProcessHeap(),  //A handle to the heap from which the memory will be allocated.
						NULL,
						fileSize);

	ReadFile(file,
		fileData,
		fileSize,
		&bytesRead,
		NULL);

	// IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;

	// IMAGE_NT_HEADERS
	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);


	// FILE_HEADER
	//fprintf(f,"\n----------- FILE HEADER -----------\n");
	//fprintf(f, "\t0x%x\t\tCharacteristics\n", imageNTHeaders->FileHeader.Characteristics);
	// OPTIONAL_HEADER
	
	fprintf(f, "\n------------ OPTIONAL HEADER ------------\n");
	fprintf(f,"\t0x%x\t\tAddress Of Entry Point (.text)\n", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);	
	//fprintf(f, "\t0x%x\t\tBase Of Code\n", imageNTHeaders->OptionalHeader.BaseOfCode);
	//fprintf(f, "\t0x%x\t\tImage Base\n", imageNTHeaders->OptionalHeader.ImageBase);


	// SECTION_HEADERS
	fprintf(f, "\n------------ SECTION HEADERS ------------\n");
	// get offset to first section header
	DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader; //move the pointer to section
	DWORD sectionLocation2 = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	//DWORD importDirectoryRVA2 = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	
	// print section data
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		/*PIMAGE_SECTION_HEADER sectionHeader2 = sectionHeader;
		if ((sectionHeader2->Characteristics & 0x20) == 0x20)		
			for (DWORD k = 0; k < sectionHeader2->SizeOfRawData; k+=sizeof(WORD)) ////Check again
			{
				fprintf(fbin, "0x% p:\t% llx\n", sectionHeader2 + k , *(sectionHeader2 + k));
				printf("0x%p:\t%llx\n", sectionHeader2 + k , *(sectionHeader2 + k));
			}
			*/

		fprintf(f, "\t%s\n", sectionHeader->Name);
		//fprintf(f, "\t\t0x%x\t\tPhysical Address\n", sectionHeader->Misc.PhysicalAddress);
		fprintf(f, "\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
		fprintf(f, "\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
		fprintf(f, "\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);

		fprintf(f, "\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
		fprintf(f, "\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations); //The file pointer to the beginning of relocation entries for the section. This is set to zero for executable images or if there are no relocations.
		fprintf(f, "\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
		fprintf(f, "\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
		fprintf(f, "\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
		fprintf(f, "\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);
		

		// save section that contains import directory table
	/*f (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}*/
		sectionLocation += sectionSize;
		
	}
	fclose(f);

	unsigned long long int* ptr;
	ptr = (unsigned long long int*)sectionLocation2;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader2 = (PIMAGE_SECTION_HEADER)sectionLocation2; 
		//PIMAGE_SECTION_HEADER sectionHeader2 = sectionHeader;
		DWORD size = sectionHeader2->SizeOfRawData;
		//char letter[100000];
		if ((sectionHeader2->Characteristics & 0x20) == 0x20)
			/*for (unsigned long int k = 0; k < sectionHeader2->SizeOfRawData; k += sizeof(WORD))
			{
				fprintf(fbin, "%llx\n", *(sectionHeader2 + k));
				printf("%llx\n", *(sectionHeader2 + k));
			}*/
			for (unsigned long long int k = 0; k < (unsigned long long int)size; k+=2)
			{
				//Create variables to save symbols in ASCII code
				char c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16;
				unsigned long long int tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9, tmp10, tmp11, tmp12, tmp13, tmp14, tmp15, tmp16;
				tmp1 = *(ptr + k) & 0xFF00000000000000;
				c1 = (*(ptr + k) & 0xFF00000000000000) >> 56;
				c2 = (*(ptr + k) & 0x00FF000000000000) >> 48;
				tmp2 = * (ptr + k) & 0x00FF000000000000;
				c3 = (*(ptr + k) & 0x0000FF0000000000) >> 40;
				tmp3 = *(ptr + k) & 0x0000FF0000000000;
				c4 = (*(ptr + k) & 0x000000FF00000000) >> 32;
				tmp4 = *(ptr + k) & 0x000000FF00000000;
				c5 = (*(ptr + k) & 0x00000000FF000000) >> 24;
				tmp5 = *(ptr + k) & 0x00000000FF000000;
				c6 = (*(ptr + k) & 0x0000000000FF0000) >> 16;
				tmp6 = *(ptr + k) & 0x0000000000FF0000;
				c7 = (*(ptr + k) & 0x000000000000FF00) >> 8;
				tmp7 =  *(ptr + k) & 0x000000000000FF00;
				c8 = (*(ptr + k) & 0x00000000000000FF) >> 0;
				tmp8 =  *(ptr + k) & 0x00000000000000FF;

				tmp9 = *(ptr + k+1) & 0xFF00000000000000;
				c9 = (*(ptr + k+1) & 0xFF00000000000000) >> 56;
				c10 = (*(ptr + k+1) & 0x00FF000000000000) >> 48;
				tmp10 = *(ptr + k+1) & 0x00FF000000000000;
				c11 = (*(ptr + k+1) & 0x0000FF0000000000) >> 40;
				tmp11 = *(ptr + k+1) & 0x0000FF0000000000;
				c12 = (*(ptr + k+1) & 0x000000FF00000000) >> 32;
				tmp12 = *(ptr + k+1) & 0x000000FF00000000;
				c13 = (*(ptr + k+1) & 0x00000000FF000000) >> 24;
				tmp13 = *(ptr + k+1) & 0x00000000FF000000;
				c14 = (*(ptr + k+1) & 0x0000000000FF0000) >> 16;
				tmp14 = *(ptr + k+1) & 0x0000000000FF0000;
				c15 = (*(ptr + k+1) & 0x000000000000FF00) >> 8;
				tmp15 = *(ptr + k+1) & 0x000000000000FF00;
				c16 = (*(ptr + k+1) & 0x00000000000000FF) >> 0;
				tmp16 = *(ptr + k+1) & 0x00000000000000FF;

				fprintf(fbin,"%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", c8, c7, c6, c5, c4, c3, c2, c1, c16, c15, c14, c13, c12, c11, c10, c9);
			}

		/*if (importDirectoryRVA2 >= sectionHeader2->VirtualAddress && importDirectoryRVA2 < sectionHeader2->VirtualAddress + sectionHeader2->Misc.VirtualSize) {
			importSection2 = sectionHeader2;
		}*/

		sectionLocation2 += sectionSize;
	}
	
	CloseHandle(file);
	fclose(fbin);
	
	return 0;
}
