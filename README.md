# RealPE

  ## RealPE (Real Portable Executable) is a project aims to make PE file into a Shellcode (X64 and X86)

  ## Usage
  
  * RealPE.exe <exe_path> <output_shellcode_path>


  ## How does it works?
  
  * Combine the [reflective shellcode](https://github.com/yoavshah/RealPE#Shellcode) and the PE found at exe_path as follows

  <img align="center" src="https://github.com/yoavshah/PEReal/blob/master/images/project_diagram.png" />


  ## Shellcode

  * The Reflective Shellcode is based on [this project - by stephenfewer](https://github.com/stephenfewer/ReflectiveDLLInjection)

  * Search for PE header <b>down in memory<b>.

  * Copy PE headers to a new memory.

  * Copy each section to a new memory.

  * Build import table.

  * Reloc addresses.

  * Run AddressOfEntry.

  * NOTE: The code resolves functions by hash using [IMPORTLESS_API](https://github.com/yoavshah/importless_api)

  ## Shellcode build

  * The Shellcode was built using [this article](https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c).

  ### Shellcode build x86.

  * The article build x64 shellcode, so I changed some stuff to create a x86 shellcode.

  * ...\x86\cl.exe /c /FA /GS- main.cpp

  * Remove INCLUDELIB

  * Change the AlignRSP code in the article to this code and add it to be the first under _TEXT SEGMENT

  AlignRSP PROC
    push esi ; Preserve RSI since we're stomping on it
	mov esi, esp ; Save the value of RSP so it can be restored
	and esp, 0FFFFFFF8h ; Align RSP to 8 byte
	sub esp, 020h ; Allocate homing space for ExecutePayload
	call _main ; Call the entry point of the payload
	mov esp, esi ; Restore the original value of RSP
	pop esi ; Restore RSI
	ret
  AlignRSP ENDP

  * Remove all segments except _TEXT segment.

  * Add assume fs:nothing at the start of the file.


 ## TODO

 * Add encryption / compression algorithm for the PE file.

 * Remove STEP 2 and STEP 3, use the original PE in the memory instead of copying it to a new location.


