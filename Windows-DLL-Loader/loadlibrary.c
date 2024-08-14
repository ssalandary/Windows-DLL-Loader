#include "loadlibrary.h"
#include "utils/logging.h"


PBYTE read_file_w(LPWSTR filename, PDWORD file_size) {
    HANDLE file_handle = CreateFileW(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file_handle == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    *file_size = GetFileSize(file_handle, NULL);
    DWORD sizeRead = 0;
    PBYTE content = (PBYTE)calloc(*file_size, sizeof(unsigned char));
    DWORD result = ReadFile(file_handle, content, *file_size, &sizeRead, NULL);
    if (!result || sizeRead != *file_size) {
        Log(Error, "read_file_w: error during %ls file read", filename);
        free(content);
        content = NULL;
    }
    CloseHandle(file_handle);
    return content;
}

/*
 * Helper that given a base address will map the element
 * in a structure representing the PE.
 */
PE* pe_create(PVOID image_base, BOOL is_memory_mapped) {
    PE* pe = (PE*)calloc(1, sizeof(PE));
    if (!pe) {
        Log(Error, "pe_create: error during PE allocation");
        return NULL;
    }

    pe->memoryMapped = is_memory_mapped;
    pe->dosHeader = image_base;
    pe->ntHeader = (IMAGE_NT_HEADERS*)((PBYTE)image_base + pe->dosHeader->e_lfanew);
    pe->optionalHeader = &(pe->ntHeader->OptionalHeader);

    if (is_memory_mapped) {
        pe->baseAddress = image_base;
    }
    else {
        pe->baseAddress = (PVOID)pe->optionalHeader->ImageBase;
    }

    pe->dataDirectory = pe->optionalHeader->DataDirectory;
    pe->sectionHeader = (IMAGE_SECTION_HEADER*)((PBYTE)(pe->optionalHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);

    DWORD export_directory_rva = (DWORD)pe->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_directory_rva == 0) {
        pe->exportDirectory = NULL;
        pe->AddressOfFunctions = NULL;
        pe->AddressOfNames = NULL;
        pe->AddressOfNameOrdinals = NULL;
        pe->NumberOfNames = 0;
    }
    else {
        pe->exportDirectory = resolve_rva(pe, export_directory_rva);
        pe->AddressOfFunctions = resolve_rva(pe, pe->exportDirectory->AddressOfFunctions);
        pe->AddressOfNames = resolve_rva(pe, pe->exportDirectory->AddressOfNames);
        pe->AddressOfNameOrdinals = resolve_rva(pe, pe->exportDirectory->AddressOfNameOrdinals);
        pe->NumberOfNames = pe->exportDirectory->NumberOfNames;
    }

    pe->relocations = NULL;
    return pe;
}


PVOID resolve_rva(PE* pe, DWORD64 rva) {
    if (pe->memoryMapped) {
        // If the PE is already mapped in memory, no need to perform
        // any computation. The rva is the offset from the file start
        return (PVOID)((DWORD64)pe->dosHeader + rva);
    }

    // If the PE is not mapped in memory *ie read from file for example*
    // some work must be done to resolve the rva :
    // https://0xrick.github.io/win-internals/pe8/#resolving-rvas
    for (SIZE_T i = 0; i < pe->ntHeader->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* section = (PVOID)((DWORD64)pe->sectionHeader + i * SECTION_SIZE);
        DWORD64 section_start = (DWORD64)section->VirtualAddress;
        DWORD64 section_end = section_start + section->Misc.VirtualSize;
        if ((DWORD64)rva >= section_start && (DWORD64)rva < section_end) {
            return (PVOID)((DWORD64)pe->dosHeader + section->PointerToRawData + ((DWORD64)rva - section_start));
        }
    }
    return NULL;
}

/*
 * Read the DLL file to load and map the section in memory
 */
PVOID minimal_memory_map(LPWSTR filepath) {
    DWORD file_size = 0;
    PBYTE dll_content = read_file_w(filepath, &file_size);

    PVOID address = NULL;

    // Parse the file into a PE structure
    PE* dll_parsed = pe_create(dll_content, FALSE);
    if (!dll_parsed) {
        Log(Error, "minimal_memory_map: failed to parse the DLL");
        return NULL;
    }

    // Allocate a section to write the DLL
    // WORKSHOP TODO: Fix the VirtualAlloc call
    // We want to allocate a page large enough to contains the whole DLL image
    // The DLL image size is stored in dll_parsed->ntHeader->OptionalHeader.SizeOfImage
    // We also want to be set a specific protection on this page
    // Change the two 0 values to fix the call
    PVOID start_address = VirtualAlloc(address, 0, MEM_COMMIT | MEM_RESERVE, 0);
    if (!start_address) {
        Log(Error, "minimal_memory_map: cannot allocate DLL memory %lu", GetLastError());
        free(dll_parsed);
        return NULL;
    }
    Log(Info, "minimal_memory_map: memory allocated at : %p", start_address);
    Log(Info, "minimal_memory_map: copy headers in memory");

    // Copy the DLL header in the allocated section
    memcpy(start_address, dll_content, dll_parsed->ntHeader->OptionalHeader.SizeOfHeaders);

    Log(Info, "[+] minimal_memory_map: copy sections in memory");
    // Copy each sections one by one in the allocated section
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(dll_parsed->ntHeader);
    for (DWORD i = 0; i < dll_parsed->ntHeader->FileHeader.NumberOfSections; i++, section_header++) {
        Log(Debug, "Copying %lu bytes from section %s", section_header->SizeOfRawData, section_header->Name);
        memcpy((PBYTE)start_address + section_header->VirtualAddress,
            (PBYTE)dll_content + section_header->PointerToRawData, section_header->SizeOfRawData);
    }
    free(dll_parsed);

    // Return the DLL base address allocated
    return start_address;
}

/*
 * Process the memory mapped DLL relocations
 */
BOOL rebase(PE* dll_parsed) {
    // Parse relocations
    // https://0xrick.github.io/win-internals/pe8/#parsing-base-relocations
    // Relocation structure
    // --------------------------
    // | IMAGE_BASE_RELOCATION  |
    // | DWORD				    |
    // | DWORD				    |
    // --------------------------
    // | IMAGE_RELOCATION_ENTRY |
    // | DWORD                  |
    // | DWORD[3]				|
    // --------------------------
    // | IMAGE_RELOCATION_ENTRY |
    // | DWORD                  |
    // | DWORD[3]				|
    // --------------------------
    // | IMAGE_BASE_RELOCATION  |
    // | DWORD				    |
    // | DWORD				    |
    // --------------------------
    // | IMAGE_RELOCATION_ENTRY |
    // | DWORD                  |
    // | DWORD[3]				|
    // --------------------------

    Log(Debug, "rebase: parsing relocations");
    SIZE_T number_of_relocations = 0;
    // Get the first relocation block
    IMAGE_BASE_RELOCATION* current_relocation = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (!dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress &&
        !dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        Log(Debug, "rebase: no relocation to do !");
        return TRUE;
    }

    // Offset between the real DLL base address and the one expected
    // by the compiler when the DLL has been compiled
    // This offset will be added to each symbol address to relocate
    DWORD64 offset = (DWORD64)dll_parsed->baseAddress - (DWORD64)dll_parsed->ntHeader->OptionalHeader.ImageBase;

    // Iterate over each relocation block
    while (current_relocation->VirtualAddress) {
        Log(Info, "rebase: relocation processed : %X", current_relocation->VirtualAddress);
        // First block
        IMAGE_RELOCATION_ENTRY* relocation_entry = (PIMAGE_RELOCATION_ENTRY)&current_relocation[1];

        // Iterate over each relocation entry contained in the relocation block
        // See relocation structure in start of the function
        while ((DWORD64)relocation_entry < (DWORD64)current_relocation + current_relocation->SizeOfBlock) {
            // Compute the address of the symbol to relocate
            DWORD64 relocation_rva = current_relocation->VirtualAddress + relocation_entry->Offset;
            PVOID relocation_address = resolve_rva(dll_parsed, relocation_rva);

            if (relocation_entry->Type == IMAGE_REL_BASED_ABSOLUTE) {
                Log(Debug, "rebase: relocation skipped as used for padding");
            }
            else if (relocation_entry->Type == IMAGE_REL_BASED_HIGHLOW) {
                if (offset > MAXDWORD) {
                    Log(Error, "rebase: relocation to long, cannot be processed");
                    return FALSE;
                }
                *((DWORD64*)relocation_address) += (DWORD)offset;
            }
            else if (relocation_entry->Type == IMAGE_REL_BASED_DIR64) {
                *((DWORD64*)relocation_address) += offset;
            }
            else {
                Log(Error, "rebase: relocation not supported");
                return FALSE;
            }

            Log(Debug, "rebase: RVA : %llX", relocation_rva);
            Log(Debug, "rebase: Offset : %d", relocation_entry->Offset);
            Log(Debug, "rebase: Type : %d", relocation_entry->Type);
            Log(Debug, "rebase: BaseOffset : 0x%llX", offset);
            Log(Debug, "rebase: StartAddress : 0x%llX", (DWORD64)dll_parsed->baseAddress);
            Log(Debug, "rebase: Reloc Address : 0x%p", relocation_address);
            Log(Debug, "rebase: New value : 0x%llX", (*(DWORD64*)relocation_address));

            // The next block is 0x08 bytes after, a ++ does the trick
            relocation_entry++;
        }

        // Current relocation processed, go to the next one
        current_relocation = (PVOID)((DWORD64)current_relocation + current_relocation->SizeOfBlock);
    }

    return TRUE;
}


/*
 * Resolve dependencies and fill the DLL IAT
 */
BOOL snapping(PE* dll_parsed) {
    Log(Debug, "snapping: parsing imports");
    if (!dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress &&
        !dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        Log(Error, "snapping: no imports to process");
        return TRUE;
    }
    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (SIZE_T i = 0; importDescriptor->Name; importDescriptor++) {
        char* dll_name = resolve_rva(dll_parsed, importDescriptor->Name);
        Log(Info, "snapping: descriptor name: %s", dll_name);
        PIMAGE_THUNK_DATA iat = resolve_rva(dll_parsed, importDescriptor->FirstThunk);
        PIMAGE_THUNK_DATA ilt = resolve_rva(dll_parsed, importDescriptor->OriginalFirstThunk);
        Log(Debug, "snapping: IAT address : 0x%p", iat);
        if (dll_name[0] == '\0') {
            continue;
        }
        HMODULE dll_handle = GetModuleHandleA(dll_name);
        if (!dll_handle) {
            Log(Debug, "DLL not found, load the DLL");
            dll_handle = LoadLibraryA(dll_name);
        }

        for (; ilt->u1.Function; iat++, ilt++) {
            if (IMAGE_SNAP_BY_ORDINAL(ilt->u1.Ordinal)) {
                int function_ordinal = IMAGE_ORDINAL(ilt->u1.Ordinal);
                iat->u1.Function = (DWORD_PTR)GetProcAddress(dll_handle, MAKEINTRESOURCE(function_ordinal));
            }
            else {
                IMAGE_IMPORT_BY_NAME* hint = resolve_rva(dll_parsed, ilt->u1.AddressOfData);
                Log(Info, "snapping: function Name : %s", hint->Name);
                // WORKSHOP TODO: Here we want to resolve the address of the function whose name
                // is stored in hint->Name and whose parent DLL is located in dllHandle
                // Replace the NULL by the right function call
                iat->u1.Function = (ULONGLONG)NULL;
                Log(Info, "snapping: function address : 0x%llX", iat->u1.Function);
            }
        }
    }

    Log(Debug, "Parsing delayed imports");
    if (dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress == 0) {
        Log(Info, "No delayed import");
        return TRUE;
    }
    IMAGE_DELAYLOAD_DESCRIPTOR* importDelayDescriptor = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    for (; importDelayDescriptor->DllNameRVA; importDelayDescriptor++) {
        char* dllName = (char*)resolve_rva(dll_parsed, importDelayDescriptor->DllNameRVA);
        Log(Info, "Descriptor name: %s", dllName);
        PIMAGE_THUNK_DATA iat = resolve_rva(dll_parsed, importDelayDescriptor->ImportAddressTableRVA);
        PIMAGE_THUNK_DATA ilt = resolve_rva(dll_parsed, importDelayDescriptor->ImportNameTableRVA);

        Log(Debug, "IAT address : 0x%p", iat);

        HMODULE dllHandle = GetModuleHandleA(dllName);
        if (!dllHandle) {
            Log(Debug, "DLL not found, load the DLL");
            dllHandle = LoadLibraryExA(dllName, NULL, 0);
            if (!dllHandle) {
                Log(Error, "Cannot load library");
                return FALSE;
            }
        }

        for (; ilt->u1.Function; iat++, ilt++) {
            if (IMAGE_SNAP_BY_ORDINAL(ilt->u1.Ordinal)) {
                LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(ilt->u1.Ordinal);
                iat->u1.Function = (DWORD_PTR)GetProcAddress(dllHandle, functionOrdinal);
            }
            else {
                IMAGE_IMPORT_BY_NAME* hint = resolve_rva(dll_parsed, ilt->u1.AddressOfData);
                Log(Info, "Function Name : %s", hint->Name);
                // WORKSHOP TODO: Here we want to resolve the address of the function whose name
                // is stored in hint->Name and whose parent DLL is located in dllHandle
                // Replace the NULL by the right function call
                iat->u1.Function = (ULONGLONG)NULL;
                Log(Info, "Function address : 0x%llX", iat->u1.Function);
            }

        }

    }
    return TRUE;
}

BOOL run_entrypoint(PE* dll_parsed) {

    // Time to re-protect all section according to their characteristics
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(dll_parsed->ntHeader);
    for (SIZE_T i = 0; i < dll_parsed->ntHeader->FileHeader.NumberOfSections; i++) {
        BOOL executable = (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL writable = (section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        BOOL readable = (section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;

        DWORD protection = 0;

        // WORKSHOP TODO: Replace the 0 by one of these values: PAGE_EXECUTE_READ, PAGE_EXECUTE, PAGE_READONLY
        if (executable && writable && readable) { protection = PAGE_EXECUTE_READWRITE; }
        else if (executable && writable && !readable) { protection = PAGE_EXECUTE_WRITECOPY; }
        else if (executable && !writable && readable) { protection = 0; }
        else if (executable && !writable && !readable) { protection = 0; }
        else if (!executable && writable && readable) { protection = PAGE_READWRITE; }
        else if (!executable && writable && !readable) { protection = PAGE_WRITECOPY; }
        else if (!executable && !writable && readable) { protection = 0; }
        else if (!executable && !writable && readable) { protection = PAGE_NOACCESS; }
        DWORD old_protection;

        // WORKSHOP TODO: Fix this function call to apply the protection on the right memory space
        // VirtualProtect take as 2nd and 3td parameter the size of the section to protect and the protection to apply
        // Replace the two 0 value by the right one.
        VirtualProtect(resolve_rva(dll_parsed, section_header->VirtualAddress), 0, 0, &old_protection);
        section_header++;
    }

    FlushInstructionCache((HANDLE)-1, NULL, 0);

    // Initialize TLS
    if (dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        PIMAGE_TLS_DIRECTORY pTlsDir = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* ppCallback = (PIMAGE_TLS_CALLBACK*)(pTlsDir->AddressOfCallBacks);

        for (; *ppCallback; ppCallback++) {
            (*ppCallback)((PVOID)dll_parsed->baseAddress, DLL_PROCESS_ATTACH, NULL);
        }
    }

    // Register SEH exceptions
    if (dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        PIMAGE_RUNTIME_FUNCTION_ENTRY pFuncEntry = resolve_rva(dll_parsed, dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        RtlAddFunctionTable(
            (PRUNTIME_FUNCTION)pFuncEntry,
            (dll_parsed->dataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1,
            (DWORD64)dll_parsed->baseAddress
        );
    }

    // Find the DLL entrypoint
    if (!dll_parsed->ntHeader->OptionalHeader.AddressOfEntryPoint) {
        // Some DLLs do not have entrypoint
        return TRUE;
    }

    // WORKSHOP TODO: Set the right value instead of 0
    DWORD64 entrypoint = 0;
    LPDLLMAIN entryPoint = (LPDLLMAIN)resolve_rva(dll_parsed, entrypoint);
    if (!entryPoint) {
        Log(Debug, "run_entrypoint: cannot find entrypoint");
        return FALSE;
    }
    else {
        Log(Info, "run_entrypoint: found entrypoint at : 0x%p", entryPoint);
        // Run the entrypoint and retrieve the execution status
        BOOL status = entryPoint((DWORD_PTR)dll_parsed->baseAddress, DLL_PROCESS_ATTACH, NULL);
        DEBUG_MEDIUM("[+] run_entrypoint: entrypoint status : %d (%d)", status, GetLastError());
        return status;
    }
    return 1;
}


PVOID load_library_ex_a(LPCSTR filepath, HANDLE file, DWORD dwFlags) {
    char cur = filepath[0];
    size_t size = 0;
    while (cur != '\0') {
        size += 1;
        cur = filepath[size];
    }
    size += 1;
    wchar_t filepath_w[MAX_PATH];
    for (int i = 0; i < size; i++) {
        filepath_w[i] = (wchar_t)filepath[i];
    }
    return load_library_ex_w(filepath_w, file, dwFlags);
}

PVOID load_library_a(LPSTR filepath) {
    return load_library_ex_a(filepath, NULL, 0);
}

PVOID load_library_w(LPWSTR filepath) {
    return load_library_ex_w(filepath, NULL, 0);
}

PVOID load_library_ex_w(LPWSTR filepath, HANDLE file, DWORD dwFlags) {
    return ldr_load_dll(filepath, file, dwFlags);
}


// WORKSHOP TODO
PVOID ldr_load_dll(LPWSTR filepath, HANDLE file, DWORD dwFlags) {
    LPWSTR dll_name = NULL;
    LPWSTR dll_path = NULL;
    DWORD dll_path_size = 0;
    DWORD dll_name_size = 0;
    BOOL result;

    // WORKSHOP TODO: replace NULL by the right function call
    PVOID startAddress = NULL;
    if (!startAddress) {
        return NULL;
    }

    // Parse the module in memory
    PE* dll_parsed = pe_create(startAddress, TRUE);
    if (!dll_parsed) {
        return NULL;
    }

    // WORKSHOP TODO: replace FALSE by the right function call
    result = FALSE;
    if (!result) {
        free(dll_parsed);
        return NULL;
    }

    // WORKSHOP TODO: replace FALSE by the function call
    result = FALSE;
    if (!result) {
        free(dll_parsed);
        return NULL;
    }

    DEBUG_MEDIUM("[+] ldr_load_dll: executing entrypoint for %ls", dll_name);
    // WORKSHOP TODO: replace FALSE by the function call
    result = FALSE;
    if (!result) {
        free(dll_parsed);
        return NULL;
    }

    DEBUG_MEDIUM("[+] ldr_load_dll: dll %ls is loaded", dll_name);
    free(dll_parsed);
    return startAddress;
}