#include <stdio.h>
#include "loadlibrary.h"
#include "utils/logging.h"
#include <windows.h>

DECLARE_HANDLE(HAMSICONTEXT);
typedef HRESULT(NTAPI* pAmsiInitialize)(
    LPCWSTR      appName,
    HAMSICONTEXT* amsiContext
    );


PVOID get_proc_address_c(HMODULE dllAddress, char* functionName) {
    PE* dllParsed = pe_create(dllAddress, TRUE);
    for (SIZE_T i = 0; i < dllParsed->exportDirectory->NumberOfFunctions; i++) {
        char* name = (char*)((DWORD64)dllAddress + dllParsed->AddressOfNames[i]);
        if (strcmp(name, functionName) == 0) {
            DWORD64 functionRVA = dllParsed->AddressOfFunctions[dllParsed->AddressOfNameOrdinals[i]];
            return resolve_rva(dllParsed, functionRVA);
        }
    }
    return NULL;
}


int main() {
    HAMSICONTEXT amsiContext = NULL;
    HMODULE amsi = load_library_a("C:\\Windows\\System32\\amsi.dll");
    getchar();
    pAmsiInitialize AmsiInitialize = (pAmsiInitialize)get_proc_address_c((HMODULE)amsi, "AmsiInitialize");
    // Once it works with the custom GetProcAddress, see if it also works with the WIN32
    // GetProcAddress. If it doesn't try to see what could block using a debugger and a decompiler
    //pAmsiInitialize AmsiInitialize = (pAmsiInitialize)GetProcAddress((HMODULE)amsi, "AmsiInitialize");
    if (!AmsiInitialize) {
        Log(Error, "Cannot Load the function");
        return 0;
    }
    else {
        Log(Debug, "AmsiInitialize address : 0x%p", AmsiInitialize);
    }

    HRESULT result = AmsiInitialize(L"Test", &amsiContext);
    if (result == S_OK) {
        Log(Debug, "AMSI Initialize success");
    }
    else {
        Log(Error, "AMSI Initialize error");
    }

    return 0;
}