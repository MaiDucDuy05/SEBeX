#include "pch.h"
#include <windows.h> // GetModuleFileNameW, CreateThread, DisableThreadLibraryCalls
#include <metahost.h> // CLRCreateInstance and also things like ICLRMetaHost
#include <mscoree.h>  // ICLRRuntimeHost (which includes Start() and ExecuteInDefaultAppDomain()), CLSID_CLRMetaHost/IID_ICLRMetaHost
#include <string>


// Links the .NET library to provide access to CLR Hosting functions
#pragma comment(lib, "mscoree.lib")

HMODULE g_hModule; // To store this dll's base address

// This is dll's path finder 
std::wstring find_dll_path(HMODULE hModule) {
    wchar_t path[MAX_PATH];
    // Gets the full file path of this loader DLL
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew
    GetModuleFileNameW(hModule, path, MAX_PATH);

    std::wstring full_path(path);
    size_t pos = full_path.find_last_of(L"\\/");
    // It takesout the filename by just leaving the folder path (e.g "C:\seb_injector\")
    return (pos != std::wstring::npos) ? full_path.substr(0, pos + 1) : L".\\";
}

// It's the main logic that "opens" .net inside seb's process
DWORD WINAPI patch_loader(LPVOID) {
    ICLRMetaHost* pMetaHost = NULL; // Searchs the windows and list all installed versions of .net like 2.0, 4.0 or 5.0 so we set it to NULL to start clean
    // Once it finds .net 4.0, this pointer points to that specific version's 'settings' and files It handles the details of that specific version
    ICLRRuntimeInfo* pRuntimeInfo = NULL; // NOTE: this pointer is ONLY filled if the metahost finds the .net 4.0 files
    ICLRRuntimeHost* pRuntimeHost = NULL; // This allows us to check if the host is active anywhere in our code... so if pRuntimeHost is still NULL then the program knows the .net isn't ready yet so it acts as a "false" flag till it is assigned a value
    DWORD retVal = 0; // This is an int, so if the patcher crashes before it can send a result back, retVal will stay 0 instead of reading random stuffs from memory

    // It combines the path with the name of the pather's dll we want to run
    std::wstring patcherPath = find_dll_path(g_hModule) + L"seb_patcher.dll";

    // Initialize the .net metahost manager
    // https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/clrcreateinstance-function
    if (FAILED(CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost)))
        return 1;

    // It request the .net 4.0 runtime (the same as SEB's .net framework's version) 
    if (FAILED(pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo)))
        return 2;

    // It gets the 'host' interface which lets us control the VM
    if (FAILED(pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&pRuntimeHost)))
        return 3;

    // Start the .net vm inside the process
    pRuntimeHost->Start();
    // NOTE for dummies: what I mean by virtual machine is a "translator engine" that runs inside the process to turn the c# code into instructions the computer’s processor can understand this is cause C# code doesn't compile into machine code instead it compiles into CIL (common intermediate language)

    // Call the patcher's code
    // This looks inside seb_patcher.dll, finds the "Entrypoint" class and runs the "Run" method
    pRuntimeHost->ExecuteInDefaultAppDomain(
        patcherPath.c_str(),         // path to seb_patcher.dll
        L"seb_patcher.Entrypoint",   // namespace.class
        L"Run",                      // method to run/execute
        L"",                         // argument
        &retVal                      // receives the exit code from the patcher (seb_patcher.dll)
    );
    // Remember, we set everything to NULL at the beginning
    // These check each pointer and if it's not NULL, we tell windows we are done with it to free up ram
    if (pRuntimeHost) pRuntimeHost->Release(); // Checks if the host started and if so, subtracts 1 from the usage counter
    if (pRuntimeInfo) pRuntimeInfo->Release(); // The version info was loaded -> releases that interface
    if (pMetaHost) pMetaHost->Release();       // The manager was opened -> releases the main .net entry point

    return 0;
}

// The dll entry point runs IMMEDIATELY when the injector puts this file in seb
// If you don't know much about dll development, just think of DlMain as the 'main' function of executables
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) // This checks if the reason for the call is that the dll has just been loaded into a new process
    {
        g_hModule = hModule;

        // This prevents windows from calling DllMain for every new thread created
        // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls
        DisableThreadLibraryCalls(hModule);

        // NOTE: for safety purposes, we got to start the .net in a new thread cause doing it directly in DllMain causes a "loader lock" which freezes the program
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
        CreateThread(NULL, 0, patch_loader, NULL, 0, NULL);
    }
    return TRUE;
}