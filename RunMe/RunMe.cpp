#include <windows.h> // For OpenProcess, OpenThread, QueueUserAPC, WaitForSingleObject, CloseHandle, VirtualAllocEx, WriteProcessMemory, VirtualFreeEx, GetModuleFileNameW, GetModuleHandleW, GetProcAddress, RegOpenKeyExW, RegSetValueExW, RegCloseKey
#include <tlhelp32.h> // CreateToolhelp32Snapshot, Process32FirstW/NextW, Thread32First/Next
#include <string>

// It tells the linker to run as a gui app instead of a console one which hides the black cmd prompt window
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

// This checks if the program ran with admin perms, cause admin perm is needed inorder to write a memory of others processes
bool admin_perm_granted() {
    BOOL fRet = false; // Defaults to false by assuming the user isn't admin until proven otherwise
    HANDLE access_token = NULL; // is used to track a process's permissions
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &access_token)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
        if (GetTokenInformation(access_token, TokenElevation, &elevation, sizeof(elevation), &dwSize)) // This tell about elevation status and if it got something it returns it so we can check on the main function 
        {
            fRet = elevation.TokenIsElevated;
        }
    }
    if (access_token) CloseHandle(access_token);
    return fRet; // TRUE = if it ran with admin perms, FALSE = if it ran without it
}


// Simple XOR encryption/decryption function
// This is used to evade the windows defender cause without this the user would need to allow it to run manually or turn off defender
std::wstring str_decrypter(const std::wstring& encrypted_str, wchar_t key)
{
    // NOTE: if you XOR any data with a key twice, you get the original data back
    std::wstring decrypted_str = encrypted_str;
    for (size_t i = 0; i < decrypted_str.length(); ++i)
    {
        decrypted_str[i] ^= key; // ^= is syntax for XOR for encrypting and decrypting a character with a key
    }
    return decrypted_str;
}

// Scans all running processes and their threads to find a match for the target
// It needs both the PID to open the process and the TID to queue the APC which you'll going to see in the next codes
DWORD find_process__thread(const std::wstring& target_process_name, DWORD& thread_id)
{
    // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    // Search for the process id (PID) that match the name 'SafeExamBrowser.exe' which is pe.szExeFile
    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            if (target_process_name == pe.szExeFile)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    // If process found, it will then find the thread id belonging to it
    if (pid != 0)
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        // See https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first, you should find the 'Next' function usage and doc in there
        if (Thread32First(snapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == pid)
                {
                    thread_id = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(snapshot, &te));
        }
    }

    CloseHandle(snapshot);
    return pid;
}

bool inject_native_dll(DWORD pid, DWORD tid, const std::wstring& dll_path)
{
    // They are 'XORed' with 0x55 to bypass AV string detection which is going to be one of the first problem when it comes to dll injection
    // Remember, the keys are different that means different keys for different types of strings (0x11 and 0x55)
    wchar_t kernelstr_encrypt[] = { 'k' ^ 0x55, 'e' ^ 0x55, 'r' ^ 0x55, 'n' ^ 0x55, 'e' ^ 0x55, 'l' ^ 0x55, '3' ^ 0x55, '2' ^ 0x55, '.' ^ 0x55, 'd' ^ 0x55, 'l' ^ 0x55, 'l' ^ 0x55, 0 };
    char loadlib_encrypt[] = { 'L' ^ 0x55, 'o' ^ 0x55, 'a' ^ 0x55, 'd' ^ 0x55, 'L' ^ 0x55, 'i' ^ 0x55, 'b' ^ 0x55, 'r' ^ 0x55, 'a' ^ 0x55, 'r' ^ 0x55, 'y' ^ 0x55, 'W' ^ 0x55, 0 };

    // This will decrypte the strings in memory before it get used
    std::wstring kernelstr_decrypt = kernelstr_encrypt;
    for (auto& c : kernelstr_decrypt) c ^= 0x55;

    std::string decLoadLib = loadlib_encrypt;
    for (auto& c : decLoadLib) c ^= 0x55;

    // Open seb's process (with very minimal perms just needed for writing memory)
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!process) return false;

    // Open seb's thread to prepare for APC injection
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
    HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    if (!thread)
    {
        CloseHandle(process);
        return false;
    }

    // Allocate space in the seb process for the dll file path string
    size_t pathSize = (dll_path.length() + 1) * sizeof(wchar_t);
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    LPVOID allocated_mem = VirtualAllocEx(process, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocated_mem)
    {
        CloseHandle(thread);
        CloseHandle(process);
        return false;
    }

    // Write the dll path (which in our case is 'C:\seb_injector\native_loader.dll' into the memory we allocated earlier
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    if (!WriteProcessMemory(process, allocated_mem, dll_path.c_str(), pathSize, NULL)) // Cleans the memory we allocated if it returns false (if you're confuse just think of it as: if(!false) = true)
    {
        VirtualFreeEx(process, allocated_mem, 0, MEM_RELEASE);
        CloseHandle(thread);
        CloseHandle(process);
        return false;
    }

    // "Locate" LoadLibraryW in seb (it's shared via kernel32.dll)
    // for more info look at https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew and https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    HMODULE kernel32 = GetModuleHandleW(kernelstr_decrypt.c_str());
    FARPROC loadlib = GetProcAddress(kernel32, decLoadLib.c_str());

    // Will start the injection using QueueUserAPC which is better than the traditional way... since it's hard to detect by a basic AVs 
    // This makes the seb's thread to run LoadLibraryW(dllPath) (which is the native loader dll)
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
    DWORD result = QueueUserAPC((PAPCFUNC)loadlib, thread, (ULONG_PTR)allocated_mem);

    // Fiannly Cleanup 
    // NOTE: we do NOT free the memory here cause the target might not have loaded the dll yet but closing the handle is a 'must'
    CloseHandle(thread);
    CloseHandle(process);

    return result != 0;
}

// Used to find where this current exe is located instead of just hardcodding the dll's path
std::wstring find_exe_directory()
{
    wchar_t path[MAX_PATH];
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring full_path(path);
    size_t lastSlash = full_path.find_last_of(L"\\//");
    if (lastSlash != std::wstring::npos)
        return full_path.substr(0, lastSlash);
    return full_path;
}

// This is not necessary but it's good to have if the user wants seb to run with the same modded way
// It makes the the exploit a startup app
void add_to_startup()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    // Registry path: "Software\Microsoft\Windows\CurrentVersion\Run"
    std::wstring regkey_encrypt = { 'S' ^ 0x21, 'o' ^ 0x21, 'f' ^ 0x21, 't' ^ 0x21, 'w' ^ 0x21, 'a' ^ 0x21, 'r' ^ 0x21, 'e' ^ 0x21, '\\' ^ 0x21,
                               'M' ^ 0x21, 'i' ^ 0x21, 'c' ^ 0x21, 'r' ^ 0x21, 'o' ^ 0x21, 's' ^ 0x21, 'o' ^ 0x21, 'f' ^ 0x21, 't' ^ 0x21, '\\' ^ 0x21,
                               'W' ^ 0x21, 'i' ^ 0x21, 'n' ^ 0x21, 'd' ^ 0x21, 'o' ^ 0x21, 'w' ^ 0x21, 's' ^ 0x21, '\\' ^ 0x21,
                               'C' ^ 0x21, 'u' ^ 0x21, 'r' ^ 0x21, 'r' ^ 0x21, 'e' ^ 0x21, 'n' ^ 0x21, 't' ^ 0x21, 'V' ^ 0x21, 'e' ^ 0x21, 'r' ^ 0x21, 's' ^ 0x21, 'i' ^ 0x21, 'o' ^ 0x21, 'n' ^ 0x21, '\\' ^ 0x21,
                               'R' ^ 0x21, 'u' ^ 0x21, 'n' ^ 0x21 };
    std::wstring decRegKey = str_decrypter(regkey_encrypt, 0x21);
    // For the next three functions, look at https://learn.microsoft.com/en-us/windows/win32/api/winreg/
    HKEY hKey;
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, decRegKey.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (status == ERROR_SUCCESS)
    {
        // It names the startup entry 'WinSysMon' to look like a generic system monitor
        RegSetValueExW(hKey, L"WinSysMon", 0, REG_SZ, (BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

struct TargetInfo {
    std::wstring target_proc;
    std::wstring dllPath;
};

DWORD WINAPI InjectorLoop(LPVOID lpParam)
{
    TargetInfo* info = (TargetInfo*)lpParam;
    std::wstring target_proc = info->target_proc;
    std::wstring dllPath = info->dllPath;

    while (true)
    {
        DWORD pid = 0;
        DWORD tid = 0;

        // It waits until target process opens
        while (true)
        {
            pid = find_process__thread(target_proc, tid);
            if (pid != 0 && tid != 0)
                break;

            Sleep(50);
        }

        // Not necessary but let's just say it's to be safe cause it makes sure the process has initialized its main window/threads before injecting
        Sleep(1000);

        // Inject the dll to target's available thread
        inject_native_dll(pid, tid, dllPath);

        // It waits for the target process to close before looking for it again
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (process)
        {
            WaitForSingleObject(process, INFINITE);
            CloseHandle(process);
        }
        else
        {
            // If we can't get a 'SYNCHRONIZE' handle, check if pid still exists MANUALLY
            DWORD init_tid = 0;
            while (find_process__thread(target_proc, init_tid) == pid)
            {
                Sleep(1000);
            }
        }
    }
    return 0;
}

int main()
{
    // Hide console window if compiler ignored #pragma (e.g. MinGW)
    HWND consoleWnd = GetConsoleWindow();
    if (consoleWnd != NULL) ShowWindow(consoleWnd, SW_HIDE);

    // Check for Admin Privileges
    if (!admin_perm_granted()) // If was run without admin perm (False)and since !False = True, it pops up a msg and closes after
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw
        MessageBoxW(NULL, L"It must be run with administrator privileges! read the docs for more info.", L"Exiting...", MB_OK | MB_ICONERROR);
        return 1; // Exit
    }
    // Sets it up to be a startup app
    add_to_startup();

    std::wstring exeDir = find_exe_directory();

    // It define the target process and the dll to be injected, it's 'XORed' for the same reason as earlier
    std::wstring target_encrypt = { 'S' ^ 0x11, 'a' ^ 0x11, 'f' ^ 0x11, 'e' ^ 0x11, 'E' ^ 0x11, 'x' ^ 0x11, 'a' ^ 0x11, 'm' ^ 0x11, 'B' ^ 0x11, 'r' ^ 0x11, 'o' ^ 0x11, 'w' ^ 0x11, 's' ^ 0x11, 'e' ^ 0x11, 'r' ^ 0x11, '.' ^ 0x11, 'e' ^ 0x11, 'x' ^ 0x11, 'e' ^ 0x11 }; // SafeExamBrowser.exe
    std::wstring target_client_encrypt = { 'S' ^ 0x11, 'a' ^ 0x11, 'f' ^ 0x11, 'e' ^ 0x11, 'E' ^ 0x11, 'x' ^ 0x11, 'a' ^ 0x11, 'm' ^ 0x11, 'B' ^ 0x11, 'r' ^ 0x11, 'o' ^ 0x11, 'w' ^ 0x11, 's' ^ 0x11, 'e' ^ 0x11, 'r' ^ 0x11, '.' ^ 0x11, 'C' ^ 0x11, 'l' ^ 0x11, 'i' ^ 0x11, 'e' ^ 0x11, 'n' ^ 0x11, 't' ^ 0x11, '.' ^ 0x11, 'e' ^ 0x11, 'x' ^ 0x11, 'e' ^ 0x11 }; // SafeExamBrowser.Client.exe
    std::wstring dll_encrypt = { 'n' ^ 0x11, 'a' ^ 0x11, 't' ^ 0x11, 'i' ^ 0x11, 'v' ^ 0x11, 'e' ^ 0x11, '_' ^ 0x11, 'l' ^ 0x11, 'o' ^ 0x11, 'a' ^ 0x11, 'd' ^ 0x11, 'e' ^ 0x11, 'r' ^ 0x11, '.' ^ 0x11, 'd' ^ 0x11, 'l' ^ 0x11, 'l' ^ 0x11 }; // native_loader.dll

    std::wstring target_proc = str_decrypter(target_encrypt, 0x11);
    std::wstring target_proc_client = str_decrypter(target_client_encrypt, 0x11);
    std::wstring dll_name = str_decrypter(dll_encrypt, 0x11);
    std::wstring dllPath = exeDir + L"\\" + dll_name;

    TargetInfo* info1 = new TargetInfo{ target_proc, dllPath };
    TargetInfo* info2 = new TargetInfo{ target_proc_client, dllPath };

    HANDLE hThread1 = CreateThread(NULL, 0, InjectorLoop, info1, 0, NULL);
    HANDLE hThread2 = CreateThread(NULL, 0, InjectorLoop, info2, 0, NULL);

    WaitForSingleObject(hThread1, INFINITE);
    WaitForSingleObject(hThread2, INFINITE);

    return 0;
}
