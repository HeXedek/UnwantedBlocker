#include <windows.h>
#include <detours.h>
#include <string>
#include <algorithm>
#include <fstream>
#include <set>
#include <shlwapi.h>   
#include <memory>       
#include <shellapi.h>   

#pragma comment(lib, "Shlwapi.lib")  
#pragma comment(lib, "detours.lib")  
#pragma comment(lib, "Shell32.lib")    


#define PIPE_NAME L"\\\\.\\pipe\\ProcessBlockerPipe"

static BOOL(WINAPI* TrueCreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessW;



bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin != 0;
}

bool IsTrustedDirectory(const std::wstring& processPath) {
    // List of trusted directories
    const std::wstring trustedDirs[] = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64",
        L"C:\\Program Files",
        L"C:\\Program Files (x86)",
        L"C:\\Windows\\WinSxS",
        L"C:\\Windows\\SystemResources",
        L"C:\\Windows\\Servicing",
        L"C:\\Windows\\Fonts",
        L"C:\\Windows"
    };



    std::wstring lowerProcessPath = processPath;
    std::transform(lowerProcessPath.begin(), lowerProcessPath.end(), lowerProcessPath.begin(), ::towlower);

    for (const auto& dir : trustedDirs) {
        // Convert dir to lowercase for case-insensitive comparison
        std::wstring lowerDir = dir;
        std::transform(lowerDir.begin(), lowerDir.end(), lowerDir.begin(), ::towlower);

        if (lowerProcessPath.find(lowerDir) == 0) {
            return true;
        }
    }

    return false; // Process is not in a trusted directory or subdirectory
}

const std::set<std::wstring> SUSPICIOUS_EXTENSIONS = {
    L".msi", L".js", L".hta", L".vbs", L".bat", L".cmd", L".scr",
    L".pif", L".ps1", L".jar", L".py", L".com", L".cpl", L".dll", L".sys", L".lnk", L".reg"
};

bool IsSuspiciousFile(const std::wstring& filePath) {
    if (filePath.empty()) {
        return false;
    }
    // Use PathFindExtensionW for robust extension finding
    LPCWSTR extensionPtr = PathFindExtensionW(filePath.c_str());

    // Check if an extension exists and is not just "."
    if (extensionPtr == nullptr || *extensionPtr == L'\0' || (wcslen(extensionPtr) == 1 && *extensionPtr == L'.')) {
        return false; // No valid extension found
    }

    std::wstring extension = extensionPtr; // Includes the dot (e.g., ".exe")
    std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);

    return SUSPICIOUS_EXTENSIONS.count(extension) > 0;
}

std::wstring GetTargetPath(LPCWSTR lpApplicationName, LPWSTR lpCommandLine) {
    wchar_t potentialPath[MAX_PATH] = { 0 };

    if (lpApplicationName != nullptr && lpApplicationName[0] != L'\0') {
        wcscpy_s(potentialPath, _countof(potentialPath), lpApplicationName);
        PathUnquoteSpacesW(potentialPath); 
        return std::wstring(potentialPath);
    }
    else if (lpCommandLine != nullptr && lpCommandLine[0] != L'\0') {
        auto cmdLineCopy = std::make_unique<wchar_t[]>(wcslen(lpCommandLine) + 1);
        wcscpy_s(cmdLineCopy.get(), wcslen(lpCommandLine) + 1, lpCommandLine);


        LPWSTR firstToken = cmdLineCopy.get();
        PathRemoveArgsW(firstToken); 
        PathUnquoteSpacesW(firstToken); 
        if (firstToken[0] != L'\0') {
            wcscpy_s(potentialPath, _countof(potentialPath), firstToken);
            return std::wstring(potentialPath);
        }
    }
    return L""; 
}

bool IsSuspiciousProcess(const std::wstring& applicationName, const std::wstring& commandLine) {
    // Check the application's own path first.
    if (!applicationName.empty() && IsSuspiciousFile(applicationName)) {
        return true;
    }

    // Parse the command line into tokens.
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(commandLine.c_str(), &argc);
    if (argv) {
        for (int i = 0; i < argc; i++) {
            std::wstring arg = argv[i];
            if (!arg.empty() && arg.front() == L'"' && arg.back() == L'"') {
                arg = arg.substr(1, arg.size() - 2);
            }
            if (IsSuspiciousFile(arg)) {
                LocalFree(argv);
                return true;
            }
        }
        LocalFree(argv);
    }
    return false;
}


bool AskController(const std::wstring& path) {
    // Select pipe based on admin status
    const wchar_t* pipeName = IsRunningAsAdmin() ? L"\\\\.\\pipe\\AdminProcessPipe" : L"\\\\.\\pipe\\NonAdminProcessPipe";

    HANDLE hPipe = CreateFileW(
        pipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        return true; 
    }

    DWORD written;
    WriteFile(hPipe, path.c_str(), (DWORD)((path.length() + 1) * sizeof(wchar_t)), &written, NULL);

    wchar_t response[10] = { 0 };
    DWORD read;
    BOOL result = ReadFile(hPipe, response, sizeof(response), &read, NULL);
    if (!result) {
        // Obs³uga b³êdu
        CloseHandle(hPipe);
        return false; // lub inna odpowiednia akcja
    }
    CloseHandle(hPipe);

    return wcscmp(response, L"ALLOW") == 0;

}



BOOL WINAPI MyCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    std::wstring targetPath = GetTargetPath(lpApplicationName, lpCommandLine);

    if (!targetPath.empty()) {
        bool isSuspicious = IsSuspiciousProcess(lpApplicationName ? lpApplicationName : L"", lpCommandLine ? lpCommandLine : L"");
        bool isTrusted = IsTrustedDirectory(targetPath); // Check the directory of the target path

        bool shouldBlock = false;


        bool requiresControllerCheck = false;

        if (isSuspicious) {
            requiresControllerCheck = true;
        }
        else if (!isTrusted) {
            requiresControllerCheck = true;
        }
        else {

        }

        if (requiresControllerCheck) {
            if (!AskController(targetPath)) { 
                shouldBlock = true;
            }
            else {
                // OutputDebugStringW(L"  - Allowed by Controller.\n");
            }
        }

        if (shouldBlock) {
            SetLastError(ERROR_ACCESS_DENIED); // Set an appropriate error code
            return FALSE; // Block the process creation
        }
    }
    else {
    }

    return TrueCreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}

void AttachHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
    DetourTransactionCommit();
}

void DetachHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
    DetourTransactionCommit();
}

DWORD WINAPI PipeListenerThread(LPVOID lpParam) {
    HMODULE hModule = (HMODULE)lpParam;

    HANDLE hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,              // Max instances
        512, 512,       // Buffer sizes
        0,              // Default timeout
        NULL            // Default security
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        return 1;
    }

    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(hPipe);
        return 1;
    }

    wchar_t buffer[256] = { 0 };
    DWORD bytesRead = 0;
    BOOL result = ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL);
    if (result) {
        buffer[bytesRead / sizeof(wchar_t)] = L'\0'; // Null-terminate
        if (wcscmp(buffer, L"UNINJECT") == 0) {
            // Unhook and unload the DLL
            DetachHooks();
            CloseHandle(hPipe);
            FreeLibraryAndExitThread(hModule, 0); // Kill this thread and unload the DLL
            return 0;
        }
    }

    CloseHandle(hPipe);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        AttachHooks();

        // Start the pipe listener in a new thread
        CloseHandle(CreateThread(nullptr, 0, PipeListenerThread, hModule, 0, nullptr));
        break;
    case DLL_PROCESS_DETACH:
        DetachHooks();
        break;
    }
    return TRUE;
}
