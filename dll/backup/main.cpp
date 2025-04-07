#include <windows.h>
#include <detours.h>
#include <string>
#include <iostream>
#include <set>
#include <algorithm>

// Suspicious file extensions
const std::set<std::wstring> SUSPICIOUS_EXTENSIONS = {
    L".exe", L".msi", L".js", L".hta", L".vbs", L".bat", L".cmd", L".scr", L".pif", L".ps1", L".jar", L".com", L".cpl", L".dll", L".sys", L".lnk", L".reg"
};

// Trusted directories
const std::set<std::wstring> TRUSTED_DIRS = {
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

// Pointer to the original CreateProcessW function
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

// Helper function to get the file extension from a path
std::wstring GetFileExtension(const std::wstring& path) {
    size_t pos = path.rfind(L'.');
    if (pos != std::wstring::npos) {
        return path.substr(pos);
    }
    return L"";
}

// Helper function to convert a string to lowercase for case-insensitive comparison
std::wstring ToLower(const std::wstring& str) {
    std::wstring lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::towlower);
    return lowerStr;
}

// Helper function to check if a path is in a trusted directory or a subdirectory of a trusted directory
bool IsInTrustedDirectory(const std::wstring& path) {
    std::wstring lowerPath = ToLower(path);  // Convert to lowercase for case-insensitive comparison

    for (const auto& trustedDir : TRUSTED_DIRS) {
        std::wstring lowerTrustedDir = ToLower(trustedDir);  // Convert trusted directory to lowercase
        if (lowerPath.find(lowerTrustedDir) == 0) {  // Check if path starts with a trusted directory
            return true;
        }
    }
    return false;
}

// The thread function that shows the message box and allows the user to block or allow the process
DWORD WINAPI ShowMessageBox(LPVOID param) {
    LPCWSTR processName = (LPCWSTR)param;

    // Create a message box that shows the process name
    HWND desktop = GetDesktopWindow();
    MessageBoxW(desktop, L"Hello from DLL", L"Test", MB_OK | MB_TOPMOST);
    return 0;
}

// The hooked version of CreateProcessW
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
    // Log to confirm hook is hit
    OutputDebugStringW(L"CreateProcessW Hooked for a new process!\n");

    // Extract the file extension from the application name
    std::wstring extension = GetFileExtension(lpApplicationName);

    // If the extension is suspicious and the directory is not trusted
    bool isSuspicious = SUSPICIOUS_EXTENSIONS.find(extension) != SUSPICIOUS_EXTENSIONS.end();
    bool isInTrustedDir = IsInTrustedDirectory(lpApplicationName);

    // Create a thread to show the message box if the extension is suspicious or the directory is untrusted
    BOOL allowProcess = TRUE;
    if (isSuspicious && !isInTrustedDir) {
        // If the extension is suspicious and not in a trusted directory, block the process
        // But first, show the message box to the user
        HANDLE hThread = CreateThread(NULL, 0, ShowMessageBox, (LPVOID)lpApplicationName, 0, NULL);
        if (hThread == NULL) {
            OutputDebugStringW(L"Error: Failed to create thread for message box.\n");
            return TRUE;  // Allow process if thread creation fails
        }

        // Wait for the thread to finish (blocks until user interacts with the message box)
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        // If the user clicked 'No', block the process
        if (!allowProcess) {
            OutputDebugStringW(L"Process creation blocked.\n");
            return FALSE;
        }
    }

    // Otherwise, allow the process creation to proceed
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

// Function to attach the hook to CreateProcessW
void AttachHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
    DetourTransactionCommit();
}

// Function to detach the hook from CreateProcessW
void DetachHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
    DetourTransactionCommit();
}

// DLL entry point to attach or detach hooks
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Attach the hook when the DLL is loaded
        AttachHooks();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        // Detach the hook when the DLL is unloaded
        DetachHooks();
    }
    return TRUE;
}
