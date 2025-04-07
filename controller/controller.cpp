#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <psapi.h> // For GetModuleBaseName
#include <tchar.h> // For _tcsicmp

#define ADMIN_PIPE_NAME L"\\\\.\\pipe\\AdminProcessPipe"
#define NON_ADMIN_PIPE_NAME L"\\\\.\\pipe\\NonAdminProcessPipe"

// Check if the application is running as administrator
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

BOOL IsWindowsTerminal(HWND hwnd) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) return FALSE;

    TCHAR exeName[MAX_PATH] = { 0 };
    BOOL result = FALSE;

    if (GetModuleBaseName(hProcess, NULL, exeName, MAX_PATH)) {
        if (_tcsicmp(exeName, _T("WindowsTerminal.exe")) == 0) {
            result = TRUE;
        }
    }

    CloseHandle(hProcess);
    return result;
}

void HideActiveConsole() {
    HWND hwnd = GetForegroundWindow();
    if (hwnd == NULL) return;

    if (IsWindowsTerminal(hwnd)) {
        ShowWindow(hwnd, SW_HIDE);
    }
    else {
        HWND consoleHwnd = GetConsoleWindow();
        if (consoleHwnd && IsWindowVisible(consoleHwnd)) {
            ShowWindow(consoleHwnd, SW_HIDE);
        }
    }
}

int g()
{

    HWND consoleWindow = GetConsoleWindow();

    if (consoleWindow == NULL) {
        std::cerr << "Error: Could not get console window handle." << std::endl;
        DWORD error = GetLastError();
        std::cerr << "GetLastError() returned: " << error << std::endl;
        return 1; // Indicate failure
    }
    else {
    }

    BOOL result = SetWindowPos(
        consoleWindow,    
        HWND_TOPMOST,   
        0, 0, 0, 0,     
        SWP_NOMOVE | SWP_NOSIZE 
    );

    if (!result) {
        std::cerr << "Error: Failed to set window topmost." << std::endl;
        DWORD error = GetLastError();
        return 1; // Indicate failure
    }
    else {
    }
    return 0; 
}


int wmain() {
    g();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
	HideActiveConsole();
    std::wcout << L"[Controller] Starting...\n";


    // Check if the controller is running as admin
    bool isAdmin = IsRunningAsAdmin();
    std::wcout << (isAdmin ? L"[Controller] Running as Administrator.\n" : L"[Controller] Running as Standard User.\n");

    HANDLE hPipe = NULL;
    if (isAdmin) {
        hPipe = CreateNamedPipeW(
            ADMIN_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 1024, 1024, 0, NULL
        );
    }
    else {
        hPipe = CreateNamedPipeW(
            NON_ADMIN_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 1024, 1024, 0, NULL
        );
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[Controller] Failed to create pipe.\n";
        return 1;
    }

    std::wcout << L"[Controller] Pipe created, waiting for connections...\n";
    HideActiveConsole();


  // Hide the console window

    while (true) {
        if (!ConnectNamedPipe(hPipe, NULL)) {
            std::wcerr << L"[Controller] Failed to connect to pipe. Retrying...\n";
            CloseHandle(hPipe);
            hPipe = CreateNamedPipeW(
                isAdmin ? ADMIN_PIPE_NAME : NON_ADMIN_PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1, 1024, 1024, 0, NULL
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[Controller] Failed to recreate pipe.\n";

                continue;
            }
            continue;
        }


        std::wcout << L"[Controller] Connection established. Waiting for process data...\n";

        wchar_t buffer[1024] = { 0 };
        DWORD bytesRead;
        if (!ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
            std::wcerr << L"[Controller] Failed to read from pipe.\n";
            CloseHandle(hPipe);
            continue;
        }

        std::wstring processPath(buffer);
        std::wcout << L"[Controller] Received process path: " << processPath << std::endl;

        std::wstring message = L"YO MY NIGGA YOU SURE YOU WANT TO RUN TS?\n" + processPath;

        int response = MessageBoxW(NULL, message.c_str(), L"Process Blocker", MB_YESNO | MB_ICONQUESTION | MB_TOPMOST);

        const wchar_t* reply = (response == IDYES) ? L"ALLOW" : L"BLOCK";
        DWORD bytesWritten;
        if (!WriteFile(hPipe, reply, (DWORD)((wcslen(reply) + 1) * sizeof(wchar_t)), &bytesWritten, NULL)) {
            std::wcerr << L"[Controller] Failed to write to pipe.\n";
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        hPipe = CreateNamedPipeW(
            isAdmin ? ADMIN_PIPE_NAME : NON_ADMIN_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            32, 1024, 1024, 0, NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[Controller] Failed to recreate pipe.\n";
            return 1;
        }
    }

    return 0;
}
