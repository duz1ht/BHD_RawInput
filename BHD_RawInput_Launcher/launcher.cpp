#include <windows.h>
#include <string>
#include <vector>
#include <fstream>

static std::wstring GetExePath()
{
    wchar_t path[MAX_PATH]{ 0 };
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return std::wstring(path);
}

static std::wstring GetExeDir()
{
    std::wstring p = GetExePath();
    size_t slash = p.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L".";
    return p.substr(0, slash);
}

static std::wstring JoinPath(const std::wstring& a, const std::wstring& b)
{
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L"\\" + b;
}

static std::wstring Trim(const std::wstring& value)
{
    const std::wstring whitespace = L" \t\r\n";
    const size_t start = value.find_first_not_of(whitespace);
    if (start == std::wstring::npos) return L"";
    const size_t end = value.find_last_not_of(whitespace);
    return value.substr(start, end - start + 1);
}

static bool IsPathAbsolute(const std::wstring& p)
{
    if (p.size() >= 2 && p[1] == L':') return true;
    if (p.size() >= 2 && ((p[0] == L'\\' && p[1] == L'\\') || (p[0] == L'/' && p[1] == L'/'))) return true;
    return false;
}

static bool FileExists(const std::wstring& p)
{
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void LogLine(std::wofstream& log, const std::wstring& s)
{
    log << s << L"\r\n";
    log.flush();
}

static void MsgError(const std::wstring& msg)
{
    MessageBoxW(nullptr, msg.c_str(), L"BHD_RawInput_Launcher", MB_ICONERROR | MB_OK);
}

static std::wstring ReadGameExeFromIni(const std::wstring& exeDir, std::wofstream& log)
{
    const std::wstring iniPath = JoinPath(exeDir, L"RawInput_Launcher.ini");
    if (!FileExists(iniPath))
    {
        LogLine(log, L"[launcher] RawInput_Launcher.ini not found. Using default.");
        return L"";
    }

    std::wifstream ini(iniPath);
    if (!ini.is_open())
    {
        LogLine(log, L"[launcher] RawInput_Launcher.ini exists but could not be opened.");
        return L"";
    }

    std::wstring line;
    while (std::getline(ini, line))
    {
        std::wstring trimmed = Trim(line);
        if (trimmed.empty()) continue;
        if (trimmed[0] == L';' || trimmed[0] == L'#') continue;

        size_t equals = trimmed.find(L'=');
        if (equals != std::wstring::npos)
        {
            trimmed = Trim(trimmed.substr(equals + 1));
        }

        if (!trimmed.empty())
        {
            LogLine(log, L"[launcher] RawInput_Launcher.ini gameExe entry: " + trimmed);
            return trimmed;
        }
    }

    LogLine(log, L"[launcher] RawInput_Launcher.ini is present but contains no valid game exe entry.");
    return L"";
}

static bool InjectDll(DWORD pid, const std::wstring& dllPath, std::wofstream& log)
{
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProc)
    {
        LogLine(log, L"[inject] OpenProcess failed. GetLastError=" + std::to_wstring(GetLastError()));
        return false;
    }

    const size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remoteMem = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem)
    {
        LogLine(log, L"[inject] VirtualAllocEx failed. GetLastError=" + std::to_wstring(GetLastError()));
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteMem, dllPath.c_str(), bytes, nullptr))
    {
        LogLine(log, L"[inject] WriteProcessMemory failed. GetLastError=" + std::to_wstring(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel)
    {
        LogLine(log, L"[inject] GetModuleHandleW(kernel32.dll) failed. GetLastError=" + std::to_wstring(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    FARPROC p = GetProcAddress(hKernel, "LoadLibraryW");
    if (!p)
    {
        LogLine(log, L"[inject] GetProcAddress(LoadLibraryW) failed. GetLastError=" + std::to_wstring(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    auto pLoadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(p);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLibraryW, remoteMem, 0, nullptr);
    if (!hThread)
    {
        LogLine(log, L"[inject] CreateRemoteThread failed. GetLastError=" + std::to_wstring(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    LogLine(log, L"[inject] LoadLibraryW returned (thread exit code) = " + std::to_wstring(exitCode));

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return (exitCode != 0);
}

int wmain(int argc, wchar_t** argv)
{
    const std::wstring exeDir = GetExeDir();
    const std::wstring logPath = JoinPath(exeDir, L"launcher_log.txt");

    std::wofstream log(logPath, std::ios::out | std::ios::trunc);
    if (!log.is_open())
    {
        MsgError(L"Could not create launcher_log.txt. Try running as Administrator for a quick test.");
        return 10;
    }

    LogLine(log, L"[launcher] Started.");
    LogLine(log, L"[launcher] ExeDir: " + exeDir);

    std::wstring gameExe;
    if (argc >= 2)
    {
        gameExe = argv[1];
        LogLine(log, L"[launcher] gameExe overridden by command-line argument.");
    }
    else
    {
        gameExe = ReadGameExeFromIni(exeDir, log);
        if (gameExe.empty())
        {
            gameExe = L"dfbhd.exe";
            LogLine(log, L"[launcher] Using default gameExe: dfbhd.exe");
        }
    }

    if (!IsPathAbsolute(gameExe))
    {
        gameExe = JoinPath(exeDir, gameExe);
    }

    const std::wstring dllPath = JoinPath(exeDir, L"BHD_RawInput_Hook.dll");

    LogLine(log, L"[launcher] gameExe: " + gameExe);
    LogLine(log, L"[launcher] dllPath: " + dllPath);

    if (!FileExists(gameExe))
    {
        LogLine(log, L"[launcher] ERROR: game executable not found.");
        MsgError(L"The game executable was not found. Check launcher_log.txt for details.");
        return 1;
    }

    if (!FileExists(dllPath))
    {
        LogLine(log, L"[launcher] ERROR: BHD_RawInput_Hook.dll not found.");
        MsgError(L"BHD_RawInput_Hook.dll was not found. Check launcher_log.txt for details.");
        return 2;
    }

    std::wstring workDir;
    {
        size_t slash = gameExe.find_last_of(L"\\/");
        workDir = (slash == std::wstring::npos) ? exeDir : gameExe.substr(0, slash);
    }
    LogLine(log, L"[launcher] workDir: " + workDir);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring cmdLine = L"\"" + gameExe + L"\"";
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    LogLine(log, L"[launcher] CreateProcessW with CREATE_SUSPENDED...");

    BOOL ok = CreateProcessW(
        nullptr,
        cmdBuf.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        workDir.c_str(),
        &si,
        &pi
    );

    if (!ok)
    {
        DWORD err = GetLastError();
        LogLine(log, L"[launcher] ERROR: CreateProcessW failed. GetLastError=" + std::to_wstring(err));
        MsgError(L"CreateProcessW failed. Check launcher_log.txt for details.");
        return 3;
    }

    LogLine(log, L"[launcher] Process created. PID=" + std::to_wstring(pi.dwProcessId));

    LogLine(log, L"[launcher] Injecting DLL...");
    if (!InjectDll(pi.dwProcessId, dllPath, log))
    {
        DWORD err = GetLastError();
        LogLine(log, L"[launcher] ERROR: Injection failed. GetLastError=" + std::to_wstring(err));
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        MsgError(L"Injection failed. Check launcher_log.txt for details.");
        return 4;
    }

    LogLine(log, L"[launcher] DLL injected. Resuming main thread...");
    ResumeThread(pi.hThread);

    LogLine(log, L"[launcher] Waiting 3000ms to confirm the game stayed open...");
    Sleep(3000);

    DWORD procExit = 0;
    if (GetExitCodeProcess(pi.hProcess, &procExit))
    {
        if (procExit == STILL_ACTIVE)
        {
            LogLine(log, L"[launcher] OK: process is still running (STILL_ACTIVE).");
        }
        else
        {
            LogLine(log, L"[launcher] WARNING: process exited quickly. ExitCode=" + std::to_wstring(procExit));
            MsgError(L"The game exited shortly after launch. Check launcher_log.txt for the ExitCode.");
        }
    }
    else
    {
        LogLine(log, L"[launcher] GetExitCodeProcess failed. GetLastError=" + std::to_wstring(GetLastError()));
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    LogLine(log, L"[launcher] Finished.");
    return 0;
}
