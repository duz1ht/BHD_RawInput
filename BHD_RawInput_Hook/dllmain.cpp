// dllmain.cpp : BHD_RawInput_Hook (WM_INPUT + ClipCursor + Shared Memory)
//
// This build does:
//  - Hooks the game window WndProc to capture WM_INPUT raw mouse deltas.
//  - Hooks user32!ClipCursor via EXE IAT patch to detect "captured" state.
//  - Publishes stats via shared memory: "Local\\BHD_RawInput_Shared".
//  - Writes hook_write.txt in the EXE directory using Win32 file APIs (reliable in DLL context).
//
// Build notes:
//  - x86
//  - Keep pch enabled for this file as in your project.

#include "pch.h"
#include <windows.h>
#include <atomic>
#include <string>
#include <vector>
#include <stdint.h>

// ------------------------------------------------------------
// Paths
// ------------------------------------------------------------

static std::wstring GetExeDirW()
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s(path);
    size_t slash = s.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? L"." : s.substr(0, slash);
}

static std::wstring JoinPathW(const std::wstring& a, const std::wstring& b)
{
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L"\\" + b;
}

static std::wstring g_logPath;

// ------------------------------------------------------------
// Logging (Win32, reliable for early DLL load)
// ------------------------------------------------------------

static void EnsureLogPathReady()
{
    if (!g_logPath.empty()) return;
    g_logPath = JoinPathW(GetExeDirW(), L"hook_write.txt");
}

static void LogLine(const wchar_t* line)
{
    EnsureLogPathReady();

    HANDLE h = CreateFileW(
        g_logPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (h == INVALID_HANDLE_VALUE)
        return;

    // Write UTF-16LE text as-is, with CRLF.
    DWORD bytes = 0;
    WriteFile(h, line, (DWORD)(wcslen(line) * sizeof(wchar_t)), &bytes, nullptr);

    const wchar_t crlf[] = L"\r\n";
    WriteFile(h, crlf, (DWORD)(2 * sizeof(wchar_t)), &bytes, nullptr);

    CloseHandle(h);
}

static void LogLineWithLastError(const wchar_t* prefix)
{
    DWORD e = GetLastError();
    wchar_t buf[256]{};
    wsprintfW(buf, L"%s (GetLastError=%lu)", prefix, (unsigned long)e);
    LogLine(buf);
}

// ------------------------------------------------------------
// Shared memory (overlay reads this)
// ------------------------------------------------------------

#pragma pack(push, 1)
struct SharedHudState
{
    uint32_t magic;       // 'BHDR'
    uint32_t version;     // 1

    volatile LONG isCaptured;      // 0/1 based on ClipCursor
    volatile LONG lastRawDx;       // last WM_INPUT delta
    volatile LONG lastRawDy;

    volatile LONG rawTotalX;       // running totals
    volatile LONG rawTotalY;

    volatile LONG rawEventCount;   // WM_INPUT events with non-zero delta
    volatile LONG tick;            // increments on each WM_INPUT non-zero delta

    volatile LONG lastUpdateMs;    // GetTickCount() at last update
};
#pragma pack(pop)

static HANDLE g_hMap = nullptr;
static SharedHudState* g_hud = nullptr;

static void HudInit()
{
    if (g_hud) return;

    g_hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        (DWORD)sizeof(SharedHudState),
        L"Local\\BHD_RawInput_Shared");

    if (!g_hMap)
    {
        LogLine(L"[hud] CreateFileMappingW failed");
        LogLineWithLastError(L"[hud] CreateFileMappingW error");
        return;
    }

    void* p = MapViewOfFile(g_hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedHudState));
    if (!p)
    {
        LogLine(L"[hud] MapViewOfFile failed");
        LogLineWithLastError(L"[hud] MapViewOfFile error");
        CloseHandle(g_hMap);
        g_hMap = nullptr;
        return;
    }

    g_hud = reinterpret_cast<SharedHudState*>(p);

    g_hud->magic = 0x52444842;   // 'BHDR'
    g_hud->version = 1;

    g_hud->isCaptured = 0;
    g_hud->lastRawDx = 0;
    g_hud->lastRawDy = 0;
    g_hud->rawTotalX = 0;
    g_hud->rawTotalY = 0;
    g_hud->rawEventCount = 0;
    g_hud->tick = 0;
    g_hud->lastUpdateMs = (LONG)GetTickCount();

    LogLine(L"[hud] Shared memory initialized: Local\\BHD_RawInput_Shared");
}

static void HudShutdown()
{
    if (g_hud)
    {
        UnmapViewOfFile(g_hud);
        g_hud = nullptr;
    }
    if (g_hMap)
    {
        CloseHandle(g_hMap);
        g_hMap = nullptr;
    }
}

// ------------------------------------------------------------
// Raw Input state
// ------------------------------------------------------------

static std::atomic<long> g_rawDx{ 0 };
static std::atomic<long> g_rawDy{ 0 };

static std::atomic<HWND>    g_hookedHwnd{ nullptr };
static std::atomic<WNDPROC> g_originalWndProc{ nullptr };
static std::atomic<bool>    g_wndprocHooked{ false };
static std::atomic<bool>    g_rawRegistered{ false };
static std::atomic<bool>    g_stop{ false };

// ------------------------------------------------------------
// Raw Input registration
// ------------------------------------------------------------

static bool RegisterRawInput(HWND hwnd)
{
    RAWINPUTDEVICE rid{};
    rid.usUsagePage = 0x01; // Generic Desktop Controls
    rid.usUsage = 0x02;     // Mouse
    rid.dwFlags = RIDEV_INPUTSINK;
    rid.hwndTarget = hwnd;

    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid)))
    {
        LogLine(L"[raw] RegisterRawInputDevices FAILED");
        LogLineWithLastError(L"[raw] RegisterRawInputDevices error");
        return false;
    }

    LogLine(L"[raw] RegisterRawInputDevices OK");
    return true;
}

// ------------------------------------------------------------
// WndProc hook (WM_INPUT capture only)
// ------------------------------------------------------------

static LRESULT CALLBACK HookWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_INPUT)
    {
        UINT size = 0;
        GetRawInputData((HRAWINPUT)lParam, RID_INPUT, nullptr, &size, sizeof(RAWINPUTHEADER));

        if (size > 0 && size < 4096)
        {
            std::vector<BYTE> buffer(size);
            if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, buffer.data(), &size, sizeof(RAWINPUTHEADER)) == size)
            {
                RAWINPUT* ri = reinterpret_cast<RAWINPUT*>(buffer.data());
                if (ri->header.dwType == RIM_TYPEMOUSE)
                {
                    LONG dx = ri->data.mouse.lLastX;
                    LONG dy = ri->data.mouse.lLastY;

                    if (dx || dy)
                    {
                        g_rawDx.fetch_add(dx, std::memory_order_relaxed);
                        g_rawDy.fetch_add(dy, std::memory_order_relaxed);

                        if (g_hud)
                        {
                            g_hud->lastRawDx = dx;
                            g_hud->lastRawDy = dy;

                            InterlockedExchangeAdd(&g_hud->rawTotalX, dx);
                            InterlockedExchangeAdd(&g_hud->rawTotalY, dy);

                            InterlockedIncrement(&g_hud->rawEventCount);
                            InterlockedIncrement(&g_hud->tick);

                            g_hud->lastUpdateMs = (LONG)GetTickCount();
                        }
                    }
                }
            }
        }

        return 0;
    }

    WNDPROC orig = g_originalWndProc.load(std::memory_order_relaxed);
    return orig ? CallWindowProcW(orig, hwnd, msg, wParam, lParam)
        : DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ------------------------------------------------------------
// Find best window for this PID (largest client area)
// ------------------------------------------------------------

static DWORD GetThisPid()
{
    return GetCurrentProcessId();
}

struct Candidate
{
    HWND hwnd = nullptr;
    int area = 0;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    Candidate* best = reinterpret_cast<Candidate*>(lParam);

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetThisPid()) return TRUE;

    if (GetWindow(hwnd, GW_OWNER)) return TRUE;

    LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
    if (ex & WS_EX_TOOLWINDOW) return TRUE;

    RECT rc{};
    if (!GetClientRect(hwnd, &rc)) return TRUE;

    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if (w < 400 || h < 300) return TRUE;

    int area = w * h;
    if (area > best->area)
    {
        best->area = area;
        best->hwnd = hwnd;
    }

    return TRUE;
}

static HWND FindBestGameWindow()
{
    Candidate best{};
    EnumWindows(EnumWindowsProc, (LPARAM)&best);
    return best.hwnd;
}

// ------------------------------------------------------------
// IAT patching (ClipCursor)
// ------------------------------------------------------------

static bool PatchIAT_ByFunctionName(void* moduleBase, const char* funcName, void* newFunc, void** outOriginal)
{
    if (!moduleBase || !funcName || !newFunc) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>((BYTE*)moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>((BYTE*)moduleBase + dir.VirtualAddress);

    for (; imp->Name; ++imp)
    {
        IMAGE_THUNK_DATA* thunkIAT = reinterpret_cast<IMAGE_THUNK_DATA*>((BYTE*)moduleBase + imp->FirstThunk);
        IMAGE_THUNK_DATA* thunkNames =
            (imp->OriginalFirstThunk)
            ? reinterpret_cast<IMAGE_THUNK_DATA*>((BYTE*)moduleBase + imp->OriginalFirstThunk)
            : thunkIAT;

        if (!thunkIAT || !thunkNames) continue;

        for (; thunkIAT->u1.Function; ++thunkIAT, ++thunkNames)
        {
            if (thunkNames->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                continue;

            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>((BYTE*)moduleBase + thunkNames->u1.AddressOfData);
            if (!ibn) continue;

            const char* name = reinterpret_cast<const char*>(ibn->Name);
            if (!name) continue;

            if (lstrcmpA(name, funcName) != 0)
                continue;

            DWORD oldProt = 0;
            if (!VirtualProtect(&thunkIAT->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProt))
                return false;

            void* original = reinterpret_cast<void*>((uintptr_t)thunkIAT->u1.Function);
            thunkIAT->u1.Function = (uintptr_t)newFunc;

            VirtualProtect(&thunkIAT->u1.Function, sizeof(void*), oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), &thunkIAT->u1.Function, sizeof(void*));

            if (outOriginal) *outOriginal = original;
            return true;
        }
    }

    return false;
}

// ------------------------------------------------------------
// ClipCursor hook to detect in-map capture
// ------------------------------------------------------------

typedef BOOL(WINAPI* PFN_ClipCursor)(const RECT*);
static PFN_ClipCursor g_realClipCursor = nullptr;

static BOOL WINAPI HookClipCursor(const RECT* rc)
{
    if (g_hud)
        g_hud->isCaptured = (rc ? 1 : 0);

    return g_realClipCursor ? g_realClipCursor(rc) : FALSE;
}

static bool InstallClipCursorIAT()
{
    void* exeBase = GetModuleHandleW(nullptr);
    if (!exeBase) return false;

    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (!hUser32) hUser32 = LoadLibraryW(L"user32.dll");
    if (!hUser32) return false;

    g_realClipCursor = (PFN_ClipCursor)GetProcAddress(hUser32, "ClipCursor");
    if (!g_realClipCursor) return false;

    void* orig = nullptr;
    bool ok = PatchIAT_ByFunctionName(exeBase, "ClipCursor", (void*)&HookClipCursor, &orig);
    if (ok && orig) g_realClipCursor = (PFN_ClipCursor)orig;

    if (ok) LogLine(L"[cursor] IAT patched: ClipCursor");
    else    LogLine(L"[cursor] IAT patch failed for ClipCursor");

    return ok;
}

// ------------------------------------------------------------
// One-shot WndProc hook installer
// ------------------------------------------------------------

static bool TryInstallWndProcOnce(HWND hwnd)
{
    if (!hwnd) return false;
    if (g_wndprocHooked.load(std::memory_order_relaxed)) return false;

    SetLastError(0);
    LONG_PTR prev = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)HookWndProc);
    DWORD e = GetLastError();

    if (prev == 0 && e != 0)
    {
        LogLine(L"[hook] SetWindowLongPtrW FAILED");
        LogLineWithLastError(L"[hook] SetWindowLongPtrW error");
        return false;
    }

    g_originalWndProc.store((WNDPROC)prev, std::memory_order_relaxed);
    g_hookedHwnd.store(hwnd, std::memory_order_relaxed);
    g_wndprocHooked.store(true, std::memory_order_relaxed);

    LogLine(L"[hook] WndProc hooked ONCE");
    return true;
}

// ------------------------------------------------------------
// Monitor thread
// ------------------------------------------------------------

static DWORD WINAPI MonitorThread(LPVOID)
{
    LogLine(L"[hook] MonitorThread started");

    bool clipHooked = false;

    while (!g_stop.load(std::memory_order_relaxed))
    {
        HWND best = FindBestGameWindow();
        if (best)
        {
            TryInstallWndProcOnce(best);

            if (!g_rawRegistered.load(std::memory_order_relaxed))
            {
                if (RegisterRawInput(best))
                    g_rawRegistered.store(true, std::memory_order_relaxed);
            }

            if (!clipHooked)
                clipHooked = InstallClipCursorIAT();
        }

        Sleep(200);
    }

    LogLine(L"[hook] MonitorThread stopping");
    HudShutdown();

    return 0;
}

// ------------------------------------------------------------
// Init thread and DllMain
// ------------------------------------------------------------

static DWORD WINAPI InitThread(LPVOID)
{
    LogLine(L"[hook] InitThread begin");

    HudInit();

    LogLine(L"[hook] WM_INPUT raw capture enabled");
    LogLine(L"[hook] ClipCursor hook enabled (capture detection)");
    LogLine(L"[hook] HUD shared memory: Local\\BHD_RawInput_Shared");
    LogLine(L"[hook] InitThread end");

    HANDLE h = CreateThread(nullptr, 0, MonitorThread, nullptr, 0, nullptr);
    if (!h)
    {
        LogLine(L"[hook] CreateThread(MonitorThread) FAILED");
        LogLineWithLastError(L"[hook] CreateThread error");
    }
    else
    {
        CloseHandle(h);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        g_stop.store(false, std::memory_order_relaxed);

        // Create log immediately to prove attach ran.
        LogLine(L"[hook] DLL_PROCESS_ATTACH");

        HANDLE h = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (!h)
        {
            LogLine(L"[hook] CreateThread(InitThread) FAILED");
            LogLineWithLastError(L"[hook] CreateThread error");
        }
        else
        {
            CloseHandle(h);
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        g_stop.store(true, std::memory_order_relaxed);
        LogLine(L"[hook] DLL_PROCESS_DETACH");
    }

    return TRUE;
}
