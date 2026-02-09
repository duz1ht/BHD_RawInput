// dllmain.cpp : BHD_RawInput_Hook
//
// Features:
//  - Hooks the game window WndProc to capture WM_INPUT raw mouse deltas.
//  - Hooks user32!ClipCursor via EXE IAT patch to detect "captured" state.
//  - Publishes window-based stats via shared memory: "Local\\BHD_RawInput_Shared" (version 2).
//  - Injects WM_INPUT deltas into the game's RawMouseX/Y by hooking the game's
//    "FIX MOUSE LOGIC" block at 0x005E48C0 (from your RE asm).
//
// Goal:
//  - Feed the engine a sum of raw input counts since last game mouse tick.
//  - Provide observable metrics (windowed HW vs Inject) so the overlay can verify behavior.
//
// Build notes:
//  - x86
//  - Keep pch enabled for this file (include pch.h first).

#include "pch.h"
#include <windows.h>
#include <atomic>
#include <string>
#include <vector>
#include <stdint.h>

// ------------------------------------------------------------
// Paths + Logging
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
// New layout: version 2
// ------------------------------------------------------------

static const DWORD kCompareWindowMs = 100;

#pragma pack(push, 1)
struct SharedHudStateV2
{
    uint32_t magic;        // 'BHDR' = 0x52444842
    uint32_t version;      // 2

    volatile LONG isCaptured;      // 0/1 based on ClipCursor(rect)/ClipCursor(NULL)

    // Last raw input delta observed (most recent WM_INPUT)
    volatile LONG hwLastDx;
    volatile LONG hwLastDy;

    // Last injected delta consumed at game tick (most recent OnFixMouseLogic)
    volatile LONG injLastDx;
    volatile LONG injLastDy;

    // "Current window" (in-progress, rolling for kCompareWindowMs)
    volatile LONG hwWinCurX;
    volatile LONG hwWinCurY;
    volatile LONG injWinCurX;
    volatile LONG injWinCurY;

    // "Last window" (finalized snapshot)
    volatile LONG hwWinLastX;
    volatile LONG hwWinLastY;
    volatile LONG injWinLastX;
    volatile LONG injWinLastY;

    // Estimated rates (updated ~1Hz)
    volatile LONG estHwEventsPerSec;     // WM_INPUT non-zero events per second
    volatile LONG estInjTicksPerSec;     // OnFixMouseLogic calls per second (game mouse tickrate estimate)

    // Counters (monotonic, but not meant for human comparison)
    volatile LONG hwEventCount;          // WM_INPUT events with non-zero delta (since start)
    volatile LONG injTickCount;          // injection ticks (since start)

    volatile LONG lastUpdateMs;          // GetTickCount() when state was last updated
};
#pragma pack(pop)

static const wchar_t* kMapName = L"Local\\BHD_RawInput_Shared";

static HANDLE g_hMap = nullptr;
static SharedHudStateV2* g_hud = nullptr;

static void HudInit()
{
    if (g_hud) return;

    g_hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        (DWORD)sizeof(SharedHudStateV2),
        kMapName);

    if (!g_hMap)
    {
        LogLine(L"[hud] CreateFileMappingW failed");
        LogLineWithLastError(L"[hud] CreateFileMappingW error");
        return;
    }

    void* p = MapViewOfFile(g_hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedHudStateV2));
    if (!p)
    {
        LogLine(L"[hud] MapViewOfFile failed");
        LogLineWithLastError(L"[hud] MapViewOfFile error");
        CloseHandle(g_hMap);
        g_hMap = nullptr;
        return;
    }

    g_hud = reinterpret_cast<SharedHudStateV2*>(p);
    ZeroMemory((void*)g_hud, sizeof(*g_hud));

    g_hud->magic = 0x52444842; // 'BHDR'
    g_hud->version = 2;
    g_hud->lastUpdateMs = (LONG)GetTickCount();

    LogLine(L"[hud] Shared memory initialized: Local\\BHD_RawInput_Shared (v2)");
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
// Raw Input capture accumulation
// ------------------------------------------------------------

static std::atomic<LONG> g_pendingDx{ 0 };
static std::atomic<LONG> g_pendingDy{ 0 };

// For event rate estimation
static std::atomic<LONG> g_hwEventsThisSecond{ 0 };
static DWORD g_hwRateLastMs = 0;

// Windowing
static DWORD g_winStartMs = 0;
static LONG  g_hwWinAccX = 0;
static LONG  g_hwWinAccY = 0;
static LONG  g_injWinAccX = 0;
static LONG  g_injWinAccY = 0;

// For injection tickrate estimation
static std::atomic<LONG> g_injTicksThisSecond{ 0 };
static DWORD g_injRateLastMs = 0;

// ------------------------------------------------------------
// Window + rate helpers
// ------------------------------------------------------------

static void FinalizeWindowIfNeeded(DWORD now)
{
    if (g_winStartMs == 0)
        g_winStartMs = now;

    if ((DWORD)(now - g_winStartMs) < kCompareWindowMs)
        return;

    if (g_hud)
    {
        g_hud->hwWinLastX = g_hwWinAccX;
        g_hud->hwWinLastY = g_hwWinAccY;
        g_hud->injWinLastX = g_injWinAccX;
        g_hud->injWinLastY = g_injWinAccY;
    }

    g_hwWinAccX = 0;
    g_hwWinAccY = 0;
    g_injWinAccX = 0;
    g_injWinAccY = 0;
    g_winStartMs = now;
}

static void UpdateRatesIfNeeded(DWORD now)
{
    // Update both estimates about once per second
    if (g_hwRateLastMs == 0) g_hwRateLastMs = now;
    if (g_injRateLastMs == 0) g_injRateLastMs = now;

    if ((DWORD)(now - g_hwRateLastMs) >= 1000)
    {
        LONG v = g_hwEventsThisSecond.exchange(0, std::memory_order_relaxed);
        if (g_hud) g_hud->estHwEventsPerSec = v;
        g_hwRateLastMs = now;
    }

    if ((DWORD)(now - g_injRateLastMs) >= 1000)
    {
        LONG v = g_injTicksThisSecond.exchange(0, std::memory_order_relaxed);
        if (g_hud) g_hud->estInjTicksPerSec = v;
        g_injRateLastMs = now;
    }
}

// ------------------------------------------------------------
// Raw Input registration + WndProc hook
// ------------------------------------------------------------

static std::atomic<HWND>    g_hookedHwnd{ nullptr };
static std::atomic<WNDPROC> g_originalWndProc{ nullptr };
static std::atomic<bool>    g_wndprocHooked{ false };
static std::atomic<bool>    g_rawRegistered{ false };
static std::atomic<bool>    g_stop{ false };

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
                        g_pendingDx.fetch_add(dx, std::memory_order_relaxed);
                        g_pendingDy.fetch_add(dy, std::memory_order_relaxed);

                        DWORD now = GetTickCount();

                        // Update shared state
                        if (g_hud)
                        {
                            g_hud->hwLastDx = dx;
                            g_hud->hwLastDy = dy;

                            // Window accumulators for HW
                            g_hwWinAccX += dx;
                            g_hwWinAccY += dy;

                            g_hud->hwWinCurX = g_hwWinAccX;
                            g_hud->hwWinCurY = g_hwWinAccY;

                            InterlockedIncrement(&g_hud->hwEventCount);
                            g_hud->lastUpdateMs = (LONG)now;
                        }

                        g_hwEventsThisSecond.fetch_add(1, std::memory_order_relaxed);

                        // Maintain rolling windows and rates
                        FinalizeWindowIfNeeded(now);
                        UpdateRatesIfNeeded(now);
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

static DWORD GetThisPid() { return GetCurrentProcessId(); }

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
// ClipCursor hook to detect capture
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
// Game addresses (from your RE asm)
// ------------------------------------------------------------

static const uintptr_t ADDR_FIX_MOUSE_LOGIC = 0x005E48C0;
static const uintptr_t ADDR_FIX_MOUSE_RET = 0x005679BA;

static const uintptr_t ADDR_CURSOR_X = 0x00F655E0;
static const uintptr_t ADDR_CURSOR_Y = 0x00F655E4;
static const uintptr_t ADDR_RAWMOUSE_X = 0x00F655EC;
static const uintptr_t ADDR_RAWMOUSE_Y = 0x00F655F0;

static const uintptr_t ADDR_VID_WIDTH = 0x009F72C0;
static const uintptr_t ADDR_VID_HEIGHT = 0x009F72C4;

// Game window handle for cursor centering
static std::atomic<HWND> g_gameHwnd{ nullptr };

// ------------------------------------------------------------
// Minimal x86 detour (JMP rel32) for FIX MOUSE LOGIC
// ------------------------------------------------------------

static uint8_t g_fixMouseOrig[6]{};
static void* g_fixMouseTrampoline = nullptr;
static std::atomic<bool> g_fixMouseHooked{ false };

static void* MakeTrampoline(const uint8_t* origBytes, size_t origLen, void* backTo)
{
    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;

    memcpy(mem, origBytes, origLen);

    uint8_t* jmpAt = mem + origLen;
    jmpAt[0] = 0xE9;
    *(int32_t*)(jmpAt + 1) = (int32_t)((uint8_t*)backTo - (jmpAt + 5));

    FlushInstructionCache(GetCurrentProcess(), mem, 64);
    return mem;
}

static bool WriteJmp5(void* at, void* to, int extraNops)
{
    DWORD oldProt = 0;
    if (!VirtualProtect(at, 5 + extraNops, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;

    uint8_t* p = (uint8_t*)at;
    p[0] = 0xE9;
    *(int32_t*)(p + 1) = (int32_t)((uint8_t*)to - (p + 5));

    for (int i = 0; i < extraNops; ++i)
        p[5 + i] = 0x90;

    DWORD tmp = 0;
    VirtualProtect(at, 5 + extraNops, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), at, 5 + extraNops);
    return true;
}

static __forceinline LONG ReadI32(uintptr_t addr) { return *(volatile LONG*)addr; }
static __forceinline void WriteI32(uintptr_t addr, LONG v) { *(volatile LONG*)addr = v; }

static bool CenterCursorOnGameClient(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd)) return false;

    RECT rc{};
    if (!GetClientRect(hwnd, &rc)) return false;

    POINT pt{};
    pt.x = (rc.right - rc.left) / 2;
    pt.y = (rc.bottom - rc.top) / 2;

    if (!ClientToScreen(hwnd, &pt)) return false;

    ::SetCursorPos(pt.x, pt.y);
    return true;
}

// Called inside the detour
static bool __stdcall OnFixMouseLogic()
{
    if (!g_hud || g_hud->isCaptured == 0)
        return false;

    // Consume all raw counts since last game mouse tick
    LONG dx = (LONG)g_pendingDx.exchange(0, std::memory_order_relaxed);
    LONG dy = (LONG)g_pendingDy.exchange(0, std::memory_order_relaxed);

    DWORD now = GetTickCount();

    // Keep OS cursor centered to preserve capture behavior
    HWND hwnd = g_gameHwnd.load(std::memory_order_relaxed);
    CenterCursorOnGameClient(hwnd);

    // Keep engine cursor centered (in its own units)
    LONG w = ReadI32(ADDR_VID_WIDTH);
    LONG h = ReadI32(ADDR_VID_HEIGHT);
    LONG halfW = (w >> 1);
    LONG halfH = (h >> 1);

    // Inject into engine
    WriteI32(ADDR_RAWMOUSE_X, dx);
    WriteI32(ADDR_RAWMOUSE_Y, dy);
    WriteI32(ADDR_CURSOR_X, halfW);
    WriteI32(ADDR_CURSOR_Y, halfH);

    // Publish injection stats
    if (g_hud)
    {
        g_hud->injLastDx = dx;
        g_hud->injLastDy = dy;

        g_injWinAccX += dx;
        g_injWinAccY += dy;
        g_hud->injWinCurX = g_injWinAccX;
        g_hud->injWinCurY = g_injWinAccY;

        InterlockedIncrement(&g_hud->injTickCount);
        g_hud->lastUpdateMs = (LONG)now;
    }

    g_injTicksThisSecond.fetch_add(1, std::memory_order_relaxed);

    // Maintain rolling windows and rates (also handles cases with no WM_INPUT)
    FinalizeWindowIfNeeded(now);
    UpdateRatesIfNeeded(now);

    return true;
}

typedef void(__stdcall* FixMouseTrampFn)();
static FixMouseTrampFn g_fixMouseTrampFn = nullptr;

__declspec(naked) void FixMouseLogic_Detour()
{
    __asm {
        pushad
        pushfd
        call OnFixMouseLogic
        test eax, eax
        jz not_captured

        popfd
        popad
        mov eax, ADDR_FIX_MOUSE_RET
        jmp eax

        not_captured :
        popfd
            popad
            jmp g_fixMouseTrampFn
    }
}

static bool FixMouseBytesLookRight()
{
    uint8_t* p = (uint8_t*)ADDR_FIX_MOUSE_LOGIC;
    __try
    {
        if (p[0] != 0x03) return false;
        if (p[1] != 0x05) return false;
        if (*(uint32_t*)(p + 2) != 0x0060C326) return false;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool InstallFixMouseLogicHookOnce()
{
    if (g_fixMouseHooked.load(std::memory_order_relaxed))
        return true;

    if (!FixMouseBytesLookRight())
    {
        LogLine(L"[mouse] FIX MOUSE LOGIC bytes do not match expected pattern, not hooking");
        return false;
    }

    uint8_t* target = (uint8_t*)ADDR_FIX_MOUSE_LOGIC;
    memcpy(g_fixMouseOrig, target, sizeof(g_fixMouseOrig));

    void* backTo = (void*)(ADDR_FIX_MOUSE_LOGIC + 6);
    g_fixMouseTrampoline = MakeTrampoline(g_fixMouseOrig, 6, backTo);
    if (!g_fixMouseTrampoline)
    {
        LogLine(L"[mouse] Failed to allocate trampoline");
        return false;
    }

    g_fixMouseTrampFn = (FixMouseTrampFn)g_fixMouseTrampoline;

    if (!WriteJmp5(target, (void*)&FixMouseLogic_Detour, 1))
    {
        LogLine(L"[mouse] Failed to patch FIX MOUSE LOGIC");
        return false;
    }

    g_fixMouseHooked.store(true, std::memory_order_relaxed);
    LogLine(L"[mouse] FIX MOUSE LOGIC hook installed at 0x005E48C0");
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
            g_gameHwnd.store(best, std::memory_order_relaxed);

            TryInstallWndProcOnce(best);

            if (!g_rawRegistered.load(std::memory_order_relaxed))
            {
                if (RegisterRawInput(best))
                    g_rawRegistered.store(true, std::memory_order_relaxed);
            }

            if (!clipHooked)
                clipHooked = InstallClipCursorIAT();

            InstallFixMouseLogicHookOnce();
        }

        Sleep(200);
    }

    LogLine(L"[hook] MonitorThread stopping");
    HudShutdown();
    return 0;
}

// ------------------------------------------------------------
// Init thread + DllMain
// ------------------------------------------------------------

static DWORD WINAPI InitThread(LPVOID)
{
    LogLine(L"[hook] InitThread begin");

    HudInit();

    g_winStartMs = GetTickCount();
    g_hwRateLastMs = g_winStartMs;
    g_injRateLastMs = g_winStartMs;

    LogLine(L"[hook] WM_INPUT raw capture enabled");
    LogLine(L"[hook] ClipCursor hook enabled (capture detection)");
    LogLine(L"[hook] HUD shared memory: Local\\BHD_RawInput_Shared (v2)");
    LogLine(L"[hook] RawMouse injector: hook at 0x005E48C0 (FIX MOUSE LOGIC)");
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
