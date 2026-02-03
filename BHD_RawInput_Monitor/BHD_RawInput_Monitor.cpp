// BHD Transparent RawInput HUD.cpp
//
// Transparent click-through overlay aligned to dfbhd.exe client area.
// Reads:
//  1) Hardware WM_INPUT totals from shared memory: Local\\BHD_RawInput_Shared
//  2) Game engine mouse values from dfbhd.exe memory: CursorX/Y and RawMouseX/Y
//
// Adds comparator (Option 1):
//  - Learns kX/kY as median(Game/HW) over recent "good" windows
//  - Converts game deltas to "counts-equivalent": GameEq = Game / k
//  - Displays HW counts, Game units, k, GameEq counts, and DiffEq
//  - Shows both current window-in-progress (cur) and last finalized window (last)
//
// Build notes:
//  - x86, Unicode
//  - Linker -> Input -> Additional Dependencies: dwmapi.lib
//  - Subsystem: Windows (/SUBSYSTEM:WINDOWS)

#include <windows.h>
#include <dwmapi.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <string>
#include <sstream>
#include <atomic>
#include <vector>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "dwmapi.lib")

// Comparator window length (ms)
static const DWORD COMPARE_WINDOW_MS = 100;

// Only accept ratio samples when the HW signal is strong enough
static const LONG MIN_HW_FOR_RATIO = 10;

// How many ratio samples to keep for median k
static const int RATIO_HISTORY = 120;

#pragma pack(push, 1)
struct SharedHudState
{
    uint32_t magic;       // 'BHDR' = 0x52444842
    uint32_t version;     // 1

    volatile LONG isCaptured;      // 0/1 based on ClipCursor(rect)/ClipCursor(NULL)
    volatile LONG lastRawDx;       // last WM_INPUT delta
    volatile LONG lastRawDy;

    volatile LONG rawTotalX;       // running totals
    volatile LONG rawTotalY;

    volatile LONG rawEventCount;   // WM_INPUT events with non-zero delta
    volatile LONG tick;            // increments on each WM_INPUT non-zero delta

    volatile LONG lastUpdateMs;    // GetTickCount() at last update
};
#pragma pack(pop)

static const wchar_t* kMapName = L"Local\\BHD_RawInput_Shared";
static const wchar_t* kGameExeName = L"dfbhd.exe";

// Game memory addresses (from your analysis)
static const uintptr_t ADDR_CURSOR_X = 0x00F655E0;
static const uintptr_t ADDR_CURSOR_Y = 0x00F655E4;
static const uintptr_t ADDR_RAWMOUSE_X = 0x00F655EC;
static const uintptr_t ADDR_RAWMOUSE_Y = 0x00F655F0;

static HANDLE g_hMap = nullptr;
static SharedHudState* g_state = nullptr;

static HWND g_hwnd = nullptr;
static HFONT g_font = nullptr;

static HWND g_targetHwnd = nullptr;
static DWORD g_targetPid = 0;
static HANDLE g_hProc = nullptr;

static std::atomic<bool> g_stop{ false };

// Game sampled values (overlay side)
static std::atomic<LONG> g_gameCursorX{ 0 };
static std::atomic<LONG> g_gameCursorY{ 0 };
static std::atomic<LONG> g_gameRawX{ 0 };
static std::atomic<LONG> g_gameRawY{ 0 };

static std::atomic<LONG> g_gameTotalX{ 0 };
static std::atomic<LONG> g_gameTotalY{ 0 };
static std::atomic<LONG> g_gameSamples{ 0 };
static std::atomic<DWORD> g_gameLastMs{ 0 };

// Previous totals for frame deltas (overlay approximations)
static LONG g_prevRawTotalX = 0;
static LONG g_prevRawTotalY = 0;
static LONG g_prevGameTotalX = 0;
static LONG g_prevGameTotalY = 0;

// Comparator window accumulators (current in-progress window)
static std::atomic<LONG> g_hwWinX{ 0 };
static std::atomic<LONG> g_hwWinY{ 0 };
static std::atomic<LONG> g_gameWinX{ 0 };
static std::atomic<LONG> g_gameWinY{ 0 };
static std::atomic<DWORD> g_winStartMs{ 0 };

// Latest finalized window snapshot (stable reference)
static std::atomic<LONG> g_hwWinLastX{ 0 };
static std::atomic<LONG> g_hwWinLastY{ 0 };
static std::atomic<LONG> g_gameWinLastX{ 0 };
static std::atomic<LONG> g_gameWinLastY{ 0 };

// Learned k (median ratio) snapshot
static std::atomic<double> g_kX{ 1.0 };
static std::atomic<double> g_kY{ 1.0 };

// Ratio history ring buffers (protected by a simple critical section)
static CRITICAL_SECTION g_ratioCs;
static bool g_ratioCsInit = false;

static std::vector<double> g_ratioX;
static std::vector<double> g_ratioY;
static int g_ratioPosX = 0;
static int g_ratioPosY = 0;

static void EnsureRatioCS()
{
    if (!g_ratioCsInit)
    {
        InitializeCriticalSection(&g_ratioCs);
        g_ratioCsInit = true;
    }
}

static void ResetRatioHistory()
{
    EnsureRatioCS();
    EnterCriticalSection(&g_ratioCs);

    g_ratioX.assign(RATIO_HISTORY, 0.0);
    g_ratioY.assign(RATIO_HISTORY, 0.0);
    g_ratioPosX = 0;
    g_ratioPosY = 0;

    LeaveCriticalSection(&g_ratioCs);

    g_kX.store(1.0, std::memory_order_relaxed);
    g_kY.store(1.0, std::memory_order_relaxed);
}

static void PushRatioSample(std::vector<double>& buf, int& pos, double v)
{
    if ((int)buf.size() != RATIO_HISTORY)
        buf.assign(RATIO_HISTORY, 0.0);

    if (pos < 0 || pos >= RATIO_HISTORY) pos = 0;
    buf[pos] = v;
    pos = (pos + 1) % RATIO_HISTORY;
}

static double MedianOfNonZero(const std::vector<double>& buf)
{
    std::vector<double> tmp;
    tmp.reserve(buf.size());

    for (double v : buf)
    {
        if (v > 0.0 && std::isfinite(v))
            tmp.push_back(v);
    }

    if (tmp.size() < 5)
        return 1.0;

    std::sort(tmp.begin(), tmp.end());
    size_t n = tmp.size();
    if (n % 2 == 1)
        return tmp[n / 2];
    return 0.5 * (tmp[n / 2 - 1] + tmp[n / 2]);
}

static void RecomputeKFromHistory()
{
    EnsureRatioCS();
    EnterCriticalSection(&g_ratioCs);

    double mx = MedianOfNonZero(g_ratioX);
    double my = MedianOfNonZero(g_ratioY);

    LeaveCriticalSection(&g_ratioCs);

    if (mx <= 0.0 || !std::isfinite(mx)) mx = 1.0;
    if (my <= 0.0 || !std::isfinite(my)) my = 1.0;

    g_kX.store(mx, std::memory_order_relaxed);
    g_kY.store(my, std::memory_order_relaxed);
}

// ------------------------------------------------------------
// Shared memory (from DLL)
// ------------------------------------------------------------

static bool OpenShared()
{
    if (g_state) return true;

    g_hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, kMapName);
    if (!g_hMap) return false;

    void* p = MapViewOfFile(g_hMap, FILE_MAP_READ, 0, 0, sizeof(SharedHudState));
    if (!p)
    {
        CloseHandle(g_hMap);
        g_hMap = nullptr;
        return false;
    }

    g_state = reinterpret_cast<SharedHudState*>(p);
    return true;
}

static void CloseShared()
{
    if (g_state)
    {
        UnmapViewOfFile(g_state);
        g_state = nullptr;
    }
    if (g_hMap)
    {
        CloseHandle(g_hMap);
        g_hMap = nullptr;
    }
}

static bool IsValidState()
{
    if (!g_state) return false;
    if (g_state->magic != 0x52444842) return false; // 'BHDR'
    if (g_state->version != 1) return false;
    return true;
}

// ------------------------------------------------------------
// Process discovery
// ------------------------------------------------------------

static DWORD FindProcessIdByName(const wchar_t* exeName)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, exeName) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

struct FindWindowCtx
{
    DWORD pid = 0;
    HWND best = nullptr;
    int bestArea = 0;
};

static BOOL CALLBACK EnumWindowsForPid(HWND hwnd, LPARAM lParam)
{
    FindWindowCtx* ctx = reinterpret_cast<FindWindowCtx*>(lParam);

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid) return TRUE;

    if (!IsWindowVisible(hwnd)) return TRUE;
    if (GetWindow(hwnd, GW_OWNER)) return TRUE;

    LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
    if (ex & WS_EX_TOOLWINDOW) return TRUE;

    RECT rc{};
    if (!GetClientRect(hwnd, &rc)) return TRUE;

    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if (w < 200 || h < 200) return TRUE;

    int area = w * h;
    if (area > ctx->bestArea)
    {
        ctx->bestArea = area;
        ctx->best = hwnd;
    }

    return TRUE;
}

static HWND FindBestWindowForPid(DWORD pid)
{
    if (!pid) return nullptr;

    FindWindowCtx ctx{};
    ctx.pid = pid;

    EnumWindows(EnumWindowsForPid, (LPARAM)&ctx);
    return ctx.best;
}

static bool GetClientRectOnScreen(HWND target, RECT& out)
{
    RECT rcClient{};
    if (!GetClientRect(target, &rcClient)) return false;

    POINT tl{ rcClient.left, rcClient.top };
    POINT br{ rcClient.right, rcClient.bottom };

    if (!ClientToScreen(target, &tl)) return false;
    if (!ClientToScreen(target, &br)) return false;

    out.left = tl.x;
    out.top = tl.y;
    out.right = br.x;
    out.bottom = br.y;
    return true;
}

// ------------------------------------------------------------
// Process handle + RPM
// ------------------------------------------------------------

static void CloseProcessHandle()
{
    if (g_hProc)
    {
        CloseHandle(g_hProc);
        g_hProc = nullptr;
    }
}

static bool EnsureProcessHandle()
{
    if (g_hProc) return true;
    if (!g_targetPid) return false;

    g_hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_targetPid);
    return (g_hProc != nullptr);
}

static bool ReadI32(uintptr_t addr, LONG& out)
{
    if (!EnsureProcessHandle()) return false;

    SIZE_T got = 0;
    LONG tmp = 0;
    if (!ReadProcessMemory(g_hProc, (LPCVOID)addr, &tmp, sizeof(tmp), &got) || got != sizeof(tmp))
        return false;

    out = tmp;
    return true;
}

// ------------------------------------------------------------
// Comparator window helpers
// ------------------------------------------------------------

static void ResetComparatorWindow(DWORD nowMs)
{
    g_hwWinX.store(0, std::memory_order_relaxed);
    g_hwWinY.store(0, std::memory_order_relaxed);
    g_gameWinX.store(0, std::memory_order_relaxed);
    g_gameWinY.store(0, std::memory_order_relaxed);
    g_winStartMs.store(nowMs, std::memory_order_relaxed);
}

static void FinalizeComparatorWindowAndLearnK()
{
    LONG hwX = g_hwWinX.load(std::memory_order_relaxed);
    LONG hwY = g_hwWinY.load(std::memory_order_relaxed);
    LONG gameX = g_gameWinX.load(std::memory_order_relaxed);
    LONG gameY = g_gameWinY.load(std::memory_order_relaxed);

    g_hwWinLastX.store(hwX, std::memory_order_relaxed);
    g_hwWinLastY.store(hwY, std::memory_order_relaxed);
    g_gameWinLastX.store(gameX, std::memory_order_relaxed);
    g_gameWinLastY.store(gameY, std::memory_order_relaxed);

    // Learn ratio samples only when HW signal is strong enough
    EnsureRatioCS();
    EnterCriticalSection(&g_ratioCs);

    if (std::labs(hwX) >= MIN_HW_FOR_RATIO)
    {
        double r = (double)std::labs(gameX) / (double)std::labs(hwX);
        if (r > 0.0 && std::isfinite(r))
            PushRatioSample(g_ratioX, g_ratioPosX, r);
    }

    if (std::labs(hwY) >= MIN_HW_FOR_RATIO)
    {
        double r = (double)std::labs(gameY) / (double)std::labs(hwY);
        if (r > 0.0 && std::isfinite(r))
            PushRatioSample(g_ratioY, g_ratioPosY, r);
    }

    LeaveCriticalSection(&g_ratioCs);

    RecomputeKFromHistory();

    ResetComparatorWindow(GetTickCount());
}

static void MaybeFinalizeComparatorWindow()
{
    DWORD now = GetTickCount();
    DWORD start = g_winStartMs.load(std::memory_order_relaxed);

    if (start == 0)
    {
        ResetComparatorWindow(now);
        return;
    }

    if ((now - start) < COMPARE_WINDOW_MS)
        return;

    FinalizeComparatorWindowAndLearnK();
}

static void AppendFixed4(std::wstringstream& ss, double v)
{
    wchar_t buf[64]{};
    swprintf_s(buf, L"%.4f", v);
    ss << buf;
}

static double SafeK(double k)
{
    if (!(k > 0.0) || !std::isfinite(k)) return 1.0;
    return k;
}

static LONG GameToEqCounts(LONG game, double k)
{
    k = SafeK(k);
    double v = (double)game / k;
    if (!std::isfinite(v)) return 0;
    return (LONG)std::llround(v);
}

// ------------------------------------------------------------
// Game polling thread
// ------------------------------------------------------------

static DWORD WINAPI GamePollThread(LPVOID)
{
    while (!g_stop.load(std::memory_order_relaxed))
    {
        if (g_targetPid == 0)
        {
            Sleep(50);
            continue;
        }

        if (!EnsureProcessHandle())
        {
            Sleep(50);
            continue;
        }

        LONG cx = 0, cy = 0, rx = 0, ry = 0;
        bool ok1 = ReadI32(ADDR_CURSOR_X, cx);
        bool ok2 = ReadI32(ADDR_CURSOR_Y, cy);
        bool ok3 = ReadI32(ADDR_RAWMOUSE_X, rx);
        bool ok4 = ReadI32(ADDR_RAWMOUSE_Y, ry);

        if (ok1) g_gameCursorX.store(cx, std::memory_order_relaxed);
        if (ok2) g_gameCursorY.store(cy, std::memory_order_relaxed);

        if (ok3) g_gameRawX.store(rx, std::memory_order_relaxed);
        if (ok4) g_gameRawY.store(ry, std::memory_order_relaxed);

        if (ok3 && ok4)
        {
            if (rx != 0 || ry != 0)
            {
                g_gameTotalX.fetch_add(rx, std::memory_order_relaxed);
                g_gameTotalY.fetch_add(ry, std::memory_order_relaxed);

                // Add to game comparator window (engine units)
                g_gameWinX.fetch_add(rx, std::memory_order_relaxed);
                g_gameWinY.fetch_add(ry, std::memory_order_relaxed);
            }

            g_gameSamples.fetch_add(1, std::memory_order_relaxed);
            g_gameLastMs.store(GetTickCount(), std::memory_order_relaxed);
        }

        Sleep(2);
    }

    return 0;
}

// ------------------------------------------------------------
// Text render
// ------------------------------------------------------------

static std::wstring MakeText()
{
    bool haveShared = OpenShared() && IsValidState();

    LONG cap = 0;
    LONG hwLastDx = 0, hwLastDy = 0;
    LONG hwTotalX = 0, hwTotalY = 0;
    LONG hwEvents = 0, hwTick = 0;
    DWORD hwAge = 0;

    if (haveShared)
    {
        cap = g_state->isCaptured;
        hwLastDx = g_state->lastRawDx;
        hwLastDy = g_state->lastRawDy;
        hwTotalX = g_state->rawTotalX;
        hwTotalY = g_state->rawTotalY;
        hwEvents = g_state->rawEventCount;
        hwTick = g_state->tick;

        DWORD now = GetTickCount();
        DWORD last = (DWORD)g_state->lastUpdateMs;
        hwAge = now - last;
    }

    // Game (engine cursor math)
    LONG gameCX = g_gameCursorX.load(std::memory_order_relaxed);
    LONG gameCY = g_gameCursorY.load(std::memory_order_relaxed);
    LONG gameRX = g_gameRawX.load(std::memory_order_relaxed);
    LONG gameRY = g_gameRawY.load(std::memory_order_relaxed);

    LONG gameTotX = g_gameTotalX.load(std::memory_order_relaxed);
    LONG gameTotY = g_gameTotalY.load(std::memory_order_relaxed);
    LONG gameSamp = g_gameSamples.load(std::memory_order_relaxed);

    DWORD now = GetTickCount();
    DWORD gLast = g_gameLastMs.load(std::memory_order_relaxed);
    DWORD gameAge = (gLast == 0) ? 0xFFFFFFFFu : (now - gLast);
    bool gameStale = (gLast == 0) || (gameAge > 1000);

    // Per-frame deltas (overlay approximations from totals)
    LONG hwFrameDx = hwTotalX - g_prevRawTotalX;
    LONG hwFrameDy = hwTotalY - g_prevRawTotalY;
    g_prevRawTotalX = hwTotalX;
    g_prevRawTotalY = hwTotalY;

    LONG gameFrameDx = gameTotX - g_prevGameTotalX;
    LONG gameFrameDy = gameTotY - g_prevGameTotalY;
    g_prevGameTotalX = gameTotX;
    g_prevGameTotalY = gameTotY;

    // Add frame delta to hardware comparator window
    g_hwWinX.fetch_add(hwFrameDx, std::memory_order_relaxed);
    g_hwWinY.fetch_add(hwFrameDy, std::memory_order_relaxed);

    // Finalize and learn if window ended
    MaybeFinalizeComparatorWindow();

    // Current window (live)
    LONG hwCurX = g_hwWinX.load(std::memory_order_relaxed);
    LONG hwCurY = g_hwWinY.load(std::memory_order_relaxed);
    LONG gameCurX = g_gameWinX.load(std::memory_order_relaxed);
    LONG gameCurY = g_gameWinY.load(std::memory_order_relaxed);

    // Last window (stable)
    LONG hwLastX = g_hwWinLastX.load(std::memory_order_relaxed);
    LONG hwLastY = g_hwWinLastY.load(std::memory_order_relaxed);
    LONG gameLastX = g_gameWinLastX.load(std::memory_order_relaxed);
    LONG gameLastY = g_gameWinLastY.load(std::memory_order_relaxed);

    DWORD winStart = g_winStartMs.load(std::memory_order_relaxed);
    DWORD winAge = (winStart == 0) ? 0 : (now - winStart);

    double kx = g_kX.load(std::memory_order_relaxed);
    double ky = g_kY.load(std::memory_order_relaxed);
    kx = SafeK(kx);
    ky = SafeK(ky);

    LONG gameEqCurX = GameToEqCounts(gameCurX, kx);
    LONG gameEqCurY = GameToEqCounts(gameCurY, ky);
    LONG gameEqLastX = GameToEqCounts(gameLastX, kx);
    LONG gameEqLastY = GameToEqCounts(gameLastY, ky);

    std::wstringstream ss;

    ss << L"BHD_RawInput_Monitor\n";
    ss << L"Target: " << kGameExeName << L"  PID: " << g_targetPid << L"\n";

    if (!haveShared)
    {
        ss << L"\nWaiting for shared data...\n";
        ss << L"Make sure the DLL is loaded and the game has started.\n";
        return ss.str();
    }

    ss << L"Captured: " << (cap ? L"YES" : L"NO") << L"\n";
    ss << L"HW data age: " << hwAge << L" ms" << (hwAge > 1000 ? L"  (stale)" : L"") << L"\n";
    ss << L"Game mem age: " << (gameAge == 0xFFFFFFFFu ? 0u : gameAge) << L" ms" << (gameStale ? L"  (stale)" : L"") << L"\n\n";

    ss << L"Hardware (WM_INPUT)\n";
    ss << L"Last dx/dy: " << hwLastDx << L", " << hwLastDy << L"\n";
    ss << L"Frame dx/dy: " << hwFrameDx << L", " << hwFrameDy << L"\n";
    ss << L"Total: " << hwTotalX << L", " << hwTotalY << L"\n";
    ss << L"Events: " << hwEvents << L"  Tick: " << hwTick << L"\n\n";

    ss << L"Game (engine values)\n";
    ss << L"CursorX/Y: " << gameCX << L", " << gameCY << L"\n";
    ss << L"RawMouseX/Y: " << gameRX << L", " << gameRY << L"\n";
    ss << L"Frame sum: " << gameFrameDx << L", " << gameFrameDy << L"\n";
    ss << L"Total sum: " << gameTotX << L", " << gameTotY << L"\n";
    ss << L"Samples: " << gameSamp << L"\n\n";

    ss << L"Compare (window " << COMPARE_WINDOW_MS << L" ms, age " << winAge << L" ms)\n";
    ss << L"HW   dx/dy (cur counts): " << hwCurX << L", " << hwCurY << L"\n";
    ss << L"Game dx/dy (cur units):  " << gameCurX << L", " << gameCurY << L"\n";
    ss << L"kX/kY (median): ";
    AppendFixed4(ss, kx);
    ss << L", ";
    AppendFixed4(ss, ky);
    ss << L"\n";
    ss << L"GameEq (cur counts):     " << gameEqCurX << L", " << gameEqCurY << L"\n";
    ss << L"DiffEq (cur counts):     " << (hwCurX - gameEqCurX) << L", " << (hwCurY - gameEqCurY) << L"\n";
    ss << L"\n";
    ss << L"HW   dx/dy (last counts): " << hwLastX << L", " << hwLastY << L"\n";
    ss << L"Game dx/dy (last units):  " << gameLastX << L", " << gameLastY << L"\n";
    ss << L"GameEq (last counts):     " << gameEqLastX << L", " << gameEqLastY << L"\n";
    ss << L"DiffEq (last counts):     " << (hwLastX - gameEqLastX) << L", " << (hwLastY - gameEqLastY) << L"\n\n";

    ss << L"Notes:\n";
    ss << L" - k is learned only when |HW| >= " << MIN_HW_FOR_RATIO << L" in a window.\n";
    ss << L" - GameEq converts engine units into hardware-count equivalents.\n";
    ss << L" - Stable DiffEq near 0 indicates linear 1:1 behavior (up to noise).\n";

    return ss.str();
}

// ------------------------------------------------------------
// Overlay window helpers
// ------------------------------------------------------------

static void MakeClickThrough(HWND hwnd)
{
    LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
    ex |= WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW;
    SetWindowLongW(hwnd, GWL_EXSTYLE, ex);

    SetLayeredWindowAttributes(hwnd, 0, 190, LWA_ALPHA);

    MARGINS m{ -1 };
    DwmExtendFrameIntoClientArea(hwnd, &m);
}

static void RefreshTarget()
{
    DWORD newPid = FindProcessIdByName(kGameExeName);
    if (newPid != g_targetPid)
    {
        g_targetPid = newPid;
        g_targetHwnd = FindBestWindowForPid(g_targetPid);

        CloseProcessHandle();

        g_gameCursorX.store(0, std::memory_order_relaxed);
        g_gameCursorY.store(0, std::memory_order_relaxed);
        g_gameRawX.store(0, std::memory_order_relaxed);
        g_gameRawY.store(0, std::memory_order_relaxed);
        g_gameTotalX.store(0, std::memory_order_relaxed);
        g_gameTotalY.store(0, std::memory_order_relaxed);
        g_gameSamples.store(0, std::memory_order_relaxed);
        g_gameLastMs.store(0, std::memory_order_relaxed);

        g_prevGameTotalX = 0;
        g_prevGameTotalY = 0;

        g_prevRawTotalX = 0;
        g_prevRawTotalY = 0;

        ResetComparatorWindow(GetTickCount());

        g_hwWinLastX.store(0, std::memory_order_relaxed);
        g_hwWinLastY.store(0, std::memory_order_relaxed);
        g_gameWinLastX.store(0, std::memory_order_relaxed);
        g_gameWinLastY.store(0, std::memory_order_relaxed);

        ResetRatioHistory();
    }

    if (!g_targetHwnd || !IsWindow(g_targetHwnd))
        g_targetHwnd = FindBestWindowForPid(g_targetPid);
}

static void UpdateOverlayPlacement()
{
    RefreshTarget();

    if (!g_targetHwnd || !IsWindow(g_targetHwnd))
        return;

    RECT rc{};
    if (!GetClientRectOnScreen(g_targetHwnd, rc))
        return;

    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0)
        return;

    SetWindowPos(g_hwnd, HWND_TOPMOST,
        rc.left, rc.top,
        w, h,
        SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

// ------------------------------------------------------------
// Win32
// ------------------------------------------------------------

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_TIMER:
        UpdateOverlayPlacement();
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;

    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rc{};
        GetClientRect(hwnd, &rc);

        HBRUSH bg = CreateSolidBrush(RGB(0, 0, 0));
        FillRect(hdc, &rc, bg);
        DeleteObject(bg);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));

        HFONT old = (HFONT)SelectObject(hdc, g_font);

        std::wstring text = MakeText();
        RECT pad = rc;
        pad.left += 10;
        pad.top += 10;
        DrawTextW(hdc, text.c_str(), (int)text.size(), &pad, DT_LEFT | DT_TOP | DT_NOPREFIX);

        SelectObject(hdc, old);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int)
{
    EnsureRatioCS();
    ResetRatioHistory();

    const wchar_t* kClass = L"BHD_RawInput_Monitor";

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.hInstance = hInst;
    wc.lpszClassName = kClass;
    wc.lpfnWndProc = WndProc;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);

    g_font = CreateFontW(
        18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Consolas");

    g_hwnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        kClass, L"BHD_RawInput_Monitor",
        WS_POPUP,
        100, 100, 640, 360,
        nullptr, nullptr, hInst, nullptr);

    MakeClickThrough(g_hwnd);
    ShowWindow(g_hwnd, SW_SHOW);

    ResetComparatorWindow(GetTickCount());

    g_stop.store(false, std::memory_order_relaxed);
    HANDLE hPoll = CreateThread(nullptr, 0, GamePollThread, nullptr, 0, nullptr);
    if (hPoll) CloseHandle(hPoll);

    SetTimer(g_hwnd, 1, 16, nullptr);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g_stop.store(true, std::memory_order_relaxed);
    Sleep(30);

    CloseShared();
    CloseProcessHandle();

    if (g_font) { DeleteObject(g_font); g_font = nullptr; }

    if (g_ratioCsInit)
    {
        DeleteCriticalSection(&g_ratioCs);
        g_ratioCsInit = false;
    }

    return 0;
}
