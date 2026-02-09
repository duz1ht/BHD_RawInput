// RawInput_Monitor.cpp
//
// Transparent click-through overlay aligned to dfbhd.exe client area.
// Reads shared memory: Local\\BHD_RawInput_Shared (version 2).
//
// Focus:
//  - Human-checkable, windowed numbers (no endless totals).
//  - Compare HW (WM_INPUT) vs Inject (what the DLL fed the engine each tick).
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
#include <cmath>

#pragma comment(lib, "dwmapi.lib")

static const wchar_t* kMapName = L"Local\\BHD_RawInput_Shared";
static const wchar_t* kGameExeName = L"dfbhd.exe";
static const DWORD kWarnStaleMs = 1000;

#pragma pack(push, 1)
struct SharedHudStateV2
{
    uint32_t magic;        // 'BHDR' = 0x52444842
    uint32_t version;      // 2

    volatile LONG isCaptured;

    volatile LONG hwLastDx;
    volatile LONG hwLastDy;

    volatile LONG injLastDx;
    volatile LONG injLastDy;

    volatile LONG hwWinCurX;
    volatile LONG hwWinCurY;
    volatile LONG injWinCurX;
    volatile LONG injWinCurY;

    volatile LONG hwWinLastX;
    volatile LONG hwWinLastY;
    volatile LONG injWinLastX;
    volatile LONG injWinLastY;

    volatile LONG estHwEventsPerSec;
    volatile LONG estInjTicksPerSec;

    volatile LONG hwEventCount;
    volatile LONG injTickCount;

    volatile LONG lastUpdateMs;
};
#pragma pack(pop)

static HANDLE g_hMap = nullptr;
static SharedHudStateV2* g_state = nullptr;

static HWND g_hwnd = nullptr;
static HFONT g_font = nullptr;

static HWND g_targetHwnd = nullptr;
static DWORD g_targetPid = 0;

// ------------------------------------------------------------
// Shared memory
// ------------------------------------------------------------

static bool OpenShared()
{
    if (g_state) return true;

    g_hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, kMapName);
    if (!g_hMap) return false;

    void* p = MapViewOfFile(g_hMap, FILE_MAP_READ, 0, 0, sizeof(SharedHudStateV2));
    if (!p)
    {
        CloseHandle(g_hMap);
        g_hMap = nullptr;
        return false;
    }

    g_state = reinterpret_cast<SharedHudStateV2*>(p);
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
    if (g_state->magic != 0x52444842) return false;
    if (g_state->version != 2) return false;
    return true;
}

// ------------------------------------------------------------
// Process discovery + overlay placement
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
// Formatting helpers
// ------------------------------------------------------------

static double SafeRatio(LONG num, LONG den)
{
    double d = (double)den;
    if (d == 0.0) return 0.0;
    return (double)num / d;
}

static void AppendFixed4(std::wstringstream& ss, double v)
{
    wchar_t buf[64]{};
    swprintf_s(buf, L"%.4f", v);
    ss << buf;
}

// ------------------------------------------------------------
// Text render
// ------------------------------------------------------------

static std::wstring MakeText()
{
    bool haveShared = OpenShared() && IsValidState();

    std::wstringstream ss;
    ss << L"BHD RawInput Monitor\n";
    ss << L"Target: " << kGameExeName << L"  PID: " << g_targetPid << L"\n";

    if (!haveShared)
    {
        ss << L"\nWaiting for shared data (v2)...\n";
        ss << L"Make sure the hook DLL is loaded.\n";
        ss << L"Expected mapping: Local\\\\BHD_RawInput_Shared\n";
        return ss.str();
    }

    DWORD now = GetTickCount();
    DWORD last = (DWORD)g_state->lastUpdateMs;
    DWORD age = now - last;

    LONG cap = g_state->isCaptured;

    LONG hwLastDx = g_state->hwLastDx;
    LONG hwLastDy = g_state->hwLastDy;
    LONG injLastDx = g_state->injLastDx;
    LONG injLastDy = g_state->injLastDy;

    LONG hwCurX = g_state->hwWinCurX;
    LONG hwCurY = g_state->hwWinCurY;
    LONG injCurX = g_state->injWinCurX;
    LONG injCurY = g_state->injWinCurY;

    LONG hwLastX = g_state->hwWinLastX;
    LONG hwLastY = g_state->hwWinLastY;
    LONG injLastX = g_state->injWinLastX;
    LONG injLastY = g_state->injWinLastY;

    LONG hwRate = g_state->estHwEventsPerSec;
    LONG injRate = g_state->estInjTicksPerSec;

    ss << L"Captured: " << (cap ? L"YES" : L"NO") << L"\n";
    ss << L"Data age: " << age << L" ms" << (age > kWarnStaleMs ? L"  (stale)" : L"") << L"\n";
    ss << L"HW events/s: " << hwRate << L"\n";
    ss << L"Inject ticks/s: " << injRate << L"\n\n";

    ss << L"Last observed\n";
    ss << L"HW last dx/dy:   " << hwLastDx << L", " << hwLastDy << L"\n";
    ss << L"INJ last dx/dy:  " << injLastDx << L", " << injLastDy << L"\n\n";

    ss << L"Compare windows (100 ms)\n";

    ss << L"CUR window\n";
    ss << L"HW  dx/dy:   " << hwCurX << L", " << hwCurY << L"\n";
    ss << L"INJ dx/dy:   " << injCurX << L", " << injCurY << L"\n";
    ss << L"Diff (HW-INJ): " << (hwCurX - injCurX) << L", " << (hwCurY - injCurY) << L"\n";
    ss << L"Ratio (INJ/HW): ";
    AppendFixed4(ss, SafeRatio(injCurX, hwCurX));
    ss << L", ";
    AppendFixed4(ss, SafeRatio(injCurY, hwCurY));
    ss << L"\n\n";

    ss << L"LAST window (finalized)\n";
    ss << L"HW  dx/dy:   " << hwLastX << L", " << hwLastY << L"\n";
    ss << L"INJ dx/dy:   " << injLastX << L", " << injLastY << L"\n";
    ss << L"Diff (HW-INJ): " << (hwLastX - injLastX) << L", " << (hwLastY - injLastY) << L"\n";
    ss << L"Ratio (INJ/HW): ";
    AppendFixed4(ss, SafeRatio(injLastX, hwLastX));
    ss << L", ";
    AppendFixed4(ss, SafeRatio(injLastY, hwLastY));
    ss << L"\n\n";

    ss << L"How to read this\n";
    ss << L" - If the injector is correct, INJ should track HW closely in the windows.\n";
    ss << L" - Diff near 0 and Ratio near 1.0 indicates counts are preserved.\n";
    ss << L" - Inject ticks/s shows the effective game mouse tickrate (measured, not assumed).\n";

    return ss.str();
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
    const wchar_t* kClass = L"RawInput_Monitor_Class";

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
        kClass, L"RawInput Monitor",
        WS_POPUP,
        100, 100, 640, 360,
        nullptr, nullptr, hInst, nullptr);

    MakeClickThrough(g_hwnd);
    ShowWindow(g_hwnd, SW_SHOW);

    SetTimer(g_hwnd, 1, 16, nullptr);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseShared();

    if (g_font) { DeleteObject(g_font); g_font = nullptr; }

    return 0;
}
