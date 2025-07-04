#include <Windows.h>
#include <Windowsx.h>
#include <thread>
#include <atomic>
#include <string>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <cmath>
#include <climits>
#include <stdint.h>
#include <random>
#include "MinHook/include/MinHook.h" // https://github.com/TsudaKageyu/minhook
#pragma comment(lib, "MinHook/lib/libMinHook.x64.lib")
#include "json.hpp"  // https://github.com/nlohmann/json
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Gdi32.lib")
using json = nlohmann::json;
#define IsKeyPressed(key) (GetAsyncKeyState(key) & 0x8000)
DWORD lastShotTime = 0;
DWORD shotCooldown = 100; // 100 ms entre les tirs
bool aiming = false;

#include <iostream>
#include <sstream> 
#include <chrono>
#include <iomanip>

#include "resource.h" 

// Génère une chaîne aléatoire de taille n (lettres majuscules + chiffres)
std::string GenerateRandomName(int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    result.resize(length);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, sizeof(charset) - 2);

    for (int i = 0; i < length; ++i) {
        result[i] = charset[distrib(gen)];
    }

    return result;
}


//void LeftClick() {
//    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
//    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
//    lastShotTime = GetTickCount();
//}
//
//void RightClickDown() {
//    mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
//}
//
//void RightClickUp() {
//    mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
//}
void MoveMouseTo(int x, int y)
{
    INPUT input = { 0 };
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    input.mi.dx = x * (65535 / GetSystemMetrics(SM_CXSCREEN));
    input.mi.dy = y * (65535 / GetSystemMetrics(SM_CYSCREEN));
    SendInput(1, &input, sizeof(INPUT));
}

//void LeftClick() {
//    INPUT input[2] = {};
//
//    input[0].type = INPUT_MOUSE;
//    input[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
//
//    input[1].type = INPUT_MOUSE;
//    input[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;
//
//    SendInput(2, input, sizeof(INPUT));
//    lastShotTime = GetTickCount();
//}

void LeftClick() {
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    Sleep(5); // petit délai
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    lastShotTime = GetTickCount();
}


void RightClickDown() {
    INPUT input = {};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;
    SendInput(1, &input, sizeof(INPUT));
}

void RightClickUp() {
    INPUT input = {};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_RIGHTUP;
    SendInput(1, &input, sizeof(INPUT));
}

// Globals
HWND g_hOverlay = NULL;
bool g_showMenu = false;
BYTE g_alpha = 150;
std::atomic<bool> g_quicktimeEvent{ false };
std::atomic<bool> g_aimbotActive{ false };
std::atomic<bool> g_aimbotHeadOnly{ true };
bool g_showRectangle = true;

bool g_allowMoveMenu = false;

RECT g_overlayRect = { 800, 400, 1000, 600 };
RECT g_menuRect = { 50, 50, 350, 750 };

RECT g_menuCorner = { 50, 50, 80, 80 };

bool g_draggingMenu = false;
POINT g_dragStart = { 0 };


const char* configFile = "overlay_config.json";

//void AimAt(int x, int y)
//{
//    int absX = (x * 65535) / cx;
//    int absY = (y * 65535) / cy;
//
//    INPUT input = { 0 };
//    input.type = INPUT_MOUSE;
//    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
//    input.mi.dx = absX;
//    input.mi.dy = absY;
//    SendInput(1, &input, sizeof(INPUT));
//}
//
//
//void ProcessFrame(const std::vector<uint8_t>& frame, int width, int height) {
//    static std::vector<uint8_t> lastFrame;
//    int totalPixels = width * height;
//
//    int screenCenterX = width / 2;
//    int screenCenterY = height / 2;
//
//    if (!lastFrame.empty()) {
//        std::unordered_map<uint32_t, int> colorHistogram;
//
//        // Étape 1 : histogramme des couleurs en mouvement
//        for (int i = 0; i < totalPixels; ++i) {
//            int offset = i * 3;
//
//            uint8_t r1 = frame[offset];
//            uint8_t g1 = frame[offset + 1];
//            uint8_t b1 = frame[offset + 2];
//
//            uint8_t r0 = lastFrame[offset];
//            uint8_t g0 = lastFrame[offset + 1];
//            uint8_t b0 = lastFrame[offset + 2];
//
//            if (abs(r1 - r0) > 20 || abs(g1 - g0) > 20 || abs(b1 - b0) > 20) {
//                uint32_t color = (r1 << 16) | (g1 << 8) | b1;
//                colorHistogram[color]++;
//            }
//        }
//
//        // Étape 2 : trouve la couleur rare
//        uint32_t rareColor = 0;
//        int rareCount = INT_MAX;
//        for (auto& pair : colorHistogram) {
//            if (pair.second < rareCount && pair.second > 10) {
//                rareCount = pair.second;
//                rareColor = pair.first;
//            }
//        }
//
//        // Étape 3 : trouve la position du pixel rare et vise dessus
//        for (int i = 0; i < totalPixels; ++i) {
//            int offset = i * 3;
//            uint32_t color = (frame[offset] << 16) | (frame[offset + 1] << 8) | frame[offset + 2];
//
//            if (color == rareColor) {
//                int x = i % width;
//                int y = i / width;
//
//                AimAt(x, y); // Déplace la souris vers la cible
//
//                if (!aiming) {
//                    RightClickDown(); // Commence à viser
//                    aiming = true;
//                }
//
//                // Si la cible est proche du centre : tir automatique (headshot)
//                if (abs(x - screenCenterX) < 50 && abs(y - screenCenterY) < 50) {
//                    DWORD now = GetTickCount();
//                    if (now - lastShotTime > shotCooldown) {
//                        LeftClick(); // Tire
//                    }
//                }
//
//                return; // Stop après la première cible trouvée
//            }
//        }
//    }
//
//    // Si aucune cible rare détectée, relâche le clic droit
//    if (aiming) {
//        RightClickUp();
//        aiming = false;
//    }
//
//    lastFrame = frame;
//}


struct Color {
    uint8_t r, g, b;
};

//Color blueColor = { 82, 158, 199 };
//Color redColor = { 205, 67, 72 };
//int toleranceRed = 15;
//int toleranceBlue = 25;

//HWND FocusWindow()
//{
//    // Exemple : focus sur la fenêtre "Cfx.re"
//    HWND found = nullptr;
//    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
//        char title[256];
//        GetWindowTextA(hwnd, title, sizeof(title));
//        if (strstr(title, "Cfx.re")) {
//            HWND* pFound = (HWND*)lParam;
//            *pFound = hwnd;
//            return FALSE;
//        }
//        return TRUE;
//        }, (LPARAM)&found);
//    return found;
//}
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    const std::string target = "Cfx.re";

    char title[256];
    GetWindowTextA(hwnd, title, sizeof(title));
    std::string windowTitle(title);

    if (windowTitle.find(target) != std::string::npos)
    {
        HWND* pFound = (HWND*)lParam;
        *pFound = hwnd;
        return FALSE;
    }
    return TRUE;
}

HWND FocusWindow()
{
    HWND found = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)&found);
    return found;
}
void PressE()
{
    keybd_event(0x45, 0, 0, 0);
    keybd_event(0x45, 0, KEYEVENTF_KEYUP, 0);
}
//void ClearPreviousLine()
//{
//    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
//    CONSOLE_SCREEN_BUFFER_INFO csbi;
//    GetConsoleScreenBufferInfo(hConsole, &csbi);
//
//    COORD pos = csbi.dwCursorPosition;
//    if (pos.Y > 0)
//    {
//        pos.Y -= 1;
//        pos.X = 0;
//        SetConsoleCursorPosition(hConsole, pos);
//        DWORD written;
//        FillConsoleOutputCharacter(hConsole, ' ', csbi.dwSize.X, pos, &written);
//        SetConsoleCursorPosition(hConsole, pos);
//    }
//}


void CaptureScreenToFile(const std::string& filename) {
    int screenX = GetSystemMetrics(SM_CXSCREEN);
    int screenY = GetSystemMetrics(SM_CYSCREEN);

    HDC hScreenDC = GetDC(NULL);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, screenX, screenY);
    SelectObject(hMemoryDC, hBitmap);

    BitBlt(hMemoryDC, 0, 0, screenX, screenY, hScreenDC, 0, 0, SRCCOPY);

    BITMAPFILEHEADER bmfHeader;
    BITMAPINFOHEADER bi;

    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = screenX;
    bi.biHeight = screenY;
    bi.biPlanes = 1;
    //bi.biBitCount = 24;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    DWORD dwBmpSize = ((screenX * bi.biBitCount + 31) / 32) * 4 * screenY;
    std::vector<BYTE> lpbitmap(dwBmpSize);

    GetDIBits(hMemoryDC, hBitmap, 0, screenY, lpbitmap.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    std::ofstream out(filename, std::ios::out | std::ios::binary);
    bmfHeader.bfType = 0x4D42;
    bmfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfReserved1 = 0;
    bmfHeader.bfReserved2 = 0;

    out.write((char*)&bmfHeader, sizeof(BITMAPFILEHEADER));
    out.write((char*)&bi, sizeof(BITMAPINFOHEADER));
    out.write((char*)lpbitmap.data(), dwBmpSize);
    out.close();

    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);
}

HBITMAP hCaptureBitmap = nullptr;
HDC hCaptureDC = nullptr;
// --- Hook BitBlt minimal (vide ici) ---
typedef BOOL(WINAPI* tBitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
tBitBlt oBitBlt = nullptr;
//decltype(&BitBlt) oBitBlt = nullptr;  // pointeur vers la fonction originale

//int cx = 0;
//int cy = 0;
int cx = 1920;
int cy = 1080;

void WriteLog(const char* message)
{
    std::ofstream log("log.txt", std::ios::app);
    if (log.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        log << "[" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] " << message << "\n";
    }
}

//inline bool IsColorMatch(uint8_t r, uint8_t g, uint8_t b, uint8_t tr, uint8_t tg, uint8_t tb, int tolerance) {
//    return abs(r - tr) <= tolerance &&
//        abs(g - tg) <= tolerance &&
//        abs(b - tb) <= tolerance;
//}

bool barInside = false;

#include <cstdint>
#include <cstring>  // memcpy
#include <windows.h>

////bool IsColorMatch(uint8_t r, uint8_t g, uint8_t b, const Color& target, int tolerance) {
////    return abs(r - target.r) <= tolerance && abs(g - target.g) <= tolerance && abs(b - target.b) <= tolerance;
////}
//#define FAST_DIFF(a, b, t) (((unsigned)((a) - (b) + (t)) <= (unsigned)((t)*2)))
//#define IS_COLOR_MATCH(r,g,b,tr,tg,tb,tol) \
//    (FAST_DIFF(r, tr, tol) && FAST_DIFF(g, tg, tol) && FAST_DIFF(b, tb, tol))
//typedef unsigned char u8;
////inline bool IsColorMatch(u8 r, u8 g, u8 b, u8 tr, u8 tg, u8 tb, int tol) {
////    return FAST_DIFF(r, tr, tol) &&
////        FAST_DIFF(g, tg, tol) &&
////        FAST_DIFF(b, tb, tol);
////}
//__forceinline bool IsColorMatch(u8 r, u8 g, u8 b, u8 tr, u8 tg, u8 tb, int tol) {
//    return FAST_DIFF(r, tr, tol) &&
//        FAST_DIFF(g, tg, tol) &&
//        FAST_DIFF(b, tb, tol);
//}
__forceinline bool IsColorMatch(uint8_t r, uint8_t g, uint8_t b,
    uint8_t tr, uint8_t tg, uint8_t tb,
    int tol) {
    return (((unsigned)(r - tr + tol) <= (unsigned)(tol * 2)) &&
        ((unsigned)(g - tg + tol) <= (unsigned)(tol * 2)) &&
        ((unsigned)(b - tb + tol) <= (unsigned)(tol * 2)));
}


////struct FastRGB {
////    BYTE b, g, r;
////};
//struct RGBA {
//    uint8_t r, g, b, a;
//};
typedef uint8_t u8;
//typedef uint32_t DWORD;

// Encode RGB en DWORD (sans alpha)
//constexpr DWORD RGB_HASH(u8 r, u8 g, u8 b) {
//    return (r << 16) | (g << 8) | b;
//}
constexpr DWORD RGB_HASH(u8 r, u8 g, u8 b) {
    return (DWORD(r) << 16) | (DWORD(g) << 8) | DWORD(b);
}
#define PACK_RGB(r, g, b) ((DWORD(r) << 16) | (DWORD(g) << 8) | DWORD(b))

// Test rapide via hash et tolérance
__forceinline bool IsColorMatchHash(DWORD color, DWORD target, int tol) {
    u8 r1 = (color >> 16) & 0xFF;
    u8 g1 = (color >> 8) & 0xFF;
    u8 b1 = color & 0xFF;

    u8 r2 = (target >> 16) & 0xFF;
    u8 g2 = (target >> 8) & 0xFF;
    u8 b2 = target & 0xFF;

    return (((unsigned)(r1 - r2 + tol) <= (unsigned)(tol * 2)) &&
        ((unsigned)(g1 - g2 + tol) <= (unsigned)(tol * 2)) &&
        ((unsigned)(b1 - b2 + tol) <= (unsigned)(tol * 2)));
}

#define PACK_RGB(r, g, b) ((DWORD(r) << 16) | (DWORD(g) << 8) | DWORD(b))

const int toleranceRed = 4;
const int toleranceBlue = 4;
void CheckQuickTimeTrigger(RGBQUAD* buffer, int width, int height, RGBQUAD* lastBuffer)
{
    static DWORD startTick = 0;
    static DWORD lastPressTime = 0;
    static DWORD barTimer = 0;
    static int pressE_count = 0;
    /*const DWORD redHash = PACK_RGB(205, 67, 72);
    const DWORD blueHash = PACK_RGB(82, 158, 199);*/

    const BYTE redR = 205, redG = 67, redB = 72;
    const BYTE blueR = 82, blueG = 158, blueB = 199;
    //    const BYTE redR = 203, redG = 66, redB = 72;         // Smooch Rouge
    //const BYTE blueR = 81, blueG = 157, blueB = 197;     // Canadian Tuxedo

    //const BYTE knockoutR = 194, knockoutG = 46, knockoutB = 46;
    //const BYTE smoochR = 203, smoochG = 66, smoochB = 72;
    //const BYTE blueR = 81, blueG = 157, blueB = 197;
    ULONGLONG now = GetTickCount64();

    //DWORD now = GetTickCount();
    bool redDetected = false;

    /*for (int i = 0; i < width * height; ++i)
    {
        RGBQUAD pixel = buffer[i];
        RGBQUAD previousPixel = lastBuffer[i];*/
    /*RGBQUAD* curr = buffer;
    RGBQUAD* prev = lastBuffer;*/


    /*int pixelCount = width * height;

    for (int i = 0; i < pixelCount; ++i) {
        RGBQUAD& curr = buffer[i];
        RGBQUAD& prev = lastBuffer[i];*/

    /*for (int y = 0; y < height; ++y) {
        for (int x = width - 1; x >= 0; --x) { //scan right to left and up to down
            int i = y * width + x;*/

            /*RGBQUAD curr = buffer[i];
            RGBQUAD prev = lastBuffer[i];*/

           /* bool isRed = IsColorMatch(curr.rgbRed, curr.rgbGreen, curr.rgbBlue,
                redR, redG, redB, toleranceRed);
            bool wasBlue = IsColorMatch(prev.rgbRed, prev.rgbGreen, prev.rgbBlue,
                blueR, blueG, blueB, toleranceBlue);*/
    /*for (int i = 0; i < width * height; ++i, ++curr, ++prev)
    {*/
    /*const DWORD redHash = RGB_HASH(redR, redG, redB);
    const DWORD blueHash = RGB_HASH(blueR, blueG, blueB);*/

    for (int i = 0; i < width * height; ++i)
    {
        RGBQUAD& curr = buffer[i];
        RGBQUAD& prev = lastBuffer[i];
        /*bool isRed = IsColorMatch(curr.rgbRed, curr.rgbGreen, curr.rgbBlue,
            redR, redG, redB, toleranceRed);
        bool wasBlue = IsColorMatch(prev.rgbRed, prev.rgbGreen, prev.rgbBlue,
            blueR, blueG, blueB, toleranceBlue);*/
        /*DWORD currHash = RGB_HASH(curr.rgbRed, curr.rgbGreen, curr.rgbBlue);
        DWORD prevHash = RGB_HASH(prev.rgbRed, prev.rgbGreen, prev.rgbBlue);

        bool isRed = IsColorMatchHash(currHash, redHash, toleranceRed);
        bool wasBlue = IsColorMatchHash(prevHash, blueHash, toleranceBlue);*/
        bool isRed = IsColorMatch(curr.rgbRed, curr.rgbGreen, curr.rgbBlue,
            redR, redG, redB, toleranceRed);
        bool wasBlue = IsColorMatch(prev.rgbRed, prev.rgbGreen, prev.rgbBlue,
            blueR, blueG, blueB, toleranceBlue);
    /*bool isRed = IsColorMatch(curr->rgbRed, curr->rgbGreen, curr->rgbBlue,
            redR, redG, redB, toleranceRed);
        bool wasBlue = IsColorMatch(prev->rgbRed, prev->rgbGreen, prev->rgbBlue,
            blueR, blueG, blueB, toleranceBlue);*/
        /*bool isRed = IsColorMatch(pixel.rgbRed, pixel.rgbGreen, pixel.rgbBlue,
            redR, redG, redB, toleranceRed);

        bool wasBlue = IsColorMatch(previousPixel.rgbRed, previousPixel.rgbGreen, previousPixel.rgbBlue,
            blueR, blueG, blueB, toleranceBlue);*/
       /* bool isRed = FAST_DIFF(pixel.rgbRed, redR, toleranceRed) &&
            FAST_DIFF(pixel.rgbGreen, redG, toleranceRed) &&
            FAST_DIFF(pixel.rgbBlue, redB, toleranceRed);

        bool wasBlue = FAST_DIFF(previousPixel.rgbRed, blueR, toleranceBlue) &&
            FAST_DIFF(previousPixel.rgbGreen, blueG, toleranceBlue) &&
            FAST_DIFF(previousPixel.rgbBlue, blueB, toleranceBlue);*/
        /*bool isRed =
            abs(pixel.rgbRed - redR) <= toleranceRed &&
            abs(pixel.rgbGreen - redG) <= toleranceRed &&
            abs(pixel.rgbBlue - redB) <= toleranceRed;

        bool wasBlue =
            abs(previousPixel.rgbRed - blueR) <= toleranceBlue &&
            abs(previousPixel.rgbGreen - blueG) <= toleranceBlue &&
            abs(previousPixel.rgbBlue - blueB) <= toleranceBlue;*/

        /*bool isRed = IsColorMatch(pixel.rgbRed, pixel.rgbGreen, pixel.rgbBlue,
            redR, redG, redB, toleranceRed);
        bool wasBlue = IsColorMatch(previousPixel.rgbRed, previousPixel.rgbGreen, previousPixel.rgbBlue,
            blueR, blueG, blueB, toleranceBlue);*/

        if (isRed && wasBlue)
        {
            redDetected = true;

            if (!barInside && (now - lastPressTime > 100))
            {
                HWND hwnd = FocusWindow();
                if (hwnd)
                {
                    if (IsIconic(hwnd)) ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);

                    PressE();
                    pressE_count++;
                    lastPressTime = now;
                    barInside = true;

                    if (startTick == 0)
                        startTick = now;
                }
            }

            barTimer = now;
            break;
        }
    }

    // Reset barInside after timeout
    if (!redDetected && barInside && (now - barTimer > 200)) {
        barInside = false;

    }
    memcpy(lastBuffer, buffer, width * height * sizeof(RGBQUAD));

}

static RGBQUAD* lastBuffer = nullptr;
static int lastBufferWidth = 0;
static int lastBufferHeight = 0;
BOOL WINAPI hkBitBlt(HDC hdcDest, int xDest, int yDest, int w, int h,
    HDC hdcSrc, int xSrc, int ySrc, DWORD rop)
{
    static bool isCapturing = false;
    if (isCapturing || rop != SRCCOPY)
        return oBitBlt(hdcDest, xDest, yDest, w, h, hdcSrc, xSrc, ySrc, rop);

    isCapturing = true;

    const int captureWidth = 200;
    const int captureHeight = 200;
    static RGBQUAD* lastBuffer = new RGBQUAD[captureWidth * captureHeight]{};

    // Calcul de la position centrale
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int captureX = (screenWidth / 2) - (captureWidth / 2);
    int captureY = (screenHeight / 2) - (captureHeight / 2);

    // Préparer la mémoire
    HDC hScreenDC = GetDC(NULL);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, captureWidth, captureHeight);
    HGDIOBJ old = SelectObject(hMemoryDC, hBitmap);

    // Capture depuis l'écran
    BitBlt(hMemoryDC, 0, 0, captureWidth, captureHeight, hScreenDC, captureX, captureY, SRCCOPY);

    // Structure bitmap
    BITMAPINFOHEADER bi = {};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = captureWidth;
    bi.biHeight = -captureHeight;  // top-down
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    std::vector<RGBQUAD> frame(captureWidth * captureHeight);

    GetDIBits(hMemoryDC, hBitmap, 0, captureHeight, frame.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    // Traitement de l'image
    if (g_quicktimeEvent)
        CheckQuickTimeTrigger(frame.data(), captureWidth, captureHeight, lastBuffer);

    memcpy(lastBuffer, frame.data(), captureWidth * captureHeight * sizeof(RGBQUAD));

    // Nettoyage
    SelectObject(hMemoryDC, old);
    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);

    isCapturing = false;
    return oBitBlt(hdcDest, xDest, yDest, w, h, hdcSrc, xSrc, ySrc, rop);
}

// Dessine checkbox 16x16 px avec texte
void DrawCheckbox(HDC hdc, RECT rc, bool checked, const char* label) {
    int size = 16;
    RECT box = { rc.left, rc.top, rc.left + size, rc.top + size };
    DrawFrameControl(hdc, &box, DFC_BUTTON, checked ? DFCS_BUTTONCHECK | DFCS_CHECKED : DFCS_BUTTONCHECK);
    RECT txt = { rc.left + size + 5, rc.top, rc.right, rc.bottom };
    DrawTextA(hdc, label, -1, &txt, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

// Dessine slider horizontal avec track et thumb
void DrawSlider(HDC hdc, RECT rc, int value, int minVal, int maxVal, const char* label) {
    int trackHeight = 8;
    RECT track = { rc.left + 10, rc.top + (rc.bottom - rc.top) / 2 - trackHeight / 2,
                   rc.right - 10, rc.top + (rc.bottom - rc.top) / 2 + trackHeight / 2 };
    FillRect(hdc, &track, (HBRUSH)GetStockObject(GRAY_BRUSH));

    int trackWidth = track.right - track.left;
    int thumbX = track.left + (value - minVal) * trackWidth / (maxVal - minVal);

    RECT thumb = { thumbX - 6, track.top - 4, thumbX + 6, track.bottom + 4 };
    FillRect(hdc, &thumb, (HBRUSH)GetStockObject(DKGRAY_BRUSH));

    std::string txtStr = std::string(label) + ": " + std::to_string(value);
    RECT txtRc = { rc.left + 10, rc.top - 20, rc.right - 10, rc.top };
    DrawTextA(hdc, txtStr.c_str(), -1, &txtRc, DT_LEFT | DT_SINGLELINE);
}

// Dessine triangle bleu (coin haut-gauche)
void DrawBlueTriangle(HDC hdc, RECT rc) {
    POINT pts[3] = {
        { rc.left, rc.top },
        { rc.right, rc.top },
        { rc.left, rc.bottom }
    };

    HBRUSH blueBrush = CreateSolidBrush(RGB(0, 0, 255));
    HPEN oldPen = (HPEN)SelectObject(hdc, GetStockObject(NULL_PEN));
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, blueBrush);

    Polygon(hdc, pts, 3);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(blueBrush);
}

// Handle slider click, change la valeur si clic sur track
bool HandleSliderClick(RECT rc, int minVal, int maxVal, int& value, POINT pt)
{
    int trackHeight = 8;
    RECT track = { rc.left + 10, rc.top + (rc.bottom - rc.top) / 2 - trackHeight / 2,
                   rc.right - 10, rc.top + (rc.bottom - rc.top) / 2 + trackHeight / 2 };

    if (PtInRect(&track, pt)) {
        int trackWidth = track.right - track.left;
        int posInTrack = pt.x - track.left;
        if (posInTrack < 0) posInTrack = 0;
        if (posInTrack > trackWidth) posInTrack = trackWidth;

        value = minVal + (posInTrack * (maxVal - minVal) / trackWidth);
        return true;
    }
    return false;
}

// Sauvegarde config dans JSON
void SaveConfig() {
    json j;
    j["overlayRect"] = { g_overlayRect.left, g_overlayRect.top, g_overlayRect.right, g_overlayRect.bottom };
    j["menuRect"] = { g_menuRect.left, g_menuRect.top, g_menuRect.right, g_menuRect.bottom };
    j["alpha"] = g_alpha;
    j["showRectangle"] = g_showRectangle;
    j["aimbotActive"] = g_aimbotActive.load();
    j["aimbotHeadOnly"] = g_aimbotHeadOnly.load();
    j["allowMoveMenu"] = g_allowMoveMenu;
    j["quicktimeEvent"] = g_quicktimeEvent.load();

    std::ofstream ofs(configFile);
    if (ofs.is_open()) {
        ofs << j.dump(4);
        ofs.close();
    }
}
RECT g_overlayCorner = { 0 }; // coin rouge pour resize

int RectWidth(const RECT& r) { return r.right - r.left; }
int RectHeight(const RECT& r) { return r.bottom - r.top; }
void SetRectFromLTWH(RECT& r, int left, int top, int width, int height) {
    r.left = left;
    r.top = top;
    r.right = left + width;
    r.bottom = top + height;
    g_overlayCorner = {
g_overlayRect.right - 15,
g_overlayRect.bottom - 15,
g_overlayRect.right,
g_overlayRect.bottom
    };
}

void LoadConfig() {
    std::ifstream ifs(configFile);
    if (ifs.is_open()) {
        json j;
        ifs >> j;
        ifs.close();

        if (j.contains("overlayRect") && j["overlayRect"].is_array()) {
            auto arr = j["overlayRect"];
            if (arr.size() == 4) {
                g_overlayRect = { arr[0], arr[1], arr[2], arr[3] };
            }
        }
        if (j.contains("menuRect") && j["menuRect"].is_array()) {
            auto arr = j["menuRect"];
            if (arr.size() == 4) {
                g_menuRect = { arr[0], arr[1], arr[2], arr[3] };

                // 🔧 Forcer une hauteur minimale de 700 si trop petit
                const int minMenuHeight = 520;
                if (RectHeight(g_menuRect) < minMenuHeight) {
                    g_menuRect.bottom = g_menuRect.top + minMenuHeight;
                }

                g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
            }
        }

        if (j.contains("alpha")) g_alpha = j["alpha"];
        if (j.contains("showRectangle")) g_showRectangle = j["showRectangle"];
        if (j.contains("quicktimeEvent")) g_quicktimeEvent = j["quicktimeEvent"];
        if (j.contains("aimbotActive")) g_aimbotActive = j["aimbotActive"];
        if (j.contains("aimbotHeadOnly")) g_aimbotHeadOnly = j["aimbotHeadOnly"];
        if (j.contains("allowMoveMenu")) g_allowMoveMenu = j["allowMoveMenu"];
    }
}


// Gestion déplacement menu (drag sur coin bleu)
void HandleMenuDrag(HWND hwnd, POINT pt, WPARAM wParam) {
    if (g_allowMoveMenu && (wParam & MK_LBUTTON) && PtInRect(&g_menuCorner, pt)) {
        if (!g_draggingMenu) {
            g_draggingMenu = true;
            g_dragStart = pt;
        }
    }
    else if (!(wParam & MK_LBUTTON)) {
        g_draggingMenu = false;
    }

    if (g_draggingMenu) {
        int dx = pt.x - g_dragStart.x;
        int dy = pt.y - g_dragStart.y;

        OffsetRect(&g_menuRect, dx, dy);
        OffsetRect(&g_menuCorner, dx, dy);
        g_dragStart = pt;

        InvalidateRect(hwnd, NULL, TRUE);
    }
}
enum SliderID {
    SLIDER_NONE = 0,
    SLIDER_OVERLAY_LEFT,
    SLIDER_OVERLAY_TOP,
    SLIDER_OVERLAY_WIDTH,
    SLIDER_OVERLAY_HEIGHT,
    SLIDER_MENU_LEFT,
    SLIDER_MENU_TOP,
    SLIDER_MENU_WIDTH,
    SLIDER_MENU_HEIGHT,
    SLIDER_ALPHA,
};

SliderID g_draggingSlider = SLIDER_NONE;

bool g_draggingOverlay = false;
POINT g_dragStartOverlay = { 0, 0 };
RECT g_overlayRectStart = { 0,0,0,0 };

// Variables globales
RECT g_rect = { 100, 100, 300, 300 };
RECT g_corner = { 0,0,0,0 };
bool g_allowMoveRect = false;
bool g_draggingRect = false;


// Met à jour la position du corner en haut-gauche de g_rect
void UpdateCorner() {
    g_corner.left = g_rect.left;
    g_corner.top = g_rect.top;
    g_corner.right = g_corner.left + 20;
    g_corner.bottom = g_corner.top + 20;
}

bool g_moveRectangle = false;
bool g_resizeRectangle = false;
bool g_changeWidthRectangle = false;

bool g_resizeSize = false;
bool g_resizeWidth = false;

bool g_draggingResizeWidth = false;
bool g_draggingResizeHeight = false;
POINT g_dragStartResize = { 0 };
RECT g_rectStartResize = { 0 };


bool g_draggingResize = false;
POINT g_resizeStartPt = { 0 };
RECT g_resizeStartRect = { 0 };

DWORD g_startTime = 0;
bool g_startTimeInitialized = false;
bool g_showMessage = true;
HFONT g_customFont = nullptr;





LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{

    static int sliderCapturedValue = 0; // Valeur temporaire du slider lors du drag

    switch (msg)
    {
    case WM_MOUSEMOVE:
    {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };

        // Si menu visible, on détecte si la souris est au-dessus d'un slider
        if (g_showMenu)
        {
            // Positions des sliders, en fonction du menu actuel
            int y = g_menuRect.top + 250;

            struct SliderInfo {
                RECT rc;
                int minVal;
                int maxVal;
                SliderID id;
            };

            SliderInfo sliders[] = {
                {{ g_menuRect.left + 10, y,       g_menuRect.right - 10, y + 20 }, 0, 1920, SLIDER_OVERLAY_LEFT},
                {{ g_menuRect.left + 10, y + 50,  g_menuRect.right - 10, y + 70 }, 0, 1080, SLIDER_OVERLAY_TOP},
                {{ g_menuRect.left + 10, y + 100, g_menuRect.right - 10, y + 120}, 50, 1920, SLIDER_OVERLAY_WIDTH},
                {{ g_menuRect.left + 10, y + 150, g_menuRect.right - 10, y + 170}, 50, 1080, SLIDER_OVERLAY_HEIGHT},
                {{ g_menuRect.left + 10, y + 200, g_menuRect.right - 10, y + 220}, 0, 1920, SLIDER_MENU_LEFT},
                {{ g_menuRect.left + 10, y + 250, g_menuRect.right - 10, y + 270}, 0, 1080, SLIDER_MENU_TOP},
                {{ g_menuRect.left + 10, y + 300, g_menuRect.right - 10, y + 320}, 50, 1920, SLIDER_MENU_WIDTH},
                {{ g_menuRect.left + 10, y + 350, g_menuRect.right - 10, y + 370}, 50, 1080, SLIDER_MENU_HEIGHT},
                {{ g_menuRect.left + 10, y + 400, g_menuRect.right - 10, y + 420}, 5, 255, SLIDER_ALPHA},
            };

            bool hoverFound = false;

            for (int i = 0; i < 9; i++)
            {
                if (PtInRect(&sliders[i].rc, pt))
                {
                    // Si on est pas déjà en train de drag un slider,
                    // on "sélectionne" ce slider (hover effect)
                    if (g_draggingSlider == SLIDER_NONE)
                    {
                        g_draggingSlider = sliders[i].id;
                        hoverFound = true;
                    }
                    break;
                }
            }
            // Si on ne survole aucun slider et qu'on n'est pas en drag, désélection slider
            if (!hoverFound && g_draggingSlider != SLIDER_NONE && !(wParam & MK_LBUTTON))
            {
                g_draggingSlider = SLIDER_NONE;
            }
        }
        if (g_draggingResize && (wParam & MK_LBUTTON)) {
            int dx = pt.x - g_resizeStartPt.x;
            int dy = pt.y - g_resizeStartPt.y;

            int newWidth = max(50, RectWidth(g_resizeStartRect) + dx);
            int newHeight = max(50, RectHeight(g_resizeStartRect) + dy);

            SetRectFromLTWH(g_overlayRect,
                g_resizeStartRect.left,
                g_resizeStartRect.top,
                newWidth,
                newHeight
            );

            // mettre à jour le coin rouge
            g_overlayCorner = {
                g_overlayRect.right - 15,
                g_overlayRect.bottom - 15,
                g_overlayRect.right,
                g_overlayRect.bottom
            };

            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        }

        //// Redimensionnement largeur
        //if (g_draggingResizeWidth && (wParam & MK_LBUTTON)) {
        //    int newWidth = g_rectStartResize.right - g_rectStartResize.left + (pt.x - g_dragStartResize.x);
        //    if (newWidth < 50) newWidth = 50; // taille minimale
        //    SetRectFromLTWH(g_overlayRect, g_overlayRect.left, g_overlayRect.top, newWidth, RectHeight(g_overlayRect));
        //    InvalidateRect(hwnd, NULL, TRUE);
        //    return 0;
        //}

        //// Redimensionnement hauteur
        //if (g_draggingResizeHeight && (wParam & MK_LBUTTON)) {
        //    int newHeight = g_rectStartResize.bottom - g_rectStartResize.top + (pt.y - g_dragStartResize.y);
        //    if (newHeight < 50) newHeight = 50; // taille minimale
        //    SetRectFromLTWH(g_overlayRect, g_overlayRect.left, g_overlayRect.top, RectWidth(g_overlayRect), newHeight);
        //    InvalidateRect(hwnd, NULL, TRUE);
        //    return 0;
        //}

        // --- Gestion drag sliders avec bouton gauche maintenu ---
        if (g_draggingSlider != SLIDER_NONE && (wParam & MK_LBUTTON))
        {
            // Récupère le rect et min/max val du slider actif
            RECT rc;
            int minVal = 0, maxVal = 0;

            switch (g_draggingSlider)
            {
            case SLIDER_OVERLAY_LEFT:
                rc = { g_menuRect.left + 10, g_menuRect.top + 250, g_menuRect.right - 10, g_menuRect.top + 270 };
                minVal = 0; maxVal = 1920;
                break;
            case SLIDER_OVERLAY_TOP:
                rc = { g_menuRect.left + 10, g_menuRect.top + 300, g_menuRect.right - 10, g_menuRect.top + 320 };
                minVal = 0; maxVal = 1080;
                break;
            case SLIDER_OVERLAY_WIDTH:
                if (!g_resizeRectangle) return 0;
                rc = { g_menuRect.left + 10, g_menuRect.top + 350, g_menuRect.right - 10, g_menuRect.top + 370 };
                minVal = 50; maxVal = 1920;
                break;
            case SLIDER_OVERLAY_HEIGHT:
                rc = { g_menuRect.left + 10, g_menuRect.top + 400, g_menuRect.right - 10, g_menuRect.top + 420 };
                minVal = 50; maxVal = 1080;
                break;
            case SLIDER_MENU_LEFT:
                rc = { g_menuRect.left + 10, g_menuRect.top + 450, g_menuRect.right - 10, g_menuRect.top + 470 };
                minVal = 0; maxVal = 1920;
                break;
            case SLIDER_MENU_TOP:
                rc = { g_menuRect.left + 10, g_menuRect.top + 500, g_menuRect.right - 10, g_menuRect.top + 520 };
                minVal = 0; maxVal = 1080;
                break;
            case SLIDER_MENU_WIDTH:
                rc = { g_menuRect.left + 10, g_menuRect.top + 550, g_menuRect.right - 10, g_menuRect.top + 570 };
                minVal = 50; maxVal = 1920;
                break;
            case SLIDER_MENU_HEIGHT:
                rc = { g_menuRect.left + 10, g_menuRect.top + 600, g_menuRect.right - 10, g_menuRect.top + 620 };
                minVal = 50; maxVal = 1080;
                break;
            case SLIDER_ALPHA:
                rc = { g_menuRect.left + 10, g_menuRect.top + 650, g_menuRect.right - 10, g_menuRect.top + 670 };
                minVal = 5; maxVal = 255;
                break;
            default:
                return 0;
            }

            // Calcule position dans slider
            int trackWidth = rc.right - rc.left - 20;
            int posInTrack = pt.x - rc.left - 10;

            if (posInTrack < 0) posInTrack = 0;
            if (posInTrack > trackWidth) posInTrack = trackWidth;

            sliderCapturedValue = minVal + posInTrack * (maxVal - minVal) / trackWidth;

            // Applique valeur selon slider actif
            switch (g_draggingSlider)
            {
            case SLIDER_OVERLAY_LEFT:
                g_overlayRect.left = sliderCapturedValue;
                break;
            case SLIDER_OVERLAY_TOP:
                g_overlayRect.top = sliderCapturedValue;
                break;
            case SLIDER_OVERLAY_WIDTH:
                if (g_changeWidthRectangle)
                    SetRectFromLTWH(g_overlayRect, g_overlayRect.left, g_overlayRect.top, sliderCapturedValue, RectHeight(g_overlayRect));
                break;
            case SLIDER_OVERLAY_HEIGHT:
                SetRectFromLTWH(g_overlayRect, g_overlayRect.left, g_overlayRect.top, RectWidth(g_overlayRect), sliderCapturedValue);
                break;
            case SLIDER_MENU_LEFT:
                SetRectFromLTWH(g_menuRect, sliderCapturedValue, g_menuRect.top, RectWidth(g_menuRect), RectHeight(g_menuRect));
                g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
                break;
            case SLIDER_MENU_TOP:
                SetRectFromLTWH(g_menuRect, g_menuRect.left, sliderCapturedValue, RectWidth(g_menuRect), RectHeight(g_menuRect));
                g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
                break;
            case SLIDER_MENU_WIDTH:
                SetRectFromLTWH(g_menuRect, g_menuRect.left, g_menuRect.top, sliderCapturedValue, RectHeight(g_menuRect));
                g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
                break;
            case SLIDER_MENU_HEIGHT:
                SetRectFromLTWH(g_menuRect, g_menuRect.left, g_menuRect.top, RectWidth(g_menuRect), sliderCapturedValue);
                g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
                break;
            case SLIDER_ALPHA:
                g_alpha = (BYTE)sliderCapturedValue;
                SetLayeredWindowAttributes(g_hOverlay, 0, g_alpha, LWA_ALPHA);
                break;
            }

            SaveConfig();
            InvalidateRect(hwnd, NULL, TRUE);
        }

        // --- Drag overlay rectangle ---
        if (g_moveRectangle && g_draggingOverlay && (wParam & MK_LBUTTON))
        {
            int dx = pt.x - g_dragStartOverlay.x;
            int dy = pt.y - g_dragStartOverlay.y;

            SetRectFromLTWH(g_overlayRect,
                g_overlayRectStart.left + dx,
                g_overlayRectStart.top + dy,
                RectWidth(g_overlayRectStart),
                RectHeight(g_overlayRectStart)
            );

            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        }
        g_overlayCorner = {
    g_overlayRect.right - 15,
    g_overlayRect.bottom - 15,
    g_overlayRect.right,
    g_overlayRect.bottom
        };

        // Drag menu handling (à garder si tu as la fonction)
        HandleMenuDrag(hwnd, pt, wParam);

        break;
    }
    //case WM_SETCURSOR:
    //{
    //    if (g_resizeRectangle && PtInRect(&g_overlayCorner, { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) })) {
    //        SetCursor(LoadCursor(NULL, IDC_SIZENWSE)); // Diagonal resize cursor
    //        return TRUE;
    //    }
    //    break;
    //}

    case WM_LBUTTONDOWN:
    {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };

        if (g_showMenu)
        {

            POINT pt;
            GetCursorPos(&pt);
            ScreenToClient(hwnd, &pt);
            RECT cbAllowMove = { g_menuCorner.right + 5, g_menuCorner.top + 7, g_menuCorner.right + 150, g_menuCorner.top + 23 };

            RECT btnRect = { cbAllowMove.right + 10, cbAllowMove.top, cbAllowMove.right + 70, cbAllowMove.bottom };

            if (PtInRect(&btnRect, pt))
            {
                DestroyWindow(g_hOverlay);   // détruit ta fenêtre overlay
                PostQuitMessage(0);          // indique au message loop de quitter
                ExitProcess(0);
                break;
                // Action du bouton
                //MessageBox(hwnd, L"Bouton Reset cliqué !", L"Info", MB_OK);
            }

            // Checkbox zones (hauteur 25px)
            RECT cbAimbot = { g_menuRect.left + 10, g_menuRect.top + 60,  g_menuRect.right - 10, g_menuRect.top + 85 };
            RECT cbHeadOnly = { g_menuRect.left + 10, g_menuRect.top + 90,  g_menuRect.right - 10, g_menuRect.top + 115 };
            RECT cbShowRect = { g_menuRect.left + 10, g_menuRect.top + 120, g_menuRect.right - 10, g_menuRect.top + 145 };
            RECT cb3 = { g_menuRect.left + 10, g_menuRect.top + 110, g_menuRect.right - 10, g_menuRect.top + 130 };


            RECT cbAllowMoveMenu = { g_menuCorner.right + 5, g_menuCorner.top + 7, g_menuCorner.right + 150, g_menuCorner.top + 32 };

            RECT cbMoveRect = { g_menuRect.left + 10, g_menuRect.top + 150, g_menuRect.right - 10, g_menuRect.top + 175 };
            RECT cbResizeRect = { g_menuRect.left + 10, g_menuRect.top + 180, g_menuRect.right - 10, g_menuRect.top + 205 };
            RECT cbChangeWidthRect = { g_menuRect.left + 10, g_menuRect.top + 210, g_menuRect.right - 10, g_menuRect.top + 235 };

            // Gestion checkbox click
            if (PtInRect(&cbMoveRect, pt)) {
                g_moveRectangle = !g_moveRectangle;
                SaveConfig();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }
            else if (PtInRect(&cbResizeRect, pt)) {
                g_resizeRectangle = !g_resizeRectangle;
                SaveConfig();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }
            /*else if (PtInRect(&cbChangeWidthRect, pt)) {
                g_changeWidthRectangle = !g_changeWidthRectangle;
                SaveConfig();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }*/

            else if (PtInRect(&cb3, pt))
            {
                g_quicktimeEvent = !g_quicktimeEvent;
                SaveConfig();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }

            else if (PtInRect(&cbAimbot, pt))
            {
                g_aimbotActive = !g_aimbotActive;
                SaveConfig();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }
            else if (PtInRect(&cbHeadOnly, pt))
            {
                g_aimbotHeadOnly = !g_aimbotHeadOnly;
                SaveConfig();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }
            else if (PtInRect(&cbShowRect, pt))
            {
                g_showRectangle = !g_showRectangle;
                SaveConfig();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }
            else if (PtInRect(&cbAllowMoveMenu, pt))
            {
                g_allowMoveMenu = !g_allowMoveMenu;
                SaveConfig();
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            }
            else
            {
                // Sliders zones (avec espaces entre chaque)
                int y = g_menuRect.top + 250;

                struct SliderInfo {
                    RECT rc;
                    int minVal;
                    int maxVal;
                    SliderID id;
                };

                SliderInfo sliders[] = {
                    {{ g_menuRect.left + 10, y,       g_menuRect.right - 10, y + 20 }, 0, 1920, SLIDER_OVERLAY_LEFT},
                    {{ g_menuRect.left + 10, y + 50,  g_menuRect.right - 10, y + 70 }, 0, 1080, SLIDER_OVERLAY_TOP},
                    {{ g_menuRect.left + 10, y + 100, g_menuRect.right - 10, y + 120}, 50, 1920, SLIDER_OVERLAY_WIDTH},
                    {{ g_menuRect.left + 10, y + 150, g_menuRect.right - 10, y + 170}, 50, 1080, SLIDER_OVERLAY_HEIGHT},
                    {{ g_menuRect.left + 10, y + 200, g_menuRect.right - 10, y + 220}, 0, 1920, SLIDER_MENU_LEFT},
                    {{ g_menuRect.left + 10, y + 250, g_menuRect.right - 10, y + 270}, 0, 1080, SLIDER_MENU_TOP},
                    {{ g_menuRect.left + 10, y + 300, g_menuRect.right - 10, y + 320}, 50, 1920, SLIDER_MENU_WIDTH},
                    {{ g_menuRect.left + 10, y + 350, g_menuRect.right - 10, y + 370}, 50, 1080, SLIDER_MENU_HEIGHT},
                    {{ g_menuRect.left + 10, y + 400, g_menuRect.right - 10, y + 420}, 5, 255, SLIDER_ALPHA},
                };

                for (int i = 0; i < 9; i++)
                {
                    if (PtInRect(&sliders[i].rc, pt))
                    {
                        // On commence drag slider
                        g_draggingSlider = sliders[i].id;

                        // Capture valeur selon position x dans slider
                        int trackWidth = sliders[i].rc.right - sliders[i].rc.left - 20;
                        int posInTrack = pt.x - sliders[i].rc.left - 10;
                        if (posInTrack < 0) posInTrack = 0;
                        if (posInTrack > trackWidth) posInTrack = trackWidth;

                        sliderCapturedValue = sliders[i].minVal + posInTrack * (sliders[i].maxVal - sliders[i].minVal) / trackWidth;

                        // Applique valeur
                        switch (g_draggingSlider)
                        {
                        case SLIDER_OVERLAY_LEFT:
                            g_overlayRect.left = sliderCapturedValue;
                            break;
                        case SLIDER_OVERLAY_TOP:
                            g_overlayRect.top = sliderCapturedValue;
                            break;
                        case SLIDER_OVERLAY_WIDTH:
                            if (g_changeWidthRectangle)
                                SetRectFromLTWH(g_overlayRect, g_overlayRect.left, g_overlayRect.top, sliderCapturedValue, RectHeight(g_overlayRect));
                            break;
                        case SLIDER_OVERLAY_HEIGHT:
                            SetRectFromLTWH(g_overlayRect, g_overlayRect.left, g_overlayRect.top, RectWidth(g_overlayRect), sliderCapturedValue);
                            break;
                        case SLIDER_MENU_LEFT:
                            SetRectFromLTWH(g_menuRect, sliderCapturedValue, g_menuRect.top, RectWidth(g_menuRect), RectHeight(g_menuRect));
                            g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
                            break;
                        case SLIDER_MENU_TOP:
                            SetRectFromLTWH(g_menuRect, g_menuRect.left, sliderCapturedValue, RectWidth(g_menuRect), RectHeight(g_menuRect));
                            g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
                            break;
                        case SLIDER_MENU_WIDTH:
                            SetRectFromLTWH(g_menuRect, g_menuRect.left, g_menuRect.top, sliderCapturedValue, RectHeight(g_menuRect));
                            g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
                            break;
                        case SLIDER_MENU_HEIGHT:
                            SetRectFromLTWH(g_menuRect, g_menuRect.left, g_menuRect.top, RectWidth(g_menuRect), sliderCapturedValue);
                            g_menuCorner = { g_menuRect.left, g_menuRect.top, g_menuRect.left + 30, g_menuRect.top + 30 };
                            break;
                        case SLIDER_ALPHA:
                            g_alpha = (BYTE)sliderCapturedValue;
                            SetLayeredWindowAttributes(g_hOverlay, 0, g_alpha, LWA_ALPHA);
                            break;
                        }

                        SaveConfig();
                        InvalidateRect(hwnd, NULL, TRUE);
                        return 0;
                    }
                }
            }
        }
        //if (g_resizeRectangle) {
        //    // Zone sensibilité droite 10px
        //    RECT rightEdge = { g_overlayRect.right - 10, g_overlayRect.top, g_overlayRect.right, g_overlayRect.bottom };
        //    // Zone sensibilité bas 10px
        //    RECT bottomEdge = { g_overlayRect.left, g_overlayRect.bottom - 10, g_overlayRect.right, g_overlayRect.bottom };

        //    if (PtInRect(&rightEdge, pt)) {
        //        g_draggingResizeWidth = true;
        //        g_dragStartResize = pt;
        //        g_rectStartResize = g_overlayRect;
        //        SetCapture(hwnd);
        //        return 0;
        //    }
        //    if (PtInRect(&bottomEdge, pt)) {
        //        g_draggingResizeHeight = true;
        //        g_dragStartResize = pt;
        //        g_rectStartResize = g_overlayRect;
        //        SetCapture(hwnd);
        //        return 0;
        //    }
        //}
        if (g_resizeRectangle && PtInRect(&g_overlayCorner, pt)) {
            g_draggingResize = true;
            g_resizeStartPt = pt;
            g_resizeStartRect = g_overlayRect;
            SetCapture(hwnd);
            return 0;
        }

        RECT cbResize = { g_menuRect.left + 10, g_menuRect.top + 180, g_menuRect.right - 10, g_menuRect.top + 200 };

        if (PtInRect(&cbResize, pt)) {
            g_resizeRectangle = !g_resizeRectangle;
            SaveConfig();
            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        }


        // Drag overlay (si visible ET move activé)
        if (g_showRectangle && g_moveRectangle && PtInRect(&g_overlayRect, pt)) {
            g_draggingOverlay = true;
            g_dragStartOverlay = pt;
            g_overlayRectStart = g_overlayRect;
            SetCapture(hwnd);
            return 0;
        }

        break;
    }

    case WM_LBUTTONUP:
    {
        /*if (g_draggingResizeWidth || g_draggingResizeHeight) {
            g_draggingResizeWidth = false;
            g_draggingResizeHeight = false;
            ReleaseCapture();
            SaveConfig();
            return 0;
        }*/
        if (g_draggingResize) {
            g_draggingResize = false;
            ReleaseCapture();
            SaveConfig();
            return 0;
        }

        if (g_draggingOverlay) {
            g_draggingOverlay = false;
            ReleaseCapture();
            SaveConfig();
            return 0;
        }

        g_draggingSlider = SLIDER_NONE;
        g_draggingMenu = false;
        SaveConfig();
        break;
    }
    /*case WM_TIMER:
        InvalidateRect(hwnd, NULL, TRUE);
        break;*/

    case WM_KEYDOWN:
        if (wParam == VK_F4 && g_showMessage)
        {
            g_showMessage = false;
            InvalidateRect(hwnd, NULL, TRUE);
        }
        break;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        if (!g_startTimeInitialized)
        {
            g_startTime = GetTickCount();
            g_startTimeInitialized = true;
        }

        if (g_showMessage)
        {
            DWORD now = GetTickCount();
            if (now - g_startTime < 10000)
            {
                SetTextColor(hdc, RGB(255, 0, 0)); // Rouge
                SetBkMode(hdc, TRANSPARENT);

                if (g_customFont)
                    SelectObject(hdc, g_customFont);

                RECT rect = { 10, 10, 600, 60 };
                DrawText(hdc, L"F4 Open Menu", -1, &rect, DT_LEFT | DT_TOP | DT_SINGLELINE);

                InvalidateRect(hwnd, NULL, TRUE); // Continuer à redessiner
            }
            else
            {
                g_showMessage = false;
                InvalidateRect(hwnd, NULL, TRUE);
            }
        }

        // Double buffering
        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBmp = CreateCompatibleBitmap(hdc, ps.rcPaint.right - ps.rcPaint.left, ps.rcPaint.bottom - ps.rcPaint.top);
        HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, memBmp);

        // Fond noir transparent
        HBRUSH eraseBrush = CreateSolidBrush(RGB(0, 0, 0));
        FillRect(memDC, &ps.rcPaint, eraseBrush);
        DeleteObject(eraseBrush);

        // Rectangle overlay principal
        if (g_showRectangle)
        {
            HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
            FrameRect(memDC, &g_overlayRect, white);
            DeleteObject(white);
            HBRUSH redBrush = CreateSolidBrush(RGB(255, 0, 0));
            POINT redTriangle[3] = {
                { g_overlayCorner.left, g_overlayCorner.bottom },
                { g_overlayCorner.right, g_overlayCorner.bottom },
                { g_overlayCorner.right, g_overlayCorner.top }
            };
            Polygon(memDC, redTriangle, 3);
            DeleteObject(redBrush);

        }

        if (g_showMenu)
        {
            HBRUSH bg = CreateSolidBrush(RGB(240, 240, 240));
            FillRect(memDC, &g_menuRect, bg);
            DeleteObject(bg);

            if (g_allowMoveMenu)
                DrawBlueTriangle(memDC, g_menuCorner);

            // Texte du menu
            std::string text = "Thunder-Menu"/* + std::to_string(g_alpha)*/;
            RECT txt = { g_menuRect.left + 10, g_menuRect.top + 30, g_menuRect.right - 10, g_menuRect.top + 50 };
            DrawTextA(memDC, text.c_str(), -1, &txt, DT_LEFT | DT_TOP);

            // Checkbox "Allow Move Menu"
            RECT cbAllowMove = { g_menuCorner.right + 5, g_menuCorner.top + 7, g_menuCorner.right + 150, g_menuCorner.top + 23 };
            DrawCheckbox(memDC, cbAllowMove, g_allowMoveMenu, "Allow Move Menu");
            RECT btnRect = { cbAllowMove.right + 10, cbAllowMove.top, cbAllowMove.right + 70, cbAllowMove.bottom };

            // Dessiner le fond du bouton
            HBRUSH btnBrush = CreateSolidBrush(RGB(200, 200, 200));
            FillRect(memDC, &btnRect, btnBrush);
            DeleteObject(btnBrush);

            // Bordure du bouton
            FrameRect(memDC, &btnRect, (HBRUSH)GetStockObject(BLACK_BRUSH));

            // Texte du bouton
            SetTextColor(memDC, RGB(0, 0, 0));
            SetBkMode(memDC, TRANSPARENT);

            DrawText(memDC, L"F12 or X", -1, &btnRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);


            // Checkboxes principales
            RECT cb1 = { g_menuRect.left + 10, g_menuRect.top + 60,  g_menuRect.right - 10, g_menuRect.top + 80 };
            RECT cb2 = { g_menuRect.left + 10, g_menuRect.top + 80,  g_menuRect.right - 10, g_menuRect.top + 100 };
            RECT cb3 = { g_menuRect.left + 10, g_menuRect.top + 110, g_menuRect.right - 10, g_menuRect.top + 130 };
            RECT cb4 = { g_menuRect.left + 10, g_menuRect.top + 130, g_menuRect.right - 10, g_menuRect.top + 150 };

            DrawCheckbox(memDC, cb1, g_aimbotActive, "Enable Aimbot");
            DrawCheckbox(memDC, cb2, g_aimbotHeadOnly, "Aim Head Only");

            DrawCheckbox(memDC, cb3, g_quicktimeEvent, "Quick Time Event");
            

            DrawCheckbox(memDC, cb4, g_showRectangle, "Show Rectangle");

            // Après les 3 checkboxes existantes
            RECT cbMoveRect = { g_menuRect.left + 10, g_menuRect.top + 150, g_menuRect.right - 10, g_menuRect.top + 170 };
            //RECT cbResizeRect = { g_menuRect.left + 10, g_menuRect.top + 180, g_menuRect.right - 10, g_menuRect.top + 200 };
            RECT cbChangeWidthRect = { g_menuRect.left + 10, g_menuRect.top + 210, g_menuRect.right - 10, g_menuRect.top + 230 };

            DrawCheckbox(memDC, cbMoveRect, g_moveRectangle, "Move Rectangle");
            /*DrawCheckbox(memDC, cbResizeRect, g_resizeRectangle, "Resize Rectangle");
            DrawCheckbox(memDC, cbChangeWidthRect, g_changeWidthRectangle, "Change Width Rectangle");*/

            RECT cbResizeRect = { g_menuRect.left + 10, g_menuRect.top + 180, g_menuRect.right - 10, g_menuRect.top + 200 };
            DrawCheckbox(memDC, cbResizeRect, g_resizeRectangle, "Resize Rectangle");


            // Sliders, position à partir de y = g_menuRect.top + 250 (pour bien séparer)
            int y = g_menuRect.top + 250;

            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, g_overlayRect.left, 0, 1920, "Overlay Left");
            y += 50;
            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, g_overlayRect.top, 0, 1080, "Overlay Top");
            y += 50;
            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, RectWidth(g_overlayRect), 50, 1920, "Overlay Width");
            y += 50;
            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, RectHeight(g_overlayRect), 50, 1080, "Overlay Height");
            y += 50;
            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, g_menuRect.left, 0, 1920, "Menu Left");
            y += 50;
            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, g_menuRect.top, 0, 1080, "Menu Top");
            y += 50;
            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, RectWidth(g_menuRect), 50, 1920, "Menu Width");
            y += 50;
            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, RectHeight(g_menuRect), 50, 1080, "Menu Height");
            y += 50;
            DrawSlider(memDC, { g_menuRect.left + 10, y, g_menuRect.right - 10, y + 20 }, g_alpha, 5, 255, "Overlay Transparency");
        }

        // Blit final
        BitBlt(hdc, ps.rcPaint.left, ps.rcPaint.top,
            ps.rcPaint.right - ps.rcPaint.left,
            ps.rcPaint.bottom - ps.rcPaint.top,
            memDC, 0, 0, SRCCOPY);

        SelectObject(memDC, oldBmp);
        DeleteObject(memBmp);
        DeleteDC(memDC);

        EndPaint(hwnd, &ps);
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    return 0;
}

HWND CreateOverlayWindow(HINSTANCE hInstance)
{
    /*WNDCLASSEX wc = { sizeof(WNDCLASSEX) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"Thunder-Menu";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
    RegisterClassEx(&wc);*/

    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
    wc.lpszClassName = L"Thunder-Menu"; //ico alt+tab

    // Icônes pour Alt+Tab et barre de titre
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));     // pour Alt+Tab
    wc.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));   // coin supérieur gauche

    RegisterClassEx(&wc);


    //DWORD exStyle = WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT; //no visible
    DWORD exStyle = WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT; //visible

    HWND hwnd = CreateWindowEx(
        exStyle,
        wc.lpszClassName, L"Thunder-Menu", WS_POPUP,
        0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
        NULL, NULL, hInstance, NULL
    );

    //SetLayeredWindowAttributes(hwnd, 0, g_alpha, LWA_ALPHA);

    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);

    ShowWindow(hwnd, SW_SHOW);
    InvalidateRect(hwnd, NULL, TRUE); // Force le premier dessin

    // Crée une police plus grande
    g_customFont = CreateFont(
        28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI"
    );

    return hwnd;
}
std::atomic<bool> g_shouldExit{ false };
static int captureCount = 0;

void OverlayThread(HINSTANCE hInstance)
{
    LoadConfig();

    g_hOverlay = CreateOverlayWindow(hInstance);

    MSG msg;
    DWORD lastTick = GetTickCount();
    bool lastF4State = false;
    bool lastF9State = false;

    while (!g_shouldExit)
    {
        SHORT f4State = GetAsyncKeyState(VK_F4);
        bool f4Pressed = (f4State & 0x8000) != 0;

        if (f4Pressed && !lastF4State) {
            g_showMenu = !g_showMenu;

            LONG style = GetWindowLong(g_hOverlay, GWL_EXSTYLE);
            if (g_showMenu)
                SetWindowLong(g_hOverlay, GWL_EXSTYLE, style & ~WS_EX_TRANSPARENT);
            else
                SetWindowLong(g_hOverlay, GWL_EXSTYLE, style | WS_EX_TRANSPARENT);

            InvalidateRect(g_hOverlay, NULL, TRUE);
        }

        lastF4State = f4Pressed;

        SHORT f9State = GetAsyncKeyState(VK_F9); // print screen
        bool f9Pressed = (f9State & 0x8000) != 0;

        //if (IsKeyPressed(VK_F9)) {
        if (f9Pressed && !lastF9State) {
            std::string filename = "capture" + std::to_string(captureCount) + ".bmp";
            CaptureScreenToFile(filename);
            captureCount = captureCount + 1;
            /*std::string randomName = "capture_" + GenerateRandomName(6) + ".bmp";
            CaptureScreenToFile(randomName);*/
        }
        lastF9State = f9Pressed;

        // Nouvelle détection de F12 pour quitter
        SHORT f12State = GetAsyncKeyState(VK_F12);
        bool f12Pressed = (f12State & 0x8000) != 0;

        if (f12Pressed) {
            g_shouldExit = true;
            DestroyWindow(g_hOverlay);   // détruit ta fenêtre overlay
            PostQuitMessage(0);          // indique au message loop de quitter
            ExitProcess(0);
            break;                      // quitte la boucle pour finir ce thread
        }

        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        DWORD now = GetTickCount();
        if (now - lastTick > 16)  // ~60 FPS
        {
            InvalidateRect(g_hOverlay, NULL, TRUE);
            UpdateWindow(g_hOverlay);
            lastTick = now;
        }
    }
}

std::thread overlayThread;
DWORD WINAPI MainThread(LPVOID)
{
    if (MH_Initialize() != MH_OK)
        return 1;

    void* pBitBlt = GetProcAddress(GetModuleHandle(L"gdi32.dll"), "BitBlt");
    if (!pBitBlt) return 1;


    if (MH_CreateHook(pBitBlt, &hkBitBlt, reinterpret_cast<void**>(&oBitBlt)) != MH_OK)
        return 1;

    if (MH_EnableHook(pBitBlt) != MH_OK)
        return 1;

    overlayThread = std::thread(OverlayThread, GetModuleHandle(NULL));
    // Optionnel : attendre la fin du thread overlay
    //overlayThread.join();
    overlayThread.detach();  // ← IMPORTANT

    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    DisableThreadLibraryCalls(hInstance);
    CreateThread(NULL, 0, MainThread, NULL, 0, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
