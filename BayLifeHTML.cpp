#include <iostream>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <vector>
#include <regex>
#include "BayLifeHTML.h"


#include <string>

#define _CRT_SECURE_NO_WARNINGS

namespace BayLife {
    std::string htmlContent;
    bool firstLaunch = true;
    bool showConsole = true;
    HANDLE hConsole = NULL;
    HWND consoleWindow = NULL;

    struct ColoredChar {
        char c;
        std::string color; // Stocke la séquence ANSI
    };
    std::vector<std::vector<ColoredChar>> imageData;
}

void InitializeConsole() {
    if (!BayLife::hConsole) {
        AllocConsole();
        BayLife::consoleWindow = GetConsoleWindow();
        freopen("CONIN$", "r", stdin);
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);

        BayLife::hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        // Activer le mode VT100 pour les séquences ANSI
        DWORD mode = 0;
        GetConsoleMode(BayLife::hConsole, &mode);
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(BayLife::hConsole, mode);

        // Configuration console avec la même taille qu'avant
        CONSOLE_SCREEN_BUFFER_INFOEX csbi = { sizeof(csbi) };
        GetConsoleScreenBufferInfoEx(BayLife::hConsole, &csbi);

        // Taille buffer = très grand pour permettre scroll, fenêtre visible standard
        csbi.dwSize = { 120, 9000 };      // Largeur fixe, hauteur très haute
        csbi.srWindow = { 0, 0, 119, 29 }; // 30 lignes visibles (0-29)
        SetConsoleScreenBufferInfoEx(BayLife::hConsole, &csbi);

        // Police console (même taille qu'avant)
        CONSOLE_FONT_INFOEX cfi = { sizeof(cfi) };
        cfi.dwFontSize.Y = 14;
        wcscpy_s(cfi.FaceName, L"Lucida Console");
        SetCurrentConsoleFontEx(BayLife::hConsole, FALSE, &cfi);

        SetConsoleTitle(L"BayLife Image Viewer");
    }
}

void BayLife::ToggleConsole(bool show) {
    showConsole = show;
    if (consoleWindow) {
        ShowWindow(consoleWindow, show ? SW_SHOW : SW_HIDE);
        if (show) SetForegroundWindow(consoleWindow);
    }
}

std::string HexToAnsiColor(const std::string& hex) {
    int r = std::stoi(hex.substr(0, 2), nullptr, 16);
    int g = std::stoi(hex.substr(2, 2), nullptr, 16);
    int b = std::stoi(hex.substr(4, 2), nullptr, 16);
    return "\033[38;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
}

void ParseHTMLToImageData() {
    BayLife::imageData.clear();
    const std::string BLACK = "\033[38;2;0;0;0m";

    // Première passe pour déterminer la largeur maximale
    size_t maxWidth = 0;
    std::istringstream htmlStream(BayLife::htmlContent);
    std::string htmlLine;

    while (std::getline(htmlStream, htmlLine)) {
        size_t lineWidth = 0;
        std::regex pattern(R"(<b style=\"color:#([0-9A-Fa-f]{6})\">([01]+)<\/b>)");
        auto words_begin = std::sregex_iterator(htmlLine.begin(), htmlLine.end(), pattern);
        auto words_end = std::sregex_iterator();

        for (std::sregex_iterator it = words_begin; it != words_end; ++it) {
            lineWidth += (*it)[2].str().length();
        }

        if (lineWidth > maxWidth) {
            maxWidth = lineWidth;
        }
    }

    // Deuxième passe pour construire l'image avec le fond et les bordures
    htmlStream.clear();
    htmlStream.seekg(0);

    // Ajouter bordure supérieure (identique à l'original)
    std::vector<BayLife::ColoredChar> topBorder(maxWidth + 2, { '0', BLACK });
    BayLife::imageData.push_back(topBorder);

    while (std::getline(htmlStream, htmlLine)) {
        std::vector<BayLife::ColoredChar> currentLine;
        std::regex pattern(R"(<b style=\"color:#([0-9A-Fa-f]{6})\">([01]+)<\/b>)");
        auto words_begin = std::sregex_iterator(htmlLine.begin(), htmlLine.end(), pattern);
        auto words_end = std::sregex_iterator();

        // Bordure gauche
        currentLine.push_back({ '0', BLACK });

        for (std::sregex_iterator it = words_begin; it != words_end; ++it) {
            std::string colorHex = (*it)[1].str();
            std::string chars = (*it)[2].str();
            std::string color = HexToAnsiColor(colorHex);

            for (char c : chars) {
                currentLine.push_back({ c, color });
            }
        }

        // Compléter avec fond noir si nécessaire
        while (currentLine.size() < maxWidth + 1) {
            currentLine.push_back({ '0', BLACK });
        }

        // Bordure droite
        currentLine.push_back({ '0', BLACK });

        if (!currentLine.empty()) {
            BayLife::imageData.push_back(currentLine);
        }
    }

    // Ajouter bordure inférieure (identique à l'original)
    BayLife::imageData.push_back(topBorder);
}

bool AdjustConsoleToImageSize() {
    if (BayLife::imageData.empty()) return false;

    HANDLE hConsole = BayLife::hConsole;
    SHORT width = (SHORT)BayLife::imageData[0].size();
    SHORT height = (SHORT)BayLife::imageData.size();

    // Récupérer info console actuelle
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        return false;
    }

    // Taille buffer minimum requise
    COORD bufferSize = csbi.dwSize;
    if (bufferSize.X < width) bufferSize.X = width;
    if (bufferSize.Y < height) bufferSize.Y = height;

    // Appliquer la taille du buffer
    if (!SetConsoleScreenBufferSize(hConsole, bufferSize)) {
        return false;
    }

    // Définir la fenêtre visible
    SMALL_RECT windowRect;
    windowRect.Left = 0;
    windowRect.Top = 0;
    windowRect.Right = width - 1;
    windowRect.Bottom = height - 1;

    if (windowRect.Right >= bufferSize.X) windowRect.Right = bufferSize.X - 1;
    if (windowRect.Bottom >= bufferSize.Y) windowRect.Bottom = bufferSize.Y - 1;

    if (!SetConsoleWindowInfo(hConsole, TRUE, &windowRect)) {
        return false;
    }

    return true;
}

void DisplayImageData() {
    if (!BayLife::showConsole || BayLife::imageData.empty()) return;

    // Ajuster la console à la taille de l'image (comme dans l'original)
    if (!AdjustConsoleToImageSize()) {
        std::cerr << "Failed to adjust console size\n";
        return;
    }

    // Positionner le curseur en haut à gauche
    std::cout << "\033[H";

    for (const auto& line : BayLife::imageData) {
        std::string currentColor;
        for (const auto& cc : line) {
            if (cc.color != currentColor) {
                std::cout << cc.color;
                currentColor = cc.color;
            }
            std::cout << cc.c;
        }
        std::cout << "\n";
    }

    // Réinitialiser les couleurs et positionner le curseur en bas
    std::cout << "\033[0m";
    COORD cursorPos = { 0, (SHORT)BayLife::imageData.size() };
    SetConsoleCursorPosition(BayLife::hConsole, cursorPos);
}

void LoadHTMLFromFile() {
    std::ifstream file("baylife.html", std::ios::binary);
    if (file) {
        std::ostringstream oss;
        oss << file.rdbuf();
        BayLife::htmlContent = oss.str();
        ParseHTMLToImageData();
    }
    else if (BayLife::showConsole) {
        std::cerr << "[ERROR] File not found\n";
    }
}

int mainBayLife() {
    if (BayLife::showConsole) {
        InitializeConsole();
        LoadHTMLFromFile();
        DisplayImageData();

        std::cout << "\nPress Enter to exit...";
        std::cin.ignore();
    }
    return 0;
}

int BayLife::BayLifeImage() {
    if (firstLaunch) {
        ToggleConsole(true);
        LoadHTMLFromFile();
        firstLaunch = false;
    }
    return mainBayLife();
}
