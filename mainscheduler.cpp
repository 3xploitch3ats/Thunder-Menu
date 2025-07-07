#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <locale>
#include <codecvt>
#include <iostream>

#pragma comment(lib, "comctl32.lib")

#define IDC_TREEVIEW 1001
#define IDC_BTN_DELETE 1002
#define IDC_BTN_REFRESH 1003

#define IDC_TASKNAME 101
#define IDC_EXEPATH 102
#define IDC_OPENFILE 103
#define IDC_DAYS 104
#define IDC_HOURS 105
#define IDC_MINUTES 106
#define IDC_CREATE 107
#define IDC_STATUS 108
#define IDC_MANAGE_TASKS 109

HWND hTreeView, hBtnDelete, hBtnRefresh;
HWND hTaskName, hExePath, hOpenFileBtn, hDays, hHours, hMinutes, hStatus;


bool IsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

void RelaunchAsAdmin(int argc, wchar_t** argv)
{
    if (!IsAdmin())
    {
        std::wstring params;
        for (int i = 1; i < argc; i++)
        {
            params += L"\"";
            params += argv[i];
            params += L"\" ";
        }
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = argv[0];
        sei.lpParameters = params.c_str();
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteExW(&sei))
        {
            MessageBoxW(NULL, L"Échec de l'élévation des privilèges.", L"Erreur", MB_ICONERROR);
            ExitProcess(1);
        }
        ExitProcess(0);
    }
}

std::wstring RunCommand(const std::wstring& cmd)
{
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return L"";

    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi = {};

    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);

    BOOL res = CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWrite);
    if (!res)
    {
        CloseHandle(hRead);
        return L"";
    }

    std::wstring output;
    char buffer[4096];
    DWORD bytesRead;

    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
    {
        buffer[bytesRead] = 0;
        int wlen = MultiByteToWideChar(CP_OEMCP, 0, buffer, bytesRead, NULL, 0);
        std::wstring wbuf(wlen, L'\0');
        MultiByteToWideChar(CP_OEMCP, 0, buffer, bytesRead, &wbuf[0], wlen);
        output += wbuf;
    }

    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output;
}

std::vector<std::wstring> ParseTaskNamesFromCSV(const std::wstring& output)
{
    std::vector<std::wstring> names;
    std::wistringstream iss(output);
    std::wstring line;

    std::getline(iss, line); // Skip header

    while (std::getline(iss, line))
    {
        if (line.empty()) continue;

        size_t commaPos = line.find(L',');
        if (commaPos != std::wstring::npos)
        {
            std::wstring fullName = line.substr(0, commaPos);
            if (!fullName.empty() && fullName.front() == L'"' && fullName.back() == L'"')
                fullName = fullName.substr(1, fullName.size() - 2);

            size_t lastSlash = fullName.rfind(L'\\');
            if (lastSlash != std::wstring::npos)
                fullName = fullName.substr(lastSlash + 1);

            if (!fullName.empty())
                names.push_back(fullName);
        }
    }

    return names;
}

std::vector<std::wstring> ParseTaskNamesFromList(const std::wstring& output)
{
    std::vector<std::wstring> names;
    std::wistringstream iss(output);
    std::wstring line;
    while (std::getline(iss, line))
    {
        if (line.find(L"TaskName:") == 0)
        {
            std::wstring fullName = line.substr(9);
            while (!fullName.empty() && (fullName.front() == L' ' || fullName.front() == L'\t'))
                fullName.erase(fullName.begin());

            size_t lastSlash = fullName.rfind(L'\\');
            if (lastSlash != std::wstring::npos)
                fullName = fullName.substr(lastSlash + 1);

            if (!fullName.empty())
                names.push_back(fullName);
        }
    }
    return names;
}

std::vector<std::wstring> GetTaskNames()
{
    std::vector<std::wstring> tasks;

    std::wstring out = RunCommand(L"schtasks /query /fo CSV");
    if (!out.empty())
    {
        tasks = ParseTaskNamesFromCSV(out);
        if (!tasks.empty())
            goto sort_tasks;
    }

    out = RunCommand(L"schtasks /query /fo LIST");
    if (!out.empty())
    {
        tasks = ParseTaskNamesFromList(out);
    }

sort_tasks:
    std::sort(tasks.begin(), tasks.end(), [](const std::wstring& a, const std::wstring& b)
        {
            std::wstring lowerA = a, lowerB = b;
            std::transform(lowerA.begin(), lowerA.end(), lowerA.begin(), ::towlower);
            std::transform(lowerB.begin(), lowerB.end(), lowerB.begin(), ::towlower);
            return lowerA < lowerB;
        });
    return tasks;
}

std::wstring FindFullTaskName(const std::wstring& shortName)
{
    std::wstring output = RunCommand(L"schtasks /query /fo LIST");
    if (!output.empty())
    {
        std::wistringstream iss(output);
        std::wstring line;
        while (std::getline(iss, line))
        {
            if (line.find(L"TaskName:") == 0)
            {
                std::wstring fullName = line.substr(9);
                while (!fullName.empty() && (fullName.front() == L' ' || fullName.front() == L'\t'))
                    fullName.erase(fullName.begin());

                if (fullName.size() >= shortName.size() &&
                    fullName.compare(fullName.size() - shortName.size(), shortName.size(), shortName) == 0)
                {
                    return fullName;
                }
            }
        }
    }

    output = RunCommand(L"schtasks /query /fo CSV");
    if (!output.empty())
    {
        std::wistringstream iss(output);
        std::wstring line;
        std::getline(iss, line); // header
        while (std::getline(iss, line))
        {
            if (line.empty()) continue;
            size_t commaPos = line.find(L',');
            if (commaPos == std::wstring::npos) continue;

            std::wstring fullName = line.substr(0, commaPos);
            if (fullName.front() == L'"' && fullName.back() == L'"')
                fullName = fullName.substr(1, fullName.size() - 2);

            if (fullName.size() >= shortName.size() &&
                fullName.compare(fullName.size() - shortName.size(), shortName.size(), shortName) == 0)
            {
                return fullName;
            }
        }
    }

    return L"";
}

void DeleteTask(const std::wstring& shortName)
{
    std::wstring fullName = FindFullTaskName(shortName);
    if (fullName.empty())
    {
        MessageBoxW(NULL, L"Impossible de trouver le nom complet de la tâche", L"Erreur", MB_ICONERROR);
        return;
    }
    std::wstring cmd = L"schtasks /delete /tn \"" + fullName + L"\" /f";
    std::wstring result = RunCommand(cmd);
    MessageBoxW(NULL, (L"Tâche \"" + shortName + L"\" supprimée avec succès").c_str(), L"Succès", MB_ICONINFORMATION);
}

void FillTreeView(HWND hwndTV, const std::vector<std::wstring>& tasks)
{
    TreeView_DeleteAllItems(hwndTV);
    for (const auto& t : tasks)
    {
        TVINSERTSTRUCTW tvis = { 0 };
        tvis.hParent = TVI_ROOT;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT;
        tvis.item.pszText = const_cast<wchar_t*>(t.c_str());
        TreeView_InsertItem(hwndTV, &tvis);
    }
}

// --- Fenêtre gestionnaire de tâches (deuxième fenêtre) ---

LRESULT CALLBACK TaskManagerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_TREEVIEW_CLASSES };
        InitCommonControlsEx(&icex);

        hTreeView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEW, NULL,
            WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
            10, 10, 460, 300, hwnd, (HMENU)IDC_TREEVIEW, GetModuleHandle(NULL), NULL);

        hBtnDelete = CreateWindowW(L"BUTTON", L"Supprimer la tâche sélectionnée",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 320, 180, 30, hwnd, (HMENU)IDC_BTN_DELETE, NULL, NULL);

        hBtnRefresh = CreateWindowW(L"BUTTON", L"Actualiser",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            200, 320, 100, 30, hwnd, (HMENU)IDC_BTN_REFRESH, NULL, NULL);

        auto tasks = GetTaskNames();
        FillTreeView(hTreeView, tasks);
    }
    break;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_BTN_DELETE)
        {
            HTREEITEM sel = TreeView_GetSelection(hTreeView);
            if (!sel)
            {
                MessageBoxW(hwnd, L"Veuillez sélectionner une tâche.", L"Avertissement", MB_ICONWARNING);
                break;
            }
            wchar_t buf[256];
            TVITEMW tvi = { 0 };
            tvi.hItem = sel;
            tvi.mask = TVIF_TEXT;
            tvi.pszText = buf;
            tvi.cchTextMax = 256;
            if (TreeView_GetItem(hTreeView, &tvi))
            {
                std::wstring taskName = buf;
                int res = MessageBoxW(hwnd,
                    (L"Supprimer la tâche '" + taskName + L"' ?").c_str(),
                    L"Confirmation",
                    MB_YESNO | MB_ICONQUESTION);
                if (res == IDYES)
                {
                    DeleteTask(taskName);
                    auto tasks = GetTaskNames();
                    FillTreeView(hTreeView, tasks);
                }
            }
        }
        else if (LOWORD(wParam) == IDC_BTN_REFRESH)
        {
            auto tasks = GetTaskNames();
            FillTreeView(hTreeView, tasks);
        }
        break;

    case WM_DESTROY:
        DestroyWindow(hwnd);
        break;

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

std::wstring GetCurrentTimeHHMM()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[6];
    swprintf(buf, 6, L"%02d:%02d", st.wHour, st.wMinute);
    return std::wstring(buf);
}

void ShowStatus(const std::wstring& msg)
{
    SetWindowText(hStatus, msg.c_str());
}

bool BrowseForFile(HWND hwnd)
{
    wchar_t filename[MAX_PATH] = { 0 };

    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Executables (*.exe)\0*.exe\0Tous les fichiers (*.*)\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrTitle = L"Sélectionnez un exécutable";

    if (GetOpenFileName(&ofn))
    {
        SetWindowText(hExePath, filename);
        return true;
    }
    return false;
}

void CreateScheduledTask(HWND hwnd)
{
    wchar_t taskName[256], exePath[512], daysStr[16], hoursStr[16], minutesStr[16];
    GetWindowText(hTaskName, taskName, 256);
    GetWindowText(hExePath, exePath, 512);
    GetWindowText(hDays, daysStr, 16);
    GetWindowText(hHours, hoursStr, 16);
    GetWindowText(hMinutes, minutesStr, 16);

    if (wcslen(taskName) == 0)
    {
        MessageBox(hwnd, L"Veuillez entrer un nom de tâche.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }
    if (wcslen(exePath) == 0)
    {
        MessageBox(hwnd, L"Veuillez entrer le chemin de l'exécutable.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    int days = _wtoi(daysStr);
    int hours = _wtoi(hoursStr);
    int minutes = _wtoi(minutesStr);

    if (minutes <= 0)
    {
        MessageBox(hwnd, L"Minutes doit être > 0.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // 1. D'abord essayer de supprimer la tâche si elle existe
    std::wstring fullTaskName = FindFullTaskName(taskName);
    if (!fullTaskName.empty())
    {
        std::wstring deleteCmd = L"schtasks /delete /tn \"" + fullTaskName + L"\" /f";
        int delResult = _wsystem(deleteCmd.c_str());
        if (delResult != 0)
        {
            MessageBox(hwnd,
                L"Impossible de supprimer la tâche existante. Veuillez vérifier les privilèges administrateur.",
                L"Erreur", MB_OK | MB_ICONERROR);
            return;
        }
    }

    // 2. Créer la nouvelle tâche
    std::wstring startTime = GetCurrentTimeHHMM();

    std::wstringstream createCmd;
    createCmd << L"schtasks /Create /TN \"" << taskName << L"\" "
        << L"/TR \"" << exePath << L"\" "
        << L"/SC MINUTE "
        << L"/MO " << minutes << L" "
        << L"/ST " << startTime;

    int ret = _wsystem(createCmd.str().c_str());

    if (ret == 0)
    {
        ShowStatus(L"Tâche créée avec succès.");
        MessageBox(hwnd,
            (L"La tâche '" + std::wstring(taskName) + L"' a été recréée et s'exécutera toutes les " +
                std::to_wstring(minutes) + L" minutes.").c_str(),
            L"Succès", MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        ShowStatus(L"Erreur lors de la création de la tâche.");
        MessageBox(hwnd,
            L"Erreur lors de la création de la tâche planifiée. Vérifiez les privilèges administrateur.",
            L"Erreur", MB_OK | MB_ICONERROR);
    }
}

void FillDefaults(HWND hwnd)
{
    SetWindowText(hTaskName, L"MyTask");
    SetWindowText(hExePath, L"parcourir");
    SetWindowText(hDays, L"0");
    SetWindowText(hHours, L"0");
    SetWindowText(hMinutes, L"5");
    ShowStatus(L"");
}

std::wstring ExecSchtasksCommand(const std::wstring& cmdLine)
{
    HANDLE hRead = NULL, hWrite = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return L"";

    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi = {};

    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);

    BOOL success = CreateProcessW(
        NULL,
        cmdBuf.data(),
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi);

    CloseHandle(hWrite);

    if (!success)
    {
        CloseHandle(hRead);
        return L"";
    }

    std::string outputAnsi;
    char buffer[4096];
    DWORD bytesRead = 0;

    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
    {
        buffer[bytesRead] = 0;
        outputAnsi += buffer;
    }

    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Convert ANSI string (CP_OEMCP) to wstring:
    int wlen = MultiByteToWideChar(CP_OEMCP, 0, outputAnsi.c_str(), -1, NULL, 0);
    if (wlen == 0)
        return L"";

    std::wstring output(wlen - 1, L'\0'); // wlen includes null terminator
    MultiByteToWideChar(CP_OEMCP, 0, outputAnsi.c_str(), -1, &output[0], wlen);

    return output;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        CreateWindowW(L"BUTTON", L"📂", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            2, 2, 30, 30, hwnd, (HMENU)IDC_MANAGE_TASKS, NULL, NULL);

        CreateWindow(L"STATIC", L"Nom de la tâche:", WS_VISIBLE | WS_CHILD, 20, 20, 120, 20, hwnd, NULL, NULL, NULL);
        hTaskName = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 150, 20, 220, 20, hwnd, (HMENU)IDC_TASKNAME, NULL, NULL);

        CreateWindow(L"STATIC", L"Chemin EXE:", WS_VISIBLE | WS_CHILD, 20, 60, 120, 20, hwnd, NULL, NULL, NULL);
        hExePath = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 150, 60, 160, 20, hwnd, (HMENU)IDC_EXEPATH, NULL, NULL);
        hOpenFileBtn = CreateWindow(L"BUTTON", L"Ouvrir fichier...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 320, 60, 80, 20, hwnd, (HMENU)IDC_OPENFILE, NULL, NULL);

        CreateWindow(L"STATIC", L"Jours (0-30):", WS_VISIBLE | WS_CHILD, 20, 100, 120, 20, hwnd, NULL, NULL, NULL);
        hDays = CreateWindow(L"EDIT", L"0", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER, 150, 100, 50, 20, hwnd, (HMENU)IDC_DAYS, NULL, NULL);

        CreateWindow(L"STATIC", L"Heures (0-24):", WS_VISIBLE | WS_CHILD, 20, 140, 120, 20, hwnd, NULL, NULL, NULL);
        hHours = CreateWindow(L"EDIT", L"0", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER, 150, 140, 50, 20, hwnd, (HMENU)IDC_HOURS, NULL, NULL);

        CreateWindow(L"STATIC", L"Minutes (1-60):", WS_VISIBLE | WS_CHILD, 20, 180, 120, 20, hwnd, NULL, NULL, NULL);
        hMinutes = CreateWindow(L"EDIT", L"5", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER, 150, 180, 50, 20, hwnd, (HMENU)IDC_MINUTES, NULL, NULL);

        HWND hButton = CreateWindow(L"BUTTON", L"Créer la tâche", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 150, 220, 150, 30, hwnd, (HMENU)IDC_CREATE, NULL, NULL);

        hStatus = CreateWindow(L"STATIC", L"", WS_VISIBLE | WS_CHILD, 20, 260, 380, 20, hwnd, (HMENU)IDC_STATUS, NULL, NULL);

        FillDefaults(hwnd);
    }
    break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_CREATE:
            CreateScheduledTask(hwnd);
            break;
        case IDC_MANAGE_TASKS:
        {
            // Relancer en admin si nécessaire
            int argc = __argc;
            wchar_t** argv = __wargv;
            RelaunchAsAdmin(argc, argv);

            // Ouvrir la fenêtre gestionnaire de tâches
            WNDCLASSW wc = { 0 };
            wc.lpfnWndProc = TaskManagerWndProc;
            wc.hInstance = GetModuleHandle(NULL);
            wc.lpszClassName = L"TaskManagerWinClass";
            wc.hCursor = LoadCursor(NULL, IDC_ARROW);
            RegisterClassW(&wc);

            HWND hTaskManagerWnd = CreateWindowW(wc.lpszClassName, L"Gestionnaire de Tâches Planifiées",
                WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME,
                CW_USEDEFAULT, CW_USEDEFAULT, 800, 650,
                NULL, NULL, GetModuleHandle(NULL), NULL);

            ShowWindow(hTaskManagerWnd, SW_SHOW);
            UpdateWindow(hTaskManagerWnd);
        }
        break;
        //case IDC_MANAGE_TASKS:
        //{
        //    // Ouvre juste la fenêtre gestionnaire de tâches, sans rien relancer ni redémarrer admin
        //    WNDCLASSW wc = { 0 };
        //    wc.lpfnWndProc = TaskManagerWndProc;
        //    wc.hInstance = GetModuleHandle(NULL);
        //    wc.lpszClassName = L"TaskManagerWinClass";
        //    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        //    RegisterClassW(&wc);

        //    HWND hTaskManagerWnd = CreateWindowW(wc.lpszClassName, L"Gestionnaire de Tâches Planifiées",
        //        WS_OVERLAPPEDWINDOW,
        //        CW_USEDEFAULT, CW_USEDEFAULT, 500, 400,
        //        hwnd, NULL, GetModuleHandle(NULL), NULL);

        //    ShowWindow(hTaskManagerWnd, SW_SHOW);
        //    UpdateWindow(hTaskManagerWnd);
        //}
        //break;

        case IDC_OPENFILE:
            BrowseForFile(hwnd);
            break;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    // Gestion ligne de commande (5 arguments : nom_tache, exe_path, jours, heures, minutes)
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc == 6)
    {
        std::wstring taskName = argv[1];
        std::wstring exePath = argv[2];
        int days = _wtoi(argv[3]);
        int hours = _wtoi(argv[4]);
        int minutes = _wtoi(argv[5]);

        // Supprimer tâche existante (ignore erreur si n'existe pas)
        std::wstringstream deleteCmd;
        deleteCmd << L"schtasks /Delete /TN \"" << taskName << L"\" /F";
        _wsystem(deleteCmd.str().c_str());

        std::wstring startTime = GetCurrentTimeHHMM();

        std::wstringstream createCmd;
        createCmd << L"schtasks /Create /TN \"" << taskName << L"\" "
            << L"/TR \"" << exePath << L"\" "
            << L"/SC MINUTE "
            << L"/MO " << minutes << L" "
            << L"/ST " << startTime;

        int ret = _wsystem(createCmd.str().c_str());

        if (ret == 0)
        {
            MessageBox(NULL, (L"La tâche '" + taskName + L"' s'exécutera toutes les " + std::to_wstring(minutes) + L" minutes.").c_str(), L"Succès", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBox(NULL, L"Erreur lors de la création de la tâche planifiée.", L"Erreur", MB_OK | MB_ICONERROR);
        }

        LocalFree(argv);
        return 0;
    }
    LocalFree(argv);

    // Sinon lancement interface graphique
    const wchar_t CLASS_NAME[] = L"TachePlanifieeWndClass";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"Créer une tâche planifiée",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 420, 330,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL)
        return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
//Scheduler.exe PixelBot "C:\Users\jason\OneDrive\Bureau\PixelBot_BayLife\x64\Release\PixelBot.exe" 0 0 5
