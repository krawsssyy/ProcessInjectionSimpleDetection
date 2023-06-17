#include "framework.h"
#include "cod.h"
#include <string>
#define _REGEX_MAX_STACK_COUNT 0
#include <regex>
#include <fstream>


#define MAX_LOADSTRING 100
typedef void( WINAPIV* MYPROC)(HWND, PWSTR);

HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
TCHAR styles[6][25] =
{
    L"Self injection", L"Classic", L"Thread Hijacking", L"MapView injection", L"QueueUserAPC injection", L"All"
};                                              // procinj styles
PWSTR pszFilePath = (PWSTR)"";                              // variable that'll hold the file path
HRESULT hr;                                     // used in open file dialog
TCHAR  ListItem[256] = L"All";                           // combo box current item


ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
void OpenFileViaDialog(HWND);
void HandleBtnClick(HWND);
BOOL handleSelf(std::string);
BOOL handleClassic(std::string);
BOOL handleHijack(std::string);
BOOL handleMapView(std::string);
BOOL handleAPC(std::string);
std::string parseAndCleanFile();

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_COD, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_COD));

    MSG msg;

    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_COD));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_COD);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance;

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, CW_USEDEFAULT, 400, 270, nullptr, nullptr, hInstance, nullptr);
   HWND hWndComboBox = CreateWindow(WC_COMBOBOX, L"Procinj technique",
       CBS_DROPDOWN | CBS_HASSTRINGS | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE,
       120, 40, 200, 200, hWnd, nullptr, hInstance, nullptr);
   HWND hWndButton = CreateWindow(WC_BUTTON, L"Run tests for procinj",
       WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
       10, 70, 150, 20, hWnd, (HMENU) ID_BTNHI, hInstance, nullptr);

   if (!hWnd)
   {
       return FALSE;
   }

   TCHAR A[25];
   memset(&A, 0, sizeof(A));
   for (int k = 0; k < 6; k ++)
   {
       wcscpy_s(A, sizeof(A) / sizeof(TCHAR), (TCHAR*)styles[k]);
       SendMessage(hWndComboBox, (UINT)CB_ADDSTRING, (WPARAM)0, (LPARAM)A);
   }

   SendMessage(hWndComboBox, CB_SETCURSEL, (WPARAM)5, (LPARAM)0);

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                int ItemIndex = SendMessage((HWND)lParam, (UINT)CB_GETCURSEL,
                    (WPARAM)0, (LPARAM)0);
                (TCHAR)SendMessage((HWND)lParam, (UINT)CB_GETLBTEXT,
                    (WPARAM)ItemIndex, (LPARAM)ListItem);
            }
            switch (wmId)
            {
            case IDM_OPENFILE:
                OpenFileViaDialog(hWnd);
                break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            case ID_BTNHI:
                HandleBtnClick(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            TextOut(hdc, 5, 43, L"Choose the style:", 18);
            TextOut(hdc, 25, 100, L"Output:(files will be written to Desktop)", 42);
            TextOut(hdc, 15, 120, L"memapis.log contains a log of the memory APIs used", 51);
            TextOut(hdc, 15, 140, L"wpmX.dmp(if exists) contains the dumped buffer", 47);
            TextOut(hdc, 5, 160, L"used by WriteProcessMemory", 27);
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        CoTaskMemFree(pszFilePath);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

void OpenFileViaDialog(HWND hWnd) {
    IFileOpenDialog* pFileOpen;
    hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL,
        IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
    if (SUCCEEDED(hr))
    {
        hr = pFileOpen->Show(NULL);
        if (SUCCEEDED(hr))
        {
            IShellItem* pItem;
            hr = pFileOpen->GetResult(&pItem);
            if (SUCCEEDED(hr))
            {
                hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                if (SUCCEEDED(hr))
                {
                    HDC hdc = GetDC(hWnd);
                    TextOut(hdc, 5, 10, L"File loaded!", 12);
                    ReleaseDC(hWnd, hdc);
                }
                pItem->Release();
            }
        }
        pFileOpen->Release();
    }
    CoUninitialize();
}

void inject_DLL(TCHAR* dllPath, HANDLE process)
{
    LPVOID lpBaseAddress;
    HANDLE hRemoteThread;
    HMODULE kernel32;
    FARPROC loadlibrary;
    SIZE_T pathLen;
    lpBaseAddress = NULL;
    hRemoteThread = NULL;
    loadlibrary = NULL;
    kernel32 = NULL;
    pathLen = _tcslen(dllPath) * sizeof(TCHAR);
    kernel32 = GetModuleHandle(_T("kernel32.dll"));
    loadlibrary = (FARPROC)GetProcAddress(kernel32, "LoadLibraryA");
    lpBaseAddress = VirtualAllocEx(process, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpBaseAddress == NULL) {
        MessageBox(HWND_DESKTOP, L"VirtualAllocEx() failed for dll injection.", L"Error", MB_ICONERROR | MB_OK);
        return;
    }
    if (!WriteProcessMemory(process, lpBaseAddress, dllPath, pathLen, NULL)) {
        MessageBox(HWND_DESKTOP, L"WriteProcessMemory() failed for dll injection.", L"Error", MB_ICONERROR | MB_OK);
        return;
    }
    hRemoteThread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)(VOID*)loadlibrary, lpBaseAddress, NULL, 0);
    if (hRemoteThread == NULL) {
        MessageBox(HWND_DESKTOP, L"CreateRemoteThread() failed for dll injection.", L"Error", MB_ICONERROR | MB_OK);
        return;
    }
    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
}

void HandleBtnClick(HWND hWnd) {
    if (pszFilePath == (PWSTR)"") {
        MessageBox(hWnd, L"An error occured loading the file or it hasn't been loaded.", L"Error", MB_ICONERROR | MB_OK);
        return;
    }
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcess(pszFilePath, (LPWSTR)"", nullptr, nullptr, false, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        MessageBox(hWnd, L"CreateProcess() failed for the given file", L"Error", MB_ICONERROR | MB_OK);
        return;
    }
    inject_DLL((TCHAR*)("logic.dll"), pi.hProcess);
    ResumeThread(pi.hThread);
    if (WaitForSingleObject(pi.hProcess, 120000) == WAIT_TIMEOUT) {
        DWORD lpExitCode;
        GetExitCodeProcess(pi.hProcess, &lpExitCode);
        ExitProcess(lpExitCode);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::string res = parseAndCleanFile();
    if (_tcscmp(ListItem, L"Self injection") == 0) {
        if (handleSelf(res))
            MessageBox(hWnd, L"Found possible self injection!", L"Alert", MB_OK);
        else
            MessageBox(hWnd, L"Didn't find signs of self injection!Needs further analysis.", L"Alert", MB_ICONERROR | MB_OK);
    }
    if (_tcscmp(ListItem, L"Classic") == 0) {
        if (handleClassic(res))
            MessageBox(hWnd, L"Found possible classic injection!", L"Alert", MB_OK);
        else
            MessageBox(hWnd, L"Didn't find signs of classic injection!Needs further analysis.", L"Alert", MB_ICONERROR | MB_OK);
    }
    if (_tcscmp(ListItem, L"Thread Hijacking") == 0) {
        if (handleHijack(res))
            MessageBox(hWnd, L"Found possible thread hijacking!", L"Alert", MB_OK);
        else
            MessageBox(hWnd, L"Didn't find signs of thread hijacking!Needs further analysis.", L"Alert", MB_ICONERROR | MB_OK);
    }
    if (_tcscmp(ListItem, L"MapView injection") == 0) {
        if (handleMapView(res))
            MessageBox(hWnd, L"Found possible MapView injection!!", L"Alert", MB_OK);
        else
            MessageBox(hWnd, L"Didn't find signs of MapView injection!Needs further analysis.", L"Alert", MB_ICONERROR | MB_OK);
    }
    if (_tcscmp(ListItem, L"QueueUserAPC injection") == 0) {
        if (handleAPC(res))
            MessageBox(hWnd, L"Found possible QueueUserAPC injection!", L"Alert", MB_OK);
        else
            MessageBox(hWnd, L"Didn't find signs of QueueUserAPC injection!Needs further analysis.", L"Alert", MB_ICONERROR | MB_OK);
    }
    if (_tcscmp(ListItem, L"All") == 0) {
        if (handleAPC(res))
            MessageBox(hWnd, L"Found possible QueueUserAPC injection!", L"Alert", MB_OK);
        else if (handleHijack(res))
            MessageBox(hWnd, L"Found possible thread hijacking!", L"Alert", MB_OK);
        else if (handleClassic(res))
            MessageBox(hWnd, L"Found possible classic injection!", L"Alert", MB_OK);
        else if (handleSelf(res))
            MessageBox(hWnd, L"Found possible self injection!", L"Alert", MB_OK);
        else if (handleMapView(res))
            MessageBox(hWnd, L"Found possible MapView injection!", L"Alert", MB_OK);
        else
            MessageBox(hWnd, L"No injection found!Needs further analysis.", L"Alert", MB_ICONERROR | MB_OK);
    }
}

BOOL handleSelf(std::string file) {
    std::regex self("VirtualAlloc.*\n(.*\n){0,5}WriteProcessMemory.*\n(.*\n){0,10}CreateThread.*\n", std::regex::extended);
    std::smatch m;
    return std::regex_search(file, m, self);
}

BOOL handleClassic(std::string file) {
    std::regex classic("(CreateProcessW|CreateProcessA|OpenProcess).*\n(.*\n){0,50}(VirtualAlloc2|VirtualAllocEx).*\n(.*\n){0,10}WriteProcessMemory.*\n(.*\n){0,10}(NtCreateThreadEx|RtlCreateUserProcess|CreateRemoteThread|CreateRemoteThreadEx).*\n", std::regex::extended);
    std::smatch m;
    return std::regex_search(file, m, classic);
}

BOOL handleHijack(std::string file) {
    std::regex hijack("OpenProcess.*\n(.*\n){0,100}(CreateRemoteThread|CreateRemoteThreadEx|NtCreateThreadEx|RtlCreateUserThread|SupendThread).*\n(.*\n){0,30}(VirtualAlloc2|VirtualAllocEx|GetThreadContext).*\n(.*\n){0,10}(WriteProcessMemory|GetThreadContext|VirtualAlloc2|VirtualAllocEx).*\n(.*\n){0,10}(GetThreadContext|WriteProcessMemory).*\n(.*\n){0,10}SetThreadContext.*\n(.*\n){0,10}ResumeThread.*\n", std::regex::extended);
    std::smatch m;
    BOOL res = std::regex_search(file, m, hijack);
    return res;
}

BOOL handleMapView(std::string file) {
    std::regex mapView("NtCreateSection.*\nNtMapViewOfSection.*\n(.*\n){0,50}(NtCreateThreadEx | RtlCreateUserThread | CreateRemoteThread | CreateRemoteThreadEx).*\n", std::regex::extended);
    std::smatch m;
    return std::regex_search(file, m, mapView);
}

BOOL handleAPC(std::string file) {
    std::regex apc("(OpenProcess|CreateProcessA|CreateProcessW).*\n(.*\n){0,100}(VirtualAlloc2|VirtualAllocEx).*\n(.*\n){0,20}WriteProcessMemory.*\n(.*\n){0,10}(QueueUserAPC|NtQueueApcThread).*\n", std::regex::extended);
    std::smatch m;
    return std::regex_search(file, m, apc);
}

std::string parseAndCleanFile() {
    WCHAR* buffer = new WCHAR[200];
    const WCHAR name[12] = L"USERPROFILE";
    DWORD result = GetEnvironmentVariable(name, buffer, 200);
    if (result > 200) {
        delete[] buffer; buffer = new WCHAR[result];
        GetEnvironmentVariable(name, buffer, result);
    }
    std::wstring s(L"");
    s += buffer;
    s += L"\\Desktop\\memapis.log";
    delete[] buffer;
    buffer = nullptr;
    std::ifstream in(s);
    std::string prevLine = "";
    std::string line;
    std::string res;
    while (!in.eof()) {
        getline(in, line);
        if (line != prevLine)
            res += (line + "\n");
        prevLine = line;
    }
    in.close();
    return res;
}