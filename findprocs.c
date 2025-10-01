#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <locale.h>
#include <sddl.h>
#include <accctrl.h>
#include <aclapi.h>
#include <lmcons.h>
#pragma comment(lib, "advapi32.lib")

// -------------------------------------------------------------
// Helpers wide / utilitários
// -------------------------------------------------------------

// trim espaços e CR/LF (wide)
static void trim_w(wchar_t* s)
{
    wchar_t* start = s;
    while (*start && iswspace(*start)) start++;
    if (start != s) wcscpy_s(s, wcslen(s) + 1, start);

    size_t len = wcslen(s);
    while (len > 0 && iswspace(s[len - 1])) { s[len - 1] = L'\0'; len--; }
}

// transforma em minúsculas (in-place)
static void tolower_w_inplace(wchar_t* s)
{
    for (; *s; ++s) *s = towlower(*s);
}

// remove ".exe" final se presente; retorna 1 se removeu, 0 caso contrário
static int remove_dot_exe_if_present_w(wchar_t* s)
{
    size_t len = wcslen(s);
    if (len >= 4) {
        if (_wcsicmp(s + len - 4, L".exe") == 0) {
            s[len - 4] = L'\0';
            return 1;
        }
    }
    return 0;
}

// normaliza um nome de processo para comparação:
// trim -> tolower -> remove .exe
static void normalize_proc_name_w(wchar_t* s, size_t bufsz)
{
    trim_w(s);
    // já segura: wcsncpy_s foi usado no chamador
    tolower_w_inplace(s);
    remove_dot_exe_if_present_w(s);
}

// obtém o caminho completo do executável (QueryFullProcessImageNameW)
// retorna 1 em sucesso (preenche buf), 0 caso contrário
static int get_process_image_path_w(DWORD pid, wchar_t* buf, size_t bufsz)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == NULL) return 0;
    DWORD size = (DWORD)bufsz;
    int ok = 0;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) ok = 1;
    CloseHandle(h);
    return ok;
}

// obtém o nome do usuário dono do processo (DOMAIN\user) quando possível
// retorna 1 em sucesso, 0 caso contrário. Preenche owner_buf (bufsz wide chars).
static int get_process_owner_w(DWORD pid, wchar_t* owner_buf, size_t bufsz)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return 0;
    }

    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return 0;
    }

    BYTE* buffer = (BYTE*)LocalAlloc(LPTR, sz);
    if (!buffer) {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return 0;
    }

    if (!GetTokenInformation(hToken, TokenUser, buffer, sz, &sz)) {
        LocalFree(buffer);
        CloseHandle(hToken);
        CloseHandle(hProc);
        return 0;
    }

    PTOKEN_USER ptu = (PTOKEN_USER)buffer;
    SID_NAME_USE sidType;
    wchar_t name[256], domain[256];
    DWORD nameLen = _countof(name), domainLen = _countof(domain);

    int result = 0;
    if (LookupAccountSidW(NULL, ptu->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
        // formatar DOMAIN\user quando domain não vazio
        if (domainLen > 0 && domain[0] != L'\0') {
            _snwprintf_s(owner_buf, bufsz, _TRUNCATE, L"%s\\%s", domain, name);
        }
        else {
            wcsncpy_s(owner_buf, bufsz, name, _TRUNCATE);
        }
        result = 1;
    }
    else {
        result = 0;
    }

    LocalFree(buffer);
    CloseHandle(hToken);
    CloseHandle(hProc);
    return result;
}

// -------------------------------------------------------------
// Função que verifica se um nome normalizado bate com a lista de targets
// targets: array de wchar_t*, ntargets: tamanho
// -------------------------------------------------------------
static int matches_any_target_w(const wchar_t* exe_norm, wchar_t** targets, int ntargets)
{
    for (int i = 0; i < ntargets; ++i) {
        if (wcscmp(exe_norm, targets[i]) == 0) return 1;
    }
    return 0;
}

// -------------------------------------------------------------
// main: aceita N parâmetros (cada um é um nome de processo)
// -------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    // define locale para imprimir corretamente acentos no console do Windows (opcional)
    setlocale(LC_ALL, "");

    if (argc < 2) {
        wprintf(L"Uso: %s <proc1> [proc2 ... procN]\n", argv[0]);
        wprintf(L"Exemplo: %s notepad chrome \"Brave.exe\"\n", argv[0]);
        return 2;
    }

    // lê e normaliza alvos
    int ntargets = argc - 1;
    wchar_t** targets = (wchar_t**)HeapAlloc(GetProcessHeap(), 0, sizeof(wchar_t*) * ntargets);
    if (!targets) {
        fwprintf(stderr, L"Erro: HeapAlloc targets\n");
        return 3;
    }

    for (int i = 0; i < ntargets; ++i) {
        targets[i] = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(wchar_t) * 512);
        if (!targets[i]) { fwprintf(stderr, L"Erro alocando target %d\n", i); return 3; }
        // copia e normaliza
        wcsncpy_s(targets[i], 512, argv[i + 1], _TRUNCATE);
        normalize_proc_name_w(targets[i], 512);
        wprintf(L"[TARGET %d] raw='%s' -> normalized='%s'\n", i + 1, argv[i + 1], targets[i]);
    }

    // cria snapshot wide
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Erro: CreateToolhelp32Snapshot falhou (GetLastError=%lu)\n", GetLastError());
        return 3;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        fwprintf(stderr, L"Erro: Process32FirstW falhou (GetLastError=%lu)\n", GetLastError());
        CloseHandle(snap);
        return 3;
    }

    // imprime cabeçalho "estilo tasklist"
    wprintf(L"\n%-28s %-7s %-7s %-8s %-10s %-50s %-20s\n",
        L"ImageName", L"PID", L"PPID", L"Threads", L"Priority", L"Path (if available)", L"Owner");
    wprintf(L"%s\n", L"----------------------------------------------------------------------------------------------------------------------------------");

    int found_count = 0;
    int idx = 0;

    do {
        idx++;

        // nome original e sua cópia normalizada
        wchar_t exe_name[512];
        wcsncpy_s(exe_name, 512, pe.szExeFile, _TRUNCATE);

        wchar_t exe_norm[512];
        wcsncpy_s(exe_norm, 512, pe.szExeFile, _TRUNCATE);
        normalize_proc_name_w(exe_norm, 512);

        // se não bater com nenhum target, ignora
        if (!matches_any_target_w(exe_norm, targets, ntargets)) {
            continue;
        }

        // se bateu, recupera dados adicionais
        wchar_t pathbuf[MAX_PATH] = L"(unavailable)";
        if (!get_process_image_path_w(pe.th32ProcessID, pathbuf, MAX_PATH)) {
            // pode falhar sem privilégios, mantemos (unavailable)
            wcsncpy_s(pathbuf, MAX_PATH, L"(no-perm-or-protected)", _TRUNCATE);
        }

        wchar_t ownerbuf[512] = L"(unknown)";
        if (!get_process_owner_w(pe.th32ProcessID, ownerbuf, _countof(ownerbuf))) {
            wcsncpy_s(ownerbuf, _countof(ownerbuf), L"(no-perm)", _TRUNCATE);
        }

        // imprime linha formatada
        wprintf(L"%-28s %-7lu %-7lu %-8lu %-10ld %-40s %-20s\n",
            exe_name,
            (unsigned long)pe.th32ProcessID,
            (unsigned long)pe.th32ParentProcessID,
            (unsigned long)pe.cntThreads,
            (long)pe.pcPriClassBase,
            pathbuf,
            ownerbuf);

        found_count++;

    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);

    // libera memória dos targets
    for (int i = 0; i < ntargets; ++i) HeapFree(GetProcessHeap(), 0, targets[i]);
    HeapFree(GetProcessHeap(), 0, targets);

    if (found_count == 0) {
        wprintf(L"\nNenhum processo encontrado para os alvos fornecidos.\n");
        return 1;
    }
    else {
        wprintf(L"\nTotal encontrados: %d\n", found_count);
        return 0;
    }
}
