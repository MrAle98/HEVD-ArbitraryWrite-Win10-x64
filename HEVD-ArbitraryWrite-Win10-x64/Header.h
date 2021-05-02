#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemCpuInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3, /* was SystemTimeInformation */
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11
};

typedef struct _WRITE_WHAT_WHERE
{
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

typedef struct SYSTEM_MODULE {
	PVOID  Reserved1;
	PVOID  Reserved2;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR   ImageName[256];
} _SYSTEM_MODULE, * _PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[0];
} _SYSTEM_MODULE_INFORMATION, * _PSYSTEM_MODULE_INFORMATION;


typedef NTSTATUS(NTAPI* PtrNtQuerySystemInformation)(
	_SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);


typedef NTSTATUS(NTAPI* PtrNtQueryIntervalProfile)(
	DWORD      ProfileSource,
	PULONG              Interval);
