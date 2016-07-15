#include "ntddk.h"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

------------------------------------------
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()


#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

//global
ULONG	g_ntcreatefile;
ULONG	g_fastcall_hookpointer;
ULONG	g_goto_origfunc;

typedef NTSTATUS 
(*NTCREATEFILE) (
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength) PVOID EaBuffer,
    __in ULONG EaLength
    );

void PageProtectOn()
{
	__asm{//恢复内存保护  
		mov  eax,cr0
		or   eax,10000h
		mov  cr0,eax
		sti
	}
}

void PageProtectOff()
{
	__asm{//去掉内存保护
		cli
		mov  eax,cr0
		and  eax,not 10000h
		mov  cr0,eax
	}
}

ULONG SearchHookPointer(ULONG StartAddress)
{
	ULONG	u_index;

	UCHAR	*p = (UCHAR*)StartAddress;

	for (u_index = 0;u_index < 200;u_index++)
	{
		if (*p==0x2B&&
			*(p+1)==0xE1&&
			*(p+2)==0xC1&&
			*(p+3)==0xE9&&
			*(p+4)==0x02)
		{
			return (ULONG)p;
		}

		p--;
	}

	return 0;
}

void FilterKiFastCallEntry(ULONG ServiceTableBase,ULONG FuncIndex)
{
	if (ServiceTableBase==(ULONG)KeServiceDescriptorTable.ServiceTableBase)
	{
		if (FuncIndex==190)
		{
			KdPrint(("%s",(char*)PsGetCurrentProcess()+0x16c));
		}
	}
}

__declspec(naked)
void NewKiFastCallEntry()
{
	__asm{
		pushad
		pushfd
		
		push	eax
		push	edi
		call	FilterKiFastCallEntry

		popfd
		popad

		sub     esp,ecx
		shr     ecx,2
		jmp		g_goto_origfunc
	}
}

void UnHookKiFastCallEntry()
{
	UCHAR	str_origfuncode[5] = {0x2B,0xE1,0xC1,0xE9,0x02};

	if (g_fastcall_hookpointer==0)
	{	return;	}

	PageProtectOff();
	RtlCopyMemory((PVOID)g_fastcall_hookpointer,str_origfuncode,5);
	PageProtectOn();
}

void HookKiFastCallEntry(ULONG HookPointer)
{
	ULONG	u_temp;
	UCHAR	str_jmp_code[5];

	str_jmp_code[0] = 0xE9;

	u_temp = (ULONG)NewKiFastCallEntry - HookPointer - 5;
	*(ULONG*)&str_jmp_code[1] = u_temp;

	PageProtectOff();

	RtlCopyMemory((PVOID)HookPointer,str_jmp_code,5);

	PageProtectOn();

}

NTSTATUS NewNtCreateFile (
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength) PVOID EaBuffer,
    __in ULONG EaLength
    )
{
	ULONG	u_call_retaddr;

	__asm{
		pushad
		mov		eax,[ebp+0x4]
		mov		u_call_retaddr,eax
		popad
	}

	g_fastcall_hookpointer = SearchHookPointer(u_call_retaddr);
	if (g_fastcall_hookpointer==0)
	{
		KdPrint(("search failed."));
	}else{
		KdPrint(("search success."));
	}

	g_goto_origfunc = g_fastcall_hookpointer + 5;
	HookKiFastCallEntry(g_fastcall_hookpointer);

	PageProtectOff();
	KeServiceDescriptorTable.ServiceTableBase[66] = (unsigned int)g_ntcreatefile;
	PageProtectOn();

	return ((NTCREATEFILE)g_ntcreatefile)(
		FileHandle,\
		DesiredAccess,\
		ObjectAttributes,\
		IoStatusBlock,\
		AllocationSize,\
		FileAttributes,\
		ShareAccess,\
		CreateDisposition,\
		CreateOptions,\
		EaBuffer,\
		EaLength);
}


void SearchKiFastCallEntry()
{

	g_ntcreatefile = KeServiceDescriptorTable.ServiceTableBase[66];
	PageProtectOff();
	KeServiceDescriptorTable.ServiceTableBase[66] = (unsigned int)NewNtCreateFile;
	PageProtectOn();
}

VOID MyUnload(PDRIVER_OBJECT pDriverObject)
{
	UnHookKiFastCallEntry();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT	pDriverObject,PUNICODE_STRING Reg_Path)
{
	SearchKiFastCallEntry();
	pDriverObject->DriverUnload = MyUnload;
	return STATUS_SUCCESS;
}