#include "GetData.h"
#include <Windows.h>
#include <WinNT.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>

const char *TableName[]={	"Export Table",
							"Import Table",
							"Resources Table",
							"Exception Table",
							"Security Table",
							"Base relocation Table",
							"Debug",
							"Copyright",
							"Global Ptr",
							"TLS",
							"LOAD_CONFIG",
							"BOUND_IMPORT",
							"IAT",
							"Delay Import",
							"COM descriptor",
							"����"};	//���������

const char *WeekDay[]={	"������",
						"����һ",
						"���ڶ�",
						"������",
						"������",
						"������",
						"������"};	//���TimeDateStamp������

//N:��Ա�� P:ָ��
#define PRINT_DOS(N) PRINT_MEMBER(1,LENGTH,#N,dos_header.##N)	//��ӡdos_header���޻س�
#define PRINT_DOS_WITHLINE(N) PRINT_MEMBER_WITHLINE(1,LENGTH,#N,dos_header.##N)	//��ӡdos_header���лس�����ͬ
#define PRINT_DOSP_WITHLINE(P) PRINT_MEMBER_POINTER_WITHLINE(1,LENGTH,#P,dos_header.##P)
#define PRINT_FILE_WITHLINE(N) PRINT_MEMBER_WITHLINE(2,LENGTH,#N,nt_headers.FileHeader.##N)
#define PRINT_FILE(N) PRINT_MEMBER(2,LENGTH,#N,nt_headers.FileHeader.##N)
#define PRINT_OPTIONAL(N) PRINT_MEMBER(2,LENGTH,#N,nt_headers.OptionalHeader.##N)
#define PRINT_OPTIONAL_WITHLINE(N) PRINT_MEMBER_WITHLINE(2,LENGTH,#N,nt_headers.OptionalHeader.##N)
#define PRINT_IMPORT_WITHLINE(i,N) PRINT_MEMBER_WITHLINE(1,LENGTH,#N,pimport_descriptor[i].##N)
#define PRINT_EXPORT_WITHLINE(N) PRINT_MEMBER_WITHLINE(1,LENGTH,#N,export_directory.##N)
#define PRINT_EXPORT(N) PRINT_MEMBER(1,LENGTH,#N,export_directory.##N)
#define PRINT_BASERELOC_WITHLINE(N) PRINT_MEMBER_WITHLINE(1,LENGTH,#N,base_reloc.##N)
//����Ƿ����ĳһCharicteristic���������ӡ
//N:����
#define TEST_FILE(N) {if (nt_headers.FileHeader.Characteristics == (nt_headers.FileHeader.Characteristics | IMAGE_FILE_##N))\
	PRINT_NOMEMBER(2,LENGTH),printf("(%s)\n",#N);}	//����ļ�����
#define TEST_SECTION(i,N) if (psection_header[i].Characteristics == (psection_header[i].Characteristics | IMAGE_SCN_##N))\
	printf("(%s)",#N)	//�����������
#define TEST_MACHINE(N) case IMAGE_FILE_MACHINE_##N: {printf(" (%s)\n",#N);break;}	//����ļ�����
#define TEST_SUBSYSTEM(N) case IMAGE_SUBSYSTEM_##N: {printf(" (%s)\n",#N);break;}	//�����ϵͳ

#define SEC_NO nt_headers.FileHeader.NumberOfSections	//ȫ����Ч���������
#define IMPORT_SIZE nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size		//��������һ���������ռ���ֽ���
#define EXPORT_SIZE nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size		//������С
#define BASERELOC_SIZE nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size	//�ض�λ���С
#define IMPORT_OFF nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress		//�������ʼRVA
#define EXPORT_OFF nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress		//�������ʼRVA
#define BASERELOC_OFF nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress	//�ض�λ����ʼRVA
#define RESOURCE_OFF nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress		//��Դ�����ʼRVA

IMAGE_DOS_HEADER dos_header;
IMAGE_NT_HEADERS nt_headers;
PIMAGE_SECTION_HEADER psection_header = NULL;
PIMAGE_IMPORT_DESCRIPTOR pimport_descriptor = NULL;
IMAGE_EXPORT_DIRECTORY export_directory;
IMAGE_BASE_RELOCATION base_reloc;
extern FILE *fp;	
char strName[256];	//��¼����
time_t ltime;	//���TimeDateStamp��
struct tm *newtime;		//���TimeDateStamp��

bool GetImage()		//��ȡIMAGE Structs
{
	fread(&dos_header,sizeof(IMAGE_DOS_HEADER),1,fp);		//��ȡDOSͷ��
	fseek(fp,dos_header.e_lfanew,SEEK_SET);		//�����ļ�ָ�뵽PEͷ�Ա��ȡ
	fread(&nt_headers,sizeof(IMAGE_NT_HEADERS),1,fp);		//��ȡPEͷ

	if (nt_headers.Signature != IMAGE_NT_SIGNATURE)	//������Ч��PEͷ
		return false;

	psection_header = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER)*SEC_NO);	//Ϊ�������ռ�
	fread(psection_header,sizeof(IMAGE_SECTION_HEADER),SEC_NO,fp);	//��ȡ�����

	if (IMPORT_SIZE)		//��ȡ�����
	{
		pimport_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)malloc(IMPORT_SIZE-sizeof(IMAGE_IMPORT_DESCRIPTOR));	//����һ��
		fseek(fp,RVAToRA(IMPORT_OFF),SEEK_SET);		//�����ļ�ָ�뵽�ʵ�λ��
		fread(pimport_descriptor,sizeof(IMAGE_IMPORT_DESCRIPTOR),IMPORT_SIZE/sizeof(IMAGE_IMPORT_DESCRIPTOR)-1,fp);	//��ȡ����������������
	}
	if (EXPORT_SIZE)	//��ȡ�����
	{
		fseek(fp,RVAToRA(EXPORT_OFF),SEEK_SET);	//�����ļ�ָ��
		fread(&export_directory,sizeof(IMAGE_EXPORT_DIRECTORY),1,fp);	//��ȡ�����
	}
	if (nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)	//��ȡ�ض�λ��
	{
		fseek(fp,RVAToRA(BASERELOC_OFF),SEEK_SET);	//�����ļ�ָ��
		fread(&base_reloc,sizeof(IMAGE_BASE_RELOCATION),1,fp);	//��ȡ�ض�λ��
	}
	return true;
}

void ShowStructs()  	//��ʾ�ṹ������
{
	if (!fp)	//��δ��ȡ
		return;

	puts("->Dos_Header:");
	PRINT_DOS(e_magic);
	printf(" (%c%c)\n",(char)(dos_header.e_magic>>8),(char)(dos_header.e_magic));	//��λ��ǰ����λ�ں�
	PRINT_DOS_WITHLINE(e_cblp);                      
	PRINT_DOS_WITHLINE(e_cp);
	PRINT_DOS_WITHLINE(e_crlc);
	PRINT_DOS_WITHLINE(e_cparhdr);
	PRINT_DOS_WITHLINE(e_minalloc);
	PRINT_DOS_WITHLINE(e_maxalloc);
	PRINT_DOS_WITHLINE(e_ss);
	PRINT_DOS_WITHLINE(e_sp);
	PRINT_DOS_WITHLINE(e_csum);
	PRINT_DOS_WITHLINE(e_ip);
	PRINT_DOS_WITHLINE(e_cs);
	PRINT_DOS_WITHLINE(e_lfarlc);
	PRINT_DOS_WITHLINE(e_ovno);
	PRINT_DOSP_WITHLINE(e_res);
	PRINT_DOS_WITHLINE(e_oemid);
	PRINT_DOS_WITHLINE(e_oeminfo);
	PRINT_DOSP_WITHLINE(e_res2);
	PRINT_DOS_WITHLINE(e_lfanew);

	puts("->NT_Headers:");
	PRINT_MEMBER(1,LENGTH,"Signature",nt_headers.Signature);
	printf(" (%c%c%c%c)\n",(char)(nt_headers.Signature>>24),(char)(nt_headers.Signature>>16),
		(char)(nt_headers.Signature>>8),(char)nt_headers.Signature);	//��λ��ǰ����λ�ں�

	puts("  ->File_Header:");
	PRINT_FILE(Machine);
	switch (nt_headers.FileHeader.Machine)
	{
		TEST_MACHINE(UNKNOWN)
		TEST_MACHINE(I386)
		TEST_MACHINE(R3000)         
		TEST_MACHINE(R4000)          
		TEST_MACHINE(R10000)        
		TEST_MACHINE(WCEMIPSV2)     
		TEST_MACHINE(ALPHA)
		TEST_MACHINE(SH3) 
		TEST_MACHINE(SH3DSP)
		TEST_MACHINE(SH3E)         
		TEST_MACHINE(SH4)    
		TEST_MACHINE(SH5)     
		TEST_MACHINE(ARM)  
		TEST_MACHINE(THUMB)   
		TEST_MACHINE(AM33)      
		TEST_MACHINE(POWERPC)   
		TEST_MACHINE(POWERPCFP)  
		TEST_MACHINE(IA64)    
		TEST_MACHINE(MIPS16)        
		TEST_MACHINE(ALPHA64)    
		TEST_MACHINE(MIPSFPU)    
		TEST_MACHINE(MIPSFPU16) 
		TEST_MACHINE(TRICORE)      
		TEST_MACHINE(CEF)        
		TEST_MACHINE(EBC)       
		TEST_MACHINE(AMD64)         
		TEST_MACHINE(M32R)          
		TEST_MACHINE(CEE)
	}

	PRINT_FILE_WITHLINE(NumberOfSections);
	//�������TimeDateStamp
	PRINT_FILE(TimeDateStamp);
	ltime=nt_headers.FileHeader.TimeDateStamp;
	newtime=gmtime(&ltime);
	printf("  %d.%d.%d %d:%d:%d %s\n",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,
		newtime->tm_hour,newtime->tm_min,newtime->tm_sec,WeekDay[newtime->tm_wday]);

	PRINT_FILE_WITHLINE(PointerToSymbolTable);
	PRINT_FILE_WITHLINE(NumberOfSymbols);
	PRINT_FILE_WITHLINE(SizeOfOptionalHeader);
	PRINT_FILE_WITHLINE(Characteristics);
	//����ļ�����
	TEST_FILE(RELOCS_STRIPPED);
	TEST_FILE(EXECUTABLE_IMAGE);
	TEST_FILE(LINE_NUMS_STRIPPED);
	TEST_FILE(LOCAL_SYMS_STRIPPED);
	TEST_FILE(AGGRESIVE_WS_TRIM);
	TEST_FILE(LARGE_ADDRESS_AWARE);
	TEST_FILE(BYTES_REVERSED_LO);
	TEST_FILE(32BIT_MACHINE);
	TEST_FILE(DEBUG_STRIPPED);
	TEST_FILE(REMOVABLE_RUN_FROM_SWAP);
	TEST_FILE(NET_RUN_FROM_SWAP);
	TEST_FILE(SYSTEM);
	TEST_FILE(DLL);
	TEST_FILE(UP_SYSTEM_ONLY);
	TEST_FILE(BYTES_REVERSED_HI);

	puts("  ->Optional_Header:");
	PRINT_OPTIONAL_WITHLINE(Magic);
	PRINT_OPTIONAL_WITHLINE(MajorLinkerVersion);
	PRINT_OPTIONAL_WITHLINE(MinorLinkerVersion);
	PRINT_OPTIONAL_WITHLINE(SizeOfCode);
	PRINT_OPTIONAL_WITHLINE(SizeOfInitializedData);
	PRINT_OPTIONAL_WITHLINE(SizeOfUninitializedData);
	PRINT_OPTIONAL_WITHLINE(AddressOfEntryPoint);
	PRINT_OPTIONAL_WITHLINE(BaseOfCode);
	PRINT_OPTIONAL_WITHLINE(BaseOfData);
	PRINT_OPTIONAL_WITHLINE(ImageBase);	
	PRINT_OPTIONAL_WITHLINE(SectionAlignment);
	PRINT_OPTIONAL_WITHLINE(FileAlignment);
	PRINT_OPTIONAL_WITHLINE(MajorOperatingSystemVersion);
	PRINT_OPTIONAL_WITHLINE(MinorOperatingSystemVersion);
	PRINT_OPTIONAL_WITHLINE(MajorImageVersion);
	PRINT_OPTIONAL_WITHLINE(MinorImageVersion);
	PRINT_OPTIONAL_WITHLINE(MajorSubsystemVersion);
	PRINT_OPTIONAL_WITHLINE(MinorSubsystemVersion);
	PRINT_OPTIONAL_WITHLINE(Win32VersionValue);
	PRINT_OPTIONAL_WITHLINE(SizeOfImage);
	PRINT_OPTIONAL_WITHLINE(SizeOfHeaders);
	PRINT_OPTIONAL_WITHLINE(CheckSum);
	//��ϵͳ
	PRINT_OPTIONAL(Subsystem);
	switch (nt_headers.OptionalHeader.Subsystem)
	{
		TEST_SUBSYSTEM(UNKNOWN)
		TEST_SUBSYSTEM(NATIVE)
		TEST_SUBSYSTEM(WINDOWS_GUI)
		TEST_SUBSYSTEM(WINDOWS_CUI)
		TEST_SUBSYSTEM(OS2_CUI)
		TEST_SUBSYSTEM(POSIX_CUI)
		TEST_SUBSYSTEM(NATIVE_WINDOWS)
		TEST_SUBSYSTEM(WINDOWS_CE_GUI)
		TEST_SUBSYSTEM(EFI_APPLICATION)
		TEST_SUBSYSTEM(EFI_BOOT_SERVICE_DRIVER)
		TEST_SUBSYSTEM(EFI_RUNTIME_DRIVER)
		TEST_SUBSYSTEM(EFI_ROM)
		TEST_SUBSYSTEM(XBOX)
		TEST_SUBSYSTEM(WINDOWS_BOOT_APPLICATION)
	}

	PRINT_OPTIONAL_WITHLINE(DllCharacteristics);
	PRINT_OPTIONAL_WITHLINE(SizeOfStackReserve);
	PRINT_OPTIONAL_WITHLINE(SizeOfStackCommit);
	PRINT_OPTIONAL_WITHLINE(SizeOfHeapReserve);
	PRINT_OPTIONAL_WITHLINE(SizeOfHeapCommit);
	PRINT_OPTIONAL_WITHLINE(LoaderFlags);
	PRINT_OPTIONAL_WITHLINE(NumberOfRvaAndSizes);
	//����Ŀ¼��
	SHOWLINE;
	printf("%-*s%-*s%-*s\n",DIRECTORY_WIDTH,"Date Directory:",DIRECTORY_WIDTH,"RVA",DIRECTORY_WIDTH,"Size");
	for (int i=0;i<IMAGE_NUMBEROF_DIRECTORY_ENTRIES;i++)
		printf("%-*s%-0*.*X%-0*.*X\n",DIRECTORY_WIDTH,TableName[i],DIRECTORY_WIDTH,sizeof(nt_headers.OptionalHeader.DataDirectory->VirtualAddress)*2,
		nt_headers.OptionalHeader.DataDirectory[i].VirtualAddress,
		DIRECTORY_WIDTH,sizeof(nt_headers.OptionalHeader.DataDirectory->VirtualAddress)*2,
		nt_headers.OptionalHeader.DataDirectory[i].Size);
	SHOWLINE;
	//�����
	puts("\n�������Ϣ��");
	printf("%-*s%-*s%-*s%-*s%-*s\n",SECTION_WIDTH,"Name",SECTION_WIDTH,"VOffset",SECTION_WIDTH,"VSize",
		SECTION_WIDTH,"ROffset",SECTION_WIDTH,"RSize");
	for (int i=0;i<nt_headers.FileHeader.NumberOfSections;i++)
	{
		IMAGE_SECTION_HEADER &s=psection_header[i];
		printf("%-*s%-*.*X%-*.*X%-*.*X%-*.*X\n",SECTION_WIDTH,s.Name,
			SECTION_WIDTH,sizeof(s.VirtualAddress)*2,s.VirtualAddress,
			SECTION_WIDTH,sizeof(s.Misc.VirtualSize)*2,s.Misc.VirtualSize,
			SECTION_WIDTH,sizeof(s.PointerToRawData)*2,s.PointerToRawData,
			SECTION_WIDTH,sizeof(s.SizeOfRawData)*2,s.SizeOfRawData);
		printf("%*c",SECTION_WIDTH,' ');
		TEST_SECTION(i,TYPE_NO_PAD);
		TEST_SECTION(i,CNT_CODE);
		TEST_SECTION(i,CNT_INITIALIZED_DATA);
		TEST_SECTION(i,CNT_UNINITIALIZED_DATA);
		TEST_SECTION(i,LNK_OTHER);
		TEST_SECTION(i,LNK_INFO);
		TEST_SECTION(i,LNK_REMOVE);
		TEST_SECTION(i,LNK_COMDAT);
		TEST_SECTION(i,NO_DEFER_SPEC_EXC);
		TEST_SECTION(i,GPREL);
		TEST_SECTION(i,MEM_FARDATA);    
		TEST_SECTION(i,MEM_PURGEABLE);  
		TEST_SECTION(i,MEM_16BIT);      
		TEST_SECTION(i,MEM_LOCKED);     
		TEST_SECTION(i,MEM_PRELOAD);     
		TEST_SECTION(i,ALIGN_1BYTES);   
		TEST_SECTION(i,ALIGN_2BYTES);  
		TEST_SECTION(i,ALIGN_4BYTES);   
		TEST_SECTION(i,ALIGN_8BYTES);   
		TEST_SECTION(i,ALIGN_16BYTES);  
		TEST_SECTION(i,ALIGN_32BYTES);  
		TEST_SECTION(i,ALIGN_64BYTES); 
		TEST_SECTION(i,ALIGN_128BYTES);  
		TEST_SECTION(i,ALIGN_256BYTES);   
		TEST_SECTION(i,ALIGN_512BYTES);  
		TEST_SECTION(i,ALIGN_1024BYTES);  
		TEST_SECTION(i,ALIGN_2048BYTES);  
		TEST_SECTION(i,ALIGN_4096BYTES);  
		TEST_SECTION(i,ALIGN_8192BYTES);  
		TEST_SECTION(i,ALIGN_MASK);     
		TEST_SECTION(i,LNK_NRELOC_OVFL);  
		TEST_SECTION(i,MEM_DISCARDABLE);  
		TEST_SECTION(i,MEM_NOT_CACHED);   
		TEST_SECTION(i,MEM_NOT_PAGED);    
		TEST_SECTION(i,MEM_SHARED);      
		TEST_SECTION(i,MEM_EXECUTE);    
		TEST_SECTION(i,MEM_READ);       
		TEST_SECTION(i,MEM_WRITE);     
		TEST_SECTION(i,SCALE_INDEX);    
		puts("\n");
	}
	//�ж��Ƿ���������
	if (IMPORT_SIZE && pimport_descriptor[0].Characteristics)
	{
		SHOWLINE;
		puts("->�����");

		for (int i=0;i<IMPORT_SIZE/sizeof(IMAGE_IMPORT_DESCRIPTOR)-1;i++)
		{
			if (!pimport_descriptor[i].Characteristics) break;		//�Ƿ��ѽ���
			PRINT_IMPORT_WITHLINE(i,OriginalFirstThunk);
			PRINT_IMPORT_WITHLINE(i,TimeDateStamp);
			PRINT_IMPORT_WITHLINE(i,ForwarderChain);

			PRINT_IMPORT_WITHLINE(i,Name);

			fseek(fp,RVAToRA(pimport_descriptor[i].Name),SEEK_SET);
			fread(strName,1,256,fp);
			PRINT_NOMEMBER(1,LENGTH);
			printf("(%s)\n",strName);

			PRINT_IMPORT_WITHLINE(i,FirstThunk);
			putchar('\n');
		}
	}
	//�ж��Ƿ���������
	if (EXPORT_SIZE && export_directory.NumberOfFunctions)
	{
		SHOWLINE;
		puts("->�����:");
		PRINT_EXPORT_WITHLINE(Characteristics);
		//�������TimeDateStamp
		PRINT_EXPORT(TimeDateStamp);
		ltime=export_directory.TimeDateStamp;
		newtime=gmtime(&ltime);
		printf("  %d.%d.%d %d:%d:%d %s\n",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,
			newtime->tm_hour,newtime->tm_min,newtime->tm_sec,WeekDay[newtime->tm_wday]);

		PRINT_EXPORT_WITHLINE(MajorVersion);
		PRINT_EXPORT_WITHLINE(MinorVersion);
		//�������
		PRINT_EXPORT_WITHLINE(Name);
		fseek(fp,RVAToRA(export_directory.Name),SEEK_SET);
		fread(strName,1,256,fp);
		PRINT_NOMEMBER(1,LENGTH);
		printf("(%s)\n",strName);

		PRINT_EXPORT_WITHLINE(Base);
		PRINT_EXPORT_WITHLINE(NumberOfFunctions);
		PRINT_EXPORT_WITHLINE(NumberOfNames);
		PRINT_EXPORT_WITHLINE(AddressOfFunctions);
		PRINT_EXPORT_WITHLINE(AddressOfNames);
		PRINT_EXPORT_WITHLINE(AddressOfNameOrdinals);
	}
	//�ж��Ƿ�����ض�λ��
	if (BASERELOC_SIZE)
	{
		SHOWLINE;
		puts("->�ض�λ��");
		PRINT_BASERELOC_WITHLINE(VirtualAddress);	//�ض�λ���λ��
		PRINT_BASERELOC_WITHLINE(SizeOfBlock);		//�ض�λ��Ĵ�С
	}
}

void ShowImport()	//��ʾ�����
{
	if (!pimport_descriptor || !pimport_descriptor[0].Characteristics)	//��δ��ȡ�������������Ϊ��
		return;

	for (int i=0;i<IMPORT_SIZE/sizeof(IMAGE_IMPORT_DESCRIPTOR)-1;i++)
	{
		if (!pimport_descriptor[i].Characteristics) break;	//�Ƿ�����������־
		//�����ӡ���������
		fseek(fp,RVAToRA(pimport_descriptor[i].Name),SEEK_SET);
		fread(strName,1,256,fp);
		printf("->%s\n",strName);
		//�����ӡ�������
		IMAGE_THUNK_DATA thunk_data;	//��ʱthunk_data
		IMAGE_IMPORT_BY_NAME import;	//��ʱimport_by_name
		fpos_t pos = RVAToRA(pimport_descriptor[i].OriginalFirstThunk);	//�ļ�λ�ó�ʼ������һ��thunk_data��ʼ��
		while (1)	//ֱ��thunk_dataΪ0���˳�
		{
			fsetpos(fp,&pos);	//�ļ�ָ�����õ���ǰthunk_data��
			fread(&thunk_data.u1.AddressOfData,sizeof(IMAGE_THUNK_DATA),1,fp);	//��ȡ��ǰthunk_data
			if (!thunk_data.u1.AddressOfData) break;	//�˳�
			fgetpos(fp,&pos);	//���浱ǰ�ļ�ָ��

			if (thunk_data.u1.AddressOfData>>31)	//���λΪ1���Ժ�����ŷ�ʽ����
			{
				printf("������ţ�%0*X\n",sizeof(thunk_data.u1.AddressOfData)*2,thunk_data.u1.AddressOfData<<1>>1);
			}
			else	//���λΪ0���Ժ�������ʽ����
			{
				fseek(fp,RVAToRA(thunk_data.u1.AddressOfData),SEEK_SET);	//�ļ�ָ�����õ����������
				fread(&import,sizeof(WORD),1,fp);	//��ȡHint
				fread(strName,1,256,fp);
				printf("Addr(%0*X)   Hint(%0*X)   Name:%s\n",sizeof(thunk_data.u1.AddressOfData)*2,thunk_data.u1.AddressOfData,
					sizeof(import.Hint)*2,import.Hint,strName);
			}
		}
	}
}

void ShowExport()	//��ʾ�����
{
	if (fp && EXPORT_SIZE && export_directory.NumberOfFunctions)	//�������ڲ��Ҳ�Ϊ��
	{
		//�������
		fseek(fp,RVAToRA(export_directory.Name),SEEK_SET);
		fread(strName,1,256,fp);
		printf("->%s\n",strName);
		fpos_t pos_func,	//������ڵ�ַ
			pos_ord,		//�������
			pos_name;	//������
		DWORD addr;		//��ʱ�������洢��ַ
		WORD ord;		//��ʱ�������洢���
		//��ʼ��������ڵ�ַ
		fseek(fp,RVAToRA(export_directory.AddressOfFunctions),SEEK_SET);
		fgetpos(fp,&pos_func);
		//��ʼ���������
		fseek(fp,RVAToRA(export_directory.AddressOfNameOrdinals),SEEK_SET);
		fgetpos(fp,&pos_ord);
		//��ʼ��������
		fseek(fp,RVAToRA(export_directory.AddressOfNames),SEEK_SET);
		fgetpos(fp,&pos_name);
		//������а����Ƶ����ĺ�����Ϣ
		for (int i=0;i<export_directory.NumberOfNames;i++)
		{
			//�����ַ
			fsetpos(fp,&pos_func);
			fread(&addr,sizeof(addr),1,fp);
			fgetpos(fp,&pos_func);	//���浱ǰ�ļ�ƫ��
			printf("Addr:%0*X ",sizeof(addr)*2,addr);
			//������
			fsetpos(fp,&pos_ord);
			fread(&ord,sizeof(ord),1,fp);
			fgetpos(fp,&pos_ord);	//���浱ǰ�ļ�ƫ��
			printf("Ord:%0*X ",sizeof(ord)*2,ord + export_directory.Base);
			//���������
			fsetpos(fp,&pos_name);
			fread(&addr,sizeof(addr),1,fp);
			fgetpos(fp,&pos_name);	//���浱ǰ�ļ�ƫ��
			fseek(fp,RVAToRA(addr),SEEK_SET);	//�ƶ���ǰ�ļ�ƫ�Ƶ���������
			fread(strName,1,256,fp);
			printf("Name: %s\n",strName);
		}
	}
}

void ShowBaseReloc()	//��ʾ�ض�λ��Ϣ
{
	//�ж��Ƿ�����ض�λ��
	if (fp && BASERELOC_SIZE)
	{
		unsigned int num = (base_reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD)-1;	//�ض�λ�������
		//�������������Ҫ�ض�λ����Ϣ
		printf("  ->�ض�λ��Ϣ��(���� %d ��)\n",num);
		//�ض�λ�������ļ��е�ƫ��---TypeOffset��ʼλ��
		fpos_t pos = RVAToRA(BASERELOC_OFF)+sizeof(DWORD)*2;	
		WORD TypeOffset;	//��ʱ��������¼ÿһ��TypeOffset
		DWORD data;	//��¼��Ҫ�ض�λ������
		for (int i=0;i<num;i++)
		{
			//���TypeOffset
			fsetpos(fp,&pos);
			fread(&TypeOffset,sizeof(TypeOffset),1,fp);
			fgetpos(fp,&pos);
			//�����Ҫ�ض�λ������
			WORD code_pos = base_reloc.VirtualAddress + (TypeOffset & 0x0FFF);	//��Ҫ�޸ĵ����ݵ�ƫ��
			fseek(fp,RVAToRA(code_pos),SEEK_SET);
			fread(&data,sizeof(data),1,fp);
			//�����Ϣ
			printf("    | Type:%0*X Offset:%0*X     Data:%0*X\n",1,TypeOffset>>12,sizeof(TypeOffset)*2,code_pos,sizeof(data)*2,data);
		}
	}
}

void ShowResource(DWORD Offset , unsigned int level)	//��ʾ��Դ�ļ���Ϣ
{
	Offset += RESOURCE_OFF;	//��ʼ�����RVA
	IMAGE_RESOURCE_DIRECTORY res;	//Ŀ¼
	fseek(fp,RVAToRA(Offset),SEEK_SET);	//�Ƶ�Ŀ¼��
	fread(&res,sizeof(res),1,fp);	//��ȡĿ¼
	//����������
	WORD nums = res.NumberOfNamedEntries + res.NumberOfIdEntries;
	for (WORD i=0;i<nums;i++)
	{
		if (1 == level)
			printf("->");
		else
			printf("%*c->",(level-1)*2,' ');	//Ԥ���
		IMAGE_RESOURCE_DIRECTORY_ENTRY entry;	//���
		fread(&entry,sizeof(entry),1,fp);	//������
		if (entry.NameIsString)	//���ַ���
		{
			fpos_t pos;	
			fgetpos(fp,&pos);	//���浱ǰ�ļ�ƫ��
			fseek(fp,RVAToRA(entry.NameOffset+RESOURCE_OFF),SEEK_SET);	//�Ƶ��ַ���¼���
			WORD Length;	//�ַ�������
			fread(&Length,sizeof(Length),1,fp);
			WCHAR strName[256];	//�ַ���
			fread(strName,sizeof(WCHAR),Length,fp);
			strName[Length] = '\0';
			fsetpos(fp,&pos);	//�ָ��ļ�ƫ��
			printf("%ls\n",strName);
		}
		else	//��ID
		{
			if (1 == level)	//����ǵ�һ��
			{
				//�ж�ID�Ƿ����ڱ�׼��Դ����
				switch (entry.NameOffset)
				{
					case 0x1:
					{
						puts("���");
						break;
					}
					case 0x2:
					{
						puts("λͼ");
						break;
					}
					case 0x3:
					{
						puts("ͼ��");
						break;
					}
					case 0x4:
					{
						puts("�˵�");
						break;
					}
					case 0x5:
					{
						puts("�Ի���");
						break;
					}
					case 0x6:
					{
						puts("�ַ���");
						break;
					}
					case 0x7:
					{
						puts("����Ŀ¼");
						break;
					}
					case 0x8:
					{
						puts("����");
						break;
					}
					case 0x9:
					{
						puts("��ݼ�");
						break;
					}
					case 0xA:
					{
						puts("δ��ʽ��Դ");
						break;
					}
					case 0xB:
					{
						puts("��Ϣ��");
						break;
					}
					case 0xC:
					{
						puts("�����");
						break;
					}
					case 0xD:
					{
						puts("ͼ����");
						break;
					}
					case 0xE:
					{
						puts("ͼ����");
						break;
					}
					case 0x10:
					{
						puts("�汾��Ϣ");
						break;
					}
					default:
					{
						printf("%d\n",entry.NameOffset);
						break;
					}
				}
			}
			else	//���ǵ�һ��ֱ�����ID
			{
				printf("%d\n",entry.NameOffset);
			}

		}
		fpos_t pos;
		fgetpos(fp,&pos);	//����ƫ��
		//�ж��Ƿ�����һ��
		if (entry.DataIsDirectory)	//������һ��
		{
			ShowResource(entry.OffsetToDirectory,level+1);
		}
		else	//���һ��
		{
			fseek(fp,RVAToRA(entry.OffsetToData + RESOURCE_OFF),SEEK_SET);	
			IMAGE_RESOURCE_DATA_ENTRY data_entry;
			fread(&data_entry,sizeof(data_entry),1,fp);	//��ȡ��Դ����ָ��
			printf("%*cOffsetToData:%0*X Size:%0*X CodePage:%0*X Reserved:%0*X\n",level*2,' ',sizeof(data_entry.OffsetToData),data_entry.OffsetToData,
				sizeof(data_entry.Size),data_entry.Size,sizeof(data_entry.CodePage),data_entry.CodePage,sizeof(data_entry.Reserved),data_entry.Reserved);
		}
		fsetpos(fp,&pos);	//�ָ�ƫ��
	}
}

DWORD RVAToRA(DWORD RVA)		//RVAת�ļ�ƫ��
{
	if (psection_header)	//�����������ȡ
	{
		int i=0;	//��λ�������
		while (psection_header[i].VirtualAddress <= RVA && i<nt_headers.FileHeader.NumberOfSections) i++;
		i--;
		return psection_header[i].PointerToRawData+(RVA-psection_header[i].VirtualAddress);
	}
	else
		return 0;
}

void Exit()		//����������
{
	if (psection_header)
	{
		free(psection_header);
		psection_header = NULL;
	}
	if (pimport_descriptor)
	{
		free(pimport_descriptor);
		pimport_descriptor = NULL;
	}
	if (fp)
	{		
		fclose(fp);
		fp = NULL;
	}
}