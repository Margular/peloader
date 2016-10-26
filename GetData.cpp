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
							"保留"};	//输入表名称

const char *WeekDay[]={	"星期日",
						"星期一",
						"星期二",
						"星期三",
						"星期四",
						"星期五",
						"星期六"};	//输出TimeDateStamp日期用

//N:成员名 P:指针
#define PRINT_DOS(N) PRINT_MEMBER(1,LENGTH,#N,dos_header.##N)	//打印dos_header，无回车
#define PRINT_DOS_WITHLINE(N) PRINT_MEMBER_WITHLINE(1,LENGTH,#N,dos_header.##N)	//打印dos_header，有回车，下同
#define PRINT_DOSP_WITHLINE(P) PRINT_MEMBER_POINTER_WITHLINE(1,LENGTH,#P,dos_header.##P)
#define PRINT_FILE_WITHLINE(N) PRINT_MEMBER_WITHLINE(2,LENGTH,#N,nt_headers.FileHeader.##N)
#define PRINT_FILE(N) PRINT_MEMBER(2,LENGTH,#N,nt_headers.FileHeader.##N)
#define PRINT_OPTIONAL(N) PRINT_MEMBER(2,LENGTH,#N,nt_headers.OptionalHeader.##N)
#define PRINT_OPTIONAL_WITHLINE(N) PRINT_MEMBER_WITHLINE(2,LENGTH,#N,nt_headers.OptionalHeader.##N)
#define PRINT_IMPORT_WITHLINE(i,N) PRINT_MEMBER_WITHLINE(1,LENGTH,#N,pimport_descriptor[i].##N)
#define PRINT_EXPORT_WITHLINE(N) PRINT_MEMBER_WITHLINE(1,LENGTH,#N,export_directory.##N)
#define PRINT_EXPORT(N) PRINT_MEMBER(1,LENGTH,#N,export_directory.##N)
#define PRINT_BASERELOC_WITHLINE(N) PRINT_MEMBER_WITHLINE(1,LENGTH,#N,base_reloc.##N)
//检测是否存在某一Charicteristic，存在则打印
//N:宏名
#define TEST_FILE(N) {if (nt_headers.FileHeader.Characteristics == (nt_headers.FileHeader.Characteristics | IMAGE_FILE_##N))\
	PRINT_NOMEMBER(2,LENGTH),printf("(%s)\n",#N);}	//检测文件属性
#define TEST_SECTION(i,N) if (psection_header[i].Characteristics == (psection_header[i].Characteristics | IMAGE_SCN_##N))\
	printf("(%s)",#N)	//检测区块属性
#define TEST_MACHINE(N) case IMAGE_FILE_MACHINE_##N: {printf(" (%s)\n",#N);break;}	//检测文件属性
#define TEST_SUBSYSTEM(N) case IMAGE_SUBSYSTEM_##N: {printf(" (%s)\n",#N);break;}	//检测子系统

#define SEC_NO nt_headers.FileHeader.NumberOfSections	//全部有效，区块表数
#define IMPORT_SIZE nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size		//包含多余一个，输入表占总字节数
#define EXPORT_SIZE nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size		//输出表大小
#define BASERELOC_SIZE nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size	//重定位表大小
#define IMPORT_OFF nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress		//输入表起始RVA
#define EXPORT_OFF nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress		//输出表起始RVA
#define BASERELOC_OFF nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress	//重定位表起始RVA
#define RESOURCE_OFF nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress		//资源表的起始RVA

IMAGE_DOS_HEADER dos_header;
IMAGE_NT_HEADERS nt_headers;
PIMAGE_SECTION_HEADER psection_header = NULL;
PIMAGE_IMPORT_DESCRIPTOR pimport_descriptor = NULL;
IMAGE_EXPORT_DIRECTORY export_directory;
IMAGE_BASE_RELOCATION base_reloc;
extern FILE *fp;	
char strName[256];	//记录名称
time_t ltime;	//输出TimeDateStamp用
struct tm *newtime;		//输出TimeDateStamp用

bool GetImage()		//读取IMAGE Structs
{
	fread(&dos_header,sizeof(IMAGE_DOS_HEADER),1,fp);		//读取DOS头部
	fseek(fp,dos_header.e_lfanew,SEEK_SET);		//设置文件指针到PE头以便读取
	fread(&nt_headers,sizeof(IMAGE_NT_HEADERS),1,fp);		//读取PE头

	if (nt_headers.Signature != IMAGE_NT_SIGNATURE)	//不是有效的PE头
		return false;

	psection_header = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER)*SEC_NO);	//为区块分配空间
	fread(psection_header,sizeof(IMAGE_SECTION_HEADER),SEC_NO,fp);	//读取区块表

	if (IMPORT_SIZE)		//读取输入表
	{
		pimport_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)malloc(IMPORT_SIZE-sizeof(IMAGE_IMPORT_DESCRIPTOR));	//多余一个
		fseek(fp,RVAToRA(IMPORT_OFF),SEEK_SET);		//设置文件指针到适当位置
		fread(pimport_descriptor,sizeof(IMAGE_IMPORT_DESCRIPTOR),IMPORT_SIZE/sizeof(IMAGE_IMPORT_DESCRIPTOR)-1,fp);	//读取输入表，不包含多余的
	}
	if (EXPORT_SIZE)	//读取输出表
	{
		fseek(fp,RVAToRA(EXPORT_OFF),SEEK_SET);	//设置文件指针
		fread(&export_directory,sizeof(IMAGE_EXPORT_DIRECTORY),1,fp);	//读取输出表
	}
	if (nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)	//读取重定位表
	{
		fseek(fp,RVAToRA(BASERELOC_OFF),SEEK_SET);	//设置文件指针
		fread(&base_reloc,sizeof(IMAGE_BASE_RELOCATION),1,fp);	//读取重定位表
	}
	return true;
}

void ShowStructs()  	//显示结构体内容
{
	if (!fp)	//还未读取
		return;

	puts("->Dos_Header:");
	PRINT_DOS(e_magic);
	printf(" (%c%c)\n",(char)(dos_header.e_magic>>8),(char)(dos_header.e_magic));	//高位在前，低位在后
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
		(char)(nt_headers.Signature>>8),(char)nt_headers.Signature);	//高位在前，低位在后

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
	//下面输出TimeDateStamp
	PRINT_FILE(TimeDateStamp);
	ltime=nt_headers.FileHeader.TimeDateStamp;
	newtime=gmtime(&ltime);
	printf("  %d.%d.%d %d:%d:%d %s\n",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,
		newtime->tm_hour,newtime->tm_min,newtime->tm_sec,WeekDay[newtime->tm_wday]);

	PRINT_FILE_WITHLINE(PointerToSymbolTable);
	PRINT_FILE_WITHLINE(NumberOfSymbols);
	PRINT_FILE_WITHLINE(SizeOfOptionalHeader);
	PRINT_FILE_WITHLINE(Characteristics);
	//获得文件属性
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
	//子系统
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
	//数据目录表
	SHOWLINE;
	printf("%-*s%-*s%-*s\n",DIRECTORY_WIDTH,"Date Directory:",DIRECTORY_WIDTH,"RVA",DIRECTORY_WIDTH,"Size");
	for (int i=0;i<IMAGE_NUMBEROF_DIRECTORY_ENTRIES;i++)
		printf("%-*s%-0*.*X%-0*.*X\n",DIRECTORY_WIDTH,TableName[i],DIRECTORY_WIDTH,sizeof(nt_headers.OptionalHeader.DataDirectory->VirtualAddress)*2,
		nt_headers.OptionalHeader.DataDirectory[i].VirtualAddress,
		DIRECTORY_WIDTH,sizeof(nt_headers.OptionalHeader.DataDirectory->VirtualAddress)*2,
		nt_headers.OptionalHeader.DataDirectory[i].Size);
	SHOWLINE;
	//区块表
	puts("\n区块表信息：");
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
	//判断是否存在输入表
	if (IMPORT_SIZE && pimport_descriptor[0].Characteristics)
	{
		SHOWLINE;
		puts("->输入表：");

		for (int i=0;i<IMPORT_SIZE/sizeof(IMAGE_IMPORT_DESCRIPTOR)-1;i++)
		{
			if (!pimport_descriptor[i].Characteristics) break;		//是否已结束
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
	//判断是否存在输出表
	if (EXPORT_SIZE && export_directory.NumberOfFunctions)
	{
		SHOWLINE;
		puts("->输出表:");
		PRINT_EXPORT_WITHLINE(Characteristics);
		//下面输出TimeDateStamp
		PRINT_EXPORT(TimeDateStamp);
		ltime=export_directory.TimeDateStamp;
		newtime=gmtime(&ltime);
		printf("  %d.%d.%d %d:%d:%d %s\n",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,
			newtime->tm_hour,newtime->tm_min,newtime->tm_sec,WeekDay[newtime->tm_wday]);

		PRINT_EXPORT_WITHLINE(MajorVersion);
		PRINT_EXPORT_WITHLINE(MinorVersion);
		//输出表名
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
	//判断是否存在重定位表
	if (BASERELOC_SIZE)
	{
		SHOWLINE;
		puts("->重定位表：");
		PRINT_BASERELOC_WITHLINE(VirtualAddress);	//重定位表的位置
		PRINT_BASERELOC_WITHLINE(SizeOfBlock);		//重定位表的大小
	}
}

void ShowImport()	//显示输入表
{
	if (!pimport_descriptor || !pimport_descriptor[0].Characteristics)	//还未读取输入表或者输入表为空
		return;

	for (int i=0;i<IMPORT_SIZE/sizeof(IMAGE_IMPORT_DESCRIPTOR)-1;i++)
	{
		if (!pimport_descriptor[i].Characteristics) break;	//是否遇到结束标志
		//下面打印输入表名称
		fseek(fp,RVAToRA(pimport_descriptor[i].Name),SEEK_SET);
		fread(strName,1,256,fp);
		printf("->%s\n",strName);
		//下面打印输入表函数
		IMAGE_THUNK_DATA thunk_data;	//临时thunk_data
		IMAGE_IMPORT_BY_NAME import;	//临时import_by_name
		fpos_t pos = RVAToRA(pimport_descriptor[i].OriginalFirstThunk);	//文件位置初始化到第一个thunk_data起始处
		while (1)	//直到thunk_data为0才退出
		{
			fsetpos(fp,&pos);	//文件指针设置到当前thunk_data处
			fread(&thunk_data.u1.AddressOfData,sizeof(IMAGE_THUNK_DATA),1,fp);	//读取当前thunk_data
			if (!thunk_data.u1.AddressOfData) break;	//退出
			fgetpos(fp,&pos);	//保存当前文件指针

			if (thunk_data.u1.AddressOfData>>31)	//最高位为1，以函数序号方式输入
			{
				printf("函数序号：%0*X\n",sizeof(thunk_data.u1.AddressOfData)*2,thunk_data.u1.AddressOfData<<1>>1);
			}
			else	//最高位为0，以函数名方式输入
			{
				fseek(fp,RVAToRA(thunk_data.u1.AddressOfData),SEEK_SET);	//文件指针设置到输入表函数处
				fread(&import,sizeof(WORD),1,fp);	//读取Hint
				fread(strName,1,256,fp);
				printf("Addr(%0*X)   Hint(%0*X)   Name:%s\n",sizeof(thunk_data.u1.AddressOfData)*2,thunk_data.u1.AddressOfData,
					sizeof(import.Hint)*2,import.Hint,strName);
			}
		}
	}
}

void ShowExport()	//显示输出表
{
	if (fp && EXPORT_SIZE && export_directory.NumberOfFunctions)	//输出表存在并且不为空
	{
		//输出名字
		fseek(fp,RVAToRA(export_directory.Name),SEEK_SET);
		fread(strName,1,256,fp);
		printf("->%s\n",strName);
		fpos_t pos_func,	//函数入口地址
			pos_ord,		//函数序号
			pos_name;	//函数名
		DWORD addr;		//临时变量，存储地址
		WORD ord;		//临时变量，存储序号
		//初始化函数入口地址
		fseek(fp,RVAToRA(export_directory.AddressOfFunctions),SEEK_SET);
		fgetpos(fp,&pos_func);
		//初始化函数序号
		fseek(fp,RVAToRA(export_directory.AddressOfNameOrdinals),SEEK_SET);
		fgetpos(fp,&pos_ord);
		//初始化函数名
		fseek(fp,RVAToRA(export_directory.AddressOfNames),SEEK_SET);
		fgetpos(fp,&pos_name);
		//输出所有按名称导出的函数信息
		for (int i=0;i<export_directory.NumberOfNames;i++)
		{
			//输出地址
			fsetpos(fp,&pos_func);
			fread(&addr,sizeof(addr),1,fp);
			fgetpos(fp,&pos_func);	//保存当前文件偏移
			printf("Addr:%0*X ",sizeof(addr)*2,addr);
			//输出序号
			fsetpos(fp,&pos_ord);
			fread(&ord,sizeof(ord),1,fp);
			fgetpos(fp,&pos_ord);	//保存当前文件偏移
			printf("Ord:%0*X ",sizeof(ord)*2,ord + export_directory.Base);
			//输出函数名
			fsetpos(fp,&pos_name);
			fread(&addr,sizeof(addr),1,fp);
			fgetpos(fp,&pos_name);	//保存当前文件偏移
			fseek(fp,RVAToRA(addr),SEEK_SET);	//移动当前文件偏移到函数名处
			fread(strName,1,256,fp);
			printf("Name: %s\n",strName);
		}
	}
}

void ShowBaseReloc()	//显示重定位信息
{
	//判断是否存在重定位表
	if (fp && BASERELOC_SIZE)
	{
		unsigned int num = (base_reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD)-1;	//重定位表的项数
		//下面输出所有需要重定位的信息
		printf("  ->重定位信息：(共计 %d 项)\n",num);
		//重定位数据在文件中的偏移---TypeOffset起始位置
		fpos_t pos = RVAToRA(BASERELOC_OFF)+sizeof(DWORD)*2;	
		WORD TypeOffset;	//临时变量，记录每一项TypeOffset
		DWORD data;	//记录需要重定位的数据
		for (int i=0;i<num;i++)
		{
			//获得TypeOffset
			fsetpos(fp,&pos);
			fread(&TypeOffset,sizeof(TypeOffset),1,fp);
			fgetpos(fp,&pos);
			//获得需要重定位的数据
			WORD code_pos = base_reloc.VirtualAddress + (TypeOffset & 0x0FFF);	//需要修改的数据的偏移
			fseek(fp,RVAToRA(code_pos),SEEK_SET);
			fread(&data,sizeof(data),1,fp);
			//输出信息
			printf("    | Type:%0*X Offset:%0*X     Data:%0*X\n",1,TypeOffset>>12,sizeof(TypeOffset)*2,code_pos,sizeof(data)*2,data);
		}
	}
}

void ShowResource(DWORD Offset , unsigned int level)	//显示资源文件信息
{
	Offset += RESOURCE_OFF;	//初始化入口RVA
	IMAGE_RESOURCE_DIRECTORY res;	//目录
	fseek(fp,RVAToRA(Offset),SEEK_SET);	//移到目录处
	fread(&res,sizeof(res),1,fp);	//读取目录
	//获得入口总数
	WORD nums = res.NumberOfNamedEntries + res.NumberOfIdEntries;
	for (WORD i=0;i<nums;i++)
	{
		if (1 == level)
			printf("->");
		else
			printf("%*c->",(level-1)*2,' ');	//预输出
		IMAGE_RESOURCE_DIRECTORY_ENTRY entry;	//入口
		fread(&entry,sizeof(entry),1,fp);	//获得入口
		if (entry.NameIsString)	//按字符串
		{
			fpos_t pos;	
			fgetpos(fp,&pos);	//保存当前文件偏移
			fseek(fp,RVAToRA(entry.NameOffset+RESOURCE_OFF),SEEK_SET);	//移到字符串录入出
			WORD Length;	//字符串长度
			fread(&Length,sizeof(Length),1,fp);
			WCHAR strName[256];	//字符串
			fread(strName,sizeof(WCHAR),Length,fp);
			strName[Length] = '\0';
			fsetpos(fp,&pos);	//恢复文件偏移
			printf("%ls\n",strName);
		}
		else	//按ID
		{
			if (1 == level)	//如果是第一层
			{
				//判断ID是否属于标准资源类型
				switch (entry.NameOffset)
				{
					case 0x1:
					{
						puts("光标");
						break;
					}
					case 0x2:
					{
						puts("位图");
						break;
					}
					case 0x3:
					{
						puts("图标");
						break;
					}
					case 0x4:
					{
						puts("菜单");
						break;
					}
					case 0x5:
					{
						puts("对话框");
						break;
					}
					case 0x6:
					{
						puts("字符串");
						break;
					}
					case 0x7:
					{
						puts("字体目录");
						break;
					}
					case 0x8:
					{
						puts("字体");
						break;
					}
					case 0x9:
					{
						puts("快捷键");
						break;
					}
					case 0xA:
					{
						puts("未格式资源");
						break;
					}
					case 0xB:
					{
						puts("消息表");
						break;
					}
					case 0xC:
					{
						puts("光标组");
						break;
					}
					case 0xD:
					{
						puts("图标组");
						break;
					}
					case 0xE:
					{
						puts("图标组");
						break;
					}
					case 0x10:
					{
						puts("版本信息");
						break;
					}
					default:
					{
						printf("%d\n",entry.NameOffset);
						break;
					}
				}
			}
			else	//不是第一层直接输出ID
			{
				printf("%d\n",entry.NameOffset);
			}

		}
		fpos_t pos;
		fgetpos(fp,&pos);	//保存偏移
		//判断是否还有下一层
		if (entry.DataIsDirectory)	//还有下一层
		{
			ShowResource(entry.OffsetToDirectory,level+1);
		}
		else	//最后一层
		{
			fseek(fp,RVAToRA(entry.OffsetToData + RESOURCE_OFF),SEEK_SET);	
			IMAGE_RESOURCE_DATA_ENTRY data_entry;
			fread(&data_entry,sizeof(data_entry),1,fp);	//获取资源数据指针
			printf("%*cOffsetToData:%0*X Size:%0*X CodePage:%0*X Reserved:%0*X\n",level*2,' ',sizeof(data_entry.OffsetToData),data_entry.OffsetToData,
				sizeof(data_entry.Size),data_entry.Size,sizeof(data_entry.CodePage),data_entry.CodePage,sizeof(data_entry.Reserved),data_entry.Reserved);
		}
		fsetpos(fp,&pos);	//恢复偏移
	}
}

DWORD RVAToRA(DWORD RVA)		//RVA转文件偏移
{
	if (psection_header)	//区块表正常读取
	{
		int i=0;	//定位区块序号
		while (psection_header[i].VirtualAddress <= RVA && i<nt_headers.FileHeader.NumberOfSections) i++;
		i--;
		return psection_header[i].PointerToRawData+(RVA-psection_header[i].VirtualAddress);
	}
	else
		return 0;
}

void Exit()		//后续清理工作
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