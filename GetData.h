#pragma once
#ifndef _GETDATA_H_
#define _GETDATA_H_

#include <stdio.h>
#include <Windows.h>

#define LENGTH 30	//其它宽度
#define DIRECTORY_WIDTH 25	//输出数据目录表宽度
#define SECTION_WIDTH 10	//区块表宽度
#define SHOWLINE puts("-------------------------------------------------------------------------------")
//C:级数 L:名称长度 S:名称 M:成员
#define PRINT_NOMEMBER(C,L) printf("%*c % *c      ",C*2,' ',L,' ')	//用于对齐
#define PRINT_MEMBER(C,L,S,M) printf("%*c|% *s:     % 0*X",C*2,' ',L,S,sizeof(M)*2,M)		//格式输出，无回车
#define PRINT_MEMBER_WITHLINE(C,L,S,M) printf("%*c|% *s:     % 0*X\n",C*2,' ',L,S,sizeof(M)*2,M)	//格式输出，有回车
#define PRINT_MEMBER_POINTER(C,L,S,M) {printf("%*c|% *s:     ",C*2,' ',L,S);\
	for (int i=0;i<sizeof(M)/sizeof(*M);i++)\
	printf("% 0*X",sizeof(M[i])*2,M[i]);}		//格式输出成员指针，无回车
#define PRINT_MEMBER_POINTER_WITHLINE(C,L,S,M) {printf("%*c|% *s:     ",C*2,' ',L,S);\
	for (int i=0;i<sizeof(M)/sizeof(*M);i++)\
	printf("% 0*X",sizeof(M[i])*2,M[i]);\
	putchar('\n');}		//格式输出成员指针，有回车

bool GetImage();		//读取IMAGE Structs
void ShowStructs();  	//显示结构体内容
void ShowImport();	//显示输入表
void ShowExport();	//显示输出表
void ShowBaseReloc();	//显示重定位信息
void ShowResource(DWORD Offset = NULL , unsigned int level = 1);	//显示资源文件信息
DWORD RVAToRA(DWORD RVA);		//RVA转文件偏移
void Exit();		//后续清理工作

#endif