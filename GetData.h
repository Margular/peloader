#pragma once
#ifndef _GETDATA_H_
#define _GETDATA_H_

#include <stdio.h>
#include <Windows.h>

#define LENGTH 30	//�������
#define DIRECTORY_WIDTH 25	//�������Ŀ¼����
#define SECTION_WIDTH 10	//�������
#define SHOWLINE puts("-------------------------------------------------------------------------------")
//C:���� L:���Ƴ��� S:���� M:��Ա
#define PRINT_NOMEMBER(C,L) printf("%*c % *c      ",C*2,' ',L,' ')	//���ڶ���
#define PRINT_MEMBER(C,L,S,M) printf("%*c|% *s:     % 0*X",C*2,' ',L,S,sizeof(M)*2,M)		//��ʽ������޻س�
#define PRINT_MEMBER_WITHLINE(C,L,S,M) printf("%*c|% *s:     % 0*X\n",C*2,' ',L,S,sizeof(M)*2,M)	//��ʽ������лس�
#define PRINT_MEMBER_POINTER(C,L,S,M) {printf("%*c|% *s:     ",C*2,' ',L,S);\
	for (int i=0;i<sizeof(M)/sizeof(*M);i++)\
	printf("% 0*X",sizeof(M[i])*2,M[i]);}		//��ʽ�����Աָ�룬�޻س�
#define PRINT_MEMBER_POINTER_WITHLINE(C,L,S,M) {printf("%*c|% *s:     ",C*2,' ',L,S);\
	for (int i=0;i<sizeof(M)/sizeof(*M);i++)\
	printf("% 0*X",sizeof(M[i])*2,M[i]);\
	putchar('\n');}		//��ʽ�����Աָ�룬�лس�

bool GetImage();		//��ȡIMAGE Structs
void ShowStructs();  	//��ʾ�ṹ������
void ShowImport();	//��ʾ�����
void ShowExport();	//��ʾ�����
void ShowBaseReloc();	//��ʾ�ض�λ��Ϣ
void ShowResource(DWORD Offset = NULL , unsigned int level = 1);	//��ʾ��Դ�ļ���Ϣ
DWORD RVAToRA(DWORD RVA);		//RVAת�ļ�ƫ��
void Exit();		//����������

#endif