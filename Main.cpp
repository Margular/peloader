/* ˵�����޸�С�������ԴID->��Դ���ͣ����˷���2������
		 �汾��Ϣ->ͼ����     
		 0x10 -> �汾��Ϣ
		 ��������С��������ͼƬ��ʾ
   ��ע��δ������⣺
         ���ڱ�����Ϊ�ο�����δʵ��������ʾ���������ʾ��ȫ������*/
#include "GetData.h"
#include <stdio.h>
#include <stdlib.h>

FILE *fp = NULL;

int main()
{
	char choice;	//ѡ�񿪹�
	while (1)
	{
		system("cls");
		printf("1->���ļ�\n"
			   "2->��ʾ�ṹ������\n"
			   "3->�鿴�����\n"
			   "4->�鿴�����\n"
			   "5->��ʾ�ض�λ��Ϣ\n"
			   "6->��ʾ��Դ�ļ���Ϣ\n"
			   "q->�˳�\n");
		if ('\n' == (choice = getchar())) continue;
		system("cls");
		while (getchar()!='\n');
		//ѡ����䲿��
		switch (choice)
		{
		case '1':		//���ļ�
			{
				if (fp)	Exit();
				char filename[256];
				puts("�������ļ�·��");
				gets(filename);
				
				if (!(fp=fopen(filename,"rb")))	
				{
					puts("�ļ�·����Ч");
					break;
				}
				if (!GetImage())
				{
					puts("�ļ�������Ч��PE�ļ�!");
					fclose(fp);
					fp = NULL;
				}
				break;
			}
		case '2':	//��ʾ�ṹ������
			{
				ShowStructs();
				break;
			}
		case '3':	//�鿴�����
			{
				ShowImport();
				break;
			}
		case '4':	//��ʾ�����
			{
				ShowExport();
				break;
			}
		case '5':	//��ʾ�ض�λ��Ϣ
			{
				ShowBaseReloc();
				break;
			}
		case '6':
			{
				ShowResource();
				break;
			}
		case 'q':	//�˳�
			{
				Exit();
				return 0;
				break;
			}
		default:		//�������
			{
				puts("�����������������!");
				break;
			}
		}
		system("pause");
	}
}