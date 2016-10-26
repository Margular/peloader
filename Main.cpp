/* 说明：修改小甲鱼的资源ID->资源类型，本人发现2处错误
		 版本信息->图标组     
		 0x10 -> 版本信息
		 其它保持小甲鱼所给图片所示
   备注：未解决问题：
         由于本程序为参考程序，未实现文字显示过多造成显示不全的问题*/
#include "GetData.h"
#include <stdio.h>
#include <stdlib.h>

FILE *fp = NULL;

int main()
{
	char choice;	//选择开关
	while (1)
	{
		system("cls");
		printf("1->打开文件\n"
			   "2->显示结构体内容\n"
			   "3->查看输入表\n"
			   "4->查看输出表\n"
			   "5->显示重定位信息\n"
			   "6->显示资源文件信息\n"
			   "q->退出\n");
		if ('\n' == (choice = getchar())) continue;
		system("cls");
		while (getchar()!='\n');
		//选择语句部分
		switch (choice)
		{
		case '1':		//打开文件
			{
				if (fp)	Exit();
				char filename[256];
				puts("请输入文件路径");
				gets(filename);
				
				if (!(fp=fopen(filename,"rb")))	
				{
					puts("文件路径无效");
					break;
				}
				if (!GetImage())
				{
					puts("文件不是有效的PE文件!");
					fclose(fp);
					fp = NULL;
				}
				break;
			}
		case '2':	//显示结构体内容
			{
				ShowStructs();
				break;
			}
		case '3':	//查看输入表
			{
				ShowImport();
				break;
			}
		case '4':	//显示输出表
			{
				ShowExport();
				break;
			}
		case '5':	//显示重定位信息
			{
				ShowBaseReloc();
				break;
			}
		case '6':
			{
				ShowResource();
				break;
			}
		case 'q':	//退出
			{
				Exit();
				return 0;
				break;
			}
		default:		//输入错误
			{
				puts("输入错误，请重新输入!");
				break;
			}
		}
		system("pause");
	}
}