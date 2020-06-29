// PEInfo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

extern void DirectoryString(DWORD dwIndex);
int main()
{
	//获取文件句柄
	HANDLE hFile = CreateFile(
		L"F:\\vsstudio\\PEInfo\\Debug\\test.exe",
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//获取文件大小
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	CHAR* pFileBuf = new CHAR[dwFileSize];
	//将文件读取到内存
	DWORD ReadSize = 0;
	ReadFile(hFile, pFileBuf, dwFileSize, &ReadSize, NULL);

	//判断是否为PE文件
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//不是PE
		printf("不是PE文件\n");
		system("pause");
		return 0;
	}

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		//不是PE文件
		printf("不是PE文件\n");
		system("pause");
		return 0;
	}

	//获取基本PE头信息
	//获取信息所用到的两个结构体指针	（这两个结构体都属于NT头）
	PIMAGE_FILE_HEADER		pFileHeader = &(pNtHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER	pOptionalHeader = &(pNtHeader->OptionalHeader);
	//输出PE头信息
	printf("================== 基 本 P E 头 信 息 ==================\n\n");
	printf("入 口 点:\t%08X\t", pOptionalHeader->AddressOfEntryPoint);
	printf("子 系 统:\t%04X\n", pOptionalHeader->Subsystem);
	printf("镜像基址:\t%08X\t", pOptionalHeader->ImageBase);
	printf("区段数目:\t%04X\n", pFileHeader->NumberOfSections);
	printf("镜像大小:\t%08X\t", pOptionalHeader->SizeOfImage);
	printf("日期时间标志:\t%08X\n", pFileHeader->TimeDateStamp);
	printf("代码基址:\t%08X\t", pOptionalHeader->BaseOfCode);
	printf("部首大小:\t%08X\n", pOptionalHeader->SizeOfHeaders);
	printf("数据基址:\t%08X\t", pOptionalHeader->BaseOfData);
	printf("特 征 值:\t%04X\n", pFileHeader->Characteristics);
	printf("块 对 齐:\t%08X\t", pOptionalHeader->SectionAlignment);
	printf("校 验 和:\t%08X\n", pOptionalHeader->CheckSum);
	printf("文件块对齐:\t%08X\t", pOptionalHeader->FileAlignment);
	printf("可选头部大小:\t%04X\n", pFileHeader->SizeOfOptionalHeader);
	printf("标 志 字:\t%04X\t\t", pOptionalHeader->Magic);
	printf("RVA数及大小:\t%08X\n\n", pOptionalHeader->NumberOfRvaAndSizes);

	printf("======================= 目 录 表 =======================\n");
	//获取目录表头指针
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionalHeader->DataDirectory;
	printf("\t\t  RAV\t\t  大小\n");
	for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		DirectoryString(i);
		printf("%08X\t%08X\n",
			pDataDirectory[i].VirtualAddress, pDataDirectory[i].Size);
	}

	printf("======================= 区 段 表 =======================\n");
	//获取区段表头指针
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	printf("名称      VOffset   VSize     ROffset   RSize     标志\n");
	//获取区段个数
	DWORD dwSectionNum = pFileHeader->NumberOfSections;
	//根据区段个数遍历区段信息
	for (DWORD i = 0; i < dwSectionNum; i++, pSectionHeader++)
	{
		for (DWORD j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++)
		{
			printf("%c", pSectionHeader->Name[j]);
		}
		printf("  %08X  %08X  %08X  %08X  %08X\n",
			pSectionHeader->VirtualAddress,
			pSectionHeader->Misc.VirtualSize,
			pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData,
			pSectionHeader->Characteristics);
	}
	printf("\n");

	system("pause");
}

void DirectoryString(DWORD dwIndex)
{
	switch (dwIndex)
	{
	case 0:printf("输出表:\t\t");
		break;
	case 1:printf("输入表:\t\t");
		break;
	case 2:printf("资源:\t\t");
		break;
	case 3:printf("异常:\t\t");
		break;
	case 4:printf("安全:\t\t");
		break;
	case 5:printf("重定位:\t\t");
		break;
	case 6:printf("调试:\t\t");
		break;
	case 7:printf("版权:\t\t");
		break;
	case 8:printf("全局指针:\t");
		break;
	case 9:printf("TLS表:\t\t");
		break;
	case 10:printf("载入配置:\t");
		break;
	case 11:printf("输入范围:\t");
		break;
	case 12:printf("IAT:\t\t");
		break;
	case 13:printf("延迟输入:\t");
		break;
	case 14:printf("COM:\t\t");
		break;
	case 15:printf("保留:\t\t");
		break;
	}
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
