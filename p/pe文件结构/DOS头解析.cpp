#include<Windows.h>
#include<iostream>

int main()
{
    HANDLE hfile = CreateFileA("test.exe",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);    
    DWORD fileSize = GetFileSize(hfile,NULL);
    char* fileBuff = new char[fileSize];
    DWORD realRead = 0;
    BOOL bsuccess = FALSE; 
    bsuccess = ReadFile(hfile,fileBuff,fileSize,&realRead,NULL);
    PIMAGE_NT_HEADERS pNtHeaders = 0;
    PIMAGE_FILE_HEADER pFileHeader = 0;
    PIMAGE_OPTIONAL_HEADER pOptionalHeaders = 0;
    if(bsuccess)
    {
        PIMAGE_DOS_HEADER pDosHeaders = (PIMAGE_DOS_HEADER)fileBuff;
        if(pDosHeaders->e_magic!=0x5A4D)
        {
            printf("不是有效的PE文件\n");
            delete[] fileBuff;
            return 0;
        }
        printf("e_lfanew=%d\n", pDosHeaders->e_lfanew);
        pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeaders->e_lfanew + (DWORD)fileBuff);
        printf("PE start at:%p\n",pNtHeaders);
        DWORD pe=pNtHeaders->Signature;
        if(pe!=0x4550)
        {
            printf("不是有效的PE文件\n");
            delete[] fileBuff;
        }
        pFileHeader= &pNtHeaders->FileHeader;
        printf("pFileHeader->Machine:%x\n",pFileHeader->Machine);
        printf("pFileHeader->NumberOfSections:%d\n",pFileHeader->NumberOfSections);
        printf("pFileHeader->PointerToSymbolTable:%d\n",pFileHeader->PointerToSymbolTable);
        printf("pFileHeader->Characteristics:%x\n",pFileHeader->Characteristics);
        pOptionalHeaders= &pNtHeaders->OptionalHeader;
        PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
        for(int i=0;i<pFileHeader->NumberOfSections;i++)
        {
            char name[9]{0};
            memcpy(name,pSectionHeaders->Name,9);
            printf("区段名称：\n",name);
        }
    }
    delete[] fileBuff;
    CloseHandle(hfile);
    return 0;
}