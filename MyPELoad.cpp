//By: DorinXL(荡影)

#include <Windows.h>
#include <stdio.h>
DWORD RVA_to_RAW(PIMAGE_NT_HEADERS pnt, DWORD rva) {
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((DWORD)pnt + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < pnt->FileHeader.NumberOfSections; i++) {
        if (rva >= pSection[i].VirtualAddress && rva < (pSection[i].VirtualAddress + pSection[i].SizeOfRawData)) {
            return (rva - pSection[i].VirtualAddress + pSection[i].PointerToRawData);
        }
    }
}

int main(int argc, char* argv[]) {
	char FilePath[] = "E:\\test\\notepad.exe";
	HANDLE hFile = CreateFileA(FilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    if (INVALID_HANDLE_VALUE == hFile || NULL == hMapping || NULL == pbFile)
    {
        printf("\n\t---------- The File Inexistence! ----------\n");
        if (NULL != pbFile)
        {
            UnmapViewOfFile(pbFile);
        }

        if (NULL != hMapping)
        {
            CloseHandle(hMapping);
        }

        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }

        return 0;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbFile;
    printf("==================================PE DOS HEADER===================================");
    printf("\ne_magic: 0x%04X", pDosHeader->e_magic);
    printf("\ne_cblp: 0x%04X", pDosHeader->e_cblp);
    printf("\ne_cp: 0x%04X", pDosHeader->e_cp);
    printf("\ne_crlc: 0x%04X", pDosHeader->e_crlc);
    printf("\ne_cparhdr: 0x%04X", pDosHeader->e_cparhdr);
    printf("\ne_minalloc: 0x%04X", pDosHeader->e_minalloc);
    printf("\ne_maxalloc: 0x%04X", pDosHeader->e_maxalloc);
    printf("\ne_ss: 0x%04X", pDosHeader->e_ss);
    printf("\ne_sp: 0x%04X", pDosHeader->e_sp);
    printf("\ne_csum: 0x%04X", pDosHeader->e_csum);
    printf("\ne_ip: 0x%04X", pDosHeader->e_ip);
    printf("\ne_cs: 0x%04X", pDosHeader->e_cs);
    printf("\ne_lfarlc: 0x%04X", pDosHeader->e_lfarlc);
    printf("\ne_ovno: 0x%04X\n", pDosHeader->e_ovno);
    for (int i = 0; i <= 3; i++) {
       printf("e_res[%d]: 0x%04X   ",i, pDosHeader->e_res[i]);
    }
    printf("\ne_oemid: 0x%04X", pDosHeader->e_oemid);
    printf("\ne_oeminfo: 0x%04X\n", pDosHeader->e_oeminfo);
    for (int i = 0; i <= 9; i++) {
        if (!(i % 4) && i) printf("\n");
        printf("e_res[%d]: 0x%04X   ", i, pDosHeader->e_res2[i]);
    }
    printf("\ne_lfanew: 0x%08X\n", pDosHeader->e_lfanew);

    printf("\n==================================PE NT HEADER===================================");//大小为F8
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pbFile + pDosHeader->e_lfanew);
    printf("\nSignature: 0x%08X", pNtHeader->Signature);

    //NT头的file header
    printf("\n==================================PE FILE HEADER===================================\n");

    printf("Machine: 0x%04X\n", pNtHeader->FileHeader.Machine);
    printf("NumberOfSections: 0x%04X\n", pNtHeader->FileHeader.NumberOfSections);           //文件中存在的节区数量
    printf("TimeDateStamp: 0x%08X\n", pNtHeader->FileHeader.TimeDateStamp);
    printf("PointerToSymbolTable: 0x%08X\n", pNtHeader->FileHeader.PointerToSymbolTable);
    printf("NumberOfSymbols: 0x%08X\n", pNtHeader->FileHeader.NumberOfSymbols);
    printf("SizeOfOptionalHeader: 0x%04X\n", pNtHeader->FileHeader.SizeOfOptionalHeader);   //指出optional header 的大小
    printf("Characteristics: 0x%04X\n", pNtHeader->FileHeader.Characteristics);             //标识文件的属性

    //NT头的optional header
    printf("\n===================================PE OPTIONAL HEADER====================================\n");

    printf("Machine:%04X\n", pNtHeader->OptionalHeader.Magic);
    printf("MajorLinkerVersion:%02X\n", pNtHeader->OptionalHeader.MajorLinkerVersion);
    printf("MinorLinkerVersion:%02X\n", pNtHeader->OptionalHeader.MinorLinkerVersion);
    printf("SizeOfCode:%08X\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("SizeOfInitializedData:%08X\n", pNtHeader->OptionalHeader.SizeOfInitializedData);
    printf("SizeOfUninitializedData:%08X\n", pNtHeader->OptionalHeader.SizeOfUninitializedData);
    printf("AddressOfEntryPoint:%08X\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);            //代码起始位置
    printf("BaseOfCode:%08X\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("BaseOfData:%08X\n", pNtHeader->OptionalHeader.BaseOfData);
    printf("ImageBase:%08X\n", pNtHeader->OptionalHeader.ImageBase);
    printf("SectionAlignment:%08X\n", pNtHeader->OptionalHeader.SectionAlignment);
    printf("FileAlignment:%08X\n", pNtHeader->OptionalHeader.FileAlignment);
    printf("MajorOperatingSystemVersion:%04X\n", pNtHeader->OptionalHeader.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion:%04X\n", pNtHeader->OptionalHeader.MinorOperatingSystemVersion);
    printf("MajorImageVersion:%04X\n", pNtHeader->OptionalHeader.MajorImageVersion);
    printf("MinorImageVersion:%04X\n", pNtHeader->OptionalHeader.MinorImageVersion);
    printf("MajorSubsystemVersion:%04X\n", pNtHeader->OptionalHeader.MajorSubsystemVersion);
    printf("MinorSubsystemVersion:%04X\n", pNtHeader->OptionalHeader.MinorSubsystemVersion);
    printf("Win32VersionValue:%08X\n", pNtHeader->OptionalHeader.Win32VersionValue);
    printf("SizeOfImage:%08X\n", pNtHeader->OptionalHeader.SizeOfImage);
    printf("SizeOfHeaders:%08X\n", pNtHeader->OptionalHeader.SizeOfHeaders);                        //整个PE头大小
    printf("CheckSum:%08X\n", pNtHeader->OptionalHeader.CheckSum);
    printf("Subsystem:%04X\n", pNtHeader->OptionalHeader.Subsystem);
    printf("DllCharacteristics:%04X\n", pNtHeader->OptionalHeader.DllCharacteristics);
    printf("SizeOfStackReserve:%08X\n", pNtHeader->OptionalHeader.SizeOfStackReserve);
    printf("SizeOfStackCommit:%08X\n", pNtHeader->OptionalHeader.SizeOfStackCommit);
    printf("SizeOfHeapReserve:%08X\n", pNtHeader->OptionalHeader.SizeOfHeapReserve);
    printf("SizeOfHeapCommit:%08X\n", pNtHeader->OptionalHeader.SizeOfHeapCommit);
    printf("LoaderFlags:%08X\n", pNtHeader->OptionalHeader.LoaderFlags);
    printf("NumberOfRvaAndSizes:%08X\n", pNtHeader->OptionalHeader.NumberOfRvaAndSizes);            //用来指定最后数组的大小
    char DataDirectoryName[][50] = { "EXPORT Directory","IMPORT Directory","RESOURCE Directory","EXCEPTION Directory","SECURITY Directory","BASERELOC Directory",
        "DEBUG Directory","COPYRIGHT Directory","GLOBALPTR Directory","TLS Directory","LOAD_CONFIG Directory","BOUND_IMPORT Directory","IAT Directory","DELAY_IMPORT Directory",
        "COM_DESCRIPTOR Directory","Reserved Directory" };
    for (int i = 0; i < pNtHeader->OptionalHeader.NumberOfRvaAndSizes; i++) {
        printf("%s : 0x%08X    0x%08X\n", DataDirectoryName[i], pNtHeader->OptionalHeader.DataDirectory[i].VirtualAddress,pNtHeader->OptionalHeader.DataDirectory[i].Size);
    }

    //节区表
    printf("\n===================================PE SECTION HEADER====================================\n\n");
    //PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        printf("--------------stction %d--------------\n\n",i+1);
        for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
            printf("%c", pSectionHeader->Name[j]);
        }//name的名称可能和实际作用没什么联系
        printf("      0x");
        for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
            printf("%X", pSectionHeader->Name[j]);
        }
        printf("\nVirtualSize : 0x%04X", pSectionHeader->Misc.VirtualSize);                 //内存中节区所占大小
        printf("\nVirtualAddress : 0x%08X", pSectionHeader->VirtualAddress);                //内存中节区起始地址
        printf("\nSizeOfRawData : 0x%08X", pSectionHeader->SizeOfRawData);                  //磁盘文件节区所占大小
        printf("\nPointerToRawData : 0x%08X", pSectionHeader->PointerToRawData);            //磁盘文件中节区起始位置
        printf("\nPointerToRelocations : 0x%08X", pSectionHeader->PointerToRelocations);
        printf("\nPointerToLinenumbers : 0x%08X", pSectionHeader->PointerToLinenumbers);
        printf("\nNumberOfRelocations : 0x%04X", pSectionHeader->NumberOfRelocations);
        printf("\nNumberOfLinenumbers : 0x%04X", pSectionHeader->NumberOfLinenumbers);
        printf("\nCharacteristics : 0x%08X", pSectionHeader->Characteristics);
        pSectionHeader++;
        printf("\n\n");
    }

    printf("\n===================================PE IMPORT====================================\n");
    DWORD pImportOffset = RVA_to_RAW(pNtHeader,pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pbFile + pImportOffset);
    while (1) {
        if (pImport->FirstThunk == 0 && pImport->ForwarderChain == 0 && pImport->Name == 0 && pImport->OriginalFirstThunk == 0 && pImport->TimeDateStamp == 0) {
            break;
        }
        //DWORD dwINT = (DWORD)pbFile + RVA_to_RAW(pNtHeader, pImport->OriginalFirstThunk);
        DWORD dwINT =  (DWORD)pbFile + RVA_to_RAW(pNtHeader, pImport->OriginalFirstThunk);
        //PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pbFile + RVA_to_RAW(pNtHeader, pImport->OriginalFirstThunk));
        DWORD dwTimeDateStamp = (DWORD)pbFile + RVA_to_RAW(pNtHeader, pImport->TimeDateStamp);
        DWORD dwForwarderChain = (DWORD)pbFile + RVA_to_RAW(pNtHeader, pImport->ForwarderChain);
        DWORD dwName = (DWORD)pbFile + RVA_to_RAW(pNtHeader, pImport->Name);
        DWORD dwFirstThunk = (DWORD)pbFile + RVA_to_RAW(pNtHeader, pImport->FirstThunk);
        //printf("%08X", pImportOffset);
        printf("------------------- %s -------------------\n",dwName);
        printf("TimeDateStamp: 0x%08X\n", pImport->TimeDateStamp);
        printf("ForwarderChain: 0x%08X\n", pImport->ForwarderChain); 
        //while (dwINT) {
        //printf("pImport->OriginalFirstThunk: 0x%X\n", pImport->OriginalFirstThunk);
        //printf(" pImport->Name: 0x%s\n", pImport->Name);
        printf("pImport->FirstThunk: 0x%X\n", pImport->FirstThunk);
        //printf("dwINT: 0x%X\n", dwINT);
        //printf("RVA_to_RAW(pNtHeader, pImport->OriginalFirstThunk) : 0x%X \n", RVA_to_RAW(pNtHeader, pImport->OriginalFirstThunk));
            //PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pbFile + RVA_to_RAW(pNtHeader, dwINT));
            //printf("pImportByName： 0x%0X\n", pImportByName);
        //DWORD ImportByName = ((DWORD)pbFile + RVA_to_RAW(pNtHeader, dwINT));
        //printf("RVA_to_RAW(pNtHeader, dwINT) : 0x%X \n", RVA_to_RAW(pNtHeader, dwINT));
        DWORD* ImportByName = (DWORD*)dwINT;
        DWORD* pFirstThunk = (DWORD*)dwFirstThunk;
        //printf("importByName： 0x%X\n", ImportByName);
        //printf("importByName： 0x%X\n", ImportByName[0]);
        int i = 0;
        printf("\nAddress\t\tHint\tName\n");
        while ((ImportByName[i])) {
            PIMAGE_IMPORT_BY_NAME pImpoetByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pbFile + RVA_to_RAW(pNtHeader, ImportByName[i]));
            printf("0x%04X\t", pFirstThunk[i]);
            printf("0x%04X\t",pImpoetByName->Hint);
            printf("%s\n", pImpoetByName->Name);
            i++;
        }
        //DWORD* pImportByName = (DWORD*)ImportByName;
        //printf("pimportbyname[0] : 0x%X \n", *pImportByName);
            dwINT++;
        //}

        pImport++;
    }



    printf("\n===================================PE EXPORT====================================\n");
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pbFile + RVA_to_RAW(pNtHeader, pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
    printf("Characteristics : 0x%X\n", pExport->Characteristics);
    printf("TimeDateStamp : 0x%X\n", pExport->TimeDateStamp);
    printf("MajorVersion : 0x%X\n", pExport->MajorVersion);
    printf("MinorVersion : 0x%X\n", pExport->MinorVersion);
    printf("Base : 0x%X\n", pExport->Base);
    printf("NumberOfNames: %d\n", pExport->NumberOfNames);
    printf("NumberOfFunctions: %d\n", pExport->NumberOfFunctions);
    DWORD* AddressOfFunctions = (DWORD*)((DWORD)pbFile + RVA_to_RAW(pNtHeader, pExport->AddressOfFunctions));
    DWORD* AddressOfNameOrdinals = (DWORD*)((DWORD)pbFile + RVA_to_RAW(pNtHeader, pExport->AddressOfNameOrdinals));
    DWORD* AddressOfNames = (DWORD*)((DWORD)pbFile + RVA_to_RAW(pNtHeader, pExport->AddressOfNames));
    DWORD* Name = (DWORD*)((DWORD)pbFile + RVA_to_RAW(pNtHeader, pExport->Name));
    WORD* pwOrdinals = (WORD*)((DWORD)pbFile + RVA_to_RAW(pNtHeader, pExport->AddressOfNameOrdinals));

    if (pExport->NumberOfFunctions == 0) {
        printf("\n\t---------- No Export Tabel! ----------\n");
        if (NULL != pbFile)
        {
            UnmapViewOfFile(pbFile);
        }

        if (NULL != hMapping)
        {
            CloseHandle(hMapping);
        }

        if (INVALID_HANDLE_VALUE != hFile)
        {
            CloseHandle(hFile);
        }

        return 0;
    }

    for (int i = 0; i < pExport->NumberOfNames; i++) {
        DWORD dwName = (DWORD)pbFile + RVA_to_RAW(pNtHeader, AddressOfNames[i]);
        DWORD VA = pNtHeader->OptionalHeader.ImageBase + AddressOfFunctions[i];
        printf("Ordinals: %d\tName: %-30s\tRVA: 0x%08X\tVA: 0x%08X\n", pwOrdinals[i], dwName, AddressOfFunctions[i], VA);
    }




    if (NULL != pbFile)
    {
        UnmapViewOfFile(pbFile);
    }

    if (NULL != hMapping)
    {
        CloseHandle(hMapping);
    }

    if (INVALID_HANDLE_VALUE != hFile)
    {
        CloseHandle(hFile);
    }
    return 0;
    
}

//一起学习，一起进步鸭