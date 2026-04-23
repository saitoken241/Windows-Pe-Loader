#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
//FORMATO PE = header do image_dos -> dos_stub -> header do image_nt -> section_header -> section 

// converte um RVA (endereco relativo a ImageBase) para um offset real no arquivo em disco
int rvaToOffset(IMAGE_NT_HEADERS* nt, DWORD RVA) {
    auto section = IMAGE_FIRST_SECTION(nt);


    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {

        DWORD sectionStart = section[i].VirtualAddress; // Calcula o inicio da section atraves do RVA
        DWORD sectionEnd = sectionStart + section[i].Misc.VirtualSize; //Calcula fim da sessao atraves do RVA+SIZE da section

        // verifica se o RVA alvo esta dentro do intervalo desta secao
        if (RVA >= sectionStart && RVA < sectionEnd) {
            // offset no arquivo = inicio da secao no arquivo + deslocamento dentro da secao
            return section[i].PointerToRawData + (RVA - sectionStart);
        }
    }
    return 0; // RVA não encontrado em nenhuma seção
}

int runIAT(std::vector<char>& buffer, IMAGE_NT_HEADERS* nt) {
  
    //RVA DO Import Table(IAT) = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    auto IAT = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD IatOffset = rvaToOffset(nt, IAT);
    std::cout << "Import Table(IAT) RVA:    0x" << std::hex << IAT << std::endl;
    std::cout << "Import Table(IAT) offset: 0x" << std::hex << IatOffset << "\n\n";

    //LISTA DE TODOS OS IMPORTS 
    //CAST DO IMAGE_IMPORT_DESCRIPTOR = IID
    // cada entrada IID representa uma DLL importada, a lista termina quando Name == 0
    auto iid = (IMAGE_IMPORT_DESCRIPTOR*)(buffer.data() + IatOffset);

    while (iid->Name != 0) {
        DWORD NameOffset = rvaToOffset(nt, iid->Name); // Name e um RVA para o nome da DLL em ASCII
        std::string dllName = (char*)(buffer.data() + NameOffset);

        std::cout << "DLL_Name: " << dllName << std::endl;

        if (iid->OriginalFirstThunk != 0) {
            // OriginalFirstThunk aponta para um array de IMAGE_THUNK_DATA
            // cada elemento do array representa uma funcao importada
            DWORD Image_Thunk_DataOffset = rvaToOffset(nt, iid->OriginalFirstThunk);
            auto itd = (IMAGE_THUNK_DATA*)(buffer.data() + Image_Thunk_DataOffset);

            // percorre o array de thunks ate encontrar o elemento zerado (fim da lista)
            while (itd->u1.AddressOfData != 0) {
                // u1.AddressOfData e um RVA para IMAGE_IMPORT_BY_NAME
                // IMAGE_IMPORT_BY_NAME contem o hint e o nome da funcao importada
                DWORD Image_Import_By_NameOffset = rvaToOffset(nt, itd->u1.AddressOfData);
                auto iibn = (IMAGE_IMPORT_BY_NAME*)(buffer.data() + Image_Import_By_NameOffset);
                std::cout << "Functions import:" << iibn->Name << std::endl;
                itd++; // avanca para a proxima funcao importada
            }
            std::cout << "\n";
        }
    
        iid++; // avanca para a proxima DLL importada

    }
    return 0;

}

int resolveIAT(std::vector<char>& buffer, IMAGE_NT_HEADERS* nt, LPVOID base_address) {
    auto IAT = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD IatOffset = rvaToOffset(nt, IAT);
    auto iid = (IMAGE_IMPORT_DESCRIPTOR*)(buffer.data() + IatOffset);
    while (iid->Name != 0) {
        DWORD NameOffset = rvaToOffset(nt, iid->Name);
        LPCSTR dllName = (char*)(buffer.data() + NameOffset);
        HMODULE hDll = LoadLibraryA(dllName);
        auto orig = (IMAGE_THUNK_DATA*)(buffer.data() + rvaToOffset(nt, iid->OriginalFirstThunk));
        auto iat = (IMAGE_THUNK_DATA*)((BYTE*)base_address + iid->FirstThunk);
        while (orig->u1.AddressOfData != 0) {
            DWORD Image_Import_By_NameOffset = rvaToOffset(nt, orig->u1.AddressOfData);
            auto iibn = (IMAGE_IMPORT_BY_NAME*)(buffer.data() + Image_Import_By_NameOffset);
            FARPROC funcAddr = GetProcAddress(hDll, iibn->Name);
            *(ULONGLONG*)iat = (ULONGLONG)funcAddr;
            if (funcAddr == nullptr) {
                std::cout << "ERRO: funcao nao resolvida: " << iibn->Name << "\n";

            }
            orig++;
            iat++;
        }
        iid++;
    }
    
   
    

    return 0;
}


    


int runPE() {
    std::ifstream file("C:\\Users\\windowsuser\\Desktop\\windows-pe-parser\\x64\\Debug\\TESTDll.dll", std::ios::binary); //abre arquivo da dll em modo binario
    if (!file) { //verifica se o file e false, se for false significa que o arquivo nao foi aberto corretamente, entao imprime a mensagem de erro e retorna 1 para apontar um erro ao completar a execucao
        std::cout << "Erro ao abrir DLL\n";
        return 1;
    }


    //cria um vetor de char para armazenar o conteudo da dll, buffer inicio = istreambuf_iterator<char>(file), buffer fim = istreambuf_iterator<char>() que representa o final do arquivo, entao o vetor de char vai conter todo o conteudo da dll 
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    //header do image_dos
    auto dos = (IMAGE_DOS_HEADER*)buffer.data();

    // para acessar o stub, basta pegar o endereço do buffer e somar o tamanho do header do image_dos (quase nunca)
    // char* stub = buffer.data() + sizeof(IMAGE_DOS_HEADER);

    //verificar se a dll é um MZ valido
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { //MZ é o signature do header do image_dos
        //e_magic é o campo do header do image_dos que contém o signature, e deve ser igual a MZ (0x5A4D) para ser um MZ valido
        std::cout << "Nao eh um MZ valido\n";  //e_magic e o inicio do header do image_dos, e o signature é o primeiro campo do header do image_dos, então basta verificar se o valor do campo e_magic é igual a MZ (0x5A4D) para verificar se é um MZ valido
        return 1; //retorna 1 para apontar um erro ao completar a execucao
    }
    //inicio do nt_header (PE header)  
    auto nt = (IMAGE_NT_HEADERS*)(buffer.data() + dos->e_lfanew); //e_lfanew é o offset do nt_header a partir do inicio do arquivo

    // verificar se a dll é um PE valido
    if (nt->Signature != IMAGE_NT_SIGNATURE) { // se nt for um PE valido, o campo Signature do nt_header deve ser igual a PE (0x00004550)
        std::cout << "Nao eh um PE valido\n"; // se nao for um PE valido, imprime a mensagem de erro e retorna 1 para apontar um erro ao completar a execucao
        return 1;
    }

    auto ImageBase = nt->OptionalHeader.ImageBase;
    std::cout << "ImageBase:  0x" << std::hex << ImageBase << "\n"; // imprime o ImageBase da dll
    std::cout << "EntryPoint: 0x" << std::hex << nt->OptionalHeader.AddressOfEntryPoint << "\n\n"; // imprime o EntryPoint da dll

    auto section = IMAGE_FIRST_SECTION(nt); // Pega a primeira secao  

    for (int i = 0; i < nt->FileHeader.NumberOfSections;i++) {
        auto& current_section = section[i];
        std::string name((char*)current_section.Name, 8);
        name = name.c_str(); // garante que a string termina no primeiro \0, evitando lixo apos o nome
        auto RVA = current_section.VirtualAddress;
        auto VA = RVA + ImageBase; // VA = RVA + ImageBase (endereco absoluto na memoria)
        auto SIZE = current_section.Misc.VirtualSize;
        auto OFFSET = current_section.PointerToRawData; // offset da secao no arquivo em disco
        DWORD sectionStart = RVA;
        DWORD sectionEnd = sectionStart + SIZE;

        std::cout << name << " | " << "RVA:0x" << std::hex << RVA << " | " << "VA:0x" << VA << " | " << "Offset:0x" << OFFSET << " | " << "Size:0x" << SIZE << "\n\n";



    }
    DWORD ep = nt->OptionalHeader.AddressOfEntryPoint;
    DWORD epOffset = rvaToOffset(nt, ep); // converte o RVA do entrypoint para offset no arquivo
    std::cout << "EntryPoint RVA:    0x" << std::hex << ep << std::endl;
    std::cout << "EntryPoint Offset: 0x" << std::hex << epOffset << "\n\n";

    
    //funcao pra listar os imports (IAT)
    runIAT(buffer,nt);
    //LISTA DE TODOS OS EXPORTS

    //RVA DO Export Table
    auto IDEE = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD IedOffset = rvaToOffset(nt, IDEE);

    //CAST DO IMAGE_EXPORT_DIRECTORY
    auto ied = (IMAGE_EXPORT_DIRECTORY*)(buffer.data() + IedOffset);
    // AddressOfNames e um RVA para um array de RVAs, cada um apontando para o nome de uma funcao exportada
    auto AddressofNameOffset = rvaToOffset(nt, ied->AddressOfNames);
    auto namesArrayRVA = (DWORD*)(buffer.data() + AddressofNameOffset); // cast para DWORD* para indexar o array
    for (int i = 0; i < ied->NumberOfNames;i++) {
        // namesArrayRVA[i] e o RVA do nome da funcao i, converte para offset e le como string ASCII
        DWORD namesArrayOffset = rvaToOffset(nt, namesArrayRVA[i]);

        std::cout << "Name of Exports: " << (char*)(buffer.data() + namesArrayOffset) << std::endl;
    }


    //aloca memoria na imagebase da dll e salva em base_address (LPVOID)ImageBase
    LPVOID base_address = (VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    //se base_addr retornar nullptr volta erro ao alocar na memoria e sai, se nao copia 
    if (base_address == nullptr) {
        std::cout << "Erro ao alocar memoria\n";
        return 1;
    }
    else { 
        std::cout << "\ncopiando o PE header do disco na memoria alocada...\n";
        memcpy(base_address,buffer.data(), nt->OptionalHeader.SizeOfHeaders); //copia pe header do disco na memoria vazia alocada
        std::cout << "copiando as sections na memoria alocada...\n";
        for (int i = 0; i < nt->FileHeader.NumberOfSections;i++) {
            auto& current_section = IMAGE_FIRST_SECTION(nt)[i];
            auto Section_Offset = current_section.PointerToRawData; // offset da secao no arquivo em disco
            memcpy((BYTE*)base_address+current_section.VirtualAddress, buffer.data() + Section_Offset, current_section.SizeOfRawData);
        
        
        }
    
    }
    //calculo do delta
    auto delta = (BYTE*)base_address - nt->OptionalHeader.ImageBase;
    
    auto TableOffset = rvaToOffset(nt, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    //auto ibr = (IMAGE_BASE_RELOCATION*)(buffer.data() + TableOffset); //cast image base relocation
    auto TableSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    BYTE* Table_reloc_start = (BYTE*)(buffer.data() + TableOffset);
    BYTE* Table_reloc_end = Table_reloc_start + TableSize;
    BYTE* current = Table_reloc_start;
  
    //tabela de relocations 
    while (current < Table_reloc_end) {
        auto reloc = (IMAGE_BASE_RELOCATION*)current;
        if (reloc->SizeOfBlock == 0 or reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) or current + reloc->SizeOfBlock > Table_reloc_end) {
            std::cout << "relocation invalida";
            break;
        }
        WORD* entries = (WORD*)(current + sizeof(IMAGE_BASE_RELOCATION));
        auto numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (int i = 0; i < numEntries; i++) {
            auto entry = entries[i];
            auto OFFSET = entry & 0x0FFF;
            auto TYPE = entry >> 12;
            auto addr = (BYTE*)base_address + reloc->VirtualAddress + OFFSET;
            if (TYPE != 3 and TYPE != 10){continue;}
            else {
                std::cout << "\nTYPE:0x" << std::hex << TYPE << " | " << "OFFSET:0x" << OFFSET << " | " << "VA:0x" << (DWORD_PTR)addr << "\n\n";
                if (TYPE == 3) {
                    std::cout << "antes: " << std::hex << *(DWORD*)addr << "\n";
                    DWORD* ptr = (DWORD*)addr;
                    *ptr += (DWORD)delta;
                    std::cout << "depois: " << std::hex << *(DWORD*)addr << "\n";
                }
                else if (TYPE == 10) {
                    std::cout << "antes: " << std::hex << *(ULONGLONG*)addr << "\n";
                    ULONGLONG* ptr = (ULONGLONG*)addr;
                    *ptr += (ULONGLONG)delta;
                    std::cout << "depois: " << std::hex << *(ULONGLONG*)addr << "\n";
                }
            }

            
        }
        current += reloc->SizeOfBlock;


    }
    //chamar resolveiat para inserir os imports na memoria alocada
    resolveIAT(buffer,nt,base_address);

    
    DllMain_t entrypoint = (DllMain_t)((BYTE*)base_address + nt->OptionalHeader.AddressOfEntryPoint);
    
    entrypoint((HINSTANCE)base_address,DLL_PROCESS_ATTACH, nullptr);






    return 0;
}

int main() {

    runPE();

    return 0;
}