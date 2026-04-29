#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <winternl.h>

typedef struct _LDR_DATA_TABLE_ENTRY_FULL { // recriar struct pois basedllname nao existe na ldr data table entry padrao                                                  
    LIST_ENTRY InLoadOrderLinks;            // portanto e necessario criar essa struct pra acessar esse campo ja existente 
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase; 
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName; //C:\Windows\System32\kernel32.dll - exemplo de output
    UNICODE_STRING BaseDllName; //kernel32.dll  - exemplo de output
} LDR_DATA_TABLE_ENTRY_FULL;
/* typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    // PARA AQUI — BaseDllName não existe
} LDR_DATA_TABLE_ENTRY;*/ 
typedef struct _PEB_LDR_DATA_FULL { //necessario criar struct full pois a struct padrao do LDR atraves do winternl 
    ULONG Length;                   // é incompleta e nao traz "InLoadOrderModuleList" consequentemente tendo que fazer um calculo 
    BOOLEAN Initialized;            // não necessario para acessar o inicio do array
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL;
/*typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
*/

typedef struct _PEB_FULL { //mesmo motivo dos anteriores
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    _PEB_LDR_DATA_FULL* Ldr;
} PEB_FULL;


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

int runIAT(std::vector<char>& buffer, IMAGE_NT_HEADERS* nt) { //funcao para percorrer a tabela de imports
  
    //RVA DO Import Table(IAT) 
    auto IAT = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress; // guarda o valor do ponteiro ntheader  apontado para o array DataDirectory indice 1 == Import Table pegando o valor do RVA
    DWORD IatOffset = rvaToOffset(nt, IAT); // converte rva do iat em offset
    std::cout << "Import Table(IAT) RVA:    0x" << std::hex << IAT << std::endl;
    std::cout << "Import Table(IAT) offset: 0x" << std::hex << IatOffset << "\n\n";

    //LISTA DE TODOS OS IMPORTS - percorrimento dentro de IAT
   
    // cada entrada IID representa uma DLL importada, a lista termina quando N ame == 0
    auto iid = (IMAGE_IMPORT_DESCRIPTOR*)(buffer.data() + IatOffset);  // joga na variavel iid um ponteiro do tipo iMAGEE_IMPORT_DESCRIPTOR pegando o inicio do bufffer da dll e somandoo o offset de import table

    while (iid->Name != 0) { //enquanto IMAGE_IMPORT_DESCRIPTOR->NAME nao chegar  no 0
        DWORD NameOffset = rvaToOffset(nt, iid->Name); // Name e um RVA para o nome da DLL em ASCII
        std::string dllName = (char*)(buffer.data() + NameOffset); //cria uma variavel string pegando o inicio da dll atraves do ponteiro buffer.data e somando offset para conseguir o nome da dll

        std::cout << "DLL_Name: " << dllName << std::endl;

        if (iid->OriginalFirstThunk != 0) { // se iid apontado pra originalfirthunk for difeente de 0, entao existe uma lista de funcoes importada
                                           // originalfirsth thunk aponta pro array thunks e cada thunk eh uma funcao importada na dll especifica
                                           // OriginalFirstThunk aponta para um array de IMAGE_THUNK_DATA
                                           // cada elemento do array representa uma funcao importada
            DWORD Image_Thunk_DataOffset = rvaToOffset(nt, iid->OriginalFirstThunk); //  iid é um ponteiro  para  IMAGE_IMPORT_DESCRIPTOR que  contem o campo  OriginalFirstThunk, transforma esse rva em offset e armazena na variavel
            auto itd = (IMAGE_THUNK_DATA*)(buffer.data() + Image_Thunk_DataOffset); // cria uma variavel ponteiro itd  com o tipo IMAGE_THUNK_DATA apontada pro inicio de IMAGE_THUNK_DATA somando o  buffer.data() com o offset da variavel Image_Thunk_DataOffset(guarda entrada de thunks e cada entrada é uma funcao importada ou variavel de outra dll)

            // percorre o array de thunks ate encontrar o elemento zerado (fim da lista)
            while (itd->u1.AddressOfData != 0) {
                // u1.AddressOfData e um RVA para IMAGE_IMPORT_BY_NAME
                // IMAGE_IMPORT_BY_NAME contem o hint e o nome da funcao importada
                DWORD Image_Import_By_NameOffset = rvaToOffset(nt, itd->u1.AddressOfData); // itd aponta para struct e busca dentro da struct o u1.AddressOfData que é um RVA, depois a funcao transforma em offset e armazena na variavel
                auto iibn = (IMAGE_IMPORT_BY_NAME*)(buffer.data() + Image_Import_By_NameOffset); //cria uma variavel com o cast de um ponteiro para uma struct, armazena o endereco  onde comeca a struct no buffer pegando a posicao de buffer.data() e somando com o offset (incio de IMAGE_IMPORT_BY_NAME)
                std::cout << "Functions import:" << iibn->Name << std::endl;// iibn é um ponteiro que contem o endereco do inicio da struct, iibn -> Name busca dentro da struct o campo Name 
                itd++; // avanca para o proximo thunk(funcao ou variavel importada)
            }
            std::cout << "\n";
        }
    
        iid++; // avanca para a proxima DLL importada

    }
    return 0;

}


int resolveIAT(std::vector<char>& buffer, IMAGE_NT_HEADERS* nt, LPVOID base_address) {
    auto pebFULL = (PEB_FULL*)__readgsqword(0x60); // variavel que guarda um ponteiro pro registrador do peb do tipo struct criado no inicio do script
    //auto peb = (PEB*)__readgsqword(0x60);
    auto ldr = (_PEB_LDR_DATA_FULL*)pebFULL->Ldr; //variavel que guarda um ponteiro do tipo _PEB_LDR_DATA_FULL(struct criada no inicio do script) que aponta para o campo ldr da struct PEB FULL
    auto IAT = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress; //variavel que guarda o RVA do import table no array dataDirectory dentro de nt header->Optionalheader
    DWORD IatOffset = rvaToOffset(nt, IAT); // converte RVA do import table para offset 
    auto iid = (IMAGE_IMPORT_DESCRIPTOR*)(buffer.data() + IatOffset); // variavel que guarda o endereco do inicio da import table
    HMODULE hDll = nullptr; // guarda o DllBase(endereco do inicio da dll) da DLL encontrada no PEB, inicia como nullptr


    while (iid->Name != 0) { //enquanto a RVA dos imports != de 0
        DWORD NameOffset = rvaToOffset(nt, iid->Name); //transforma RVA dos imports em offset
        LPCSTR dllName = (char*)(buffer.data() + NameOffset); // variavel que contem o endereco do nome da dll
        auto current = ldr->InLoadOrderModuleList.Flink; //variavel que guarda o inicio dos modulos carregados no processo
        auto end = &ldr->InLoadOrderModuleList;// variavel que guarda o fim da lista de modulos carregados

        wchar_t nomeDllwide[MAX_PATH]; //cria uma variavel wchar, wchar = dobro de bytes de um char=1byte normal, por padrao char e ascii, wchar=2bytes tem suporte para utf-16/unicode
        MultiByteToWideChar(CP_ACP, 0, dllName, -1, nomeDllwide, 260);// convertendo dllname char para wchar

        while (current != end) { //enquanto modulo atual for diferente do modulo final 
            auto entry = (_LDR_DATA_TABLE_ENTRY_FULL*)(current); // cria variavel ponteiro apontando pro endereco dentro de current
                                                                // cast de current para a struct completa do modulo
                                                                // permite acessar os campos DllBase e BaseDllName do modulo atual
            
            if (_wcsicmp(entry->BaseDllName.Buffer, nomeDllwide) == 0) { // se a comparacao entre o valor do endereco da BaseDllName e nome da Dll wchar_T forem iguais( igual a 0) entao faca

                hDll = (HMODULE)entry->DllBase; // joga pra variavel hDll o endereco da dll
                break;
            }
            current = current->Flink; //pula para o proximo da lista
        }

   
        auto orig = (IMAGE_THUNK_DATA*)(buffer.data() + rvaToOffset(nt, iid->OriginalFirstThunk)); // cria uma variavel com o endereco do primeiro thunk
        auto iat = (IMAGE_THUNK_DATA*)((BYTE*)base_address + iid->FirstThunk); // aponta para o slot da IAT na memoria alocada onde sera escrito o endereco real da funcao
                                                                                // FirstThunk e o RVA do array de slots na IAT
                                                                                // base_address + FirstThunk = endereco do slot na memoria mapeada
        if (hDll == nullptr) {
            std::cout << "ERRO: DLL nao encontrada no PEB:" << dllName << "\n";
            iid++;
            continue; // pula para a proxima DLL
        }
        while (orig->u1.AddressOfData != 0) {// enquanto ainda existir funcao no array (!= 0) faca

            DWORD Image_Import_By_NameOffset = rvaToOffset(nt, orig->u1.AddressOfData); // converte RVA para Offset do addressofdata
            auto iibn = (IMAGE_IMPORT_BY_NAME*)(buffer.data() + Image_Import_By_NameOffset); // cria o cast para acessar o campo name da funcao, contem 2 campos:
                                                                                            // Hint — indice da funcao na export table (usado para otimizacao)
                                                                                            // Name — nome da funcao em ASCII ex: "MessageBoxA"
            
            FARPROC funcAddr = GetProcAddress(hDll, iibn->Name); // getprocaddres retorna o endereco da funcao e passa para a variavel
            *(ULONGLONG*)iat = (ULONGLONG)funcAddr;
            // escreve o endereco real da funcao no slot da IAT na memoria mapeada
            // agora quando a DLL chamar essa funcao, ela vai encontrar o endereco correto

            if (funcAddr == nullptr) {
                std::cout << "ERRO: funcao nao resolvida: " << iibn->Name << "\n";

            }

            orig++;// pula pro proximo thunk
            iat++; // pula pro proximo slot
        }
        iid++; //pula pro proximo rva da lista de imports
    }

    //int runEAT() {}
    
    
   
    

    return 0;
}


    
//C:\Users\dudue\source\repos\Estudo_LoaderDLL\x64\Debug

int runPE() {
    LoadLibraryA("user32.dll");
    std::ifstream file("C:\\Users\\dudue\\source\\repos\\Estudo_LoaderDLL\\x64\\Debug\\TESTDll.dll", std::ios::binary); //abre arquivo da dll em modo binario
    if (!file) { //verifica se o file e false, se for false significa que o arquivo nao foi aberto corretamente, entao imprime a mensagem de erro e retorna 1 para apontar um erro ao completar a execucao
        std::cout << "Erro ao abrir DLL\n";
        return 1;
    }


    //cria um vetor de char para armazenar o conteudo da dll, buffer inicio = istreambuf_iterator<char>(file), buffer fim = istreambuf_iterator<char>() que representa o final do arquivo, entao o vetor de char vai conter todo o conteudo da dll 
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    
    auto dos = (IMAGE_DOS_HEADER*)buffer.data(); //cria um ponteiro que guarda o endereco, ele aponta para o inicio da struct IMAGE_DOS_HEADER

    // para acessar o stub, basta pegar o endereço do buffer e somar o tamanho do header do image_dos (quase nunca é necessario acessar o stub)
    // char* stub = buffer.data() + sizeof(IMAGE_DOS_HEADER);

    //verificar se a dll é um MZ valido
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { //MZ é o signature do header do image_dos
        //e_magic é o campo do header do image_dos que contém o signature, e deve ser igual a MZ (0x5A4D) para ser um MZ valido
        std::cout << "Nao eh um MZ valido\n";  //e_magic e o inicio do header do image_dos, e o signature é o primeiro campo do header do image_dos, então basta verificar se o valor do campo e_magic é igual a MZ (0x5A4D) para verificar se é um MZ valido
        return 1; //retorna 1 para apontar um erro ao completar a execucao
    }
    //cria um ponteiro que guarda o endereco do inicio da struct IMAGE_NT_HEADERS 
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
    DWORD ep = nt->OptionalHeader.AddressOfEntryPoint; // guarda o valor de  RVA do entrypoint na variavel ep
   
    DWORD epOffset = rvaToOffset(nt, ep); // converte o RVA do entrypoint para offset 
    if (ep == 0) {
        std::cout << "Não tem entrypoint ! \n\n";
    }
    else{
    std::cout << "EntryPoint RVA:    0x" << std::hex << ep << std::endl;
    std::cout << "EntryPoint Offset: 0x" << std::hex << epOffset << "\n\n";
    }

    //funcao pra listar os imports (IAT)
    runIAT(buffer, nt);
    //LISTA DE TODOS OS EXPORTS

    //RVA DO Export Table
    auto IDEE = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD IedOffset = rvaToOffset(nt, IDEE);

    //CAST DO IMAGE_EXPORT_DIRECTORY
    auto ied = (IMAGE_EXPORT_DIRECTORY*)(buffer.data() + IedOffset);
    // AddressOfNames e um RVA para um array de RVAs, cada um apontando para o nome de uma funcao exportada
    auto AddressofNameOffset = rvaToOffset(nt, ied->AddressOfNames);
    auto namesArrayRVA = (DWORD*)(buffer.data() + AddressofNameOffset); // cast para DWORD* para indexar o array
    if (IDEE != 0) {
        for (int i = 0; i < ied->NumberOfNames;i++) {
            // namesArrayRVA[i] e o RVA do nome da funcao i, converte para offset e le como string ASCII
            DWORD namesArrayOffset = rvaToOffset(nt, namesArrayRVA[i]);

            std::cout << "Name of Exports: " << (char*)(buffer.data() + namesArrayOffset) << std::endl;
        }
    }
    else {
        std::cout << "Sem Exports!\n";
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

