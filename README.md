# 🔍 Windows Internals — PE Parser → Manual Mapper

Um projeto evolutivo em C++ que começou como um parser do formato PE e evoluiu para um manual mapper completo com PEB Walking, sem depender de APIs de alto nível do Windows.

---

## 🗺️ Evolução do Projeto

```
Etapa 1: PE Parser
      ↓
Etapa 2: Manual Mapper (IAT via LoadLibrary + GetProcAddress)
      ↓
Etapa 3: Manual Mapper + PEB Walking (IAT sem LoadLibrary)
```

---

## 📚 Sobre o Formato PE

O formato PE é o padrão de executáveis no Windows. Todo `.exe`, `.dll` e `.sys` segue essa estrutura:

```
IMAGE_DOS_HEADER → DOS Stub → IMAGE_NT_HEADERS → Section Headers → Sections
```

Este projeto percorre cada uma dessas camadas manualmente, sem depender de loaders ou APIs de alto nível.

---

## 🚀 Etapa 1 — PE Parser

Lê um arquivo `.exe` ou `.dll` diretamente do disco e extrai manualmente as estruturas internas do formato PE.

### Funcionalidades
- ✅ Validação de assinatura **MZ** (`IMAGE_DOS_HEADER`)
- ✅ Validação de assinatura **PE** (`IMAGE_NT_HEADERS`)
- ✅ Exibição de **ImageBase** e **EntryPoint**
- ✅ Listagem de todas as **Sections** com RVA, VA, Offset e Size
- ✅ Conversão de **RVA → Offset em disco** (`rvaToOffset`)
- ✅ Leitura da **Import Table (IAT)** — lista todas as DLLs e funções importadas
- ✅ Leitura da **Export Table** — lista todos os nomes de funções exportadas

### Conceitos Abordados

| Conceito | Descrição |
|---|---|
| `RVA` | Relative Virtual Address — endereço relativo à ImageBase |
| `VA` | Virtual Address — endereço absoluto na memória (`RVA + ImageBase`) |
| `Offset` | Posição física do dado no arquivo em disco |
| `IMAGE_DOS_HEADER` | Cabeçalho legado com a assinatura `MZ` e ponteiro para o NT Header |
| `IMAGE_NT_HEADERS` | Cabeçalho principal do PE com `Signature`, `FileHeader` e `OptionalHeader` |
| `IMAGE_SECTION_HEADER` | Descreve cada seção (`.text`, `.data`, `.rdata`, etc.) |
| `IMAGE_IMPORT_DESCRIPTOR` | Representa uma DLL importada na Import Table |
| `IMAGE_THUNK_DATA` | Array de thunks que aponta para os nomes das funções importadas |
| `IMAGE_IMPORT_BY_NAME` | Estrutura com o `Hint` e o nome ASCII da função importada |
| `IMAGE_EXPORT_DIRECTORY` | Descreve a Export Table com os nomes das funções exportadas |

---

## 🚀 Etapa 2 — Manual Mapper

Carrega uma DLL na memória manualmente, replicando o que o Windows Loader faz internamente — sem chamar `LoadLibrary` para a DLL alvo.

### O que é Manual Map?
É carregar uma DLL na memória sem avisar o Windows. A DLL executa normalmente, mas permanece invisível para ferramentas que listam módulos carregados no processo.

### Funcionalidades adicionadas
- ✅ Alocação de memória com `VirtualAlloc`
- ✅ Mapeamento do PE Header na memória alocada
- ✅ Mapeamento de cada **Section** no endereço correto
- ✅ Aplicação da **Relocation Table** — correção de endereços absolutos com base no delta (`base_address - ImageBase`)
- ✅ Resolução da **IAT** com `LoadLibraryA` + `GetProcAddress`
- ✅ Chamada manual do **EntryPoint** (`DllMain`)

### Conceitos Abordados

| Conceito | Descrição |
|---|---|
| `VirtualAlloc` | Aloca memória com permissões `RWX` para mapear o PE |
| `SizeOfHeaders` | Tamanho do cabeçalho PE copiado para a memória |
| `PointerToRawData` | Offset da seção no arquivo em disco |
| `IMAGE_BASE_RELOCATION` | Estrutura que descreve um bloco de relocations |
| `Delta` | Diferença entre `base_address` real e `ImageBase` original |
| `TYPE 3 / TYPE 10` | Tipos de relocation: 32-bit (HIGHLOW) e 64-bit (DIR64) |
| `FirstThunk` | RVA dos slots da IAT onde os endereços reais são escritos |
| `DllMain` | EntryPoint chamado com `DLL_PROCESS_ATTACH` |

---

## 🚀 Etapa 3 — PEB Walking

Evolução do Manual Mapper: elimina o `LoadLibrary` da resolução da IAT navegando diretamente pelas estruturas internas do Windows.

### O problema da Etapa 2
`LoadLibrary` notifica o Windows e registra o módulo na PEB — exatamente o que um manual mapper tenta evitar. Além disso, é uma chamada WinAPI monitorada por EDRs e anti-cheats.

### O que é PEB Walking?
Em vez de chamar `LoadLibrary`, o código navega diretamente pela estrutura interna do Windows:

```
gs:[0x60] → PEB → Ldr → InLoadOrderModuleList → [módulos carregados]
```

Para cada módulo na lista, compara o `BaseDllName` com o nome da DLL necessária. Ao encontrar, obtém o `DllBase` diretamente — sem nenhuma chamada à WinAPI.

### Funcionalidades adicionadas
- ✅ Acesso direto à **PEB** via `gs:[0x60]`
- ✅ Navegação pela **`InLoadOrderModuleList`** — lista encadeada de módulos carregados
- ✅ Resolução do `DllBase` sem `LoadLibrary`
- ✅ Structs completas recriadas manualmente (`PEB_FULL`, `PEB_LDR_DATA_FULL`, `LDR_DATA_TABLE_ENTRY_FULL`)

### Por que recriar as structs?
As structs do `winternl.h` são intencionalmente incompletas — campos como `BaseDllName` e `InLoadOrderModuleList` não estão expostos. Foi necessário recriar as structs completas para acessar esses campos.

### Conceitos Abordados

| Conceito | Descrição |
|---|---|
| `PEB` | Process Environment Block — estrutura interna do processo |
| `gs:[0x60]` | Registrador que aponta para a PEB em x64 |
| `PEB_LDR_DATA` | Campo do PEB que aponta para a lista de módulos carregados |
| `InLoadOrderModuleList` | Lista duplamente encadeada com todos os módulos do processo |
| `LDR_DATA_TABLE_ENTRY` | Entrada na lista: contém `DllBase`, `BaseDllName`, `FullDllName` |
| `BaseDllName` | Nome do módulo sem o caminho (ex: `kernel32.dll`) |
| `DllBase` | Endereço base da DLL na memória do processo |

### Estado atual da IAT
| Etapa | LoadLibrary | GetProcAddress |
|---|---|---|
| Etapa 2 | ✅ chamado | ✅ chamado |
| Etapa 3 | ❌ removido | ✅ ainda presente |

> **Próximo passo:** substituir `GetProcAddress` por um parser manual da **Export Table (EAT)**, lendo diretamente a `IMAGE_EXPORT_DIRECTORY` da DLL na memória.

---

## 🛠️ Como compilar

### Requisitos
- Windows
- Visual Studio (com suporte a C++)

### Visual Studio
1. Crie um novo projeto **Console Application** em C++
2. Substitua o `main.cpp` pelo código deste repositório
3. Compile em modo **x64** e execute (`Ctrl+F5`)

> ⚠️ O projeto usa `__readgsqword(0x60)` — compatível apenas com x64.

---

## 🚀 Exemplo de saída (Etapa 1 — PE Parser)

```
ImageBase:  0x7fff00000000
EntryPoint: 0x00012345

.text  | RVA:0x1000 | VA:0x7fff00001000 | Offset:0x400  | Size:0xa3200
.rdata | RVA:0xaa000 | VA:0x7fff000aa000 | Offset:0xa7800 | Size:0x1e400
.data  | RVA:0xa5000 | VA:0x7fff000a5000 | Offset:0xa3600 | Size:0x4200

Import Table(IAT) RVA:    0xb1234
Import Table(IAT) offset: 0xaf634

DLL_Name: KERNEL32.dll
Functions import: LoadLibraryA
Functions import: GetProcAddress
Functions import: VirtualAlloc

Name of Exports: AddAtomA
Name of Exports: AddAtomW
```

---

## 📁 Estrutura do código

```
pe_loader/
└── main.cpp
    ├── rvaToOffset()    — converte RVA para offset físico no arquivo
    ├── runIAT()         — lista imports da DLL (Etapa 1)
    ├── resolveIAT()     — resolve imports na memória, com PEB Walking (Etapa 3)
    └── runPE()          — lógica principal: parse, map, relocate, resolve, execute
```

---

## ⚠️ Aviso

Este projeto é **estritamente educacional**. O objetivo é entender como o Windows Loader funciona internamente — base para quem quer trabalhar com desenvolvimento de EDR, análise de malware ou segurança ofensiva.

---

## 📖 Referências

- [Microsoft PE Format Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [corkami/pe-bear](https://github.com/hasherezade/pe-bear) — visualizador de PE
- *Windows Internals* — Mark Russinovich
- [Inside Windows — PEB Structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)

---

## 📄 Licença

MIT License — use, modifique e distribua livremente.
