# 🔍 PE Parser

Um parser manual do formato **Portable Executable (PE)** escrito em C++, sem uso de bibliotecas externas de análise binária. O projeto lê um arquivo `.exe` ou `.dll` diretamente do disco e extrai manualmente as estruturas internas do formato PE.

---

## 📚 Sobre o Formato PE

O formato PE é o padrão de executáveis no Windows. Todo `.exe`, `.dll` e `.sys` segue essa estrutura:

```
IMAGE_DOS_HEADER → DOS Stub → IMAGE_NT_HEADERS → Section Headers → Sections
```

Este projeto percorre cada uma dessas camadas manualmente, sem depender de loaders ou APIs de alto nível.

---

## ✨ Funcionalidades

- ✅ Validação de assinatura **MZ** (`IMAGE_DOS_HEADER`)
- ✅ Validação de assinatura **PE** (`IMAGE_NT_HEADERS`)
- ✅ Exibição de **ImageBase** e **EntryPoint**
- ✅ Listagem de todas as **Sections** com RVA, VA, Offset e Size
- ✅ Conversão de **RVA → Offset em disco** (`rvaToOffset`)
- ✅ Leitura da **Import Table (IAT)** — lista todas as DLLs e funções importadas
- ✅ Leitura da **Export Table** — lista todos os nomes de funções exportadas

---

## 🧠 Conceitos Abordados

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

## 🛠️ Como compilar

### Requisitos
- Windows
- Visual Studio (com suporte a C++) **ou** MinGW/g++

### Visual Studio
1. Crie um novo projeto **Console Application** em C++
2. Substitua o `main.cpp` pelo código deste repositório
3. Compile e execute (`Ctrl+F5`)

### g++ (MinGW)
```bash
g++ -o pe_parser main.cpp
./pe_parser
```

---

## 🚀 Exemplo de saída

```
ImageBase:  0x7fff00000000
EntryPoint: 0x00012345

.text  | RVA:0x1000 | VA:0x7fff00001000 | Offset:0x400  | Size:0xa3200
.data  | RVA:0xa5000 | VA:0x7fff000a5000 | Offset:0xa3600 | Size:0x4200
.rdata | RVA:0xaa000 | VA:0x7fff000aa000 | Offset:0xa7800 | Size:0x1e400

EntryPoint RVA:    0x12345
EntryPoint Offset: 0x11945

Import Table(IAT) RVA:    0xb1234
Import Table(IAT) offset: 0xaf634

dllName: KERNEL32.dll
  LoadLibraryA
  GetProcAddress
  VirtualAlloc
  ...

Name of Exports: AddAtomA
Name of Exports: AddAtomW
Name of Exports: ...
```

---

## 📁 Estrutura do código

```
pe_parser/
└── main.cpp
    ├── rvaToOffset()   — converte RVA para offset físico no arquivo
    └── runPE()         — lógica principal de parsing do PE
```

---

## ⚠️ Aviso

Este projeto é **estritamente educacional**. O objetivo é entender o formato PE internamente — como loaders, debuggers e ferramentas de análise como PE-bear, CFF Explorer e dumpbin funcionam por baixo dos panos.

---

## 📖 Referências

- [Microsoft PE Format Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [corkami/pe-bear](https://github.com/hasherezade/pe-bear) — visualizador de PE
- *Windows Internals* — Mark Russinovich

---

## 📄 Licença

MIT License — use, modifique e distribua livremente.
