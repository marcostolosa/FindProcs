# FindProcs — utilitário Windows para localizar e detalhar processos por nome

**Descrição curta**  
FindProcs é uma ferramenta minimalista e *powerful* para Windows, escrita em C (Unicode / wide APIs). Recebe **um ou mais nomes de executáveis** e retorna uma listagem formatada (estilo `tasklist`) somente dos processos que casam com esses alvos — incluindo PID, PPID, Threads, Prioridade, Caminho completo (quando possível) e Owner (DOMAIN\User). Feita para investigação, troubleshooting e automação.

> **Público-alvo:** administradores, engenheiros de suporte, pesquisadores e operadores de investigação (uso responsável).

---

## Funcionalidades principais
- Aceita múltiplos alvos via parâmetros: `findprocs.exe notepad chrome brave`.
- Normalização inteligente:
  - case-insensitive;
  - aceita com ou sem `.exe` (`notepad` == `notepad.exe`);
  - trim de espaços/CRLF.
- Saída tabular detalhada:
  - **ImageName**, **PID**, **PPID**, **Threads**, **Priority**, **Path**, **Owner**.
- Implementado com APIs Windows wide: `CreateToolhelp32Snapshot`, `Process32FirstW/Process32NextW`, `QueryFullProcessImageNameW`, `OpenProcessToken`, `LookupAccountSidW`.
- Tolerância a permissões: marca `(no-perm)` quando não consegue recuperar Path/Owner.
- Compilável com MSVC e MinGW (instruções abaixo).

---

## Compilação

### Visual Studio (Developer Command Prompt)
```powershell
cl /W4 /EHsc findprocs.c
````

### MinGW (exemplo)

```bash
gcc -Wall -Wextra -municode -o findprocs.exe findprocs.c -ladvapi32
```

> Obs: `-municode` ajuda a usar `wmain`/Unicode em MinGW. O arquivo já define `_CRT_SECURE_NO_WARNINGS` para reduzir warnings sobre `_s` APIs.

---

## Uso

```powershell
# buscar notepad e chrome
findprocs.exe notepad chrome

# aceitar .exe no argumento
findprocs.exe Notepad.exe Brave.exe

# múltiplos alvos
findprocs.exe notepad chrome brave edge
```

Exemplo de saída:

```
ImageName                     PID     PPID    Threads  Priority   Path (if available)                     Owner
---------------------------------------------------------------------------------------------------------------
Notepad.exe                   5092    1234    4        8          C:\Windows\System32\notepad.exe        DESKTOP\User
chrome.exe                    14560   4320    12       8          C:\Program Files\Google\Chrome\...\chrome.exe DOMAIN\User
...
Total encontrados: 3
```

---

## Opções & Comportamento

* Aceita qualquer número de parâmetros; todos são normalizados e usados como *exact name* após normalização.
* Para Path/Owner a ferramenta usa `PROCESS_QUERY_LIMITED_INFORMATION` e `OpenProcessToken`. Processos protegidos/EDR/serviços do sistema podem devolver `(no-perm)` ou `(no-perm-or-protected)`.
* Exit codes:

  * `0` — >= 1 processo encontrado
  * `1` — nenhum processo encontrado
  * `2` — uso incorreto (nenhum argumento)
  * `3` — erro crítico (snapshot/API)

---

## Internals — resumo técnico

1. `wmain` recebe parâmetros em Unicode.
2. Para cada target: trim, lowercase, remove `.exe`.
3. `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` → itera `PROCESSENTRY32W` via `Process32FirstW/Process32NextW`.
4. Para processos que casam:

   * `QueryFullProcessImageNameW` para caminho (quando permitido).
   * `OpenProcessToken` + `GetTokenInformation(TokenUser)` + `LookupAccountSidW` para OWNER (quando permitido).
5. Imprime linha formatada com campos do `PROCESSENTRY32W`.

APIs usadas: `CreateToolhelp32Snapshot`, `PROCESSENTRY32W`, `Process32FirstW`, `Process32NextW`, `OpenProcess`, `QueryFullProcessImageNameW`, `OpenProcessToken`, `GetTokenInformation`, `LookupAccountSidW`.

---

## Segurança, Privacidade e Boas Práticas

* **Uso responsável:** não execute em sistemas alheios sem autorização legal.
* **Permissões:** rodar como Administrador aumenta chance de recuperar Path/Owner.
* **EDR/Proteções:** não tente contornar proteções comerciais; processos protegidos podem negar acesso.
* **Logs:** trate outputs que contenham nomes de usuários ou caminhos como dados sensíveis.

---

## Troubleshooting

* **Nada encontrado:** confirme argumentos, rode `tasklist`, execute como Administrador.
* **Strings corrompidas:** certifique-se que você compilou a versão Unicode (usa `wmain` e `PROCESSENTRY32W`).
* **Avisos MSVC sobre `wcsncpy`/_wcslwr:** `_CRT_SECURE_NO_WARNINGS` está definido; o código já usa variantes `_s` onde apropriado.

---
