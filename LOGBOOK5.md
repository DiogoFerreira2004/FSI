# Relatório: Buffer-Overflow Attack Lab - Set-UID Version

Este documento detalha todo o processo de resolução das tarefas especificadas no guião Buffer-Overflow Attack Lab - Set-UID Version.

Antes de começarmos as tarefas, desligamos alguns dos mecanismos de defesa do sistema operativo que normalmente dificultam o ataque do buffer-overflow:

1. Randomização do Espaço de Endereços

    ```
    $ sudo sysctl -w kernel.randomize_va_space=0
    ```

2. Proibição ao nível da shell de manter permissões elevadas em programas executados com Set-UID

    ```
    $ sudo ln -sf /bin/zsh /bin/sh
    ```

## Task 1: Getting Familiar with Shellcode

Nesta tarefa estudamos o funcionamento do shellcode, uma vez que é um dos métodos mais comuns em ataques de buffer overflow. O objetivo final destes ataques é injetar código malicioso no programa.

O código do ficheiro `call_shellcode.c` contém o programa em C para o shellcode (código que lança uma shell) com as versões em 32-bit e em 64-bit. 

Ao correr o comando `ps`, conseguimos visualizar quais são os processos ativos na sessão atual.

Assim, começamos por compilar o programa `call_shellcode.c` e, antes de corrermos o programa compilado, executamos o comando `ps` para analisar os processos (Figura 1). Observamos que havia 2 processos em execução:

- Um para o `bash`, que é a shell atual;
- Outro para o `ps`, que é a instrução que acabamos de executar.  

![Figura 1](/Images/LOGBOOK5/Task1_image1.png)

*Figura 1: comandos para compilar o `call_shellcode.c` e processos ativos antes de correr o programa.*

Depois corremos os programas `a32.out` (Figura 2) e `a64.out` (Figura 3), resultantes da compilação do `call_shellcode.c`, e o comando `ps`.

![Figura 2](/Images/LOGBOOK5/Task1_image2.png)

*Figura 2: processos ativos depois de correr `a32.out`.*

![Figura 3](/Images/LOGBOOK5/Task1_image3.png)

*Figura 3: processos ativos depois de correr `a64.out`.*

Como se observa nas Figuras 2 e 3 ao correr o comando `ps`, em ambos os casos foi criado um novo processo `sh`, i.e., foi lançada uma nova shell.

## Task 2: Understanding the Vulnerable Program

Nesta tarefa estudamos um programa que tem uma vulnerabilidade de buffer-overflow. 

Começamos por alterar o valor da variável `L1` da `Makefile` disponível na pasta `Labsetup/code` para o valor `100+8*G`, onde G é o número do nosso grupo prático: `G=4` (Figura 4).

![Figura 4](/Images/LOGBOOK5/Task2_image1.png)

*Figura 4: alteração de `L1` no `Makefile`.*

Depois compilamos o programa `stack-L1` com o comando da Figura 5 já com o tamanho do buffer de 132 bytes (valor de L1). 

![Figura 5](/Images/LOGBOOK5/Task2_image2.png)

*Figura 5: comando para compilar `stack-L1`.*

Por fim, verificamos que o programa é um Set-UID utilizando o comando `ll` (Figura 6). O bit `s` na permissão -rwsr-xr-x indica que o programa `stack-L1` tem o bit Set-UID ativado. Assim, o programa vai ser executado com privilégios de root mesmo quando é um user normal a executá-lo.

![Figura 6](/Images/LOGBOOK5/Task2_image3.png)

*Figura 6: verificação que o programa é um Set-UID.*


## Task 3: Launching Attack on 32-bit Program (Level 1)

Começamos por criar um ficheiro `badfile` vazio na pasta `Labsetup/code`:

```
$ touch badfile
```

Como o programa tem uma vulnerabilidade de buffer-overflow, podemos executar o código em modo debug para observarmos a stack e percebermos a distância entre o buffer e a posição do endereço de retorno:

```
$ gdb stack-L1-dbg
```

Já em modo debug, colocamos um breakpoint na função `bof()` (Figura 7):

```
gdb-peda$ b bof
```

![Figura 7](/Images/LOGBOOK5/Task3_image1.png)

*Figura 7: colocação de breakpoint na função `bof()`.*

Executamos o programa até ele parar no breakpoint:

```
gdb-peda$ run
```

Quando atingimos o breakpoint, avançamos no código utilizando o comando `next` até chegarmos à linha vulnerável `strcpy(buffer, str)` (Figura 8).

![Figura 8](/Images/LOGBOOK5/Task3_image2.png)

*Figura 8: linha vulnerável pelo debug.*

Assim, neste momento conseguimos obter o `ebp` e o endereço do início do buffer e podemos calcular a diferença entre os dois, uma vez que vamos precisar desse valor para o *offset* do ficheiro `exploit.py` - Figura 9.

![Figura 9](/Images/LOGBOOK5/Task3_image3.png)

*Figura 9: `ebp` e endereço do início do buffer.*

Depois atualizamos o `exploit.py` com algumas alterações:

1. Alteramos o valor da variável `shellcode` para o shellcode de 32-bits que executa uma shell (que está no ficheiro `call_shellcode.c`):

    ![Figura 10](/Images/LOGBOOK5/Task3_image4.png)

    *Figura 10: alteração da variável `shellcode` no ficheiro `exploit.py`.*

2. Alteramos os valores das variáveis `start`, `ret` e `offset`.

- **start**: indica onde e que o shellcode vai começar a ser inserido. Os primeiros 50 bytes do buffer estão preenchidos com NOPs.
- **ret**: corresponde ao `ebp`.
- **offset**: distância entre o início do buffer e o endereço de retorno: `ebp - buffer + 4`. O ajuste dos 4 bytes deve-se ao endereço de retorno estar armazenado logo acima do valor do ebp na *stack*.

    ![Figura 11](/Images/LOGBOOK5/Task3_image5.png)

    *Figura 11: alteração das variáveis `start`, `ret` e `offset`no ficheiro `exploit.py`.*

Por fim, corremos o `exploit.py`, que gerou o ficheiro `badfile`, e executamos o programa `stack-L1`, que resultou no buffer overflow e lançou uma shell com permissões de root (Figura 12).

![Figura 12](/Images/LOGBOOK5/Task3_image6.png)

*Figura 12: alteração das variáveis `start`, `ret` e `offset`no ficheiro `exploit.py`.*