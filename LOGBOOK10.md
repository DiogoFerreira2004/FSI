# Relatório: Hash Length Extension Attack Lab

## Task 1: Send Request to List Files

### Passo 1: Configuração do Servidor Web
Antes de enviar a requisição ao servidor, foi necessário mapear o domínio www.seedlab-hashlen.com para o endereço IP do container do servidor web, o qual está configurado na máquina virtual com o IP 10.9.0.80.

Para isso, foi necessário editar o arquivo `/etc/hosts` na máquina virtual, adicionando a seguinte linha:

```
10.9.0.80 www.seedlab-hashlen.com
```

Isso garantiu que qualquer requisição ao domínio www.seedlab-hashlen.com fosse direcionada para o servidor web correto, hospedado no container com o IP 10.9.0.80.

![Figura 1](/Images/LOGBOOK10/Task1_image1.png)

![Figura 2](/Images/LOGBOOK10/Task1_image2.png)

Depois, iniciamos o Docker container com a instrução da Figura:

![Figura 3](/Images/LOGBOOK10/Task1_image3.png)

### Passo 2: Construção da Requisição Inicial

A tarefa exigia o envio de uma requisição simples para o servidor para percebermos como é que o servidor respondia ao pedido, onde alguns parâmetros precisavam ser preenchidos. A URL da requisição a ser enviada era:

```
http://www.seedlab-hashlen.com/?myname=<name>&uid=<need-to-fill>&lstcmd=1&mac=<need-to-calculate>
```

Para preencher os campos em falta, seguimos as instruções presentes no guião:

- `myname`: O valor para o nome foi definido como DiogoFerreira.  
- `uid`: O número de identificação (UID) foi retirado do arquivo `key.txt` presente no diretório LabHome. Escolhemos o UID `1004`, que tem a chave associada `88zjxc`.

### Passo 3: Cálculo do MAC

O MAC (Mensagem de Autenticação de Código) é necessário para garantir a integridade e autenticidade da requisição. Para calcular o MAC, concatenamos a chave com os parâmetros da requisição, usando um : entre a chave do utilizador e os parâmetros.

No nosso caso, o valor de Key:R foi:

```
88zjxc:myname=DiogoFerreira&uid=1004&lstcmd=1
```

Esse valor foi então processado com o comando `sha256sum` para gerar o hash, que serve como o MAC:

```
$ echo -n "88zjxc:myname=DiogoFerreira&uid=1004&lstcmd=1" | sha256sum
080b8693d101634644d021c09205aa1d8c48cd4450c2acd68a88f25cce5da909 -
```

### Passo 4: Montagem da Requisição Completa
Com todos os parâmetros preenchidos, a requisição completa para ser enviada ao servidor ficou da seguinte forma:

```
http://www.seedlab-hashlen.com/?myname=DiogoFerreira&uid=1004&lstcmd=1&mac=080b8693d101634644d021c09205aa1d8c48cd4450c2acd68a88f25cce5da909
```

### Passo 5: Envio da Requisição
 
Após construir a URL completa com todos os parâmetros preenchidos corretamente, a requisição foi enviada ao servidor utilizando o navegador. O servidor então processou a requisição e respondeu conforme esperado.

![Figura 4](/Images/LOGBOOK10/Task1_image4.png)

![Figura 5](/Images/LOGBOOK10/Task1_image5.png)


## Task 2: Create Padding

Nesta tarefa o objetivo é perceber como funciona o padding, e calcular o padding correto para a nossa mensagem original. 

Neste caso a estrutura do padding segue a seguinte forma: 

- byte inicial ```0x80```
- zeros ```0x00```
- tamanho da mensagem original como um numero inteiro Big-Endian de 8 bytes

No nosso caso, a mensagem é ``88zjxc:myname=DiogoFerreira&uid=1004&lstcmd=1``, com um tamanho de 45 bytes (45x8=360 bits). Passando este valor para hexadecimal obtemos o valor de ``0x168``.

O block size do SHA-256 é 64 bytes.
Para calcular o padding necessário, fazemos 64-45=19 bytes. Subtraindo o byte inicial e os bytes correspondentes ao tamanho original da mensagem temos 19-3=16 bytes ```0x00```.

Desta forma, obtemos o seguinte url encoded, e já temos a nossa mensagem pronta para a Task 3:

```88zjxc:myname=DiogoFerreira&uid=1004&lstcmd=1%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%68```

## Task 3: The Length Extension Attack

Nesta tarefa vamos gerar o endereço MAC sem o conhecimento da chave.
Usando o MAC da Task1 e adicionando a extra-mensage, mudamos o ficheiro length_ext.c conforme a imagem:

![Figura6](/Images/LOGBOOK10/length_ext.png)

Depois de executar conforme a imagem em baixo geramos um novo endereço MAC: ```cc3360baba9a53c871df6a5f20621367d568210355f74d9b0ff776671c3f8043```.

![Figura7](/Images/LOGBOOK10/task3.png)

Depois construimos o nosso url de acordo de acordo com o padding e o novo endereço MAC:

```
http://www.seedlab-hashlen.com/?myname=DiogoFerreira&uid=1004&lstcmd=1%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%68&download=secret.txt&mac=cc3360baba9a53c871df6a5f20621367d568210355f74d9b0ff776671c3f8043
```


Desta forma, conseguimos com sucesso obter acesso ao conteúdo do ficheiro secret.txt, e, desta forma, confirmar a vulnerabilidade do sistema.

![Figura8](/Images/LOGBOOK10/Captura_de_ecrã_2024-12-02_164533.png)
