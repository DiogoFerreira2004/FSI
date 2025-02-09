# CTF Semana #7 (XSS)

Este documento apresenta as etapas seguidas para a realização de um ataque web utilizando cross-site scripting (XSS).

## 1. Reconhecimento

A página web que estamos a tentar atacar trata-se de um serviço copyparty. Analisando os diferentes conteúdos, encontramos um ficheiro com o nome de `flag.txt` que é o que achamos que vai ter a flag (Figura 1).

![Figura 1](/Images/CTF7/Figura1.png)

Figura 1: localização do ficheiro `flag.txt` no serviço copyparty.

Abrindo este ficheiro conseguimos perceber que só vamos conseguir aceder ao seu conteúdo utilizando JavaScript para fazer um ataque (Figura 2).

![Figura 2](/Images/CTF7/Figura2.png)

Figura 2: conteúdo inicial do ficheiro `flag.txt`.

## 2. Pesquisa por Vulnerabilidades

Como mencionado, a página web trata-se de um serviço copyparty. Assim, pesquisamos no google por vulnerabilidades do tipo XSS associadas a este tipo de serviços. 

Encontramos a vulnerabilidade [CVE-2023-38501](https://www.cve.org/CVERecord?id=CVE-2023-38501), associada a serviços copyparty com versões inferiores à 1.8.1. Analisando a versão do serviço da nossa página web, podemos concluir que deverá estar vulnerável a esta CVE (Figura 3).

![Figura 3](/Images/CTF7/Figura3.png)

Figura 3: versão do serviço copyparty da página web explorada.

Esta vulnerabilidade permite fazer um ataque de Cross-Site Scripting (XSS) através dos parâmetros `?k304=...` e `?setck=...`. Isto permite que o atacante consiga executar código javascript malicioso, induzindo os users a carregar num link malicioso.

## 3. Escolha da Vulnerabilidade

Ao tentarmos injetar código javascript na nossa página web através do parâmetro `?k304=...`, conseguimos de facto detetar que o nosso sistema estava vulnerável à CVE mencionada anteriormente:

```
http://ctf-fsi.fe.up.pt:5007/?k304=y%0D%0A%0D%0A%3Cimg+src%3Dcopyparty+onerror%3Dalert(1)%3E
```

O output está apresentado na Figura 4.

![Figura 4](/Images/CTF7/Figura4.png)

Figura 4: deteção da exposição à CVE-2023-38501.

## 4. Encontrar um Exploit

O passo seguinte foi construir código javascript malicioso para que, se o user carregasse no botão, fizesse o download do conteúdo correto do ficheiro `flag.txt`.

```
<a hidden='true' href='flag.txt' download='flag.txt' id='downloadLink' onclick='this.click()'>Get the Flag!!!</a>
```

- `hidden='true'`: torna o link invisível na interface do user.
- `href='flag.txt'`: path do ficheiro que queremos fazer download.
- `download='flag.txt'`: diz ao browser para inciar o download do ficheiro ao carregar no link. 
- `onclick='this.click()'`: simula um click manual no próprio elemento, mesmo que o link esteja oculto.
- `"Get the Flag!!!"`: este texto está visível e atrai o user a interagir com o link.  

## 5. Explorar a Vulnerabilidade

Colocando o código javascript anterior no url através do parâmetro `?k304=...`

```
http://ctf-fsi.fe.up.pt:5007/?k304=y%0D%0A%0D%0A<a+href%3D'flag.txt'>Get+the+Flag!!!<%2Fa><a+hidden%3D'true'+href%3D'flag.txt'+download%3D'flag.txt'+id%3D'downloadLink'+onclick%3D'this.click()'>Get+the+Flag!!!<%2Fa>
```

geramos a página apresentada na Figura 5.

![Figura 5](/Images/CTF7/Figura5.png)

Figura 5: texto clicável para fazer o download do conteúdo do ficheiro `flag.txt`.

Ao carregar em "Get the Flag" conseguimos determinar que a flag deste CTF é `flag{youGotMeReallyGood}` como vemos na Figura 6.

![Figura 6](/Images/CTF7/Figura6.png)

Figura 6: conteúdo do ficheiro `flag.txt`.