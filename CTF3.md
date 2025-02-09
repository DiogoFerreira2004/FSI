# CTF Semana #3

Este documento apresenta as etapas seguidas para a detecção de uma vulnerabilidade para efetuar login como administrador no servidor WordPress http://143.47.40.175:5001, utilizando uma CVE com exploit conhecido. Descreve ainda como se obteve o acesso como administrador na página, demonstrando a falha de segurança detetada.

## 1. Reconhecimento

A primeira etapa foi o reconhecimento da instância WordPress, através da recolha das seguintes informações:

- A versão do WordPress e os plugins instalados, juntamente com a sua versão, estão disponíveis na secção *Additional Information* da página http://143.47.40.175:5001/product/wordpress-hosting/.

- Possíveis utilizadores da página podem ser encontrados na secção *Recent Comments*: Orval Sanford e admin.

Estas informações podem ser observadas na Figura 1.

![Reconhecimento de Vulnerabilidades](/Images/CTF3/Figure1.png)

*Figura 1: Reconhecimento de Vulnerabilidades*


## 2. Pesquisa por Vulnerabilidades

Com a informação identificada na Etapa 1, utilizou-se a base de dados disponível em https://cve.mitre.org para verificar se o software tem alguma vulnerabilidade conhecida.

Pesquisou-se por "Wordpress 5.8.1", "MStore API 3.9.0", "WooCommerce plugin 5.7.1" e "Booster for WooCommerce plugin".


## 3. Escolha da Vulnerabilidade

Para o objetivo proposto neste trabalho de fazer login como administrador num servidor Wordpress, foram encontradas 3 CVEs relevantes para a versão 3.9.0 do plugin *MStore API*, como se observa na Figura 2.

![Escolha da Vulnerabilidade](/Images/CTF3/Figure2.png)

*Figura 2: CVEs relevantes para o plugin MStore API 3.9.0*

A CVE correta foi detetada como **flag{CVE-2023-2732}**.


## 4. Encontrar um Exploit

Após a identificação da CVE correta, foi utilizado o Google para localizar uma exploit conhecida.

Foi encontrado o repositório no GitHub https://github.com/ThatNotEasy/CVE-2023-2732/tree/main, que disponibiliza a ferramenta *MStore WordPress APIs Vulnerable Scanner* que permite explorar a CVE contra o servidor.


## 5. Explorar a Vulnerabilidade

Após instalação e configuração da ferramenta com o servidor de Wordpress em análise, foi possível utilizar a exploit contra o servidor. 

Assim, como mostra a Figura 3, foi detetado o utilizador *admin*, com id = 1, e foi possível fazer login como administrador, utilizando o url http://143.47.40.175:5001//wp-json/wp/v2/add-listing?id=1, fornecido pela ferramenta.  

![Explorar a Vulnerabilidade](/Images/CTF3/Figure3.png)

*Figura 3: Ferramenta MStore WordPress APIs Vulnerable Scanner executada para o servidor Wordpress em análise*

Através da exploração da página, identificou-se na secção *Posts* o post privado "Message to our employees". Ao abrir esse post, visível na Figura 4, foi encontrada a segunda flag necessária para o CTF - **{byebye}**.

![Explorar a Vulnerabilidade](/Images/CTF3/Figure4.png)

*Figura 4: Mensagem privada visível apenas para o utilizador admin*