
# Trabalho realizado nas Semanas #2 e #3

## Identificação

- Vulnerabilidade: Dados não confiáveis podem injetar scripts executáveis em páginas da web.
- Sistemas/Aplicativos Afetados: Aplicações web que lidam com entrada de usuário e geram conteúdo dinâmico.
- SO: Todas as plataformas que executam navegadores web afetados.
- Explorações: Ignora a política de mesma origem do navegador, executando scripts maliciosos.

## Catalogação

- Data de reporte: Reportado a 28 de agosto de 2024 por Alexey Solovyev​
- Descrição: Vulnerabilidade de Stored XSS no editor de imagens do Concrete CMS, afeta as versões 9.0.0 até 9.3.3
- Gravidade: Classificada como baixa (CVSS v4: 2.1), devido à elevada complexidade de ataque e exigência de privilégios altos
- Bug Bounty: Reportada através da plataforma HackerOne, embora o valor do bounty não tenha sido especificado​

## Exploit

- Reflected XSS: Conteúdo malicioso é refletido imediatamente da solicitação HTTP e executado pelo navegador da vítima.
- Stored XSS: Dados perigosos são armazenados e exibidos posteriormente aos usuários, potencialmente comprometendo usuários privilegiados ou dados sensíveis.
- DOM-based XSS: Injeção no lado do cliente por meio de scripts fornecidos pelo servidor, manipulando o DOM para executar código malicioso.

## Ataques

- British Airways: Em 2018, o Magecart explorou uma vulnerabilidade de XSS, roubando dados de cartões de crédito de 380.000 transações usando um script malicioso.
- Fortnite: Em 2019, uma página insegura com uma vulnerabilidade de XSS colocou em risco 200 milhões de usuários, potencialmente permitindo acesso não autorizado a dados e roubo de sua moeda virtual.
- eBay: De 2015 a 2016, o parâmetro de URL não validado do eBay levou a ataques de XSS, comprometendo contas de vendedores e manipulando listagens de produtos de alto valor.

## Fontes
- [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2024-8291#range-13295579)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [opencve](https://app.opencve.io/cve/CVE-2024-8291)
- [Ataques](https://brightsec.com/blog/xss-attack/)
