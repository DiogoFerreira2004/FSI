# CTF Semana #11 (Weak Encryption)

Este documento descreve as etapas  seguidas para a realização de um ataque para descobrir o conteúdo de um criptograma, explorando uma vulnerabilidade na geração inadequada de chaves simétricas, sem acesso direto à chave utilizada na cifração.

## 1. Reconhecimento

A primeira etapa foi a investigação do ficheiro `cipherspec.py` fornecido no enunciado do CTF para compreender o que está errado na forma como estes algoritmos estão a cifrar:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

KEYLEN = 16

def gen(): 
	offset = 3 # Hotfix to make Crypto blazing fast!!
	key = bytearray(b'\x00'*(KEYLEN-offset)) 
	key.extend(os.urandom(offset))
	return bytes(key)

def enc(k, m, nonce):
	cipher = Cipher(algorithms.AES(k), modes.CTR(nonce))
	encryptor = cipher.encryptor()
	cph = b""
	cph += encryptor.update(m)
	cph += encryptor.finalize()
	return cph

def dec(k, c, nonce):
	cipher = Cipher(algorithms.AES(k), modes.CTR(nonce))
	decryptor = cipher.decryptor()
	msg = b""
	msg += decryptor.update(c)
	msg += decryptor.finalize()
	return msg
```

### 1.1. Análise da vulnerabilidade

Este ficheiro contém os algoritmos de geração de chaves (`gen`), cifração (`enc`) e decifração (`dec`). A cifra foi feita com AES-CTR (AES, em modo de operação counter mode), o que significa que:

- A chave tem: 128 bits (16 bytes)

Analisando o código, vemos que a função `gen` usa apenas 3 bytes aleatórios (`os.urandom(offset)` com `offset = 3`), enquanto que os outros 13 bytes são fixados como `0x00`.

Isto diminui o número de combinações possíveis de `2^128`, caso todos os bytes fossem aleatórios, para `2^24`. Assim, torna o algoritmo mais vulnerável a ataques, facilitando a exploração das diferentes combinações possíveis dos últimos 3 bytes até encontrar a correta.

### 1.2. Uso da ciphersuite para cifrar e decifrar dados

Considerando uma mensagem de exemplo para cifrar e convertendo-a para bytes com o método `.encode()`:

```python
message = "flag{exemplo}".encode()
```

1. Gerar uma chave e um nononce

    ```python
    key = gen()              # Chave gerada com vulnerabilidade
    nonce = os.urandom(16)   # Gera um nonce de 12 bytes
    ```

    Que gera, por exemplo:
    
    ```
    Key: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb4!{'
    Nonce: b'\xfa\x11\x86\x88,\xb1\xa0\xdc\xc2\xcc\x9dY\xce9$\xae'
    ```

2. Cifrar a mensagem

    ```python
    ciphertext = enc(key, message, nonce) # Cifra a mensagem
    ```

    Correndo o comando, convertemos a mensagem original numa mensagem cifrada:

    ```
    3c23e256d11cc3c64f8dafaac3
    ```

3. Decifrar a mensagem 

    ```python
    decodedtext = dec(key, ciphertext, nonce) # Decifra a mensagem
    ```

    Correndo o comando, obtemos a mensagem original a partir do ciphertext:

    ```
    flag{exemplo}
    ```

### 1.3. Como usar a vulnerabilidade para quebrar o código?

A vulnerabilidade na função `gen()` já explicada permite que a chave seja recuperada através de um ataque de brute force nos últimos 3 bytes, uma vez que são os únicos aleatórios. 

Assim, podemos fixar os 13 primeiros bytes como `0x00` e tentar todas as combinações possíveis para os últimos 3 bytes.

### 1.4. Automatização do processo para detetar a flag

O nonce e o criptograma são fornecidos no enunciado do CTF e estão diponíveis no ficheiro [CTF11_L14G04](/CTF11_L14G04.cph):

- A primeira linha é o nonce:

    ```python
    nonce_hex = "a5e295591a6acc874c3f71a6da21ff56"
    ```

- A segunda linha é o criptograma:

    ```python
    cipher_hex = "05e9e46af13436edfe9f3ad5112e095fed9b6d166124"
    ```

1. Converter o nonce e o criptograma de hexadecimal para bytes:

    ```python
    nonce = unhexlify(nonce_hex)
    cipher = unhexlify(cipher_hex)
    ```

2. Determinar o número de combinações possíveis para a chave: `2^24`, como já explicado anteriormente;

    ```python
    combinations = 2 ** 24
    ```

3. Realizar o ataque de força bruta, iterando em cada combinação possível das `2^24` para o valor da chave, utilizando a função `dec()` para decifrar o criptograma, e validar se o valor decifrado está no formato `flag{...}`.

Com estas informações, construimos o seguinte payload:

```python
from cipherspec import dec, gen
from binascii import unhexlify

# nonce e criptograma em hexadecimal, fornecidos no enunciado
nonce_hex = "a5e295591a6acc874c3f71a6da21ff56"
cipher_hex = "05e9e46af13436edfe9f3ad5112e095fed9b6d166124"

# conversão do nonce e do criptograma para bytes
nonce = unhexlify(nonce_hex)
cipher = unhexlify(cipher_hex)

# número de combinações da chave
offset = 3
combinations = 2 ** (8 * offset)

# ataque de brute force
for i in range(combinations):
    key = bytearray(b'\x00' * (16 - offset))
    key.extend(i.to_bytes(offset, 'big'))

    try:
        # decifrar com a chave atual
        decodedtext = dec(bytes(key), cipher, nonce)

        # validar se o texto decifrado é uma flag
        if decodedtext.startswith(b"flag{") and decodedtext.endswith(b"}"):
            print(f"A flag foi decifrada: {decodedtext.decode()}")
            break  
    except Exception:
        continue
else:
    print("Ataque terminado. Não foi possível decifrar a flag :(")
```

Ao executarmos este script conseguimos completar o ataque de brute force de forma automática e obtivemos a flag deste CTF: `flag{oaheowgxombkhvel}`!

![Figura 1](/Images/CTF11/Figura1.png)


## 2. Tamanho do Offset para Ataque ser Inviável num Período de 10 anos 

Para avaliar o quão grande o offset precisaria ser para tornar o ataque de brute force inviável nas nossas máquinas pessoais no intervalo de 10 anos, começamos por estimar de forma experimental quantas chaves conseguimos testar por segundo. Consideramos um tempo experimental de 30 segundos.

Para isso, tivemos que fazer algumas alterações no payload anterior para incluir o tempo decorrido, o número total de chaves testadas nesse tempo e o cálculo do número de chaves por segundo:

```python
import time
from cipherspec import dec, gen
from binascii import unhexlify

# nonce e criptograma em hexadecimal, fornecidos no enunciado
nonce_hex = "a5e295591a6acc874c3f71a6da21ff56"
cipher_hex = "05e9e46af13436edfe9f3ad5112e095fed9b6d166124"

# conversão do nonce e do criptograma para bytes
nonce = unhexlify(nonce_hex)
cipher = unhexlify(cipher_hex)

# número de combinações da chave
offset = 3
combinations = 2 ** 24

# cronómetro
start_time = time.time()
keys_tested = 0

# ataque de brute force
for i in range(combinations):
    key = bytearray(b'\x00' * (16 - offset))
    key.extend(i.to_bytes(offset, 'big'))

    try:
        # decifrar com a chave atual
        decodedtext = dec(bytes(key), cipher, nonce)

        # validar se o texto decifrado é uma flag
        if decodedtext.startswith(b"flag{") and decodedtext.endswith(b"}"):
            print(f"A flag foi decifrada: {decodedtext.decode()}")
            break  
    except Exception:
        continue

    keys_tested += 1

    # análise para 30 segundos
    if time.time() - start_time > 30:
        break

# estatísticas finais
elapsed_time = time.time() - start_time
keys_per_second = keys_tested / elapsed_time

print(f"Chaves testadas: {keys_tested}")
print(f"Tempo: {elapsed_time:.2f} s")
print(f"Velocidade: {keys_per_second:.2f} chaves/s")
```

De seguida, executamos o script 5 vezes e obtivemos os seguintes resultados:

### Experiência 1

![Figura2](/Images/CTF11/Figura2.png)

### Experiência 2

![Figura3](/Images/CTF11/Figura3.png)

### Experiência 3

![Figura4](/Images/CTF11/Figura4.png)

### Experiência 4

![Figura4](/Images/CTF11/Figura4.png)

### Experiência 5

![Figura5](/Images/CTF11/Figura5.png)

Calculamos o valor médio dos 5 valores obtidos para a velocidade: `81816.14 chaves/s`.

O passo seguinte foi fazer a extrapolação para 10 anos:

```
chaves (10 anos) = velocidade(chaves/s) * 10 * 365 * 24 * 60 * 60
```

Substituindo o valor da velocidade pelo nosso valor médio cálculado, obtivemos o número de chaves que se podem testar em 10 anos: `2.58 * 10^13`.

Por fim, podemos determinar qual o offset corespondente a estar a decifrar chaves durante 10 anos. Sabendo que:

```
número de combinações = 2 exp (8 * offset)
```

Para tornar o ataque inviável, o número de combinações tem que ser maior que o número de chaves que podem ser testadas em 10 anos:

```
2 exp (8 * offset) > chaves (10 anos)
```

Resolvendo a expressão anterior, obtemos que o offset tem que ser maior do que `5.6`.

## 3. Ineficácia de usar um nonce de 1 byte

O nonce é um valor único, que garante que em cada cifragem é obtido um resultado diferente, mesmo usando a mesma chave.

A nova "otimização" de usar um nonce com apenas 1 byte (8 bits) e não o enviar pela rede é uma ideia inadequada pelos seguintes motivos:

- Um nonce de 1 byte gera apenas `2^8 = 256` valores possíveis. Isto significa que em sistemas em que ocorrem cifragens de muitas mensagens com a mesma chave, o nonce vai ser reutilizado após apenas 256 cifragens, o compromete seriamente a segurança.

- Esta alteração faz com que seja necessário testar 256 possibilidades de nonce para cada chave. No entanto, isto adiciona apenas `2^32` testes ao valor total, o que ainda é computacionalmente viável para máquinas modernas.

- Não enviar o nonce pela rede não tem grande impacto, porque o atacante pode determinar o nonce correto através da análise do texto cifrado. Por exemplo, sabendo que o texto original segue certo padrão (por exemplo, flag{), o atacante pode testar cada nonce e verificar qual resulta no padrão esperado.