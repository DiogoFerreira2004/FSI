# CTF Semana #12 (RSA)

Este documento descreve as etapas seguidas neste CTF, onde exploraramos o mecanismo de cifração baseado em RSA.

## 1. Algorítmo para Testar Primalidade de Números

Como no centro deste desafio está a necessidade de encontrar primos, o primeiro passo foi criar uma função que testa se um número é ou não primo. Para isso, utilizamos o algorítmo sugerido no enunciado, o Miller-Rabin, definido no [Geeks For Geeks](https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/):

```python
import random 
 
def power(x, y, p):
    res = 1 
     
    x = x % p 
    while (y > 0):
        if (y & 1):
            res = (res * x) % p
 
        y = y>>1 
        x = (x * x) % p
     
    return res
 
def miillerTest(d, n):
    a = 2 + random.randint(1, n - 4)
 
    x = power(a, d, n)
 
    if (x == 1 or x == n - 1):
        return True

    while (d != n - 1):
        x = (x * x) % n
        d *= 2
 
        if (x == 1):
            return False
        if (x == n - 1):
            return True
 
    return False
 
def is_prime( n, k = 4 ):
    if (n <= 1 or n == 4):
        return False
    if (n <= 3):
        return True

    d = n - 1
    while (d % 2 == 0):
        d //= 2
 
    for i in range(k):
        if (miillerTest(d, n) == False):
            return False
 
    return True
```

## 2. Valores usados no RSA que cifrou a flag

Temos indicação no enunciado que `p` é um primo próximo de `2 exp (500 + ((14-1) * 10 + 4) // 2))` e `q` próximo de `2 exp (501 + (((14-1)*10 + 4) // 2))`. Podemos usar esta informação para inferir os valores reais de `p` e `q` usados.

### 2.1 Inferência 

O nosso processo de inferência consistiu em determinar os valores de `p` e `q` com base nas potências indicadas no enunciado (`p_start` e `q_start`). A partir destes valores iniciais, realizamos uma procura num intervalo próximo.

Começamos por verificar a proximidade de `p` a partir de `p_start`. Se `p` não for encontrado, passamos a procurar `q` a partir de `q_start`. Quando um divisor é encontrado, calculamos o outro dividindo `n` pelo divisor identificado.

### 2.2. Validação da inferência

A validação é feita verificando se os valores encontrados para `p` e `q` são primos e satisfazem a equação `p * q = n`.

Assim, o payload completo para a determinação dos valores usados no RSA que cifrou a flag é o seguinte:

```python
# Calcular p e q 
base_exp = 500 + (((14 - 1) * 10 + 4) // 2)
p_start = 2 ** base_exp
q_start = 2 ** (base_exp + 1)

p = 0
q = 0

for p_candidate in range(p_start, p_start + 1000000):
    if isPrime(p_candidate) and n % p_candidate == 0:
        p = p_candidate
        q = n // p_candidate
        break

if p == 0:  
    for q_candidate in range(q_start, q_start + 1000000):
        if isPrime(q_candidate) and n % q_candidate == 0:
            q = q_candidate
            p = n // q_candidate
            break
```

## 3. Implementação do RSA

Antes de implementarmos o RSA, analisamos o ficheiro `gen_example.py`, onde é ilustrado como os criptogramas foram gerados. 

Nesta implementação está a faltar o algorítmo das funções `getRandomPrime` e `extendedEuclidean`. 

O `extendedEuclidean` calcula o mínimo divisor comum (MDC) entre dois números `a` e `b` e calcula os coeficientes `x` e `y` tais que:

```
a * x + b * y = mdc(a, b)
```

Assim, podemos implementar o algorítmo que calcula o MDC através da seguinte função:

```python 
def extended_euclidean(a, b):
    x, y, x1, y1 = 1, 0, 0, 1
    a1, b1 = a, b

    while (b1) :
        q = a1 // b1
        a1, b1 = (b1, a1 - q * b1)
        x, x1 = (x1, x - q * x1)
        y, y1 = (y1, y - q * y1)
    
    return x % b
```

Do [enunciado fornecido](/CTF12_L14G04.cph) sabemos os valores de `n` (*Modulus*), de `e` (*Public exponent*) e a cifra em formato hexadecimal. Para implementarmos o RSA que vai descodificar a flag temos que considerar os seguintes passos:

1. Calcular `ϕ(n)` tal que `ϕ(n) = (p - 1) * (q - 1)`.
2. Sabendo `e`, determinar o inverso multiplicativo `d` usando o `extendedEuclidean`.
3. Fazer a desencriptação do criptograma:  

    3.1. Conversão do criptograma hexadecimal para bytes.   
    3.2. Conversão do criptograma de bytes para inteiro.  
    3.3. Aplicar a fórmula do RSA para desencriptar a mensagem: `cipher_msg = pow(cipher_int, d, n)`.  
    3.4. Conversão do resultado de volta para bytes.  
    3.5. Decodificação dos bytes para uma string.

```python
# Desencriptar o criptograma
def decrypt(n, d, cipher_hex):
    cipher = unhexlify(cipher_hex)
    cipher_int = int.from_bytes(cipher, "little") 
    cipher_text = pow(cipher_int, d, n)

    num_bytes = (cipher_text.bit_length() + 7) // 8
    cipher_bytes = cipher_text.to_bytes(num_bytes, "little")

    try:
        return cipher_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        return f"Decoding error: {e}"

# 1. Calcular ϕ(n)
phi_n = (p - 1) * (q - 1)

# 2. Calcular d
d = extended_euclidean(e, phi_n)

# 3. Desencriptar o criptograma
flag = decrypt(n, d, cipher_hex)
```

## 4. Extração da chave do criptograma

Para extrairmos a chave do criptograma, a única coisa que falta é correr o `exploit.py` e imprimir o valor obtido pelo algorítmo de desencriptação!

O resultado obtido foi `flag{fralvaowkbmtnmee}`!

```python
import random
from binascii import unhexlify

# Miller-Rabin
def power(x, y, p):
    res = 1 
     
    x = x % p 
    while (y > 0):
        if (y & 1):
            res = (res * x) % p
 
        y = y>>1 # y = y/2
        x = (x * x) % p
     
    return res
 
def miillerTest(d, n):
    a = 2 + random.randint(1, n - 4)
 
    x = power(a, d, n)
 
    if (x == 1 or x == n - 1):
        return True

    while (d != n - 1):
        x = (x * x) % n
        d *= 2
 
        if (x == 1):
            return False
        if (x == n - 1):
            return True
 
    return False
 
def isPrime( n, k = 4 ):
    if (n <= 1 or n == 4):
        return False
    if (n <= 3):
        return True

    d = n - 1
    while (d % 2 == 0):
        d //= 2
 
    for i in range(k):
        if (miillerTest(d, n) == False):
            return False
 
    return True

# Extended Euclidean Algorithm
def extended_euclidean(a, b):
    x, y, x1, y1 = 1, 0, 0, 1
    a1, b1 = a, b

    while (b1) :
        q = a1 // b1
        a1, b1 = (b1, a1 - q * b1)
        x, x1 = (x1, x - q * x1)
        y, y1 = (y1, y - q * y1)
    
    return x % b

# Desencriptar o criptograma
def decrypt(n, d, cipher_hex):
    cipher = unhexlify(cipher_hex)
    cipher_int = int.from_bytes(cipher, "little")
    cipher_text = pow(cipher_int, d, n)

    num_bytes = (cipher_text.bit_length() + 7) // 8
    cipher_bytes = cipher_text.to_bytes(num_bytes, "little")

    try:
        return cipher_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        return f"Decoding error: {e}"

e = 65537 
n = 466707820837761455322512769464155020211302289912725822831690960471494276398406664442343627457870268190886264853466102955203697268333710866167706427690205579269901069425528076342695735329859595337943242795633777807196930272829988770301087256643936379277676219705919425147379575283429391839615405090167060609011093460141991294863901452159132181
cipher_hex = "9acc9bae0e1db7c471981aad68775c3f3b5356ccd9d28cb6cbd7bb1d9360fc9740a1a2ad37dd40bfbcf30880714823d520d9fdd7c8d17e0553318bf2c5946ef5c5549fe2622650a942930770f965c253cbc71e904edd56665c1573c1cd9d6f1f7038d9f30adab1b910540c3911219115968d6ea4f4a6f4394a110eb615f303f597e35e710e13696f681654139470000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    
# Calcular p e q 
base_exp = 500 + (((14 - 1) * 10 + 4) // 2)
p_start = 2 ** base_exp
q_start = 2 ** (base_exp + 1)

p = 0
q = 0

for p_candidate in range(p_start, p_start + 1000000):
    if isPrime(p_candidate) and n % p_candidate == 0:
        p = p_candidate
        q = n // p_candidate
        break

if p == 0:  
    for q_candidate in range(q_start, q_start + 1000000):
        if isPrime(q_candidate) and n % q_candidate == 0:
            q = q_candidate
            p = n // q_candidate
            break
    
# Calcular ϕ(n)
phi_n = (p - 1) * (q - 1)

# Calcular d
d = extended_euclidean(e, phi_n)

# Desencriptar o criptograma
flag = decrypt(n, d, cipher_hex)
print(flag)
```