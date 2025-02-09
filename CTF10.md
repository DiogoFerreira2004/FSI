# CTF Semana #10 (Classical Encryption)

## 1. Reconhecimento

O primeiro passo para a resolução deste CTF foi a investigação do [criptograma](/L14G04.cph) do nosso grupo, de forma a entender como a cifra em questão pode estar a cifrar os dados. A cifra é composta por um conjunto de símbolos, que substituem letras.

Para isso, começamos por fazer uma análise de frequência dos diferentes símbolos que aparecem no texto. Isso foi feito utilizando o seguinte algorítmo, fornecido no Secret-Key Encryption Lab:

```python
#!/usr/bin/env python3

from collections import Counter
import re

TOP_K  = 26
N_GRAM = 3

# Generate all the n-grams for value n
def ngrams(n, text):
    for i in range(len(text) -n + 1):
        # Ignore n-grams containing white space
        if not re.search(r'\s', text[i:i+n]):
           yield text[i:i+n]

# Read the data from the ciphertext
with open('L14G04.cph') as f:
    text = f.read()

# Count, sort, and print out the n-grams
for N in range(N_GRAM):
   print("-------------------------------------")
   print("{}-gram (top {}):".format(N+1, TOP_K))
   counts = Counter(ngrams(N+1, text))        # Count
   sorted_counts = counts.most_common(TOP_K)  # Sort 
   for ngram, count in sorted_counts:                  
       print("{}: {}".format(ngram, count))   # Print
```

Os resultados obtidos foram os seguintes:

### 1-gram (top 26):

| Símbolo    | Frequência  |
|------------|-------------|
| `;`        | 72          |
| `^`        | 53          |
| `%`        | 53          |
| `~`        | 42          |
| `\|`       | 34          |
| `/`        | 33          |
| `#`        | 30          |
| `.`        | 29          |
| `:`        | 28          |
| `)`        | 24          |
| `<`        | 24          |
| `>`        | 23          |
| `,`        | 16          |
| `(`        | 15          |
| `=`        | 12          |
| `*`        | 8           |
| `+`        | 6           |
| `-`        | 4           |
| `?`        | 3           |
| `$`        | 3           |
| `@`        | 2           |
| `]`        | 2           |

### 2-gram (top 26):

| Símbolos   | Frequência  |
|------------|-------------|
| `#;`       | 13          |
| `#^`       | 10          |
| `;/`       | 9           |
| `\|;`      | 9           |
| `%#`       | 9           |
| `.;`       | 9           |
| `/^`       | 9           |
| `^<`       | 8           |
| `.%`       | 8           |
| `;.`       | 8           |
| `%>`       | 7           |
| `)^`       | 7           |
| `^/`       | 7           |
| `~>`       | 7           |
| `~.`       | 7           |
| `;=`       | 6           |
| `~/`       | 6           |
| `;%`       | 6           |
| `^\|`      | 6           |
| `;#`       | 6           |
| `\|~`      | 6           |
| `)%`       | 5           |
| `=;`       | 5           |
| `\|%`      | 5           |
| `;>`       | 5           |
| `%.`       | 5           |

### 3-gram (top 26):

| Símbolos   | Frequência  |
|------------|-------------|
| `;/^`      | 5           |
| `%#;`      | 5           |
| `;.;`      | 5           |
| `;=;`      | 4           |
| `.%>`      | 4           |
| `.;%`      | 4           |
| `#;/`      | 3           |
| `;%#`      | 3           |
| `/:<`      | 3           |
| `;.%`      | 3           |
| `>)^`      | 3           |
| `^\|~`     | 3           |
| `;#;`      | 3           |
| `)%=`      | 2           |
| `%=^`      | 2           |
| `,;\|`     | 2           |
| `;\|)`     | 2           |
| `\|;>`     | 2           |
| `<~/`      | 2           |
| `~//`      | 2           |
| `//;`      | 2           |
| `/;%`      | 2           |
| `%#^`      | 2           |
| `;~/`      | 2           |
| `$%(`      | 2           |
| `%(%`      | 2           |


## 2. Tentativas de Substituição

Tal como fizemos no Secret-Key Encryptation Lab, após identificarmos os símbolos mais frequentes no criptograma (1-gram), tentamos substituí-los pelas letras mais usadas na [língua portuguesa](https://www.dcc.fc.up.pt/~rvr/naulas/tabelasPT/):

![Figura 1](/Images/CTF10/Figura1.png)

Por exemplo, o símbolo mais frequente foi inicialmente substituído pela letra A, o segundo mais frequente por E, etc. Fizemos isto para os 10 caracteres mais frequentes através do comando:

```
tr ';^%~|/#.:)' 'aeosridntc' < L14G04.cph > out.txt
```

No entanto, no output que obtivemos não conseguimos identificar nenhuma sequência de caracteres que fizesse sentido como palavras em português:

```
srenco=e,arc=a=arcsrdai?cro+etcra>i<siiaode<asit<$o(odona<=eo>acode*ai-tece*o,da>*aaie(tsrcere<oit<reit<oa,ar(adodocor>esodains>no>anoeie<ra(te*sno<oi$o(oieinonsa=aside(a,eie<<trra@+se,desr,a>da+ra>nae<dt*,s>ce<s>snso?o$et<aiersede=ro(ra<aiio*rea?sicorsado+tce*o,no>cs>taaiersededs]t,(anaoda<oda,sdadentr,s>(eicae<siiaoana*ano<o<t>dsa,densn,onroiieo<s>sicersodaa(rsnt,ctra=einaiea,s<e>canao<a=ano>isderoto>ce<-tea>e(onsanaodaie(t>daeca=adas>ce(ranaoetro=esadaa(rsnt,ctra=orct(teia+osno>isderada<tsco={sont@+c]-sna-o>t}
```

Assim, descartamos este mapeamento inicial e começamos de novo a análise.

Com base na análise de frequência, concluímos que o símbolo `;` correspondia à letra A, uma vez que é a mais utilizada no português, com uma diferença de frequência significativa em relação às outras letras.

Sabendo que `; = a`, analisamos palavras de 6 letras no texto cifrado utilizadas várias vezes. Recorremos novamente ao algorítmo fornecido no Secret-Key Encryption Lab, já apresentado anteriormente:

### 6-gram (usadas mais do que 1 vez):

| Símbolos   | Frequência  |
|------------|-------------|
| `<~//;%`   | 2           |
| `;/^\|~^`  | 2           |
| `/^\|~^#`  | 2           |
| `^\|~^#^`  | 2           |
| `;.;%#;`   | 2           |
| `#;;(\|~`  | 2           |
| `;;(\|~.`  | 2           |
| `;(\|~.:`  | 2           |
| `(\|~.:,`  | 2           |
| `\|~.:,)`  | 2           |
| `~.:,):`   | 2           |
| `.:,):\|`  | 2           |
| `:,):\|;`  | 2           |
| `,):\|;=`  | 2           |
| `.%>/~#`   | 2           |
| `%>/~#^`   | 2           |
| `>/~#^\|`  | 2           |

Analisando estas palavras, reparamos logo na primeira `<~//;%`, que tem dois caracteres seguidos iguais (`//`). Na língua portuguesa os dois caracteres que mais se repetem neste padrão são o `ss` e o `rr`. Assim, utilizando a ferramenta da página [Dicio](https://www.dicio.com.br/pesquisa-avancada/?tipo=comecam&qword=EREMOS&letras=0), procuramos por palavras de 6 caracteres em que na 3ª e 4ª posição estava o `r` ou o `s` e que na quinta estava o `a`:

![Figura2](/Images/CTF10/Figura2.png)

![Figura3](/Images/CTF10/Figura3.png)

Analisando as diferentes palavras obtidas e sabendo que o contexto desta mensagem encriptada é que pertence a um jornal, decidimos experimentar o mapeamento de acordo com a palavra `missão`. Para isso, corremos o comando:

```
tr '<~/;%' 'misao' < L14G04.cph > out.txt
```

O output que tivemos foi:

```
i|^.)o=^,a|)=a=a|)i|#as?)|o+^:)|a>smissao#^mais:m$o(o#o.am=^o>a)o#^*as-:^)^*o,#a>*aas^(:i|)^|^mos:m|^s:moa,a|(a#o#o)o|>^io#as.i>.o>a.o^s^m|a(:^*i.omos$o(os^s.o.ia=ais#^(a,^s^mm:||a@+i^,#^i|,a>#a+|a>.a^m#:*,i>)^mi>i.io?o$^:mas^|i^#^=|o(|amasso*|^a?is)o|ia#o+:)^*o,.o>)i>:aas^|i^#^#i]:,(a.ao#amo#a,i#a#^.:|,i>(^s)a^missaoa.a*a.omom:>#ia,#^.i.,o.|oss^omi>is)^|io#aa(|i.:,):|a=^s.as^a,im^>)a.aoma=a.o>si#^|o:o>)^m-:^a>^(o.ia.ao#as^(:>#a^)a=a#ai>)^(|a.ao^:|o=^ia#aa(|i.:,):|a=o|):(:^sa+oi.o>si#^|a#am:i)o={io.:@+)]-i.a-o>:}
```

Ao analisar o resultado identificamos, para além da palavra `missão`, as palavras `mas` e `mais`, o que nos levou a acreditar que este mapeamento estaria correto. 

A restante metodologia de substituição foi feita através da comparação das frequências de caracteres do texto encriptado versus frequência de caracteres na língua portuguesa e, também, da tentativa de formar palavras olhando para os caracteres já decifrados no texto.

## 3. Decifração Completa

Conseguimos por fim chegar ao mapeamento final:

| Símbolo    | Letra       |
|------------|-------------|
| `;`        | A           |
| `^`        | E           |
| `%`        | O           |
| `~`        | I           |
| `\|`       | R           |
| `/`        | S           |
| `#`        | D           |
| `.`        | C           |
| `:`        | U           |
| `)`        | T           |
| `<`        | M           |
| `>`        | N           |
| `,`        | L           |
| `(`        | G           |
| `=`        | P           |
| `*`        | B           |
| `+`        | F           |
| `-`        | Q           |
| `?`        | H           |
| `$`        | J           |
| `@`        | Y           |
| `]`        | V           |

Executamos a instrução:

```
tr ';^%~|/#.:)<>,(=-$*+@?]' 'aeoirsdcutmnlgpqjbfyhv' < L14G04.cph > out.txt
```

Que nos deu o output:

```
irectopelartpapartirdashtrofeutransmissaodemaisumjogodocampeonatodebasqueteboldanbaaseguirteremosumresumoalargadodotorneiodascinconacoesemraguebicomosjogosescociapaisdegalesemmurrayfieldeirlandafrancaemdublinteminiciohojeumaseriedeprogramassobreahistoriadofutebolcontinuaaseriededivulgacaodamodalidadecurlingestaemissaoacabacomomundialdeciclocrosseoministeriodaagriculturapescasealimentacaomapaconsiderouontemqueanegociacaodasegundaetapadaintegracaoeuropeiadaagriculturaportuguesafoiconsideradamuitop{iocuyftvqicaqonu}
```

E como podemos ver, a flag do nosso texto encriptado corresponde a: `flag{iocuyftvqicaqonu}`.
