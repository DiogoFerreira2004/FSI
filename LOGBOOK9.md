# Relatório: Secret-Key Encryption Lab

## Task 1: Frequency Analysis

Começamos por determinar o top 10 das letras mais utilizadas em inglês, de acordo com o gráfico apresentado na [página](https://en.wikipedia.org/wiki/Frequency_analysis) fornecida no enunciado:

1 - E  
2 - T  
3 - A   
4 - O  
5 - I  
6 - N  
7 - S  
8 - R  
9 - H  
10 - L  
11 - D  
12 - U  
13 - C  
14 - M  
15 - F  
16 - W  
17 - Y  
18 - G  
19 - P  
20 - B  

Analisando as frequências de uma letra do ficheiro `freq.py` (Figura 1), começamos por experimentar o seguinte mapeamento que relaciona as letras mais usadas no texto com as letras mais usadas em inglês:

1 - E -> N  
2 - T -> Y   
3 - A -> V    
4 - O -> X   
5 - I -> U   
6 - N -> Q  
7 - S -> M   
8 - R -> H   
9 - H -> T  
10 - L -> I   
11 - D -> P    
12 - U -> A   
13 - C -> C  
14 - M -> Z  
15 - F -> L  
16 - W -> G  
17 - Y -> B  
18 - G -> R  
19 - P -> E   
20 - B -> D 

![Figura 1](/Images/LOGBOOK9/Task1_image1.png)

Figura 1: análise de frequências de letras singulares no ficheiro `ciphertext.txt`.

Depois corremos o comando

```C
tr ’nyvxuqmhtipaczlgbred’ ’ETAOINSRHLDUCMFWYGPB’ < ciphertext.txt > out.txt
```

para experimentar esta substituição de letras e obtivemos o seguinte output:

```
**THE** ONUARN TMRI  OI NMIDAB FHSUH NEECN AWOMT RSGHT AYTER THSN LOIG NTRAIGE
AFARDN TRSP THE WAGGER YEELN LSsE A IOIAGEIARSAI TOO

**THE** AFARDN RAUE FAN WOOsEIDED WB **THE** DECSNE OY HARfEB FESINTESI AT STN OMTNET
AID THE APPAREIT SCPLONSOI OY HSN YSLC UOCPAIB AT THE EID AID ST FAN NHAPED WB
THE ECERGEIUE OY CETOO TSCEN MP WLAUsGOFI POLSTSUN ARCUAIDB AUTSfSNC AID
A IATSOIAL UOIfERNATSOI AN WRSEY AID CAD AN A YEfER DREAC AWOMT FHETHER THERE
OMGHT TO WE A PRENSDEIT FSIYREB THE NEANOI DSDIT oMNT NEEC EkTRA LOIG ST FAN
EkTRA LOIG WEUAMNE **THE** ONUARN FERE COfED TO THE YSRNT FEEsEID SI CARUH TO
AfOSD UOIYLSUTSIG FSTH **THE** ULONSIG UERECOIB OY **THE** FSITER OLBCPSUN THAIsN
PBEOIGUHAIG
...
```

Analisando este output, conseguimos perceber que o mapeamento que fizemos para obter as letras `T`, `H` e `E` está correto:

y → T  
t → H  
n → E   

Na nossa segunda tentativa analisamos as frequências binárias (sequências de 2 letras) no texto (Figura 2) e fizemos o mapeamento tendo em consideração as [frequências binárias](https://en.wikipedia.org/wiki/Bigram) da língua inglesa e também as letras que já sabemos que estão corretas.

1 → yt → TH  
2 → tn → HE  
3 → mu → IN  
4 → nh → ER  
5 → vh → AR  
6 → hn → RE   
7 → vu → AN  
8 → nq → ES  
9 → xu → ON  
10 → up → ND  
11 → xh → OR  
12 → yn → TE  
13 → np → ED  
14 → vy → AT  
15 → nu → EN  
16 → qy → ST    
17 → vq → AS  
18 → vi → AL  
19 → gn → WE  
20 → av → UA  

![Figura 2](/Images/LOGBOOK9/Task1_image2.png)

Figura 2: análise de frequências de letras binárias no ficheiro `ciphertext.txt`.

Depois corremos o comando

```
tr 'nyvxmuqhtipaczlgbred' 'ETAOINSRHLDUCMFWYGPB' < ciphertext.txt > out.txt
```

para experimentar esta substituição de letras e obtivemos o seguinte output:

```
**THE** OSUARS TMRN  ON SMNDAB FHIUH SEECS AWOMT RIGHT AYTER THIS LONG STRANGE
AFARDS TRIP THE WAGGER YEELS LIsE A NONAGENARIAN TOO

THE AFARDS RAUE FAS WOOsENDED WB THE DECISE OY HARfEB FEINSTEIN AT ITS OMTSET
**AND THE APPARENT** ICPLOSION OY HIS YILC UOCPANB AT THE END AND IT FAS SHAPED WB
THE ECERGENUE OY CETOO TICES MP WLAUsGOFN POLITIUS ARCUANDB AUTIfISC **AND
A NATIONAL*** UONfERSATION AS WRIEY AND CAD AS A YEfER DREAC AWOMT FHETHER THERE
OMGHT TO WE A **PRESIDENT** FINYREB **THE SEASON DIDNT** oMST SEEC EkTRA LONG IT FAS
EkTRA LONG WEUAMSE THE OSUARS FERE COfED TO THE YIRST FEEsEND IN CARUH TO
AfOID UONYLIUTING FITH THE ULOSING UERECONB OY THE FINTER OLBCPIUS THANsS
PBEONGUHANG

ONE WIG jMESTION SMRROMNDING THIS BEARS AUADECB AFARDS IS HOF OR IY THE
UERECONB FILL **ADDRESS** CETOO ESPEUIALLB AYTER **THE GOLDEN** GLOWES FHIUH WEUACE
A oMWILANT UOCINGOMT PARTB YOR TICES MP THE COfECENT SPEARHEADED WB 
POFERYML HOLLBFOOD FOCEN FHO HELPED RAISE CILLIONS OY **DOLLARS** TO YIGHT SEkMAL
HARASSCENT AROMND THE UOMNTRB

...
```

Analisando este output, conseguimos adicionar mais algumas letras ao nosso mapeamento correto:

y → T  
t → H  
n → E  

//////////  

v → A  
u → N  
p → D   
e → P  
h → R  
q → S  
m → I    
x → O  
i → L

Na terceira tentativa analisamos as frequências ternárias (sequências de 3 letras) no texto (Figura 3) e fizemos o mapeamento tendo em consideração as [frequências ternárias](https://en.wikipedia.org/wiki/Trigram) da língua inglesa e também as letras que já sabemos que estão corretas.

1 → ytn → THE  
2 → vup → AND
3 → mur → ING  
4 → ynh → TER  
5 → xzy → OUT  
6 → mxu → ION   
7 → gnq → BES  
8 → ytv → THA  
9 → nqy → EST  
10 → vii → ALL  
11 → bxh → FOR  
12 → lvq → WAS  
13 → nuy → ENT   
14 → vyn → ATE  
15 → uvy → ENT  
16 → lmu → WIN    
17 → nvh → EAR  
18 → cmu → MIN  
19 → tmq → HIS  
20 → vhp → ARD  

![Figura 3](/Images/LOGBOOK9/Task1_image3.png)

Figura 3: análise de frequências ternárias de letras no ficheiro `ciphertext.txt`.

Depois corremos o comando

```
tr 'nyvxmuqhtipaczlgbred' 'ETAOINSRHLDUCMFWYGPB' < ciphertext.txt > out.txt
```

para experimentar esta substituição de letras e obtivemos o seguinte output:

```
THE OSCARS TURN  ON SUNDAY WHICH SEEMS ABOUT RIGHT AFTER THIS LONG STRANGE
AWARDS TRIP THE BAGGER FEELS LIsE A NONAGENARIAN TOO

THE AWARDS RACE WAS BOOsENDED BY THE DEMISE OF HARfEY WEINSTEIN AT ITS OUTSET
AND THE APPARENT IMPLOSION OF HIS FILM COMPANY AT THE END AND IT WAS SHAPED BY
THE EMERGENCE OF METOO TIMES UP BLACsGOWN POLITICS ARMCANDY ACTIfISM AND
A NATIONAL CONfERSATION AS BRIEF AND MAD AS A FEfER DREAM ABOUT WHETHER THERE
OUGHT TO BE A PRESIDENT WINFREY THE SEASON DIDNT oUST SEEM EkTRA LONG IT WAS
EkTRA LONG BECAUSE THE OSCARS WERE MOfED TO THE FIRST WEEsEND IN MARCH TO
AfOID CONFLICTING WITH THE CLOSING CEREMONY OF THE WINTER OLYMPICS THANsS
PYEONGCHANG

ONE BIG jUESTION SURROUNDING THIS YEARS ACADEMY AWARDS IS HOW OR IF THE
CEREMONY WILL ADDRESS METOO ESPECIALLY AFTER THE GOLDEN GLOBES WHICH BECAME**
A oUBILANT COMINGOUT PARTY FOR TIMES UP THE MOfEMENT SPEARHEADED BY 
POWERFUL HOLLYWOOD WOMEN WHO HELPED RAISE MILLIONS OF DOLLARS TO FIGHT SEkUAL
HARASSMENT AROUND THE COUNTRY
...
```

Analisando este output, conseguimos adicionar as últimas letras que experimentamos ao nosso mapeamento correto:

y → T  
t → H  
n → E  
//////////  

v → A  
u → N  
p → D   
e → P  
h → R  
q → S  
m → I    
x → O  
i → L 

//////////  
q → S   
z → U  
r → G  
g → B  
b → F  
t → H  
a → C  
c → M  
l → W  
d → Y    
  
Assim, neste momento já só falta o mapeamento das letras J, K, Q, V, X, Z. Analisando o texto, facilmente conseguimos perceber que estas letras deverão corresponder a:

o → J  
s → K  
j → Q  
f → V  
k → X  
w → Z     
                                   
Correndo pela última vez o comando para desencriptar:

```
tr 'nyvxmuqhtipzacbldregfskjow' 'ETAOINSRHLDUCMFWYGPBVKXQJZ' < ciphertext.txt > out.txt
```

Obtemos o texto completo:

```
THE OSCARS TURN  ON SUNDAY WHICH SEEMS ABOUT RIGHT AFTER THIS LONG STRANGE
AWARDS TRIP THE BAGGER FEELS LIKE A NONAGENARIAN TOO

THE AWARDS RACE WAS BOOKENDED BY THE DEMISE OF HARVEY WEINSTEIN AT ITS OUTSET
AND THE APPARENT IMPLOSION OF HIS FILM COMPANY AT THE END AND IT WAS SHAPED BY
THE EMERGENCE OF METOO TIMES UP BLACKGOWN POLITICS ARMCANDY ACTIVISM AND
A NATIONAL CONVERSATION AS BRIEF AND MAD AS A FEVER DREAM ABOUT WHETHER THERE
OUGHT TO BE A PRESIDENT WINFREY THE SEASON DIDNT JUST SEEM EXTRA LONG IT WAS
EXTRA LONG BECAUSE THE OSCARS WERE MOVED TO THE FIRST WEEKEND IN MARCH TO
AVOID CONFLICTING WITH THE CLOSING CEREMONY OF THE WINTER OLYMPICS THANKS
PYEONGCHANG

ONE BIG QUESTION SURROUNDING THIS YEARS ACADEMY AWARDS IS HOW OR IF THE
CEREMONY WILL ADDRESS METOO ESPECIALLY AFTER THE GOLDEN GLOBES WHICH BECAME
A JUBILANT COMINGOUT PARTY FOR TIMES UP THE MOVEMENT SPEARHEADED BY 
POWERFUL HOLLYWOOD WOMEN WHO HELPED RAISE MILLIONS OF DOLLARS TO FIGHT SEXUAL
HARASSMENT AROUND THE COUNTRY

SIGNALING THEIR SUPPORT GOLDEN GLOBES ATTENDEES SWATHED THEMSELVES IN BLACK
SPORTED LAPEL PINS AND SOUNDED OFF ABOUT SEXIST POWER IMBALANCES FROM THE RED
CARPET AND THE STAGE ON THE AIR E WAS CALLED OUT ABOUT PAY INEQUITY AFTER
ITS FORMER ANCHOR CATT SADLER QUIT ONCE SHE LEARNED THAT SHE WAS MAKING FAR
LESS THAN A MALE COHOST AND DURING THE CEREMONY NATALIE PORTMAN TOOK A BLUNT
AND SATISFYING DIG AT THE ALLMALE ROSTER OF NOMINATED DIRECTORS HOW COULD
THAT BE TOPPED

AS IT TURNS OUT AT LEAST IN TERMS OF THE OSCARS IT PROBABLY WONT BE

WOMEN INVOLVED IN TIMES UP SAID THAT ALTHOUGH THE GLOBES SIGNIFIED THE
INITIATIVES LAUNCH THEY NEVER INTENDED IT TO BE JUST AN AWARDS SEASON
CAMPAIGN OR ONE THAT BECAME ASSOCIATED ONLY WITH REDCARPET ACTIONS INSTEAD
A SPOKESWOMAN SAID THE GROUP IS WORKING BEHIND CLOSED DOORS AND HAS SINCE
AMASSED  MILLION FOR ITS LEGAL DEFENSE FUND WHICH AFTER THE GLOBES WAS
FLOODED WITH THOUSANDS OF DONATIONS OF  OR LESS FROM PEOPLE IN SOME 
COUNTRIES


NO CALL TO WEAR BLACK GOWNS WENT OUT IN ADVANCE OF THE OSCARS THOUGH THE
MOVEMENT WILL ALMOST CERTAINLY BE REFERENCED BEFORE AND DURING THE CEREMONY 
ESPECIALLY SINCE VOCAL METOO SUPPORTERS LIKE ASHLEY JUDD LAURA DERN AND
NICOLE KIDMAN ARE SCHEDULED PRESENTERS

ANOTHER FEATURE OF THIS SEASON NO ONE REALLY KNOWS WHO IS GOING TO WIN BEST
PICTURE ARGUABLY THIS HAPPENS A LOT OF THE TIME INARGUABLY THE NAILBITER
NARRATIVE ONLY SERVES THE AWARDS HYPE MACHINE BUT OFTEN THE PEOPLE FORECASTING
THE RACE SOCALLED OSCAROLOGISTS CAN MAKE ONLY EDUCATED GUESSES

THE WAY THE ACADEMY TABULATES THE BIG WINNER DOESNT HELP IN EVERY OTHER
CATEGORY THE NOMINEE WITH THE MOST VOTES WINS BUT IN THE BEST PICTURE
CATEGORY VOTERS ARE ASKED TO LIST THEIR TOP MOVIES IN PREFERENTIAL ORDER IF A
MOVIE GETS MORE THAN  PERCENT OF THE FIRSTPLACE VOTES IT WINS WHEN NO
MOVIE MANAGES THAT THE ONE WITH THE FEWEST FIRSTPLACE VOTES IS ELIMINATED AND
ITS VOTES ARE REDISTRIBUTED TO THE MOVIES THAT GARNERED THE ELIMINATED BALLOTS
SECONDPLACE VOTES AND THIS CONTINUES UNTIL A WINNER EMERGES

IT IS ALL TERRIBLY CONFUSING BUT APPARENTLY THE CONSENSUS FAVORITE COMES OUT
AHEAD IN THE END THIS MEANS THAT ENDOFSEASON AWARDS CHATTER INVARIABLY
INVOLVES TORTURED SPECULATION ABOUT WHICH FILM WOULD MOST LIKELY BE VOTERS
SECOND OR THIRD FAVORITE AND THEN EQUALLY TORTURED CONCLUSIONS ABOUT WHICH
FILM MIGHT PREVAIL

IN  IT WAS A TOSSUP BETWEEN BOYHOOD AND THE EVENTUAL WINNER BIRDMAN
IN  WITH LOTS OF EXPERTS BETTING ON THE REVENANT OR THE BIG SHORT THE
PRIZE WENT TO SPOTLIGHT LAST YEAR NEARLY ALL THE FORECASTERS DECLARED LA
LA LAND THE PRESUMPTIVE WINNER AND FOR TWO AND A HALF MINUTES THEY WERE
CORRECT BEFORE AN ENVELOPE SNAFU WAS REVEALED AND THE RIGHTFUL WINNER
MOONLIGHT WAS CROWNED

THIS YEAR AWARDS WATCHERS ARE UNEQUALLY DIVIDED BETWEEN THREE BILLBOARDS
OUTSIDE EBBING MISSOURI THE FAVORITE AND THE SHAPE OF WATER WHICH IS
THE BAGGERS PREDICTION WITH A FEW FORECASTING A HAIL MARY WIN FOR GET OUT

BUT ALL OF THOSE FILMS HAVE HISTORICAL OSCARVOTING PATTERNS AGAINST THEM THE
SHAPE OF WATER HAS  NOMINATIONS MORE THAN ANY OTHER FILM AND WAS ALSO
NAMED THE YEARS BEST BY THE PRODUCERS AND DIRECTORS GUILDS YET IT WAS NOT
NOMINATED FOR A SCREEN ACTORS GUILD AWARD FOR BEST ENSEMBLE AND NO FILM HAS
WON BEST PICTURE WITHOUT PREVIOUSLY LANDING AT LEAST THE ACTORS NOMINATION
SINCE BRAVEHEART IN  THIS YEAR THE BEST ENSEMBLE SAG ENDED UP GOING TO
THREE BILLBOARDS WHICH IS SIGNIFICANT BECAUSE ACTORS MAKE UP THE ACADEMYS
LARGEST BRANCH THAT FILM WHILE DIVISIVE ALSO WON THE BEST DRAMA GOLDEN GLOBE
AND THE BAFTA BUT ITS FILMMAKER MARTIN MCDONAGH WAS NOT NOMINATED FOR BEST
DIRECTOR AND APART FROM ARGO MOVIES THAT LAND BEST PICTURE WITHOUT ALSO
EARNING BEST DIRECTOR NOMINATIONS ARE FEW AND FAR BETWEEN
```


## Task 2: Encryption using Different Ciphers and Modes

Nesta tarefa, criámos o ficheiro plaintext.txt com pelo menos 1000 bytes, que contém o seguinte texto:

```
A tecnologia tem desempenhado um papel crucial na transformação da sociedade moderna. Com o avanço da internet e das comunicações digitais, as pessoas estão mais conectadas do que nunca. A informação está disponível na ponta dos dedos, e o conhecimento é compartilhado globalmente em questão de segundos.

A inteligência artificial e a automação estão revolucionando indústrias inteiras, desde a manufatura até os serviços. Máquinas inteligentes estão assumindo tarefas repetitivas, permitindo que os seres humanos se concentrem em atividades mais criativas e estratégicas.

No entanto, esses avanços também trazem desafios. Questões relacionadas à privacidade, segurança de dados e ética na inteligência artificial estão no centro dos debates atuais. É essencial que o desenvolvimento tecnológico seja acompanhado por regulamentações adequadas e uma compreensão profunda de suas implicações sociais.

A educação também está se adaptando a essa nova realidade. O aprendizado online e os recursos digitais estão tornando a educação mais acessível, mas também exigem novas habilidades dos educadores e estudantes. A capacidade de aprender continuamente e se adaptar é mais importante do que nunca no mercado de trabalho em constante evolução.

Em resumo, a tecnologia oferece inúmeras oportunidades para melhorar a vida humana, mas é necessário abordá-la com responsabilidade e consciência. O futuro dependerá de como equilibramos a inovação com os valores humanos fundamentais.
```

Posteriormente, encriptámos e desencriptámos este texto utilizando três diferentes modos de cifra.
Para tal utilizámos as seguintes credenciais:

**Chave**: 00112233445566778899aabbccddeeff
**IV**: 0102030405060708090a0b0c0d0e0f10

### aes-128-ecb (Electronic Codebook):

**Encriptação:**
Comando utilizado:

![Figura 2](/Images/LOGBOOK9/Task2_image1.png)

Flags especificadas:
-aes-128-ecb: Especifica o algoritmo e modo de cifra.
-e: Indica que queremos cifrar.
-in plaintext.txt: Ficheiro de entrada.
-out ciphertext_ecb.bin: Ficheiro de saída.
-K: Chave em hexadecimal.

![Figura 3](/Images/LOGBOOK9/Task2_image2.png)

**Desencriptação:**
Comando utilizado:

![Figura 4](/Images/LOGBOOK9/Task2_image3.png)

Flags especificadas:
-aes-128-ecb: Especifica o algoritmo e modo de cifra.
-d: Indica decifragem.
-in: Ficheiro cifrado.
-out: Ficheiro decifrado.
-K: Chave em hexadecimal.

Conteúdo do ficheiro desencriptado (decrypted_ecb.txt):

```
A tecnologia tem desempenhado um papel crucial na transformação da sociedade moderna. Com o avanço da internet e das comunicações digitais, as pessoas estão mais conectadas do que nunca. A informação está disponível na ponta dos dedos, e o conhecimento é compartilhado globalmente em questão de segundos.

A inteligência artificial e a automação estão revolucionando indústrias inteiras, desde a manufatura até os serviços. Máquinas inteligentes estão assumindo tarefas repetitivas, permitindo que os seres humanos se concentrem em atividades mais criativas e estratégicas.

No entanto, esses avanços também trazem desafios. Questões relacionadas à privacidade, segurança de dados e ética na inteligência artificial estão no centro dos debates atuais. É essencial que o desenvolvimento tecnológico seja acompanhado por regulamentações adequadas e uma compreensão profunda de suas implicações sociais.

A educação também está se adaptando a essa nova realidade. O aprendizado online e os recursos digitais estão tornando a educação mais acessível, mas também exigem novas habilidades dos educadores e estudantes. A capacidade de aprender continuamente e se adaptar é mais importante do que nunca no mercado de trabalho em constante evolução.

Em resumo, a tecnologia oferece inúmeras oportunidades para melhorar a vida humana, mas é necessário abordá-la com responsabilidade e consciência. O futuro dependerá de como equilibramos a inovação com os valores humanos fundamentais.
```

**Conclusão:** O conteúdo foi desencriptado corretamente e é idêntico ao texto original.

### aes-128-cbc (Cipher Block Chaining):

**Encriptação:**
Comando utilizado:

![Figura 5](/Images/LOGBOOK9/Task2_image4.png)

Flags especificadas:
-aes-128-cbc: Algoritmo e modo de cifra.
-e: Indica que queremos cifrar.
-in plaintext.txt: Ficheiro de entrada.
-out ciphertext_cbc.bin: Ficheiro de saída.
-K: Chave em hexadecimal.
-iv: Vetor de inicialização.

![Figura 6](/Images/LOGBOOK9/Task2_image5.png)

**Desencriptação:**
Comando utilizado:

![Figura 7](/Images/LOGBOOK9/Task2_image6.png)

Flags especificadas:
-aes-128-cbc: Algoritmo e modo de cifra.
-d: Indica que queremos desencriptar.
-in ciphertext_cbc.bin: Ficheiro cifrado.
-out decrypted_cbc.txt: Ficheiro desencriptado.
-K: Chave em hexadecimal.
-iv: Vetor de inicialização.

Conteúdo do ficheiro desencriptado (decrypted_cbc.txt):
```
A tecnologia tem desempenhado um papel crucial na transformação da sociedade moderna. Com o avanço da internet e das comunicações digitais, as pessoas estão mais conectadas do que nunca. A informação está disponível na ponta dos dedos, e o conhecimento é compartilhado globalmente em questão de segundos.

A inteligência artificial e a automação estão revolucionando indústrias inteiras, desde a manufatura até os serviços. Máquinas inteligentes estão assumindo tarefas repetitivas, permitindo que os seres humanos se concentrem em atividades mais criativas e estratégicas.

No entanto, esses avanços também trazem desafios. Questões relacionadas à privacidade, segurança de dados e ética na inteligência artificial estão no centro dos debates atuais. É essencial que o desenvolvimento tecnológico seja acompanhado por regulamentações adequadas e uma compreensão profunda de suas implicações sociais.

A educação também está se adaptando a essa nova realidade. O aprendizado online e os recursos digitais estão tornando a educação mais acessível, mas também exigem novas habilidades dos educadores e estudantes. A capacidade de aprender continuamente e se adaptar é mais importante do que nunca no mercado de trabalho em constante evolução.

Em resumo, a tecnologia oferece inúmeras oportunidades para melhorar a vida humana, mas é necessário abordá-la com responsabilidade e consciência. O futuro dependerá de como equilibramos a inovação com os valores humanos fundamentais.
```

**Conclusão:** O conteúdo foi desencriptado corretamente e é idêntico ao texto original.

### aes-128-ctr (Counter Mode)

**Encriptação:**
Comando utilizado:

![Figura 8](/Images/LOGBOOK9/Task2_image7.png)

Flags especificadas:
-aes-128-ctr: Algoritmo e modo de cifra.
-e: Indica que queremos cifrar.
-in plaintext.txt: Ficheiro de entrada.
-out ciphertext_ctr.bin: Ficheiro de saída.
-K: Chave em hexadecimal.
-iv: Vetor de inicialização.

![Figura 9](/Images/LOGBOOK9/Task2_image8.png)

**Desencriptação:**
Comando utilizado:

![Figura 10](/Images/LOGBOOK9/Task2_image9.png)

Flags especificadas:
-aes-128-ctr: Algoritmo e modo de cifra.
-d: Indica que queremos desencriptar.
-in ciphertext_ctr.bin: Ficheiro cifrado.
-out decrypted_ctr.txt: Ficheiro desencriptado.
-K: Chave em hexadecimal.
-iv: Vetor de inicialização.

Conteúdo do ficheiro desencriptado (decrypted_ctr.txt):
```
A tecnologia tem desempenhado um papel crucial na transformação da sociedade moderna. Com o avanço da internet e das comunicações digitais, as pessoas estão mais conectadas do que nunca. A informação está disponível na ponta dos dedos, e o conhecimento é compartilhado globalmente em questão de segundos.

A inteligência artificial e a automação estão revolucionando indústrias inteiras, desde a manufatura até os serviços. Máquinas inteligentes estão assumindo tarefas repetitivas, permitindo que os seres humanos se concentrem em atividades mais criativas e estratégicas.

No entanto, esses avanços também trazem desafios. Questões relacionadas à privacidade, segurança de dados e ética na inteligência artificial estão no centro dos debates atuais. É essencial que o desenvolvimento tecnológico seja acompanhado por regulamentações adequadas e uma compreensão profunda de suas implicações sociais.

A educação também está se adaptando a essa nova realidade. O aprendizado online e os recursos digitais estão tornando a educação mais acessível, mas também exigem novas habilidades dos educadores e estudantes. A capacidade de aprender continuamente e se adaptar é mais importante do que nunca no mercado de trabalho em constante evolução.

Em resumo, a tecnologia oferece inúmeras oportunidades para melhorar a vida humana, mas é necessário abordá-la com responsabilidade e consciência. O futuro dependerá de como equilibramos a inovação com os valores humanos fundamentais.
```

**Conclusão:** O conteúdo foi desencriptado corretamente e é idêntico ao texto original.

### Pergunta: Ao cifrar, que flags teve que especificar? Qual a diferença entre estes diversos modos?

1. Flags especificadas:

Comum a todos os modos:

-e: Indica que queremos cifrar.
-in: Nome do ficheiro de entrada (plaintext.txt no caso).
-out: Nome do ficheiro de saída (ciphertext_{modo}.bin).
-K: Chave de encriptação em hexadecimal.

Para aes-128-cbc e aes-128-ctr:

-iv: Vetor de inicialização (Initialization Vector) em hexadecimal.

2. Diferenças entre os modos:

ECB (Electronic Codebook):

Simples e rápido, mas não utiliza IV.
Blocos idênticos de plaintext resultam em blocos idênticos de ciphertext, expondo padrões no texto cifrado.
CBC (Cipher Block Chaining):

Usa um IV para encadear os blocos.
Cada bloco de plaintext é combinado (XOR) com o bloco cifrado anterior antes de ser encriptado.
Mais seguro que o ECB, pois elimina padrões.
CTR (Counter Mode):

Usa um IV combinado com um contador que incrementa a cada bloco.
Converte o bloco em um cifrador de fluxo (stream cipher).
Permite cifragem paralela, ao contrário do CBC e ECB.

### Pergunta: Ao decifrar, que flags teve que especificar? Qual a diferença principal entre aes-128-ctr e os restantes modos?

1. Flags especificadas:

Comum a todos os modos:

-d: Indica que queremos decifrar.
-in: Nome do ficheiro cifrado de entrada (ciphertext_{modo}.bin).
-out: Nome do ficheiro decifrado de saída (decrypted_{modo}.txt).
-K: Chave de encriptação em hexadecimal.
Para aes-128-cbc e aes-128-ctr:

-iv: O mesmo IV usado durante a cifragem.

2. Diferença principal entre aes-128-ctr e os restantes modos:

CTR é um modo de fluxo (stream cipher):

Cada bloco é processado de forma independente.
O IV combinado com o contador cria um fluxo pseudoaleatório para cifrar os blocos.
Permite decifrar blocos específicos sem necessidade de processar todos os anteriores (acesso aleatório).
Resistente à propagação de erros: um erro em um bloco não afeta os seguintes.
ECB e CBC são modos de bloco (block ciphers):

ECB: Decifra blocos de forma independente, mas vulnerável a padrões.
CBC: Depende dos blocos anteriores devido ao encadeamento. Um erro em um bloco afeta o seguinte.

Em resumo, podemos concluir que o modo aes-128-ctr oferece maior flexibilidade, eficiência paralela e resistência a erros, enquanto os modos cbc e ecb apresentam um processamento mais linear.

## Task 5: Error Propagation – Corrupted Cipher Text

Nesta tarefa, investigámos o impacto de corromper um único byte no criptograma ao utilizar os modos de cifra aes-128-ecb, aes-128-cbc e aes-128-ctr. Para isso, realizámos os seguintes passos:

### aes-128-ecb (Electronic Codebook):

**Ficheiro utilizado:**

O ficheiro de entrada foi o plaintext.txt, criado nas tarefas anteriores, com pelo menos 1000 bytes.

**Encriptação:**
Comando utilizado:

```
openssl enc -aes-128-ecb -e -in plaintext.txt -out ciphertext_ecb.bin \
-K 00112233445566778899aabbccddeeff
```

**Alteração do Byte 54:**

Alterámos o valor hexadecimal do byte na posição 200 ( 200 = 50 * 4) utilizando o editor bless:

```
bless ciphertext_ecb.bin
```

![Figura 11](/Images/LOGBOOK9/Task3_image1.png)

![Figura 12](/Images/LOGBOOK9/Task3_image2.png)

**Desencriptação:**
Comando utilizado:

```
openssl enc -aes-128-ecb -d -in ciphertext_ecb.bin -out decrypted_ecb.txt \
-K 00112233445566778899aabbccddeeff
```

Conteúdo do ficheiro desencriptado (decrypted_ctr.txt):

```
A tecnologia tem desempenhado um papel crucial na transformaÃ§Ã£o da sociedade moderna. Com o avanÃ§o da internet e das comunicaÃ§Ãµes digitais, as pessoas estÃ£o mais conectadas do que nunca.ý(u8Üž°ÛBpO¿JxÁestÃ¡ disponÃ­vel na ponta dos dedos, e o conhecimento Ã© compartilhado globalmente em questÃ£o de segundos.

A inteligÃªncia artificial e a automaÃ§Ã£o estÃ£o revolucionando indÃºstrias inteiras, desde a manufatura atÃ© os serviÃ§os. MÃ¡quinas inteligentes estÃ£o assumindo tarefas repetitivas, permitindo que os seres humanos se concentrem em atividades mais criativas e estratÃ©gicas.

No entanto, esses avanÃ§os tambÃ©m trazem desafios. QuestÃµes relacionadas Ã  privacidade, seguranÃ§a de dados e Ã©tica na inteligÃªncia artificial estÃ£o no centro dos debates atuais. Ã essencial que o desenvolvimento tecnolÃ³gico seja acompanhado por regulamentaÃ§Ãµes adequadas e uma compreensÃ£o profunda de suas implicaÃ§Ãµes sociais.

A educaÃ§Ã£o tambÃ©m estÃ¡ se adaptando a essa nova realidade. O aprendizado online e os recursos digitais estÃ£o tornando a educaÃ§Ã£o mais acessÃ­vel, mas tambÃ©m exigem novas habilidades dos educadores e estudantes. A capacidade de aprender continuamente e se adaptar Ã© mais importante do que nunca no mercado de trabalho em constante evoluÃ§Ã£o.

Em resumo, a tecnologia oferece inÃºmeras oportunidades para melhorar a vida humana, mas Ã© necessÃ¡rio abordÃ¡-la com responsabilidade e consciÃªncia. O futuro dependerÃ¡ de como equilibramos a inovaÃ§Ã£o com os valores humanos fundamentais.
```


### aes-128-cbc (Cipher Block Chaining):

**Ficheiro utilizado:**

O ficheiro de entrada foi o plaintext.txt, criado nas tarefas anteriores, com pelo menos 1000 bytes.

**Encriptação:**
Comando utilizado:

```
openssl enc -aes-128-cbc -e -in plaintext.txt -out ciphertext_cbc.bin \
-K 00112233445566778899aabbccddeeff -iv 0102030405060708090a0b0c0d0e0f10
```

**Alteração do Byte 54:**

Alterámos o valor hexadecimal do byte na posição 200 ( 200 = 50 * 4) utilizando o editor bless:

```
bless ciphertext_cbc.bin
```

![Figura 13](/Images/LOGBOOK9/Task3_image3.png)

![Figura 14](/Images/LOGBOOK9/Task3_image4.png)

**Desencriptação:**
Comando utilizado:

```
openssl enc -aes-128-cbc -d -in ciphertext_cbc.bin -out decrypted_cbc.txt \
-K 00112233445566778899aabbccddeeff -iv 0102030405060708090a0b0c0d0e0f10
```

Conteúdo do ficheiro desencriptado (decrypted_ctr.txt):
```
A tecnologia tem desempenhado um papel crucial na transformaÃ§Ã£o da sociedade moderna. Com o avanÃ§o da internet e das comunicaÃ§Ãµes digitais, as pessoas estÃ£o mais conectadas do que nunca.]K¡«}Ëž`µ	estÃ¡ di²ponÃ­vel na ponta dos dedos, e o conhecimento Ã© compartilhado globalmente em questÃ£o de segundos.

A inteligÃªncia artificial e a automaÃ§Ã£o estÃ£o revolucionando indÃºstrias inteiras, desde a manufatura atÃ© os serviÃ§os. MÃ¡quinas inteligentes estÃ£o assumindo tarefas repetitivas, permitindo que os seres humanos se concentrem em atividades mais criativas e estratÃ©gicas.

No entanto, esses avanÃ§os tambÃ©m trazem desafios. QuestÃµes relacionadas Ã  privacidade, seguranÃ§a de dados e Ã©tica na inteligÃªncia artificial estÃ£o no centro dos debates atuais. Ã essencial que o desenvolvimento tecnolÃ³gico seja acompanhado por regulamentaÃ§Ãµes adequadas e uma compreensÃ£o profunda de suas implicaÃ§Ãµes sociais.

A educaÃ§Ã£o tambÃ©m estÃ¡ se adaptando a essa nova realidade. O aprendizado online e os recursos digitais estÃ£o tornando a educaÃ§Ã£o mais acessÃ­vel, mas tambÃ©m exigem novas habilidades dos educadores e estudantes. A capacidade de aprender continuamente e se adaptar Ã© mais importante do que nunca no mercado de trabalho em constante evoluÃ§Ã£o.

Em resumo, a tecnologia oferece inÃºmeras oportunidades para melhorar a vida humana, mas Ã© necessÃ¡rio abordÃ¡-la com responsabilidade e consciÃªncia. O futuro dependerÃ¡ de como equilibramos a inovaÃ§Ã£o com os valores humanos fundamentais.
```


### aes-128-ctr (Counter Mode)

**Ficheiro utilizado:**

O ficheiro de entrada foi o plaintext.txt, criado nas tarefas anteriores, com pelo menos 1000 bytes.

**Encriptação:**
Comando utilizado:

```
openssl enc -aes-128-ctr -e -in plaintext.txt -out ciphertext_ctr.bin \
-K 00112233445566778899aabbccddeeff -iv 0102030405060708090a0b0c0d0e0f10
```

**Alteração do Byte 54:**

Alterámos o valor hexadecimal do byte na posição 200 ( 200 = 50 * 4) utilizando o editor bless:

```
bless ciphertext_ctr.bin
```

![Figura 14](/Images/LOGBOOK9/Task3_image5.png)

![Figura 15](/Images/LOGBOOK9/Task3_image6.png)

**Desencriptação:**
Comando utilizado:

```
openssl enc -aes-128-ctr -d -in ciphertext_ctr.bin -out decrypted_ctr.txt \
-K 00112233445566778899aabbccddeeff -iv 0102030405060708090a0b0c0d0e0f10
```

Conteúdo do ficheiro desencriptado (decrypted_ctr.txt):

```
A tecnologia tem desempenhado um papel crucial na transformaÃ§Ã£o da sociedade moderna. Com o avanÃ§o da internet e das comunicaÃ§Ãµes digitais, as pessoas estÃ£o mais conectadas do que nunca. A infor:aÃ§Ã£o estÃ¡ disponÃ­vel na ponta dos dedos, e o conhecimento Ã© compartilhado globalmente em questÃ£o de segundos.

A inteligÃªncia artificial e a automaÃ§Ã£o estÃ£o revolucionando indÃºstrias inteiras, desde a manufatura atÃ© os serviÃ§os. MÃ¡quinas inteligentes estÃ£o assumindo tarefas repetitivas, permitindo que os seres humanos se concentrem em atividades mais criativas e estratÃ©gicas.

No entanto, esses avanÃ§os tambÃ©m trazem desafios. QuestÃµes relacionadas Ã  privacidade, seguranÃ§a de dados e Ã©tica na inteligÃªncia artificial estÃ£o no centro dos debates atuais. Ã essencial que o desenvolvimento tecnolÃ³gico seja acompanhado por regulamentaÃ§Ãµes adequadas e uma compreensÃ£o profunda de suas implicaÃ§Ãµes sociais.

A educaÃ§Ã£o tambÃ©m estÃ¡ se adaptando a essa nova realidade. O aprendizado online e os recursos digitais estÃ£o tornando a educaÃ§Ã£o mais acessÃ­vel, mas tambÃ©m exigem novas habilidades dos educadores e estudantes. A capacidade de aprender continuamente e se adaptar Ã© mais importante do que nunca no mercado de trabalho em constante evoluÃ§Ã£o.

Em resumo, a tecnologia oferece inÃºmeras oportunidades para melhorar a vida humana, mas Ã© necessÃ¡rio abordÃ¡-la com responsabilidade e consciÃªncia. O futuro dependerÃ¡ de como equilibramos a inovaÃ§Ã£o com os valores humanos fundamentais.
```

### Análise do Impacto
Abaixo, apresentamos os resultados obtidos ao alterar o byte 54 nos diferentes modos de cifra:

a. aes-128-ecb

Impacto no texto decifrado:

Apenas o bloco correspondente ao byte 54 foi corrompido.
Não houve propagação do erro para os outros blocos.
Razão para o comportamento:

No modo ECB, cada bloco é cifrado de forma independente. Um erro em um byte do criptograma afeta apenas o bloco correspondente no texto decifrado.

b) aes-128-cbc

Impacto no texto decifrado:

O erro afetou:
O bloco correspondente ao byte 54 (totalmente corrompido).
O bloco seguinte (parcialmente corrompido).
Razão para o comportamento:

No modo CBC, cada bloco depende do bloco anterior devido ao encadeamento. Um erro em um byte do criptograma propaga-se para o bloco seguinte.

c) aes-128-ctr

Impacto no texto decifrado:

Apenas o byte correspondente ao byte 54 no texto decifrado foi corrompido.
Não houve impacto em outros bytes ou blocos.
Razão para o comportamento:

No modo CTR, cada byte é cifrado/decifrado de forma independente usando um fluxo pseudoaleatório gerado pelo contador. Alterar um byte no criptograma afeta apenas o byte correspondente no texto decifrado.

### Tabela de Comparação dos Modos

| Modo | Bytes Corrompidos no Texto Decifrado | Propagação de Erros |
|------|--------------------------------------|----------------------|
| ECB  | 1 bloco (16 bytes)                  | Não                 |
| CBC  | 1 bloco (16 bytes) + bloco seguinte | Sim                 |
| CTR  | 1 byte                              | Não                 |
