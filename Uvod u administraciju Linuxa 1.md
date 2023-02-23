# Uvod u administraciju Linuxa 1 - Bilješke 🐧

Ispod možete naći bilješke iz materijala [**Osnove administracije operacijskog sustava 1 (Linux) - Ivan Rako**](https://www.srce.unizg.hr/files/srce/docs/edu/l101_polaznik_1.pdf).
Navedeni materijali predtavljaju sjajan izvor informacija svima koji se počijnu baviti administracijom operativnog sustava Linux.

- [📖 1 UVOD](#1-uvod)
- [📖 2 INSTALACIJA LINUXA](#2-instalacija-linuxa)
- [📖 3 NAREDBENA LINIJA](#3-naredbena-linija)
- [📖 4 UPRAVLJANJE DATOTEKAMA I DIREKTORIJIMA](#4-upravljanje-datotekama-i-direktorijima)
- [📖 5 OBRADA TEKSTA](#5-obrada-teksta)
- [📖 6 NAPREDNO UPRAVLJANJE TEKSTOM](#6-Napredno-upravljanje-tekstom)
- [📖 7 UREĐIVAČ TEKSTA VI](#7-Uređivač teksta vi)
- [📖 8 UPRAVLJANJE UREĐAJIMA U DIREKTORIJU /DEV](#8-Upravljanje uređajima u direktoriju /dev)
- [📖 9 DATOTEČNI SUSTAV](#9- Datotečni sustav)
- [📖 10 UPRAVLJANJE PROCESIMA](#10-Upravljanje procesima)
- [📖 11 INSTALACIJA SOFTVERA](#5-Instalacija softvera)

# 📖 1 UVOD

- Linux je ime za jezgru (kernel) OS-a sličnog Unix-u, a dobio je ime po Linusu Torvaldsu.
- Linus je 1991. g. objavio izvorni kod na Internetu, te pozvao sve zainteresirane da sudjeluju u njegovom daljnjem razvoju.
Tako da je danas kernel Linuxa zajedničko djelo progtramera i hakera diljem svijeta.
- Linux je slobodan softver.
Za njegov spontani razvoj zaslužni su brzi razvoj Interneta i licenca za korištenje GPL.
1996. g. utemeljen je KDE (K Desktop Environment), koji je Linuxu dao vrhunsko grafičko sučelje.
Budući da KDE u početku nije bio slobodan softver, potaknula je godinu kasnije razvoj grafičkog sučelja GNOME.

## Prednosti uporabe Linuxa

- SIGURNOST: 
Osnovni dizajn Linuxa otežava ozbiljne napade na sustav.
- STABILNOST:
Stabilnosti sustava pridonosi modularan dizajn kernela Linuxa, koji omogućava da se pojedini dijelovi sustava zaustavljaju i ponovno pokreću prema potrebi.
- POSJEDOVANJE VIŠE GRAFIČKIH SUUČELJA:
Linux se s nekim vizualno siromašnijim sučeljem može instalirati i na znatno sporijim računalima, koja bi za Windows OS bila ipak preslaba.


## Filozofija slobodnog softvera i otvorenog izvornog koda

- SLOBODNA PROGRAMSKA PODRŠKA (slobodni softver) je takav softver koji se može upotrebljavati proučavati i mijenjati bez ograničenja, kao i presnimavati i distribuirati bez ograničenja.
- Da bi se softver mogao distibuirati kao slobodan, mora biti dostupan u obliku koji je čovjeku razumljiv ( u izvornom kodu).
- 80-tih godina 20. stoljeća nastao je pokret koji se zalaže za ponovno uvođenje slobodnog softvera u svakodnevni rad.
Taj je pokret utemeljio Richard Stallman, iako je slobodni softver postojao i prije njega.

- Stallman-ova definicija slobodnog softvera:
1. Sloboda pokretanja programa u bilo koje svrhe.
2. Sloboda proučavanja rada programa i njegove prilagodbe svojim osobnim potrebama.
3. Sloboda distribucije presnimaka da bi se pomoglo.
4. Sloboda poboljšavanja programa i izmjenjenih inačica javnosti za dobrobit zajednice.

## Najpopularnije Linux distribucije

- OS Linuxa je sastavljen od:
1. Linux jezgre ;
2. sistemskih i aplikacijskih programa GNU;
3. grafičkog sustava Xorg;
4. grafičkog okruženja.

Softver se može distribuirati :
1. U izvornom kodu;
2. U predviđenim paketima (koji sadrže izvršne inačice softvera);
3. Kao izvršni program ili skripta koja sama instalira softver (također u izvrđnom obliku).

Dva su najčešća sustava za upravljanje paketima : RPM i DPKG.
- RPM-distribucije: RedHat, Fedora, Mandriva, OpenSuse, ...
- DPKG distribucije su sve one koje se temelje na Debianu.
Debian je veliki međunarodni projekt sa filozofijom slobodnog softvera i osnova je za najveći broj drugih distribucija.

## Web serveri

- Apache HTTP SERVER: je besplatni web server otorenog koda za OS-ove temeljene na Unixu.
Apache je najčešće korišteni web-server na Internetu sa udjelom višim od 50%.

- Nginx je treći najpopularniji web-server iza Apache-a i MS IIS-a, također otvorenog koda.
Projekt Nginx pokrenut je sa fokusom na visoku konkurentnost, performanse i malu potrošnju RAM-a.

## Sustavi za upravljanje bazama podataka

- PostgreSQL je robustan , objektno orjentiran sustav za upravljanje relacijskim bazama podataka otvorenog koda, i sadrži bogat izvor vrsta podataka, laku nadogradivost i nadograđeni skup SQL naredbi.
- MySQL je također sustav za upravljanje bazama podataka otvorenog koda i čest je izbor baze za projekte otvorenog koda, a distribuira se kao sastavni dio server distribucija. MySQL je optimiziran da bude brz nauštrb njegove funkcionalnosti.
Nasuprot tome, vrlo je stabilna i ima dobro dokumentirane module i ekstenzije, te podršku brojnih programskih jezika: PHP, Java, Pearl, Python,....

## Serveri elektroničke pošte

- Sendmail je praktično najčešći i najrašireniji, a i jedan od prvih programa za razmjenu elektroničke pošte.
Sendmail glasi kao brz, skalabilan i potpun MTA (Mail Transfer Agent) - u smislu podržavanja najvećeg broja mogućnosti i proširenja protokola.
Riječ je o jednom od najpotpunijih i vjerojatno najsloženijih MTA-ova na tržištu.
- Postfix je program napisan kao alternativa Sendmailu. Postfix je prilično sigurna implementacija SMTP-a (Simple Mail Transfer Protocol) i
arhitekturalno je server podijeljen na niz minimalnih jednostavnih servisa, od kojih svaki obavlja svoj posao.
Postfix je brz, učinkovit i siguran.

## DNS BIND

- DNS (Domain Name Server) je hijerarhijsko raspoređen sustav imenovanja računala, servisa ili  bilo kojeg uređaja spojenog na mrežu.
On povezuje različite informacije sa domenskim imenima pripisanim svakom od subjekata u domeni.
Prevodi lako pamtljiva imena u numeričke IP adrese, koje su potrebne za lociranje servisa i uređaja.
- 1984 godine je BIND koji se naširoko distribuirao i bio je dominantan imenički server korišten na Internetu.
- Bind je otvorenog koda i postao je de facto standard za imeničke servere.

## ISC DHCP

- DHCP (Dynamic Host Configuration Protocol) je mrežni protokol koji se koristi za automatsko dodjeljivanje IP adresa i drugih mrežnih postavki kao što su:
gateway, subnet maska i DNS.  
- ISC DHCP (Internet Software Consorcium DHCP) je najpoznatija implementacija otvorenog koda.

# 📖 2. INSTALACIJA LINUXA

## Struktura datotečnog sustava

- Za pristupanje resursima na tvrdom disku , OS se koristi mehanizmom koji se zove montiranje (mounting). Za Linux OS-ove to znači da se spaja (montira) na direktorij koje se zove točka montiranja (mount point).

- Za korisnika je datotečni sustav jednostavno stablo s direktorijima i poddirektorijima.
- Korijen tog stabla se zove root i pokazuje se znakom: / 
- To je prvi direktorij na koji OS uključuje disk ili neki resurs, koji se onda zove root device.
- Vaćno je naglasiti da postoji i direktorij /root , koji služi za korisničke podatke administratorskog korisnika root.
- Proces dijeljenja diska na manje dijelove (particije) se zove particioniranje diska.

- / - Primarna hijerarhija, root direktorij cjelokupnog sustava i "početak";
- /bin - izvršne datoteke važnih naredbi na rzini single-user moda, i naredbe za sve korisnike;
- /dev - Datoteke koje predstavljaju same fizičke i virtualne direktorije;
- /etc - konfiguracijske datoteke sustava koje vrijede za cijeli sustav;
- /lib - važne biblioteke za programe iz direktorija /bin/ i /sbin/ ;
- /mnt - privremeno montirani datotečni sustavi;
- /proc - virtualni datotečni sustav za prikaz rada kernela i procesau obliku tekstualnih datoteka;
-  /sbin - važni sistemski programi (npr.:  `init` ,  `route`, `ifconfig` )

Kada je root motiran (priključen), direktoriji i poddirektoriji na tom uređaju (root device) mogu se koristiti kao točke montiranja i za druge resurse, formirajući tako slijed direktorija uređen kao stablo!

- Program za pokretanje OS-a (bootloader) prilikom pokretanja OS-a daje kernelu informacije gdje se nalazi root device.
- Drugi uređaji su montirani čitajući instrukcije iz datoteke /etc/fstab.

## SWAP

- Prostor za SWAP na Linuxu je jedan oblik virtualne memorije. To znači ako računalo ostane bez radne memorije, može da koristi virtualnu memoriju ili swap.
- Particija SWAP je osnovna za procese suspendiranja i hibernacije računala.
- Tokom particioniranja diskova treba donijeti odluku koliko je prostora potrebno za particiju SWAP. Za to nema određenih pravila , a veličina prostora za SWAP ovisi o vrsti aplikacija koje se pokreću na računalu.
- Preporučena vrijednost SWAP particije tradicionalno je bila dvostruko veća od količine ugrađene radne memorije (RAM-a).

## Instalacija distribucije Debian GNU/Linux

Postoje 2 načina instalacije distribucije Debiana:
- mrežna instalacija;
- cjelovita instalacija sa medija.

Podrazumjevano grafičko sučelje koje dolazi sa distribucijom Debian GNU/Linux je GNOME.
Prilikom instalacije moguće je odabrati i neke još 3 najčešće upotrebljavana grafička sučelja:
- KDE (K Desktop Environment);
- LXDE;
- Xfce.

- Mrežna instalacija :
Kod ovog načina instalacije na mediju se nalaze samo mrežne datoteke za pokretanje procedure. Svi se drugi paketi preuzimaju izravno sa udaljenog servera na kojem se nalazi repozitorij Debian paketa. Instalacijski medij je relativno malen ( oko 200 MB) i može se brzo preuzeti na računalo. To je ujedno i najčešći način instalcije Linux Debian OS-a.

- Cjelovita instalacija s medija:
Kod ovog načina instalacije na mediju već se nalaze svi programski paketi potrebni za instalaciju Debiana.

## Instalacija Debian Linuxa

- Prije instalacije treba prikupiti podatke o mrežnim parametrima servera na koji će se instalirati OS Debian.
- Ako je konfiguracija mrežnih parametara dinamička (DHCP), ti će se parametri podesiti automatski.
- Ako je konfiguracija statička, treba prikupiti i IP adresu, mrežnu masku, default gateway i adrese DNS-ova.
- I kod statičke i dinamičke konfiguracije potrebno je prije pripremiti ime računla i njegovu domenu.
- Potrebno je zatim i odabrati regionalne postavke;
- Slijedi postavka mreže, lozinke i izrada prvog korisničkog računa;
- Zatim slijedi particioniranje diskova, odabir točke montiranja i kreiranja swap particije;
- Na kraju slijedi odabir dodatnog softvera i prijava na sustav , gdje se kreira i GRUB bootloader koji je pokretač OS-a i može raditi i sa Windows i Linux OS-ovima.


# 📖 3 NAREDBENA LINIJA

## 3.1. DOKUMENTACIJA

### Stranica man

- Linux sustavi su generalno jako dobro dokumentirani.
- Informacije o korištenju određene naredbe ili funkcije mogu se naći na tzv. man stranicama.
- MAN (Unix Programmer's Manual)pružaju informacije o naredbama, sistemskim pozivima, formatima datoteka i održavanju sustava.
- sintaksa naredbe man:
   `man mkdir`
   
- MAN stranice su podijeljene u nekoliko dijelova:
- NAME - naziv naredbe;
- SYNOPSYS - prikazuuje sintaksu naredbe i raspoložive opcije i argumente;
- DESCRIPTION - pregled djelovanja datoteke;
- OPTIONS - raspoložive opcije koje mjenjaju funkciju ili efekt naredbe;
- OPERANDS - cilj naredbe na kojemu se naredba izvršava;
- FILES - datoteke vezane za tu naredbu;
- SEE ALSO - upućuje na povezane naredbe i teme.

### Naredba whatis

- Naredba whatis služi za pretraživanje man stranica po ključnoj riječi.
  `whatis mkdir`
  
## 3.2. NAREDBENA LINIJA

### 3.2.1. Interaktivna ljuska (shell)

- Osnovni način interakcije sa računalom na Linuxu je naredbena linija.
- Ljuska (shell) interpretira instrukcije utipkane sa tastature.
- Kao posrednik između korisnika i OS-a služi program koji se zove ljuska (eng. shell).
- Shell je zapravo programski jezik sa varijablama, kontrolnim naredbama, potprogramima, prekidima itd. Organiziran je kao tumač ili interpreter naredbi,
što znači da pročita redak teksta, interpretira naredbu i poduzme sve potrebne akcije za njezino izvođenje.
Kada je naredba izvedena, ljuska (shell) daje informaciju korisniku (prompt) da je spremna prihvatiti sljedeću naredbu.
Prompt ljuske završava znakom $ za običnog korisnika ili znakom # za administratora.

- Ljuska (shell) nije dio kernela sustava, nego korisnički program. Svatko može napisati svoj program koji će imati ulogu ljuske, međutim poželjno je da to bude standardni program rasprostranjen na svim instalacijama Linuxa, čime se postiže kompatibilnost rada na različitim računalima.
- Ljuska je također i programsko okruženje u kojem se mogu izvoditi automatizirani zadaci.
- Programi ljuske (shell programs) nazivaju se skripte.

- Najčešće ljuske:
- /bin/sh - The Bourne Shell
- /bin/bash - The Bourne Again Shell
- /bin/ksh - The Korn Shell
- /bin/csh - The C Shell
- /bin/tcsh - Tom's C Shell 
- /bin/zsh - Z Shell

- Najčešće upotrebljavana ljuska na Linux distribucijama je BASH ( The Bourne Again Shell).
- Sintaksa naredbe ljuske:
  `naredba [opcije] {argumenti}`
  ```
  $ echo "ovo je tekst" 
  ovo je tekst
  ```

- Za razliku od DOS operativnog sustava , u kojem je bilo moguće pokrenuti upisivanjem samo ime za naredbu (bez njene putanje) u tekućem direktoriju čija putanja nije ekspicitno definirana u varijabli PATH, u okruženju Unix/Linux to nije moguće.
Za pokretanje izvršne datoteke koja se nalazi u tekućem direktoriju treba se koristiti njenom relativnom ili apsolutnm putanjom.

Npr. apsolutna putanja do naredbe fdisk:
`# /sbin/fdisk`
Njezina relativna putanja je:
`# ../sbin/fdisk`

### 3.2.2. Varijable ljuske (shell)

- Varijable ljuske , slične su varijablama korištenim u drugim programskim jezicima.
- U imenu varijable se mogu koristiti samo ALFANUMERIČKI ZNAKOVI.

Naredba echo služi za ispis teksta na zaslonu ili za ispis vrijednosti varijable.
Varijabla se poziva svojim imenom kojem prethodi znak $:
```
$ echo $BROJ 
300 
$ echo BROJ 
BROJ
```

### 3.2.3. Vrste varijabli ljuske

- Postoje 2 vrste varijabli:
- LOKALNE;
- IZVEZENE (EXPORTED);

- Lokalne varijable dostupne su samo iz trenutačne ljuske.
- Izvezene varijable dostupne su i iz trenutačne ljuske ali i svih ljuski (djece) koje su pokrenute iz te ljuske.

- Naredbe SET i ENV služe za ispis definiranih varijabli:
- Naredba SET - ispisuje sve varijable (i lokalne , i izvezene);
- Naredba ENV - ispisuje sve izvezene varijable;

- Izvezene varijable su globalne utoliko što ih "djeca" mogu referencirati!

-  Svaka lokalna varijabla može postati izvezena koristeći naredbu : export.
```
$ env | grep BROJ 
$ export BROJ 
$ env | grep BROJ 
BROJ=300
```

### 3.2.4. Osnovne predefinirane varijable

- Kada se korisnik prijavi na sustav, pokrene se njegova ljuska u kojoj može izvršavati naredbe.
- Ta ljuska ima PREDEFINIRANE VARIJABLE.
- Najčešće rabljene varijable:
- DISPLAY - Rabi ju grafičko okruženje X Windows System;
- HISTFILE - Putanja do korisnikove datoteke s povijesti naredbi;
- HOME - Putanja do korisnikova direktorija;
- LOGNAME - Ime korisnika pod kojim se pokreće trenutna ljuska;
- PATH - Popis direktorija u kojima ljuska pretražuje izvršne programe;
- PWD - Korisnikov trenutni direktorij;
- SHELL - Korisnikova trenutna ljuska;
```
$ echo $DISPLAY 
:0 
$ echo $HISTFILE 
/home/tux/.bash_history 
$ echo $HOME 
/home/tux 
$ echo $LOGNAME 
tux 
$ echo $PATH 
:/usr/local/bin:/usr/bin:/bin 
$ echo $PWD 
/home/tux 
$ echo $SHELL 
/bin/bash
```

### 3.2.5. Preusmjeravanje standardnog ulaza i izlaza

- Programima (procesima) aktiviranim iz ljuske (shella) automatski se pridjeljuju 3 "otvorene" datoteke:
stdin (standard input), stdout (standard output), stderr (standard error) sa pripadajućim brojevima : 0,1, i 2.
- Ti brojevi (File Descriptors) opisuju (adresiraju) "otovorene datoteke".
- Pojam "otvorene datoteke" označava da određeni proces ima vlasništvo nad dotičnom datotekom.
- Datoteka stdin (0) je otvorena za čitanje; a rabi se kao standardni ulaz i obično je to tipkovnica.
- Datoteka stdout (1) je otvorena za pisanje i upotrebljava se kao standardni izlaz (po definiciji je to korisnički ekran).
- Datoteka stderr (2) je otvorena za pisanje i upotrebljava se za ispis pogrešaka (isto tako je u pitanju korisnikov ekran).
- Ljuska (shell) može mjenjati dodijeljene ulazno-izlazne datoteke.
- To se postiže specijalnim znakovima <, > ili 2> u retku naredbe ispred imena datoteke za koju želimo da bude  standardni ulaz ili izlaz.
- Pritom izlaz za pogreške ostaje nepromjenjen (ekran).
- Time se izbjegava da poruke o pogreškama budu "sakrivene" u nekoj datoteci.
- Znakove < i > tumači ljuska (shell) i ne prosljeđuje ih samoj naredbi.
- Zato nije potrebno posebno kodiranje u tom slučaju.

Sljedeća naredba i slika prikazuju preusmjeravanje datoteke ime_dat na standardni ulaz procesa:
`$ naredba < ime_dat`

Sljedeća naredba i slika prikazuju preusmjeravanje standardnog izlaza procesa na datoteku ime_dat:
`$ naredba > ime_dat`

Sljedeća naredba i slika prikazuju preusmjeravanje datoteke ime_dat1 na standardni ulaz procesa, te standardnog izlaza procesa na datoteku ime_dat2:
`$ naredba < ime_dat1 > ime_dat2`

Sljedeća naredba i slika prikazuju preusmjeravanje standardnog izlaza procesa na datoteku ime_dat. Time se neće presnimiti datoteka ime_dat, tj. novi podaci će se zapisati na kraj datoteke:
`$ naredba >> ime_dat`

Ako se želi standardni izlaz za pogreške preusmjeriti u neku datoteku, to se postiže posebnim znakovima 2>. Slijedi primjer preusmjeravanja standardnog izlaza za pogreške u datoteku ime_datoteke:

`$ naredba 2> ime_dat`

### 3.2.6 Ulančavanje procesa

- Važna je osobina Unix/Linux OS-ova mogućnost ulančavanja procesa, tj. stvaranje kanala (pipes) kojima se izlaz iz jednog procesa dovodi na ulaz drugog procesa.
- Po istom principu po kojem je u prethodnim slučajevima preusmjeravan ulaz-izlaz u neku datoteku, u okviru ljuske (shella) moguće je i preusmjeravanje na drugi proces. Tijekom takvog poziva naredbe nastaje sakrivena i privremena datoteka zvana pipe na principu FIFO reda (prvi untra, prvi vani), koja omogućava programima (procesima) da rade paralelno i uz sinkronizaciju sustava , te da prenose podatke iz jednog procesa u drugi.
- Notacija za povezivanje dvaju procesa kanalom vrlo je jednostavno. Između dviju naredbi treba utipkati znak: | 
- `$ naredba1 | naredba2`
- Jednostavna notacija je imala značajan utjecaj na programsku metodologiju korisnika Unix/Linux OS-ova koji su potaknuti jednostavnošću počeli kombinirati postojeće programe umjesto gradnje novih.
- Ideja je da se od niza malih komadića (programa) kombiniraju složeniji moduli sa određenim ciljem.
- Tako je lakše definirati , dokumentirati i održavati manje cjeline; dok se povećava pouzdanost modula izvedenih iz osnovnih programa. 
- Ako želimo preusmjeriti standardni izlaz i u datoteku i na zaslon, to možemo pomoću naredbe : tee.
- Naredba tee čita ono što dobije na standardni ulaz , preusmjerava na standardni izlaz i u datoteku koja je postavljena u argumentu naredbe tee:

`$ naredba | tee ime_datoteke`

- Sljedećom naredbom ispisat ćemo sve datoteke koje počinju nizom passwd u direktorij /etc:

```
$ ls /etc/passwd* 
/etc/passwd 
/etc/passwd-
```

Ako se taj popis želi preusmjeriti u datoteku, dovoljno je u datoteku preusmjeriti standardni izlaz. Time se popis datoteka neće ispisati na zaslon (tj. standardni izlaz):

```
$ ls /etc/passwd* > /tmp/popis.txt 
$ cat /tmp/popis.txt 
/etc/passwd 
/etc/passwd-
```

Ako se taj popis želi prikazati i na zaslonu (standardni izlaz) i preusmjeriti u datoteku, potrebno je rabiti naredbe tee:

```
$ ls /etc/passwd* | tee /tmp/popis.txt 
/etc/passwd 
/etc/passwd- 
$ cat /tmp/popis.txt 
/etc/passwd 
/etc/passwd-
```

### 3.2.7. Povijest naredbi (history)

- Da bi se izlistao popis već prije pokrenutih naredbi, ljuska (shell) ima ugrađenu naredbu: history.
- Naredba history pokreće se bez argumenata i daje popis izvršenih naredbi:

```
$ history 
1 VRIJEME="Danasnji datum je `date +%d.%m.%Y.`" 
2 echo $VRIJEME
```

- Ljuska (shell) popis svih naredbi snima u datoteku ~/.bash_history 

- Korisnik može i strelicama na tipkovnici gore i dole doći do neke od ranije izvršenih naredbi, odabirom i pritiskom na tipku : Enter

- Ako korisnik kao prvi znak naredbe unese znak !, te iza njega neki drugi znak, ljuska (shell) će pokrenuti zadnju izvršenu naredbu koja je počinjala sa tim znakom.
- Ako odaberete broj iz povijesti, koji je dobijen naredbom history izvršit će se naredba pod tim rednim brojem.

Sljedeća naredba pokreće zadnju izvršenu naredbu koja je započinjala znakom x:
`$ !x`

Sljedeća naredba pokreće naredbu s rednim brojem 2 u povijesti naredbi:
`$ !2`

Sljedeća naredba pokreće zadnju izvršenu naredbu:
`$ !!`

Sljedeća naredba pokreće zadnju naredbu tako da zamijeni string1 sa string2 u toj naredbi:
`$ ^string1^string2`

### 3.2.8. Aliasi i automatsko nadopunjavanje

- Ako korisnik ima potrebu za češćim pokretanjem određene naredbe , može napraviti alias ( sa naredbom: alias)

`$ alias mojprogram='naredba [opcije] {argumenti}'`

- Slijedi primjer gdje se izrađuje alias naziva trazi koji pokreće naredbu find /etc -name passwd.
- Alias trazi time pokreće naredbu find koja pretražuje direktorij /etc i traži sve datoteke koje se zovu passwd.

```
$ alias trazi='find /etc -name passwd' 
$ trazi 
/etc/pam.d/passwd 
/etc/cron.daily/passwd 
/etc/passwd
```

- Ako se alias želi poništiti, to se može naredbom unalias. Dovoljno je u argumentu naredbe dodati alias koji se briše:

`$ unalias trazi`

### 3.2.9. Izvršavanje više naredbi

- Korisnik može izvršavati i više naredbi u nizu ; bez obzira na uspješnost prethodne pokrenute naredbe:

`$ naredba1; naredba2; naredba3`

- Naredbe se izvršavaju jedna za drugom samo u slučaju da prethodna naredba ima izlazni kod 0 (uspješno izvršena):

`$ naredba1 && naredba2 && naredba3`

- Naredbe se izvršavaju jedna za drugom samo u slučaju da prethodna naredba ima izlazni kod različit od 0 (neuspješno izvršena):

`$ naredba1 || naredba2 || naredba3`

- Prva naredba prikazuje ispis pogreške jer datoteka /etc/ne_postoji stvarno ne postoji. Naredba echo prikazuje izlazni kod prve naredbe, koji je 2. 

```
$ ls /etc/ne_postoji 
ls: cannot access /etc/ne_postoji: No such file or directory 
$ echo $? 
2
```

- Ova naredba prikazuje ispis datoteke koja postoji, a budući da je naredba uredno izvršena, njezin izlazni kod je 0.

```
$ ls /etc/passwd 
/etc/passwd 
$ echo $? 
0
```

- U sljedećem su se primjeru obje naredbe izvršile jer ne postoji uvjet izvršavanja druge naredbe:

```
$ ls /etc/ne_postoji ; ls /etc/passwd 
ls: cannot access /etc/ne_postoji: No such file or directory 
/etc/passwd
```

### 3.2.10 Naredba exec

- Naredba exec rabi se kad želimo zamijeniti trenutačnu interaktivnu ljusku s nekim drugim programom:

` exec program`

- Kad se korisnik prijavi u sustav kao administratorski korisnik root, automatski će se pokrenuti ljuska bash. Ako korisnik želi promijeniti trenutačnu ljusku u zsh, pokrenut će naredbu:

`# exec zsh`

- Kod takve upotrebe naredbe exec ne stvara se novi proces, kao što bi se dogodilo da smo ovako pokrenuli novi proces:

`# zsh`

nego se postojeći zamjenjuje sa zsh.

- U sljedećem je primjeru vidljivo da je pokretanjem ljuske zsh pomoću naredbe exec nova ljuska zsh dobila isti identifikacijski broj procesa kao i stara ljuska bash (9823). Znači, proces stare ljuske je nestao i umjesto njega je pod istim identifikacijskim brojem pokrenuta nova ljuska.

Naredba ps služi za ispisivanje popisa aktivnih procesa, a naredba grep za filtriranje linija koje sadrže određenu riječ.

```
# ps -ef | grep bash | grep -v grep 
root 9823 16169 0 18:00 pts/5 00:00:00 bash 
# exec zsh 
# ps -ef | grep 9823 | grep -v grep 
root 9823 16169 0 18:00 pts/5 00:00:00 zsh
```







# 📖 4 UPRAVLJANJE DATOTEKAMA I DIREKTORIJIMA

## 4.1. Kretanje po datotečnom sustavu

### 4.1.1. Apsolutna i relativna putanja

- Datoteci ili direktoriju može se pristupiti PUNOM PUTANJOM koja započinje znakom / (ishodišnim direktorijem - root), ili RELATIVNOM PUTANJOM koja započinje od trenutačnog direktorija u kojem se nalazi sam korisnik .

- APSOLUTNA PUTANJA je neovisna o trenutačnom direktoriju i počinje znakom  / .

```
/etc/passwd
/root/.bashrc
/usr/local/bin/command
```
 - RELATIVNA PUTANJA ovisi o tome u kojem se direktoriju nalazi sam korisnik i ne počinje znakom /. Može započinjati znakovima .. (prethodni direktorij) ili znakom . (označava trenutačni direktorij).

```
passwd
root/.bashrc
../local/bin/command
```

### Naredbe pwd i cd

- Kao i u bilo kojem drugom strukturiranom datotečnom sustavu, postoji nekoliko alata koji korisniku pomažu se kretati kroz datotečni sustav (pwd i cd).

- pwd (print working directory) - ova naredba prikazuje trenutačnu lokaciju korisnika. Lokacija se prikazuje u obliku apsolutne putanje do trenutnog direktorija.

 - cd (change directory) - ova naredba služi za promjenu trenutačnog direktorija.

```
$ pwd 
/root 
$ cd /usr/local/bin/ 
$ pwd 
/usr/local/bin
```

- Oznaka ~ označava osobni direktorij korisnika. Ako se korisnik nalazi u nekom drugom direktoriju, u svoj se direktorij može vratiti naredbom cd ~.

```
$ pwd 
/usr/local/bin 
$ cd ~ 
$ pwd 
/home/korisnik
```

- Ako se korisnik želi vratiti u prethodni direktorij u kojem je bio, može se koristiti naredbom cd -.

```
$ pwd 
/home/korisnik 
$ cd - 
$ pwd 
/usr/local/bin
```

## 4.2. Pronalaženje datoteka i direktorija

### 4.2.1. Naredba find

- U Linux okruženju ima više naredbi za pretraživanje datoteka i direktorija.
- Najčešće se upotrebljavaju sljedeće:
-  find ;
-  locate;
-  which.

- Naredba find služi za pretraživanje datotečnog sustava. Njezina je sintaksa:

find <direktorij> <kriterij> [-exec {} \;]
   
- <direktorij> argument znači da pretraga uključuje taj direktorij i sve poddirektorije u njemu.
- Argumentom <kriterij> definiramo prema kojem kriteriju pretražujemo datoteke:
   ime datoteke, tip (direktorij ili datoteka), vlasnik, vrijeme pristupa, izrade ili modificiranja.
   
 - Sljedeća naredba pretražuje datoteke u direktoriju /home koje se zovu .zshrc:
 ```
 $ find /home –name .zshrc 
 /home/irako/.zshrc 
 /home/sabina/.zshrc 
 /home/tux/.zshrc
  ```
 
 - Naredba pretražuje datoteke u direktoriju /etc čije ime započinje znakom x:

```
$ find /etc -name "x*" 
/etc/xinetd.d 
/etc/xinetd.conf 
/etc/xml 
/etc/xml/xml-core.xml 
/etc/xml/xml-core.xml.old 
/etc/init.d/x11-common 
/etc/init.d/xinetd
```
   
### 4.2.3. Naredba locate

   - Pretraživanje naredbom find može biti sporo.
   - Pretraživanje svih montiranih datotečnih sustava može potrajati čak i desetke minuta.
   
   - Zbog toga postoji naredba: locate, koja pretražuje osjetno brže.
   - Radi tako da naredba: updatedb, koja se pokreće iz CRONA (servisa koji u točno određeno vrijeme pokreće određene programe, i to obično noću),
   te da spremi popis datoteka i direktorija u lokalnu bazu podataka.
   - Naredba locate pokreće upit u toj lokalnoj bazi podataka i tako puno brže dolazi do rezultata koje onda ispisuje na ekran od korisnika.
   - Treba uzeti u obzir da pretražuje stanje montiranih datotečnih sustava u vrijeme zadnjeg izvršavanja naredbe: updatedb.
   
   `$ locate STRING`
   
   ( U argumentu se navodi dio imena datoteke ili direktorija koji se pretražuje)
   
   ```
   $ locate /etc/pass 
   /etc/passwd 
   /etc/passwd-
   ```
   
   ### 4.2.4. Naredba which
   
   - Naredba which vraća punu putanju do naredbe koju pretražujemo unutar direktorija definiranih u korisnikovoj varijabli PATH.
   
   `$ which STRING`
    
   ( U argumentu se navodi dio imena datoteke ili direktorija koji se traži.)
   
   ```
   $ which ls /bin/ls
   ```
   
   ## 4.3. UPRAVLJANJE DIREKTORIJIMA
   
   ### 4.3.1. Izrada novog direktorija
   
  -  Naredba za izradu novog direktorija je mkdir. Kao argument se koristi apsolutna ili relativna putanja do direktorija koji se želi izraditi.
Primjer je izrade direktorija /tmp/novi:
   
   `$ mkdir /tmp/novi`
   
   - Korisna je opcija -p, koja automatski stvara sve poddirektorije koji su potrebni.
U sljedećem će primjeru biti napravljeni direktorij /tmp/novi i u njemu /tmp/novi/dir.
   
   `$ mkdir -p /tmp/novi/dir`
   
   ### 4.3.2. Brisanje direktorija
   
   - Naredbe za brisanje direktorija su rmdir ili rm -r. Ako ste prijavljeni kao root, možete dodati opciju -f koja prisiljava na brisanje svih datoteka u direktoriju     koji je zadan kao argument.
   
   - Ako se rabi više opcija naredbe (npr. i -r i -f) tada se one mogu pisati zajedno kao -rf.
   - Naredba briše sve datoteke i poddirektorije unutar direktorija /dir1, tj. ostavlja direktorij /dir1 praznim:
   
   `$ rm –rf /dir1/*`
   
   ### 4.3.2. Kopiranje datoteka i direktorija
   
   - Naredba cp služi za brisanje datoteka i direktorija:
   
   cp [opcije] datoteka1 datoteka2
   cp [opcije] datoteke direktorij
   
   - Važno je napomenuti da naredba cp datoteka1 datoteka2 kopira datoteka1 i ostavlja je nepromijenjenu.
   
   
   - Isto se tako može kopirati nekoliko datoteka u direktorij, pomoću liste direktorija ili zamjenskog znaka *.
   
   - Naredba kopira sve datoteke i poddirektorije u direktoriju /dir bez samog direktorija /dir.
   
   `$ cp -r /dir/* /dir2/`
   
   ### 4.3.4. Premještanje i preimenovanje datoteka i direktorija
   
   Naredba mv služi za premještanje i preimenovanje datoteka i direktorija, a njena sintaksa je sljedeća:
   
   ```
   mv [opcije] staroime novoime
   mv [opcije] izvor odredište
   mv [opcije] izvor direktorij
   ```
   
   - Ako je staroime datoteka, a novoime direktorij, tada će premjestiti datoteku staroime u direktorij novoime.
   - Ako su izvor i odredište u istom datotečnom sustavu, tada se datoteka neće kopirati nego će se ažurirati inode (pokazivač na blok s podacima) s informacijom o          novoj lokaciji.
   - Najčešće se rabe opcije -f (prisilno premještanje) i -i (interaktivni način rada), koje imaju isto značenje kao i kod naredbe cp.
   
   
   ## 4.4. PERMANENTNE I SIMBOLIČKE POVEZNICE
   
   ### 4.4.1.  Simbolička poveznica
   
   
   - SIMBOLIČKA POVEZNICA je alias ili prečac prema datoteci ili direktoriju.
   - Izradom te poveznice kreirat će se novi: inode (dio na disku koji sadrži pokazivač) koji zapravo pokazuje na isto mjesto s podacima.
   - Naredba `ln –s` rabi se za izradu simboličkih poveznica.
   
   `$ ln –s passwd passwd.sym `
   
   ```
   $ ls -al passwd passwd.sym 
   -rw-r--r-- 1 root root 2661 Mar 2 11:02 passwd 
   lrwxrwxrwx 1 root root 6 Mar 3 16:11 passwd.sym -> passwd
   ```
   
   Iz ovog se prikaza vidi da je passwd datoteka, a da je passwd.sym simbolička poveznica koja pokazuje na datoteku passwd. Isto tako se vidi da je referentni broj 1 i za datoteku i za simboličku poveznicu.
   
   - SIMBOLIČKE POVEZNICE SE MOGU IZRADITI KROZ RAZLIČITE DATOTEČNE SUSTAVE. TO ZNAČI DA SE NA JEDNOM DATOTEČNOM SUSTAVU MOŽE NAPRAVITI I SIMBOLIČKA POVEZNICA NA NEKI DRUGI DATOTEČNI SUSTAV.
   
   ### 4.4.2. Permanenetne poveznice
   
   - PERMANENTNA POVEZNICA je još jedno ime za isti inode i referentni broj za svaku datoteku koji se povećava izradom svake nove poveznice na tu datoteku.
   - Naredba ln se rabi i za izradu permanentnih poveznica.
   
   ```
   $ ln passwd passwd.link 
   
   $ ls -al passwd passwd.link 
   -rw-r--r-- 2 root root 2661 Mar 2 11:02 passwd 
   -rw-r--r-- 2 root root 2661 Mar 2 11:02 passwd.link
   ```
   
   - PERMANENTNE POVEZNICE MOGU BITI IZRAĐENE SAMO UNUTAR ISTOG DATOTEČNOG SUSTAVA.
   
   ## 4.5. IZRADA DATOTEKA
   
   ### 4.5.1. Naredba touch
   
   - Neka datoteka se može izraditi na više načina. 
   - Najčešća naredba je : touch .
   
   `$ touch [opcije] datoteka`
   
   - Ukoliko datoteka ne postoji, naredba je onda izrađuje.
   - Isto tako je moguće mjenjati vrijeme pristupa datoteci [-a], vrijeme zadnje izmjene [-m], ili pomoću opcije [-r] aplicirati vremenske atribute neke druge datoteke.
   
   `$ touch datoteka1.txt datoteka2.txt`
   
   - Sljedećom naredbom datoteka preuzima atribute datoteke /etc/passwd :
   
   `$ touch datoteka -r /etc/passwd`
   
   ### 4.5.2. Naredba dd
   
   - Druga često korištena naredba je : dd .
   - Tom se naredbom kopiraju datoteke sa promjenjivim veličinama bloka.
   
   - Glavne opcije su if= (input file, ulazna datoteka) i of= (output file, izlazna datoteka).
   
   - Za razliku od naredbe cp, naredba dd može kopirati cijeli uređaj i pritom sačuvati datotečni sustav koji leži na tom uređaju.
   
   
   
   # 📖 5 OBRADA TEKSTA
   
   ## 5.1. PREGLED DATOTEKA
   
   ### 5.1.1. Naredba cat
   
   - Naredba cat služi za prikaz sadržaja neke datoteke. Njezina je sintaksa:
   `cat [opcije] datoteka1`
   
   - Sljedeća naredba ispisuje sadržaj datoteke /etc/hosts:
   
   ```
   $ cat /etc/hosts 
   127.0.0.1 localhost 
   
   192.168.1.5 linux.srce.hr linux
   ```
   
   - Ova naredba ispisuje sadržaj datoteke /etc/hosts i redni broj linije (opcija -n):
   ```
   $ cat -n /etc/hosts 
   1 127.0.0.1 localhost 
   2 
   3 192.168.1.5 linux.srce.hr linux
   ```
   
   ### 5.1.3 Naredba tac
   
   - Naredba cat prikazuje datoteku od njezina početka do kraja. Ako se datoteka želi prikazati od kraja do početka, tome služi naredba tac. Sintaksa naredbe je     identična naredbi cat.
    - U sljedećem će se primjeru ispisat datoteka /etc/hosts od kraja do početka:
   
   ```
   $ tac /etc/hosts 
   192.168.1.5 linux.test.hr linux
   
   127.0.0.1 localhost
   ```
   
   
   ## 5.2. JEDNOSTAVNI ALATI
   
   ### 5.2.1. Naredbe head i tail
   
   - Naredbe head i tail najviše se koriste za analiziranje log datoteka.
   - Log datoteke su tekstualne datoteke u koje se pohranjuju sistemski zapisi rada samog sustava (eng. logs).
   - Te se naredbe također mogu upotrebljavati i za druge tekstualne datoteke.
   - One po defaultu prikazuju 10 linija s početka ili kraja datoteke. osim u slučaju kada nije određen eksplicitno broj linija koje će se prikazati:
   
   - U sljedećem će se primjeru primjenom naredbe head prikazati prvih 20 linija datoteke /var/log/messages:
   
   `head -n 20 /var/log/messages`
   
   - Sljedeći primjer ispisuje datoteku /var/log/messages od njezina 25. retka do kraja datoteke:
   
   `tail -n +25 /var/log/messages`
   
   - Log-datoteke stalno se povećevaju dodavanjem novih log zapisa na kraj datoteke. Ako se u realnom vremenu želi pregledati što se od svježih log-zapisa zapisuje u određenu log datoteku, može se rabiti naredba tail -f.
   
   ### 5.2.2. Naredba wc
  
   
   Naredba wc (word count) služi za brojanje broja znakova, riječi i linija u nekoj tekstnoj datoteci:
   
   ```
   $ wc /etc/passwd 
   224 437 12709 /etc/passwd
   ```
   Znači, datoteka /etc/passwd sadrži 224 linije, 437 riječi i 12709 znakova.
   
   
   ### 5.2.3. Naredbe od i hexdump
   
   - Sve dosada obrađene naredbe služile su za prikaz tekstualnih datoteka.
   Međutim, postoji i nekoliko alata za prikaz binarnih datoteka. Najčešće se upotrebljavaju od (octal dump) i hexdump.
   
   ```
   $ od /bin/ls 
   0000000 042577 043114 000402 000001 000000 000000 000000 000000 
   0000020 000002 000076 000001 000000 044200 000100 000000 000000 
   0000040 000100 000000 000000 000000 133160 000001 000000 000000 
   ...
   ```
   
   - Primjer za uporabu naredbe hexdump:
   
   ```
   $ hexdump /bin/ls 
   0000000 457f 464c 0102 0001 0000 0000 0000 0000 
   0000010 0002 003e 0001 0000 4880 0040 0000 0000 
   0000020 0040 0000 0000 0000 b670 0001 0000 0000 
   ...
   ```
   
   ### 5.2.4. Naredba split
   
   - Ako se neka tekstna datoteka želi razdijeliti na više manjih datoteka, tome će poslužiti naredba split. Kriterij za smanjivanje je prema broju linija.
   
   ```
   $ split -l 5 /etc/passwd 
   $ ls 
   xaa xab xac xad xae xaf xag xah
   ```
   
   - Iz navedenog je primjera vidljivo da će se datoteka, preddefinirano, podijeliti na više manjih datoteka koje počinju znakom x.
   
   - Opcija -l 5 u naredbi određuje da će se svaka podijeljena datoteka sastojati od 5 linija. U gornjem primjeru datoteka /etc/passwd se sastoji od najviše 40 linija te je njenom podjelom nastalo 8 datoteka.
   
   - Ako se umjesto x želi rabiti neki drugi znak ili niz znakova, to treba upisati u argument:
   ```
   $ split -l 5 /etc/passwd passwd 
   $ ls 
   passwdaa passwdab passwdac passwdad passwdae passwdaf passwdag passwdah
   ```
   
   
   ### Naredbe uniq i sort
   
   - Kod prikaza tekstnih datoteka često se pojavljuju uzastopne identične linije.
   - Naredba uniq ispisat će samo jednu uzastopnu liniju, makar je na svoj standardni ulaz dobila više istih linija.
   ```
   $ uniq > /tmp/UNIQUE 
   linija 1 
   linija 2 
   linija 2 
   linija 3 
   linija 3 
   linija 3 
   linija 1
   ```
   
   - Naredbom cat ispisat ćemo datoteku:
   
   ```
   $ cat /tmp/UNIQUE 
   linija 1 
   linija 2 
   linija 3 
   linija 1
   ```
   
   - Ako se žele izbaciti sve iste linije, koje nisu uzastopne, može se koristiti kombinacija naredbi sort i uniq.
   - Naredba sort razvrstat će sve linije, tako da se istoznačne pojave jedna ispod druge, a izbacit će ih naredba uniq.
   
   ```
   $ cat /tmp/UNIQUE | sort | uniq 
   linija 1 
   linija 2 
   linija 3
   ```
   
   # 📖 6 NAPREDNO UPRAVLJANJE TEKSTOM
   
   ## 6.1. REGULARNI IZRAZI
   
   - U računarstvu, regularni izraz (regex) je niz znakova koji opisuje druge nizove znakova (string) u skladu sa određenim sintaksnim pravilima.
   - Prvenstveno, svrha regularnog izraza je opisivanje uzorka za pretraživanje niza znakova.
   
   - Regularnim izrazima koriste se mnogi uređivači teksta i pomoćni programi.
   - Mnogi programski jezici podržavaju regularne izraze za manipulacijom niza znakova (string).
   
   - Skup pomoćnih programa (uključujući uređivač ed i filter grep) koji se standardno distribuira s Unixovim distribucijama znatno je doprinio promociji i popularizaciji koncepta regularnih izraza.
   
   ### 6.1.2. Osnovni koncepti regexa
   
   - Regularni izraz, često zvan uzorak ili pattern, izraz je koji opisuje nizove znakova (string). Obično se rabe za davanje opisa nizova znakova, bez potrebe za nabrajanjem svih elemenata.
   
   - Većina formalizama pruža ove operacije pri konstrukciji regularnih izraza:
   
   - ALTERNACIJA :
   Okomita crta razdvaja alternative. Na primjer, gray|grey se može skratiti u istovjetan izraz gr(a|e)y i pri tome spariti gray ili grey.
   
   - GRUPIRANJE:
   Zagrade se rabe za definiranje područja djelovanja (scope) i prednosti operatora. Na primjer, gray|grey i gr(a|e)y su različiti uzorci, ali i jedan i drugi opisuju niz koji sadrži gray ili grey.
   
   - KVANTIFIKACIJA:
   Kvantifikator nakon znaka ili skupine njih određuje učestalost pojavljivanja izraza koji prethodi. Najčešće se rabe kvantifikatori ?, *, i +
   
   ### 6.1.3. Tradicionalni regularni izrazi na Unixu
   
   „Osnovna“ sintaksa regularnih izraza na Unixu je prema POSIX-ovim definicijama danas zastarjela, iako se naširoko rabi radi unazadne kompatibilnosti. Većina      pomoćnih programa na Unixu (npr. grep i sed) rabi tradicionalne regularne izraze, a prošireni se regularni izrazi koriste preko naredbenolinijskih argumenata.
   
   - . - Sparuje bilo koji znak samo jednom. Unutar [ ] ima svoje uobičajeno značenje (točka).
   - [] - Sparuje jedan znak sadržan unutar uglatih zagrada. Na primjer, [abc] sparuje "a", "b", ili "c". [a-z] sparuje sva mala slova.
   - [^] - Sparuje jedan znak koji nije sadržan unutar uglatih zagrada. Na primjer, [^abc] sparuje bilo koji znak osim "a", "b", i "c". [^a-z] sparuje bilo koji znak koji nije malo slovo.
   - ^ - Sparuje početak linije (bilo koje linije, kad je primjenjen u višelinijskom načinu rada).
   - $ - Sparuje kraj linije (bilo koje linije, kad je primjenjen u višelinijskom načinu rada).
   - () - Definira „označeni podizraz“. Što zagradama obuhvaćeni izraz sparuje, poslije može biti dohvaćeno za daljnju obradu, a način dohvata opisan je unosom za \n (sljedeći redak). „Označeni podizraz“ je također „blok“.
   - \n - Pri čemu je n znamenka od 1 do 9 - sparuje n-ti spareni označeni podizraz. Taj konstrukt je teoretski neregularan i nije prihvaćen u proširenoj sintaksi regularnih izraza.

 
   ## 6.2. PRONALAŽENJE SADRŽAJA U DATOTEKAMA
   
   ### 6.2.1. Naredba grep
   
   
