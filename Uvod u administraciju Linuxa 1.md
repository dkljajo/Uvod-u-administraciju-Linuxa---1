# Uvod u administraciju Linuxa 1 - Bilješke

Ispod možete naći bilješke iz materijala [**Osnove administracije operacijskog sustava 1 (Linux) - Ivan Rako**](https://www.srce.unizg.hr/files/srce/docs/edu/l101_polaznik_1.pdf).
Navedeni materijali predtavljaju sjajan izvor informacija svima koji se počijnu baviti administracijom operativnog sustava Linux.

- [📖 1 UVOD](#1-uvod)
- [📖 2 INSTALACIJA LINUXA](#2-instalacija-linuxa)
- [📖 3 NAREDBENA LINIJA](#3-naredbena-linija)
- [📖 4 UPRAVLJANJE DATOTEKAMA I DIREKTORIJIMA](#4-Upravljanje datotekama i direktorijima)
- [📖 5 OBRADA TEKSTA](#5- Obrada teksta)
- [📖 6 NAPREDNO UPRAVLJANJE TEKSTOM](#6-Napredno upravljanje tekstom)
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

### 3.2.7. Metaznakovi

Metaznakovi:

- * - zamjenjuje bilo koju skupinu slova u riječi
- ? - zamjenjuje bilo koje slovo u riječi
- [..] - zamjenjuje bilo koji od znakova u zagradama
- ~ - označuje korisnikovo izvorno kazalo, tj. korisnikov kućni direktorij (home directory)
- > znači preusmjerivanje izlaza
- < - znači preusmjerivanje ulaza
- >> - znači dodavanje izlazu
- | - znači povezivanje procesa u kanale
- & - znači nalog za izvođenje procesa (naredbe) u pozadini
- ! - (u prvom stupcu naredbe) poziva jednu od prethodno zadanih naredbi

