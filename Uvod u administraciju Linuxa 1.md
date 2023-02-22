# Uvod u administraciju Linuxa 1 - Bilješke

Ispod možete naći bilješke iz materijala [**Osnove administracije operacijskog sustava 1 (Linux) - Ivan Rako**].
Navedeni materijali predtavljaju sjajan izvor informacija svima koji se počijnu baviti administracijom operativnog sustava Linux.

- [📖 1. UVOD U LINUX](#1-Uvod u Linux)
- [📖 2. INSTALACIJA LINUXA](#2-Instalacija Linuxa)
- [📖 3. NAREDBENA LINIJA](#3-Naredbena linija)
- [📖 4. UPRAVLJANJE DATOTEKAMA I DIREKTORIJIMA](#4-Upravljanje datotekama i direktorijima)
- [📖 5. OBRADA TEKSTA](#5- Obrada teksta)
- [📖 6. NAPREDNO UPRAVLJANJE TEKSTOM](#6-Napredno upravljanje tekstom)
- [📖 7. UREĐIVAČ TEKSTA VI](#7-Uređivač teksta vi)
- [📖 8. UPRAVLJANJE UREĐAJIMA U DIREKTORIJU /DEV](#8-Upravljanje uređajima u direktoriju /dev)
- [📖 9. DATOTEČNI SUSTAV](#9- Datotečni sustav)
- [📖 10. UPRAVLJANJE PROCESIMA](#10-Upravljanje procesima)
- [📖 11. INSTALACIJA SOFTVERA](#5-Instalacija softvera)

# 📖 1 UVOD U LINUX

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
