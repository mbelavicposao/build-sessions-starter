# Vuln Watch - jutarnji pregled ranjivosti koje se mene tiču

Jedna HTML stranica koju otvorim dvoklikom i vidim samo javno objavljene ranjivosti za softver koji vrtim, za danas i prošlih 20 dana.

## IN (što alat radi)

- Čita moj lažni popis softvera i verzija (CSV) i lažni feed objavljenih ranjivosti (CSV).
- Filtrira: softver je s popisa **i** (CVSS ≥ 9.0 **ili** moja verzija je pogođena **ili** je u KEV katalogu).
- Groupira po grupi: Distro/kernel, Platforma (K8s, OpenStack, Docker), Alati (Grafana, Jenkins, Ansible...).
- Za svaki zapis: CVE, softver, moja verzija, CVSS, KEV da/ne, datum objave, link na advisory, status fixa.
- Gore brojači: danas / 7 dana / 20 dana.
- Filtri po grupi, softveru i "samo KEV", plus pretraga.
- Sve se računa u samoj stranici, bez servera i bez interneta.

## OUT (što namjerno nije dio)

- Ne skenira i ne dira moje servere, ne traži lozinke niti ključeve.
- Nema ticketinga, mailova, Slack/Jira obavijesti.
- Ne otkriva strojeve: radi samo s onim što je upisano u popis.
- Ništa ne objavljuje na internet.

## Sample data (sve izmišljeno)

Podaci žive u dva bloka na dnu `index.html` (browser ne smije sam čitati druge fileove kad stranicu otvoriš dvoklikom).

Blok **SOFTWARE** - stroj, softver, verzija, grupa, owner
32 retka, npr. `k8s-node-01,kubelet,1.28.4,Platforma,tim-b@example.com`

Blok **VULNS** - cve, softver, pogodene_versije, fiksno_izdanje, cvss, kev, dana_ako, izvor_url
54 retaka raspoređenih po zadnjih 20 dana (dana_ako = prije koliko dana), uključujući 3 dana bez ijednog zapisa.
CVE brojevi i linkovi su izmišljeni i vode na example.com.

## Done when

- Otvorim `index.html` dvoklikom i vidim listu: CVE, softver, moja verzija, CVSS, KEV da/ne, advisory link.
- Brojači gore pokazuju danas / 7 dana / 20 dana i brojevi se slažu s tablicom ispod.
- Mogu filtrirati po grupi, softveru i KEV.
- Test: u blok SOFTWARE upišem verziju koja je u bloku VULNS označena kao pogođena → zapis se odmah pojavi na listi; promijenim verziju na fixanu → nestane s liste.
