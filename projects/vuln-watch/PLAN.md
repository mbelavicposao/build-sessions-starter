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

`data/software.csv` - stroj, softver, verzija, grupa, owner
30 redaka, npr. `node-07, kubelet, 1.28.4, Platforma, tim-a@example.com`

`data/vulns.csv` - cve, softver, pogođene_versije, fiksno_izdanje, cvss, kev, datum_objave, izvor_url
60 redaka raspoređenih po zadnjih 20 dana, uključujući 3 dana bez ijednog zapisa.

## Done when

- Otvorim `index.html` dvoklikom i vidim listu: CVE, softver, moja verzija, CVSS, KEV da/ne, advisory link.
- Brojači gore pokazuju danas / 7 dana / 20 dana i brojevi se slažu s tablicom ispod.
- Mogu filtrirati po grupi, softveru i KEV.
- Test: u `software.csv` upišem verziju koja je u `vulns.csv` označena kao pogođena → zapis se odmah pojavi na listi; promijenim verziju na fixanu → nestane s liste.
