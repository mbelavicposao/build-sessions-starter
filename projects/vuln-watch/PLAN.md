# Vuln Watch - jutarnji pregled ranjivosti koje se mene tiču

Jedna HTML stranica koju otvorim dvoklikom i vidim samo javno objavljene ranjivosti za softver koji vrtim, za danas i prošlih 20 dana.

## IN (što alat radi)

- Čita moj **izmišljeni** popis softvera i verzija (CSV) i **stvarni** popis prijavljenih ranjivosti (CSV, snapshot javnih feedova).
- Izvor ranjivosti: NVD API (`services.nvd.nist.gov`) i CISA KEV katalog. Osvježava se ručno s `bash fetch.sh` pa `powershell -File refresh.ps1`; otvaranje stranice ne ide na internet.
- Filtrira: softver je s popisa **i** (CVSS ≥ 9.0 **ili** moja verzija je pogođena **ili** je u KEV katalogu).
- Groupira po grupi: Distro/kernel, Platforma (K8s, OpenStack, Docker), Alati (Grafana, Jenkins, Ansible...).
- Za svaki zapis: CVE, softver + opseg pogodjenih verzija, **vendor / product i opis iz te iste NVD objave** (da vidim da redak i link govore o istoj stvari), moja verzija, CVSS (s verzijom tablice), KEV da/ne, datum objave, link na NVD i na advisory izvora, u koje izdanje je fixano.
- Gore brojači: danas / 7 dana / 20 dana, graf po danima, i napomena koliko prijava još nema strojno čitljiv opseg verzija.
- Filtri po grupi, softveru, "samo KEV", "samo pogođena verzija", plus pretraga.
- Sve se računa u samoj stranici, bez servera i bez interneta.

## OUT (što namjerno nije dio)

- Ne skenira i ne dira moje servere, ne traži lozinke niti ključeve.
- Nema ticketinga, mailova, Slack/Jira obavijesti.
- Ne otkriva strojeve: radi samo s onim što je upisano u popis.
- Ništa ne objavljuje na internet.

## Podaci

Podaci žive u dva bloka na dnu `index.html` (browser ne smije sam čitati druge fileove kad stranicu otvoriš dvoklikom).

Blok **SOFTWARE** - stroj, softver, verzija, grupa, owner. **Izmišljen, to mijenjaš sam.**
32 retka, npr. `k8s-node-01,kubelet,1.33.4,Platforma,tim-b@example.com`

Blok **VULNS** - cve, softver, izvor_proizvod (vendor / product iz NVD objave), pogodene_versije, fiksno_izdanje, cvss, cvss_ver, kev, datum, izvor_url, nvd_url, opis (prvih ~150 znakova opisa iz NVD objave).
**Stvarni javni podaci** (snapshot, datum snimke je u naslovu stranice): 173 prijave za softver s moga popisa, zadnjih 20 dana.
CVSS uzimam iz NVD zapisa (prvo 3.x Primary), KEV zastavica iz CISA kataloga, `nvd_url` je `https://nvd.nist.gov/vuln/detail/<CVE>`.
Ne diram ga ručno - generira ga `refresh.ps1` iz `data/raw/*.json` i `data/kev.json`.

## Done when

- Otvorim `index.html` dvoklikom i vidim listu: CVE, softver i opseg, moja verzija, CVSS, KEV da/ne, advisory link.
- CVSS nije izmišljen: svaki broj se može naći u `data/raw/*.json` za taj CVE, i svaki link radi.
- Redak i link govore isto: stupac "iz NVD objave" ima vendor / product i opis te iste prijave, pa po njemu prepoznajem na što se link odnosi.
- Brojači gore pokazuju danas / 7 dana / 20 dana i brojevi se slažu s tablicom ispod.
- Mogu filtrirati po grupi, softveru, KEV i "samo pogođena verzija".
- Test: u blok SOFTWARE upišem verziju koja je u opsegu → zapis se pojavi; promijenim verziju na fixanu → nestane s liste.
- `cscript //nologo check.js` prolazi bez greške.
