# Vuln Watch - jutarnji pregled ranjivosti koje se mene tiču

Jedna HTML stranica koju otvorim dvoklikom i vidim samo javno objavljene ranjivosti za softver koji vrtim, za danas i prošlih 20 dana.

## IN (što alat radi)

- Čita moj **izmišljeni** popis softvera i verzija (CSV) i **stvarni** popis prijavljenih ranjivosti (CSV, snapshot javnih feedova).
- Izvor ranjivosti: NVD API (`services.nvd.nist.gov`) i CISA KEV katalog. Osvježava se ručno s `bash fetch.sh` pa `powershell -File refresh.ps1`; otvaranje stranice ne ide na internet.
- Filtrira: softver je s popisa **i** (CVSS ≥ 9.0 **ili** moja verzija je pogođena **ili** je u KEV katalogu).
- Groupira po grupi: Distro/kernel, Platforma (K8s, OpenStack, Docker), Alati (Grafana, Jenkins, Ansible...).
- Za svaki zapis: CVE, softver + opseg pogodjenih verzija, **vendor / product i opis iz te iste NVD objave** (da vidim da redak i link govore o istoj stvari), moja verzija, CVSS (s verzijom tablice), **EPSS** (vjerojatnost da će se propust pokušati iskoristiti, + percentil), KEV da/ne, datum objave, link na NVD i na advisory izvora, te je li fix objavljen i u koje izdanje (ili "ne - NVD ne navodi izdanje").
- **NOVO / PROMIJENJENO**: usporedba sa snimkom od prošli put (`data/prev.csv`) - novi zapisi, promijenjen CVSS, KEV, fiks ili opseg verzija. EPSS se mijenja svaki dan i zato se ne računa kao promjena.
- **Top 5** - panel "kreni od ovdje": KEV, pa pogođena moja verzija, pa novo, pa CVSS, pa EPSS, i kratak razlog zašto je tu.
- Izgled: tamno / svijetlo i normalno / gusto, urezani naslovi stupaca dok se skrola, tanka pruga uz redak po ozbiljnosti. Izbor se pamti u browseru.
- **Notifikacija**: `notify.ps1` iskoči Windows notifikacijom s brojem novo / promijenjeno / KEV / CVSS 9+ i upiše redak u `notes/notify.log`. Radi bez interneta, bez instalacije i bez administratora; može ju zakazati svako jutro preko `schtasks`.
- Gore brojači: danas / 7 dana / 20 dana, graf po danima, i napomena koliko prijava još nema strojno čitljiv opseg verzija.
- Filtri po grupi, softveru, "samo KEV", "samo pogođena verzija", "samo novo / promijenjeno", plus pretraga. Klik na naslov stupca sortira, drugi klik obrće smjer.
- Sve se računa u samoj stranici, bez servera i bez interneta.

## OUT (što namjerno nije dio)

- Ne skenira i ne dira moje servere, ne traži lozinke niti ključeve.
- Nema ticketinga, mailova, Slack/Jira obavijesti. Notifikacija je lokalna poruka na moj ekran - ništa se nigdje ne šalje.
- Ne otkriva strojeve: radi samo s onim što je upisano u popis.
- Ništa ne objavljuje na internet.

## Podaci

Podaci žive u tri bloka na dnu `index.html` (browser ne smije sam čitati druge fileove kad stranicu otvoriš dvoklikom).

Blok **SOFTWARE** - stroj, softver, verzija, grupa, owner. **Izmišljen, to mijenjaš sam.**
32 retka, npr. `k8s-node-01,kubelet,1.33.4,Platforma,tim-b@example.com`

Blok **VULNS** - cve, softver, izvor_proizvod (vendor / product iz NVD objave), pogodene_versije, fiksno_izdanje, cvss, cvss_ver, epss, epss_pct, kev, datum, izvor_url, nvd_url, opis (prvih ~150 znakova opisa iz NVD objave).
**Stvarni javni podaci** (snapshot, datum snimke je u naslovu stranice): 173 prijave za softver s moga popisa, zadnjih 20 dana.
CVSS uzimam iz NVD zapisa (prvo 3.x Primary), KEV zastavica iz CISA kataloga, EPSS iz FIRST-ova dnevnog snimka (`data/epss.csv`, datum snimke je zapisan u njemu i u naslovu stranice), `nvd_url` je `https://nvd.nist.gov/vuln/detail/<CVE>`.
Ne diram ga ručno - generira ga `refresh.ps1` iz `data/raw/*.json`, `data/kev.json` i `data/epss.csv`.

Blok **PROSLA SNIMKA** (`csv-prev`) - ono što je alat pokazivao prošli put (cve, softver, cvss, kev, fiks, opseg). Piše ga `refresh.ps1` iz starog `data/vulns.csv` neposredno prije nego ga prepiše, pa oznake NOVO / PROMIJENJENO nisu izmišljene.

## Done when

- Otvorim `index.html` dvoklikom i vidim listu: CVE, softver i opseg, moja verzija, CVSS, KEV da/ne, advisory link.
- CVSS nije izmišljen: svaki broj se može naći u `data/raw/*.json` za taj CVE, i svaki link radi.
- Redak i link govore isto: stupac "iz NVD objave" ima vendor / product i opis te iste prijave, pa po njemu prepoznajem na što se link odnosi.
- Brojači gore pokazuju danas / 7 dana / 20 dana i brojevi se slažu s tablicom ispod.
- Mogu filtrirati po grupi, softveru, KEV i "samo pogođena verzija".
- Vidim je li fix objavljen: ili "da - <izdanje>" ili "ne - NVD ne navodi izdanje", i sortiram klikom na naslov stupca.
- EPSS: svaka ocjena u tablici doslovno je iz `data/epss.csv`; nema je za neki zapis → u tablici piše "nema ocjene", a ne 0, i bilješka gore kaže koliko ih je tako.
- Novo od prošli put: nakon drugog osvježavanja redci imaju oznaku NOVO ili PROMIJENJENO (prelet mišom pokazuje što se to promijenilo), a panel "Top 5" je složeno po KEV, mojoj verziji, pa CVSS i EPSS.
- `powershell -File notify.ps1` pokaže lokalnu notifikaciju s brojkama i upiše redak u `notes/notify.log`; `-dry` ispiše isto bez notifikacije.
- Test: u blok SOFTWARE upišem verziju koja je u opsegu → zapis se pojavi; promijenim verziju na fixanu → nestane s liste.
- `cscript //nologo check.js` prolazi bez greške.
