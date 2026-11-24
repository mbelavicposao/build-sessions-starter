# What I learned

The agent adds two short sentences after each step.

## Korak 1 - upoznavanje
Upoznali smo se: Linux sysadmin / DevOps, radi s terminalom, YAML-om, Kubernetesom, OpenStackom i nadzorom; koristi chat AI (razina 2).
Vrijedi zapamtiti: razina 2 znači da danas možemo preskočiti objašnjenja oko alata i više vremena potrošiti na sam alat i njegovu provjeru.

## Korak 4 - plan
Napisan `projects/vuln-watch/PLAN.md`: jedna HTML stranica + dva lažna CSV filea, filter "moje" = softver s popisa i (CVSS ≥ 9 ili pogođena verzija ili KEV), prikaz za danas i 20 dana.
Vrijedi zapamtiti: alat namjerno ne dira servere i ne otkriva strojeve, pa "done" ovisi o testu gdje lažna verzija uđe i izađe s liste.

## Korak 5 - gradnja
Napravljen `projects/vuln-watch/index.html`: jedan file bez servera, s ugrađenim lažnim CSV podacima, brojačima danas/7/20 dana, grafom po danima, filtrima i tablicom grupiranom po Distro/Platforma/Alati.
Vrijedi zapamtiti: browser iz sigurnosnih razloga ne smije čitati tuđe fileove kad HTML otvoriš dvoklikom, zato su podaci u istom fileu; "pogodena verzija" se računa numeričkom usporedbom verzija, ne tekstualnom.

## Korak 6 - provjera
Pokrenut `cscript //nologo check.js` u mapi projekta: 20/20 testova prošlo, na listi upada 48 od 54 objava (danas 4, 7 dana 19, 20 dana 48), ispalo je samo ono što ne vrtim (mysql, wordpress, nginx, git), test s verzijom radi u oba smjera.
Vrijedi zapamtiti: Chrome i Edge se u ovoj sesiji ne dižu, pa izgled stranice i filtere mora pogledati čovjek; logika je dokazana pravim JS testom, ne "izgleda ok".

## Korak 7 - korisno: CVSS mora biti stvaran
Izbačeni izmišljeni podaci o propustima. `fetch.sh` povuče NVD API (24 keyword upita, zadnjih 20 dana) i CISA KEV katalog u `data/`, `refresh.ps1` od toga napravi `data/vulns.csv` i upiše ga u `index.html` (173 prijave, 1 KEV, svaki redak ima link na NVD i advisory izvora). `check.js` prepisan: provjerava da se svaki CVSS broj nalazi u sirovom NVD odgovoru za taj CVE i da KEV zastavica odgovara CISA katalogu u oba smjera - 20/20 testova prošlo.
Vrijedi zapamtiti: NVD za 123 prijave (najviše kernel) još nema strojno čitljiv opseg verzija, samo commit hash, pa se ne može izračunati pogađa li tebe - alat to kaže u napomeni umjesto da nagađa; browserove stranice NVD-a ovdje ne mogu otvoriti (Cloudflare), provjereno je samo da linkovi vraćaju 200 i da brojevi dolaze iz API odgovora.
