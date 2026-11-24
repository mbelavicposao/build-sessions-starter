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
