# refresh.ps1 - iz dohvacenih JAVNIH podataka (data/kev.json + data/raw/*.json) popunjava VULNS blok u index.html
# Pokreni prvo: bash fetch.sh   zatim: powershell -ExecutionPolicy Bypass -File refresh.ps1
# Nista se ne objavljuje ni salje van; ovdje se samo cita vec preuzete datoteke.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)
$culture = [Globalization.CultureInfo]::InvariantCulture
$today = (Get-Date).ToUniversalTime().Date
$windowDays = 20

function VerParts([string]$v) {
  $out = New-Object System.Collections.ArrayList
  foreach ($p in ($v -split '[.\-_+]')) {
    $n = 0
    if ([int]::TryParse(($p -replace '[^0-9].*$', ''), [ref]$n)) { [void]$out.Add($n) }
  }
  return $out.ToArray()
}
function Compare-Ver([string]$a, [string]$b) {
  $A = VerParts $a; $B = VerParts $b
  for ($i = 0; $i -lt [Math]::Max($A.Length, $B.Length); $i++) {
    $x = 0; if ($i -lt $A.Length) { $x = $A[$i] }
    $y = 0; if ($i -lt $B.Length) { $y = $B[$i] }
    if ($x -ne $y) { if ($x -lt $y) { return -1 } else { return 1 } }
  }
  return 0
}
# verzija mora biti brojka; git commit hash ili tekst s razmacima nisu verzija
function Usable([string]$v) {
  if ($v -eq '' -or $v -eq '*') { return $false }
  if ($v -match '[\s<>=,;]') { return $false }
  if ($v -imatch '^[0-9]*[a-f][0-9a-f]{6,}$') { return $false }
  return ($v -match '^[0-9]')
}
function Clean([string]$s) {
  if ($null -eq $s) { return '' }
  return ($s -replace '[",]', ' ').Trim()
}

# --- 1) moj popis softvera (izmisljen) iz index.html ---
$html = Get-Content -Raw -Encoding UTF8 'index.html'
$softBlock = [regex]::Match($html, '(?s)<script type="text/csv" id="csv-software">(.*?)</script>').Groups[1].Value
$softLines = $softBlock -split "`r?`n" | Where-Object { $_.Trim() -ne '' }
$mine = @{}
foreach ($l in ($softLines | Select-Object -Skip 1)) {
  $c = $l.Split(',')
  if ($c.Count -lt 4) { continue }
  $mine[$c[1].Trim()] = $true
}
Write-Host ("na mom popisu: {0} naziva softvera" -f $mine.Count)

# --- 2) kako se zove svaki moj softver u javnim objavama ---
$MAP = [ordered]@{
  'kernel'            = @{ p = '^linux$'; v = '^linux$' }
  'openssl'           = @{ p = '^openssl$'; v = 'openssl' }
  'glibc'             = @{ p = '^(glibc|gnu c library)$'; v = 'gnu|red ?hat|canonical|debian|suse|amazon' }
  'sudo'              = @{ p = '^sudo$'; v = 'todd miller|sudo|greenie' }
  'openssh'           = @{ p = '^openssh( portable)?$'; v = 'openbsd|openssh|hyperlogic' }
  'curl'              = @{ p = '^curl$'; v = 'curl|haxx' }
  'systemd'           = @{ p = '^systemd$'; v = 'systemd|freedesktop|red ?hat|canonical|debian|suse|amazon' }
  'bash'              = @{ p = '^bash$'; v = 'gnu|free software foundation|red ?hat|apple' }
  'zlib'              = @{ p = '^zlib$'; v = 'zlib|gailly' }
  'kube-apiserver'    = @{ p = '^kube-apiserver$'; v = 'kubernetes' }
  'kubelet'           = @{ p = '^(kubelet|kubernetes)$'; v = 'kubernetes' }
  'etcd'              = @{ p = '^etcd$'; v = 'etcd|coreos|linux foundation' }
  'containerd'        = @{ p = '^containerd$'; v = 'containerd|linux foundation|docker' }
  'runc'              = @{ p = '^runc$'; v = 'opencontainers|docker|red ?hat|suse|canonical' }
  'openstack-nova'    = @{ p = '^nova$'; v = 'openstack' }
  'openstack-neutron' = @{ p = '^neutron$'; v = 'openstack' }
  'ingress-nginx'     = @{ p = '^ingress-nginx$'; v = 'kubernetes|ingress' }
  'helm'              = @{ p = '^helm$'; v = 'helm' }
  'grafana'           = @{ p = '^grafana( (enterprise|oss)|-(enterprise|oss))?$'; v = 'grafana' }
  'prometheus'        = @{ p = '^prometheus$'; v = 'prometheus' }
  'loki'              = @{ p = '^loki$'; v = 'grafana' }
  'jenkins'           = @{ p = '^jenkins(-core)?$'; v = 'jenkins|cloudbees' }
  'gitlab-runner'     = @{ p = '^gitlab-runner$'; v = 'gitlab' }
  'ansible'           = @{ p = '^ansible( core|-core|-engine|-base|-automation-platform)?$'; v = 'red ?hat|ansible|linux foundation' }
  'vault'             = @{ p = '^vault( (enterprise|-enterprise))?$'; v = 'hashicorp' }
  'argocd'            = @{ p = '^argocd$'; v = 'argocd|argoproj|intuit' }
}
$tokens = @($MAP.Keys | Where-Object { $mine.ContainsKey($_) })

# --- 3) stvarno koristeni KEV popisi (CISA) ---
$kevText = Get-Content -Raw -Encoding UTF8 'data/kev.json'
$kevIds = @{}
$kevDue = @{}
foreach ($m in [regex]::Matches($kevText, '"cveID": *"([A-Z0-9-]+)"[^}]*?"dateAdded": *"([0-9-]{10})"')) {
  $kevIds[$m.Groups[1].Value] = $true
  $kevDue[$m.Groups[1].Value] = $m.Groups[2].Value
}
Write-Host ("KEV: {0} zapisa" -f $kevIds.Count)

# --- 3b) EPSS (FIRST): vjerojatnost da ce netko pokusati iskoristiti ovaj propust ---
$epss = @{}
$epssDate = ''
if (Test-Path 'data/epss.csv') {
  foreach ($l in (Get-Content -Encoding UTF8 'data/epss.csv')) {
    if ($l -match '^# *score_date:([0-9-]{10})') { $epssDate = $matches[1]; continue }
    $c = $l.Split(',')
    if ($c.Count -lt 3 -or $c[0] -eq '' -or $c[0] -eq 'cve') { continue }
    $epss[$c[0]] = @{ e = $c[1]; p = $c[2] }
  }
}
Write-Host ("EPSS: {0} ocjena (snimka {1})" -f $epss.Count, $epssDate)

# --- 4) projdi kroz NVD zapis ---
$rows = @{}
$unknown = @{}
$noRange = @{}
$noRangeSeen = @{}
$noScore = 0
$seen = 0
foreach ($file in (Get-ChildItem 'data/raw/*.json' | Sort-Object Name)) {
  $text = Get-Content -Raw -Encoding UTF8 $file.FullName
  $chunks = $text -split '\{"cve":\{'
  for ($i = 1; $i -lt $chunks.Length; $i++) {
    $c = $chunks[$i]
    $idm = [regex]::Match($c, '"id":"(CVE-[0-9]{4}-[0-9]+)"')
    if (-not $idm.Success) { continue }
    $cve = $idm.Groups[1].Value
    $seen++
    $pub = [regex]::Match($c, '"published":"([0-9]{4}-[0-9]{2}-[0-9]{2})').Groups[1].Value
    if ($pub -eq '') { continue }
    $days = [int]($today - [datetime]::ParseExact($pub, 'yyyy-MM-dd', $culture)).TotalDays
    if ($days -lt 0 -or $days -gt $windowDays) { continue }

    # CVSS: prvo Primary pa Secondary; V3.x prije V4
    $best = $null
    foreach ($mm in [regex]::Matches($c, '"type":"(Primary|Secondary)","cvssData":\{"version":"([0-9.]+)","vectorString":"[^"]*"[^}]*?"baseScore":([0-9.]+)')) {
      $ver = $mm.Groups[2].Value
      if ($ver -notmatch '^3\.') { if ($best -and $best.ver -match '^3\.') { continue } }
      if ($null -eq $best) { $best = @{ score = [double]$mm.Groups[3].Value; ver = $ver; type = $mm.Groups[1].Value } }
      elseif ($mm.Groups[1].Value -eq 'Primary' -and $best.type -ne 'Primary') { $best = @{ score = [double]$mm.Groups[3].Value; ver = $ver; type = $mm.Groups[1].Value } }
    }
    if ($null -eq $best) { $noScore++; continue }

    $refs = [regex]::Match($c, '"references":\[(.*?)\]').Groups[1].Value
    $url = ''
    foreach ($u in [regex]::Matches($refs, '"url":"(https?://[^"]+)"')) {
      $cand = $u.Groups[1].Value
      if ($cand -match 'nvd\.nist\.gov|nvd\.nist\.org|vulnshop|mailman|lists\.') { continue }
      if ($url -eq '') { $url = $cand }
      if ($cand -imatch 'advisory|advisories|security|announce|cert/') { $url = $cand; break }
    }

    # koji od mojih softvera je spomenut u ovoj objavi
    $opis = [regex]::Match($c, '"lang":"en","value":"((?:[^"\\]|\\.)*)"').Groups[1].Value
    $opis = (Clean ($opis -replace '\\[nrtuv][0-9a-fA-F]*', ' '))
    if ($opis.Length -gt 150) { $opis = $opis.Substring(0, 147) + '...' }
    foreach ($am in [regex]::Matches($c, '"vendor":"([^"]*)","product":"([^"]*)"(?:(?!"vendor":).)*?"versions":\[([^\]]*)\]')) {
      $vendor = $am.Groups[1].Value
      $product = $am.Groups[2].Value
      $vers = $am.Groups[3].Value
      $hitToken = $null
      foreach ($t in $tokens) {
        if ($product -imatch $MAP[$t].p -and ($vendor -imatch $MAP[$t].v -or $MAP[$t].v -eq '')) { $hitToken = $t; break }
      }
      if (-not $hitToken) {
        $key = Clean ("{0} / {1}" -f $vendor, $product)
        if ($key -ne '') { if ($unknown.ContainsKey($key)) { $unknown[$key] = $unknown[$key] + 1 } else { $unknown[$key] = 1 } }
        continue
      }

      $specs = New-Object System.Collections.ArrayList
      $fixes = New-Object System.Collections.ArrayList
      $fixed = ''
      foreach ($vpiece in ($vers -split '\},\{')) {
        $vver = [regex]::Match($vpiece, '"version":"([^"]*)"').Groups[1].Value
        $lt = [regex]::Match($vpiece, '"lessThan":"([^"]*)"').Groups[1].Value
        $lte = [regex]::Match($vpiece, '"lessThanOrEqual":"([^"]*)"').Groups[1].Value
        $st = [regex]::Match($vpiece, '"status":"([^"]*)"').Groups[1].Value
        if ($st -ne 'affected') {
          if ($st -ne 'unaffected' -or -not (Usable $vver) -or $vver -eq '0' -or $lt -ne '') { continue }
          # popravak po grani (Linux kernel): 6.12.116 vrijedi samo za granu 6.12.*
          if ($lte -imatch '^([0-9]+\.[0-9]+)\.\*$') {
            [void]$fixes.Add($vver)
            [void]$specs.Add('>=' + $matches[1] + '.0;<' + $vver)
            continue
          }
          if ($lte -ne '') { continue }
          if ($fixed -eq '' -or (Compare-Ver $vver $fixed) -lt 0) { $fixed = $vver }
          continue
        }
        if (-not (Usable $vver)) {
          # "sve do" - vrijedi samo ako je gornja granica stvarna verzija
          if (Usable $lt) { [void]$specs.Add('<' + $lt); if ($fixed -eq '') { $fixed = $lt } }
          elseif (Usable $lte) { [void]$specs.Add('<=' + $lte) }
          continue
        }
        if ($lt -ne '' -and -not (Usable $lt)) { continue }
        if ($lte -ne '' -and -not (Usable $lte)) { continue }
        if ($lt -ne '') { [void]$specs.Add('>=' + $vver + ';<' + $lt); if ($fixed -eq '') { $fixed = $lt } }
        elseif ($lte -ne '') { [void]$specs.Add('>=' + $vver + ';<=' + $lte) }
      }
      if ($fixes.Count -gt 0) {
        $seenF = @{}
        $ord = @()
        foreach ($f in $fixes) { if (-not $seenF.ContainsKey($f)) { $seenF[$f] = 1; $ord += $f } }
        if ($fixed -eq '') { $fixed = ($ord -join '/') }
      }
      $spec = (($specs | Sort-Object -Unique) -join '|')
      if ($spec -eq '') {
        # NVD još nema strojno čitljiv raspon verzija (najčešće kernel: samo commit hash)
        $nk = $cve + '|' + $hitToken
        if (-not $noRangeSeen.ContainsKey($nk)) {
          $noRangeSeen[$nk] = 1
          if ($noRange.ContainsKey($hitToken)) { $noRange[$hitToken] = $noRange[$hitToken] + 1 } else { $noRange[$hitToken] = 1 }
        }
        continue
      }
      $key = $cve + '|' + $hitToken
      $proizvod = Clean ("{0} / {1}" -f $vendor, $product)
      if ($rows.ContainsKey($key)) {
        $old = $rows[$key]
        if ($spec -notlike ('*' + $spec + '*')) { $old.spec = ($old.spec + '|' + $spec) }
        if ($old.proizvod -notlike ('*' + $proizvod + '*')) { $old.proizvod = ($old.proizvod + ' + ' + $proizvod) }
        if ($best.score -gt $old.cvss) { $old.cvss = $best.score; $old.cver = $best.ver }
      }
      else {
        $ep = $null
        if ($epss.ContainsKey($cve)) { $ep = $epss[$cve] }
        $rows[$key] = [pscustomobject]@{
          cve = $cve; softver = $hitToken; proizvod = $proizvod; opis = $opis
          spec = $spec; fixed = $fixed; date = $pub; days = $days
          cvss = $best.score; cver = $best.ver; epss = $(if ($ep) { $ep.e } else { '' }); epssPct = $(if ($ep) { $ep.p } else { '' })
          kev = $(if ($kevIds.ContainsKey($cve)) { 'da' } else { 'ne' }); url = $url
        }
      }
    }
  }
}

$list = @($rows.Values | Sort-Object @{Expression = 'days'; Descending = $false }, @{Expression = 'cvss'; Descending = $true })

# --- 4b) što je alat pokazivao prošli put (za oznake NOVO / PROMIJENJENO) ---
# uzimamo staru data/vulns.csv PRIJE nego je prepišemo; stupci su namjerno malobrojni
$prevDate = [regex]::Match($html, 'id="snapshot">([0-9-]{10})<').Groups[1].Value
$prevLines = New-Object System.Collections.ArrayList
[void]$prevLines.Add('cve,softver,cvss,kev,fiksno_izdanje,pogodene_versije')
if (Test-Path 'data/vulns.csv') {
  $oldLines = @((Get-Content -Raw -Encoding UTF8 'data/vulns.csv') -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
  if ($oldLines.Count -gt 1) {
    $oh = $oldLines[0].Split(','); $ix = @{}
    for ($q = 0; $q -lt $oh.Count; $q++) { $ix[$oh[$q].Trim()] = $q }
    foreach ($l in ($oldLines | Select-Object -Skip 1)) {
      $c = $l.Split(',')
      $cells = @()
      foreach ($n in @('cve', 'softver', 'cvss', 'kev', 'fiksno_izdanje', 'pogodene_versije')) {
        $v = ''
        if ($ix.ContainsKey($n) -and $ix[$n] -lt $c.Count) { $v = $c[$ix[$n]] }
        $cells += (Clean $v)
      }
      [void]$prevLines.Add(($cells -join ','))
    }
  }
}
$prevCsv = $prevLines -join "`n"
[IO.File]::WriteAllText((Join-Path (Get-Location) 'data/prev.csv'), $prevCsv, (New-Object Text.UTF8Encoding($false)))
Write-Host ("prošla snimka za usporedbu: {0} zapisa (od {1})" -f ($prevLines.Count - 1), $prevDate)

# --- 5) CSV za index.html + upis u blok ---
$lines = New-Object System.Collections.ArrayList
[void]$lines.Add('cve,softver,izvor_proizvod,pogodene_versije,fiksno_izdanje,cvss,cvss_ver,epss,epss_pct,kev,datum,izvor_url,nvd_url,opis')
foreach ($r in $list) {
  $u = $r.url
  if ($u -eq '') { $u = 'https://nvd.nist.gov/vuln/detail/' + $r.cve }
  [void]$lines.Add((
      $r.cve, $r.softver, (Clean $r.proizvod), (Clean $r.spec), (Clean $r.fixed),
      $r.cvss.ToString('0.0', $culture), $r.cver, $r.epss, $r.epssPct, $r.kev, $r.date,
      (Clean $u), ('https://nvd.nist.gov/vuln/detail/' + $r.cve), (Clean $r.opis)) -join ',')
}
$csv = $lines -join "`n"
[IO.File]::WriteAllText((Join-Path (Get-Location) 'data/vulns.csv'), $csv, (New-Object Text.UTF8Encoding($false)))

$nrange = ''
$noRangeTotal = 0
if ($noRange.Count -gt 0) {
  $noRangeTotal = ($noRange.Values | Measure-Object -Sum).Sum
  $parts = @($noRange.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { '{0} {1}' -f $_.Key, $_.Value })
  $nrange = ('{0} prijava u NVD još nema strojno čitljiv raspon verzija ({1}), pa ovdje ne može biti izračunato pogađa li tebe. Osvježi ih kasnije.' -f $noRangeTotal, ($parts -join ', '))
}

$html = [regex]::Replace($html, '(?s)(<script type="text/csv" id="csv-vulns">).*?(</script>)', {
    param($m) $m.Groups[1].Value + "`n" + $csv + "`n" + $m.Groups[2].Value
})
$html = [regex]::Replace($html, '(?s)(<script type="text/csv" id="csv-prev">).*?(</script>)', {
    param($m) $m.Groups[1].Value + "`n" + $prevCsv + "`n" + $m.Groups[2].Value
})
$html = [regex]::Replace($html, '(id="prevdate">)[^<]*(<)', ('${1}' + $prevDate + '${2}'))
$html = [regex]::Replace($html, '(id="norange">)[^<]*(<)', ('${1}' + $nrange + '${2}'))
$html = [regex]::Replace($html, '(id="snapshot">)[^<]*(<)', ('${1}' + $today.ToString('yyyy-MM-dd', $culture) + '${2}'))

$noEpss = @($list | Where-Object { $_.epss -eq '' })
$epnote = ''
if ($list.Count -gt 0) {
  if ($epss.Count -eq 0) { $epnote = 'EPSS ocjena nije dohvaćena - pokreni bash fetch.sh pa ovu skriptu.' }
  elseif ($noEpss.Count -gt 0) { $epnote = ('EPSS (snimka {0}): bez ocjene je {1} od {2} zapisa - takvi redovi imaju "-".' -f $epssDate, $noEpss.Count, $list.Count) }
  else { $epnote = ('EPSS (snimka {0}): ocjena postoji za svih {1} zapisa.' -f $epssDate, $list.Count) }
}
$html = [regex]::Replace($html, '(id="epssdate">)[^<]*(<)', ('${1}' + $epssDate + '${2}'))
$html = [regex]::Replace($html, '(id="epssnote">)[^<]*(<)', ('${1}' + $epnote + '${2}'))
[IO.File]::WriteAllText((Join-Path (Get-Location) 'index.html'), $html, (New-Object Text.UTF8Encoding($false)))

# --- 6) kratko izvjesce ---
Write-Host ""
Write-Host ("zapisa u VULNS: {0} (KEV {1}, danas {2})" -f $list.Count, @($list | Where-Object { $_.kev -eq 'da' }).Count, @($list | Where-Object { $_.days -eq 0 }).Count)
Write-Host ("bez strojno čitljivog raspona verzija, nisu u tablici: {0}" -f ($noRange.Values | Measure-Object -Sum).Sum)
Write-Host ("EPSS: {0} ocjena u snimci {1}, bez ocjene u tablici: {2}" -f $epss.Count, $epssDate, $noEpss.Count)
Write-Host "po softveru:"
$list | Group-Object softver | Sort-Object Count -Descending | ForEach-Object { Write-Host ("  {0,-18} {1}" -f $_.Name, $_.Count) }
Write-Host ""
Write-Host ("neprepoznati proizvodi u objavama (top 15, moze se dopuniti u MAP):")
$unknown.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | ForEach-Object { Write-Host ("  {0,-46} {1}" -f $_.Key, $_.Value) }
