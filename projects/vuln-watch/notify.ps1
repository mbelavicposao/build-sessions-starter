# notify.ps1 - Windows notifikacija: sto je NOVO ili PROMIJENJENO od proslog osvjezavanja alata.
# Radi bez instalacije, bez administratora i bez interneta: cita samo data/vulns.csv i data/prev.csv.
#   notifikacija:  powershell -NoProfile -ExecutionPolicy Bypass -File notify.ps1
#   proba bez skocke:  ... -File notify.ps1 -dry
param([switch]$dry, [int]$seconds = 12)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

if (-not (Test-Path 'data/vulns.csv')) {
  Write-Host 'nema data/vulns.csv - prvo pokreni: bash fetch.sh pa powershell -ExecutionPolicy Bypass -File refresh.ps1'
  exit 1
}

$cur = @(Import-Csv -Encoding UTF8 'data/vulns.csv')
$prev = @()
if (Test-Path 'data/prev.csv') { $prev = @(Import-Csv -Encoding UTF8 'data/prev.csv') }

$prevDate = [regex]::Match((Get-Content -Raw -Encoding UTF8 'index.html'), 'id="prevdate">([0-9-]{10})<').Groups[1].Value

# usporedba je ista ona koju radi stranica: isti kljuc (CVE + softver), iste promjene
$ix = @{}
foreach ($p in $prev) { $ix[$p.cve + '|' + $p.softver] = $p }
$novo = 0; $novoKev = 0; $novoHigh = 0; $prom = 0
foreach ($r in $cur) {
  $p = $null
  if ($ix.ContainsKey($r.cve + '|' + $r.softver)) { $p = $ix[$r.cve + '|' + $r.softver] }
  if ($null -eq $p) {
    $novo++
    if ($r.kev -eq 'da') { $novoKev++ }
    if ([double]$r.cvss -ge 9) { $novoHigh++ }
    continue
  }
  if ($p.cvss -ne $r.cvss -or $p.kev -ne $r.kev -or $p.fiksno_izdanje -ne $r.fiksno_izdanje -or $p.pogodene_versije -ne $r.pogodene_versije) { $prom++ }
}
$kev = @($cur | Where-Object { $_.kev -eq 'da' }).Count
$high = @($cur | Where-Object { [double]$_.cvss -ge 9 }).Count

# ozbiljna notifikacija samo kad je novo nešto doista opasno (KEV ili CVSS 9+)
$alarm = ($novoKev -gt 0 -or $novoHigh -gt 0)
if ($prev.Count -eq 0) {
  $text = ('Prva snimka: oznake NOVO i PROMIJENJENO idu od sljedeceg osvjezavanja.' + "`n" + '{0} prijava, KEV {1}, CVSS 9+ {2}. Otvori index.html.' -f $cur.Count, $kev, $high)
} else {
  $text = ('NOVO {0} (KEV {1}, CVSS 9+ {2}) · PROMIJENJENO {3}' -f $novo, $novoKev, $novoHigh, $prom) + "`n" +
    ('Ukupno {0} prijava, KEV {1}, CVSS 9+ {2}. Usporedba sa snimkom {3}. Otvori index.html.' -f $cur.Count, $kev, $high, $prevDate)
}

Write-Host $text
$dir = 'notes'
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$line = ('{0}Z | {1} | {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'), $(if ($dry) { 'suho' } else { 'skocka' }), ($text -replace "`n", ' / '))
Add-Content -Path (Join-Path $dir 'notify.log') -Value $line -Encoding UTF8

if ($dry) { Write-Host '(-dry: notifikacija nije pokazana)'; exit 0 }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$ni = New-Object System.Windows.Forms.NotifyIcon
$ni.Icon = $(if ($alarm) { [System.Drawing.SystemIcons]::Warning } else { [System.Drawing.SystemIcons]::Information })
$ni.BalloonTipIcon = $(if ($alarm) { [System.Windows.Forms.ToolTipIcon]::Warning } else { [System.Windows.Forms.ToolTipIcon]::Info })
$ni.BalloonTipTitle = 'vuln-watch'
$ni.BalloonTipText = $text
$ni.Visible = $true
$ni.ShowBalloonTip($seconds * 1000)
$deadline = (Get-Date).AddSeconds($seconds)
while ((Get-Date) -lt $deadline) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 200 }
$ni.Visible = $false
$ni.Dispose()
Write-Host 'notifikacija pokazana'
