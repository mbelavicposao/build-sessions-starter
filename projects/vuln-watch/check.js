// check.js - test logike i podataka za Vuln Watch
// Pokretanje:  cscript //nologo check.js   (iz mape projects\vuln-watch)
// 1) što je u tablici  2) jesu li CVSS i KEV stvarni (usporedba s data/raw i data/kev.json)
// 3) pravilo "moje"  4) brojači  5) verzija gore -> zapis nestaje / dolje -> zapis se pojavi

var fso = new ActiveXObject('Scripting.FileSystemObject');
var HERE = fso.GetParentFolderName(WScript.ScriptFullName);

function readUtf8(path) {
  var s = new ActiveXObject('ADODB.Stream');
  s.Type = 2; s.Charset = 'utf-8'; s.Open(); s.LoadFromFile(path);
  var t = s.ReadText(-1); s.Close(); return t;
}

// Polyfilli: cscript koristi stari JS engine bez ovih metoda.
if (!String.prototype.trim) { String.prototype.trim = function () { return this.replace(/^\s+|\s+$/g, ''); }; }
if (!Array.prototype.forEach) { Array.prototype.forEach = function (f) { for (var i = 0; i < this.length; i++) f(this[i], i, this); }; }
if (!Array.prototype.map) { Array.prototype.map = function (f) { var o = []; for (var i = 0; i < this.length; i++) o[i] = f(this[i], i, this); return o; }; }
if (!Array.prototype.filter) { Array.prototype.filter = function (f) { var o = []; for (var i = 0; i < this.length; i++) if (f(this[i], i, this)) o.push(this[i]); return o; }; }
if (!Array.prototype.every) { Array.prototype.every = function (f) { for (var i = 0; i < this.length; i++) if (!f(this[i], i, this)) return false; return true; }; }
if (!Array.prototype.some) { Array.prototype.some = function (f) { for (var i = 0; i < this.length; i++) if (f(this[i], i, this)) return true; return false; }; }
if (!Array.prototype.indexOf) { Array.prototype.indexOf = function (x) { for (var i = 0; i < this.length; i++) if (this[i] === x) return i; return -1; }; }

var html = readUtf8(HERE + '\\index.html');

function block(id) {
  var re = new RegExp('<script type="text/csv" id="' + id + '">([\\s\\S]*?)<\\/script>');
  var m = html.match(re);
  if (!m) throw new Error('nema bloka ' + id + ' u index.html');
  return m[1];
}
var logicMatch = html.match(/LOGIKA-POCETAK ===== \*\/([\s\S]*?)\/\* ===== LOGIKA-KRAJ/);
if (!logicMatch) throw new Error('nema LOGIKA bloka u index.html');

var api = new Function(logicMatch[1] +
  '; return { parseCsv: parseCsv, compareVersions: compareVersions, isAffected: isAffected,' +
  ' buildEntries: buildEntries, countersFor: countersFor, WINDOW_DAYS: WINDOW_DAYS,' +
  ' cmp: cmp, val: val, head: head, SORT: SORT, COLS: COLS };')();

var software = api.parseCsv(block('csv-software'));
var vulns = api.parseCsv(block('csv-vulns'));
var snapMatch = html.match(/id="snapshot">([0-9]{4})-([0-9]{2})-([0-9]{2})</);
if (!snapMatch) throw new Error('nema datuma snimke u index.html');
var today = new Date(Number(snapMatch[1]), Number(snapMatch[2]) - 1, Number(snapMatch[3]));

var fails = 0;
function check(name, ok, detail) {
  WScript.Echo((ok ? 'PASS ' : 'FAIL ') + name + (detail ? '  -> ' + detail : ''));
  if (!ok) fails++;
}
// cijeli JS iz stranice mora se parsirati bez sintaksne greške (render() nije u LOGIKA bloku)
var pageJs = html.match(/<script>([\s\S]*?)<\/script>/);
var jsErr = '';
try { if (!pageJs) throw new Error('nema <script> bloka'); new Function(pageJs[1]); } catch (err) { jsErr = err.message; }
check('JS u stranici se parsira bez sintaksne greške', jsErr === '', jsErr);
function parseDate(s) {
  var m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : null;
}

// ===== 1) oblik podataka u tablici =====
check('SOFTWARE ima retke', software.length > 0, 'ima ' + software.length);
check('VULNS ima retke', vulns.length > 0, 'ima ' + vulns.length);

var embedded = block('csv-vulns').replace(/^\s+|\s+$/g, '');
var csvFile = readUtf8(HERE + '\\data\\vulns.csv').replace(/^\s+|\s+$/g, '');
check('VULNS u index.html je ist kao data/vulns.csv', embedded === csvFile,
  embedded.length + ' vs ' + csvFile.length + ' znakova');

var badShape = [], badShapeEx = '';
var allowedSoft = {};
for (var i = 0; i < software.length; i++) allowedSoft[software[i].softver] = 1;
for (i = 0; i < vulns.length; i++) {
  var v = vulns[i];
  var why = '';
  if (!/^CVE-[0-9]{4}-[0-9]{4,}$/.test(v.cve)) why = 'CVE oblik';
  else if (!allowedSoft[v.softver]) why = 'softver nije na mom popisu: ' + v.softver;
  else if (v.pogodene_versije === '' || v.pogodene_versije.indexOf(' ') >= 0 || /[<>=]/.test(v.pogodene_versije) === false) why = 'raspon';
  else if (isNaN(Number(v.cvss)) || Number(v.cvss) < 0 || Number(v.cvss) > 10) why = 'CVSS';
  else if (!/^[34]\.[01](\.[0-9])?$/.test(v.cvss_ver)) why = 'verzija CVSS: ' + v.cvss_ver;
  else if (!v.izvor_proizvod || v.izvor_proizvod.indexOf('/') < 0) why = 'izvor_proizvod';
  else if (!v.opis || v.opis.length < 20) why = 'opis';
  else if (v.kev !== 'da' && v.kev !== 'ne') why = 'kev';
  else if (!parseDate(v.datum)) why = 'datum';
  else if (v.nvd_url !== 'https://nvd.nist.gov/vuln/detail/' + v.cve) why = 'nvd_url';
  else if (!/^https?:\/\//.test(v.izvor_url) || v.izvor_url.indexOf('example.com') >= 0) why = 'izvor_url';
  else if (v.fiksno_izdanje === '0') why = 'fiksno izdanje 0';
  if (why) { badShape.push(v.cve + ' ' + why); if (badShapeEx === '') badShapeEx = v.cve + ': ' + why; }
}
check('svaki redak ima ispravne stupce', badShape.length === 0, badShape.length + ' (prvi: ' + badShapeEx + ')');

var outWindow = vulns.filter(function (v) {
  var d = parseDate(v.datum);
  var days = Math.round((today - d) / 86400000);
  return days < 0 || days > api.WINDOW_DAYS;
});
check('datum je u prozoru 0-' + api.WINDOW_DAYS + ' dana od snimke', outWindow.length === 0,
  'izvan: ' + outWindow.map(function (v) { return v.cve + ' ' + v.datum; }).join(' '));
check('nema izmišljenih e-mail adresa u podacima o propustima',
  block('csv-vulns').indexOf('example.com') < 0);

// ===== 2) jesu li CVSS i KEV stvarni (iz feeda, ne izmišljeni) =====
var rawFiles = [];
var enm = new Enumerator(fso.GetFolder(HERE + '\\data\\raw').Files);
for (; !enm.atEnd(); enm.moveNext()) if (/\.json$/i.test(enm.item().Name)) rawFiles.push(enm.item().Path);
check('data/raw ima spremljene NVD odgovore', rawFiles.length > 0, 'datoteka: ' + rawFiles.length);

var kevText = readUtf8(HERE + '\\data\\kev.json');
var kevIds = {};
var km = /"cveID": *"([A-Z0-9-]+)"/g, kmMatch;
while ((kmMatch = km.exec(kevText)) !== null) kevIds[kmMatch[1]] = 1;
check('data/kev.json sadrži KEV zapise', function () { var n = 0; for (var k in kevIds) n++; return n; }() > 100, 'CVE-ova: ' + (function () { var n = 0; for (var k in kevIds) n++; return n; })());

// svaki CVE iz tablice mora biti u NVD odgovoru, s tom istom ocjenom, proizvodom i opisom
function norm(s) {
  return String(s).replace(/\\[nrtuv][0-9a-fA-F]*/g, ' ').replace(/[",]/g, ' ').replace(/\s+/g, ' ');
}
var want = {};
vulns.forEach(function (v) {
  want[v.cve + '|' + v.softver] = {
    cve: v.cve, score: Number(v.cvss), found: false, scored: false,
    proizvod: v.izvor_proizvod, opis: v.opis, prodOk: false, opisOk: false
  };
});
var rawIds = {};
for (var f = 0; f < rawFiles.length; f++) {
  var text = readUtf8(rawFiles[f]);
  var chunks = text.split('{"cve":{');
  for (var c = 1; c < chunks.length; c++) {
    var idm = chunks[c].match(/"id":"(CVE-[0-9]{4}-[0-9]+)"/);
    if (!idm) continue;
    var id = idm[1];
    rawIds[id] = 1;
    var chunkNorm = norm(chunks[c]);
    var scores = chunks[c].match(/"baseScore":[0-9.]+/g);
    for (var w in want) {
      var e = want[w];
      if (e.cve !== id) continue;
      if (!e.scored && scores) {
        for (var s = 0; s < scores.length; s++) {
          if (Number(scores[s].replace(/[^0-9.]/g, '')) === e.score) { e.found = true; e.scored = true; break; }
        }
      }
      if (!e.prodOk) {
        var parts = e.proizvod.split(' + ');
        var all = parts.length > 0;
        for (var p = 0; p < parts.length; p++) {
          var vp = parts[p].split(' / ');
          if (chunkNorm.indexOf(norm(vp[0])) < 1 || chunkNorm.indexOf(norm(vp[1] || vp[0])) < 1) { all = false; break; }
        }
        e.prodOk = all;
      }
      if (!e.opisOk) {
        var lead = norm(e.opis).replace(/^\s+|\s+$/g, '').substring(0, 60);
        e.opisOk = lead.length > 20 && chunkNorm.indexOf(lead) >= 0;
      }
    }
  }
}
var notInRaw = [], wrongScore = [], wrongProd = [], wrongOpis = [];
for (var key in want) {
  var w2 = want[key];
  if (!w2.found) { (rawIds[w2.cve] ? wrongScore : notInRaw).push(key); }
  if (!w2.prodOk) wrongProd.push(key + ' <- ' + w2.proizvod);
  if (!w2.opisOk) wrongOpis.push(key + ' <- ' + String(w2.opis).substring(0, 50));
}
check('svaki CVSS u tablici postoji u sirovom NVD odgovoru', notInRaw.length === 0 && wrongScore.length === 0,
  'nema ga u feedu: ' + notInRaw.length + ', ocjena se ne podudara: ' + wrongScore.length +
  (notInRaw.length ? ' (prvi: ' + notInRaw[0] + ')' : '') + (wrongScore.length ? ' (prvi: ' + wrongScore[0] + ')' : ''));
check('proizvod iz retka je onaj iz NVD objave (vendor / product)', wrongProd.length === 0,
  wrongProd.length + ' (prvi: ' + (wrongProd[0] || '') + ')');
check('opis u retku je doslovno iz te NVD objave', wrongOpis.length === 0,
  wrongOpis.length + ' (prvi: ' + (wrongOpis[0] || '') + ')');

var kevYes = vulns.filter(function (v) { return v.kev === 'da'; });
var kevNoButListed = vulns.filter(function (v) { return v.kev !== 'da' && kevIds[v.cve]; });
var kevYesButMissing = kevYes.filter(function (v) { return !kevIds[v.cve]; });
check('KEV zastavica odgovara CISA katalogu (u oba smjera)',
  kevYesButMissing.length === 0 && kevNoButListed.length === 0,
  'krivo da: ' + kevYesButMissing.length + ', krivo ne: ' + kevNoButListed.length);
check('KEV zapisi postoje i nisu izmišljeni', kevYes.length > 0, 'KEV zapisa: ' + kevYes.length);

// ===== 3) pravilo "moje" =====
var entries = api.buildEntries(software, vulns, today);
function has(list, cve) { for (var j = 0; j < list.length; j++) if (list[j].cve === cve) return true; return false; }
check('na listi je samo softver s moga popisa',
  entries.every(function (e) { return allowedSoft[e.softver]; }));
var noReason = entries.filter(function (e) { return e.cvss < 9 && !e.hit.length && e.kev !== 'da'; });
check('svaki zapis ima razlog (CVSS >= 9, KEV ili pogođena verzija)', noReason.length === 0, 'bez razloga: ' + noReason.length);
var hits = entries.filter(function (e) { return e.hit.length; });
check('barem jedan zapis pogađa moju verziju', hits.length > 0, 'pogođenih: ' + hits.length + ' od ' + entries.length);
var wrongHit = entries.filter(function (e) {
  return e.hit.length !== vulns.filter(function (v) { return v.cve === e.cve && v.softver === e.softver; })
    .filter(function (v) {
      return software.some(function (s) { return s.softver === v.softver && api.isAffected(s.verzija, v.pogodene_versije); });
    }).length;
});
check('pogoci su izračunati iz raspona, ne upisani ručno', wrongHit.length === 0, 'nered: ' + wrongHit.length);

// ===== 4) brojači =====
var counters = api.countersFor(entries);
check('brojači su točni',
  counters.danas === entries.filter(function (e) { return e.days === 0; }).length &&
  counters.tjedan === entries.filter(function (e) { return e.days <= 6; }).length &&
  counters.sve === entries.length,
  'danas ' + counters.danas + ', 7 dana ' + counters.tjedan + ', 20 dana ' + counters.sve);
var todayRows = vulns.filter(function (v) { return Math.round((today - parseDate(v.datum)) / 86400000) === 0; });
check('brojač "danas" odgovara podacima', counters.danas <= todayRows.length &&
  entries.filter(function (e) { return e.days === 0; }).length === todayRows.filter(function (v) { return has(entries, v.cve); }).length,
  'danas prijavljenih: ' + todayRows.length + ', na listi: ' + counters.danas);

// ===== 5) verzija gore -> zapis nestaje =====
var bumpable = null;
for (i = 0; i < entries.length; i++) {
  var e = entries[i];
  if (e.hit.length && e.cvss < 9 && e.kev !== 'da' && e.fixed) { bumpable = e; break; }
}
if (!bumpable) throw new Error('nema zapisa za test verzije (treba hit, CVSS < 9, bez KEV)');
var fixedVer = bumpable.fixed.split('/')[0];
var host = software.filter(function (s) { return s.softver === bumpable.softver && api.isAffected(s.verzija, bumpable.spec); })[0];
var raised = software.map(function (s) {
  var copy = {}; for (var k in s) copy[k] = s[k];
  if (copy.stroj === host.stroj) copy.verzija = fixedVer;
  return copy;
});
var afterRaise = api.buildEntries(raised, vulns, today);
check(bumpable.cve + ' NESTAJE kad ' + host.stroj + ' ide s ' + host.verzija + ' na ' + fixedVer, !has(afterRaise, bumpable.cve),
  'CVSS ' + bumpable.cvss + ', KEV ' + bumpable.kev);

// ===== 6) nova pogođena verzija -> zapis se pojavi =====
var growable = null, growVer = '';
for (i = 0; i < vulns.length; i++) {
  var v = vulns[i];
  if (allowedSoft[v.softver] && !has(entries, v.cve) && v.cvss < 9 && v.kev !== 'da' && /^>=[^;|]+;/.test(v.pogodene_versije)) {
    growable = v; growVer = v.pogodene_versije.match(/^>=([^;|]+)/)[1]; break;
  }
}
if (!growable) throw new Error('nema zapisa za test nove verzije');
var grown = software.concat([{ stroj: 'novi-01', softver: growable.softver, verzija: growVer, grupa: 'Alati', owner: 'tim-n@example.com' }]);
check(growable.cve + ' se POJAVI kad novi stroj ' + growVer + ' dođe na popis',
  has(api.buildEntries(grown, vulns, today), growable.cve), 'CVSS ' + growable.cvss + ' < 9, bez KEV, samo zbog verzije');

// ===== 7) fiks dostupan + sortiranje po stupcima =====
var withFix = entries.filter(function (e) { return e.fixed; });
var noFix = entries.filter(function (e) { return !e.fixed; });
check('stranica kaze je li fiks dostupan', html.indexOf('ne - NVD ne navodi izdanje') >= 0 && html.indexOf('da - ') >= 0,
  's fiksom ' + withFix.length + ', bez fiksa ' + noFix.length);

api.SORT.key = ''; api.SORT.dir = 1;
var hdr = api.head();
var noClick = [], noKey = [];
for (i = 0; i < api.COLS.length; i++) {
  if (hdr.indexOf('sortBy(\'' + api.COLS[i][0] + '\')') < 0) noClick.push(api.COLS[i][0]);
  if (typeof entries[0][api.COLS[i][0]] === 'undefined') noKey.push(api.COLS[i][0]);
}
check('svaki stupac u naslovu je kliknut za sortiranje',
  noClick.length === 0 && hdr.split('<th class="s"').length - 1 === api.COLS.length,
  'kliknutih naslova: ' + (hdr.split('<th class="s"').length - 1) + ' / ' + api.COLS.length + ', bez kliknutja: ' + noClick.join(' '));
check('svaki kljuc za sortiranje postoji u zapisu', noKey.length === 0, 'nema ga: ' + noKey.join(' '));

var sortBad = [];
for (i = 0; i < api.COLS.length; i++) {
  var key = api.COLS[i][0];
  for (var dir = -1; dir <= 1; dir += 2) {
    api.SORT.key = key; api.SORT.dir = dir;
    var s = entries.slice(0).sort(api.cmp);
    for (var j = 1; j < s.length; j++) {
      var x = api.val(s[j - 1], key), y = api.val(s[j], key);
      x = (typeof x === 'number') ? x : String(x).toLowerCase();
      y = (typeof y === 'number') ? y : String(y).toLowerCase();
      if (dir < 0 ? x < y : x > y) { sortBad.push(key + ' ' + (dir < 0 ? 'dolje' : 'gore')); break; }
    }
  }
}
check('svaki stupac sortira u oba smjera', sortBad.length === 0, 'krivo: ' + sortBad.join(' '));

api.SORT.key = 'fixed'; api.SORT.dir = -1;
var byFix = entries.slice(0).sort(api.cmp);
check('sort po "fiks dostupan" - s fiksom prvi', withFix.length > 0 && (function () {
  for (var k = 0; k < withFix.length; k++) if (!byFix[k].fixed) return false;
  return true;
})(), 's fiksom ' + withFix.length + ' od ' + entries.length);
api.SORT.key = ''; api.SORT.dir = 1;

WScript.Echo('');
WScript.Echo('rezultat: ' + (fails === 0 ? 'SVI TESTOVI PROSLI' : fails + ' TEST(A) NIJE PROSLIO') +
  ' | ' + vulns.length + ' stvarnih prijava, na listi ' + entries.length + ', pogođeno ' + hits.length +
  ', KEV ' + kevYes.length);
WScript.Quit(fails === 0 ? 0 : 1);
