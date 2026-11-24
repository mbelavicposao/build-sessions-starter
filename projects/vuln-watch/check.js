// check.js - test logike za Vuln Watch
// Pokretanje:  cscript //nologo check.js   (iz mape projects\vuln-watch)
// Testira pravila iz PLAN.md: tko upada na listu, brojači i test s verzijom.

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
  ' buildEntries: buildEntries, countersFor: countersFor, WINDOW_DAYS: WINDOW_DAYS };')();

var software = api.parseCsv(block('csv-software'));
var vulns = api.parseCsv(block('csv-vulns'));
var today = new Date(2026, 10, 24);

var fails = 0;
function check(name, ok, detail) {
  WScript.Echo((ok ? 'PASS ' : 'FAIL ') + name + (detail ? '  -> ' + detail : ''));
  if (!ok) fails++;
}

// 1) podaci
check('SOFTWARE ima 32 retka', software.length === 32, 'ima ' + software.length);
check('VULNS ima 54 retka', vulns.length === 54, 'ima ' + vulns.length);
var badCols = 0;
var i;
for (i = 0; i < software.length; i++) if (!software[i].stroj || !software[i].softver || !software[i].verzija || !software[i].grupa) badCols++;
for (i = 0; i < vulns.length; i++) if (!vulns[i].cve || !vulns[i].softver || !vulns[i].pogodene_versije || isNaN(Number(vulns[i].cvss)) || isNaN(Number(vulns[i].dana_ako))) badCols++;
check('svi required stubci su popunjeni', badCols === 0, 'praznih: ' + badCols);
var badDays = vulns.filter(function (v) { return Number(v.dana_ako) < 0 || Number(v.dana_ako) > api.WINDOW_DAYS; });
check('dana_ako je u prozoru 0-' + api.WINDOW_DAYS, badDays.length === 0, 'izvan: ' + badDays.length);

// 2) usporedba verzija
check('1.28.4 < 1.28.7', api.compareVersions('1.28.4', '1.28.7') === -1);
check('2.426.2 < 2.440.2', api.compareVersions('2.426.2', '2.440.2') === -1);
check('5.15.0-91 nije < 5.10.0-30', api.isAffected('5.15.0-91', '<5.10.0-30') === false);
check('6.1.0-13 upada u >=6.0.0;<6.1.5', api.isAffected('6.1.0-13', '>=6.0.0;<6.1.5') === true);
check('6.0.30 upada u >=6.0.0;<6.1.5', api.isAffected('6.0.30', '>=6.0.0;<6.1.5') === true);
check('2.9.4 upada u <2.9.6', api.isAffected('2.9.4', '<2.9.6') === true);
check('2.9.6 ne upada u <2.9.6', api.isAffected('2.9.6', '<2.9.6') === false);

// 3) pravilo "moje"
var entries = api.buildEntries(software, vulns, today);
var counters = api.countersFor(entries);
var listedSoft = {};
for (i = 0; i < entries.length; i++) listedSoft[entries[i].softver] = 1;
var mySoft = {};
for (i = 0; i < software.length; i++) mySoft[software[i].softver] = 1;
var strangers = [];
for (var key in listedSoft) if (!mySoft[key]) strangers.push(key);
check('na listi je samo softver s popisa', strangers.length === 0, 'strani: ' + strangers.join(','));
var noReason = entries.filter(function (e) { return e.cvss < 9 && !e.kev && e.hit.length === 0; });
check('svaki zapis ima razlog (Critical, KEV ili pogođena verzija)', noReason.length === 0, 'bez razloga: ' + noReason.length);
var dropped = vulns.filter(function (v) { return !has(entries, v.cve); });
var droppedMine = dropped.filter(function (v) { return mySoft[v.softver]; });
check('ispalo je samo softver koji ne vrtim (mysql, wordpress, nginx, git)', droppedMine.length === 0,
  'ispalo iz moga popisa: ' + dropped.map(function (v) { return v.softver; }).join(','));
check('runi brojači', counters.danas === entries.filter(function (e) { return e.days === 0; }).length &&
  counters.tjedan === entries.filter(function (e) { return e.days <= 6; }).length && counters.sve === entries.length,
  'danas ' + counters.danas + ', 7 dana ' + counters.tjedan + ', 20 dana ' + counters.sve);

// 4) test iz plana: verzija gore -> zapis nestaje
var withFixedLoki = software.map(function (s) {
  var copy = {}; for (var k in s) copy[k] = s[k];
  if (copy.stroj === 'mon-03') copy.verzija = '2.9.6';
  return copy;
});
var afterFix = api.buildEntries(withFixedLoki, vulns, today);
function has(list, cve) { for (var j = 0; j < list.length; j++) if (list[j].cve === cve) return true; return false; }
check('CVE-2026-10160 (loki 4.5, bez KEV) je PRIJE testa na listi', has(entries, 'CVE-2026-10160'));
check('CVE-2026-10160 NESTAJE kad je verzija 2.9.6 (fiksna)', !has(afterFix, 'CVE-2026-10160'));
check('broj zapisa pao točno za 1', afterFix.length === entries.length - 1, entries.length + ' -> ' + afterFix.length);

// 5) test iz plana: nova pogođena verzija -> zapis se pojavi
var extra = software.concat([{ stroj: 'db-01', softver: 'mysql', verzija: '8.0.30', grupa: 'Alati', owner: 'tim-c@example.com' }]);
var withMysql = api.buildEntries(extra, vulns, today);
check('mysql 8.0.30 se POJAVI (CVE-2026-10058, CVSS 5.6, bez KEV, samo zbog verzije)', has(withMysql, 'CVE-2026-10058'));
var extraFixed = software.concat([{ stroj: 'db-01', softver: 'mysql', verzija: '8.0.36', grupa: 'Alati', owner: 'tim-c@example.com' }]);
check('mysql 8.0.36 (fiksni) NE ulazi na listu', !has(api.buildEntries(extraFixed, vulns, today), 'CVE-2026-10058'));

WScript.Echo('');
WScript.Echo('rezultat: ' + (fails === 0 ? 'SVI TESTOVI PROSLI' : fails + ' TEST(A) NIJE PROSLIO') +
  ' | na listi ' + entries.length + ' od ' + vulns.length + ' objava');
WScript.Quit(fails === 0 ? 0 : 1);
