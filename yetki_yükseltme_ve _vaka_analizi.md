# Saldırı Bazlı Genel Privilege Escalation Yöntemleri  
## Root Yetkili İş Akışlarını, Saldırgan Kontrollü Dosyalarla Suistimal Etme Rehberi

> **Amaç:** Bu rapor belirli bir makineye ya da tek bir CVE’ye odaklanmaz. WingData senaryosundaki saldırı mantığını temel alarak, benzer privilege escalation zincirlerini **genel yöntemler**, **neden-sonuç ilişkileri**, **hangi şartlarda işe yarar**, **nasıl keşfedilir** ve **nasıl doğrulanır** başlıklarıyla anlatır.

> **Bağlam:** Yetkili laboratuvar, CTF, eğitim ve savunma amaçlı analiz içindir.

---

## 0. Ana Fikir

Bu saldırı sınıfının özü şudur:

```text
Düşük yetkili kullanıcı
  ↓
Kendi kontrol ettiği bir dosya/input üretir
  ↓
Daha yüksek yetkili bir süreç bu inputu işler
  ↓
İşleme sırasında dosya sistemi, komut veya kimlik doğrulama üzerinde etki oluşur
  ↓
Bu etki root yetkisine çevrilir
```

Bu raporun temel cümlesi:

> Privilege escalation çoğu zaman “root exploit çalıştırmak” değil, **root olarak çalışan güvenilir bir süreci saldırgan kontrollü veriyle yanlış davranmaya zorlamaktır.**

---

# 1. Saldırı Modeli: Üçlü Denklem

Bu tarz saldırılar genellikle üç parçadan oluşur:

```text
1. Yetkili işlem
2. Saldırgan kontrollü veri
3. Güven sınırı hatası
```

## 1.1. Yetkili İşlem

Yetkili işlem şunlardan biri olabilir:

```text
root çalışan cron job
root çalışan systemd servisi
sudo ile root çalışan script
backup/restore otomasyonu
admin panelin arka planda çalıştırdığı işlem
deploy pipeline
log rotate/import/export scripti
```

Örnek:

```text
root olarak çalışan restore_backup_clients.py
```

## 1.2. Saldırgan Kontrollü Veri

Saldırganın kontrol ettiği veri şunlar olabilir:

```text
tar/zip arşivi
dosya adı
dizin adı
config dosyası
log dosyası
environment değişkeni
script argümanı
upload edilen paket
template dosyası
backup dosyası
```

Örnek:

```text
/opt/backup_clients/backups/backup_9999.tar
```

## 1.3. Güven Sınırı Hatası

Güven sınırı hatası şu şekilde olur:

```text
Düşük yetkili kullanıcının kontrol ettiği veri,
yüksek yetkili işlem tarafından fazla güvenilerek işlenir.
```

Örnek:

```text
wacky kullanıcısının oluşturduğu tar dosyası,
root olarak çalışan Python script tarafından extract edilir.
```

---

# 2. Neden-Sonuç Zinciri

Bu saldırı sınıfını anlamak için tek tek bulgulara değil, **bulguların birleşimine** bakmak gerekir.

## 2.1. Tek Başına Önemsiz Görünen Bulgular

Aşağıdaki bulgular tek başına root vermez:

```text
Bir dizine yazabiliyorum.
Bir backup dosyası oluşturabiliyorum.
Bir script sudo ile çalışıyor.
Bir tar arşivi extract ediliyor.
Bir symlink oluşturabiliyorum.
Bir Python sürümü zafiyetli olabilir.
```

Ama bu bulgular birleşince saldırı zinciri oluşur.

## 2.2. Birleşince Kritik Hale Gelen Zincir

```text
Kullanıcı backup dizinine yazabiliyor
  +
sudo script root olarak o dizinden dosya okuyor
  +
script tar arşivini extract ediyor
  +
tar extraction mekanizması bypass edilebilir
  +
root olarak /etc/sudoers.d altına dosya yazdırılabiliyor
  =
root shell
```

## 2.3. Genel Denklem

```text
Writable input + privileged parser + unsafe side effect = privilege escalation
```

Buradaki “side effect” şunlardan biri olabilir:

```text
dosya yazma
dosya okuma
komut çalıştırma
servis yeniden başlatma
yetki dosyası değiştirme
credential üretme
authorized_keys ekleme
cron görevi oluşturma
```

---

# 3. Bu Sınıftaki Saldırı Aileleri

Aşağıdaki yöntemler aynı ana fikrin farklı formlarıdır.

---

## 3.1. Root Tar/Zip Extraction Abuse

### Mantık

Kullanıcı bir arşiv dosyası oluşturur. Root çalışan bir süreç bu arşivi açar. Arşiv içindeki path, symlink, hardlink veya metadata hatalı işlenirse hedef dizin dışına dosya yazılabilir.

### Nerede Görülür?

```text
backup restore scriptleri
web panel yedek geri yükleme özellikleri
CI/CD artifact extraction
kullanıcı upload edilen zip/tar import işlemleri
log arşivi açan scriptler
müşteri verisi restore eden otomasyonlar
```

### İşe Yaraması İçin Gerekli Şartlar

```text
[+] Arşiv saldırgan tarafından oluşturulabiliyor.
[+] Arşiv daha yüksek yetkili kullanıcı tarafından açılıyor.
[+] Extraction root veya daha yetkili kullanıcı contextinde yapılıyor.
[+] Arşiv metadata’sı yeterince doğrulanmıyor.
[+] Dosya yazdırma hedefi privesc’e çevrilebiliyor.
```

### Saldırıya Çevrilebilecek Hedefler

```text
/etc/sudoers.d/<dosya>
/root/.ssh/authorized_keys
/etc/cron.d/<dosya>
/etc/systemd/system/<servis>.service
root tarafından çalışan script/config
```

### Keşif İpuçları

```bash
sudo -l
find / -name "*backup*" -o -name "*restore*" 2>/dev/null
find / -type d -writable 2>/dev/null
find /opt /usr/local /var -type f -iname "*.py" -o -iname "*.sh" 2>/dev/null
grep -RniE "extractall|tarfile|ZipFile|unpack_archive|tar -|unzip" /opt /usr/local /var/www 2>/dev/null
```

### Karar Soruları

```text
Bu arşivi kim oluşturuyor?
Bu arşivi kim açıyor?
Ben arşiv içeriğini kontrol ediyor muyum?
Extraction hedefi sabit mi?
Symlink/hardlink kabul ediliyor mu?
Path traversal engelleniyor mu?
Root context var mı?
```

---

## 3.2. Sudo Script Abuse

### Mantık

Kullanıcı belirli bir scripti root olarak çalıştırabilir. Script doğrudan shell vermez ama kullanıcıdan argüman veya dosya alır. Bu input üzerinden root etkisi oluşturulur.

### Örnek Sudo Kuralı

```text
(root) NOPASSWD: /usr/bin/python3 /opt/app/restore.py *
```

### İşe Yaraması İçin Gerekli Şartlar

```text
[+] sudo -l içinde özel script vardır.
[+] Script root olarak çalışır.
[+] Script kullanıcı argümanı veya kullanıcı kontrollü dosya kullanır.
[+] Script dosya yazar, komut çalıştırır, arşiv açar veya parser kullanır.
[+] Scriptin davranışı root yetkisine çevrilebilir.
```

### Scriptte Aranacak Tehlikeli Fonksiyonlar

```python
os.system(...)
subprocess.run(..., shell=True)
open(path, "w")
shutil.copy(...)
tar.extractall(...)
zipfile.extractall(...)
yaml.load(...)
pickle.load(...)
eval(...)
exec(...)
```

### Keşif Komutları

```bash
sudo -l
ls -la /opt /usr/local /var/www 2>/dev/null
find /opt /usr/local /var/www -type f -readable -ls 2>/dev/null
grep -RniE "system\(|subprocess|extractall|open\(|copy|move|tarfile|zipfile|pickle|yaml|eval|exec" /opt /usr/local /var/www 2>/dev/null
```

### Düşünme Şekli

Yanlış yaklaşım:

```text
Bu script doğrudan shell vermiyor, işe yaramaz.
```

Doğru yaklaşım:

```text
Bu script root olarak neyi okuyor, neyi yazıyor, hangi inputu bana bırakıyor?
```

---

## 3.3. Dosya Yazdırma Primitive’i

### Mantık

Saldırgan doğrudan root olmasa bile root contextinde bir dosya yazdırabiliyorsa, bunu yetki yükseltmeye çevirebilir.

### Dosya Yazdırma Neden Root’a Götürür?

Çünkü Linux’ta bazı dosyalar davranışı belirler:

```text
sudo yetkileri
cron işleri
SSH authorized_keys
systemd servisleri
dynamic linker ayarları
PAM ayarları
root tarafından çalışan scriptler
```

### Hedef Dosya Örnekleri

| Hedef | Etki |
|---|---|
| `/etc/sudoers.d/<file>` | Kullanıcıya sudo yetkisi verme |
| `/root/.ssh/authorized_keys` | Root SSH erişimi |
| `/etc/cron.d/<file>` | Root komut çalıştırma |
| `/etc/systemd/system/<service>` | Root servis oluşturma |
| Root-owned script | Sonraki çalışmada code execution |

### En Kontrollü Hedef

Genellikle en kontrollü hedef:

```text
/etc/sudoers.d/<dosya>
```

Çünkü tek satırla yetki verilebilir:

```text
kullanici ALL=(ALL) NOPASSWD: ALL
```

Ama dikkat:

```text
Yanlış syntax sudo’yu bozabilir.
Ana /etc/sudoers dosyasını overwrite etmek risklidir.
```

Daha güvenli hedef:

```text
/etc/sudoers.d/custom_file
```

---

## 3.4. Symlink Abuse

### Mantık

Süreç bir dosyayı güvenli dizinde sanır ama symlink yüzünden işlem başka bir hedefe gider.

Örnek:

```text
safe/output.conf -> /etc/sudoers.d/wacky
```

Root süreç `safe/output.conf` dosyasına yazdığını sanır, aslında `/etc/sudoers.d/wacky` dosyasına yazar.

### Nerede Görülür?

```text
backup restore
log yazma
temporary file kullanımı
upload edilen dosya işleme
report export
cache oluşturma
```

### İşe Yaraması İçin Şartlar

```text
[+] Saldırgan symlink oluşturabiliyor.
[+] Root süreç symlink’i takip ediyor.
[+] Yazma işlemi root contextinde.
[+] Hedef dosya privesc’e çevrilebilir.
```

### Keşif

```bash
find / -type d -writable 2>/dev/null
find / -type l -ls 2>/dev/null | head
```

Script incelemesinde:

```text
open(path, "w")
copy(src, dst)
move(src, dst)
tar extraction
zip extraction
temporary file oluşturma
```

---

## 3.5. Hardlink Abuse

### Mantık

Hardlink aynı dosyanın başka bir adı gibidir. Eğer root süreç hardlink’i yanlış işlerse, saldırgan kontrollü path üzerinden hassas dosyaya etki edebilir.

### Ne Zaman Mümkün?

```text
Sistem hardlink korumaları zayıfsa
Aynı filesystem üzerinde hedeflenebilir dosya varsa
Extractor hardlink metadata’sını işliyorsa
Root süreç link hedefini yanlış doğruluyorsa
```

### Kontrol

```bash
sysctl fs.protected_hardlinks
```

Eğer `1` ise normal kullanıcıların sahip olmadığı dosyalara hardlink oluşturması engellenir. Fakat arşiv extraction gibi işlemlerde hardlink metadata’sı root süreç tarafından oluşturuluyorsa farklı saldırı yüzeyi doğabilir.

---

## 3.6. Path Traversal

### Mantık

Uygulama çıktı dizinine yazdığını düşünür:

```text
/var/app/output/<filename>
```

Ama saldırgan filename olarak şunu verir:

```text
../../../../etc/sudoers.d/wacky
```

Sonuç:

```text
/etc/sudoers.d/wacky
```

### Nerede Görülür?

```text
file upload
archive extraction
template export
backup restore
download endpointleri
log viewer
image converter
```

### İşe Yaraması İçin Şartlar

```text
[+] Kullanıcı path veya filename kontrol ediyor.
[+] Path normalize edilmiyor.
[+] Realpath destination altında mı kontrol edilmiyor.
[+] Yazma/okuma yetkili contextte yapılıyor.
```

---

## 3.7. TOCTOU / Race Condition

### Mantık

Sistem önce kontrol yapar, sonra dosyayı kullanır.

```python
if os.path.isfile(path):
    open(path)
```

Arada saldırgan dosyayı değiştirirse, kontrol edilen dosya ile kullanılan dosya farklı olabilir.

```text
Time Of Check → Time Of Use
```

### İşe Yaraması İçin Şartlar

```text
[+] Kontrol ve kullanım ayrı adımlardır.
[+] Saldırgan bu iki adım arasında dosyayı değiştirebilir.
[+] İşlem yüksek yetkilidir.
[+] Yarış penceresi yakalanabilir.
```

### Keşif İşaretleri

```text
os.path.exists + open
isfile + tarfile.open
stat + copy
access + write
temporary file name predict edilebilir
```

### Değerlendirme

Race zafiyetleri teorik olarak mümkün görünse bile pratikte stabil olmayabilir. Önce daha deterministik yollar denenmelidir.

---

## 3.8. Python Import Hijacking

### Mantık

Root olarak çalışan Python script bir modül import eder. Eğer Python import path içinde saldırganın yazabildiği dizin varsa, sahte modül yüklenebilir.

### Riskli Durum

```python
import helper
```

Ve dizin:

```text
/opt/app/helper.py saldırgan tarafından yazılabilir
```

### Keşif

```bash
grep -RniE "^import |^from " /opt /usr/local 2>/dev/null
find /opt /usr/local -writable -ls 2>/dev/null
```

### İşe Yaraması İçin Şartlar

```text
[+] Script root çalışıyor.
[+] Import edilen modül path’i kontrol edilebilir.
[+] Yazılabilir dizin sys.path içinde.
[+] Script çalıştırıldığında sahte modül yükleniyor.
```

---

## 3.9. PATH Hijacking

### Mantık

Root script tam path kullanmadan komut çağırır:

```bash
tar -xf backup.tar
```

Eğer PATH saldırgan tarafından etkilenebiliyorsa, sahte `tar` çalıştırılır.

### İşe Yaraması İçin Şartlar

```text
[+] Root script relative komut kullanıyor.
[+] PATH kontrol edilebilir veya writable dizin PATH içinde.
[+] sudo secure_path engellemiyor.
```

### Keşif

```bash
sudo -l
env
echo $PATH
grep -RniE "tar |cp |mv |bash |sh |python " /opt /usr/local 2>/dev/null
```

---

# 4. Saldırı Tabanlı Keşif Metodolojisi

Bu bölüm, sistemi “hangi exploit var?” diye değil, “hangi saldırı primitive’i çıkar?” diye taramayı öğretir.

---

## 4.1. İlk Aşama: Kimlik ve Yetki

```bash
id
groups
whoami
hostname
uname -a
cat /etc/os-release
```

Sorular:

```text
Ben kimim?
Hangi gruplardayım?
Sistem ne?
Kernel güncel mi?
Ek grup yetkim var mı?
```

Özel gruplar:

```text
sudo
adm
docker
lxd
disk
backup
systemd-journal
www-data
```

---

## 4.2. Sudo Yüzeyi

```bash
sudo -l
```

Çıktıyı şöyle oku:

```text
Komut root mu çalışıyor?
NOPASSWD var mı?
Wildcard var mı?
Argüman kontrolü bana mı ait?
Komut script mi binary mi?
Script hangi dosyaları işliyor?
```

Sudo çıktısı değerli olduğunda hemen exploit arama. Önce scripti oku.

---

## 4.3. Yazılabilir Alanlar

```bash
find / -writable -type d 2>/dev/null
find / -group "$(id -gn)" -writable -ls 2>/dev/null
find / -user root -writable -type f 2>/dev/null
```

Yazılabilir alanları sınıflandır:

```text
/tmp gibi normal alanlar
uygulama dizinleri
backup dizinleri
deploy dizinleri
log dizinleri
root-owned ama group-writable dizinler
```

En önemli bulgu tipi:

```text
root:<benim_grubum> ve group-writable dizin
```

Çünkü bu genellikle “root süreç + kullanıcı inputu” ilişkisinin ipucudur.

---

## 4.4. Özel Uygulama Dizinleri

```bash
ls -la /opt
ls -la /usr/local
ls -la /var/www
find /opt /usr/local /var/www -maxdepth 4 -ls 2>/dev/null
```

Aranacak isimler:

```text
backup
restore
deploy
client
sync
admin
worker
import
export
scheduler
```

---

## 4.5. Parser ve Extraction Arama

```bash
grep -RniE "extractall|tarfile|ZipFile|shutil.unpack_archive|tar -|unzip|pickle|yaml.load|json.load" /opt /usr/local /var/www 2>/dev/null
```

Bu arama şu soruya cevap verir:

```text
Sistem kullanıcı kontrollü bir formatı yüksek yetkili olarak parse ediyor mu?
```

Parserlar tehlikelidir çünkü veri formatı sadece içerik değil, davranış da taşıyabilir.

---

## 4.6. Root Process Analizi

```bash
ps auxww | grep '^root'
systemctl list-units --type=service --all
systemctl list-timers --all
```

Aranacak şeyler:

```text
custom servis
python/bash script
backup/restore/deploy job
web worker
queue processor
cron
```

Kısa süreli processleri yakalamak için:

```text
pspy benzeri process izleme araçları
```

---

# 5. Saldırıyı Değerlendirme: “Bu İşe Yarar mı?”

Bir yöntem bulduğunda şu matrisi kullan.

## 5.1. Root Context Var mı?

```text
Hayır → privesc olmayabilir.
Evet → devam et.
```

## 5.2. Input Kontrolü Var mı?

```text
Hayır → davranışı etkileyemeyebilirsin.
Evet → devam et.
```

## 5.3. Etki Türü Ne?

```text
Dosya okuma
Dosya yazma
Komut çalıştırma
Servis restart
Credential üretme
Parser tetikleme
```

En değerli etkiler:

```text
komut çalıştırma > dosya yazma > dosya okuma
```

## 5.4. Dosya Yazmayı Root’a Çevirebilir misin?

Evetse hedefler:

```text
/etc/sudoers.d
/root/.ssh/authorized_keys
/etc/cron.d
systemd service
root script overwrite
```

## 5.5. Koruma Var mı?

```text
path normalization
symlink rejection
hardlink rejection
filter="data"
secure_path
AppArmor/SELinux
fs.protected_symlinks
fs.protected_hardlinks
```

Koruma varsa:

```text
Koruma tam mı, kütüphane bypassı var mı, sürüm etkileniyor mu?
```

---

# 6. Başarısız Testleri Yorumlama

Başarısız testler doğru okunursa saldırıya yaklaştırır.

## 6.1. “Permission Denied”

Anlamları:

```text
Hedef dosyaya doğrudan erişimin yok.
Ama root process üzerinden dolaylı erişim hâlâ mümkün olabilir.
```

## 6.2. “Invalid Header”

Arşiv senaryosunda:

```text
Sistem dosyayı açmaya çalıştı ama format uygun değil.
```

Bu bazen iyi haberdir:

```text
Dosya takip edildi fakat parser beklediği formatı bulamadı.
```

## 6.3. “Would be extracted outside destination”

Anlamı:

```text
Path traversal koruması çalışıyor.
```

Bu durumda klasik `../` yerine daha karmaşık parser/link bypass veya farklı primitive aranır.

## 6.4. “SUID Bit Kayboldu”

Anlamı:

```text
Extractor izinleri normalize ediyor.
```

Bu durumda SUID payload yerine dosya yazdırma veya config değiştirme hedeflenir.

---

# 7. Bu Saldırı Sınıfında Genel Exploit Stratejileri

Bu bölüm kod vermeden, saldırı stratejilerini kavramsal açıklar.

## 7.1. Strateji A: Direkt Path Traversal

```text
Arşiv üyesi path dışına çıkar:
../../../../etc/sudoers.d/file
```

Çalışması için:

```text
Path normalize edilmiyor olmalı.
```

## 7.2. Strateji B: Symlink Pivot

```text
Arşiv önce symlink oluşturur:
escape -> /etc

Sonra:
escape/sudoers.d/file
```

Çalışması için:

```text
Extractor symlink’i takip etmeli.
```

## 7.3. Strateji C: Hardlink Pivot

```text
Hardlink bir hassas dosyaya bağlanır.
Sonra aynı isimle regular file yazılır.
```

Çalışması için:

```text
Extractor hardlink’i kabul etmeli ve hedef çözümlemesi hatalı olmalı.
```

## 7.4. Strateji D: Parser Bug / CVE Bypass

```text
Güvenli görünen filter veya validation mekanizması,
özel crafted inputla bypass edilir.
```

Çalışması için:

```text
Sürüm etkilenmeli.
Kod gerçekten ilgili API’yi kullanmalı.
Input attacker-controlled olmalı.
İşlem yüksek yetkili olmalı.
```

## 7.5. Strateji E: Output Dosyasını Yetki Dosyasına Çevirmek

Amaç:

```text
Dosya yazma primitive’ini root shell’e çevirmek.
```

Hedefler:

```text
sudoers.d
authorized_keys
cron.d
systemd service
```

---

# 8. Hangi Durumda Hangi Yöntem Denenir?

## 8.1. Root Script Tar Açıyorsa

Önce şunları kontrol et:

```text
Arşiv bana mı ait?
Extraction root mu?
Hangi filter kullanılıyor?
Python/tar/zip sürümü ne?
Symlink/hardlink davranışı ne?
Output dizini neresi?
```

Deneme sırası:

```text
1. Basit path traversal testi
2. Symlink testi
3. Hardlink testi
4. SUID permission testi
5. CVE/sürüm araştırması
6. Dosya yazdırma hedefi belirleme
```

## 8.2. Root Script Shell Komutu Çalıştırıyorsa

Kontrol:

```text
shell=True var mı?
Argüman quote ediliyor mu?
Komut tam path mi?
Wildcard var mı?
PATH kontrol edilebilir mi?
```

## 8.3. Root Script Dosya Kopyalıyorsa

Kontrol:

```text
source bana mı ait?
destination sabit mi?
symlink takip ediyor mu?
overwrite var mı?
dosya izinleri korunuyor mu?
```

## 8.4. Root Cron Yazılabilir Dizin İşliyorsa

Kontrol:

```text
Cron hangi dizinde çalışıyor?
Wildcard kullanıyor mu?
Script relative path kullanıyor mu?
Dosya isimleri komuta dahil ediliyor mu?
```

## 8.5. Web Uygulaması Root/Service Yetkisiyle Upload İşliyorsa

Kontrol:

```text
Upload edilen dosya nerede saklanıyor?
Arka planda kim işliyor?
Dosya tipi gerçekten doğrulanıyor mu?
Arşiv veya template açılıyor mu?
```

---

# 9. Saldırıyı Root’a Çevirmede Hedef Seçimi

## 9.1. `/etc/sudoers.d`

Avantaj:

```text
Tek satırla yetki verilebilir.
Komut çalıştırma kolaydır.
```

Risk:

```text
Syntax hatası sudo’yu bozabilir.
Dosya izinleri çok gevşekse sudo reddedebilir.
```

## 9.2. `/root/.ssh/authorized_keys`

Avantaj:

```text
Kalıcı root SSH erişimi sağlar.
```

Risk:

```text
SSH root login kapalı olabilir.
.ssh dizini yoksa izinler problem olabilir.
```

## 9.3. `/etc/cron.d`

Avantaj:

```text
Root komut çalıştırma sağlar.
```

Risk:

```text
Cron syntax hassastır.
Zamanlama beklemek gerekir.
```

## 9.4. Systemd Service

Avantaj:

```text
Root servis çalıştırabilir.
```

Risk:

```text
systemctl daemon-reload/restart gerekebilir.
Yazma yetse bile tetikleme yetmeyebilir.
```

## 9.5. Root Script Overwrite

Avantaj:

```text
Bir sonraki root çalıştırmada code execution.
```

Risk:

```text
Script tekrar çalışmayabilir.
Dosya bütünlüğü fark edilebilir.
```

---

# 10. Genel Raporlama Şablonu

Bir privesc saldırısını raporlarken şu yapı kullanılmalı:

## 10.1. Başlık

```text
Saldırı sınıfı + etki
Örnek: Root Tar Extraction Abuse ile sudoers.d Yazdırma
```

## 10.2. Ön Koşullar

```text
Elde edilen kullanıcı:
Sudo yetkisi:
Yazılabilir dizin:
Root çalışan süreç:
Kütüphane/sürüm:
```

## 10.3. Teknik Kök Neden

```text
Root process, düşük yetkili kullanıcının kontrol ettiği arşivi güvenli olmayan/bypass edilebilir şekilde işledi.
```

## 10.4. Saldırı Zinciri

```text
1. Kullanıcı backup dizinine arşiv koydu.
2. Root restore scripti çalıştırıldı.
3. Arşiv metadata’sı güven sınırını aştı.
4. /etc/sudoers.d altında dosya yazıldı.
5. sudo ile root shell alındı.
```

## 10.5. Etki

```text
Tam root yetkisi
Sistem dosyalarını değiştirme
Kalıcı erişim oluşturma potansiyeli
```

## 10.6. Düzeltme

```text
Kullanıcı kontrollü arşivleri root olarak açma.
Arşivleri sandbox içinde aç.
Symlink/hardlink reddet.
Kütüphane güncelle.
sudo kuralını daralt.
Dosya yazma hedeflerini allowlist ile sınırla.
```

---

# 11. Savunma Perspektifi

## 11.1. Güvenli Extraction İlkeleri

```text
Arşivi root olarak açma.
Önce düşük yetkili geçici kullanıcıyla aç.
Symlink ve hardlink kabul etme.
Pathleri realpath ile doğrula.
Allowlist kullan.
Extraction sonrası dosyaları tek tek taşı.
Kütüphane sürümünü güncel tut.
```

## 11.2. Güvenli Sudo Script İlkeleri

```text
NOPASSWD kullanımını azalt.
Wildcard argümanlardan kaçın.
Kullanıcı kontrollü dosyaları root contextinde işlememe.
Gerekirse dosya sahipliğini ve pathini doğrula.
Symlink takip etmeyen open yöntemleri kullan.
Scripti minimal yetkili kullanıcıyla çalıştır.
```

## 11.3. Dosya Bütünlüğü İzleme

İzlenmesi gereken dosyalar:

```text
/etc/sudoers
/etc/sudoers.d/*
/etc/cron.d/*
/root/.ssh/authorized_keys
/etc/systemd/system/*
```

---

# 12. Uygulamalı Düşünme Egzersizi

Bir sistemde şunu gördün:

```text
sudo -l:
(root) NOPASSWD: /usr/bin/python3 /opt/tools/import_backup.py *
```

Scriptte:

```python
with tarfile.open(user_backup) as tar:
    tar.extractall("/opt/app/imported", filter="data")
```

Düşünme sırası:

```text
1. user_backup pathini ben kontrol ediyor muyum?
2. Dosya hangi dizinden alınıyor?
3. O dizine yazabiliyor muyum?
4. Python sürümü nedir?
5. filter="data" kullanılan sürümde bilinen bypass var mı?
6. Symlink/hardlink kabul ediliyor mu?
7. Root olarak hangi dosyaya yazdırırsam yetki alırım?
8. /etc/sudoers.d hedeflenebilir mi?
9. Başarısız testler hangi savunmayı gösteriyor?
10. Daha güvenli exploit hedefi ne?
```

---

# 13. Kısa Özet

Bu saldırı bazlı genel yöntemin adı şu şekilde düşünülebilir:

```text
Privileged File Processing Abuse
```

Alt teknikler:

```text
Privileged archive extraction abuse
Sudo script input abuse
Symlink/hardlink/path traversal abuse
Parser filter bypass
Root file write primitive
Sudoers/cron/authorized_keys privilege conversion
```

Ana prensip:

```text
Root olan şeyi bul.
Root’un ne işlediğini bul.
O işlenen şeyde senin kontrolün var mı bul.
Bu kontrolü dosya yazma/komut çalıştırmaya çevir.
Dosya yazmayı root shell’e dönüştür.
```

En önemli zihinsel model:

```text
Exploit değil, primitive ara.
```

Primitive örnekleri:

```text
Dosya yazdırabiliyorum.
Dosya okutabiliyorum.
Komut argümanını etkileyebiliyorum.
Arşiv içeriğini belirleyebiliyorum.
Root’un çalıştıracağı path’i etkileyebiliyorum.
```

Primitive’i bulduktan sonra asıl iş:

```text
Bu primitive root etkisine nasıl çevrilir?
```

---

# 14. Sonuç

WingData benzeri saldırılarda başarı, tek bir komutla değil, doğru güven sınırını keşfetmekle gelir.

Bu sınıfta root’a giden yol genellikle şöyledir:

```text
Düşük yetki
  ↓
Yazılabilir input alanı
  ↓
Root tarafından işlenen parser/restore/deploy süreci
  ↓
Path/link/parser bypass
  ↓
Root dosya yazdırma
  ↓
sudoers/cron/ssh hedefi
  ↓
Root shell
```

Bu yaklaşımı öğrendiğinde, sadece CVE-2025-4517 özelinde değil; backup restore, CI/CD artifact, web upload, admin import/export, log arşivi ve sudo script tabanlı pek çok yetki yükseltme senaryosunda aynı mantığı uygulayabilirsin.

---

## Ek: Genel Kontrol Listesi

```text
[ ] sudo -l alındı mı?
[ ] root çalışan özel script var mı?
[ ] kullanıcı kontrollü dosya/input var mı?
[ ] root bu inputu parse ediyor mu?
[ ] archive extraction var mı?
[ ] symlink/hardlink/path traversal davranışı test edildi mi?
[ ] parser/kütüphane sürümü kontrol edildi mi?
[ ] dosya yazdırma primitive’i var mı?
[ ] bu primitive sudoers.d/cron/authorized_keys’e çevrilebilir mi?
[ ] başarısız testlerin anlamı çıkarıldı mı?
[ ] savunma mekanizması mı var, yoksa exploit koşulu mu eksik?
```
