# Yetki Yükseltme Zafiyetleri: Neden-Sonuç İlişkisi, Keşif Metodolojisi ve WingData Vaka Analizi

> **Kapsam:** Bu rapor, yetkili laboratuvar/CTF ortamında incelenen privilege escalation tekniklerini öğretici şekilde açıklar. Amaç, rastgele exploit çalıştırmaktan ziyade **hangi bulgunun ne anlama geldiğini**, **hangi koşullarda saldırıya dönüşebileceğini** ve **nasıl sistematik keşif yapılacağını** anlamaktır.

---

## İçindekiler

1. [Yönetici Özeti](#1-yönetici-özeti)
2. [Privilege Escalation Mantığı](#2-privilege-escalation-mantığı)
3. [Temel Neden-Sonuç Modeli](#3-temel-neden-sonuç-modeli)
4. [WingData Vaka Analizi](#4-wingdata-vaka-analizi)
5. [Bu Tarz Zafiyetler Hangi Durumlarda İşe Yarar?](#5-bu-tarz-zafiyetler-hangi-durumlarda-işe-yarar)
6. [Keşif Metodolojisi](#6-keşif-metodolojisi)
7. [Sudo Tabanlı Yetki Yükseltme](#7-sudo-tabanlı-yetki-yükseltme)
8. [Arşiv Açma ve Dosya Yazdırma Zafiyetleri](#8-arşiv-açma-ve-dosya-yazdırma-zafiyetleri)
9. [Symlink, Hardlink ve Path Traversal Mantığı](#9-symlink-hardlink-ve-path-traversal-mantığı)
10. [CVE-2025-4517 Mantığı](#10-cve-2025-4517-mantığı)
11. [Başarısız Testleri Okuma Sanatı](#11-başarısız-testleri-okuma-sanatı)
12. [Diğer Privesc Sınıfları](#12-diğer-privesc-sınıfları)
13. [Karar Ağacı](#13-karar-ağacı)
14. [Savunma ve Hardening Önerileri](#14-savunma-ve-hardening-önerileri)
15. [Kısa Kontrol Listeleri](#15-kısa-kontrol-listeleri)
16. [Sonuç](#16-sonuç)
17. [Kaynaklar](#17-kaynaklar)

---

# 1. Yönetici Özeti

Bu raporda incelenen senaryoda düşük yetkili `wacky` kullanıcısı, sistemde bulunan özel bir `sudo` kuralı sayesinde belirli bir Python yedek geri yükleme scriptini root olarak çalıştırabiliyordu:

```text
(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

İlk bakışta script güvenli görünüyordu; çünkü tar arşivini açarken Python `tarfile` modülünün güvenlik filtresini kullanıyordu:

```python
tar.extractall(path=staging_dir, filter="data")
```

Ancak ortamda Python `3.12.3` kullanıldığı için, `filter="data"` korumasını bypass eden `CVE-2025-4517` sınıfı bir zafiyet uygulanabilir hale geldi. Sonuçta saldırgan kontrollü tar arşivi, root yetkisiyle çalışan restore sürecine `/etc/sudoers.d` altında bir dosya yazdırdı ve `wacky` kullanıcısına parolasız tam sudo yetkisi tanımlandı.

Başarı zinciri:

```text
wacky shell
  ↓
sudo -l ile özel root çalıştırma kuralı
  ↓
root olarak çalışan Python tar extraction
  ↓
saldırgan kontrollü tar arşivi
  ↓
tarfile filter bypass
  ↓
/etc/sudoers.d içine NOPASSWD kuralı yazdırma
  ↓
sudo /bin/bash
  ↓
root shell
```

Bu saldırının ana dersi şudur:

> Exploit doğrudan root üretmedi. Root olarak çalışan meşru bir otomasyon sürecini, saldırgan kontrollü veriyle yanlış dosyaya yazmaya zorladı.

---

# 2. Privilege Escalation Mantığı

Privilege escalation, düşük yetkili bir erişimi daha yüksek yetkiye dönüştürme sürecidir. Linux sistemlerde tipik hedefler şunlardır:

```text
www-data  → user
service   → user
user      → root
container → host root
```

Yetki yükseltme genellikle tek bir “sihirli komut” değildir. Daha çok şu üç bileşenin birleşimidir:

```text
1. Yetkili bir işlem
2. Saldırganın kontrol ettiği bir girdi
3. Güven sınırının yanlış kurulması
```

Örneğin:

```text
Root olarak çalışan script
+ saldırganın yazabildiği tar dosyası
+ güvenli olmayan extraction mantığı
= root dosya yazdırma
```

Bu yüzden privesc düşünürken önce exploit aramak yerine şu sorular sorulmalıdır:

```text
Kim root olarak çalışıyor?
Ben bu sürece hangi veriyi verebiliyorum?
Bu veri root yetkisiyle nereye etki ediyor?
Bu etkiyi komut çalıştırmaya, dosya yazmaya veya kimlik bilgisi okumaya çevirebilir miyim?
```

---

# 3. Temel Neden-Sonuç Modeli

## 3.1. Privesc Bir Etki Zinciridir

Bir bulgu tek başına zafiyet olmayabilir. Önemli olan bulgunun zincirde nereye oturduğudur.

Örnek:

```text
/opt/backup_clients/backups dizinine yazabiliyorum
```

Bu tek başına root değildir.

Ama şu bilgiyle birleşirse anlam kazanır:

```text
root, bu dizindeki tar dosyasını sudo script ile açıyor
```

O zaman ilişki şu hale gelir:

```text
Yazılabilir backup dizini
  ↓
root tarafından işlenen dosya
  ↓
saldırgan kontrollü input
  ↓
root context içinde dosya sistemi etkisi
```

## 3.2. “Neden Çalıştı?” Sorusu

Bu vakada saldırı şu yüzden çalıştı:

| Neden | Sonuç |
|---|---|
| `wacky`, backup dizinine tar koyabiliyordu | Saldırgan kontrollü arşiv oluşturulabildi |
| `sudo` kuralı restore scriptini root çalıştırıyordu | Arşiv root yetkisiyle açıldı |
| Script `tarfile.extractall()` kullanıyordu | Tar metadata davranışı güvenlik açısından kritik hale geldi |
| Python sürümü zafiyetliydi | `filter="data"` bypass edilebildi |
| Hedef `/etc/sudoers.d` idi | Yetki kalıcı sudo kuralına çevrildi |
| `NOPASSWD: ALL` yazıldı | `sudo /bin/bash` root shell verdi |

## 3.3. “Neden Daha Önceki Testler Çalışmadı?”

Bazı klasik yöntemler başarısız oldu:

| Test | Sonuç | Anlamı |
|---|---|---|
| `../` path traversal | Engellendi | `filter="data"` temel path dışına çıkışı yakalıyor |
| Absolute symlink | Engellendi | `/etc/passwd` gibi doğrudan hedefler reddediliyor |
| SUID bitli dosya | SUID temizlendi | Tar filter privilege bitlerini güvenli hale getiriyor |
| Directory chmod 777 | Güvenli moda çekildi | Extraction izinleri normalize ediyor |
| FIFO backup | `os.path.isfile()` reddetti | Script FIFO’yu normal dosya saymadı |
| Symlink backup | Tar olarak açmaya çalıştı ama hata verdi | Symlink takip var, fakat hedef geçerli tar olmalıydı |

Bu başarısızlıklar boşa zaman değildir. Her biri koruma mekanizmasının sınırını anlamamızı sağladı.

---

# 4. WingData Vaka Analizi

## 4.1. Başlangıç Durumu

Elde edilen kullanıcı:

```text
wacky
```

Sistem bilgisi:

```text
Debian GNU/Linux 12
Linux kernel: 6.1.0-42-amd64
Python: 3.12.3
```

Kritik sudo çıktısı:

```text
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3
        /opt/backup_clients/restore_backup_clients.py *
```

Burada dikkat edilmesi gereken nokta şudur:

```text
wacky herhangi bir Python kodunu root çalıştıramıyor.
Sadece belirli scripti root çalıştırabiliyor.
```

Yani şu çalışmadı:

```bash
sudo /usr/local/bin/python3 -c 'import os; os.system("id")'
```

Çünkü sudo kuralı doğrudan Python interpreter kullanımına değil, belirli script path’ine izin veriyordu.

## 4.2. Restore Scriptinin Davranışı

Scriptin önemli bölümü:

```python
BACKUP_BASE_DIR = "/opt/backup_clients/backups"
STAGING_BASE = "/opt/backup_clients/restored_backups"

backup_path = os.path.join(BACKUP_BASE_DIR, args.backup)
staging_dir = os.path.join(STAGING_BASE, args.restore_dir)

with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

Scriptte üç önemli güvenlik kontrolü vardı:

```text
1. Backup adı backup_<id>.tar formatında olmalı.
2. Restore dizini restore_ ile başlamalı.
3. Tar extraction filter="data" ile yapılmalı.
```

Bu kontroller scripti klasik saldırılara karşı güçlü hale getiriyordu.

## 4.3. Erişim Kontrolleri

Dosya izinleri:

```text
/opt/backup_clients                 root:wacky 750
/opt/backup_clients/backups         root:wacky 770
/opt/backup_clients/restored_backups root:wacky 750
restore_backup_clients.py           root:wacky 750
```

Buradan çıkan sonuç:

```text
wacky backup dizinine yazabilir.
wacky restore output dizinine doğrudan yazamaz.
root script restore output dizinine yazabilir.
```

Bu çok önemlidir. Çünkü saldırgan çıktı dizinine doğrudan müdahale edemese bile, root scriptin yazacağı input’u kontrol edebiliyor.

## 4.4. Başarılı Exploit Etkisi

Saldırının sonunda şu test başarılı oldu:

```bash
sudo -n id
```

Çıktı:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Ardından:

```bash
sudo /bin/bash
```

ile root shell elde edildi.



---

# 5. Bu Tarz Zafiyetler Hangi Durumlarda İşe Yarar?

Bu sınıftaki saldırılar her sistemde çalışmaz. Belirli koşulların aynı anda bulunması gerekir.

## 5.1. Gerekli Ön Koşullar

Aşağıdaki koşullar birlikte varsa risk yüksektir:

```text
1. Düşük yetkili kullanıcı bir arşiv, yedek veya input dosyası oluşturabiliyor.
2. Daha yüksek yetkili bir süreç bu dosyayı işliyor.
3. İşleme sırasında dosya sistemi üzerinde yazma etkisi oluşuyor.
4. Extraction/parsing işlemi symlink, hardlink, path veya metadata gibi tehlikeli tar özelliklerini işliyor.
5. Hedefte yazılabilecek dosya root yetkisine etki ediyor.
```

Örnek riskli senaryolar:

```text
Backup restore scriptleri
Log import/export scriptleri
CI/CD artifact extraction işleri
Docker build context veya deploy paketleri
Kullanıcı upload edilen .tar/.zip dosyaları
Admin panel üzerinden alınan yedekleri geri yükleme
Cron ile işlenen arşiv dosyaları
```

## 5.2. Ne Zaman İşe Yaramaz?

Şu koşullarda çalışması beklenmez:

```text
Extraction düşük yetkili izole kullanıcıyla yapılıyorsa
Tar üyeleri tek tek güvenli doğrulanıyorsa
Symlink/hardlink tamamen reddediliyorsa
Extraction chroot/container/sandbox içinde yapılıyorsa
Çıktı dizini dışında dosya yazma mümkün değilse
Python/CVE sürümü etkilenmiyorsa
Root tarafından işlenen input saldırgan kontrolünde değilse
```

## 5.3. Kritik Ayrım

Bir exploitin işe yaraması için zafiyetli kütüphane tek başına yetmez.

```text
Zafiyetli Python var
```

Bu tek başına root değildir.

Şuna ihtiyaç vardır:

```text
Zafiyetli Python + root olarak çalışan extraction + saldırgan kontrollü tar
```

---

# 6. Keşif Metodolojisi

Yetki yükseltme keşfinde amaç rastgele exploit denemek değil, sistemdeki güven sınırlarını haritalamaktır.

## 6.1. İlk 10 Dakika Planı

```bash
id
hostname
uname -a
cat /etc/os-release
sudo -l
```

Sorular:

```text
Hangi kullanıcıdayım?
Hangi gruplardayım?
Sudo yetkim var mı?
Sistem güncel mi?
Özel uygulama veya servis var mı?
```

## 6.2. Dosya Sistemi Haritalama

```bash
find / -perm -4000 -type f -ls 2>/dev/null
getcap -r / 2>/dev/null
find / -writable -type d 2>/dev/null
find / -user root -writable -type f 2>/dev/null
```

Bu komutlar şu sınıfları bulmaya yarar:

```text
SUID binary
Linux capabilities
Yazılabilir dizin
Root-owned ama yazılabilir dosya
```

## 6.3. Grup Bazlı Arama

```bash
find / -group "$(id -gn)" -ls 2>/dev/null
find / -group "$(id -gn)" -writable -ls 2>/dev/null
```

Bu önemlidir çünkü bazen root dosyaları kullanıcı grubuna açılmıştır:

```text
root:wacky 770 backups
root:devops 775 deploy
root:backup 770 archives
```

Bu tür dizinler genellikle intended privesc yüzeyidir.

## 6.4. Process ve Servis Analizi

```bash
ps auxww
systemctl list-units --type=service --state=running
systemctl list-timers --all
```

Aranacak şeyler:

```text
root çalışan custom process
python/bash/sh scriptleri
backup/restore/deploy isimli servisler
root cron işleri
özel binary veya servis kullanıcıları
```

## 6.5. Cron ve Timer Analizi

```bash
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly 2>/dev/null
grep -RniE "backup|restore|tar|python|sh|bash" /etc/cron* /var/spool/cron 2>/dev/null
```

Kısa süreli processleri kaçırıyorsan:

```text
pspy gibi canlı process izleme aracı kullanılır.
```

## 6.6. Log ve İpucu Arama

```bash
find /var/log -type f -readable -ls 2>/dev/null
grep -RniE "password|passwd|sudo|backup|restore|token|key|admin" /var/log 2>/dev/null
```

Loglar şu bilgileri verebilir:

```text
Çalışan cron komutları
Hatalı script pathleri
Kullanılan parola veya token izleri
Admin panel aktiviteleri
Backup/restore denemeleri
```

---

# 7. Sudo Tabanlı Yetki Yükseltme

## 7.1. Sudo Kuralını Doğru Okumak

Örnek:

```text
(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

Bu şu anlama gelir:

```text
Kullanıcı sadece bu komut şablonunu root olarak çalıştırabilir.
```

Yanlış çıkarım:

```text
Python root çalışıyor, o zaman istediğim Python kodunu çalıştırırım.
```

Doğru çıkarım:

```text
Bu scriptin argümanları ve işlediği dosyalar üzerinden root etkisi aranmalı.
```

## 7.2. Sudo Script İnceleme Soruları

Bir sudo script gördüğünde şunları sor:

```text
Script hangi dosyaları okuyor?
Hangi dosyaları yazıyor?
Bu dosyaların pathleri kullanıcıdan mı geliyor?
Script shell=True kullanıyor mu?
Subprocess çağrılarında kullanıcı inputu var mı?
Python import path hijack mümkün mü?
Environment değişkenleri korunuyor mu?
Wildcard argüman genişlemesi var mı?
Symlink takip ediyor mu?
Temporary file güvenli mi?
```

## 7.3. Sudo Scriptte Tehlikeli Kalıplar

Riskli örnekler:

```python
os.system(user_input)
subprocess.run(user_input, shell=True)
open(user_controlled_path, "w")
shutil.copy(user_file, root_path)
tar.extractall(user_controlled_archive)
zip.extractall(user_controlled_archive)
yaml.load(user_input)
pickle.load(user_input)
```

## 7.4. Güvenli Görünüp Riskli Olan Durum

Şu kod güvenli gibi görünebilir:

```python
tar.extractall(path=staging_dir, filter="data")
```

Ancak kütüphane seviyesinde bir bypass varsa, bu satır root context içinde tehlikeli hale gelir.

Ders:

```text
Kodu sadece niyetiyle değil, kullandığı kütüphane sürümüyle birlikte değerlendir.
```

---

# 8. Arşiv Açma ve Dosya Yazdırma Zafiyetleri

Arşiv dosyaları sadece dosya içermez; metadata da içerir:

```text
Dosya adı
Dosya yolu
Sahiplik bilgisi
İzinler
Symlink hedefi
Hardlink hedefi
Dosya tipi
Zaman bilgisi
```

Bu metadata güvenli doğrulanmazsa, extraction işlemi dosya yazdırma primitive’ine dönüşebilir.

## 8.1. Klasik Zip Slip / Tar Slip Mantığı

Zararlı arşiv üyesi:

```text
../../../../etc/passwd
```

Eğer extraction bunu normalize etmeden yazarsa:

```text
hedef_dizin/../../../../etc/passwd
```

sonuçta hedef dizin dışına çıkılır.

## 8.2. Symlink Tabanlı Yazdırma

Arşiv şu üyeleri içerir:

```text
link -> /etc
link/sudoers.d/file
```

Eğer extractor symlink’i takip ederse, ikinci dosya aslında `/etc/sudoers.d/file` olur.

## 8.3. Hardlink Tabanlı Yazdırma

Hardlink daha ince bir primitive sağlar:

```text
hardlink_member -> escape/sudoers.d/file
same_member regular file content
```

Eğer extractor hardlink hedefini yanlış çözerse, içerik hedef dosyaya yazılabilir.

## 8.4. Yetki Yükseltmeye Çevrilebilecek Hedefler

Saldırganın root olarak dosya yazdırabildiği durumlarda hedefler:

| Hedef | Etki |
|---|---|
| `/etc/sudoers.d/<file>` | Kullanıcıya sudo yetkisi verme |
| `/root/.ssh/authorized_keys` | Root SSH erişimi |
| `/etc/cron.d/<file>` | Root cron komutu çalıştırma |
| `/etc/systemd/system/<service>` | Servis tanımlama |
| `/etc/ld.so.preload` | Dinamik linker hijack |
| `/etc/passwd` | Kullanıcı/parola manipülasyonu |
| Root tarafından çalışan script | Komut yürütme |

En güvenli ve kontrollü hedef genellikle `/etc/sudoers.d/<file>` olur. Ana `/etc/sudoers` dosyasını bozmak sistemi kilitleyebilir.

---

# 9. Symlink, Hardlink ve Path Traversal Mantığı

## 9.1. Symlink Nedir?

Symlink, başka bir dosya veya dizine işaret eden özel dosyadır.

```text
escape -> /etc
```

Bu durumda:

```text
escape/sudoers.d/file
```

aslında:

```text
/etc/sudoers.d/file
```

anlamına gelebilir.

## 9.2. Hardlink Nedir?

Hardlink, aynı inode’a ikinci bir dosya adı verir. Yani iki farklı path aynı gerçek dosyayı gösterebilir.

Bu yüzden hardlink tehlikelidir:

```text
A dosyası hedef dosyanın inode’una bağlıysa,
A’ya yazmak hedef dosyaya yazmak anlamına gelebilir.
```

## 9.3. Path Traversal Nedir?

Path traversal, `../` kullanarak beklenen dizin dışına çıkmaktır.

```text
restore_dir/../../../../etc/sudoers.d/file
```

Güvenli extraction bunun normalize edilmiş mutlak yolunu kontrol etmelidir.

## 9.4. Neden Birlikte Güçlüler?

Tek başına `../` engellenebilir.
Tek başına absolute symlink engellenebilir.
Tek başına hardlink engellenebilir.

Ama karmaşık zincirlerde path resolution bug’ları ortaya çıkabilir:

```text
uzun path
+ nested symlink
+ relative traversal
+ hardlink
+ aynı path’e regular file yazma
```

Bu tarz kombinasyonlar filtrelerin beklemediği durumları tetikleyebilir.

---

# 10. CVE-2025-4517 Mantığı

## 10.1. Zafiyetin Özü

CVE-2025-4517, Python `tarfile` modülünde extraction filter mekanizmasının belirli crafted tar arşivleriyle bypass edilmesine yol açan bir sınıftır. Etkilenen kullanım kalıbı:

```python
tar.extractall(path=destination, filter="data")
```

veya:

```python
tar.extract(path=destination, filter="tar")
```

gibi filtreli extraction işlemleridir.

## 10.2. Neden Beklenmedik?

`filter="data"` normalde güvenlik için kullanılır. Ama burada sorun şu:

```text
Güvenlik filtresi var diye her crafted path/link kombinasyonu güvenli varsayılıyor.
```

Zafiyet, filtreleme ile gerçek dosya sistemi path çözümleme davranışı arasındaki farktan doğar.

## 10.3. Bizim Senaryoda Neden Kritik Oldu?

Şu üç koşul birleşti:

```text
1. Python 3.12.3 kullanılıyordu.
2. Script root olarak çalışıyordu.
3. Tar arşivi saldırgan kontrolündeydi.
```

Bu yüzden kütüphane seviyesindeki bypass, sistem seviyesinde root dosya yazdırmaya dönüştü.

## 10.4. Exploitin Kavramsal Aşamaları

Detaylı exploit kodundan bağımsız olarak mantık şuydu:

```text
1. Tar içinde çok uzun ve iç içe dizin yapıları oluştur.
2. Symlink zinciriyle path çözümlemeyi karmaşık hale getir.
3. Bir kaçış symlink’i ile /etc alanına ulaş.
4. Hardlink ile /etc/sudoers.d içindeki dosyaya referans üret.
5. Aynı tar üyesine regular file içeriği yazarak hedef dosyayı değiştir.
```

## 10.5. Yazılan İçerik

Hedef dosyaya yazılan mantıksal sudo kuralı:

```text
wacky ALL=(ALL) NOPASSWD: ALL
```

Bu kuralın etkisi:

```text
wacky kullanıcısı herhangi bir komutu herhangi bir kullanıcı olarak şifresiz çalıştırabilir.
```

Bu nedenle:

```bash
sudo /bin/bash
```

root shell verdi.

---

# 11. Başarısız Testleri Okuma Sanatı

Privesc sırasında başarısız testler, doğru yolu bulmanın parçasıdır.

## 11.1. SUID Dosyası Neden Root Olmadı?

Denendi:

```text
SUID bitli rootshell tar içine koyuldu.
Root script bunu extract etti.
```

Sonuç:

```text
-rwxr-xr-x root root rootshell
```

SUID kayboldu.

Anlamı:

```text
filter="data" veya extraction mantığı privilege bitlerini temizledi.
```

## 11.2. Path Traversal Neden Olmadı?

Denendi:

```text
../../tmp/pwned_by_tar
```

Hata:

```text
would be extracted outside the destination
```

Anlamı:

```text
Python tarfile filter path dışına çıkışı algıladı.
```

## 11.3. Absolute Symlink Neden Olmadı?

Denendi:

```text
passwd_link -> /etc/passwd
```

Hata:

```text
is a link to an absolute path
```

Anlamı:

```text
Doğrudan absolute symlink engelleniyor.
```

## 11.4. Symlink Backup Neden Root Vermedi?

Denendi:

```text
backup_2000.tar -> /etc/passwd
```

Sonuç:

```text
invalid header
```

Anlamı:

```text
Script symlink’i takip ediyor ama hedef tar olmadığı için parse edemiyor.
```

Bu bulgu yine değerlidir. Çünkü şunu gösterir:

```text
os.path.isfile() symlink’i kabul ediyor.
```

Fakat exploit için hedefin geçerli tar olması gerekiyordu.

---

# 12. Diğer Privesc Sınıfları

Bu vaka tarfile tabanlıydı. Ancak privesc keşfi her zaman çok yönlü yapılmalıdır.

## 12.1. SUID Binary

Arama:

```bash
find / -perm -4000 -type f -ls 2>/dev/null
```

Riskli durum:

```text
Custom SUID binary
GTFOBins’de bilinen binary
PATH hijack yapan SUID program
Config dosyası yazılabilir SUID servis
```

## 12.2. Linux Capabilities

Arama:

```bash
getcap -r / 2>/dev/null
```

Riskli capability örnekleri:

```text
cap_setuid+ep
cap_dac_read_search+ep
cap_dac_override+ep
cap_sys_admin+ep
```

## 12.3. Cron Jobs

Arama:

```bash
cat /etc/crontab
ls -la /etc/cron.d
grep -RniE "backup|sh|python|tar" /etc/cron* 2>/dev/null
```

Riskli durum:

```text
Root cron, yazılabilir script çalıştırıyor.
Root cron, wildcard ile dosya işliyor.
Root cron, saldırganın yazabildiği dizinde çalışıyor.
```

## 12.4. Writable Service Files

Arama:

```bash
find /etc/systemd /lib/systemd /usr/lib/systemd -writable -ls 2>/dev/null
```

Riskli durum:

```text
Servis dosyası yazılabilir
EnvironmentFile yazılabilir
ExecStart scripti yazılabilir
WorkingDirectory yazılabilir ve relative path kullanılıyor
```

## 12.5. PATH Hijacking

Riskli script:

```bash
tar -xf backup.tar
```

Eğer script `tar` için tam path kullanmıyorsa ve PATH kontrol edilebiliyorsa:

```text
Sahte tar binary/script çalıştırılabilir.
```

Ama sudo `secure_path` aktifse bu genellikle zorlaşır.

## 12.6. Python Import Hijacking

Riskli script:

```python
import backup_utils
```

Eğer Python script root çalışırken import path saldırganın yazabildiği dizini içeriyorsa, sahte modül ile code execution alınabilir.

Kontrol:

```bash
python3 -c 'import sys; print(sys.path)'
```

## 12.7. Credentials ve Password Reuse

Bu vakada `wacky` SSH erişimi şu zincirle geldi:

```text
Wing FTP kullanıcı XML dosyası
  ↓
wacky hash
  ↓
sha256(password + "WingFTP") formatı
  ↓
hashcat ile parola
  ↓
aynı parola Linux wacky hesabında da geçerli
```

Ders:

```text
Uygulama kullanıcısı ile sistem kullanıcısı aynı isimdeyse parola reuse mutlaka test edilir.
```

---

# 13. Karar Ağacı

Aşağıdaki karar ağacı, privesc araştırırken izlenebilir.

```text
Başla
 |
 |-- sudo -l var mı?
 |     |
 |     |-- Evet
 |     |    |
 |     |    |-- Direkt shell veren binary mi?
 |     |    |-- Script mi?
 |     |         |
 |     |         |-- Kullanıcı inputu alıyor mu?
 |     |         |-- Dosya okuyor/yazıyor mu?
 |     |         |-- Archive extraction var mı?
 |     |         |-- Subprocess/shell var mı?
 |     |         |-- Import hijack mümkün mü?
 |     |
 |     |-- Hayır
 |
 |-- SUID/capability var mı?
 |     |
 |     |-- Custom veya GTFOBins uyumlu mu?
 |
 |-- Yazılabilir root-owned dosya/dizin var mı?
 |     |
 |     |-- Root process burayı kullanıyor mu?
 |
 |-- Cron/timer var mı?
 |     |
 |     |-- Yazılabilir script veya dizin var mı?
 |
 |-- Servisler var mı?
 |     |
 |     |-- Config/EnvironmentFile/ExecStart yazılabilir mi?
 |
 |-- Log/credential/ipucu var mı?
 |
 |-- Kernel/local exploit mantıklı mı?
       |
       |-- Sürüm etkileniyor mu?
       |-- Mitigation var mı?
       |-- Stabil mi?
```

---

# 14. Savunma ve Hardening Önerileri

## 14.1. Sudo Kuralını Daralt

Riskli:

```text
(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

Daha güvenli:

```text
Sadece root tarafından kontrol edilen input dosyalarını işle.
Kullanıcı kontrollü backup dizinini root scriptle doğrudan işleme.
NOPASSWD kullanımını minimuma indir.
```

## 14.2. Arşivleri İzole Aç

Güvenli yaklaşım:

```text
1. Arşivi düşük yetkili geçici kullanıcıyla aç.
2. Sandbox/chroot/container kullan.
3. Çıkan dosyaları tek tek doğrula.
4. Sonra gerekli dosyaları allowlist ile hedefe taşı.
```

## 14.3. Symlink/Hardlink Reddet

Tar extraction öncesi üyeleri kontrol et:

```python
for member in tar.getmembers():
    if member.issym() or member.islnk():
        raise Exception("Links are not allowed")
```

## 14.4. Gerçek Path Kontrolü Yap

Her üye için:

```text
resolved_path = realpath(destination/member.name)
resolved_path destination altında mı?
```

Ama bu kontrol symlink/hardlink yarışları ve kütüphane bug’ları nedeniyle tek başına yeterli olmayabilir.

## 14.5. Kütüphane Güncelle

Python runtime güncel tutulmalı. CVE-2025-4517 gibi kütüphane seviyesindeki zafiyetler, güvenli görünen kodu riskli hale getirebilir.

## 14.6. Sudoers.d Dosyalarını Denetle

```bash
ls -la /etc/sudoers.d
sudo -l -U <user>
visudo -c
```

Şüpheli dosyalar:

```text
world-writable
beklenmeyen NOPASSWD
README dosyasının policy dosyasına dönüşmesi
```

## 14.7. Audit Önerileri

İzlenmesi gereken olaylar:

```text
/etc/sudoers
/etc/sudoers.d/*
/etc/cron.d/*
/root/.ssh/authorized_keys
systemd service değişiklikleri
root çalışan extraction scriptleri
```

---

# 15. Kısa Kontrol Listeleri

## 15.1. Sudo Script Checklist

```text
[ ] sudo -l çıktısı alındı mı?
[ ] Komut wildcard içeriyor mu?
[ ] Script okunabiliyor mu?
[ ] Kullanıcı kontrollü argüman var mı?
[ ] Kullanıcı kontrollü dosya var mı?
[ ] Root olarak dosya yazıyor mu?
[ ] Archive extraction var mı?
[ ] shell=True var mı?
[ ] Import hijack mümkün mü?
[ ] Symlink takip ediyor mu?
[ ] Temp file güvenli mi?
[ ] Sürüm/CVE kontrol edildi mi?
```

## 15.2. Archive Extraction Checklist

```text
[ ] Tar/zip kullanıcıdan mı geliyor?
[ ] Extraction kim olarak çalışıyor?
[ ] Destination neresi?
[ ] Symlink/hardlink kabul ediliyor mu?
[ ] ../ path engelleniyor mu?
[ ] Absolute path engelleniyor mu?
[ ] Permission/SUID normalize ediliyor mu?
[ ] Kütüphane sürümü etkileniyor mu?
[ ] Çıktı dizini dışına yazma mümkün mü?
```

## 15.3. Dosya Yazdırma Primitive Checklist

Eğer root olarak dosya yazdırabiliyorsan:

```text
[ ] /etc/sudoers.d/<file> yazılabilir mi?
[ ] /root/.ssh/authorized_keys yazılabilir mi?
[ ] /etc/cron.d/<file> yazılabilir mi?
[ ] Root çalışan script overwrite edilebilir mi?
[ ] Dosya içeriği tam kontrol ediliyor mu?
[ ] Dosya izinleri hedef servis tarafından kabul ediliyor mu?
[ ] Syntax hatası sistemi kilitler mi?
```

## 15.4. Başarısızlık Analizi Checklist

```text
[ ] Hata path validation mı?
[ ] Hata permission mı?
[ ] Hata dosya tipi mi?
[ ] Hata parser mı?
[ ] Hata syntax mı?
[ ] Hata exploit koşulu eksikliği mi?
[ ] Başarısız test hangi savunmayı doğruladı?
```

---

# 16. Sonuç

Bu vaka, privilege escalation’ın yalnızca exploit çalıştırmak olmadığını çok iyi gösterir. Başarı şu zincirin kurulmasıyla geldi:

```text
Sudo kuralı
+ root çalışan restore script
+ kullanıcı kontrollü tar arşivi
+ Python tarfile filter bypass
+ /etc/sudoers.d dosya yazdırma
= root shell
```

En kritik dersler:

```text
1. Privesc, bulgular arasındaki ilişkiyi okumaktır.
2. Başarısız testler koruma sınırlarını gösterir.
3. Root olarak çalışan her parser, saldırgan kontrollü input alıyorsa risklidir.
4. Güvenli görünen kütüphane parametreleri bile sürüm/CVE bağlamında doğrulanmalıdır.
5. Dosya yazdırma primitive’i root’a çevrilebiliyorsa, en temiz hedeflerden biri /etc/sudoers.d olur.
```

Bu tarz zafiyetleri keşfetmek için bakış açısı şudur:

```text
“Bu sistemde kim benden daha yetkili çalışıyor ve ben onun davranışını hangi dosya/input ile etkileyebiliyorum?”
```

Bu soruya sistematik cevap verebildiğinde, karmaşık privilege escalation zincirleri daha görünür hale gelir.

---

# 17. Kaynaklar

- NVD, CVE-2025-4517 açıklaması: https://nvd.nist.gov/vuln/detail/CVE-2025-4517
- Python `tarfile` dokümantasyonu: https://docs.python.org/3/library/tarfile.html
- CPython public issue: Multiple tarfile extraction filter bypasses: https://github.com/python/cpython/issues/135034
- Red Hat advisory notu: RHSA-2025:10484 / CVE-2025-4517 arbitrary writes via tarfile realpath overflow: https://access.redhat.com/errata/RHSA-2025%3A10484

---

## Ek: Vaka İçin Kısa Zaman Çizelgesi

```text
1. Wing FTP RCE ile servis kullanıcısı elde edildi.
2. Uygulama kullanıcı XML dosyalarından wacky hash’i çıkarıldı.
3. Hash formatının sha256(password + "WingFTP") olduğu anlaşıldı.
4. wacky parolası kırıldı ve SSH ile kullanıcı erişimi alındı.
5. sudo -l ile restore script yetkisi bulundu.
6. Klasik tar saldırıları test edildi ve çoğu engellendi.
7. Python 3.12.3 ve tarfile filter="data" doğrulandı.
8. CVE-2025-4517 sınıfı bypass uygulandı.
9. /etc/sudoers.d altında NOPASSWD kuralı yazdırıldı.
10. sudo /bin/bash ile root shell alındı.
```
