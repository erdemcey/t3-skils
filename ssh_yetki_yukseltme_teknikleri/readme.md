# SSH Kullanılarak Yetki Yükseltme Teknikleri

## Genel Pentest / CTF Odaklı Teknik Rapor

> Bu rapor aktif bir makineye özel çözüm paylaşmadan, SSH altyapısında görülen yanlış yapılandırmalar üzerinden yetki yükseltmenin nasıl keşfedildiğini ve mantığını anlatır.  
> Amaç, gerçek pentest veya CTF senaryosunda **“SSH tarafında nereye bakmalıyım?”** sorusuna sistematik cevap vermektir.

---

## İçindekiler

- [1. SSH Neden Yetki Yükseltmede Önemlidir?](#1-ssh-neden-yetki-yükseltmede-önemlidir)
- [2. İlk Bakılması Gereken SSH Dosyaları](#2-ilk-bakılması-gereken-ssh-dosyaları)
- [3. SSH Yetki Yükseltmede Zihin Modeli](#3-ssh-yetki-yükseltmede-zihin-modeli)
- [4. `PermitRootLogin` Değerleri ve Yanlış Yorumlama](#4-permitrootlogin-değerleri-ve-yanlış-yorumlama)
- [5. Teknik 1 — Okunabilir Private SSH Key ile Kullanıcı Değiştirme](#5-teknik-1--okunabilir-private-ssh-key-ile-kullanıcı-değiştirme)
- [6. Teknik 2 — `authorized_keys` Yanlış İzinleri](#6-teknik-2--authorized_keys-yanlış-izinleri)
- [7. Teknik 3 — SSH Certificate Authentication Abuse](#7-teknik-3--ssh-certificate-authentication-abuse)
- [8. Teknik 4 — `AuthorizedPrincipalsFile` Yanlış Yapılandırması](#8-teknik-4--authorizedprincipalsfile-yanlış-yapılandırması)
- [9. Teknik 5 — SSH Agent Forwarding Abuse](#9-teknik-5--ssh-agent-forwarding-abuse)
- [10. Teknik 6 — SSH Config İçindeki `Match` Block Hataları](#10-teknik-6--ssh-config-içindeki-match-block-hataları)
- [11. Teknik 7 — `ForceCommand` Bypass](#11-teknik-7--forcecommand-bypass)
- [12. Teknik 8 — `ChrootDirectory` Yanlış Sahiplikleri](#12-teknik-8--chrootdirectory-yanlış-sahiplikleri)
- [13. Teknik 9 — Deploy Key ve Service Account Abuse](#13-teknik-9--deploy-key-ve-service-account-abuse)
- [14. Teknik 10 — SSH Keylerin Backup İçinde Kalması](#14-teknik-10--ssh-keylerin-backup-içinde-kalması)
- [15. Teknik 11 — Writable SSH Config ile Dolaylı Abuse](#15-teknik-11--writable-ssh-config-ile-dolaylı-abuse)
- [16. Teknik 12 — `ControlMaster` / `ControlPath` Socket Abuse](#16-teknik-12--controlmaster--controlpath-socket-abuse)
- [17. Teknik 13 — SSH ile Localhost’a Kullanıcı Geçişi](#17-teknik-13--ssh-ile-localhosta-kullanıcı-geçişi)
- [18. Teknik 14 — Sudo ile SSH Bağlantılı Yetki Yükseltme](#18-teknik-14--sudo-ile-ssh-bağlantılı-yetki-yükseltme)
- [19. Teknik 15 — SSHD Include Dosyalarında Grup Bazlı Açıklar](#19-teknik-15--sshd-include-dosyalarında-grup-bazlı-açıklar)
- [20. SSH Yetki Yükseltme İçin Pratik Kontrol Listesi](#20-ssh-yetki-yükseltme-için-pratik-kontrol-listesi)
- [21. Hangi Bulgular Gerçekten Kritik?](#21-hangi-bulgular-gerçekten-kritik)
- [22. SSH Certificate Abuse Zinciri: Genel Senaryo](#22-ssh-certificate-abuse-zinciri-genel-senaryo)
- [23. Savunma / Hardening Önerileri](#23-savunma--hardening-önerileri)
- [24. CTF İçin Pratik SSH Privesc Akış Şeması](#24-ctf-için-pratik-ssh-privesc-akış-şeması)
- [25. En Önemli Ders](#25-en-önemli-ders)

---

# 1. SSH Neden Yetki Yükseltmede Önemlidir?

SSH çoğu Linux sisteminde yalnızca **uzaktan bağlanma servisi** gibi görülür. Ancak pratikte SSH çok daha kritik bir güvenlik bileşenidir.

SSH şu alanları yönetir:

```text
Kullanıcı kimlik doğrulaması
Anahtar tabanlı giriş
Sertifika tabanlı giriş
Root login politikası
Yetkili kullanıcı listesi
Komut kısıtlamaları
Deploy/service hesapları
Bastion/jump host geçişleri
Agent forwarding
Otomasyon hesapları
```

Bu yüzden SSH yanlış yapılandırılmışsa, sistemde doğrudan root shell vermese bile şu sonuçlara yol açabilir:

```text
Başka kullanıcıya geçiş
Service account ele geçirme
Deploy hesabından root seviyesine yükselme
SSH certificate abuse
Writable authorized_keys ile kalıcı erişim
Root tarafından güvenilen CA key’in kötüye kullanılması
Agent socket üzerinden kimlik taklidi
Backup/config dosyalarından key veya parola bulma
```

SSH tabanlı yetki yükseltmede temel amaç şudur:

```text
Sistemin güvendiği SSH kimliklerini, anahtarlarını, sertifikalarını veya config ilişkilerini bulmak.
```

---

# 2. İlk Bakılması Gereken SSH Dosyaları

Bir Linux makinede SSH ile ilgili temel dosyalar şunlardır:

```text
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/*.conf
/etc/ssh/ssh_config
/etc/ssh/ssh_config.d/*.conf

~/.ssh/
~/.ssh/authorized_keys
~/.ssh/id_rsa
~/.ssh/id_ed25519
~/.ssh/config
~/.ssh/known_hosts

/root/.ssh/
/home/*/.ssh/
```

Modern sistemlerde ana SSH daemon config çoğu zaman tek dosyada değil, include dizinindedir:

```text
/etc/ssh/sshd_config.d/
```

Bu yüzden yalnızca şuna bakmak eksik kalır:

```bash
cat /etc/ssh/sshd_config
```

Daha doğru yaklaşım:

```bash
ls -la /etc/ssh/
ls -la /etc/ssh/sshd_config.d/

grep -RniE 'Include|Match|PasswordAuthentication|PubkeyAuthentication|PermitRootLogin|TrustedUserCAKeys|AuthorizedKeysFile|AuthorizedPrincipalsFile|AllowUsers|AllowGroups|DenyUsers|DenyGroups|ForceCommand|ChrootDirectory' /etc/ssh 2>/dev/null
```

Bu komutlar bize şunları gösterir:

```text
SSH hangi config dosyalarını okuyor?
Root login nasıl ayarlanmış?
Password auth açık mı?
Public key auth açık mı?
Sertifika tabanlı auth kullanılıyor mu?
Özel grup/kullanıcı kuralları var mı?
```

---

# 3. SSH Yetki Yükseltmede Zihin Modeli

SSH üzerinden yetki yükseltme ararken şu sorular sorulur:

```text
1. SSH hangi kimlik doğrulama yöntemlerini kabul ediyor?
2. Root için parola mı yasak, yoksa tüm giriş mi yasak?
3. Public key authentication açık mı?
4. Sertifika tabanlı authentication var mı?
5. TrustedUserCAKeys tanımlı mı?
6. CA private key bir grup/kullanıcı tarafından okunabiliyor mu?
7. AuthorizedKeysFile veya AuthorizedPrincipalsFile writable mı?
8. Kullanıcının .ssh dizini yanlış izinli mi?
9. Agent forwarding açık mı?
10. Deploy/service hesaplarının keyleri veya configleri okunabiliyor mu?
11. SSH config içinde Match block ile özel bir kullanıcı/grup ayrıcalığı var mı?
12. ForceCommand veya internal-sftp kısıtı bypass edilebilir mi?
```

Bu sorular seni komut ezberinden çıkarır.

Asıl mesele şudur:

```text
Sistem hangi kullanıcıya, hangi key’e, hangi certificate’e veya hangi gruba güveniyor?
Ben bu güven ilişkisinin bir parçasını okuyabiliyor, yazabiliyor veya taklit edebiliyor muyum?
```

---

# 4. `PermitRootLogin` Değerleri ve Yanlış Yorumlama

SSH privesc sırasında en çok yanlış yorumlanan ayarlardan biri:

```text
PermitRootLogin
```

Önemli değerler:

```text
PermitRootLogin yes
PermitRootLogin no
PermitRootLogin prohibit-password
PermitRootLogin forced-commands-only
```

## 4.1 `PermitRootLogin yes`

Root ile doğrudan girişe izin verir.

```text
Root parola veya key ile login olabilir.
```

Risk:

```text
Root password veya root private key ele geçirilirse doğrudan root shell alınır.
```

## 4.2 `PermitRootLogin no`

Root ile SSH girişi tamamen kapalıdır.

```text
Root parolası doğru olsa bile SSH girişine izin verilmez.
Root key doğru olsa bile SSH girişine izin verilmez.
```

Bu en sıkı seçenektir.

## 4.3 `PermitRootLogin prohibit-password`

Bu ayar çok kritiktir.

Anlamı:

```text
Root parola ile giriş yapamaz.
Ama public key / certificate ile giriş yapabilir.
```

Bu ayar şunu söylemez:

```text
Root SSH tamamen kapalı.
```

Asıl anlamı şudur:

```text
Root için password auth kapalı, key/certificate auth mümkün.
```

Bu nedenle sistemde şunlar varsa ciddi risk doğar:

```text
TrustedUserCAKeys tanımlıysa
Root için geçerli certificate üretilebiliyorsa
Root authorized_keys içine key eklenebiliyorsa
Root private key bulunabiliyorsa
```

---

# 5. Teknik 1 — Okunabilir Private SSH Key ile Kullanıcı Değiştirme

## Mantık

Bir kullanıcının private key dosyası okunabiliyorsa, o kullanıcı olarak SSH girişi denenebilir.

Örnek dosyalar:

```text
/home/user/.ssh/id_rsa
/home/user/.ssh/id_ed25519
/root/.ssh/id_rsa
/opt/app/.ssh/deploy_key
/var/backups/id_rsa
```

Arama:

```bash
find / -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*key*' \) 2>/dev/null
```

İçerik kontrolü:

```bash
head -n 2 /path/to/key
```

Beklenen private key formatları:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
```

## Neden Yetki Yükseltir?

Çünkü mevcut kullanıcıdan daha yetkili bir kullanıcının SSH private key’i okunabiliyorsa:

```text
mevcut_user -> daha_yetkili_user
```

geçişi yapılabilir.

## Dikkat Edilecekler

Key dosyasının izinleri uygun değilse SSH kabul etmeyebilir:

```bash
chmod 600 keyfile
```

Bağlanma örneği:

```bash
ssh -i keyfile targetuser@localhost
```

Gerçek pentestte dış bağlantıyı artırmadan önce local doğrulama yapılabilir:

```bash
ssh -i keyfile targetuser@localhost 'id; hostname'
```

---

# 6. Teknik 2 — `authorized_keys` Yanlış İzinleri

## Mantık

Bir kullanıcının `authorized_keys` dosyasına yazabiliyorsan, kendi public key’ini ekleyip o kullanıcı olarak SSH girişi alabilirsin.

Kontrol:

```bash
ls -ld /home/user/.ssh
ls -l /home/user/.ssh/authorized_keys
```

Riskli izin örnekleri:

```text
/home/user/.ssh world-writable
authorized_keys group-writable
authorized_keys mevcut kullanıcı tarafından yazılabilir
```

Arama:

```bash
find /home -path '*/.ssh/authorized_keys' -type f -writable 2>/dev/null
find /root -path '*/.ssh/authorized_keys' -type f -writable 2>/dev/null
```

## Neden Yetki Yükseltir?

Çünkü SSH server, `authorized_keys` içindeki public keyleri güvenilir kabul eder.

Eğer saldırgan kendi public keyini hedef kullanıcının dosyasına eklerse, hedef kullanıcı olarak giriş yapabilir.

## Savunma

Doğru izinler:

```text
~/.ssh                 700
~/.ssh/authorized_keys 600
owner                  ilgili kullanıcı
```

---

# 7. Teknik 3 — SSH Certificate Authentication Abuse

Bu en güçlü ve en ilginç SSH privesc tekniklerinden biridir.

## 7.1 SSH Certificate Authentication Nedir?

Normal SSH key auth şu şekildedir:

```text
Kullanıcı public keyi -> authorized_keys içinde varsa giriş yapılır
```

SSH certificate auth ise farklı çalışır:

```text
Bir CA public key sshd tarafından trusted kabul edilir.
Bu CA tarafından imzalanmış kullanıcı sertifikaları geçerli sayılır.
```

sshd config içinde şöyle bir satır varsa:

```text
TrustedUserCAKeys /path/to/ca.pub
```

bu şu anlama gelir:

```text
Bu CA tarafından imzalanan SSH kullanıcı sertifikalarına güven.
```

## 7.2 Kritik Yanlış Yapılandırma

Eğer şunlar birlikte varsa:

```text
TrustedUserCAKeys /path/to/ca.pub
CA private key okunabilir
PermitRootLogin prohibit-password veya yes
```

o zaman saldırgan kendi public keyini CA private key ile imzalayıp root veya başka kullanıcı adına certificate üretebilir.

## 7.3 Nasıl Fark Edilir?

SSH config içinde ara:

```bash
grep -RniE 'TrustedUserCAKeys|AuthorizedPrincipalsFile|Certificate|CA' /etc/ssh 2>/dev/null
```

CA public key path’i bulunur:

```text
TrustedUserCAKeys /opt/company/ssh/ca.pub
```

Sonra aynı dizinde veya yakınında private key aranır:

```bash
ls -la /opt/company/ssh/
```

Riskli durum:

```text
-rw-r----- root deployers ca
-rw-r--r-- root root      ca.pub
```

Eğer mevcut kullanıcı `deployers` grubundaysa ve `ca` dosyasını okuyabiliyorsa, bu kritik bir bulgudur.

Kontrol:

```bash
id
groups
head -n 2 /path/to/ca
```

Private key görünümü:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
```

## 7.4 Root Principal ile Sertifika Üretme Mantığı

Önce geçici bir key pair oluşturulur:

```bash
ssh-keygen -t ed25519 -f /tmp/temp_root_key -N '' -q
```

Sonra public key, trusted CA private key ile imzalanır:

```bash
ssh-keygen -s /path/to/ca \
-I test-root \
-n root \
-V +1h \
/tmp/temp_root_key.pub
```

Parametreler:

```text
-s  -> imzalayan CA private key
-I  -> certificate identity
-n  -> geçerli principal yani hedef kullanıcı adı
-V  -> geçerlilik süresi
```

Oluşan certificate:

```text
/tmp/temp_root_key-cert.pub
```

Kontrol:

```bash
ssh-keygen -L -f /tmp/temp_root_key-cert.pub
```

Aranacak kısım:

```text
Principals:
        root
```

Sonra root olarak bağlanılır:

```bash
ssh -i /tmp/temp_root_key \
-o CertificateFile=/tmp/temp_root_key-cert.pub \
root@localhost
```

## 7.5 Neden Çalışır?

Çünkü sshd şunu söyler:

```text
Bu CA’ya güveniyorum.
Bu CA root için bir certificate imzalamış.
O zaman bu key root olarak kabul edilebilir.
```

Bu, klasik private key çalmaktan daha güçlüdür. Çünkü CA private key ile birden fazla kullanıcı için certificate üretilebilir.

## 7.6 Savunma

CA private key kesinlikle şunlara açık olmamalı:

```text
Uygulama kullanıcıları
Deploy grupları
Web servis kullanıcıları
Normal kullanıcılar
```

Doğru yaklaşım:

```text
CA private key offline tutulmalı
Sunucuda sadece ca.pub bulunmalı
CA private key root dışında okunamamalı
Certificate principal kısıtları kullanılmalı
Kısa süreli sertifika politikaları uygulanmalı
Audit log tutulmalı
```

---

# 8. Teknik 4 — `AuthorizedPrincipalsFile` Yanlış Yapılandırması

## Mantık

SSH certificate auth kullanıldığında, certificate içindeki principal değerinin hangi kullanıcı için geçerli olduğu kontrol edilir.

Config örneği:

```text
AuthorizedPrincipalsFile .ssh/authorized_principals
```

veya:

```text
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

Bu dosyada kullanıcının kabul ettiği principal isimleri bulunur.

Örnek:

```text
root
admin
deploy
```

## Risk

Eğer bu dosya yazılabiliyorsa, saldırgan kendi certificate principal’ını hedef kullanıcıya ekleyebilir.

Arama:

```bash
grep -RniE 'AuthorizedPrincipalsFile' /etc/ssh 2>/dev/null
```

Dosya izinlerini kontrol:

```bash
ls -l /etc/ssh/auth_principals/
find /etc/ssh -type f -name '*principal*' -ls 2>/dev/null
```

## Neden Yetki Yükseltir?

Çünkü certificate zaten trusted CA ile imzalanmışsa, principal dosyasındaki eşleşme girişe izin verebilir.

Örneğin saldırgan certificate içinde principal olarak `deploy` kullanıyorsa ve root için authorized principals dosyasına `deploy` yazabiliyorsa, root login mümkün olabilir.

---

# 9. Teknik 5 — SSH Agent Forwarding Abuse

## SSH Agent Nedir?

SSH agent, private key’i diskte tekrar tekrar kullanmadan authentication yapmayı sağlar.

Kullanıcı login olduğunda ortam değişkeni oluşabilir:

```text
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNN
```

Kontrol:

```bash
echo $SSH_AUTH_SOCK
ls -la "$SSH_AUTH_SOCK"
```

## Risk

Eğer yüksek yetkili bir kullanıcı, özellikle root veya admin, agent forwarding ile sisteme bağlanmışsa ve başka kullanıcı bu socket’e erişebiliyorsa, o kullanıcının agent’ı üzerinden authentication denenebilir.

Arama:

```bash
find /tmp -type s -name 'agent.*' 2>/dev/null
find / -type s -name 'agent.*' 2>/dev/null
```

Süreçlerde kontrol:

```bash
ps aux | grep ssh-agent
```

## Neden Yetki Yükseltir?

Private key dosyasını çalmazsın. Ama agent üzerinden imzalama yaptırırsın.

Bu şu anlama gelir:

```text
Key sende değil
ama key sahibi adına authentication isteği imzalatabiliyorsun
```

## Savunma

```text
Agent forwarding kapatılmalı
ForwardAgent no
Root/admin kullanıcılar production hostlara agent forwarding ile bağlanmamalı
/tmp socket izinleri sıkı olmalı
```

Client config:

```text
Host *
    ForwardAgent no
```

---

# 10. Teknik 6 — SSH Config İçindeki `Match` Block Hataları

`Match` blokları belirli kullanıcı, grup veya IP için özel SSH politikası tanımlar.

Örnek:

```text
Match Group deployers
    PasswordAuthentication yes
    PermitTTY yes
    ForceCommand /usr/local/bin/deploy-shell
```

Arama:

```bash
grep -RniE '^Match|ForceCommand|AllowTcpForwarding|PermitTTY|X11Forwarding|PermitTunnel|ChrootDirectory|AllowGroups|AllowUsers' /etc/ssh 2>/dev/null
```

## Riskli Durumlar

```text
Bir gruba gereğinden fazla SSH yetkisi verilmiş olabilir
ForceCommand bypass edilebilir olabilir
Chroot yanlış sahiplikte olabilir
SFTP-only kullanıcı shell alabilir
AllowTcpForwarding açık kalmış olabilir
```

## Neden Yetki Yükseltir?

Match block bazen güvenlik kısıtı sanılır ama yanlış yazıldığında ayrıcalık kapısı olur.

Örneğin:

```text
Match Group deployers
    PermitTTY yes
    AllowTcpForwarding yes
```

Deploy hesabı üzerinden internal servislere erişim veya port forward mümkün olabilir.

---

# 11. Teknik 7 — `ForceCommand` Bypass

## ForceCommand Nedir?

SSH config veya authorized_keys içinde kullanıcı login olduğunda normal shell yerine zorunlu komut çalıştırılabilir.

Örnek:

```text
ForceCommand /usr/local/bin/restricted-deploy
```

veya authorized_keys içinde:

```text
command="/usr/local/bin/backup.sh" ssh-rsa AAAA...
```

## Risk

Zorunlu komut şu durumlarda bypass edilebilir:

```text
Komut shell injection içeriyorsa
Komut environment variable kabul ediyorsa
Komut PATH hijack’e açıksa
Komut writable dizinden binary çalıştırıyorsa
Komut editor/pager açıyorsa
Komut rsync/scp/git gibi shell escape destekleyen aracı çağırıyorsa
```

Kontrol:

```bash
grep -RniE 'ForceCommand|command=' /etc/ssh /home/*/.ssh 2>/dev/null
```

Komut dosyasının izinlerine bak:

```bash
ls -l /usr/local/bin/restricted-deploy
file /usr/local/bin/restricted-deploy
```

## Neden Yetki Yükseltir?

Eğer ForceCommand root veya daha yetkili kullanıcı bağlamında çalışıyorsa, onun çağırdığı komut zincirinde zayıflık varsa shell alınabilir.

---

# 12. Teknik 8 — `ChrootDirectory` Yanlış Sahiplikleri

SFTP-only kullanıcılar için sık görülür:

```text
ChrootDirectory /srv/sftp/%u
ForceCommand internal-sftp
```

## Kritik Kural

OpenSSH chroot dizini root tarafından sahiplenilmeli ve kullanıcı tarafından yazılamamalıdır.

Doğru:

```text
drwxr-xr-x root root /srv/sftp/user
```

Riskli:

```text
drwxrwxrwx user user /srv/sftp/user
drwxrwx--- user group /srv/sftp/user
```

Kontrol:

```bash
grep -RniE 'ChrootDirectory|internal-sftp' /etc/ssh 2>/dev/null
ls -ld /srv/sftp /srv/sftp/*
```

## Neden Önemlidir?

Yanlış chroot sahiplikleri bazen SSH girişini engeller, bazen de SFTP izolasyonunun hatalı kurulmasına yol açar. Direkt root privesc olmayabilir ama kullanıcı izolasyonunu kırabilir.

---

# 13. Teknik 9 — Deploy Key ve Service Account Abuse

Gerçek sistemlerde en çok karşılaşılanlardan biri budur.

## Tipik Dosyalar

```text
/opt/app/.ssh/id_rsa
/opt/deploy/.ssh/id_ed25519
/var/lib/jenkins/.ssh/id_rsa
/home/git/.ssh/id_rsa
/root/.ssh/deploy_key
```

## Arama

```bash
find /opt /var /home -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*deploy*key*' -o -name '*.pem' \) 2>/dev/null
```

## Neden Yetki Yükseltir?

Deploy key genelde şu erişimlere sahiptir:

```text
Git server
CI/CD server
Production server
Backup server
Root-owned deployment script
SSH bastion
```

Bir deploy hesabına geçiş bazen doğrudan root vermez ama şu zinciri açar:

```text
web user -> deploy user -> deploy script -> sudo/root
```

---

# 14. Teknik 10 — SSH Keylerin Backup İçinde Kalması

Private keyler çoğu zaman yanlışlıkla backup dosyalarında kalır.

Aranacak dosyalar:

```text
*.zip
*.tar
*.tar.gz
*.bak
*.old
*.backup
*.pem
```

Komut:

```bash
find / -type f \( -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.bak' -o -name '*.old' -o -name '*.backup' -o -name '*.pem' \) 2>/dev/null
```

İçerik araması:

```bash
grep -RniE 'BEGIN OPENSSH PRIVATE KEY|BEGIN RSA PRIVATE KEY|PRIVATE KEY' /opt /var /home 2>/dev/null
```

## Gerçek Pentest Notu

Her şeyi indirmek yerine önce içeride grep ile bakmak daha temizdir:

```bash
grep -RniE 'PRIVATE KEY|password|ssh-rsa|ssh-ed25519' /opt 2>/dev/null
```

---

# 15. Teknik 11 — Writable SSH Config ile Dolaylı Abuse

SSH client config de önemlidir:

```text
~/.ssh/config
/etc/ssh/ssh_config
/etc/ssh/ssh_config.d/*.conf
```

Riskli direktifler:

```text
ProxyCommand
LocalCommand
IdentityFile
CertificateFile
User
HostName
Include
ForwardAgent
```

Arama:

```bash
grep -RniE 'ProxyCommand|LocalCommand|IdentityFile|CertificateFile|ForwardAgent|Include' /etc/ssh /home/*/.ssh 2>/dev/null
```

## Neden Yetki Yükseltir?

Eğer yüksek yetkili kullanıcı belirli bir hosta SSH yaparken writable config dosyasını okuyorsa, saldırgan config manipülasyonu ile komut çalıştırma zinciri kurabilir.

Özellikle riskli direktifler:

```text
LocalCommand
ProxyCommand
Include writable_path
```

Bu daha çok post-exploitation / lateral movement tarafında görülür.

---

# 16. Teknik 12 — `ControlMaster` / `ControlPath` Socket Abuse

SSH multiplexing kullanılıyorsa socket dosyaları oluşabilir.

Config örneği:

```text
ControlMaster auto
ControlPath ~/.ssh/control-%r@%h:%p
ControlPersist yes
```

Arama:

```bash
find /tmp /home -type s 2>/dev/null
find /home -name 'control-*' 2>/dev/null
```

## Risk

Eğer başka kullanıcıya ait master SSH connection socket’i erişilebilir durumdaysa, aynı bağlantıyı kullanarak komut çalıştırmak mümkün olabilir.

Savunma:

```text
ControlPath dosyaları kullanıcıya özel ve 700 dizinde tutulmalı
/tmp gibi ortak dizinler kullanılmamalı
```

---

# 17. Teknik 13 — SSH ile Localhost’a Kullanıcı Geçişi

Bazı CTF/pentest senaryolarında doğrudan `su` çalışmaz ama SSH ile localhost’a geçiş yapılabilir.

Örnek:

```bash
ssh targetuser@localhost
```

Neden işe yarayabilir?

```text
PAM kuralları farklı olabilir
su kısıtlı olabilir
SSH key/certificate auth açık olabilir
Shell environment farklı olabilir
Match block kullanıcıya özel izin verebilir
```

Kontrol:

```bash
ssh -v targetuser@localhost
```

Verbose modda şunlar incelenir:

```text
Accepted publickey
Accepted password
Offering public key
Offering certificate
Authentications that can continue
```

---

# 18. Teknik 14 — Sudo ile SSH Bağlantılı Yetki Yükseltme

Doğrudan SSH değil ama SSH araçları sudo ile birleşince risk doğurur.

Kontrol:

```bash
sudo -l
```

Riskli izinler:

```text
sudo ssh
sudo ssh-keygen
sudo scp
sudo sftp
sudo rsync
sudo git
sudo tar
sudo vi
sudo less
```

Örnek risk:

```text
Kullanıcı sudo ile ssh-keygen çalıştırabiliyorsa,
root-owned authorized_keys veya certificate dosyaları manipüle edilebilir.
```

Sudo + SSH genelde şu mantıkla incelenir:

```text
Komut root olarak dosya okuyabiliyor mu?
Komut root olarak dosya yazabiliyor mu?
Komut shell escape veriyor mu?
Komut environment/PATH etkileniyor mu?
```

---

# 19. Teknik 15 — SSHD Include Dosyalarında Grup Bazlı Açıklar

Modern Ubuntu/Debian sistemlerde cloud-init, uygulama veya otomasyon araçları özel SSH config bırakabilir:

```text
/etc/ssh/sshd_config.d/50-cloud-init.conf
/etc/ssh/sshd_config.d/60-app.conf
/etc/ssh/sshd_config.d/company.conf
```

Kontrol:

```bash
ls -la /etc/ssh/sshd_config.d/
cat /etc/ssh/sshd_config
grep -RniE '.' /etc/ssh/sshd_config.d/ 2>/dev/null
```

Özellikle dosya izinleri:

```bash
ls -la /etc/ssh/sshd_config.d/
```

Riskli örnek:

```text
-rw-r----- root deployers 60-company.conf
```

Bu şunu gösterir:

```text
deployers grubu SSH config okuyabiliyor.
```

Okuyabilmek tek başına privesc değildir. Ama config içinde şunlar varsa yol açar:

```text
TrustedUserCAKeys
AuthorizedPrincipalsFile
PermitRootLogin prohibit-password
Match Group deployers
ForceCommand
```

---

# 20. SSH Yetki Yükseltme İçin Pratik Kontrol Listesi

Bir kullanıcı shell’i aldığında şu sırayla ilerlenebilir.

## 20.1 Kullanıcı ve Grup Bilgisi

```bash
whoami
id
groups
hostname
```

## 20.2 SSH Config İncelemesi

```bash
ls -la /etc/ssh/
ls -la /etc/ssh/sshd_config.d/

grep -RniE 'PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|TrustedUserCAKeys|AuthorizedPrincipalsFile|AuthorizedKeysFile|Match|ForceCommand|AllowGroups|AllowUsers|ChrootDirectory' /etc/ssh 2>/dev/null
```

## 20.3 SSH CA Kontrolü

```bash
grep -RniE 'TrustedUserCAKeys' /etc/ssh 2>/dev/null
```

Bulunan path için:

```bash
ls -la /path/to/ca_directory
```

Private key var mı?

```bash
head -n 2 /path/to/possible_ca
```

## 20.4 Kullanıcı SSH Dizini

```bash
ls -la ~/.ssh 2>/dev/null
cat ~/.ssh/config 2>/dev/null
cat ~/.ssh/authorized_keys 2>/dev/null
```

## 20.5 Tüm Home Dizinleri

```bash
find /home -maxdepth 3 -name '.ssh' -type d -ls 2>/dev/null
find /home -path '*/.ssh/*' -type f -ls 2>/dev/null
```

## 20.6 Private Key Araması

```bash
find / -type f \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*key*' \) 2>/dev/null
```

## 20.7 Agent Socket Araması

```bash
echo $SSH_AUTH_SOCK
find /tmp -type s -name 'agent.*' 2>/dev/null
```

## 20.8 Sudo İzinleri

```bash
sudo -l
```

---

# 21. Hangi Bulgular Gerçekten Kritik?

SSH tarafında her bulgu eşit değildir.

## Düşük / Bilgi Seviyesi

```text
PubkeyAuthentication yes
PasswordAuthentication yes
SSH version bilgisi
Kullanıcı .ssh dizini var
```

## Orta Seviye

```text
Başka kullanıcıların authorized_keys dosyalarını okuyabilmek
SSH config içinde özel Match block görmek
Deploy kullanıcılarına ait notlar/configler görmek
```

## Yüksek Seviye

```text
Başka kullanıcı private keyini okumak
Authorized_keys dosyasına yazabilmek
Writable AuthorizedPrincipalsFile
SSH agent socket erişimi
```

## Kritik Seviye

```text
TrustedUserCAKeys tanımlı ve CA private key okunabilir
Root authorized_keys yazılabilir
Root private key okunabilir
PermitRootLogin key/cert auth için açık ve key/cert üretilebiliyor
```

---

# 22. SSH Certificate Abuse Zinciri: Genel Senaryo

Bu bölüm aktif makineye özel değil, genel bir yanlış yapılandırma zinciridir.

## Senaryo

Bir sistemde şu yapılandırma olsun:

```text
TrustedUserCAKeys /opt/company/ssh/ca.pub
PermitRootLogin prohibit-password
```

Ve dosya izinleri şöyle olsun:

```text
-rw-r----- root deployers /opt/company/ssh/ca
-rw-r--r-- root root      /opt/company/ssh/ca.pub
```

Kullanıcı:

```text
svc-deploy
```

grupları:

```text
svc-deploy deployers
```

## Sonuç

`svc-deploy`, CA private key’i okuyabilir. Bu nedenle kendi public key’ini `root` principal’ı ile imzalayabilir.

Zincir:

```text
svc-deploy shell
        ↓
deployers grubunun okuyabildiği CA private key
        ↓
root principal için SSH certificate üretimi
        ↓
sshd bu certificate’i ca.pub üzerinden trusted kabul eder
        ↓
root@localhost SSH login
```

## Güvenlik Hatası

Asıl hata root login ayarı değildir. Asıl hata:

```text
CA private key’in normal bir grup tarafından okunabilir olmasıdır.
```

Çünkü trusted CA private key, pratikte **hangi kullanıcı adına SSH certificate üretileceğini belirleme yetkisi** verir.

---

# 23. Savunma / Hardening Önerileri

## 23.1 Root Login

En güvenlisi:

```text
PermitRootLogin no
```

Eğer root için certificate gerekiyorsa:

```text
Çok sınırlı principal
Kısa süreli certificate
Ayrı audit
Offline CA
```

## 23.2 CA Private Key

```text
Sunucuda private CA key tutulmamalı
Sadece ca.pub sunucuda olmalı
CA private key root dışında okunamamalı
Deploy grupları okuyamamalı
```

Doğru izin:

```text
-rw------- root root ca
-rw-r--r-- root root ca.pub
```

Daha iyi:

```text
Sunucuda ca private key hiç bulunmamalı.
```

## 23.3 Authorized Keys

```text
~/.ssh                 700
~/.ssh/authorized_keys 600
```

Kullanıcı home dizini de world-writable olmamalı:

```bash
chmod go-w /home/user
```

## 23.4 Agent Forwarding

Server tarafı:

```text
AllowAgentForwarding no
```

Client tarafı:

```text
ForwardAgent no
```

Özellikle production sistemlerde root/admin kullanıcılar agent forwarding kullanmamalı.

## 23.5 SSH Config Audit

Düzenli olarak şu ayarlar kontrol edilmeli:

```text
PermitRootLogin
TrustedUserCAKeys
AuthorizedPrincipalsFile
AuthorizedKeysFile
Match
ForceCommand
ChrootDirectory
AllowGroups
AllowUsers
PasswordAuthentication
PubkeyAuthentication
AllowAgentForwarding
AllowTcpForwarding
PermitTunnel
```

---

# 24. CTF İçin Pratik SSH Privesc Akış Şeması

```text
Shell aldın
   ↓
whoami; id; groups
   ↓
/etc/ssh ve /etc/ssh/sshd_config.d incele
   ↓
TrustedUserCAKeys var mı?
   ↓
Varsa CA private key okunabiliyor mu?
   ↓
Okunuyorsa certificate abuse
   ↓
Yoksa authorized_keys / private key / agent / sudo kontrol et
   ↓
Deploy veya service account dosyalarını incele
   ↓
Root’a giden güven ilişkisini bul
```

---

# 25. En Önemli Ders

SSH privesc çoğu zaman “exploit çalıştırmak” değildir.

Asıl mesele şudur:

```text
Sistem hangi kimliklere güveniyor?
Bu güveni hangi dosya veya key temsil ediyor?
Ben bu dosyayı okuyabiliyor veya değiştirebiliyor muyum?
Bu güven ilişkisini daha yetkili bir kullanıcı adına kullanabilir miyim?
```

Özellikle SSH certificate yapılarında:

```text
ca.pub = sshd’nin güvendiği otorite
ca     = o otoritenin imza yetkisi
```

Eğer CA private key ele geçerse, bu basit bir key sızıntısı değil, kimlik üretme yetkisinin ele geçirilmesidir.

Bu yüzden SSH tabanlı yetki yükseltmede en kritik cümle şudur:

```text
Private key sadece giriş anahtarı değildir; bazen güven zincirinin köküdür.
```
