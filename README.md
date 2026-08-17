# ex3501-root

Zyxel **EX3501-T1** (Türk Telekom HGW) fabrika resetinden sonra LAN üzerinden root + SSH geri kazandıran tek Python scripti.

Yalnızca **kendi cihazınızda** kullanın.

## Ne yapar

1. FTP kapalıysa web/DAL ile FTP’yi LAN-only açar
2. `/data/zcfg_config.json` indirir, yedekler, düzenler, yükler
3. Root hesabını açar, verdiğiniz şifrenin SHA-512 crypt hash’ini yazar
4. LAN’da SSH/Telnet portlarını açar (`X_TTNET.UserInterface.LocalAccess`)
5. ISP TR-069/CWMP’yi kapatır (ACS inform / STUN)
6. ACS/TR111 Management static route’unu `Enable=false` yapar (diğer route’lara dokunmaz)
7. WAN RemoteAccess’i kapalı tutar; yönetim servisleri `LAN_ONLY`
8. Reboot eder (`POST /cgi-bin/Reboot`)
9. `/var/passwd` ile root shell = `/bin/sh`
10. Overlay’e `/etc/init.d/S99zyroot` kurar (reboot sonrası shell + dropbear)

## Gereksinimler

- Aynı LAN’da bir makine
- Python 3.8+
- Cihaz: EX3501-T1, Türk Telekom firmware (başka modele güvenmeyin)
- Cihazın **admin** şifresi (etiket / web paneli)

```bash
pip install pycryptodome     # web login + otomatik reboot + FTP’yi DAL ile açma
pip install paramiko         # isteğe bağlı: SSH doğrulama
```

`pycryptodome` yoksa script FTP’yi DAL ile açamaz ve reboot’u sizden (güç kes-tak) ister.

## Kullanım

```bash
python3 ex3501-root.py
```

Sorar: router IP (varsayılan `192.168.1.1`), admin kullanıcı/şifre, yeni root şifresi (boş = rastgele üretir).

```bash
python3 ex3501-root.py \
  --ip 192.168.1.1 \
  --admin-user admin \
  --admin-pass '...' \
  --root-pass '...' \
  --yes
```

Ortam değişkenleri: `EX3501_IP`, `EX3501_ADMIN_USER`, `EX3501_ADMIN_PASS`, `EX3501_ROOT_PASS`.

Hash öz-testi (cihaza dokunmaz):

```bash
python3 ex3501-root.py --self-test
```

Bittikten sonra:

```bash
ssh root@192.168.1.1
```

Script yeniden çalıştırılabilir: config zaten istenen durumdaysa reboot atlar.

## Giriş sonrası

| | |
|---|---|
| SSH | `root` + seçtiğiniz şifre |
| Telnet | aynı |
| Web / FTP | sizin admin hesabınız (değişmez) |

Yedek: çalıştırıldığı dizinde `zcfg_config.backup-*.json` ve cihazda `/data/zcfg_config.backup-*.json`. Bu yedek **tüm modem config’ini** içerir — paylaşma.

## Bilinçli sınırlar

- Fabrika reset → her şey (CWMP, TR111, root) stok haline döner; scripti tekrar çalıştırın.
- Fiber OLT/OMCI hattı scriptin işi değil; santral cihazı yine provision/reset edebilir.
- Firmware büyük değişirse DAL/LocalAccess davranışı sapabilir.
- `clinicLAN` / `homeLAN` gibi sizin eklediğiniz route’lara dokunulmaz; yalnızca `TR111` veya ACS IP’sini (`ManagementServer.X_TTNET_ACS_IP`) kapsayan static route kapatılır.

## Güvenlik notu

Script kişisel kimlik bilgisi taşımaz. Paylaşırken **sadece** `ex3501-root.py` + bu README gitsin. Config yedeklerini, session loglarını, eski notları koymayın.
