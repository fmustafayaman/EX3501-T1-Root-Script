#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ex3501-root.py — Zyxel EX3501-T1 (Turk Telekom HGW) fabrika reseti sonrasi
root erisimini bastan sonda geri kazandiran tek script.

Akis (otomatik, asamalar durum kontrolu ile atlanabilir — yeniden calistirilabilir):
  [0] SHA-512 crypt oz-testi (yanlis hash yazmamak icin)
  [1] FTP ile /data/zcfg_config.json indir + yedekle (yerel + cihaz uzerine)
  [2] Config duzenle:
        - X_ZYXEL_LoginCfg root hesabi: Enabled=true + shadow hash (sectiginiz sifre)
        - X_TTNET.Users.User: root Enable=true, Allowed_LA_Protocols +SSH,TELNET
        - X_TTNET.UserInterface.LocalAccess: Port +22,23 / Protocol +SSH,TELNET
        - RemoteManagement servisleri LAN_ONLY; WAN RemoteAccess kapali
        - ISP TR-069/CWMP kapat (EnableCWMP/PeriodicInform/STUN=false)
        - ACS/TR111 Management static route Disable
  [3] FTP ile config yukle (DELE+STOR) + round-trip dogrula (hata olursa yedegi geri yazar)
  [4] Reboot: POST /cgi-bin/Reboot (GUI'nin gercek endpoint'i) — pycryptodome yoksa
      elle fiş cekme talimati; portlarin donmesini bekler
  [5] FTP ile /var/passwd: root shell -> /bin/sh (telnetin tam shell icin)
  [6] Telnet root ile /etc/init.d/S99zyroot kalicilik script'i kur
      (her reboot'ta root shell + dropbear garanti)
  [7] Dogrulama: telnet 'id' -> uid=0; paramiko varsa SSH root testi

Gereksinimler:
  - Python 3.8+ (standart kutuphane yeterli; telnet/FTP ham socket+ftplib)
  - Istege bagli: pycryptodome (web login/reboot icin), paramiko (SSH dogrulama icin)
      pip install pycryptodome paramiko

Kullanim:
  python3 ex3501-root.py                 # interaktif: IP, admin sifresi, root sifresi sorar
  python3 ex3501-root.py --yes           # onay sormadan devam
  python3 ex3501-root.py --ip 192.168.1.1 --admin-user admin --admin-pass ... --root-pass ...
  python3 ex3501-root.py --self-test     # sadece hash oz-testi

Not: Script yalnizca yerel agdan (LAN) calisir; cihazin kendi aginizda olmasi gerekir.
"""
import argparse
import base64
import ftplib
import hashlib
import http.cookiejar
import io
import json
import os
import random
import secrets
import socket
import string
import sys
import time
import urllib.error
import urllib.request

try:
    from Crypto.Cipher import PKCS1_v1_5, AES
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad, unpad
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

try:
    import paramiko
    HAVE_PARAMIKO = True
except ImportError:
    HAVE_PARAMIKO = False

CONFIG_PATH = "/data/zcfg_config.json"
PASSWD_CONTENT = (
    "daemon:*:1:1:daemon:/var:/bin/false\n"
    "ubus:x:81:81:ubus:/var/run/ubus:/bin/false\n"
    "nobody:x:99:99:nobody:/nonexistent:/bin/false\n"
    "root:x:0:0:root:/home/root:/bin/sh\n"
    "admin:x:21:21:admin:/home/admin:/usr/bin/zysh\n"
)
INIT_SCRIPT_SH = """#!/bin/sh
# Zyroot: her reboot'ta root shell'i ve dropbear'i garanti et
grep -v ^root: /var/passwd > /tmp/pw2 2>/dev/null
echo root:x:0:0:root:/home/root:/bin/sh >> /tmp/pw2
mv /tmp/pw2 /var/passwd
pidof dropbear >/dev/null 2>&1 || /usr/sbin/dropbear -p 22 -P /var/run/dropbear.pid -E &
exit 0
"""

# --------------------------------------------------------------------------
# SHA-512 crypt (glibc $6$) — saf Python, dis bagimlilik yok
# --------------------------------------------------------------------------

_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b64_24bit(b2, b1, b0, n, out):
    w = ((b2 & 0xFF) << 16) | ((b1 & 0xFF) << 8) | (b0 & 0xFF)
    for _ in range(n):
        out.append(_B64[w & 0x3F])
        w >>= 6


def sha512_crypt(password: bytes, salt: bytes, rounds: int = 5000) -> str:
    """glibc SHA-crypt ($6$), Drepper spec'i madde 1-22 (OpenSSL passwd -6 ile birebir).
    https://www.akkadia.org/drepper/SHA-crypt.txt"""
    pw, s = password, salt
    pwlen, slen = len(pw), len(s)

    # 1-3: A = SHA512(P + S)
    a = hashlib.sha512(pw + s)
    # 4-8: B = SHA512(P + S + P)
    digest_b = hashlib.sha512(pw + s + pw).digest()
    # 9: her tam 64-byte P blogu icin B'yi A'ya ekle
    a.update(digest_b * (pwlen // 64))
    # 10: kalan N byte icin B'nin ilk N bayti
    if pwlen % 64:
        a.update(digest_b[:pwlen % 64])
    # 11: len(P)'nin her biti icin (LSB'den): 1 -> B, 0 -> P
    cnt = pwlen
    while cnt > 0:
        a.update(digest_b if cnt & 1 else pw)
        cnt >>= 1
    # 12
    digest_a = a.digest()

    # 13-15: DP = SHA512(P * len(P))
    dp = hashlib.sha512(pw * pwlen).digest()
    # 16: P dizisi = DP'nin tekrarından len(P) bayt
    p_seq = (dp * (pwlen // 64 + 1))[:pwlen]
    # 17-19: DS = SHA512(S * (16 + A[0]))
    ds = hashlib.sha512(s * (16 + digest_a[0])).digest()
    # 20: S dizisi = DS tekrarından len(S) bayt
    s_seq = (ds * (slen // 64 + 1))[:slen] if slen else b""

    # 21: rounds dongusu
    for i in range(rounds):
        hc = hashlib.sha512()
        if i & 1:
            hc.update(p_seq)       # b: tek turlarda P
        else:
            hc.update(digest_a)    # c: cift turlarda A/C
        if i % 3:
            hc.update(s_seq)       # d: 3'e bolunmeyenlerde S
        if i % 7:
            hc.update(p_seq)       # e: 7'ye bolunmeyenlerde P
        if i & 1:
            hc.update(digest_a)    # f: tek turlarda A/C
        else:
            hc.update(p_seq)       # g: cift turlarda P
        digest_a = hc.digest()     # h

    # 22e: SHA-512 cikti permutasyonu (spec'teki tablonun b[i] siralamasi)
    b = digest_a
    out = []
    order = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45),
             (25, 46, 4), (47, 5, 26), (6, 27, 48), (28, 49, 7),
             (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
             (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57),
             (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19),
             (62, 20, 41)]
    for i2, i1, i0 in order:
        _b64_24bit(b[i2], b[i1], b[i0], 4, out)
    _b64_24bit(0, 0, b[63], 2, out)
    return "$6$%s$%s" % (salt.decode(), "".join(out))





def self_test():
    """OpenSSL-referansli dogrulama; gecemezse cihaza ASLA hash yazmayiz."""
    vectors = [
        (b"Hello world!", b"foo",
         "$6$foo$X8YnpPR7bKsPCeR0ylqlgdvvgojD1LEEZlhxbBf9IgbmRnsrhNmrzTzcW/JKLCy3/aRtUIhhxpbIBQuPT.o/u1"),
        (b"test password", b"abc123",
         "$6$abc123$2Kc8qEEUxWoCejqAcsC0bYrOhRBlAnv0y6Riwcj04G7LVc2H68.PpshF9rifz04tYzFX8Bv68q/KMMcypnM8s."),
    ]
    ok_all = True
    for pw, salt, want in vectors:
        got = sha512_crypt(pw, salt, 5000)
        ok = got == want
        ok_all &= ok
        print("[self-test] %s: %s" % (salt.decode(), "OK" if ok else "FAIL\n  want: %s\n  got : %s" % (want, got)))
    if not ok_all:
        sys.exit("FATAL: sha512_crypt hatali — hash yazma islemi iptal edildi.")
    print("[self-test] gecti.\n")


# --------------------------------------------------------------------------
# Yardimcilar
# --------------------------------------------------------------------------

def banner(t):
    print("\n" + "=" * 62)
    print("  " + t)
    print("=" * 62)


def port_open(ip, p, timeout=2.5):
    sk = socket.socket()
    sk.settimeout(timeout)
    try:
        return sk.connect_ex((ip, p)) == 0
    finally:
        sk.close()


def wait_port(ip, p, deadline_s, want=True, settle=3.0):
    """Port istenen duruma gelene kadar bekle. True=acilmasini bekle."""
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        if port_open(ip, p) == want:
            time.sleep(settle)
            return True
        time.sleep(3)
    return False


def ftp_connect(ip, user, pw, timeout=15):
    ftp = ftplib.FTP()
    ftp.connect(ip, 21, timeout=timeout)
    ftp.login(user, pw)
    return ftp


def ftp_read(ftp, path):
    d = io.BytesIO()
    ftp.retrbinary("RETR " + path, d.write, blocksize=131072)
    return d.getvalue()


def ftp_write(ftp, path, data: bytes):
    try:
        ftp.delete(path)
    except Exception:
        pass
    ftp.storbinary("STOR " + path, io.BytesIO(data))


# --------------------------------------------------------------------------
# Web login + reboot (AES+RSA hibrit protokol, GUI'nin kullandigi sekliyle)
# --------------------------------------------------------------------------

class WebSession:
    def __init__(self, ip, user, pw):
        self.ip = ip
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj))
        self.opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        self.aes_key_b64 = None
        self.csrf = ""
        self._login(user, pw)

    def _plain_get(self, url):
        return self.opener.open(
            urllib.request.Request("http://%s%s" % (self.ip, url)), timeout=15
        ).read().decode()

    def _login(self, user, pw):
        key = json.loads(self._plain_get("/getRSAPublickKey"))["RSAPublicKey"]
        rsa = RSA.import_key(key)
        payload = json.dumps({
            "Input_Account": user,
            "Input_Passwd": base64.b64encode(pw.encode()).decode(),
            "currLang": "tr",
            "RememberPassword": 0,
            "SHA512_password": False,
        })
        self.aes_key_b64 = base64.b64encode(os.urandom(32)).decode()
        iv_b64 = base64.b64encode(os.urandom(32)).decode()
        key_bytes = base64.b64decode(self.aes_key_b64)
        cipher = AES.new(key_bytes, AES.MODE_CBC, base64.b64decode(iv_b64)[:16])
        content = base64.b64encode(
            cipher.encrypt(pad(payload.encode(), AES.block_size))).decode()
        key_enc = base64.b64encode(
            PKCS1_v1_5.new(rsa).encrypt(self.aes_key_b64.encode())).decode()
        body = json.dumps(
            {"content": content, "key": key_enc, "iv": iv_b64}).encode()
        req = urllib.request.Request(
            "http://%s/UserLogin" % self.ip, data=body,
            headers={"Content-Type": "application/json"})
        raw = self.opener.open(req, timeout=15).read().decode()
        rj = self._decrypt(key_bytes, json.loads(raw))
        if not isinstance(rj, dict) or rj.get("result") != "ZCFG_SUCCESS":
            raise RuntimeError("Web login basarisiz: %s" % str(rj)[:200])
        self.csrf = rj.get("sessionkey", "")

    @staticmethod
    def _decrypt(key_bytes, rj):
        if isinstance(rj, dict) and "content" in rj and "iv" in rj:
            iv = base64.b64decode(rj["iv"])[:16]
            pt = unpad(AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(
                base64.b64decode(rj["content"])), AES.block_size)
            return json.loads(pt.decode())
        return rj

    def _dal_request(self, url, obj, method):
        iv = base64.b64encode(os.urandom(16)).decode()
        key_bytes = base64.b64decode(self.aes_key_b64)
        if method == "GET":
            req = urllib.request.Request(
                "http://%s%s" % (self.ip, url),
                headers={"CSRFToken": self.csrf or ""})
        else:
            cipher = AES.new(key_bytes, AES.MODE_CBC, base64.b64decode(iv))
            content = base64.b64encode(
                cipher.encrypt(pad(json.dumps(obj).encode(), AES.block_size))).decode()
            extra = {"content": content, "iv": iv}
            if method == "PUT":
                extra["key"] = ""
            body = json.dumps(extra).encode()
            req = urllib.request.Request(
                "http://%s%s" % (self.ip, url), data=body,
                headers={"Content-Type": "application/json",
                         "CSRFToken": self.csrf or ""},
                method=method)
        try:
            resp = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as e:
            resp = e
        raw = resp.read().decode()
        try:
            out = self._decrypt(key_bytes, json.loads(raw))
        except Exception:
            return raw
        if isinstance(out, dict) and out.get("sessionkey"):
            self.csrf = out["sessionkey"]
        return out

    def get(self, url):
        return self._dal_request(url, None, "GET")

    def post(self, url, obj):
        return self._dal_request(url, obj, "POST")

    def put(self, url, obj):
        return self._dal_request(url, obj, "PUT")


def web_reboot(ip, user, pw):
    """Gercek reboot endpoint'i: POST /cgi-bin/Reboot (DAL?oid=reboot CALISMAZ)."""
    s = WebSession(ip, user, pw)
    r = s.post("/cgi-bin/Reboot", {})
    return r


def enable_ftp_via_dal(ip, user, pw):
    """FTP kapaliysa web/DAL ile LAN_ONLY ac. FTP gerekmez."""
    s = WebSession(ip, user, pw)
    r = s.get("/cgi-bin/DAL?oid=mgmt_srv")
    objs = r.get("Object", []) if isinstance(r, dict) else []
    if not objs:
        raise RuntimeError("mgmt_srv okunamadi: %s" % str(r)[:200])
    found = False
    for o in objs:
        if o.get("Name") == "FTP":
            o["Mode"] = "LAN_ONLY"
            o["Enable"] = True
            o["LANEnable"] = True
            o["WLANEnable"] = True
            o["WANEnable"] = False
            o["TrustDmEnable"] = False
            found = True
    if not found:
        raise RuntimeError("mgmt_srv icinde FTP servisi yok")
    try:
        out = s.put("/cgi-bin/DAL?oid=mgmt_srv", objs)
        print("[+] DAL PUT mgmt_srv:", str(out)[:120])
    except Exception as e:
        # zcmd servisleri restart ederken baglanti kopabilir — normal
        print("[i] DAL PUT baglanti koptu (beklenen olabilir):", type(e).__name__, str(e)[:80])


def ensure_ftp(ip, user, pw):
    """Port 21 acik degilse DAL ile FTP ac, sonra FTP login dene."""
    if port_open(ip, 21):
        return
    print("[!] FTP (21) kapali — web/DAL ile LAN_ONLY acilacak")
    if not HAVE_CRYPTO:
        sys.exit(
            "FTP kapali ve pycryptodome yok; DAL ile acilamiyor.\n"
            "  pip install pycryptodome  (sonra scripti tekrar calistir)\n"
            "  veya web GUI > Maintenance > Remote MGMT: FTP = LAN only")
    try:
        enable_ftp_via_dal(ip, user, pw)
    except Exception as e:
        sys.exit("FTP acilamadi: %s\nWeb GUI'den FTP'yi LAN only yapip tekrar deneyin." % e)
    print("[*] FTP portu bekleniyor...")
    if not wait_port(ip, 21, 90):
        sys.exit(
            "FTP (21) hâlâ kapali. Web GUI > Maintenance > Remote MGMT:\n"
            "  FTP Enable + Mode = LAN only, sonra scripti tekrar calistirin.")
    print("[+] FTP (21) acildi")



# --------------------------------------------------------------------------
# Telnet surucusu
# --------------------------------------------------------------------------

class TelnetRoot:
    def __init__(self, ip, root_pw, timeout=15):
        self.s = socket.socket()
        self.s.settimeout(timeout)
        self.s.connect((ip, 23))
        time.sleep(1.5)
        self.s.recv(4096)                      # login prompt
        self.s.send(b"root\r\n")
        time.sleep(0.8)
        self.s.recv(4096)
        self.s.send(root_pw.encode() + b"\r\n")
        time.sleep(2.0)
        try:
            self.s.recv(8192)
        except Exception:
            pass

    def cmd(self, c, wait=2.5):
        import select
        self.s.send(c.encode() + b"\n")
        time.sleep(wait)
        buf = b""
        while True:
            r, _, _ = select.select([self.s], [], [], 1)
            if not r:
                break
            try:
                d = self.s.recv(65536)
            except Exception:
                break
            if not d:
                break
            buf += d
        return buf.decode(errors="replace")

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Config duzenleme
# --------------------------------------------------------------------------

def make_shadow_line(root_pw):
    salt = "".join(random.choice(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        for _ in range(8)).encode()
    h = sha512_crypt(root_pw.encode(), salt)
    days = int(time.time() // 86400)
    return "root:%s:%d::::::\n" % (h, days)


def shadow_matches(current_shadow, password):
    """Cihazdaki mevcut root hash'i sectigimiz sifreyle uyusuyor mu?
    Mevcut hash'in salt'ini alip sifreyi kendi sha512_crypt'imizle hash'leriz —
    dis bagimlilik (crypt modulu) gerekmez, salt farki sorun olmaz."""
    if not current_shadow:
        return False
    first = current_shadow.strip().split("\n")[0]
    parts = first.split(":")
    if len(parts) < 2 or not parts[1].startswith("$6$"):
        return False
    try:
        _, _, salt, _ = parts[1].split("$", 3)
    except ValueError:
        return False
    # rounds belirtilmediyse 5000 (bu cihazin kullandigi varsayilan)
    if "rounds=" in salt:
        return False  # nadir durum; yeniden yazmak guvenli
    return sha512_crypt(password.encode(), salt.encode()) == parts[1]



def edit_config(j, shadow_line, root_pw=None):
    """Config uzerinde gereken degisiklikleri yapar; (degisiklik listesi) dondurur."""
    diffs = []

    # 1) X_ZYXEL_LoginCfg root hesabi: Enabled + shadow
    for gp in j.get("X_ZYXEL_LoginCfg", {}).get("LogGp", []):
        for acc in gp.get("Account", []):
            if acc.get("Username") == "root":
                if not acc.get("Enabled"):
                    acc["Enabled"] = True
                    diffs.append("LoginCfg root Enabled -> true")
                if not shadow_matches(acc.get("shadow"), root_pw):
                    diffs.append("LoginCfg root shadow -> yeni sifre hash'i")
                    acc["shadow"] = shadow_line

    # 2) X_TTNET.Users.User: root enable + LA protokolleri
    for u in j.get("X_TTNET", {}).get("Users", {}).get("User", []):
        if u.get("Username") == "root":
            if not u.get("Enable"):
                u["Enable"] = True
                diffs.append("TTNET root Enable -> true")
            if "SSH" not in (u.get("Allowed_LA_Protocols") or ""):
                u["Allowed_LA_Protocols"] = "HTTP,HTTPS,SSH,TELNET"
                diffs.append("TTNET root Allowed_LA_Protocols -> +SSH,TELNET")
        if u.get("Username") == "admin":
            if "SSH" not in (u.get("Allowed_LA_Protocols") or ""):
                u["Allowed_LA_Protocols"] = "HTTP,HTTPS,FTP,SSH,TELNET"
                diffs.append("TTNET admin Allowed_LA_Protocols -> +SSH,TELNET")

    # 3) LocalAccess — PORTLARI ACAN ASIL AYAR (bu olmadan 22/23 acilmaz!)
    ui = j.get("X_TTNET", {}).get("UserInterface", {})
    la = ui.get("LocalAccess")
    if not isinstance(la, dict):
        la = {"Port": "80,443,21", "Protocol": "HTTP,HTTPS,FTP", "Enable": True}
        ui["LocalAccess"] = la
    ports = [p.strip() for p in (la.get("Port") or "").split(",") if p.strip()]
    protos = [p.strip() for p in (la.get("Protocol") or "").split(",") if p.strip()]
    ch = False
    for extra in ("22", "23"):
        if extra not in ports:
            ports.append(extra)
            ch = True
    for extra in ("SSH", "TELNET"):
        if extra not in protos:
            protos.append(extra)
            ch = True
    if ch:
        la["Port"] = ",".join(ports)
        la["Protocol"] = ",".join(protos)
        la["Enable"] = True
        diffs.append("LocalAccess Port/Protocol -> +22,23 / +SSH,TELNET")

    # 4) RemoteManagement: tum yonetim servisleri LAN_ONLY (WAN'dan kapali)
    for svc in j.get("X_ZYXEL_RemoteManagement", {}).get("Service", []):
        name = svc.get("Name")
        if name in ("HTTP", "HTTPS", "FTP", "TELNET", "SSH", "SNMP", "PING"):
            if svc.get("Mode") != "LAN_ONLY" or not svc.get("Enable"):
                diffs.append("%s Service: Mode=%s Enable=%s -> LAN_ONLY+true" % (
                    name, svc.get("Mode"), svc.get("Enable")))
                svc["Mode"] = "LAN_ONLY"
                svc["Enable"] = True
            if svc.get("WANEnable"):
                svc["WANEnable"] = False
                diffs.append("%s WANEnable -> false" % name)

    # 5) TT / TR-069 RemoteAccess kapali
    ra = j.get("X_TTNET", {}).get("UserInterface", {}).get("RemoteAccess")
    if isinstance(ra, dict) and ra.get("Enable"):
        ra["Enable"] = False
        ra["Port"] = ""
        ra["Protocol"] = ""
        diffs.append("X_TTNET.UserInterface.RemoteAccess Enable -> false")
    ura = j.get("UserInterface", {}).get("RemoteAccess")
    if isinstance(ura, dict) and ura.get("Enable"):
        ura["Enable"] = False
        diffs.append("UserInterface.RemoteAccess Enable -> false")
    for u in j.get("X_TTNET", {}).get("Users", {}).get("User", []):
        if u.get("RemoteAccessCapable"):
            u["RemoteAccessCapable"] = False
            diffs.append("TTNET user %s RemoteAccessCapable -> false" % u.get("Username"))

    # 6) ISP TR-069 / CWMP kapat (ACS artik baglanamaz)
    ms = j.get("ManagementServer")
    if isinstance(ms, dict):
        for key in ("EnableCWMP", "PeriodicInformEnable", "STUNEnable",
                    "X_ZYXEL_Supplemental_EnableCWMP"):
            if ms.get(key):
                ms[key] = False
                diffs.append("ManagementServer.%s -> false" % key)

    # 7) ACS / TR111 Management static route kapat (silme — dizi indeksi bozulmasin)
    acs_ips = _acs_ips(j)
    for router in j.get("Routing", {}).get("Router", []) or []:
        for rt in router.get("IPv4Forwarding", []) or []:
            if not rt.get("Enable"):
                continue
            if _is_acs_mgmt_route(rt, acs_ips):
                rt["Enable"] = False
                diffs.append("route %s %s/%s Enable -> false" % (
                    rt.get("Alias") or "?",
                    rt.get("DestIPAddress") or "",
                    rt.get("DestSubnetMask") or ""))

    return diffs


def _ip_int(s):
    try:
        a, b, c, d = [int(x) for x in (s or "").split(".")]
        return (a << 24) | (b << 16) | (c << 8) | d
    except Exception:
        return None


def _subnet_covers(dest, mask, ip):
    di, mi, ii = _ip_int(dest), _ip_int(mask), _ip_int(ip)
    if None in (di, mi, ii):
        return False
    return (di & mi) == (ii & mi)


def _acs_ips(j):
    ips = set()
    ms = j.get("ManagementServer") or {}
    for k in ("X_TTNET_ACS_IP", "X_TTNET_ACS_IP_ETH"):
        v = ms.get(k)
        if v:
            ips.add(v)
    return ips


def _is_acs_mgmt_route(rt, acs_ips):
    alias = (rt.get("Alias") or "").upper()
    dest = rt.get("DestIPAddress") or ""
    mask = rt.get("DestSubnetMask") or ""
    if alias == "TR111":
        return True
    if dest in acs_ips:
        return True
    return any(_subnet_covers(dest, mask, ip) for ip in acs_ips)


def config_state_ok(j):
    """Cihazin config'i istenen durumda mi? (reboot/skip karari icin)"""
    root_ok = la_ok = False
    for gp in j.get("X_ZYXEL_LoginCfg", {}).get("LogGp", []):
        for acc in gp.get("Account", []):
            if acc.get("Username") == "root" and acc.get("Enabled") \
                    and (acc.get("shadow") or "").startswith("root:$6$"):
                root_ok = True
    la = j.get("X_TTNET", {}).get("UserInterface", {}).get("LocalAccess", {})
    ports = (la.get("Port") or "").split(",")
    protos = (la.get("Protocol") or "").split(",")
    if "22" in ports and "SSH" in protos:
        la_ok = True
    ms = j.get("ManagementServer") or {}
    cwmp_ok = not ms.get("EnableCWMP", False)
    ra = (j.get("X_TTNET") or {}).get("UserInterface", {}).get("RemoteAccess") or {}
    ra_ok = not ra.get("Enable", False)
    acs_ips = _acs_ips(j)
    routes_ok = True
    for router in j.get("Routing", {}).get("Router", []) or []:
        for rt in router.get("IPv4Forwarding", []) or []:
            if rt.get("Enable") and _is_acs_mgmt_route(rt, acs_ips):
                routes_ok = False
    return root_ok and la_ok and cwmp_ok and ra_ok and routes_ok




# --------------------------------------------------------------------------
# Asamalar
# --------------------------------------------------------------------------

def ask(msg, default=None, hidden=False):
    if hidden:
        import getpass
        v = getpass.getpass(msg + ("" if default is None else " [%s]: " % default) if default is not None else msg + ": ")
    else:
        d = "" if default is None else " [%s]" % default
        v = input(msg + d + ": ").strip()
    if not v and default is not None:
        return default
    return v


def main():
    ap = argparse.ArgumentParser(description="EX3501-T1 root geri kazanim (fabrika reseti sonrasi)")
    ap.add_argument("--ip", default=os.environ.get("EX3501_IP"))
    ap.add_argument("--admin-user", default=os.environ.get("EX3501_ADMIN_USER"))
    ap.add_argument("--admin-pass", default=os.environ.get("EX3501_ADMIN_PASS"))
    ap.add_argument("--root-pass", default=os.environ.get("EX3501_ROOT_PASS"))
    ap.add_argument("--yes", action="store_true", help="onay sormadan devam et")
    ap.add_argument("--self-test", action="store_true", help="hash oz-testi ve cik")
    args = ap.parse_args()

    print(__doc__.splitlines()[2])
    self_test()
    if args.self_test:
        return

    # ---- Bilgi toplama (interaktif veya argumanlarla) ----
    ip = args.ip or ask("Router IP adresi", "192.168.1.1")
    admin_user = args.admin_user or ask("Admin kullanicisi (web/FTP)", "admin")
    admin_pass = args.admin_pass or ask("Admin sifresi (web/FTP — genelde cihaz etiketinde)", hidden=True)
    if not admin_pass:
        sys.exit("Admin sifresi zorunlu.")
    if args.root_pass:
        root_pw = args.root_pass
    else:
        root_pw = ask("Yeni root sifresi (bos birakirsan rastgele uretilir)", hidden=True)
        if not root_pw:
            root_pw = "".join(secrets.choice(
                string.ascii_letters + string.digits) for _ in range(16))
            print("[i] Uretilen root sifresi: %s  (not alin!)" % root_pw)
    if len(root_pw) < 6:
        sys.exit("Root sifresi en az 6 karakter olmali.")

    print("\nHedef : http://%s  (admin: %s)" % (ip, admin_user))
    print("Root sifresi: %s%s" % ("*" * len(root_pw), " (%d karakter)" % len(root_pw)))
    if not args.yes:
        r = input("\nDevam? Config degisecek ve cihaz REBOOT edecek. [y/N] ").strip().lower()
        if r != "y":
            sys.exit("Iptal edildi.")

    # ---- 1) FTP (kapaliysa once DAL ile ac) ----
    banner("[1/6] FTP ile config indir + yedekle")
    ensure_ftp(ip, admin_user, admin_pass)
    try:
        ftp = ftp_connect(ip, admin_user, admin_pass)
    except Exception as e:
        sys.exit("FTP girisi basarisiz (%s). Admin sifresini kontrol edin." % e)
    print("[+] FTP girisi OK")

    try:
        raw = ftp_read(ftp, CONFIG_PATH)
    except Exception as e:
        sys.exit("Config indirilemedi: %s" % e)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    local_bak = "zcfg_config.backup-%s.json" % stamp
    with open(local_bak, "wb") as f:
        f.write(raw)
    print("[+] Yedek (yerel): %s (%d byte)" % (local_bak, len(raw)))
    try:
        ftp.storbinary("STOR /data/zcfg_config.backup-%s.json" % stamp,
                       io.BytesIO(raw))
        print("[+] Yedek (cihaz): /data/zcfg_config.backup-%s.json" % stamp)
    except Exception as e:
        print("[!] Cihaza yedek yazilamadi (sorun degil): %s" % e)

    try:
        j = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as e:
        sys.exit("Config JSON cozulemedi: %s" % e)

    # ---- 2) Config duzenle ----
    banner("[2/6] Config duzenle")
    shadow_line = make_shadow_line(root_pw)
    diffs = edit_config(j, shadow_line, root_pw)
    need_reboot = False
    if not diffs:
        print("[i] Config zaten istenen durumda — degisiklik gerekmiyor.")
        if not config_state_ok(j):
            print("[!] Durum dogrulamasi gecemedi (root blok/LA bulunamadi?) — upload yine denenecek.")
            diffs = ["force: durum dogrulamasi gecemedi"]
    if diffs:
        for d in diffs:
            print("  *", d)
        new_raw = json.dumps(j, ensure_ascii=False, indent=2).encode()

        # ---- 3) Yukle + dogrula ----
        banner("[3/6] Config yukle (FTP DELE+STOR)")
        ftp_write(ftp, CONFIG_PATH, new_raw)
        time.sleep(2)
        try:
            back = json.loads(ftp_read(ftp, CONFIG_PATH).decode("utf-8", errors="replace"))
        except Exception as e:
            print("[!] Round-trip okunamadi (%s) — YEDEK GERI YUKLENIYOR." % e)
            ftp_write(ftp, CONFIG_PATH, raw)
            sys.exit("Config geri yuklendi, iptal.")
        ok = config_state_ok(back)
        root_shadow_ok = False
        for gp in back.get("X_ZYXEL_LoginCfg", {}).get("LogGp", []):
            for acc in gp.get("Account", []):
                if acc.get("Username") == "root" and \
                        shadow_matches(acc.get("shadow"), root_pw):
                    root_shadow_ok = True
        if not (ok and root_shadow_ok):
            print("[!] Dogrulama basarisiz — YEDEK GERI YUKLENIYOR.")
            ftp_write(ftp, CONFIG_PATH, raw)
            sys.exit("Config geri yuklendi, iptal.")
        print("[+] Yukleme dogrulandi (round-trip OK)")
        need_reboot = True
    ftp.quit()

    # ---- 4) Reboot ----
    if need_reboot:
        banner("[4/6] Reboot")
        if HAVE_CRYPTO:
            try:
                r = web_reboot(ip, admin_user, admin_pass)
                print("[+] POST /cgi-bin/Reboot:", str(r)[:120])
            except Exception as e:
                print("[!] Web reboot basarisiz: %s" % e)
                manual_reboot_prompt()
        else:
            print("[i] pycryptodome yok — web uzerinden reboot yapilamiyor.")
            manual_reboot_prompt()
        print("[*] Cihazin geri gelmesi bekleniyor (reboot ~90-120 sn)...")
        # once dusmesini bekle (10 sn icinde), sonra yukselmesini
        t0 = time.time()
        while time.time() - t0 < 30 and port_open(ip, 80):
            time.sleep(2)
        ok80 = wait_port(ip, 80, 420)
        print("[%s] web (80): %s" % (time.strftime("%H:%M:%S"), "acildi" if ok80 else "TIMEOUT"))
        if not ok80:
            sys.exit("Web geri gelmedi — cihazi kontrol edin ve scripti yeniden calistirin.")
    else:
        banner("[4/6] Reboot")
        print("[i] Reboot gerekmedi (config degismedi).")

    # ---- 5) /var/passwd duzelt ----
    banner("[5/6] /var/passwd: root -> /bin/sh")
    if not wait_port(ip, 21, 120):
        sys.exit("FTP (21) acilamadi.")
    try:
        ftp = ftp_connect(ip, admin_user, admin_pass)
    except Exception as e:
        sys.exit("Reboot sonrasi FTP girisi basarisiz: %s" % e)
    cur = ""
    try:
        cur = ftp_read(ftp, "/var/passwd").decode(errors="replace")
    except Exception:
        pass
    if "root:x:0:0:root:/home/root:/bin/sh" in cur:
        print("[i] /var/passwd zaten dogru.")
    else:
        ftp_write(ftp, "/var/passwd", PASSWD_CONTENT.encode())
        back = ftp_read(ftp, "/var/passwd").decode(errors="replace")
        if "root:x:0:0:root:/home/root:/bin/sh" not in back:
            sys.exit("/var/passwd yazimi dogrulanamadi.")
        print("[+] /var/passwd guncellendi (root shell /bin/sh)")
    ftp.quit()

    # ---- 6) Kalicilik + dogrulama ----
    banner("[6/6] Kalicilik (S99zyroot) + dogrulama")
    if not wait_port(ip, 23, 120):
        sys.exit("Telnet (23) acilamadi — LocalAccess guncellemesi reboot ile uygulanmamis olabilir.")
    t = TelnetRoot(ip, root_pw)
    out = t.cmd("id")
    if "uid=0" not in out:
        t.close()
        sys.exit("Telnet root girisi oldu ama tam shell yok (ZySH?). Cikti: %r\n"
                 "Not: 5. asamanin (/var/passwd yazimi) basarili oldugundan emin olun." % out[-300:])
    print("[+] Telnet root: uid=0 tam shell OK")
    # S99zyroot kurulumu: printf quoting tuzağına dusmemek icin base64 ile yaz
    # (telnesten $ isareti ve quoting bozulmaz — dokuman Bolum 13/1)
    b64 = base64.b64encode(INIT_SCRIPT_SH.encode()).decode()
    want_md5 = hashlib.md5(INIT_SCRIPT_SH.encode()).hexdigest()
    exact = t.cmd("md5sum /etc/init.d/S99zyroot 2>/dev/null")
    if want_md5 in exact:
        print("[i] S99zyroot zaten kurulu (md5 eslesti).")
    else:
        if exact.strip():
            print("[i] S99zyroot eski/farkli icerikle var — yeniden yaziliyor.")
        # Cihazda base64 applet yok ama /usr/bin/openssl var (dogrulandi).
        # b64'yi 200'luk parcalara bolup /tmp'e yaz, openssl ile coz.
        cmds = [": > /tmp/s99.b64"]
        for k in range(0, len(b64), 200):
            cmds.append("echo %s >> /tmp/s99.b64" % b64[k:k + 200])
        cmds += ["openssl base64 -d -in /tmp/s99.b64 > /etc/init.d/S99zyroot",
                 "rm -f /tmp/s99.b64",
                 "chmod 755 /etc/init.d/S99zyroot",
                 "ln -sf /etc/init.d/S99zyroot /etc/rc.d/S99zyroot 2>/dev/null || "
                 "cp /etc/init.d/S99zyroot /etc/rc.d/S99zyroot; chmod 755 /etc/rc.d/S99zyroot"]
        for c in cmds:
            t.cmd(c, 1.2)
        exact = t.cmd("md5sum /etc/init.d/S99zyroot 2>/dev/null")
        if want_md5 not in exact:
            t.close()
            sys.exit("S99zyroot icerigi dogrulanamadi (md5 uyusmadi):\n" + exact[-400:])
        print("[+] /etc/init.d/S99zyroot kuruldu ve md5 ile dogrulandi "
              "(her reboot'ta root shell + dropbear)")
    time.sleep(1)
    t.close()

    if wait_port(ip, 22, 60):
        print("[+] SSH (22) acik")
    else:
        print("[!] SSH (22) henuz acik degil — dropbear bir sonraki reboot'ta S99zyroot ile garanti.")

    if HAVE_PARAMIKO and port_open(ip, 22):
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(ip, 22, username="root", password=root_pw, timeout=15,
                      allow_agent=False, look_for_keys=False)
            _, o, _ = c.exec_command("id")
            res = o.read().decode()
            c.close()
            if "uid=0" in res:
                print("[+] SSH dogrulandi:", res.strip())
            else:
                print("[!] SSH baglandi ama 'id' beklenmedik cikti:", res[:100])
        except Exception as e:
            print("[!] SSH testi basarisiz: %s" % e)

    banner("TAMAMLANDI")
    print("  SSH    : ssh root@%s   (sifre: sectiginiz root sifresi)" % ip)
    print("  Telnet : root (telnet %s)" % ip)
    print("  Kalicilik: /etc/init.d/S99zyroot (reboot'a dayanikli)")
    print("  Yedek  : %s (yerel)" % local_bak)
    print("  Not: telnet her reboot'ta tekrar tam shell istenirse bu scripti calistirin")
    print("        (5. asama /var/passwd'yi yeniden yazar; SSH etkilenmez).")


def manual_reboot_prompt():
    print("=" * 50)
    print("  Cihazi elle yeniden baslatin:")
    print("  1. Modemin guc kablosunu cekin")
    print("  2. 5 sn bekleyin, tekrar takin")
    print("  3. Web arayuzu acilana kadar bekleyin (~1-2 dk)")
    input("  Hazir olunca Enter'a basin...")
    print("=" * 50)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nIptal edildi.")
