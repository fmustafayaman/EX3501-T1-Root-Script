#!/bin/sh
# opkg-usb-fix.sh — EX3501-T1 / benzeri Zyxel OpenWrt
# BusyBox wget segfault → curl shim; opkg varsayılan dest = seçilen USB.
#
# Eğitim / araştırma. Yalnızca kendi cihazınızda, root olarak çalıştırın.
# Garanti yok; sorumluluk kullanıcıya aittir.
#
# Kullanım (cihazda root shell):
#   sh opkg-usb-fix.sh
#   sh opkg-usb-fix.sh --noninteractive   # tek USB varsa onu seçer

set -eu

NONINT=0
[ "${1:-}" = "--noninteractive" ] && NONINT=1

die() { echo "HATA: $*" >&2; exit 1; }
info() { echo "[*] $*"; }
ok() { echo "[+] $*"; }

[ "$(id -u)" = "0" ] || die "root olun (ssh/telnet root)."

command -v curl >/dev/null 2>&1 || die "curl yok; wget shim kurulamaz."
[ -x /rom/bin/opkg ] || die "/rom/bin/opkg yok; sarmalayici kurulamaz."
[ -f /etc/opkg.conf ] || die "/etc/opkg.conf yok."

# --- USB / cikarilabilir disk mount'lari ---
# tmpfs, overlay, rom, ubi, mtd, loop (zydefault) haric.
is_skip_mp() {
    case "$1" in
        /|/rom|/overlay|/tmp|/dev|/proc|/sys|/data|/misc|/misc2) return 0 ;;
        /sys/*|/proc/*|/dev/*|/tmp/*) return 0 ;;
        /mnt/zydefault) return 0 ;;
    esac
    return 1
}

is_skip_dev() {
    case "$1" in
        /dev/loop*|/dev/mtd*|/dev/ubi*|/dev/root|/dev/ram*) return 0 ;;
    esac
    return 1
}

# N satirlari: "dev|mp|fs|size"
CAND=""
N=0
while read -r dev mp fs _rest; do
    [ -n "$dev" ] || continue
    is_skip_dev "$dev" && continue
    is_skip_mp "$mp" && continue
    case "$fs" in
        ext2|ext3|ext4|exfat|vfat|ntfs|fuseblk|hfsplus) ;;
        *) continue ;;
    esac
    # USB ipucu: sd*, removable, mount yolunda usb
    hint=0
    case "$dev" in /dev/sd*|/dev/mmcblk*) hint=1 ;; esac
    case "$mp" in *usb*|*USB*|*sda*|*sdb*) hint=1 ;; esac
    base=$(echo "$dev" | sed 's|/dev/||; s|[0-9]*$||; s|p[0-9]*$||')
    if [ -f "/sys/block/$base/removable" ]; then
        [ "$(cat "/sys/block/$base/removable" 2>/dev/null)" = "1" ] && hint=1
    fi
    [ "$hint" = "1" ] || continue

    size=$(df -h "$mp" 2>/dev/null | awk 'NR==2{print $2" toplam, "$4" bos"}')
    [ -n "$size" ] || size="?"
    N=$((N + 1))
    CAND="${CAND}${N}|${dev}|${mp}|${fs}|${size}
"
done < /proc/mounts

[ "$N" -gt 0 ] || die "Takili/mount edilmis USB bulunamadi. Stick'i takin, mount edin, tekrar calistirin."

echo
echo "Bulunan diskler:"
echo "$CAND" | while IFS="|" read -r i dev mp fs size; do
    [ -n "$i" ] || continue
    echo "  [$i]  $dev  ->  $mp  ($fs, $size)"
done
echo

SEL=""
if [ "$NONINT" = "1" ]; then
    [ "$N" = "1" ] || die "--noninteractive icin tam bir USB olmali (simdi $N tane)."
    SEL=1
else
    if [ "$N" = "1" ]; then
        printf "Tek USB var. Bunu kullan? [Y/n] "
        read -r ans || ans=Y
        case "$ans" in n|N) die "iptal" ;; esac
        SEL=1
    else
        printf "Numara secin (1-%s): " "$N"
        read -r SEL || true
    fi
fi

echo "$SEL" | grep -q '^[0-9][0-9]*$' || die "gecersiz secim"
[ "$SEL" -ge 1 ] && [ "$SEL" -le "$N" ] || die "secim 1-$N araliginda olmali"

MP=""
echo "$CAND" | while IFS="|" read -r i dev mp fs size; do
    [ "$i" = "$SEL" ] || continue
    echo "$mp" > /tmp/opkg-usb-mp
    echo "Secilen: $dev -> $mp ($fs, $size)"
done
MP=$(cat /tmp/opkg-usb-mp 2>/dev/null) || true
rm -f /tmp/opkg-usb-mp
[ -n "$MP" ] && [ -d "$MP" ] || die "mount noktasi okunamadi"
DEST="$MP/opkg"
mkdir -p "$DEST" || die "olusturulamadi: $DEST"

# --- wget -> curl (BusyBox wget bu firmware'de SIGSEGV) ---
WGET=/usr/bin/wget
NEED_WGET=1
if [ -f "$WGET" ] && grep -q 'exec /usr/bin/curl' "$WGET" 2>/dev/null; then
    NEED_WGET=0
    ok "wget zaten curl shim"
fi
if [ "$NEED_WGET" = "1" ]; then
    info "BusyBox wget yerine curl shim yaziliyor ($WGET)"
    rm -f "$WGET"
    cat > "$WGET" << 'EOF'
#!/bin/sh
# BusyBox wget bu firmware'de segfault; opkg wget cagirir.
OUT=""
URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    -O) OUT="$2"; shift 2 ;;
    -O*) OUT="${1#-O}"; shift ;;
    -q|-c|-S|--spider|-Y) shift ;;
    -o|-P|-U|--header) shift 2 ;;
    -*) shift ;;
    *) URL="$1"; shift ;;
  esac
done
[ -n "$URL" ] || { echo "wget: missing URL" >&2; exit 1; }
if [ -n "$OUT" ]; then
  exec /usr/bin/curl -fsSL --connect-timeout 20 -o "$OUT" "$URL"
fi
exec /usr/bin/curl -fsSL --connect-timeout 20 "$URL"
EOF
    chmod 755 "$WGET"
    ok "wget shim kuruldu"
fi

# --- dest usb ---
if grep -q "^dest usb " /etc/opkg.conf; then
    sed -i "s|^dest usb .*|dest usb $DEST|" /etc/opkg.conf
    ok "opkg.conf dest usb -> $DEST"
else
    echo "dest usb $DEST" >> /etc/opkg.conf
    ok "opkg.conf dest usb eklendi"
fi

# --- /bin/opkg sarmalayici (varsayilan -d usb) ---
if [ -f /bin/opkg ] && grep -q 'exec /rom/bin/opkg -d usb' /bin/opkg 2>/dev/null; then
    ok "opkg sarmalayici zaten var"
else
    info "/bin/opkg overlay sarmalayici (asli /rom/bin/opkg)"
    rm -f /bin/opkg
    cat > /bin/opkg << 'EOF'
#!/bin/sh
d=0
for a in "$@"; do
  [ "$a" = "-d" ] && d=1
done
if [ "$d" -eq 0 ]; then
  exec /rom/bin/opkg -d usb "$@"
fi
exec /rom/bin/opkg "$@"
EOF
    chmod 755 /bin/opkg
    ok "opkg sarmalayici kuruldu"
fi

# --- PATH: profile.d + shinit (SSH login-shell degil, profile okunmaz) ---
PROF=/etc/profile.d/opkg-usb.sh
mkdir -p /etc/profile.d
cat > "$PROF" << EOF
# opkg usb dest ($DEST)
export PATH=$DEST/usr/bin:$DEST/bin:\$PATH
export LD_LIBRARY_PATH=$DEST/usr/lib:$DEST/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}
EOF
chmod 644 "$PROF"
ok "PATH profile.d: $PROF"

if [ -f /etc/shinit ] && ! grep -q opkg-usb.sh /etc/shinit; then
    echo '[ -f /etc/profile.d/opkg-usb.sh ] && . /etc/profile.d/opkg-usb.sh' >> /etc/shinit
    ok "PATH /etc/shinit (SSH/ash interactive)"
fi

# --- reboot + USB takilinca dest yolunu guncelle ---
HERE=$(dirname "$0")
if [ -f "$HERE/opkg-usb-bind.sh" ]; then
    cp "$HERE/opkg-usb-bind.sh" /usr/sbin/opkg-usb-bind
elif [ -f /usr/sbin/opkg-usb-bind ]; then
    :
else
    die "opkg-usb-bind.sh bu script ile ayni dizinde olmali"
fi
chmod 755 /usr/sbin/opkg-usb-bind

mkdir -p /etc/hotplug.d/block
cat > /etc/hotplug.d/block/90-opkg-usb << 'EOF'
[ "$ACTION" = "add" ] || exit 0
sleep 2
[ -x /usr/sbin/opkg-usb-bind ] && /usr/sbin/opkg-usb-bind
EOF
chmod 755 /etc/hotplug.d/block/90-opkg-usb
ok "hotplug: /etc/hotplug.d/block/90-opkg-usb"
if [ -f /etc/init.d/S99zyroot ]; then
    if ! grep -q opkg-usb-bind /etc/init.d/S99zyroot; then
        grep -v '^exit 0' /etc/init.d/S99zyroot > /tmp/s99n
        echo '( sleep 12; /usr/sbin/opkg-usb-bind ) >/dev/null 2>&1 &' >> /tmp/s99n
        echo 'exit 0' >> /tmp/s99n
        cat /tmp/s99n > /etc/init.d/S99zyroot
        rm -f /tmp/s99n
        chmod 755 /etc/init.d/S99zyroot
        ok "S99zyroot: boot'ta opkg-usb-bind"
    fi
else
    info "S99zyroot yok — sadece hotplug ile baglanir (USB tak/cikar veya bind elle)"
fi

/usr/sbin/opkg-usb-bind || true

echo
echo "Tamam."
echo "  USB dest : $DEST"
echo "  opkg install <paket>     -> USB"
echo "  opkg -d root install ... -> overlay (kucuk, dikkat)"
echo "  PATH: yeni SSH/telnet oturumu (veya: . /etc/profile.d/opkg-usb.sh)"
echo "  USB reboot/takilinca dest otomatik guncellenir."
echo
echo "Not: resmi OpenWrt kmod-* bu vendor kernel ile uyumlu degil; kurmayin."
echo "     airoha/ex3501_t1_tt feed 404 olabilir; base/packages genelde iner."
