#!/bin/sh
# opkg-usb-bind — mount edilmiş USB'yi bul, dest usb + PATH guncelle.
# Secim yok. Boot (S99) ve hotplug.d/block cagirir.
# Eğitim amaçlı; sorumluluk kullanıcıya aittir.

LOG=/tmp/opkg-usb-bind.log
CONF=/etc/opkg.conf
PROF=/etc/profile.d/opkg-usb.sh

log() { echo "$(date +%H:%M:%S) $*" >> "$LOG"; }

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

# cikti: mp satirlari
list_usb_mp() {
    while read -r dev mp fs _rest; do
        [ -n "$dev" ] || continue
        is_skip_dev "$dev" && continue
        is_skip_mp "$mp" && continue
        case "$fs" in
            ext2|ext3|ext4|exfat|vfat|ntfs|fuseblk|hfsplus) ;;
            *) continue ;;
        esac
        hint=0
        case "$dev" in /dev/sd*|/dev/mmcblk*) hint=1 ;; esac
        case "$mp" in *usb*|*USB*|*sda*|*sdb*) hint=1 ;; esac
        base=$(echo "$dev" | sed 's|/dev/||; s|[0-9]*$||; s|p[0-9]*$||')
        if [ -f "/sys/block/$base/removable" ]; then
            [ "$(cat "/sys/block/$base/removable" 2>/dev/null)" = "1" ] && hint=1
        fi
        [ "$hint" = "1" ] || continue
        echo "$mp"
    done < /proc/mounts
}

apply_dest() {
    mp=$1
    dest="$mp/opkg"
    mkdir -p "$dest" || return 1
    if grep -q "^dest usb " "$CONF" 2>/dev/null; then
        sed -i "s|^dest usb .*|dest usb $dest|" "$CONF"
    else
        echo "dest usb $dest" >> "$CONF"
    fi
    mkdir -p /etc/profile.d
    cat > "$PROF" << EOF
# opkg usb dest (auto)
export PATH=$dest/usr/bin:$dest/bin:\$PATH
export LD_LIBRARY_PATH=$dest/usr/lib:$dest/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}
EOF
    chmod 644 "$PROF"
    log "dest usb -> $dest"
}

cur=$(awk '/^dest usb /{print $3; exit}' "$CONF" 2>/dev/null || true)
# dest usb /mnt/foo/opkg -> parent /mnt/foo
cur_mp=""
case "$cur" in
    */opkg) cur_mp=${cur%/opkg} ;;
    *) cur_mp=$cur ;;
esac

found=$(list_usb_mp)
if [ -z "$found" ]; then
    log "usb yok"
    exit 0
fi

# 1) mevcut dest hâlâ mount
if [ -n "$cur_mp" ] && [ -d "$cur_mp" ]; then
    echo "$found" | grep -qx "$cur_mp" && {
        mkdir -p "$cur_mp/opkg"
        log "korundu $cur"
        exit 0
    }
fi

# 2) icinde zaten opkg agaci olan
pick=""
echo "$found" | while read -r mp; do
    [ -d "$mp/opkg/usr" ] || [ -d "$mp/opkg" ] || continue
    echo "$mp" > /tmp/opkg-usb-pick
    break
done
[ -f /tmp/opkg-usb-pick ] && pick=$(cat /tmp/opkg-usb-pick)
rm -f /tmp/opkg-usb-pick

# 3) ilk aday
if [ -z "$pick" ]; then
    pick=$(echo "$found" | head -n 1)
fi

[ -n "$pick" ] || exit 0
apply_dest "$pick"
exit 0
