#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  AegisGuard ISO Builder                                          ║
# ║  Creates a fully offline bootable ISO (UEFI + BIOS)              ║
# ║  Run on: WSL2 (Debian/Ubuntu) or any Linux system as root        ║
# ║  Result:  build/aegisguard.iso  (~1.5-2GB)                       ║
# ╚══════════════════════════════════════════════════════════════════╝
set -e

# ── Colors ────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${G}[✓]${NC} $*"; }
info() { echo -e "${C}[→]${NC} $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; }
err()  { echo -e "${R}[✗]${NC} $*"; exit 1; }
step() { echo -e "\n${C}━━━ $* ━━━${NC}"; }

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# Use Linux tmp for build (NTFS/Windows FS breaks chroot/squashfs)
WORK="/tmp/aegisguard-build"
CHROOT="${WORK}/chroot"
ISO_DIR="${WORK}/iso"
# Final ISO goes to the project build folder
OUTPUT="${SCRIPT_DIR}/aegisguard.iso"

[ "$(id -u)" -eq 0 ] || err "Run as root: sudo bash build/build-iso.sh"

echo ""
echo -e "${C}  ╔═══════════════════════════════════════════════╗${NC}"
echo -e "${C}  ║   AegisGuard ISO Builder — Debian 12           ║${NC}"
echo -e "${C}  ║   Fully offline — no internet on target needed  ║${NC}"
echo -e "${C}  ╚═══════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Install build tools ───────────────────────────────────────────────
step "1/9  Installing build tools"
apt-get update -qq
apt-get install -y --no-install-recommends \
    debootstrap squashfs-tools xorriso isolinux syslinux-efi \
    grub-efi-amd64-bin grub-pc-bin mtools dosfstools \
    rsync curl 2>/dev/null || \
apt-get install -y debootstrap squashfs-tools xorriso \
    isolinux syslinux grub-efi-amd64-bin grub-pc-bin \
    mtools dosfstools rsync curl
log "Build tools ready"

# ── Step 2: Bootstrap Debian 12 ───────────────────────────────────────────────
step "2/9  Bootstrapping Debian 12 (bookworm)"
rm -rf "$WORK"
mkdir -p "$CHROOT" "$ISO_DIR/boot/grub" "$ISO_DIR/live"

info "Running debootstrap (takes 3-5 min)..."
debootstrap --arch=amd64 --variant=minbase \
    bookworm "$CHROOT" http://deb.debian.org/debian
log "Debian 12 base system created"

# ── Step 3: Configure chroot ──────────────────────────────────────────────────
step "3/9  Configuring base system"

# Mount pseudo-filesystems
mount --bind /dev     "${CHROOT}/dev"
mount --bind /dev/pts "${CHROOT}/dev/pts"
mount --bind /proc    "${CHROOT}/proc"
mount --bind /sys     "${CHROOT}/sys"
mount --bind /run     "${CHROOT}/run"

cleanup() {
    for m in run sys proc dev/pts dev; do
        umount -lf "${CHROOT}/${m}" 2>/dev/null || true
    done
}
trap cleanup EXIT

# Hostname, locale, timezone
echo "aegisguard" > "${CHROOT}/etc/hostname"
cat > "${CHROOT}/etc/hosts" << 'EOF'
127.0.0.1   localhost
127.0.1.1   aegisguard
EOF

# resolv.conf for package downloads inside chroot
cp /etc/resolv.conf "${CHROOT}/etc/resolv.conf"

# APT sources
cat > "${CHROOT}/etc/apt/sources.list" << 'EOF'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free
deb http://deb.debian.org/debian bookworm-updates main contrib non-free
EOF

chroot "$CHROOT" apt-get update -qq
chroot "$CHROOT" apt-get install -y locales
echo "en_US.UTF-8 UTF-8" > "${CHROOT}/etc/locale.gen"
chroot "$CHROOT" locale-gen
echo "LANG=en_US.UTF-8" > "${CHROOT}/etc/locale.conf"
chroot "$CHROOT" ln -sf /usr/share/zoneinfo/UTC /etc/localtime
log "Base system configured"

# ── Step 4: Install all packages ─────────────────────────────────────────────
step "4/9  Installing packages (takes 5-10 min)"

PACKAGES=(
    # Kernel + boot (bin-only packages avoid conflict)
    linux-image-amd64 grub-efi-amd64-bin grub-pc-bin grub-common grub2-common
    initramfs-tools live-boot live-config
    # Python
    python3 python3-pip python3-venv python3-full
    # Firewall + networking
    iptables iptables-persistent netfilter-persistent
    iproute2 net-tools iputils-ping tcpdump nmap
    conntrack conntrackd
    dnsmasq
    dhcpcd5
    # VPN
    openvpn openssl
    wireguard wireguard-tools
    strongswan strongswan-swanctl charon-systemd
    # Security
    fail2ban
    clamav clamav-daemon
    # HA
    keepalived
    # Utilities
    ssh openssh-server
    rsync curl wget
    vim nano htop
    ca-certificates
    systemd systemd-sysv
    bash-completion
    sudo
)

DEBIAN_FRONTEND=noninteractive chroot "$CHROOT" apt-get install -y \
    --no-install-recommends "${PACKAGES[@]}"
log "System packages installed"

# ── Step 5: Install Python packages ──────────────────────────────────────────
step "5/9  Installing Python packages"

chroot "$CHROOT" python3 -m venv /opt/aegisguard-venv
chroot "$CHROOT" /opt/aegisguard-venv/bin/pip install --upgrade pip -q
chroot "$CHROOT" /opt/aegisguard-venv/bin/pip install \
    fastapi uvicorn[standard] jinja2 pydantic python-multipart psutil -q
log "Python packages installed"

# ── Step 6: Install AegisGuard ────────────────────────────────────────────────
step "6/9  Installing AegisGuard"

mkdir -p "${CHROOT}/opt/aegisguard"
rsync -a \
    --exclude=".git" \
    --exclude="__pycache__" \
    --exclude="*.pyc" \
    --exclude="firewall.db" \
    --exclude="build/iso-work" \
    --exclude="build/aegisguard.iso" \
    "${PROJECT_DIR}/" "${CHROOT}/opt/aegisguard/"

# Update service to use venv
sed -i "s|ExecStart=.*|ExecStart=/opt/aegisguard-venv/bin/python -m uvicorn web.api:app --host 0.0.0.0 --port 8080 --workers 1|" \
    "${CHROOT}/opt/aegisguard/build/aegisguard.service"

# Install services
cp "${CHROOT}/opt/aegisguard/build/aegisguard.service" \
   "${CHROOT}/etc/systemd/system/"
cp "${CHROOT}/opt/aegisguard/build/aegisguard-firstboot.service" \
   "${CHROOT}/etc/systemd/system/"

# Install logrotate config
cp "${CHROOT}/opt/aegisguard/build/aegisguard-logrotate" \
   "${CHROOT}/etc/logrotate.d/aegisguard"

# Install journald config
mkdir -p "${CHROOT}/etc/systemd/journald.conf.d"
cp "${CHROOT}/opt/aegisguard/build/journald-aegisguard.conf" \
   "${CHROOT}/etc/systemd/journald.conf.d/"

# Enable services
chroot "$CHROOT" systemctl enable aegisguard
chroot "$CHROOT" systemctl enable aegisguard-firstboot
chroot "$CHROOT" systemctl enable dnsmasq
chroot "$CHROOT" systemctl enable fail2ban
chroot "$CHROOT" systemctl enable ssh

# Initialize database
chroot "$CHROOT" bash -c "
    cd /opt/aegisguard
    /opt/aegisguard-venv/bin/python -c 'from db import database; database.initialize()'
    echo 'Database initialized'
"

# MOTD
cat > "${CHROOT}/etc/motd" << 'EOF'

  ╔══════════════════════════════════════════════════════╗
  ║              AegisGuard Network Security             ║
  ║                                                      ║
  ║  Web UI:  http://10.0.0.1:8080                       ║
  ║  Default: admin / AegisGuard2024!                    ║
  ║                                                      ║
  ║  Connect to LAN port to access the Web UI            ║
  ╚══════════════════════════════════════════════════════╝

EOF

# Root password
echo "root:AegisGuard2024!" | chroot "$CHROOT" chpasswd

# SSH config — allow root login for initial setup
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' \
    "${CHROOT}/etc/ssh/sshd_config" 2>/dev/null || true

log "AegisGuard installed"

# ── Step 7: Install auto-installer ───────────────────────────────────────────
step "7/9  Installing auto-installer"

# Copy the auto-install script into the live system
cp "${SCRIPT_DIR}/auto-install.sh" "${CHROOT}/usr/local/bin/aegisguard-install"
chmod +x "${CHROOT}/usr/local/bin/aegisguard-install"

# Systemd service that runs the installer on first boot of live ISO
cat > "${CHROOT}/etc/systemd/system/aegisguard-autoinstall.service" << 'SVCEOF'
[Unit]
Description=AegisGuard Auto Installer
After=network.target
ConditionPathExists=!/installed

[Service]
Type=oneshot
ExecStart=/usr/local/bin/aegisguard-install
StandardOutput=console
StandardError=console
TTYPath=/dev/tty1
TTYVHangup=yes

[Install]
WantedBy=multi-user.target
SVCEOF

chroot "$CHROOT" systemctl enable aegisguard-autoinstall

# fstab placeholder
cat > "${CHROOT}/etc/fstab" << 'EOF'
# /etc/fstab — configured by AegisGuard installer
proc  /proc  proc  defaults  0  0
EOF

log "Auto-installer ready"

# ── Step 8: Create squashfs ───────────────────────────────────────────────────
step "8/9  Creating filesystem image (squashfs)"

# Unmount before squashfs
cleanup
trap - EXIT

# Clean up apt cache to reduce ISO size
chroot "$CHROOT" apt-get clean
rm -rf "${CHROOT}/var/cache/apt/archives"/*.deb 2>/dev/null || true
rm -rf "${CHROOT}/var/lib/apt/lists"/* 2>/dev/null || true
rm -rf "${CHROOT}/tmp"/* 2>/dev/null || true

info "Building squashfs (takes 2-5 min)..."
mksquashfs "$CHROOT" "${ISO_DIR}/live/filesystem.squashfs" \
    -comp xz -e boot -noappend -quiet
log "Squashfs created: $(du -sh "${ISO_DIR}/live/filesystem.squashfs" | cut -f1)"

# Copy kernel and initrd from chroot
KERNEL=$(ls "${CHROOT}/boot/vmlinuz-"* | sort | tail -1)
INITRD=$(ls "${CHROOT}/boot/initrd.img-"* | sort | tail -1)
cp "$KERNEL" "${ISO_DIR}/live/vmlinuz"
cp "$INITRD" "${ISO_DIR}/live/initrd.img"
log "Kernel and initrd copied"

# ── Step 9: Build bootable ISO ────────────────────────────────────────────────
step "9/9  Building bootable ISO (UEFI + BIOS)"

# GRUB config (UEFI)
mkdir -p "${ISO_DIR}/boot/grub"
cat > "${ISO_DIR}/boot/grub/grub.cfg" << 'EOF'
set default=0
set timeout=5

insmod all_video
insmod gfxterm
terminal_output gfxterm

menuentry "AegisGuard — Install to disk" --class aegisguard {
    linux   /live/vmlinuz boot=live components quiet splash toram
    initrd  /live/initrd.img
}

menuentry "AegisGuard — Install (verbose)" --class aegisguard {
    linux   /live/vmlinuz boot=live components
    initrd  /live/initrd.img
}

menuentry "Boot from hard disk" {
    chainloader (hd0,1)+1
}
EOF

# Create EFI image
mkdir -p "${ISO_DIR}/EFI/BOOT"
EFI_IMG="${ISO_DIR}/boot/grub/efi.img"
dd if=/dev/zero of="$EFI_IMG" bs=1M count=10 2>/dev/null
mkfs.fat -F 12 "$EFI_IMG"
mmd -i "$EFI_IMG" ::/EFI ::/EFI/BOOT

# Copy GRUB EFI binary
GRUB_EFI=$(find /usr -name "grubx64.efi" 2>/dev/null | head -1)
if [ -z "$GRUB_EFI" ]; then
    grub-mkimage -O x86_64-efi -o /tmp/grubx64.efi \
        -p /boot/grub \
        fat iso9660 part_gpt part_msdos \
        normal boot linux efifwsetup efi_gop \
        ls search search_label search_fs_uuid search_fs_file \
        gfxterm gfxterm_background gfxterm_menu test all_video loadenv \
        exfat ext2 ntfs btrfs hfsplus 2>/dev/null
    GRUB_EFI="/tmp/grubx64.efi"
fi
mcopy -i "$EFI_IMG" "$GRUB_EFI" ::/EFI/BOOT/BOOTX64.EFI

# BIOS isolinux — copy ALL required modules
mkdir -p "${ISO_DIR}/isolinux"

SYSLINUX_BIOS=""
for d in /usr/lib/syslinux/modules/bios /usr/lib/ISOLINUX /usr/share/syslinux; do
    [ -f "${d}/isolinux.bin" ] && SYSLINUX_BIOS="$d" && break
done

if [ -n "$SYSLINUX_BIOS" ]; then
    cp "${SYSLINUX_BIOS}/isolinux.bin" "${ISO_DIR}/isolinux/"
    # Copy all .c32 modules needed
    for mod in ldlinux.c32 libcom32.c32 libutil.c32 menu.c32 vesamenu.c32; do
        cp "${SYSLINUX_BIOS}/${mod}" "${ISO_DIR}/isolinux/" 2>/dev/null || true
    done
fi

# Simple isolinux.cfg — no UI dependency, works on all BIOS systems
cat > "${ISO_DIR}/isolinux/isolinux.cfg" << 'EOF'
DEFAULT install
PROMPT 1
TIMEOUT 50
ONTIMEOUT install

LABEL install
  SAY Installing AegisGuard Network Security...
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img boot=live components quiet

LABEL verbose
  SAY Installing AegisGuard (verbose)...
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd.img boot=live components
EOF

# Build the ISO
info "Building ISO with xorriso..."
xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "AEGISGUARD" \
    -appid "AegisGuard Network Security" \
    -publisher "AegisGuard" \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -b isolinux/isolinux.bin \
    -c isolinux/boot.cat \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    -output "$OUTPUT" \
    "$ISO_DIR" 2>/dev/null

# Make hybrid (bootable from USB)
isohybrid "$OUTPUT" 2>/dev/null || true

ISO_SIZE=$(du -sh "$OUTPUT" | cut -f1)

echo ""
echo -e "${G}  ╔════════════════════════════════════════════════════╗${NC}"
echo -e "${G}  ║   ISO built successfully!                           ║${NC}"
echo -e "${G}  ║                                                     ║${NC}"
echo -e "${G}  ║   File: build/aegisguard.iso                        ║${NC}"
echo -e "${G}  ║   Size: ${ISO_SIZE}                                         ║${NC}"
echo -e "${G}  ║                                                     ║${NC}"
echo -e "${G}  ║   Hyper-V:  New VM → Generation 2 → attach ISO      ║${NC}"
echo -e "${G}  ║   USB:      dd if=aegisguard.iso of=/dev/sdX bs=4M  ║${NC}"
echo -e "${G}  ║             or balenaEtcher on Windows              ║${NC}"
echo -e "${G}  ║                                                     ║${NC}"
echo -e "${G}  ║   After install, access: http://10.0.0.1:8080       ║${NC}"
echo -e "${G}  ║   Default root password:  AegisGuard2024!           ║${NC}"
echo -e "${G}  ╚════════════════════════════════════════════════════╝${NC}"
echo ""

# Cleanup work directory
rm -rf "$WORK"
log "Build directory cleaned up"
