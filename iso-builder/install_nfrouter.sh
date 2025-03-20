#!/bin/sh
#* This file is part of NFRouter. *
# Copyright (C) 2024 Claudiu Trăistaru
#
# Licensed under GNU Affero General Public License

ifconfig eth0 up
udhcpc

REPO_MAIN="http://dl-cdn.alpinelinux.org/alpine/latest-stable/main"
REPO_COMMUNITY="http://dl-cdn.alpinelinux.org/alpine/latest-stable/community"

# Backup existing repositories
cp /etc/apk/repositories /etc/apk/repositories.backup

# Set new repositories
echo "$REPO_MAIN" > /etc/apk/repositories
echo "$REPO_COMMUNITY" >> /etc/apk/repositories

apk fetch
apk add e2fsprogs sfdisk frr dnsmasq conntrack-tools iptables tcpdump lsblk

# List available disks with numbering
echo "Available disks:"
lsblk -d -o NAME,SIZE,TYPE | grep disk | nl

# Prompt user to select disk
echo "Please select the target disk by number (e.g., 1, 2, 3):"
read disk_number

# Validate selection
target_disk=$(lsblk -d -o NAME,TYPE | grep disk | sed -n "${disk_number}p" | awk '{print $1}')

if [ -z "$target_disk" ]; then
    echo "Invalid selection. Exiting."
    exit 1
fi

target_disk="/dev/$target_disk"
echo "You selected $target_disk. Starting installation..."

# Generate answerfile
answerfile="/tmp/answerfile"
cat <<EOF > "$answerfile"
KEYMAPOPTS="us us"
HOSTNAMEOPTS="-n nfrouter"
INTERFACESOPTS="auto eth0"
TIMEZONEOPTS="-z UTC"
PROXYOPTS="none"
APKREPOSOPTS="-1"
SSHDOPTS="-c openssh"
NTPOPTS="-c chrony"
DISKOPTS="-m sys $target_disk"
DNSOPTS="-d nfrouter.local -n 8.8.8.8 8.8.4.4"
USEROPTS="none"
EOF

setup-alpine -f "$answerfile"

# Mount partition
mkdir -p /mnt
mount "${target_disk}3" /mnt

# Copy nfrouter executable
cp /nfrouter /mnt/usr/local/bin/nfrouter
chmod +x /mnt/usr/local/bin/nfrouter

mkdir -p /mnt/config

# Configure OverlayFS for /etc
cat <<EOS >> /mnt/etc/fstab
tmpfs /etc-overlay tmpfs defaults,noatime,mode=0755 0 0
overlay /etc overlay lowerdir=/etc,upperdir=/etc-overlay/upper,workdir=/etc-overlay/work 0 0
EOS

# Create OpenRC init script for OverlayFS
cat <<'EOS' > /mnt/etc/init.d/mount-etc
#!/sbin/openrc-run

depend() {
    before localmount
}

start() {
    ebegin "Mounting OverlayFS on /etc"

    mount -t tmpfs tmpfs /etc-overlay || return 1
    mkdir -p /etc-overlay/upper /etc-overlay/work

    mount -t overlay overlay \
        -o lowerdir=/etc,upperdir=/etc-overlay/upper,workdir=/etc-overlay/work \
        /etc || return 1

    eend $?
}
EOS

chmod +x /mnt/etc/init.d/mount-etc
chroot /mnt rc-update add mount-etc boot

# Start nfrouter on boot
cat <<EOS > /mnt/etc/local.d/nfrouter.start
#!/bin/sh
/usr/local/bin/nfrouter -d
EOS

chmod +x /mnt/etc/local.d/nfrouter.start
chroot /mnt rc-update add local default

# Enable FRR services
daemons_file="/mnt/etc/frr/daemons"
if [ -f "$daemons_file" ]; then
    sed -i 's/^ripd=no/ripd=yes/' "$daemons_file"
    sed -i 's/^ripngd=no/ripngd=yes/' "$daemons_file"
fi

chroot /mnt rc-update add frr default
chroot /mnt rc-update add dnsmasq default

echo "Installation complete. Rebooting..."
