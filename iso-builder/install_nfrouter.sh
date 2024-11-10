#!/bin/sh
#* This file is part of NFRouter. *
# Copyright (C) 2024 Claudiu Trăistaru
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

ifconfig eth0 up
udhcpc
REPO_MAIN="http://dl-cdn.alpinelinux.org/alpine/latest-stable/main"
REPO_COMMUNITY="http://dl-cdn.alpinelinux.org/alpine/latest-stable/community"

# Backup the existing repositories file (just in case)
cp /etc/apk/repositories /etc/apk/repositories.backup

# Add the repositories to the /etc/apk/repositories file
echo "Adding repositories to /etc/apk/repositories..."
echo "$REPO_MAIN" | tee /etc/apk/repositories
echo "$REPO_COMMUNITY" | tee -a /etc/apk/repositories

apk fetch
#install required packages 
apk add e2fsprogs sfdisk frr dnsmasq
#apk add --allow-untrusted --force-non-repository --initdb --cache-dir=/apk_cache --repositories-file=/dev/null /apks/dnsmasq.apk /apks/frr.apk /apks/e2fsprogs.apk /apks/sfdisk.apk /apks/mtools /apks/initramfs-generator /apks/syslinux

# Set the installation target (e.g., /dev/sda)
TARGET_DISK="/dev/sda"

echo "Starting installation on $TARGET_DISK..."

# Partition the disk
# sfdisk $TARGET_DISK <<EOF2
# label: dos
# label-id: 0x83
# device: $TARGET_DISK
# unit: sectors

# ${TARGET_DISK}1 : start=        2048, size=     2097152, type=83, bootable
# EOF2

# Format the partition
#mkfs.ext4 "${TARGET_DISK}1" -t ext4


setup-alpine -f ./answerfile

# Mount the partition
mount "${TARGET_DISK}3" /mnt

# Copy nfrouter executable
cp /media/cdrom/nfrouter /mnt/usr/local/bin/nfrouter
chmod +x /mnt/usr/local/bin/nfrouter

#create config directory
mkdir /mnt/config

# # Configure nfrouter to start on boot
cat <<EOS > /mnt/etc/local.d/nfrouter.start
#!/bin/sh
/usr/local/bin/nfrouter -d
EOS
chmod +x /mnt/etc/local.d/nfrouter.start
chroot /mnt rc-update add local default


#tee /mnt/etc/init.d/nfrouter <<EOS
# cat <<EOS > /mnt/etc/init.d/nfrouter
# #!/sbin/openrc-run

# description="NFRouter Service"

# command="/usr/local/bin/nfrouter"
# command_args="-d"

# depend() {
#     after net
#     after bootmisc
#     after local
#     after frr
#     after dnsmasq
# }

# start() {
#     ebegin "Running NFRouter configuration"
#     start-stop-daemon --start --exec $command -- $command_args
#     eend $? "Failed to run NFRouter configuration"
# }

# stop() {
#     ebegin "Stopping NFRouter"
#     eend 0
# }
# EOS
# chmod +x /mnt/etc/init.d/nfrouter
# chroot /mnt rc-update add nfrouter default


# REPO_FILE="/mnt/etc/apk/repositories"
# echo "Enabling the Alpine community repository in $REPO_FILE..."
# sed -i 's/^#\(.*\/community\)/\1/' $REPO_FILE
# echo "Community repository enabled successfully."
chroot /mnt apk fetch
chroot /mnt apk add dnsmasq frr conntrack-tools iptables

DAEMONS_FILE="/etc/frr/daemons"
if [ ! -f "$DAEMONS_FILE" ]; then
    echo "Error: $DAEMONS_FILE not found!"
    exit 1
fi

sed -i 's/^ripd=no/ripd=yes/' $DAEMONS_FILE
sed -i 's/^ripngd=no/ripngd=yes/' $DAEMONS_FILE


chroot /mnt rc-update add frr default
chroot /mnt rc-update add dnsmasq default

echo "Installation complete. Rebooting..."
#reboot