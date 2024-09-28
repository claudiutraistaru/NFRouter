#!/bin/sh
#
# This file is part of NFRouter. *
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
udhcpc eth0

#install required packages 
apk add e2fsprogs sfdisk frr dnsmasq

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


# Install Alpine Linux
setup-alpine -f /media/cdrom/answerfile

# Mount the partition
mount "${TARGET_DISK}3" /mnt

# Copy nfrouter executable
cp /media/cdrom/nfrouter /mnt/usr/local/bin/nfrouter
chmod +x /mnt/usr/local/bin/nfrouter

#create config directory
mkdir /mnt/config

# Configure nfrouter to start on boot
cat <<EOS > /mnt/etc/local.d/nfrouter.start
#!/bin/sh
/usr/local/bin/nfrouter -d&
EOS
chmod +x /mnt/etc/local.d/nfrouter.start

# Enable local service
chroot /mnt rc-update add local default

echo "Installation complete. Rebooting..."
#reboot