#!/bin/bash

echo "Step 1: Updating packages and installing necessary tools..."
apt-get update && apt-get install -y qemu-system-x86 qemu-kvm socat bridge-utils iproute2 jq udhcpd iputils-ping ipcalc tcpdump iptables

/run/generate-dhcpd-conf.sh qemubr0 > /run/dhcpd.conf

echo "Step 2: Creating the ifup script..."
cat <<EOL > /run/qemubr0-ifup
#!/usr/bin/env bash
QEMU_BRIDGE="qemubr0"
ip link set dev \$1 up
ip link set dev \$1 master \$QEMU_BRIDGE
EOL

cat <<EOL > /run/qemubr1-ifup
#!/usr/bin/env bash
QEMU_BRIDGE2="qemubr1"
ip link set dev \$1 up
ip link set dev \$1 master \$QEMU_BRIDGE2
EOL

echo "Step 3: Creating the ifdown script..."
cat <<EOL > /run/qemubr0-ifdown
#!/usr/bin/env bash
QEMU_BRIDGE="qemubr0"
ip link set dev \$1 nomaster
ip link set dev \$1 down
EOL

cat <<EOL > /run/qemubr1-ifdown
#!/usr/bin/env bash
QEMU_BRIDGE="qemubr1"
ip link set dev \$1 nomaster
ip link set dev \$1 down
EOL

echo "Step 4: Making the ifup and ifdown scripts executable..."
chmod +x /run/qemubr0-ifup /run/qemubr0-ifdown
chmod +x /run/qemubr1-ifup /run/qemubr1-ifdown

echo "Step 5: Setting up variables..."
QEMU_BRIDGE="qemubr0"
QEMU_BRIDGE2="qemubr1"
DUMMY_DHCPD_IP="192.168.10.1"
DHCPD_CONF_FILE="/run/dhcpd.conf"
QEMU_MAC=${QEMU_MAC}

echo "Step 6: Ensuring DHCP leases file exists..."
mkdir -p /var/lib/misc
touch /var/lib/misc/udhcpd.leases

echo "Generated dhcpd.conf:"
cat $DHCPD_CONF_FILE

ip addr flush dev eth0
ip addr flush dev eth1
echo "Step 8: Creating the bridges (qemubr0 and qemubr1)..."
ip link add $QEMU_BRIDGE type bridge
ip link add $QEMU_BRIDGE2 type bridge

echo "Step 9: Adding eth0 and eth1 to the bridges..."
ip link set dev eth0 master $QEMU_BRIDGE
ip link set dev eth1 master $QEMU_BRIDGE2

echo "Step 11: Setting up the bridges..."
ip link set dev eth0 up
ip link set dev eth1 up
ip link set dev $QEMU_BRIDGE up
ip link set dev $QEMU_BRIDGE2 up

echo "Step 14: Starting the DHCP server..."
udhcpd -I $DUMMY_DHCPD_IP -f $DHCPD_CONF_FILE &

echo "Step 15: Running QEMU..."
exec qemu-system-x86_64 -enable-kvm -m 1024M \
-nic tap,script=/run/qemubr0-ifup,downscript=/run/qemubr0-ifdown,br=$QEMU_BRIDGE,mac=$QEMU_MAC \
-nic tap,script=/run/qemubr1-ifup,downscript=/run/qemubr1-ifdown,br=$QEMU_BRIDGE2 \
-hda /root/alpine.qcow2 \
-nographic -serial unix:/root/serial.sock,server,nowait \
-cdrom /root/cloud-init.iso \
-virtfs local,path=../../target,mount_tag=host_target,security_model=passthrough,id=host_target