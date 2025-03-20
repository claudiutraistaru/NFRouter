FROM alpine:latest

# Install necessary tools
RUN apk add --no-cache wget xorriso syslinux e2fsprogs cpio gzip squashfs-tools

# Download Alpine ISO
RUN wget -O /alpine-standard.iso https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.2-x86_64.iso

# Create directories for mounting and extraction
RUN mkdir -p /iso_temp /rootfs_squash

# Extract ISO contents
RUN xorriso -osirrox on -indev /alpine-standard.iso -extract / /iso_temp || (echo "ISO extraction failed" && exit 1)

# Locate and extract SquashFS filesystem
RUN find /iso_temp -name "*.squashfs" -exec mv {} /iso_temp/rootfs.squashfs \;
RUN unsquashfs -d /rootfs_squash /iso_temp/rootfs.squashfs

# Copy nfrouter directly into /usr/bin in the SquashFS
COPY target/x86_64-unknown-linux-musl/release/nfrouter /rootfs_squash/usr/bin/nfrouter
RUN chmod +x /rootfs_squash/usr/bin/nfrouter

# Optionally, copy installation script (if needed)
COPY iso-builder/install_nfrouter.sh /rootfs_squash/usr/bin/install_nfrouter.sh
RUN chmod +x /rootfs_squash/usr/bin/install_nfrouter.sh

# Repack SquashFS filesystem
RUN mksquashfs /rootfs_squash /iso_temp/boot/squashfs-rootfs -comp xz -Xbcj x86 || (echo "SquashFS repacking failed" && exit 1)

# Replace original SquashFS
RUN mv /iso_temp/boot/squashfs-rootfs /iso_temp/rootfs.squashfs

# Rebuild ISO with modified filesystem
RUN xorriso -as mkisofs \
    -o /alpine-nfrouter.iso \
    -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
    -c boot/syslinux/boot.cat \
    -b boot/syslinux/isolinux.bin \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -V "nfrouter ALPHA" \
    /iso_temp || (echo "ISO creation failed" && exit 1)

CMD ["sh"]
