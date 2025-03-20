FROM alpine:latest

# Install necessary tools
RUN apk add --no-cache wget xorriso syslinux e2fsprogs cpio gzip squashfs-tools

# Download Alpine ISO
RUN wget -O /alpine-standard.iso https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.2-x86_64.iso

# Create directories for mounting and extraction
RUN mkdir -p /iso_temp /rootfs_squash

# Extract ISO contents
RUN xorriso -osirrox on -indev /alpine-standard.iso -extract / /iso_temp || (echo "ISO extraction failed" && exit 1)

## Correctly identify and move SquashFS (root filesystem)
#RUN mv /iso_temp/boot/squashfs /iso_temp/rootfs.squashfs
#Move correct root filesystem SquashFS
RUN ls /iso_temp/boot


# # Modify /etc/profile.d/ to add /media/cdrom/nfrouter to PATH
# RUN mkdir -p /rootfs_squash/etc/profile.d/
# RUN echo 'export PATH=$PATH:/media/cdrom/nfrouter' > /rootfs_squash/etc/profile.d/nfrouter_path.sh
# RUN chmod +x /rootfs_squash/etc/profile.d/nfrouter_path.sh
# Unpack initramfs-lts
RUN mkdir -p /initramfs_extracted && \
    cd /initramfs_extracted && \
    gzip -dc /iso_temp/boot/initramfs-lts | cpio -idmv

# Add nfrouter directly to /usr/bin
COPY target/x86_64-unknown-linux-musl/release/nfrouter /initramfs_extracted/nfrouter
RUN chmod +x /initramfs_extracted/nfrouter
COPY iso-builder/install_nfrouter.sh /initramfs_extracted/usr/bin/install-nfrouter

# Repack initramfs-lts
RUN sed -i '/exec switch_root/i mkdir -p \/sysroot\/usr\/bin \&\& cp \/nfrouter \/sysroot\/nfrouter \&\& cp \/usr\/bin\/install-nfrouter \/sysroot\/usr\/bin\/install-nfrouter' /initramfs_extracted/init


# Repack initramfs-lts
RUN cd /initramfs_extracted && \
    find . | cpio -H newc -o | gzip -9 > /iso_temp/boot/initramfs-lts

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
