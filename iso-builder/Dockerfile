# Dockerfile
FROM alpine:latest

# Install necessary tools
RUN apk add --no-cache wget xorriso syslinux e2fsprogs

# Download the standard Alpine ISO
RUN wget -O /alpine-standard.iso https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-standard-3.20.2-x86_64.iso

# Create directories for mounting and extraction
#RUN mkdir /mnt/iso /mnt/newiso /overlay


# Create a directory for extraction
RUN mkdir /iso_temp
# Extract the ISO contents using xorriso
RUN xorriso -osirrox on -indev /alpine-standard.iso -extract / /iso_temp || (echo "ISO extraction failed" && exit 1)

# List the contents of /iso_temp to verify extraction
RUN echo "Contents of /iso_temp after extraction:" && ls -l /iso_temp

# Verify bootloader files
RUN find /iso_temp -name isolinux.bin -exec ls -l {} \; || echo "isolinux.bin not found"

# # Mount the ISO and copy its contents
# RUN mkdir /iso_temp && \
#     mount -o loop /alpine-standard.iso /mnt/iso && \
#     cp -r /mnt/iso/* /iso_temp/ && \
#     umount /mnt/iso

# Copy the nfrouter executable and installation script into the overlay 
# We are using debug build for the time being
COPY target/x86_64-unknown-linux-musl/release/nfrouter /iso_temp/nfrouter
COPY iso-builder/answerfile /iso_temp/answerfile
COPY iso-builder/install_nfrouter.sh /iso_temp/install_nfrouter.sh


# Make the installation script executable
RUN chmod +x /iso_temp/install_nfrouter.sh

# Verify bootloader files
RUN find /iso_temp -name install_nfrouter.sh -exec ls -l {} \; || echo "install_nfrouter.sh not found"
# Copy the dnsmasq and frr apk packages into the ISO


# Modify isolinux.cfg to automatically boot and run the installation script
#RUN sed -i 's/DEFAULT menu.c32/DEFAULT install_nfrouter/' /iso_temp/boot/isolinux/isolinux.cfg && \
#    echo -e '\nLABEL install_nfrouter\n  MENU LABEL Install Alpine with nfrouter\n  KERNEL /boot/vmlinuz-lts\n  INITRD /boot/initramfs-lts\n  APPEND modules=loop,squashfs,sd-mod,usb-storage,ext4 modloop=/boot/modloop-lts init=/install_nfrouter.sh' >> /iso_temp/boot/isolinux/isolinux.cfg

# Extract the ISO contents using xorriso


# List the contents to verify extraction
RUN echo "Contents of /iso_temp/:" && ls -l /iso_temp/
RUN echo "Contents of /iso_temp/boot:" && ls -l /iso_temp/boot
RUN echo "Contents of /iso_temp/boot/grub:" && ls -l /iso_temp/boot/grub


# Repack the ISO using Syslinux bootloader files
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
