.PHONY: all
all:
	mkdir -p fs/dev
	mkdir -p fs/proc
	mkdir -p fs/sys
	rm fs/init
	cd src/exfatid && make
	cd src/espid && make
	cd src/bootstrap && make
	cd src/init && make
	cd fs && find | cpio -H newc -o > ../init.cpio
	make -C linux -j`nproc`

.PHONY: disk
disk: all
	cd disk && dev=$$(sudo losetup -fP --show disk.img) && sudo mount "$${dev}p1" /mnt && sudo cp ../linux/arch/x86/boot/bzImage /mnt/iso/Arch.efi && sudo umount /mnt && sudo losetup -d "$$dev"

.PHONY: test
test: all
	cd disk && qemu-system-x86_64 --enable-kvm --machine q35,accel=kvm -cpu host -m 8192 -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/x64/OVMF_CODE.4m.fd -drive if=pflash,format=raw,file=OVMF_VARS.4m.fd -drive file=disk.img,format=raw,if=virtio -serial mon:stdio -boot menu=on
