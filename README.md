# ntfs-volume-manager

This focuses on infrastructure that allows using an NTFS partition like a
volume manager. NTFS supports snapshots. Ventoy can be used as a bootloader,
as it knows how to boot VHD files containing Windows, so booting Windows is
solved like that, while it can also start EFI applications, and such
applications can be the Linux kernel, so it also addresses this part. Storing
the OSes in raw disk files has the advantage that it allows for more flexible
space allocation, while also making it easier to roam the OSes between
machines. It is an interesting experiment imo which I am daily driving.

Generate EFI file that can boot a UKI and which should be presented in
Ventoy's boot menu. The goal is to have all OSs (Windows and Linux flavours,
at present only Arch is tested) on an NTFS partition as fixed size VHDs (which
are just raw disk images with a 512-byte footer, really simple).

Ventoy can directly boot VHDs containing Windows, so booting Windows is taken
care of. Partition has to be NTFS or exFAT, I chose NTFS because it is natively
supported by Linux as well, and doesn't show an ugly warning at boot and is
more resilient and supports snapshots.

For Linux, one has to create a small bootstraper - Ventoy can also launch EFI
applications, and in this case, the Linux kernel is compiled as an EFI
application. What it does, is it searches the disk for an image hardcoded in
its init (check out `src/init`), mounts that with `losetup`, and kexecs the
kernel from there, specifying a custom init that does the same thing in the
kexecd kernel before handing everything off to the init in the original system.
This way, as opposed to Ventoy's method, no crap has to be installed in the
target distro, it can be largely untouched, provided that its initrd loads the
modules that are required to locate and `losetup` the image. On Arch, such
thing can be done by specifying things in the initcpio like this:

```
MODULES=(loop ntfs3)
```

That's largely it. That file stays put during upgrades, and no kernel modules
or other hooks are necessary, everything is done from the prepared bootstrapper
largely. Before kexecing the new kernel, it also takes care to enable DirectIO
on the loop device. Kexecing is done via a tiny C application that parses the
UKI of the kernel to boot - yes, another prerequisite (for now) is that the
kernel to be booted is an UKI. With a different `src/bootstrap`, other types
of images could be supported, but I use UKI so that is what is in for now.

Folder `kconfig` contains some kernel config examples. The kernel to be built
should be placed in a folder called `linux` in the root of the repo.

Folder `snap` contains a script that reboots Linux at a specific time, and
changes the bootorder to have Windows boot next time from Ventoy. That install
should snapshot the disk, and then reboot or turn off the PC. This is to
ensure, in case diaster strikes, that you have a quick way of reverting to
some working state quickly. Regular backups should be made as well though, this
just spares you from reconfiguring everything in case you mess something up.

`raw2vhd` is a script that converts any raw disk image to a VHD. The conversion
is done in place, and is instantaneous. What it does, it appends a 512-byte
section at the end of the raw disk image, magically converting it to a raw
fixed size VHD from which Windows can be booted. It should be used after
enlarging the VHD file using the usual commands like `truncate`. Then, once
booted, you can grow the partition and enlarge the file system in Windows.
The VHD can also be booted just fine with qemu, which sees it as a raw disk,
which is fine. When you want to enlarge the disk, simply enlarge the file,
then recreate the VHD footer with this script, so as to be able to still boot
from Ventoy.

User space of this is made up with precompiled binaries from Alpine Linux
(BusyBox), as showcased by Nir Lichtman. I recommend these videos from him:

* https://www.youtube.com/watch?v=vPU1j8aCD-w
* https://www.youtube.com/watch?v=u2Juz5sQyYQ

The initrd of this bootstraper should be placed in a folder called `fs` in the
root folder. For reference, it should contain something like:

```
fs
├── bin
│   ├── [ -> /bin/busybox
│   ├── [[ -> /bin/busybox
│   ├── acpid -> /bin/busybox
│   ├── addgroup -> /bin/busybox
│   ├── add-shell -> /bin/busybox
│   ├── adduser -> /bin/busybox
│   ├── adjtimex -> /bin/busybox
│   ├── arch -> /bin/busybox
│   ├── arp -> /bin/busybox
│   ├── arping -> /bin/busybox
│   ├── ash -> /bin/busybox
│   ├── awk -> /bin/busybox
│   ├── base64 -> /bin/busybox
│   ├── basename -> /bin/busybox
│   ├── bbconfig -> /bin/busybox
│   ├── bc -> /bin/busybox
│   ├── beep -> /bin/busybox
│   ├── blkdiscard -> /bin/busybox
│   ├── blkid -> /bin/busybox
│   ├── blockdev -> /bin/busybox
│   ├── bootstrap
│   ├── brctl -> /bin/busybox
│   ├── bunzip2 -> /bin/busybox
│   ├── busybox
│   ├── bzcat -> /bin/busybox
│   ├── bzip2 -> /bin/busybox
│   ├── cal -> /bin/busybox
│   ├── cat -> /bin/busybox
│   ├── chattr -> /bin/busybox
│   ├── chgrp -> /bin/busybox
│   ├── chmod -> /bin/busybox
│   ├── chown -> /bin/busybox
│   ├── chpasswd -> /bin/busybox
│   ├── chroot -> /bin/busybox
│   ├── chvt -> /bin/busybox
│   ├── cksum -> /bin/busybox
│   ├── clear -> /bin/busybox
│   ├── cmp -> /bin/busybox
│   ├── comm -> /bin/busybox
│   ├── cp -> /bin/busybox
│   ├── cpio -> /bin/busybox
│   ├── crond -> /bin/busybox
│   ├── crontab -> /bin/busybox
│   ├── cryptpw -> /bin/busybox
│   ├── cut -> /bin/busybox
│   ├── date -> /bin/busybox
│   ├── dc -> /bin/busybox
│   ├── dd -> /bin/busybox
│   ├── deallocvt -> /bin/busybox
│   ├── delgroup -> /bin/busybox
│   ├── deluser -> /bin/busybox
│   ├── depmod -> /bin/busybox
│   ├── df -> /bin/busybox
│   ├── diff -> /bin/busybox
│   ├── dirname -> /bin/busybox
│   ├── dmesg -> /bin/busybox
│   ├── dnsdomainname -> /bin/busybox
│   ├── dos2unix -> /bin/busybox
│   ├── du -> /bin/busybox
│   ├── dumpkmap -> /bin/busybox
│   ├── echo -> /bin/busybox
│   ├── egrep -> /bin/busybox
│   ├── eject -> /bin/busybox
│   ├── env -> /bin/busybox
│   ├── espid
│   ├── ether-wake -> /bin/busybox
│   ├── exfatid
│   ├── expand -> /bin/busybox
│   ├── expr -> /bin/busybox
│   ├── factor -> /bin/busybox
│   ├── fallocate -> /bin/busybox
│   ├── false -> /bin/busybox
│   ├── fatattr -> /bin/busybox
│   ├── fbset -> /bin/busybox
│   ├── fbsplash -> /bin/busybox
│   ├── fdflush -> /bin/busybox
│   ├── fdisk -> /bin/busybox
│   ├── fgrep -> /bin/busybox
│   ├── find -> /bin/busybox
│   ├── findfs -> /bin/busybox
│   ├── flock -> /bin/busybox
│   ├── fold -> /bin/busybox
│   ├── free -> /bin/busybox
│   ├── fsck -> /bin/busybox
│   ├── fstrim -> /bin/busybox
│   ├── fsync -> /bin/busybox
│   ├── fuser -> /bin/busybox
│   ├── getopt -> /bin/busybox
│   ├── getty -> /bin/busybox
│   ├── grep -> /bin/busybox
│   ├── groups -> /bin/busybox
│   ├── gunzip -> /bin/busybox
│   ├── gzip -> /bin/busybox
│   ├── halt -> /bin/busybox
│   ├── hd -> /bin/busybox
│   ├── head -> /bin/busybox
│   ├── hexdump -> /bin/busybox
│   ├── hostid -> /bin/busybox
│   ├── hostname -> /bin/busybox
│   ├── hwclock -> /bin/busybox
│   ├── id -> /bin/busybox
│   ├── ifconfig -> /bin/busybox
│   ├── ifdown -> /bin/busybox
│   ├── ifenslave -> /bin/busybox
│   ├── ifup -> /bin/busybox
│   ├── init -> /bin/busybox
│   ├── inotifyd -> /bin/busybox
│   ├── insmod -> /bin/busybox
│   ├── install -> /bin/busybox
│   ├── ionice -> /bin/busybox
│   ├── iostat -> /bin/busybox
│   ├── ip -> /bin/busybox
│   ├── ipaddr -> /bin/busybox
│   ├── ipcalc -> /bin/busybox
│   ├── ipcrm -> /bin/busybox
│   ├── ipcs -> /bin/busybox
│   ├── iplink -> /bin/busybox
│   ├── ipneigh -> /bin/busybox
│   ├── iproute -> /bin/busybox
│   ├── iprule -> /bin/busybox
│   ├── iptunnel -> /bin/busybox
│   ├── kbd_mode -> /bin/busybox
│   ├── kill -> /bin/busybox
│   ├── killall -> /bin/busybox
│   ├── killall5 -> /bin/busybox
│   ├── klogd -> /bin/busybox
│   ├── last -> /bin/busybox
│   ├── less -> /bin/busybox
│   ├── link -> /bin/busybox
│   ├── linux32 -> /bin/busybox
│   ├── linux64 -> /bin/busybox
│   ├── ln -> /bin/busybox
│   ├── loadfont -> /bin/busybox
│   ├── loadkmap -> /bin/busybox
│   ├── logger -> /bin/busybox
│   ├── login -> /bin/busybox
│   ├── logread -> /bin/busybox
│   ├── losetup -> /bin/busybox
│   ├── ls -> /bin/busybox
│   ├── lsattr -> /bin/busybox
│   ├── lsmod -> /bin/busybox
│   ├── lsof -> /bin/busybox
│   ├── lsusb -> /bin/busybox
│   ├── lzcat -> /bin/busybox
│   ├── lzma -> /bin/busybox
│   ├── lzop -> /bin/busybox
│   ├── lzopcat -> /bin/busybox
│   ├── makemime -> /bin/busybox
│   ├── md5sum -> /bin/busybox
│   ├── mdev -> /bin/busybox
│   ├── mesg -> /bin/busybox
│   ├── microcom -> /bin/busybox
│   ├── mkdir -> /bin/busybox
│   ├── mkdosfs -> /bin/busybox
│   ├── mkfifo -> /bin/busybox
│   ├── mkfs.vfat -> /bin/busybox
│   ├── mknod -> /bin/busybox
│   ├── mkpasswd -> /bin/busybox
│   ├── mkswap -> /bin/busybox
│   ├── mktemp -> /bin/busybox
│   ├── modinfo -> /bin/busybox
│   ├── modprobe -> /bin/busybox
│   ├── more -> /bin/busybox
│   ├── mount -> /bin/busybox
│   ├── mountpoint -> /bin/busybox
│   ├── mpstat -> /bin/busybox
│   ├── mv -> /bin/busybox
│   ├── nameif -> /bin/busybox
│   ├── nanddump -> /bin/busybox
│   ├── nandwrite -> /bin/busybox
│   ├── nbd-client -> /bin/busybox
│   ├── nc -> /bin/busybox
│   ├── netstat -> /bin/busybox
│   ├── nice -> /bin/busybox
│   ├── nl -> /bin/busybox
│   ├── nmeter -> /bin/busybox
│   ├── nohup -> /bin/busybox
│   ├── nologin -> /bin/busybox
│   ├── nproc -> /bin/busybox
│   ├── nsenter -> /bin/busybox
│   ├── nslookup -> /bin/busybox
│   ├── ntpd -> /bin/busybox
│   ├── od -> /bin/busybox
│   ├── openvt -> /bin/busybox
│   ├── partprobe -> /bin/busybox
│   ├── passwd -> /bin/busybox
│   ├── paste -> /bin/busybox
│   ├── pgrep -> /bin/busybox
│   ├── pidof -> /bin/busybox
│   ├── ping -> /bin/busybox
│   ├── ping6 -> /bin/busybox
│   ├── pipe_progress -> /bin/busybox
│   ├── pivot_root -> /bin/busybox
│   ├── pkill -> /bin/busybox
│   ├── pmap -> /bin/busybox
│   ├── poweroff -> /bin/busybox
│   ├── printenv -> /bin/busybox
│   ├── printf -> /bin/busybox
│   ├── ps -> /bin/busybox
│   ├── pscan -> /bin/busybox
│   ├── pstree -> /bin/busybox
│   ├── pwd -> /bin/busybox
│   ├── pwdx -> /bin/busybox
│   ├── raidautorun -> /bin/busybox
│   ├── rdate -> /bin/busybox
│   ├── rdev -> /bin/busybox
│   ├── readahead -> /bin/busybox
│   ├── readlink -> /bin/busybox
│   ├── realpath -> /bin/busybox
│   ├── reboot -> /bin/busybox
│   ├── reformime -> /bin/busybox
│   ├── remove-shell -> /bin/busybox
│   ├── renice -> /bin/busybox
│   ├── reset -> /bin/busybox
│   ├── resize -> /bin/busybox
│   ├── rev -> /bin/busybox
│   ├── rfkill -> /bin/busybox
│   ├── rm -> /bin/busybox
│   ├── rmdir -> /bin/busybox
│   ├── rmmod -> /bin/busybox
│   ├── route -> /bin/busybox
│   ├── run-parts -> /bin/busybox
│   ├── sed -> /bin/busybox
│   ├── sendmail -> /bin/busybox
│   ├── seq -> /bin/busybox
│   ├── setconsole -> /bin/busybox
│   ├── setfont -> /bin/busybox
│   ├── setkeycodes -> /bin/busybox
│   ├── setlogcons -> /bin/busybox
│   ├── setpriv -> /bin/busybox
│   ├── setserial -> /bin/busybox
│   ├── setsid -> /bin/busybox
│   ├── sh -> /bin/busybox
│   ├── sha1sum -> /bin/busybox
│   ├── sha256sum -> /bin/busybox
│   ├── sha3sum -> /bin/busybox
│   ├── sha512sum -> /bin/busybox
│   ├── showkey -> /bin/busybox
│   ├── shred -> /bin/busybox
│   ├── shuf -> /bin/busybox
│   ├── slattach -> /bin/busybox
│   ├── sleep -> /bin/busybox
│   ├── sort -> /bin/busybox
│   ├── split -> /bin/busybox
│   ├── stat -> /bin/busybox
│   ├── strings -> /bin/busybox
│   ├── stty -> /bin/busybox
│   ├── su -> /bin/busybox
│   ├── sum -> /bin/busybox
│   ├── swapoff -> /bin/busybox
│   ├── swapon -> /bin/busybox
│   ├── switch_root -> /bin/busybox
│   ├── sync -> /bin/busybox
│   ├── sysctl -> /bin/busybox
│   ├── syslogd -> /bin/busybox
│   ├── tac -> /bin/busybox
│   ├── tail -> /bin/busybox
│   ├── tar -> /bin/busybox
│   ├── tee -> /bin/busybox
│   ├── test -> /bin/busybox
│   ├── time -> /bin/busybox
│   ├── timeout -> /bin/busybox
│   ├── top -> /bin/busybox
│   ├── touch -> /bin/busybox
│   ├── tr -> /bin/busybox
│   ├── traceroute -> /bin/busybox
│   ├── traceroute6 -> /bin/busybox
│   ├── tree -> /bin/busybox
│   ├── true -> /bin/busybox
│   ├── truncate -> /bin/busybox
│   ├── tty -> /bin/busybox
│   ├── ttysize -> /bin/busybox
│   ├── tunctl -> /bin/busybox
│   ├── udhcpc -> /bin/busybox
│   ├── udhcpc6 -> /bin/busybox
│   ├── umount -> /bin/busybox
│   ├── uname -> /bin/busybox
│   ├── unexpand -> /bin/busybox
│   ├── uniq -> /bin/busybox
│   ├── unix2dos -> /bin/busybox
│   ├── unlink -> /bin/busybox
│   ├── unlzma -> /bin/busybox
│   ├── unlzop -> /bin/busybox
│   ├── unshare -> /bin/busybox
│   ├── unxz -> /bin/busybox
│   ├── unzip -> /bin/busybox
│   ├── uptime -> /bin/busybox
│   ├── usleep -> /bin/busybox
│   ├── uudecode -> /bin/busybox
│   ├── uuencode -> /bin/busybox
│   ├── vconfig -> /bin/busybox
│   ├── vi -> /bin/busybox
│   ├── vlock -> /bin/busybox
│   ├── volname -> /bin/busybox
│   ├── watch -> /bin/busybox
│   ├── watchdog -> /bin/busybox
│   ├── wc -> /bin/busybox
│   ├── wget -> /bin/busybox
│   ├── which -> /bin/busybox
│   ├── who -> /bin/busybox
│   ├── whoami -> /bin/busybox
│   ├── whois -> /bin/busybox
│   ├── xargs -> /bin/busybox
│   ├── xxd -> /bin/busybox
│   ├── xzcat -> /bin/busybox
│   ├── yes -> /bin/busybox
│   ├── zcat -> /bin/busybox
│   └── zcip -> /bin/busybox
├── boot
├── dev
├── etc
│   ├── busybox-paths.d
│   │   └── busybox
│   ├── logrotate.d
│   │   └── acpid
│   ├── network
│   │   ├── if-down.d
│   │   ├── if-post-down.d
│   │   ├── if-post-up.d
│   │   ├── if-pre-down.d
│   │   ├── if-pre-up.d
│   │   └── if-up.d
│   │       └── dad
│   ├── securetty
│   └── udhcpc
│       └── udhcpc.conf
├── init
├── lib
│   ├── ld-musl-x86_64.so.1
│   └── libc.musl-x86_64.so.1 -> ld-musl-x86_64.so.1
├── proc
├── sbin
├── sys
└── usr
    ├── sbin
    └── share
        └── udhcpc
            └── default.script

23 directories, 317 files
```

How to obtain this structure is explained in one of the videos above.
Basically, download busybox and muslc from Alpine Linux, and extract them
on top of `fs` folder in this repo. Symlinks for busybox are already created.

