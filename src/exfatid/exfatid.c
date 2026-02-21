typedef long off_t;
typedef long ssize_t;
typedef unsigned long size_t;

int sys_open(const char *pathname, int flags, int mode);
off_t sys_lseek(int fd, off_t offset, int whence);
ssize_t sys_write(int fd, const void *buf, size_t count);
ssize_t sys_read(int fd, void *buf, size_t count);
int sys_close(int fd);
void sys_exit(int rv);

#define O_RDONLY    0
#define SEEK_SET    0

int main(int argc, char** argv) {
    int fd;
    unsigned char buf[4];
    
    if (argc != 2) {
        sys_write(2, "Usage: exfatid /dev/vda1\n", 24);
        return -1;
    }

    fd = sys_open(argv[1], O_RDONLY, 0);
    if (fd < 0) {
        sys_write(2, "open failed\n", 13);
        return -1;
    }
    
    if (sys_lseek(fd, 100, SEEK_SET) != 100) {
        sys_write(2, "lseek failed\n", 14);
        sys_close(fd);
        return -1;
    }
    
    if (sys_read(fd, buf, 4) != 4) {
        sys_write(2, "read failed\n", 13);
        sys_close(fd);
        return -1;
    }
    sys_close(fd);
    
    const char *hex = "0123456789ABCDEF-";
    sys_write(1, hex + ((buf[3] >> 4) & 0xf), 1);
    sys_write(1, hex + (buf[3] & 0xf), 1);
    sys_write(1, hex + ((buf[2] >> 4) & 0xf), 1);
    sys_write(1, hex + (buf[2] & 0xf), 1);
    sys_write(1, hex + 16, 1);
    sys_write(1, hex + ((buf[1] >> 4) & 0xf), 1);
    sys_write(1, hex + (buf[1] & 0xf), 1);
    sys_write(1, hex + ((buf[0] >> 4) & 0xf), 1);
    sys_write(1, hex + (buf[0] & 0xf), 1);
    sys_write(1, 0, 1);
    
    return 0;
}

