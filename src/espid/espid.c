#define O_RDONLY 0
#define DT_BLK 6
#define SEEK_SET 0

typedef unsigned long size_t;
typedef long ssize_t;
typedef long off_t;
typedef unsigned long uint64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef long int64_t;
typedef int int32_t;
typedef short int16_t;
typedef signed char int8_t;
#define NULL ((void *)0)

// Syscall prototypes
long sys_open(const char *path, int flags, int mode);
ssize_t sys_read(int fd, void *buf, size_t count);
int sys_close(int fd);
long sys_getdents64(int fd, void *dirp, size_t count);
ssize_t sys_write(int fd, const void *buf, size_t count);
void sys_exit(int code);
off_t sys_lseek(int fd, off_t offset, int whence);
int sys_fsync(int fd);

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

// GPT Header (LBA 1)
struct gpt_header {
    uint8_t  signature[8];      // "EFI PART"
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t my_lba;
    uint64_t alternate_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t  disk_guid[16];
    uint64_t partition_entry_lba;
    uint32_t num_partition_entries;
    uint32_t partition_entry_size;
    uint32_t partition_array_crc32;
};

// GPT Partition Entry (128 bytes each)
struct gpt_partition {
    uint8_t  type_guid[16];
    uint8_t  unique_guid[16];
    uint64_t starting_lba;
    uint64_t ending_lba;
    uint64_t attributes;
    uint16_t name[36];          // UTF-16LE
};

// EFI System Partition GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
// Stored in little-endian mixed format
static const uint8_t ESP_GUID[16] = {
    0x28, 0x73, 0x2a, 0xc1,  // little-endian uint32_t
    0x1f, 0xf8,              // little-endian uint16_t
    0xd2, 0x11,              // little-endian uint16_t
    0xba, 0x4b,              // big-endian (byte array)
    0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b
};

static size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

static char *strcat(char *dest, const char *src) {
    char *d = dest + strlen(dest);
    while ((*d++ = *src++));
    return dest;
}

static int memcmp(const void *a, const void *b, int n) {
    const uint8_t *p = a, *q = b;
    for (int i = 0; i < n; i++) {
        if (p[i] != q[i]) return 1;
    }
    return 0;
}

static void memset(void *dst, int c, size_t n) {
    uint8_t *p = dst;
    while (n--) *p++ = c;
}

static void print(const char *s) {
    sys_write(1, s, strlen(s));
    sys_fsync(1);
}

static int is_fat32_partition(int disk_fd, uint64_t start_lba) {
    uint8_t buf[512];
    
    if (sys_lseek(disk_fd, start_lba * 512, SEEK_SET) < 0) return 0;
    if (sys_read(disk_fd, buf, 512) != 512) return 0;
    
    // Check boot signature
    if (buf[510] != 0x55 || buf[511] != 0xAA) return 0;
    
    // Check FAT32 string at offset 82
    if (memcmp(&buf[82], "FAT32   ", 8) == 0) return 1;
    
    // Alternative check: sectors_per_fat_32 non-zero and sectors_per_fat_16 zero
    uint32_t spf32 = buf[36] | (buf[37] << 8) | (buf[38] << 16) | (buf[39] << 24);
    uint16_t spf16 = buf[22] | (buf[23] << 8);
    if (spf32 > 0 && spf16 == 0) return 1;
    
    return 0;
}

static char* scandisk(char *disk_path) {
    uint8_t buf[512];
    struct gpt_header hdr;
    struct gpt_partition part;
    
    int fd = sys_open(disk_path, O_RDONLY, 0);
    if (fd < 0) return NULL;
    
    // Read protective MBR (LBA 0) and verify
    if (sys_read(fd, buf, 512) != 512) goto done;
    if (buf[510] != 0x55 || buf[511] != 0xAA) goto done;
    
    // Check for GPT protective MBR (partition type 0xEE)
    int has_gpt = 0;
    for (int i = 0; i < 4; i++) {
        if (buf[446 + i*16 + 4] == 0xEE) {
            has_gpt = 1;
            break;
        }
    }
    if (!has_gpt) goto done;
    
    // Read GPT header (LBA 1)
    if (sys_lseek(fd, 512, SEEK_SET) < 0) goto done;
    if (sys_read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) goto done;
    
    // Verify GPT signature
    if (memcmp(hdr.signature, "EFI PART", 8) != 0) goto done;
    
    // Read partition entries
    uint64_t part_lba = hdr.partition_entry_lba;
    uint32_t num_entries = hdr.num_partition_entries;
    uint32_t entry_size = hdr.partition_entry_size;
    
    if (entry_size < sizeof(struct gpt_partition)) goto done;
    
    for (uint32_t i = 0; i < num_entries; i++) {
        off_t offset = part_lba * 512 + i * entry_size;
        if (sys_lseek(fd, offset, SEEK_SET) < 0) break;
        
        memset(&part, 0, sizeof(part));
        if (sys_read(fd, &part, sizeof(part)) != sizeof(part)) break;
        
        // Check if partition is empty (all zeros in type GUID)
        int empty = 1;
        for (int j = 0; j < 16; j++) {
            if (part.type_guid[j] != 0) { empty = 0; break; }
        }
        if (empty) continue;
        
        // Check if it's an ESP partition
        if (memcmp(part.type_guid, ESP_GUID, 16) != 0) continue;
        
        // Verify it has FAT32 filesystem
        if (!is_fat32_partition(fd, part.starting_lba)) continue;

        sys_close(fd);
        strcat(disk_path, "p");
        disk_path[strlen(disk_path)] = '0' + i + 1;
        return disk_path;
    }
done:
    sys_close(fd);
    return NULL;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        sys_write(2, "Usage: espid /dev/loop0\n", 25);
        return -1;
    }

    int fd = sys_open("/dev", O_RDONLY, 0);
    if (fd < 0) {
        return -1;
    }

    char path[256];
    char dirent_buf[4096];
    int nread;
    struct linux_dirent64 *d;
    while ((nread = sys_getdents64(fd, dirent_buf, sizeof(dirent_buf))) > 0) {
        for (int pos = 0; pos < nread; ) {
            d = (struct linux_dirent64 *)(dirent_buf + pos);
            if (d->d_type == DT_BLK) {
                strcpy(path, "/dev/");
                strcat(path, d->d_name);
                if (!memcmp(path, argv[1], strlen(argv[1])) && scandisk(path)) {
                    print(path);
                }
            }
            pos += d->d_reclen;
        }
    }

    return 0;
}

