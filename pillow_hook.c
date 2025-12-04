/*
 * pillow_hook.c - Combined LD_PRELOAD library for faking pillow USB devices
 *
 * This combines:
 * 1. udev hooks - fake USB device attributes for PTY serial devices
 * 2. open() hooks - redirect /dev/ttyUSB* opens to PTYs
 * 3. PTY management - create and manage fake pillow PTYs
 *
 * Compile (cross-compile for aarch64):
 *   aarch64-linux-gnu-gcc -shared -fPIC -o pillow_hook.so pillow_hook.c -ldl -lutil -pthread
 *
 * Usage:
 *   export PILLOW_HOOK_CONFIG="left:1:1.3.4,right:1:1.3.1"
 *   export PILLOW_HOOK_LOG="/tmp/pillow_hook.log"
 *   LD_PRELOAD=/path/to/pillow_hook.so /path/to/frankenfirmware
 *
 * Config format: side:busnum:devpath,side:busnum:devpath
 *   side = "left" or "right"
 *   busnum = USB bus number (e.g., "1")
 *   devpath = USB device path (e.g., "1.3.4")
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <termios.h>
#include <pty.h>
#include <pthread.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <dirent.h>

/* Bridge protocol - must match pillow_bridge.c */
#define MSG_DATA        0x00  /* Raw serial data */
#define MSG_BAUD        0x01  /* Baud rate change */
#define MSG_CONNECTED   0x02  /* Device connected */
#define MSG_DISCONNECTED 0x03 /* Device disconnected */
#define CHAN_LEFT   0x00
#define CHAN_RIGHT  0x01

/* Bridge connection config - Pod5 where physical pillows are connected */
#define BRIDGE_HOST "192.168.1.209"
#define BRIDGE_PORT 5580

/* Linux dirent64 structure for getdents64 syscall */
struct linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

/* Forward declare udev types as opaque pointers */
struct udev;
struct udev_device;
struct udev_enumerate;
struct udev_list_entry;

/* Handle for dynamically loaded libudev */
static void* libudev_handle = NULL;

/* ============================================================================
 * Configuration and State
 * ============================================================================ */

#define MAX_FAKE_DEVICES 4
#define MAX_PATH_LEN 256
#define LOG_BUF_SIZE 4096

typedef struct {
    char side[16];           /* "left" or "right" */
    char busnum[16];         /* e.g., "1" */
    char devpath[64];        /* e.g., "1.3.4" */
    char devnode[MAX_PATH_LEN];  /* e.g., "/dev/ttyUSB0" */
    int master_fd;           /* PTY master fd */
    int slave_fd;            /* PTY slave fd */
    char slave_path[MAX_PATH_LEN]; /* PTY slave path, e.g., "/dev/pts/3" */
    int active;
    int frank_fd;            /* fd that frank has for this device */
} fake_pillow_t;

static fake_pillow_t fake_pillows[MAX_FAKE_DEVICES];
static int num_fake_pillows = 0;
static int initialized = 0;
static int initializing = 0;  /* Flag to prevent recursive init */
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Track device-label file fd to patch F08 -> H08 */
static int device_label_fd = -1;

/* Track inotify fd for debugging */
static int inotify_fd = -1;

/* Track current udev device being queried (thread-local) */
static __thread const char* current_devnode = NULL;
static __thread fake_pillow_t* current_fake = NULL;

/* Bridge connection state */
static int bridge_fd = -1;
static pthread_mutex_t bridge_mutex = PTHREAD_MUTEX_INITIALIZER;
static int bridge_connected = 0;
static int left_connected = 0;   /* Left pillow connected on bridge */
static int right_connected = 0;  /* Right pillow connected on bridge */

/* ============================================================================
 * Original Function Pointers
 * ============================================================================ */

/* libc */
static int (*real_open)(const char *path, int flags, ...) = NULL;
static int (*real_openat)(int dirfd, const char *path, int flags, ...) = NULL;
static int (*real_close)(int fd) = NULL;
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*real_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
static int (*real_stat)(const char *path, struct stat *buf) = NULL;
static int (*real_lstat)(const char *path, struct stat *buf) = NULL;
static int (*real___xstat)(int ver, const char *path, struct stat *buf) = NULL;
static int (*real___lxstat)(int ver, const char *path, struct stat *buf) = NULL;
static int (*real_fstatat)(int dirfd, const char *pathname, struct stat *buf, int flags) = NULL;
static DIR* (*real_opendir)(const char *name) = NULL;
static struct dirent* (*real_readdir)(DIR *dirp) = NULL;
static int (*real_closedir)(DIR *dirp) = NULL;
static int (*real_tcsetattr)(int fd, int actions, const struct termios *t) = NULL;
static int (*real_tcgetattr)(int fd, struct termios *t) = NULL;
static int (*real_ioctl)(int fd, unsigned long request, ...) = NULL;

/* inotify */
static int (*real_inotify_init)(void) = NULL;
static int (*real_inotify_init1)(int flags) = NULL;
static int (*real_inotify_add_watch)(int fd, const char *pathname, uint32_t mask) = NULL;

/* dlopen/dlsym */
static void* (*real_dlopen)(const char *filename, int flags) = NULL;
static void* (*real_dlsym)(void *handle, const char *symbol) = NULL;

/* udev */
static struct udev* (*real_udev_new)(void) = NULL;
static struct udev_enumerate* (*real_udev_enumerate_new)(struct udev *udev) = NULL;
static int (*real_udev_enumerate_add_match_subsystem)(struct udev_enumerate *enumerate, const char *subsystem) = NULL;
static int (*real_udev_enumerate_scan_devices)(struct udev_enumerate *enumerate) = NULL;
static struct udev_list_entry* (*real_udev_enumerate_get_list_entry)(struct udev_enumerate *enumerate) = NULL;
static struct udev_list_entry* (*real_udev_list_entry_get_next)(struct udev_list_entry *entry) = NULL;
static const char* (*real_udev_list_entry_get_name)(struct udev_list_entry *entry) = NULL;
static struct udev_device* (*real_udev_device_new_from_syspath)(struct udev *udev, const char *syspath) = NULL;
static const char* (*real_udev_device_get_devnode)(struct udev_device *dev) = NULL;
static const char* (*real_udev_device_get_sysattr_value)(struct udev_device *dev, const char *attr) = NULL;
static struct udev_device* (*real_udev_device_get_parent_with_subsystem_devtype)(
    struct udev_device *dev, const char *subsystem, const char *devtype) = NULL;
static void (*real_udev_device_unref)(struct udev_device *dev) = NULL;
static void (*real_udev_enumerate_unref)(struct udev_enumerate *enumerate) = NULL;
static void (*real_udev_unref)(struct udev *udev) = NULL;

/* ============================================================================
 * Fake Directory Tracking (used by fstatat, opendir, getdents64)
 * ============================================================================ */

#define MAX_FAKE_DIRS 16
typedef struct {
    int fd;              /* The real fd from opening /tmp or similar */
    int pillow_index;    /* Which pillow this is for */
    int is_tty_subdir;   /* Are we in the /tty subdir? */
    int entries_returned; /* How many entries have been returned via getdents64 */
    int active;
} fake_dir_fd_t;

static fake_dir_fd_t fake_dir_fds[MAX_FAKE_DIRS];
static int num_fake_dir_fds = 0;
static pthread_mutex_t fake_dir_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Find a fake dir entry by fd */
static fake_dir_fd_t* find_fake_dir_by_fd(int fd) {
    for (int i = 0; i < MAX_FAKE_DIRS; i++) {
        if (fake_dir_fds[i].active && fake_dir_fds[i].fd == fd) {
            return &fake_dir_fds[i];
        }
    }
    return NULL;
}

/* ============================================================================
 * Logging
 * ============================================================================ */

static void get_timestamp(char *buf, size_t len) {
    struct timeval tv;
    struct tm *tm_info;
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    snprintf(buf, len, "%02d:%02d:%02d.%03ld",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             tv.tv_usec / 1000);
}

static void hook_log(const char *fmt, ...) {
    if (!log_file) return;

    pthread_mutex_lock(&log_mutex);

    char ts[32];
    get_timestamp(ts, sizeof(ts));
    fprintf(log_file, "[%s] ", ts);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_file, fmt, ap);
    va_end(ap);

    fprintf(log_file, "\n");
    fflush(log_file);

    pthread_mutex_unlock(&log_mutex);
}

static void log_hex(const char *prefix, const unsigned char *data, size_t len) {
    if (!log_file || len == 0) return;

    pthread_mutex_lock(&log_mutex);

    char ts[32];
    get_timestamp(ts, sizeof(ts));
    fprintf(log_file, "[%s] %s (%zu bytes): ", ts, prefix, len);

    for (size_t i = 0; i < len && i < 128; i++) {
        fprintf(log_file, "%02x", data[i]);
    }
    if (len > 128) fprintf(log_file, "...");

    fprintf(log_file, "\n");
    fflush(log_file);

    pthread_mutex_unlock(&log_mutex);
}

/* ============================================================================
 * PTY Management
 * ============================================================================ */

static int create_pty_pair(fake_pillow_t *pillow) {
    int master_fd, slave_fd;
    char slave_name[MAX_PATH_LEN];

    hook_log("Creating PTY for side=%s...", pillow->side);

    if (openpty(&master_fd, &slave_fd, slave_name, NULL, NULL) < 0) {
        hook_log("ERROR: openpty() failed for %s: %s", pillow->side, strerror(errno));
        return -1;
    }
    hook_log("openpty() succeeded: master=%d, slave=%d, path=%s", master_fd, slave_fd, slave_name);
    fflush(log_file);

    /* Set non-blocking on master */
    hook_log("Setting non-blocking on master fd");
    fflush(log_file);
    int flags = fcntl(master_fd, F_GETFL, 0);
    hook_log("Got flags: %d", flags);
    fflush(log_file);
    fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
    hook_log("Set non-blocking done");
    fflush(log_file);

    /* Configure raw mode - use raw termios manipulation to avoid glibc version issues
     * Use real_tcgetattr directly to avoid hook recursion during init */
    hook_log("Getting termios");
    fflush(log_file);
    struct termios tty;
    if (real_tcgetattr) {
        real_tcgetattr(slave_fd, &tty);
    } else {
        /* Fallback if real_tcgetattr not yet loaded */
        hook_log("real_tcgetattr is NULL, trying direct call");
        fflush(log_file);
        extern int __tcgetattr(int fd, struct termios *t);
        __tcgetattr(slave_fd, &tty);
    }
    hook_log("Got termios");
    /* Raw mode flags */
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    tty.c_oflag &= ~OPOST;
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    tty.c_cflag &= ~(CSIZE | PARENB);
    tty.c_cflag |= CS8;
    /* Set baud rate directly in c_cflag/c_ispeed/c_ospeed - B921600 = 0x1007 on most systems */
    tty.c_cflag &= ~CBAUD;
    tty.c_cflag |= B921600;
    /* Use real_tcsetattr directly to avoid hook recursion during init */
    if (real_tcsetattr) {
        real_tcsetattr(slave_fd, TCSANOW, &tty);
    } else {
        extern int __tcsetattr(int fd, int optional_actions, const struct termios *t);
        __tcsetattr(slave_fd, TCSANOW, &tty);
    }

    pillow->master_fd = master_fd;
    pillow->slave_fd = slave_fd;
    strncpy(pillow->slave_path, slave_name, MAX_PATH_LEN - 1);

    hook_log("Created PTY for %s: master=%d, slave=%d, path=%s",
             pillow->side, master_fd, slave_fd, slave_name);

    return 0;
}

/* ============================================================================
 * Pillow Protocol Responder
 *
 * Responds to pillow protocol commands on the PTY master side.
 * This makes frank think pillows are connected.
 *
 * Protocol format:
 *   0x7e <length> <cmd> [payload] <crc16-msb> <crc16-lsb>
 *
 * Commands observed:
 *   0x01 - Status request (response: 0x81)
 * ============================================================================ */

/* CRC-16/CCITT table */
static const uint16_t crc16_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
};

static uint16_t calc_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc << 8) ^ crc16_table[(crc >> 8) ^ data[i]];
    }
    return crc;
}

/* Build a pillow response frame
 * Protocol: 7E [length] [type] [payload...] [crc16]
 * Length encoding:
 *   - If length <= 127: single byte
 *   - If length > 127: two bytes with high bit set on first byte (0x80 | hi, lo)
 * Length includes type byte only (not length bytes themselves) */
static int build_pillow_frame(uint8_t *buf, size_t bufsize, uint8_t cmd, const uint8_t *payload, size_t plen) {
    size_t content_len = 1 + plen;  /* type + payload */
    if (bufsize < 5 + plen) return -1;

    int idx = 0;
    buf[idx++] = 0x7e;  /* Start marker */

    /* Variable length encoding */
    if (content_len > 127) {
        /* Extended length format: high bit set, then 15-bit length */
        buf[idx++] = 0x80 | ((content_len >> 8) & 0x7F);
        buf[idx++] = content_len & 0xFF;
    } else {
        /* Short length format: single byte */
        buf[idx++] = content_len & 0x7F;
    }

    buf[idx++] = cmd;  /* type/command */
    if (plen > 0) {
        memcpy(&buf[idx], payload, plen);
        idx += plen;
    }

    /* Calculate CRC over length bytes + type + payload */
    uint16_t crc = calc_crc16(&buf[1], idx - 1);
    buf[idx++] = (crc >> 8) & 0xFF;  /* CRC high byte */
    buf[idx++] = crc & 0xFF;         /* CRC low byte */

    return idx;
}

/* ============================================================================
 * Bridge Forwarder Thread - forwards PTY data to/from Pod5 bridge
 * ============================================================================ */
static pthread_t responder_thread;
static int responder_running = 0;

/* Get channel number for a pillow side */
static int get_channel_for_side(const char *side) {
    if (strcmp(side, "left") == 0) return CHAN_LEFT;
    if (strcmp(side, "right") == 0) return CHAN_RIGHT;
    return -1;
}

/* Get pillow index for a channel */
static int get_pillow_for_channel(int channel) {
    const char *side = (channel == CHAN_LEFT) ? "left" : "right";
    for (int i = 0; i < num_fake_pillows; i++) {
        if (strcmp(fake_pillows[i].side, side) == 0) {
            return i;
        }
    }
    return -1;
}

/* Send a message to the bridge */
static int bridge_send(uint8_t type, uint8_t channel, const uint8_t *data, uint16_t len) {
    pthread_mutex_lock(&bridge_mutex);
    if (bridge_fd < 0) {
        pthread_mutex_unlock(&bridge_mutex);
        return -1;
    }

    uint8_t header[4];
    header[0] = type;
    header[1] = channel;
    header[2] = (len >> 8) & 0xFF;
    header[3] = len & 0xFF;

    ssize_t sent = write(bridge_fd, header, 4);
    if (sent != 4) {
        hook_log("BRIDGE: Failed to send header: %s", strerror(errno));
        pthread_mutex_unlock(&bridge_mutex);
        return -1;
    }

    if (len > 0 && data) {
        sent = write(bridge_fd, data, len);
        if (sent != len) {
            hook_log("BRIDGE: Failed to send data: %s", strerror(errno));
            pthread_mutex_unlock(&bridge_mutex);
            return -1;
        }
    }

    pthread_mutex_unlock(&bridge_mutex);
    return 0;
}

/* Send baud rate change to bridge */
static void bridge_send_baud(int channel, int baud) {
    uint8_t data[4];
    data[0] = (baud >> 24) & 0xFF;
    data[1] = (baud >> 16) & 0xFF;
    data[2] = (baud >> 8) & 0xFF;
    data[3] = baud & 0xFF;
    hook_log("BRIDGE: Sending baud=%d to channel=%d", baud, channel);
    bridge_send(MSG_BAUD, channel, data, 4);
}

/* Connect to the bridge */
static int bridge_connect(void) {
    hook_log("BRIDGE: Connecting to %s:%d...", BRIDGE_HOST, BRIDGE_PORT);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        hook_log("BRIDGE: socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(BRIDGE_PORT),
    };
    if (inet_pton(AF_INET, BRIDGE_HOST, &addr.sin_addr) != 1) {
        hook_log("BRIDGE: Invalid address: %s", BRIDGE_HOST);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        hook_log("BRIDGE: connect() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Set TCP_NODELAY for low latency */
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    /* Make non-blocking */
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    pthread_mutex_lock(&bridge_mutex);
    bridge_fd = fd;
    bridge_connected = 1;
    pthread_mutex_unlock(&bridge_mutex);

    hook_log("BRIDGE: Connected! fd=%d", fd);
    return 0;
}

/* Disconnect from bridge */
static void bridge_disconnect(void) {
    pthread_mutex_lock(&bridge_mutex);
    if (bridge_fd >= 0) {
        close(bridge_fd);
        bridge_fd = -1;
    }
    bridge_connected = 0;
    left_connected = 0;
    right_connected = 0;
    pthread_mutex_unlock(&bridge_mutex);
    hook_log("BRIDGE: Disconnected");
}

/* Main forwarder thread */
static void* pillow_responder(void* arg) {
    (void)arg;
    hook_log("BRIDGE: Forwarder thread started");

    uint8_t net_rxbuf[4096];
    int net_rxlen = 0;
    int reconnect_delay = 1;  /* seconds */

    while (responder_running) {
        /* Connect to bridge if not connected */
        if (!bridge_connected) {
            if (bridge_connect() < 0) {
                hook_log("BRIDGE: Connection failed, retry in %ds", reconnect_delay);
                sleep(reconnect_delay);
                if (reconnect_delay < 30) reconnect_delay *= 2;
                continue;
            }
            reconnect_delay = 1;
        }

        /* Build fd_set for select() */
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;

        pthread_mutex_lock(&bridge_mutex);
        if (bridge_fd >= 0) {
            FD_SET(bridge_fd, &rfds);
            if (bridge_fd > maxfd) maxfd = bridge_fd;
        }
        pthread_mutex_unlock(&bridge_mutex);

        for (int i = 0; i < num_fake_pillows; i++) {
            if (fake_pillows[i].active && fake_pillows[i].master_fd >= 0) {
                FD_SET(fake_pillows[i].master_fd, &rfds);
                if (fake_pillows[i].master_fd > maxfd) maxfd = fake_pillows[i].master_fd;
            }
        }

        if (maxfd < 0) {
            usleep(100000);
            continue;
        }

        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            hook_log("BRIDGE: select() error: %s", strerror(errno));
            bridge_disconnect();
            continue;
        }

        if (ret == 0) continue;  /* Timeout */

        /* Handle data from bridge */
        pthread_mutex_lock(&bridge_mutex);
        int bfd = bridge_fd;
        pthread_mutex_unlock(&bridge_mutex);

        if (bfd >= 0 && FD_ISSET(bfd, &rfds)) {
            ssize_t n = read(bfd, net_rxbuf + net_rxlen, sizeof(net_rxbuf) - net_rxlen);
            if (n <= 0) {
                if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    hook_log("BRIDGE: Connection lost");
                    bridge_disconnect();
                    net_rxlen = 0;
                    continue;
                }
            } else {
                net_rxlen += n;
                /* Per-packet logging disabled to reduce eMMC wear */

                /* Process complete messages */
                while (net_rxlen >= 4) {
                    uint8_t msg_type = net_rxbuf[0];
                    uint8_t channel = net_rxbuf[1];
                    uint16_t msg_len = (net_rxbuf[2] << 8) | net_rxbuf[3];

                    if (net_rxlen < 4 + (int)msg_len) {
                        break;  /* Incomplete message */
                    }

                    const char *ch_name = (channel == CHAN_LEFT) ? "left" : "right";

                    switch (msg_type) {
                        case MSG_DATA: {
                            /* Forward data to PTY master */
                            int idx = get_pillow_for_channel(channel);
                            if (idx >= 0 && fake_pillows[idx].master_fd >= 0) {
                                ssize_t written = write(fake_pillows[idx].master_fd,
                                                       net_rxbuf + 4, msg_len);
                                if (written < 0) {
                                    hook_log("BRIDGE: [%s] PTY write failed: %s",
                                             ch_name, strerror(errno));
                                }
                                /* Per-packet logging disabled to reduce eMMC wear */
                            }
                            break;
                        }

                        case MSG_CONNECTED:
                            hook_log("BRIDGE: [%s] Pillow connected on Pod5", ch_name);
                            if (channel == CHAN_LEFT) left_connected = 1;
                            else right_connected = 1;
                            break;

                        case MSG_DISCONNECTED:
                            hook_log("BRIDGE: [%s] Pillow disconnected on Pod5", ch_name);
                            if (channel == CHAN_LEFT) left_connected = 0;
                            else right_connected = 0;
                            break;

                        default:
                            hook_log("BRIDGE: Unknown message type 0x%02x", msg_type);
                            break;
                    }

                    /* Remove processed message */
                    int total = 4 + msg_len;
                    memmove(net_rxbuf, net_rxbuf + total, net_rxlen - total);
                    net_rxlen -= total;
                }
            }
        }

        /* Handle data from PTY masters -> forward to bridge */
        for (int i = 0; i < num_fake_pillows; i++) {
            if (!fake_pillows[i].active || fake_pillows[i].master_fd < 0)
                continue;

            if (FD_ISSET(fake_pillows[i].master_fd, &rfds)) {
                uint8_t buf[1024];
                ssize_t n = read(fake_pillows[i].master_fd, buf, sizeof(buf));
                if (n > 0) {
                    int channel = get_channel_for_side(fake_pillows[i].side);
                    if (channel >= 0) {
                        /* Per-packet logging disabled to reduce eMMC wear */
                        if (bridge_send(MSG_DATA, channel, buf, n) < 0) {
                            hook_log("BRIDGE: [%s] Failed to send to bridge",
                                     fake_pillows[i].side);
                        }
                    }
                } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    hook_log("BRIDGE: [%s] PTY read error: %s",
                             fake_pillows[i].side, strerror(errno));
                }
            }
        }
    }

    bridge_disconnect();
    hook_log("BRIDGE: Forwarder thread exiting");
    return NULL;
}

static void start_responder_thread(void) {
    if (responder_running) return;
    responder_running = 1;
    pthread_create(&responder_thread, NULL, pillow_responder, NULL);
}

static void stop_responder_thread(void) {
    if (!responder_running) return;
    responder_running = 0;
    pthread_join(responder_thread, NULL);
}

/* ============================================================================
 * Configuration Parsing
 * ============================================================================ */

static void parse_config(void) {
    const char* config = getenv("PILLOW_HOOK_CONFIG");
    if (!config) {
        hook_log("PILLOW_HOOK_CONFIG not set, using defaults");
        /* Default config for testing */
        config = "left:1:1.3.4,right:1:1.3.1";
    }

    hook_log("Parsing config: %s", config);
    fflush(log_file);

    char* config_copy = strdup(config);
    hook_log("Config copied, about to tokenize");
    char* saveptr1;
    char* token = strtok_r(config_copy, ",", &saveptr1);

    while (token && num_fake_pillows < MAX_FAKE_DEVICES) {
        hook_log("Processing token: %s", token);
        char* saveptr2;
        char* side = strtok_r(token, ":", &saveptr2);
        char* busnum = strtok_r(NULL, ":", &saveptr2);
        char* devpath = strtok_r(NULL, ":", &saveptr2);

        hook_log("Parsed: side=%s busnum=%s devpath=%s", side, busnum, devpath);

        if (side && busnum && devpath) {
            fake_pillow_t *p = &fake_pillows[num_fake_pillows];

            strncpy(p->side, side, sizeof(p->side) - 1);
            strncpy(p->busnum, busnum, sizeof(p->busnum) - 1);
            strncpy(p->devpath, devpath, sizeof(p->devpath) - 1);

            /* Assign device node based on side */
            if (strcmp(side, "left") == 0) {
                strncpy(p->devnode, "/dev/ttyUSB0", MAX_PATH_LEN - 1);
            } else if (strcmp(side, "right") == 0) {
                strncpy(p->devnode, "/dev/ttyUSB1", MAX_PATH_LEN - 1);
            } else {
                snprintf(p->devnode, MAX_PATH_LEN, "/dev/ttyUSB%d", num_fake_pillows);
            }

            p->master_fd = -1;
            p->slave_fd = -1;
            p->frank_fd = -1;
            p->active = 1;

            /* Create PTY pair - symlinks created later after inotify watch */
            if (create_pty_pair(p) == 0) {
                hook_log("Registered fake pillow: %s -> %s (busnum=%s, devpath=%s, pty=%s)",
                         p->side, p->devnode, p->busnum, p->devpath, p->slave_path);
                num_fake_pillows++;
            }
        }

        token = strtok_r(NULL, ",", &saveptr1);
    }

    free(config_copy);
    hook_log("Registered %d fake pillows", num_fake_pillows);
}

/* ============================================================================
 * Lookup Functions
 * ============================================================================ */

static fake_pillow_t* find_pillow_by_devnode(const char* devnode) {
    if (!devnode) return NULL;
    for (int i = 0; i < num_fake_pillows; i++) {
        if (fake_pillows[i].active && strcmp(fake_pillows[i].devnode, devnode) == 0) {
            return &fake_pillows[i];
        }
    }
    return NULL;
}

static fake_pillow_t* find_pillow_by_frank_fd(int fd) {
    for (int i = 0; i < num_fake_pillows; i++) {
        if (fake_pillows[i].active && fake_pillows[i].frank_fd == fd) {
            return &fake_pillows[i];
        }
    }
    return NULL;
}

static fake_pillow_t* find_pillow_by_busnum_devpath(const char* busnum, const char* devpath) {
    if (!busnum || !devpath) return NULL;
    for (int i = 0; i < num_fake_pillows; i++) {
        if (fake_pillows[i].active &&
            strcmp(fake_pillows[i].busnum, busnum) == 0 &&
            strcmp(fake_pillows[i].devpath, devpath) == 0) {
            return &fake_pillows[i];
        }
    }
    return NULL;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

static void load_real_functions(void) {
    /* dlopen - get the real implementation */
    real_dlopen = dlsym(RTLD_NEXT, "dlopen");

    /* libc functions */
    real_open = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_close = dlsym(RTLD_NEXT, "close");
    real_read = dlsym(RTLD_NEXT, "read");
    real_write = dlsym(RTLD_NEXT, "write");
    real_readlink = dlsym(RTLD_NEXT, "readlink");
    real_stat = dlsym(RTLD_NEXT, "stat");
    real_lstat = dlsym(RTLD_NEXT, "lstat");
    real___xstat = dlsym(RTLD_NEXT, "__xstat");
    real___lxstat = dlsym(RTLD_NEXT, "__lxstat");
    real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    real_opendir = dlsym(RTLD_NEXT, "opendir");
    real_readdir = dlsym(RTLD_NEXT, "readdir");
    real_closedir = dlsym(RTLD_NEXT, "closedir");
    real_tcsetattr = dlsym(RTLD_NEXT, "tcsetattr");
    real_tcgetattr = dlsym(RTLD_NEXT, "tcgetattr");
    real_ioctl = dlsym(RTLD_NEXT, "ioctl");

    /* inotify functions */
    real_inotify_init = dlsym(RTLD_NEXT, "inotify_init");
    real_inotify_init1 = dlsym(RTLD_NEXT, "inotify_init1");
    real_inotify_add_watch = dlsym(RTLD_NEXT, "inotify_add_watch");

    /* udev functions - these might not exist if libudev isn't loaded yet
     * They will be loaded from libudev when we intercept dlopen */
}

/* Load udev functions from the real libudev library */
static void load_udev_functions_from_lib(void* handle) {
    hook_log("Loading udev functions from handle %p", handle);

    /* Use regular dlsym - not hooked */
    real_udev_new = dlsym(handle, "udev_new");
    real_udev_enumerate_new = dlsym(handle, "udev_enumerate_new");
    real_udev_enumerate_add_match_subsystem = dlsym(handle, "udev_enumerate_add_match_subsystem");
    real_udev_enumerate_scan_devices = dlsym(handle, "udev_enumerate_scan_devices");
    real_udev_enumerate_get_list_entry = dlsym(handle, "udev_enumerate_get_list_entry");
    real_udev_list_entry_get_next = dlsym(handle, "udev_list_entry_get_next");
    real_udev_list_entry_get_name = dlsym(handle, "udev_list_entry_get_name");
    real_udev_device_new_from_syspath = dlsym(handle, "udev_device_new_from_syspath");
    real_udev_device_get_devnode = dlsym(handle, "udev_device_get_devnode");
    real_udev_device_get_sysattr_value = dlsym(handle, "udev_device_get_sysattr_value");
    real_udev_device_get_parent_with_subsystem_devtype = dlsym(handle, "udev_device_get_parent_with_subsystem_devtype");
    real_udev_device_unref = dlsym(handle, "udev_device_unref");
    real_udev_enumerate_unref = dlsym(handle, "udev_enumerate_unref");
    real_udev_unref = dlsym(handle, "udev_unref");

    hook_log("Loaded udev: new=%p, get_devnode=%p, get_sysattr=%p",
             real_udev_new, real_udev_device_get_devnode, real_udev_device_get_sysattr_value);
}

static void init_hook(void) {
    pthread_mutex_lock(&init_mutex);

    if (initialized || initializing) {
        pthread_mutex_unlock(&init_mutex);
        return;
    }

    initializing = 1;  /* Prevent recursive init from hooks like tcgetattr */

    /* Open log file */
    const char* log_path = getenv("PILLOW_HOOK_LOG");
    if (!log_path) log_path = "/tmp/pillow_hook.log";
    log_file = fopen(log_path, "a");
    if (log_file) {
        setvbuf(log_file, NULL, _IOLBF, 0);
    }

    hook_log("========== PILLOW HOOK INITIALIZING ==========");
    hook_log("PID: %d", getpid());

    load_real_functions();

    hook_log("Loaded libc functions: open=%p, close=%p, read=%p, write=%p",
             real_open, real_close, real_read, real_write);
    hook_log("Loaded udev functions: udev_new=%p, get_devnode=%p, get_sysattr=%p",
             real_udev_new, real_udev_device_get_devnode, real_udev_device_get_sysattr_value);

    parse_config();

    initialized = 1;
    initializing = 0;  /* Clear the flag */
    hook_log("========== PILLOW HOOK INITIALIZED ==========");

    /* Start the pillow responder thread */
    start_responder_thread();

    pthread_mutex_unlock(&init_mutex);
}

/* ============================================================================
 * Hooked libc Functions
 * ============================================================================ */

int open(const char *path, int flags, ...) {
    /* Debug: log to stderr BEFORE init to see if we're even called */
    static int first_call = 1;
    if (first_call) {
        fprintf(stderr, "[pillow_hook] open() CALLED for first time! path=%s\n", path ? path : "(null)");
        first_call = 0;
    }
    init_hook();

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    /* Check if this is a fake pillow device */
    fake_pillow_t *pillow = find_pillow_by_devnode(path);
    if (pillow) {
        hook_log("OPEN INTERCEPT: %s -> redirecting to PTY %s (slave_fd=%d)",
                 path, pillow->slave_path, pillow->slave_fd);

        /* Dup the slave fd so frank gets its own fd */
        int fd = dup(pillow->slave_fd);
        if (fd >= 0) {
            pillow->frank_fd = fd;
            hook_log("OPEN SUCCESS: %s -> fd=%d (PTY slave)", path, fd);
        } else {
            hook_log("OPEN ERROR: dup() failed: %s", strerror(errno));
        }
        return fd;
    }

    /* Not a fake device, pass through */
    int fd = real_open(path, flags, mode);

    /* Log ALL /sys accesses */
    if (strstr(path, "/sys/")) {
        hook_log("OPEN /sys: %s (flags=0x%x) -> fd=%d", path, flags, fd);
    }
    /* Log serial port opens */
    else if (strstr(path, "tty") || strstr(path, "USB")) {
        hook_log("OPEN PASSTHROUGH: %s -> fd=%d", path, fd);
    }

    /* Track device-label file to patch F08 -> H08 */
    if (strstr(path, "device-label") && fd >= 0) {
        device_label_fd = fd;
        hook_log("OPEN device-label: fd=%d (will patch F08 -> H08)", fd);
    }

    return fd;
}

/* open64 hook - many 64-bit programs use this */
int open64(const char *path, int flags, ...) {
    /* Debug: log to stderr BEFORE init */
    static int first_call = 1;
    if (first_call) {
        fprintf(stderr, "[pillow_hook] open64() CALLED! path=%s\n", path ? path : "(null)");
        first_call = 0;
    }
    init_hook();

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    /* Check if this is a fake pillow device */
    fake_pillow_t *pillow = find_pillow_by_devnode(path);
    if (pillow) {
        hook_log("OPEN64 INTERCEPT: %s -> PTY %s", path, pillow->slave_path);
        int fd = dup(pillow->slave_fd);
        if (fd >= 0) pillow->frank_fd = fd;
        return fd;
    }

    int fd = real_open(path, flags, mode);
    if (path && (strstr(path, "tty") || strstr(path, "USB"))) {
        hook_log("OPEN64 PASSTHROUGH: %s -> fd=%d", path, fd);
    }
    return fd;
}

/* openat hook - many programs use this instead of open */
int openat(int dirfd, const char *path, int flags, ...) {
    init_hook();

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    int fd = real_openat ? real_openat(dirfd, path, flags, mode) : -1;

    /* Track device-label file to patch F08 -> H08 */
    if (path && strstr(path, "device-label") && fd >= 0) {
        device_label_fd = fd;
        hook_log("OPENAT device-label: fd=%d (will patch F08 -> H08)", fd);
    }

    return fd;
}

int close(int fd) {
    init_hook();

    /* Clear device-label tracking */
    if (fd == device_label_fd) {
        device_label_fd = -1;
    }

    fake_pillow_t *pillow = find_pillow_by_frank_fd(fd);
    if (pillow) {
        hook_log("CLOSE: fd=%d (fake pillow %s)", fd, pillow->side);
        pillow->frank_fd = -1;
    }

    return real_close(fd);
}

/* readlink hook - to trace sysfs symlink resolution */
ssize_t readlink(const char *path, char *buf, size_t bufsiz) {
    init_hook();

    /* Log all readlink calls for sysfs and ttyUSB paths */
    if (path && (strstr(path, "/sys") || strstr(path, "ttyUSB"))) {
        hook_log(">>> READLINK: %s <<<", path);
    }

    /* For fake devices, we could return fake sysfs paths here */
    /* For now, just passthrough */
    ssize_t ret = real_readlink ? real_readlink(path, buf, bufsiz) : -1;

    if (path && (strstr(path, "/sys") || strstr(path, "ttyUSB"))) {
        if (ret > 0) {
            char tmp[256];
            size_t len = ret < 255 ? ret : 255;
            memcpy(tmp, buf, len);
            tmp[len] = '\0';
            hook_log(">>> READLINK result: %s -> %s <<<", path, tmp);
        } else {
            hook_log(">>> READLINK failed: %s (errno=%d) <<<", path, errno);
        }
    }

    return ret;
}

/* Check if path is a fake USB sysfs path we should intercept */
static int is_fake_usb_sysfs_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; i < num_fake_pillows; i++) {
        if (!fake_pillows[i].active) continue;
        /* Build expected sysfs path: /sys/bus/usb/devices/{bus}-{devpath}/{bus}-{devpath}:1.0 */
        char expected[256];
        snprintf(expected, sizeof(expected), "/sys/bus/usb/devices/%s-%s/%s-%s:1.0",
                 fake_pillows[i].busnum, fake_pillows[i].devpath,
                 fake_pillows[i].busnum, fake_pillows[i].devpath);
        if (strcmp(path, expected) == 0) {
            return i + 1;  /* Return 1-based index */
        }
        /* Also check for the tty subdir */
        snprintf(expected, sizeof(expected), "/sys/bus/usb/devices/%s-%s/%s-%s:1.0/tty",
                 fake_pillows[i].busnum, fake_pillows[i].devpath,
                 fake_pillows[i].busnum, fake_pillows[i].devpath);
        if (strcmp(path, expected) == 0) {
            return i + 1;
        }
    }
    return 0;
}

/* stat hook - trace file existence checks */
int stat(const char *path, struct stat *buf) {
    init_hook();

    /* Log ALL stat calls on /sys paths for debugging */
    if (path && strstr(path, "/sys")) {
        hook_log(">>> STAT /sys: %s <<<", path);
    }

    /* Check if this is a fake USB sysfs path */
    int fake_idx = is_fake_usb_sysfs_path(path);
    if (fake_idx > 0) {
        hook_log(">>> STAT FAKE: %s -> SUCCESS (pillow %d) <<<", path, fake_idx - 1);
        /* Return fake stat for a directory */
        memset(buf, 0, sizeof(*buf));
        buf->st_mode = S_IFDIR | 0755;
        buf->st_nlink = 2;
        return 0;
    }

    int ret = real_stat ? real_stat(path, buf) : -1;

    /* Log ALL sysfs stat calls with more detail */
    if (path && strstr(path, "/sys")) {
        hook_log(">>> STAT REAL: %s -> %d (errno=%d) <<<", path, ret, ret < 0 ? errno : 0);
    }

    return ret;
}

int lstat(const char *path, struct stat *buf) {
    init_hook();

    /* Check if this is a fake USB sysfs path - use same check as stat */
    int fake_idx = is_fake_usb_sysfs_path(path);
    if (fake_idx > 0) {
        hook_log(">>> LSTAT FAKE: %s -> SUCCESS (pillow %d) <<<", path, fake_idx - 1);
        memset(buf, 0, sizeof(*buf));
        buf->st_mode = S_IFDIR | 0755;
        buf->st_nlink = 2;
        return 0;
    }

    int ret = real_lstat ? real_lstat(path, buf) : -1;

    /* Log sysfs lstat calls */
    if (path && strstr(path, "/sys")) {
        hook_log(">>> LSTAT REAL: %s -> %d (errno=%d) <<<", path, ret, ret < 0 ? errno : 0);
    }

    return ret;
}

/* __xstat - glibc internal stat wrapper (older glibc) */
int __xstat(int ver, const char *path, struct stat *buf) {
    init_hook();

    int fake_idx = is_fake_usb_sysfs_path(path);
    if (fake_idx > 0) {
        hook_log(">>> __XSTAT FAKE: %s -> SUCCESS (pillow %d) <<<", path, fake_idx - 1);
        memset(buf, 0, sizeof(*buf));
        buf->st_mode = S_IFDIR | 0755;
        buf->st_nlink = 2;
        return 0;
    }

    int ret = real___xstat ? real___xstat(ver, path, buf) : -1;
    if (path && strstr(path, "/sys")) {
        hook_log(">>> __XSTAT REAL: %s -> %d <<<", path, ret);
    }
    return ret;
}

/* __lxstat - glibc internal lstat wrapper (older glibc) */
int __lxstat(int ver, const char *path, struct stat *buf) {
    init_hook();

    int fake_idx = is_fake_usb_sysfs_path(path);
    if (fake_idx > 0) {
        hook_log(">>> __LXSTAT FAKE: %s -> SUCCESS (pillow %d) <<<", path, fake_idx - 1);
        memset(buf, 0, sizeof(*buf));
        buf->st_mode = S_IFDIR | 0755;
        buf->st_nlink = 2;
        return 0;
    }

    int ret = real___lxstat ? real___lxstat(ver, path, buf) : -1;
    if (path && strstr(path, "/sys")) {
        hook_log(">>> __LXSTAT REAL: %s -> %d <<<", path, ret);
    }
    return ret;
}

/* fstatat hook - C++ filesystem uses this with directory fd + relative path */
int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    init_hook();

    /* Always log fstatat calls for debugging */
    hook_log(">>> FSTATAT ENTRY: dirfd=%d, path=%s, flags=0x%x <<<",
             dirfd, pathname ? pathname : "(null)", flags);

    /* Check if dirfd is one of our fake directories */
    pthread_mutex_lock(&fake_dir_mutex);
    fake_dir_fd_t *fake = find_fake_dir_by_fd(dirfd);
    pthread_mutex_unlock(&fake_dir_mutex);

    if (fake && pathname) {
        hook_log(">>> FSTATAT FAKE DIR: dirfd=%d, path=%s, flags=0x%x <<<",
                 dirfd, pathname, flags);

        /* Handle relative paths within our fake directory */
        if (strcmp(pathname, ".") == 0 || strcmp(pathname, "..") == 0) {
            memset(buf, 0, sizeof(*buf));
            buf->st_mode = S_IFDIR | 0755;
            buf->st_nlink = 2;
            buf->st_ino = (strcmp(pathname, ".") == 0) ? 1 : 2;
            hook_log(">>> FSTATAT FAKE: %s -> SUCCESS (dir) <<<", pathname);
            return 0;
        }
        if (strcmp(pathname, "tty") == 0) {
            memset(buf, 0, sizeof(*buf));
            buf->st_mode = S_IFDIR | 0755;
            buf->st_nlink = 2;
            buf->st_ino = 100;
            hook_log(">>> FSTATAT FAKE: tty -> SUCCESS (dir) <<<");
            return 0;
        }
        if (strncmp(pathname, "ttyUSB", 6) == 0) {
            memset(buf, 0, sizeof(*buf));
            buf->st_mode = S_IFLNK | 0777;  /* ttyUSBx is a symlink */
            buf->st_nlink = 1;
            buf->st_ino = 100 + fake->pillow_index;
            hook_log(">>> FSTATAT FAKE: %s -> SUCCESS (symlink) <<<", pathname);
            return 0;
        }

        /* Unknown entry in fake directory - return ENOENT */
        hook_log(">>> FSTATAT FAKE: %s -> ENOENT <<<", pathname);
        errno = ENOENT;
        return -1;
    }

    /* Also handle absolute paths that match our fake sysfs paths */
    if (pathname && strstr(pathname, "/sys/bus/usb/devices/")) {
        int fake_idx = is_fake_usb_sysfs_path(pathname);
        if (fake_idx > 0) {
            hook_log(">>> FSTATAT FAKE ABS: %s -> SUCCESS <<<", pathname);
            memset(buf, 0, sizeof(*buf));
            buf->st_mode = S_IFDIR | 0755;
            buf->st_nlink = 2;
            return 0;
        }
    }

    int ret = real_fstatat ? real_fstatat(dirfd, pathname, buf, flags) : -1;

    if (pathname && (strstr(pathname, "/sys") || strstr(pathname, "tty"))) {
        hook_log(">>> FSTATAT REAL: dirfd=%d path=%s -> %d (errno=%d) <<<",
                 dirfd, pathname, ret, ret < 0 ? errno : 0);
    }

    return ret;
}

/* __fxstatat64 hook - glibc internal stat with version */
static int (*real___fxstatat64)(int ver, int dirfd, const char *pathname, struct stat *buf, int flags) = NULL;

int __fxstatat64(int ver, int dirfd, const char *pathname, struct stat *buf, int flags) {
    init_hook();

    if (!real___fxstatat64) {
        real___fxstatat64 = dlsym(RTLD_NEXT, "__fxstatat64");
    }

    hook_log(">>> __FXSTATAT64: ver=%d, dirfd=%d, path=%s, flags=0x%x <<<",
             ver, dirfd, pathname ? pathname : "(null)", flags);

    /* Check if dirfd is one of our fake directories */
    pthread_mutex_lock(&fake_dir_mutex);
    fake_dir_fd_t *fake = find_fake_dir_by_fd(dirfd);
    pthread_mutex_unlock(&fake_dir_mutex);

    if (fake && pathname) {
        hook_log(">>> __FXSTATAT64 FAKE DIR: dirfd=%d, path=%s <<<", dirfd, pathname);

        /* Handle relative paths within our fake directory */
        if (strcmp(pathname, ".") == 0 || strcmp(pathname, "..") == 0) {
            memset(buf, 0, sizeof(*buf));
            buf->st_mode = S_IFDIR | 0755;
            buf->st_nlink = 2;
            buf->st_ino = (strcmp(pathname, ".") == 0) ? 1 : 2;
            return 0;
        }
        if (strcmp(pathname, "tty") == 0) {
            memset(buf, 0, sizeof(*buf));
            buf->st_mode = S_IFDIR | 0755;
            buf->st_nlink = 2;
            buf->st_ino = 100;
            return 0;
        }
        if (strncmp(pathname, "ttyUSB", 6) == 0) {
            memset(buf, 0, sizeof(*buf));
            buf->st_mode = S_IFLNK | 0777;
            buf->st_nlink = 1;
            buf->st_ino = 100 + fake->pillow_index;
            return 0;
        }

        errno = ENOENT;
        return -1;
    }

    return real___fxstatat64 ? real___fxstatat64(ver, dirfd, pathname, buf, flags) : -1;
}

/* newfstatat hook - used by some glibc versions (alias for fstatat) */
int newfstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    init_hook();

    hook_log(">>> NEWFSTATAT: dirfd=%d, path=%s, flags=0x%x <<<",
             dirfd, pathname ? pathname : "(null)", flags);

    /* Use our fstatat implementation */
    return fstatat(dirfd, pathname, buf, flags);
}

/* ============================================================================
 * Fake Directory Handling
 *
 * Frank iterates /sys/bus/usb/devices/X-X.X.X/X-X.X.X:1.0/ looking for "tty"
 * and then /sys/bus/usb/devices/X-X.X.X/X-X.X.X:1.0/tty/ looking for ttyUSBx
 *
 * C++ std::filesystem uses getdents64 syscall directly, so we need to:
 * 1. Open a real directory to get a valid fd
 * 2. Track that fd and what fake entries it should return
 * 3. Intercept getdents64 to return fake entries for tracked fds
 *
 * Note: fake_dir_fd_t and find_fake_dir_by_fd() are defined earlier in this file.
 * ============================================================================ */

/* Legacy fake_dir_t for readdir-based iteration (kept for compatibility) */
#define FAKE_DIR_MAGIC 0xF4AEED17
typedef struct {
    int magic;
    int pillow_index;
    int entry_index;  /* 0=first call, 1=., 2=.., 3=tty or ttyUSBx, 4=done */
    int is_tty_subdir; /* Are we in the /tty subdir? */
} fake_dir_t;

static fake_dir_t fake_dirs[8];
static int num_fake_dirs = 0;

/* Check if path matches a fake USB sysfs directory we should intercept */
static int get_fake_dir_info(const char *path, int *pillow_idx, int *is_tty) {
    if (!path) return 0;
    for (int i = 0; i < num_fake_pillows; i++) {
        if (!fake_pillows[i].active) continue;
        char base[256], tty[256];
        snprintf(base, sizeof(base), "/sys/bus/usb/devices/%s-%s/%s-%s:1.0",
                 fake_pillows[i].busnum, fake_pillows[i].devpath,
                 fake_pillows[i].busnum, fake_pillows[i].devpath);
        snprintf(tty, sizeof(tty), "%s/tty", base);
        if (strcmp(path, base) == 0) {
            *pillow_idx = i;
            *is_tty = 0;
            return 1;
        }
        if (strcmp(path, tty) == 0) {
            *pillow_idx = i;
            *is_tty = 1;
            return 1;
        }
    }
    return 0;
}

DIR *opendir(const char *name) {
    init_hook();

    /* Log ALL opendir calls for debugging */
    hook_log(">>> OPENDIR: %s <<<", name ? name : "(null)");

    int pillow_idx, is_tty;
    if (get_fake_dir_info(name, &pillow_idx, &is_tty)) {
        /* For fake directories, we open /tmp to get a real DIR* with a real fd,
         * then track that fd so we can intercept getdents64 calls on it */
        DIR *real_dir = real_opendir ? real_opendir("/tmp") : NULL;
        if (!real_dir) {
            hook_log(">>> OPENDIR FAKE: %s FAILED (can't open /tmp) <<<", name);
            errno = ENOENT;
            return NULL;
        }

        /* Get the fd from the DIR structure */
        int fd = dirfd(real_dir);

        /* Track this fd as a fake directory */
        pthread_mutex_lock(&fake_dir_mutex);
        int slot = -1;
        for (int i = 0; i < MAX_FAKE_DIRS; i++) {
            if (!fake_dir_fds[i].active) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            pthread_mutex_unlock(&fake_dir_mutex);
            real_closedir(real_dir);
            hook_log(">>> OPENDIR FAKE: %s FAILED (no slots) <<<", name);
            errno = EMFILE;
            return NULL;
        }

        fake_dir_fds[slot].fd = fd;
        fake_dir_fds[slot].pillow_index = pillow_idx;
        fake_dir_fds[slot].is_tty_subdir = is_tty;
        fake_dir_fds[slot].entries_returned = 0;
        fake_dir_fds[slot].active = 1;
        num_fake_dir_fds++;
        pthread_mutex_unlock(&fake_dir_mutex);

        hook_log(">>> OPENDIR FAKE: %s -> fd=%d (pillow %d, is_tty=%d) <<<",
                 name, fd, pillow_idx, is_tty);
        return real_dir;
    }

    return real_opendir ? real_opendir(name) : NULL;
}

/* Static dirent for fake entries */
static struct dirent fake_dirent;

struct dirent *readdir(DIR *dirp) {
    init_hook();

    /* Check if this DIR corresponds to a fake directory fd */
    int dir_fd = dirfd(dirp);
    pthread_mutex_lock(&fake_dir_mutex);
    fake_dir_fd_t *fake = find_fake_dir_by_fd(dir_fd);
    pthread_mutex_unlock(&fake_dir_mutex);

    if (fake) {
        fake->entries_returned++;
        int idx = fake->entries_returned;
        hook_log(">>> READDIR FAKE: fd=%d entry_index=%d <<<", dir_fd, idx);

        if (idx == 1) {
            /* Return "." */
            memset(&fake_dirent, 0, sizeof(fake_dirent));
            fake_dirent.d_ino = 1;
            fake_dirent.d_off = 1;
            fake_dirent.d_reclen = sizeof(fake_dirent);
            fake_dirent.d_type = DT_DIR;
            strcpy(fake_dirent.d_name, ".");
            hook_log(">>> READDIR FAKE: returning . <<<");
            return &fake_dirent;
        }
        if (idx == 2) {
            /* Return ".." */
            memset(&fake_dirent, 0, sizeof(fake_dirent));
            fake_dirent.d_ino = 2;
            fake_dirent.d_off = 2;
            fake_dirent.d_reclen = sizeof(fake_dirent);
            fake_dirent.d_type = DT_DIR;
            strcpy(fake_dirent.d_name, "..");
            hook_log(">>> READDIR FAKE: returning .. <<<");
            return &fake_dirent;
        }
        if (idx == 3) {
            memset(&fake_dirent, 0, sizeof(fake_dirent));
            fake_dirent.d_ino = 100 + fake->pillow_index;
            fake_dirent.d_off = 3;
            fake_dirent.d_reclen = sizeof(fake_dirent);
            /* Frank looks for entries starting with "tty" in the interface dir
             * and uses the entry name as the device name. So we return "ttyUSB0" directly */
            fake_dirent.d_type = DT_DIR;
            snprintf(fake_dirent.d_name, sizeof(fake_dirent.d_name),
                     "ttyUSB%d", fake->pillow_index);
            hook_log(">>> READDIR FAKE: returning %s (direct in interface dir) <<<", fake_dirent.d_name);
            return &fake_dirent;
        }

        /* End of directory - IMPORTANT: set errno = 0 to indicate normal end, not error */
        hook_log(">>> READDIR FAKE: end of dir <<<");
        errno = 0;
        return NULL;
    }

    return real_readdir ? real_readdir(dirp) : NULL;
}

int closedir(DIR *dirp) {
    init_hook();

    /* Check if this directory fd is one of our tracked fake directories */
    int fd = dirfd(dirp);
    pthread_mutex_lock(&fake_dir_mutex);
    fake_dir_fd_t *fake = find_fake_dir_by_fd(fd);
    if (fake) {
        hook_log(">>> CLOSEDIR FAKE: fd=%d <<<", fd);
        fake->active = 0;
        num_fake_dir_fds--;
    }
    pthread_mutex_unlock(&fake_dir_mutex);

    /* Always call real closedir since we're using a real DIR* */
    return real_closedir ? real_closedir(dirp) : -1;
}

/* ============================================================================
 * getdents64 hook - C++ std::filesystem uses this syscall directly
 * ============================================================================ */

/* Helper to add a linux_dirent64 entry to a buffer */
static int add_dirent64(char *buf, int offset, int bufsize,
                        uint64_t ino, const char *name, unsigned char type) {
    int name_len = strlen(name) + 1;
    /* d_reclen must be 8-byte aligned */
    int reclen = (offsetof(struct linux_dirent64, d_name) + name_len + 7) & ~7;

    if (offset + reclen > bufsize) {
        return 0;  /* Buffer full */
    }

    struct linux_dirent64 *ent = (struct linux_dirent64 *)(buf + offset);
    ent->d_ino = ino;
    ent->d_off = offset + reclen;  /* Offset of next entry */
    ent->d_reclen = reclen;
    ent->d_type = type;
    strcpy(ent->d_name, name);

    return reclen;
}

/* Hook for getdents64 syscall - this is what C++ filesystem uses
 * Note: The signature matches glibc's declaration in dirent_ext.h */
__ssize_t getdents64(int fd, void *buffer, size_t length) {
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)buffer;
    size_t count = length;
    init_hook();

    /* Check if this fd is a fake directory */
    pthread_mutex_lock(&fake_dir_mutex);
    fake_dir_fd_t *fake = find_fake_dir_by_fd(fd);
    pthread_mutex_unlock(&fake_dir_mutex);

    if (fake) {
        int offset = 0;
        int added;

        hook_log(">>> GETDENTS64 FAKE: fd=%d, count=%zu, entries_returned=%d <<<",
                 fd, count, fake->entries_returned);

        /* Return fake entries based on how many have been returned */
        if (fake->entries_returned == 0) {
            /* First call: return all entries at once */
            /* Entry 1: "." */
            added = add_dirent64((char*)dirp, offset, count, 1, ".", DT_DIR);
            if (added == 0) goto buffer_full;
            offset += added;

            /* Entry 2: ".." */
            added = add_dirent64((char*)dirp, offset, count, 2, "..", DT_DIR);
            if (added == 0) goto buffer_full;
            offset += added;

            /* Entry 3: "tty" or "ttyUSBx" */
            if (fake->is_tty_subdir) {
                char name[32];
                snprintf(name, sizeof(name), "ttyUSB%d", fake->pillow_index);
                added = add_dirent64((char*)dirp, offset, count, 100 + fake->pillow_index, name, DT_LNK);
                hook_log(">>> GETDENTS64 FAKE: returning ., .., %s <<<", name);
            } else {
                added = add_dirent64((char*)dirp, offset, count, 100, "tty", DT_DIR);
                hook_log(">>> GETDENTS64 FAKE: returning ., .., tty <<<");
            }
            if (added == 0) goto buffer_full;
            offset += added;

            fake->entries_returned = 3;  /* All entries returned */
            return offset;
        }

        /* Subsequent calls: return 0 (end of directory) */
        hook_log(">>> GETDENTS64 FAKE: end of dir <<<");
        return 0;

buffer_full:
        hook_log(">>> GETDENTS64 FAKE: buffer too small! <<<");
        errno = EINVAL;
        return -1;
    }

    /* Not a fake directory, use real syscall */
    long ret = syscall(SYS_getdents64, fd, dirp, count);
    return ret;
}

/* inotify hooks for debugging */
int inotify_init(void) {
    init_hook();
    int fd = real_inotify_init ? real_inotify_init() : -1;
    hook_log(">>> INOTIFY_INIT: fd=%d <<<", fd);
    if (fd >= 0) inotify_fd = fd;
    return fd;
}

int inotify_init1(int flags) {
    init_hook();
    int fd = real_inotify_init1 ? real_inotify_init1(flags) : -1;
    hook_log(">>> INOTIFY_INIT1: flags=0x%x, fd=%d <<<", flags, fd);
    if (fd >= 0) inotify_fd = fd;
    return fd;
}

/* Track if symlinks have been created */
static int symlinks_created = 0;

/* Create symlinks for fake devices - called after inotify watch is set up */
static void create_device_symlinks(void) {
    if (symlinks_created) return;
    symlinks_created = 1;

    hook_log(">>> CREATING DEVICE SYMLINKS (after inotify watch) <<<");
    for (int i = 0; i < num_fake_pillows; i++) {
        fake_pillow_t *p = &fake_pillows[i];
        if (p->active && p->slave_path[0]) {
            unlink(p->devnode);  /* Remove if exists */
            if (symlink(p->slave_path, p->devnode) == 0) {
                hook_log("Created symlink: %s -> %s", p->devnode, p->slave_path);
            } else {
                hook_log("WARNING: symlink %s -> %s failed: %s",
                         p->devnode, p->slave_path, strerror(errno));
            }
        }
    }
}

int inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    init_hook();
    int wd = real_inotify_add_watch ? real_inotify_add_watch(fd, pathname, mask) : -1;
    hook_log(">>> INOTIFY_ADD_WATCH: fd=%d, path=%s, mask=0x%x -> wd=%d <<<",
             fd, pathname ? pathname : "(null)", mask, wd);

    /* If frank is watching /dev for IN_CREATE, create our symlinks now */
    if (pathname && strcmp(pathname, "/dev") == 0 && (mask & 0x100)) {
        hook_log(">>> /dev watch detected, will create symlinks in 100ms <<<");
        /* Small delay to ensure frank's watch is fully active */
        usleep(100000);
        create_device_symlinks();
    }

    return wd;
}

ssize_t read(int fd, void *buf, size_t count) {
    init_hook();

    ssize_t ret = real_read(fd, buf, count);

    /* Log inotify reads */
    if (fd == inotify_fd && ret > 0 && buf) {
        struct inotify_event *event = (struct inotify_event *)buf;
        hook_log(">>> INOTIFY READ: %zd bytes, name=%s, mask=0x%x <<<",
                 ret, event->len > 0 ? event->name : "(none)", event->mask);
    }

    /* Patch device-label: F08 -> H08 to enable pillow hub mode */
    if (fd == device_label_fd && ret > 0 && buf) {
        char *p = memmem(buf, ret, "F08", 3);
        if (p) {
            p[0] = 'H';  /* Change F08 to H08 */
            hook_log("PATCHED device-label: F08 -> H08");
        }
    }

    /* Per-packet logging disabled to reduce eMMC wear */
    (void)find_pillow_by_frank_fd(fd);  /* Keep fd tracking working */

    return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
    init_hook();

    /* Per-packet logging disabled to reduce eMMC wear */

    return real_write(fd, buf, count);
}

int tcsetattr(int fd, int actions, const struct termios *t) {
    init_hook();

    fake_pillow_t *pillow = find_pillow_by_frank_fd(fd);
    if (pillow) {
        /* Extract baud rate from c_cflag
         * NOTE: Target system uses old-style termios encoding:
         * - Standard speeds 0-15 in low nibble
         * - Extended speeds use CBAUDEX (0x1000) + index
         * Cross-compiler may use different values, so hardcode target values */
        speed_t baud_flag = t->c_cflag & 0x100f;  /* CBAUD on target */
        int baud_int = 0;
        const char* baud_str = "?";

        /* Target system (aarch64 glibc 2.35) baud encodings */
        switch(baud_flag) {
            case 0:       baud_int = 0;       baud_str = "0";       break;
            case 13:      baud_int = 9600;    baud_str = "9600";    break;
            case 14:      baud_int = 19200;   baud_str = "19200";   break;
            case 15:      baud_int = 38400;   baud_str = "38400";   break;  /* 0xf */
            case 0x1001:  baud_int = 57600;   baud_str = "57600";   break;
            case 0x1002:  baud_int = 115200;  baud_str = "115200";  break;
            case 0x1003:  baud_int = 230400;  baud_str = "230400";  break;
            case 0x1004:  baud_int = 460800;  baud_str = "460800";  break;
            case 0x1005:  baud_int = 500000;  baud_str = "500000";  break;
            case 0x1006:  baud_int = 576000;  baud_str = "576000";  break;
            case 0x1007:  baud_int = 921600;  baud_str = "921600";  break;
            case 0x1008:  baud_int = 1000000; baud_str = "1000000"; break;
            default: break;
        }
        hook_log("TCSETATTR: fd=%d (%s) baud=%s (%d) (baud_flag=0x%x c_cflag=0x%x)",
                 fd, pillow->side, baud_str, baud_int, (unsigned)baud_flag, (unsigned)t->c_cflag);

        /* Send baud rate change to bridge */
        if (baud_int > 0 && bridge_connected) {
            int channel = get_channel_for_side(pillow->side);
            if (channel >= 0) {
                bridge_send_baud(channel, baud_int);
            }
        }
    }

    return real_tcsetattr(fd, actions, t);
}

int tcgetattr(int fd, struct termios *t) {
    init_hook();
    if (!real_tcgetattr) {
        hook_log("ERROR: real_tcgetattr is NULL! Using syscall directly.");
        /* Fall back to direct syscall if hook not ready */
        extern int __tcgetattr(int fd, struct termios *t);
        return __tcgetattr(fd, t);
    }
    return real_tcgetattr(fd, t);
}

/* ============================================================================
 * Fake udev Structures and Functions
 * ============================================================================ */

/* Magic markers to identify our fake objects */
#define FAKE_DEVICE_MAGIC 0x851EE901
#define FAKE_PARENT_MAGIC 0x851EE902
#define FAKE_ENTRY_MAGIC  0x851EE903

/* Fake udev_list_entry - linked list of fake devices */
typedef struct fake_list_entry {
    int magic;
    int pillow_index;                    /* Index into fake_pillows */
    char syspath[256];                   /* Fake syspath like /sys/class/tty/ttyUSB0 */
    struct fake_list_entry *next;        /* Next fake entry or NULL */
    struct udev_list_entry *real_next;   /* First real entry after fakes */
} fake_list_entry_t;

/* Fake udev_device for our pillows */
typedef struct {
    int magic;
    int pillow_index;
    int is_parent;                       /* Is this the USB parent device? */
    struct udev *udev;
} fake_udev_device_t;

/* Static storage for fake objects */
static fake_list_entry_t fake_entries[MAX_FAKE_DEVICES];
static fake_udev_device_t fake_devices[MAX_FAKE_DEVICES * 2];  /* Device + parent for each */
static int fake_devices_used = 0;

/* Track if current enumeration is for "tty" subsystem */
static __thread int enumerating_tty = 0;
static __thread struct udev_enumerate *current_enumerate = NULL;

/* Old unused functions removed - all fake udev handling is done in the exported functions below */

/* ============================================================================
 * Hooked dlopen Function
 * ============================================================================ */

/* Handle to our own library, returned to frank instead of real libudev */
static void* our_handle = NULL;

void* dlopen(const char *filename, int flags) {
    init_hook();

    /* Use real_dlopen if available, otherwise fall back to RTLD_NEXT */
    if (!real_dlopen) {
        hook_log("DLOPEN: real_dlopen is NULL, getting from RTLD_NEXT");
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");
        hook_log("DLOPEN: real_dlopen = %p", real_dlopen);
    }

    if (!real_dlopen) {
        hook_log("DLOPEN: ERROR - could not get real_dlopen!");
        return NULL;
    }

    void* handle = real_dlopen(filename, flags);

    if (filename) {
        hook_log("DLOPEN: %s -> handle=%p", filename, handle);

        /* If this is libudev, intercept it! */
        if (strstr(filename, "libudev") && handle) {
            hook_log("DLOPEN: Detected libudev!");

            /* Save the real handle for our internal use */
            libudev_handle = handle;
            load_udev_functions_from_lib(handle);

            /* Get a handle to our own library to return to frank */
            if (!our_handle) {
                our_handle = real_dlopen("/tmp/pillow_hook.so", RTLD_NOW | RTLD_GLOBAL);
                hook_log("DLOPEN: Got handle to pillow_hook.so: %p", our_handle);
            }

            /* Return OUR handle instead of the real libudev handle!
             * This way, when frank calls dlsym(handle, "udev_new"),
             * it will get OUR udev_new function instead of the real one. */
            if (our_handle) {
                hook_log("DLOPEN: Returning pillow_hook.so handle instead of libudev!");
                return our_handle;
            }
        }
    } else {
        hook_log("DLOPEN: filename=(null) flags=%d -> handle=%p", flags, handle);
    }

    return handle;
}

/* ============================================================================
 * Hooked dlsym Function
 *
 * This is critical: frank uses dlsym() on the libudev handle to get function
 * pointers. We intercept dlsym and return our fake functions for udev calls.
 * ============================================================================ */

/* NOTE: We do NOT hook dlsym because getting the real dlsym without recursion
 * is not reliably possible on all systems (__libc_dlsym may not be exported).
 *
 * Instead, we make dlopen return a handle to our own library when frank
 * tries to open libudev. This way, frank's dlsym calls will resolve to our
 * exported udev functions.
 */

/* ============================================================================
 * Exported udev Functions
 *
 * These are exported so when frank dlsym's our handle (which we returned from
 * dlopen), it gets OUR functions instead of the real libudev functions.
 * ============================================================================ */

/* udev context functions */
struct udev* udev_new(void) {
    /* AGGRESSIVE debug - write to stderr immediately */
    fprintf(stderr, "[pillow_hook] !!! UDEV_NEW CALLED !!!\n");
    fflush(stderr);

    init_hook();
    hook_log(">>> UDEV_NEW CALLED <<<");

    /* Write to trace file for debugging */
    int trace_fd = real_open ? real_open("/tmp/udev_trace.log", O_WRONLY|O_CREAT|O_APPEND, 0644) : -1;
    if (trace_fd >= 0) {
        const char* msg = "udev_new() CALLED\n";
        if (real_write) real_write(trace_fd, msg, strlen(msg));
        if (real_close) real_close(trace_fd);
    }

    /* Call real udev_new */
    if (real_udev_new) {
        struct udev *u = real_udev_new();
        hook_log("udev_new: returning real context %p", u);
        return u;
    }
    hook_log("ERROR: real_udev_new is NULL!");
    return NULL;
}

void udev_unref(struct udev *udev) {
    init_hook();
    hook_log("udev_unref(%p)", udev);
    if (real_udev_unref) {
        real_udev_unref(udev);
    }
}

struct udev* udev_ref(struct udev *udev) {
    init_hook();
    hook_log("udev_ref(%p)", udev);
    /* Just return the same pointer - we don't have real_udev_ref */
    return udev;
}

/* udev enumerate functions */
struct udev_enumerate* udev_enumerate_new(struct udev *udev) {
    init_hook();
    hook_log("udev_enumerate_new(%p)", udev);
    if (real_udev_enumerate_new) {
        return real_udev_enumerate_new(udev);
    }
    return NULL;
}

int udev_enumerate_add_match_subsystem(struct udev_enumerate *enumerate, const char *subsystem) {
    init_hook();
    hook_log("udev_enumerate_add_match_subsystem(%p, %s)", enumerate, subsystem ? subsystem : "(null)");

    /* Track if we're enumerating tty subsystem - this is where we inject fakes */
    if (subsystem && strcmp(subsystem, "tty") == 0) {
        enumerating_tty = 1;
        current_enumerate = enumerate;
        hook_log(">>> TTY ENUMERATION DETECTED - will inject %d fake devices <<<", num_fake_pillows);
    }

    if (real_udev_enumerate_add_match_subsystem) {
        return real_udev_enumerate_add_match_subsystem(enumerate, subsystem);
    }
    return -1;
}

int udev_enumerate_scan_devices(struct udev_enumerate *enumerate) {
    init_hook();
    hook_log("udev_enumerate_scan_devices(%p)", enumerate);
    if (real_udev_enumerate_scan_devices) {
        return real_udev_enumerate_scan_devices(enumerate);
    }
    return -1;
}

struct udev_list_entry* udev_enumerate_get_list_entry(struct udev_enumerate *enumerate) {
    init_hook();
    hook_log("udev_enumerate_get_list_entry(%p) enumerating_tty=%d", enumerate, enumerating_tty);

    /* Get the real list first */
    struct udev_list_entry *real_list = NULL;
    if (real_udev_enumerate_get_list_entry) {
        real_list = real_udev_enumerate_get_list_entry(enumerate);
    }

    /* If this is a tty enumeration and we have fake pillows, prepend them */
    if (enumerating_tty && num_fake_pillows > 0 && enumerate == current_enumerate) {
        hook_log(">>> INJECTING %d FAKE TTY DEVICES <<<", num_fake_pillows);

        /* Build linked list of fake entries */
        for (int i = 0; i < num_fake_pillows; i++) {
            fake_entries[i].magic = FAKE_ENTRY_MAGIC;
            fake_entries[i].pillow_index = i;
            /* Create fake syspath like /sys/class/tty/ttyUSB0 */
            snprintf(fake_entries[i].syspath, sizeof(fake_entries[i].syspath),
                     "/sys/class/tty/ttyUSB%d", i);

            if (i < num_fake_pillows - 1) {
                fake_entries[i].next = &fake_entries[i + 1];
                fake_entries[i].real_next = NULL;
            } else {
                fake_entries[i].next = NULL;
                fake_entries[i].real_next = real_list;  /* Chain to real entries */
            }
            hook_log("  Fake entry %d: %s", i, fake_entries[i].syspath);
        }

        enumerating_tty = 0;  /* Reset for next enumeration */
        current_enumerate = NULL;

        /* Return our fake entries first */
        return (struct udev_list_entry*)&fake_entries[0];
    }

    return real_list;
}

void udev_enumerate_unref(struct udev_enumerate *enumerate) {
    init_hook();
    hook_log("udev_enumerate_unref(%p)", enumerate);
    if (real_udev_enumerate_unref) {
        real_udev_enumerate_unref(enumerate);
    }
}

/* udev list functions */
struct udev_list_entry* udev_list_entry_get_next(struct udev_list_entry *entry) {
    init_hook();

    /* Check if this is a fake entry */
    fake_list_entry_t *fake = (fake_list_entry_t*)entry;
    if (fake && fake->magic == FAKE_ENTRY_MAGIC) {
        if (fake->next) {
            hook_log("udev_list_entry_get_next: fake -> next fake");
            return (struct udev_list_entry*)fake->next;
        } else if (fake->real_next) {
            hook_log("udev_list_entry_get_next: fake -> real list");
            return fake->real_next;
        }
        hook_log("udev_list_entry_get_next: fake -> NULL (end of list)");
        return NULL;
    }

    if (real_udev_list_entry_get_next) {
        return real_udev_list_entry_get_next(entry);
    }
    return NULL;
}

const char* udev_list_entry_get_name(struct udev_list_entry *entry) {
    init_hook();

    /* Check if this is a fake entry */
    fake_list_entry_t *fake = (fake_list_entry_t*)entry;
    if (fake && fake->magic == FAKE_ENTRY_MAGIC) {
        hook_log("udev_list_entry_get_name: returning fake syspath %s", fake->syspath);
        return fake->syspath;
    }

    if (real_udev_list_entry_get_name) {
        return real_udev_list_entry_get_name(entry);
    }
    return NULL;
}

/* udev device functions */
struct udev_device* udev_device_new_from_syspath(struct udev *udev, const char *syspath) {
    init_hook();
    hook_log(">>> udev_device_new_from_syspath(%p, %s) <<<", udev, syspath ? syspath : "(null)");

    /* Write to trace file */
    int trace_fd = real_open ? real_open("/tmp/udev_trace.log", O_WRONLY|O_CREAT|O_APPEND, 0644) : -1;
    if (trace_fd >= 0) {
        char buf[512];
        int len = snprintf(buf, sizeof(buf), "udev_device_new_from_syspath(%s)\n", syspath ? syspath : "(null)");
        if (real_write) real_write(trace_fd, buf, len);
        if (real_close) real_close(trace_fd);
    }

    /* Check if this is one of our fake syspaths */
    if (syspath) {
        for (int i = 0; i < num_fake_pillows; i++) {
            char expected_path[256];
            snprintf(expected_path, sizeof(expected_path), "/sys/class/tty/ttyUSB%d", i);
            if (strcmp(syspath, expected_path) == 0) {
                /* Create a fake device for this pillow */
                if (fake_devices_used < MAX_FAKE_DEVICES * 2) {
                    fake_udev_device_t *fake = &fake_devices[fake_devices_used++];
                    fake->magic = FAKE_DEVICE_MAGIC;
                    fake->pillow_index = i;
                    fake->is_parent = 0;
                    fake->udev = udev;
                    hook_log(">>> CREATED FAKE DEVICE for pillow %d (%s) <<<",
                             i, fake_pillows[i].side);
                    return (struct udev_device*)fake;
                }
            }
        }
    }

    if (real_udev_device_new_from_syspath) {
        return real_udev_device_new_from_syspath(udev, syspath);
    }
    return NULL;
}

void udev_device_unref(struct udev_device *dev) {
    init_hook();

    /* Check if this is a fake device - don't unref fake devices */
    fake_udev_device_t *fake = (fake_udev_device_t*)dev;
    if (fake && (fake->magic == FAKE_DEVICE_MAGIC || fake->magic == FAKE_PARENT_MAGIC)) {
        hook_log("udev_device_unref(%p): fake device, ignoring", dev);
        return;
    }

    hook_log("udev_device_unref(%p)", dev);
    if (real_udev_device_unref) {
        real_udev_device_unref(dev);
    }
}

const char* udev_device_get_devnode(struct udev_device *dev) {
    init_hook();

    /* Check if this is a fake device */
    fake_udev_device_t *fake = (fake_udev_device_t*)dev;
    if (fake && fake->magic == FAKE_DEVICE_MAGIC) {
        const char *devnode = fake_pillows[fake->pillow_index].devnode;
        hook_log("UDEV get_devnode: FAKE device %d -> %s", fake->pillow_index, devnode);
        return devnode;
    }

    if (!real_udev_device_get_devnode) {
        hook_log("ERROR: real_udev_device_get_devnode is NULL!");
        return NULL;
    }

    const char* result = real_udev_device_get_devnode(dev);

    /* Track current device */
    current_devnode = result;
    current_fake = find_pillow_by_devnode(result);

    hook_log("UDEV get_devnode: %s%s", result ? result : "(null)",
             current_fake ? " [FAKE]" : "");

    return result;
}

struct udev_device* udev_device_get_parent_with_subsystem_devtype(
    struct udev_device *dev, const char *subsystem, const char *devtype)
{
    init_hook();

    /* Check if this is a fake device */
    fake_udev_device_t *fake = (fake_udev_device_t*)dev;
    if (fake && fake->magic == FAKE_DEVICE_MAGIC) {
        hook_log("UDEV get_parent_with_subsystem_devtype: FAKE dev=%p, subsystem=%s, devtype=%s",
                 dev, subsystem ? subsystem : "(null)", devtype ? devtype : "(null)");

        if (subsystem && strcmp(subsystem, "usb") == 0 &&
            devtype && strcmp(devtype, "usb_device") == 0) {
            /* Create a fake parent device */
            if (fake_devices_used < MAX_FAKE_DEVICES * 2) {
                fake_udev_device_t *parent = &fake_devices[fake_devices_used++];
                parent->magic = FAKE_PARENT_MAGIC;
                parent->pillow_index = fake->pillow_index;
                parent->is_parent = 1;
                parent->udev = fake->udev;
                hook_log(">>> CREATED FAKE USB PARENT for pillow %d (%s) <<<",
                         fake->pillow_index, fake_pillows[fake->pillow_index].side);
                return (struct udev_device*)parent;
            }
        }
        return NULL;
    }

    if (!real_udev_device_get_parent_with_subsystem_devtype) {
        hook_log("ERROR: real_udev_device_get_parent_with_subsystem_devtype is NULL!");
        return NULL;
    }

    /* Get devnode first to identify the device */
    const char* devnode = NULL;
    if (real_udev_device_get_devnode) {
        devnode = real_udev_device_get_devnode(dev);
    }

    fake_pillow_t *pillow = find_pillow_by_devnode(devnode);

    hook_log("UDEV get_parent_with_subsystem_devtype: dev=%p, subsystem=%s, devtype=%s, devnode=%s%s",
             dev, subsystem ? subsystem : "(null)", devtype ? devtype : "(null)",
             devnode ? devnode : "(null)", pillow ? " [FAKE]" : "");

    if (pillow && subsystem && strcmp(subsystem, "usb") == 0 &&
        devtype && strcmp(devtype, "usb_device") == 0) {
        /* For fake devices, return the device itself as "parent" */
        /* We'll intercept get_sysattr_value to return fake attributes */
        current_fake = pillow;
        hook_log("UDEV get_parent: returning self for fake device %s", pillow->devnode);
        return dev;
    }

    return real_udev_device_get_parent_with_subsystem_devtype(dev, subsystem, devtype);
}

const char* udev_device_get_sysattr_value(struct udev_device *dev, const char *attr) {
    init_hook();

    /* Check if this is a fake parent device - these have the busnum/devpath */
    fake_udev_device_t *fake = (fake_udev_device_t*)dev;
    if (fake && fake->magic == FAKE_PARENT_MAGIC && attr) {
        fake_pillow_t *pillow = &fake_pillows[fake->pillow_index];
        if (strcmp(attr, "busnum") == 0) {
            hook_log(">>> UDEV get_sysattr_value: FAKE PARENT busnum -> %s <<<", pillow->busnum);
            return pillow->busnum;
        }
        if (strcmp(attr, "devpath") == 0) {
            hook_log(">>> UDEV get_sysattr_value: FAKE PARENT devpath -> %s <<<", pillow->devpath);
            return pillow->devpath;
        }
        hook_log("UDEV get_sysattr_value: FAKE PARENT unknown attr %s", attr);
        return NULL;
    }

    if (!real_udev_device_get_sysattr_value) {
        hook_log("ERROR: real_udev_device_get_sysattr_value is NULL!");
        return NULL;
    }

    /* Check if we're querying a fake device (legacy path) */
    fake_pillow_t *pillow = current_fake;

    /* Also try to identify by devnode */
    if (!pillow && real_udev_device_get_devnode) {
        const char* devnode = real_udev_device_get_devnode(dev);
        pillow = find_pillow_by_devnode(devnode);
    }

    if (pillow && attr) {
        if (strcmp(attr, "busnum") == 0) {
            hook_log("UDEV get_sysattr_value(%s, busnum) -> %s [FAKE]",
                     pillow->devnode, pillow->busnum);
            return pillow->busnum;
        }
        if (strcmp(attr, "devpath") == 0) {
            hook_log("UDEV get_sysattr_value(%s, devpath) -> %s [FAKE]",
                     pillow->devnode, pillow->devpath);
            return pillow->devpath;
        }
    }

    const char* result = real_udev_device_get_sysattr_value(dev, attr);
    hook_log("UDEV get_sysattr_value(attr=%s) -> %s", attr, result ? result : "(null)");

    return result;
}

/* ============================================================================
 * Public API for External Control
 * ============================================================================ */

/*
 * Write data to a fake pillow's PTY master (simulating data FROM pillow TO frank)
 * This can be called from an external process via the master fd
 */
int pillow_hook_get_master_fd(const char* side) {
    init_hook();
    for (int i = 0; i < num_fake_pillows; i++) {
        if (fake_pillows[i].active && strcmp(fake_pillows[i].side, side) == 0) {
            return fake_pillows[i].master_fd;
        }
    }
    return -1;
}

/* Constructor - runs when library is loaded */
__attribute__((constructor))
static void pillow_hook_init(void) {
    /* Early debug - write directly since log isn't open yet */
    fprintf(stderr, "[pillow_hook] CONSTRUCTOR CALLED PID=%d\n", getpid());
    init_hook();
    fprintf(stderr, "[pillow_hook] CONSTRUCTOR DONE, dlopen=%p\n", (void*)dlopen);
}

/* Destructor - runs when library is unloaded */
__attribute__((destructor))
static void pillow_hook_cleanup(void) {
    hook_log("========== PILLOW HOOK CLEANUP ==========");

    /* Stop the responder thread first */
    stop_responder_thread();

    for (int i = 0; i < num_fake_pillows; i++) {
        /* Remove symlinks from /dev */
        if (fake_pillows[i].devnode[0]) {
            unlink(fake_pillows[i].devnode);
            hook_log("Removed symlink: %s", fake_pillows[i].devnode);
        }
        if (fake_pillows[i].master_fd >= 0) {
            close(fake_pillows[i].master_fd);
        }
        if (fake_pillows[i].slave_fd >= 0) {
            close(fake_pillows[i].slave_fd);
        }
    }

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
