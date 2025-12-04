/*
 * pillow_bridge.c - Network bridge for forwarding pillow serial data
 *
 * Runs on Pod5 (where physical pillows are connected).
 * Listens for TCP connections from Pod3's pillow_hook.
 * Forwards serial data bidirectionally and handles baud rate changes.
 *
 * Compile (native on Pod5, or cross-compile):
 *   gcc -o pillow_bridge pillow_bridge.c -lpthread
 *   # or cross-compile:
 *   aarch64-linux-gnu-gcc -o pillow_bridge pillow_bridge.c -lpthread -static
 *
 * Usage:
 *   ./pillow_bridge [-p port] [-l left_device] [-r right_device]
 *
 * Defaults:
 *   port: 5580
 *   left_device: /dev/ttyUSB1 (USB port 1-1.3.4)
 *   right_device: /dev/ttyUSB0 (USB port 1-1.3.1)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>

/* Protocol message types */
#define MSG_DATA        0x00  /* Raw serial data */
#define MSG_BAUD        0x01  /* Baud rate change */
#define MSG_CONNECTED   0x02  /* Device connected */
#define MSG_DISCONNECTED 0x03 /* Device disconnected */

/* Channels */
#define CHAN_LEFT   0x00
#define CHAN_RIGHT  0x01

/* Configuration */
#define DEFAULT_PORT 5580
#define BUFFER_SIZE 4096

/* USB port paths for pillows (same as Pod3 machine.json) */
#define LEFT_USB_PORT  "1-1.3.4"
#define RIGHT_USB_PORT "1-1.3.1"

static volatile int running = 1;
static int listen_fd = -1;
static int client_fd = -1;
static int left_fd = -1;
static int right_fd = -1;
static pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Discovered device paths (updated dynamically) */
static char left_device[64] = "";
static char right_device[64] = "";
static int listen_port = DEFAULT_PORT;
static int left_device_set = 0;  /* Set via command line */
static int right_device_set = 0;

/* Track current baud rates for device recovery */
static int left_baud = 921600;
static int right_baud = 921600;
static time_t left_last_error = 0;
static time_t right_last_error = 0;

#include <dirent.h>

static void log_msg(const char *fmt, ...) {
    char buf[256];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    int offset = snprintf(buf, sizeof(buf), "[%02d:%02d:%02d] ",
                          tm->tm_hour, tm->tm_min, tm->tm_sec);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + offset, sizeof(buf) - offset, fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", buf);
}

/* Find ttyUSB device for a given USB port path (e.g., "1-1.3.4") */
static int find_tty_for_usb_port(const char *usb_port, char *tty_path, size_t tty_path_size) {
    char sysfs_path[256];
    DIR *dir;
    struct dirent *entry;

    /* Method 1: Look for ttyUSB* directly in the interface directory */
    snprintf(sysfs_path, sizeof(sysfs_path),
             "/sys/bus/usb/devices/%s:1.0", usb_port);
    dir = opendir(sysfs_path);
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, "ttyUSB", 6) == 0) {
                snprintf(tty_path, tty_path_size, "/dev/%s", entry->d_name);
                closedir(dir);
                return 0;
            }
        }
        closedir(dir);
    }

    /* Method 2: Look in tty subdirectory (older kernel layout) */
    snprintf(sysfs_path, sizeof(sysfs_path),
             "/sys/bus/usb/devices/%s:1.0/tty", usb_port);
    dir = opendir(sysfs_path);
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, "ttyUSB", 6) == 0) {
                snprintf(tty_path, tty_path_size, "/dev/%s", entry->d_name);
                closedir(dir);
                return 0;
            }
        }
        closedir(dir);
    }

    return -1;
}

/* Discover pillow devices by USB port path */
static void discover_devices(void) {
    if (!left_device_set) {
        if (find_tty_for_usb_port(LEFT_USB_PORT, left_device, sizeof(left_device)) == 0) {
            log_msg("Discovered left pillow: %s (USB port %s)", left_device, LEFT_USB_PORT);
        } else {
            log_msg("Left pillow not found at USB port %s", LEFT_USB_PORT);
            left_device[0] = '\0';
        }
    }

    if (!right_device_set) {
        if (find_tty_for_usb_port(RIGHT_USB_PORT, right_device, sizeof(right_device)) == 0) {
            log_msg("Discovered right pillow: %s (USB port %s)", right_device, RIGHT_USB_PORT);
        } else {
            log_msg("Right pillow not found at USB port %s", RIGHT_USB_PORT);
            right_device[0] = '\0';
        }
    }
}

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* Convert baud rate integer to termios speed_t */
static speed_t int_to_baud(int baud) {
    switch (baud) {
        case 9600:   return B9600;
        case 19200:  return B19200;
        case 38400:  return B38400;
        case 57600:  return B57600;
        case 115200: return B115200;
        case 230400: return B230400;
        case 460800: return B460800;
        case 500000: return B500000;
        case 576000: return B576000;
        case 921600: return B921600;
        default:     return B38400;
    }
}

/* Set baud rate on serial device */
static int set_baud_rate(int fd, int baud) {
    struct termios tio;
    if (tcgetattr(fd, &tio) < 0) {
        log_msg("tcgetattr failed: %s", strerror(errno));
        return -1;
    }

    speed_t speed = int_to_baud(baud);
    cfsetispeed(&tio, speed);
    cfsetospeed(&tio, speed);

    /* 8N1, raw mode */
    tio.c_cflag &= ~(PARENB | CSTOPB | CSIZE);
    tio.c_cflag |= CS8 | CLOCAL | CREAD;
    tio.c_iflag &= ~(IXON | IXOFF | IXANY | ICRNL | INLCR);
    tio.c_oflag &= ~OPOST;
    tio.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tio) < 0) {
        log_msg("tcsetattr failed: %s", strerror(errno));
        return -1;
    }

    log_msg("Set baud rate to %d", baud);
    return 0;
}

/* Open and configure serial device */
static int open_serial(const char *path, int initial_baud) {
    int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        log_msg("Failed to open %s: %s", path, strerror(errno));
        return -1;
    }

    /* Set initial baud rate */
    if (set_baud_rate(fd, initial_baud) < 0) {
        close(fd);
        return -1;
    }

    log_msg("Opened %s (fd=%d) at %d baud", path, fd, initial_baud);
    return fd;
}

/* Forward declaration */
static int send_msg(uint8_t type, uint8_t channel, const uint8_t *data, uint16_t len);

/* Try to reopen a device after disconnection */
static int try_reopen_device(int channel) {
    const char *usb_port = (channel == CHAN_LEFT) ? LEFT_USB_PORT : RIGHT_USB_PORT;
    const char *side = (channel == CHAN_LEFT) ? "left" : "right";
    int *fd_ptr = (channel == CHAN_LEFT) ? &left_fd : &right_fd;
    char *device = (channel == CHAN_LEFT) ? left_device : right_device;
    int baud = (channel == CHAN_LEFT) ? left_baud : right_baud;
    time_t *last_error = (channel == CHAN_LEFT) ? &left_last_error : &right_last_error;

    /* Don't retry too frequently */
    time_t now = time(NULL);
    if (now - *last_error < 2) {
        return -1;  /* Wait at least 2 seconds between retries */
    }
    *last_error = now;

    /* Close existing fd if open */
    if (*fd_ptr >= 0) {
        close(*fd_ptr);
        *fd_ptr = -1;
        send_msg(MSG_DISCONNECTED, channel, NULL, 0);
    }

    /* Re-discover device path */
    char new_device[64];
    if (find_tty_for_usb_port(usb_port, new_device, sizeof(new_device)) != 0) {
        log_msg("[%s] Device not found at USB port %s, will retry", side, usb_port);
        return -1;
    }

    /* Check if device path changed */
    if (strcmp(device, new_device) != 0) {
        log_msg("[%s] Device changed: %s -> %s", side, device, new_device);
        strncpy(device, new_device, 63);
        device[63] = '\0';
    }

    /* Try to open */
    int new_fd = open_serial(device, baud);
    if (new_fd < 0) {
        log_msg("[%s] Failed to reopen device", side);
        return -1;
    }

    *fd_ptr = new_fd;
    log_msg("[%s] Successfully reopened device at %d baud", side, baud);
    send_msg(MSG_CONNECTED, channel, NULL, 0);
    return 0;
}

/* Send message to network client */
static int send_msg(uint8_t type, uint8_t channel, const uint8_t *data, uint16_t len) {
    pthread_mutex_lock(&client_mutex);
    if (client_fd < 0) {
        pthread_mutex_unlock(&client_mutex);
        return -1;
    }

    /* Message format: [type][channel][len_hi][len_lo][data...] */
    uint8_t header[4];
    header[0] = type;
    header[1] = channel;
    header[2] = (len >> 8) & 0xFF;
    header[3] = len & 0xFF;

    ssize_t sent = write(client_fd, header, 4);
    if (sent != 4) {
        pthread_mutex_unlock(&client_mutex);
        return -1;
    }

    if (len > 0 && data) {
        sent = write(client_fd, data, len);
        if (sent != len) {
            pthread_mutex_unlock(&client_mutex);
            return -1;
        }
    }

    pthread_mutex_unlock(&client_mutex);
    return 0;
}

/* Process incoming network message */
static int process_msg(uint8_t type, uint8_t channel, const uint8_t *data, uint16_t len) {
    int *fd_ptr = (channel == CHAN_LEFT) ? &left_fd : &right_fd;
    int *baud_ptr = (channel == CHAN_LEFT) ? &left_baud : &right_baud;
    const char *side = (channel == CHAN_LEFT) ? "left" : "right";

    /* Try to reopen if device is not open */
    if (*fd_ptr < 0) {
        try_reopen_device(channel);
        if (*fd_ptr < 0) {
            /* Still not open, drop message silently (avoid log spam) */
            return -1;
        }
    }

    switch (type) {
        case MSG_DATA:
            /* Forward data to serial device */
            if (len > 0) {
                ssize_t written = write(*fd_ptr, data, len);
                if (written < 0) {
                    log_msg("[%s] Write failed: %s, will try to reopen", side, strerror(errno));
                    try_reopen_device(channel);
                    return -1;
                }
                /* Per-packet logging disabled to reduce eMMC wear */
            }
            break;

        case MSG_BAUD:
            /* Set baud rate */
            if (len >= 4) {
                int baud = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
                log_msg("[%s] Setting baud rate to %d", side, baud);
                *baud_ptr = baud;  /* Track for device recovery */
                if (set_baud_rate(*fd_ptr, baud) < 0) {
                    log_msg("[%s] Baud rate set failed, will try to reopen", side);
                    try_reopen_device(channel);
                }
            }
            break;

        default:
            log_msg("[%s] Unknown message type 0x%02x", side, type);
            break;
    }

    return 0;
}

/* Read from network and process messages */
static int handle_network_data(void) {
    static uint8_t rx_buf[BUFFER_SIZE];
    static int rx_len = 0;

    /* Read available data */
    ssize_t n = read(client_fd, rx_buf + rx_len, sizeof(rx_buf) - rx_len);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            log_msg("Client disconnected");
            return -1;
        }
        return 0;
    }
    rx_len += n;

    /* Process complete messages */
    while (rx_len >= 4) {
        uint8_t type = rx_buf[0];
        uint8_t channel = rx_buf[1];
        uint16_t msg_len = (rx_buf[2] << 8) | rx_buf[3];

        if (rx_len < 4 + msg_len) {
            break;  /* Incomplete message */
        }

        /* Process message */
        process_msg(type, channel, rx_buf + 4, msg_len);

        /* Remove processed message from buffer */
        int total_len = 4 + msg_len;
        memmove(rx_buf, rx_buf + total_len, rx_len - total_len);
        rx_len -= total_len;
    }

    return 0;
}

/* Read from serial device and forward to network */
static int handle_serial_data(int serial_fd, uint8_t channel) {
    const char *side = (channel == CHAN_LEFT) ? "left" : "right";
    uint8_t buf[BUFFER_SIZE];
    ssize_t n = read(serial_fd, buf, sizeof(buf));

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        log_msg("[%s] Serial read error: %s, will try to reopen", side, strerror(errno));
        try_reopen_device(channel);
        return -1;
    }

    if (n == 0) {
        /* EOF - device disconnected */
        log_msg("[%s] Serial device disconnected (EOF), will try to reopen", side);
        try_reopen_device(channel);
        return -1;
    }

    /* Per-packet logging disabled to reduce eMMC wear */
    send_msg(MSG_DATA, channel, buf, n);
    return 0;
}

/* Main connection handler */
static void handle_client(int cfd) {
    log_msg("Client connected");

    pthread_mutex_lock(&client_mutex);
    client_fd = cfd;
    pthread_mutex_unlock(&client_mutex);

    /* Set TCP_NODELAY for low latency */
    int flag = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    /* Make non-blocking */
    fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK);

    /* Open serial devices at 921600 (frank's initial baud rate)
     * Frank sends heartbeats at 921600, detects bootloader garbage,
     * then switches to 38400 for bootloader mode */
    if (left_device[0]) {
        left_fd = open_serial(left_device, 921600);
    } else {
        log_msg("Left pillow device not configured");
        left_fd = -1;
    }
    if (right_device[0]) {
        right_fd = open_serial(right_device, 921600);
    } else {
        log_msg("Right pillow device not configured");
        right_fd = -1;
    }

    /* Send connection status */
    if (left_fd >= 0) {
        send_msg(MSG_CONNECTED, CHAN_LEFT, NULL, 0);
    }
    if (right_fd >= 0) {
        send_msg(MSG_CONNECTED, CHAN_RIGHT, NULL, 0);
    }

    /* Main loop */
    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);

        int maxfd = cfd;
        FD_SET(cfd, &rfds);

        if (left_fd >= 0) {
            FD_SET(left_fd, &rfds);
            if (left_fd > maxfd) maxfd = left_fd;
        }
        if (right_fd >= 0) {
            FD_SET(right_fd, &rfds);
            if (right_fd > maxfd) maxfd = right_fd;
        }

        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_msg("select error: %s", strerror(errno));
            break;
        }

        if (ret == 0) {
            /* Timeout - try to reopen any disconnected devices */
            if (left_fd < 0 && left_device[0]) {
                try_reopen_device(CHAN_LEFT);
            }
            if (right_fd < 0 && right_device[0]) {
                try_reopen_device(CHAN_RIGHT);
            }
            continue;
        }

        /* Handle network data */
        if (FD_ISSET(cfd, &rfds)) {
            if (handle_network_data() < 0) {
                break;
            }
        }

        /* Handle serial data */
        if (left_fd >= 0 && FD_ISSET(left_fd, &rfds)) {
            handle_serial_data(left_fd, CHAN_LEFT);
        }
        if (right_fd >= 0 && FD_ISSET(right_fd, &rfds)) {
            handle_serial_data(right_fd, CHAN_RIGHT);
        }
    }

    /* Cleanup */
    pthread_mutex_lock(&client_mutex);
    client_fd = -1;
    pthread_mutex_unlock(&client_mutex);

    if (left_fd >= 0) {
        close(left_fd);
        left_fd = -1;
    }
    if (right_fd >= 0) {
        close(right_fd);
        right_fd = -1;
    }
    close(cfd);

    log_msg("Client session ended");
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-p port] [-l left_dev] [-r right_dev]\n", prog);
    fprintf(stderr, "  -p port       TCP listen port (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -l left_dev   Left pillow device (default: %s)\n", left_device);
    fprintf(stderr, "  -r right_dev  Right pillow device (default: %s)\n", right_device);
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "p:l:r:h")) != -1) {
        switch (opt) {
            case 'p':
                listen_port = atoi(optarg);
                break;
            case 'l':
                strncpy(left_device, optarg, sizeof(left_device) - 1);
                left_device[sizeof(left_device) - 1] = '\0';
                left_device_set = 1;
                break;
            case 'r':
                strncpy(right_device, optarg, sizeof(right_device) - 1);
                right_device[sizeof(right_device) - 1] = '\0';
                right_device_set = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    log_msg("Pillow Bridge starting");

    /* Discover devices by USB port path if not specified */
    discover_devices();

    log_msg("  Left pillow:  %s", left_device[0] ? left_device : "(not found)");
    log_msg("  Right pillow: %s", right_device[0] ? right_device : "(not found)");
    log_msg("  Listen port:  %d", listen_port);

    /* Create listening socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        log_msg("socket failed: %s", strerror(errno));
        return 1;
    }

    int reuseaddr = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(listen_port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg("bind failed: %s", strerror(errno));
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {
        log_msg("listen failed: %s", strerror(errno));
        close(listen_fd);
        return 1;
    }

    log_msg("Listening on port %d", listen_port);

    /* Accept connections */
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int cfd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            log_msg("accept failed: %s", strerror(errno));
            break;
        }

        log_msg("Connection from %s:%d",
                inet_ntoa(client_addr.sin_addr),
                ntohs(client_addr.sin_port));

        handle_client(cfd);
    }

    close(listen_fd);
    log_msg("Pillow Bridge stopped");
    return 0;
}
