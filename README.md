# Pillow Bridge

A solution for forwarding pillow serial communications between two Pod devices over the network.

## Background

Pillows have two connections to the Pod:
1. **Water/thermal connection** - provides heating/cooling to the pillow
2. **USB serial connection** - provides sensor data, button input, and vibration control

The USB connection provides:
- Temperature sensing (ambient temp, humidity)
- Presence detection via piezoelectric sensors
- Button/gesture input (double-tap, triple-tap)
- Vibration motor for alarms

**The problem:** Older Pods do not present a usable USB interface for the pillows. This project solves that by allowing the pillow's water connection to go to Pod A (older Pod, for heating/cooling) while the USB data connection goes to Pod B (newer Pod with working USB interface), with data forwarded over the network back to Pod A.

This enables scenarios where:
- Pillows have their water connection to one Pod but USB connection to another
- You want to use pillow features from a Pod that doesn't have working USB pillow ports
- Testing/development with pillows on a different device

## Architecture

```
Pod A (Controller)                   Network                Pod B (USB Host)
Water connection to pillows                                 USB connection to pillows
┌─────────────────┐                                        ┌─────────────────┐
│  frankenfirmware│                                        │                 │
│       │         │                                        │  pillow_bridge  │
│       ▼         │                                        │       │         │
│  pillow_hook.so │◄────────── TCP:5580 ──────────────────►│       ▼         │
│  (LD_PRELOAD)   │                                        │  /dev/ttyUSB0   │──► Left Pillow (USB)
│       │         │                                        │  /dev/ttyUSB1   │──► Right Pillow (USB)
│       ▼         │                                        │                 │
│  Fake PTYs      │                                        └─────────────────┘
│  /dev/pts/X     │
└─────────────────┘
```

### Components

1. **pillow_bridge** (runs on Pod B - where pillows are USB-connected)
   - TCP server listening on port 5580
   - Opens physical USB serial devices (/dev/ttyUSB0, /dev/ttyUSB1)
   - Forwards serial data bidirectionally over the network
   - Handles baud rate changes
   - Auto-reconnects if devices are unplugged/replugged

2. **pillow_hook.so** (runs on Pod A - the controlling hub with water connection)
   - LD_PRELOAD library that intercepts frank's serial device access
   - Creates fake PTY pairs for each pillow
   - Connects to pillow_bridge over the network
   - Forwards data between frank and the remote pillows
   - Handles all the udev/sysfs spoofing so frank thinks pillows are locally USB-connected

## Protocol

The bridge uses a simple framed protocol over TCP:

```
┌──────┬─────────┬────────────┬──────────────┐
│ Type │ Channel │ Length (BE)│    Data      │
│ 1B   │ 1B      │ 2B         │ 0-65535B     │
└──────┴─────────┴────────────┴──────────────┘
```

Message Types:
- `0x00` MSG_DATA - Raw serial data
- `0x01` MSG_BAUD - Baud rate change (4 bytes, big-endian)
- `0x02` MSG_CONNECTED - Device connected notification
- `0x03` MSG_DISCONNECTED - Device disconnected notification

Channels:
- `0x00` CHAN_LEFT - Left pillow
- `0x01` CHAN_RIGHT - Right pillow

## Installation

### Prerequisites

- Two Pods with SSH access (port 8822)
- Cross-compiler for aarch64 (or compile natively on the Pods)
- Root access to both Pods

### Building

```bash
# Cross-compile for aarch64
aarch64-linux-gnu-gcc -o pillow_bridge pillow_bridge.c -lpthread -static
aarch64-linux-gnu-gcc -shared -fPIC -o pillow_hook.so pillow_hook.c -ldl -lpthread

# Or compile natively on the Pod
gcc -o pillow_bridge pillow_bridge.c -lpthread
gcc -shared -fPIC -o pillow_hook.so pillow_hook.c -ldl -lpthread
```

### Installing on Pod B (Pillow Host)

```bash
# Remount filesystem read-write
ssh -p 8822 root@<POD_B_IP> 'mount -o remount,rw /'

# Copy binary and service
scp -P 8822 pillow_bridge root@<POD_B_IP>:/opt/pillow_bridge
scp -P 8822 pillow_bridge.service root@<POD_B_IP>:/etc/systemd/system/

# Enable and start service
ssh -p 8822 root@<POD_B_IP> 'systemctl daemon-reload && systemctl enable pillow_bridge && systemctl start pillow_bridge'
```

### Installing on Pod A (Controller)

```bash
# Remount filesystem read-write
ssh -p 8822 root@<POD_A_IP> 'mount -o remount,rw /'

# Copy hook library
scp -P 8822 pillow_hook.so root@<POD_A_IP>:/opt/pillow_hook.so

# Create frank.service override to load the hook
ssh -p 8822 root@<POD_A_IP> 'mkdir -p /etc/systemd/system/frank.service.d'
ssh -p 8822 root@<POD_A_IP> 'cat > /etc/systemd/system/frank.service.d/override.conf << EOF
[Service]
Environment=LD_PRELOAD=/opt/pillow_hook.so
Environment=LD_LIBRARY_PATH=/opt/fakelib
EOF'

# Reload and restart
ssh -p 8822 root@<POD_A_IP> 'systemctl daemon-reload && systemctl restart frank'
```

## Configuration

### Pillow USB Port Mapping

The USB port assignments are configured in `/opt/eight/config/machine.json`:

```json
{
    "leftPillowPort": "1-1.3.4",
    "rightPillowPort": "1-1.3.1"
}
```

To swap left/right pillow mapping, edit this file on Pod A and restart frank.

### Bridge Host Configuration

The hook connects to the bridge at a hardcoded address. To change it, modify these defines in `pillow_hook.c`:

```c
#define BRIDGE_HOST "192.168.1.209"
#define BRIDGE_PORT 5580
```

## Troubleshooting

### Check Service Status

```bash
# On Pod B (bridge)
ssh -p 8822 root@<POD_B_IP> 'systemctl status pillow_bridge'
ssh -p 8822 root@<POD_B_IP> 'journalctl -u pillow_bridge -f'

# On Pod A (hook)
ssh -p 8822 root@<POD_A_IP> 'systemctl status frank'
ssh -p 8822 root@<POD_A_IP> 'cat /tmp/pillow_hook.log'
```

### Verify Pillow Detection

```bash
# Check if frank sees the pillows
ssh -p 8822 root@<POD_A_IP> 'journalctl -u frank | grep -E "left-pillow|right-pillow" | tail -20'

# Check pillow temperatures
ssh -p 8822 root@<POD_A_IP> 'journalctl -u frank | grep "\[tmp\]" | tail -10'
```

### Common Issues

1. **"Connection refused" errors in hook log**
   - Ensure pillow_bridge is running on Pod B
   - Check firewall allows TCP port 5580
   - Verify the BRIDGE_HOST IP is correct

2. **Pillows not detected**
   - Check physical USB connections on Pod B
   - Verify USB port paths match machine.json
   - Check `journalctl -u pillow_bridge` for device discovery messages

3. **Left/Right pillows swapped**
   - Edit `/opt/eight/config/machine.json` on Pod A
   - Swap the `leftPillowPort` and `rightPillowPort` values
   - Restart frank: `systemctl restart frank`

## Files

| File | Description |
|------|-------------|
| `pillow_bridge.c` | TCP bridge server (runs on pillow host) |
| `pillow_hook.c` | LD_PRELOAD hook library (runs on controller) |
| `pillow_bridge.service` | systemd service for bridge |
| `install-bridge.sh` | Installation script for pillow host |
| `install-hook.sh` | Installation script for controller |

## License

MIT License - See LICENSE file for details.

## Acknowledgments

This project is part of the [free-sleep](https://github.com/throwaway96/free-sleep) ecosystem.
