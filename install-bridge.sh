#!/bin/bash
# Install pillow_bridge on the Pod with pillow USB connections
# This Pod has the pillows' USB serial cables connected to it.
# (The pillows' water/thermal connections may go to a different Pod)
# Usage: ./install-bridge.sh <pod_ip>

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <pod_ip>"
    echo "Example: $0 192.168.1.209"
    exit 1
fi

POD="root@$1"
SSH_PORT=8822

echo "=== Installing pillow_bridge on $1 ==="

# Remount root as read-write
echo "Remounting filesystem..."
ssh -p $SSH_PORT $POD 'mount -o remount,rw /'

# Stop existing service/process
echo "Stopping existing pillow_bridge..."
ssh -p $SSH_PORT $POD 'systemctl stop pillow_bridge 2>/dev/null || true; pkill -9 pillow_bridge 2>/dev/null || true'

# Copy binary
echo "Copying pillow_bridge binary..."
scp -P $SSH_PORT pillow_bridge $POD:/opt/pillow_bridge
ssh -p $SSH_PORT $POD 'chmod +x /opt/pillow_bridge'

# Copy and install service
echo "Installing systemd service..."
scp -P $SSH_PORT pillow_bridge.service $POD:/etc/systemd/system/
ssh -p $SSH_PORT $POD 'systemctl daemon-reload'
ssh -p $SSH_PORT $POD 'systemctl enable pillow_bridge'

# Start service
echo "Starting pillow_bridge service..."
ssh -p $SSH_PORT $POD 'systemctl start pillow_bridge'

# Verify
sleep 2
echo ""
echo "=== Service Status ==="
ssh -p $SSH_PORT $POD 'systemctl status pillow_bridge --no-pager'

echo ""
echo "Done! pillow_bridge is installed and running."
