#!/bin/bash
# Install pillow_hook on the controller Pod (with pillow water/thermal connections)
# This Pod has the pillows' water connections but lacks working USB ports for pillows.
# The hook intercepts USB device access and forwards to a remote Pod via network.
# Uses the existing frank.service with a systemd override.
# Usage: ./install-hook.sh <pod_ip>

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <pod_ip>"
    echo "Example: $0 192.168.1.13"
    exit 1
fi

POD="root@$1"
SSH_PORT=8822

echo "=== Installing pillow_hook on $1 ==="

# Remount root as read-write
echo "Remounting filesystem..."
ssh -p $SSH_PORT $POD 'mount -o remount,rw /'

# Stop existing frank processes
echo "Stopping existing frankenfirmware..."
ssh -p $SSH_PORT $POD 'systemctl stop frank 2>/dev/null || true; pkill -9 frankenfirmware 2>/dev/null || true'
sleep 1

# Create directories
echo "Creating directories..."
ssh -p $SSH_PORT $POD 'mkdir -p /opt/fakelib /etc/systemd/system/frank.service.d'

# Copy hook library
echo "Copying pillow_hook.so..."
scp -P $SSH_PORT pillow_hook.so $POD:/opt/pillow_hook.so

# Create systemd override for frank.service
echo "Creating frank.service override..."
ssh -p $SSH_PORT $POD 'cat > /etc/systemd/system/frank.service.d/override.conf << "EOF"
[Service]
Environment=LD_PRELOAD=/opt/pillow_hook.so
Environment=LD_LIBRARY_PATH=/opt/fakelib
EOF'

# Reload systemd
ssh -p $SSH_PORT $POD 'systemctl daemon-reload'

# Ensure frank.service is enabled
ssh -p $SSH_PORT $POD 'systemctl enable frank'

# Start service
echo "Starting frank service..."
ssh -p $SSH_PORT $POD 'systemctl start frank'

# Verify
sleep 3
echo ""
echo "=== Service Status ==="
ssh -p $SSH_PORT $POD 'systemctl status frank --no-pager' || true

echo ""
echo "=== Recent Hook Logs ==="
ssh -p $SSH_PORT $POD 'tail -30 /tmp/pillow_hook.log 2>/dev/null || journalctl -u frank -n 30 --no-pager'

echo ""
echo "Done! pillow_hook is installed and frank.service is running with the hook."
