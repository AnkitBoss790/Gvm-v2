#!/bin/bash

echo "🚀 GVM Panel v2.0 - Complete Installation Script"
echo "=================================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (sudo bash setup.sh)"
    exit 1
fi

echo "✅ Running as root"
echo ""

# Update system
echo "📦 Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

# Install LXD/LXC
echo "📦 Installing LXD/LXC..."
snap install lxd --channel=latest/stable
lxd init --auto

# Install Python and dependencies
echo "📦 Installing Python 3 and pip..."
apt-get install -y python3 python3-pip python3-venv -qq

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo "📦 Installing Python packages..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# Create directories
echo "📁 Creating directories..."
mkdir -p static/css static/js templates/admin
chmod -R 755 static templates

# Initialize database
echo "🗄️ Initializing database..."
python3 << EOF
from app import app, db, User
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@gvmpanel.local', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created: username=admin, password=admin")
    else:
        print("✅ Admin user already exists")
EOF

# Create systemd service
echo "⚙️ Creating systemd service..."
cat > /etc/systemd/system/gvm-panel.service << 'SERVICEEOF'
[Unit]
Description=GVM Panel v2.0 - LXC Container Management
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/gvm-panel-v2
Environment="PATH=/root/gvm-panel-v2/venv/bin"
ExecStart=/root/gvm-panel-v2/venv/bin/python3 app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Enable and start service
systemctl daemon-reload
systemctl enable gvm-panel.service

# Configure firewall (if UFW is installed)
if command -v ufw &> /dev/null; then
    echo "🔥 Configuring firewall..."
    ufw allow 5000/tcp
    ufw --force enable
fi

echo ""
echo "✅ Installation Complete!"
echo "========================="
echo ""
echo "🎉 GVM Panel v2.0 is ready!"
echo ""
echo "📝 Default Login:"
echo "   Username: admin"
echo "   Password: admin"
echo ""
echo "🌐 Access Panel:"
echo "   http://YOUR_SERVER_IP:5000"
echo ""
echo "⚙️ Control Service:"
echo "   Start:   systemctl start gvm-panel"
echo "   Stop:    systemctl stop gvm-panel"
echo "   Restart: systemctl restart gvm-panel"
echo "   Status:  systemctl status gvm-panel"
echo "   Logs:    journalctl -u gvm-panel -f"
echo ""
echo "🔒 Security: Change admin password after first login!"
echo ""
