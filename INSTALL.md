# GVM Panel v2.0 - Complete Installation Guide

## 🎯 Quick Start (5 Minutes)

```bash
# 1. Download or upload files to your server
cd /root

# 2. Make setup script executable
chmod +x gvm-panel-v2/setup.sh

# 3. Run installer
cd gvm-panel-v2
sudo bash setup.sh

# 4. Wait 3-5 minutes for installation

# 5. Access panel
# http://YOUR_SERVER_IP:5000
# Username: admin
# Password: admin
```

---

## 📦 What's Included

```
gvm-panel-v2/
├── app.py                          # Main application (Flask backend)
├── config.py                       # Configuration management
├── requirements.txt                # Python dependencies
├── setup.sh                        # Auto-installer script
├── README.md                       # Full documentation
├── INSTALL.md                      # This file
├── templates/                      # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── container_detail.html
│   └── admin/
│       ├── panel.html
│       └── create_container.html
└── static/                         # CSS & JavaScript
    ├── css/
    │   └── style.css
    └── js/
        └── main.js
```

---

## 🔧 Manual Installation (Step-by-Step)

### Step 1: System Requirements Check

```bash
# Check OS
lsb_release -a
# Should be: Ubuntu 20.04/22.04 or Debian 11/12

# Check RAM
free -h
# Minimum: 4GB (Recommended: 8GB+)

# Check Disk Space
df -h
# Need: 20GB+ free space

# Check Python
python3 --version
# Should be: 3.8+
```

### Step 2: Update System

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl wget
```

### Step 3: Install LXD/LXC

```bash
# Install LXD via snap
sudo snap install lxd --channel=latest/stable

# Initialize LXD (auto mode)
sudo lxd init --auto

# Verify installation
lxc list
```

### Step 4: Setup Application

```bash
# Navigate to project directory
cd /root/gvm-panel-v2

# Create Python virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 5: Initialize Database

```bash
# Still in virtual environment
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
        print("✅ Admin user created")
EOF
```

### Step 6: Create Systemd Service

```bash
# Create service file
sudo tee /etc/systemd/system/gvm-panel.service > /dev/null << 'EOF'
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
EOF

# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable gvm-panel

# Start service
sudo systemctl start gvm-panel

# Check status
sudo systemctl status gvm-panel
```

### Step 7: Configure Firewall

```bash
# If using UFW
sudo ufw allow 5000/tcp
sudo ufw allow 22/tcp
sudo ufw enable

# If using firewalld
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload

# Verify
sudo ufw status
# or
sudo firewall-cmd --list-all
```

### Step 8: Access Panel

```
Open browser: http://YOUR_SERVER_IP:5000

Login:
- Username: admin
- Password: admin

⚠️ CHANGE PASSWORD IMMEDIATELY!
```

---

## 🌐 Production Deployment (HTTPS with Nginx)

### Install Nginx

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

### Configure Nginx Reverse Proxy

```bash
sudo tee /etc/nginx/sites-available/gvm-panel > /dev/null << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/gvm-panel /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

### Setup SSL Certificate (Let's Encrypt)

```bash
# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal is configured by default
# Test renewal
sudo certbot renew --dry-run
```

### Update Firewall

```bash
sudo ufw allow 'Nginx Full'
sudo ufw delete allow 5000/tcp
sudo ufw status
```

Now access via: `https://your-domain.com`

---

## 🔐 Security Hardening

### 1. Change Default Admin Password

```bash
# Login to panel
# Go to profile settings
# Change password to strong one (16+ characters)
```

### 2. Disable Root SSH (After setup)

```bash
sudo nano /etc/ssh/sshd_config

# Change:
PermitRootLogin no

# Restart SSH
sudo systemctl restart sshd
```

### 3. Setup Fail2Ban

```bash
# Install fail2ban
sudo apt install -y fail2ban

# Create config
sudo tee /etc/fail2ban/jail.local > /dev/null << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOF

# Start fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 4. Setup Automatic Updates

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## 🧪 Testing Installation

### Test 1: Service Status

```bash
sudo systemctl status gvm-panel
# Should show: active (running)
```

### Test 2: LXD Connectivity

```bash
lxc list
# Should show empty list or existing containers
```

### Test 3: Web Access

```bash
curl http://localhost:5000
# Should return HTML content
```

### Test 4: Create Test Container

1. Login as admin
2. Go to Admin Panel
3. Click "Create Container"
4. Select your user, set resources
5. Click Create
6. Wait 2-5 minutes
7. Check if container appears in dashboard

---

## 🐛 Troubleshooting

### Issue: Service Won't Start

```bash
# Check logs
sudo journalctl -u gvm-panel -n 50 --no-pager

# Check app.py errors
cd /root/gvm-panel-v2
source venv/bin/activate
python3 app.py
# See error output
```

### Issue: Can't Access Web Panel

```bash
# Check if service is running
sudo systemctl status gvm-panel

# Check if port is open
sudo lsof -i :5000

# Check firewall
sudo ufw status

# Try accessing locally
curl http://localhost:5000
```

### Issue: Database Errors

```bash
cd /root/gvm-panel-v2

# Backup old database
mv gvm_panel.db gvm_panel_backup.db

# Recreate database
source venv/bin/activate
python3 -c "from app import init_db; init_db()"
```

### Issue: LXD Not Working

```bash
# Check LXD status
snap list lxd
sudo systemctl status snap.lxd.daemon

# Reinitialize LXD
sudo lxd init --auto

# Test LXD
lxc list
```

### Issue: Permission Denied

```bash
# Ensure running as root
sudo systemctl restart gvm-panel

# Check file permissions
cd /root/gvm-panel-v2
ls -la
# Should be owned by root
```

---

## 📊 Performance Tuning

### For High Load (Many Containers)

Edit `app.py` and change:

```python
# Increase check interval (default: 600 seconds = 10 min)
CHECK_INTERVAL = 1800  # 30 minutes

# Use production WSGI server
# Install gunicorn
pip install gunicorn

# Run with:
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### For Limited Resources

```bash
# Edit monitoring thresholds
nano /root/gvm-panel-v2/.env

# Add:
CPU_THRESHOLD=85
RAM_THRESHOLD=85
CHECK_INTERVAL=900
```

---

## 🔄 Updating

```bash
cd /root/gvm-panel-v2

# Stop service
sudo systemctl stop gvm-panel

# Backup database
cp gvm_panel.db gvm_panel_backup_$(date +%Y%m%d).db

# Pull updates (if using git)
git pull

# Reinstall dependencies
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Start service
sudo systemctl start gvm-panel
```

---

## 🗑️ Uninstallation

```bash
# Stop and disable service
sudo systemctl stop gvm-panel
sudo systemctl disable gvm-panel

# Remove service file
sudo rm /etc/systemd/system/gvm-panel.service
sudo systemctl daemon-reload

# Remove application
cd /root
rm -rf gvm-panel-v2

# Optional: Remove LXD
sudo snap remove lxd

# Optional: Remove all containers
lxc list --format json | jq -r '.[].name' | xargs -I {} lxc delete {} --force
```

---

## 📞 Support

**Common Issues:**
- Service won't start → Check logs: `journalctl -u gvm-panel -f`
- Can't create containers → Check LXD: `lxc list`
- Database errors → Recreate database
- Permission issues → Ensure running as root

**Need Help?**
- Check logs in: `/root/gvm-panel-v2/gvm_panel.log`
- Review service logs: `journalctl -u gvm-panel -f`
- Test manually: `cd /root/gvm-panel-v2 && source venv/bin/activate && python3 app.py`

---

## ✅ Post-Installation Checklist

- [ ] Service is running: `systemctl status gvm-panel`
- [ ] Can access web panel at `http://IP:5000`
- [ ] Changed default admin password
- [ ] Created test container successfully
- [ ] Firewall configured properly
- [ ] (Optional) Setup HTTPS with Nginx
- [ ] (Optional) Setup automatic backups
- [ ] (Optional) Configure monitoring alerts

---

**🎉 Installation Complete!**

Your GVM Panel v2.0 is ready to use!

Access: `http://YOUR_SERVER_IP:5000`

Login: `admin` / `admin` (Change immediately!)
