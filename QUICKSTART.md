# 🚀 GVM Panel v2.0 - Quick Start Guide (5 Minutes!)

## Step 1: Download & Extract (30 seconds)

```bash
# Upload gvm-panel-v2-complete.tar.gz to your server
# Then extract:

cd /root
tar -xzf gvm-panel-v2-complete.tar.gz
cd gvm-panel-v2
```

## Step 2: Run Auto-Installer (3-4 minutes)

```bash
chmod +x setup.sh
sudo bash setup.sh
```

**Wait for installation to complete...**

You'll see:
```
✅ Installation Complete!
========================

🎉 GVM Panel v2.0 is ready!

📝 Default Login:
   Username: admin
   Password: admin

🌐 Access Panel:
   http://YOUR_SERVER_IP:5000
```

## Step 3: Access Panel (10 seconds)

Open browser:
```
http://YOUR_SERVER_IP:5000
```

Login:
- Username: `admin`
- Password: `admin`

## Step 4: Change Password (30 seconds)

⚠️ **IMPORTANT:** Change default password immediately!

## Step 5: Create Your First Container (2 minutes)

1. Click **"Admin Panel"**
2. Click **"Create Container"**
3. Select user: `admin`
4. Set resources:
   - RAM: 2 GB
   - CPU: 2 cores
   - Disk: 20 GB
5. Click **"Create Container"**
6. Wait 2-5 minutes for creation

## 🎉 Done! Your container is ready!

---

## 📚 What's Next?

### Start Managing Containers:
- ✅ Start/Stop/Restart containers
- ✅ View live statistics
- ✅ Access via SSH
- ✅ Create snapshots
- ✅ Share with other users

### Explore Features:
- 📊 Real-time monitoring
- 🔒 Auto-suspension system
- 📸 Snapshot backups
- 🤝 Container sharing
- 👨‍💼 Admin panel

---

## 🆘 Need Help?

**Service not starting?**
```bash
sudo journalctl -u gvm-panel -f
```

**Can't access panel?**
```bash
sudo systemctl status gvm-panel
sudo ufw allow 5000/tcp
```

**Container creation failed?**
```bash
lxc list
lxd init --auto
```

---

## 📖 Full Documentation

- `README.md` - Complete features & usage
- `INSTALL.md` - Detailed installation guide
- `FEATURES.md` - All 100+ features listed

---

## 🔥 Key Commands

```bash
# Service Control
systemctl start gvm-panel      # Start panel
systemctl stop gvm-panel       # Stop panel
systemctl restart gvm-panel    # Restart panel
systemctl status gvm-panel     # Check status

# Logs
journalctl -u gvm-panel -f     # Live logs
cat /root/gvm-panel-v2/gvm_panel.log  # App logs

# LXD/LXC
lxc list                       # List containers
lxc info <container>           # Container info
```

---

## 💡 Pro Tips

1. **Access via HTTPS**: See `INSTALL.md` for Nginx setup
2. **Backup Database**: `cp gvm_panel.db backup.db`
3. **Monitor Host**: Check CPU usage in Admin Panel
4. **Use Snapshots**: Create before major changes
5. **Share Wisely**: Only share with trusted users

---

**🎉 Enjoy GVM Panel v2.0!**

The most complete LXC management system with 100+ features!
