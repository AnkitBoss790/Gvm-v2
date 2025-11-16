# GVM Panel v2.0 - Complete LXC Container Management System

**🚀 Enterprise-Grade Web Panel for LXC/LXD Container Management**

A powerful, feature-rich web interface for managing LXC containers with advanced monitoring, security, and administration capabilities.

---

## ✨ Features

### 🎯 Core Features
- ✅ **Container Management**: Create, Start, Stop, Restart, Delete containers
- ✅ **User Management**: Multi-user system with role-based access control
- ✅ **Resource Allocation**: Configure CPU, RAM, and Disk for each container
- ✅ **SSH Access**: Pre-configured SSH with auto-generated credentials
- ✅ **Live Statistics**: Real-time CPU, RAM, Disk, and Process monitoring
- ✅ **Container Sharing**: Share containers with other users
- ✅ **Snapshot Management**: Create and restore container snapshots

### 🔒 Security Features
- ✅ **User Authentication**: Secure login/registration system
- ✅ **Admin Panel**: Comprehensive administration interface
- ✅ **Audit Logging**: Complete activity tracking
- ✅ **Access Control**: Owner/Shared/Admin permission system
- ✅ **Session Management**: Secure session handling

### 📊 Advanced Monitoring
- ✅ **Host CPU Monitoring**: Auto-stop all containers if host CPU > 90%
- ✅ **Per-Container Monitoring**: Auto-suspend abusive containers
- ✅ **Resource Thresholds**: Configurable CPU/RAM limits
- ✅ **Suspension History**: Track all suspension events
- ✅ **Real-time Stats**: Live container resource usage
- ✅ **Process Viewer**: See running processes in containers
- ✅ **Log Viewer**: Access container logs

### ⚡ Admin Features
- ✅ **System Overview**: Dashboard with all statistics
- ✅ **User Management**: Manage users and assign admin roles
- ✅ **Container Control**: Full control over all containers
- ✅ **Bulk Operations**: Stop/Start multiple containers
- ✅ **Resource Resizing**: Adjust container resources on-the-fly
- ✅ **Suspension Management**: Manually suspend/unsuspend containers
- ✅ **Monitoring Toggle**: Enable/disable auto-monitoring

---

## 📋 Requirements

- **OS**: Ubuntu 20.04/22.04 LTS or Debian 11/12
- **LXD/LXC**: Latest stable version (installed via snap)
- **Python**: 3.8 or higher
- **Root Access**: Required for installation
- **RAM**: Minimum 4GB (recommended 8GB+)
- **Disk**: 20GB+ free space

---

## 🚀 Quick Installation

### 1. Clone or Download the Project

```bash
cd /root
git clone <your-repo-url> gvm-panel-v2
cd gvm-panel-v2
```

Or if you have the files:

```bash
cd /root/gvm-panel-v2
```

### 2. Run Installation Script

```bash
sudo bash setup.sh
```

The installer will:
- ✅ Update system packages
- ✅ Install LXD/LXC
- ✅ Install Python 3 and dependencies
- ✅ Create virtual environment
- ✅ Install Python packages
- ✅ Initialize database
- ✅ Create default admin user
- ✅ Setup systemd service
- ✅ Configure firewall

### 3. Access the Panel

```
http://YOUR_SERVER_IP:5000
```

**Default Login:**
- Username: `admin`
- Password: `admin`

**⚠️ Change the default password immediately after first login!**

---

## 🎮 Usage

### For Users

#### View Containers
1. Login to dashboard
2. See all your containers with status
3. View shared containers from other users

#### Manage Container
1. Click "View" on any container
2. Start/Stop/Restart from controls
3. View live statistics (CPU, RAM, Disk)
4. Access SSH connection details
5. Create/Restore snapshots

#### Share Container
1. Go to container details (owner only)
2. Enter User ID in "Share Management"
3. Click "Share"
4. Shared user gets read/control access

### For Admins

#### Access Admin Panel
1. Click "Admin Panel" in navigation
2. View system overview and statistics
3. Monitor all users and containers

#### Create Container
1. Go to Admin Panel
2. Click "Create Container"
3. Select user and configure resources
4. Submit to create (takes 2-5 minutes)

#### Manage Users
1. View all users in admin panel
2. Toggle admin status for any user
3. See container count per user

#### Suspend/Unsuspend
1. Find container in admin panel
2. Click suspend button and provide reason
3. User cannot start until unsuspended
4. Click unsuspend to restore access

#### Resize Container
1. Click resize button in admin panel
2. Enter new RAM/CPU/Disk values
3. Changes apply immediately

#### Monitor System
- View host CPU usage in real-time
- Toggle auto-monitoring on/off
- Review audit logs for all activities

---

## ⚙️ Configuration

### Environment Variables

Create `.env` file:

```bash
# Monitoring Thresholds
CPU_THRESHOLD=90          # Host CPU threshold (%)
RAM_THRESHOLD=90          # Container RAM threshold (%)
CHECK_INTERVAL=600        # Check interval (seconds)

# LXD Configuration
DEFAULT_STORAGE_POOL=default

# Flask Configuration
FLASK_SECRET_KEY=your-secret-key-here
```

### Monitoring Configuration

The panel includes two monitoring systems:

#### 1. Host CPU Monitor
- Checks host CPU every 60 seconds
- If CPU > 90%, stops ALL running containers
- Prevents system crash from overload
- Logs event in audit log

#### 2. Per-Container Monitor
- Checks running containers every 10 minutes
- If container CPU > 90% OR RAM > 90%:
  - Auto-stops the container
  - Marks as suspended
  - Records in suspension history
  - User cannot restart until admin unsuspends

### Adjust Thresholds

Edit `app.py`:

```python
CPU_THRESHOLD = int(os.getenv('CPU_THRESHOLD', '90'))
RAM_THRESHOLD = int(os.getenv('RAM_THRESHOLD', '90'))
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '600'))
```

---

## 🔧 Service Management

### Control GVM Panel Service

```bash
# Start service
systemctl start gvm-panel

# Stop service
systemctl stop gvm-panel

# Restart service
systemctl restart gvm-panel

# Check status
systemctl status gvm-panel

# View logs
journalctl -u gvm-panel -f

# Enable auto-start
systemctl enable gvm-panel

# Disable auto-start
systemctl disable gvm-panel
```

### Manual Start (Development)

```bash
cd /root/gvm-panel-v2
source venv/bin/activate
python3 app.py
```

---

## 📊 API Endpoints

### Container Stats
```
GET /api/container/<id>/stats
Returns: {status, stats: {cpu, memory, disk, processes}}
```

### Container Processes
```
GET /api/container/<id>/processes
Returns: {processes: "..."}
```

### Container Logs
```
GET /api/container/<id>/logs?lines=50
Returns: {logs: "..."}
```

---

## 🗄️ Database Schema

### Users
- id, username, email, password_hash
- is_admin, created_at
- Relationships: containers

### Containers
- id, name, user_id
- ram_gb, cpu_cores, disk_gb
- status, ssh_password, suspended
- suspension_history (JSON)
- shared_with (JSON array of user IDs)
- created_at

### ContainerSnapshot
- id, container_id, snapshot_name
- description, created_at

### AuditLog
- id, user_id, action
- timestamp, ip_address, details

---

## 🛠️ Troubleshooting

### Container Creation Fails

```bash
# Check LXD status
lxc list

# Reinitialize LXD
lxd init

# Check storage
lxc storage list
```

### Permission Issues

```bash
# Run panel as root
sudo systemctl restart gvm-panel

# Check service user
systemctl status gvm-panel | grep User
```

### Database Issues

```bash
cd /root/gvm-panel-v2
rm gvm_panel.db
python3 -c "from app import init_db; init_db()"
```

### Port Already in Use

```bash
# Find process using port 5000
lsof -i :5000

# Kill process
kill -9 <PID>

# Or change port in app.py
app.run(host='0.0.0.0', port=8000)
```

---

## 🔐 Security Best Practices

1. **Change Default Admin Password**
   - Login as admin immediately
   - Change password to strong one

2. **Firewall Configuration**
   ```bash
   ufw allow 5000/tcp
   ufw allow 22/tcp
   ufw enable
   ```

3. **SSL/TLS Setup** (Recommended)
   - Use reverse proxy (Nginx/Apache)
   - Install SSL certificate (Let's Encrypt)
   - Force HTTPS

4. **Regular Backups**
   ```bash
   # Backup database
   cp gvm_panel.db gvm_panel_backup_$(date +%Y%m%d).db
   
   # Backup LXD containers
   lxc export container-name backup.tar.gz
   ```

5. **Update Regularly**
   ```bash
   apt update && apt upgrade -y
   snap refresh lxd
   ```

---

## 📝 License

This project is open-source and available under the MIT License.

---

## 👨‍💻 Author

Created with ❤️ for the community

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

---

## 📞 Support

For issues and questions:
- Check this README
- Review logs: `journalctl -u gvm-panel -f`
- Check container logs in the panel

---

## 🎉 Changelog

### v2.0 (Current)
- ✅ Complete rewrite with Flask
- ✅ Modern responsive UI
- ✅ All Discord bot features integrated
- ✅ Advanced monitoring system
- ✅ Container sharing
- ✅ Snapshot management
- ✅ Comprehensive admin panel
- ✅ Audit logging
- ✅ Auto-installation script

---

**Made with 🚀 by GVM Team**
