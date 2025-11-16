from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import subprocess
import json
import os
from datetime import datetime, timedelta
import secrets
import logging
import threading
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('gvm_panel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gvm_panel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# System Configuration
CPU_THRESHOLD = int(os.getenv('CPU_THRESHOLD', '90'))
RAM_THRESHOLD = int(os.getenv('RAM_THRESHOLD', '90'))
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '600'))
DEFAULT_STORAGE_POOL = os.getenv('DEFAULT_STORAGE_POOL', 'default')

db = SQLAlchemy(app)

# Global monitoring state
monitoring_active = True

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    containers = db.relationship('Container', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Container(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ram_gb = db.Column(db.Integer, default=1)
    cpu_cores = db.Column(db.Integer, default=1)
    disk_gb = db.Column(db.Integer, default=10)
    status = db.Column(db.String(20), default='stopped')
    ssh_password = db.Column(db.String(50), nullable=True)
    suspended = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Enhanced fields
    suspension_history = db.Column(db.Text, default='[]')  # JSON array
    shared_with = db.Column(db.Text, default='[]')  # JSON array of user IDs

class ContainerSnapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    container_id = db.Column(db.Integer, db.ForeignKey('container.id'), nullable=False)
    snapshot_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    details = db.Column(db.Text)

# LXC Management Functions
class LXCManager:
    @staticmethod
    def execute_command(command, timeout=120):
        """Execute system command safely"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Command timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def list_containers():
        """List all LXC containers"""
        result = LXCManager.execute_command("lxc list --format json")
        if result['success']:
            try:
                return json.loads(result['output'])
            except json.JSONDecodeError:
                return []
        return []

    @staticmethod
    def get_container_status(name):
        """Get container status"""
        containers = LXCManager.list_containers()
        for container in containers:
            if container['name'] == name:
                return container.get('status', 'Unknown')
        return 'Not Found'

    @staticmethod
    def get_container_stats(name):
        """Get container resource usage"""
        stats = {
            'cpu': '0%',
            'memory': '0MB',
            'disk': '0GB',
            'network': '0 KB/s',
            'processes': 'Unknown'
        }
        
        # Get CPU usage
        result = LXCManager.execute_command(f"lxc exec {name} -- top -bn1 | grep 'Cpu(s)'", timeout=10)
        if result['success']:
            try:
                cpu_line = result['output']
                if 'id,' in cpu_line:
                    idle = float(cpu_line.split('id,')[0].split()[-1])
                    stats['cpu'] = f"{100 - idle:.1f}%"
            except:
                pass

        # Get memory usage
        result = LXCManager.execute_command(f"lxc exec {name} -- free -m", timeout=10)
        if result['success']:
            try:
                lines = result['output'].split('\n')
                if len(lines) > 1:
                    mem_line = lines[1].split()
                    used = int(mem_line[2])
                    total = int(mem_line[1])
                    stats['memory'] = f"{used}MB / {total}MB ({(used/total*100):.1f}%)"
            except:
                pass

        # Get disk usage
        result = LXCManager.execute_command(f"lxc exec {name} -- df -h /", timeout=10)
        if result['success']:
            try:
                lines = result['output'].split('\n')
                for line in lines:
                    if '/dev/' in line and ' /' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            stats['disk'] = f"{parts[2]} / {parts[1]} ({parts[4]})"
            except:
                pass

        # Get process count
        result = LXCManager.execute_command(f"lxc exec {name} -- ps aux | wc -l", timeout=10)
        if result['success']:
            try:
                stats['processes'] = result['output'].strip()
            except:
                pass

        return stats

    @staticmethod
    def get_cpu_percentage(name):
        """Get CPU usage as percentage (float)"""
        result = LXCManager.execute_command(f"lxc exec {name} -- top -bn1 | grep 'Cpu(s)'", timeout=10)
        if result['success']:
            try:
                cpu_line = result['output']
                if 'id,' in cpu_line:
                    idle = float(cpu_line.split('id,')[0].split()[-1])
                    return 100 - idle
            except:
                pass
        return 0.0

    @staticmethod
    def get_ram_percentage(name):
        """Get RAM usage as percentage (float)"""
        result = LXCManager.execute_command(f"lxc exec {name} -- free -m", timeout=10)
        if result['success']:
            try:
                lines = result['output'].split('\n')
                if len(lines) > 1:
                    mem_line = lines[1].split()
                    used = int(mem_line[2])
                    total = int(mem_line[1])
                    return (used / total * 100) if total > 0 else 0.0
            except:
                pass
        return 0.0

    @staticmethod
    def create_container(name, ram_gb, cpu_cores, disk_gb, ssh_password):
        """Create new LXC container with SSH"""
        try:
            # Create container
            result = LXCManager.execute_command(f"lxc init ubuntu:22.04 {name} --storage {DEFAULT_STORAGE_POOL}")
            if not result['success']:
                return {'success': False, 'error': result['error']}

            # Set resources
            ram_mb = ram_gb * 1024
            LXCManager.execute_command(f"lxc config set {name} limits.memory {ram_mb}MB")
            LXCManager.execute_command(f"lxc config set {name} limits.cpu {cpu_cores}")
            LXCManager.execute_command(f"lxc config device override {name} root size={disk_gb}GB")

            # Start container
            result = LXCManager.execute_command(f"lxc start {name}")
            if not result['success']:
                LXCManager.execute_command(f"lxc delete {name} --force")
                return {'success': False, 'error': 'Failed to start container'}

            # Wait for container to be ready
            time.sleep(5)

            # Install and configure SSH
            commands = [
                f"lxc exec {name} -- apt-get update",
                f"lxc exec {name} -- apt-get install -y openssh-server",
                f"lxc exec {name} -- systemctl enable ssh",
                f"lxc exec {name} -- systemctl start ssh",
                f"lxc exec {name} -- useradd -m -s /bin/bash gvmuser",
                f"lxc exec {name} -- bash -c \"echo 'gvmuser:{ssh_password}' | chpasswd\"",
                f"lxc exec {name} -- usermod -aG sudo gvmuser"
            ]

            for cmd in commands:
                LXCManager.execute_command(cmd, timeout=300)

            return {'success': True}

        except Exception as e:
            LXCManager.execute_command(f"lxc delete {name} --force")
            return {'success': False, 'error': str(e)}

    @staticmethod
    def delete_container(name):
        """Delete LXC container"""
        result = LXCManager.execute_command(f"lxc delete {name} --force")
        return result['success']

    @staticmethod
    def start_container(name):
        """Start container"""
        result = LXCManager.execute_command(f"lxc start {name}")
        return result['success']

    @staticmethod
    def stop_container(name):
        """Stop container"""
        result = LXCManager.execute_command(f"lxc stop {name} --force")
        return result['success']

    @staticmethod
    def restart_container(name):
        """Restart container"""
        result = LXCManager.execute_command(f"lxc restart {name} --force")
        return result['success']

    @staticmethod
    def get_ssh_info(name):
        """Get SSH connection information"""
        result = LXCManager.execute_command(f"lxc list {name} --format json")
        if result['success']:
            try:
                container_info = json.loads(result['output'])[0]
                addresses = container_info.get('state', {}).get('network', {}).get('eth0', {}).get('addresses', [])
                for addr in addresses:
                    if addr.get('family') == 'inet':
                        return addr.get('address')
            except:
                pass
        return None

    @staticmethod
    def create_snapshot(name, snapshot_name):
        """Create container snapshot"""
        result = LXCManager.execute_command(f"lxc snapshot {name} {snapshot_name}")
        return result['success']

    @staticmethod
    def restore_snapshot(name, snapshot_name):
        """Restore container from snapshot"""
        result = LXCManager.execute_command(f"lxc restore {name} {snapshot_name}")
        return result['success']

    @staticmethod
    def list_snapshots(name):
        """List container snapshots"""
        result = LXCManager.execute_command(f"lxc info {name}")
        if result['success']:
            snapshots = []
            in_snapshots = False
            for line in result['output'].split('\n'):
                if 'Snapshots:' in line:
                    in_snapshots = True
                    continue
                if in_snapshots and line.strip():
                    if line.startswith(' '):
                        snapshot_name = line.strip().split()[0]
                        snapshots.append(snapshot_name)
            return snapshots
        return []

    @staticmethod
    def execute_command_in_container(name, command):
        """Execute command inside container"""
        result = LXCManager.execute_command(f"lxc exec {name} -- {command}", timeout=30)
        return result

    @staticmethod
    def get_container_logs(name, lines=50):
        """Get container logs"""
        result = LXCManager.execute_command(f"lxc exec {name} -- journalctl -n {lines}")
        return result.get('output', 'No logs available')

    @staticmethod
    def get_container_processes(name):
        """Get running processes"""
        result = LXCManager.execute_command(f"lxc exec {name} -- ps aux")
        return result.get('output', 'No processes available')

    @staticmethod
    def clone_container(source_name, target_name):
        """Clone a container"""
        result = LXCManager.execute_command(f"lxc copy {source_name} {target_name}")
        return result['success']

    @staticmethod
    def resize_container(name, ram_gb=None, cpu_cores=None, disk_gb=None):
        """Resize container resources"""
        try:
            if ram_gb:
                ram_mb = ram_gb * 1024
                LXCManager.execute_command(f"lxc config set {name} limits.memory {ram_mb}MB")
            
            if cpu_cores:
                LXCManager.execute_command(f"lxc config set {name} limits.cpu {cpu_cores}")
            
            if disk_gb:
                LXCManager.execute_command(f"lxc config device set {name} root size={disk_gb}GB")
            
            return True
        except:
            return False

# Monitoring Functions
def get_host_cpu_usage():
    """Get host CPU usage"""
    try:
        result = subprocess.run(['top', '-bn1'], capture_output=True, text=True)
        output = result.stdout
        
        for line in output.split('\n'):
            if '%Cpu(s):' in line:
                words = line.split()
                for i, word in enumerate(words):
                    if word == 'id,':
                        idle_str = words[i-1].rstrip(',')
                        try:
                            idle = float(idle_str)
                            return 100.0 - idle
                        except ValueError:
                            pass
                break
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU usage: {e}")
        return 0.0

def host_cpu_monitor():
    """Monitor host CPU and stop all containers if threshold exceeded"""
    global monitoring_active
    
    while monitoring_active:
        try:
            cpu_usage = get_host_cpu_usage()
            logger.info(f"Host CPU usage: {cpu_usage}%")
            
            if cpu_usage > CPU_THRESHOLD:
                logger.warning(f"CPU usage ({cpu_usage}%) exceeded threshold ({CPU_THRESHOLD}%). Stopping all containers.")
                
                with app.app_context():
                    containers = Container.query.all()
                    for container in containers:
                        if container.status == 'running':
                            LXCManager.stop_container(container.name)
                            container.status = 'stopped'
                    
                    db.session.commit()
                    
                    # Log event
                    log = AuditLog(
                        user_id=None,
                        action=f"Auto-stopped all containers due to high CPU usage: {cpu_usage}%",
                        details=f"Threshold: {CPU_THRESHOLD}%"
                    )
                    db.session.add(log)
                    db.session.commit()
            
            time.sleep(60)  # Check every minute
        except Exception as e:
            logger.error(f"Error in host CPU monitor: {e}")
            time.sleep(60)

def container_monitor():
    """Monitor individual containers for resource abuse"""
    global monitoring_active
    
    while monitoring_active:
        try:
            with app.app_context():
                containers = Container.query.filter_by(status='running', suspended=False).all()
                
                for container in containers:
                    try:
                        cpu_pct = LXCManager.get_cpu_percentage(container.name)
                        ram_pct = LXCManager.get_ram_percentage(container.name)
                        
                        if cpu_pct > CPU_THRESHOLD or ram_pct > RAM_THRESHOLD:
                            reason = f"High resource usage: CPU {cpu_pct:.1f}%, RAM {ram_pct:.1f}% (threshold: {CPU_THRESHOLD}% CPU / {RAM_THRESHOLD}% RAM)"
                            logger.warning(f"Auto-suspending {container.name}: {reason}")
                            
                            # Stop container
                            LXCManager.stop_container(container.name)
                            container.suspended = True
                            container.status = 'stopped'
                            
                            # Add to suspension history
                            history = json.loads(container.suspension_history)
                            history.append({
                                'time': datetime.now().isoformat(),
                                'reason': reason,
                                'by': 'Auto-System'
                            })
                            container.suspension_history = json.dumps(history)
                            
                            db.session.commit()
                            
                            # Log event
                            log = AuditLog(
                                user_id=container.user_id,
                                action=f"Auto-suspended container: {container.name}",
                                details=reason
                            )
                            db.session.add(log)
                            db.session.commit()
                            
                    except Exception as e:
                        logger.error(f"Error monitoring {container.name}: {e}")
                
            time.sleep(CHECK_INTERVAL)  # Check every 10 minutes
        except Exception as e:
            logger.error(f"Error in container monitor: {e}")
            time.sleep(60)

# Start monitoring threads
def start_monitoring():
    host_thread = threading.Thread(target=host_cpu_monitor, daemon=True)
    host_thread.start()
    
    container_thread = threading.Thread(target=container_monitor, daemon=True)
    container_thread.start()
    
    logger.info("Monitoring threads started")

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def log_action(action, details=None):
    """Log user action"""
    try:
        if 'user_id' in session:
            log = AuditLog(
                user_id=session['user_id'],
                action=action,
                ip_address=request.remote_addr,
                details=details
            )
            db.session.add(log)
            db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log action: {e}")

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('register.html')

        if len(username) < 3:
            flash('Username must be at least 3 characters', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html')

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        log_action(f"New user registered: {username}")
        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            session.permanent = True
            
            log_action(f"User logged in: {username}")
            
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    log_action(f"User logged out: {username}")
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    containers = Container.query.filter_by(user_id=user.id).all()
    
    # Update container statuses
    for container in containers:
        container.status = LXCManager.get_container_status(container.name)
    
    db.session.commit()
    
    # Get shared containers
    shared_containers = []
    all_containers = Container.query.all()
    for container in all_containers:
        shared_with = json.loads(container.shared_with)
        if user.id in shared_with:
            shared_containers.append(container)
    
    return render_template('dashboard.html', user=user, containers=containers, shared_containers=shared_containers)

@app.route('/container/<int:container_id>')
@login_required
def container_detail(container_id):
    container = Container.query.get_or_404(container_id)
    
    # Check ownership or shared access or admin
    shared_with = json.loads(container.shared_with)
    if container.user_id != session['user_id'] and session['user_id'] not in shared_with and not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get live stats
    container.status = LXCManager.get_container_status(container.name)
    stats = LXCManager.get_container_stats(container.name) if container.status == 'Running' else None
    ssh_ip = LXCManager.get_ssh_info(container.name)
    
    # Get snapshots
    snapshots = ContainerSnapshot.query.filter_by(container_id=container.id).order_by(ContainerSnapshot.created_at.desc()).all()
    
    # Get suspension history
    suspension_history = json.loads(container.suspension_history)
    
    # Check if user is owner or shared
    is_owner = (container.user_id == session['user_id'])
    is_shared = (session['user_id'] in shared_with)
    
    return render_template('container_detail.html', 
                         container=container, 
                         stats=stats, 
                         ssh_ip=ssh_ip,
                         snapshots=snapshots,
                         suspension_history=suspension_history,
                         is_owner=is_owner,
                         is_shared=is_shared)

# Container Actions
@app.route('/container/<int:container_id>/start', methods=['POST'])
@login_required
def start_container(container_id):
    container = Container.query.get_or_404(container_id)
    
    shared_with = json.loads(container.shared_with)
    if container.user_id != session['user_id'] and session['user_id'] not in shared_with and not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if container.suspended and not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Container is suspended'}), 403
    
    success = LXCManager.start_container(container.name)
    if success:
        container.status = 'Running'
        container.suspended = False
        db.session.commit()
        log_action(f"Started container: {container.name}")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Failed to start container'}), 500

@app.route('/container/<int:container_id>/stop', methods=['POST'])
@login_required
def stop_container(container_id):
    container = Container.query.get_or_404(container_id)
    
    shared_with = json.loads(container.shared_with)
    if container.user_id != session['user_id'] and session['user_id'] not in shared_with and not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    success = LXCManager.stop_container(container.name)
    if success:
        container.status = 'Stopped'
        db.session.commit()
        log_action(f"Stopped container: {container.name}")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Failed to stop container'}), 500

@app.route('/container/<int:container_id>/restart', methods=['POST'])
@login_required
def restart_container(container_id):
    container = Container.query.get_or_404(container_id)
    
    shared_with = json.loads(container.shared_with)
    if container.user_id != session['user_id'] and session['user_id'] not in shared_with and not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if container.suspended and not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Container is suspended'}), 403
    
    success = LXCManager.restart_container(container.name)
    if success:
        container.status = 'Running'
        db.session.commit()
        log_action(f"Restarted container: {container.name}")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Failed to restart container'}), 500

@app.route('/container/<int:container_id>/delete', methods=['POST'])
@login_required
def delete_container(container_id):
    container = Container.query.get_or_404(container_id)
    
    if container.user_id != session['user_id'] and not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    success = LXCManager.delete_container(container.name)
    if success:
        log_action(f"Deleted container: {container.name}")
        db.session.delete(container)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Failed to delete container'}), 500

# Enhanced Features
@app.route('/container/<int:container_id>/snapshot', methods=['POST'])
@login_required
def create_snapshot(container_id):
    container = Container.query.get_or_404(container_id)
    
    if container.user_id != session['user_id'] and not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    description = request.json.get('description', '')
    snapshot_name = f"snap-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    success = LXCManager.create_snapshot(container.name, snapshot_name)
    if success:
        snapshot = ContainerSnapshot(
            container_id=container.id,
            snapshot_name=snapshot_name,
            description=description
        )
        db.session.add(snapshot)
        db.session.commit()
        
        log_action(f"Created snapshot {snapshot_name} for container: {container.name}", description)
        return jsonify({'success': True, 'snapshot_name': snapshot_name})
    
    return jsonify({'success': False, 'error': 'Failed to create snapshot'}), 500

@app.route('/container/<int:container_id>/restore/<int:snapshot_id>', methods=['POST'])
@login_required
def restore_snapshot(container_id, snapshot_id):
    container = Container.query.get_or_404(container_id)
    snapshot = ContainerSnapshot.query.get_or_404(snapshot_id)
    
    if container.user_id != session['user_id'] and not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if snapshot.container_id != container.id:
        return jsonify({'success': False, 'error': 'Snapshot mismatch'}), 403
    
    success = LXCManager.restore_snapshot(container.name, snapshot.snapshot_name)
    if success:
        log_action(f"Restored snapshot {snapshot.snapshot_name} for container: {container.name}")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Failed to restore snapshot'}), 500

@app.route('/container/<int:container_id>/share', methods=['POST'])
@login_required
def share_container(container_id):
    container = Container.query.get_or_404(container_id)
    
    if container.user_id != session['user_id']:
        return jsonify({'success': False, 'error': 'Only owner can share'}), 403
    
    share_with_id = request.json.get('user_id')
    user_to_share = User.query.get(share_with_id)
    
    if not user_to_share:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    shared_with = json.loads(container.shared_with)
    if share_with_id not in shared_with:
        shared_with.append(share_with_id)
        container.shared_with = json.dumps(shared_with)
        db.session.commit()
        
        log_action(f"Shared container {container.name} with user: {user_to_share.username}")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Already shared'}), 400

@app.route('/container/<int:container_id>/unshare', methods=['POST'])
@login_required
def unshare_container(container_id):
    container = Container.query.get_or_404(container_id)
    
    if container.user_id != session['user_id']:
        return jsonify({'success': False, 'error': 'Only owner can unshare'}), 403
    
    unshare_user_id = request.json.get('user_id')
    
    shared_with = json.loads(container.shared_with)
    if unshare_user_id in shared_with:
        shared_with.remove(unshare_user_id)
        container.shared_with = json.dumps(shared_with)
        db.session.commit()
        
        user = User.query.get(unshare_user_id)
        log_action(f"Unshared container {container.name} from user: {user.username if user else unshare_user_id}")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Not shared with this user'}), 400

# Admin Routes
@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    containers = Container.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    
    # Update container statuses
    for container in containers:
        container.status = LXCManager.get_container_status(container.name)
    db.session.commit()
    
    stats = {
        'total_users': len(users),
        'total_containers': len(containers),
        'running_containers': sum(1 for c in containers if c.status == 'Running'),
        'suspended_containers': sum(1 for c in containers if c.suspended),
        'host_cpu': get_host_cpu_usage(),
        'monitoring_active': monitoring_active
    }
    
    return render_template('admin/panel.html', users=users, containers=containers, logs=logs, stats=stats)

@app.route('/admin/create-container', methods=['GET', 'POST'])
@admin_required
def admin_create_container():
    if request.method == 'POST':
        user_id = request.form.get('user_id', type=int)
        ram_gb = request.form.get('ram_gb', type=int)
        cpu_cores = request.form.get('cpu_cores', type=int)
        disk_gb = request.form.get('disk_gb', type=int)
        
        user = User.query.get_or_404(user_id)
        
        # Generate container name
        container_count = Container.query.filter_by(user_id=user_id).count() + 1
        container_name = f"gvm-{user.username}-{container_count}"
        
        # Generate SSH password
        ssh_password = secrets.token_urlsafe(12)
        
        # Create container
        result = LXCManager.create_container(container_name, ram_gb, cpu_cores, disk_gb, ssh_password)
        
        if result['success']:
            # Save to database
            container = Container(
                name=container_name,
                user_id=user_id,
                ram_gb=ram_gb,
                cpu_cores=cpu_cores,
                disk_gb=disk_gb,
                status='Running',
                ssh_password=ssh_password
            )
            db.session.add(container)
            db.session.commit()
            
            log_action(f"Admin created container {container_name} for user {user.username}")
            flash(f'Container created successfully for {user.username}', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash(f'Failed to create container: {result.get("error", "Unknown error")}', 'danger')
    
    users = User.query.all()
    return render_template('admin/create_container.html', users=users)

@app.route('/admin/user/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        return jsonify({'success': False, 'error': 'Cannot modify own admin status'}), 403
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    log_action(f"Toggled admin status for user {user.username}: {user.is_admin}")
    return jsonify({'success': True, 'is_admin': user.is_admin})

@app.route('/admin/container/<int:container_id>/suspend', methods=['POST'])
@admin_required
def suspend_container(container_id):
    container = Container.query.get_or_404(container_id)
    reason = request.json.get('reason', 'Manually suspended by admin')
    
    LXCManager.stop_container(container.name)
    container.suspended = True
    container.status = 'Stopped'
    
    # Add to suspension history
    history = json.loads(container.suspension_history)
    history.append({
        'time': datetime.now().isoformat(),
        'reason': reason,
        'by': session.get('username', 'Admin')
    })
    container.suspension_history = json.dumps(history)
    
    db.session.commit()
    
    log_action(f"Suspended container: {container.name}", reason)
    return jsonify({'success': True})

@app.route('/admin/container/<int:container_id>/unsuspend', methods=['POST'])
@admin_required
def unsuspend_container(container_id):
    container = Container.query.get_or_404(container_id)
    
    container.suspended = False
    db.session.commit()
    
    log_action(f"Unsuspended container: {container.name}")
    return jsonify({'success': True})

@app.route('/admin/container/<int:container_id>/resize', methods=['POST'])
@admin_required
def admin_resize_container(container_id):
    container = Container.query.get_or_404(container_id)
    
    ram_gb = request.json.get('ram_gb')
    cpu_cores = request.json.get('cpu_cores')
    disk_gb = request.json.get('disk_gb')
    
    success = LXCManager.resize_container(container.name, ram_gb, cpu_cores, disk_gb)
    
    if success:
        if ram_gb:
            container.ram_gb = ram_gb
        if cpu_cores:
            container.cpu_cores = cpu_cores
        if disk_gb:
            container.disk_gb = disk_gb
        
        db.session.commit()
        log_action(f"Resized container {container.name}: RAM={ram_gb}, CPU={cpu_cores}, Disk={disk_gb}")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Failed to resize'}), 500

@app.route('/admin/monitoring/toggle', methods=['POST'])
@admin_required
def toggle_monitoring():
    global monitoring_active
    monitoring_active = not monitoring_active
    
    log_action(f"Toggled monitoring: {monitoring_active}")
    return jsonify({'success': True, 'monitoring_active': monitoring_active})

# API Routes
@app.route('/api/container/<int:container_id>/stats')
@login_required
def api_container_stats(container_id):
    container = Container.query.get_or_404(container_id)
    
    shared_with = json.loads(container.shared_with)
    if container.user_id != session['user_id'] and session['user_id'] not in shared_with and not session.get('is_admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    stats = LXCManager.get_container_stats(container.name)
    status = LXCManager.get_container_status(container.name)
    
    return jsonify({
        'status': status,
        'stats': stats
    })

@app.route('/api/container/<int:container_id>/processes')
@login_required
def api_container_processes(container_id):
    container = Container.query.get_or_404(container_id)
    
    shared_with = json.loads(container.shared_with)
    if container.user_id != session['user_id'] and session['user_id'] not in shared_with and not session.get('is_admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    processes = LXCManager.get_container_processes(container.name)
    return jsonify({'processes': processes})

@app.route('/api/container/<int:container_id>/logs')
@login_required
def api_container_logs(container_id):
    container = Container.query.get_or_404(container_id)
    
    shared_with = json.loads(container.shared_with)
    if container.user_id != session['user_id'] and session['user_id'] not in shared_with and not session.get('is_admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    lines = request.args.get('lines', 50, type=int)
    logs = LXCManager.get_container_logs(container.name, lines)
    return jsonify({'logs': logs})

# Initialize database and start monitoring
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create default admin if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@gvmpanel.local',
                is_admin=True
            )
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin user created (username: admin, password: admin)")
        
        # Start monitoring
        start_monitoring()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
