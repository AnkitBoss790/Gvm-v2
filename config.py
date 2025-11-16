"""
GVM Panel v2.0 - Configuration File
Centralized configuration management
"""

import os
from datetime import timedelta

class Config:
    """Base configuration"""
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32).hex())
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///gvm_panel.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # LXD/LXC
    DEFAULT_STORAGE_POOL = os.getenv('DEFAULT_STORAGE_POOL', 'default')
    DEFAULT_NETWORK = os.getenv('DEFAULT_NETWORK', 'lxdbr0')
    
    # Container Defaults
    DEFAULT_RAM_GB = int(os.getenv('DEFAULT_RAM_GB', '2'))
    DEFAULT_CPU_CORES = int(os.getenv('DEFAULT_CPU_CORES', '2'))
    DEFAULT_DISK_GB = int(os.getenv('DEFAULT_DISK_GB', '20'))
    DEFAULT_OS = os.getenv('DEFAULT_OS', 'ubuntu:22.04')
    
    # Monitoring
    CPU_THRESHOLD = int(os.getenv('CPU_THRESHOLD', '90'))
    RAM_THRESHOLD = int(os.getenv('RAM_THRESHOLD', '90'))
    DISK_THRESHOLD = int(os.getenv('DISK_THRESHOLD', '90'))
    CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '600'))  # seconds
    ENABLE_AUTO_SUSPEND = os.getenv('ENABLE_AUTO_SUSPEND', 'true').lower() == 'true'
    
    # Limits
    MAX_CONTAINERS_PER_USER = int(os.getenv('MAX_CONTAINERS_PER_USER', '10'))
    MAX_RAM_PER_CONTAINER = int(os.getenv('MAX_RAM_PER_CONTAINER', '64'))
    MAX_CPU_PER_CONTAINER = int(os.getenv('MAX_CPU_PER_CONTAINER', '32'))
    MAX_DISK_PER_CONTAINER = int(os.getenv('MAX_DISK_PER_CONTAINER', '500'))
    
    # Security
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '6'))
    USERNAME_MIN_LENGTH = int(os.getenv('USERNAME_MIN_LENGTH', '3'))
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Logging
    LOG_FILE = os.getenv('LOG_FILE', 'gvm_panel.log')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', '10485760'))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Features
    ENABLE_REGISTRATION = os.getenv('ENABLE_REGISTRATION', 'true').lower() == 'true'
    ENABLE_CONTAINER_SHARING = os.getenv('ENABLE_CONTAINER_SHARING', 'true').lower() == 'true'
    ENABLE_SNAPSHOTS = os.getenv('ENABLE_SNAPSHOTS', 'true').lower() == 'true'
    ENABLE_CLONING = os.getenv('ENABLE_CLONING', 'true').lower() == 'true'
    
    # Admin
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@gvmpanel.local')
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')  # Change this!
    
    # UI
    ITEMS_PER_PAGE = int(os.getenv('ITEMS_PER_PAGE', '20'))
    REFRESH_INTERVAL = int(os.getenv('REFRESH_INTERVAL', '30'))  # seconds
    
    # API
    API_TIMEOUT = int(os.getenv('API_TIMEOUT', '30'))
    
    @staticmethod
    def init_app(app):
        """Initialize application with config"""
        pass


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
