import os

class Config:
    """Configuration settings for the CLY to STL Converter"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size (increased from 100MB)
    
    # File paths
    UPLOAD_FOLDER = 'uploads'
    OUTPUT_FOLDER = 'outputs'
    
    # Logging
    LOG_LEVEL = 'DEBUG'
    LOG_FILE = 'cly_converter.log'
    
    # Server settings
    HOST = '0.0.0.0'
    PORT = 5000
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    LOG_LEVEL = 'INFO'
    SECRET_KEY = os.environ.get('SECRET_KEY')

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG' 