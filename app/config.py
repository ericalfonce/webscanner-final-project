"""
Configuration settings for the WebScanner application.
Uses environment variables with secure defaults.
"""

import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration class with shared settings."""

    # Flask secret key — change this in production
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-2024')

    # SQLite database stored in the instance/ folder
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f"sqlite:///{BASE_DIR / 'instance' / 'scanner.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF protection (Flask-WTF)
    WTF_CSRF_ENABLED = True

    # Scanner settings
    SCAN_REQUEST_TIMEOUT = 10          # seconds per HTTP request
    SCAN_REQUEST_DELAY = 0.5           # seconds between requests (rate limiting)
    SCAN_MAX_PAGES = 50                # maximum pages to crawl
    SCAN_CRAWL_DEPTH = 2              # maximum crawl depth

    # Payload file paths
    SQLI_PAYLOADS_FILE = BASE_DIR / 'data' / 'payloads' / 'sqli_payloads.json'
    XSS_PAYLOADS_FILE  = BASE_DIR / 'data' / 'payloads' / 'xss_payloads.json'
    VULN_INFO_FILE     = BASE_DIR / 'data' / 'educational' / 'vuln_info.json'

    # User-agent header for scanner requests
    SCANNER_USER_AGENT = (
        'WebScanner/1.0 (Educational Tool - ATC Diploma Project; '
        'only scan authorized targets)'
    )


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration — set SECRET_KEY and DATABASE_URL via env vars."""
    DEBUG = False
    WTF_CSRF_ENABLED = True


# Map config names to config classes
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
