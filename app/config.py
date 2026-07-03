"""
Configuration settings for the WebScanner application.
Uses environment variables with secure defaults.
"""

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration."""

    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-2024')

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f"sqlite:///{BASE_DIR / 'instance' / 'scanner.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CSRF
    WTF_CSRF_ENABLED = True

    # Session — expire after 30 min of inactivity (refreshed on each request)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False   # set True in production (requires HTTPS)

    # Remember-me cookie — capped at 7 days
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = False  # set True in production

    # Scanner settings
    SCAN_REQUEST_TIMEOUT = 10
    SCAN_REQUEST_DELAY = 0.5
    SCAN_MAX_PAGES = 50
    SCAN_CRAWL_DEPTH = 2

    SQLI_PAYLOADS_FILE = BASE_DIR / 'data' / 'payloads' / 'sqli_payloads.json'
    XSS_PAYLOADS_FILE  = BASE_DIR / 'data' / 'payloads' / 'xss_payloads.json'
    VULN_INFO_FILE     = BASE_DIR / 'data' / 'educational' / 'vuln_info.json'

    SCANNER_USER_AGENT = (
        'WebScanner/1.0 (Educational Tool - ATC Diploma Project; '
        'only scan authorized targets)'
    )


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
