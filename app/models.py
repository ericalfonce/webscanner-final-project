"""
Database models for the WebScanner application.
Uses SQLAlchemy ORM with SQLite backend.
"""

from datetime import datetime, timezone
from flask_login import UserMixin
from . import db, login_manager


# ---------------------------------------------------------------------------
# User loader — required by Flask-Login
# ---------------------------------------------------------------------------

# Flask-Login calls this every request to turn the session's user ID
# back into a real User object so current_user works everywhere.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    """Registered user account."""
    __tablename__ = 'users'

    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(64), unique=True, nullable=False)
    email        = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Links to all scans this user has run.
    # backref='user' means you can do scan.user to get the owner back.
    # lazy='dynamic' means it returns a query object, not a full list — efficient for large datasets.
    scans = db.relationship('Scan', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'


class Scan(db.Model):
    """Represents a single vulnerability scan job."""
    __tablename__ = 'scans'

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_url   = db.Column(db.String(2048), nullable=False)
    scan_type    = db.Column(db.String(20), default='quick')   # 'quick' or 'full'
    # Which modules are enabled (comma-separated): 'sqli,xss,headers'
    scan_modules = db.Column(db.String(100), default='sqli,xss,headers')
    status       = db.Column(db.String(20), default='pending')  # pending/running/completed/failed
    started_at   = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    pages_crawled = db.Column(db.Integer, default=0)
    total_tests   = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)

    # Relationships
    # cascade='all, delete-orphan' means if you delete a scan,
    # all its findings and logs get deleted automatically too.
    findings = db.relationship('Finding', backref='scan', lazy='dynamic',
                               cascade='all, delete-orphan')
    logs     = db.relationship('ScanLog', backref='scan', lazy='dynamic',
                               cascade='all, delete-orphan')

    # -------------------------------------------------------------------------
    # Convenience properties
    # -------------------------------------------------------------------------

    @property
    def duration_seconds(self):
        """How long the scan took. Returns None if scan hasn't finished yet."""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return int(delta.total_seconds())
        return None

    @property
    def high_count(self):
        return self.findings.filter_by(severity='high').count()

    @property
    def medium_count(self):
        return self.findings.filter_by(severity='medium').count()

    @property
    def low_count(self):
        return self.findings.filter_by(severity='low').count()

    @property
    def info_count(self):
        return self.findings.filter_by(severity='info').count()

    @property
    def total_findings(self):
        return self.findings.count()

    @property
    def modules_list(self):
        """Return enabled modules as a Python list."""
        return [m.strip() for m in (self.scan_modules or '').split(',') if m.strip()]

    def __repr__(self):
        return f'<Scan {self.id} → {self.target_url} [{self.status}]>'


class Finding(db.Model):
    """A single vulnerability finding within a scan."""
    __tablename__ = 'findings'

    id                 = db.Column(db.Integer, primary_key=True)
    scan_id            = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    vuln_type          = db.Column(db.String(20), nullable=False)  # 'sqli','xss','header'
    severity           = db.Column(db.String(10), nullable=False)  # high/medium/low/info
    title              = db.Column(db.String(200), nullable=False)
    description        = db.Column(db.Text)
    affected_url       = db.Column(db.String(2048))
    affected_parameter = db.Column(db.String(200))
    payload_used       = db.Column(db.Text)
    evidence           = db.Column(db.Text)          # response snippet
    remediation        = db.Column(db.Text)
    educational_info   = db.Column(db.Text)          # JSON string with learn-more data
    created_at         = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Finding {self.title} [{self.severity}]>'


class ScanLog(db.Model):
    """Log entries for a scan — used for the real-time progress display."""
    __tablename__ = 'scan_logs'

    id        = db.Column(db.Integer, primary_key=True)
    scan_id   = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    log_level = db.Column(db.String(10))   # info/warning/error
    message   = db.Column(db.Text)

    def __repr__(self):
        return f'<ScanLog [{self.log_level}] {self.message[:40]}>'
