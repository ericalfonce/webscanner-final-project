"""
Dashboard routes — the main landing page after login.
Shows recent scans, statistics, and quick-start options.
"""

from flask import Blueprint, render_template
from flask_login import login_required, current_user

from ..models import Scan, Finding

dashboard_bp = Blueprint('dashboard', __name__, template_folder='../templates/dashboard')


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Main dashboard page."""
    # Fetch the 10 most recent scans for this user
    recent_scans = (
        Scan.query
        .filter_by(user_id=current_user.id)
        .order_by(Scan.id.desc())
        .limit(10)
        .all()
    )

    # Aggregate statistics for the current user
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()

    completed_scans = Scan.query.filter_by(
        user_id=current_user.id, status='completed'
    ).count()

    # Count total findings across all this user's scans
    total_findings = (
        Finding.query
        .join(Scan)
        .filter(Scan.user_id == current_user.id)
        .count()
    )

    high_findings = (
        Finding.query
        .join(Scan)
        .filter(Scan.user_id == current_user.id, Finding.severity == 'high')
        .count()
    )

    stats = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'total_findings': total_findings,
        'high_findings': high_findings,
    }

    return render_template(
        'dashboard/index.html',
        title='Dashboard',
        recent_scans=recent_scans,
        stats=stats
    )
