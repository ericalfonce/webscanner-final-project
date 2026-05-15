"""
Scanner routes — new scan, progress polling, results, and PDF download.
Scans run in a background thread so the browser stays responsive.
"""

import json
import re
import threading
import time
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, jsonify, send_file, current_app
)
from flask_login import login_required, current_user

from .. import db
from ..models import Scan, Finding, ScanLog
from .crawler import Crawler
from .sqli_scanner import SQLiScanner
from .xss_scanner import XSSScanner
from .header_scanner import HeaderScanner
from .analyzer import deduplicate_findings, sort_by_severity
from .reporter import build_report_context, generate_pdf_report

import io

logger = logging.getLogger(__name__)
scanner_bp = Blueprint('scanner', __name__, template_folder='../templates/scanner')


# ---------------------------------------------------------------------------
# New scan form
# ---------------------------------------------------------------------------

@scanner_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    """Display and process the new scan configuration form."""
    if request.method == 'POST':
        target_url  = request.form.get('target_url', '').strip()
        scan_type   = request.form.get('scan_type', 'quick')
        modules     = request.form.getlist('modules')  # checkboxes

        # ---- Validation ----
        error = None
        if not target_url:
            error = 'Please enter a target URL.'
        elif not _is_valid_url(target_url):
            error = 'Please enter a valid URL (must start with http:// or https://).'
        elif not modules:
            error = 'Please select at least one scan module.'

        if error:
            flash(error, 'danger')
            return render_template('scanner/new_scan.html', title='New Scan')

        # ---- Create Scan record ----
        scan = Scan(
            user_id      = current_user.id,
            target_url   = target_url,
            scan_type    = scan_type,
            scan_modules = ','.join(modules),
            status       = 'pending',
        )
        db.session.add(scan)
        db.session.commit()

        # Scans can take minutes — we run them in a background thread so
        # the browser isn't just stuck waiting. The page polls for updates every 2s.
        # daemon=True means the thread dies automatically if the server shuts down.
        thread = threading.Thread(
            target=_run_scan,
            args=(current_app._get_current_object(), scan.id),
            daemon=True
        )
        thread.start()

        flash('Scan started! Monitoring progress below.', 'info')
        return redirect(url_for('scanner.scan_progress', scan_id=scan.id))

    return render_template('scanner/new_scan.html', title='New Scan')


# ---------------------------------------------------------------------------
# Progress page
# ---------------------------------------------------------------------------

@scanner_bp.route('/progress/<int:scan_id>')
@login_required
def scan_progress(scan_id):
    scan = _get_user_scan(scan_id)
    return render_template('scanner/scan_progress.html', scan=scan, title='Scan Progress')


# ---------------------------------------------------------------------------
# AJAX status endpoint — polled every 2 s by the progress page
# ---------------------------------------------------------------------------

@scanner_bp.route('/status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    scan = _get_user_scan(scan_id)

    # Grab the 20 most recent log lines for the live progress panel.
    # We order descending first (to get the latest), then reverse the list
    # so they display oldest-to-newest in the UI.
    recent_logs = (
        ScanLog.query
        .filter_by(scan_id=scan_id)
        .order_by(ScanLog.id.desc())
        .limit(20)
        .all()
    )

    log_entries = [
        {'level': l.log_level, 'message': l.message,
         'time': l.timestamp.strftime('%H:%M:%S')}
        for l in reversed(recent_logs)
    ]

    return jsonify({
        'status':         scan.status,
        'pages_crawled':  scan.pages_crawled,
        'total_tests':    scan.total_tests,
        'findings_count': scan.total_findings,
        'high_count':     scan.high_count,
        'medium_count':   scan.medium_count,
        'low_count':      scan.low_count,
        'logs':           log_entries,
    })


# ---------------------------------------------------------------------------
# Results / report view
# ---------------------------------------------------------------------------

@scanner_bp.route('/results/<int:scan_id>')
@login_required
def scan_results(scan_id):
    scan     = _get_user_scan(scan_id)
    from sqlalchemy import case as sa_case
    sev_order = sa_case(
        (Finding.severity == 'high',   0),
        (Finding.severity == 'medium', 1),
        (Finding.severity == 'low',    2),
        else_=3
    )
    findings = (
        Finding.query
        .filter_by(scan_id=scan_id)
        .order_by(sev_order)
        .all()
    )

    context = build_report_context(scan, findings)
    return render_template('scanner/results.html', title='Scan Results', **context)


# ---------------------------------------------------------------------------
# PDF download
# ---------------------------------------------------------------------------

@scanner_bp.route('/results/<int:scan_id>/pdf')
@login_required
def download_pdf(scan_id):
    scan     = _get_user_scan(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).all()

    pdf_bytes = generate_pdf_report(scan, findings)

    if pdf_bytes is None:
        flash('PDF generation failed. Please ensure reportlab is installed.', 'danger')
        return redirect(url_for('scanner.scan_results', scan_id=scan_id))

    filename = f"scan_report_{scan_id}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )


# ---------------------------------------------------------------------------
# Scan history (all user scans)
# ---------------------------------------------------------------------------

@scanner_bp.route('/history')
@login_required
def scan_history():
    scans = (
        Scan.query
        .filter_by(user_id=current_user.id)
        .order_by(Scan.id.desc())
        .all()
    )
    return render_template('scanner/history.html', scans=scans, title='Scan History')


# ---------------------------------------------------------------------------
# Delete a scan
# ---------------------------------------------------------------------------

@scanner_bp.route('/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = _get_user_scan(scan_id)
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted successfully.', 'success')
    return redirect(url_for('scanner.scan_history'))


# ===========================================================================
# Background scan runner
# ===========================================================================

def _run_scan(app, scan_id):
    """
    Execute the full scan pipeline.
    Runs in a separate thread with its own Flask application context.
    """
    # Background threads don't inherit Flask's app context automatically,
    # so we push one manually — without this, db calls would crash.
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        scan.status     = 'running'
        scan.started_at = datetime.now(timezone.utc)
        db.session.commit()

        _add_log(scan_id, 'info', f'Scan started for target: {scan.target_url}')
        _add_log(scan_id, 'info', f'Modules: {scan.scan_modules} | Type: {scan.scan_type}')

        try:
            config = app.config
            modules = scan.modules_list

            # ---- Build shared requests.Session ----
            # One shared HTTP session for the whole scan — keeps TCP connections
            # alive between requests which is faster than opening a new one each time.
            session = requests.Session()
            session.headers.update({'User-Agent': config['SCANNER_USER_AGENT']})
            session.verify = False   # skip SSL cert checks so we can scan dev/test sites with self-signed certs
            requests.packages.urllib3.disable_warnings()  # silence the SSL warning spam that comes with verify=False

            # ---- Phase 1: Crawl ----
            _add_log(scan_id, 'info', 'Phase 1/3: Crawling target...')

            # Quick scan = shallow crawl (10 pages, 1 level deep) so it finishes fast.
            # Full scan = deeper crawl using the limits from config.py.
            max_pages = 10 if scan.scan_type == 'quick' else config['SCAN_MAX_PAGES']
            max_depth = 1  if scan.scan_type == 'quick' else config['SCAN_CRAWL_DEPTH']

            crawler = Crawler(
                base_url  = scan.target_url,
                session   = session,
                max_pages = max_pages,
                max_depth = max_depth,
                delay     = config['SCAN_REQUEST_DELAY'],
                timeout   = config['SCAN_REQUEST_TIMEOUT'],
            )
            pages = crawler.crawl()

            # Save crawler logs
            for log_entry in crawler.crawl_log:
                _add_log(scan_id, log_entry['level'], log_entry['message'])

            scan.pages_crawled = len(pages)
            db.session.commit()
            _add_log(scan_id, 'info', f'Crawl complete: {len(pages)} pages discovered.')

            # ---- Phase 2: Security Headers ----
            all_findings = []
            total_tests  = 0

            if 'headers' in modules:
                _add_log(scan_id, 'info', 'Phase 2: Checking security headers...')
                h_scanner = HeaderScanner(session=session, timeout=config['SCAN_REQUEST_TIMEOUT'])
                h_findings = h_scanner.scan(scan.target_url)

                for log_entry in h_scanner.logs:
                    _add_log(scan_id, log_entry['level'], log_entry['message'])

                all_findings.extend(h_findings)
                total_tests += len(HeaderScanner.__init__.__defaults__ or [])  # approximation
                total_tests += 7   # number of headers checked

                _add_log(scan_id, 'info', f'Header scan: {len(h_findings)} findings.')

            # ---- Phase 3: SQLi / XSS on each crawled page ----
            if 'sqli' in modules or 'xss' in modules:
                sqli_scanner = None
                xss_scanner  = None

                if 'sqli' in modules:
                    sqli_scanner = SQLiScanner(
                        session       = session,
                        payloads_file = config['SQLI_PAYLOADS_FILE'],
                        timeout       = config['SCAN_REQUEST_TIMEOUT'],
                        delay         = config['SCAN_REQUEST_DELAY'],
                    )

                if 'xss' in modules:
                    xss_scanner = XSSScanner(
                        session       = session,
                        payloads_file = config['XSS_PAYLOADS_FILE'],
                        timeout       = config['SCAN_REQUEST_TIMEOUT'],
                        delay         = config['SCAN_REQUEST_DELAY'],
                    )

                for page in pages:
                    page_url = page['url']
                    has_inputs = page.get('params') or page.get('forms')

                    if not has_inputs:
                        continue   # no forms or URL params = nowhere to inject, skip this page

                    _add_log(scan_id, 'info', f'Testing: {page_url}')

                    if sqli_scanner:
                        sqli_findings = sqli_scanner.scan_page(page)
                        for log_e in sqli_scanner.logs[-5:]:
                            _add_log(scan_id, log_e['level'], log_e['message'])
                        all_findings.extend(sqli_findings)
                        total_tests += 1

                    if xss_scanner:
                        xss_findings = xss_scanner.scan_page(page)
                        for log_e in xss_scanner.logs[-5:]:
                            _add_log(scan_id, log_e['level'], log_e['message'])
                        all_findings.extend(xss_findings)
                        total_tests += 1

            # Multiple scanners can find the same bug — remove duplicates before saving.
            # Then sort so the most critical issues appear first in the report.
            unique_findings = deduplicate_findings(all_findings)
            unique_findings = sort_by_severity(unique_findings)

            for f in unique_findings:
                finding = Finding(
                    scan_id            = scan_id,
                    vuln_type          = f['vuln_type'],
                    severity           = f['severity'],
                    title              = f['title'],
                    description        = f['description'],
                    affected_url       = f.get('affected_url'),
                    affected_parameter = f.get('affected_parameter'),
                    payload_used       = f.get('payload_used'),
                    evidence           = f.get('evidence'),
                    remediation        = f.get('remediation'),
                    educational_info   = f.get('educational_info'),
                )
                db.session.add(finding)

            scan.total_tests   = total_tests
            scan.status        = 'completed'
            scan.completed_at  = datetime.now(timezone.utc)
            db.session.commit()

            _add_log(scan_id, 'info',
                     f'Scan completed. {len(unique_findings)} unique findings saved.')

        except Exception as e:
            logger.exception(f'Scan {scan_id} failed: {e}')
            scan.status        = 'failed'
            scan.error_message = str(e)
            scan.completed_at  = datetime.now(timezone.utc)
            db.session.commit()
            _add_log(scan_id, 'error', f'Scan failed: {e}')


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _add_log(scan_id, level, message):
    """Insert a log entry for the given scan."""
    try:
        log = ScanLog(scan_id=scan_id, log_level=level, message=message)
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass   # logging should NEVER crash the actual scan — silently ignore failures here


def _get_user_scan(scan_id):
    """Return the scan or 404 if it doesn't belong to the current user."""
    from flask import abort
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return scan


def _is_valid_url(url):
    """Return True if the URL is a valid http/https URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False
