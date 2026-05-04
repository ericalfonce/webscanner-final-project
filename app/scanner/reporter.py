"""
Reporting Module
Generates HTML and PDF vulnerability reports from scan findings.
"""

import io
import json
import logging
from datetime import datetime, timezone

from flask import render_template, current_app
from .analyzer import summarise, classify_overall_risk

logger = logging.getLogger(__name__)


def build_report_context(scan, findings_list):
    """
    Build the template context dict used for both HTML and PDF reports.
    findings_list — list of Finding model objects.
    """
    findings_data = []
    for f in findings_list:
        edu = {}
        if f.educational_info:
            try:
                edu = json.loads(f.educational_info)
            except json.JSONDecodeError:
                edu = {}

        findings_data.append({
            'id':                  f.id,
            'vuln_type':           f.vuln_type,
            'severity':            f.severity,
            'title':               f.title,
            'description':         f.description,
            'affected_url':        f.affected_url,
            'affected_parameter':  f.affected_parameter,
            'payload_used':        f.payload_used,
            'evidence':            f.evidence,
            'remediation':         f.remediation,
            'edu':                 edu,
        })

    raw_summary = {
        'total':   len(findings_data),
        'high':    sum(1 for f in findings_data if f['severity'] == 'high'),
        'medium':  sum(1 for f in findings_data if f['severity'] == 'medium'),
        'low':     sum(1 for f in findings_data if f['severity'] == 'low'),
        'info':    sum(1 for f in findings_data if f['severity'] == 'info'),
        'by_type': {},
    }
    for f in findings_data:
        raw_summary['by_type'].setdefault(f['vuln_type'], 0)
        raw_summary['by_type'][f['vuln_type']] += 1

    overall_risk = classify_overall_risk(raw_summary)

    return {
        'scan':         scan,
        'findings':     findings_data,
        'summary':      raw_summary,
        'overall_risk': overall_risk,
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
    }


def generate_pdf_report(scan, findings_list):
    """
    Generate a PDF report using reportlab.
    Returns PDF bytes or None on error.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable
        )

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )

        styles = getSampleStyleSheet()
        elements = []

        # ---- Title ----
        title_style = ParagraphStyle(
            'ReportTitle', parent=styles['Title'],
            fontSize=20, textColor=colors.HexColor('#1a3a5c'),
            spaceAfter=6
        )
        elements.append(Paragraph('Web Vulnerability Scan Report', title_style))
        elements.append(Paragraph(
            f"Target: {scan.target_url}", styles['Normal']
        ))
        elements.append(Paragraph(
            f"Date: {scan.completed_at.strftime('%Y-%m-%d %H:%M') if scan.completed_at else 'N/A'}",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.5*cm))
        elements.append(HRFlowable(width='100%', color=colors.HexColor('#1a3a5c')))
        elements.append(Spacer(1, 0.3*cm))

        # ---- Summary table ----
        elements.append(Paragraph('Summary', styles['Heading2']))
        summary_data = [
            ['Metric', 'Value'],
            ['Target URL',      scan.target_url],
            ['Scan Type',       scan.scan_type.capitalize()],
            ['Status',          scan.status.capitalize()],
            ['Pages Crawled',   str(scan.pages_crawled)],
            ['Total Tests',     str(scan.total_tests)],
            ['Total Findings',  str(len(findings_list))],
            ['High Severity',   str(scan.high_count)],
            ['Medium Severity', str(scan.medium_count)],
            ['Low Severity',    str(scan.low_count)],
            ['Informational',   str(scan.info_count)],
        ]
        t = Table(summary_data, colWidths=[6*cm, 11*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.HexColor('#f8f9fa'), colors.white]),
            ('BOX',  (0, 0), (-1, -1), 0.5, colors.grey),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.5*cm))

        # ---- Findings ----
        sev_colors = {
            'high':   colors.HexColor('#dc3545'),
            'medium': colors.HexColor('#fd7e14'),
            'low':    colors.HexColor('#ffc107'),
            'info':   colors.HexColor('#0dcaf0'),
        }

        elements.append(Paragraph('Detailed Findings', styles['Heading2']))

        if not findings_list:
            elements.append(Paragraph('No vulnerabilities were detected.', styles['Normal']))
        else:
            for idx, finding in enumerate(findings_list, 1):
                sev   = finding.severity
                color = sev_colors.get(sev, colors.grey)

                elements.append(Paragraph(
                    f'{idx}. {finding.title}',
                    ParagraphStyle('FTitle', parent=styles['Heading3'],
                                   textColor=color, spaceAfter=2)
                ))

                detail_data = [
                    ['Severity',   sev.capitalize()],
                    ['Type',       finding.vuln_type.upper()],
                    ['Affected URL', finding.affected_url or 'N/A'],
                    ['Parameter',  finding.affected_parameter or 'N/A'],
                    ['Payload',    (finding.payload_used or 'N/A')[:80]],
                ]
                dt = Table(detail_data, colWidths=[4.5*cm, 12.5*cm])
                dt.setStyle(TableStyle([
                    ('FONTNAME',  (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1),
                     [colors.HexColor('#f8f9fa'), colors.white]),
                    ('BOX',  (0, 0), (-1, -1), 0.5, colors.grey),
                    ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                    ('PADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(dt)

                if finding.description:
                    elements.append(Spacer(1, 0.15*cm))
                    elements.append(Paragraph(
                        f'<b>Description:</b> {finding.description}', styles['Normal']
                    ))

                if finding.evidence:
                    elements.append(Paragraph(
                        f'<b>Evidence:</b> {finding.evidence[:300]}', styles['Normal']
                    ))

                if finding.remediation:
                    elements.append(Paragraph(
                        f'<b>Remediation:</b> {finding.remediation}', styles['Normal']
                    ))

                elements.append(Spacer(1, 0.4*cm))

        # ---- Disclaimer ----
        elements.append(HRFlowable(width='100%', color=colors.grey))
        elements.append(Spacer(1, 0.2*cm))
        disclaimer_style = ParagraphStyle(
            'Disclaimer', parent=styles['Italic'],
            fontSize=8, textColor=colors.grey
        )
        elements.append(Paragraph(
            'This report was generated by WebScanner — an educational tool for '
            'authorised security testing only. Only scan systems you have explicit '
            'permission to test. Arusha Technical College Diploma Project.',
            disclaimer_style
        ))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

    except ImportError:
        logger.error("reportlab is not installed. PDF generation unavailable.")
        return None
    except Exception as e:
        logger.exception(f"PDF generation error: {e}")
        return None
