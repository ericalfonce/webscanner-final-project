"""
Analysis Module
Classifies, deduplicates, and summarises scan findings.
"""

import logging

logger = logging.getLogger(__name__)

# Severity ordering (higher index = higher priority)
SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}


def deduplicate_findings(findings):
    """
    Remove duplicate findings that share the same vuln_type, parameter, and payload.
    Returns a deduplicated list.
    """
    seen = set()
    unique = []
    for f in findings:
        key = (
            f.get('vuln_type', ''),
            f.get('affected_parameter', ''),
            f.get('payload_used', '')[:50] if f.get('payload_used') else '',
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def sort_by_severity(findings):
    """Sort findings so highest severity appears first."""
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'info'), 0),
        reverse=True,
    )


def summarise(findings):
    """
    Return a summary dict with counts per severity and per vuln_type.
    """
    summary = {
        'total':  len(findings),
        'high':   0,
        'medium': 0,
        'low':    0,
        'info':   0,
        'by_type': {},
    }

    for f in findings:
        sev  = f.get('severity', 'info')
        vtype = f.get('vuln_type', 'unknown')

        if sev in summary:
            summary[sev] += 1

        summary['by_type'].setdefault(vtype, 0)
        summary['by_type'][vtype] += 1

    return summary


def classify_overall_risk(summary):
    """
    Return an overall risk label based on the summary.
    High > Medium > Low > Info > None.
    """
    if summary['high'] > 0:
        return 'High'
    if summary['medium'] > 0:
        return 'Medium'
    if summary['low'] > 0:
        return 'Low'
    if summary['info'] > 0:
        return 'Informational'
    return 'None'
