"""Email parsing and analysis logic for MBOX files."""

import mailbox
import re
from collections import defaultdict
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from typing import Generator


# Sender patterns that indicate automated/service emails
SERVICE_SENDER_PATTERNS = [
    r'^noreply@',
    r'^no-reply@',
    r'^no\.reply@',
    r'^notifications?@',
    r'^notify@',
    r'^support@',
    r'^team@',
    r'^hello@',
    r'^info@',
    r'^help@',
    r'^account@',
    r'^accounts@',
    r'^billing@',
    r'^orders?@',
    r'^newsletter@',
    r'^news@',
    r'^updates?@',
    r'^alert@',
    r'^alerts@',
    r'^security@',
    r'^mailer@',
    r'^mail@',
    r'^admin@',
    r'^service@',
    r'^do-not-reply@',
    r'^donotreply@',
]

# Subject patterns that indicate service/account emails
SERVICE_SUBJECT_PATTERNS = [
    r'welcome to',
    r'verify your (email|account)',
    r'confirm your (email|account|registration)',
    r'password reset',
    r'reset your password',
    r'security alert',
    r'security notification',
    r'your order',
    r'order confirmation',
    r'receipt for',
    r'invoice',
    r'subscription',
    r'your account',
    r'account (created|update|verification)',
    r'sign[- ]?in',
    r'log[- ]?in',
    r'verification code',
    r'one[- ]?time (password|code)',
    r'2fa|two[- ]?factor',
    r'shipping (confirmation|update)',
    r'delivery (confirmation|update)',
    r'payment (received|confirmation)',
    r'thank you for (your order|signing up|registering)',
]

# Compile patterns for efficiency
COMPILED_SENDER_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SERVICE_SENDER_PATTERNS]
COMPILED_SUBJECT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SERVICE_SUBJECT_PATTERNS]


def extract_domain(email_address: str) -> str | None:
    """Extract domain from an email address."""
    _, addr = parseaddr(email_address)
    if '@' in addr:
        return addr.split('@')[1].lower()
    return None


def parse_date(date_str: str | None) -> datetime | None:
    """Parse email date string to datetime."""
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except (ValueError, TypeError):
        return None


def parse_mbox(filepath: str) -> Generator[dict, None, None]:
    """
    Parse MBOX file and yield email metadata dictionaries.

    Only extracts metadata (sender, subject, date) - skips body for speed.
    """
    mbox = mailbox.mbox(filepath)

    for message in mbox:
        try:
            sender = message.get('From', '')
            subject = message.get('Subject', '')
            date_str = message.get('Date', '')

            # Decode subject if needed
            if subject:
                try:
                    from email.header import decode_header
                    decoded_parts = decode_header(subject)
                    subject = ''
                    for part, encoding in decoded_parts:
                        if isinstance(part, bytes):
                            subject += part.decode(encoding or 'utf-8', errors='replace')
                        else:
                            subject += part
                except Exception:
                    pass  # Keep original subject if decoding fails

            yield {
                'sender': sender,
                'subject': subject,
                'date': parse_date(date_str),
                'domain': extract_domain(sender),
            }
        except Exception:
            # Skip malformed messages
            continue

    mbox.close()


def is_service_email(email: dict) -> tuple[bool, int]:
    """
    Determine if an email is from a service/automated sender.

    Returns (is_service, confidence_score).
    Confidence: 0 = not a service, 1 = low, 2 = medium, 3 = high
    """
    sender = email.get('sender', '').lower()
    subject = email.get('subject', '').lower()

    confidence = 0

    # Check sender patterns
    for pattern in COMPILED_SENDER_PATTERNS:
        if pattern.search(sender):
            confidence += 2
            break

    # Check subject patterns
    for pattern in COMPILED_SUBJECT_PATTERNS:
        if pattern.search(subject):
            confidence += 1
            break

    # Normalize confidence to 0-3 scale
    confidence = min(confidence, 3)

    return confidence > 0, confidence


def analyze_emails(filepath: str) -> dict:
    """
    Analyze MBOX file and return grouped results by domain.

    Returns dict with:
    - services: list of service info dicts sorted by email count
    - total_emails: total number of emails processed
    - service_emails: number of emails identified as service emails
    """
    domain_data = defaultdict(lambda: {
        'count': 0,
        'first_seen': None,
        'last_seen': None,
        'subjects': [],
        'confidence_sum': 0,
        'senders': set(),
    })

    total_emails = 0
    service_emails = 0

    for email in parse_mbox(filepath):
        total_emails += 1
        domain = email.get('domain')

        if not domain:
            continue

        is_service, confidence = is_service_email(email)

        if not is_service:
            continue

        service_emails += 1
        data = domain_data[domain]
        data['count'] += 1
        data['confidence_sum'] += confidence
        data['senders'].add(email.get('sender', ''))

        # Track date range
        email_date = email.get('date')
        if email_date:
            if data['first_seen'] is None or email_date < data['first_seen']:
                data['first_seen'] = email_date
            if data['last_seen'] is None or email_date > data['last_seen']:
                data['last_seen'] = email_date

        # Keep sample subjects (up to 5)
        subject = email.get('subject', '').strip()
        if subject and len(data['subjects']) < 5:
            if subject not in data['subjects']:
                data['subjects'].append(subject)

    # Convert to list and sort by count
    services = []
    for domain, data in domain_data.items():
        avg_confidence = data['confidence_sum'] / data['count'] if data['count'] > 0 else 0

        # Determine confidence level label
        if avg_confidence >= 2.5:
            confidence_label = 'high'
        elif avg_confidence >= 1.5:
            confidence_label = 'medium'
        else:
            confidence_label = 'low'

        services.append({
            'domain': domain,
            'count': data['count'],
            'first_seen': data['first_seen'].isoformat() if data['first_seen'] else None,
            'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None,
            'subjects': data['subjects'],
            'confidence': confidence_label,
            'sender_count': len(data['senders']),
        })

    # Sort by count descending
    services.sort(key=lambda x: x['count'], reverse=True)

    return {
        'services': services,
        'total_emails': total_emails,
        'service_emails': service_emails,
    }
