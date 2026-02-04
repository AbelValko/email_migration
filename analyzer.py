"""Email parsing and analysis logic for MBOX files and IMAP."""

import imaplib
import mailbox
import re
from collections import defaultdict
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header
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


def decode_header_value(value: str | None) -> str:
    """Decode an email header value that may be encoded."""
    if not value:
        return ''
    try:
        decoded_parts = decode_header(value)
        result = ''
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                result += part.decode(encoding or 'utf-8', errors='replace')
            else:
                result += part
        return result
    except Exception:
        return value if value else ''


def parse_imap(host: str, username: str, password: str, folder: str = 'INBOX',
               limit: int | None = None,
               progress_callback=None) -> Generator[dict, None, None]:
    """
    Connect to IMAP server and yield email metadata dictionaries.

    Only fetches headers (FROM, SUBJECT, DATE) - not full body for speed.
    """
    print(f"[IMAP] Connecting to {host}...", flush=True)
    if progress_callback:
        progress_callback(0, 0, 'Connecting...')

    mail = imaplib.IMAP4_SSL(host, 993)
    try:
        print(f"[IMAP] Logging in as {username}...", flush=True)
        if progress_callback:
            progress_callback(0, 0, 'Logging in...')
        mail.login(username, password)

        print(f"[IMAP] Selecting folder: {folder}", flush=True)
        if progress_callback:
            progress_callback(0, 0, f'Opening {folder}...')
        mail.select(folder, readonly=True)

        # Search for all emails
        print("[IMAP] Searching for emails...", flush=True)
        if progress_callback:
            progress_callback(0, 0, 'Counting emails...')
        _, message_numbers = mail.search(None, 'ALL')

        if not message_numbers[0]:
            print("[IMAP] No emails found in folder", flush=True)
            return

        msg_nums = message_numbers[0].split()
        total_in_folder = len(msg_nums)
        print(f"[IMAP] Found {total_in_folder} emails in folder", flush=True)

        # Apply limit if specified (fetch most recent)
        if limit and len(msg_nums) > limit:
            msg_nums = msg_nums[-limit:]
            print(f"[IMAP] Limiting to most recent {limit} emails", flush=True)

        # Batch fetch for efficiency - fetch in chunks of 50
        BATCH_SIZE = 50
        total_to_fetch = len(msg_nums)
        print(f"[IMAP] Fetching {total_to_fetch} email headers in batches of {BATCH_SIZE}...", flush=True)
        if progress_callback:
            progress_callback(0, total_to_fetch, 'Fetching emails...')

        for batch_start in range(0, total_to_fetch, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, total_to_fetch)
            batch = msg_nums[batch_start:batch_end]

            # Create a range string for batch fetch (e.g., "1,2,3,4,5")
            msg_set = b','.join(batch)

            try:
                # Fetch only headers for entire batch
                _, msg_data = mail.fetch(msg_set, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')

                if not msg_data:
                    continue

                # Process each message in the batch response
                for item in msg_data:
                    if not item or not isinstance(item, tuple) or len(item) < 2:
                        continue

                    raw_headers = item[1]
                    if isinstance(raw_headers, bytes):
                        try:
                            msg = message_from_bytes(raw_headers)

                            sender = decode_header_value(msg.get('From', ''))
                            subject = decode_header_value(msg.get('Subject', ''))
                            date_str = msg.get('Date', '')

                            yield {
                                'sender': sender,
                                'subject': subject,
                                'date': parse_date(date_str),
                                'domain': extract_domain(sender),
                            }
                        except Exception:
                            continue
            except Exception as e:
                print(f"[IMAP] Error fetching batch: {e}")
                continue

            print(f"[IMAP] Fetched {batch_end}/{total_to_fetch} emails...", flush=True)
            if progress_callback:
                progress_callback(batch_end, total_to_fetch, 'Fetching emails...')
    finally:
        print("[IMAP] Disconnecting...", flush=True)
        try:
            mail.logout()
        except Exception:
            pass
        print("[IMAP] Done fetching emails", flush=True)


def analyze_emails_imap(host: str, username: str, password: str,
                        folder: str = 'INBOX', limit: int | None = None,
                        progress_callback=None) -> dict:
    """
    Analyze emails from IMAP server and return grouped results by domain.

    Returns same format as analyze_emails() for template compatibility.
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

    for email in parse_imap(host, username, password, folder, limit, progress_callback):
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

    services.sort(key=lambda x: x['count'], reverse=True)

    print(f"[IMAP] Analysis complete: {total_emails} total, {service_emails} service emails, {len(services)} unique domains", flush=True)
    if progress_callback:
        progress_callback(total_emails, total_emails, 'Complete!')

    return {
        'services': services,
        'total_emails': total_emails,
        'service_emails': service_emails,
    }
