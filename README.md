# Email Service Analyzer

A web app that scans your email to identify all the services and accounts linked to your email address. Useful when migrating to a new email provider and need to update your email across various services.

## Features

- **MBOX Import** - Upload exported mailbox files
- **IMAP Connection** - Connect directly to Yahoo Mail
- **Service Detection** - Identifies automated emails (noreply, notifications, receipts, etc.)
- **Domain Grouping** - Groups emails by sender domain with sample subjects
- **Migration Help** - LLM-generated instructions for updating your email on each service (requires Anthropic API key)
- **Scan History** - Save and revisit previous scans
- **Progress Tracking** - Mark services as "transferred" to track migration progress

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Start the server
python app.py

# Optional: Enable LLM-powered migration help
export ANTHROPIC_API_KEY=your-key-here
python app.py
```

Open http://localhost:5000 in your browser.

## How It Works

The analyzer scans email headers (not body content) looking for patterns that indicate automated/service emails:

- Sender patterns: `noreply@`, `notifications@`, `support@`, etc.
- Subject patterns: "verify your email", "password reset", "order confirmation", etc.

Results are grouped by domain and sorted by email count, showing you which services you interact with most.

## Privacy

- **MBOX files** are processed locally and deleted after analysis
- **IMAP credentials** are used only for the connection and never stored
- **Scan results** are saved locally in `data/` (gitignored)
- Only email headers are read, not message bodies
