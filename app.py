"""Flask application for Email Service Analyzer."""

import os
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash

from analyzer import analyze_emails, analyze_emails_imap

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB default
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


@app.route('/')
def index():
    """Display the upload form."""
    return render_template('index.html', max_size_mb=MAX_CONTENT_LENGTH // (1024 * 1024))


@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle file upload and run analysis."""
    if 'mbox_file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('index'))

    file = request.files['mbox_file']

    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))

    if not file.filename.lower().endswith('.mbox'):
        flash('Please upload an MBOX file', 'error')
        return redirect(url_for('index'))

    # Save to temp file and analyze
    temp_file = None
    try:
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.mbox')
        file.save(temp_file.name)
        temp_file.close()

        # Run analysis
        results = analyze_emails(temp_file.name)

        return render_template('results.html', results=results)

    except Exception as e:
        flash(f'Error analyzing file: {str(e)}', 'error')
        return redirect(url_for('index'))

    finally:
        # Clean up temp file
        if temp_file and os.path.exists(temp_file.name):
            os.unlink(temp_file.name)


@app.route('/imap')
def imap():
    """Display the IMAP login form."""
    return render_template('imap.html')


@app.route('/analyze-imap', methods=['POST'])
def analyze_imap():
    """Connect to IMAP server and run analysis."""
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    folder = request.form.get('folder', 'INBOX')
    limit = request.form.get('limit', '')

    if not email or not password:
        flash('Email and password are required', 'error')
        return redirect(url_for('imap'))

    # Parse limit if provided
    limit_int = None
    if limit:
        try:
            limit_int = int(limit)
            if limit_int <= 0:
                limit_int = None
        except ValueError:
            pass

    try:
        results = analyze_emails_imap(
            host='imap.mail.yahoo.com',
            username=email,
            password=password,
            folder=folder,
            limit=limit_int
        )
        return render_template('results.html', results=results)

    except Exception as e:
        error_msg = str(e)
        if 'AUTHENTICATIONFAILED' in error_msg:
            flash('Authentication failed. Check your email and App Password.', 'error')
        elif 'getaddrinfo failed' in error_msg or 'Connection refused' in error_msg:
            flash('Could not connect to Yahoo mail server.', 'error')
        else:
            flash(f'Error connecting to email: {error_msg}', 'error')
        return redirect(url_for('imap'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
