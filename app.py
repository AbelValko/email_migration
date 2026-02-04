"""Flask application for Email Service Analyzer."""

import json
import os
import tempfile
import threading
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

import anthropic

from analyzer import analyze_emails, analyze_emails_imap

app = Flask(__name__)
app.secret_key = os.urandom(24)

# In-memory task storage for background jobs
tasks = {}

# Directory for storing scan results
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# Directory for caching LLM responses
CACHE_DIR = os.path.join(os.path.dirname(__file__), 'cache')
os.makedirs(CACHE_DIR, exist_ok=True)

# Initialize Anthropic client (uses ANTHROPIC_API_KEY env var)
def get_llm_client():
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        return None
    return anthropic.Anthropic(api_key=api_key)


def save_scan(email: str, folder: str, results: dict) -> str:
    """Save scan results to a JSON file. Returns the scan ID."""
    scan_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().isoformat()

    scan_data = {
        'id': scan_id,
        'email': email,
        'folder': folder,
        'timestamp': timestamp,
        'results': results,
        'transferred': []  # List of domains marked as transferred
    }

    filepath = os.path.join(DATA_DIR, f'{scan_id}.json')
    with open(filepath, 'w') as f:
        json.dump(scan_data, f, indent=2)

    return scan_id


def update_scan(scan_id: str, updates: dict) -> bool:
    """Update a saved scan with new data."""
    filepath = os.path.join(DATA_DIR, f'{scan_id}.json')
    if not os.path.exists(filepath):
        return False

    with open(filepath, 'r') as f:
        data = json.load(f)

    data.update(updates)

    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

    return True


def load_scan(scan_id: str) -> dict | None:
    """Load a saved scan by ID."""
    filepath = os.path.join(DATA_DIR, f'{scan_id}.json')
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'r') as f:
        return json.load(f)


def list_scans() -> list:
    """List all saved scans, sorted by newest first."""
    scans = []
    for filename in os.listdir(DATA_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(DATA_DIR, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    scans.append({
                        'id': data['id'],
                        'email': data['email'],
                        'folder': data['folder'],
                        'timestamp': data['timestamp'],
                        'total_emails': data['results']['total_emails'],
                        'service_emails': data['results']['service_emails'],
                        'service_count': len(data['results']['services'])
                    })
            except (json.JSONDecodeError, KeyError):
                continue
    scans.sort(key=lambda x: x['timestamp'], reverse=True)
    return scans

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


def run_imap_task(task_id, host, username, password, folder, limit):
    """Background task to fetch and analyze IMAP emails."""
    def progress_callback(current, total, stage):
        tasks[task_id]['current'] = current
        tasks[task_id]['total'] = total
        tasks[task_id]['stage'] = stage

    try:
        results = analyze_emails_imap(
            host=host,
            username=username,
            password=password,
            folder=folder,
            limit=limit,
            progress_callback=progress_callback
        )
        # Save results to disk
        scan_id = save_scan(username, folder, results)
        tasks[task_id]['status'] = 'complete'
        tasks[task_id]['results'] = results
        tasks[task_id]['scan_id'] = scan_id
    except Exception as e:
        tasks[task_id]['status'] = 'error'
        error_msg = str(e)
        if 'AUTHENTICATIONFAILED' in error_msg:
            tasks[task_id]['error'] = 'Authentication failed. Check your email and App Password.'
        elif 'getaddrinfo failed' in error_msg or 'Connection refused' in error_msg:
            tasks[task_id]['error'] = 'Could not connect to Yahoo mail server.'
        else:
            tasks[task_id]['error'] = f'Error: {error_msg}'


@app.route('/analyze-imap', methods=['POST'])
def analyze_imap():
    """Start background IMAP analysis task."""
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    folder = request.form.get('folder', 'INBOX')
    limit = request.form.get('limit', '')

    if not email or not password:
        flash('Email and password are required', 'error')
        return redirect(url_for('imap'))

    # Parse limit - no default, allow fetching all
    limit_int = None
    if limit:
        try:
            limit_int = int(limit)
            if limit_int <= 0:
                limit_int = None
        except ValueError:
            pass

    # Create task
    task_id = str(uuid.uuid4())
    tasks[task_id] = {
        'status': 'running',
        'current': 0,
        'total': 0,
        'stage': 'Connecting...',
        'results': None,
        'error': None
    }

    # Start background thread
    thread = threading.Thread(
        target=run_imap_task,
        args=(task_id, 'imap.mail.yahoo.com', email, password, folder, limit_int)
    )
    thread.daemon = True
    thread.start()

    return redirect(url_for('progress', task_id=task_id))


@app.route('/progress/<task_id>')
def progress(task_id):
    """Show progress page for a running task."""
    if task_id not in tasks:
        flash('Task not found', 'error')
        return redirect(url_for('imap'))
    return render_template('progress.html', task_id=task_id)


@app.route('/api/progress/<task_id>')
def api_progress(task_id):
    """API endpoint to get task progress."""
    if task_id not in tasks:
        return jsonify({'error': 'Task not found'}), 404

    task = tasks[task_id]
    return jsonify({
        'status': task['status'],
        'current': task['current'],
        'total': task['total'],
        'stage': task['stage'],
        'error': task['error']
    })


@app.route('/results/<task_id>')
def results(task_id):
    """Show results for a completed task."""
    if task_id not in tasks:
        flash('Task not found', 'error')
        return redirect(url_for('imap'))

    task = tasks[task_id]
    if task['status'] != 'complete':
        return redirect(url_for('progress', task_id=task_id))

    # Redirect to the saved scan
    scan_id = task.get('scan_id')
    if scan_id:
        return redirect(url_for('view_scan', scan_id=scan_id))

    return render_template('results.html', results=task['results'])


@app.route('/history')
def history():
    """Show list of saved scans."""
    scans = list_scans()
    return render_template('history.html', scans=scans)


@app.route('/scan/<scan_id>')
def view_scan(scan_id):
    """View a saved scan."""
    scan = load_scan(scan_id)
    if not scan:
        flash('Scan not found', 'error')
        return redirect(url_for('history'))
    return render_template('results.html', results=scan['results'], scan=scan)


@app.route('/scan/<scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    """Delete a saved scan."""
    filepath = os.path.join(DATA_DIR, f'{scan_id}.json')
    if os.path.exists(filepath):
        os.remove(filepath)
        flash('Scan deleted', 'success')
    return redirect(url_for('history'))


@app.route('/api/email-change-help/<domain>')
def email_change_help(domain):
    """Get LLM-generated instructions for changing email on a service."""
    llm_client = get_llm_client()
    if not llm_client:
        return jsonify({
            'error': 'API key not set. Run: export ANTHROPIC_API_KEY=your-key-here'
        }), 503

    # Check cache first
    cache_file = os.path.join(CACHE_DIR, f'{domain.replace(".", "_")}.json')
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            return jsonify(json.load(f))

    # Query LLM
    prompt = f"""I need to change the email address associated with my account on {domain}.

Please provide:
1. Step-by-step instructions for how to change/update the email address for an account on {domain}
2. The direct URL to the account settings or email change page if you know it (be specific, not just the homepage)

If this is a well-known service, provide specific instructions. If you're not certain about the exact steps for this specific service, provide general guidance and note that the user should look for account settings.

Format your response as:
**Steps:**
1. [step 1]
2. [step 2]
...

**Direct Link:** [URL if known, or "Check account settings on the website"]

**Notes:** [Any important notes about the process, like if they send verification emails, have waiting periods, etc.]

Keep the response concise and actionable."""

    try:
        response = llm_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        result = {
            'domain': domain,
            'instructions': response.content[0].text
        }

        # Cache the result
        with open(cache_file, 'w') as f:
            json.dump(result, f, indent=2)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'LLM error: {str(e)}'}), 500


@app.route('/api/scan/<scan_id>/transfer', methods=['POST'])
def toggle_transfer(scan_id):
    """Toggle transferred status for a domain."""
    scan = load_scan(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    data = request.get_json()
    domain = data.get('domain')
    transferred = data.get('transferred', True)

    if not domain:
        return jsonify({'error': 'Domain required'}), 400

    # Get current transferred list (handle old scans without this field)
    transferred_list = scan.get('transferred', [])

    if transferred and domain not in transferred_list:
        transferred_list.append(domain)
    elif not transferred and domain in transferred_list:
        transferred_list.remove(domain)

    update_scan(scan_id, {'transferred': transferred_list})

    return jsonify({
        'success': True,
        'domain': domain,
        'transferred': domain in transferred_list,
        'total_transferred': len(transferred_list)
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
