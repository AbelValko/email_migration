"""Flask application for Email Service Analyzer."""

import os
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash

from analyzer import analyze_emails

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


if __name__ == '__main__':
    app.run(debug=True, port=5000)
