# ========================================
# THREAT SCANNER - CYBERSECURITY TOOL
# Flask web app for file vulnerability scanning
# ========================================
from flask import Flask, render_template, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
import os
import re
from datetime import datetime
from collections import Counter

app = Flask(__name__)
app.config['SECRET_KEY'] = 'threat-scanner-2026-key'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Threat patterns - real cybersecurity rules (ALL FIXED)
THREAT_PATTERNS = {
    'weak_password': {
        'pattern': r'(password|pass)=["\']?(admin|123456|password|qwerty)',
        'severity': 'HIGH',
        'message': 'Weak/hardcoded password detected'
    },
    'sql_injection': {
        'pattern': r'(select\s+\*?|union\s+select|drop\s+table|insert\s+into)',
        'severity': 'CRITICAL',
        'message': 'SQL injection risk detected'
    },
    'api_key': {
        'pattern': r'(api[_-]?key|secret[_-]?key|token)=["\']?[a-zA-Z0-9]{16,}',
        'severity': 'CRITICAL',
        'message': 'Exposed API key/secret detected'
    },
    'debug_mode': {
        'pattern': r'debug[_-]?mode\s*=\s*(true|1|yes)',
        'severity': 'HIGH',
        'message': 'Debug mode enabled in production'
    }
}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('upload.html')  # ✅ FIXED: Your upload.html

@app.route('/scan', methods=['POST'])
def scan_file():
    """Scan uploaded file for threats"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if file:
        start_time = datetime.now()
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Scan the file
        findings = scan_content(filepath)
        
        # Calculate required template variables
        scan_time = (datetime.now() - start_time).total_seconds()
        severity_count = Counter([f['severity'] for f in findings])
        
        return render_template('results.html', 
                             filename=filename, 
                             findings=findings,
                             total=len(findings),
                             severity_count=dict(severity_count),
                             scan_time=scan_time)

def scan_content(filepath):
    """Scan file content for threats"""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        for threat_name, threat_info in THREAT_PATTERNS.items():
            matches = re.finditer(threat_info['pattern'], content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'threat': threat_name.replace('_', ' ').title(),
                    'severity': threat_info['severity'],
                    'location': f"Line {content[:match.start()].count('\n') + 1}",  # ✅ FIXED
                    'issue': threat_info['message']
                })
    except Exception as e:
        flash(f'Scan error: {str(e)}')
    
    return findings

if __name__ == '__main__':
    app.run(debug=False)  # Production ready
