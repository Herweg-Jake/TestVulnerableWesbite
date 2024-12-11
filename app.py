import os
from pathlib import Path
import sqlite3
import time
import json
import subprocess
import requests
from datetime import datetime, timedelta
from flask import Flask, request, render_template, redirect, jsonify, session, send_file, url_for, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename

# Configuration
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / 'medical_files'
DATABASE_PATH = BASE_DIR / 'medical_records.db'

app = Flask(__name__)
app.secret_key = 'medical_secret_key_123'  # Intentionally weak secret
app.config['JWT_SECRET_KEY'] = 'jwt_medical_key_123'  # Intentionally weak JWT
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

jwt = JWTManager(app)

# Create necessary directories
UPLOAD_FOLDER.mkdir(exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Template context processor for utility functions
@app.context_processor
def utility_processor():
    def now(format_string):
        return datetime.now().strftime(format_string)
    return dict(now=now)

# Basic page routes
@app.route('/')
def index():
    if not session.get('user_id'):
        return redirect(url_for('login_page'))
    return redirect(url_for('dashboard'))

@app.route('/login')
def login_page():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('login_page'))
    return render_template('dashboard.html')

@app.route('/patients')
def patients_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('patients.html')

@app.route('/records')
def records_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('records.html')

@app.route('/admin')
def admin_page():
    if not session.get('user_id') or session.get('role') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    return render_template('admin.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login_page'))

# Authentication and User Management API routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = c.execute(query).fetchone()
    conn.close()
    
    if result:
        session['user_id'] = result[0]
        session['username'] = result[1]
        session['role'] = result[3]
        
        token = create_access_token(
            identity=username,
            headers={'alg': 'none'}
        )
        flash('Login successful', 'success')
        return jsonify({
            'token': token,
            'role': result[3],
            'user_id': result[0]
        })
    flash('Invalid credentials', 'error')
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/users/create', methods=['POST'])
def create_user():
    data = request.json
    # Vulnerable direct object creation
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    query = f"""
    INSERT INTO users (username, password, role, email) 
    VALUES ('{data["username"]}', '{data["password"]}', 
            '{data.get("role", "staff")}', '{data["email"]}')
    """
    c.execute(query)
    conn.commit()
    conn.close()
    return jsonify({'status': 'user created'})

# 2. Patient Records Management
@app.route('/api/patients', methods=['GET'])
@jwt_required()
def get_patients():
    # Vulnerable to IDOR and information disclosure
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    patients = c.execute('SELECT * FROM patients').fetchall()
    conn.close()
    return jsonify([{
        'id': p[0],
        'name': p[1],
        'ssn': p[2],  # Exposing sensitive data
        'dob': p[3],
        'medical_history': p[4]
    } for p in patients])

@app.route('/api/patients/<int:patient_id>', methods=['GET'])
@jwt_required()
def get_patient(patient_id):
    # Vulnerable to IDOR
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    patient = c.execute(f'SELECT * FROM patients WHERE id={patient_id}').fetchone()
    conn.close()
    return jsonify({
        'id': patient[0],
        'name': patient[1],
        'ssn': patient[2],
        'dob': patient[3],
        'medical_history': patient[4]
    })

@app.route('/api/patients/<int:patient_id>/update', methods=['POST'])
@jwt_required()
def update_patient(patient_id):
    data = request.json
    # Vulnerable SQL query
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    query = f"""
    UPDATE patients 
    SET medical_history='{data["medical_history"]}', 
        allergies='{data.get("allergies", "")}' 
    WHERE id={patient_id}
    """
    c.execute(query)
    conn.commit()
    conn.close()
    return jsonify({'status': 'updated'})

# 3. Medical Records and File Management
@app.route('/api/records/upload', methods=['POST'])
@jwt_required()
def upload_medical_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    patient_id = request.form.get('patient_id')
    
    if file:
        # Vulnerable file handling
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Store file reference in database
        conn = sqlite3.connect(str(DATABASE_PATH))
        c = conn.cursor()
        c.execute("""
            INSERT INTO medical_files (patient_id, filename, upload_date) 
            VALUES (?, ?, ?)
        """, (patient_id, filename, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'file uploaded'})
    return jsonify({'error': 'Invalid file'}), 400

@app.route('/api/records/<int:patient_id>/files', methods=['GET'])
@jwt_required()
def get_patient_files(patient_id):
    # Vulnerable to directory traversal
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    files = c.execute(f'SELECT * FROM medical_files WHERE patient_id={patient_id}').fetchall()
    conn.close()
    return jsonify([{
        'id': f[0],
        'filename': f[2],
        'upload_date': f[3]
    } for f in files])

@app.route('/api/records/download/<path:filename>')
@jwt_required()
def download_medical_file(filename):
    # Vulnerable to path traversal
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# 4. Prescription Management
@app.route('/api/prescriptions/create', methods=['POST'])
@jwt_required()
def create_prescription():
    data = request.json
    # Vulnerable SQL injection
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    query = f"""
    INSERT INTO prescriptions (patient_id, medication, dosage, prescribed_by, notes) 
    VALUES (
        {data['patient_id']}, 
        '{data['medication']}', 
        '{data['dosage']}',
        '{get_jwt_identity()}',
        '{data.get("notes", "")}'
    )
    """
    c.execute(query)
    conn.commit()
    conn.close()
    return jsonify({'status': 'prescription created'})

@app.route('/api/prescriptions/<int:patient_id>', methods=['GET'])
@jwt_required()
def get_prescriptions(patient_id):
    # Vulnerable to IDOR
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    prescriptions = c.execute(f"""
        SELECT * FROM prescriptions WHERE patient_id={patient_id}
    """).fetchall()
    conn.close()
    return jsonify([{
        'id': p[0],
        'medication': p[2],
        'dosage': p[3],
        'prescribed_by': p[4],
        'notes': p[5]
    } for p in prescriptions])

# 5. Administrative Functions
@app.route('/api/admin/system-check', methods=['POST'])
@jwt_required()
def system_check():
    # Vulnerable command injection
    command = request.json.get('command', '')
    try:
        output = subprocess.check_output(f'ping -c 1 {command}', shell=True)
        return jsonify({'output': output.decode()})
    except:
        return jsonify({'error': 'Command failed'}), 500

@app.route('/api/admin/logs')
@jwt_required()
def get_logs():
    # Vulnerable direct file access
    log_file = request.args.get('file', 'app.log')
    try:
        with open(os.path.join('logs', log_file), 'r') as f:
            return jsonify({'logs': f.read()})
    except:
        return jsonify({'error': 'Log file not found'}), 404

@app.route('/api/admin/backup', methods=['POST'])
@jwt_required()
def backup_database():
    # Vulnerable SSRF
    backup_service = request.json.get('backup_service')
    try:
        response = requests.post(backup_service, json={
            'database': 'medical_records',
            'timestamp': datetime.now().isoformat()
        })
        return jsonify({'status': 'backup initiated'})
    except:
        return jsonify({'error': 'Backup failed'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
