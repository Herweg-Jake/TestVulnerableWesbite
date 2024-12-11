import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
import json

DATABASE_PATH = Path(__file__).resolve().parent / 'medical_records.db'

def init_db():
    """Initialize medical records database with test data."""
    conn = sqlite3.connect(str(DATABASE_PATH))
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY,
                  username TEXT UNIQUE,
                  password TEXT,
                  role TEXT,
                  email TEXT,
                  last_login TEXT)''')
                  
    c.execute('''CREATE TABLE IF NOT EXISTS patients
                 (id INTEGER PRIMARY KEY,
                  name TEXT,
                  ssn TEXT,
                  dob TEXT,
                  medical_history TEXT,
                  allergies TEXT,
                  insurance_info TEXT)''')
                  
    c.execute('''CREATE TABLE IF NOT EXISTS medical_files
                 (id INTEGER PRIMARY KEY,
                  patient_id INTEGER,
                  filename TEXT,
                  upload_date TEXT,
                  file_type TEXT,
                  notes TEXT)''')
                  
    c.execute('''CREATE TABLE IF NOT EXISTS prescriptions
                 (id INTEGER PRIMARY KEY,
                  patient_id INTEGER,
                  medication TEXT,
                  dosage TEXT,
                  prescribed_by TEXT,
                  notes TEXT,
                  date_prescribed TEXT)''')
                  
    c.execute('''CREATE TABLE IF NOT EXISTS appointments
                 (id INTEGER PRIMARY KEY,
                  patient_id INTEGER,
                  doctor_id INTEGER,
                  appointment_date TEXT,
                  notes TEXT,
                  status TEXT)''')

    # Insert test data
    test_data = [
        # Users
        ("INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
         [('admin', 'admin123', 'admin', 'admin@medical.local'),
          ('doctor1', 'doctor123', 'doctor', 'doctor1@medical.local'),
          ('nurse1', 'nurse123', 'nurse', 'nurse1@medical.local'),
          ('staff1', 'staff123', 'staff', 'staff1@medical.local')]),
          
        # Patients
        ("INSERT OR IGNORE INTO patients (name, ssn, dob, medical_history, allergies, insurance_info) VALUES (?, ?, ?, ?, ?, ?)",
         [('John Doe', '123-45-6789', '1980-05-15', 'Hypertension, Diabetes', 'Penicillin', 'BCBS-123456'),
          ('Jane Smith', '987-65-4321', '1975-08-22', 'Asthma', 'None', 'UHC-789012'),
          ('Bob Wilson', '456-78-9012', '1990-12-03', 'Anxiety', 'Sulfa', 'Aetna-345678')]),
          
        # Prescriptions
        ("INSERT OR IGNORE INTO prescriptions (patient_id, medication, dosage, prescribed_by, date_prescribed) VALUES (?, ?, ?, ?, ?)",
         [(1, 'Lisinopril', '10mg daily', 'doctor1', '2024-01-01'),
          (1, 'Metformin', '500mg twice daily', 'doctor1', '2024-01-01'),
          (2, 'Albuterol', '2 puffs as needed', 'doctor1', '2024-01-02')])
    ]

    # Execute all test data insertions
    for query, data_list in test_data:
        for data in data_list:
            try:
                c.execute(query, data)
            except sqlite3.IntegrityError:
                continue

    conn.commit()
    conn.close()

def reset_db():
    """Reset the database by removing and reinitializing it."""
    if DATABASE_PATH.exists():
        DATABASE_PATH.unlink()
    init_db()

if __name__ == "__main__":
    reset_db()