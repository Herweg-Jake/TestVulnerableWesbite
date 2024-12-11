# Vulnerable Medical Records System

**WARNING: This is a deliberately vulnerable application designed for security testing. DO NOT deploy in a production environment.**

## Purpose

This application is designed to demonstrate common web security vulnerabilities in a medical records system context. It's intended for:
- Security testing and validation
- Security training and education
- Vulnerability scanning practice

## Setup

1. Clone the repository:
```bash
git clone [repository-url]
cd vulnerable-medical-records
```

2. Build and run with Docker:
```bash
docker-compose up --build
```

The application will be available at `http://localhost:5000`

## Default Credentials

- Admin: admin/admin123
- Doctor: doctor1/doctor123
- Nurse: nurse1/nurse123
- Staff: staff1/staff123

## Security Notice

This application contains numerous security vulnerabilities including but not limited to:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Insecure Direct Object References (IDOR)
- File Upload Vulnerabilities
- Path Traversal
- Information Disclosure

**DO NOT:**
- Deploy this application on a public network
- Use real patient data
- Use real credentials
- Connect to a production database

## Directory Structure

```
vulnerable-medical-records/
├── app/
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── patients.html
│   │   └── records.html
│   ├── app.py
│   └── database.py
├── medical_files/
├── logs/
├── uploads/
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Testing

The application is designed to be tested with security testing frameworks and vulnerability scanners. Test cases include:
- Authentication bypass attempts
- SQL injection points
- File upload exploitation
- Command injection vectors
- Information disclosure vulnerabilities

## Contributing

This is a testing environment. Feel free to:
- Add new vulnerabilities
- Improve existing vulnerabilities
- Add new features to test
- Enhance documentation

## License

For educational purposes only.