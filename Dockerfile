FROM python:3.9-slim

WORKDIR /app

# Install system dependencies for python-magic
RUN apt-get update && \
    apt-get install -y libmagic1 && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p medical_files logs uploads && \
    chmod 777 medical_files logs uploads

# Initialize the database
RUN python database.py

EXPOSE 5000

CMD ["python", "app.py"]