#!/bin/bash
# Script สำหรับรัน Termdee Farm ใน virtual environment

cd "$(dirname "$0")"

# ตรวจสอบว่า venv มีอยู่หรือไม่
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# ติดตั้ง dependencies (ถ้ายังไม่ได้ติดตั้ง)
if [ ! -f "venv/.installed" ]; then
    echo "Installing dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    touch venv/.installed
fi

# Initialize database
echo "Initializing database..."
python -c "from app import app, init_db; app.app_context().push(); init_db()"

# รันแอป
echo "Starting Termdee Farm..."
echo "Server will be available at: http://localhost:5000"
echo "Default admin login: admin / admin123"
echo ""
python app.py




