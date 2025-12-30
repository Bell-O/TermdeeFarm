#!/usr/bin/env python
"""
Script สำหรับรันแอปพลิเคชัน Termdee Farm
"""
from app import app, init_db

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5003)

