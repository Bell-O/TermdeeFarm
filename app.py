from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import time
from collections import defaultdict
from models import db, User, Order, OrderItem, Task, TaskItem, Log, Settings, OrderTemplate, PageContent, IPLog, BlockedIP, CSRFToken
import string
import random
import os
import requests
import csv
import io
import json
import qrcode
from collections import defaultdict
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# ==================== HELPER FUNCTIONS ====================

def db_transaction(func):
    """Decorator สำหรับจัดการ database transaction พร้อม rollback เมื่อเกิด error"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            db.session.commit()
            return result
        except Exception as e:
            db.session.rollback()
            print(f"Database error in {func.__name__}: {e}")
            raise
    return wrapper

def paginate_query(query, per_page=20):
    """Helper function สำหรับ pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', per_page, type=int)
    
    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    return pagination

def validate_password(password):
    """ตรวจสอบความแข็งแกร่งของรหัสผ่าน"""
    if not password or len(password) < 4:
        return False, 'รหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร'
    if len(password) < 8:
        return True, 'warning'  # แนะนำให้ใช้ 8 ตัวอักษรขึ้นไป
    return True, 'ok'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# รองรับทั้ง SQLite (local) และ PostgreSQL (production)
# Railway, Render, Heroku ใช้ PostgreSQL และ DATABASE_URL จะเป็น postgresql://...
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # แปลงเป็นรูปแบบที่ SQLAlchemy ใช้
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # ใช้ SQLite สำหรับ local development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///termdee_farm.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message='ไม่พบหน้าที่คุณต้องการ'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error_code=500, error_message='เกิดข้อผิดพลาดภายในระบบ'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error_code=403, error_message='คุณไม่มีสิทธิ์เข้าถึงหน้านี้'), 403

@app.errorhandler(Exception)
def handle_exception(e):
    db.session.rollback()
    if request.is_json:
        return jsonify({'error': 'เกิดข้อผิดพลาด: ' + str(e)}), 500
    return render_template('error.html', error_code=500, error_message='เกิดข้อผิดพลาด: ' + str(e)), 500

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'farmer_login'

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

# ฟังก์ชันแปลงสถานะเป็นภาษาไทย
def get_status_th(status):
    """แปลงสถานะเป็นภาษาไทย"""
    status_map = {
        'queued': 'รอคิว',
        'assigned': 'มอบหมายแล้ว',
        'farming': 'กำลังฟาร์ม',
        'delivering': 'กำลังส่ง',
        'done': 'เสร็จแล้ว',
        'canceled': 'ยกเลิก',
        'issue': 'มีปัญหา',
        'accepted': 'รับงานแล้ว',
        'paused': 'พักงาน',
        'ready_to_deliver': 'พร้อมส่ง',
        'delivered': 'ส่งแล้ว'
    }
    return status_map.get(status, status)

# เพิ่ม context processor เพื่อใช้ใน templates
@app.context_processor
def utility_processor():
    # สร้าง CSRF token สำหรับฟอร์ม (เก็บใน session เพื่อใช้ซ้ำได้)
    from flask import session
    import secrets
    
    # สร้าง session_id ถ้ายังไม่มี
    if 'session_id' not in session:
        session['session_id'] = secrets.token_urlsafe(16)
    
    # สร้างหรือใช้ CSRF token ที่มีอยู่
    if 'csrf_token' not in session:
        csrf_token = CSRFToken.generate_token(session_id=session.get('session_id'))
        session['csrf_token'] = csrf_token
    else:
        csrf_token = session['csrf_token']
        # ตรวจสอบว่า token ยังใช้ได้หรือไม่ (ยังไม่ถูกใช้และยังไม่หมดอายุ)
        token_obj = CSRFToken.query.filter_by(token=csrf_token, used=False).first()
        if not token_obj or token_obj.expires_at < datetime.utcnow():
            csrf_token = CSRFToken.generate_token(session_id=session.get('session_id'))
            session['csrf_token'] = csrf_token
    
    return dict(get_status_th=get_status_th, Settings=Settings, csrf_token=csrf_token)

# Helper function สำหรับส่ง Discord webhook
def send_discord_notification(message, webhook_url=None):
    """ส่งแจ้งเตือนไปยัง Discord webhook"""
    if not webhook_url:
        settings = Settings.query.first()
        if settings and settings.discord_webhook_url:
            webhook_url = settings.discord_webhook_url
        else:
            return False
    
    try:
        payload = {
            "content": message
        }
        response = requests.post(webhook_url, json=payload, timeout=5)
        return response.status_code == 204
    except Exception as e:
        print(f"Discord webhook error: {e}")
        return False

# ==================== SECURITY MIDDLEWARE ====================

def get_client_ip():
    """ดึง IP address ของ client"""
    if request.headers.get('X-Forwarded-For'):
        # ถ้าใช้ proxy/load balancer
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip

# Rate limiting storage (in-memory, สำหรับ production ควรใช้ Redis)
rate_limit_store = defaultdict(list)

def rate_limit(max_requests=60, per_minutes=1, endpoint_specific=False):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # ข้าม rate limiting สำหรับ static files
            if request.endpoint == 'static' or request.path.startswith('/static'):
                return f(*args, **kwargs)
            
            # Public endpoints ที่ไม่ต้องการ rate limiting เข้มงวด
            public_endpoints = ['index', 'track_order', 'track_order_key', 'estimator']
            effective_max_requests = max_requests
            if request.endpoint in public_endpoints:
                # เพิ่ม limit สำหรับ public endpoints
                effective_max_requests = max(max_requests, 120)
            
            ip = get_client_ip()
            
            # ตรวจสอบว่า IP ถูก block หรือไม่ (ข้าม public endpoints)
            if request.endpoint not in public_endpoints:
                if BlockedIP.is_blocked(ip):
                    if request.is_json:
                        return jsonify({'error': 'IP address has been blocked'}), 403
                    return render_template('error.html', error_code=403, error_message='IP address ของคุณถูกบล็อก'), 403
            
            # สร้าง key สำหรับ rate limiting
            if endpoint_specific:
                key = f"{ip}:{request.endpoint}"
            else:
                key = ip
            
            now = time.time()
            window_start = now - (per_minutes * 60)
            
            # ลบ requests เก่าที่อยู่นอก window
            rate_limit_store[key] = [req_time for req_time in rate_limit_store[key] if req_time > window_start]
            
            # ตรวจสอบจำนวน requests
            if len(rate_limit_store[key]) >= effective_max_requests:
                # Log suspicious activity (ข้าม static files)
                if request.endpoint and request.endpoint != 'static':
                    try:
                        IPLog.log_request(ip, request.endpoint or 'unknown', request.method, 
                                        request.headers.get('User-Agent'), 
                                        request.headers.get('Referer'), 429, 0)
                    except Exception:
                        pass  # ไม่ให้ logging error ทำให้ request fail
                
                # Auto-block ถ้าเกิน threshold มาก (เฉพาะ non-public endpoints)
                if request.endpoint not in public_endpoints and len(rate_limit_store[key]) >= effective_max_requests * 2:
                    BlockedIP.block_ip(ip, f'Rate limit exceeded: {len(rate_limit_store[key])} requests in {per_minutes} minutes', 
                                     blocked_until=datetime.utcnow() + timedelta(hours=1))
                    send_discord_notification(f"🚨 Auto-blocked IP: {ip} - {len(rate_limit_store[key])} requests in {per_minutes} minutes")
                
                if request.is_json:
                    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
                return render_template('error.html', error_code=429, error_message='คุณส่งคำขอมากเกินไป กรุณาลองใหม่อีกครั้งในภายหลัง'), 429
            
            # เพิ่ม request time
            rate_limit_store[key].append(now)
            
            # Log request
            start_time = time.time()
            try:
                result = f(*args, **kwargs)
                response_time = (time.time() - start_time) * 1000  # milliseconds
                
                # Log successful request (ข้าม static files)
                if request.endpoint and request.endpoint != 'static':
                    status_code = 200
                    if hasattr(result, 'status_code'):
                        status_code = result.status_code
                    elif isinstance(result, tuple) and len(result) > 1:
                        status_code = result[1] if isinstance(result[1], int) else 200
                    
                    try:
                        IPLog.log_request(ip, request.endpoint or 'unknown', request.method,
                                        request.headers.get('User-Agent'),
                                        request.headers.get('Referer'),
                                        status_code, response_time)
                    except Exception:
                        pass  # ไม่ให้ logging error ทำให้ request fail
                
                return result
            except Exception as e:
                response_time = (time.time() - start_time) * 1000
                if request.endpoint and request.endpoint != 'static':
                    try:
                        IPLog.log_request(ip, request.endpoint or 'unknown', request.method,
                                        request.headers.get('User-Agent'),
                                        request.headers.get('Referer'),
                                        500, response_time)
                    except Exception:
                        pass  # ไม่ให้ logging error ทำให้ request fail
                raise
        
        return decorated_function
    return decorator

def csrf_protect(f):
    """CSRF protection decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # ข้าม CSRF check สำหรับ GET requests และ static files
        if request.method == 'GET' or request.endpoint == 'static':
            return f(*args, **kwargs)
        
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            from flask import session
            
            # ข้าม CSRF check สำหรับ public endpoints ที่ไม่ต้องการ authentication
            public_endpoints = ['farmer_login', 'api_estimate', 'track_order']
            if request.endpoint in public_endpoints:
                return f(*args, **kwargs)
            
            # ดึง token จากหลายแหล่ง
            token = None
            if request.is_json and request.json:
                token = request.json.get('csrf_token')
            if not token:
                token = request.headers.get('X-CSRF-Token')
            if not token:
                token = request.form.get('csrf_token')
            
            if not token:
                if request.is_json:
                    return jsonify({'error': 'CSRF token missing'}), 403
                flash('CSRF token missing', 'error')
                return redirect(request.referrer or url_for('index'))
            
            session_id = session.get('session_id') or request.cookies.get('session') or None
            
            # Validate token (ไม่ mark as used เพื่อให้ใช้ได้หลายครั้งใน session เดียวกัน)
            if not CSRFToken.validate_token(token, session_id, mark_used=False):
                if request.is_json:
                    return jsonify({'error': 'Invalid CSRF token'}), 403
                flash('Invalid CSRF token', 'error')
                return redirect(request.referrer or url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def hide_endpoint(f):
    """ซ่อน endpoint จาก robots และ security scanners"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # ข้าม hide_endpoint สำหรับ public endpoints
        public_endpoints = ['index', 'track_order', 'track_order_key', 'estimator', 'static']
        if request.endpoint in public_endpoints:
            return f(*args, **kwargs)
        
        # ตรวจสอบ user agent ที่น่าสงสัย (เฉพาะสำหรับ admin/api endpoints)
        user_agent = request.headers.get('User-Agent', '').lower()
        
        # อนุญาตให้ bots ที่เป็นประโยชน์ผ่าน (เช่น Googlebot, Bingbot)
        allowed_bots = ['googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'yandexbot']
        if any(bot in user_agent for bot in allowed_bots):
            return f(*args, **kwargs)
        
        # เฉพาะ security scanners ที่อันตราย
        suspicious_agents = ['sqlmap', 'nikto', 'masscan', 'nmap', 'nessus', 'acunetix', 'burpsuite', 'w3af']
        
        if any(agent in user_agent for agent in suspicious_agents):
            ip = get_client_ip()
            try:
                IPLog.log_request(ip, request.endpoint or 'unknown', request.method,
                                request.headers.get('User-Agent'),
                                request.headers.get('Referer'),
                                403, 0)
            except Exception:
                pass  # ไม่ให้ logging error ทำให้ request fail
            return render_template('error.html', error_code=404, error_message='ไม่พบหน้าที่คุณต้องการ'), 404
        
        return f(*args, **kwargs)
    return decorated_function

# Before request handler - Log all requests
@app.before_request
def before_request():
    """Log และตรวจสอบ IP ก่อนทุก request"""
    # ข้าม processing สำหรับ static files
    if request.endpoint == 'static' or request.path.startswith('/static'):
        return None
    
    ip = get_client_ip()
    
    # ตรวจสอบ blocked IP (ข้าม public endpoints)
    public_endpoints = ['index', 'track_order', 'estimator']
    if request.endpoint and request.endpoint not in public_endpoints:
        if BlockedIP.is_blocked(ip):
            if 'api' in request.endpoint or 'admin' in request.endpoint:
                return jsonify({'error': 'IP address has been blocked'}), 403
            return render_template('error.html', error_code=403, error_message='IP address ของคุณถูกบล็อก'), 403
    
    # Cleanup expired CSRF tokens (ทำแค่บางครั้งเพื่อไม่ให้ช้า)
    if random.random() < 0.01:  # 1% chance
        try:
            CSRFToken.cleanup_expired()
        except Exception:
            pass  # ไม่ให้ cleanup error ทำให้ request fail

# After request handler - Log response
@app.after_request
def after_request(response):
    """Log response หลังจาก request"""
    # Log จะทำใน rate_limit decorator แล้ว
    return response

# Decorators
def admin_required(f):
    @wraps(f)
    @login_required
    @hide_endpoint
    @rate_limit(max_requests=100, per_minutes=1)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'super_admin']:
            flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    @login_required
    @hide_endpoint
    @rate_limit(max_requests=100, per_minutes=1)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'super_admin':
            flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้ (ต้องเป็นแอดมินหลัก)', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def farmer_required(f):
    @wraps(f)
    @login_required
    @rate_limit(max_requests=120, per_minutes=1)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['farmer', 'admin']:
            flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def generate_order_key():
    """สร้าง Order Key แบบสุ่ม"""
    chars = string.ascii_uppercase + string.digits
    while True:
        key = 'TD-' + ''.join(random.choices(chars, k=6))
        if not Order.query.filter_by(order_key=key).first():
            return key

def calculate_queue_and_eta(order):
    """คำนวณตำแหน่งคิวและเวลารอโดยประมาณ"""
    if order.status in ['done', 'canceled']:
        return None
    
    settings = Settings.get_settings()
    
    # หาออเดอร์ที่อยู่ในคิว
    queue_orders = Order.query.filter(
        Order.status.in_(['queued', 'assigned', 'farming']),
        Order.created_at < order.created_at
    ).order_by(Order.created_at).all()
    
    position = len(queue_orders) + 1
    
    # คำนวณเวลารอจากออเดอร์ที่อยู่ข้างหน้า
    total_wait_minutes = 0
    for q_order in queue_orders:
        # หา tasks ของออเดอร์นี้
        q_tasks = Task.query.filter_by(order_id=q_order.id).all()
        if q_tasks:
            # ใช้ planned_duration_hours จาก tasks ถ้ามี
            order_duration = sum(t.planned_duration_hours or 0 for t in q_tasks)
            if order_duration > 0:
                total_wait_minutes += int(order_duration * 60)
            else:
                # ถ้าไม่มี planned_duration ใช้ค่าเฉลี่ย
                total_wait_minutes += settings['avg_minutes_per_order']
        else:
            # ถ้ายังไม่มี tasks ใช้ค่าเฉลี่ย
            total_wait_minutes += settings['avg_minutes_per_order']
    
    # คำนวณเวลาของออเดอร์นี้เอง
    tasks = Task.query.filter_by(order_id=order.id).all()
    if tasks:
        # ใช้ planned_duration_hours จาก tasks
        order_duration = sum(t.planned_duration_hours or 0 for t in tasks)
        if order_duration > 0:
            order_minutes = int(order_duration * 60)
        else:
            # ถ้าไม่มี planned_duration ใช้ค่าเฉลี่ย
            order_minutes = settings['avg_minutes_per_order']
    else:
        # ถ้ายังไม่มี tasks ใช้ค่าเฉลี่ย
        order_minutes = settings['avg_minutes_per_order']
    
    # รวมเวลารอ + เวลาของออเดอร์นี้
    eta_minutes = total_wait_minutes + order_minutes
    
    # เพิ่ม buffer
    eta_minutes = int(eta_minutes * (1 + settings['eta_buffer_percent'] / 100))
    
    if eta_minutes < 60:
        eta_display = f"{eta_minutes} นาที"
    else:
        hours = eta_minutes // 60
        minutes = eta_minutes % 60
        eta_display = f"{hours} ชั่วโมง {minutes} นาที" if minutes > 0 else f"{hours} ชั่วโมง"
    
    return {
        'position': position,
        'eta_minutes': eta_minutes,
        'eta_display': eta_display
    }

# ==================== PUBLIC ROUTES ====================

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role in ['admin', 'super_admin']:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('farmer_tasks'))
    
    # ดึงเนื้อหาหน้า index จาก database
    page_content = PageContent.get_content('index', {
        'title': 'Termdee Farm',
        'subtitle': 'Termdee Farm ไม่ได้ถูกสร้างมาเพื่อเป็นร้านรับฟาร์มทั่วไป แต่เป็นระบบจัดการงานฟาร์มสำหรับคอมมูนิตี้เกม',
        'content': ''
    })
    
    return render_template('index.html', page_content=page_content)

@app.route('/estimator')
def estimator():
    """หน้า Price & Time Estimator"""
    return render_template('estimator.html')

@app.route('/api/settings', methods=['GET'])
def api_get_settings():
    """API สำหรับดึง settings (สำหรับหน้า estimator)"""
    settings = Settings.query.first()
    if not settings:
        settings = Settings()
        db.session.add(settings)
        db.session.commit()
    
    settings_dict = Settings.get_settings()
    return jsonify({
        'success': True,
        'settings': settings_dict
    })

@app.route('/api/estimate', methods=['POST'])
@rate_limit(max_requests=20, per_minutes=1)
def api_estimate():
    """API สำหรับคำนวณราคาและเวลา"""
    data = request.get_json(force=True, silent=True) or {}
    
    farm_type = data.get('farm_type', 'manual')
    discount_percent = float(data.get('discount_percent', 0.0))
    settings = Settings.get_settings()
    
    # ฟาร์มเครื่องขุด: รับ item_type และ amount เดียว
    if farm_type == 'drill':
        item_type = data.get('item_type', '')
        amount = int(data.get('amount', 0))
        
        if not item_type or amount <= 0:
            return jsonify({'error': 'กรุณากรอกข้อมูลให้ครบถ้วน'}), 400
        
        if item_type.lower() not in ['stone', 'metal', 'sulfur', 'hqm']:
            return jsonify({'error': 'ฟาร์มเครื่องขุดมีบริการเฉพาะ Stone, Metal, Sulfur, HQM เท่านั้น'}), 400
        
        # คำนวณราคา
        price_result = Settings.calculate_total_price_with_bonus(
            item_type, amount, discount_percent, farm_type, settings
        )
        
        # คำนวณเวลา
        estimated_hours = Settings.calculate_duration_hours(item_type, amount)
        
        response_data = {
            'success': True,
            'estimate': {
                'farm_type': farm_type,
                'item_type': item_type,
                'amount': amount,
                'discount_percent': discount_percent,
                'base_price': price_result['base_price'],
                'service_fee': price_result['service_fee'],
                'bonus_items': price_result['bonus_items'],
                'bonus_price': price_result['bonus_price'],
                'bonus_discount_percent': settings.get('bonus_discount_percent', 50.0),
                'total_price': price_result['total_price'],
                'estimated_hours': estimated_hours
            }
        }
        
        # ถ้าเป็นฟาร์มเครื่องขุดและมีการเลือกประเภทที่เหมาะสมกว่า ให้แจ้งเตือน
        if 'optimal_item_type' in price_result and price_result['optimal_item_type'] != item_type.lower():
            response_data['estimate']['price_optimization'] = {
                'message': f'ระบบคำนวณราคาจาก {price_result["optimal_item_type"].upper()} แทน {item_type.upper()} เพื่อป้องกันการโกงราคา',
                'optimal_item_type': price_result['optimal_item_type'],
                'optimal_amount': price_result['optimal_amount'],
                'original_item_type': price_result.get('original_item_type', item_type),
                'original_amount': price_result.get('original_amount', amount)
            }
        
        return jsonify(response_data)
    
    # ฟาร์มมือ: รับ items array (หลายประเภท)
    else:
        items = data.get('items', [])
        
        if not items or len(items) == 0:
            return jsonify({'error': 'กรุณาเพิ่มอย่างน้อย 1 รายการ'}), 400
        
        # ตรวจสอบข้อจำกัด: แต่ละรายการไม่เกิน max_amount
        max_amount = settings.get('manual_farm_max_amount', 15000)
        for item in items:
            if item.get('target_amount', 0) > max_amount:
                return jsonify({'error': f'ฟาร์มมือไม่รับออเดอร์เกิน {max_amount:,} ชิ้นต่อรายการ'}), 400
        
        # คำนวณราคารวมจากทุก items
        total_base_price = 0.0
        total_estimated_hours = 0.0
        all_items_info = []
        
        for item in items:
            item_type = item.get('item_type', '')
            target_amount = int(item.get('target_amount', 0))
            
            if not item_type or target_amount <= 0:
                continue
            
            # คำนวณราคา (ฟาร์มมือไม่มีของแถม)
            item_price = Settings.calculate_price_before_commission(item_type, target_amount, discount_percent)
            total_base_price += item_price
            
            # คำนวณเวลา
            item_hours = Settings.calculate_duration_hours(item_type, target_amount)
            if item_hours:
                total_estimated_hours += item_hours
            
            all_items_info.append({
                'item_type': item_type,
                'target_amount': target_amount,
                'price': item_price,
                'hours': item_hours
            })
        
        service_fee = settings.get('service_fee', 10.0)
        total_price = total_base_price + service_fee
        
        estimated_hours = total_estimated_hours if total_estimated_hours > 0 else None
        
        return jsonify({
            'success': True,
            'estimate': {
                'farm_type': farm_type,
                'items': all_items_info,
                'discount_percent': discount_percent,
                'base_price': total_base_price,
                'service_fee': service_fee,
                'bonus_items': {},
                'bonus_price': 0.0,
                'bonus_discount_percent': 0.0,
                'total_price': total_price,
                'estimated_hours': estimated_hours
            }
        })

@app.route('/track', methods=['GET', 'POST'])
def track_order():
    if request.method == 'POST':
        order_key = request.form.get('order_key', '').strip().upper()
        return redirect(url_for('track_order_key', order_key=order_key))
    return render_template('track.html')

@app.route('/track/<order_key>')
def track_order_key(order_key):
    order = Order.query.filter_by(order_key=order_key.upper()).first()
    
    if not order:
        return render_template('track.html', error='ไม่พบออเดอร์นี้')
    
    tasks = Task.query.filter_by(order_id=order.id).all()
    queue_data = calculate_queue_and_eta(order)
    
    total_target = sum(t.target_amount for t in tasks) if tasks else order.target_amount
    total_current = sum(t.current_amount for t in tasks)
    
    # คำนวณเวลาที่คาดว่าจะใช้จาก tasks
    total_duration_hours = 0
    if tasks:
        # ใช้ planned_duration_hours จาก tasks
        total_duration_hours = sum(t.planned_duration_hours or 0 for t in tasks)
        if total_duration_hours == 0:
            # ถ้าไม่มี planned_duration ให้คำนวณจาก target_amount
            for task in tasks:
                duration = Settings.calculate_duration_hours(task.item_type, task.target_amount)
                total_duration_hours += duration
    
    return render_template('track.html', 
                         order=order, 
                         order_key=order_key,
                         tasks=tasks,
                         queue_data=queue_data,
                         total_target=total_target,
                         total_current=total_current,
                         total_duration_hours=total_duration_hours)

# ==================== FARMER ROUTES ====================

@app.route('/farmer/login', methods=['GET', 'POST'])
def farmer_login():
    if request.method == 'POST':
        # ตรวจสอบว่าเป็น JSON หรือ form data
        if request.is_json:
            data = request.get_json(force=True, silent=True) or {}
        else:
            data = request.form
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            error_msg = 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            return render_template('farmer/login.html', error=error_msg)
        
        user = User.query.filter_by(username=username, active=True).first()
        
        if not user:
            error_msg = 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
            if request.is_json:
                return jsonify({'error': error_msg}), 401
            return render_template('farmer/login.html', error=error_msg)
        
        if not check_password_hash(user.password_hash, password):
            error_msg = 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'
            if request.is_json:
                return jsonify({'error': error_msg}), 401
            return render_template('farmer/login.html', error=error_msg)
        
        if user.role not in ['admin', 'super_admin', 'farmer']:
            error_msg = 'คุณไม่มีสิทธิ์เข้าถึงระบบนี้'
            if request.is_json:
                return jsonify({'error': error_msg}), 403
            return render_template('farmer/login.html', error=error_msg)
        
        login_user(user, remember=True)
        user.last_seen_at = datetime.utcnow()
        try:
            db.session.commit()
        except:
            db.session.rollback()
        
        # Redirect ตาม role
        if user.role in ['admin', 'super_admin']:
            redirect_url = url_for('admin_dashboard')
        else:
            redirect_url = url_for('farmer_tasks')
        
        if request.is_json:
            return jsonify({'success': True, 'redirect': redirect_url})
        return redirect(redirect_url)
    
    return render_template('farmer/login.html')

@app.route('/farmer/logout')
@login_required
def farmer_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/farmer/tasks')
@farmer_required
def farmer_tasks():
    query = Task.query.filter_by(farmer_id=current_user.id).order_by(Task.created_at.desc())
    pagination = paginate_query(query, per_page=20)
    return render_template('farmer/tasks.html', 
                         tasks=pagination.items,
                         pagination=pagination)

@app.route('/farmer/available-tasks')
@farmer_required
def farmer_available_tasks():
    """หน้าสำหรับคนฟาร์มดูงานที่ยังไม่มีคนฟาร์มและกดรับได้"""
    # งานที่ยังไม่มีคนฟาร์ม และยังไม่ได้เริ่ม
    available_tasks = Task.query.filter(
        Task.farmer_id.is_(None),
        Task.status.in_(['assigned'])
    ).order_by(Task.created_at.desc()).all()
    return render_template('farmer/available_tasks.html', available_tasks=available_tasks)

@app.route('/farmer/task/<int:task_id>')
@login_required
def farmer_task_detail(task_id):
    task = Task.query.get_or_404(task_id)
    
    # อนุญาตให้คนฟาร์มดูงานที่:
    # 1. ถูก assign ให้ตัวเองแล้ว (task.farmer_id == current_user.id)
    # 2. หรือยังไม่มีคนฟาร์ม (task.farmer_id is None) - เพื่อให้รับงานได้
    # 3. หรือเป็น admin
    if current_user.role == 'admin':
        # Admin ดูได้ทุกงาน
        pass
    elif current_user.role == 'farmer':
        # คนฟาร์มดูได้เฉพาะงานที่:
        # - ถูก assign ให้ตัวเอง (task.farmer_id == current_user.id)
        # - หรือยังไม่มีคนฟาร์ม (task.farmer_id is None) - เพื่อให้รับงานได้
        if task.farmer_id is not None and task.farmer_id != current_user.id:
            flash('คุณไม่มีสิทธิ์ดูงานนี้', 'error')
            return redirect(url_for('farmer_tasks'))
        # ถ้า task.farmer_id is None หรือ task.farmer_id == current_user.id ก็ผ่าน
    else:
        flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้', 'error')
        return redirect(url_for('index'))
    
    order = Order.query.get(task.order_id)
    if not order:
        flash('ไม่พบออเดอร์ที่เกี่ยวข้อง', 'error')
        return redirect(url_for('farmer_tasks') if current_user.role == 'farmer' else url_for('admin_orders'))
    
    return render_template('farmer/task_detail.html', task=task, order=order)

@app.route('/farmer/leaderboard')
@farmer_required
def farmer_leaderboard():
    """หน้า Leader Board แสดงสถิติคนฟาร์มทั้งหมด"""
    farmers = User.query.filter_by(role='farmer').all()
    
    leaderboard = []
    for farmer in farmers:
        # นับงานทั้งหมด
        total_tasks = Task.query.filter_by(farmer_id=farmer.id).count()
        
        # นับงานที่เสร็จแล้ว
        completed_tasks = Task.query.filter_by(farmer_id=farmer.id, status='delivered').count()
        
        # นับงานที่กำลังทำ
        active_tasks = Task.query.filter_by(farmer_id=farmer.id).filter(
            Task.status.in_(['assigned', 'accepted', 'farming', 'paused', 'ready_to_deliver'])
        ).count()
        
        # คำนวณยอดฟาร์มรวม
        tasks = Task.query.filter_by(farmer_id=farmer.id).all()
        total_amount = sum(t.current_amount for t in tasks)
        
        # แยกตามประเภท
        item_breakdown = {}
        for t in tasks:
            if t.item_type:
                item_breakdown[t.item_type] = item_breakdown.get(t.item_type, 0) + t.current_amount
        
        leaderboard.append({
            'farmer': farmer,
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'active_tasks': active_tasks,
            'total_amount': total_amount,
            'item_breakdown': item_breakdown
        })
    
    # เรียงตามงานที่เสร็จแล้ว แล้วค่อยยอดฟาร์มรวม
    leaderboard.sort(key=lambda x: (x['completed_tasks'], x['total_amount']), reverse=True)
    
    return render_template('farmer/leaderboard.html', leaderboard=leaderboard)

# ==================== FARMER API ====================

@app.route('/api/farmer/task/<int:task_id>/accept', methods=['POST'])
@farmer_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_farmer_accept_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # ตรวจสอบว่า task ถูก assign ให้คนฟาร์มคนนี้แล้วหรือยัง
    if task.farmer_id is None:
        return jsonify({'error': 'งานนี้ยังไม่ได้ถูก assign ให้คุณ กรุณาใช้ปุ่ม "รับงาน" ในหน้าวงานที่รับได้'}), 400
    
    if task.farmer_id != current_user.id:
        return jsonify({'error': 'คุณไม่มีสิทธิ์ในงานนี้'}), 403
    
    if task.status != 'assigned':
        return jsonify({'error': 'ไม่สามารถรับงานนี้ได้'}), 400
    
    task.status = 'accepted'
    task.accepted_at = datetime.utcnow()
    task.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task.id, 
                   'accept_task', 0, f'{current_user.display_name} รับงาน')
    
    return jsonify({'success': True})

@app.route('/api/farmer/task/<int:task_id>/start', methods=['POST'])
@farmer_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_farmer_start_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.farmer_id != current_user.id:
        return jsonify({'error': 'คุณไม่มีสิทธิ์ในงานนี้'}), 403
    
    if task.status not in ['accepted', 'paused']:
        return jsonify({'error': 'ไม่สามารถเริ่มงานนี้ได้'}), 400
    
    task.status = 'farming'
    if not task.started_at:
        task.started_at = datetime.utcnow()
    task.updated_at = datetime.utcnow()
    
    # อัพเดตสถานะ order ถ้ายังไม่ได้เริ่ม
    order = Order.query.get(task.order_id)
    if order.status in ['queued', 'assigned']:
        order.status = 'farming'
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task.id, 
                   'start_task', 0, f'{current_user.display_name} เริ่มฟาร์ม')
    
    return jsonify({'success': True})

@app.route('/api/farmer/task/<int:task_id>/progress', methods=['POST'])
@farmer_required
@csrf_protect
@rate_limit(max_requests=60, per_minutes=1)
@db_transaction
def api_farmer_update_progress(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.farmer_id != current_user.id:
        return jsonify({'error': 'คุณไม่มีสิทธิ์ในงานนี้'}), 403
    
    data = request.get_json(force=True, silent=True) or {}
    # รองรับทั้ง 'amount' และ 'delta' เพื่อความเข้ากันได้
    delta = data.get('delta') or data.get('amount', 0)
    
    # แปลงเป็น int ถ้ายังเป็น string
    try:
        delta = int(delta)
    except (ValueError, TypeError):
        return jsonify({'error': 'จำนวนไม่ถูกต้อง'}), 400
    
    if delta == 0:
        return jsonify({'error': 'จำนวนต้องไม่เท่ากับ 0'}), 400
    
    settings = Settings.get_settings()
    abs_delta = abs(delta)
    if abs_delta > settings['max_delta_per_action']:
        return jsonify({'error': f'จำนวนต้องไม่เกิน {settings["max_delta_per_action"]:,}'}), 400
    
    # คำนวณจำนวนใหม่ (รองรับทั้งเพิ่มและลด)
    new_amount = task.current_amount + delta
    
    # ตรวจสอบว่าจำนวนใหม่ไม่เป็นลบ
    if new_amount < 0:
        return jsonify({'error': 'จำนวนไม่สามารถเป็นลบได้'}), 400
    
    # ตรวจสอบว่าจำนวนใหม่ไม่เกินเป้าหมาย (ถ้าเป็นการเพิ่ม)
    if delta > 0:
        new_amount = min(new_amount, task.target_amount)
    
    task.current_amount = new_amount
    task.updated_at = datetime.utcnow()
    
    # บันทึก log
    if delta > 0:
        log_message = f'{current_user.display_name} เพิ่ม +{delta:,}'
    else:
        log_message = f'{current_user.display_name} ลด {delta:,}'
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task.id, 
                   'update_progress', delta, log_message)
    
    return jsonify({'success': True, 'current_amount': task.current_amount})

@app.route('/api/farmer/task/<int:task_id>/pause', methods=['POST'])
@farmer_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_farmer_pause_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.farmer_id != current_user.id:
        return jsonify({'error': 'คุณไม่มีสิทธิ์ในงานนี้'}), 403
    
    if task.status != 'farming':
        return jsonify({'error': 'ไม่สามารถพักงานนี้ได้'}), 400
    
    task.status = 'paused'
    task.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task.id, 
                   'pause_task', 0, f'{current_user.display_name} พักงาน')
    
    return jsonify({'success': True})

@app.route('/api/farmer/task/<int:task_id>/ready', methods=['POST'])
@farmer_required
@db_transaction
def api_farmer_ready_to_deliver(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.farmer_id != current_user.id:
        return jsonify({'error': 'คุณไม่มีสิทธิ์ในงานนี้'}), 403
    
    if task.status != 'farming':
        return jsonify({'error': 'ไม่สามารถแจ้งพร้อมส่งได้'}), 400
    
    task.status = 'ready_to_deliver'
    task.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task.id, 
                   'ready_to_deliver', 0, f'{current_user.display_name} พร้อมส่ง')
    
    return jsonify({'success': True})

@app.route('/api/farmer/task/<int:task_id>/delivered', methods=['POST'])
@farmer_required
@db_transaction
def api_farmer_delivered(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.farmer_id != current_user.id:
        return jsonify({'error': 'คุณไม่มีสิทธิ์ในงานนี้'}), 403
    
    if task.status != 'ready_to_deliver':
        return jsonify({'error': 'ไม่สามารถยืนยันส่งแล้วได้'}), 400
    
    task.status = 'delivered'
    task.finished_at = datetime.utcnow()
    task.updated_at = datetime.utcnow()
    
    # ตรวจสอบว่าออเดอร์เสร็จหมดหรือยัง
    order = task.order
    all_tasks_delivered = all(t.status == 'delivered' for t in order.tasks)
    
    if all_tasks_delivered:
        order.status = 'done'
        order.updated_at = datetime.utcnow()
        # แจ้งเตือนเมื่อออเดอร์เสร็จ
        send_discord_notification(
            f"✅ **ออเดอร์เสร็จสมบูรณ์**\n\n"
            f"**Order Key:** `{order.order_key}`\n"
            f"**ลูกค้า:** {order.customer_ref or '-'}\n"
            f"**เซิร์ฟเวอร์:** {order.server_name or '-'}\n"
            f"**ประเภท:** {order.item_type.upper()}\n"
            f"**จำนวน:** {order.target_amount:,}"
        )
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task.id, 
                   'delivered', 0, f'{current_user.display_name} ส่งแล้ว')
    
    return jsonify({'success': True})

# ==================== ADMIN ROUTES ====================

@app.route('/admin')
@admin_required
def admin_dashboard():
    # สถิติรวม
    total_orders = Order.query.count()
    active_orders = Order.query.filter(Order.status.in_(['queued', 'assigned', 'farming', 'delivering'])).count()
    completed_orders = Order.query.filter_by(status='done').count()
    total_farmers = User.query.filter_by(role='farmer', active=True).count()
    
    # สถิติรายได้
    settings = Settings.get_settings()
    commission = settings.get('commission_percent', 10.0)
    
    # รายได้เดือนนี้
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)
    tasks_this_month = Task.query.join(Order).filter(
        Task.status == 'delivered',
        Task.updated_at >= month_start
    ).all()
    
    total_revenue = 0.0
    total_paid_to_farmers = 0.0
    total_commission = 0.0
    
    for task in tasks_this_month:
        order = task.order
        farmer_earning = Settings.calculate_price(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        customer_price = Settings.calculate_price_before_commission(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        commission_amount = customer_price - farmer_earning
        
        total_revenue += customer_price
        total_paid_to_farmers += farmer_earning
        total_commission += commission_amount
    
    # สถิติรายได้รายสัปดาห์
    week_start = now - timedelta(days=now.weekday())
    tasks_this_week = Task.query.join(Order).filter(
        Task.status == 'delivered',
        Task.updated_at >= week_start
    ).all()
    
    week_revenue = 0.0
    week_paid = 0.0
    
    for task in tasks_this_week:
        order = task.order
        farmer_earning = Settings.calculate_price(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        customer_price = Settings.calculate_price_before_commission(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        week_revenue += customer_price
        week_paid += farmer_earning
    
    # สถิติตามประเภทของ
    item_stats = defaultdict(lambda: {'count': 0, 'amount': 0, 'revenue': 0.0})
    all_tasks = Task.query.join(Order).filter(Task.status == 'delivered').all()
    
    for task in all_tasks:
        order = task.order
        item_stats[task.item_type]['count'] += 1
        item_stats[task.item_type]['amount'] += task.current_amount
        revenue = Settings.calculate_price_before_commission(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        item_stats[task.item_type]['revenue'] += revenue
    
    # ออเดอร์ล่าสุด
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    
    # ดึงข้อมูลทั้งหมดสำหรับ template
    all_orders = Order.query.order_by(Order.created_at.desc()).all()
    all_farmers = User.query.filter_by(role='farmer', active=True).all()
    
    return render_template('admin/dashboard.html',
                         total_orders=total_orders,
                         active_orders=active_orders,
                         completed_orders=completed_orders,
                         total_farmers=total_farmers,
                         recent_orders=recent_orders,
                         orders=all_orders,
                         farmers=all_farmers,
                         total_revenue=total_revenue,
                         total_paid_to_farmers=total_paid_to_farmers,
                         total_commission=total_commission,
                         week_revenue=week_revenue,
                         week_paid=week_paid,
                         item_stats=dict(item_stats))

@app.route('/admin/orders')
@admin_required
def admin_orders():
    # Search & Filter
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip()
    item_type_filter = request.args.get('item_type', '').strip()
    
    query = Order.query
    
    if search:
        query = query.filter(
            (Order.order_key.contains(search.upper())) |
            (Order.customer_ref.contains(search)) |
            (Order.server_name.contains(search))
        )
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    if item_type_filter:
        query = query.filter_by(item_type=item_type_filter)
    
    query = query.order_by(Order.created_at.desc())
    pagination = paginate_query(query, per_page=20)
    
    # Preload order_items เพื่อป้องกัน N+1 query
    from sqlalchemy.orm import joinedload
    order_ids = [o.id for o in pagination.items]
    if order_ids:
        orders_with_items = db.session.query(Order).options(joinedload(Order.order_items)).filter(Order.id.in_(order_ids)).all()
        order_items_map = {o.id: o.order_items for o in orders_with_items}
    else:
        order_items_map = {}
    
    # Attach order_items to orders
    for order in pagination.items:
        order.order_items = order_items_map.get(order.id, [])
    
    # คำนวณยอดจ่ายให้คนฟาร์มต่อออเดอร์ (จาก tasks ทั้งหมดในออเดอร์)
    order_payments = {}
    for order in pagination.items:
        tasks = Task.query.filter_by(order_id=order.id).all()
        total_payment = 0.0
        for task in tasks:
            if task.item_type and task.target_amount:
                payment = Settings.calculate_price(
                    task.item_type, 
                    task.target_amount, 
                    order.discount_percent or 0
                )
                total_payment += payment
        order_payments[order.id] = round(total_payment, 2)
    
    # Get all statuses and item types for filter dropdown
    all_statuses = ['queued', 'assigned', 'farming', 'delivering', 'done', 'canceled', 'issue']
    all_item_types = ['wood', 'stone', 'sulfur', 'metal', 'scrap', 'hqm']
    
    return render_template('admin/orders.html', 
                         orders=pagination.items,
                         pagination=pagination,
                         search=search,
                         status_filter=status_filter,
                         item_type_filter=item_type_filter,
                         all_statuses=all_statuses,
                         all_item_types=all_item_types,
                         order_payments=order_payments)

@app.route('/admin/order/<int:order_id>')
@admin_required
def admin_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    tasks = Task.query.filter_by(order_id=order_id).all()
    farmers = User.query.filter_by(role='farmer', active=True).all()
    logs = Log.query.filter_by(order_id=order_id).order_by(Log.created_at.desc()).limit(50).all()
    
    # Load order_items
    from sqlalchemy.orm import joinedload
    order_with_items = db.session.query(Order).options(joinedload(Order.order_items)).filter_by(id=order_id).first()
    order.order_items = order_with_items.order_items if order_with_items else []
    
    # นับจำนวนงานที่คนฟาร์มแต่ละคนกำลังทำอยู่ (แก้ N+1 query)
    farmer_ids = [f.id for f in farmers]
    if farmer_ids:
        from sqlalchemy import func
        task_counts = db.session.query(
            Task.farmer_id,
            func.count(Task.id).label('count')
        ).filter(
            Task.farmer_id.in_(farmer_ids),
            Task.status.in_(['assigned', 'accepted', 'farming', 'paused'])
        ).group_by(Task.farmer_id).all()
        
        farmer_task_counts = {farmer_id: count for farmer_id, count in task_counts}
    else:
        farmer_task_counts = {}
    
    # เติม 0 สำหรับคนฟาร์มที่ไม่มีงาน
    for farmer in farmers:
        if farmer.id not in farmer_task_counts:
            farmer_task_counts[farmer.id] = 0
    
    return render_template('admin/order_detail.html', 
                          order=order, 
                          tasks=tasks, 
                          farmers=farmers, 
                          logs=logs, 
                          farmer_task_counts=farmer_task_counts)

@app.route('/admin/farmers')
@admin_required
def admin_farmers():
    # Search & Filter
    search = request.args.get('search', '').strip()
    active_filter = request.args.get('active', '')
    role_filter = request.args.get('role', '').strip()
    
    # Query สำหรับคนฟาร์ม
    farmer_query = User.query.filter_by(role='farmer')
    
    if search:
        farmer_query = farmer_query.filter(
            (User.username.contains(search)) |
            (User.display_name.contains(search)) |
            (User.real_name.contains(search))
        )
    
    if active_filter == 'true':
        farmer_query = farmer_query.filter_by(active=True)
    elif active_filter == 'false':
        farmer_query = farmer_query.filter_by(active=False)
    
    if role_filter == 'farmer':
        farmers = farmer_query.all()
    elif role_filter == 'admin':
        farmers = []
    else:
        farmers = farmer_query.all()
    
    # Query สำหรับแอดมิน (เฉพาะ super_admin)
    admins = []
    if current_user.role == 'super_admin':
        admin_query = User.query.filter(User.role.in_(['admin', 'super_admin']))
        
        if search:
            admin_query = admin_query.filter(
                (User.username.contains(search)) |
                (User.display_name.contains(search))
            )
        
        if active_filter == 'true':
            admin_query = admin_query.filter_by(active=True)
        elif active_filter == 'false':
            admin_query = admin_query.filter_by(active=False)
        
        if role_filter == 'admin':
            admins = admin_query.all()
        elif role_filter == 'farmer':
            admins = []
        else:
            admins = admin_query.all()
    
    # นับสถิติสำหรับแต่ละคนฟาร์ม
    farmer_stats = {}
    for farmer in farmers:
        total_tasks = Task.query.filter_by(farmer_id=farmer.id).count()
        completed_tasks = Task.query.filter_by(farmer_id=farmer.id, status='delivered').count()
        active_tasks = Task.query.filter_by(farmer_id=farmer.id).filter(
            Task.status.in_(['assigned', 'accepted', 'farming', 'paused'])
        ).count()
        
        farmer_stats[farmer.id] = {
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'active_tasks': active_tasks
        }
    
    return render_template('admin/farmers.html', 
                         farmers=farmers,
                         admins=admins if current_user.role == 'super_admin' else [],
                         farmer_stats=farmer_stats,
                         search=search,
                         active_filter=active_filter,
                         role_filter=role_filter,
                         current_user_role=current_user.role)

@app.route('/admin/queue')
@admin_required
def admin_queue():
    # ออเดอร์ที่อยู่ในคิว
    queue_orders = Order.query.filter(
        Order.status.in_(['queued', 'assigned', 'farming'])
    ).order_by(Order.created_at).all()
    
    queue_data = []
    for order in queue_orders:
        tasks = Task.query.filter_by(order_id=order.id).all()
        total_target = sum(t.target_amount for t in tasks) if tasks else order.target_amount
        total_current = sum(t.current_amount for t in tasks)
        progress = (total_current / total_target * 100) if total_target > 0 else 0
        
        queue_info = calculate_queue_and_eta(order)
        
        queue_data.append({
            'order': order,
            'tasks': tasks,
            'progress': progress,
            'queue_info': queue_info
        })
    
    return render_template('admin/queue.html', queue_data=queue_data)

@app.route('/admin/logs')
@admin_required
def admin_logs():
    logs = Log.query.order_by(Log.created_at.desc()).limit(100).all()
    return render_template('admin/logs.html', logs=logs)

@app.route('/admin/activity')
@admin_required
def admin_activity():
    """หน้าแสดงกิจกรรมของผู้ใช้ทั้งหมด"""
    # ดึง logs ทั้งหมดพร้อมข้อมูลผู้ใช้
    logs = Log.query.order_by(Log.created_at.desc()).limit(200).all()
    
    # จัดกลุ่มตามผู้ใช้
    user_activities = {}
    for log in logs:
        user_id = log.actor_user_id
        if user_id not in user_activities:
            user = User.query.get(user_id)
            if user:  # Only add if user exists
                user_activities[user_id] = {
                    'user': user,
                    'activities': []
                }
        if user_id in user_activities:  # Only append if user was found
            user_activities[user_id]['activities'].append(log)
    
    return render_template('admin/activity.html', user_activities=user_activities)

@app.route('/admin/settings')
@admin_required
def admin_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings()
        db.session.add(settings)
        try:
            db.session.commit()
        except:
            db.session.rollback()
    
    return render_template('admin/settings.html', settings=settings)

@app.route('/api/admin/page-content/<page_key>', methods=['GET'])
@admin_required
def api_admin_get_page_content(page_key):
    """ดึงเนื้อหาหน้าเว็บ"""
    content = PageContent.query.filter_by(page_key=page_key).first()
    if content:
        return jsonify({
            'success': True,
            'content': {
                'id': content.id,
                'page_key': content.page_key,
                'title': content.title,
                'subtitle': content.subtitle,
                'content': content.content
            }
        })
    return jsonify({
        'success': True,
        'content': None
    })

@app.route('/api/admin/page-content/<page_key>', methods=['PUT'])
@admin_required
@csrf_protect
@rate_limit(max_requests=20, per_minutes=1)
@db_transaction
def api_admin_update_page_content(page_key):
    """อัพเดตเนื้อหาหน้าเว็บ"""
    data = request.get_json(force=True, silent=True) or {}
    
    content = PageContent.query.filter_by(page_key=page_key).first()
    if not content:
        content = PageContent(page_key=page_key)
        db.session.add(content)
    
    if 'title' in data:
        content.title = data['title'].strip() if data['title'] else None
    if 'subtitle' in data:
        content.subtitle = data['subtitle'].strip() if data['subtitle'] else None
    if 'content' in data:
        content.content = data['content'].strip() if data['content'] else None
    
    content.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, None, None,
                   'update_page_content', 0, f'อัพเดตเนื้อหาหน้า {page_key}')
    
    return jsonify({
        'success': True,
        'message': 'บันทึกเนื้อหาสำเร็จ'
    })

@app.route('/admin/change-password')
@admin_required
def admin_change_password():
    """หน้าเปลี่ยนรหัสผ่านแอดมิน"""
    return render_template('admin/change_password.html')

@app.route('/admin/security')
@super_admin_required
def admin_security():
    """หน้าจัดการความปลอดภัย: IP blocking และ logs"""
    # ดึง blocked IPs
    blocked_ips = BlockedIP.query.filter_by(is_active=True).order_by(BlockedIP.blocked_at.desc()).all()
    
    # ดึง suspicious IPs
    suspicious_ips = IPLog.get_suspicious_ips(minutes=5, threshold=50)
    
    # ดึง IP logs ล่าสุด
    recent_logs = IPLog.query.order_by(IPLog.created_at.desc()).limit(100).all()
    
    return render_template('admin/security.html', 
                         blocked_ips=blocked_ips,
                         suspicious_ips=suspicious_ips,
                         recent_logs=recent_logs)

@app.route('/api/admin/security/block-ip', methods=['POST'])
@super_admin_required
@csrf_protect
@rate_limit(max_requests=10, per_minutes=1)
@db_transaction
def api_admin_block_ip():
    """Block IP manually"""
    data = request.get_json(force=True, silent=True) or {}
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Manual block by admin')
    hours = int(data.get('hours', 0))  # 0 = permanent
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    blocked_until = None
    if hours > 0:
        blocked_until = datetime.utcnow() + timedelta(hours=hours)
    
    BlockedIP.block_ip(ip_address, reason, blocked_until, blocked_by=str(current_user.id))
    
    return jsonify({'success': True, 'message': f'Blocked IP: {ip_address}'})

@app.route('/api/admin/security/unblock-ip', methods=['POST'])
@super_admin_required
@csrf_protect
@rate_limit(max_requests=10, per_minutes=1)
@db_transaction
def api_admin_unblock_ip():
    """Unblock IP"""
    data = request.get_json(force=True, silent=True) or {}
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    BlockedIP.unblock_ip(ip_address)
    
    return jsonify({'success': True, 'message': f'Unblocked IP: {ip_address}'})

# ==================== ADMIN API ====================

@app.route('/api/admin/order', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_admin_create_order():
    data = request.get_json(force=True, silent=True) or {}
    
    order_key = generate_order_key()
    discount_percent = float(data.get('discount_percent', 0.0))
    
    # รองรับทั้งแบบเก่า (item_type, target_amount) และแบบใหม่ (items array)
    items = data.get('items', [])
    if not items:
        # แบบเก่า: ใช้ item_type และ target_amount เดียว
        items = [{
            'item_type': data.get('item_type', ''),
            'target_amount': int(data.get('target_amount', 0))
        }]
    
    # ใช้ item แรกเป็นค่า default สำหรับ backward compatibility
    first_item = items[0] if items else {}
    order = Order(
        order_key=order_key,
        customer_ref=data.get('customer_ref', ''),
        server_name=data.get('server_name', ''),
        item_type=first_item.get('item_type', ''),
        target_amount=int(first_item.get('target_amount', 0)),
        priority=data.get('priority', 'normal'),
        discount_percent=discount_percent,
        note_admin=data.get('note_admin', '')
    )
    
    db.session.add(order)
    db.session.flush()
    
    # สร้าง OrderItem สำหรับทุก item
    for item_data in items:
        if item_data.get('item_type') and item_data.get('target_amount', 0) > 0:
            order_item = OrderItem(
                order_id=order.id,
                item_type=item_data['item_type'],
                target_amount=int(item_data['target_amount'])
            )
            db.session.add(order_item)
    
    Log.create_log(current_user.id, current_user.role, order.id, None, 
                   'create_order', 0, f'สร้างออเดอร์ {order_key}')
    
    return jsonify({
        'success': True, 
        'order_id': order.id,
        'order_key': order_key
    })

@app.route('/api/admin/order/<int:order_id>/task', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_admin_create_task(order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json(force=True, silent=True) or {}
    
    # รองรับทั้งแบบเก่า (item_type, target_amount) และแบบใหม่ (items array)
    items = data.get('items', [])
    if not items:
        # แบบเก่า: ใช้ item_type และ target_amount เดียว
        items = [{
            'item_type': data.get('item_type', order.item_type),
            'target_amount': int(data.get('target_amount', 0))
        }]
    
    # ใช้ item แรกเป็นค่า default สำหรับ backward compatibility
    first_item = items[0] if items else {}
    item_type = first_item.get('item_type', '')
    target_amount = int(first_item.get('target_amount', 0))
    total_target = sum(int(item.get('target_amount', 0)) for item in items)
    
    # คำนวณเวลาที่ใช้ในการฟาร์มอัตโนมัติ (ถ้ายังไม่ได้ระบุ)
    planned_duration_hours = None
    if data.get('planned_duration_hours'):
        planned_duration_hours = float(data['planned_duration_hours'])
    elif total_target > 0 and item_type:
        # คำนวณอัตโนมัติจาก total_target และ item_type (ใช้ item_type แรก)
        planned_duration_hours = Settings.calculate_duration_hours(item_type, total_target)
    
    # Parse planned_start with error handling
    planned_start = None
    if data.get('planned_start'):
        try:
            planned_start = datetime.fromisoformat(data['planned_start'])
        except (ValueError, TypeError):
            planned_start = None
    
    task = Task(
        order_id=order_id,
        farmer_id=data.get('farmer_id'),
        server_name=data.get('server_name', order.server_name),
        item_type=item_type,  # DEPRECATED - เก็บไว้สำหรับ backward compatibility
        target_amount=total_target,  # DEPRECATED - sum of all items
        current_amount=0,  # DEPRECATED - sum of all items
        planned_start=planned_start,
        planned_duration_hours=planned_duration_hours
    )
    
    db.session.add(task)
    db.session.flush()
    
    # สร้าง TaskItem สำหรับทุก item
    for item_data in items:
        if item_data.get('item_type') and item_data.get('target_amount', 0) > 0:
            task_item = TaskItem(
                task_id=task.id,
                item_type=item_data['item_type'],
                target_amount=int(item_data['target_amount']),
                current_amount=0
            )
            db.session.add(task_item)
    
    # อัพเดต current_amount ของ task เป็น sum ของ task_items
    task.current_amount = 0  # จะถูกคำนวณใหม่จาก task_items
    
    # อัพเดตสถานะ order ถ้ายังไม่ได้ assign
    if order.status == 'queued':
        order.status = 'assigned'
    
    msg = f'สร้าง Task #{task.id}'
    if task.farmer_id:
        farmer = User.query.get(task.farmer_id)
        msg += f' มอบหมายให้ {farmer.display_name}'
    
    Log.create_log(current_user.id, current_user.role, order_id, task.id, 
                   'create_task', 0, msg)
    
    # ส่งแจ้งเตือน Discord เมื่อมี Task ใหม่ (สำหรับคนฟาร์ม)
    order = Order.query.get(order_id)
    settings_data = Settings.get_settings()
    commission = settings_data.get('commission_percent', 10.0)
    
    # คำนวณเงินที่จะได้
    price_after = Settings.calculate_price(task.item_type, task.target_amount, order.discount_percent or 0)
    
    message = f"🔔 **งานใหม่ที่รับได้**\n\n"
    message += f"**Order Key:** {order.order_key}\n"
    message += f"**เซิร์ฟเวอร์:** {task.server_name or order.server_name or '-'}\n"
    message += f"**ประเภท:** {task.item_type.upper()}\n"
    message += f"**เป้าหมาย:** {task.target_amount:,}\n"
    
    # เวลาที่คาดว่าจะใช้
    if task.planned_duration_hours:
        if task.planned_duration_hours >= 1:
            message += f"**เวลาที่คาดว่าจะใช้:** {task.planned_duration_hours:.1f} ชั่วโมง\n"
        else:
            message += f"**เวลาที่คาดว่าจะใช้:** {int(task.planned_duration_hours * 60)} นาที\n"
    
    # เงินที่จะได้
    message += f"**เงินที่จะได้:** {price_after:.2f} บาท (หลังหักค่าคนกลาง {commission}%)\n"
    if order.discount_percent and order.discount_percent > 0:
        message += f"*มีส่วนลด {order.discount_percent}% ให้ลูกค้า*\n"
    
    if task.farmer_id:
        farmer = User.query.get(task.farmer_id)
        message += f"\n**มอบหมายให้:** {farmer.display_name}"
    else:
        message += f"\n**สถานะ:** รอรับงาน - กดรับได้เลย!"
    
    send_discord_notification(message)
    
    return jsonify({'success': True, 'task_id': task.id})

@app.route('/api/admin/task/<int:task_id>', methods=['GET'])
@admin_required
def api_admin_get_task(task_id):
    """ดึงข้อมูล Task"""
    task = Task.query.get_or_404(task_id)
    return jsonify({
        'success': True,
        'task': {
            'id': task.id,
            'server_name': task.server_name,
            'item_type': task.item_type,
            'target_amount': task.target_amount,
            'current_amount': task.current_amount,
            'planned_start': task.planned_start.isoformat() if task.planned_start else None,
            'planned_duration_hours': task.planned_duration_hours
        }
    })

@app.route('/api/admin/task/<int:task_id>', methods=['PATCH'])
@admin_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_admin_update_task(task_id):
    """แก้ไขข้อมูล Task"""
    task = Task.query.get_or_404(task_id)
    data = request.get_json(force=True, silent=True) or {}
    
    # ตรวจสอบว่ายังไม่เสร็จ
    if task.status == 'delivered':
        return jsonify({'error': 'ไม่สามารถแก้ไขงานที่เสร็จแล้วได้'}), 400
    
    # อัพเดตข้อมูล
    if 'target_amount' in data:
        try:
            target_amount = int(data['target_amount'])
            if target_amount <= 0:
                return jsonify({'error': 'เป้าหมายต้องมากกว่า 0'}), 400
            # ตรวจสอบว่า current_amount ไม่เกิน target_amount ใหม่
            if task.current_amount > target_amount:
                return jsonify({'error': f'จำนวนปัจจุบัน ({task.current_amount:,}) มากกว่าเป้าหมายใหม่ ({target_amount:,})'}), 400
            task.target_amount = target_amount
        except (ValueError, TypeError):
            return jsonify({'error': 'เป้าหมายไม่ถูกต้อง'}), 400
    
    if 'server_name' in data:
        task.server_name = data['server_name'].strip() if data['server_name'] else None
    
    if 'item_type' in data:
        if data['item_type'] not in ['wood', 'stone', 'sulfur', 'metal', 'scrap', 'hqm']:
            return jsonify({'error': 'ประเภทไม่ถูกต้อง'}), 400
        task.item_type = data['item_type']
    
    if 'planned_start' in data:
        if data['planned_start']:
            try:
                task.planned_start = datetime.fromisoformat(data['planned_start'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                try:
                    task.planned_start = datetime.strptime(data['planned_start'], '%Y-%m-%dT%H:%M')
                except ValueError:
                    return jsonify({'error': 'รูปแบบวันที่ไม่ถูกต้อง'}), 400
        else:
            task.planned_start = None
    
    if 'planned_duration_hours' in data:
        if data['planned_duration_hours']:
            try:
                duration = float(data['planned_duration_hours'])
                if duration <= 0:
                    return jsonify({'error': 'ระยะเวลาต้องมากกว่า 0'}), 400
                task.planned_duration_hours = duration
            except (ValueError, TypeError):
                return jsonify({'error': 'ระยะเวลาไม่ถูกต้อง'}), 400
        else:
            task.planned_duration_hours = None
    
    task.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task_id, 
                   'update_task', 0, f'แก้ไขข้อมูล Task #{task_id}')
    
    return jsonify({'success': True, 'task': {
        'id': task.id,
        'target_amount': task.target_amount,
        'server_name': task.server_name,
        'item_type': task.item_type,
        'planned_start': task.planned_start.isoformat() if task.planned_start else None,
        'planned_duration_hours': task.planned_duration_hours
    }})

@app.route('/api/admin/task/<int:task_id>/assign', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_admin_assign_task(task_id):
    task = Task.query.get_or_404(task_id)
    data = request.get_json(force=True, silent=True) or {}
    
    farmer_id = data.get('farmer_id')
    if not farmer_id:
        return jsonify({'error': 'กรุณาเลือกคนฟาร์ม'}), 400
    
    farmer = User.query.get(farmer_id)
    if not farmer or farmer.role != 'farmer':
        return jsonify({'error': 'ไม่พบคนฟาร์ม'}), 404
    
    old_farmer = User.query.get(task.farmer_id) if task.farmer_id else None
    task.farmer_id = farmer_id
    
    # อัพเดตเวลาที่วางแผนไว้ (ถ้ามี)
    if data.get('planned_start'):
        try:
            task.planned_start = datetime.fromisoformat(data['planned_start'])
        except (ValueError, TypeError):
            pass  # Ignore invalid date format
    
    # คำนวณเวลาที่ใช้ในการฟาร์มอัตโนมัติ (ถ้ายังไม่ได้ระบุ)
    if data.get('planned_duration_hours'):
        task.planned_duration_hours = float(data['planned_duration_hours'])
    elif task.target_amount > 0 and task.item_type:
        # คำนวณอัตโนมัติจาก target_amount และ item_type
        task.planned_duration_hours = Settings.calculate_duration_hours(task.item_type, task.target_amount)
    
    task.updated_at = datetime.utcnow()
    
    if old_farmer:
        msg = f'เปลี่ยนคนฟาร์มจาก {old_farmer.display_name} เป็น {farmer.display_name}'
    else:
        msg = f'มอบหมายงานให้ {farmer.display_name}'
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task_id, 
                   'assign_task', 0, msg)
    
    return jsonify({'success': True})

@app.route('/api/admin/task/<int:task_id>/unassign', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_admin_unassign_task(task_id):
    """แอดมินถอดคนฟาร์มออกจากงาน"""
    task = Task.query.get_or_404(task_id)
    
    if not task.farmer_id:
        return jsonify({'error': 'งานนี้ยังไม่มีคนฟาร์ม'}), 400
    
    farmer = User.query.get(task.farmer_id)
    farmer_name = farmer.display_name if farmer else 'Unknown'
    
    task.farmer_id = None
    task.status = 'assigned'  # เปลี่ยนกลับเป็น assigned เพื่อให้คนอื่นรับได้
    task.accepted_at = None
    task.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task_id, 
                   'unassign_task', 0, f'ถอด {farmer_name} ออกจากงาน')
    
    return jsonify({'success': True})

@app.route('/api/farmer/task/<int:task_id>/self-assign', methods=['POST'])
@login_required
@db_transaction
def api_farmer_self_assign(task_id):
    """คนฟาร์มกดรับงานเอง"""
    # ตรวจสอบว่าเป็น farmer หรือ admin
    if current_user.role not in ['farmer', 'admin']:
        return jsonify({'error': 'คุณไม่มีสิทธิ์เข้าถึงหน้านี้'}), 403
    
    task = Task.query.get_or_404(task_id)
    
    if task.farmer_id is not None:
        return jsonify({'error': 'งานนี้มีคนฟาร์มรับแล้ว'}), 400
    
    if task.status != 'assigned':
        return jsonify({'error': 'ไม่สามารถรับงานนี้ได้'}), 400
    
    # ตรวจสอบว่าคนฟาร์มมีงานที่กำลังทำอยู่หรือไม่ (จำกัดให้รับได้ทีละงาน)
    active_tasks = Task.query.filter_by(farmer_id=current_user.id).filter(
        Task.status.in_(['assigned', 'accepted', 'farming', 'paused', 'ready_to_deliver'])
    ).count()
    
    if active_tasks > 0:
        return jsonify({'error': 'คุณมีงานที่กำลังทำอยู่แล้ว กรุณาเสร็จงานก่อนรับงานใหม่'}), 400
    
    task.farmer_id = current_user.id
    task.status = 'accepted'
    task.accepted_at = datetime.utcnow()
    task.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, task.order_id, task_id, 
                   'self_assign', 0, f'{current_user.display_name} รับงานเอง')
    
    # ส่งแจ้งเตือน Discord เมื่อมีคนฟาร์มรับงาน
    order = Order.query.get(task.order_id)
    settings_data = Settings.get_settings()
    commission = settings_data.get('commission_percent', 10.0)
    
    # คำนวณเงินที่จะได้
    price_after = Settings.calculate_price(task.item_type, task.target_amount, order.discount_percent or 0)
    
    message = f"✅ **งานถูกรับแล้ว**\n\n"
    message += f"**Order Key:** {order.order_key}\n"
    message += f"**คนฟาร์ม:** {current_user.display_name}\n"
    message += f"**เซิร์ฟเวอร์:** {task.server_name or order.server_name or '-'}\n"
    message += f"**ประเภท:** {task.item_type.upper()}\n"
    message += f"**เป้าหมาย:** {task.target_amount:,}\n"
    message += f"**เงินที่จะได้:** {price_after:.2f} บาท (หลังหักค่าคนกลาง {commission}%)\n"
    if order.discount_percent and order.discount_percent > 0:
        message += f"*มีส่วนลด {order.discount_percent}% ให้ลูกค้า*"
    send_discord_notification(message)
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/admin/order/<int:order_id>/status', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_admin_update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json(force=True, silent=True) or {}
    
    new_status = data.get('status')
    if not new_status:
        return jsonify({'error': 'กรุณาระบุสถานะ'}), 400
    
    old_status = order.status
    order.status = new_status
    order.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, order_id, None, 
                   'change_status', 0, f'เปลี่ยนสถานะจาก {old_status} เป็น {new_status}')
    
    return jsonify({'success': True})

@app.route('/api/admin/admin', methods=['POST'])
@super_admin_required
@db_transaction
def api_admin_create_admin():
    """สร้างบัญชีแอดมินใหม่ (เฉพาะ super_admin)"""
    data = request.get_json(force=True, silent=True) or {}
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    display_name = data.get('display_name', '').strip()
    role = data.get('role', 'admin').strip()  # admin หรือ super_admin
    
    if not username or not password:
        return jsonify({'error': 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน'}), 400
    
    # Validate password
    is_valid, msg = validate_password(password)
    if not is_valid:
        return jsonify({'error': msg}), 400
    
    if role not in ['admin', 'super_admin']:
        return jsonify({'error': 'Role ไม่ถูกต้อง'}), 400
    
    # แอดมินธรรมดาไม่สามารถสร้าง super_admin ได้
    if role == 'super_admin' and current_user.role != 'super_admin':
        return jsonify({'error': 'คุณไม่มีสิทธิ์สร้างแอดมินหลัก'}), 403
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'ชื่อผู้ใช้นี้มีอยู่แล้ว'}), 400
    
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        display_name=display_name or username,
        active=True
    )
    
    db.session.add(user)
    db.session.flush()
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'create_admin', 0, f'สร้างบัญชีแอดมิน {username} (role: {role})')
    
    return jsonify({'success': True, 'user_id': user.id})

@app.route('/api/admin/admin/<int:admin_id>', methods=['GET'])
@super_admin_required
def api_admin_get_admin(admin_id):
    """ดึงข้อมูลแอดมิน"""
    admin = User.query.get_or_404(admin_id)
    
    if admin.role not in ['admin', 'super_admin']:
        return jsonify({'error': 'ไม่ใช่บัญชีแอดมิน'}), 400
    
    # แอดมินธรรมดาไม่สามารถดูข้อมูล super_admin ได้
    if admin.role == 'super_admin' and current_user.role != 'super_admin':
        return jsonify({'error': 'คุณไม่มีสิทธิ์ดูข้อมูลแอดมินหลัก'}), 403
    
    return jsonify({
        'success': True,
        'admin': {
            'id': admin.id,
            'username': admin.username,
            'display_name': admin.display_name,
            'role': admin.role,
            'active': admin.active,
            'created_at': admin.created_at.isoformat() if admin.created_at else None
        }
    })

@app.route('/api/admin/admin/<int:admin_id>', methods=['PATCH'])
@super_admin_required
@db_transaction
def api_admin_update_admin(admin_id):
    """แก้ไขข้อมูลแอดมิน"""
    admin = User.query.get_or_404(admin_id)
    
    if admin.role not in ['admin', 'super_admin']:
        return jsonify({'error': 'ไม่ใช่บัญชีแอดมิน'}), 400
    
    # แอดมินธรรมดาไม่สามารถแก้ไข super_admin ได้
    if admin.role == 'super_admin' and current_user.role != 'super_admin':
        return jsonify({'error': 'คุณไม่มีสิทธิ์แก้ไขแอดมินหลัก'}), 403
    
    # ไม่สามารถแก้ไขตัวเองได้ (ป้องกันการล็อกเอาต์)
    if admin.id == current_user.id:
        return jsonify({'error': 'ไม่สามารถแก้ไขบัญชีตัวเองได้'}), 400
    
    data = request.get_json(force=True, silent=True) or {}
    
    if 'display_name' in data:
        admin.display_name = data['display_name'].strip()
    
    if 'role' in data:
        new_role = data['role'].strip()
        if new_role not in ['admin', 'super_admin']:
            return jsonify({'error': 'Role ไม่ถูกต้อง'}), 400
        # แอดมินธรรมดาไม่สามารถเปลี่ยน role เป็น super_admin ได้
        if new_role == 'super_admin' and current_user.role != 'super_admin':
            return jsonify({'error': 'คุณไม่มีสิทธิ์เปลี่ยน role เป็น super_admin'}), 403
        admin.role = new_role
    
    if 'active' in data:
        admin.active = bool(data['active'])
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'update_admin', 0, f'แก้ไขข้อมูลแอดมิน {admin.username}')
    
    return jsonify({'success': True})

@app.route('/api/admin/admin/<int:admin_id>', methods=['DELETE'])
@super_admin_required
@csrf_protect
@rate_limit(max_requests=50, per_minutes=1)
@db_transaction
def api_admin_delete_admin(admin_id):
    """ลบบัญชีแอดมิน"""
    admin = User.query.get_or_404(admin_id)
    
    if admin.role not in ['admin', 'super_admin']:
        return jsonify({'error': 'ไม่ใช่บัญชีแอดมิน'}), 400
    
    # แอดมินธรรมดาไม่สามารถลบ super_admin ได้
    if admin.role == 'super_admin' and current_user.role != 'super_admin':
        return jsonify({'error': 'คุณไม่มีสิทธิ์ลบแอดมินหลัก'}), 403
    
    # ไม่สามารถลบตัวเองได้
    if admin.id == current_user.id:
        return jsonify({'error': 'ไม่สามารถลบบัญชีตัวเองได้'}), 400
    
    # ตรวจสอบว่ามี logs หรือ tasks ที่เกี่ยวข้องหรือไม่
    logs_count = Log.query.filter_by(actor_user_id=admin_id).count()
    
    username = admin.username
    admin_role = admin.role
    
    # ลบ logs ที่เกี่ยวข้อง
    Log.query.filter_by(actor_user_id=admin_id).delete()
    
    db.session.delete(admin)
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'delete_admin', 0, f'ลบบัญชีแอดมิน {username} (role: {admin_role})')
    
    return jsonify({'success': True})

@app.route('/api/admin/farmer', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=20, per_minutes=1)
@db_transaction
def api_admin_create_farmer():
    data = request.get_json(force=True, silent=True) or {}
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    display_name = data.get('display_name', '').strip()
    real_name = data.get('real_name', '').strip()
    bank_name = data.get('bank_name', '').strip()
    bank_account = data.get('bank_account', '').strip()
    user_title = data.get('user_title', '').strip()
    
    if not username or not password:
        return jsonify({'error': 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน'}), 400
    
    # Validate password
    is_valid, msg = validate_password(password)
    if not is_valid:
        return jsonify({'error': msg}), 400
    
    if not real_name or not bank_name or not bank_account:
        return jsonify({'error': 'กรุณากรอกชื่อจริง ชื่อธนาคาร และบัญชีธนาคาร'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'ชื่อผู้ใช้นี้มีอยู่แล้ว'}), 400
    
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='farmer',
        display_name=display_name or username,
        real_name=real_name,
        bank_name=bank_name,
        bank_account=bank_account,
        user_title=user_title or '',
        active=True
    )
    
    db.session.add(user)
    db.session.flush()
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'create_farmer', 0, f'สร้างบัญชีคนฟาร์ม {username} ({real_name})')
    
    return jsonify({'success': True, 'user_id': user.id})

@app.route('/api/admin/farmer/<int:farmer_id>', methods=['GET'])
@admin_required
def api_admin_get_farmer(farmer_id):
    """ดึงข้อมูลคนฟาร์ม"""
    farmer = User.query.get_or_404(farmer_id)
    
    if farmer.role != 'farmer':
        return jsonify({'error': 'ไม่ใช่บัญชีคนฟาร์ม'}), 400
    
    return jsonify({
        'success': True,
        'farmer': {
            'id': farmer.id,
            'username': farmer.username,
            'display_name': farmer.display_name,
            'real_name': farmer.real_name,
            'bank_name': farmer.bank_name,
            'bank_account': farmer.bank_account,
            'user_title': farmer.user_title,
            'active': farmer.active
        }
    })

@app.route('/api/admin/farmer/<int:farmer_id>', methods=['PATCH'])
@admin_required
@csrf_protect
@rate_limit(max_requests=20, per_minutes=1)
@db_transaction
def api_admin_update_farmer(farmer_id):
    """แก้ไขข้อมูลคนฟาร์ม"""
    farmer = User.query.get_or_404(farmer_id)
    
    if farmer.role != 'farmer':
        return jsonify({'error': 'ไม่ใช่บัญชีคนฟาร์ม'}), 400
    
    data = request.get_json(force=True, silent=True) or {}
    
    if 'display_name' in data:
        farmer.display_name = data['display_name'].strip()
    if 'real_name' in data:
        farmer.real_name = data['real_name'].strip()
    if 'bank_name' in data:
        farmer.bank_name = data['bank_name'].strip()
    if 'bank_account' in data:
        farmer.bank_account = data['bank_account'].strip()
    if 'user_title' in data:
        farmer.user_title = data['user_title'].strip()
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'update_farmer', 0, f'แก้ไขข้อมูลคนฟาร์ม {farmer.username}')
    
    return jsonify({'success': True})

@app.route('/api/admin/farmer/<int:farmer_id>/reset_password', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=10, per_minutes=1)
@db_transaction
def api_admin_reset_farmer_password(farmer_id):
    """เปลี่ยนรหัสผ่านคนฟาร์ม"""
    farmer = User.query.get_or_404(farmer_id)
    
    if farmer.role != 'farmer':
        return jsonify({'error': 'ไม่ใช่บัญชีคนฟาร์ม'}), 400
    
    data = request.get_json(force=True, silent=True) or {}
    new_password = data.get('password', '').strip()
    
    # Validate password
    is_valid, msg = validate_password(new_password)
    if not is_valid:
        return jsonify({'error': msg}), 400
    
    farmer.password_hash = generate_password_hash(new_password)
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'reset_password', 0, f'เปลี่ยนรหัสผ่านคนฟาร์ม {farmer.username}')
    
    return jsonify({'success': True})

@app.route('/api/admin/farmer/<int:farmer_id>/toggle', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=20, per_minutes=1)
@db_transaction
def api_admin_toggle_farmer(farmer_id):
    farmer = User.query.get_or_404(farmer_id)
    
    if farmer.role != 'farmer':
        return jsonify({'error': 'ไม่ใช่บัญชีคนฟาร์ม'}), 400
    
    farmer.active = not farmer.active
    
    status_text = 'เปิดใช้งาน' if farmer.active else 'ปิดใช้งาน'
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'toggle_farmer', 0, f'{status_text}บัญชี {farmer.username}')
    
    return jsonify({'success': True, 'active': farmer.active})

@app.route('/api/admin/farmer/<int:farmer_id>', methods=['DELETE'])
@admin_required
@csrf_protect
@rate_limit(max_requests=50, per_minutes=1)
@db_transaction
def api_admin_delete_farmer(farmer_id):
    """ลบบัญชีคนฟาร์ม"""
    farmer = User.query.get_or_404(farmer_id)
    
    if farmer.role != 'farmer':
        return jsonify({'error': 'ไม่ใช่บัญชีคนฟาร์ม'}), 400
    
    # ตรวจสอบว่ามีงานที่กำลังทำอยู่หรือไม่
    active_tasks = Task.query.filter_by(farmer_id=farmer_id).filter(
        Task.status.in_(['assigned', 'accepted', 'farming', 'paused', 'ready_to_deliver'])
    ).count()
    
    if active_tasks > 0:
        return jsonify({'error': f'ไม่สามารถลบได้ เนื่องจากมีงานที่กำลังทำอยู่ {active_tasks} งาน'}), 400
    
    # ลบ tasks ที่เกี่ยวข้อง
    tasks = Task.query.filter_by(farmer_id=farmer_id).all()
    for task in tasks:
        # ลบ logs ที่เกี่ยวข้องกับ task
        logs_to_delete = Log.query.filter_by(task_id=task.id).all()
        for log in logs_to_delete:
            db.session.delete(log)
        db.session.delete(task)
    
    # ลบ logs ที่เกี่ยวข้องกับ farmer
    farmer_logs = Log.query.filter_by(actor_user_id=farmer_id).all()
    for log in farmer_logs:
        db.session.delete(log)
    
    # ลบ user
    username = farmer.username
    db.session.delete(farmer)
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'delete_farmer', 0, f'ลบบัญชีคนฟาร์ม {username}')
    
    return jsonify({'success': True, 'message': f'ลบบัญชี {username} สำเร็จ'})

@app.route('/api/admin/user/<int:user_id>/role', methods=['PATCH'])
@super_admin_required
@db_transaction
def api_admin_update_user_role(user_id):
    """เปลี่ยน role ของ user (ขึ้นยศคนฟาร์มเป็นแอดมิน)"""
    user = User.query.get_or_404(user_id)
    data = request.get_json(force=True, silent=True) or {}
    
    new_role = data.get('role', '').strip()
    if new_role not in ['farmer', 'admin', 'super_admin']:
        return jsonify({'error': 'Role ไม่ถูกต้อง'}), 400
    
    # ไม่สามารถเปลี่ยน role ของตัวเองได้
    if user.id == current_user.id:
        return jsonify({'error': 'ไม่สามารถเปลี่ยน role ของตัวเองได้'}), 400
    
    old_role = user.role
    user.role = new_role
    
    role_names = {
        'farmer': 'คนฟาร์ม',
        'admin': 'แอดมิน',
        'super_admin': 'แอดมินหลัก'
    }
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'change_user_role', 0, 
                   f'เปลี่ยน role ของ {user.username} จาก {role_names.get(old_role, old_role)} เป็น {role_names.get(new_role, new_role)}')
    
    return jsonify({
        'success': True, 
        'role': new_role,
        'role_display': role_names.get(new_role, new_role)
    })

@app.route('/api/admin/order/<int:order_id>', methods=['DELETE'])
@admin_required
@csrf_protect
@rate_limit(max_requests=20, per_minutes=1)
@db_transaction
def api_admin_delete_order(order_id):
    """ลบออเดอร์ - admin สามารถลบได้แม้มีงานกำลังทำอยู่"""
    order = Order.query.get_or_404(order_id)
    order_key = order.order_key
    
    # ลบ order_items ที่เกี่ยวข้อง
    order_items = OrderItem.query.filter_by(order_id=order_id).all()
    for item in order_items:
        db.session.delete(item)
    
    # ลบ tasks ที่เกี่ยวข้อง
    tasks = Task.query.filter_by(order_id=order_id).all()
    for task in tasks:
        # ลบ logs ที่เกี่ยวข้องกับ task
        task_logs = Log.query.filter_by(task_id=task.id).all()
        for log in task_logs:
            db.session.delete(log)
        db.session.delete(task)
    
    # ลบ logs ที่เกี่ยวข้องกับ order
    order_logs = Log.query.filter_by(order_id=order_id).all()
    for log in order_logs:
        db.session.delete(log)
    
    # ลบ order
    db.session.delete(order)
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'delete_order', 0, f'ลบออเดอร์ {order_key}')
    
    return jsonify({'success': True, 'message': f'ลบออเดอร์ {order_key} สำเร็จ'})

# ==================== EXPORT & REPORTS ====================

@app.route('/api/admin/export/orders', methods=['GET'])
@admin_required
def api_admin_export_orders():
    """Export ออเดอร์ทั้งหมดเป็น CSV"""
    # Get filter parameters
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '')
    item_type_filter = request.args.get('item_type', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = Order.query
    
    if search:
        query = query.filter(
            (Order.order_key.contains(search.upper())) |
            (Order.customer_ref.contains(search)) |
            (Order.server_name.contains(search))
        )
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    if item_type_filter:
        query = query.filter_by(item_type=item_type_filter)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Order.created_at >= date_from_obj)
        except:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Order.created_at < date_to_obj)
        except:
            pass
    
    orders = query.order_by(Order.created_at.desc()).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        'Order Key', 'ลูกค้า', 'เซิร์ฟเวอร์', 'ประเภท', 'เป้าหมาย', 
        'สถานะ', 'ส่วนลด (%)', 'สร้างเมื่อ', 'อัพเดตล่าสุด'
    ])
    
    # Data
    for order in orders:
        writer.writerow([
            order.order_key,
            order.customer_ref or '',
            order.server_name or '',
            order.item_type.upper(),
            order.target_amount,
            get_status_th(order.status),
            order.discount_percent or 0,
            order.created_at.strftime('%Y-%m-%d %H:%M:%S') if order.created_at else '',
            order.updated_at.strftime('%Y-%m-%d %H:%M:%S') if order.updated_at else ''
        ])
    
    # Create response
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=orders_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

@app.route('/api/admin/export/payments', methods=['GET'])
@admin_required
def api_admin_export_payments():
    """Export รายงานการจ่ายเงินให้คนฟาร์ม"""
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = Task.query.join(Order).filter(Task.status == 'delivered')
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Task.updated_at >= date_from_obj)
        except:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Task.updated_at < date_to_obj)
        except:
            pass
    
    tasks = query.order_by(Task.updated_at.desc()).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        'Order Key', 'คนฟาร์ม', 'ประเภท', 'จำนวน', 'ราคาก่อนหัก', 
        'ส่วนลด (%)', 'ค่าคนกลาง (%)', 'เงินที่ได้รับ', 'ส่งเมื่อ'
    ])
    
    settings = Settings.get_settings()
    commission = settings.get('commission_percent', 10.0)
    
    # Data
    for task in tasks:
        order = task.order
        farmer = task.farmer
        price_before = Settings.calculate_price_before_commission(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        price_after = Settings.calculate_price(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        
        writer.writerow([
            order.order_key,
            farmer.display_name if farmer else '-',
            task.item_type.upper(),
            task.current_amount,
            f'{price_before:.2f}',
            order.discount_percent or 0,
            commission,
            f'{price_after:.2f}',
            task.updated_at.strftime('%Y-%m-%d %H:%M:%S') if task.updated_at else ''
        ])
    
    # Create response
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=payments_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

@app.route('/api/admin/export/payments/pdf', methods=['GET'])
@admin_required
def api_admin_export_payments_pdf():
    """Export รายงานการจ่ายเงินเป็น PDF"""
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = Task.query.join(Order).filter(Task.status == 'delivered')
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Task.updated_at >= date_from_obj)
        except:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Task.updated_at < date_to_obj)
        except:
            pass
    
    tasks = query.order_by(Task.updated_at.desc()).all()
    
    # Create PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph("รายงานการจ่ายเงินให้คนฟาร์ม", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 0.2*inch))
    
    # Date range
    if date_from or date_to:
        date_text = f"ช่วงวันที่: {date_from or 'เริ่มต้น'} ถึง {date_to or 'ปัจจุบัน'}"
        elements.append(Paragraph(date_text, styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
    
    # Table data
    settings = Settings.get_settings()
    commission = settings.get('commission_percent', 10.0)
    
    data = [['Order Key', 'คนฟาร์ม', 'ประเภท', 'จำนวน', 'ราคาก่อนหัก', 
             'ส่วนลด (%)', 'ค่าคนกลาง (%)', 'เงินที่ได้รับ', 'ส่งเมื่อ']]
    
    for task in tasks:
        order = task.order
        farmer = task.farmer
        price_before = Settings.calculate_price_before_commission(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        price_after = Settings.calculate_price(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        
        data.append([
            order.order_key,
            farmer.display_name if farmer else '-',
            task.item_type.upper(),
            f'{task.current_amount:,}',
            f'{price_before:.2f}',
            f'{order.discount_percent or 0}',
            f'{commission}',
            f'{price_after:.2f}',
            task.updated_at.strftime('%d/%m/%Y %H:%M') if task.updated_at else ''
        ])
    
    # Create table
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
    ]))
    
    elements.append(table)
    
    # Summary
    total_revenue = sum(Settings.calculate_price_before_commission(
        t.item_type, t.current_amount, t.order.discount_percent or 0
    ) for t in tasks)
    total_paid = sum(Settings.calculate_price(
        t.item_type, t.current_amount, t.order.discount_percent or 0
    ) for t in tasks)
    
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph(f"<b>สรุป:</b> รายได้รวม {total_revenue:.2f} บาท, จ่ายให้คนฟาร์ม {total_paid:.2f} บาท, ค่าคนกลาง {total_revenue - total_paid:.2f} บาท", styles['Normal']))
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=payments_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    
    return response

@app.route('/api/admin/export/farmers', methods=['GET'])
@admin_required
def api_admin_export_farmers():
    """Export ข้อมูลคนฟาร์ม"""
    farmers = User.query.filter_by(role='farmer').all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        'ID', 'ชื่อผู้ใช้', 'ชื่อแสดง', 'ชื่อจริง', 'ยศ', 
        'ธนาคาร', 'บัญชี', 'สถานะ', 'สร้างเมื่อ'
    ])
    
    # Data
    for farmer in farmers:
        writer.writerow([
            farmer.id,
            farmer.username,
            farmer.display_name or '',
            farmer.real_name or '',
            farmer.user_title or '',
            farmer.bank_name or '',
            farmer.bank_account or '',
            'ใช้งาน' if farmer.active else 'ปิดใช้งาน',
            farmer.created_at.strftime('%Y-%m-%d %H:%M:%S') if farmer.created_at else ''
        ])
    
    # Create response
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=farmers_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return response

# ==================== BULK OPERATIONS ====================

@app.route('/api/admin/orders/bulk-delete', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=5, per_minutes=1)
@db_transaction
def api_admin_bulk_delete_orders():
    """ลบหลายออเดอร์พร้อมกัน"""
    data = request.get_json(force=True, silent=True) or {}
    order_ids = data.get('order_ids', [])
    
    if not order_ids or not isinstance(order_ids, list):
        return jsonify({'error': 'กรุณาระบุออเดอร์ที่ต้องการลบ'}), 400
    
    deleted_count = 0
    errors = []
    
    for order_id in order_ids:
        try:
            order = Order.query.get(order_id)
            if not order:
                errors.append(f'ไม่พบออเดอร์ ID: {order_id}')
                continue
            
            order_key = order.order_key
            
            # ลบ order_items ที่เกี่ยวข้อง
            order_items = OrderItem.query.filter_by(order_id=order_id).all()
            for item in order_items:
                db.session.delete(item)
            
            # ลบ tasks ที่เกี่ยวข้อง
            tasks = Task.query.filter_by(order_id=order_id).all()
            for task in tasks:
                task_logs = Log.query.filter_by(task_id=task.id).all()
                for log in task_logs:
                    db.session.delete(log)
                db.session.delete(task)
            
            # ลบ logs ที่เกี่ยวข้องกับ order
            order_logs = Log.query.filter_by(order_id=order_id).all()
            for log in order_logs:
                db.session.delete(log)
            
            # ลบ order
            db.session.delete(order)
            deleted_count += 1
            
        except Exception as e:
            errors.append(f'เกิดข้อผิดพลาดในการลบออเดอร์ ID: {order_id} - {str(e)}')
    
    if deleted_count > 0:
        Log.create_log(current_user.id, current_user.role, None, None, 
                      'bulk_delete_orders', 0, f'ลบออเดอร์ {deleted_count} รายการ')
    
    return jsonify({
        'success': True,
        'deleted_count': deleted_count,
        'errors': errors,
        'message': f'ลบสำเร็จ {deleted_count} ออเดอร์' + (f' ({len(errors)} ข้อผิดพลาด)' if errors else '')
    })

@app.route('/api/admin/orders/bulk-status', methods=['POST'])
@admin_required
@db_transaction
def api_admin_bulk_update_status():
    """เปลี่ยนสถานะหลายออเดอร์พร้อมกัน"""
    data = request.get_json(force=True, silent=True) or {}
    order_ids = data.get('order_ids', [])
    new_status = data.get('status', '').strip()
    
    if not order_ids or not isinstance(order_ids, list):
        return jsonify({'error': 'กรุณาระบุออเดอร์'}), 400
    
    if not new_status:
        return jsonify({'error': 'กรุณาระบุสถานะใหม่'}), 400
    
    updated_count = 0
    
    for order_id in order_ids:
        order = Order.query.get(order_id)
        if order:
            old_status = order.status
            order.status = new_status
            order.updated_at = datetime.utcnow()
            updated_count += 1
            
            Log.create_log(current_user.id, current_user.role, order_id, None, 
                          'change_status', 0, f'เปลี่ยนสถานะจาก {old_status} เป็น {new_status}')
    
    return jsonify({
        'success': True,
        'updated_count': updated_count,
        'message': f'อัพเดตสถานะ {updated_count} ออเดอร์'
    })

# ==================== STATISTICS & REPORTS ====================

@app.route('/admin/templates')
@admin_required
def admin_templates():
    """หน้าเทมเพลตออเดอร์"""
    templates = OrderTemplate.query.order_by(OrderTemplate.updated_at.desc()).all()
    return render_template('admin/templates.html', templates=templates)

@app.route('/admin/reports')
@admin_required
def admin_reports():
    """หน้ารายงานและสถิติ"""
    return render_template('admin/reports.html')

@app.route('/api/admin/reports/summary', methods=['GET'])
@admin_required
def api_admin_reports_summary():
    """API สำหรับดึงสถิติสรุป"""
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = Task.query.join(Order).filter(Task.status == 'delivered')
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Task.updated_at >= date_from_obj)
        except:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Task.updated_at < date_to_obj)
        except:
            pass
    
    tasks = query.all()
    
    # สรุปข้อมูล
    total_tasks = len(tasks)
    total_amount = sum(t.current_amount for t in tasks)
    total_revenue = 0.0
    total_paid = 0.0
    
    for task in tasks:
        order = task.order
        farmer_earning = Settings.calculate_price(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        customer_price = Settings.calculate_price_before_commission(
            task.item_type, task.current_amount, order.discount_percent or 0
        )
        total_revenue += customer_price
        total_paid += farmer_earning
    
    # สถิติตามคนฟาร์ม
    farmer_stats = defaultdict(lambda: {'tasks': 0, 'amount': 0, 'revenue': 0.0, 'paid': 0.0})
    
    for task in tasks:
        order = task.order
        farmer = task.farmer
        if farmer:
            farmer_earning = Settings.calculate_price(
                task.item_type, task.current_amount, order.discount_percent or 0
            )
            customer_price = Settings.calculate_price_before_commission(
                task.item_type, task.current_amount, order.discount_percent or 0
            )
            farmer_stats[farmer.id]['tasks'] += 1
            farmer_stats[farmer.id]['amount'] += task.current_amount
            farmer_stats[farmer.id]['revenue'] += customer_price
            farmer_stats[farmer.id]['paid'] += farmer_earning
    
    # แปลงเป็น dict พร้อมชื่อ
    farmer_stats_list = []
    for farmer_id, stats in farmer_stats.items():
        farmer = User.query.get(farmer_id)
        if farmer:
            farmer_stats_list.append({
                'farmer_id': farmer_id,
                'farmer_name': farmer.display_name or farmer.username,
                'tasks': stats['tasks'],
                'amount': stats['amount'],
                'revenue': round(stats['revenue'], 2),
                'paid': round(stats['paid'], 2)
            })
    
    return jsonify({
        'success': True,
        'summary': {
            'total_tasks': total_tasks,
            'total_amount': total_amount,
            'total_revenue': round(total_revenue, 2),
            'total_paid': round(total_paid, 2),
            'total_commission': round(total_revenue - total_paid, 2)
        },
        'farmer_stats': farmer_stats_list
    })

# ==================== ADVANCED FEATURES ====================

@app.route('/api/admin/order/<int:order_id>/duplicate', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=20, per_minutes=1)
@db_transaction
def api_admin_duplicate_order(order_id):
    """คัดลอกออเดอร์"""
    original_order = Order.query.get_or_404(order_id)
    
    # Load order_items
    from sqlalchemy.orm import joinedload
    order_with_items = db.session.query(Order).options(joinedload(Order.order_items)).filter_by(id=order_id).first()
    original_items = order_with_items.order_items if order_with_items else []
    
    # ใช้ item แรกเป็นค่า default สำหรับ backward compatibility
    first_item = original_items[0] if original_items else None
    item_type = first_item.item_type if first_item else original_order.item_type
    target_amount = first_item.target_amount if first_item else original_order.target_amount
    
    # สร้างออเดอร์ใหม่
    new_order_key = generate_order_key()
    new_order = Order(
        order_key=new_order_key,
        customer_ref=original_order.customer_ref,
        server_name=original_order.server_name,
        item_type=item_type,
        target_amount=target_amount,
        priority=original_order.priority,
        discount_percent=original_order.discount_percent,
        note_admin=original_order.note_admin
    )
    
    db.session.add(new_order)
    db.session.flush()
    
    # คัดลอก order_items
    for item in original_items:
        new_item = OrderItem(
            order_id=new_order.id,
            item_type=item.item_type,
            target_amount=item.target_amount
        )
        db.session.add(new_item)
    
    Log.create_log(current_user.id, current_user.role, new_order.id, None, 
                   'duplicate_order', 0, f'คัดลอกจากออเดอร์ {original_order.order_key}')
    
    return jsonify({
        'success': True,
        'order_id': new_order.id,
        'order_key': new_order_key,
        'message': f'คัดลอกออเดอร์สำเร็จ: {new_order_key}'
    })

@app.route('/api/admin/order/<int:order_id>', methods=['PATCH'])
@admin_required
@csrf_protect
@rate_limit(max_requests=30, per_minutes=1)
@db_transaction
def api_admin_update_order(order_id):
    """แก้ไขข้อมูลออเดอร์"""
    order = Order.query.get_or_404(order_id)
    data = request.get_json(force=True, silent=True) or {}
    
    # ตรวจสอบว่าออเดอร์ยังไม่เสร็จ (เพื่อป้องกันการแก้ไขออเดอร์ที่เสร็จแล้ว)
    if order.status == 'done':
        return jsonify({'error': 'ไม่สามารถแก้ไขออเดอร์ที่เสร็จแล้วได้'}), 400
    
    # อัพเดตข้อมูล
    if 'customer_ref' in data:
        order.customer_ref = data['customer_ref'].strip() if data['customer_ref'] else None
    if 'server_name' in data:
        order.server_name = data['server_name'].strip() if data['server_name'] else None
    if 'item_type' in data:
        if data['item_type'] not in ['wood', 'stone', 'sulfur', 'metal', 'scrap', 'hqm']:
            return jsonify({'error': 'ประเภทไม่ถูกต้อง'}), 400
        order.item_type = data['item_type']
    if 'target_amount' in data:
        try:
            target_amount = int(data['target_amount'])
            if target_amount <= 0:
                return jsonify({'error': 'เป้าหมายต้องมากกว่า 0'}), 400
            order.target_amount = target_amount
        except (ValueError, TypeError):
            return jsonify({'error': 'เป้าหมายไม่ถูกต้อง'}), 400
    if 'discount_percent' in data:
        try:
            discount = float(data['discount_percent'])
            if discount < 0 or discount > 100:
                return jsonify({'error': 'ส่วนลดต้องอยู่ระหว่าง 0-100'}), 400
            order.discount_percent = discount
        except (ValueError, TypeError):
            return jsonify({'error': 'ส่วนลดไม่ถูกต้อง'}), 400
    if 'priority' in data:
        if data['priority'] not in ['normal', 'express']:
            return jsonify({'error': 'Priority ไม่ถูกต้อง'}), 400
        order.priority = data['priority']
    
    order.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, order_id, None, 
                   'update_order', 0, f'แก้ไขข้อมูลออเดอร์ {order.order_key}')
    
    return jsonify({'success': True, 'order': {
        'id': order.id,
        'order_key': order.order_key,
        'customer_ref': order.customer_ref,
        'server_name': order.server_name,
        'item_type': order.item_type,
        'target_amount': order.target_amount,
        'discount_percent': order.discount_percent,
        'priority': order.priority
    }})

@app.route('/api/admin/order/<int:order_id>/note', methods=['POST'])
@admin_required
@db_transaction
def api_admin_update_order_note(order_id):
    """อัพเดตหมายเหตุออเดอร์"""
    order = Order.query.get_or_404(order_id)
    data = request.get_json(force=True, silent=True) or {}
    
    note = data.get('note', '').strip()
    order.note_admin = note
    order.updated_at = datetime.utcnow()
    
    Log.create_log(current_user.id, current_user.role, order_id, None, 
                   'update_note', 0, f'อัพเดตหมายเหตุออเดอร์ {order.order_key}')
    
    return jsonify({'success': True})

# ==================== BACKUP & RESTORE ====================

@app.route('/api/qrcode/<order_key>')
def api_generate_qrcode(order_key):
    """สร้าง QR Code สำหรับลิงก์ติดตามออเดอร์"""
    order = Order.query.filter_by(order_key=order_key.upper()).first()
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    track_url = url_for('track_order_key', order_key=order_key, _external=True)

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(track_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to a BytesIO object
    byte_io = io.BytesIO()
    img.save(byte_io, 'PNG')
    byte_io.seek(0)

    return send_file(byte_io, mimetype='image/png')

@app.route('/api/admin/backup', methods=['GET'])
@admin_required
def api_admin_backup():
    """สำรองข้อมูลทั้งหมดเป็น JSON"""
    import json
    
    # ดึงข้อมูลทั้งหมด
    orders = Order.query.all()
    tasks = Task.query.all()
    users = User.query.all()
    logs = Log.query.order_by(Log.created_at.desc()).limit(10000).all()  # จำกัด logs
    
    # แปลงเป็น dict
    backup_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0',
        'orders': [{
            'id': o.id,
            'order_key': o.order_key,
            'customer_ref': o.customer_ref,
            'server_name': o.server_name,
            'item_type': o.item_type,
            'target_amount': o.target_amount,
            'status': o.status,
            'priority': o.priority,
            'discount_percent': o.discount_percent,
            'note_admin': o.note_admin,
            'created_at': o.created_at.isoformat() if o.created_at else None,
            'updated_at': o.updated_at.isoformat() if o.updated_at else None
        } for o in orders],
        'tasks': [{
            'id': t.id,
            'order_id': t.order_id,
            'farmer_id': t.farmer_id,
            'item_type': t.item_type,
            'target_amount': t.target_amount,
            'current_amount': t.current_amount,
            'status': t.status,
            'server_name': t.server_name,
            'planned_start': t.planned_start.isoformat() if t.planned_start else None,
            'planned_duration_hours': t.planned_duration_hours,
            'created_at': t.created_at.isoformat() if t.created_at else None,
            'accepted_at': t.accepted_at.isoformat() if t.accepted_at else None,
            'updated_at': t.updated_at.isoformat() if t.updated_at else None,
            'task_items': [{
                'item_type': item.item_type,
                'target_amount': item.target_amount,
                'current_amount': item.current_amount
            } for item in t.task_items]
        } for t in tasks],
        'users': [{
            'id': u.id,
            'username': u.username,
            'display_name': u.display_name,
            'role': u.role,
            'active': u.active,
            'real_name': u.real_name,
            'bank_name': u.bank_name,
            'bank_account': u.bank_account,
            'user_title': u.user_title,
            'created_at': u.created_at.isoformat() if u.created_at else None
        } for u in users if u.role != 'admin'],  # ไม่ backup admin accounts
        'logs': [{
            'id': l.id,
            'actor_user_id': l.actor_user_id,
            'actor_role': l.actor_role,
            'order_id': l.order_id,
            'task_id': l.task_id,
            'action': l.action,
            'delta': l.delta_amount,
            'message': l.message,
            'created_at': l.created_at.isoformat() if l.created_at else None
        } for l in logs]
    }
    
    # สร้าง JSON response
    output = io.StringIO()
    json.dump(backup_data, output, indent=2, ensure_ascii=False)
    output.seek(0)
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'backup', 0, 'สำรองข้อมูล')
    
    return response

@app.route('/api/admin/restore', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=2, per_minutes=1)
@db_transaction
def api_admin_restore():
    """กู้คืนข้อมูลจากไฟล์ JSON backup"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'ไม่พบไฟล์'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'กรุณาเลือกไฟล์'}), 400
        
        if not file.filename.endswith('.json'):
            return jsonify({'error': 'ไฟล์ต้องเป็น JSON'}), 400
        
        # อ่านไฟล์
        content = file.read().decode('utf-8')
        backup_data = json.loads(content)
        
        # ตรวจสอบ version
        if backup_data.get('version') != '1.0':
            return jsonify({'error': 'เวอร์ชันไฟล์ไม่รองรับ'}), 400
        
        # ยืนยันการ restore
        confirm = request.form.get('confirm', '').lower() == 'true'
        if not confirm:
            return jsonify({'error': 'ต้องยืนยันการ restore'}), 400
        
        # เริ่ม restore
        restored_count = {
            'orders': 0,
            'tasks': 0,
            'users': 0,
            'logs': 0
        }
        
        # Restore Users (แต่ไม่ restore admin)
        user_id_map = {}  # เก็บ mapping ของ user id เก่า -> ใหม่
        for user_data in backup_data.get('users', []):
            if user_data.get('role') in ['admin', 'super_admin']:
                continue  # ข้าม admin accounts
            
            # ตรวจสอบว่ามี username อยู่แล้วหรือไม่
            existing_user = User.query.filter_by(username=user_data['username']).first()
            if existing_user:
                # อัพเดตข้อมูลที่มีอยู่ (เขียนทับ)
                existing_user.display_name = user_data.get('display_name')
                existing_user.real_name = user_data.get('real_name')
                existing_user.bank_name = user_data.get('bank_name')
                existing_user.bank_account = user_data.get('bank_account')
                existing_user.user_title = user_data.get('user_title')
                existing_user.active = user_data.get('active', True)
                # ไม่เปลี่ยน password และ role
                user_id_map[user_data['id']] = existing_user.id
                restored_count['users'] += 1
            else:
                # สร้าง user ใหม่ (ไม่มี password - ต้อง reset)
                new_user = User(
                    username=user_data['username'],
                    password_hash=generate_password_hash('temp123456'),  # รหัสชั่วคราว
                    role=user_data.get('role', 'farmer'),
                    display_name=user_data.get('display_name'),
                    real_name=user_data.get('real_name'),
                    bank_name=user_data.get('bank_name'),
                    bank_account=user_data.get('bank_account'),
                    user_title=user_data.get('user_title'),
                    active=user_data.get('active', True)
                )
                db.session.add(new_user)
                db.session.flush()  # เพื่อให้ได้ id
                user_id_map[user_data['id']] = new_user.id
                restored_count['users'] += 1
        
        # Restore Orders
        order_id_map = {}  # เก็บ mapping ของ order id เก่า -> ใหม่
        for order_data in backup_data.get('orders', []):
            # ตรวจสอบว่ามี order_key อยู่แล้วหรือไม่
            existing_order = Order.query.filter_by(order_key=order_data['order_key']).first()
            if existing_order:
                # อัพเดตข้อมูลที่มีอยู่ (เขียนทับ)
                existing_order.customer_ref = order_data.get('customer_ref')
                existing_order.server_name = order_data.get('server_name')
                existing_order.item_type = order_data.get('item_type')
                existing_order.target_amount = order_data.get('target_amount', 0)
                existing_order.status = order_data.get('status', 'queued')
                existing_order.priority = order_data.get('priority', 'normal')
                existing_order.discount_percent = order_data.get('discount_percent', 0.0)
                existing_order.note_admin = order_data.get('note_admin')
                if order_data.get('updated_at'):
                    try:
                        existing_order.updated_at = datetime.fromisoformat(order_data['updated_at'].replace('Z', '+00:00'))
                    except:
                        pass
                # ลบ order_items เก่าและสร้างใหม่ (ถ้ามีใน backup)
                OrderItem.query.filter_by(order_id=existing_order.id).delete()
                if 'order_items' in order_data:
                    for item_data in order_data['order_items']:
                        order_item = OrderItem(
                            order_id=existing_order.id,
                            item_type=item_data.get('item_type'),
                            target_amount=item_data.get('target_amount', 0)
                        )
                        db.session.add(order_item)
                order_id_map[order_data['id']] = existing_order.id
                restored_count['orders'] += 1
            else:
                new_order = Order(
                    order_key=order_data['order_key'],
                    customer_ref=order_data.get('customer_ref'),
                    server_name=order_data.get('server_name'),
                    item_type=order_data.get('item_type'),
                    target_amount=order_data.get('target_amount', 0),
                    status=order_data.get('status', 'queued'),
                    priority=order_data.get('priority', 'normal'),
                    discount_percent=order_data.get('discount_percent', 0.0),
                    note_admin=order_data.get('note_admin')
                )
                if order_data.get('created_at'):
                    try:
                        new_order.created_at = datetime.fromisoformat(order_data['created_at'].replace('Z', '+00:00'))
                    except:
                        pass
                if order_data.get('updated_at'):
                    try:
                        new_order.updated_at = datetime.fromisoformat(order_data['updated_at'].replace('Z', '+00:00'))
                    except:
                        pass
                
                db.session.add(new_order)
                db.session.flush()
                order_id_map[order_data['id']] = new_order.id
                restored_count['orders'] += 1
                
                # Restore OrderItems (ถ้ามีใน backup)
                if 'order_items' in order_data:
                    for item_data in order_data['order_items']:
                        order_item = OrderItem(
                            order_id=new_order.id,
                            item_type=item_data.get('item_type'),
                            target_amount=item_data.get('target_amount', 0)
                        )
                        db.session.add(order_item)
        
        # Restore Tasks
        task_id_map = {}  # เก็บ mapping ของ task id เก่า -> ใหม่
        for task_data in backup_data.get('tasks', []):
            # ใช้ order_id_map และ user_id_map
            new_order_id = order_id_map.get(task_data.get('order_id'))
            if not new_order_id:
                continue  # ข้ามถ้าไม่มี order
            
            new_farmer_id = user_id_map.get(task_data.get('farmer_id')) if task_data.get('farmer_id') else None
            
            # ตรวจสอบว่ามี task อยู่แล้วหรือไม่ (ใช้ order_id + item_type + target_amount เป็น key)
            existing_task = None
            if task_data.get('item_type') and task_data.get('target_amount'):
                existing_task = Task.query.filter_by(
                    order_id=new_order_id,
                    item_type=task_data.get('item_type'),
                    target_amount=task_data.get('target_amount', 0)
                ).first()
            
            if existing_task:
                # อัพเดตข้อมูลที่มีอยู่ (เขียนทับ)
                existing_task.farmer_id = new_farmer_id
                existing_task.current_amount = task_data.get('current_amount', 0)
                existing_task.status = task_data.get('status', 'accepted')
                existing_task.server_name = task_data.get('server_name')
                if task_data.get('planned_start'):
                    try:
                        existing_task.planned_start = datetime.fromisoformat(task_data['planned_start'].replace('Z', '+00:00'))
                    except:
                        pass
                if task_data.get('planned_duration_hours'):
                    existing_task.planned_duration_hours = task_data.get('planned_duration_hours')
                if task_data.get('accepted_at'):
                    try:
                        existing_task.accepted_at = datetime.fromisoformat(task_data['accepted_at'].replace('Z', '+00:00'))
                    except:
                        pass
                if task_data.get('updated_at'):
                    try:
                        existing_task.updated_at = datetime.fromisoformat(task_data['updated_at'].replace('Z', '+00:00'))
                    except:
                        pass
                # ลบ task_items เก่าและสร้างใหม่ (ถ้ามีใน backup)
                TaskItem.query.filter_by(task_id=existing_task.id).delete()
                if 'task_items' in task_data:
                    for item_data in task_data['task_items']:
                        task_item = TaskItem(
                            task_id=existing_task.id,
                            item_type=item_data.get('item_type'),
                            target_amount=item_data.get('target_amount', 0),
                            current_amount=item_data.get('current_amount', 0)
                        )
                        db.session.add(task_item)
                task_id_map[task_data['id']] = existing_task.id
                restored_count['tasks'] += 1
            else:
                new_task = Task(
                    order_id=new_order_id,
                    farmer_id=new_farmer_id,
                    item_type=task_data.get('item_type'),
                    target_amount=task_data.get('target_amount', 0),
                    current_amount=task_data.get('current_amount', 0),
                    status=task_data.get('status', 'accepted'),
                    server_name=task_data.get('server_name')
                )
                if task_data.get('planned_start'):
                    try:
                        new_task.planned_start = datetime.fromisoformat(task_data['planned_start'].replace('Z', '+00:00'))
                    except:
                        pass
                if task_data.get('planned_duration_hours'):
                    new_task.planned_duration_hours = task_data.get('planned_duration_hours')
                if task_data.get('created_at'):
                    try:
                        new_task.created_at = datetime.fromisoformat(task_data['created_at'].replace('Z', '+00:00'))
                    except:
                        pass
                if task_data.get('accepted_at'):
                    try:
                        new_task.accepted_at = datetime.fromisoformat(task_data['accepted_at'].replace('Z', '+00:00'))
                    except:
                        pass
                if task_data.get('updated_at'):
                    try:
                        new_task.updated_at = datetime.fromisoformat(task_data['updated_at'].replace('Z', '+00:00'))
                    except:
                        pass
                
                db.session.add(new_task)
                db.session.flush()
                task_id_map[task_data['id']] = new_task.id
                restored_count['tasks'] += 1
                
                # Restore TaskItems (ถ้ามีใน backup)
                if 'task_items' in task_data:
                    for item_data in task_data['task_items']:
                        task_item = TaskItem(
                            task_id=new_task.id,
                            item_type=item_data.get('item_type'),
                            target_amount=item_data.get('target_amount', 0),
                            current_amount=item_data.get('current_amount', 0)
                        )
                        db.session.add(task_item)
        
        # Restore Logs (จำกัดจำนวน)
        for log_data in backup_data.get('logs', [])[:5000]:  # จำกัด 5000 logs
            new_actor_id = user_id_map.get(log_data.get('actor_user_id')) if log_data.get('actor_user_id') else None
            new_order_id = order_id_map.get(log_data.get('order_id')) if log_data.get('order_id') else None
            new_task_id = task_id_map.get(log_data.get('task_id')) if log_data.get('task_id') else None
            
            new_log = Log(
                actor_user_id=new_actor_id,
                actor_role=log_data.get('actor_role'),
                order_id=new_order_id,
                task_id=new_task_id,
                action=log_data.get('action'),
                delta=log_data.get('delta', 0),
                message=log_data.get('message')
            )
            if log_data.get('created_at'):
                try:
                    new_log.created_at = datetime.fromisoformat(log_data['created_at'].replace('Z', '+00:00'))
                except:
                    pass
            
            db.session.add(new_log)
            restored_count['logs'] += 1
        
        Log.create_log(current_user.id, current_user.role, None, None, 
                      'restore', 0, f'กู้คืนข้อมูล: Orders={restored_count["orders"]}, Tasks={restored_count["tasks"]}, Users={restored_count["users"]}, Logs={restored_count["logs"]}')
        
        return jsonify({
            'success': True,
            'message': f'กู้คืนข้อมูลสำเร็จ: ออเดอร์ {restored_count["orders"]} รายการ, งาน {restored_count["tasks"]} รายการ, ผู้ใช้ {restored_count["users"]} คน, Logs {restored_count["logs"]} รายการ',
            'restored': restored_count
        })
        
    except json.JSONDecodeError:
        return jsonify({'error': 'ไฟล์ JSON ไม่ถูกต้อง'}), 400
    except Exception as e:
        print(f"Restore error: {e}")
        return jsonify({'error': f'เกิดข้อผิดพลาด: {str(e)}'}), 500

@app.route('/api/admin/change_password', methods=['POST'])
@admin_required
@db_transaction
def api_admin_change_password():
    """เปลี่ยนรหัสผ่านแอดมิน"""
    data = request.get_json(force=True, silent=True) or {}
    
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()
    
    if not current_password or not new_password:
        return jsonify({'error': 'กรุณากรอกข้อมูลให้ครบถ้วน'}), 400
    
    if len(new_password) < 4:
        return jsonify({'error': 'รหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร'}), 400
    
    # ตรวจสอบรหัสผ่านปัจจุบัน
    if not check_password_hash(current_user.password_hash, current_password):
        return jsonify({'error': 'รหัสผ่านปัจจุบันไม่ถูกต้อง'}), 400
    
    # Validate password
    is_valid, msg = validate_password(new_password)
    if not is_valid:
        return jsonify({'error': msg}), 400
    
    # เปลี่ยนรหัสผ่าน
    current_user.password_hash = generate_password_hash(new_password)
    
    Log.create_log(current_user.id, current_user.role, None, None, 
                   'change_password', 0, f'เปลี่ยนรหัสผ่านแอดมิน')
    
    return jsonify({'success': True})

@app.route('/api/admin/settings', methods=['POST'])
@admin_required
@csrf_protect
@rate_limit(max_requests=20, per_minutes=1)
@db_transaction
def api_admin_update_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings()
        db.session.add(settings)
    
    data = request.get_json(force=True, silent=True) or {}
    
    # Update farm settings
    if 'drill_farm_enabled' in data:
        settings.drill_farm_enabled = bool(data['drill_farm_enabled'])
    if 'drill_farm_metal_per_2000_stone' in data:
        settings.drill_farm_metal_per_2000_stone = int(data['drill_farm_metal_per_2000_stone'])
    if 'drill_farm_sulfur_per_2000_stone' in data:
        settings.drill_farm_sulfur_per_2000_stone = int(data['drill_farm_sulfur_per_2000_stone'])
    if 'drill_farm_hqm_per_2000_stone' in data:
        settings.drill_farm_hqm_per_2000_stone = int(data['drill_farm_hqm_per_2000_stone'])
    if 'bonus_discount_percent' in data:
        settings.bonus_discount_percent = float(data['bonus_discount_percent'])
    if 'manual_farm_max_amount' in data:
        settings.manual_farm_max_amount = int(data['manual_farm_max_amount'])
    if 'service_fee' in data:
        settings.service_fee = float(data['service_fee'])
    
    if 'avg_minutes_per_order' in data:
        settings.avg_minutes_per_order = int(data['avg_minutes_per_order'])
    if 'eta_buffer_percent' in data:
        settings.eta_buffer_percent = float(data['eta_buffer_percent'])
    if 'max_delta_per_click' in data:
        settings.max_delta_per_click = int(data['max_delta_per_click'])
    if 'max_delta_per_action' in data:
        settings.max_delta_per_action = int(data['max_delta_per_action'])
    
    # อัพเดตอัตราการฟาร์มต่อชั่วโมง
    if 'farming_rate_wood' in data:
        settings.farming_rate_wood = int(data['farming_rate_wood'])
    if 'farming_rate_stone' in data:
        settings.farming_rate_stone = int(data['farming_rate_stone'])
    if 'farming_rate_sulfur' in data:
        settings.farming_rate_sulfur = int(data['farming_rate_sulfur'])
    if 'farming_rate_metal' in data:
        settings.farming_rate_metal = int(data['farming_rate_metal'])
    if 'farming_rate_scrap' in data:
        settings.farming_rate_scrap = int(data['farming_rate_scrap'])
    if 'farming_rate_hqm' in data:
        settings.farming_rate_hqm = int(data['farming_rate_hqm'])
    
    # อัพเดตราคา
    if 'price_per_1000_wood' in data:
        settings.price_per_1000_wood = float(data['price_per_1000_wood'])
    if 'price_per_1000_stone' in data:
        settings.price_per_1000_stone = float(data['price_per_1000_stone'])
    if 'price_per_1000_sulfur' in data:
        settings.price_per_1000_sulfur = float(data['price_per_1000_sulfur'])
    if 'price_per_1000_metal' in data:
        settings.price_per_1000_metal = float(data['price_per_1000_metal'])
    if 'price_per_1000_scrap' in data:
        settings.price_per_1000_scrap = float(data['price_per_1000_scrap'])
    if 'price_per_100_hqm' in data:
        settings.price_per_100_hqm = float(data['price_per_100_hqm'])
    
    # อัพเดต Discord Webhook
    if 'discord_webhook_url' in data:
        settings.discord_webhook_url = data['discord_webhook_url'] if data['discord_webhook_url'] else None
    
    # อัพเดต Farm Settings
    if 'drill_farm_enabled' in data:
        settings.drill_farm_enabled = bool(data['drill_farm_enabled'])
    if 'drill_farm_metal_per_2000_stone' in data:
        settings.drill_farm_metal_per_2000_stone = int(data['drill_farm_metal_per_2000_stone'])
    if 'drill_farm_sulfur_per_2000_stone' in data:
        settings.drill_farm_sulfur_per_2000_stone = int(data['drill_farm_sulfur_per_2000_stone'])
    if 'drill_farm_hqm_per_2000_stone' in data:
        settings.drill_farm_hqm_per_2000_stone = int(data['drill_farm_hqm_per_2000_stone'])
    if 'bonus_discount_percent' in data:
        settings.bonus_discount_percent = float(data['bonus_discount_percent'])
    if 'manual_farm_max_amount' in data:
        settings.manual_farm_max_amount = int(data['manual_farm_max_amount'])
    if 'service_fee' in data:
        settings.service_fee = float(data['service_fee'])
    
    settings.updated_at = datetime.utcnow()
    
    return jsonify({'success': True})

# ==================== DATABASE INIT ====================

def init_db():
    """สร้างตารางและข้อมูลเริ่มต้น"""
    db.create_all()
    
    # Migration: เพิ่ม planned_start และ planned_duration_hours ถ้ายังไม่มี
    try:
        # ตรวจสอบโดยใช้ raw SQL (รองรับทั้ง SQLite และ PostgreSQL)
        with db.engine.connect() as conn:
            # ตรวจสอบว่าเป็น SQLite หรือ PostgreSQL
            is_sqlite = 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'].lower()
            
            if is_sqlite:
                result = conn.execute(db.text("PRAGMA table_info(tasks)"))
                columns = [row[1] for row in result]
            else:
                # PostgreSQL
                result = conn.execute(db.text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='tasks'
                """))
                columns = [row[0] for row in result]
            if 'planned_start' not in columns:
                print("🔄 กำลัง migrate database: เพิ่มฟิลด์ planned_start และ planned_duration_hours...")
                conn.execute(db.text('ALTER TABLE tasks ADD COLUMN planned_start DATETIME'))
                conn.execute(db.text('ALTER TABLE tasks ADD COLUMN planned_duration_hours FLOAT'))
                conn.commit()
                print("✅ Migration สำเร็จ")
    except Exception as e:
        print(f"⚠️ Migration tasks: {e}")
    
            # Migration: เพิ่มฟิลด์อัตราการฟาร์มใน Settings (ต้องทำก่อน query Settings)
    try:
        with db.engine.connect() as conn:
            is_sqlite = 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'].lower()
            
            if is_sqlite:
                result = conn.execute(db.text("PRAGMA table_info(settings)"))
                columns = [row[1] for row in result]
            else:
                result = conn.execute(db.text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='settings'
                """))
                columns = [row[0] for row in result]
            if 'farming_rate_wood' not in columns:
                print("🔄 กำลัง migrate database: เพิ่มฟิลด์อัตราการฟาร์ม...")
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN farming_rate_wood INTEGER DEFAULT 4800'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN farming_rate_stone INTEGER DEFAULT 4800'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN farming_rate_sulfur INTEGER DEFAULT 4800'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN farming_rate_metal INTEGER DEFAULT 4800'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN farming_rate_scrap INTEGER DEFAULT 4800'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN farming_rate_hqm INTEGER DEFAULT 4800'))
                conn.commit()
                print("✅ Migration อัตราการฟาร์มสำเร็จ")
            
            # เพิ่มฟิลด์ราคาและ Discord webhook
            if 'price_per_1000_wood' not in columns:
                print("🔄 กำลัง migrate database: เพิ่มฟิลด์ราคาและ Discord webhook...")
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN price_per_1000_wood REAL DEFAULT 8.0'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN price_per_1000_stone REAL DEFAULT 7.0'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN price_per_1000_sulfur REAL DEFAULT 30.0'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN price_per_1000_metal REAL DEFAULT 9.0'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN price_per_1000_scrap REAL DEFAULT 125.0'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN price_per_100_hqm REAL DEFAULT 100.0'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN discord_webhook_url VARCHAR(500)'))
                conn.commit()
                print("✅ Migration ราคาและ Discord webhook สำเร็จ")
            
            # เพิ่มฟิลด์ Drill Farm และ Manual Farm
            if 'drill_farm_enabled' not in columns:
                print("🔄 กำลัง migrate database: เพิ่มฟิลด์ Drill Farm และ Manual Farm...")
                if is_sqlite:
                    conn.execute(db.text('ALTER TABLE settings ADD COLUMN drill_farm_enabled INTEGER DEFAULT 1'))
                else:
                    conn.execute(db.text('ALTER TABLE settings ADD COLUMN drill_farm_enabled BOOLEAN DEFAULT TRUE'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN drill_farm_metal_per_2000_stone INTEGER DEFAULT 500'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN drill_farm_sulfur_per_2000_stone INTEGER DEFAULT 200'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN drill_farm_hqm_per_2000_stone INTEGER DEFAULT 40'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN bonus_discount_percent REAL DEFAULT 50.0'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN manual_farm_max_amount INTEGER DEFAULT 15000'))
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN service_fee REAL DEFAULT 10.0'))
                conn.commit()
                print("✅ Migration Drill Farm และ Manual Farm สำเร็จ")
            
            # เพิ่มฟิลด์ commission_percent
            if 'commission_percent' not in columns:
                print("🔄 กำลัง migrate database: เพิ่มฟิลด์ค่าคนกลาง...")
                conn.execute(db.text('ALTER TABLE settings ADD COLUMN commission_percent REAL DEFAULT 10.0'))
                conn.commit()
                print("✅ Migration ค่าคนกลางสำเร็จ")
    except Exception as e:
        print(f"⚠️ Migration settings: {e}")
    
    # Migration: เพิ่มฟิลด์ discount_percent ใน Order
    try:
        with db.engine.connect() as conn:
            is_sqlite = 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'].lower()
            
            if is_sqlite:
                result = conn.execute(db.text("PRAGMA table_info(orders)"))
                columns = [row[1] for row in result]
            else:
                result = conn.execute(db.text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='orders'
                """))
                columns = [row[0] for row in result]
            if 'discount_percent' not in columns:
                print("🔄 กำลัง migrate database: เพิ่มฟิลด์ส่วนลดใน Order...")
                conn.execute(db.text('ALTER TABLE orders ADD COLUMN discount_percent REAL DEFAULT 0.0'))
                conn.commit()
                print("✅ Migration ส่วนลดสำเร็จ")
    except Exception as e:
        print(f"⚠️ Migration orders: {e}")
    
    # Migration: สร้างตาราง order_items ถ้ายังไม่มี
    try:
        with db.engine.connect() as conn:
            is_sqlite = 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'].lower()
            
            if is_sqlite:
                result = conn.execute(db.text("SELECT name FROM sqlite_master WHERE type='table' AND name='order_items'"))
            else:
                result = conn.execute(db.text("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_name='order_items'
                """))
            
            if not result.fetchone():
                print("🔄 กำลัง migrate database: สร้างตาราง order_items...")
                if is_sqlite:
                    conn.execute(db.text("""
                        CREATE TABLE order_items (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            order_id INTEGER NOT NULL,
                            item_type VARCHAR(50) NOT NULL,
                            target_amount INTEGER NOT NULL DEFAULT 0,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(order_id) REFERENCES orders(id)
                        )
                    """))
                else:
                    conn.execute(db.text("""
                        CREATE TABLE order_items (
                            id SERIAL PRIMARY KEY,
                            order_id INTEGER NOT NULL,
                            item_type VARCHAR(50) NOT NULL,
                            target_amount INTEGER NOT NULL DEFAULT 0,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(order_id) REFERENCES orders(id)
                        )
                    """))
                conn.commit()
                print("✅ Migration order_items สำเร็จ")
    except Exception as e:
        print(f"⚠️ Migration order_items: {e}")
    
    # Migration: เพิ่มฟิลด์ใหม่ใน User (real_name, bank_name, bank_account, user_title)
    try:
        with db.engine.connect() as conn:
            is_sqlite = 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'].lower()
            
            if is_sqlite:
                result = conn.execute(db.text("PRAGMA table_info(users)"))
                columns = [row[1] for row in result]
            else:
                result = conn.execute(db.text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='users'
                """))
                columns = [row[0] for row in result]
            if 'real_name' not in columns:
                print("🔄 กำลัง migrate database: เพิ่มฟิลด์ข้อมูลคนฟาร์ม...")
                conn.execute(db.text('ALTER TABLE users ADD COLUMN real_name VARCHAR(200)'))
                conn.execute(db.text('ALTER TABLE users ADD COLUMN bank_name VARCHAR(200)'))
                conn.execute(db.text('ALTER TABLE users ADD COLUMN bank_account VARCHAR(100)'))
                conn.execute(db.text('ALTER TABLE users ADD COLUMN user_title VARCHAR(50)'))
                conn.commit()
                print("✅ Migration ข้อมูลคนฟาร์มสำเร็จ")
    except Exception as e:
        print(f"⚠️ Migration users: {e}")
    
    # ตรวจสอบว่ามี super_admin user หรือยัง
    super_admin = User.query.filter_by(username='admin', role='super_admin').first()
    if not super_admin:
        # ตรวจสอบว่ามี admin เก่าหรือไม่ (migrate จาก admin เป็น super_admin)
        old_admin = User.query.filter_by(username='admin').first()
        if old_admin:
            old_admin.role = 'super_admin'
            print("✅ อัปเดต admin เป็น super_admin")
        else:
            super_admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                role='super_admin',
                display_name='Super Admin',
                active=True
            )
            db.session.add(super_admin)
            print("✅ สร้างบัญชี super_admin (username: admin, password: admin123)")
    
    # Migration: สร้างตาราง page_contents ถ้ายังไม่มี
    try:
        with db.engine.connect() as conn:
            is_sqlite = 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'].lower()
            
            if is_sqlite:
                result = conn.execute(db.text("SELECT name FROM sqlite_master WHERE type='table' AND name='page_contents'"))
            else:
                result = conn.execute(db.text("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_name='page_contents'
                """))
            
            if not result.fetchone():
                print("🔄 กำลัง migrate database: สร้างตาราง page_contents...")
                if is_sqlite:
                    conn.execute(db.text("""
                        CREATE TABLE page_contents (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            page_key VARCHAR(50) UNIQUE NOT NULL,
                            title VARCHAR(200),
                            subtitle VARCHAR(500),
                            content TEXT,
                            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                else:
                    conn.execute(db.text("""
                        CREATE TABLE page_contents (
                            id SERIAL PRIMARY KEY,
                            page_key VARCHAR(50) UNIQUE NOT NULL,
                            title VARCHAR(200),
                            subtitle VARCHAR(500),
                            content TEXT,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                conn.commit()
                print("✅ Migration page_contents สำเร็จ")
    except Exception as e:
        print(f"⚠️ Migration page_contents: {e}")
    
    # ตรวจสอบว่ามี settings หรือยัง (ทำหลัง migration)
    settings = Settings.query.first()
    if not settings:
        settings = Settings()
        db.session.add(settings)
        print("✅ สร้าง settings เริ่มต้น")
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
    # รองรับ PORT environment variable สำหรับ Railway, Render, Heroku
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)
