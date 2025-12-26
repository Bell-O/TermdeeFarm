from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from models import db, User, Order, Task, Log, Settings, OrderTemplate
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
    return dict(get_status_th=get_status_th, Settings=Settings)

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

# Decorators
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'super_admin']:
            flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'super_admin':
            flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้ (ต้องเป็นแอดมินหลัก)', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def farmer_required(f):
    @wraps(f)
    @login_required
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
    return render_template('track.html')

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
                         all_item_types=all_item_types)

@app.route('/admin/order/<int:order_id>')
@admin_required
def admin_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    tasks = Task.query.filter_by(order_id=order_id).all()
    farmers = User.query.filter_by(role='farmer', active=True).all()
    logs = Log.query.filter_by(order_id=order_id).order_by(Log.created_at.desc()).limit(50).all()
    
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

@app.route('/admin/change-password')
@admin_required
def admin_change_password():
    """หน้าเปลี่ยนรหัสผ่านแอดมิน"""
    return render_template('admin/change_password.html')

# ==================== ADMIN API ====================

@app.route('/api/admin/order', methods=['POST'])
@admin_required
@db_transaction
def api_admin_create_order():
    data = request.get_json(force=True, silent=True) or {}
    
    order_key = generate_order_key()
    discount_percent = float(data.get('discount_percent', 0.0))
    
    order = Order(
        order_key=order_key,
        customer_ref=data.get('customer_ref', ''),
        server_name=data.get('server_name', ''),
        item_type=data.get('item_type', ''),
        target_amount=int(data.get('target_amount', 0)),
        priority=data.get('priority', 'normal'),
        discount_percent=discount_percent,
        note_admin=data.get('note_admin', '')
    )
    
    db.session.add(order)
    db.session.flush()
    
    Log.create_log(current_user.id, current_user.role, order.id, None, 
                   'create_order', 0, f'สร้างออเดอร์ {order_key}')
    
    return jsonify({
        'success': True, 
        'order_id': order.id,
        'order_key': order_key
    })

@app.route('/api/admin/order/<int:order_id>/task', methods=['POST'])
@admin_required
@db_transaction
def api_admin_create_task(order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json(force=True, silent=True) or {}
    
    item_type = data.get('item_type', order.item_type)
    target_amount = int(data.get('target_amount', 0))
    
    # คำนวณเวลาที่ใช้ในการฟาร์มอัตโนมัติ (ถ้ายังไม่ได้ระบุ)
    planned_duration_hours = None
    if data.get('planned_duration_hours'):
        planned_duration_hours = float(data['planned_duration_hours'])
    elif target_amount > 0 and item_type:
        # คำนวณอัตโนมัติจาก target_amount และ item_type
        planned_duration_hours = Settings.calculate_duration_hours(item_type, target_amount)
    
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
        item_type=item_type,
        target_amount=target_amount,
        planned_start=planned_start,
        planned_duration_hours=planned_duration_hours
    )
    
    db.session.add(task)
    db.session.flush()
    
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
@db_transaction
def api_admin_delete_order(order_id):
    """ลบออเดอร์"""
    order = Order.query.get_or_404(order_id)
    
    # ตรวจสอบว่ามี tasks ที่ยังไม่เสร็จหรือไม่
    active_tasks = Task.query.filter_by(order_id=order_id).filter(
        Task.status.in_(['assigned', 'accepted', 'farming', 'paused', 'ready_to_deliver'])
    ).count()
    
    if active_tasks > 0:
        return jsonify({'error': f'ไม่สามารถลบได้ เนื่องจากมีงานที่กำลังทำอยู่ {active_tasks} งาน'}), 400
    
    order_key = order.order_key
    
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
            
            # ตรวจสอบว่ามีงานที่กำลังทำอยู่หรือไม่
            active_tasks = Task.query.filter_by(order_id=order_id).filter(
                Task.status.in_(['assigned', 'accepted', 'farming', 'paused', 'ready_to_deliver'])
            ).count()
            
            if active_tasks > 0:
                errors.append(f'ออเดอร์ {order.order_key} มีงานที่กำลังทำอยู่')
                continue
            
            order_key = order.order_key
            
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
@db_transaction
def api_admin_duplicate_order(order_id):
    """คัดลอกออเดอร์"""
    original_order = Order.query.get_or_404(order_id)
    
    # สร้างออเดอร์ใหม่
    new_order_key = generate_order_key()
    new_order = Order(
        order_key=new_order_key,
        customer_ref=original_order.customer_ref,
        server_name=original_order.server_name,
        item_type=original_order.item_type,
        target_amount=original_order.target_amount,
        priority=original_order.priority,
        discount_percent=original_order.discount_percent,
        note_admin=original_order.note_admin
    )
    
    db.session.add(new_order)
    db.session.flush()
    
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
            'planned_start': t.planned_start.isoformat() if t.planned_start else None,
            'planned_duration_hours': t.planned_duration_hours,
            'created_at': t.created_at.isoformat() if t.created_at else None,
            'accepted_at': t.accepted_at.isoformat() if t.accepted_at else None,
            'updated_at': t.updated_at.isoformat() if t.updated_at else None
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
            'delta': l.delta,
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
@db_transaction
def api_admin_update_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings()
        db.session.add(settings)
    
    data = request.get_json(force=True, silent=True) or {}
    
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
