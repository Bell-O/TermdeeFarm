from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # super_admin, admin, farmer
    display_name = db.Column(db.String(100))
    # ข้อมูลสำหรับคนฟาร์ม
    real_name = db.Column(db.String(200))  # ชื่อจริง
    bank_name = db.Column(db.String(200))  # ชื่อธนาคาร
    bank_account = db.Column(db.String(100))  # บัญชีธนาคาร
    user_title = db.Column(db.String(50))  # ยศผู้ใช้ (เช่น Senior Farmer, Junior Farmer)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime)
    
    # Relationships
    tasks = db.relationship('Task', backref='farmer', lazy=True)
    logs = db.relationship('Log', backref='actor', lazy=True)

class Order(db.Model):
    __tablename__ = 'orders'
    
    id = db.Column(db.Integer, primary_key=True)
    order_key = db.Column(db.String(20), unique=True, nullable=False)
    customer_ref = db.Column(db.String(200))  # UID/ชื่อในเกม/ช่องทางแชท
    server_name = db.Column(db.String(100))
    item_type = db.Column(db.String(50))  # wood, stone, sulfur, metal, scrap, hqm
    target_amount = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='queued')  # queued, assigned, farming, delivering, done, canceled, issue
    priority = db.Column(db.String(20), default='normal')  # normal, express
    discount_percent = db.Column(db.Float, default=0.0)  # ส่วนลดให้ลูกค้า (%)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    note_admin = db.Column(db.Text)
    
    # Relationships
    tasks = db.relationship('Task', backref='order', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('Log', backref='order', lazy=True)

class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    farmer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    server_name = db.Column(db.String(100))
    item_type = db.Column(db.String(50))
    target_amount = db.Column(db.Integer, default=0)
    current_amount = db.Column(db.Integer, default=0)
    status = db.Column(db.String(30), default='assigned')  # assigned, accepted, farming, paused, ready_to_deliver, delivered
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accepted_at = db.Column(db.DateTime)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    planned_start = db.Column(db.DateTime)  # เวลาที่วางแผนจะเริ่มงาน
    planned_duration_hours = db.Column(db.Float)  # ระยะเวลาที่คาดว่าจะใช้ (ชั่วโมง)
    note_farmer = db.Column(db.Text)
    
    # Relationships
    logs = db.relationship('Log', backref='task', lazy=True)

class Log(db.Model):
    __tablename__ = 'logs'
    
    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    actor_role = db.Column(db.String(20))
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=True)
    action = db.Column(db.String(50))  # create_order, assign_task, add_progress, status_change, etc.
    delta_amount = db.Column(db.Integer, default=0)
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @staticmethod
    def create_log(user_id, role, order_id, task_id, action, delta, message):
        log = Log(
            actor_user_id=user_id,
            actor_role=role,
            order_id=order_id,
            task_id=task_id,
            action=action,
            delta_amount=delta,
            message=message
        )
        db.session.add(log)
        return log

class Settings(db.Model):
    __tablename__ = 'settings'
    
    id = db.Column(db.Integer, primary_key=True)
    avg_minutes_per_order = db.Column(db.Integer, default=25)
    eta_buffer_percent = db.Column(db.Float, default=10.0)
    max_delta_per_click = db.Column(db.Integer, default=10000)
    max_delta_per_action = db.Column(db.Integer, default=50000)
    commission_percent = db.Column(db.Float, default=10.0)  # ค่าคนกลาง (%)
    # อัตราการฟาร์มต่อชั่วโมง (items per hour) สำหรับแต่ละประเภท
    farming_rate_wood = db.Column(db.Integer, default=4800)  # ไม้ 24,000 / 5 ชม. = 4,800/ชม.
    farming_rate_stone = db.Column(db.Integer, default=4800)
    farming_rate_sulfur = db.Column(db.Integer, default=4800)
    farming_rate_metal = db.Column(db.Integer, default=4800)
    farming_rate_scrap = db.Column(db.Integer, default=4800)
    farming_rate_hqm = db.Column(db.Integer, default=4800)
    # ราคาต่อ 1000 items (หรือ 100 สำหรับ HQM)
    price_per_1000_wood = db.Column(db.Float, default=8.0)  # 1000 ไม้ = 8 บาท
    price_per_1000_stone = db.Column(db.Float, default=7.0)  # 1000 หิน = 7 บาท
    price_per_1000_sulfur = db.Column(db.Float, default=30.0)  # 1000 กำมะถัน = 30 บาท
    price_per_1000_metal = db.Column(db.Float, default=9.0)  # 1000 เหล็ก = 9 บาท
    price_per_1000_scrap = db.Column(db.Float, default=125.0)  # 1000 Scrap = 125 บาท
    price_per_100_hqm = db.Column(db.Float, default=100.0)  # 100 HQM = 100 บาท
    # Discord Webhook
    discord_webhook_url = db.Column(db.String(500))  # Discord webhook URL สำหรับแจ้งเตือน
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get_settings():
        settings = Settings.query.first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.commit()
        return {
            'avg_minutes_per_order': settings.avg_minutes_per_order,
            'eta_buffer_percent': settings.eta_buffer_percent,
            'max_delta_per_click': settings.max_delta_per_click,
            'max_delta_per_action': settings.max_delta_per_action,
            'commission_percent': settings.commission_percent,
            'farming_rate_wood': settings.farming_rate_wood,
            'farming_rate_stone': settings.farming_rate_stone,
            'farming_rate_sulfur': settings.farming_rate_sulfur,
            'farming_rate_metal': settings.farming_rate_metal,
            'farming_rate_scrap': settings.farming_rate_scrap,
            'farming_rate_hqm': settings.farming_rate_hqm,
            'price_per_1000_wood': settings.price_per_1000_wood,
            'price_per_1000_stone': settings.price_per_1000_stone,
            'price_per_1000_sulfur': settings.price_per_1000_sulfur,
            'price_per_1000_metal': settings.price_per_1000_metal,
            'price_per_1000_scrap': settings.price_per_1000_scrap,
            'price_per_100_hqm': settings.price_per_100_hqm,
            'discord_webhook_url': settings.discord_webhook_url
        }
    
    @staticmethod
    def get_farming_rate(item_type):
        """ดึงอัตราการฟาร์มต่อชั่วโมงตามประเภทของ"""
        settings = Settings.query.first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.commit()
        
        rate_map = {
            'wood': settings.farming_rate_wood,
            'stone': settings.farming_rate_stone,
            'sulfur': settings.farming_rate_sulfur,
            'metal': settings.farming_rate_metal,
            'scrap': settings.farming_rate_scrap,
            'hqm': settings.farming_rate_hqm
        }
        
        return rate_map.get(item_type.lower(), settings.farming_rate_wood)  # default = wood
    
    @staticmethod
    def calculate_duration_hours(item_type, target_amount):
        """คำนวณเวลาที่ใช้ในการฟาร์ม (ชั่วโมง) จากประเภทและจำนวน"""
        if not target_amount or target_amount <= 0:
            return None
        
        rate = Settings.get_farming_rate(item_type)
        if not rate or rate <= 0:
            return None
        
        hours = target_amount / rate
        return round(hours, 2)  # ปัดเป็น 2 ตำแหน่ง
    
    @staticmethod
    def calculate_price(item_type, amount, discount_percent=0.0, commission_percent=None):
        """คำนวณเงินที่จะได้จากประเภทและจำนวน (หลังหักส่วนลดและค่าคนกลาง)"""
        if not amount or amount <= 0:
            return 0.0
        
        settings = Settings.query.first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.commit()
        
        # ใช้ค่าจาก Settings ถ้าไม่ได้ระบุ
        if commission_percent is None:
            commission_percent = settings.commission_percent
        
        item_type_lower = item_type.lower()
        base_price = 0.0
        
        if item_type_lower == 'wood':
            base_price = (amount / 1000) * settings.price_per_1000_wood
        elif item_type_lower == 'stone':
            base_price = (amount / 1000) * settings.price_per_1000_stone
        elif item_type_lower == 'sulfur':
            base_price = (amount / 1000) * settings.price_per_1000_sulfur
        elif item_type_lower == 'metal':
            base_price = (amount / 1000) * settings.price_per_1000_metal
        elif item_type_lower == 'scrap':
            base_price = (amount / 1000) * settings.price_per_1000_scrap
        elif item_type_lower == 'hqm':
            base_price = (amount / 100) * settings.price_per_100_hqm
        
        # หักส่วนลดให้ลูกค้า
        if discount_percent > 0:
            base_price = base_price * (1 - discount_percent / 100)
        
        # หักค่าคนกลาง (commission)
        if commission_percent > 0:
            base_price = base_price * (1 - commission_percent / 100)
        
        return round(base_price, 2)
    
    @staticmethod
    def calculate_price_before_commission(item_type, amount, discount_percent=0.0):
        """คำนวณเงินก่อนหักค่าคนกลาง (สำหรับแสดง)"""
        if not amount or amount <= 0:
            return 0.0
        
        settings = Settings.query.first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.commit()
        
        item_type_lower = item_type.lower()
        base_price = 0.0
        
        if item_type_lower == 'wood':
            base_price = (amount / 1000) * settings.price_per_1000_wood
        elif item_type_lower == 'stone':
            base_price = (amount / 1000) * settings.price_per_1000_stone
        elif item_type_lower == 'sulfur':
            base_price = (amount / 1000) * settings.price_per_1000_sulfur
        elif item_type_lower == 'metal':
            base_price = (amount / 1000) * settings.price_per_1000_metal
        elif item_type_lower == 'scrap':
            base_price = (amount / 1000) * settings.price_per_1000_scrap
        elif item_type_lower == 'hqm':
            base_price = (amount / 100) * settings.price_per_100_hqm
        
        # หักส่วนลดให้ลูกค้า
        if discount_percent > 0:
            base_price = base_price * (1 - discount_percent / 100)
        
        return round(base_price, 2)

class OrderTemplate(db.Model):
    """เทมเพลตออเดอร์สำหรับสร้างออเดอร์ซ้ำๆ"""
    __tablename__ = 'order_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)  # ชื่อเทมเพลต
    customer_ref = db.Column(db.String(200))
    server_name = db.Column(db.String(100))
    item_type = db.Column(db.String(50))
    target_amount = db.Column(db.Integer, default=0)
    priority = db.Column(db.String(20), default='normal')
    discount_percent = db.Column(db.Float, default=0.0)
    note_admin = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

