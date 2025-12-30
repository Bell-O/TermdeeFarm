from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
from collections import defaultdict
import time

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

class OrderItem(db.Model):
    """รายการของในออเดอร์ (หนึ่งออเดอร์สามารถมีหลาย item types ได้)"""
    __tablename__ = 'order_items'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    item_type = db.Column(db.String(50), nullable=False)  # wood, stone, sulfur, metal, scrap, hqm
    target_amount = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    order = db.relationship('Order', backref='order_items', lazy=True)

class Order(db.Model):
    __tablename__ = 'orders'
    
    id = db.Column(db.Integer, primary_key=True)
    order_key = db.Column(db.String(20), unique=True, nullable=False)
    customer_ref = db.Column(db.String(200))  # UID/ชื่อในเกม/ช่องทางแชท
    server_name = db.Column(db.String(100))
    item_type = db.Column(db.String(50))  # wood, stone, sulfur, metal, scrap, hqm (DEPRECATED - ใช้ order_items แทน)
    target_amount = db.Column(db.Integer, default=0)  # DEPRECATED - ใช้ order_items แทน
    status = db.Column(db.String(20), default='queued')  # queued, assigned, farming, delivering, done, canceled, issue
    priority = db.Column(db.String(20), default='normal')  # normal, express
    discount_percent = db.Column(db.Float, default=0.0)  # ส่วนลดให้ลูกค้า (%)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    note_admin = db.Column(db.Text)
    
    # Relationships
    tasks = db.relationship('Task', backref='order', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('Log', backref='order', lazy=True)

class TaskItem(db.Model):
    """รายการของใน Task (หนึ่ง Task สามารถมีหลาย item types ได้)"""
    __tablename__ = 'task_items'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    item_type = db.Column(db.String(50), nullable=False)  # wood, stone, sulfur, metal, scrap, hqm
    target_amount = db.Column(db.Integer, default=0, nullable=False)
    current_amount = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    task = db.relationship('Task', backref='task_items', lazy=True)

class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    farmer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    server_name = db.Column(db.String(100))
    item_type = db.Column(db.String(50))  # DEPRECATED - ใช้ task_items แทน
    target_amount = db.Column(db.Integer, default=0)  # DEPRECATED - ใช้ task_items แทน
    current_amount = db.Column(db.Integer, default=0)  # DEPRECATED - ใช้ task_items แทน (sum of all items)
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
    
    # Drill Farm Settings
    drill_farm_enabled = db.Column(db.Boolean, default=True)
    drill_farm_metal_per_2000_stone = db.Column(db.Integer, default=500)  # ต่อ 2000 stone ได้ metal เท่าไหร่
    drill_farm_sulfur_per_2000_stone = db.Column(db.Integer, default=200)  # ต่อ 2000 stone ได้ sulfur เท่าไหร่
    drill_farm_hqm_per_2000_stone = db.Column(db.Integer, default=40)  # ต่อ 2000 stone ได้ HQM เท่าไหร่
    bonus_discount_percent = db.Column(db.Float, default=50.0)  # ส่วนลดของแถม (%)
    
    # Manual Farm Settings
    manual_farm_max_amount = db.Column(db.Integer, default=15000)  # จำนวนสูงสุดที่รับฟาร์มมือ
    
    # Service Fee
    service_fee = db.Column(db.Float, default=10.0)  # ค่าบริการร้าน Termdee (บาท)
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get_settings():
        settings = Settings.query.first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.flush()  # ใช้ flush แทน commit เพื่อไม่รบกวน transaction
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
            'discord_webhook_url': settings.discord_webhook_url,
            'drill_farm_enabled': settings.drill_farm_enabled if hasattr(settings, 'drill_farm_enabled') else True,
            'drill_farm_metal_per_2000_stone': settings.drill_farm_metal_per_2000_stone if hasattr(settings, 'drill_farm_metal_per_2000_stone') else 500,
            'drill_farm_sulfur_per_2000_stone': settings.drill_farm_sulfur_per_2000_stone if hasattr(settings, 'drill_farm_sulfur_per_2000_stone') else 200,
            'drill_farm_hqm_per_2000_stone': settings.drill_farm_hqm_per_2000_stone if hasattr(settings, 'drill_farm_hqm_per_2000_stone') else 40,
            'bonus_discount_percent': settings.bonus_discount_percent if hasattr(settings, 'bonus_discount_percent') else 50.0,
            'manual_farm_max_amount': settings.manual_farm_max_amount if hasattr(settings, 'manual_farm_max_amount') else 15000,
            'service_fee': settings.service_fee if hasattr(settings, 'service_fee') else 10.0
        }
    
    @staticmethod
    def get_farming_rate(item_type):
        """ดึงอัตราการฟาร์มต่อชั่วโมงตามประเภทของ"""
        settings = Settings.query.first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.flush()  # ใช้ flush แทน commit เพื่อไม่รบกวน transaction
        
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
            db.session.flush()  # ใช้ flush แทน commit เพื่อไม่รบกวน transaction
        
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
    def calculate_drill_farm_bonus(item_type, item_amount, settings=None):
        """
        คำนวณของแถมจากฟาร์มเครื่องขุด
        - ถ้าซื้อ Stone → แถม Metal + Sulfur + HQM
        - ถ้าซื้อ Metal → แถม Stone + Sulfur + HQM
        - ถ้าซื้อ Sulfur → แถม Stone + Metal + HQM
        - ถ้าซื้อ HQM → แถม Stone + Metal + Sulfur
        
        Returns: dict with 'stone', 'metal', 'sulfur', 'hqm' (ของแถมทั้งหมด)
        """
        if settings is None:
            settings_obj = Settings.query.first()
            if not settings_obj:
                settings = {}
            else:
                settings = Settings.get_settings()
        
        metal_per_2000 = settings.get('drill_farm_metal_per_2000_stone', 500)
        sulfur_per_2000 = settings.get('drill_farm_sulfur_per_2000_stone', 200)
        hqm_per_2000 = settings.get('drill_farm_hqm_per_2000_stone', 40)
        
        item_type_lower = item_type.lower()
        
        # คำนวณ stone equivalent จาก item ที่ซื้อ
        if item_type_lower == 'stone':
            stone_amount = item_amount
        elif item_type_lower == 'metal':
            # 500 metal = 2000 stone
            stone_amount = (item_amount / metal_per_2000) * 2000.0
        elif item_type_lower == 'sulfur':
            # 200 sulfur = 2000 stone
            stone_amount = (item_amount / sulfur_per_2000) * 2000.0
        elif item_type_lower == 'hqm':
            # 40 HQM = 2000 stone
            stone_amount = (item_amount / hqm_per_2000) * 2000.0
        else:
            # wood, scrap ไม่มีของแถม
            return {'stone': 0, 'metal': 0, 'sulfur': 0, 'hqm': 0}
        
        # คำนวณของแถมทั้งหมดจาก stone equivalent
        multiplier = stone_amount / 2000.0
        bonus_metal = int(metal_per_2000 * multiplier)
        bonus_sulfur = int(sulfur_per_2000 * multiplier)
        bonus_hqm = int(hqm_per_2000 * multiplier)
        bonus_stone = int(2000 * multiplier)  # stone equivalent
        
        # สร้าง dict ของแถม (ไม่รวมตัวที่ซื้อ)
        bonus = {
            'stone': bonus_stone if item_type_lower != 'stone' else 0,
            'metal': bonus_metal if item_type_lower != 'metal' else 0,
            'sulfur': bonus_sulfur if item_type_lower != 'sulfur' else 0,
            'hqm': bonus_hqm if item_type_lower != 'hqm' else 0
        }
        
        return bonus
    
    @staticmethod
    def calculate_drill_farm_optimal_price(amount, settings=None):
        """
        คำนวณราคาที่สูงสุดจากทุกประเภทที่เป็นไปได้ (ป้องกันการโกงราคา)
        ตัวอย่าง: ต้องการ Stone 50,000 แต่ถ้าใส่ Metal 12,500 จะได้ Stone 50,000 เหมือนกัน
        แต่ราคา Metal 12,500 อาจถูกกว่า Stone 50,000
        
        Returns: dict with 'item_type', 'amount', 'price', 'stone_equivalent'
        """
        if settings is None:
            settings = Settings.get_settings()
        
        metal_per_2000 = settings.get('drill_farm_metal_per_2000_stone', 500)
        sulfur_per_2000 = settings.get('drill_farm_sulfur_per_2000_stone', 200)
        hqm_per_2000 = settings.get('drill_farm_hqm_per_2000_stone', 40)
        
        # คำนวณ stone equivalent จากทุกประเภท
        # 2000 stone = 500 metal = 200 sulfur = 40 hqm
        stone_equivalent = amount  # ถ้าเป็น stone
        
        # คำนวณราคาจากทุกประเภทที่เป็นไปได้
        options = []
        
        # Option 1: Stone
        stone_amount = amount
        stone_price = Settings.calculate_price_before_commission('stone', stone_amount, 0)
        options.append({
            'item_type': 'stone',
            'amount': stone_amount,
            'price': stone_price,
            'stone_equivalent': stone_amount
        })
        
        # Option 2: Metal (แปลงเป็น stone equivalent)
        metal_amount = amount
        metal_stone_equiv = (metal_amount / metal_per_2000) * 2000.0
        metal_price = Settings.calculate_price_before_commission('metal', metal_amount, 0)
        options.append({
            'item_type': 'metal',
            'amount': metal_amount,
            'price': metal_price,
            'stone_equivalent': metal_stone_equiv
        })
        
        # Option 3: Sulfur (แปลงเป็น stone equivalent)
        sulfur_amount = amount
        sulfur_stone_equiv = (sulfur_amount / sulfur_per_2000) * 2000.0
        sulfur_price = Settings.calculate_price_before_commission('sulfur', sulfur_amount, 0)
        options.append({
            'item_type': 'sulfur',
            'amount': sulfur_amount,
            'price': sulfur_price,
            'stone_equivalent': sulfur_stone_equiv
        })
        
        # Option 4: HQM (แปลงเป็น stone equivalent)
        hqm_amount = amount
        hqm_stone_equiv = (hqm_amount / hqm_per_2000) * 2000.0
        hqm_price = Settings.calculate_price_before_commission('hqm', hqm_amount, 0)
        options.append({
            'item_type': 'hqm',
            'amount': hqm_amount,
            'price': hqm_price,
            'stone_equivalent': hqm_stone_equiv
        })
        
        # หา stone equivalent ที่ใกล้เคียงกันมากที่สุด (ใช้ stone equivalent ที่ใกล้เคียงกับ amount ที่ต้องการ)
        # แล้วเลือกราคาที่สูงสุดจากตัวเลือกที่มี stone equivalent ใกล้เคียงกัน
        
        # จัดกลุ่มตาม stone equivalent (ปัดเศษ)
        target_stone_equiv = amount  # ถ้าเป็น stone
        for opt in options:
            if opt['item_type'] != 'stone':
                # คำนวณ stone equivalent ใหม่
                if opt['item_type'] == 'metal':
                    opt['stone_equivalent'] = (opt['amount'] / metal_per_2000) * 2000.0
                elif opt['item_type'] == 'sulfur':
                    opt['stone_equivalent'] = (opt['amount'] / sulfur_per_2000) * 2000.0
                elif opt['item_type'] == 'hqm':
                    opt['stone_equivalent'] = (opt['amount'] / hqm_per_2000) * 2000.0
        
        # เลือกตัวเลือกที่มี stone equivalent ใกล้เคียงกับ target มากที่สุด (ภายใน 5%)
        # แล้วเลือกราคาที่สูงสุด
        best_option = None
        best_price = 0
        
        for opt in options:
            # ตรวจสอบว่า stone equivalent ใกล้เคียงกับ target หรือไม่ (ภายใน 5%)
            diff_percent = abs(opt['stone_equivalent'] - target_stone_equiv) / target_stone_equiv * 100
            if diff_percent <= 5:  # ใกล้เคียงภายใน 5%
                if opt['price'] > best_price:
                    best_price = opt['price']
                    best_option = opt
        
        # ถ้าไม่เจอที่ใกล้เคียง ให้เลือกราคาสูงสุดเลย
        if best_option is None:
            best_option = max(options, key=lambda x: x['price'])
        
        return best_option
    
    @staticmethod
    def calculate_total_price_with_bonus(item_type, amount, discount_percent=0.0, farm_type='manual', settings=None):
        """
        คำนวณราคารวม (รวมของแถมถ้าเป็นฟาร์มเครื่องขุด และหักส่วนลดของแถม)
        สำหรับฟาร์มเครื่องขุด: จะคำนวณราคาจากทุกประเภทที่เป็นไปได้และเลือกราคาสูงสุด (ป้องกันการโกงราคา)
        
        Returns: dict with 'base_price', 'bonus_items', 'bonus_price', 'service_fee', 'total_price', 'optimal_item_type'
        """
        if settings is None:
            settings = Settings.get_settings()
        
        service_fee = settings.get('service_fee', 10.0)
        bonus_discount = settings.get('bonus_discount_percent', 50.0)
        
        optimal_item_type = item_type
        optimal_amount = amount
        
        # ถ้าเป็นฟาร์มเครื่องขุด ให้หาราคาสูงสุดจากทุกประเภทที่เป็นไปได้
        if farm_type == 'drill' and item_type.lower() in ['stone', 'metal', 'sulfur', 'hqm']:
            # คำนวณ stone equivalent จาก item ที่ใส่เข้ามา
            metal_per_2000 = settings.get('drill_farm_metal_per_2000_stone', 500)
            sulfur_per_2000 = settings.get('drill_farm_sulfur_per_2000_stone', 200)
            hqm_per_2000 = settings.get('drill_farm_hqm_per_2000_stone', 40)
            
            if item_type.lower() == 'stone':
                target_stone = amount
            elif item_type.lower() == 'metal':
                target_stone = (amount / metal_per_2000) * 2000.0
            elif item_type.lower() == 'sulfur':
                target_stone = (amount / sulfur_per_2000) * 2000.0
            elif item_type.lower() == 'hqm':
                target_stone = (amount / hqm_per_2000) * 2000.0
            else:
                target_stone = amount
            
            # คำนวณราคาจากทุกประเภทที่เป็นไปได้
            options = []
            
            # Option 1: Stone
            stone_price = Settings.calculate_price_before_commission('stone', int(target_stone), discount_percent)
            options.append({
                'item_type': 'stone',
                'amount': int(target_stone),
                'price': stone_price
            })
            
            # Option 2: Metal
            metal_amount = int((target_stone / 2000.0) * metal_per_2000)
            metal_price = Settings.calculate_price_before_commission('metal', metal_amount, discount_percent)
            options.append({
                'item_type': 'metal',
                'amount': metal_amount,
                'price': metal_price
            })
            
            # Option 3: Sulfur
            sulfur_amount = int((target_stone / 2000.0) * sulfur_per_2000)
            sulfur_price = Settings.calculate_price_before_commission('sulfur', sulfur_amount, discount_percent)
            options.append({
                'item_type': 'sulfur',
                'amount': sulfur_amount,
                'price': sulfur_price
            })
            
            # Option 4: HQM
            hqm_amount = int((target_stone / 2000.0) * hqm_per_2000)
            hqm_price = Settings.calculate_price_before_commission('hqm', hqm_amount, discount_percent)
            options.append({
                'item_type': 'hqm',
                'amount': hqm_amount,
                'price': hqm_price
            })
            
            # เลือกราคาสูงสุด
            best_option = max(options, key=lambda x: x['price'])
            optimal_item_type = best_option['item_type']
            optimal_amount = best_option['amount']
        
        # ราคาหลัก (ใช้ราคาที่สูงสุด)
        base_price = Settings.calculate_price_before_commission(optimal_item_type, optimal_amount, discount_percent)
        
        # ราคารวม (รวมค่าบริการ)
        total_price = base_price + service_fee
        bonus_items = {}
        bonus_price = 0.0
        
        # ถ้าเป็นฟาร์มเครื่องขุด ให้คำนวณของแถม (ใช้ optimal_item_type และ optimal_amount)
        if farm_type == 'drill' and optimal_item_type.lower() in ['stone', 'metal', 'sulfur', 'hqm']:
            bonus_items = Settings.calculate_drill_farm_bonus(optimal_item_type, optimal_amount, settings)
            
            # คำนวณราคาของแถม (หักส่วนลด) - ใช้ราคาจาก Settings ที่ตั้งค่าในหน้าแอดมิน "ตั้งค่าราคา (บาท)"
            if bonus_items.get('stone', 0) > 0:
                stone_price = Settings.calculate_price_before_commission('stone', bonus_items['stone'], 0)
                bonus_price += stone_price * (1 - bonus_discount / 100)
            
            if bonus_items.get('metal', 0) > 0:
                metal_price = Settings.calculate_price_before_commission('metal', bonus_items['metal'], 0)
                bonus_price += metal_price * (1 - bonus_discount / 100)
            
            if bonus_items.get('sulfur', 0) > 0:
                sulfur_price = Settings.calculate_price_before_commission('sulfur', bonus_items['sulfur'], 0)
                bonus_price += sulfur_price * (1 - bonus_discount / 100)
            
            if bonus_items.get('hqm', 0) > 0:
                hqm_price = Settings.calculate_price_before_commission('hqm', bonus_items['hqm'], 0)
                bonus_price += hqm_price * (1 - bonus_discount / 100)
        
        return {
            'base_price': base_price,
            'bonus_items': bonus_items,
            'bonus_price': bonus_price,
            'service_fee': service_fee,
            'total_price': total_price + bonus_price,
            'optimal_item_type': optimal_item_type,
            'optimal_amount': optimal_amount,
            'original_item_type': item_type,
            'original_amount': amount
        }
    
    @staticmethod
    def calculate_price_before_commission(item_type, amount, discount_percent=0.0):
        """คำนวณเงินก่อนหักค่าคนกลาง (สำหรับแสดง)"""
        if not amount or amount <= 0:
            return 0.0
        
        settings = Settings.query.first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.flush()  # ใช้ flush แทน commit เพื่อไม่รบกวน transaction
        
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

class PageContent(db.Model):
    """เนื้อหาหน้าเว็บที่แก้ไขได้"""
    __tablename__ = 'page_contents'
    
    id = db.Column(db.Integer, primary_key=True)
    page_key = db.Column(db.String(50), unique=True, nullable=False)  # เช่น 'index', 'about'
    title = db.Column(db.String(200))
    subtitle = db.Column(db.String(500))
    content = db.Column(db.Text)  # JSON หรือ HTML content
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get_content(page_key, default_content=None):
        """ดึงเนื้อหาหน้าเว็บ"""
        content = PageContent.query.filter_by(page_key=page_key).first()
        if content:
            return content
        # ถ้ายังไม่มี สร้างด้วย default content
        if default_content:
            new_content = PageContent(
                page_key=page_key,
                title=default_content.get('title', ''),
                subtitle=default_content.get('subtitle', ''),
                content=default_content.get('content', '')
            )
            db.session.add(new_content)
            try:
                db.session.commit()
            except:
                db.session.rollback()
            return new_content
        return None

class IPLog(db.Model):
    """บันทึก IP และ request logs"""
    __tablename__ = 'ip_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)  # รองรับ IPv6
    endpoint = db.Column(db.String(200), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    user_agent = db.Column(db.String(500))
    referer = db.Column(db.String(500))
    status_code = db.Column(db.Integer)
    response_time = db.Column(db.Float)  # milliseconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    @staticmethod
    def log_request(ip_address, endpoint, method, user_agent=None, referer=None, status_code=200, response_time=0):
        """บันทึก request"""
        log = IPLog(
            ip_address=ip_address,
            endpoint=endpoint,
            method=method,
            user_agent=user_agent,
            referer=referer,
            status_code=status_code,
            response_time=response_time
        )
        db.session.add(log)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        return log
    
    @staticmethod
    def get_recent_requests(ip_address, minutes=1):
        """ดึง requests ล่าสุดของ IP นี้"""
        since = datetime.utcnow() - timedelta(minutes=minutes)
        return IPLog.query.filter(
            IPLog.ip_address == ip_address,
            IPLog.created_at >= since
        ).count()
    
    @staticmethod
    def get_suspicious_ips(minutes=5, threshold=50):
        """หา IP ที่มี requests มากเกินไป"""
        since = datetime.utcnow() - timedelta(minutes=minutes)
        logs = IPLog.query.filter(IPLog.created_at >= since).all()
        
        ip_counts = defaultdict(int)
        for log in logs:
            ip_counts[log.ip_address] += 1
        
        suspicious = [ip for ip, count in ip_counts.items() if count >= threshold]
        return suspicious

class BlockedIP(db.Model):
    """IP ที่ถูก block"""
    __tablename__ = 'blocked_ips'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(500))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_until = db.Column(db.DateTime)  # None = block ถาวร
    blocked_by = db.Column(db.String(100))  # 'system' หรือ user_id
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    @staticmethod
    def is_blocked(ip_address):
        """ตรวจสอบว่า IP ถูก block หรือไม่"""
        blocked = BlockedIP.query.filter_by(
            ip_address=ip_address,
            is_active=True
        ).first()
        
        if not blocked:
            return False
        
        # ตรวจสอบว่า block หมดอายุหรือยัง
        if blocked.blocked_until and blocked.blocked_until < datetime.utcnow():
            blocked.is_active = False
            try:
                db.session.commit()
            except:
                db.session.rollback()
            return False
        
        return True
    
    @staticmethod
    def block_ip(ip_address, reason='Rate limit exceeded', blocked_until=None, blocked_by='system'):
        """Block IP"""
        existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
        if existing:
            existing.is_active = True
            existing.reason = reason
            existing.blocked_at = datetime.utcnow()
            existing.blocked_until = blocked_until
            existing.blocked_by = blocked_by
        else:
            blocked = BlockedIP(
                ip_address=ip_address,
                reason=reason,
                blocked_until=blocked_until,
                blocked_by=blocked_by
            )
            db.session.add(blocked)
        try:
            db.session.commit()
        except:
            db.session.rollback()
    
    @staticmethod
    def unblock_ip(ip_address):
        """Unblock IP"""
        blocked = BlockedIP.query.filter_by(ip_address=ip_address).first()
        if blocked:
            blocked.is_active = False
            try:
                db.session.commit()
            except:
                db.session.rollback()

class CSRFToken(db.Model):
    """CSRF tokens สำหรับป้องกัน CSRF attacks"""
    __tablename__ = 'csrf_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    session_id = db.Column(db.String(100), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def generate_token(session_id=None):
        """สร้าง CSRF token ใหม่"""
        import secrets
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        csrf_token = CSRFToken(
            token=token,
            session_id=session_id,
            expires_at=expires_at
        )
        db.session.add(csrf_token)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        return token
    
    @staticmethod
    def validate_token(token, session_id=None, mark_used=True):
        """ตรวจสอบ CSRF token"""
        csrf_token = CSRFToken.query.filter_by(
            token=token,
            used=False
        ).first()
        
        if not csrf_token:
            return False
        
        # ตรวจสอบว่า token หมดอายุหรือยัง
        if csrf_token.expires_at < datetime.utcnow():
            return False
        
        # ถ้ามี session_id ให้ตรวจสอบด้วย
        if session_id and csrf_token.session_id and csrf_token.session_id != session_id:
            return False
        
        # Mark as used (เฉพาะเมื่อ mark_used=True)
        if mark_used:
            csrf_token.used = True
            try:
                db.session.commit()
            except:
                db.session.rollback()
        return True
    
    @staticmethod
    def cleanup_expired():
        """ลบ tokens ที่หมดอายุ"""
        expired = CSRFToken.query.filter(CSRFToken.expires_at < datetime.utcnow()).all()
        for token in expired:
            db.session.delete(token)
        try:
            db.session.commit()
        except:
            db.session.rollback()

