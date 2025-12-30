# Termdee Farm - ระบบติดตามฟาร์ม Oxide

ระบบจัดการและติดตามการฟาร์ม Oxide สำหรับร้าน Termdee โดยใช้ Flask + SQLite

## คุณสมบัติ

### ฝั่งลูกค้า
- ดูสถานะออเดอร์ผ่าน Order Key (ไม่ต้อง login)
- ดูความคืบหน้าการฟาร์มแบบ real-time
- ดูคิวและเวลารอโดยประมาณ
- Auto-refresh ทุก 30 วินาที

### ฝั่งคนฟาร์ม
- Login เพื่อดูงานที่ได้รับมอบหมาย
- รับงาน (Accept Task)
- อัปเดตความคืบหน้า (+1000, +5000, +10000 หรือกำหนดเอง)
- เปลี่ยนสถานะงาน (พัก, พร้อมส่ง, ส่งแล้ว)
- ดูเฉพาะงานของตัวเอง

### ฝั่ง Admin (ร้าน)
- สร้างออเดอร์ใหม่
- แตกออเดอร์เป็น Task และมอบหมายให้คนฟาร์ม
- จัดการคิวและ ETA
- ดู Logs ทั้งหมด
- จัดการคนฟาร์ม (เพิ่ม, ปิดใช้งาน)
- เปลี่ยนสถานะออเดอร์

## การติดตั้ง

### 1. ติดตั้ง Dependencies

```bash
pip install -r requirements.txt
```

### 2. ตั้งค่า Environment Variables

สร้างไฟล์ `.env` จาก `.env.example`:

```bash
cp .env.example .env
```

แก้ไขค่าใน `.env`:
- `SECRET_KEY`: เปลี่ยนเป็น secret key ที่ปลอดภัย
- `DATABASE_URL`: ใช้ SQLite (default) หรือ PostgreSQL

### 3. รันแอปพลิเคชัน

```bash
python app.py
```

แอปจะรันที่ `http://localhost:5000`

### 4. Login ครั้งแรก

- **Username:** `admin`
- **Password:** `admin123`

**⚠️ เปลี่ยนรหัสผ่านทันทีหลัง login ครั้งแรก!**

## โครงสร้างโปรเจกต์

```
TermdeeFarm/
├── app.py                 # Flask application
├── models.py              # Database models
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates
│   ├── base.html
│   ├── track.html         # หน้าติดตามออเดอร์ (ลูกค้า)
│   ├── farmer/            # หน้าคนฟาร์ม
│   │   ├── login.html
│   │   ├── tasks.html
│   │   └── task_detail.html
│   └── admin/              # หน้าจัดการ (Admin)
│       ├── dashboard.html
│       ├── orders.html
│       ├── order_detail.html
│       ├── farmers.html
│       ├── queue.html
│       └── logs.html
└── static/                 # Static files
    ├── css/
    │   └── style.css
    └── js/
        └── main.js
```

## Database Schema

### Users
- `id`, `username`, `password_hash`, `role` (admin/farmer)
- `display_name`, `active`, `created_at`, `last_seen_at`

### Orders
- `id`, `order_key` (unique), `customer_ref`, `server_name`
- `item_type` (wood/stone/sulfur/metal/scrap/hqm)
- `target_amount`, `status`, `priority`, `created_at`

### Tasks
- `id`, `order_id`, `farmer_id`, `server_name`, `item_type`
- `target_amount`, `current_amount`, `status`
- `accepted_at`, `started_at`, `finished_at`

### Logs
- `id`, `actor_user_id`, `actor_role`, `order_id`, `task_id`
- `action`, `delta_amount`, `message`, `created_at`

### Settings
- `avg_minutes_per_order`, `eta_buffer_percent`
- `max_delta_per_click`, `max_delta_per_action`

## API Endpoints

### Public
- `GET /track/<order_key>` - ดูสถานะออเดอร์
- `GET /api/track/<order_key>` - API สำหรับ track

### Farmer
- `POST /farmer/login` - Login
- `GET /farmer/tasks` - ดูงานทั้งหมด
- `GET /farmer/task/<id>` - ดูรายละเอียดงาน
- `POST /api/farmer/task/<id>/accept` - รับงาน
- `POST /api/farmer/task/<id>/start` - เริ่มฟาร์ม
- `POST /api/farmer/task/<id>/progress` - อัปเดตความคืบหน้า
- `POST /api/farmer/task/<id>/pause` - พักงาน
- `POST /api/farmer/task/<id>/ready` - พร้อมส่ง
- `POST /api/farmer/task/<id>/delivered` - ส่งแล้ว

### Admin
- `POST /api/admin/order` - สร้างออเดอร์
- `POST /api/admin/order/<id>/task` - สร้าง Task
- `POST /api/admin/task/<id>/assign` - มอบหมายงาน
- `POST /api/admin/order/<id>/status` - เปลี่ยนสถานะ
- `POST /api/admin/farmer` - เพิ่มคนฟาร์ม
- `POST /api/admin/farmer/<id>/disable` - ปิดใช้งานคนฟาร์ม

## Workflow

1. **ลูกค้าสั่งผ่านแชท** → Admin สร้าง Order → ส่ง Order Key ให้ลูกค้า
2. **Admin แชทตกลงกับคนฟาร์ม** → สร้าง Task → Assign ให้คนฟาร์ม
3. **คนฟาร์ม Login** → รับงาน → เริ่มฟาร์ม → อัปเดต progress
4. **คนฟาร์มกดพร้อมส่ง** → Admin แชทนัดส่ง → คนฟาร์มกดส่งแล้ว
5. **Admin ปิดงาน** → Order status = done

## การใช้งาน

### สร้างออเดอร์ใหม่
1. Login เป็น Admin
2. ไปที่ "จัดการออเดอร์"
3. กด "สร้างออเดอร์ใหม่"
4. กรอกข้อมูล → ได้ Order Key
5. ส่งลิงก์ `termdee.com/track/<order_key>` ให้ลูกค้า

### มอบหมายงานให้คนฟาร์ม
1. เปิดรายละเอียดออเดอร์
2. กด "สร้าง Task ใหม่"
3. กำหนดเป้าหมายและเลือกคนฟาร์ม (หรือปล่อยว่างไว้)
4. คนฟาร์มจะเห็นงานในหน้า "งานของฉัน"

### คนฟาร์มอัปเดตความคืบหน้า
1. Login เป็น Farmer
2. ไปที่ "งานของฉัน"
3. กด "ดูรายละเอียด"
4. กดปุ่ม +1000, +5000, +10000 หรือกำหนดเอง
5. ระบบจะอัปเดตอัตโนมัติ → ลูกค้าเห็นทันที

## หมายเหตุ

- ระบบใช้ SQLite เป็น default (เหมาะสำหรับใช้งานเล็ก-กลาง)
- สำหรับ production แนะนำใช้ PostgreSQL
- เปลี่ยน `SECRET_KEY` ใน production
- Backup database เป็นประจำ
- ระบบ Log ทุกการกระทำเพื่อ audit

## License

Private - สำหรับ Termdee Farm เท่านั้น




